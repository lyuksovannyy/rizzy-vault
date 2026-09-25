//! `transcript.json` (tier B, CRYPTO.md §15 item 1): the regression transcript of a whole
//! Server-mode account life in M1, driven by one seeded `ChaCha20Rng` fed to opaque-ke through
//! the §5.1 adapter.
//!
//! 1. **Signup** (§11.1): the Secret Key, the server setup, `pw_in`, OPAQUE registration with
//!    `RizzySuiteV1` at `kdf_id` 1, the account key, `E_srv` under the `server_unlock_key` from
//!    the `export_key`, and the device's `E_local`.
//! 2. **Login on a new device** (§11.2): OPAQUE login with the Context; the `export_key`
//!    matches, and `E_srv` opens to the same account key.
//! 3. **Unlock** (§11.3): `E_local` opens under the local unlock key.
//!
//! Every value comes from this implementation; none is an independent known answer. Three
//! 64 MiB Argon2id runs: the registration KSF, the login KSF and the local unlock key.

use chacha20::ChaCha20Rng;
use rand_core::{Rng as _, SeedableRng as _};
use serde_json::{Map, Value};

use super::{Obj, Vector, num, text, u64_of};
use crate::envelope::purpose::{AccountKeyLocalWrapCtx, AccountKeyServerWrapCtx};
use crate::ids::{AccountId, DeviceId};
use crate::kdf::KdfId;
use crate::keys::AccountKey;
use crate::normalize::{LoginName, ServerOrigin};
use crate::opaque::{
    CredentialIdentifier, OpaqueContext, PasswordInput, RegisteredCredential, ServerSetup,
    client_login_finish, client_login_start, client_registration_finish, client_registration_start,
    server_login_finish, server_login_start, server_registration_finish, server_registration_start,
};
use crate::secret_key::SecretKey;

pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    vec![Vector::build(
        compute,
        "transcript",
        "signup-login-unlock",
        0,
        Obj::new()
            .u64("seed", rng.next_u64())
            .text("password", "correct horse battery staple")
            .text("login_name", "Alice")
            .text("server_origin", "https://vault.example.com")
            .num("kdf_id", 1),
    )]
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat table of test vectors reads best as one function"
)]
pub(super) fn compute(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    assert_eq!(name, "signup-login-unlock");
    let mut rng = ChaCha20Rng::seed_from_u64(u64_of(m, "seed"));
    let origin = ServerOrigin::parse(text(m, "server_origin")).expect("an origin");
    let login = LoginName::parse(text(m, "login_name")).expect("a login name");
    let kdf_id = KdfId::from_u16(num(m, "kdf_id")).expect("an allowed kdf_id");
    let password = text(m, "password");

    // 1. Signup.
    let secret_key = SecretKey::generate(&mut rng);
    let setup = ServerSetup::generate(&mut rng);
    let account_id = AccountId::generate(&mut rng);
    let device_id = DeviceId::generate(&mut rng);
    let pw_in = PasswordInput::derive_for_new_password(password, &secret_key).expect("pw_in");
    let context = OpaqueContext::new(kdf_id, &origin);
    let (reg_state, request) = client_registration_start(&mut rng, &pw_in).expect("KE0");
    let credential = CredentialIdentifier::for_account(account_id);
    let response = server_registration_start(&setup, &request, &credential).expect("response");
    let reg = client_registration_finish(&mut rng, reg_state, &pw_in, &response, kdf_id)
        .expect("registration");
    let password_file = server_registration_finish(&reg.upload).expect("record");
    let password_file_bytes = password_file.to_bytes();

    let account_key = AccountKey::generate(&mut rng, 0);
    let srv_ctx = AccountKeyServerWrapCtx {
        account_id,
        account_key_epoch: 0,
        password_epoch: 0,
        kdf_id,
    };
    let server_unlock_key = reg
        .export_key
        .server_unlock_key(account_id)
        .expect("server_unlock_key");
    let e_srv = server_unlock_key
        .wrap_account_key(&mut rng, &srv_ctx, &account_key)
        .expect("E_srv");
    let mut device_salt = [0u8; 16];
    rng.fill_bytes(&mut device_salt);
    let local = pw_in
        .local_unlock_key(&device_salt, kdf_id, account_id, device_id)
        .expect("local_unlock_key");
    let local_ctx = AccountKeyLocalWrapCtx {
        account_id,
        device_id,
        account_key_epoch: 0,
        password_epoch: 0,
        kdf_id,
    };
    let e_local = local
        .wrap_account_key(&mut rng, &local_ctx, &account_key)
        .expect("E_local");

    // 2. Login on a new device.
    let (login_state, ke1) = client_login_start(&mut rng, &pw_in).expect("KE1");
    let record = RegisteredCredential {
        account_id,
        password_file,
        kdf_id,
    };
    let start =
        server_login_start(&mut rng, &setup, &login, Some(record), &ke1, &context).expect("KE2");
    let ke2 = start.ke2;
    let fin = client_login_finish(&mut rng, login_state, &pw_in, &ke2, &context).expect("KE3");
    server_login_finish(start.state, &fin.ke3, &context).expect("server finish");
    assert_eq!(
        fin.export_key.expose_secret(),
        reg.export_key.expose_secret()
    );
    let from_login = fin
        .export_key
        .server_unlock_key(account_id)
        .expect("server_unlock_key")
        .unwrap_account_key(&srv_ctx, &e_srv)
        .expect("E_srv opens after login");
    assert_eq!(
        from_login.key().expose_secret(),
        account_key.key().expose_secret()
    );

    // 3. Unlock.
    let unlocked = local
        .unwrap_account_key(&local_ctx, &e_local)
        .expect("E_local opens");
    assert_eq!(
        unlocked.key().expose_secret(),
        account_key.key().expose_secret()
    );

    let key_id = |k: &crate::secret::Key32| *k.key_id().expect("key id").as_bytes();
    Obj::new()
        .bytes("secret_key", secret_key.expose_secret())
        .bytes("server_setup", setup.to_bytes().expose_secret())
        .bytes("account_id", account_id.as_bytes())
        .bytes("device_id", device_id.as_bytes())
        .bytes("pw_in", pw_in.expose_secret())
        .bytes("context", context.as_bytes())
        .bytes("registration_request", &request)
        .bytes("registration_response", &response)
        .bytes("registration_upload", &reg.upload)
        .bytes("password_file", &password_file_bytes)
        .bytes("export_key", reg.export_key.expose_secret())
        .bytes(
            "server_unlock_key",
            server_unlock_key.key_for_tests().expose_secret(),
        )
        .bytes("account_key", account_key.key().expose_secret())
        .bytes("account_key_id", &key_id(account_key.key()))
        .bytes("e_srv", &e_srv)
        .bytes("device_salt", &device_salt)
        .bytes("local_unlock_key", local.key_for_tests().expose_secret())
        .bytes("e_local", &e_local)
        .bytes("ke1", &ke1)
        .bytes("ke2", &ke2)
        .bytes("ke3", &fin.ke3)
        .done()
}
