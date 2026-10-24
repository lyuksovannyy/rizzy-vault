// SPDX-License-Identifier: AGPL-3.0-only

//! Threat model INV-6: "no path from the master password to a key or an authenticator is
//! cheaper than one Argon2id evaluation at an allowed `kdf_id`. Each flow runs a fixed number of
//! evaluations", counted here with the `cfg(test)` counter of [`crate::kdf::argon2id`]
//! ([`crate::kdf::test_hooks`]), which sees the OPAQUE KSF and the local wraps alike.
//!
//! Each test runs one row of INV-6's table through this crate's primitives, in the order of
//! CRYPTO.md §11 (the shape of the transcript vector, `test_vectors/transcript.rs`), at the real
//! `kdf_id` 1 (64 MiB), and checks the count and that every evaluation ran at that `kdf_id`:
//!
//! | Flow (CRYPTO.md) | Evaluations |
//! |---|---|
//! | signup on a durable client (§11.1) | 2: the registration KSF, the local wrap |
//! | signup in the web vault (§11.1, §11.4) | 1: the registration KSF |
//! | first login on a new device (§11.2) | 2: the login KSF, the local wrap |
//! | web-vault login (§11.4) | 1: the login KSF |
//! | unlock on an enrolled device (§11.3) | 1: the local unlock key |
//! | re-enrolment after a rotation, knowing only the new password (§11.3 step 5) | 2 |
//! | password change in Server mode (§11.5) | 3: re-authentication, registration, local wrap |
//!
//! What it proves: each primitive's cost (registration and login one KSF each, the local unlock
//! key one evaluation; `pw_in`, the server half, the `server_unlock_key` from the `export_key`
//! and every wrap none), so a flow built from them costs what the table says. What it does not
//! prove: that `rizzy-client`'s flows call them in exactly this way. The counter is `cfg(test)`
//! in this crate and so invisible to `rizzy-client`'s tests; counting there needs a hook visible
//! across crates (a cargo feature or an accessor in this crate), which is the owner's decision.
//! The keystore unlock through `E_ks` (no evaluation, INV-62) is not built yet.

use chacha20::ChaCha20Rng;
use rand_core::{Rng as _, SeedableRng as _};

use crate::envelope::purpose::{AccountKeyLocalWrapCtx, AccountKeyServerWrapCtx};
use crate::ids::{AccountId, DeviceId};
use crate::kdf::KdfId;
use crate::kdf::test_hooks::runs;
use crate::keys::AccountKey;
use crate::normalize::{LoginName, ServerOrigin};
use crate::opaque::{
    CredentialIdentifier, OpaqueContext, PasswordFile, PasswordInput, RegisteredCredential,
    ServerSetup, client_login_finish, client_login_start, client_registration_finish,
    client_registration_start, server_login_finish, server_login_start, server_registration_finish,
    server_registration_start,
};
use crate::secret_key::SecretKey;

/// The master password before a change.
const PASSWORD: &str = "correct horse battery staple";

/// The master password after a change.
const NEW_PASSWORD: &str = "a different master password";

/// The server side of an account and what the client keeps, as far as these flows need it.
struct Fixture {
    /// The OPAQUE server setup.
    setup: ServerSetup,
    /// The account.
    account_id: AccountId,
    /// The Secret Key.
    secret_key: SecretKey,
    /// The OPAQUE record, serialised.
    password_file: Vec<u8>,
    /// `E_srv`.
    e_srv: Vec<u8>,
    /// The `password_epoch` of `E_srv`.
    password_epoch: u32,
    /// The account key (what every flow must reach).
    account_key: AccountKey,
}

/// Runs `f`; returns its result and how many Argon2id evaluations it ran, after checking they
/// all ran at `kdf_id` 1.
fn counted<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = runs().len();
    let out = f();
    let ran = runs().split_off(before);
    assert!(ran.iter().all(|id| *id == KdfId::DEFAULT.get()), "{ran:?}");
    (out, ran.len())
}

/// The `E_local` context of a device at account-key epoch 0.
fn local_ctx(account_id: AccountId, device_id: DeviceId) -> AccountKeyLocalWrapCtx {
    AccountKeyLocalWrapCtx {
        account_id,
        device_id,
        account_key_epoch: 0,
        password_epoch: 0,
        kdf_id: KdfId::DEFAULT,
    }
}

/// OPAQUE registration of `pw_in` and `E_srv` under its `export_key` (§11.1, §11.5 step 3).
fn register(rng: &mut ChaCha20Rng, account: &mut Fixture, pw_in: &PasswordInput) {
    let (state, request) = client_registration_start(rng, pw_in).unwrap();
    let credential = CredentialIdentifier::for_account(account.account_id);
    let response = server_registration_start(&account.setup, &request, &credential).unwrap();
    let reg = client_registration_finish(rng, state, pw_in, &response, KdfId::DEFAULT).unwrap();
    account.password_file = server_registration_finish(&reg.upload).unwrap().to_bytes();
    let ctx = AccountKeyServerWrapCtx {
        account_id: account.account_id,
        account_key_epoch: 0,
        password_epoch: account.password_epoch,
        kdf_id: KdfId::DEFAULT,
    };
    account.e_srv = reg
        .export_key
        .server_unlock_key(account.account_id)
        .unwrap()
        .wrap_account_key(rng, &ctx, &account.account_key)
        .unwrap();
}

/// An OPAQUE login with `password` and `E_srv` opened under its `export_key` (§11.2 steps
/// 2–6); checks the account key it yields.
fn login(rng: &mut ChaCha20Rng, account: &Fixture, password: &str) {
    let pw_in = PasswordInput::derive(password, &account.secret_key).unwrap();
    let origin = ServerOrigin::parse("https://vault.example.com").unwrap();
    let context = OpaqueContext::new(KdfId::DEFAULT, &origin);
    let (state, ke1) = client_login_start(rng, &pw_in).unwrap();
    let record = RegisteredCredential {
        account_id: account.account_id,
        password_file: PasswordFile::from_bytes(&account.password_file).unwrap(),
        kdf_id: KdfId::DEFAULT,
    };
    let name = LoginName::parse("alice").unwrap();
    let start =
        server_login_start(rng, &account.setup, &name, Some(record), &ke1, &context).unwrap();
    let fin = client_login_finish(rng, state, &pw_in, &start.ke2, &context).unwrap();
    server_login_finish(start.state, &fin.ke3, &context).unwrap();
    let ctx = AccountKeyServerWrapCtx {
        account_id: account.account_id,
        account_key_epoch: 0,
        password_epoch: account.password_epoch,
        kdf_id: KdfId::DEFAULT,
    };
    let key = fin
        .export_key
        .server_unlock_key(account.account_id)
        .unwrap()
        .unwrap_account_key(&ctx, &account.e_srv)
        .unwrap();
    assert_eq!(
        key.key().expose_secret(),
        account.account_key.key().expose_secret()
    );
}

/// A device's local wrap under `password` (§11.1 step 7, §11.2 step 7): a fresh salt, the local
/// unlock key, `E_local`. Returns the device, its salt and `E_local`.
fn local_wrap(
    rng: &mut ChaCha20Rng,
    account: &Fixture,
    password: &str,
) -> (DeviceId, [u8; 16], Vec<u8>) {
    let device_id = DeviceId::generate(rng);
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let pw_in = PasswordInput::derive(password, &account.secret_key).unwrap();
    let e_local = pw_in
        .local_unlock_key(&salt, KdfId::DEFAULT, account.account_id, device_id)
        .unwrap()
        .wrap_account_key(
            rng,
            &local_ctx(account.account_id, device_id),
            &account.account_key,
        )
        .unwrap();
    (device_id, salt, e_local)
}

/// A web-vault signup (§11.1 with no local wrap): the account, before any device.
fn signup_web(rng: &mut ChaCha20Rng) -> Fixture {
    let mut account = Fixture {
        setup: ServerSetup::generate(rng),
        account_id: AccountId::generate(rng),
        secret_key: SecretKey::generate(rng),
        password_file: Vec::new(),
        e_srv: Vec::new(),
        password_epoch: 0,
        account_key: AccountKey::generate(rng, 0),
    };
    let pw_in = PasswordInput::derive_for_new_password(PASSWORD, &account.secret_key).unwrap();
    register(rng, &mut account, &pw_in);
    account
}

/// Signup on a durable client and in the web vault (§11.1).
#[test]
fn signup_runs_two_evaluations_on_a_durable_client_and_one_in_the_web_vault() {
    let mut rng = ChaCha20Rng::seed_from_u64(6001);
    let (_, n) = counted(|| signup_web(&mut rng));
    assert_eq!(n, 1, "web-vault signup");
    let (_, n) = counted(|| {
        let account = signup_web(&mut rng);
        local_wrap(&mut rng, &account, PASSWORD)
    });
    assert_eq!(n, 2, "durable signup");
}

/// First login on a new device, web-vault login, and unlock on an enrolled device (§11.2–§11.4).
#[test]
fn login_runs_two_evaluations_on_a_new_device_one_in_the_web_vault_and_unlock_one() {
    let mut rng = ChaCha20Rng::seed_from_u64(6002);
    let account = signup_web(&mut rng);
    let ((), n) = counted(|| login(&mut rng, &account, PASSWORD));
    assert_eq!(n, 1, "web-vault login");
    let ((device_id, salt, e_local), n) = counted(|| {
        login(&mut rng, &account, PASSWORD);
        local_wrap(&mut rng, &account, PASSWORD)
    });
    assert_eq!(n, 2, "first login on a new device");
    let (key, n) = counted(|| {
        PasswordInput::derive(PASSWORD, &account.secret_key)
            .unwrap()
            .local_unlock_key(&salt, KdfId::DEFAULT, account.account_id, device_id)
            .unwrap()
            .unwrap_account_key(&local_ctx(account.account_id, device_id), &e_local)
            .unwrap()
    });
    assert_eq!(n, 1, "unlock on an enrolled device");
    assert_eq!(
        key.key().expose_secret(),
        account.account_key.key().expose_secret()
    );
}

/// A password change in Server mode (§11.5), then the re-enrolment of a device that knows only
/// the new password (§11.3 step 5: an OPAQUE login and a new local wrap).
#[test]
fn a_password_change_runs_three_evaluations_and_a_re_enrolment_two() {
    let mut rng = ChaCha20Rng::seed_from_u64(6003);
    let mut account = signup_web(&mut rng);
    let ((), n) = counted(|| {
        // Re-authentication with the old password.
        login(&mut rng, &account, PASSWORD);
        // Registration of the new one, and the new local wrap of this device.
        let pw_in =
            PasswordInput::derive_for_new_password(NEW_PASSWORD, &account.secret_key).unwrap();
        account.password_epoch = 1;
        register(&mut rng, &mut account, &pw_in);
        local_wrap(&mut rng, &account, NEW_PASSWORD);
    });
    assert_eq!(n, 3, "password change");
    let (_, n) = counted(|| {
        login(&mut rng, &account, NEW_PASSWORD);
        local_wrap(&mut rng, &account, NEW_PASSWORD)
    });
    assert_eq!(n, 2, "re-enrolment with the new password");
}

/// The steps that must not stretch: `pw_in`, the server half of registration and login, and
/// the `server_unlock_key` (one evaluation feeds both OPAQUE and `E_srv`, threat model §5.1).
#[test]
fn pw_in_and_the_server_half_run_no_evaluation() {
    let mut rng = ChaCha20Rng::seed_from_u64(6004);
    let sk = SecretKey::generate(&mut rng);
    let ((), n) = counted(|| {
        PasswordInput::derive(PASSWORD, &sk).unwrap();
        let setup = ServerSetup::generate(&mut rng);
        let pw_in = PasswordInput::derive(PASSWORD, &sk).unwrap();
        let (_, request) = client_registration_start(&mut rng, &pw_in).unwrap();
        let credential = CredentialIdentifier::for_account(AccountId::generate(&mut rng));
        server_registration_start(&setup, &request, &credential).unwrap();
    });
    assert_eq!(n, 0);
}
