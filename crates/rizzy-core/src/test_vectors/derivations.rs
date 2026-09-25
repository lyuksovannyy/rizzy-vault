//! `derivations.json`: every §4.3 derivation M1 implements, with the derived value itself.
//!
//! Not here: the M3–M6 derivations (relay key, local index key, shares, pairing, the
//! password-verifier and re-sync PSKs), which have no code yet. The envelope subkey and
//! commitment are in `envelopes.json`, next to the envelopes they belong to, and the SK and
//! recovery-code check characters in `encodings.json`.

use chacha20::ChaCha20Rng;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use super::{
    Obj, Vector, arr, bytes, bytes_list, child_rng, num, opt_bytes, random, random_vec, small,
    text, u64_of,
};
use crate::envelope::purpose::AccountKeyDeviceGrantCtx;
use crate::export::password_file_key;
use crate::hpke::{HpkePsk, HpkePublicKey, HpkeSecretKey};
use crate::ids::{AccountId, DeviceId, KeyType, PublicKeyId, SymmetricKeyId};
use crate::kdf::KdfId;
use crate::keys::{
    AccountFingerprint, AccountKey, IdentityPublicKeys, LocalUnlockKey, ServerUnlockKey,
    device_set_hash, settings_hash,
};
use crate::labels::{self, Label};
use crate::normalize::{LoginName, ServerOrigin};
use crate::opaque::{CredentialIdentifier, EnumKey, OpaqueContext, PasswordInput};
use crate::secret::{Key32, SecretArray};
use crate::secret_key::{RecoveryCode, SecretKey};
use crate::server_seal::ServerDataKey;
use crate::sign::{
    DeviceCertificate, DeviceKind, DeviceRevocation, DeviceSigningKey, IdentitySigningKey,
    IdentityVerifyingKey, Verified,
};

const KIND: &str = "derivation";

fn vector(name: &str, index: usize, inputs: Obj) -> Vector {
    Vector::build(compute, KIND, name, index, inputs)
}

/// A 32-byte X25519 public key of a fresh key pair.
fn x25519_public(rng: &mut ChaCha20Rng) -> [u8; 32] {
    *HpkeSecretKey::generate_x25519(rng).public_key().as_bytes()
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat table of test vectors reads best as one function"
)]
pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    let mut out = Vec::new();

    for i in 0..2 {
        out.push(vector(
            "key-id/symmetric",
            i,
            Obj::new().bytes("key", &random::<32>(rng)),
        ));
    }
    for (i, key_type) in KeyType::ALL.into_iter().enumerate() {
        let public_key = match key_type {
            KeyType::IdentityEd25519 | KeyType::DeviceEd25519 => {
                *DeviceSigningKey::generate(rng).verifying_key().as_bytes()
            }
            _ => x25519_public(rng),
        };
        out.push(vector(
            "key-id",
            i,
            Obj::new()
                .num("key_type", u32::from(key_type.to_u8()))
                .bytes("public_key", &public_key),
        ));
    }

    // pw_in: an ASCII password, and one whose NFC differs from its input (a decomposed é and
    // a character outside the BMP), so NFC is part of the vector.
    for (i, password) in [
        "correct horse battery staple",
        "Pa\u{0301}sswo\u{0308}rd \u{1F511}",
    ]
    .into_iter()
    .enumerate()
    {
        out.push(vector(
            "opaque/password",
            i,
            Obj::new()
                .text("password", password)
                .bytes("secret_key", &random::<16>(rng)),
        ));
    }
    for (i, origin) in [
        "https://vault.example.com",
        "HTTPS://Vault.Example.COM:443/",
        "http://192.168.1.20:8080",
    ]
    .into_iter()
    .enumerate()
    {
        out.push(vector(
            "opaque/context",
            i,
            Obj::new().num("kdf_id", 1).text("server_origin", origin),
        ));
    }
    for (i, name) in ["alice", "Bob.Smith+vault@Example.org"]
        .into_iter()
        .enumerate()
    {
        out.push(vector(
            "opaque/fake-credential-id",
            i,
            Obj::new().text("login_name", name),
        ));
        out.push(vector(
            "opaque/fake-kdf",
            i,
            Obj::new()
                .bytes("enum_key", &random::<32>(rng))
                .text("login_name", name),
        ));
    }

    out.push(vector(
        "unlock-key/server",
        0,
        Obj::new()
            .bytes("export_key", &random::<64>(rng))
            .bytes("account_id", &random::<16>(rng)),
    ));
    // One 64 MiB Argon2id run.
    out.push(vector(
        "unlock-key/local",
        0,
        Obj::new()
            .bytes("pw_in", &random::<32>(rng))
            .bytes("device_salt", &random::<16>(rng))
            .num("kdf_id", 1)
            .bytes("account_id", &random::<16>(rng))
            .bytes("device_id", &random::<16>(rng)),
    ));
    let recovery_code = random::<16>(rng);
    out.push(vector(
        "recovery/wrap-key",
        0,
        Obj::new().bytes("recovery_code", &recovery_code),
    ));
    out.push(vector(
        "recovery/auth-token",
        0,
        Obj::new().bytes("recovery_code", &recovery_code),
    ));
    // One 64 MiB Argon2id run each.
    out.push(vector(
        "export/key",
        0,
        Obj::new()
            .text("export_password", "exp\u{00E9}rt pa\u{0073}\u{0073}")
            .bytes("export_salt", &random::<16>(rng))
            .num("kdf_id", 1)
            .bytes("export_id", &random::<16>(rng)),
    ));
    out.push(vector(
        "server/secrets-backup",
        0,
        Obj::new()
            .text("passphrase", "operator backup passphrase")
            .bytes("backup_salt", &random::<16>(rng))
            .num("kdf_id", 1)
            .bytes("backup_id", &random::<16>(rng)),
    ));
    let server_data_key = random::<32>(rng);
    for name in ["server/totp-secret", "server/login-state"] {
        out.push(vector(
            name,
            0,
            Obj::new()
                .bytes("server_data_key", &server_data_key)
                .num("data_key_id", 3),
        ));
    }
    out.push(vector(
        "hpke-psk/device-grant",
        0,
        Obj::new()
            .bytes("previous_account_key", &random::<32>(rng))
            .bytes("account_id", &random::<16>(rng))
            .num("account_key_epoch", 1 + small(rng, 5))
            .bytes("recipient_device_id", &random::<16>(rng)),
    ));

    let (a, b) = (random::<16>(rng), random::<16>(rng));
    let (a_ed, b_ed) = (
        *IdentitySigningKey::generate(rng).verifying_key().as_bytes(),
        *IdentitySigningKey::generate(rng).verifying_key().as_bytes(),
    );
    let (a_x, b_x) = (x25519_public(rng), x25519_public(rng));
    out.push(vector(
        "fingerprint",
        0,
        Obj::new()
            .bytes("account_id", &a)
            .bytes("identity_ed25519_public_key", &a_ed)
            .bytes("identity_x25519_public_key", &a_x)
            .bytes("other_account_id", &b)
            .bytes("other_identity_ed25519_public_key", &b_ed)
            .bytes("other_identity_x25519_public_key", &b_x),
    ));

    for (i, inputs) in device_sets(&mut child_rng(rng)).into_iter().enumerate() {
        out.push(vector("device-set", i, inputs));
    }

    out.push(vector(
        "settings",
        0,
        Obj::new().u64("settings_seq", 0).null("settings_envelope"),
    ));
    out.push(vector(
        "settings",
        1,
        Obj::new()
            .u64("settings_seq", 7)
            .bytes("settings_envelope", &random_vec(rng, 200)),
    ));
    out
}

/// Three device sets: empty (web-vault signup), one desktop device, and four certificates of
/// which the web-vault one (kind 4) and a revoked one are left out.
fn device_sets(rng: &mut ChaCha20Rng) -> Vec<Obj> {
    let account = AccountId::from_bytes(random(rng));
    let identity = IdentitySigningKey::generate(rng);
    let identity_epoch = 0;
    let base = Obj::new()
        .bytes("account_id", account.as_bytes())
        .bytes("identity_public_key", identity.verifying_key().as_bytes())
        .num("identity_epoch", identity_epoch);
    let t0 = 1_780_000_000_000u64;
    let mut cert = |kind: DeviceKind, created: u64, expires: u64| {
        let device = DeviceSigningKey::generate(rng);
        DeviceCertificate {
            account_id: account,
            device_id: DeviceId::from_bytes(random(rng)),
            identity_epoch,
            device_ed25519: *device.verifying_key(),
            device_x25519: HpkePublicKey::x25519(x25519_public(rng)),
            device_kind: kind,
            created_at_ms: created,
            expires_at_ms: expires,
        }
    };
    let desktop = cert(DeviceKind::DesktopCli, t0, 0);
    let extension = cert(DeviceKind::Extension, t0 + 1_000, 0);
    let mobile = cert(DeviceKind::Mobile, t0 + 2_000, 0);
    let web = cert(DeviceKind::WebEphemeral, t0 + 3_000, t0 + 3_000 + 3_600_000);
    let sign = |c: &DeviceCertificate| c.sign(&identity).expect("valid certificate");
    let revocation = DeviceRevocation {
        account_id: account,
        device_id: extension.device_id,
        last_accepted_device_seq: 41,
        revoked_at_ms: t0 + 10_000,
    }
    .sign(&identity)
    .expect("valid revocation");
    vec![
        Obj(base.0.clone())
            .bytes_list("certificates", &[])
            .bytes_list("revocations", &[]),
        Obj(base.0.clone())
            .bytes_list("certificates", &[sign(&desktop)])
            .bytes_list("revocations", &[]),
        base.bytes_list(
            "certificates",
            &[sign(&web), sign(&mobile), sign(&extension), sign(&desktop)],
        )
        .bytes_list("revocations", &[revocation]),
    ]
}

/// `{key, key_id}` of a derived symmetric key.
fn key_outputs(key: &Key32) -> Map<String, Value> {
    Obj::new()
        .bytes("key", key.expose_secret())
        .bytes("key_id", key.key_id().expect("key id").as_bytes())
        .done()
}

fn kdf(m: &Map<String, Value>) -> KdfId {
    KdfId::from_u16(num(m, "kdf_id")).expect("an allowed kdf_id")
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat table of test vectors reads best as one function"
)]
pub(super) fn compute(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    match name {
        "key-id/symmetric" => {
            let key = Key32::from_slice(&bytes(m, "key")).expect("32 bytes");
            let id = SymmetricKeyId::derive(&key).expect("key id");
            assert_eq!(id, key.key_id().expect("key id"));
            Obj::new().bytes("key_id", id.as_bytes()).done()
        }
        "key-id" => {
            let key_type = KeyType::from_u8(num(m, "key_type")).expect("a key type");
            let id = PublicKeyId::derive(key_type, &arr(m, "public_key"));
            Obj::new().bytes("key_id", id.as_bytes()).done()
        }
        "opaque/password" => {
            let password = text(m, "password");
            let sk = SecretKey::from_slice(&bytes(m, "secret_key")).expect("16 bytes");
            let pw_in = PasswordInput::derive(password, &sk).expect("pw_in");
            let nfc = crate::kdf::normalize_password(password).expect("NFC");
            Obj::new()
                .bytes("nfc_utf8", nfc.expose_secret())
                .bytes("pw_in", pw_in.expose_secret())
                .done()
        }
        "opaque/context" => {
            let origin = ServerOrigin::parse(text(m, "server_origin")).expect("an origin");
            let context = OpaqueContext::new(kdf(m), &origin);
            Obj::new()
                .text("server_origin", origin.as_str())
                .bytes("context", context.as_bytes())
                .done()
        }
        "opaque/fake-credential-id" => {
            let login = LoginName::parse(text(m, "login_name")).expect("a login name");
            let id = CredentialIdentifier::fake(&login);
            Obj::new()
                .text("login_name", login.as_str())
                .bytes("credential_id", id.as_bytes())
                .done()
        }
        "opaque/fake-kdf" => {
            let login = LoginName::parse(text(m, "login_name")).expect("a login name");
            let key = EnumKey::from_slice(&bytes(m, "enum_key")).expect("32 bytes");
            let selector = key.fake_kdf_selector(&login).expect("selector");
            Obj::new().u64("selector", selector).done()
        }
        "unlock-key/server" => {
            let export_key =
                SecretArray::<64>::from_slice(&bytes(m, "export_key")).expect("64 bytes");
            let account = AccountId::from_bytes(arr(m, "account_id"));
            let key = ServerUnlockKey::derive(&export_key, account).expect("derive");
            key_outputs(key.key_for_tests())
        }
        "unlock-key/local" => {
            let pw_in = Key32::from_slice(&bytes(m, "pw_in")).expect("32 bytes");
            let key = LocalUnlockKey::derive(
                &pw_in,
                &arr(m, "device_salt"),
                kdf(m),
                AccountId::from_bytes(arr(m, "account_id")),
                DeviceId::from_bytes(arr(m, "device_id")),
            )
            .expect("derive");
            key_outputs(key.key_for_tests())
        }
        "recovery/wrap-key" => {
            let code = RecoveryCode::from_slice(&bytes(m, "recovery_code")).expect("16 bytes");
            key_outputs(code.wrap_key().expect("derive").key_for_tests())
        }
        "recovery/auth-token" => {
            let code = RecoveryCode::from_slice(&bytes(m, "recovery_code")).expect("16 bytes");
            let token = code.auth_token().expect("derive");
            let server_hash = token.server_hash();
            assert_eq!(
                server_hash,
                <[u8; 32]>::from(Sha256::digest(token.expose_secret()))
            );
            assert!(crate::keys::RecoveryAuthToken::matches_server_hash(
                token.expose_secret(),
                &server_hash
            ));
            Obj::new()
                .bytes("token", token.expose_secret())
                .bytes("server_hash", &server_hash)
                .done()
        }
        "export/key" => key_outputs(
            &password_file_key(
                text(m, "export_password"),
                &arr(m, "export_salt"),
                kdf(m),
                labels::EXPORT_KEY,
                &arr(m, "export_id"),
            )
            .expect("derive"),
        ),
        "server/secrets-backup" => key_outputs(
            &password_file_key(
                text(m, "passphrase"),
                &arr(m, "backup_salt"),
                kdf(m),
                labels::SERVER_SECRETS_BACKUP,
                &arr(m, "backup_id"),
            )
            .expect("derive"),
        ),
        "server/totp-secret" | "server/login-state" => {
            let label: Label = if name == "server/totp-secret" {
                labels::SERVER_TOTP_SECRET
            } else {
                labels::SERVER_LOGIN_STATE
            };
            let key =
                ServerDataKey::from_slice(&bytes(m, "server_data_key"), num(m, "data_key_id"))
                    .expect("32 bytes");
            key_outputs(&key.subkey_for_tests(label).expect("derive"))
        }
        "hpke-psk/device-grant" => device_grant_psk(m),
        "fingerprint" => fingerprint(m),
        "device-set" => device_set(m),
        "settings" => {
            let envelope = opt_bytes(m, "settings_envelope");
            let hash = settings_hash(u64_of(m, "settings_seq"), envelope.as_deref())
                .expect("consistent settings inputs");
            Obj::new().bytes("settings_hash", &hash).done()
        }
        other => panic!("unknown derivation vector {other}"),
    }
}

fn device_grant_psk(m: &Map<String, Value>) -> Map<String, Value> {
    let epoch: u32 = num(m, "account_key_epoch");
    let previous = AccountKey::generate(
        &mut super::ExactRng::new(&bytes(m, "previous_account_key")),
        epoch - 1,
    );
    let ctx = |sender: u8| AccountKeyDeviceGrantCtx {
        account_id: AccountId::from_bytes(arr(m, "account_id")),
        account_key_epoch: epoch,
        sender_device_id: DeviceId::from_bytes([sender; 16]),
        recipient_device_id: DeviceId::from_bytes(arr(m, "recipient_device_id")),
    };
    let psk = HpkePsk::device_grant(&previous, &ctx(0)).expect("psk");
    // The PSK does not depend on the sender (§4.3).
    let other = HpkePsk::device_grant(&previous, &ctx(0xff)).expect("psk");
    assert_eq!(psk.secret().expose_secret(), other.secret().expose_secret());
    Obj::new()
        .bytes("psk", psk.secret().expose_secret())
        .bytes("psk_id", labels::HPKE_PSK_DEVICE_GRANT.as_bytes())
        .done()
}

fn fingerprint(m: &Map<String, Value>) -> Map<String, Value> {
    let one = |prefix: &str| {
        let keys = IdentityPublicKeys {
            ed25519: IdentityVerifyingKey::from_bytes(&arr(
                m,
                &format!("{prefix}identity_ed25519_public_key"),
            ))
            .expect("an Ed25519 key"),
            x25519: HpkePublicKey::x25519(arr(m, &format!("{prefix}identity_x25519_public_key"))),
        };
        AccountFingerprint::compute(
            AccountId::from_bytes(arr(m, &format!("{prefix}account_id"))),
            &keys,
        )
    };
    let (a, b) = (one(""), one("other_"));
    assert_eq!(a.pair_safety_number(&b), b.pair_safety_number(&a));
    Obj::new()
        .bytes("fingerprint", a.as_bytes())
        .text("safety_number", &a.safety_number())
        .bytes("other_fingerprint", b.as_bytes())
        .text("other_safety_number", &b.safety_number())
        .text("pair_safety_number", &a.pair_safety_number(&b))
        .done()
}

fn device_set(m: &Map<String, Value>) -> Map<String, Value> {
    let account = AccountId::from_bytes(arr(m, "account_id"));
    let identity =
        IdentityVerifyingKey::from_bytes(&arr(m, "identity_public_key")).expect("an Ed25519 key");
    let epoch: u32 = num(m, "identity_epoch");
    let certs: Vec<Verified<DeviceCertificate>> = bytes_list(m, "certificates")
        .iter()
        .map(|w| DeviceCertificate::verify(w, &identity, epoch).expect("a valid certificate"))
        .collect();
    let revocations: Vec<Verified<DeviceRevocation>> = bytes_list(m, "revocations")
        .iter()
        .map(|w| DeviceRevocation::verify(w, &identity).expect("a valid revocation"))
        .collect();
    let hash = device_set_hash(account, &certs, &revocations).expect("a device set");
    // The members, rebuilt from the §10.2 text: SHA-256 of the signed message of every
    // non-revoked certificate with device_kind ≠ 4, sorted bytewise.
    let mut members: Vec<[u8; 32]> = certs
        .iter()
        .filter(|c| c.device_kind != DeviceKind::WebEphemeral)
        .filter(|c| !revocations.iter().any(|r| r.device_id == c.device_id))
        .map(|c| *c.message_hash())
        .collect();
    members.sort_unstable();
    let mut digest = Sha256::new();
    digest.update(labels::DEVICE_SET.as_bytes());
    digest.update([0x00]);
    for h in &members {
        digest.update(h);
    }
    assert_eq!(<[u8; 32]>::from(digest.finalize()), hash);
    Obj::new()
        .bytes_list(
            "members",
            &members.iter().map(|h| h.to_vec()).collect::<Vec<_>>(),
        )
        .bytes("device_set_hash", &hash)
        .done()
}
