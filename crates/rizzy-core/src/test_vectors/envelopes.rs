//! `envelopes.json`: one envelope per M1 purpose of CRYPTO.md §8.4 (two for the padded ones),
//! with its context bytes, AAD, subkey and commitment.
//!
//! Each vector gives the raw wrapping key (or, for the HPKE device grant, the recipient's
//! X25519 secret key and the previous account key the PSK comes from), the context fields, the
//! plaintext and the random bytes the seal draws (`nonce`, or HPKE's `ikm_e`). The replay seals
//! through the generic entry points and, where a typed key can be built from those inputs,
//! through the typed wrap function too, and requires the same bytes from both.
//!
//! The plaintexts of `ITEM_OP`, `ITEM_SNAPSHOT`, `ACCOUNT_SETTINGS`, `EXPORT_FILE` and the
//! server purposes are opaque placeholder bytes: the item-record encoding (ADR 0018, Proposed)
//! and the other plaintext formats are not implemented yet, and the envelope does not look
//! inside them.

use chacha20::ChaCha20Rng;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use serde_json::{Map, Value};

use super::{ExactRng, Obj, Vector, arr, bytes, num, object, random, random_vec, small, u64_of};
use crate::envelope::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyLocalWrapCtx, AccountKeyRecoveryWrapCtx,
    AccountKeyServerWrapCtx, AccountSettingsCtx, DeviceSecretKeysCtx, ExportFileCtx,
    IdentitySecretKeysCtx, ItemKeyWrapCtx, ItemOpCtx, ItemSnapshotCtx, Milestone,
    RetiredSecretKeyCtx, ServerLoginStateCtx, ServerSecretsBackupCtx, ServerTotpSecretCtx,
    VaultKeySelfGrantCtx,
};
use crate::envelope::symmetric::{server_open, server_seal};
use crate::envelope::{
    Context, PlaintextRule, Purpose, ServerContext, SymmetricContext, open, seal,
};
use crate::hpke::{self, HpkePsk, HpkeSecretKey};
use crate::ids::{
    AccountId, BackupId, DeviceId, ExportId, ItemId, KeyType, LoginId, OpId, PublicKeyId,
    SnapshotId, VaultId,
};
use crate::kdf::{self, KdfId};
use crate::keys::{AccountKey, ItemKey, RetiredSecretKey, VaultKey};
use crate::labels;
use crate::padding;
use crate::secret::Key32;
use crate::sign::IdentitySigningKey;

const KIND: &str = "envelope";

fn vector(name: &str, index: usize, inputs: Obj) -> Vector {
    Vector::build(compute, KIND, name, index, inputs)
}

/// An X25519 secret key in the form this crate stores it (the `E_id`, `E_dev` and retired-key
/// plaintexts): a fresh key pair's secret half, written out.
pub(super) fn x25519_secret(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let key = HpkeSecretKey::generate_x25519(rng);
    let mut out = [0u8; 32];
    key.write_secret(&mut out);
    out
}

/// A symmetric vector's inputs: key, context, plaintext and nonce.
fn symmetric(rng: &mut ChaCha20Rng, ctx: Obj, plaintext: &[u8]) -> Obj {
    Obj::new()
        .bytes("key", &random::<32>(rng))
        .obj("ctx", ctx)
        .bytes("plaintext", plaintext)
        .bytes("nonce", &random::<24>(rng))
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat table of test vectors reads best as one function"
)]
pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    let mut out = Vec::new();
    let id = |rng: &mut ChaCha20Rng| random::<16>(rng);

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .num("account_key_epoch", small(rng, 4))
        .num("password_epoch", small(rng, 4))
        .num("kdf_id", 1);
    let pt = random::<32>(rng);
    out.push(vector(
        "ACCOUNT_KEY_SERVER_WRAP",
        0,
        symmetric(rng, ctx, &pt),
    ));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .bytes("device_id", &id(rng))
        .num("account_key_epoch", small(rng, 4))
        .num("password_epoch", small(rng, 4))
        .num("kdf_id", 1);
    let pt = random::<32>(rng);
    out.push(vector(
        "ACCOUNT_KEY_LOCAL_WRAP",
        0,
        symmetric(rng, ctx, &pt),
    ));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .num("account_key_epoch", small(rng, 4))
        .num("recovery_epoch", 1 + small(rng, 4));
    let pt = random::<32>(rng);
    out.push(vector(
        "ACCOUNT_KEY_RECOVERY_WRAP",
        0,
        symmetric(rng, ctx, &pt),
    ));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .num("account_key_epoch", 1 + small(rng, 4))
        .bytes("sender_device_id", &id(rng))
        .bytes("recipient_device_id", &id(rng));
    out.push(vector(
        "ACCOUNT_KEY_DEVICE_GRANT",
        0,
        Obj::new()
            .bytes("recipient_x25519_secret_key", &x25519_secret(rng))
            .bytes("previous_account_key", &random::<32>(rng))
            .obj("ctx", ctx)
            .bytes("plaintext", &random::<32>(rng))
            .bytes("ikm_e", &random::<32>(rng)),
    ));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .num("identity_epoch", small(rng, 4));
    let mut pt = random::<32>(rng).to_vec();
    pt.extend_from_slice(&x25519_secret(rng));
    out.push(vector("IDENTITY_SECRET_KEYS", 0, symmetric(rng, ctx, &pt)));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .bytes("device_id", &id(rng));
    let mut pt = vec![1u8];
    pt.extend_from_slice(&random::<32>(rng));
    pt.extend_from_slice(&x25519_secret(rng));
    out.push(vector("DEVICE_SECRET_KEYS", 0, symmetric(rng, ctx, &pt)));

    let retired = x25519_secret(rng);
    let retired_public = *HpkeSecretKey::from_x25519_bytes(&retired)
        .expect("32 bytes")
        .public_key()
        .as_bytes();
    let ctx = Obj::new().bytes("account_id", &id(rng)).bytes(
        "retired_key_id",
        PublicKeyId::derive(KeyType::IdentityX25519, &retired_public).as_bytes(),
    );
    let mut pt = vec![KeyType::IdentityX25519.to_u8()];
    pt.extend_from_slice(&retired);
    out.push(vector("RETIRED_SECRET_KEY", 0, symmetric(rng, ctx, &pt)));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .u64("settings_seq", 1 + u64::from(small(rng, 100)));
    let pt = random_vec(rng, 120);
    out.push(vector("ACCOUNT_SETTINGS", 0, symmetric(rng, ctx, &pt)));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .bytes("vault_id", &id(rng))
        .num("account_key_epoch", small(rng, 4))
        .num("vault_key_epoch", small(rng, 4));
    let pt = random::<32>(rng);
    out.push(vector("VAULT_KEY_SELF_GRANT", 0, symmetric(rng, ctx, &pt)));

    let epoch = 1 + small(rng, 4);
    let ctx = Obj::new()
        .bytes("vault_id", &id(rng))
        .bytes("item_id", &id(rng))
        .num("vault_key_epoch", epoch);
    let mut pt = vec![1u8];
    pt.extend_from_slice(&(epoch - 1).to_be_bytes());
    pt.extend_from_slice(&random::<32>(rng));
    out.push(vector("ITEM_KEY_WRAP", 0, symmetric(rng, ctx, &pt)));

    // Padded purposes: one plaintext inside the 256-byte minimum frame, one past it.
    for (i, len) in [40usize, 700].into_iter().enumerate() {
        let ctx = Obj::new()
            .bytes("vault_id", &id(rng))
            .bytes("item_id", &id(rng))
            .num("item_schema_version", 1)
            .bytes("op_id", &id(rng))
            .bytes("device_id", &id(rng))
            .u64("device_seq", 1 + u64::from(small(rng, 1000)))
            .u64(
                "hlc",
                (1_780_000_000_000u64 << 16) | u64::from(small(rng, 100)),
            )
            .bytes("op_header_hash", &random::<32>(rng));
        let pt = random_vec(rng, len);
        out.push(vector("ITEM_OP", i, symmetric(rng, ctx, &pt)));
    }
    for (i, len) in [0usize, 1500].into_iter().enumerate() {
        let ctx = Obj::new()
            .bytes("vault_id", &id(rng))
            .bytes("item_id", &id(rng))
            .num("item_schema_version", 1)
            .bytes("snapshot_id", &id(rng))
            .bytes("snapshot_header_hash", &random::<32>(rng));
        let pt = random_vec(rng, len);
        out.push(vector("ITEM_SNAPSHOT", i, symmetric(rng, ctx, &pt)));
    }

    let ctx = Obj::new()
        .bytes("export_id", &id(rng))
        .u64(
            "created_at_ms",
            1_780_000_000_000 + u64::from(small(rng, 1_000_000)),
        )
        .num("kdf_id", 1)
        .bytes("export_salt", &random::<16>(rng));
    out.push(vector(
        "EXPORT_FILE",
        0,
        symmetric(rng, ctx, br#"{"format":"placeholder","items":[]}"#),
    ));

    let ctx = Obj::new()
        .bytes("account_id", &id(rng))
        .num("totp_credential_seq", 1 + small(rng, 4));
    let pt = random::<20>(rng);
    out.push(vector("SERVER_TOTP_SECRET", 0, symmetric(rng, ctx, &pt)));

    let ctx = Obj::new()
        .bytes("login_id", &id(rng))
        .bytes("credential_identifier", &id(rng))
        .u64("expires_at_ms", 1_780_000_060_000);
    let pt = random_vec(rng, 128);
    out.push(vector("SERVER_LOGIN_STATE", 0, symmetric(rng, ctx, &pt)));

    let ctx = Obj::new()
        .bytes("backup_id", &id(rng))
        .u64("created_at_ms", 1_780_000_000_000)
        .num("kdf_id", 1)
        .bytes("backup_salt", &random::<16>(rng));
    let pt = random_vec(rng, 300);
    out.push(vector("SERVER_SECRETS_BACKUP", 0, symmetric(rng, ctx, &pt)));
    out
}

/// Every M1 purpose with a context type has a vector, and every vector is for a registered
/// purpose.
pub(super) fn check_file(vectors: &[super::Vector]) {
    let names: Vec<&str> = vectors.iter().map(|v| v.name.as_str()).collect();
    for p in Purpose::ALL {
        // VAULT_KEY_MEMBER_GRANT is M9; its context exists only in tests.
        if p.spec().first_used == Milestone::M1 {
            assert!(
                names.contains(&p.name()),
                "no envelope vector for {}",
                p.name()
            );
        }
    }
    for name in names {
        assert!(Purpose::ALL.iter().any(|p| p.name() == name), "{name}");
    }
}

// ---------------------------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------------------------

fn account(c: &Map<String, Value>) -> AccountId {
    AccountId::from_bytes(arr(c, "account_id"))
}

fn device(c: &Map<String, Value>, key: &str) -> DeviceId {
    DeviceId::from_bytes(arr(c, key))
}

fn vault(c: &Map<String, Value>) -> VaultId {
    VaultId::from_bytes(arr(c, "vault_id"))
}

fn kdf_id(c: &Map<String, Value>) -> KdfId {
    KdfId::from_u16(num(c, "kdf_id")).expect("an allowed kdf_id")
}

fn key(m: &Map<String, Value>) -> Key32 {
    Key32::from_slice(&bytes(m, "key")).expect("32 bytes")
}

/// A typed key built from the vector's raw key: `generate` draws exactly its 32 bytes.
fn typed<T>(m: &Map<String, Value>, make: impl FnOnce(&mut ExactRng) -> T) -> T {
    let mut rng = ExactRng::new(&bytes(m, "key"));
    let out = make(&mut rng);
    rng.finish();
    out
}

/// Seals with the vector's nonce through `f`, requiring that `f` draws exactly the nonce.
fn with_nonce(m: &Map<String, Value>, f: impl FnOnce(&mut ExactRng) -> Vec<u8>) -> Vec<u8> {
    let mut rng = ExactRng::new(&bytes(m, "nonce"));
    let out = f(&mut rng);
    rng.finish();
    out
}

#[expect(
    clippy::too_many_lines,
    reason = "one flat table of test vectors reads best as one function"
)]
pub(super) fn compute(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    let c = object(m, "ctx");
    let pt = bytes(m, "plaintext");
    match name {
        "ACCOUNT_KEY_SERVER_WRAP" => symmetric_outputs(
            m,
            &AccountKeyServerWrapCtx {
                account_id: account(c),
                account_key_epoch: num(c, "account_key_epoch"),
                password_epoch: num(c, "password_epoch"),
                kdf_id: kdf_id(c),
            },
        ),
        "ACCOUNT_KEY_LOCAL_WRAP" => symmetric_outputs(
            m,
            &AccountKeyLocalWrapCtx {
                account_id: account(c),
                device_id: device(c, "device_id"),
                account_key_epoch: num(c, "account_key_epoch"),
                password_epoch: num(c, "password_epoch"),
                kdf_id: kdf_id(c),
            },
        ),
        "ACCOUNT_KEY_RECOVERY_WRAP" => symmetric_outputs(
            m,
            &AccountKeyRecoveryWrapCtx {
                account_id: account(c),
                account_key_epoch: num(c, "account_key_epoch"),
                recovery_epoch: num(c, "recovery_epoch"),
            },
        ),
        "ACCOUNT_KEY_DEVICE_GRANT" => device_grant(m),
        "IDENTITY_SECRET_KEYS" => {
            let ctx = IdentitySecretKeysCtx {
                account_id: account(c),
                identity_epoch: num(c, "identity_epoch"),
            };
            let mut out = symmetric_outputs(m, &ctx);
            // Typed: unwrap, then wrap again with the same nonce.
            let ak = typed(m, |r| AccountKey::generate(r, 0));
            let env = bytes(&out, "envelope");
            let keys = ak.unwrap_identity_keys(&ctx, &env).expect("E_id opens");
            let again = with_nonce(m, |r| ak.wrap_identity_keys(r, &ctx, &keys).expect("wrap"));
            assert_eq!(again, env, "wrap_identity_keys");
            // The public halves of the wrapped keys (§11.2 step 6 compares them with the
            // bundle).
            let seed: [u8; 32] = pt.get(..32).and_then(|s| s.try_into().ok()).expect("seed");
            let ed = IdentitySigningKey::from_seed(&seed);
            assert_eq!(keys.public_keys().ed25519, *ed.verifying_key());
            out.extend(
                Obj::new()
                    .bytes("identity_ed25519_public_key", ed.verifying_key().as_bytes())
                    .bytes(
                        "identity_x25519_public_key",
                        keys.public_keys().x25519.as_bytes(),
                    )
                    .done(),
            );
            out
        }
        "DEVICE_SECRET_KEYS" => {
            let ctx = DeviceSecretKeysCtx {
                account_id: account(c),
                device_id: device(c, "device_id"),
            };
            let mut out = symmetric_outputs(m, &ctx);
            let ak = typed(m, |r| AccountKey::generate(r, 0));
            let env = bytes(&out, "envelope");
            let keys = ak.unwrap_device_keys(&ctx, &env).expect("E_dev opens");
            let again = with_nonce(m, |r| ak.wrap_device_keys(r, &ctx, &keys).expect("wrap"));
            assert_eq!(again, env, "wrap_device_keys");
            out.extend(
                Obj::new()
                    .bytes(
                        "device_ed25519_public_key",
                        keys.public_keys().ed25519.as_bytes(),
                    )
                    .bytes(
                        "device_x25519_public_key",
                        keys.public_keys().x25519.as_bytes(),
                    )
                    .done(),
            );
            out
        }
        "RETIRED_SECRET_KEY" => {
            let ctx = RetiredSecretKeyCtx {
                account_id: account(c),
                retired_key_id: PublicKeyId::from_bytes(arr(c, "retired_key_id")),
            };
            let out = symmetric_outputs(m, &ctx);
            let ak = typed(m, |r| AccountKey::generate(r, 0));
            let env = bytes(&out, "envelope");
            let retired: RetiredSecretKey = ak
                .unwrap_retired_key(&ctx, &env)
                .expect("retired key opens");
            let again = with_nonce(m, |r| ak.wrap_retired_key(r, &ctx, &retired).expect("wrap"));
            assert_eq!(again, env, "wrap_retired_key");
            out
        }
        "ACCOUNT_SETTINGS" => symmetric_outputs(
            m,
            &AccountSettingsCtx {
                account_id: account(c),
                settings_seq: u64_of(c, "settings_seq"),
            },
        ),
        "VAULT_KEY_SELF_GRANT" => {
            let ctx = VaultKeySelfGrantCtx {
                account_id: account(c),
                vault_id: vault(c),
                account_key_epoch: num(c, "account_key_epoch"),
                vault_key_epoch: num(c, "vault_key_epoch"),
            };
            let out = symmetric_outputs(m, &ctx);
            let ak = typed(m, |r| AccountKey::generate(r, ctx.account_key_epoch));
            let env = bytes(&out, "envelope");
            let vk = ak.unwrap_vault_key(&ctx, &env).expect("self-grant opens");
            let again = with_nonce(m, |r| ak.wrap_vault_key(r, &ctx, &vk).expect("wrap"));
            assert_eq!(again, env, "wrap_vault_key");
            out
        }
        "ITEM_KEY_WRAP" => {
            let ctx = ItemKeyWrapCtx {
                vault_id: vault(c),
                item_id: ItemId::from_bytes(arr(c, "item_id")),
                vault_key_epoch: num(c, "vault_key_epoch"),
            };
            let out = symmetric_outputs(m, &ctx);
            let vk = typed(m, |r| {
                VaultKey::generate(r, ctx.vault_id, ctx.vault_key_epoch)
            });
            let env = bytes(&out, "envelope");
            let ik: ItemKey = vk.unwrap_item_key(&ctx, &env).expect("item key wrap opens");
            let again = with_nonce(m, |r| vk.wrap_item_key(r, &ctx, &ik).expect("wrap"));
            assert_eq!(again, env, "wrap_item_key");
            out
        }
        "ITEM_OP" => symmetric_outputs(
            m,
            &ItemOpCtx {
                vault_id: vault(c),
                item_id: ItemId::from_bytes(arr(c, "item_id")),
                item_schema_version: num(c, "item_schema_version"),
                op_id: OpId::from_bytes(arr(c, "op_id")),
                device_id: device(c, "device_id"),
                device_seq: u64_of(c, "device_seq"),
                hlc: u64_of(c, "hlc"),
                op_header_hash: arr(c, "op_header_hash"),
            },
        ),
        "ITEM_SNAPSHOT" => symmetric_outputs(
            m,
            &ItemSnapshotCtx {
                vault_id: vault(c),
                item_id: ItemId::from_bytes(arr(c, "item_id")),
                item_schema_version: num(c, "item_schema_version"),
                snapshot_id: SnapshotId::from_bytes(arr(c, "snapshot_id")),
                snapshot_header_hash: arr(c, "snapshot_header_hash"),
            },
        ),
        "EXPORT_FILE" => symmetric_outputs(
            m,
            &ExportFileCtx {
                export_id: ExportId::from_bytes(arr(c, "export_id")),
                created_at_ms: u64_of(c, "created_at_ms"),
                kdf_id: kdf_id(c),
                export_salt: arr(c, "export_salt"),
            },
        ),
        "SERVER_TOTP_SECRET" => server_outputs(
            m,
            &ServerTotpSecretCtx {
                account_id: account(c),
                totp_credential_seq: num(c, "totp_credential_seq"),
            },
        ),
        "SERVER_LOGIN_STATE" => server_outputs(
            m,
            &ServerLoginStateCtx {
                login_id: LoginId::from_bytes(arr(c, "login_id")),
                credential_identifier: arr(c, "credential_identifier"),
                expires_at_ms: u64_of(c, "expires_at_ms"),
            },
        ),
        "SERVER_SECRETS_BACKUP" => server_outputs(
            m,
            &ServerSecretsBackupCtx {
                backup_id: BackupId::from_bytes(arr(c, "backup_id")),
                created_at_ms: u64_of(c, "created_at_ms"),
                kdf_id: kdf_id(c),
                backup_salt: arr(c, "backup_salt"),
            },
        ),
        other => panic!("unknown envelope vector {other}"),
    }
}

/// Seals and opens a client purpose, then checks the envelope against the §8.3 formula.
fn symmetric_outputs<C: SymmetricContext>(m: &Map<String, Value>, ctx: &C) -> Map<String, Value> {
    let key = key(m);
    let pt = bytes(m, "plaintext");
    let envelope = with_nonce(m, |r| seal(r, &key, ctx, &pt).expect("seal"));
    let opened = open(&key, ctx, &envelope).expect("open");
    assert_eq!(opened.expose_secret(), pt.as_slice());
    formula_outputs(m, &key, ctx, &envelope)
}

/// The same for a server-only purpose, through the server's table.
fn server_outputs<C: ServerContext>(m: &Map<String, Value>, ctx: &C) -> Map<String, Value> {
    let key = key(m);
    let pt = bytes(m, "plaintext");
    let envelope = with_nonce(m, |r| server_seal(r, &key, ctx, &pt).expect("seal"));
    let opened = server_open(&key, ctx, &envelope).expect("open");
    assert_eq!(opened.expose_secret(), pt.as_slice());
    // A client never opens it (§9.5 rule 2).
    assert!(C::PURPOSE.client_decrypt_allow_list().is_empty());
    formula_outputs(m, &key, ctx, &envelope)
}

/// Rebuilds the §8.3 construction from its formula and checks the envelope against it:
/// `aad = header ‖ u16(purpose) ‖ ctx`, `okm = HKDF(K, salt = nonce, LABEL ‖ 0x00 ‖ aad, 64)`,
/// the commitment is `okm[32..64]`, and the body decrypts under raw XChaCha20-Poly1305 with
/// `k_enc = okm[0..32]` to the (framed, for padded purposes) plaintext.
fn formula_outputs<C: Context>(
    m: &Map<String, Value>,
    key: &Key32,
    ctx: &C,
    envelope: &[u8],
) -> Map<String, Value> {
    let nonce = arr::<24>(m, "nonce");
    let pt = bytes(m, "plaintext");
    let header = envelope.get(..18).expect("a header");
    assert_eq!(
        header.get(..2),
        Some(&[0x01, 0x01][..]),
        "version and alg_id"
    );
    assert_eq!(
        header.get(2..),
        Some(&key.key_id().expect("key id").as_bytes()[..])
    );
    let ctx_bytes = ctx.ctx_bytes();
    let mut aad = header.to_vec();
    aad.extend_from_slice(&C::PURPOSE.id().to_be_bytes());
    aad.extend_from_slice(&ctx_bytes);
    let mut okm = [0u8; 64];
    kdf::hkdf_sha256(
        key.expose_secret(),
        Some(&nonce),
        labels::ENVELOPE_XCHACHA20POLY1305,
        &aad,
        &mut okm,
    )
    .expect("HKDF");
    let (k_enc, commitment) = okm.split_at(32);
    assert_eq!(envelope.get(18..42), Some(&nonce[..]), "nonce");
    assert_eq!(envelope.get(42..74), Some(commitment), "commitment");
    let body = XChaCha20Poly1305::new_from_slice(k_enc)
        .expect("a key")
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: envelope.get(74..).expect("a body"),
                aad: &aad,
            },
        )
        .expect("the raw AEAD opens the body under k_enc");
    let expected_body = match C::PURPOSE.plaintext_rule() {
        PlaintextRule::Padded => padding::frame(&pt).expect("frame").expose_secret().to_vec(),
        _ => pt,
    };
    assert_eq!(body, expected_body);
    Obj::new()
        .bytes("ctx", &ctx_bytes)
        .bytes("aad", &aad)
        .bytes("k_enc", k_enc)
        .bytes("commitment", commitment)
        .bytes("envelope", envelope)
        .done()
}

/// The HPKE PSK-mode device grant (§9.2, §10.1).
fn device_grant(m: &Map<String, Value>) -> Map<String, Value> {
    let c = object(m, "ctx");
    let ctx = AccountKeyDeviceGrantCtx {
        account_id: account(c),
        account_key_epoch: num(c, "account_key_epoch"),
        sender_device_id: device(c, "sender_device_id"),
        recipient_device_id: device(c, "recipient_device_id"),
    };
    let recipient =
        HpkeSecretKey::from_x25519_bytes(&arr(m, "recipient_x25519_secret_key")).expect("a key");
    let mut prev_rng = ExactRng::new(&bytes(m, "previous_account_key"));
    let previous = AccountKey::generate(&mut prev_rng, ctx.account_key_epoch - 1);
    prev_rng.finish();
    let psk = HpkePsk::device_grant(&previous, &ctx).expect("psk");
    let pt = bytes(m, "plaintext");
    let mut rng = ExactRng::new(&bytes(m, "ikm_e"));
    let envelope = hpke::seal_psk(&mut rng, recipient.public_key(), &psk, &ctx, &pt).expect("seal");
    rng.finish();
    let opened = hpke::open_psk(&recipient, &psk, &ctx, &envelope).expect("open");
    assert_eq!(opened.expose_secret(), pt.as_slice());

    // The §9.2 layout and inputs, rebuilt from the text.
    let recipient_id = recipient.public_key().key_id(KeyType::DeviceX25519);
    let header = envelope.get(..18).expect("a header");
    assert_eq!(header.get(..2), Some(&[0x01, 0x12][..]));
    assert_eq!(header.get(2..), Some(&recipient_id.as_bytes()[..]));
    let purpose = Purpose::AccountKeyDeviceGrant.id().to_be_bytes();
    let info = labels::HPKE.info(&purpose);
    let ctx_bytes = ctx.ctx_bytes();
    let mut aad = header.to_vec();
    aad.extend_from_slice(&purpose);
    aad.extend_from_slice(&ctx_bytes);
    // Opening with the raw RFC 9180 call and these rebuilt inputs gives the plaintext back.
    let enc: [u8; 32] = envelope
        .get(18..50)
        .and_then(|e| e.try_into().ok())
        .expect("enc");
    let (ct, tag) = envelope.get(50..).expect("a body").split_at(pt.len());
    let mut body = ct.to_vec();
    hpke::raw_open_in_place(
        &recipient,
        Some((
            psk.secret().expose_secret().as_slice(),
            labels::HPKE_PSK_DEVICE_GRANT.as_bytes(),
        )),
        &enc,
        &info,
        &aad,
        &mut body,
        tag.try_into().expect("a tag"),
    )
    .expect("raw HPKE open");
    assert_eq!(body, pt);
    Obj::new()
        .bytes(
            "recipient_x25519_public_key",
            recipient.public_key().as_bytes(),
        )
        .bytes("recipient_key_id", recipient_id.as_bytes())
        .bytes("psk", psk.secret().expose_secret())
        .bytes("psk_id", labels::HPKE_PSK_DEVICE_GRANT.as_bytes())
        .bytes("info", &info)
        .bytes("ctx", &ctx_bytes)
        .bytes("aad", &aad)
        .bytes("envelope", &envelope)
        .done()
}
