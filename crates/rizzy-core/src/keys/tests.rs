//! Key-hierarchy tests: independent known answers for the §4.3 derivations and the signed
//! device grant, round trips of every M1 wrapped-key object, context binding (a wrap moved to
//! another item, vault, device, account or epoch does not open), the seal-time consistency
//! checks, and the device-grant acceptance rules.
//!
//! Known answers marked "independent" were computed with a separate Python implementation
//! written from CRYPTO.md (Python `cryptography` 50.0.1, `hmac`/`hashlib`, `argon2-cffi` 25.1.0
//! for Argon2id), not from this code.

use super::*;
use crate::envelope::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyLocalWrapCtx, AccountKeyRecoveryWrapCtx,
    AccountKeyServerWrapCtx, AccountSettingsCtx, DeviceSecretKeysCtx, IdentitySecretKeysCtx,
    ItemKeyWrapCtx, RetiredSecretKeyCtx, VaultKeySelfGrantCtx,
};
use crate::envelope::{open, seal};
use crate::error::{DecryptError, EncryptError, ParseError};
use crate::ids::{AccountId, DeviceId, ItemId};
use crate::kdf::KdfId;
use crate::secret::SecretArray;
use crate::sign::{
    AccountState, DeviceCertificate, DeviceKind, DeviceRevocation, SyncMode, Verified,
};
use crate::test_util::{FixedRng, hex, seeded_rng};

// ---------------------------------------------------------------------------------------------
// Fixtures (the same values as the independent computation)
// ---------------------------------------------------------------------------------------------

const CREATED: u64 = 1_700_000_000_000;

fn account() -> AccountId {
    AccountId::from_bytes([0x0a; 16])
}

fn sender_device() -> DeviceId {
    DeviceId::from_bytes([0x0d; 16])
}

fn recipient_device() -> DeviceId {
    DeviceId::from_bytes([0x0e; 16])
}

fn vault() -> VaultId {
    VaultId::from_bytes([0x0f; 16])
}

fn item() -> ItemId {
    ItemId::from_bytes([0x01; 16])
}

fn key32(byte: u8) -> Key32 {
    Key32::from_slice(&[byte; 32]).unwrap()
}

fn account_key(byte: u8, epoch: u32) -> AccountKey {
    AccountKey::from_key(key32(byte), epoch)
}

fn identity_keys() -> IdentityKeys {
    IdentityKeys {
        signing: IdentitySigningKey::from_seed(&[0x66; 32]),
        kem: HpkeSecretKey::from_x25519_bytes(&[0x77; 32]).unwrap(),
        epoch: 0,
    }
}

fn recipient_keys() -> DeviceKeys {
    DeviceKeys {
        signing: DeviceSigningKey::from_seed(&[0x88; 32]),
        kem: HpkeSecretKey::from_x25519_bytes(&[0x33; 32]).unwrap(),
    }
}

fn sender_keys() -> DeviceKeys {
    DeviceKeys {
        signing: DeviceSigningKey::from_seed(&[0x55; 32]),
        kem: HpkeSecretKey::from_x25519_bytes(&[0x34; 32]).unwrap(),
    }
}

fn certificate(device_id: DeviceId, keys: &DeviceKeys, kind: DeviceKind) -> DeviceCertificate {
    let public = keys.public_keys();
    DeviceCertificate {
        account_id: account(),
        device_id,
        identity_epoch: 0,
        device_ed25519: public.ed25519,
        device_x25519: public.x25519,
        device_kind: kind,
        created_at_ms: CREATED,
        expires_at_ms: if kind == DeviceKind::WebEphemeral {
            CREATED + 1
        } else {
            0
        },
    }
}

fn verified(cert: &DeviceCertificate) -> Verified<DeviceCertificate> {
    let identity = identity_keys();
    let wire = cert.sign(identity.signing_key()).unwrap();
    DeviceCertificate::verify(&wire, identity.signing_key().verifying_key(), 0).unwrap()
}

fn recipient_cert() -> Verified<DeviceCertificate> {
    verified(&certificate(
        recipient_device(),
        &recipient_keys(),
        DeviceKind::DesktopCli,
    ))
}

fn sender_cert() -> Verified<DeviceCertificate> {
    verified(&certificate(
        sender_device(),
        &sender_keys(),
        DeviceKind::Mobile,
    ))
}

fn grant_ctx() -> AccountKeyDeviceGrantCtx {
    AccountKeyDeviceGrantCtx {
        account_id: account(),
        account_key_epoch: 1,
        sender_device_id: sender_device(),
        recipient_device_id: recipient_device(),
    }
}

// Independent known answers.
const SERVER_UNLOCK_KEY: &str = "228dd209483cd7f2d7008458f97bb1b4a764dbe5e865d036bc46140c4201d9e6";
const LOCAL_UNLOCK_KEY: &str = "723f2587e7770c07327b1fc575846cef690bb98e82879503005aca7a3cc7c830";
const RECOVERY_WRAP_KEY: &str = "2eac38c1abf235dc459da8b33c858ded14366fa7591397cbc8f4b13a28c86d06";
const RECOVERY_AUTH_TOKEN: &str =
    "f4de81668edfb3d95555201cc963ea7bcbe4f2e1641500e40d7678f674cef632";
const RECOVERY_AUTH_TOKEN_HASH: &str =
    "81a1a020c9fe0af792fdecfd6943baed305a9730159b1dc1e310c3c5e267a7dd";
const FINGERPRINT: &str = "e507650911920b9feb944c1598bd98ad6ab883791bfb4a994533dbf6143cd9bd";
const SAFETY_NUMBER: &str = "727535512446040193858710969436";
const DEVICE_SET_HASH_EMPTY: &str =
    "ceed12dd75032f322df46a36b7c015eae9ec50dfb556ce77756ba3f65d4e03c7";
const DEVICE_SET_HASH_ONE: &str =
    "8a76dc093c66172b62b36d0303d15d95472a80de28805b40170c4d2b09e02b6e";
/// Independent: the signed `ACCOUNT_KEY_DEVICE_GRANT` (key-grant wire, HPKE envelope inside).
const KEY_GRANT_WIRE: &str = "0000008a000100048b4f02d8c0c813226bd2f5ab5c54e8cdcfc73380bda7467f0b0fa7b309c67b76000000620112cfc73380bda7467f0b0fa7b309c67b7686e76b8dd088dabf46d94d4820a251861376de69c3a36f2e53f8bffcdb519e008af61a94cfae79e703dad5b2b8bd10f7ec486c68920bdee3ef0a4f2c6fffdecb5ae7f9f8b8318632e6fa830e56af4a7201018b4f02d8c0c813226bd2f5ab5c54e8cdf09cf8d2c2eade4f6bfed14a55468fb995267fdd05bb16884187b6e9f40213eff4e71275b6f58851979039130339250ddd6bcd359a4c0371b7e2cc3aaf530b01";

// ---------------------------------------------------------------------------------------------
// §4.3 derivations
// ---------------------------------------------------------------------------------------------

#[test]
fn server_unlock_key_and_recovery_known_answers() {
    let export_key = SecretArray::<EXPORT_KEY_LEN>::from_slice(&[0x42; 64]).unwrap();
    let server = ServerUnlockKey::derive(&export_key, account()).unwrap();
    assert_eq!(
        server.key.expose_secret().as_slice(),
        hex(SERVER_UNLOCK_KEY).as_slice()
    );
    // Bound to the account.
    let other = ServerUnlockKey::derive(&export_key, AccountId::from_bytes([0x0b; 16])).unwrap();
    assert_ne!(other.key.expose_secret(), server.key.expose_secret());

    let code = SecretArray::<RECOVERY_CODE_LEN>::from_slice(&[0xc3; 16]).unwrap();
    let wrap = RecoveryWrapKey::derive(&code).unwrap();
    assert_eq!(
        wrap.key.expose_secret().as_slice(),
        hex(RECOVERY_WRAP_KEY).as_slice()
    );
    let token = RecoveryAuthToken::derive(&code).unwrap();
    assert_eq!(
        token.expose_secret().as_slice(),
        hex(RECOVERY_AUTH_TOKEN).as_slice()
    );
    let stored: [u8; 32] = hex(RECOVERY_AUTH_TOKEN_HASH).try_into().unwrap();
    assert_eq!(token.server_hash(), stored);
    assert!(RecoveryAuthToken::matches_server_hash(
        token.expose_secret(),
        &stored
    ));
    assert!(!RecoveryAuthToken::matches_server_hash(&[0; 32], &stored));
    // Wrap key and token are different values from one code.
    assert_ne!(wrap.key.expose_secret(), token.expose_secret());
    let text = format!("{server:?} {wrap:?} {token:?}");
    assert_eq!(text.matches("[REDACTED]").count(), 3);
}

/// Runs Argon2id at `kdf_id` 1 twice (64 MiB each).
#[test]
fn local_unlock_key_known_answer_and_wrong_password() {
    let local = LocalUnlockKey::derive(
        &key32(0x99),
        &[0x5a; 16],
        KdfId::DEFAULT,
        account(),
        recipient_device(),
    )
    .unwrap();
    assert_eq!(
        local.key.expose_secret().as_slice(),
        hex(LOCAL_UNLOCK_KEY).as_slice()
    );

    let ctx = AccountKeyLocalWrapCtx {
        account_id: account(),
        device_id: recipient_device(),
        account_key_epoch: 0,
        password_epoch: 0,
        kdf_id: KdfId::DEFAULT,
    };
    let ak = account_key(0x11, 0);
    let e_local = local
        .wrap_account_key(&mut seeded_rng(1), &ctx, &ak)
        .unwrap();
    let opened = local.unwrap_account_key(&ctx, &e_local).unwrap();
    assert_eq!(opened.key().expose_secret(), ak.key().expose_secret());
    // A wrong password (another pw_in) gives another key: "wrong password".
    let wrong = LocalUnlockKey::derive(
        &key32(0x98),
        &[0x5a; 16],
        KdfId::DEFAULT,
        account(),
        recipient_device(),
    )
    .unwrap();
    assert_eq!(
        wrong.unwrap_account_key(&ctx, &e_local).map(|_| ()),
        Err(DecryptError)
    );
}

#[test]
fn account_fingerprint_and_safety_numbers() {
    let fp = AccountFingerprint::compute(account(), &identity_keys().public_keys());
    assert_eq!(fp.as_bytes().as_slice(), hex(FINGERPRINT).as_slice());
    assert!(fp == <[u8; 32]>::try_from(hex(FINGERPRINT)).unwrap());
    assert_eq!(fp.safety_number(), SAFETY_NUMBER);
    assert_eq!(fp.account_id(), account());
    // The pair number is in account_id order, whichever side computes it.
    let other = AccountFingerprint::compute(
        AccountId::from_bytes([0x01; 16]),
        &IdentityKeys::generate(&mut seeded_rng(2), 0).public_keys(),
    );
    let pair = fp.pair_safety_number(&other);
    assert_eq!(pair, other.pair_safety_number(&fp));
    assert_eq!(pair.len(), 60);
    assert!(pair.ends_with(SAFETY_NUMBER));
    // Either identity key changes the fingerprint.
    let mut changed = identity_keys().public_keys();
    changed.x25519 = crate::hpke::HpkePublicKey::x25519([9; 32]);
    assert_ne!(
        AccountFingerprint::compute(account(), &changed).as_bytes(),
        fp.as_bytes()
    );
}

#[test]
fn device_set_hash_rules() {
    let none: [&Verified<DeviceCertificate>; 0] = [];
    let no_revocations: [&Verified<DeviceRevocation>; 0] = [];
    assert_eq!(
        device_set_hash(account(), none, no_revocations)
            .unwrap()
            .as_slice(),
        hex(DEVICE_SET_HASH_EMPTY).as_slice()
    );
    let recipient = recipient_cert();
    assert_eq!(
        device_set_hash(account(), [&recipient], no_revocations)
            .unwrap()
            .as_slice(),
        hex(DEVICE_SET_HASH_ONE).as_slice()
    );
    // Kind 4 is never in the set.
    let web = verified(&certificate(
        DeviceId::from_bytes([0x44; 16]),
        &DeviceKeys::generate(&mut seeded_rng(3)),
        DeviceKind::WebEphemeral,
    ));
    let with_web = device_set_hash(account(), [&recipient, &web], no_revocations).unwrap();
    assert_eq!(with_web.as_slice(), hex(DEVICE_SET_HASH_ONE).as_slice());
    // Order does not matter.
    let sender = sender_cert();
    let ab = device_set_hash(account(), [&recipient, &sender], no_revocations).unwrap();
    let ba = device_set_hash(account(), [&sender, &recipient], no_revocations).unwrap();
    assert_eq!(ab, ba);
    assert_ne!(ab.as_slice(), hex(DEVICE_SET_HASH_ONE).as_slice());
    // A revoked device leaves the set.
    let identity = identity_keys();
    let revocation = DeviceRevocation {
        account_id: account(),
        device_id: sender_device(),
        last_accepted_device_seq: 3,
        revoked_at_ms: CREATED,
    };
    let revocation = DeviceRevocation::verify(
        &revocation.sign(identity.signing_key()).unwrap(),
        identity.signing_key().verifying_key(),
    )
    .unwrap();
    let after = device_set_hash(account(), [&recipient, &sender], [&revocation]).unwrap();
    assert_eq!(after.as_slice(), hex(DEVICE_SET_HASH_ONE).as_slice());
    // Two certificates for one device, or another account's, are refused.
    assert_eq!(
        device_set_hash(account(), [&recipient, &recipient], no_revocations),
        Err(DeviceSetError::DuplicateDevice)
    );
    assert_eq!(
        device_set_hash(AccountId::from_bytes([1; 16]), [&recipient], no_revocations),
        Err(DeviceSetError::AccountMismatch)
    );
}

#[test]
fn settings_hash_rules_and_state_checks() {
    assert_eq!(settings_hash(0, None), Some([0; 32]));
    assert_eq!(settings_hash(0, Some(b"envelope")), None);
    assert_eq!(settings_hash(1, None), None);
    // Built through the real envelope.
    let ak = account_key(0x11, 0);
    let ctx = AccountSettingsCtx {
        account_id: account(),
        settings_seq: 1,
    };
    let envelope = seal(&mut seeded_rng(4), ak.key(), &ctx, b"settings").unwrap();
    let hash = settings_hash(1, Some(&envelope)).unwrap();
    assert_eq!(
        hash,
        <[u8; 32]>::from(<sha2::Sha256 as sha2::Digest>::digest(&envelope))
    );
    let state = AccountState {
        account_id: account(),
        state_seq: 2,
        identity_epoch: 0,
        account_key_epoch: 0,
        account_key_id: ak.key_id().unwrap(),
        password_epoch: 0,
        kdf_id: KdfId::DEFAULT,
        recovery_epoch: 1,
        recovery_enabled: true,
        sync_mode: SyncMode::Server,
        mail_key_epoch: 0,
        bundle_hash: [1; 32],
        device_set_hash: [2; 32],
        settings_seq: 1,
        settings_hash: hash,
    };
    assert!(state.matches_settings(Some(&envelope)));
    // An older, validly encrypted settings object is rejected against the committed hash.
    let older = seal(&mut seeded_rng(5), ak.key(), &ctx, b"settings").unwrap();
    assert!(!state.matches_settings(Some(&older)));
    assert!(!state.matches_settings(None));
    // The committed account key: its id and its epoch.
    assert!(state.matches_account_key(&ak));
    assert!(!state.matches_account_key(&account_key(0x12, 0)));
    assert!(!state.matches_account_key(&account_key(0x11, 1)));
    assert!(ak.matches_key_id(&state.account_key_id));
}

// ---------------------------------------------------------------------------------------------
// Wrapped-key objects: round trips and context binding
// ---------------------------------------------------------------------------------------------

#[test]
fn e_srv_round_trip_and_binding() {
    let export_key = SecretArray::<EXPORT_KEY_LEN>::from_slice(&[0x42; 64]).unwrap();
    let unlock = ServerUnlockKey::derive(&export_key, account()).unwrap();
    let ctx = AccountKeyServerWrapCtx {
        account_id: account(),
        account_key_epoch: 3,
        password_epoch: 2,
        kdf_id: KdfId::DEFAULT,
    };
    let ak = account_key(0x21, 3);
    let e_srv = unlock
        .wrap_account_key(&mut seeded_rng(1), &ctx, &ak)
        .unwrap();
    let opened = unlock.unwrap_account_key(&ctx, &e_srv).unwrap();
    assert_eq!(opened.epoch(), 3);
    assert_eq!(opened.key().expose_secret(), ak.key().expose_secret());
    for moved in [
        AccountKeyServerWrapCtx {
            account_key_epoch: 2,
            ..ctx
        },
        AccountKeyServerWrapCtx {
            password_epoch: 1,
            ..ctx
        },
    ] {
        assert_eq!(
            unlock.unwrap_account_key(&moved, &e_srv).map(|_| ()),
            Err(DecryptError)
        );
    }
    let other_account = AccountKeyServerWrapCtx {
        account_id: AccountId::from_bytes([0x0b; 16]),
        ..ctx
    };
    assert!(unlock.unwrap_account_key(&other_account, &e_srv).is_err());
    // Seal-time checks.
    assert_eq!(
        unlock
            .wrap_account_key(&mut seeded_rng(1), &ctx, &account_key(0x21, 2))
            .map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
    assert_eq!(
        unlock
            .wrap_account_key(&mut seeded_rng(1), &other_account, &ak)
            .map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
}

#[test]
fn e_local_is_bound_to_its_device() {
    let local = LocalUnlockKey {
        key: key32(0x31),
        account_id: account(),
        device_id: recipient_device(),
    };
    let ctx = AccountKeyLocalWrapCtx {
        account_id: account(),
        device_id: recipient_device(),
        account_key_epoch: 0,
        password_epoch: 0,
        kdf_id: KdfId::DEFAULT,
    };
    let e_local = local
        .wrap_account_key(&mut seeded_rng(1), &ctx, &account_key(0x11, 0))
        .unwrap();
    assert!(local.unwrap_account_key(&ctx, &e_local).is_ok());
    let other_device = AccountKeyLocalWrapCtx {
        device_id: sender_device(),
        ..ctx
    };
    assert!(local.unwrap_account_key(&other_device, &e_local).is_err());
    assert_eq!(
        local
            .wrap_account_key(&mut seeded_rng(1), &other_device, &account_key(0x11, 0))
            .map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
    // The same key under the context of another device's key (same bytes) still fails: the
    // device id is in the AAD.
    let impostor = LocalUnlockKey {
        key: key32(0x31),
        account_id: account(),
        device_id: sender_device(),
    };
    assert!(
        impostor
            .unwrap_account_key(&other_device, &e_local)
            .is_err()
    );
    let moved = AccountKeyLocalWrapCtx {
        password_epoch: 1,
        ..ctx
    };
    assert!(local.unwrap_account_key(&moved, &e_local).is_err());
}

#[test]
fn e_rec_round_trip_and_binding() {
    let code = SecretArray::<RECOVERY_CODE_LEN>::from_slice(&[0xc3; 16]).unwrap();
    let wrap = RecoveryWrapKey::derive(&code).unwrap();
    let ctx = AccountKeyRecoveryWrapCtx {
        account_id: account(),
        account_key_epoch: 1,
        recovery_epoch: 1,
    };
    let e_rec = wrap
        .wrap_account_key(&mut seeded_rng(1), &ctx, &account_key(0x22, 1))
        .unwrap();
    let opened = wrap.unwrap_account_key(&ctx, &e_rec).unwrap();
    assert_eq!(opened.key().expose_secret(), &[0x22; 32]);
    assert_eq!(opened.epoch(), 1);
    for moved in [
        AccountKeyRecoveryWrapCtx {
            recovery_epoch: 2,
            ..ctx
        },
        AccountKeyRecoveryWrapCtx {
            account_key_epoch: 0,
            ..ctx
        },
        AccountKeyRecoveryWrapCtx {
            account_id: AccountId::from_bytes([1; 16]),
            ..ctx
        },
    ] {
        assert!(wrap.unwrap_account_key(&moved, &e_rec).is_err());
    }
    let other_code = SecretArray::<RECOVERY_CODE_LEN>::from_slice(&[0xc4; 16]).unwrap();
    let other = RecoveryWrapKey::derive(&other_code).unwrap();
    assert!(other.unwrap_account_key(&ctx, &e_rec).is_err());
}

#[test]
fn e_id_round_trip_restores_both_keys() {
    let ak = account_key(0x11, 0);
    let keys = IdentityKeys::generate(&mut seeded_rng(6), 2);
    let ctx = IdentitySecretKeysCtx {
        account_id: account(),
        identity_epoch: 2,
    };
    let e_id = ak
        .wrap_identity_keys(&mut seeded_rng(1), &ctx, &keys)
        .unwrap();
    assert_eq!(e_id.len(), 90 + 64);
    let opened = ak.unwrap_identity_keys(&ctx, &e_id).unwrap();
    assert_eq!(opened.public_keys(), keys.public_keys());
    assert_eq!(opened.epoch(), 2);
    // The restored key signs like the original.
    let bundle_key = opened.signing_key().verifying_key();
    assert_eq!(bundle_key, keys.signing_key().verifying_key());
    assert!(
        ak.unwrap_identity_keys(
            &IdentitySecretKeysCtx {
                identity_epoch: 1,
                ..ctx
            },
            &e_id
        )
        .is_err()
    );
    assert!(
        account_key(0x12, 0)
            .unwrap_identity_keys(&ctx, &e_id)
            .is_err()
    );
    assert_eq!(
        ak.wrap_identity_keys(
            &mut seeded_rng(1),
            &IdentitySecretKeysCtx {
                identity_epoch: 1,
                ..ctx
            },
            &keys
        )
        .map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
    assert!(format!("{opened:?}").contains("[REDACTED]"));
}

#[test]
fn e_dev_round_trip_and_version() {
    let ak = account_key(0x11, 0);
    let keys = DeviceKeys::generate(&mut seeded_rng(7));
    let ctx = DeviceSecretKeysCtx {
        account_id: account(),
        device_id: recipient_device(),
    };
    let e_dev = ak
        .wrap_device_keys(&mut seeded_rng(1), &ctx, &keys)
        .unwrap();
    assert_eq!(e_dev.len(), 90 + 65);
    let opened = ak.unwrap_device_keys(&ctx, &e_dev).unwrap();
    assert_eq!(opened.public_keys(), keys.public_keys());
    assert_eq!(opened.kem_key_id(), keys.kem_key_id());
    // Moved to another device's slot: rejected.
    let other = DeviceSecretKeysCtx {
        device_id: sender_device(),
        ..ctx
    };
    assert!(ak.unwrap_device_keys(&other, &e_dev).is_err());
    // A plaintext with version 2 is rejected after a valid AEAD.
    let mut plaintext = [0u8; 65];
    plaintext[0] = 2;
    let v2 = seal(&mut seeded_rng(1), ak.key(), &ctx, &plaintext).unwrap();
    assert_eq!(
        ak.unwrap_device_keys(&ctx, &v2).map(|_| ()),
        Err(DecryptError)
    );
    plaintext[0] = DEVICE_SECRET_KEYS_VERSION;
    let v1 = seal(&mut seeded_rng(1), ak.key(), &ctx, &plaintext).unwrap();
    assert!(ak.unwrap_device_keys(&ctx, &v1).is_ok());
}

#[test]
fn vault_self_grant_round_trip_and_binding() {
    let ak = account_key(0x11, 4);
    let vk = VaultKey::generate(&mut seeded_rng(8), vault(), 2);
    let ctx = VaultKeySelfGrantCtx {
        account_id: account(),
        vault_id: vault(),
        account_key_epoch: 4,
        vault_key_epoch: 2,
    };
    let grant = ak.wrap_vault_key(&mut seeded_rng(1), &ctx, &vk).unwrap();
    let opened = ak.unwrap_vault_key(&ctx, &grant).unwrap();
    assert_eq!(opened.vault_id(), vault());
    assert_eq!(opened.epoch(), 2);
    assert_eq!(opened.key().expose_secret(), vk.key().expose_secret());
    for moved in [
        VaultKeySelfGrantCtx {
            vault_id: VaultId::from_bytes([0x10; 16]),
            ..ctx
        },
        VaultKeySelfGrantCtx {
            vault_key_epoch: 1,
            ..ctx
        },
        VaultKeySelfGrantCtx {
            account_id: AccountId::from_bytes([1; 16]),
            ..ctx
        },
    ] {
        assert!(ak.unwrap_vault_key(&moved, &grant).is_err(), "{moved:?}");
    }
    // Opened with a key of another account-key epoch: refused before any crypto.
    assert!(account_key(0x11, 3).unwrap_vault_key(&ctx, &grant).is_err());
    // Seal-time checks: every field must describe the keys.
    for bad in [
        VaultKeySelfGrantCtx {
            account_key_epoch: 3,
            ..ctx
        },
        VaultKeySelfGrantCtx {
            vault_key_epoch: 3,
            ..ctx
        },
        VaultKeySelfGrantCtx {
            vault_id: VaultId::from_bytes([0x10; 16]),
            ..ctx
        },
    ] {
        assert_eq!(
            ak.wrap_vault_key(&mut seeded_rng(1), &bad, &vk).map(|_| ()),
            Err(EncryptError::ContextMismatch)
        );
    }
}

#[test]
fn item_key_wrap_moves_to_another_item_vault_or_epoch_fail() {
    let vk = VaultKey::generate(&mut seeded_rng(9), vault(), 1);
    let ik = ItemKey::generate(&mut seeded_rng(10), 1);
    let ctx = ItemKeyWrapCtx {
        vault_id: vault(),
        item_id: item(),
        vault_key_epoch: 1,
    };
    let wrap = vk.wrap_item_key(&mut seeded_rng(1), &ctx, &ik).unwrap();
    assert_eq!(wrap.len(), 90 + 37);
    let opened = vk.unwrap_item_key(&ctx, &wrap).unwrap();
    assert_eq!(opened.key().expose_secret(), ik.key().expose_secret());
    assert_eq!(opened.created_vault_key_epoch(), 1);

    // Another item of the same vault.
    let other_item = ItemKeyWrapCtx {
        item_id: ItemId::from_bytes([0x02; 16]),
        ..ctx
    };
    assert_eq!(
        vk.unwrap_item_key(&other_item, &wrap).map(|_| ()),
        Err(DecryptError)
    );
    // Another vault: the same key bytes under another vault's id do not open it either.
    let other_vault = VaultKey {
        key: Key32::from_slice(vk.key().expose_secret()).unwrap(),
        vault_id: VaultId::from_bytes([0x10; 16]),
        epoch: 1,
    };
    let other_vault_ctx = ItemKeyWrapCtx {
        vault_id: other_vault.vault_id(),
        ..ctx
    };
    assert!(
        other_vault
            .unwrap_item_key(&other_vault_ctx, &wrap)
            .is_err()
    );
    // Another epoch: the same key bytes at epoch 2 do not open an epoch-1 wrap.
    let next_epoch = VaultKey {
        key: Key32::from_slice(vk.key().expose_secret()).unwrap(),
        vault_id: vault(),
        epoch: 2,
    };
    let epoch_ctx = ItemKeyWrapCtx {
        vault_key_epoch: 2,
        ..ctx
    };
    assert!(next_epoch.unwrap_item_key(&epoch_ctx, &wrap).is_err());
    // A context that does not describe the unwrapping key is refused before any crypto.
    assert!(vk.unwrap_item_key(&epoch_ctx, &wrap).is_err());
}

#[test]
fn item_key_creation_epoch_survives_rotation_and_drives_the_writer_rule() {
    let vk1 = VaultKey::generate(&mut seeded_rng(11), vault(), 1);
    let ik = ItemKey::generate(&mut seeded_rng(12), 1);
    assert!(!ik.is_stale(1));
    // Rotation: a new vault key at epoch 2 re-wraps the item key with its creation epoch.
    let vk2 = vk1.generate_next(&mut seeded_rng(13)).unwrap();
    assert_eq!((vk2.vault_id(), vk2.epoch()), (vault(), 2));
    let ctx2 = ItemKeyWrapCtx {
        vault_id: vault(),
        item_id: item(),
        vault_key_epoch: 2,
    };
    let rewrap = vk2.wrap_item_key(&mut seeded_rng(1), &ctx2, &ik).unwrap();
    let opened = vk2.unwrap_item_key(&ctx2, &rewrap).unwrap();
    assert_eq!(opened.created_vault_key_epoch(), 1);
    assert!(
        opened.is_stale(vk2.epoch()),
        "a writer must generate a fresh item key"
    );
    let fresh = ItemKey::generate(&mut seeded_rng(14), vk2.epoch());
    assert!(!fresh.is_stale(vk2.epoch()));
    // An item key cannot be created in a later epoch than the key that wraps it.
    let future = ItemKey::generate(&mut seeded_rng(15), 3);
    assert_eq!(
        vk2.wrap_item_key(&mut seeded_rng(1), &ctx2, &future)
            .map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
    // The same, or a bad wrap_version, written by hand, is rejected by the reader.
    let mut plaintext = [0u8; 37];
    plaintext[0] = ITEM_KEY_WRAP_VERSION;
    plaintext[1..5].copy_from_slice(&3u32.to_be_bytes());
    let crafted = seal(&mut seeded_rng(1), vk2.key(), &ctx2, &plaintext).unwrap();
    assert!(vk2.unwrap_item_key(&ctx2, &crafted).is_err());
    plaintext[1..5].copy_from_slice(&2u32.to_be_bytes());
    plaintext[0] = 2;
    let crafted = seal(&mut seeded_rng(1), vk2.key(), &ctx2, &plaintext).unwrap();
    assert!(vk2.unwrap_item_key(&ctx2, &crafted).is_err());
    plaintext[0] = ITEM_KEY_WRAP_VERSION;
    let crafted = seal(&mut seeded_rng(1), vk2.key(), &ctx2, &plaintext).unwrap();
    assert_eq!(
        vk2.unwrap_item_key(&ctx2, &crafted)
            .unwrap()
            .created_vault_key_epoch(),
        2
    );
    // The item key encrypts ops through the envelope, and its key id is what their headers
    // carry.
    let id = fresh.key_id().unwrap();
    assert!(fresh.matches_key_id(&id));
    assert!(!ik.matches_key_id(&id));
}

#[test]
fn retired_secret_key_round_trip_and_type_binding() {
    let ak = account_key(0x11, 1);
    let old_identity = HpkeSecretKey::from_x25519_bytes(&[0x77; 32]).unwrap();
    let retired = RetiredSecretKey::new(KeyType::IdentityX25519, old_identity).unwrap();
    let ctx = RetiredSecretKeyCtx {
        account_id: account(),
        retired_key_id: retired.public_key_id(),
    };
    let envelope = ak
        .wrap_retired_key(&mut seeded_rng(1), &ctx, &retired)
        .unwrap();
    assert_eq!(envelope.len(), 90 + 33);
    let opened = ak.unwrap_retired_key(&ctx, &envelope).unwrap();
    assert_eq!(opened.key_type(), KeyType::IdentityX25519);
    assert_eq!(
        opened.secret_key().public_key(),
        retired.secret_key().public_key()
    );
    // The context names the key by id, which includes its type.
    let as_mail = RetiredSecretKeyCtx {
        retired_key_id: retired
            .secret_key()
            .public_key()
            .key_id(KeyType::MailX25519),
        ..ctx
    };
    assert!(ak.unwrap_retired_key(&as_mail, &envelope).is_err());
    assert_eq!(
        ak.wrap_retired_key(&mut seeded_rng(1), &as_mail, &retired)
            .map(|_| ()),
        Err(EncryptError::ContextMismatch)
    );
    // A plaintext whose type byte disagrees with the context's id is rejected after the AEAD.
    let mut plaintext = [0x77u8; 33];
    plaintext[0] = KeyType::MailX25519.to_u8();
    let crafted = seal(&mut seeded_rng(1), ak.key(), &ctx, &plaintext).unwrap();
    assert!(ak.unwrap_retired_key(&ctx, &crafted).is_err());
    // Only X25519 key types can be retired.
    for kt in [
        KeyType::IdentityEd25519,
        KeyType::DeviceEd25519,
        KeyType::DeviceX25519,
    ] {
        let secret = HpkeSecretKey::from_x25519_bytes(&[0x70; 32]).unwrap();
        assert_eq!(
            RetiredSecretKey::new(kt, secret).map(|_| ()),
            Err(ParseError::InvalidValue)
        );
    }
}

#[test]
fn epochs_and_generation() {
    let ak = AccountKey::generate(&mut seeded_rng(16), 0);
    let next = ak.generate_next(&mut seeded_rng(17)).unwrap();
    assert_eq!(next.epoch(), 1);
    assert_ne!(next.key().expose_secret(), ak.key().expose_secret());
    assert_eq!(
        account_key(1, u32::MAX)
            .generate_next(&mut seeded_rng(1))
            .map(|_| ()),
        Err(EpochOverflow)
    );
    let a = AccountKey::generate(&mut seeded_rng(18), 0);
    let b = AccountKey::generate(&mut seeded_rng(18), 0);
    assert_eq!(a.key().expose_secret(), b.key().expose_secret());
    let text = format!(
        "{a:?} {:?} {:?} {:?} {:?}",
        VaultKey::generate(&mut seeded_rng(1), vault(), 0),
        ItemKey::generate(&mut seeded_rng(1), 0),
        recipient_keys(),
        identity_keys()
    );
    assert_eq!(text.matches("[REDACTED]").count(), 5);
    assert!(!text.contains(&format!(
        "{:02x}{:02x}",
        a.key().expose_secret()[0],
        a.key().expose_secret()[1]
    )));
}

// ---------------------------------------------------------------------------------------------
// ACCOUNT_KEY_DEVICE_GRANT (§10.1, §11.3 step 4, §11.6 step 6)
// ---------------------------------------------------------------------------------------------

fn seal_grant(signer: GrantSigner<'_>) -> Vec<u8> {
    seal_account_key_device_grant(
        &mut FixedRng::new(&[0x44; 32]),
        &grant_ctx(),
        &account_key(0x22, 1),
        &account_key(0x11, 0),
        &recipient_cert(),
        signer,
    )
    .unwrap()
}

#[test]
fn device_grant_known_answer_and_acceptance() {
    let sender = sender_keys();
    let wire = seal_grant(GrantSigner::Device(sender.signing_key()));
    assert_eq!(wire, hex(KEY_GRANT_WIRE));
    let delivered = open_account_key_device_grant(
        &wire,
        &grant_ctx(),
        &recipient_keys(),
        &account_key(0x11, 0),
        GrantSender::Device(&sender_cert()),
    )
    .unwrap();
    assert_eq!(delivered.epoch(), 1);
    assert_eq!(delivered.key().expose_secret(), &[0x22; 32]);
    // The last grant's key must be the committed account key: that check is the caller's.
    let committed = account_key(0x22, 1).key_id().unwrap();
    assert!(delivered.matches_key_id(&committed));
}

#[test]
fn device_grant_from_a_web_vault_is_signed_by_the_identity_key() {
    let identity = identity_keys();
    let wire = seal_grant(GrantSigner::Identity(identity.signing_key()));
    let identity_public = *identity.signing_key().verifying_key();
    let delivered = open_account_key_device_grant(
        &wire,
        &grant_ctx(),
        &recipient_keys(),
        &account_key(0x11, 0),
        GrantSender::Identity(&identity_public),
    )
    .unwrap();
    assert_eq!(delivered.key().expose_secret(), &[0x22; 32]);
    // The same grant is not accepted as if a device had signed it, nor the reverse.
    assert!(matches!(
        open_account_key_device_grant(
            &wire,
            &grant_ctx(),
            &recipient_keys(),
            &account_key(0x11, 0),
            GrantSender::Device(&sender_cert()),
        ),
        Err(GrantError::Verify(_))
    ));
    let device_signed = seal_grant(GrantSigner::Device(sender_keys().signing_key()));
    assert!(matches!(
        open_account_key_device_grant(
            &device_signed,
            &grant_ctx(),
            &recipient_keys(),
            &account_key(0x11, 0),
            GrantSender::Identity(&identity_public),
        ),
        Err(GrantError::Verify(_))
    ));
}

#[test]
fn device_grant_rejections_by_sender() {
    let wire = seal_grant(GrantSigner::Device(sender_keys().signing_key()));
    let open = |ctx: &AccountKeyDeviceGrantCtx,
                recipient: &DeviceKeys,
                previous: &AccountKey,
                sender: GrantSender<'_>| {
        open_account_key_device_grant(&wire, ctx, recipient, previous, sender).map(|_| ())
    };
    let prev = account_key(0x11, 0);

    // The sender certificate must be the device the AAD names, and durable.
    let other_device = verified(&certificate(
        DeviceId::from_bytes([0x0c; 16]),
        &sender_keys(),
        DeviceKind::Mobile,
    ));
    assert_eq!(
        open(
            &grant_ctx(),
            &recipient_keys(),
            &prev,
            GrantSender::Device(&other_device)
        ),
        Err(GrantError::WrongSender)
    );
    let web_sender = verified(&certificate(
        sender_device(),
        &sender_keys(),
        DeviceKind::WebEphemeral,
    ));
    assert_eq!(
        open(
            &grant_ctx(),
            &recipient_keys(),
            &prev,
            GrantSender::Device(&web_sender)
        ),
        Err(GrantError::WrongSender)
    );
    // Another device of the account signed it: its certificate names the sender id, but its
    // key did not sign.
    let impostor = verified(&certificate(
        sender_device(),
        &DeviceKeys::generate(&mut seeded_rng(20)),
        DeviceKind::Mobile,
    ));
    assert!(matches!(
        open(
            &grant_ctx(),
            &recipient_keys(),
            &prev,
            GrantSender::Device(&impostor)
        ),
        Err(GrantError::Verify(_))
    ));
}

#[test]
fn device_grant_rejections_by_recipient_psk_and_context() {
    let wire = seal_grant(GrantSigner::Device(sender_keys().signing_key()));
    let open = |ctx: &AccountKeyDeviceGrantCtx,
                recipient: &DeviceKeys,
                previous: &AccountKey,
                sender: GrantSender<'_>| {
        open_account_key_device_grant(&wire, ctx, recipient, previous, sender).map(|_| ())
    };
    let prev = account_key(0x11, 0);
    let sender = sender_cert();

    // Not addressed to this device's X25519 key.
    let other_recipient = DeviceKeys::generate(&mut seeded_rng(21));
    assert_eq!(
        open(
            &grant_ctx(),
            &other_recipient,
            &prev,
            GrantSender::Device(&sender)
        ),
        Err(GrantError::WrongRecipient)
    );
    // The PSK comes from the previous account key: another key of the right epoch fails, a key
    // of the wrong epoch is refused before any crypto.
    assert_eq!(
        open(
            &grant_ctx(),
            &recipient_keys(),
            &account_key(0x12, 0),
            GrantSender::Device(&sender)
        ),
        Err(GrantError::Decrypt)
    );
    assert_eq!(
        open(
            &grant_ctx(),
            &recipient_keys(),
            &account_key(0x11, 1),
            GrantSender::Device(&sender)
        ),
        Err(GrantError::EpochMismatch)
    );
    // Rebuilt for another recipient device or epoch: the context no longer matches.
    let for_other_recipient = AccountKeyDeviceGrantCtx {
        recipient_device_id: DeviceId::from_bytes([0x0c; 16]),
        ..grant_ctx()
    };
    assert_eq!(
        open(
            &for_other_recipient,
            &recipient_keys(),
            &prev,
            GrantSender::Device(&sender)
        ),
        Err(GrantError::Decrypt)
    );
    let later = AccountKeyDeviceGrantCtx {
        account_key_epoch: 2,
        ..grant_ctx()
    };
    assert_eq!(
        open(
            &later,
            &recipient_keys(),
            &account_key(0x11, 1),
            GrantSender::Device(&sender)
        ),
        Err(GrantError::Decrypt)
    );
    // Stripping the signature and re-signing with another key fails the sender check.
    let resigned = crate::sign::KeyGrant::sign(
        crate::envelope::Purpose::AccountKeyDeviceGrant,
        DeviceKeys::generate(&mut seeded_rng(22)).signing_key(),
        crate::sign::KeyGrant::verify(&wire, &sender.device_ed25519)
            .unwrap()
            .envelope(),
    )
    .unwrap();
    assert!(matches!(
        open_account_key_device_grant(
            &resigned,
            &grant_ctx(),
            &recipient_keys(),
            &prev,
            GrantSender::Device(&sender)
        ),
        Err(GrantError::Verify(_))
    ));
}

#[test]
fn device_grant_seal_checks() {
    let sender = sender_keys();
    let signer = GrantSigner::Device(sender.signing_key());
    let seal_with = |ctx: &AccountKeyDeviceGrantCtx,
                     new: &AccountKey,
                     prev: &AccountKey,
                     recipient: &Verified<DeviceCertificate>| {
        seal_account_key_device_grant(&mut seeded_rng(1), ctx, new, prev, recipient, signer)
            .map(|_| ())
    };
    let (new, prev) = (account_key(0x22, 1), account_key(0x11, 0));
    assert_eq!(
        seal_with(
            &grant_ctx(),
            &account_key(0x22, 2),
            &prev,
            &recipient_cert()
        ),
        Err(GrantError::EpochMismatch)
    );
    assert_eq!(
        seal_with(&grant_ctx(), &new, &account_key(0x11, 1), &recipient_cert()),
        Err(GrantError::EpochMismatch)
    );
    // The recipient certificate must be the recipient the context names, and a durable device.
    assert_eq!(
        seal_with(&grant_ctx(), &new, &prev, &sender_cert()),
        Err(GrantError::WrongRecipient)
    );
    let web = verified(&certificate(
        recipient_device(),
        &recipient_keys(),
        DeviceKind::WebEphemeral,
    ));
    assert_eq!(
        seal_with(&grant_ctx(), &new, &prev, &web),
        Err(GrantError::WrongRecipient)
    );
}

#[test]
fn a_device_several_rotations_behind_opens_its_grants_in_order() {
    let sender = sender_keys();
    let signer = GrantSigner::Device(sender.signing_key());
    let keys = [
        AccountKey::generate(&mut seeded_rng(30), 0),
        AccountKey::generate(&mut seeded_rng(31), 1),
        AccountKey::generate(&mut seeded_rng(32), 2),
    ];
    let ctx = |epoch| AccountKeyDeviceGrantCtx {
        account_key_epoch: epoch,
        ..grant_ctx()
    };
    let grants: Vec<Vec<u8>> = (1..3)
        .map(|epoch| {
            seal_account_key_device_grant(
                &mut seeded_rng(u64::from(epoch)),
                &ctx(epoch),
                &keys[usize::try_from(epoch).unwrap()],
                &keys[usize::try_from(epoch).unwrap() - 1],
                &recipient_cert(),
                signer,
            )
            .unwrap()
        })
        .collect();
    let mut held =
        AccountKey::from_key(Key32::from_slice(keys[0].key().expose_secret()).unwrap(), 0);
    for (epoch, grant) in (1u32..).zip(&grants) {
        held = open_account_key_device_grant(
            grant,
            &ctx(epoch),
            &recipient_keys(),
            &held,
            GrantSender::Device(&sender_cert()),
        )
        .unwrap();
    }
    assert_eq!(held.epoch(), 2);
    assert!(held.matches_key_id(&keys[2].key_id().unwrap()));
    // Out of order: the epoch-2 grant needs the epoch-1 key.
    assert_eq!(
        open_account_key_device_grant(
            &grants[1],
            &ctx(2),
            &recipient_keys(),
            &account_key(0, 0),
            GrantSender::Device(&sender_cert()),
        )
        .map(|_| ()),
        Err(GrantError::EpochMismatch)
    );
    // The delivered key really is the new account key: it opens what the rotation wrapped.
    let settings = AccountSettingsCtx {
        account_id: account(),
        settings_seq: 1,
    };
    let envelope = seal(&mut seeded_rng(3), keys[2].key(), &settings, b"s").unwrap();
    assert_eq!(
        open(held.key(), &settings, &envelope)
            .unwrap()
            .expose_secret(),
        b"s"
    );
}
