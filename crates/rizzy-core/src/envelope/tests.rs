//! Envelope tests: registries, context layouts, round trips for every M1 symmetric purpose,
//! known answers, and the negative tests of CRYPTO.md §15 item 4.

use std::collections::HashSet;

use proptest::prelude::*;
use rand_core::Rng as _;

use super::parse::{self, MAX_SYMMETRIC_ENVELOPE_LEN, parse_for_purpose};
use super::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyLocalWrapCtx, AccountKeyRecoveryWrapCtx,
    AccountKeyServerWrapCtx, AccountSettingsCtx, DeviceSecretKeysCtx, ExportFileCtx,
    IdentitySecretKeysCtx, ItemKeyWrapCtx, ItemOpCtx, ItemSnapshotCtx, RetiredSecretKeyCtx,
    ServerLoginStateCtx, ServerSecretsBackupCtx, ServerTotpSecretCtx, Side, VaultKeySelfGrantCtx,
};
use super::symmetric::{self, MAX_PLAINTEXT_LEN, OVERHEAD, server_open, server_seal, test_hooks};
use super::*;
use crate::error::{DecryptError, EncryptError, ParseError};
use crate::ids::{
    AccountId, BackupId, DeviceId, ExportId, ItemId, KeyType, LoginId, OpId, PublicKeyId,
    SnapshotId, VaultId,
};
use crate::kdf::KdfId;
use crate::padding;
use crate::secret::Key32;
use crate::test_util::{FixedRng, hex, seeded_rng};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn key(byte: u8) -> Key32 {
    Key32::from_slice(&[byte; 32]).unwrap()
}

fn account() -> AccountId {
    AccountId::from_bytes([0x0a; 16])
}

fn device() -> DeviceId {
    DeviceId::from_bytes([0x0d; 16])
}

fn vault() -> VaultId {
    VaultId::from_bytes([0x0e; 16])
}

fn item() -> ItemId {
    ItemId::from_bytes([0x01; 16])
}

fn op_ctx() -> ItemOpCtx {
    ItemOpCtx {
        vault_id: vault(),
        item_id: item(),
        item_schema_version: 1,
        op_id: OpId::from_bytes([0x0f; 16]),
        device_id: device(),
        device_seq: 42,
        hlc: 0x0001_8f3a_0000_0007,
        op_header_hash: ItemOpCtx::header_hash(b"canonical op header"),
    }
}

/// Counts AEAD openings during `f`.
fn aead_opens_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = test_hooks::aead_opens();
    let out = f();
    (out, test_hooks::aead_opens() - before)
}

// ---------------------------------------------------------------------------------------------
// Registries (CRYPTO.md §8.4, §9.4, §9.5, §15 item 10)
// ---------------------------------------------------------------------------------------------

/// The §8.4 table: every purpose with its id.
const CRYPTO_MD_PURPOSES: [(&str, u16); 31] = [
    ("ACCOUNT_KEY_SERVER_WRAP", 0x0001),
    ("ACCOUNT_KEY_LOCAL_WRAP", 0x0002),
    ("ACCOUNT_KEY_RECOVERY_WRAP", 0x0003),
    ("ACCOUNT_KEY_DEVICE_GRANT", 0x0004),
    ("PASSWORD_VERIFIER_GRANT", 0x0005),
    ("ACCOUNT_KEY_KEYSTORE_WRAP", 0x0006),
    ("ACCOUNT_KEY_FORWARD", 0x0007),
    ("IDENTITY_SECRET_KEYS", 0x0010),
    ("DEVICE_SECRET_KEYS", 0x0011),
    ("MAIL_SECRET_KEY", 0x0012),
    ("RETIRED_SECRET_KEY", 0x0013),
    ("ACCOUNT_SETTINGS", 0x0014),
    ("VAULT_KEY_SELF_GRANT", 0x0020),
    ("VAULT_KEY_MEMBER_GRANT", 0x0021),
    ("ITEM_KEY_WRAP", 0x0030),
    ("ITEM_OP", 0x0031),
    ("ITEM_SNAPSHOT", 0x0032),
    ("ATTACHMENT_CHUNK", 0x0033),
    ("ATTACHMENT_KEY_WRAP", 0x0034),
    ("RELAY_BATCH", 0x0040),
    ("PAIRING_TRANSFER", 0x0041),
    ("PAIRING_TRANSFER_SEALED", 0x0042),
    ("RESYNC_TRANSFER", 0x0043),
    ("SHARE_SNAPSHOT", 0x0050),
    ("MAIL_MESSAGE", 0x0060),
    ("EXPORT_FILE", 0x0070),
    ("BACKUP_FILE", 0x0071),
    ("LOCAL_CACHE_INDEX", 0x0090),
    ("SERVER_TOTP_SECRET", 0x0100),
    ("SERVER_LOGIN_STATE", 0x0101),
    ("SERVER_SECRETS_BACKUP", 0x0102),
];

#[test]
fn purpose_registry_matches_crypto_md_8_4() {
    let registered: Vec<(&str, u16)> = Purpose::ALL.iter().map(|p| (p.name(), p.id())).collect();
    assert_eq!(registered, CRYPTO_MD_PURPOSES);
    for p in Purpose::ALL {
        assert_eq!(Purpose::from_id(p.id()), Some(p));
        assert_eq!(p.spec().id, p.id());
    }
    assert_eq!(Purpose::from_id(0x0000), None);
    assert_eq!(Purpose::from_id(0x0103), None);
}

#[test]
fn purpose_ids_and_names_are_unique() {
    let ids: HashSet<u16> = Purpose::ALL.iter().map(|p| p.id()).collect();
    assert_eq!(ids.len(), Purpose::ALL.len());
    let names: HashSet<&str> = Purpose::ALL.iter().map(|p| p.name()).collect();
    assert_eq!(names.len(), Purpose::ALL.len());
}

#[test]
fn every_purpose_has_one_encrypt_algorithm_in_its_decrypt_family() {
    for p in Purpose::ALL {
        let spec = p.spec();
        assert!(spec.decrypt.contains(&spec.encrypt), "{}", spec.name);
        for alg in spec.decrypt {
            // A symmetric purpose never accepts HPKE; a PSK purpose never accepts Base mode,
            // and vice versa (§9.5 rule 2).
            assert_eq!(alg.family(), spec.encrypt.family(), "{}", spec.name);
        }
    }
}

#[test]
fn m1_allow_lists_match_crypto_md_9_5() {
    let psk = [
        Purpose::AccountKeyDeviceGrant,
        Purpose::PasswordVerifierGrant,
        Purpose::PairingTransferSealed,
        Purpose::ResyncTransfer,
    ];
    let base = [Purpose::VaultKeyMemberGrant, Purpose::MailMessage];
    for p in Purpose::ALL {
        let expected: &[AlgId] = if psk.contains(&p) {
            &[AlgId::HpkePskX25519]
        } else if base.contains(&p) {
            &[AlgId::HpkeBaseX25519]
        } else if p == Purpose::AttachmentChunk {
            &[AlgId::ChunkedXChaCha20Poly1305]
        } else {
            &[AlgId::XChaCha20Poly1305Committed]
        };
        assert_eq!(p.spec().decrypt, expected, "{}", p.name());
        assert_eq!(p.encrypt_alg(), expected[0], "{}", p.name());
    }
}

#[test]
fn server_only_purposes_are_in_no_client_allow_list() {
    let server: Vec<Purpose> = Purpose::ALL
        .into_iter()
        .filter(|p| (0x0100..=0x01FF).contains(&p.id()))
        .collect();
    assert_eq!(
        server,
        [
            Purpose::ServerTotpSecret,
            Purpose::ServerLoginState,
            Purpose::ServerSecretsBackup
        ]
    );
    for p in Purpose::ALL {
        if server.contains(&p) {
            assert_eq!(p.side(), Side::Server);
            assert!(p.client_decrypt_allow_list().is_empty(), "{}", p.name());
            assert_eq!(
                p.server_decrypt_allow_list(),
                &[AlgId::XChaCha20Poly1305Committed]
            );
        } else {
            assert_eq!(p.side(), Side::Client);
            assert!(p.server_decrypt_allow_list().is_empty(), "{}", p.name());
            assert_eq!(p.client_decrypt_allow_list(), p.spec().decrypt);
        }
    }
}

#[test]
fn plaintext_rules_match_crypto_md_8_5() {
    let padded: HashSet<&str> = [
        "ITEM_OP",
        "ITEM_SNAPSHOT",
        "SHARE_SNAPSHOT",
        "RELAY_BATCH",
        "PAIRING_TRANSFER_SEALED",
        "RESYNC_TRANSFER",
        "MAIL_MESSAGE",
    ]
    .into_iter()
    .collect();
    for p in Purpose::ALL {
        assert_eq!(
            p.plaintext_rule() == PlaintextRule::Padded,
            padded.contains(p.name()),
            "{}",
            p.name()
        );
    }
    assert_eq!(
        Purpose::ItemKeyWrap.plaintext_rule(),
        PlaintextRule::Fixed(37)
    );
    assert_eq!(
        Purpose::DeviceSecretKeys.plaintext_rule(),
        PlaintextRule::Fixed(65)
    );
    assert_eq!(
        Purpose::RetiredSecretKey.plaintext_rule(),
        PlaintextRule::Fixed(33)
    );
    assert_eq!(
        Purpose::IdentitySecretKeys.plaintext_rule(),
        PlaintextRule::Fixed(64)
    );
    for p in [
        Purpose::AccountKeyServerWrap,
        Purpose::AccountKeyLocalWrap,
        Purpose::AccountKeyRecoveryWrap,
        Purpose::AccountKeyDeviceGrant,
        Purpose::VaultKeySelfGrant,
    ] {
        assert_eq!(p.plaintext_rule(), PlaintextRule::Fixed(32), "{}", p.name());
    }
}

#[test]
fn algorithm_registry_matches_crypto_md_9_4() {
    let registered: Vec<u8> = (0..=u8::MAX)
        .filter(|v| AlgId::from_u8(*v).is_some())
        .collect();
    assert_eq!(registered, [0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13]);
    for alg in AlgId::ALL {
        assert_eq!(AlgId::from_u8(alg.to_u8()), Some(alg));
    }
    let implemented: Vec<AlgId> = AlgId::ALL
        .into_iter()
        .filter(|a| a.is_implemented())
        .collect();
    assert_eq!(
        implemented,
        [
            AlgId::XChaCha20Poly1305Committed,
            AlgId::HpkeBaseX25519,
            AlgId::HpkePskX25519
        ]
    );
    assert_eq!(AlgId::XChaCha20Poly1305Committed.overhead(), Some(90));
    assert_eq!(AlgId::HpkeBaseX25519.overhead(), Some(66));
    assert_eq!(AlgId::HpkePskX25519.overhead(), Some(66));
    assert_eq!(AlgId::Aes256GcmSivCommitted.overhead(), None);
    // Invalid, reserved PQ range, test-only range and the extension escape are not values.
    for v in [0x00u8, 0x04, 0x0f, 0x14, 0x1f, 0xf0, 0xfe, 0xff] {
        assert_eq!(AlgId::from_u8(v), None, "{v:#04x}");
    }
}

// ---------------------------------------------------------------------------------------------
// Context layouts (§8.4)
// ---------------------------------------------------------------------------------------------

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn check<C: Context>(ctx: &C, expected: &[u8]) {
    assert_eq!(ctx.ctx_bytes(), expected, "{}", C::PURPOSE.name());
    assert_eq!(ctx.ctx_len(), expected.len(), "{}", C::PURPOSE.name());
}

#[test]
fn m1_context_layouts_account_key_wraps() {
    let kdf = KdfId::DEFAULT;
    let a = account();
    let d = device();

    let c = AccountKeyServerWrapCtx {
        account_id: a,
        account_key_epoch: 1,
        password_epoch: 2,
        kdf_id: kdf,
    };
    check(
        &c,
        &cat(&[a.as_bytes(), &[0, 0, 0, 1], &[0, 0, 0, 2], &[0, 1]]),
    );

    let c = AccountKeyLocalWrapCtx {
        account_id: a,
        device_id: d,
        account_key_epoch: 3,
        password_epoch: 4,
        kdf_id: kdf,
    };
    check(
        &c,
        &cat(&[
            a.as_bytes(),
            d.as_bytes(),
            &[0, 0, 0, 3],
            &[0, 0, 0, 4],
            &[0, 1],
        ]),
    );

    let c = AccountKeyRecoveryWrapCtx {
        account_id: a,
        account_key_epoch: 5,
        recovery_epoch: 6,
    };
    check(&c, &cat(&[a.as_bytes(), &[0, 0, 0, 5], &[0, 0, 0, 6]]));

    let other = DeviceId::from_bytes([0x33; 16]);
    let c = AccountKeyDeviceGrantCtx {
        account_id: a,
        account_key_epoch: 7,
        sender_device_id: d,
        recipient_device_id: other,
    };
    check(
        &c,
        &cat(&[a.as_bytes(), &[0, 0, 0, 7], d.as_bytes(), other.as_bytes()]),
    );
}

#[test]
fn m1_context_layouts_account_objects() {
    let a = account();
    let d = device();
    let c = IdentitySecretKeysCtx {
        account_id: a,
        identity_epoch: 8,
    };
    check(&c, &cat(&[a.as_bytes(), &[0, 0, 0, 8]]));

    let c = DeviceSecretKeysCtx {
        account_id: a,
        device_id: d,
    };
    check(&c, &cat(&[a.as_bytes(), d.as_bytes()]));

    let retired = PublicKeyId::derive(KeyType::IdentityX25519, &[9; 32]);
    let c = RetiredSecretKeyCtx {
        account_id: a,
        retired_key_id: retired,
    };
    check(&c, &cat(&[a.as_bytes(), retired.as_bytes()]));

    let c = AccountSettingsCtx {
        account_id: a,
        settings_seq: 0x0102_0304_0506_0708,
    };
    check(&c, &cat(&[a.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]]));
}

#[test]
fn m1_context_layouts_vault_and_item_objects() {
    let a = account();
    let d = device();
    let c = VaultKeySelfGrantCtx {
        account_id: a,
        vault_id: vault(),
        account_key_epoch: 9,
        vault_key_epoch: 10,
    };
    check(
        &c,
        &cat(&[
            a.as_bytes(),
            vault().as_bytes(),
            &[0, 0, 0, 9],
            &[0, 0, 0, 10],
        ]),
    );

    let c = ItemKeyWrapCtx {
        vault_id: vault(),
        item_id: item(),
        vault_key_epoch: 11,
    };
    check(
        &c,
        &cat(&[vault().as_bytes(), item().as_bytes(), &[0, 0, 0, 11]]),
    );

    let c = op_ctx();
    check(
        &c,
        &cat(&[
            vault().as_bytes(),
            item().as_bytes(),
            &[0, 1],
            &[0x0f; 16],
            d.as_bytes(),
            &42u64.to_be_bytes(),
            &0x0001_8f3a_0000_0007u64.to_be_bytes(),
            &c.op_header_hash,
        ]),
    );

    let c = ItemSnapshotCtx {
        vault_id: vault(),
        item_id: item(),
        item_schema_version: 1,
        snapshot_id: SnapshotId::from_bytes([0x5e; 16]),
        snapshot_header_hash: ItemSnapshotCtx::header_hash(b"snapshot header"),
    };
    check(
        &c,
        &cat(&[
            vault().as_bytes(),
            item().as_bytes(),
            &[0, 1],
            &[0x5e; 16],
            &c.snapshot_header_hash,
        ]),
    );
}

#[test]
fn m1_context_layouts_files_and_server_objects() {
    let kdf = KdfId::DEFAULT;
    let a = account();
    let c = ExportFileCtx {
        export_id: ExportId::from_bytes([0xe0; 16]),
        created_at_ms: 1_758_800_000_000,
        kdf_id: kdf,
        export_salt: [0x5a; 16],
    };
    check(
        &c,
        &cat(&[
            &[0xe0; 16],
            &1_758_800_000_000u64.to_be_bytes(),
            &[0, 1],
            &[0x5a; 16],
        ]),
    );

    let c = ServerTotpSecretCtx {
        account_id: a,
        totp_credential_seq: 1,
    };
    check(&c, &cat(&[a.as_bytes(), &[0, 0, 0, 1]]));

    let c = ServerLoginStateCtx {
        login_id: LoginId::from_bytes([0x1d; 16]),
        credential_identifier: [0xc1; 16],
        expires_at_ms: 60_000,
    };
    check(
        &c,
        &cat(&[&[0x1d; 16], &[0xc1; 16], &60_000u64.to_be_bytes()]),
    );

    let c = ServerSecretsBackupCtx {
        backup_id: BackupId::from_bytes([0xbb; 16]),
        created_at_ms: 7,
        kdf_id: kdf,
        backup_salt: [0x55; 16],
    };
    check(
        &c,
        &cat(&[&[0xbb; 16], &7u64.to_be_bytes(), &[0, 1], &[0x55; 16]]),
    );

    assert_eq!(ItemOpCtx::header_hash(b"abc").len(), 32);
}

#[test]
fn contexts_fix_their_purpose() {
    fn purpose_of<C: Context>(_: &C) -> Purpose {
        C::PURPOSE
    }
    assert_eq!(purpose_of(&op_ctx()), Purpose::ItemOp);
    assert_eq!(
        purpose_of(&DeviceSecretKeysCtx {
            account_id: account(),
            device_id: device()
        }),
        Purpose::DeviceSecretKeys
    );
}

// ---------------------------------------------------------------------------------------------
// Known answers, computed independently (§15 item 1)
// ---------------------------------------------------------------------------------------------

/// Envelopes computed by an independent implementation of §8.3/§9.1: Python `cryptography`
/// 41.0.7 (HKDF-SHA-256, IETF ChaCha20-Poly1305) plus `HChaCha20` written from
/// draft-irtf-cfrg-xchacha-03 §2.2, which reproduced that draft's §2.2.1 `HChaCha20` and §A.3.1
/// AEAD vectors first. The nonce comes from a fixed test RNG, not from any nonce parameter.
#[test]
fn known_answer_envelopes_match_an_independent_implementation() {
    let k = Key32::from_slice(&(0x80..=0x9f).collect::<Vec<u8>>()).unwrap();
    let nonce: Vec<u8> = (0x40..=0x57).collect();
    let vault_id = VaultId::from_slice(&(0xa0..=0xaf).collect::<Vec<u8>>()).unwrap();
    let item_id = ItemId::from_slice(&(0xb0..=0xbf).collect::<Vec<u8>>()).unwrap();

    let wrap_ctx = ItemKeyWrapCtx {
        vault_id,
        item_id,
        vault_key_epoch: 7,
    };
    let mut plaintext = vec![0x01, 0, 0, 0, 3];
    plaintext.extend_from_slice(&[0x77; 32]);
    let env = seal(&mut FixedRng::new(&nonce), &k, &wrap_ctx, &plaintext).unwrap();
    assert_eq!(env, hex(ITEM_KEY_WRAP_VECTOR));
    assert_eq!(
        open(&k, &wrap_ctx, &env).unwrap().expose_secret(),
        plaintext
    );

    let op = ItemOpCtx {
        vault_id,
        item_id,
        item_schema_version: 1,
        op_id: OpId::from_bytes([0xc0; 16]),
        device_id: DeviceId::from_bytes([0xd0; 16]),
        device_seq: 5,
        hlc: 0x0123_4567_89ab_cdef,
        op_header_hash: ItemOpCtx::header_hash(b"canonical op header"),
    };
    let env = seal(&mut FixedRng::new(&nonce), &k, &op, b"hello, vault").unwrap();
    assert_eq!(env, hex(ITEM_OP_VECTOR));
    assert_eq!(
        open(&k, &op, &env).unwrap().expose_secret(),
        b"hello, vault"
    );
}

const ITEM_KEY_WRAP_VECTOR: &str = "
    0101c84ff799a8cc6d1495e98b8526dc72e4404142434445464748494a4b4c4d4e4f5051525354555657
    0a680c6205bc3e6c1c89b02a044b49bb6de1f1b003b4d2e7b65b1172917cb042
    00737219ac308a6dacded0558b5549dfb49830d07ae5abe687e9fdaac86b7c01a9ba2bff36
    c99e81726dccdd4af090b3ed1c3a70b3";

const ITEM_OP_VECTOR: &str = "
    0101c84ff799a8cc6d1495e98b8526dc72e4404142434445464748494a4b4c4d4e4f5051525354555657
    3e5e019e2800341e22de231f03551f940afde0dc9adacf21577c441bef2a3d81
    26349794312be430391bd49be8496fd27cd2e67e34dadd1cd4302a08c5909624a172ea5d37035d50f44d933fc34df3a3
    a55b05bff7d59dec4769e6e6e331f53e0a403b56c168a38d17ae7dedd7fa3927f790e8283946cfe56f474f735e27c652
    ccc8f9a04ebfba15e482fe1be75e458039fd84b77b7525ebad185f8bf552ef016dd524ca72e6ab943a06c6aff0e2c908
    b506da571abe2f0a8344b887ad2f839f0a18479fdbe9e1e23729ea44b145e25f3eb3b0d8dd8262e2c91ec17878d4fe32
    66c27921f5265e8bb1d5969e0c7c26617e708aaca41ca7a6936a6bb524d09d72becc5f776da4154fef45af2d02d05b63
    fd293d8d827c27f9ab9d83021914fd40dc40001e897c2a71a0e254fd6b24d040";

/// draft-irtf-cfrg-xchacha-03 §A.3.1 XChaCha20-Poly1305 test vector, run against the pinned
/// `chacha20poly1305` through the same in-place API the envelope uses.
#[test]
fn xchacha20poly1305_draft_03_vector() {
    use chacha20poly1305::{AeadInOut as _, KeyInit as _, Tag, XChaCha20Poly1305, XNonce};

    let key: Vec<u8> = (0x80..=0x9f).collect();
    let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap());
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
tip for the future, sunscreen would be it.";
    let expected_ct = hex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13b52e",
    );
    let expected_tag = hex("c0875924c1c7987947deafd8780acf49");

    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &aad, buf.as_mut_slice().into())
        .unwrap();
    assert_eq!(buf, expected_ct);
    assert_eq!(tag.as_slice(), expected_tag);

    let tag = Tag::try_from(expected_tag.as_slice()).unwrap();
    cipher
        .decrypt_inout_detached(&XNonce::from(nonce), &aad, buf.as_mut_slice().into(), &tag)
        .unwrap();
    assert_eq!(buf, plaintext);
}

#[test]
fn envelope_layout_is_crypto_md_9_1() {
    let k = key(0x21);
    let ctx = DeviceSecretKeysCtx {
        account_id: account(),
        device_id: device(),
    };
    let nonce = [0x99u8; 24];
    let env = seal(&mut FixedRng::new(&nonce), &k, &ctx, &[0x42; 65]).unwrap();
    assert_eq!(env.len(), OVERHEAD + 65);
    assert_eq!(env[0], FORMAT_VERSION);
    assert_eq!(env[1], 0x01);
    assert_eq!(&env[2..18], k.key_id().unwrap().as_bytes());
    assert_eq!(&env[18..42], &nonce);
    let parsed = parse::parse(&env).unwrap();
    let EnvelopeRef::Symmetric(s) = parsed else {
        unreachable!("0x01 parses as symmetric")
    };
    assert_eq!(s.header(), &env[..18]);
    assert_eq!(s.nonce(), &nonce);
    assert_eq!(s.commitment().as_slice(), &env[42..74]);
    assert_eq!(s.ciphertext(), &env[74..74 + 65]);
    assert_eq!(s.tag().as_slice(), &env[74 + 65..]);
    assert_eq!(parsed.alg_id(), AlgId::XChaCha20Poly1305Committed);
    assert_eq!(parsed.key_id(), k.key_id().unwrap().as_bytes());
    assert_eq!(parsed.to_vec(), env);
}

// ---------------------------------------------------------------------------------------------
// Round trips for every M1 symmetric purpose
// ---------------------------------------------------------------------------------------------

fn round_trip<C: SymmetricContext>(ctx: &C, plaintext: &[u8]) {
    let mut rng = seeded_rng(u64::from(C::PURPOSE.id()));
    let k = Key32::generate(&mut rng);
    let env = seal(&mut rng, &k, ctx, plaintext).unwrap();
    let expected_len = match C::PURPOSE.plaintext_rule() {
        PlaintextRule::Padded => OVERHEAD + padding::padded_len(plaintext.len()).unwrap(),
        _ => OVERHEAD + plaintext.len(),
    };
    assert_eq!(env.len(), expected_len, "{}", C::PURPOSE.name());
    let opened = open(&k, ctx, &env).unwrap();
    assert_eq!(opened.expose_secret(), plaintext, "{}", C::PURPOSE.name());
    // A second seal of the same plaintext uses a fresh nonce.
    let again = seal(&mut rng, &k, ctx, plaintext).unwrap();
    assert_ne!(env[18..42], again[18..42]);
    assert_ne!(env, again);
}

#[test]
fn every_m1_account_purpose_round_trips() {
    let kdf = KdfId::DEFAULT;
    let a = account();
    let d = device();
    round_trip(
        &AccountKeyServerWrapCtx {
            account_id: a,
            account_key_epoch: 0,
            password_epoch: 0,
            kdf_id: kdf,
        },
        &[1; 32],
    );
    round_trip(
        &AccountKeyLocalWrapCtx {
            account_id: a,
            device_id: d,
            account_key_epoch: 0,
            password_epoch: 0,
            kdf_id: kdf,
        },
        &[2; 32],
    );
    round_trip(
        &AccountKeyRecoveryWrapCtx {
            account_id: a,
            account_key_epoch: 0,
            recovery_epoch: 1,
        },
        &[3; 32],
    );
    round_trip(
        &IdentitySecretKeysCtx {
            account_id: a,
            identity_epoch: 0,
        },
        &[4; 64],
    );
    let mut dev_keys = vec![1u8];
    dev_keys.extend_from_slice(&[5; 64]);
    round_trip(
        &DeviceSecretKeysCtx {
            account_id: a,
            device_id: d,
        },
        &dev_keys,
    );
    let mut retired = vec![KeyType::IdentityX25519.to_u8()];
    retired.extend_from_slice(&[6; 32]);
    round_trip(
        &RetiredSecretKeyCtx {
            account_id: a,
            retired_key_id: PublicKeyId::derive(KeyType::IdentityX25519, &[7; 32]),
        },
        &retired,
    );
    for len in [0usize, 1, 500] {
        round_trip(
            &AccountSettingsCtx {
                account_id: a,
                settings_seq: 1,
            },
            &vec![8; len],
        );
    }
}

#[test]
fn every_m1_vault_and_item_purpose_round_trips() {
    let kdf = KdfId::DEFAULT;
    let a = account();
    round_trip(
        &VaultKeySelfGrantCtx {
            account_id: a,
            vault_id: vault(),
            account_key_epoch: 0,
            vault_key_epoch: 0,
        },
        &[9; 32],
    );
    let mut wrap = vec![1u8, 0, 0, 0, 0];
    wrap.extend_from_slice(&[10; 32]);
    round_trip(
        &ItemKeyWrapCtx {
            vault_id: vault(),
            item_id: item(),
            vault_key_epoch: 0,
        },
        &wrap,
    );
    for len in [0usize, 1, 252, 253, 5000] {
        round_trip(&op_ctx(), &vec![11; len]);
        round_trip(
            &ItemSnapshotCtx {
                vault_id: vault(),
                item_id: item(),
                item_schema_version: 1,
                snapshot_id: SnapshotId::from_bytes([12; 16]),
                snapshot_header_hash: [13; 32],
            },
            &vec![14; len],
        );
    }
    round_trip(
        &ExportFileCtx {
            export_id: ExportId::from_bytes([15; 16]),
            created_at_ms: 1,
            kdf_id: kdf,
            export_salt: [16; 16],
        },
        b"{\"items\":[]}",
    );
}

#[test]
fn server_purposes_round_trip_through_the_server_table_only() {
    let mut rng = seeded_rng(0x0100);
    let k = Key32::generate(&mut rng);
    let totp = ServerTotpSecretCtx {
        account_id: account(),
        totp_credential_seq: 1,
    };
    let env = server_seal(&mut rng, &k, &totp, b"JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(
        server_open(&k, &totp, &env).unwrap().expose_secret(),
        b"JBSWY3DPEHPK3PXP"
    );

    let login = ServerLoginStateCtx {
        login_id: LoginId::generate(&mut rng),
        credential_identifier: [1; 16],
        expires_at_ms: 1_000,
    };
    let env = server_seal(&mut rng, &k, &login, &[2; 200]).unwrap();
    assert_eq!(
        server_open(&k, &login, &env).unwrap().expose_secret(),
        &[2; 200]
    );

    let backup = ServerSecretsBackupCtx {
        backup_id: BackupId::generate(&mut rng),
        created_at_ms: 1,
        kdf_id: KdfId::DEFAULT,
        backup_salt: [3; 16],
    };
    let env = server_seal(&mut rng, &k, &backup, b"secrets").unwrap();
    assert_eq!(
        server_open(&k, &backup, &env).unwrap().expose_secret(),
        b"secrets"
    );

    // The same ctx bytes under a client purpose (IDENTITY_SECRET_KEYS: account_id ‖ u32) do not
    // open a server-sealed object: the purpose differs, so the commitment fails first.
    let env = server_seal(&mut rng, &k, &totp, &[4; 64]).unwrap();
    let as_client = IdentitySecretKeysCtx {
        account_id: account(),
        identity_epoch: 1,
    };
    assert_eq!(as_client.ctx_bytes(), totp.ctx_bytes());
    let (result, aead) = aead_opens_during(|| open(&k, &as_client, &env));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(aead, 0);
}

// ---------------------------------------------------------------------------------------------
// Plaintext rules and limits on seal
// ---------------------------------------------------------------------------------------------

#[test]
fn fixed_size_purposes_reject_other_lengths() {
    let mut rng = seeded_rng(1);
    let k = key(1);
    let ctx = VaultKeySelfGrantCtx {
        account_id: account(),
        vault_id: vault(),
        account_key_epoch: 0,
        vault_key_epoch: 0,
    };
    for len in [0usize, 31, 33, 64] {
        assert_eq!(
            seal(&mut rng, &k, &ctx, &vec![0; len]),
            Err(EncryptError::InvalidPlaintextLength),
            "{len}"
        );
    }
}

#[test]
fn padded_purposes_hide_the_exact_length() {
    let mut rng = seeded_rng(2);
    let k = key(2);
    let sizes: HashSet<usize> = (0..=252)
        .map(|len| {
            seal(&mut rng, &k, &op_ctx(), &vec![0x61; len])
                .unwrap()
                .len()
        })
        .collect();
    assert_eq!(sizes.into_iter().collect::<Vec<_>>(), [OVERHEAD + 256]);
}

#[test]
fn the_16_mib_limit_is_enforced() {
    let mut rng = seeded_rng(3);
    let k = key(3);
    let settings = AccountSettingsCtx {
        account_id: account(),
        settings_seq: 1,
    };
    // Exactly 16 MiB is allowed. One real encryption at the limit (about 5 s unoptimised).
    let env = seal(&mut rng, &k, &settings, &vec![0u8; MAX_PLAINTEXT_LEN]).unwrap();
    assert_eq!(env.len(), MAX_SYMMETRIC_ENVELOPE_LEN);
    // One byte more is refused before any crypto.
    let over = vec![0u8; MAX_PLAINTEXT_LEN + 1];
    assert_eq!(
        seal(&mut rng, &k, &settings, &over),
        Err(EncryptError::PlaintextTooLong)
    );
    // Padded: 16 MiB - 4 bytes of data frame to exactly 16 MiB (see the padding tests); one
    // more byte pads past the limit and is refused before any crypto.
    assert_eq!(
        padding::padded_len(MAX_PLAINTEXT_LEN - 4).unwrap(),
        MAX_PLAINTEXT_LEN
    );
    let data = vec![0u8; MAX_PLAINTEXT_LEN - 3];
    assert_eq!(
        seal(&mut rng, &k, &op_ctx(), &data),
        Err(EncryptError::PlaintextTooLong)
    );
    // Opening: the length gate (§9.5 step 1) admits exactly 16 MiB + 90 bytes.
    let allow = Purpose::AccountSettings.client_decrypt_allow_list();
    let mut max = vec![0u8; MAX_SYMMETRIC_ENVELOPE_LEN];
    max[..2].copy_from_slice(&[0x01, 0x01]);
    assert!(parse_for_purpose(&max, allow).is_ok());
    max.push(0);
    assert_eq!(parse_for_purpose(&max, allow), Err(DecryptError));
    let (result, aead) = aead_opens_during(|| open(&k, &settings, &max));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(aead, 0);
    // The generic parser applies the same limit.
    assert_eq!(parse::parse(&max), Err(ParseError::TooLong));
}

// ---------------------------------------------------------------------------------------------
// Negative tests (§15 item 4): commitment before AEAD, one error for everything
// ---------------------------------------------------------------------------------------------

fn sealed_op() -> (Key32, Vec<u8>) {
    let mut rng = seeded_rng(4);
    let k = Key32::generate(&mut rng);
    let env = seal(&mut rng, &k, &op_ctx(), b"attack at dawn").unwrap();
    (k, env)
}

#[test]
fn wrong_context_fields_fail_at_the_commitment() {
    let (k, env) = sealed_op();
    let base = op_ctx();
    let variants = [
        ItemOpCtx {
            vault_id: VaultId::from_bytes([0xee; 16]),
            ..base
        },
        ItemOpCtx {
            item_id: ItemId::from_bytes([0xee; 16]),
            ..base
        },
        ItemOpCtx {
            item_schema_version: 2,
            ..base
        },
        ItemOpCtx {
            op_id: OpId::from_bytes([0xee; 16]),
            ..base
        },
        ItemOpCtx {
            device_id: DeviceId::from_bytes([0xee; 16]),
            ..base
        },
        ItemOpCtx {
            device_seq: base.device_seq + 1,
            ..base
        },
        ItemOpCtx {
            hlc: base.hlc + 1,
            ..base
        },
        ItemOpCtx {
            op_header_hash: [0; 32],
            ..base
        },
    ];
    for ctx in variants {
        let (result, aead) = aead_opens_during(|| open(&k, &ctx, &env));
        assert_eq!(result.map(|_| ()), Err(DecryptError), "{ctx:?}");
        assert_eq!(aead, 0, "commitment must fail before the AEAD: {ctx:?}");
    }
    // The right context still opens, and reaches the AEAD exactly once.
    let (result, aead) = aead_opens_during(|| open(&k, &base, &env));
    assert_eq!(result.unwrap().expose_secret(), b"attack at dawn");
    assert_eq!(aead, 1);
}

#[test]
fn wrong_epoch_fails_at_the_commitment() {
    let mut rng = seeded_rng(5);
    let k = Key32::generate(&mut rng);
    let ctx = VaultKeySelfGrantCtx {
        account_id: account(),
        vault_id: vault(),
        account_key_epoch: 3,
        vault_key_epoch: 4,
    };
    let env = seal(&mut rng, &k, &ctx, &[1; 32]).unwrap();
    for wrong in [
        VaultKeySelfGrantCtx {
            account_key_epoch: 2,
            ..ctx
        },
        VaultKeySelfGrantCtx {
            vault_key_epoch: 5,
            ..ctx
        },
    ] {
        let (result, aead) = aead_opens_during(|| open(&k, &wrong, &env));
        assert_eq!(result.map(|_| ()), Err(DecryptError));
        assert_eq!(aead, 0);
    }
}

#[test]
fn wrong_purpose_with_identical_ctx_bytes_fails_at_the_commitment() {
    // DEVICE_SECRET_KEYS (account_id ‖ device_id) and RETIRED_SECRET_KEY (account_id ‖ 16-byte
    // key id) can carry identical ctx bytes; only the purpose id differs.
    let mut rng = seeded_rng(6);
    let k = Key32::generate(&mut rng);
    let dev = DeviceSecretKeysCtx {
        account_id: account(),
        device_id: DeviceId::from_bytes([0x44; 16]),
    };
    let retired = RetiredSecretKeyCtx {
        account_id: account(),
        retired_key_id: PublicKeyId::from_bytes([0x44; 16]),
    };
    assert_eq!(dev.ctx_bytes(), retired.ctx_bytes());
    let env = seal(&mut rng, &k, &dev, &[0x55; 65]).unwrap();
    let (result, aead) = aead_opens_during(|| open(&k, &retired, &env));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(aead, 0);
}

#[test]
fn wrong_key_fails_before_any_aead() {
    let (_, env) = sealed_op();
    let other = key(0x77);
    // Plain wrong key: the header key id does not match (§9.5 step 4).
    let (result, aead) = aead_opens_during(|| open(&other, &op_ctx(), &env));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(aead, 0);
    // An attacker relabels the header with the wrong key's id: the key id check passes, and
    // the commitment, which covers the key and the header, fails before the AEAD.
    let mut relabelled = env.clone();
    relabelled[2..18].copy_from_slice(other.key_id().unwrap().as_bytes());
    let (result, aead) = aead_opens_during(|| open(&other, &op_ctx(), &relabelled));
    assert_eq!(result.map(|_| ()), Err(DecryptError));
    assert_eq!(aead, 0);
}

#[test]
fn every_single_bit_flip_is_rejected_and_only_ct_or_tag_flips_reach_the_aead() {
    let (k, env) = sealed_op();
    let ctx = op_ctx();
    let body_start = HEADER_LEN + symmetric::NONCE_LEN + symmetric::COMMITMENT_LEN;
    for i in 0..env.len() {
        for bit in 0..8 {
            let mut bad = env.clone();
            bad[i] ^= 1 << bit;
            let (result, aead) = aead_opens_during(|| open(&k, &ctx, &bad));
            assert_eq!(result.map(|_| ()), Err(DecryptError), "byte {i} bit {bit}");
            let expected_aead = usize::from(i >= body_start);
            assert_eq!(aead, expected_aead, "byte {i} bit {bit}");
        }
    }
}

#[test]
fn truncation_and_extension_at_every_length_never_panic() {
    let (k, env) = sealed_op();
    let ctx = op_ctx();
    for n in 0..env.len() {
        assert_eq!(
            open(&k, &ctx, &env[..n]).map(|_| ()),
            Err(DecryptError),
            "{n}"
        );
        let _ = parse::parse(&env[..n]);
    }
    let mut longer = env.clone();
    longer.push(0);
    assert_eq!(open(&k, &ctx, &longer).map(|_| ()), Err(DecryptError));
    let mut shifted = vec![0u8];
    shifted.extend_from_slice(&env);
    assert_eq!(open(&k, &ctx, &shifted).map(|_| ()), Err(DecryptError));
}

#[test]
fn version_and_algorithm_outside_the_allow_list_are_rejected_before_crypto() {
    let (k, env) = sealed_op();
    let ctx = op_ctx();
    for version in [0x00u8, 0x02, 0xff] {
        let mut bad = env.clone();
        bad[0] = version;
        let (result, aead) = aead_opens_during(|| open(&k, &ctx, &bad));
        assert_eq!(result.map(|_| ()), Err(DecryptError));
        assert_eq!(aead, 0);
    }
    for alg in [
        0x00u8, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x14, 0xf0, 0xfe, 0xff,
    ] {
        let mut bad = env.clone();
        bad[1] = alg;
        let (result, aead) = aead_opens_during(|| open(&k, &ctx, &bad));
        assert_eq!(result.map(|_| ()), Err(DecryptError), "{alg:#04x}");
        assert_eq!(aead, 0);
        assert_eq!(
            parse_for_purpose(&bad, Purpose::ItemOp.client_decrypt_allow_list()),
            Err(DecryptError)
        );
    }
}

#[test]
fn check_order_is_length_version_allow_list() {
    let allow = Purpose::ItemOp.client_decrypt_allow_list();
    // Shorter than 90 bytes: rejected whatever the header says.
    let mut short = vec![0x01, 0x01];
    short.resize(89, 0);
    assert_eq!(parse_for_purpose(&short, allow), Err(DecryptError));
    let mut ok = vec![0x01, 0x01];
    ok.resize(90, 0);
    assert!(parse_for_purpose(&ok, allow).is_ok());
    // An HPKE-shaped envelope on a symmetric purpose, and a symmetric one on a PSK purpose.
    let mut hpke = vec![0x01, 0x12];
    hpke.resize(200, 0);
    assert_eq!(parse_for_purpose(&hpke, allow), Err(DecryptError));
    assert!(
        parse_for_purpose(
            &hpke,
            Purpose::AccountKeyDeviceGrant.client_decrypt_allow_list()
        )
        .is_ok()
    );
    let mut base = hpke.clone();
    base[1] = 0x10;
    // Base mode on a PSK purpose would drop the PSK: rejected.
    assert_eq!(
        parse_for_purpose(
            &base,
            Purpose::AccountKeyDeviceGrant.client_decrypt_allow_list()
        ),
        Err(DecryptError)
    );
    assert_eq!(
        parse_for_purpose(
            &ok,
            Purpose::AccountKeyDeviceGrant.client_decrypt_allow_list()
        ),
        Err(DecryptError)
    );
    // Server-only purposes have an empty client allow-list: everything is rejected.
    assert_eq!(
        parse_for_purpose(&ok, Purpose::ServerTotpSecret.client_decrypt_allow_list()),
        Err(DecryptError)
    );
    // Reserved algorithm purposes cannot be parsed for decryption yet.
    assert_eq!(
        parse_for_purpose(&ok, Purpose::AttachmentChunk.client_decrypt_allow_list()),
        Err(DecryptError)
    );
}

#[test]
fn plaintext_rule_failures_after_the_aead_are_the_same_error() {
    use zeroize::Zeroizing;
    let finish = |rule, bytes: &[u8]| {
        symmetric::finish_plaintext(rule, Zeroizing::new(bytes.to_vec()))
            .map(|p| p.expose_secret().to_vec())
    };
    let good = padding::frame(b"abc").unwrap();
    assert_eq!(
        finish(PlaintextRule::Padded, good.expose_secret()).unwrap(),
        b"abc"
    );
    // data_len larger than the frame, non-zero padding, wrong padded length.
    let mut too_long = good.expose_secret().to_vec();
    too_long[3] = 0xff;
    let mut dirty = good.expose_secret().to_vec();
    dirty[200] = 1;
    for bad in [&too_long[..], &dirty[..], &good.expose_secret()[..255]] {
        assert_eq!(finish(PlaintextRule::Padded, bad), Err(DecryptError));
    }
    assert_eq!(
        finish(PlaintextRule::Fixed(32), &[0; 31]),
        Err(DecryptError)
    );
    assert_eq!(finish(PlaintextRule::Fixed(32), &[0; 32]).unwrap(), [0; 32]);
    assert_eq!(
        finish(PlaintextRule::Unspecified, &[0; 32]),
        Err(DecryptError)
    );
    assert_eq!(finish(PlaintextRule::Unpadded, b"x").unwrap(), b"x");
    assert_eq!(DecryptError::from(ParseError::NonZeroPadding), DecryptError);
}

// ---------------------------------------------------------------------------------------------
// Parser (§9.5 rule 5)
// ---------------------------------------------------------------------------------------------

#[test]
fn parse_rejects_reserved_and_invalid_algorithms() {
    let mut env = vec![0x01, 0x01];
    env.resize(100, 0);
    for alg in 0..=u8::MAX {
        env[1] = alg;
        let implemented = matches!(alg, 0x01 | 0x10 | 0x12);
        assert_eq!(parse::parse(&env).is_ok(), implemented, "{alg:#04x}");
        if !implemented {
            assert_eq!(parse::parse(&env), Err(ParseError::InvalidValue));
        }
    }
    env[1] = 0x01;
    env[0] = 0x02;
    assert_eq!(parse::parse(&env), Err(ParseError::InvalidValue));
    assert_eq!(parse::parse(&[0x01; 17]), Err(ParseError::Truncated));
    assert_eq!(parse::parse(&[0x01; 89]), Err(ParseError::Truncated));
    let mut hpke = vec![0x01, 0x10];
    hpke.resize(65, 0);
    assert_eq!(parse::parse(&hpke), Err(ParseError::Truncated));
    hpke.push(0);
    let parsed = parse::parse(&hpke).unwrap();
    let EnvelopeRef::Hpke(h) = parsed else {
        unreachable!("0x10 parses as HPKE")
    };
    assert_eq!(h.alg_id(), AlgId::HpkeBaseX25519);
    assert!(h.ciphertext().is_empty());
    assert_eq!(h.enc(), &[0; 32]);
    assert_eq!(h.header(), &hpke[..18]);
    assert_eq!(h.key_id(), &[0; 16]);
    assert_eq!(h.tag(), &[0; 16]);
    assert_eq!(parsed.to_vec(), hpke);
}

proptest! {
    #[test]
    fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = parse::parse(&bytes);
        for p in Purpose::ALL {
            let _ = parse_for_purpose(&bytes, p.client_decrypt_allow_list());
        }
    }

    #[test]
    fn parse_then_serialise_is_the_identity(
        alg in prop_oneof![Just(0x01u8), Just(0x10u8), Just(0x12u8)],
        body in proptest::collection::vec(any::<u8>(), 88..400),
    ) {
        let mut env = vec![0x01, alg];
        env.extend_from_slice(&body);
        let parsed = parse::parse(&env).unwrap();
        prop_assert_eq!(parsed.alg_id().to_u8(), alg);
        prop_assert_eq!(parsed.encoded_len(), env.len());
        prop_assert_eq!(parsed.to_vec(), env);
    }

    #[test]
    fn random_ops_round_trip(
        data in proptest::collection::vec(any::<u8>(), 0..2000),
        device_seq in any::<u64>(),
        hlc in any::<u64>(),
        seed in any::<u64>(),
    ) {
        let mut rng = seeded_rng(seed);
        let k = Key32::generate(&mut rng);
        let ctx = ItemOpCtx { device_seq, hlc, ..op_ctx() };
        let env = seal(&mut rng, &k, &ctx, &data).unwrap();
        let opened = open(&k, &ctx, &env).unwrap();
        prop_assert_eq!(opened.expose_secret(), data.as_slice());
        // A random single-byte change anywhere is rejected.
        let i = usize::try_from(rng.next_u64() % env.len() as u64).unwrap();
        let mut bad = env.clone();
        bad[i] ^= 0x80;
        prop_assert_eq!(open(&k, &ctx, &bad).map(|_| ()), Err(DecryptError));
    }
}
