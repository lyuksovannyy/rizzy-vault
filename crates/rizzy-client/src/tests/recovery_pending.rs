// SPDX-License-Identifier: AGPL-3.0-only

//! The recovery-pending stage of the device-state record ([ADR 0046] §1, §5): the known-answer
//! vector of a stage-3 record, the parser's and encoder's stage-3 rules (`has_local = 1`, no
//! pending record, and no `E_ks`, ADR 0057 §2), the refusals of the ordinary unlocks and of the
//! load, `unlock_recovery_pending` with real keys, the `pending_commit` rule of `load::open`,
//! the floors, the device authentication without reconciliation objects, and a property test
//! over every stage and flag combination.
//!
//! The flow against the real server, and the crash cases of ADR 0046 §5, are
//! `rizzy-server`'s `tests/http/recovery.rs` and `rv`'s `tests/account.rs`.
//!
//! [ADR 0046]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0046-recovery-pending-device-stage.md

use proptest::prelude::*;
use rizzy_core::kdf::KdfId;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::DeviceKind;

use super::*;
use crate::device::{KeystoreWrap, LocalWrap};
use crate::session::{device_auth_finish_recovery_pending, device_auth_start_recovery_pending};
use crate::store::floors::Floors;
use crate::store::load;
use crate::store::record::{DeviceRecord, PendingRecord, Stage};
use crate::store::rows::{CacheRows, Write};

/// A symmetric envelope's bytes, enough for the parser: the header and a minimal body.
fn envelope(fill: u8) -> Vec<u8> {
    let mut out = vec![0x01, 0x01];
    out.extend(core::iter::repeat_n(fill, 88));
    out
}

/// The fixed fields of the ADR 0026 vectors in `stage`, with the flags given.
fn record(stage: Stage, has_local: bool, has_ks: bool, pending: bool) -> DeviceRecord {
    DeviceRecord {
        stage,
        server_origin: ServerOrigin::parse(ORIGIN).unwrap(),
        account_id: AccountId::from_bytes([0xa1; 16]),
        device_id: DeviceId::from_bytes([0xd2; 16]),
        device_kind: DeviceKind::DesktopCli,
        secret_key: SecretKey::from_slice(&[0x11; 16]).unwrap(),
        device_salt: [0x22; 16],
        kdf_id: KdfId::DEFAULT,
        device_keys_wrap: envelope(0x33),
        local_wrap: has_local.then(|| LocalWrap {
            envelope: envelope(0x44),
            account_key_epoch: 7,
            password_epoch: 3,
        }),
        keystore_wrap: has_ks.then(|| KeystoreWrap {
            envelope: envelope(0x88),
            account_key_epoch: 7,
        }),
        forward: Vec::new(),
        pending: pending.then(|| PendingRecord {
            secret_key: SecretKey::from_slice(&[0x55; 16]).unwrap(),
            device_salt: [0x66; 16],
            kdf_id: KdfId::DEFAULT,
            local_wrap: LocalWrap {
                envelope: envelope(0x77),
                account_key_epoch: 8,
                password_epoch: 4,
            },
            device_keys_wrap: None,
        }),
    }
}

/// The bytes of [`record`], written out field by field from ADR 0057 §2 with the stage byte
/// of ADR 0046 §1.
fn record_bytes(stage: u8, has_local: bool, has_ks: bool, pending: bool) -> Vec<u8> {
    let bytes_of = |out: &mut Vec<u8>, x: &[u8]| {
        out.extend_from_slice(&u32::try_from(x.len()).unwrap().to_be_bytes());
        out.extend_from_slice(x);
    };
    let mut out = Vec::new();
    out.extend_from_slice(&[0x00, 0x02, stage]);
    bytes_of(&mut out, ORIGIN.as_bytes());
    out.extend_from_slice(&[0xa1; 16]);
    out.extend_from_slice(&[0xd2; 16]);
    out.push(1);
    out.extend_from_slice(&[0x11; 16]);
    out.extend_from_slice(&[0x22; 16]);
    out.extend_from_slice(&[0x00, 0x01]);
    bytes_of(&mut out, &envelope(0x33));
    if has_local {
        out.push(1);
        out.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 3]);
        bytes_of(&mut out, &envelope(0x44));
    } else {
        out.push(0);
    }
    if has_ks {
        out.push(1);
        out.extend_from_slice(&[0, 0, 0, 7]);
        bytes_of(&mut out, &envelope(0x88));
    } else {
        out.push(0);
    }
    out.push(0);
    if pending {
        out.push(1);
        out.extend_from_slice(&[0x55; 16]);
        out.extend_from_slice(&[0x66; 16]);
        out.extend_from_slice(&[0x00, 0x01]);
        out.extend_from_slice(&[0, 0, 0, 8, 0, 0, 0, 4]);
        bytes_of(&mut out, &envelope(0x77));
        bytes_of(&mut out, &[]);
    } else {
        out.push(0);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// ADR 0046 §5: the known-answer vector of a stage-3 record. It differs from the committed
/// vector in the stage byte only, and parses back to itself (one state, one encoding).
#[test]
fn recovery_pending_vector() {
    let encoded = record(Stage::RecoveryPending, true, false, false)
        .encode()
        .unwrap();
    assert_eq!(hex(&encoded), hex(&record_bytes(3, true, false, false)));
    // Fixed here so that a change of the layout cannot pass by changing encoder and helper
    // together: version 2, stage 3, then the origin's length.
    assert_eq!(hex(&encoded[..7]), "00020300000019");
    assert_eq!(
        encoded.len(),
        3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + 1 + 8 + 94 + 1 + 1 + 1
    );
    // `E_local`'s last byte, `has_ks = 0`, `forward_count = 0`, `pending = 0`.
    assert_eq!(hex(&encoded[encoded.len() - 4..]), "44000000");
    let committed = record(Stage::Committed, true, false, false)
        .encode()
        .unwrap();
    let differs: Vec<usize> = (0..encoded.len())
        .filter(|&i| encoded[i] != committed[i])
        .collect();
    assert_eq!(differs, [2]);
    for capable in [false, true] {
        let parsed = DeviceRecord::parse(&encoded, capable).unwrap();
        assert_eq!(parsed.stage(), Stage::RecoveryPending);
        assert!(parsed.stage().is_pending());
        assert!(parsed.has_local() && !parsed.has_pending() && !parsed.has_keystore());
        assert_eq!(parsed.encode().unwrap().as_slice(), encoded.as_slice());
        // Finalising (ADR 0046 §2, §3) changes the stage byte and nothing else.
        let finalised = parsed.committed();
        assert_eq!(finalised.stage(), Stage::Committed);
        assert_eq!(finalised.encode().unwrap().as_slice(), committed.as_slice());
    }
}

/// ADR 0088 §1 "stage 3 is valid in both": a version-1 stage-3 record (the stage-3 vector
/// with `record_version = 1` and the `has_ks`/`forward_count` bytes removed) parses with
/// `keystore_capable` false and true, gives [`Stage::RecoveryPending`], and encodes to exactly
/// the committed version-2 stage-3 vector (ADR 0088 §1 "encode always writes version 2";
/// ADR 0057 §3 upgrade on the first write).
#[test]
fn recovery_pending_v1_vector_upgrades_to_v2() {
    let v2 = record_bytes(3, true, false, false);
    assert_eq!(&v2[..2], &[0x00, 0x02]);
    // The v1 vector: same bytes as the v2 stage-3 vector, with `00 02` → `00 01` at the start
    // and the `has_ks = 0` and `forward_count = 0` bytes removed. Those two bytes sit right
    // after `[local]` and before the `pending` flag; `[local]` ends at the last envelope byte,
    // so they are the two bytes before the trailing `pending = 0` byte.
    let mut v1 = v2.clone();
    v1[0] = 0x00;
    v1[1] = 0x01;
    let pending_flag = v1.pop().unwrap();
    assert_eq!(pending_flag, 0);
    let forward_count = v1.pop().unwrap();
    assert_eq!(forward_count, 0);
    let has_ks = v1.pop().unwrap();
    assert_eq!(has_ks, 0);
    v1.push(pending_flag);
    assert_eq!(v1.len(), v2.len() - 2);
    assert_eq!(v1.len(), 297);
    assert_eq!(hex(&v1[..7]), "00010300000019");

    let v2_committed = record(Stage::RecoveryPending, true, false, false)
        .encode()
        .unwrap();
    assert_eq!(hex(&v2_committed), hex(&v2));

    for capable in [false, true] {
        let parsed = DeviceRecord::parse(&v1, capable).unwrap();
        assert_eq!(parsed.stage(), Stage::RecoveryPending);
        assert!(parsed.has_local() && !parsed.has_pending() && !parsed.has_keystore());
        // encode writes version 2, so a v1 record upgrades to the committed v2 vector.
        assert_eq!(hex(&parsed.encode().unwrap()), hex(&v2_committed));
    }
}

/// ADR 0046 §1 and ADR 0057 §2: stage 3 requires `E_local`, refuses a nested pending record
/// and refuses `E_ks`, in the parser (`CacheCorrupt`) and in the encoder (`Internal`, so no
/// such record is ever written). A stage byte above 3 is corrupt.
#[test]
fn recovery_pending_rules() {
    for (has_local, has_ks, pending) in [
        (false, false, false),
        (true, false, true),
        (true, true, false),
        (true, true, true),
    ] {
        let bytes = record_bytes(3, has_local, has_ks, pending);
        for capable in [false, true] {
            assert_eq!(
                DeviceRecord::parse(&bytes, capable).unwrap_err(),
                ClientError::CacheCorrupt,
                "{has_local} {has_ks} {pending} {capable}"
            );
        }
        assert_eq!(
            record(Stage::RecoveryPending, has_local, has_ks, pending)
                .encode()
                .unwrap_err(),
            ClientError::Internal
        );
    }
    // The same flags in stage 1 parse (`E_ks` behind the gate): the rule is stage 3's.
    assert!(DeviceRecord::parse(&record_bytes(1, true, true, false), true).is_ok());
    assert!(DeviceRecord::parse(&record_bytes(1, true, false, true), false).is_ok());
    for stage in [0u8, 4, 5, 0xff] {
        assert_eq!(
            DeviceRecord::parse(&record_bytes(stage, true, false, false), false).unwrap_err(),
            ClientError::CacheCorrupt
        );
    }
}

/// A stage-3 record does not unlock for ordinary use (`RecoveryPending`, before any key is
/// derived), nor loads; `unlock_recovery_pending` is for stage 3 only.
#[test]
fn recovery_pending_does_not_unlock() {
    let pending = record(Stage::RecoveryPending, true, false, false);
    assert_eq!(
        pending.unlock(PASSWORD).err(),
        Some(ClientError::RecoveryPending)
    );
    assert_eq!(
        pending.unlock_keystore(&[0; 32]).err(),
        Some(ClientError::RecoveryPending)
    );
    for stage in [Stage::Committed, Stage::SignupPending] {
        assert_eq!(
            record(stage, true, false, false)
                .unlock_recovery_pending(PASSWORD)
                .err(),
            Some(ClientError::InvalidInput)
        );
    }
    assert_eq!(
        device_auth_start_recovery_pending(&record(Stage::Committed, true, false, false))
            .unwrap_err(),
        ClientError::InvalidInput
    );
    assert_eq!(ClientError::RecoveryPending.code(), "recovery_pending");
}

/// The lifecycle with real keys, against the fake server: a stage-3 record built from a
/// device state unlocks with its password only, through `unlock_recovery_pending`, to the same
/// keys; its cache rows open only with `pending_commit`; the load refuses it; the floors admit
/// it; the device authentication of ADR 0046 §3 step 2 carries no reconciliation objects and
/// succeeds exactly for a device the server lists; and finalising makes an ordinary record.
#[test]
fn recovery_pending_lifecycle() {
    let mut rng = ChaCha20Rng::seed_from_u64(46);
    let mut server = Server::new(46);
    let signed = signup(&mut server, &mut rng, DeviceKind::DesktopCli);
    let state = signed.device.unwrap();
    let stage3 = state.record(Stage::RecoveryPending).unwrap();
    assert_eq!(
        stage3.unlock(PASSWORD).err(),
        Some(ClientError::RecoveryPending)
    );
    assert_eq!(
        stage3.unlock_recovery_pending("not the password").err(),
        Some(ClientError::WrongPasswordOrSecretKey)
    );
    let unlocked = stage3.unlock_recovery_pending(PASSWORD).unwrap();
    assert_eq!(unlocked.account_id(), state.account_id);
    assert_eq!(unlocked.device_id(), state.device_id);
    assert_eq!(
        unlocked.account_key.key_id().unwrap(),
        signed.unlocked.account_key.key_id().unwrap()
    );

    // The cache rows of a stage-3 record: `pending_commit` must be there, and only then.
    let mut changeset = crate::store::create_writes(&stage3).unwrap();
    let mut rows = CacheRows::default();
    rows.apply(&changeset);
    assert_eq!(
        load::open(&rows, false).unwrap_err(),
        ClientError::CacheCorrupt
    );
    changeset.push(Write::PendingCommit(Some(b"{}".to_vec())));
    let mut floors = Floors::empty();
    floors.admit(&changeset).unwrap();
    let mut rows = CacheRows::default();
    rows.apply(&changeset);
    let opened = load::open(&rows, false).unwrap();
    assert_eq!(opened.stage(), Stage::RecoveryPending);
    assert_eq!(
        load::load(&rows, &opened, &unlocked, T0).err().unwrap(),
        ClientError::RecoveryPending
    );
    // Finalised: `pending_commit` goes with the stage, and the ordinary unlock works.
    let finalised = crate::store::finalize_writes(&opened.committed()).unwrap();
    rows.apply(&finalised);
    let committed = load::open(&rows, false).unwrap();
    assert_eq!(committed.stage(), Stage::Committed);
    assert!(rows.pending_commit.is_none());
    assert!(committed.unlock(PASSWORD).is_ok());

    // ADR 0046 §3 step 2: the record's own ids, never reconciliation objects.
    let start = device_auth_start_recovery_pending(&stage3).unwrap();
    assert!(start.reconciliation.is_none());
    assert_eq!(start.device_id.to_bytes(), state.device_id.to_bytes());
    let challenge = server.device_auth_start(&start);
    let finish = device_auth_finish_recovery_pending(&stage3, &unlocked, &challenge).unwrap();
    assert!(finish.reconciliation.is_none());
    assert!(server.device_auth_finish(&finish).is_ok());
    // Keys of another device id are refused locally (the server's `401` for a device it does not
    // list is `rizzy-server`'s test).
    let mut stranger = state.record(Stage::RecoveryPending).unwrap();
    stranger.device_id = DeviceId::from_bytes([0xee; 16]);
    let challenge =
        server.device_auth_start(&device_auth_start_recovery_pending(&stranger).unwrap());
    assert_eq!(
        device_auth_finish_recovery_pending(&stranger, &unlocked, &challenge).unwrap_err(),
        ClientError::InvalidInput
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Over every stage byte and flag combination, on either side of the platform gate: the
    /// record parses exactly when ADR 0026 §2, ADR 0057 §2 and ADR 0046 §1 allow it, encodes
    /// back to itself, and a pending stage never unlocks.
    #[test]
    fn stage_rules_hold_for_every_combination(
        stage in 0u8..=5,
        has_local in any::<bool>(),
        has_ks in any::<bool>(),
        pending in any::<bool>(),
        capable in any::<bool>(),
    ) {
        let bytes = record_bytes(stage, has_local, has_ks, pending);
        let pending_stage = stage == 2 || stage == 3;
        let allowed = (1..=3).contains(&stage)
            && !(pending_stage && (!has_local || pending))
            && !(stage == 3 && has_ks)
            && !(has_ks && (!has_local || !capable));
        match DeviceRecord::parse(&bytes, capable) {
            Ok(parsed) => {
                prop_assert!(allowed);
                prop_assert_eq!(parsed.encode().unwrap().to_vec(), bytes);
                prop_assert_eq!(parsed.stage().is_pending(), pending_stage);
                if pending_stage {
                    prop_assert!(matches!(
                        parsed.unlock(PASSWORD).err(),
                        Some(ClientError::SignupPending | ClientError::RecoveryPending)
                    ));
                }
            }
            Err(e) => {
                prop_assert!(!allowed);
                prop_assert_eq!(e, ClientError::CacheCorrupt);
            }
        }
    }
}
