// SPDX-License-Identifier: AGPL-3.0-only

//! Device-state record version 2 ([ADR 0057] §5): known-answer vectors of a record with `E_ks`
//! and forward envelopes and at the `forward_count` boundary, the canonical form, the
//! `has_ks = 1 ⇒ has_local = 1` rule and the platform gate (INV-81) under both
//! `keystore_capable` values, in the parser and in the floors, and the v1 → v2 upgrade.
//!
//! [ADR 0057]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0057-device-state-v2-keystore.md

use proptest::prelude::*;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::DeviceKind;

use super::*;
use crate::device::{ForwardWrap, KeystoreWrap, LocalWrap, MAX_FORWARD_COUNT};
use crate::store::floors::Floors;
use crate::store::record::{DeviceRecord, MAX_DEVICE_STATE_LEN, RECORD_VERSION, Stage};
use crate::store::rows::{Changeset, Write};

/// A symmetric envelope's bytes, enough for the parser: the header and a minimal body.
fn envelope(fill: u8) -> Vec<u8> {
    let mut out = vec![0x01, 0x01];
    out.extend(core::iter::repeat_n(fill, 88));
    out
}

/// The record of the vectors: the fixed fields of the ADR 0026 vectors, `E_local` at
/// account-key epoch 7, `E_ks` (if any) at the end of the chain, and `forward` envelopes
/// `7 → 8 → … → 7 + forward`.
fn ks_record(has_local: bool, has_ks: bool, forward: u32) -> DeviceRecord {
    DeviceRecord {
        stage: Stage::Committed,
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
            account_key_epoch: 7 + forward,
        }),
        forward: (0..forward)
            .map(|i| ForwardWrap {
                envelope: envelope(0x90 + u8::try_from(i).unwrap()),
                from_account_key_epoch: 7 + i,
                to_account_key_epoch: 8 + i,
            })
            .collect(),
        pending: None,
    }
}

/// The vector bytes, written out field by field from ADR 0057 §2.
fn ks_bytes(has_local: bool, has_ks: bool, forward: u32) -> Vec<u8> {
    let bytes_of = |out: &mut Vec<u8>, x: &[u8]| {
        out.extend_from_slice(&u32::try_from(x.len()).unwrap().to_be_bytes());
        out.extend_from_slice(x);
    };
    let mut out = vec![0x00, 0x02, 0x01];
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
        out.extend_from_slice(&(7 + forward).to_be_bytes());
        bytes_of(&mut out, &envelope(0x88));
    } else {
        out.push(0);
    }
    out.push(u8::try_from(forward).unwrap());
    for i in 0..forward {
        out.extend_from_slice(&(7 + i).to_be_bytes());
        out.extend_from_slice(&(8 + i).to_be_bytes());
        bytes_of(&mut out, &envelope(0x90 + u8::try_from(i).unwrap()));
    }
    out.push(0);
    out
}

/// ADR 0057 §5: a v2 record with `has_ks = 1` and forward envelopes, and the boundary at 8,
/// against bytes written out from the grammar; each parses back to itself on a keystore-capable
/// host (one state, one encoding) and is refused as corrupt on any other (INV-81).
#[test]
fn v2_record_vectors() {
    for (has_ks, forward) in [(true, 1), (true, 2), (true, 8), (false, 2), (false, 8)] {
        let record = ks_record(true, has_ks, forward);
        let encoded = record.encode().unwrap();
        assert_eq!(
            hex_of(&encoded),
            hex_of(&ks_bytes(true, has_ks, forward)),
            "{has_ks} {forward}"
        );
        let parsed = DeviceRecord::parse(&encoded, true).unwrap();
        assert_eq!(parsed.has_keystore(), has_ks);
        assert_eq!(parsed.forward_count(), usize::try_from(forward).unwrap());
        assert_eq!(parsed.encode().unwrap().as_slice(), encoded.as_slice());
        // The gate only concerns `has_ks`: a forward chain alone parses everywhere.
        assert_eq!(
            DeviceRecord::parse(&encoded, false).map(|r| r.forward_count()),
            if has_ks {
                Err(ClientError::CacheCorrupt)
            } else {
                Ok(usize::try_from(forward).unwrap())
            }
        );
    }
    // Fixed here so that a layout change cannot pass by changing encoder and helper together:
    // the length of the one-forward vector and the bytes around `has_ks`.
    let one = ks_record(true, true, 1).encode().unwrap();
    assert_eq!(
        one.len(),
        3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + (1 + 8 + 94) + (1 + 4 + 94) + 1 + (8 + 94) + 1
    );
    let ks_at = 3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + 1 + 8 + 94;
    assert_eq!(hex_of(&one[ks_at..ks_at + 9]), "01000000080000005a");
    let count_at = ks_at + 1 + 4 + 94;
    assert_eq!(hex_of(&one[count_at..count_at + 9]), "010000000700000008");
    assert_eq!(one[one.len() - 1], 0);
    assert_eq!(RECORD_VERSION, 2);
    assert_eq!(MAX_FORWARD_COUNT, 8);
}

/// ADR 0057 §2: `forward_count` 9 is refused before any entry is read, under both gate values;
/// the encoder refuses to write it.
#[test]
fn nine_forward_envelopes_are_refused() {
    let mut nine = ks_bytes(true, false, 8);
    // Patch the count to 9 and append a ninth entry before the pending flag.
    let count_at = nine.len() - 1 - 8 * (8 + 4 + 90) - 1;
    assert_eq!(nine[count_at], 8);
    nine[count_at] = 9;
    let pending = nine.pop().unwrap();
    nine.extend_from_slice(&15u32.to_be_bytes());
    nine.extend_from_slice(&16u32.to_be_bytes());
    nine.extend_from_slice(&90u32.to_be_bytes());
    nine.extend_from_slice(&envelope(0x99));
    nine.push(pending);
    for capable in [false, true] {
        assert_eq!(
            DeviceRecord::parse(&nine, capable).unwrap_err(),
            ClientError::CacheCorrupt
        );
    }
    // 255 with no entries behind it is refused the same way.
    let mut many = ks_bytes(true, false, 0);
    let at = many.len() - 2;
    many[at] = 0xff;
    assert_eq!(
        DeviceRecord::parse(&many, true).unwrap_err(),
        ClientError::CacheCorrupt
    );
    let mut record = ks_record(true, false, 8);
    record.forward.push(ForwardWrap {
        envelope: envelope(0x99),
        from_account_key_epoch: 15,
        to_account_key_epoch: 16,
    });
    assert_eq!(record.encode().unwrap_err(), ClientError::Internal);
    // A full record still fits ADR 0026 §2's bound.
    assert!(ks_bytes(true, true, 8).len() <= MAX_DEVICE_STATE_LEN);
}

/// ADR 0057 §2: `has_ks = 1` requires `has_local = 1`; flags outside 0/1, a truncated `[ks]`
/// or forward entry, a non-envelope `E_ks` and a trailing byte are refused.
#[test]
fn v2_refusals() {
    for capable in [false, true] {
        assert_eq!(
            DeviceRecord::parse(&ks_bytes(false, true, 0), capable).unwrap_err(),
            ClientError::CacheCorrupt
        );
    }
    assert_eq!(
        ks_record(false, true, 0).encode().unwrap_err(),
        ClientError::Internal
    );
    let good = ks_bytes(true, true, 2);
    assert!(DeviceRecord::parse(&good, true).is_ok());
    let ks_at = 3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + 1 + 8 + 94;
    let mut flag = good.clone();
    flag[ks_at] = 2;
    assert!(DeviceRecord::parse(&flag, true).is_err());
    // `E_ks` that is not a symmetric envelope.
    let mut not_envelope = good.clone();
    not_envelope[ks_at + 1 + 4 + 4] = 0x02;
    assert!(DeviceRecord::parse(&not_envelope, true).is_err());
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(DeviceRecord::parse(&trailing, true).is_err());
    for cut in 1..good.len() {
        assert!(
            DeviceRecord::parse(&good[..cut], true).is_err(),
            "cut {cut}"
        );
    }
    // A pending flag outside 0/1 after the forward entries.
    let mut pending = good;
    let last = pending.len() - 1;
    pending[last] = 2;
    assert!(DeviceRecord::parse(&pending, true).is_err());
}

/// ADR 0057 §3: a v1 record reads as `has_ks = 0`, `forward_count = 0` and is written back as
/// version 2: the same bytes with the version raised and the two new zero bytes in place.
#[test]
fn v1_records_are_read_and_written_as_v2() {
    let v2 = ks_bytes(true, false, 0);
    // The v1 form: version 1, without the `has_ks` and `forward_count` bytes.
    let mut v1 = v2.clone();
    v1[1] = 1;
    let at = v1.len() - 3;
    v1.drain(at..at + 2);
    assert_eq!(v1.len() + 2, v2.len());
    for capable in [false, true] {
        let record = DeviceRecord::parse(&v1, capable).unwrap();
        assert!(!record.has_keystore());
        assert_eq!(record.forward_count(), 0);
        assert_eq!(hex_of(&record.encode().unwrap()), hex_of(&v2));
    }
    // A v1 record has no `has_ks`: one more byte where v2 has it is trailing data.
    let mut v1_with_flag = v1.clone();
    v1_with_flag.insert(at, 0);
    assert!(DeviceRecord::parse(&v1_with_flag, true).is_err());
    // Version 3 is "update required"; version 0 corrupt.
    let mut v3 = v2.clone();
    v3[1] = 3;
    assert_eq!(
        DeviceRecord::parse(&v3, true).unwrap_err(),
        ClientError::CacheUpdateRequired
    );
    let mut v0 = v2;
    v0[1] = 0;
    assert_eq!(
        DeviceRecord::parse(&v0, true).unwrap_err(),
        ClientError::CacheCorrupt
    );
}

/// INV-81 in the floors: a written record with `has_ks = 1` is admitted only after the host
/// turned the gate on; a record without `E_ks` is admitted either way.
#[test]
fn floors_apply_the_platform_gate() {
    let write = |has_ks: bool| crate::store::create_writes(&ks_record(true, has_ks, 1)).unwrap();
    let mut floors = Floors::empty();
    assert_eq!(floors.admit(&write(true)), Err(ClientError::Internal));
    assert!(floors.admit(&write(false)).is_ok());
    // A later write of a record with `E_ks` is refused too, one without it admitted.
    let mut later = Changeset::new();
    later.push(Write::DeviceState(
        ks_record(true, true, 1).encode().unwrap(),
    ));
    assert_eq!(floors.admit(&later), Err(ClientError::Internal));
    let mut later = Changeset::new();
    later.push(Write::DeviceState(
        ks_record(true, false, 2).encode().unwrap(),
    ));
    assert!(floors.admit(&later).is_ok());
    let mut capable = Floors::empty();
    capable.set_keystore_capable(true);
    assert!(capable.admit(&write(true)).is_ok());
}

/// The `Debug` form shows flags and counts, never envelope bytes or the Secret Key.
#[test]
fn v2_debug_is_redacted() {
    let shown = format!("{:?}", ks_record(true, true, 2));
    assert!(shown.contains("has_ks: true"));
    assert!(shown.contains("forward_count: 2"));
    assert!(!shown.contains("136"), "{shown}");
    assert!(!shown.contains("17, 17"), "{shown}");
}

proptest! {
    /// Round trip: any combination of the v2 fields encodes, parses (on a capable host) and
    /// encodes again to the same bytes.
    #[test]
    fn v2_round_trip(
        has_local in any::<bool>(),
        has_ks in any::<bool>(),
        forward in 0u32..=8,
        ks_epoch in any::<u32>(),
        epochs in proptest::collection::vec((any::<u32>(), any::<u32>()), 8),
        fill in any::<u8>(),
    ) {
        let mut record = ks_record(has_local, has_ks && has_local, forward);
        if let Some(ks) = record.keystore_wrap.as_mut() {
            ks.account_key_epoch = ks_epoch;
            ks.envelope = envelope(fill);
        }
        for (step, (from, to)) in record.forward.iter_mut().zip(epochs) {
            step.from_account_key_epoch = from;
            step.to_account_key_epoch = to;
        }
        let encoded = record.encode().unwrap();
        prop_assert!(encoded.len() <= MAX_DEVICE_STATE_LEN);
        let parsed = DeviceRecord::parse(&encoded, true).unwrap();
        prop_assert_eq!(parsed.encode().unwrap().to_vec(), encoded.to_vec());
        prop_assert_eq!(
            DeviceRecord::parse(&encoded, false).is_ok(),
            !(has_ks && has_local)
        );
    }

    /// Any one flipped byte of a v2 record with `E_ks` and a chain parses to a record that
    /// encodes back to the flipped bytes, or is refused; never a panic.
    #[test]
    fn v2_flipped_bytes_stay_canonical(at in 0usize..1000, bit in 0u8..8) {
        let mut bytes = ks_bytes(true, true, 3);
        let at = at % bytes.len();
        bytes[at] ^= 1 << bit;
        for capable in [false, true] {
            if let Ok(record) = DeviceRecord::parse(&bytes, capable) {
                prop_assert_eq!(record.encode().unwrap().to_vec(), bytes.clone());
            }
        }
    }
}
