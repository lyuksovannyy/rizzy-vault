// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzzes `rizzy-client`'s device-state record parser (ADR 0026 §2, §6; record version 2, ADR
//! 0057 §2, §5; the recovery-pending stage 3, ADR 0046 §1, §5): the record is read back from a file anyone with the user's rights can change,
//! so it is untrusted input.
//!
//! Each input is parsed under both values of the platform gate `keystore_capable`. For each:
//!
//! - [`DeviceRecord::parse`] never panics, and never accepts more than
//!   [`MAX_DEVICE_STATE_LEN`] bytes.
//! - The gate only concerns `has_ks` (INV-81): a record parses without the gate exactly when
//!   it parses with it and has no `E_ks`; a refusal for the gate is `CacheCorrupt`.
//! - `has_ks = 1` always comes with `E_local`, and `forward_count` is at most
//!   [`MAX_FORWARD_COUNT`].
//! - One state has one encoding: a version-2 record encodes back to the input byte for byte; a
//!   version-1 record encodes to its version-2 form (two bytes longer, `has_ks = 0`, no
//!   forward envelopes), which is canonical in turn.
//! - A stage-2 or stage-3 record never has a pending record and always has `E_local`; a
//!   stage-3 record never has `E_ks` (ADR 0057 §2). Neither unlocks: `unlock` answers
//!   `SignupPending` or `RecoveryPending` before any key is derived.
//! - The stage byte is 1, 2 or 3.
//! - The lifecycle steps the host runs on a parsed record (`with_pending` is not reachable
//!   from bytes; `promote_pending`, `without_pending`, `committed`) keep it encodable, and
//!   what they encode parses under the same gate.
//!
//! No key is derived: the offline and keystore unlocks behind a parsed record are covered by
//! `rizzy-client`'s tests.
//!
//! ```text
//! cargo +nightly fuzz run client_device_state
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::ClientError;
use rizzy_client::device::MAX_FORWARD_COUNT;
use rizzy_client::store::record::{DeviceRecord, MAX_DEVICE_STATE_LEN, Stage};

/// A record the lifecycle steps produced encodes, and the encoding parses back to itself.
fn assert_canonical(record: &DeviceRecord, capable: bool) {
    let encoded = record
        .encode()
        .expect("a record built from a parsed one encodes");
    let again = DeviceRecord::parse(&encoded, capable).expect("and its encoding parses");
    assert_eq!(
        again.encode().expect("encodes again").as_slice(),
        encoded.as_slice()
    );
}

/// The checks of the module docs for one value of the gate.
fn check(data: &[u8], capable: bool) -> Option<bool> {
    let record = match DeviceRecord::parse(data, capable) {
        Ok(record) => record,
        Err(e) => {
            assert!(matches!(
                e,
                ClientError::CacheCorrupt | ClientError::CacheUpdateRequired
            ));
            return None;
        }
    };
    assert!(data.len() <= MAX_DEVICE_STATE_LEN);
    assert!(!record.has_keystore() || (capable && record.has_local()));
    assert!(record.forward_count() <= MAX_FORWARD_COUNT);
    let encoded = record.encode().expect("a parsed record encodes");
    match data.get(..2) {
        Some([0, 2]) => assert_eq!(encoded.as_slice(), data, "one state has one encoding"),
        Some([0, 1]) => {
            assert_eq!(encoded.len(), data.len() + 2, "v1 is written as v2");
            assert_eq!(encoded.get(..2), Some(&[0u8, 2][..]));
            assert!(!record.has_keystore() && record.forward_count() == 0);
            assert_canonical(&record, capable);
        }
        _ => panic!("only record versions 1 and 2 parse"),
    }
    match record.stage() {
        Stage::Committed => assert_eq!(data.get(2), Some(&1)),
        Stage::SignupPending => {
            assert_eq!(data.get(2), Some(&2));
            assert!(record.has_local() && !record.has_pending());
            assert_eq!(record.unlock("").err(), Some(ClientError::SignupPending));
        }
        Stage::RecoveryPending => {
            assert_eq!(data.get(2), Some(&3));
            assert!(record.has_local() && !record.has_pending() && !record.has_keystore());
            assert_eq!(record.unlock("").err(), Some(ClientError::RecoveryPending));
            assert_eq!(
                record.unlock_keystore(&[0; 32]).err(),
                Some(ClientError::RecoveryPending)
            );
        }
    }
    let has_ks = record.has_keystore();
    let has_pending = record.has_pending();
    let promoted = DeviceRecord::parse(data, capable)
        .expect("parses twice")
        .promote_pending();
    assert!(!promoted.has_pending());
    // A pending record always carries `E_local'`.
    assert!(!has_pending || promoted.has_local());
    assert_canonical(&promoted, capable);
    assert_canonical(
        &DeviceRecord::parse(data, capable)
            .expect("parses")
            .without_pending(),
        capable,
    );
    let committed = record.committed();
    assert_eq!(committed.stage(), Stage::Committed);
    assert_canonical(&committed, capable);
    Some(has_ks)
}

fuzz_target!(|data: &[u8]| {
    let gated = check(data, false);
    let capable = check(data, true);
    // Without the gate a record parses exactly when it parses with it and has no `E_ks`.
    assert_eq!(gated.is_some(), capable == Some(false));
    if capable == Some(true) {
        assert_eq!(
            DeviceRecord::parse(data, false).map(|_| ()),
            Err(ClientError::CacheCorrupt)
        );
    }
});
