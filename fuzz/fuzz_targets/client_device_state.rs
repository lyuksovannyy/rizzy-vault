//! Fuzzes `rizzy-client`'s device-state record parser (ADR 0026 §2, §6): the record is read
//! back from a file anyone with the user's rights can change, so it is untrusted input.
//!
//! For each input:
//!
//! - [`DeviceRecord::parse`] never panics, and never accepts more than
//!   [`MAX_DEVICE_STATE_LEN`] bytes.
//! - One state has one encoding: a record that parses encodes back to the input, byte for
//!   byte, and parses again to the same stage and flags.
//! - A stage-2 record never has a pending record and always has `E_local`.
//! - The lifecycle steps the host runs on a parsed record (`with_pending` is not reachable
//!   from bytes; `promote_pending`, `without_pending`, `committed`) keep it encodable, and
//!   what they encode parses.
//!
//! No key is derived: the offline unlock behind a parsed record is one Argon2id run and is
//! covered by `rizzy-client`'s tests.
//!
//! ```text
//! cargo +nightly fuzz run client_device_state
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_client::ClientError;
use rizzy_client::store::record::{DeviceRecord, MAX_DEVICE_STATE_LEN, Stage};

/// A record the lifecycle steps produced encodes, and the encoding parses back to itself.
fn assert_canonical(record: &DeviceRecord) {
    let encoded = record
        .encode()
        .expect("a record built from a parsed one encodes");
    let again = DeviceRecord::parse(&encoded).expect("and its encoding parses");
    assert_eq!(
        again.encode().expect("encodes again").as_slice(),
        encoded.as_slice()
    );
}

fuzz_target!(|data: &[u8]| {
    let record = match DeviceRecord::parse(data) {
        Ok(record) => record,
        Err(e) => {
            assert!(matches!(
                e,
                ClientError::CacheCorrupt | ClientError::CacheUpdateRequired
            ));
            return;
        }
    };
    assert!(data.len() <= MAX_DEVICE_STATE_LEN);
    let encoded = record.encode().expect("a parsed record encodes");
    assert_eq!(encoded.as_slice(), data, "one state has one encoding");
    if record.stage() == Stage::SignupPending {
        assert!(record.has_local() && !record.has_pending());
    }
    let has_pending = record.has_pending();
    let promoted = DeviceRecord::parse(data)
        .expect("parses twice")
        .promote_pending();
    assert!(!promoted.has_pending());
    // A pending record always carries `E_local'`.
    assert!(!has_pending || promoted.has_local());
    assert_canonical(&promoted);
    assert_canonical(&DeviceRecord::parse(data).expect("parses").without_pending());
    let committed = record.committed();
    assert_eq!(committed.stage(), Stage::Committed);
    assert_canonical(&committed);
});
