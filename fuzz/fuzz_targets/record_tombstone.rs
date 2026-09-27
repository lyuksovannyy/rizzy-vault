//! Fuzzes the snapshot-data parser of the item record on tombstones (ADR 0018 §5
//! `parse_snapshot`, record kind `0x03`), which clients keep for the life of the vault and
//! read back on every load. The parser must never panic, never allocate in proportion to a
//! count before checking it against the input, and accept only the one canonical encoding of
//! each tombstone.
//!
//! Input layout: a canonical version vector (ADR 0012 §3), which stands for the snapshot
//! header's covered VV, then the tombstone data without its kind byte, which the target
//! supplies so that every input exercises the tombstone layout. Inputs whose prefix is not a
//! canonical vector are skipped: the `sync_types` target covers that decoder.
//!
//! When [`parse_snapshot`] accepts:
//!
//! - [`encode_snapshot`] gives back exactly the data, and [`canonical_state`] is
//!   `u16 1 ‖ covered VV ‖ data` (ADR 0018 §1, §4);
//! - the tombstone holds what §4 and §5 promise: `purge_dot` and every entry of `c` covered by
//!   the covered VV; at most 4,096 late registers, keys strictly ascending, never
//!   `@lifecycle`; 1 to 256 values per late register, dots strictly ascending, covered by the
//!   covered VV and not by `c`; values of at most 64 KiB; data of at most 12 MiB, and with no
//!   late register exactly 53 + 24·c bytes (ADR 0018 §3);
//! - [`parse_op`] refuses the same bytes (§5 rule 1).
//!
//! Part of CRYPTO.md §15 item 7, "item-record parsers" (ADR 0018 §12: tombstone).
//!
//! ```text
//! cargo +nightly fuzz run record_tombstone
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::encoding::Reader;
use rizzy_sync::record::{
    MAX_GROUPS, MAX_SNAPSHOT_DATA_LEN, MAX_VALUE_LEN, MAX_VALUES, SnapshotData, canonical_state,
    encode_snapshot, parse_op, parse_snapshot,
};
use rizzy_sync::vv::VersionVector;

fuzz_target!(|input: &[u8]| {
    let mut reader = Reader::new(input);
    let Ok(covered) = VersionVector::read(&mut reader) else {
        return;
    };
    let data = [&[0x03][..], reader.rest()].concat();
    let Ok(snapshot) = parse_snapshot(&covered, &data) else {
        return;
    };
    let again = encode_snapshot(&covered, &snapshot).expect("an accepted tombstone encodes");
    assert_eq!(again.expose_secret(), data.as_slice());
    let state = canonical_state(&covered, &snapshot).expect("an accepted state encodes");
    let prefix = [&[0x00, 0x01][..], &covered.to_vec().expect("a decoded vector encodes")].concat();
    assert_eq!(state.expose_secret(), [prefix.as_slice(), &data].concat());
    assert!(data.len() <= MAX_SNAPSHOT_DATA_LEN);
    assert!(parse_op(&data).is_err());

    let SnapshotData::Tombstone(tombstone) = snapshot else {
        panic!("record kind 0x03 parsed as a live snapshot");
    };
    let c = tombstone.context();
    assert!(covered.covers(tombstone.purge_dot()));
    assert!(c.entries().all(|d| covered.covers(d)));
    let late = tombstone.late();
    assert!(late.len() <= MAX_GROUPS);
    assert!(late.windows(2).all(|p| matches!(p, [a, b] if a.key() < b.key())));
    if late.is_empty() {
        assert_eq!(data.len(), 53 + 24 * c.len());
    }
    for register in late {
        assert!(!register.key().is_lifecycle());
        let entries = register.entries();
        assert!((1..=MAX_VALUES).contains(&entries.len()));
        assert!(entries.windows(2).all(|p| matches!(p, [a, b] if a.dot() < b.dot())));
        for e in entries {
            assert!(covered.covers(e.dot()) && !c.covers(e.dot()));
            assert!(e.value().len() <= MAX_VALUE_LEN);
        }
    }
});
