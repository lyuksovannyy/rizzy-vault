//! Fuzzes the snapshot-data parser of the item record on live snapshots (ADR 0018 §5
//! `parse_snapshot`, record kind `0x02`), which reads the decrypted `data` of `ITEM_SNAPSHOT`
//! envelopes: every register, history group and value of an item. The parser must never panic,
//! never allocate in proportion to a count before checking it against the input, and accept
//! only the one canonical encoding of each state.
//!
//! Input layout: a canonical version vector (ADR 0012 §3), which stands for the snapshot
//! header's covered VV, then the live snapshot data without its kind byte, which the target
//! supplies so that every input exercises the live layout. Inputs whose prefix is not a
//! canonical vector are skipped: the `sync_types` target covers that decoder.
//!
//! When [`parse_snapshot`] accepts:
//!
//! - [`encode_snapshot`] gives back exactly the data, and [`canonical_state`] is
//!   `u16 1 ‖ covered VV ‖ data` (ADR 0018 §1, §4);
//! - the state holds what §4 and §5 promise: at most 12 MiB; 1 to 4,096 registers, the first
//!   `@lifecycle`, keys strictly ascending; at most 4,096 history groups, keys strictly
//!   ascending and each the key of a current register; 1 to 256 entries per group, dots
//!   strictly ascending and covered by the covered VV; `@lifecycle` values the single byte
//!   `0x01` or `0x02`; no dot both in a register and in its history group; values of at most
//!   64 KiB;
//! - [`parse_op`] refuses the same bytes (§5 rule 1).
//!
//! Part of CRYPTO.md §15 item 7, "item-record parsers" (ADR 0018 §12: snapshot data).
//!
//! ```text
//! cargo +nightly fuzz run record_snapshot
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::encoding::Reader;
use rizzy_sync::record::{
    Lifecycle, MAX_GROUPS, MAX_SNAPSHOT_DATA_LEN, MAX_VALUE_LEN, MAX_VALUES, Register,
    SnapshotData, canonical_state, encode_snapshot, parse_op, parse_snapshot,
};
use rizzy_sync::vv::VersionVector;

/// Checks one register production: 1 to 256 entries, dots strictly ascending and covered,
/// values within the limit, and `@lifecycle` values that name `Active` or `Trashed`.
fn check_register(register: &Register<'_>, covered: &VersionVector) {
    let entries = register.entries();
    assert!((1..=MAX_VALUES).contains(&entries.len()));
    assert!(
        entries
            .windows(2)
            .all(|p| matches!(p, [a, b] if a.dot() < b.dot()))
    );
    for e in entries {
        assert!(covered.covers(e.dot()));
        assert!(e.value().len() <= MAX_VALUE_LEN);
        if register.key().is_lifecycle() {
            assert!(Lifecycle::from_register_value(e.value()).is_some());
        }
    }
}

/// Whether the keys of `groups` are strictly ascending.
fn ascending(groups: &[Register<'_>]) -> bool {
    groups
        .windows(2)
        .all(|p| matches!(p, [a, b] if a.key() < b.key()))
}

fuzz_target!(|input: &[u8]| {
    let mut reader = Reader::new(input);
    let Ok(covered) = VersionVector::read(&mut reader) else {
        return;
    };
    let data = [&[0x02][..], reader.rest()].concat();
    let Ok(snapshot) = parse_snapshot(&covered, &data) else {
        return;
    };
    let again = encode_snapshot(&covered, &snapshot).expect("an accepted snapshot encodes");
    assert_eq!(again.expose_secret(), data.as_slice());
    let state = canonical_state(&covered, &snapshot).expect("an accepted state encodes");
    let prefix = [
        &[0x00, 0x01][..],
        &covered.to_vec().expect("a decoded vector encodes"),
    ]
    .concat();
    assert_eq!(state.expose_secret(), [prefix.as_slice(), &data].concat());
    assert!(data.len() <= MAX_SNAPSHOT_DATA_LEN);
    assert!(parse_op(&data).is_err());

    let SnapshotData::Live(live) = snapshot else {
        panic!("record kind 0x02 parsed as a tombstone");
    };
    let (registers, history) = (live.registers(), live.history());
    assert!((1..=MAX_GROUPS).contains(&registers.len()));
    assert!(history.len() <= MAX_GROUPS);
    assert!(registers.first().is_some_and(|r| r.key().is_lifecycle()));
    assert!(ascending(registers) && ascending(history));
    for register in registers.iter().chain(history) {
        check_register(register, &covered);
    }
    for group in history {
        let current = registers
            .iter()
            .find(|r| r.key() == group.key())
            .expect("rule 7: every history group has a current register");
        let shared = group
            .entries()
            .iter()
            .any(|h| current.entries().iter().any(|c| c.dot() == h.dot()));
        assert!(!shared, "§4 uniqueness: a dot twice under one key");
    }
});
