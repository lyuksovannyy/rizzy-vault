//! Record unit tests.
//!
//! - The kind and offset each rejection reports, on representative inputs (the negative
//!   vectors in [`super::vectors`] cover every rule; these pin the local diagnostics).
//! - Rules 5 and 6 on history groups and late registers as well as current registers: m = 0,
//!   `@lifecycle` values and coverage.
//! - "Nothing else rejects a version-1 record" (ADR 0018 §5): each state the ADR lists as
//!   parsing, and values and keys no M1 schema knows, parse and are carried verbatim.
//! - Every §10 limit at its boundary, on the parser (fed raw bytes, so that no writer refuses
//!   first) and on the writers; the op and snapshot data limits apply before decoding; the
//!   parser's `count × minimum size ≤ remaining input` check at its exact boundary for every
//!   count.
//! - The writers refuse what the parser refuses; [`canonical_state`] lays out
//!   `u16 1 ‖ covered VV ‖ data` and has an encoding for an oversize state.
//! - Keys, values, the lifecycle marker and whether a snapshot is live or a tombstone never
//!   reach `Debug`, `Display` or an error.
//! - The record layer takes a key exactly when `rizzy-core`'s schema layer accepts it, on
//!   every path: [`FieldKey::new`], op writes, live registers and late registers.
//! - The small API: [`FieldKey::new`], [`Lifecycle`], [`RecordKind`], [`RecordErrorKind::rule`].

use rizzy_core::ids::SymmetricKeyId;

use super::testkit::{Spec, dot, hlc, key, key_of_len, record_layer_accepts, to_hex, vv};
use super::*;

/// Device bytes.
const A: u8 = 0xaa;
/// Device B.
const B: u8 = 0xbb;

fn op_err(data: &[u8]) -> (RecordErrorKind, usize) {
    let e = parse_op(data).unwrap_err();
    (e.kind(), e.offset())
}

fn snap_err(covered: &VersionVector, data: &[u8]) -> (RecordErrorKind, usize) {
    let e = parse_snapshot(covered, data).unwrap_err();
    (e.kind(), e.offset())
}

/// An `Active` op with the given writes, written verbatim.
fn raw_op(writes: &[(&str, &[u8])]) -> Vec<u8> {
    let n = u16::try_from(writes.len()).unwrap();
    writes
        .iter()
        .fold(Spec::new().u8(0x01).u8(0x01).u16(n), |s, (k, v)| {
            s.write(k, v)
        })
        .done()
}

/// `@lifecycle` = Active by A:1, as a register production.
fn lc(s: Spec) -> Spec {
    s.register("@lifecycle", &[(A, 1, hlc(0, 0), &[0x01])])
}

use RecordErrorKind as K;

#[test]
fn op_rejections_and_offsets() {
    assert_eq!(op_err(&[]), (K::Truncated, 0));
    assert_eq!(op_err(&[0x02, 0x01, 0x00, 0x00]), (K::WrongKind, 0));
    assert_eq!(op_err(&[0x01]), (K::Truncated, 1));
    assert_eq!(op_err(&[0x01, 0x04, 0x00, 0x00]), (K::InvalidLifecycle, 1));
    assert_eq!(op_err(&[0x01, 0x01, 0x00]), (K::Truncated, 2));
    assert_eq!(op_err(&[0x01, 0x01, 0x04, 0x01]), (K::CountTooLarge, 2));
    // Two writes claimed, room for one at 8 bytes each.
    let mut d = raw_op(&[("a.b", &[])]);
    d[3] = 2;
    assert_eq!(op_err(&d), (K::Truncated, 2));
    let d = Spec::new()
        .u8(0x01)
        .u8(0x02)
        .u16(1)
        .write("a.b", &[])
        .done();
    assert_eq!(op_err(&d), (K::WritesWithoutActive, 2));
    // Keys: length 0 and 161, and the grammar, all at the key's `str` field.
    assert_eq!(op_err(&raw_op(&[("", &[])])), (K::KeyLength, 4));
    let long = format!("a.{}", "b".repeat(159));
    assert_eq!(op_err(&raw_op(&[(&long, &[])])), (K::KeyLength, 4));
    assert_eq!(op_err(&raw_op(&[("item.Name", &[])])), (K::KeyGrammar, 4));
    let d = raw_op(&[("a.a", &[]), ("tag/6A", &[])]);
    assert_eq!(op_err(&d), (K::KeyGrammar, 4 + 11));
    assert_eq!(
        op_err(&raw_op(&[("@lifecycle", &[])])),
        (K::MisplacedLifecycle, 4)
    );
    let d = raw_op(&[("b.b", &[]), ("a.a", &[])]);
    assert_eq!(op_err(&d), (K::NotAscending, 4 + 11));
    // A key length that runs past the end.
    let d = Spec::new()
        .u8(0x01)
        .u8(0x01)
        .u16(1)
        .u16(0)
        .u16(9)
        .raw(b"a.b")
        .u16(0)
        .u16(0)
        .done();
    assert_eq!(op_err(&d), (K::Truncated, 4));
    // Values: over the limit at the length field; past the end; trailing bytes.
    let big = vec![0u8; MAX_VALUE_LEN + 1];
    assert_eq!(op_err(&raw_op(&[("a.b", &big)])), (K::ValueTooLong, 4 + 7));
    let mut d = raw_op(&[("a.b", &[1, 2])]);
    d.pop();
    assert_eq!(op_err(&d), (K::Truncated, 4 + 7));
    let mut d = raw_op(&[("a.b", &[1, 2])]);
    d.push(0);
    assert_eq!(op_err(&d), (K::TrailingBytes, 4 + 7 + 6));
}

#[test]
fn snapshot_rejections_and_offsets() {
    let cov = vv(&[(A, 3), (B, 1)]);
    assert_eq!(snap_err(&cov, &[]), (K::Truncated, 0));
    for kind in [0x00, 0x01, 0x04, 0x05, 0xff] {
        assert_eq!(snap_err(&cov, &[kind, 0x00, 0x00]), (K::WrongKind, 0));
    }
    // Live: counts.
    assert_eq!(snap_err(&cov, &[0x02, 0x10, 0x01]), (K::CountTooLarge, 1));
    assert_eq!(
        snap_err(&cov, &[0x02, 0x00, 0x00, 0x00, 0x00]),
        (K::NoRegister, 1)
    );
    assert_eq!(snap_err(&cov, &[0x02, 0x00, 0x01]), (K::Truncated, 1));
    // The first register is not @lifecycle.
    let d = Spec::new()
        .u8(0x02)
        .u16(1)
        .register("a.b", &[(A, 1, hlc(0, 0), &[])])
        .u16(0)
        .done();
    assert_eq!(snap_err(&cov, &d), (K::MissingLifecycle, 3));
    // @lifecycle entries: m = 0, over 256, seq 0, out of order, not covered, a bad value.
    let lc_reg = |entries: &[(u8, u64, &[u8])]| {
        let e: Vec<_> = entries
            .iter()
            .map(|&(b, s, v)| (b, s, hlc(0, 0), v))
            .collect();
        Spec::new()
            .u8(0x02)
            .u16(1)
            .register("@lifecycle", &e)
            .u16(0)
            .done()
    };
    let key_end = 3 + 4 + 10;
    assert_eq!(snap_err(&cov, &lc_reg(&[])), (K::EmptyRegister, key_end));
    let d = Spec::new()
        .u8(0x02)
        .u16(1)
        .str("@lifecycle")
        .u16(257)
        .done();
    assert_eq!(snap_err(&cov, &d), (K::CountTooLarge, key_end));
    let first = key_end + 2;
    assert_eq!(
        snap_err(&cov, &lc_reg(&[(A, 0, &[1])])),
        (K::ZeroSeq, first + 16)
    );
    assert_eq!(
        snap_err(&cov, &lc_reg(&[(A, 2, &[1]), (A, 1, &[1])])),
        (K::NotAscending, first + 37)
    );
    assert_eq!(
        snap_err(&cov, &lc_reg(&[(A, 1, &[1]), (A, 1, &[1])])),
        (K::NotAscending, first + 37)
    );
    assert_eq!(
        snap_err(&cov, &lc_reg(&[(A, 4, &[1])])),
        (K::NotCovered, first)
    );
    assert_eq!(
        snap_err(&cov, &lc_reg(&[(0x01, 1, &[1])])),
        (K::NotCovered, first)
    );
    for bad in [&[][..], &[0x00], &[0x03], &[0x01, 0x00]] {
        assert_eq!(
            snap_err(&cov, &lc_reg(&[(A, 1, bad)])),
            (K::InvalidLifecycleValue, first + 32)
        );
    }
    // History: an orphan group and a dot shared with the register.
    let regs = lc(Spec::new().u8(0x02).u16(1));
    let hist_at = regs.0.len() + 2;
    let d = regs
        .clone()
        .u16(1)
        .register("a.b", &[(A, 2, hlc(0, 0), &[])])
        .done();
    assert_eq!(snap_err(&cov, &d), (K::OrphanHistory, hist_at));
    let d = regs
        .clone()
        .u16(1)
        .register("@lifecycle", &[(A, 1, hlc(0, 0), &[0x01])])
        .done();
    assert_eq!(snap_err(&cov, &d), (K::DuplicateDot, hist_at));
    let d = regs.clone().u16(0).u8(0).done();
    assert_eq!(snap_err(&cov, &d), (K::TrailingBytes, hist_at));
}

#[test]
fn tombstone_rejections_and_offsets() {
    let cov = vv(&[(A, 3), (B, 1)]);
    // purge_dot, c, late registers.
    let head = |purge: (u8, u64), c: &[(u8, u64)]| {
        Spec::new()
            .u8(0x03)
            .dot(purge.0, purge.1)
            .u64(0)
            .vv(c)
            .raw(&[0x4b; 16])
    };
    assert_eq!(
        snap_err(&cov, &head((A, 4), &[]).u16(0).done()),
        (K::NotCovered, 1)
    );
    assert_eq!(
        snap_err(&cov, &head((A, 0), &[]).u16(0).done()),
        (K::ZeroSeq, 17)
    );
    let c_at = 1 + 24 + 8;
    assert_eq!(
        snap_err(&cov, &head((A, 3), &[(A, 1), (0x01, 1)]).u16(0).done()),
        (K::NotAscending, c_at + 2 + 24)
    );
    assert_eq!(
        snap_err(&cov, &head((A, 3), &[(A, 1), (B, 2)]).u16(0).done()),
        (K::NotCovered, c_at + 2 + 24)
    );
    let late_at = c_at + 2 + 24 + 16 + 2;
    let d = head((A, 3), &[(A, 2)])
        .u16(1)
        .register("a.b", &[(A, 2, hlc(0, 0), &[])])
        .done();
    assert_eq!(
        snap_err(&cov, &d),
        (K::LateValueCovered, late_at + 4 + 3 + 2)
    );
    let d = head((A, 3), &[(A, 2)])
        .u16(1)
        .register("@lifecycle", &[(A, 3, hlc(0, 0), &[0x01])])
        .done();
    assert_eq!(snap_err(&cov, &d), (K::MisplacedLifecycle, late_at));
    let d = head((A, 3), &[(A, 2)]).u16(1).str("a.b").u16(0).done();
    assert_eq!(snap_err(&cov, &d), (K::EmptyRegister, late_at + 7));
    let d = head((A, 3), &[(A, 2)]).u16(0).u8(0).done();
    assert_eq!(snap_err(&cov, &d), (K::TrailingBytes, late_at));
    // A tombstone cut short inside item_key_id.
    let d = Spec::new()
        .u8(0x03)
        .dot(A, 3)
        .u64(0)
        .vv(&[])
        .raw(&[0; 15])
        .done();
    assert_eq!(snap_err(&cov, &d), (K::Truncated, 1 + 24 + 8 + 2));
}

/// Rules 5 and 6 on history groups and late registers, not only on current registers: §5 rule 5
/// names "any `register` production (current register, history group or late register)", and
/// §4 "Coverage" names every dot, "`purge_dot` and the late values' dots included".
///
/// Each case also parses once the one rule it breaks is mended, so it breaks only that rule.
#[test]
fn history_groups_and_late_registers_follow_rules_5_and_6() {
    // A live snapshot whose only current register is `@lifecycle` with one one-byte value
    // (4 + 10 + 2 + 36 + 1 = 53 bytes from offset 3), then the history list: `u16 h` at 56, the
    // first group at 58, its `u16 m` at 72, its first dot at 74 and that entry's value at 106.
    let (group_at, m_at, dot_at, value_at) = (58, 72, 74, 106);
    let live = |current: (u8, u64), hist: Spec| {
        Spec::new()
            .u8(0x02)
            .u16(1)
            .register("@lifecycle", &[(current.0, current.1, hlc(0, 0), &[0x01])])
            .raw(&hist.done())
            .done()
    };
    let one_group = |entry: (u8, u64, &[u8])| {
        Spec::new()
            .u16(1)
            .register("@lifecycle", &[(entry.0, entry.1, hlc(0, 0), entry.2)])
    };
    assert_eq!(live((A, 1), Spec::new().u16(0)).len(), group_at);

    // Rule 6, a history entry: covered {A:1}, current A:1, history B:1.
    let d = live((A, 1), one_group((B, 1, &[0x01])));
    assert_eq!(snap_err(&vv(&[(A, 1)]), &d), (K::NotCovered, dot_at));
    assert!(parse_snapshot(&vv(&[(A, 1), (B, 1)]), &d).is_ok());

    // Rule 5, a history group with m = 0, under the key of a current register.
    let cov = vv(&[(A, 2)]);
    let d = live((A, 2), Spec::new().u16(1).str("@lifecycle").u16(0));
    assert_eq!(snap_err(&cov, &d), (K::EmptyRegister, m_at));
    assert!(parse_snapshot(&cov, &live((A, 2), one_group((A, 1, &[0x01])))).is_ok());

    // Rule 5, a `@lifecycle` history entry whose value is not the single byte 0x01 or 0x02.
    // History entries are the values removed from the register (§3 "Lifecycle": "Values
    // removed from `@lifecycle` go into history like any others"), so rule 5's "a `@lifecycle`
    // value" covers them; this reading is reported to the owner.
    for bad in [&[][..], &[0x00], &[0x03], &[0x01, 0x00]] {
        let d = live((A, 2), one_group((A, 1, bad)));
        assert_eq!(snap_err(&cov, &d), (K::InvalidLifecycleValue, value_at));
    }
    for good in [0x01, 0x02] {
        assert!(parse_snapshot(&cov, &live((A, 2), one_group((A, 1, &[good])))).is_ok());
    }

    // Rule 6, a late value: covered {A:2}, purge A:2, c {A:1}, a late `item.name` at B:1 that
    // `c` does not cover either (so rule 8 holds). `u16 l` at 75, the register at 77, its
    // first dot at 77 + 13 + 2 = 92.
    let tomb = |late: (u8, u64)| {
        Spec::new()
            .u8(0x03)
            .dot(A, 2)
            .u64(0)
            .vv(&[(A, 1)])
            .raw(&[0x4b; 16])
            .u16(1)
            .register("item.name", &[(late.0, late.1, hlc(0, 0), &[0x01, b'x'])])
            .done()
    };
    assert_eq!(snap_err(&cov, &tomb((B, 1))), (K::NotCovered, 92));
    assert!(parse_snapshot(&vv(&[(A, 2), (B, 1)]), &tomb((B, 1))).is_ok());
}

/// The parser's own count checks (ADR 0018 §5 "Shape", §10), fed raw bytes so that no writer
/// refuses the input first: each §10 count limit at its boundary for `r`, `h` and `l`, and the
/// `count × minimum size ≤ remaining input` check at its exact boundary for every count.
#[test]
fn parser_count_limits_and_minimum_sizes() {
    let cov = vv(&[(A, 2)]);
    // Where each list's `u16` count sits: `r` at 1; `h` at 56, after one `@lifecycle`
    // register; `l` at 51, after a tombstone head with an empty `c`.
    let r_head = Spec::new().u8(0x02);
    let h_head = lc(Spec::new().u8(0x02).u16(1));
    let l_head = Spec::new()
        .u8(0x03)
        .dot(A, 2)
        .u64(0)
        .vv(&[])
        .raw(&[0x4b; 16]);
    assert_eq!((h_head.0.len(), l_head.0.len()), (56, 51));
    for (head, at) in [(r_head, 1), (h_head, 56), (l_head, 51)] {
        // The §10 limit: `count` followed by `count × 6` zero bytes, so the minimum-size check
        // passes and only the limit can refuse 4,097. At 4,096 the parser goes on and refuses
        // the first key, which is empty.
        for (count, expected) in [
            (MAX_GROUPS + 1, (K::CountTooLarge, at)),
            (MAX_GROUPS, (K::KeyLength, at + 2)),
        ] {
            let n = u16::try_from(count).unwrap();
            let d = head.clone().u16(n).raw(&vec![0; count * 6]).done();
            assert_eq!(snap_err(&cov, &d), expected, "count {count} at {at}");
        }
        // The minimum size of a register, 6 bytes (an empty key and `u16 m`): two claimed
        // with 11 bytes left are refused at the count; with 12 the parser reads the first.
        let d = head.clone().u16(2).raw(&[0; 11]).done();
        assert_eq!(snap_err(&cov, &d), (K::Truncated, at));
        let d = head.u16(2).raw(&[0; 12]).done();
        assert_eq!(snap_err(&cov, &d), (K::KeyLength, at + 2));
    }

    // The minimum size of an entry, 36 bytes (a dot, an HLC and an empty value): a register
    // `a.b` after `@lifecycle`, its `u16 m` at 56 + 7 = 63, claiming two entries. With both
    // (72 bytes) the count passes and the parser runs out at `u16 h`; one byte short, the
    // count is refused at `m`.
    let m_at = 63;
    let two = lc(Spec::new().u8(0x02).u16(2))
        .register("a.b", &[(A, 1, hlc(0, 0), &[]), (A, 2, hlc(0, 0), &[])])
        .done();
    assert_eq!(two.len(), m_at + 2 + 72);
    assert_eq!(snap_err(&cov, &two), (K::Truncated, two.len()));
    assert_eq!(snap_err(&cov, &two[..two.len() - 1]), (K::Truncated, m_at));
    // m = 256 is within §10 and needs 256 × 36 bytes: one short is refused at `m`; with all of
    // them the parser reads the first entry and refuses its seq 0.
    let many = |len: usize| {
        lc(Spec::new().u8(0x02).u16(2))
            .str("a.b")
            .u16(256)
            .raw(&vec![0; len])
            .done()
    };
    assert_eq!(
        snap_err(&cov, &many(MAX_VALUES * 36 - 1)),
        (K::Truncated, m_at)
    );
    assert_eq!(
        snap_err(&cov, &many(MAX_VALUES * 36)),
        (K::ZeroSeq, m_at + 2 + 16)
    );

    // The minimum size of an op write, 8 bytes (two empty lengths), and the writes limit at
    // its boundary.
    let head = Spec::new().u8(0x01).u8(0x01);
    assert_eq!(
        op_err(&head.clone().u16(2).raw(&[0; 15]).done()),
        (K::Truncated, 2)
    );
    assert_eq!(
        op_err(&head.clone().u16(2).raw(&[0; 16]).done()),
        (K::KeyLength, 4)
    );
    let n = u16::try_from(MAX_WRITES).unwrap();
    assert_eq!(
        op_err(&head.clone().u16(n).raw(&vec![0; MAX_WRITES * 8]).done()),
        (K::KeyLength, 4)
    );
    assert_eq!(
        op_err(&head.u16(n + 1).raw(&vec![0; (MAX_WRITES + 1) * 8]).done()),
        (K::CountTooLarge, 2)
    );
}

/// ADR 0018 §5: these parse and are carried verbatim, although no honest merge produces
/// most of them.
#[test]
fn nothing_else_rejects() {
    let cov = vv(&[(A, 3), (B, 2)]);
    let (h1, h2) = (hlc(0, 0), hlc(5, 7));
    // Several current values from one device in one register; one dot with different HLCs
    // under different keys; a register holding only the Cleared value; a @lifecycle history
    // group; values of unknown or malformed types; keys no M1 schema knows.
    let d = Spec::new()
        .u8(0x02)
        .u16(6)
        .register("@lifecycle", &[(A, 2, h1, &[0x01]), (B, 1, h1, &[0x02])])
        .register("item.name", &[(A, 1, h1, &[0x01, 0xff, 0xfe])])
        .register("item.notes", &[(A, 1, h2, &[])])
        .register(
            "login.username",
            &[(A, 1, h1, &[0x03, 0x02]), (A, 2, h2, &[0x01])],
        )
        .register("passkey/00ff/cred", &[(B, 2, h2, &[0xee; 3])])
        .register("zz.future", &[(B, 2, h1, &[0x07])])
        .u16(1)
        .register("@lifecycle", &[(A, 1, h1, &[0x01])])
        .done();
    let SnapshotData::Live(live) = parse_snapshot(&cov, &d).unwrap() else {
        panic!("live");
    };
    assert_eq!(live.registers().len(), 6);
    assert_eq!(live.registers()[2].entries()[0].value(), Value::CLEARED);
    assert_eq!(
        live.registers()[1].entries()[0].value().expose_secret(),
        [0x01, 0xff, 0xfe]
    );
    assert_eq!(
        encode_snapshot(&cov, &SnapshotData::Live(live))
            .unwrap()
            .expose_secret(),
        d
    );

    // A purge_dot that c covers; a late value whose dot is purge_dot; any item_key_id.
    let d = Spec::new()
        .u8(0x03)
        .dot(B, 2)
        .u64(h2.to_u64())
        .vv(&[(A, 3)])
        .raw(&[0; 16])
        .u16(1)
        .register("login.password", &[(B, 2, h1, &[0x01, b'x'])])
        .done();
    assert!(parse_snapshot(&cov, &d).is_ok());
    let d = Spec::new()
        .u8(0x03)
        .dot(A, 3)
        .u64(h2.to_u64())
        .vv(&[(A, 3), (B, 1)])
        .raw(&[0xff; 16])
        .u16(0)
        .done();
    let SnapshotData::Tombstone(t) = parse_snapshot(&cov, &d).unwrap() else {
        panic!("tombstone");
    };
    assert!(t.context().covers(t.purge_dot()));
    assert_eq!(t.item_key_id(), SymmetricKeyId::from_bytes([0xff; 16]));

    // An op: a restore with no write, and an edit of unknown keys with malformed values.
    assert!(
        parse_op(&[0x01, 0x01, 0x00, 0x00])
            .unwrap()
            .writes()
            .is_empty()
    );
    let d = raw_op(&[
        ("a.b", &[0x01, 0xc3]),
        ("tag/00", &[0x03, 0x07]),
        ("z.z", &[0xf0]),
    ]);
    let op = parse_op(&d).unwrap();
    assert_eq!(op.writes()[1].value().expose_secret(), [0x03, 0x07]);
    assert_eq!(encode_op(&op).unwrap().expose_secret(), d);
}

/// Distinct grammar keys `f.k0000`, `f.k0001`, …, ascending.
fn keys(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("f.k{i:04}")).collect()
}

/// `Active` op data writing `value` to each of `keys`.
fn active_writes<'a>(keys: &'a [String], value: &'a [u8]) -> OpData<'a> {
    let writes = keys
        .iter()
        .map(|k| Write::new(key(k), Value::new(value)))
        .collect();
    OpData::new(Lifecycle::Active, writes)
}

#[test]
fn op_limits() {
    let ks = keys(MAX_WRITES + 1);
    let x: &[u8] = &[0x01];
    // 1,024 writes parse; 1,025 do not.
    let ok = active_writes(&ks[..MAX_WRITES], x);
    let bytes = encode_op(&ok).unwrap();
    assert_eq!(parse_op(bytes.expose_secret()), Ok(ok));
    let over = active_writes(&ks, x);
    assert_eq!(encode_op(&over).unwrap_err().kind(), K::CountTooLarge);
    let raw = raw_op(
        &ks.iter()
            .map(|k| (k.as_str(), x))
            .collect::<Vec<(&str, &[u8])>>(),
    );
    assert_eq!(op_err(&raw), (K::CountTooLarge, 2));
    // A value of 65,536 bytes parses; 65,537 does not.
    let (max, over) = (vec![0x02; MAX_VALUE_LEN], vec![0x02; MAX_VALUE_LEN + 1]);
    let a_b = ["a.b".to_owned()];
    assert!(encode_op(&active_writes(&a_b, &max)).is_ok());
    let e = encode_op(&active_writes(&a_b, &over)).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::ValueTooLong, 4 + 7));
    // A key of 160 bytes parses; 161 is refused by FieldKey::new and by the parser.
    let k160 = key_of_len(MAX_KEY_LEN);
    assert!(parse_op(&raw_op(&[(&k160, &[])])).is_ok());
    assert!(FieldKey::new(&k160).is_ok());
    let k161 = key_of_len(MAX_KEY_LEN + 1);
    assert_eq!(FieldKey::new(&k161).unwrap_err().kind(), K::KeyLength);
    assert_eq!(op_err(&raw_op(&[(&k161, &[])])), (K::KeyLength, 4));

    // Op data of exactly 1 MiB parses; one byte more is refused before decoding. Writes of
    // `f.kNNNN` (7 bytes) with maximal values, the last one sized to reach 1 MiB.
    let full = 4 + 7 + 4 + MAX_VALUE_LEN;
    let n = (MAX_OP_DATA_LEN - 4) / full;
    let last = MAX_OP_DATA_LEN - 4 - n * full - (4 + 7 + 4);
    let mut values = vec![vec![0x02; MAX_VALUE_LEN]; n];
    values.push(vec![0x02; last]);
    let op = |values: &[Vec<u8>]| {
        let writes = ks
            .iter()
            .zip(values)
            .map(|(k, v)| Write::new(key(k), Value::new(v)))
            .collect();
        encode_op(&OpData::new(Lifecycle::Active, writes))
    };
    let data = op(&values).unwrap();
    assert_eq!(data.len(), MAX_OP_DATA_LEN);
    assert!(parse_op(data.expose_secret()).is_ok());
    let mut longer = data.expose_secret().to_vec();
    longer.push(0);
    assert_eq!(op_err(&longer), (K::DataTooLong, 0));
    // The limit applies before anything is read: not even the kind byte is looked at.
    assert_eq!(
        op_err(&vec![0xff; MAX_OP_DATA_LEN + 1]),
        (K::DataTooLong, 0)
    );
    values.last_mut().unwrap().push(0x02);
    let e = op(&values).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::DataTooLong, 0));
}

#[test]
fn snapshot_group_limits() {
    let h = hlc(0, 0);
    let active: &[u8] = &[0x01];
    // 4,096 current registers and 4,096 history groups (each a key of a current register).
    let ks = keys(MAX_GROUPS);
    let current = |n: usize| {
        let mut regs = vec![Register::new(
            FieldKey::LIFECYCLE,
            vec![Entry::new(dot(A, 2), h, Value::new(active))],
        )];
        regs.extend(
            ks[..n - 1]
                .iter()
                .map(|k| Register::new(key(k), vec![Entry::new(dot(A, 2), h, Value::CLEARED)])),
        );
        regs
    };
    let history = |n: usize| {
        let mut regs = vec![Register::new(
            FieldKey::LIFECYCLE,
            vec![Entry::new(dot(A, 1), h, Value::new(active))],
        )];
        regs.extend(
            ks[..n - 1]
                .iter()
                .map(|k| Register::new(key(k), vec![Entry::new(dot(A, 1), h, Value::CLEARED)])),
        );
        regs
    };
    let cov = vv(&[(A, 2)]);
    let live = SnapshotData::Live(LiveSnapshot::new(current(MAX_GROUPS), history(MAX_GROUPS)));
    let bytes = encode_snapshot(&cov, &live).unwrap();
    assert_eq!(parse_snapshot(&cov, bytes.expose_secret()), Ok(live));
    // 4,097 registers: the count is refused, on the writer and in the parser.
    let ks_over = keys(MAX_GROUPS + 1);
    let mut over = current(MAX_GROUPS);
    over.push(Register::new(
        key(&ks_over[MAX_GROUPS]),
        vec![Entry::new(dot(A, 2), h, Value::CLEARED)],
    ));
    let e =
        encode_snapshot(&cov, &SnapshotData::Live(LiveSnapshot::new(over, vec![]))).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::CountTooLarge, 1));
    let mut raw = Spec::new().u8(0x02).u16(4_097).done();
    raw.extend(vec![0; 4_097 * 43]);
    assert_eq!(snap_err(&cov, &raw), (K::CountTooLarge, 1));
    // 4,097 history groups: the writer refuses the count at `u16 h`, before it looks at the
    // groups (the 4,097th cannot name a current register; there are at most 4,096). The
    // parser's refusal is in `parser_count_limits_and_minimum_sizes`.
    let h_at = encode_snapshot(
        &cov,
        &SnapshotData::Live(LiveSnapshot::new(current(MAX_GROUPS), vec![])),
    )
    .unwrap()
    .len()
        - 2;
    let mut hist_over = history(MAX_GROUPS);
    hist_over.push(Register::new(
        key(&ks_over[MAX_GROUPS]),
        vec![Entry::new(dot(A, 1), h, Value::CLEARED)],
    ));
    let e = encode_snapshot(
        &cov,
        &SnapshotData::Live(LiveSnapshot::new(current(MAX_GROUPS), hist_over)),
    )
    .unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::CountTooLarge, h_at));

    // 4,096 late registers.
    let cov = vv(&[(A, 2), (B, 1)]);
    let late: Vec<Register<'_>> = ks
        .iter()
        .map(|k| Register::new(key(k), vec![Entry::new(dot(B, 1), h, Value::CLEARED)]))
        .collect();
    let tomb = |late| {
        SnapshotData::Tombstone(Tombstone::new(
            dot(A, 2),
            h,
            vv(&[(A, 1)]),
            SymmetricKeyId::from_bytes([7; 16]),
            late,
        ))
    };
    let t = tomb(late.clone());
    let bytes = encode_snapshot(&cov, &t).unwrap();
    assert_eq!(parse_snapshot(&cov, bytes.expose_secret()), Ok(t));
    let mut over = late;
    over.push(Register::new(
        key(&ks_over[MAX_GROUPS]),
        vec![Entry::new(dot(B, 1), h, Value::CLEARED)],
    ));
    assert_eq!(
        encode_snapshot(&cov, &tomb(over)).unwrap_err().kind(),
        K::CountTooLarge
    );
}

#[test]
fn register_value_limit() {
    let (h, active): (_, &[u8]) = (hlc(0, 0), &[0x01]);
    // 256 values in a register parse; 257 do not.
    let entries = |n: u64| {
        (1..=n)
            .map(|s| Entry::new(dot(A, s), h, Value::new(active)))
            .collect()
    };
    let cov = vv(&[(A, 257)]);
    let live = |n| {
        SnapshotData::Live(LiveSnapshot::new(
            vec![Register::new(FieldKey::LIFECYCLE, entries(n))],
            vec![],
        ))
    };
    assert!(encode_snapshot(&cov, &live(256)).is_ok());
    assert_eq!(
        encode_snapshot(&cov, &live(257)).unwrap_err().kind(),
        K::CountTooLarge
    );
}

/// A live snapshot of `@lifecycle` = Active by A:1 and one register `f.big` holding `values`,
/// written by A:2, A:3, ….
fn big_register(values: &[Vec<u8>]) -> SnapshotData<'_> {
    let h = hlc(0, 0);
    let big = values
        .iter()
        .zip(2..)
        .map(|(v, s)| Entry::new(dot(A, s), h, Value::new(v)))
        .collect();
    SnapshotData::Live(LiveSnapshot::new(
        vec![
            Register::new(
                FieldKey::LIFECYCLE,
                vec![Entry::new(dot(A, 1), h, Value::new(&[0x01]))],
            ),
            Register::new(key("f.big"), big),
        ],
        vec![],
    ))
}

#[test]
fn snapshot_data_limit() {
    // One register of maximal values, the last sized so the data is exactly 12 MiB.
    let lifecycle_reg = 4 + 10 + 2 + 36 + 1;
    let base = 1 + 2 + lifecycle_reg + (4 + 5 + 2) + 2;
    let full = 36 + MAX_VALUE_LEN;
    let n = (MAX_SNAPSHOT_DATA_LEN - base) / full;
    let last = MAX_SNAPSHOT_DATA_LEN - base - n * full - 36;
    let mut values = vec![vec![0x02; MAX_VALUE_LEN]; n];
    values.push(vec![0x02; last]);
    let cov = vv(&[(A, u64::try_from(values.len()).unwrap() + 1)]);
    let build = big_register;
    let data = encode_snapshot(&cov, &build(&values)).unwrap();
    assert_eq!(data.len(), MAX_SNAPSHOT_DATA_LEN);
    assert!(parse_snapshot(&cov, data.expose_secret()).is_ok());
    let mut longer = data.expose_secret().to_vec();
    longer.push(0);
    assert_eq!(snap_err(&cov, &longer), (K::DataTooLong, 0));
    assert_eq!(
        snap_err(&cov, &vec![0xff; MAX_SNAPSHOT_DATA_LEN + 1]),
        (K::DataTooLong, 0)
    );
    values.last_mut().unwrap().push(0x02);
    let e = encode_snapshot(&cov, &build(&values)).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (K::DataTooLong, 0));
    // The state-hash input has no §10 limit.
    assert!(canonical_state(&cov, &build(&values)).is_ok());
}

#[test]
fn writers_refuse_what_the_parser_refuses() {
    let (time, value) = (hlc(0, 0), Value::new(&[0x01, b'x']));
    let write = |k| Write::new(key(k), value);
    let unsorted = OpData::new(Lifecycle::Active, vec![write("b.b"), write("a.a")]);
    assert_eq!(encode_op(&unsorted).unwrap_err().kind(), K::NotAscending);
    let dup = OpData::new(Lifecycle::Active, vec![write("a.a"), write("a.a")]);
    assert_eq!(encode_op(&dup).unwrap_err().kind(), K::NotAscending);
    let trash = OpData::new(Lifecycle::Trashed, vec![write("a.a")]);
    assert_eq!(
        encode_op(&trash).unwrap_err().kind(),
        K::WritesWithoutActive
    );
    let lifecycle = OpData::new(
        Lifecycle::Active,
        vec![Write::new(FieldKey::LIFECYCLE, value)],
    );
    assert_eq!(
        encode_op(&lifecycle).unwrap_err().kind(),
        K::MisplacedLifecycle
    );

    let cov = vv(&[(A, 1)]);
    let lc = || {
        Register::new(
            FieldKey::LIFECYCLE,
            vec![Entry::new(dot(A, 1), time, Value::new(&[0x01]))],
        )
    };
    let uncovered = SnapshotData::Live(LiveSnapshot::new(
        vec![
            lc(),
            Register::new(key("a.a"), vec![Entry::new(dot(B, 1), time, value)]),
        ],
        vec![],
    ));
    assert_eq!(
        encode_snapshot(&cov, &uncovered).unwrap_err().kind(),
        K::NotCovered
    );
    let no_lifecycle = SnapshotData::Live(LiveSnapshot::new(
        vec![Register::new(
            key("a.a"),
            vec![Entry::new(dot(A, 1), time, value)],
        )],
        vec![],
    ));
    assert_eq!(
        encode_snapshot(&cov, &no_lifecycle).unwrap_err().kind(),
        K::MissingLifecycle
    );
    let empty = SnapshotData::Live(LiveSnapshot::new(
        vec![lc(), Register::new(key("a.a"), vec![])],
        vec![],
    ));
    assert_eq!(
        encode_snapshot(&cov, &empty).unwrap_err().kind(),
        K::EmptyRegister
    );
    let orphan = SnapshotData::Live(LiveSnapshot::new(
        vec![lc()],
        vec![Register::new(
            key("a.a"),
            vec![Entry::new(dot(A, 1), time, value)],
        )],
    ));
    assert_eq!(
        encode_snapshot(&cov, &orphan).unwrap_err().kind(),
        K::OrphanHistory
    );
    let covered_late = SnapshotData::Tombstone(Tombstone::new(
        dot(A, 1),
        time,
        vv(&[(A, 1)]),
        SymmetricKeyId::from_bytes([0; 16]),
        vec![Register::new(
            key("a.a"),
            vec![Entry::new(dot(A, 1), time, value)],
        )],
    ));
    assert_eq!(
        encode_snapshot(&cov, &covered_late).unwrap_err().kind(),
        K::LateValueCovered
    );
    // The writer's own version-vector bytes equal VersionVector::encode's.
    let tomb = SnapshotData::Tombstone(Tombstone::new(
        dot(A, 2),
        time,
        vv(&[(B, 1), (A, 1)]),
        SymmetricKeyId::from_bytes([9; 16]),
        vec![],
    ));
    let bytes = encode_snapshot(&vv(&[(A, 2), (B, 1)]), &tomb).unwrap();
    let context = vv(&[(A, 1), (B, 1)]).to_vec().unwrap();
    assert_eq!(
        &bytes.expose_secret()[33..33 + context.len()],
        context.as_slice()
    );
}

#[test]
fn canonical_state_layout() {
    let h = hlc(0, 0);
    let cov = vv(&[(A, 1), (B, 3)]);
    let live = SnapshotData::Live(LiveSnapshot::new(
        vec![Register::new(
            FieldKey::LIFECYCLE,
            vec![Entry::new(dot(B, 3), h, Value::new(&[0x02]))],
        )],
        vec![],
    ));
    let state = canonical_state(&cov, &live).unwrap();
    let data = encode_snapshot(&cov, &live).unwrap();
    let expected = [
        &[0x00, 0x01][..],
        &cov.to_vec().unwrap(),
        data.expose_secret(),
    ]
    .concat();
    assert_eq!(state.expose_secret(), expected.as_slice());
    // An oversize state (257 values in a register) has a state encoding but no snapshot.
    let cov = vv(&[(A, 257)]);
    let entries = (1..=257)
        .map(|s| Entry::new(dot(A, s), h, Value::new(&[0x01])))
        .collect();
    let big = SnapshotData::Live(LiveSnapshot::new(
        vec![Register::new(FieldKey::LIFECYCLE, entries)],
        vec![],
    ));
    assert_eq!(
        encode_snapshot(&cov, &big).unwrap_err().kind(),
        K::CountTooLarge
    );
    assert!(canonical_state(&cov, &big).is_ok());
    // Every other rule still applies.
    let uncovered = vv(&[(A, 256)]);
    assert_eq!(
        canonical_state(&uncovered, &big).unwrap_err().kind(),
        K::NotCovered
    );
}

#[test]
fn keys_and_values_never_reach_debug_or_errors() {
    let secret_key = "login.password";
    let secret_value = b"hunter2-correct-horse";
    let op = OpData::new(
        Lifecycle::Active,
        vec![Write::new(key(secret_key), Value::new(secret_value))],
    );
    let bytes = encode_op(&op).unwrap();
    let parsed = parse_op(bytes.expose_secret()).unwrap();
    let hex_value = to_hex(secret_value);
    for text in [
        format!("{op:?}"),
        format!("{parsed:?}"),
        format!("{:?}", parsed.writes()[0].key()),
        format!("{:?}", parsed.writes()[0].value()),
        format!("{bytes:?}"),
    ] {
        assert!(
            !text.contains("password") && !text.contains("hunter2"),
            "{text}"
        );
        assert!(!text.contains(&hex_value), "{text}");
        assert!(!text.contains("104, 117, 110"), "{text}");
    }
    assert_eq!(format!("{:?}", key(secret_key)), "FieldKey([REDACTED])");
    assert_eq!(
        format!("{:?}", Value::new(secret_value)),
        "Value([REDACTED])"
    );
    // The lifecycle marker is item content as well (ADR 0012 §5): no variant name reaches
    // `Debug`, on the marker or on the op data that carries it.
    for marker in [Lifecycle::Active, Lifecycle::Trashed, Lifecycle::Purge] {
        let op = OpData::new(marker, vec![]);
        let bytes = encode_op(&op).unwrap();
        let parsed = parse_op(bytes.expose_secret()).unwrap();
        for text in [
            format!("{marker:?}"),
            format!("{op:?}"),
            format!("{parsed:?}"),
            format!("{:?}", parsed.lifecycle()),
        ] {
            for name in ["Active", "Trashed", "Purge"] {
                assert!(!text.contains(name), "{text}");
            }
        }
        assert_eq!(format!("{marker:?}"), "Lifecycle([REDACTED])");
        // Only an `Active` op has writes, so the op data prints no count either.
        assert_eq!(format!("{parsed:?}"), "OpData([REDACTED])");
    }
    assert_eq!(format!("{op:?}"), "OpData([REDACTED])");
    // Whether an item is live or purged is item content too (the record kind is inside the
    // encrypted `data`): a live snapshot and a tombstone print the same text, and neither
    // prints its registers, its purge or its `c`.
    let cov = vv(&[(A, 2)]);
    let trashed = Lifecycle::Trashed.register_value().unwrap();
    let live = SnapshotData::Live(LiveSnapshot::new(
        vec![Register::new(
            FieldKey::LIFECYCLE,
            vec![Entry::new(dot(A, 1), hlc(0, 0), trashed)],
        )],
        vec![],
    ));
    let tombstone = SnapshotData::Tombstone(Tombstone::new(
        dot(A, 1),
        hlc(0, 0),
        vv(&[(A, 1)]),
        SymmetricKeyId::from_bytes([0x4b; 16]),
        vec![Register::new(
            key("item.name"),
            vec![Entry::new(dot(A, 2), hlc(0, 1), Value::CLEARED)],
        )],
    ));
    for snapshot in [live, tombstone] {
        let bytes = encode_snapshot(&cov, &snapshot).unwrap();
        let parsed = parse_snapshot(&cov, bytes.expose_secret()).unwrap();
        assert_eq!(parsed, snapshot);
        let inner = match &parsed {
            SnapshotData::Live(live) => format!("{live:?}"),
            SnapshotData::Tombstone(tombstone) => format!("{tombstone:?}"),
        };
        for text in [format!("{snapshot:?}"), format!("{parsed:#?}"), inner] {
            assert_eq!(text, "SnapshotData([REDACTED])");
        }
        assert_eq!(format!("{:?}", parsed.kind()), "RecordKind([REDACTED])");
    }
    for kind in [
        RecordKind::Op,
        RecordKind::LiveSnapshot,
        RecordKind::Tombstone,
    ] {
        assert_eq!(format!("{kind:?}"), "RecordKind([REDACTED])");
    }
    // A rejected record's error names a kind and an offset only.
    let mut broken = bytes.expose_secret().to_vec();
    broken.push(0);
    let e = parse_op(&broken).unwrap_err();
    assert_eq!(
        e.to_string(),
        format!(
            "trailing bytes after the record at byte {}",
            broken.len() - 1
        )
    );
    let e = FieldKey::new("login.Password").unwrap_err();
    assert!(!e.to_string().contains("assword"));
    assert!(!format!("{e:?}").contains("assword"));
}

/// The record layer and the schema layer accept exactly the same keys (ADR 0018 §5 rules 2
/// and 3, §7, §10): every way the record layer takes a key agrees with `rizzy-core`'s
/// [`FieldKeyRef::parse`] on the keys of the §7 table, the §12 negative cases, the boundaries
/// of `name`, `elem` and the 160-byte limit, and bytes outside the grammar's alphabet. The
/// expected answer is spelled out too, so the agreement is never two layers refusing
/// everything. The property version is in `proptests`.
#[test]
fn both_layers_accept_the_same_keys() {
    use rizzy_core::item::key::FieldKeyRef;

    let id = "00112233445566778899aabbccddeeff";
    let n32 = "a".repeat(32);
    let hex128 = "ab".repeat(64);
    let mut cases: Vec<(Vec<u8>, bool)> = [
        "item.type",
        "item.name",
        "item.notes",
        "item.favorite",
        "import.created_ms",
        "login.username",
        "login.password",
        "login.totp",
        "card.exp_month",
        "identity.drivers_license",
        "vault.name",
        "tag/61",
        "tag/6162",
        "tag/00",
        "a.b.c.d",
        "x9_.y",
    ]
    .iter()
    .map(|k| (k.as_bytes().to_vec(), true))
    .collect();
    for attr in ["label", "kind", "value", "order"] {
        cases.push((format!("field/{id}/{attr}").into_bytes(), true));
    }
    for k in [
        format!("uri/{id}/match"),
        format!("pwhist/{id}/ms"),
        format!("share/{id}/secret"),
        format!("{n32}.{n32}"),
        format!("tag/{hex128}"),
        // The longest `elem` with an attribute name that brings the key to exactly 160 bytes.
        format!("x/{hex128}/{}", "a".repeat(29)),
        key_of_len(MAX_KEY_LEN),
    ] {
        cases.push((k.into_bytes(), true));
    }
    for k in [
        // ADR 0018 §12: an odd hex count, a 33-byte name, uppercase hex; a 161-byte key.
        "uri/abc/value".to_owned(),
        format!("{}.a", "a".repeat(33)),
        "tag/6A".to_owned(),
        "tag/AA".to_owned(),
        key_of_len(MAX_KEY_LEN + 1),
        // A grammar key of 163 bytes: a 32-byte attribute after the longest `elem`.
        format!("x/{hex128}/{n32}"),
        // A lone name, empty parts, stray separators, a bad first byte, too long an `elem`.
        "notes".to_owned(),
        String::new(),
        "tag/a".to_owned(),
        "item.".to_owned(),
        ".item".to_owned(),
        "item..name".to_owned(),
        "item.name.".to_owned(),
        "tag/".to_owned(),
        "tag/61/".to_owned(),
        "tag/61/value/x".to_owned(),
        "tag/61.x".to_owned(),
        "item.name/61".to_owned(),
        "a.b/00".to_owned(),
        "Item.name".to_owned(),
        "1tem.name".to_owned(),
        "_tem.name".to_owned(),
        "item.Name".to_owned(),
        "item.na-me".to_owned(),
        LIFECYCLE_KEY.to_owned(),
        "item.name\u{e9}".to_owned(),
        "item.name\0".to_owned(),
        format!("{n32}b.x"),
        format!("tag/{hex128}00"),
        format!("tag/{}", "a".repeat(127)),
    ] {
        cases.push((k.into_bytes(), false));
    }
    cases.push((b"item.\xffname".to_vec(), false));
    cases.push((b"tag/\xc3\xa9".to_vec(), false));

    for (bytes, expected) in &cases {
        let schema = FieldKeyRef::parse(bytes).is_ok();
        let text = String::from_utf8_lossy(bytes);
        assert_eq!(schema, *expected, "{text:?}");
        assert_eq!(record_layer_accepts(bytes), [schema; 4], "{text:?}");
    }
}

#[test]
fn small_api() {
    assert_eq!(FieldKey::new(""), Err(RecordError::new(K::KeyLength, 0)));
    assert_eq!(
        FieldKey::new("tag/6A"),
        Err(RecordError::new(K::KeyGrammar, 0))
    );
    let k161 = key_of_len(161);
    assert_eq!(FieldKey::new(&k161), Err(RecordError::new(K::KeyLength, 0)));
    assert_eq!(
        FieldKey::new(LIFECYCLE_KEY).unwrap_err().kind(),
        K::KeyGrammar
    );
    let k = FieldKey::new("tag/61").unwrap();
    assert_eq!(
        (k.expose_secret(), k.len(), k.is_empty(), k.is_lifecycle()),
        ("tag/61", 6, false, false)
    );
    assert!(FieldKey::LIFECYCLE.is_lifecycle());
    assert!(FieldKey::LIFECYCLE < k);
    assert!(Value::CLEARED.is_empty());
    assert_eq!(Value::new(&[1, 2]).len(), 2);

    for (m, byte) in [
        (Lifecycle::Active, 1),
        (Lifecycle::Trashed, 2),
        (Lifecycle::Purge, 3),
    ] {
        assert_eq!(m.to_u8(), byte);
        assert_eq!(Lifecycle::from_u8(byte), Some(m));
    }
    assert_eq!(Lifecycle::from_u8(0), None);
    assert_eq!(Lifecycle::from_u8(4), None);
    assert_eq!(
        Lifecycle::Active.register_value().unwrap().expose_secret(),
        [0x01]
    );
    assert_eq!(
        Lifecycle::Trashed.register_value().unwrap().expose_secret(),
        [0x02]
    );
    assert_eq!(Lifecycle::Purge.register_value(), None);
    assert_eq!(
        Lifecycle::from_register_value(Value::new(&[0x02])),
        Some(Lifecycle::Trashed)
    );
    assert_eq!(Lifecycle::from_register_value(Value::new(&[0x03])), None);

    assert_eq!(
        [
            RecordKind::Op,
            RecordKind::LiveSnapshot,
            RecordKind::Tombstone
        ]
        .map(RecordKind::to_u8),
        [1, 2, 3]
    );
    assert_eq!(RecordKind::RESERVED_SHARE_SNAPSHOT, 4);

    let all = [
        (K::WrongKind, 1),
        (K::DataTooLong, 2),
        (K::Truncated, 2),
        (K::TrailingBytes, 2),
        (K::CountTooLarge, 2),
        (K::NoRegister, 2),
        (K::ValueTooLong, 2),
        (K::KeyLength, 2),
        (K::KeyGrammar, 3),
        (K::NotAscending, 3),
        (K::DuplicateDot, 3),
        (K::InvalidLifecycle, 4),
        (K::WritesWithoutActive, 4),
        (K::MissingLifecycle, 5),
        (K::InvalidLifecycleValue, 5),
        (K::MisplacedLifecycle, 5),
        (K::EmptyRegister, 5),
        (K::ZeroSeq, 6),
        (K::NotCovered, 6),
        (K::OrphanHistory, 7),
        (K::LateValueCovered, 8),
    ];
    for (kind, rule) in all {
        assert_eq!(kind.rule(), rule, "{kind:?}");
        assert!(!kind.to_string().is_empty());
    }

    // The accessors of a parsed tombstone.
    let t = Tombstone::new(
        dot(A, 2),
        hlc(1, 2),
        vv(&[(A, 1)]),
        SymmetricKeyId::from_bytes([5; 16]),
        vec![],
    );
    assert_eq!((t.purge_dot(), t.purge_hlc()), (dot(A, 2), hlc(1, 2)));
    assert!(t.late().is_empty());
    assert_eq!(SnapshotData::Tombstone(t).kind(), RecordKind::Tombstone);
}
