//! Version-vector tests.
//!
//! - Known answers for the canonical encoding (ADR 0012 §3), independent of insertion order,
//!   and for its bytewise entry order being first-byte-most-significant.
//! - One negative case per rejection rule (truncated count or entries, a hostile count, `seq`
//!   0, out of order, duplicate, trailing bytes), each asserting that the reader did not move.
//!   They also pin the kind and offset each decoder documents; those are local diagnostics,
//!   not format (see [`crate::error`]).
//! - The worked examples of the ADRs: the ADR 0012 §7 cover that a VV check cannot tell from a
//!   withheld op, ADR 0021 §2's clamp, ADR 0018 §3's join of purge contexts.
//! - The `u16` bound on both sides.
//! - Property tests: join and meet form a lattice (commutative, associative, idempotent,
//!   absorptive, least upper and greatest lower bounds), `compare`, `PartialOrd` and `covers`
//!   agree with it, encode → parse is the identity with the encoded ids strictly ascending as
//!   byte strings, and parse accepts only canonical bytes and never panics.

use proptest::prelude::*;

use super::*;

/// A device id whose 16 bytes are all `b`.
fn device(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

fn dot(b: u8, seq: u64) -> Dot {
    Dot::new(device(b), seq).unwrap()
}

fn vv(entries: &[(u8, u64)]) -> VersionVector {
    entries.iter().map(|&(b, seq)| dot(b, seq)).collect()
}

/// `u16 n` and then each `(b × 16) ‖ u64 seq`, written out by hand.
fn raw(entries: &[(u8, u64)]) -> Vec<u8> {
    let mut out = u16::try_from(entries.len()).unwrap().to_be_bytes().to_vec();
    for &(b, seq) in entries {
        out.extend_from_slice(&[b; 16]);
        out.extend_from_slice(&seq.to_be_bytes());
    }
    out
}

fn rejects(bytes: &[u8], kind: DecodeErrorKind, offset: usize) {
    let e = VersionVector::parse(bytes).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (kind, offset), "{bytes:02x?}");
    let mut r = Reader::new(bytes);
    if VersionVector::read(&mut r).is_err() {
        assert_eq!(r.remaining(), bytes.len(), "reader moved on error");
    }
}

#[test]
fn encoding_known_answers() {
    assert_eq!(VersionVector::new().to_vec().unwrap(), [0x00, 0x00]);
    assert_eq!(VersionVector::new().encoded_len(), 2);
    let v = vv(&[(0xb0, 0x0102), (0x0a, 1)]);
    let expected = [
        0x00, 0x02, // n = 2
        0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
        0x0a, // device 0a…
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // seq 1
        0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0,
        0xb0, // device b0…
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, // seq 0x0102
    ];
    assert_eq!(v.to_vec().unwrap(), expected);
    assert_eq!(v.to_vec().unwrap(), raw(&[(0x0a, 1), (0xb0, 0x0102)]));
    assert_eq!(v.encoded_len(), expected.len());
    // Insertion order does not matter, and a lower seq for a device does not lower it.
    let w = vv(&[(0x0a, 1), (0xb0, 3), (0xb0, 0x0102), (0x0a, 1)]);
    assert_eq!(w, v);
    assert_eq!(w.to_vec().unwrap(), expected);
    assert_eq!(VersionVector::parse(&expected), Ok(v.clone()));
    // encode appends.
    let mut out = vec![0xee];
    v.encode(&mut out).unwrap();
    assert_eq!(out.first(), Some(&0xee));
    assert_eq!(out.get(1..), Some(expected.as_slice()));
}

/// "Strictly ascending bytewise" (ADR 0012 §3) is lexicographic from the first byte. The ids
/// A = 00 ff … ff and B = 01 00 … 00 disagree in their first and last bytes, so any order over
/// reversed or permuted bytes (for example a little-endian integer key) would put B first.
#[test]
fn bytewise_order_is_first_byte_most_significant() {
    let mut a_id = [0xff; 16];
    a_id[0] = 0x00;
    let mut b_id = [0x00; 16];
    b_id[0] = 0x01;
    let (a, b) = (DeviceId::from_bytes(a_id), DeviceId::from_bytes(b_id));
    let v: VersionVector = [Dot::new(b, 1).unwrap(), Dot::new(a, 1).unwrap()]
        .into_iter()
        .collect();
    let a_then_b = [
        0x00, 0x02, // n = 2
        0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, // A
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // seq 1
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // B
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // seq 1
    ];
    assert_eq!(v.to_vec().unwrap(), a_then_b);
    assert_eq!(
        v.entries().collect::<Vec<_>>(),
        [Dot::new(a, 1).unwrap(), Dot::new(b, 1).unwrap()]
    );
    assert_eq!(VersionVector::parse(&a_then_b), Ok(v));
    // The same entries written B first are not canonical.
    let mut b_then_a = a_then_b[..2].to_vec();
    b_then_a.extend_from_slice(&a_then_b[26..]);
    b_then_a.extend_from_slice(&a_then_b[2..26]);
    rejects(&b_then_a, DecodeErrorKind::NotAscending, 26);
}

#[test]
fn entries_get_and_covers() {
    let v = vv(&[(3, 7), (1, 2)]);
    assert_eq!(v.len(), 2);
    assert!(!v.is_empty());
    assert_eq!(v.entries().collect::<Vec<_>>(), [dot(1, 2), dot(3, 7)]);
    assert_eq!(v.get(device(1)), 2);
    assert_eq!(v.get(device(2)), 0);
    assert!(v.covers(dot(3, 7)) && v.covers(dot(3, 1)));
    assert!(!v.covers(dot(3, 8)) && !v.covers(dot(2, 1)));
    assert!(VersionVector::new().is_empty());
    assert_eq!(VersionVector::default(), VersionVector::new());
}

#[test]
fn every_rejection_rule() {
    // Count missing or incomplete.
    rejects(&[], DecodeErrorKind::Truncated, 0);
    rejects(&[0x00], DecodeErrorKind::Truncated, 0);
    // Fewer bytes than n entries need, checked before any entry is read: a hostile count.
    let one = raw(&[(1, 1)]);
    rejects(&[0xff, 0xff], DecodeErrorKind::Truncated, 0);
    let mut hostile = one.clone();
    hostile[..2].copy_from_slice(&[0xff, 0xff]);
    rejects(&hostile, DecodeErrorKind::Truncated, 0);
    let mut short = raw(&[(1, 1), (2, 1)]);
    short.pop();
    rejects(&short, DecodeErrorKind::Truncated, 0);
    // seq 0, in the first and a later entry: offset of the seq field.
    rejects(&raw(&[(1, 0)]), DecodeErrorKind::ZeroSeq, 18);
    rejects(&raw(&[(1, 5), (2, 0)]), DecodeErrorKind::ZeroSeq, 42);
    // Out of order, and a duplicate: offset of the offending device id.
    rejects(&raw(&[(2, 1), (1, 1)]), DecodeErrorKind::NotAscending, 26);
    rejects(&raw(&[(1, 1), (1, 2)]), DecodeErrorKind::NotAscending, 26);
    rejects(
        &raw(&[(1, 1), (3, 1), (2, 1)]),
        DecodeErrorKind::NotAscending,
        50,
    );
    // Out of order only in the last byte of the id.
    let mut last_byte = raw(&[(1, 1), (1, 1)]);
    last_byte[17] = 0x02;
    rejects(&last_byte, DecodeErrorKind::NotAscending, 26);
    // Trailing bytes: `parse` rejects them, `read` leaves them.
    let mut trailing = one.clone();
    trailing.push(0x00);
    rejects(&trailing, DecodeErrorKind::TrailingBytes, 26);
    let mut r = Reader::new(&trailing);
    assert_eq!(VersionVector::read(&mut r), Ok(vv(&[(1, 1)])));
    assert_eq!(r.remaining(), 1);
}

#[test]
fn read_reports_offsets_relative_to_its_start() {
    let mut bytes = vec![0xaa; 5];
    bytes.extend_from_slice(&raw(&[(1, 1), (2, 0)]));
    let mut r = Reader::new(&bytes);
    r.take(5).unwrap();
    let e = VersionVector::read(&mut r).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (DecodeErrorKind::ZeroSeq, 42));
    assert_eq!(r.remaining(), bytes.len() - 5);
}

/// ADR 0012 §7 "Chain check after compaction": X's snapshot has VV[D] = 50, so a VV check
/// counts D's seq 12, an edit of item Z, as covered. The retained header is what tells them
/// apart; coverage alone cannot.
#[test]
fn adr_0012_withheld_op_example() {
    let snapshot_of_x = vv(&[(0xd0, 50)]);
    assert!(snapshot_of_x.covers(dot(0xd0, 12)));
    let cursor = vv(&[(0xd0, 10)]);
    assert!(!cursor.covers(dot(0xd0, 12)));
    assert_eq!(cursor.compare(&snapshot_of_x), VvOrdering::Less);
}

/// ADR 0021 §2: `clamped(S)[d] = min(covered(S)[d], h(V, d))`, zero entries left out.
#[test]
fn adr_0021_clamp_is_a_meet() {
    let mut clamped = vv(&[(1, 50), (2, 3), (4, u64::MAX)]);
    let heads = vv(&[(1, 40), (3, 9), (4, 12)]);
    clamped.meet(&heads);
    assert_eq!(clamped, vv(&[(1, 40), (4, 12)]));
    assert_eq!(clamped.get(device(2)), 0);
    assert_eq!(clamped.to_vec().unwrap(), raw(&[(1, 40), (4, 12)]));
    // A snapshot never covers an op stored after it.
    assert!(!clamped.covers(dot(1, 41)));
}

/// ADR 0018 §3 "Context": `c` is the canonical join of the applied purges' contexts.
#[test]
fn adr_0018_purge_context_join() {
    let mut c = vv(&[(1, 4), (2, 9)]);
    c.join(&vv(&[(1, 6), (3, 1)]));
    assert_eq!(c, vv(&[(1, 6), (2, 9), (3, 1)]));
    let mut again = c.clone();
    again.join(&vv(&[(1, 5)]));
    assert_eq!(again, c);
}

#[test]
fn compare_and_partial_ord() {
    let a = vv(&[(1, 2), (2, 1)]);
    let b = vv(&[(1, 3), (2, 1)]);
    let c = vv(&[(1, 1), (3, 1)]);
    assert_eq!(a.compare(&a.clone()), VvOrdering::Equal);
    assert_eq!(a.compare(&b), VvOrdering::Less);
    assert_eq!(b.compare(&a), VvOrdering::Greater);
    assert_eq!(a.compare(&c), VvOrdering::Concurrent);
    assert_eq!(VersionVector::new().compare(&a), VvOrdering::Less);
    assert!(a < b);
    assert!(b > a);
    assert!(a <= a.clone());
    assert_eq!(a.partial_cmp(&c), None);
    assert_eq!(c.partial_cmp(&a), None);
}

#[test]
fn the_u16_count_bounds_both_sides() {
    let mut full: VersionVector = (0..u16::MAX)
        .map(|i| {
            let mut id = [0u8; 16];
            id.iter_mut()
                .zip(i.to_be_bytes())
                .for_each(|(dst, src)| *dst = src);
            Dot::new(DeviceId::from_bytes(id), 1).unwrap()
        })
        .collect();
    assert_eq!(full.len(), VersionVector::MAX_ENTRIES);
    assert_eq!(VersionVector::MAX_ENTRIES, usize::from(u16::MAX));
    let bytes = full.to_vec().unwrap();
    assert_eq!(bytes.len(), 2 + 24 * 65_535);
    assert_eq!(bytes.get(..2), Some([0xff, 0xff].as_slice()));
    assert_eq!(VersionVector::parse(&bytes).as_ref(), Ok(&full));
    full.add(Dot::new(DeviceId::from_bytes([0xff; 16]), 1).unwrap());
    let mut out = vec![0xee];
    assert_eq!(full.encode(&mut out), Err(EncodeError::TooManyEntries));
    assert_eq!(out, [0xee]);
    assert_eq!(full.to_vec(), Err(EncodeError::TooManyEntries));
}

// ---------------------------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------------------------

/// Devices: mostly from a small pool, so that vectors share entries, and sometimes any id.
fn arb_device() -> impl Strategy<Value = DeviceId> {
    prop_oneof![
        4 => (0u8..5).prop_map(device),
        1 => any::<[u8; 16]>().prop_map(DeviceId::from_bytes),
    ]
}

/// Sequence numbers: mostly small, sometimes at the top of the range.
fn arb_seq() -> impl Strategy<Value = u64> {
    prop_oneof![
        4 => 1u64..6,
        1 => u64::MAX - 2..=u64::MAX,
        1 => 1..=u64::MAX,
    ]
}

fn arb_dot() -> impl Strategy<Value = Dot> {
    (arb_device(), arb_seq()).prop_map(|(d, s)| Dot::new(d, s).unwrap())
}

fn arb_vv() -> impl Strategy<Value = VersionVector> {
    prop::collection::vec(arb_dot(), 0..8).prop_map(|dots| dots.into_iter().collect())
}

fn joined(a: &VersionVector, b: &VersionVector) -> VersionVector {
    let mut v = a.clone();
    v.join(b);
    v
}

fn met(a: &VersionVector, b: &VersionVector) -> VersionVector {
    let mut v = a.clone();
    v.meet(b);
    v
}

/// Entrywise `a ≤ b`, computed directly from the entries.
fn leq(a: &VersionVector, b: &VersionVector) -> bool {
    a.entries().all(|d| b.get(d.device_id()) >= d.seq())
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn join_is_commutative_associative_idempotent(
        a in arb_vv(), b in arb_vv(), c in arb_vv()
    ) {
        prop_assert_eq!(joined(&a, &b), joined(&b, &a));
        prop_assert_eq!(joined(&joined(&a, &b), &c), joined(&a, &joined(&b, &c)));
        prop_assert_eq!(joined(&a, &a), a.clone());
        prop_assert_eq!(joined(&a, &VersionVector::new()), a);
    }

    #[test]
    fn meet_is_commutative_associative_idempotent(
        a in arb_vv(), b in arb_vv(), c in arb_vv()
    ) {
        prop_assert_eq!(met(&a, &b), met(&b, &a));
        prop_assert_eq!(met(&met(&a, &b), &c), met(&a, &met(&b, &c)));
        prop_assert_eq!(met(&a, &a), a.clone());
        prop_assert_eq!(met(&a, &VersionVector::new()), VersionVector::new());
    }

    #[test]
    fn join_and_meet_are_the_bounds(a in arb_vv(), b in arb_vv(), probe in arb_dot()) {
        let (j, m) = (joined(&a, &b), met(&a, &b));
        // Absorption.
        prop_assert_eq!(joined(&a, &m), a.clone());
        prop_assert_eq!(met(&a, &j), a.clone());
        // Upper and lower bounds.
        prop_assert!(leq(&a, &j) && leq(&b, &j) && leq(&m, &a) && leq(&m, &b));
        // Least and greatest: coverage is exactly "either" and "both".
        prop_assert_eq!(j.covers(probe), a.covers(probe) || b.covers(probe));
        prop_assert_eq!(m.covers(probe), a.covers(probe) && b.covers(probe));
        // Entry by entry.
        let d = probe.device_id();
        prop_assert_eq!(j.get(d), a.get(d).max(b.get(d)));
        prop_assert_eq!(m.get(d), a.get(d).min(b.get(d)));
        // No zero entry is ever stored.
        prop_assert!(j.entries().chain(m.entries()).all(|e| e.seq() >= 1));
    }

    #[test]
    fn compare_agrees_with_the_entrywise_order(a in arb_vv(), b in arb_vv()) {
        let expected = match (leq(&a, &b), leq(&b, &a)) {
            (true, true) => VvOrdering::Equal,
            (true, false) => VvOrdering::Less,
            (false, true) => VvOrdering::Greater,
            (false, false) => VvOrdering::Concurrent,
        };
        prop_assert_eq!(a.compare(&b), expected);
        let reversed = match expected {
            VvOrdering::Less => VvOrdering::Greater,
            VvOrdering::Greater => VvOrdering::Less,
            other => other,
        };
        prop_assert_eq!(b.compare(&a), reversed);
        prop_assert_eq!(expected == VvOrdering::Equal, a == b);
        prop_assert_eq!(a <= b, leq(&a, &b));
        prop_assert_eq!(leq(&a, &b), joined(&a, &b) == b);
        prop_assert_eq!(leq(&a, &b), met(&a, &b) == a);
    }

    #[test]
    fn add_is_a_join_with_one_entry(a in arb_vv(), d in arb_dot()) {
        let mut added = a.clone();
        added.add(d);
        prop_assert!(added.covers(d));
        prop_assert_eq!(&added, &joined(&a, &core::iter::once(d).collect()));
        prop_assert!(leq(&a, &added));
    }

    #[test]
    fn encode_then_parse_is_the_identity(a in arb_vv(), tail in any::<Vec<u8>>()) {
        let bytes = a.to_vec().unwrap();
        prop_assert_eq!(bytes.len(), a.encoded_len());
        // The encoded ids are strictly ascending as byte strings, compared as slices: an
        // oracle independent of `DeviceId`'s `Ord`.
        let ids: Vec<&[u8]> = bytes[2..]
            .chunks(VersionVector::ENTRY_LEN)
            .map(|e| &e[..16])
            .collect();
        prop_assert!(ids.windows(2).all(|w| w[0] < w[1]));
        prop_assert_eq!(VersionVector::parse(&bytes), Ok(a.clone()));
        // Inside a larger structure, `read` stops at the vector's end.
        let mut longer = bytes.clone();
        longer.extend_from_slice(&tail);
        let mut r = Reader::new(&longer);
        prop_assert_eq!(VersionVector::read(&mut r), Ok(a));
        prop_assert_eq!(r.remaining(), tail.len());
    }

    #[test]
    fn non_canonical_encodings_are_rejected(
        a in arb_vv(), cut in any::<prop::sample::Index>(), pick in any::<prop::sample::Index>()
    ) {
        let bytes = a.to_vec().unwrap();
        // Every truncation.
        let len = cut.index(bytes.len());
        prop_assert!(VersionVector::parse(bytes.get(..len).unwrap()).is_err());
        // Any trailing byte.
        let mut longer = bytes.clone();
        longer.push(0);
        prop_assert!(VersionVector::parse(&longer).is_err());
        let entries: Vec<Dot> = a.entries().collect();
        if !entries.is_empty() {
            let i = pick.index(entries.len());
            // A duplicated entry, in place.
            let mut dup = entries.clone();
            dup.insert(i, dup[i]);
            prop_assert!(VersionVector::parse(&encode_list(&dup)).is_err());
            // A zero seq.
            let mut zeroed = a.to_vec().unwrap();
            let seq_at = 2 + 24 * i + 16;
            zeroed[seq_at..seq_at + 8].fill(0);
            prop_assert!(VersionVector::parse(&zeroed).is_err());
        }
        if entries.len() >= 2 {
            // Two entries swapped.
            let i = pick.index(entries.len() - 1);
            let mut swapped = entries.clone();
            swapped.swap(i, i + 1);
            prop_assert!(VersionVector::parse(&encode_list(&swapped)).is_err());
        }
    }

    #[test]
    fn arbitrary_bytes_parse_only_if_canonical(bytes in any::<Vec<u8>>(), n in 0u16..4) {
        // Random bytes after a small count, so that some inputs reach the entry checks.
        let mut input = n.to_be_bytes().to_vec();
        input.extend_from_slice(&bytes);
        for candidate in [&bytes, &input] {
            if let Ok(v) = VersionVector::parse(candidate) {
                prop_assert_eq!(&v.to_vec().unwrap(), candidate);
            }
        }
    }
}

/// Encodes a list of entries as given, in its order and with its duplicates.
fn encode_list(entries: &[Dot]) -> Vec<u8> {
    let mut out = u16::try_from(entries.len()).unwrap().to_be_bytes().to_vec();
    for d in entries {
        d.encode(&mut out);
    }
    out
}
