//! Record property tests (ADR 0018 §12 "Property tests", first bullet).
//!
//! Generated op data, live snapshots and tombstones, over random grammar keys (known and
//! unknown alike) and random value bytes (valid, malformed and of unknown types alike):
//!
//! - encode → parse → encode is the identity, the encoder's bytes equal the independent
//!   [`Spec`] writer's, and unknown keys and values are carried through byte for byte;
//! - the writers' first pass sizes the output exactly, so the plaintext buffer is never
//!   reallocated (and never leaves an unwiped copy behind, CRYPTO.md §12.2);
//! - [`canonical_state`] is `u16 1 ‖ covered VV ‖ data`;
//! - reordering two adjacent elements, duplicating one, truncating the data anywhere or
//!   appending a byte is rejected, never a panic;
//! - changing one byte of a valid record never yields the same record;
//! - a mutation of a valid encoding (a changed, inserted or removed byte, an overwritten
//!   `u16`) that still parses re-encodes to exactly the mutated bytes, so each record has one
//!   encoding;
//! - arbitrary bytes never panic (a no-panic test only: random bytes practically never parse).

use std::collections::BTreeMap;

use proptest::prelude::*;
use rizzy_core::ids::SymmetricKeyId;

use super::encode::{op_len, snapshot_len};
use super::testkit::{Spec, SpecEntry, dot, key, vv};
use super::*;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Grammar keys: `fixed` and `element` forms, short enough to collide now and then.
fn arb_key() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-c][a-c0-9_]{0,3}(\\.[a-c][a-c0-9_]{0,3}){1,2}",
        "[a-c]{1,3}/([0-9a-f]{2}){1,2}(/[a-c][a-c0-9_]{0,2})?",
    ]
}

/// Value bytes of any kind, the Cleared value included.
fn arb_value() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..10)
}

/// A register's values: dot `(device byte 1–3, seq 1–6)` → `(hlc, value)`.
type Vals = BTreeMap<(u8, u64), (u64, Vec<u8>)>;

fn arb_vals(
    len: core::ops::Range<usize>,
    value: BoxedStrategy<Vec<u8>>,
) -> impl Strategy<Value = Vals> {
    prop::collection::btree_map((1..=3u8, 1..=6u64), (any::<u64>(), value), len)
}

/// Owned op data.
#[derive(Clone, Debug)]
struct OpModel {
    /// The marker.
    lifecycle: Lifecycle,
    /// The writes, by key.
    writes: BTreeMap<String, Vec<u8>>,
}

fn arb_op() -> impl Strategy<Value = OpModel> {
    prop_oneof![
        4 => prop::collection::btree_map(arb_key(), arb_value(), 0..8)
            .prop_map(|writes| OpModel { lifecycle: Lifecycle::Active, writes }),
        1 => prop_oneof![Just(Lifecycle::Trashed), Just(Lifecycle::Purge)]
            .prop_map(|lifecycle| OpModel { lifecycle, writes: BTreeMap::new() }),
    ]
}

impl OpModel {
    fn record(&self) -> OpData<'_> {
        let writes = self
            .writes
            .iter()
            .map(|(k, v)| Write::new(key(k), Value::new(v)))
            .collect();
        OpData::new(self.lifecycle, writes)
    }

    fn writes(&self) -> Vec<(&str, &[u8])> {
        self.writes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect()
    }
}

/// Op data written verbatim by [`Spec`], in the order given.
fn spec_op(lifecycle: Lifecycle, writes: &[(&str, &[u8])]) -> Vec<u8> {
    let n = u16::try_from(writes.len()).unwrap();
    writes
        .iter()
        .fold(
            Spec::new().u8(0x01).u8(lifecycle.to_u8()).u16(n),
            |s, (k, v)| s.write(k, v),
        )
        .done()
}

/// A register list for [`Spec`]: keys and entries in the order given.
type SpecRegs<'a> = Vec<(&'a str, Vec<SpecEntry<'a>>)>;

fn spec_list(s: Spec, regs: &SpecRegs<'_>) -> Spec {
    let n = u16::try_from(regs.len()).unwrap();
    regs.iter().fold(s.u16(n), |s, (k, e)| s.register(k, e))
}

fn spec_regs(regs: &BTreeMap<String, Vals>) -> SpecRegs<'_> {
    regs.iter()
        .map(|(k, vals)| {
            let entries = vals
                .iter()
                .map(|(&(b, seq), (h, v))| (b, seq, Hlc::from_u64(*h), v.as_slice()))
                .collect();
            (k.as_str(), entries)
        })
        .collect()
}

fn registers(regs: &BTreeMap<String, Vals>) -> Vec<Register<'_>> {
    regs.iter()
        .map(|(k, vals)| {
            let entries = vals
                .iter()
                .map(|(&(b, seq), (h, v))| {
                    Entry::new(dot(b, seq), Hlc::from_u64(*h), Value::new(v))
                })
                .collect();
            Register::new(key(k), entries)
        })
        .collect()
}

/// Owned live-snapshot data with its covered VV.
#[derive(Clone, Debug)]
struct LiveModel {
    /// Current registers, `@lifecycle` included.
    regs: BTreeMap<String, Vals>,
    /// History groups, each a key of `regs`, dots disjoint from its register's.
    hist: BTreeMap<String, Vals>,
    /// Every dot, plus extra entries.
    covered: VersionVector,
}

fn lifecycle_value() -> BoxedStrategy<Vec<u8>> {
    prop_oneof![Just(vec![0x01]), Just(vec![0x02])].boxed()
}

fn arb_live() -> impl Strategy<Value = LiveModel> {
    (
        arb_vals(1..3, lifecycle_value()),
        prop::collection::btree_map(arb_key(), arb_vals(1..4, arb_value().boxed()), 0..5),
        prop::collection::vec(
            (
                any::<prop::sample::Index>(),
                arb_vals(1..3, arb_value().boxed()),
            ),
            0..4,
        ),
        prop::collection::vec((1..=4u8, 1..=9u64), 0..2),
    )
        .prop_map(|(lifecycle, mut regs, hist_picks, extra)| {
            regs.insert(LIFECYCLE_KEY.to_owned(), lifecycle);
            let keys: Vec<String> = regs.keys().cloned().collect();
            let mut hist: BTreeMap<String, Vals> = BTreeMap::new();
            for (pick, mut vals) in hist_picks {
                let k = pick.get(&keys).clone();
                vals.retain(|d, _| !regs[&k].contains_key(d));
                if k == LIFECYCLE_KEY {
                    for (_, v) in vals.values_mut() {
                        *v = vec![0x02];
                    }
                }
                if !vals.is_empty() {
                    hist.insert(k, vals);
                }
            }
            let mut covered: VersionVector = regs
                .values()
                .chain(hist.values())
                .flat_map(|vals| vals.keys().map(|&(b, s)| dot(b, s)))
                .collect();
            covered.join(&vv(&extra));
            LiveModel {
                regs,
                hist,
                covered,
            }
        })
}

impl LiveModel {
    fn record(&self) -> SnapshotData<'_> {
        SnapshotData::Live(LiveSnapshot::new(
            registers(&self.regs),
            registers(&self.hist),
        ))
    }
}

/// Live snapshot data written verbatim by [`Spec`] from its registers and history groups.
fn spec_live(regs: &SpecRegs<'_>, hist: &SpecRegs<'_>) -> Vec<u8> {
    spec_list(spec_list(Spec::new().u8(0x02), regs), hist).done()
}

/// Owned tombstone data with its covered VV.
#[derive(Clone, Debug)]
struct TombModel {
    /// The recorded purge's dot.
    purge: (u8, u64),
    /// Its HLC.
    purge_hlc: u64,
    /// `c`.
    c: VersionVector,
    /// `item_key_id`.
    item_key_id: [u8; 16],
    /// The late registers, dots outside `c`.
    late: BTreeMap<String, Vals>,
    /// Every dot and every entry of `c`, plus extra entries.
    covered: VersionVector,
}

fn arb_tomb() -> impl Strategy<Value = TombModel> {
    (
        (1..=3u8, 1..=6u64),
        any::<u64>(),
        prop::collection::vec((1..=3u8, 1..=4u64), 0..3),
        any::<[u8; 16]>(),
        prop::collection::btree_map(arb_key(), arb_vals(1..4, arb_value().boxed()), 0..4),
        prop::collection::vec((1..=4u8, 1..=9u64), 0..2),
    )
        .prop_map(|(purge, purge_hlc, c, item_key_id, mut late, extra)| {
            let c = vv(&c);
            for vals in late.values_mut() {
                vals.retain(|&(b, s), _| !c.covers(dot(b, s)));
            }
            late.retain(|_, vals| !vals.is_empty());
            let mut covered: VersionVector = late
                .values()
                .flat_map(|vals| vals.keys().map(|&(b, s)| dot(b, s)))
                .collect();
            covered.add(dot(purge.0, purge.1));
            covered.join(&c);
            covered.join(&vv(&extra));
            TombModel {
                purge,
                purge_hlc,
                c,
                item_key_id,
                late,
                covered,
            }
        })
}

impl TombModel {
    fn record(&self) -> SnapshotData<'_> {
        SnapshotData::Tombstone(Tombstone::new(
            dot(self.purge.0, self.purge.1),
            Hlc::from_u64(self.purge_hlc),
            self.c.clone(),
            SymmetricKeyId::from_bytes(self.item_key_id),
            registers(&self.late),
        ))
    }

    fn spec(&self, late: &SpecRegs<'_>) -> Vec<u8> {
        let c: Vec<(u8, u64)> = self
            .c
            .entries()
            .map(|d| (d.device_id().as_bytes()[0], d.seq()))
            .collect();
        let s = Spec::new()
            .u8(0x03)
            .dot(self.purge.0, self.purge.1)
            .u64(self.purge_hlc)
            .vv(&c)
            .raw(&self.item_key_id);
        spec_list(s, late).done()
    }
}

/// Every proper prefix and a one-byte extension are rejected.
fn truncations_and_extensions(bytes: &[u8], parse: impl Fn(&[u8]) -> Result<(), RecordError>) {
    for len in 0..bytes.len() {
        assert!(
            parse(&bytes[..len]).is_err(),
            "prefix of {len} bytes accepted"
        );
    }
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert_eq!(
        parse(&longer).unwrap_err().kind(),
        RecordErrorKind::TrailingBytes
    );
}

/// Swaps elements `i` and `i + 1`.
fn swapped<T: Clone>(items: &[T], i: usize) -> Vec<T> {
    let mut v = items.to_vec();
    v.swap(i, i + 1);
    v
}

/// Inserts a copy of element `i` after it.
fn duplicated<T: Clone>(items: &[T], i: usize) -> Vec<T> {
    let mut v = items.to_vec();
    v.insert(i + 1, items[i].clone());
    v
}

/// One change to a valid encoding, at a position picked in proportion to its length.
#[derive(Clone, Debug)]
enum Mutation {
    /// XOR one byte with a non-zero mask.
    Flip(prop::sample::Index, u8),
    /// Insert one byte before a position (or at the end).
    Insert(prop::sample::Index, u8),
    /// Remove 1–8 bytes from a position, as many as there are.
    Remove(prop::sample::Index, usize),
    /// Overwrite two bytes with a big-endian `u16`: a count, most often, or half a length.
    SetU16(prop::sample::Index, u16),
}

/// Any [`Mutation`], each kind equally likely.
fn arb_mutation() -> impl Strategy<Value = Mutation> {
    let at = any::<prop::sample::Index>;
    prop_oneof![
        (at(), 1..=255u8).prop_map(|(i, m)| Mutation::Flip(i, m)),
        (at(), any::<u8>()).prop_map(|(i, b)| Mutation::Insert(i, b)),
        (at(), 1..=8usize).prop_map(|(i, n)| Mutation::Remove(i, n)),
        (at(), any::<u16>()).prop_map(|(i, v)| Mutation::SetU16(i, v)),
    ]
}

impl Mutation {
    /// The mutated copy of `bytes` (never empty: every encoding here has at least 4 bytes).
    fn apply(&self, bytes: &[u8]) -> Vec<u8> {
        let mut m = bytes.to_vec();
        match *self {
            Self::Flip(ref i, mask) => m[i.index(bytes.len())] ^= mask,
            Self::Insert(ref i, byte) => m.insert(i.index(bytes.len() + 1), byte),
            Self::Remove(ref i, n) => {
                let at = i.index(bytes.len());
                m.drain(at..(at + n).min(bytes.len()));
            }
            Self::SetU16(ref i, value) => {
                let at = i.index(bytes.len() - 1);
                m[at..at + 2].copy_from_slice(&value.to_be_bytes());
            }
        }
        m
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn op_round_trip(m in arb_op()) {
        let record = m.record();
        let bytes = encode_op(&record).unwrap();
        let spec = spec_op(m.lifecycle, &m.writes());
        // The writer sized its buffer exactly, so it never reallocated plaintext.
        prop_assert_eq!(op_len(&record, Limits::V1), Ok(bytes.len()));
        prop_assert_eq!(bytes.expose_secret(), spec.as_slice());
        let parsed = parse_op(bytes.expose_secret()).unwrap();
        prop_assert_eq!(&parsed, &record);
        let again = encode_op(&parsed).unwrap();
        prop_assert_eq!(again.expose_secret(), bytes.expose_secret());
        for (w, (k, v)) in parsed.writes().iter().zip(&m.writes) {
            prop_assert_eq!(w.key().expose_secret(), k.as_str());
            prop_assert_eq!(w.value().expose_secret(), v.as_slice());
        }
        truncations_and_extensions(bytes.expose_secret(), |d| parse_op(d).map(drop));
    }

    #[test]
    fn op_reordering_and_duplication_are_rejected(m in arb_op(), i in any::<prop::sample::Index>()) {
        let writes = m.writes();
        if writes.len() >= 2 {
            let i = i.index(writes.len() - 1);
            let e = parse_op(&spec_op(m.lifecycle, &swapped(&writes, i))).unwrap_err();
            prop_assert_eq!(e.kind(), RecordErrorKind::NotAscending);
        }
        if !writes.is_empty() {
            let i = i.index(writes.len());
            let e = parse_op(&spec_op(m.lifecycle, &duplicated(&writes, i))).unwrap_err();
            prop_assert_eq!(e.kind(), RecordErrorKind::NotAscending);
        }
    }

    #[test]
    fn live_round_trip(m in arb_live()) {
        let record = m.record();
        let bytes = encode_snapshot(&m.covered, &record).unwrap();
        let spec = spec_live(&spec_regs(&m.regs), &spec_regs(&m.hist));
        prop_assert_eq!(snapshot_len(&record, Limits::V1), Ok(bytes.len()));
        prop_assert_eq!(bytes.expose_secret(), spec.as_slice());
        let parsed = parse_snapshot(&m.covered, bytes.expose_secret()).unwrap();
        prop_assert_eq!(&parsed, &record);
        let again = encode_snapshot(&m.covered, &parsed).unwrap();
        prop_assert_eq!(again.expose_secret(), bytes.expose_secret());
        let state = canonical_state(&m.covered, &parsed).unwrap();
        let expected = [&[0x00, 0x01][..], &m.covered.to_vec().unwrap(), bytes.expose_secret()].concat();
        prop_assert_eq!(state.expose_secret(), expected.as_slice());
        truncations_and_extensions(bytes.expose_secret(), |d| parse_snapshot(&m.covered, d).map(drop));
    }

    #[test]
    fn live_reordering_and_duplication_are_rejected(m in arb_live(), i in any::<prop::sample::Index>(), j in any::<prop::sample::Index>()) {
        let regs = spec_regs(&m.regs);
        let hist = spec_regs(&m.hist);
        // Registers and history groups: swapping two or repeating one breaks the key order,
        // or (for the first register) the @lifecycle rule.
        if regs.len() >= 2 {
            prop_assert!(parse_snapshot(&m.covered, &spec_live(&swapped(&regs, i.index(regs.len() - 1)), &hist)).is_err());
        }
        prop_assert!(parse_snapshot(&m.covered, &spec_live(&duplicated(&regs, i.index(regs.len())), &hist)).is_err());
        if !hist.is_empty() {
            let e = parse_snapshot(&m.covered, &spec_live(&regs, &duplicated(&hist, i.index(hist.len())))).unwrap_err();
            prop_assert_eq!(e.kind(), RecordErrorKind::NotAscending);
        }
        // Entries: swapping two or repeating one breaks the dot order.
        let r = i.index(regs.len());
        let mut changed = regs.clone();
        changed[r].1 = duplicated(&regs[r].1, j.index(regs[r].1.len()));
        let e = parse_snapshot(&m.covered, &spec_live(&changed, &hist)).unwrap_err();
        prop_assert_eq!(e.kind(), RecordErrorKind::NotAscending);
        if regs[r].1.len() >= 2 {
            let mut changed = regs.clone();
            changed[r].1 = swapped(&regs[r].1, j.index(regs[r].1.len() - 1));
            let e = parse_snapshot(&m.covered, &spec_live(&changed, &hist)).unwrap_err();
            prop_assert_eq!(e.kind(), RecordErrorKind::NotAscending);
        }
    }

    #[test]
    fn tombstone_round_trip(m in arb_tomb()) {
        let record = m.record();
        let bytes = encode_snapshot(&m.covered, &record).unwrap();
        let spec = m.spec(&spec_regs(&m.late));
        prop_assert_eq!(snapshot_len(&record, Limits::V1), Ok(bytes.len()));
        prop_assert_eq!(bytes.expose_secret(), spec.as_slice());
        let parsed = parse_snapshot(&m.covered, bytes.expose_secret()).unwrap();
        prop_assert_eq!(&parsed, &record);
        let again = encode_snapshot(&m.covered, &parsed).unwrap();
        prop_assert_eq!(again.expose_secret(), bytes.expose_secret());
        if m.late.is_empty() {
            prop_assert_eq!(bytes.len(), 53 + 24 * m.c.len());
        }
        truncations_and_extensions(bytes.expose_secret(), |d| parse_snapshot(&m.covered, d).map(drop));
    }

    #[test]
    fn tombstone_reordering_and_duplication_are_rejected(m in arb_tomb(), i in any::<prop::sample::Index>()) {
        let late = spec_regs(&m.late);
        if late.len() >= 2 {
            let e = parse_snapshot(&m.covered, &m.spec(&swapped(&late, i.index(late.len() - 1)))).unwrap_err();
            prop_assert_eq!(e.kind(), RecordErrorKind::NotAscending);
        }
        if !late.is_empty() {
            let e = parse_snapshot(&m.covered, &m.spec(&duplicated(&late, i.index(late.len())))).unwrap_err();
            prop_assert_eq!(e.kind(), RecordErrorKind::NotAscending);
        }
    }

    /// One changed byte never gives back the same record: each record has one encoding.
    #[test]
    fn a_changed_byte_never_gives_the_same_record(m in arb_live(), t in arb_tomb(), pos in any::<prop::sample::Index>(), flip in 1..=255u8) {
        let record = m.record();
        let mut bytes = encode_snapshot(&m.covered, &record).unwrap().expose_secret().to_vec();
        let i = pos.index(bytes.len());
        bytes[i] ^= flip;
        prop_assert_ne!(parse_snapshot(&m.covered, &bytes).ok(), Some(record));
        let record = t.record();
        let mut bytes = encode_snapshot(&t.covered, &record).unwrap().expose_secret().to_vec();
        let i = pos.index(bytes.len());
        bytes[i] ^= flip;
        prop_assert_ne!(parse_snapshot(&t.covered, &bytes).ok(), Some(record));
    }

    /// A mutation of a valid encoding that still parses re-encodes to exactly the mutated
    /// bytes: each record has one encoding (ADR 0018 §4). Mutations inside values, HLCs and
    /// `item_key_id` parse often, so the check runs on accepted inputs (the vectors' mutation
    /// test requires that on the committed vectors).
    #[test]
    fn accepted_mutations_are_canonical(o in arb_op(), m in arb_live(), t in arb_tomb(), mutation in arb_mutation()) {
        let bytes = encode_op(&o.record()).unwrap();
        let mutated = mutation.apply(bytes.expose_secret());
        if let Ok(op) = parse_op(&mutated) {
            let again = encode_op(&op).unwrap();
            prop_assert_eq!(again.expose_secret(), mutated.as_slice());
        }
        for (covered, record) in [(&m.covered, m.record()), (&t.covered, t.record())] {
            let bytes = encode_snapshot(covered, &record).unwrap();
            let mutated = mutation.apply(bytes.expose_secret());
            if let Ok(s) = parse_snapshot(covered, &mutated) {
                let again = encode_snapshot(covered, &s).unwrap();
                prop_assert_eq!(again.expose_secret(), mutated.as_slice());
            }
        }
    }

    /// Arbitrary bytes, the kind byte steered towards the three kinds, never panic the parsers.
    /// A no-panic test only: random bytes practically never form a valid record, so the
    /// re-encoding check below almost never runs. Canonicality is checked from valid encodings
    /// by `accepted_mutations_are_canonical` and the vectors' mutation test.
    #[test]
    fn arbitrary_bytes_never_panic(kind in 0..=4u8, rest in prop::collection::vec(any::<u8>(), 0..160), covered in prop::collection::vec((1..=3u8, 1..=6u64), 0..4)) {
        let covered = vv(&covered);
        let data = [&[kind][..], &rest].concat();
        if let Ok(op) = parse_op(&data) {
            let again = encode_op(&op).unwrap();
            prop_assert_eq!(again.expose_secret(), data.as_slice());
        }
        if let Ok(s) = parse_snapshot(&covered, &data) {
            let again = encode_snapshot(&covered, &s).unwrap();
            prop_assert_eq!(again.expose_secret(), data.as_slice());
        }
    }
}
