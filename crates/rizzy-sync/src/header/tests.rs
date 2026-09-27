//! Header tests.
//!
//! - Known answers for both layouts (ADR 0012 §3), spelled out field by field, and their
//!   lengths against the bounds `rizzy-core`'s statements enforce.
//! - The bytes round-trip through [`OpStatement`] and [`SnapshotStatement`], and the AAD
//!   contexts carry the header's fields and the hash of exactly the signed bytes.
//! - One rejection per strict-parsing rule (version, `device_seq` 0, schema version 0 and
//!   `0xFFFF`, non-canonical version vector, truncation at every length, trailing bytes),
//!   pinning the kind and offset each documents; an unknown but valid schema version parses.
//! - Canonicality (one encoding per header): every mutation of a valid header that still
//!   parses re-encodes to exactly the mutated bytes, exhaustively on the known answers and on
//!   random mutations of random headers.
//! - Property tests: encode → parse is the identity; a changed byte never gives back the same
//!   header; arbitrary bytes never panic the parser.

use proptest::prelude::*;
use rizzy_core::sign::statements::{
    OP_HEADER_MAX_LEN, OP_HEADER_MIN_LEN, SNAPSHOT_HEADER_MAX_LEN, SNAPSHOT_HEADER_MIN_LEN,
};

use super::*;

/// A device id whose 16 bytes are all `b`.
fn device(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

fn vv(entries: &[(u8, u64)]) -> VersionVector {
    entries
        .iter()
        .map(|&(b, seq)| Dot::new(device(b), seq).unwrap())
        .collect()
}

fn op_header() -> OpHeader {
    OpHeader {
        vault_id: VaultId::from_bytes([0x11; 16]),
        item_id: ItemId::from_bytes([0x22; 16]),
        op_id: OpId::from_bytes([0x33; 16]),
        dot: Dot::new(device(0x44), 5).unwrap(),
        vault_prev_seq: 3,
        hlc: Hlc::from_u64(0x0102_0304_0506_0708),
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: 2,
        causal_context: vv(&[(0x55, 9), (0x44, 4)]),
    }
}

fn snapshot_header() -> SnapshotHeader {
    SnapshotHeader {
        vault_id: VaultId::from_bytes([0x11; 16]),
        item_id: ItemId::from_bytes([0x22; 16]),
        snapshot_id: SnapshotId::from_bytes([0x66; 16]),
        author: device(0x44),
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: 0x0a0b_0c0d,
        covered: vv(&[(0x44, 5), (0x55, 9)]),
    }
}

/// The op header above, written out field by field from ADR 0012 §3.
fn op_header_bytes() -> Vec<u8> {
    [
        &[0x01][..],                                       // header_version
        &[0x11; 16],                                       // vault_id
        &[0x22; 16],                                       // item_id
        &[0x33; 16],                                       // op_id
        &[0x44; 16],                                       // device_id
        &5u64.to_be_bytes(),                               // device_seq
        &3u64.to_be_bytes(),                               // vault_prev_seq
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // hlc
        &[0x00, 0x01],                                     // item_schema_version
        &[0x00, 0x00, 0x00, 0x02],                         // vault_key_epoch
        &[0x00, 0x02],                                     // n = 2
        &[0x44; 16],                                       // device 44…
        &4u64.to_be_bytes(),                               // seq 4
        &[0x55; 16],                                       // device 55…
        &9u64.to_be_bytes(),                               // seq 9
    ]
    .concat()
}

/// The snapshot header above, written out field by field from ADR 0012 §3.
fn snapshot_header_bytes() -> Vec<u8> {
    [
        &[0x01][..],               // header_version
        &[0x11; 16],               // vault_id
        &[0x22; 16],               // item_id
        &[0x66; 16],               // snapshot_id
        &[0x44; 16],               // author device_id
        &[0x00, 0x01],             // item_schema_version
        &[0x0a, 0x0b, 0x0c, 0x0d], // vault_key_epoch
        &[0x00, 0x02],             // n = 2
        &[0x44; 16],               // device 44…
        &5u64.to_be_bytes(),       // seq 5
        &[0x55; 16],               // device 55…
        &9u64.to_be_bytes(),       // seq 9
    ]
    .concat()
}

#[test]
fn known_answers() {
    let bytes = op_header_bytes();
    assert_eq!(op_header().to_vec().unwrap(), bytes);
    assert_eq!(bytes.len(), OP_HEADER_FIXED_LEN + 2 * 24);
    assert_eq!(op_header().encoded_len(), bytes.len());
    assert_eq!(OpHeader::parse(&bytes), Ok(op_header()));

    let bytes = snapshot_header_bytes();
    assert_eq!(snapshot_header().to_vec().unwrap(), bytes);
    assert_eq!(bytes.len(), SNAPSHOT_HEADER_FIXED_LEN + 2 * 24);
    assert_eq!(snapshot_header().encoded_len(), bytes.len());
    assert_eq!(SnapshotHeader::parse(&bytes), Ok(snapshot_header()));

    // encode appends.
    let mut out = vec![0xee];
    op_header().encode(&mut out).unwrap();
    assert_eq!(out.get(1..), Some(op_header_bytes().as_slice()));
}

/// The fixed parts are the minimum lengths `rizzy-core` accepts for the signed header, and a
/// header with the most entries a `u16` count allows is its maximum.
#[test]
fn lengths_match_the_statement_bounds() {
    assert_eq!(OP_HEADER_FIXED_LEN, OP_HEADER_MIN_LEN);
    assert_eq!(SNAPSHOT_HEADER_FIXED_LEN, SNAPSHOT_HEADER_MIN_LEN);
    assert_eq!(
        OP_HEADER_FIXED_LEN + VersionVector::MAX_ENTRIES * VersionVector::ENTRY_LEN,
        OP_HEADER_MAX_LEN
    );
    assert_eq!(
        SNAPSHOT_HEADER_FIXED_LEN + VersionVector::MAX_ENTRIES * VersionVector::ENTRY_LEN,
        SNAPSHOT_HEADER_MAX_LEN
    );
    let mut empty = op_header();
    empty.causal_context = VersionVector::new();
    assert_eq!(empty.to_vec().unwrap().len(), OP_HEADER_MIN_LEN);
}

/// The canonical header is exactly what the statements sign and hand back, and the AAD
/// contexts bind the hash of exactly those bytes.
#[test]
fn statements_and_envelope_contexts() {
    let header = op_header();
    let bytes = header.to_vec().unwrap();
    let st = OpStatement::new(&bytes, b"op envelope", None).unwrap();
    assert_eq!(st.header(), bytes.as_slice());
    assert_eq!(OpHeader::parse_statement(&st), Ok(header.clone()));
    let ctx = header.envelope_context().unwrap();
    assert_eq!(ctx.vault_id, header.vault_id);
    assert_eq!(ctx.item_id, header.item_id);
    assert_eq!(ctx.item_schema_version, 1);
    assert_eq!(ctx.op_id, header.op_id);
    assert_eq!(ctx.device_id, device(0x44));
    assert_eq!(ctx.device_seq, 5);
    assert_eq!(ctx.hlc, 0x0102_0304_0506_0708);
    assert_eq!(ctx.op_header_hash, st.header_hash());

    let header = snapshot_header();
    let bytes = header.to_vec().unwrap();
    let st = SnapshotStatement::new(&bytes, b"snapshot envelope", Some(b"wrap")).unwrap();
    assert_eq!(SnapshotHeader::parse_statement(&st), Ok(header.clone()));
    let ctx = header.envelope_context().unwrap();
    assert_eq!(ctx.snapshot_id, header.snapshot_id);
    assert_eq!(ctx.item_schema_version, 1);
    assert_eq!(ctx.snapshot_header_hash, st.header_hash());

    // A statement over bytes that are not a canonical header verifies in rizzy-core (it checks
    // only the length) and is refused here.
    let mut bad = op_header_bytes();
    bad[0] = 0x02;
    let st = OpStatement::new(&bad, b"op envelope", None).unwrap();
    assert_eq!(
        OpHeader::parse_statement(&st).unwrap_err().kind(),
        HeaderErrorKind::UnknownHeaderVersion
    );
}

fn op_rejects(bytes: &[u8], kind: HeaderErrorKind, offset: usize) {
    let e = OpHeader::parse(bytes).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (kind, offset), "{bytes:02x?}");
}

fn snapshot_rejects(bytes: &[u8], kind: HeaderErrorKind, offset: usize) {
    let e = SnapshotHeader::parse(bytes).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (kind, offset), "{bytes:02x?}");
}

#[test]
fn one_rejection_per_rule() {
    use HeaderErrorKind as K;
    let good = op_header_bytes();
    // header_version.
    for version in [0x00, 0x02, 0xff] {
        let mut b = good.clone();
        b[0] = version;
        op_rejects(&b, K::UnknownHeaderVersion, 0);
    }
    // device_seq 0 at offset 1 + 4 × 16 + 16.
    let mut b = good.clone();
    b[65..73].fill(0);
    op_rejects(&b, K::ZeroSeq, 65);
    // item_schema_version 0 and 0xFFFF at 1 + 64 + 24.
    for schema in [[0x00, 0x00], [0xff, 0xff]] {
        let mut b = good.clone();
        b[89..91].copy_from_slice(&schema);
        op_rejects(&b, K::InvalidSchemaVersion, 89);
    }
    // A context entry with seq 0; entries out of order; a duplicate device.
    let ctx = 97;
    let mut b = good.clone();
    b[ctx + 16..ctx + 24].fill(0);
    op_rejects(&b, K::ZeroSeq, ctx + 16);
    let mut b = good.clone();
    b[ctx..ctx + 24].copy_from_slice(&[[0x66; 16].as_slice(), &4u64.to_be_bytes()].concat());
    op_rejects(&b, K::NotAscending, ctx + 24);
    let mut b = good.clone();
    b[ctx + 24..ctx + 40].fill(0x44);
    op_rejects(&b, K::NotAscending, ctx + 24);
    // Trailing bytes.
    let mut b = good.clone();
    b.push(0);
    op_rejects(&b, K::TrailingBytes, good.len());

    let good = snapshot_header_bytes();
    let mut b = good.clone();
    b[0] = 0x00;
    snapshot_rejects(&b, K::UnknownHeaderVersion, 0);
    for schema in [[0x00, 0x00], [0xff, 0xff]] {
        let mut b = good.clone();
        b[65..67].copy_from_slice(&schema);
        snapshot_rejects(&b, K::InvalidSchemaVersion, 65);
    }
    let vv = 73;
    let mut b = good.clone();
    b[vv + 24 + 16..vv + 48].fill(0);
    snapshot_rejects(&b, K::ZeroSeq, vv + 24 + 16);
    let mut b = good.clone();
    b[vv..vv + 16].fill(0x55);
    snapshot_rejects(&b, K::NotAscending, vv + 24);
    let mut b = good.clone();
    b.push(0);
    snapshot_rejects(&b, K::TrailingBytes, good.len());
}

#[test]
fn truncation_at_every_length_is_refused() {
    let bytes = op_header_bytes();
    for len in 0..bytes.len() {
        let e = OpHeader::parse(&bytes[..len]).unwrap_err();
        assert_eq!(e.kind(), HeaderErrorKind::Truncated, "{len}");
    }
    let bytes = snapshot_header_bytes();
    for len in 0..bytes.len() {
        let e = SnapshotHeader::parse(&bytes[..len]).unwrap_err();
        assert_eq!(e.kind(), HeaderErrorKind::Truncated, "{len}");
    }
}

/// ADR 0018 §11: 0 and `0xFFFF` are rejected; every other version parses, and only 1 is one
/// the record layer reads (the rest are parked).
#[test]
fn schema_versions() {
    assert_eq!(ItemSchemaVersion::new(0), None);
    assert_eq!(ItemSchemaVersion::new(0xFFFF), None);
    assert_eq!(ItemSchemaVersion::new(1), Some(ItemSchemaVersion::V1));
    assert!(ItemSchemaVersion::V1.is_known());
    let v2 = ItemSchemaVersion::new(2).unwrap();
    assert!(!v2.is_known());
    assert_eq!(v2.get(), 2);
    let mut header = op_header();
    header.item_schema_version = ItemSchemaVersion::new(0xFFFE).unwrap();
    let bytes = header.to_vec().unwrap();
    assert_eq!(OpHeader::parse(&bytes), Ok(header));
}

/// Checks every mutation of `good` that [`every_accepted_mutation_is_canonical`] lists, with
/// `reencode` returning the re-encoding of the bytes if they parse; returns how many parsed.
fn accepted_mutations(
    good: &[u8],
    count_at: usize,
    reencode: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> usize {
    let mut accepted = 0;
    let mut check = |m: &[u8]| {
        if let Some(again) = reencode(m) {
            assert_eq!(again, m, "{m:02x?}");
            accepted += 1;
        }
    };
    let mut m = good.to_vec();
    for i in 0..good.len() {
        for v in (0..=u8::MAX).filter(|&v| v != good[i]) {
            m[i] = v;
            check(&m);
        }
        m[i] = good[i];
    }
    for i in 0..=good.len() {
        for v in 0..=u8::MAX {
            check(&[&good[..i], &[v], &good[i..]].concat());
        }
    }
    for i in 0..good.len() {
        for j in i + 1..=good.len() {
            check(&[&good[..i], &good[j..]].concat());
        }
    }
    for n in 0..=u16::MAX {
        m[count_at..count_at + 2].copy_from_slice(&n.to_be_bytes());
        check(&m);
    }
    accepted
}

/// Each header has exactly one encoding: every mutation of a known-answer header that still
/// parses re-encodes to exactly the mutated bytes. Exhaustive: every byte set to every other
/// value, every byte value inserted at every position, every range removed, and every value of
/// the entry count. Changes to ids, `vault_prev_seq`, the HLC and the epoch parse, so the check
/// runs on thousands of accepted inputs; the test requires that, so it cannot pass vacuously.
#[test]
fn every_accepted_mutation_is_canonical() {
    let accepted = accepted_mutations(&op_header_bytes(), OP_HEADER_FIXED_LEN - 2, |b| {
        OpHeader::parse(b).ok().map(|h| h.to_vec().unwrap())
    });
    assert!(accepted > 10_000, "{accepted} op-header mutations parsed");
    let accepted = accepted_mutations(
        &snapshot_header_bytes(),
        SNAPSHOT_HEADER_FIXED_LEN - 2,
        |b| SnapshotHeader::parse(b).ok().map(|h| h.to_vec().unwrap()),
    );
    assert!(
        accepted > 10_000,
        "{accepted} snapshot-header mutations parsed"
    );
}

/// One random change to a valid header: a byte changed by a non-zero mask, a byte inserted, 1–32 bytes removed, the
/// entry count overwritten, or an entry appended with the count raised to match. `at`, `byte`
/// and `n` pick the position and the new values.
fn mutate(
    good: &[u8],
    count_at: usize,
    kind: u8,
    at: prop::sample::Index,
    byte: u8,
    n: u16,
) -> Vec<u8> {
    let mut m = good.to_vec();
    match kind {
        0 => m[at.index(good.len())] ^= byte.max(1),
        1 => m.insert(at.index(good.len() + 1), byte),
        2 => {
            let i = at.index(good.len());
            m.drain(i..(i + usize::from(byte % 32) + 1).min(good.len()));
        }
        3 => m[count_at..count_at + 2].copy_from_slice(&n.to_be_bytes()),
        _ => {
            let count = u16::from_be_bytes([m[count_at], m[count_at + 1]]);
            m[count_at..count_at + 2].copy_from_slice(&count.wrapping_add(1).to_be_bytes());
            m.extend_from_slice(&[byte; 16]);
            m.extend_from_slice(&u64::from(n).to_be_bytes());
        }
    }
    m
}

#[test]
fn error_display() {
    let e = OpHeader::parse(&[]).unwrap_err();
    assert_eq!(e.to_string(), "header truncated at byte 0");
    for kind in [
        HeaderErrorKind::Truncated,
        HeaderErrorKind::TrailingBytes,
        HeaderErrorKind::UnknownHeaderVersion,
        HeaderErrorKind::ZeroSeq,
        HeaderErrorKind::NotAscending,
        HeaderErrorKind::InvalidSchemaVersion,
    ] {
        assert!(!kind.to_string().is_empty());
    }
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn arb_vv() -> impl Strategy<Value = VersionVector> {
    prop::collection::vec((any::<[u8; 16]>(), 1..=u64::MAX), 0..6).prop_map(|entries| {
        entries
            .into_iter()
            .map(|(d, s)| Dot::new(DeviceId::from_bytes(d), s).unwrap())
            .collect()
    })
}

fn arb_schema() -> impl Strategy<Value = ItemSchemaVersion> {
    (1..0xFFFFu16).prop_map(|v| ItemSchemaVersion::new(v).unwrap())
}

prop_compose! {
    fn arb_op_header()(
        ids in any::<[[u8; 16]; 4]>(), seq in 1..=u64::MAX, prev in any::<u64>(),
        hlc in any::<u64>(), schema in arb_schema(), epoch in any::<u32>(), ctx in arb_vv()
    ) -> OpHeader {
        let [vault, item, op, dev] = ids;
        OpHeader {
            vault_id: VaultId::from_bytes(vault),
            item_id: ItemId::from_bytes(item),
            op_id: OpId::from_bytes(op),
            dot: Dot::new(DeviceId::from_bytes(dev), seq).unwrap(),
            vault_prev_seq: prev,
            hlc: Hlc::from_u64(hlc),
            item_schema_version: schema,
            vault_key_epoch: epoch,
            causal_context: ctx,
        }
    }
}

prop_compose! {
    fn arb_snapshot_header()(
        ids in any::<[[u8; 16]; 4]>(), schema in arb_schema(), epoch in any::<u32>(),
        covered in arb_vv()
    ) -> SnapshotHeader {
        let [vault, item, snapshot, author] = ids;
        SnapshotHeader {
            vault_id: VaultId::from_bytes(vault),
            item_id: ItemId::from_bytes(item),
            snapshot_id: SnapshotId::from_bytes(snapshot),
            author: DeviceId::from_bytes(author),
            item_schema_version: schema,
            vault_key_epoch: epoch,
            covered,
        }
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn op_header_round_trips(h in arb_op_header()) {
        let bytes = h.to_vec().unwrap();
        prop_assert_eq!(bytes.len(), h.encoded_len());
        prop_assert!((OP_HEADER_MIN_LEN..=OP_HEADER_MAX_LEN).contains(&bytes.len()));
        prop_assert_eq!(OpHeader::parse(&bytes), Ok(h));
    }

    #[test]
    fn snapshot_header_round_trips(h in arb_snapshot_header()) {
        let bytes = h.to_vec().unwrap();
        prop_assert_eq!(bytes.len(), h.encoded_len());
        prop_assert!((SNAPSHOT_HEADER_MIN_LEN..=SNAPSHOT_HEADER_MAX_LEN).contains(&bytes.len()));
        prop_assert_eq!(SnapshotHeader::parse(&bytes), Ok(h));
    }

    /// Any byte string: parse never panics. A no-panic test only: a random string practically
    /// never parses (it needs version 1, a length of exactly 97 + 24n or 73 + 24n, a matching
    /// count and ascending entries), so the re-encoding check below almost never runs.
    /// Canonicality is checked from valid headers by `accepted_mutations_are_canonical` and
    /// `every_accepted_mutation_is_canonical`.
    #[test]
    fn parse_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(h) = OpHeader::parse(&bytes) {
            prop_assert_eq!(h.to_vec().unwrap(), bytes.clone());
        }
        if let Ok(h) = SnapshotHeader::parse(&bytes) {
            prop_assert_eq!(h.to_vec().unwrap(), bytes);
        }
    }

    /// A random mutation of a random valid header ([`mutate`]) that still parses re-encodes to
    /// exactly the mutated bytes: each header has one encoding.
    #[test]
    fn accepted_mutations_are_canonical(
        op in arb_op_header(), snapshot in arb_snapshot_header(), kind in 0..5u8,
        at in any::<prop::sample::Index>(), byte in any::<u8>(), n in any::<u16>()
    ) {
        let bytes = mutate(&op.to_vec().unwrap(), OP_HEADER_FIXED_LEN - 2, kind, at, byte, n);
        if let Ok(h) = OpHeader::parse(&bytes) {
            prop_assert_eq!(h.to_vec().unwrap(), bytes);
        }
        let bytes = mutate(&snapshot.to_vec().unwrap(), SNAPSHOT_HEADER_FIXED_LEN - 2, kind, at, byte, n);
        if let Ok(h) = SnapshotHeader::parse(&bytes) {
            prop_assert_eq!(h.to_vec().unwrap(), bytes);
        }
    }

    /// Flipping any one byte of a valid header gives a different header or a rejection, never
    /// the same header.
    #[test]
    fn a_changed_byte_changes_or_breaks_the_header(h in arb_op_header(), pos in any::<usize>(), flip in 1..=255u8) {
        let mut bytes = h.to_vec().unwrap();
        let i = pos % bytes.len();
        bytes[i] ^= flip;
        prop_assert_ne!(OpHeader::parse(&bytes).ok(), Some(h));
    }
}
