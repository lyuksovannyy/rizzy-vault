//! The canonical op and snapshot headers of ADR 0012 §3, written out by hand for the vectors.
//!
//! The headers are `rizzy-sync`'s (`rizzy_sync::header`, ADR 0012 §13), which this crate cannot
//! depend on (ADR 0016: core ← sync). `rizzy-core` itself takes a header as an opaque byte
//! string: the `op` and `snapshot` statements sign it (CRYPTO.md §10.2) and the `ITEM_OP` and
//! `ITEM_SNAPSHOT` contexts bind its `SHA-256` (§8.4). So that the vectors carry headers a real
//! client accepts, the generator encodes them here, field by field from the ADR text:
//!
//! ```text
//! op header        u8 header_version = 1 ‖ vault_id ‖ item_id ‖ op_id ‖ device_id ‖
//!                  u64 device_seq ‖ u64 vault_prev_seq ‖ u64 hlc ‖ u16 item_schema_version ‖
//!                  u32 vault_key_epoch ‖ causal context (u16 n ‖ n × (device_id ‖ u64 seq))
//!
//! snapshot header  u8 header_version = 1 ‖ vault_id ‖ item_id ‖ snapshot_id ‖
//!                  author device_id ‖ u16 item_schema_version ‖ u32 vault_key_epoch ‖
//!                  covered VV (u16 n ‖ n × (device_id ‖ u64 seq))
//! ```
//!
//! Ids are 16 bytes and integers big-endian (CRYPTO.md §2). A version vector is canonical:
//! entries strictly ascending by `device_id` bytewise, every `seq` ≥ 1 (ADR 0012 §3 "Canonical
//! VV encoding").
//!
//! This is test code and a second, independent writer and reader of the layout: the encoders
//! here and the strict decoders below share nothing with `rizzy-sync`. A `rizzy-sync` test
//! (`header::tests`, the `core_vectors` tests) parses every header of the committed vector
//! files with `rizzy_sync::header` and re-encodes it byte for byte, which ties the two
//! implementations together.

use crate::encoding::{Reader, put_u8, put_u16, put_u32, put_u64};

/// `header_version` of both headers (ADR 0012 §3).
const HEADER_VERSION: u8 = 1;

/// One version-vector entry: `device_id`, `seq`.
pub(super) type VvEntry = ([u8; 16], u64);

/// The fields of an op header, in ADR 0012 §3 order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OpHeaderFields {
    /// The vault the op belongs to.
    pub(super) vault_id: [u8; 16],
    /// The item the op saves.
    pub(super) item_id: [u8; 16],
    /// The op's random id.
    pub(super) op_id: [u8; 16],
    /// The authoring device: the device whose key signs the `op` statement (INV-22).
    pub(super) device_id: [u8; 16],
    /// The author's sequence number, at least 1.
    pub(super) device_seq: u64,
    /// The author's previous `device_seq` in this vault, or 0.
    pub(super) vault_prev_seq: u64,
    /// The op's hybrid logical clock: `millis << 16 | counter`.
    pub(super) hlc: u64,
    /// The version of the op's `data` encoding (ADR 0018 §11); 1 in M1.
    pub(super) item_schema_version: u16,
    /// The vault key epoch the author believed current.
    pub(super) vault_key_epoch: u32,
    /// The causal context, in any order; [`OpHeaderFields::encode`] sorts it.
    pub(super) causal_context: Vec<VvEntry>,
}

/// The fields of a snapshot header, in ADR 0012 §3 order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapshotHeaderFields {
    /// The vault the snapshot belongs to.
    pub(super) vault_id: [u8; 16],
    /// The item it snapshots.
    pub(super) item_id: [u8; 16],
    /// The snapshot's random id.
    pub(super) snapshot_id: [u8; 16],
    /// The device that wrote and signed it.
    pub(super) author: [u8; 16],
    /// The version of the snapshot's `data` encoding (ADR 0018 §11); 1 in M1.
    pub(super) item_schema_version: u16,
    /// The vault key epoch the author believed current.
    pub(super) vault_key_epoch: u32,
    /// The covered VV, in any order; [`SnapshotHeaderFields::encode`] sorts it.
    pub(super) covered: Vec<VvEntry>,
}

/// Appends the canonical VV encoding: `u16 n ‖ n × (device_id ‖ u64 seq)`, entries strictly
/// ascending by `device_id`. Panics (failing the generator) on a duplicate device or a zero
/// `seq`, which have no canonical encoding.
fn put_vv(out: &mut Vec<u8>, entries: &[VvEntry]) {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    assert!(
        sorted.windows(2).all(|w| w[0].0 < w[1].0),
        "a version vector names each device once"
    );
    assert!(sorted.iter().all(|&(_, seq)| seq >= 1), "every seq is ≥ 1");
    put_u16(
        out,
        u16::try_from(sorted.len()).expect("at most 65,535 entries"),
    );
    for (device_id, seq) in sorted {
        out.extend_from_slice(&device_id);
        put_u64(out, seq);
    }
}

/// Reads a canonical VV, strictly: the count, then exactly that many ascending entries.
fn read_vv(r: &mut Reader<'_>) -> Vec<VvEntry> {
    let n = r.u16().expect("a VV count");
    let entries: Vec<VvEntry> = (0..n)
        .map(|_| {
            (
                *r.array::<16>().expect("a device id"),
                r.u64().expect("a seq"),
            )
        })
        .collect();
    assert!(
        entries.windows(2).all(|w| w[0].0 < w[1].0),
        "VV entries strictly ascending by device_id"
    );
    assert!(entries.iter().all(|&(_, seq)| seq >= 1), "every seq is ≥ 1");
    entries
}

/// Checks the two schema-version values ADR 0018 §11 rejects.
fn assert_schema_version(version: u16) {
    assert!(
        version != 0 && version != 0xFFFF,
        "item_schema_version 0 and 0xFFFF are invalid"
    );
}

impl OpHeaderFields {
    /// The canonical encoding (ADR 0012 §3): 97 bytes plus 24 per context entry.
    pub(super) fn encode(&self) -> Vec<u8> {
        assert!(self.device_seq >= 1, "device_seq starts at 1");
        assert_schema_version(self.item_schema_version);
        let mut out = Vec::new();
        put_u8(&mut out, HEADER_VERSION);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.item_id);
        out.extend_from_slice(&self.op_id);
        out.extend_from_slice(&self.device_id);
        put_u64(&mut out, self.device_seq);
        put_u64(&mut out, self.vault_prev_seq);
        put_u64(&mut out, self.hlc);
        put_u16(&mut out, self.item_schema_version);
        put_u32(&mut out, self.vault_key_epoch);
        put_vv(&mut out, &self.causal_context);
        assert_eq!(out.len(), 97 + 24 * self.causal_context.len());
        out
    }

    /// Reads a canonical op header that fills all of `bytes`; panics (failing the test) on
    /// any other byte string. The context comes back in its encoded, ascending order.
    pub(super) fn decode(bytes: &[u8]) -> Self {
        let mut r = Reader::new(bytes);
        assert_eq!(r.u8().expect("header_version"), HEADER_VERSION);
        let fields = Self {
            vault_id: *r.array().expect("vault_id"),
            item_id: *r.array().expect("item_id"),
            op_id: *r.array().expect("op_id"),
            device_id: *r.array().expect("device_id"),
            device_seq: r.u64().expect("device_seq"),
            vault_prev_seq: r.u64().expect("vault_prev_seq"),
            hlc: r.u64().expect("hlc"),
            item_schema_version: r.u16().expect("item_schema_version"),
            vault_key_epoch: r.u32().expect("vault_key_epoch"),
            causal_context: read_vv(&mut r),
        };
        r.finish().expect("nothing after the causal context");
        assert!(fields.device_seq >= 1, "device_seq starts at 1");
        assert_schema_version(fields.item_schema_version);
        assert_eq!(fields.encode(), bytes, "one encoding per header");
        fields
    }
}

impl SnapshotHeaderFields {
    /// The canonical encoding (ADR 0012 §3): 73 bytes plus 24 per covered-VV entry.
    pub(super) fn encode(&self) -> Vec<u8> {
        assert_schema_version(self.item_schema_version);
        let mut out = Vec::new();
        put_u8(&mut out, HEADER_VERSION);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.item_id);
        out.extend_from_slice(&self.snapshot_id);
        out.extend_from_slice(&self.author);
        put_u16(&mut out, self.item_schema_version);
        put_u32(&mut out, self.vault_key_epoch);
        put_vv(&mut out, &self.covered);
        assert_eq!(out.len(), 73 + 24 * self.covered.len());
        out
    }

    /// Reads a canonical snapshot header that fills all of `bytes`; panics (failing the test)
    /// on any other byte string. The covered VV comes back in its encoded, ascending order.
    pub(super) fn decode(bytes: &[u8]) -> Self {
        let mut r = Reader::new(bytes);
        assert_eq!(r.u8().expect("header_version"), HEADER_VERSION);
        let fields = Self {
            vault_id: *r.array().expect("vault_id"),
            item_id: *r.array().expect("item_id"),
            snapshot_id: *r.array().expect("snapshot_id"),
            author: *r.array().expect("author device_id"),
            item_schema_version: r.u16().expect("item_schema_version"),
            vault_key_epoch: r.u32().expect("vault_key_epoch"),
            covered: read_vv(&mut r),
        };
        r.finish().expect("nothing after the covered VV");
        assert_schema_version(fields.item_schema_version);
        assert_eq!(fields.encode(), bytes, "one encoding per header");
        fields
    }
}

/// The op header of ADR 0012 §3 spelled out byte by byte, against the encoder and the decoder.
#[test]
fn op_header_layout_is_the_adr_0012_layout() {
    let fields = OpHeaderFields {
        vault_id: [0x11; 16],
        item_id: [0x22; 16],
        op_id: [0x33; 16],
        device_id: [0x44; 16],
        device_seq: 5,
        vault_prev_seq: 3,
        hlc: 0x0102_0304_0506_0708,
        item_schema_version: 1,
        vault_key_epoch: 2,
        // Given out of order: the encoder sorts.
        causal_context: vec![([0x55; 16], 9), ([0x44; 16], 4)],
    };
    let expected = [
        &[0x01][..],                                       // header_version
        &[0x11; 16],                                       // vault_id
        &[0x22; 16],                                       // item_id
        &[0x33; 16],                                       // op_id
        &[0x44; 16],                                       // device_id
        &[0, 0, 0, 0, 0, 0, 0, 5],                         // device_seq
        &[0, 0, 0, 0, 0, 0, 0, 3],                         // vault_prev_seq
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // hlc
        &[0x00, 0x01],                                     // item_schema_version
        &[0x00, 0x00, 0x00, 0x02],                         // vault_key_epoch
        &[0x00, 0x02],                                     // n = 2
        &[0x44; 16],                                       // device 44…
        &[0, 0, 0, 0, 0, 0, 0, 4],                         // seq 4
        &[0x55; 16],                                       // device 55…
        &[0, 0, 0, 0, 0, 0, 0, 9],                         // seq 9
    ]
    .concat();
    assert_eq!(fields.encode(), expected);
    assert_eq!(expected.len(), 97 + 2 * 24);
    let mut sorted = fields.clone();
    sorted.causal_context.sort_unstable();
    assert_eq!(OpHeaderFields::decode(&expected), sorted);
}

/// The snapshot header of ADR 0012 §3 spelled out byte by byte.
#[test]
fn snapshot_header_layout_is_the_adr_0012_layout() {
    let fields = SnapshotHeaderFields {
        vault_id: [0x11; 16],
        item_id: [0x22; 16],
        snapshot_id: [0x66; 16],
        author: [0x44; 16],
        item_schema_version: 1,
        vault_key_epoch: 0x0a0b_0c0d,
        covered: vec![([0x44; 16], 5)],
    };
    let expected = [
        &[0x01][..],               // header_version
        &[0x11; 16],               // vault_id
        &[0x22; 16],               // item_id
        &[0x66; 16],               // snapshot_id
        &[0x44; 16],               // author device_id
        &[0x00, 0x01],             // item_schema_version
        &[0x0a, 0x0b, 0x0c, 0x0d], // vault_key_epoch
        &[0x00, 0x01],             // n = 1
        &[0x44; 16],               // device 44…
        &[0, 0, 0, 0, 0, 0, 0, 5], // seq 5
    ]
    .concat();
    assert_eq!(fields.encode(), expected);
    assert_eq!(expected.len(), 73 + 24);
    assert_eq!(SnapshotHeaderFields::decode(&expected), fields);
}

/// The decoders refuse what `rizzy-sync`'s strict parser refuses, so a placeholder header can
/// never come back into a vector file unnoticed.
#[test]
fn decoders_refuse_non_canonical_headers() {
    let op = OpHeaderFields {
        vault_id: [0x11; 16],
        item_id: [0x22; 16],
        op_id: [0x33; 16],
        device_id: [0x44; 16],
        device_seq: 5,
        vault_prev_seq: 3,
        hlc: 7,
        item_schema_version: 1,
        vault_key_epoch: 0,
        causal_context: vec![([0x44; 16], 4), ([0x55; 16], 9)],
    }
    .encode();
    let refused = |bytes: Vec<u8>| std::panic::catch_unwind(|| OpHeaderFields::decode(&bytes));
    assert!(refused(op.clone()).is_ok());
    // header_version 2, device_seq 0, schema version 0, a trailing byte, a truncated entry.
    let mut version = op.clone();
    version[0] = 2;
    assert!(refused(version).is_err());
    let mut seq = op.clone();
    seq[65..73].fill(0);
    assert!(refused(seq).is_err());
    let mut schema = op.clone();
    schema[89..91].fill(0);
    assert!(refused(schema).is_err());
    let mut trailing = op.clone();
    trailing.push(0);
    assert!(refused(trailing).is_err());
    assert!(refused(op[..op.len() - 1].to_vec()).is_err());
    // Entries in descending order, and an entry with seq 0.
    let mut swapped = op.clone();
    swapped[97..113].fill(0x66);
    assert!(refused(swapped).is_err());
    let mut zero = op.clone();
    zero[113..121].fill(0);
    assert!(refused(zero).is_err());
    // Random bytes of a valid length, as the vectors carried before: refused.
    assert!(refused(vec![0xa7; 97]).is_err());
    let snapshot =
        |bytes: Vec<u8>| std::panic::catch_unwind(|| SnapshotHeaderFields::decode(&bytes));
    assert!(snapshot(vec![0xa7; 97]).is_err());
}
