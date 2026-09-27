//! Writers of op and snapshot data (ADR 0018 §3), and the §4 state-hash input.
//!
//! Each writer runs in three passes:
//!
//! 1. **Size.** Compute the exact encoded length, checking every count and length against
//!    the limits in force, and the total against the data limit, before any byte is written.
//!    A failure here returns an error with nothing allocated.
//! 2. **Write.** Allocate the output once at that length and write it; nothing can fail, so
//!    no partial plaintext is left in a buffer that is not wiped (CRYPTO.md §12.2). The buffer
//!    becomes a zeroizing [`SecretBytes`].
//! 3. **Check.** Parse the output with the reader's own code ([`super::parse`]) under the same
//!    limits. Order, uniqueness, grammar, coverage and every other ADR 0018 §5 rule are
//!    therefore enforced on writers exactly as on readers, and "every serializer output
//!    within the §10 limits must parse" (ADR 0018 §1) holds by construction. On failure the
//!    buffer is wiped and the parser's error returned.
//!
//! The writers do not sort or deduplicate: the caller supplies keys and dots in canonical
//! order (the merge keeps its state that way), and anything else is refused in pass 3.

use rizzy_core::encoding::{put_u8, put_u16, put_u32, put_u64};
use rizzy_core::secret::SecretBytes;

use super::parse::{op_with, snapshot_with};
use super::{
    Entry, FieldKey, Limits, LiveSnapshot, OpData, RecordError, RecordErrorKind as K, RecordKind,
    Register, SnapshotData, Tombstone, Value,
};
use crate::dot::Dot;
use crate::header::ItemSchemaVersion;
use crate::vv::VersionVector;

/// The running length of an encoding, with the limits it must respect. An error names the
/// offset at which the offending field would start.
#[derive(Debug)]
struct Sizer {
    /// Bytes counted so far.
    len: usize,
    /// The limits in force.
    limits: Limits,
}

impl Sizer {
    /// Adds `n` bytes.
    fn add(&mut self, n: usize) -> Result<(), RecordError> {
        self.len = self
            .len
            .checked_add(n)
            .ok_or(RecordError::new(K::DataTooLong, 0))?;
        Ok(())
    }

    /// Checks a count against `max` and adds its `u16`.
    fn count(&mut self, n: usize, max: usize) -> Result<(), RecordError> {
        if n > max {
            return Err(RecordError::new(K::CountTooLarge, self.len));
        }
        self.add(2)
    }

    /// Adds `str(key)`. Keys are 1–160 bytes by construction.
    fn key(&mut self, key: FieldKey<'_>) -> Result<(), RecordError> {
        self.add(4)?;
        self.add(key.len())
    }

    /// Checks a value against the value limit and adds `bytes(value)`.
    fn value(&mut self, value: Value<'_>) -> Result<(), RecordError> {
        if value.len() > self.limits.value {
            return Err(RecordError::new(K::ValueTooLong, self.len));
        }
        self.add(4)?;
        self.add(value.len())
    }

    /// Adds one `register` production.
    fn register(&mut self, reg: &Register<'_>) -> Result<(), RecordError> {
        self.key(reg.key)?;
        self.count(reg.entries.len(), self.limits.values)?;
        for e in &reg.entries {
            self.add(Dot::ENCODED_LEN + 8)?;
            self.value(e.value)?;
        }
        Ok(())
    }

    /// Adds a list of registers with its `u16` count.
    fn registers(&mut self, regs: &[Register<'_>]) -> Result<(), RecordError> {
        self.count(regs.len(), self.limits.groups)?;
        regs.iter().try_for_each(|r| self.register(r))
    }

    /// Adds a canonical version vector.
    fn vv(&mut self, vv: &VersionVector) -> Result<(), RecordError> {
        if vv.len() > VersionVector::MAX_ENTRIES {
            return Err(RecordError::new(K::CountTooLarge, self.len));
        }
        self.add(vv.encoded_len())
    }
}

/// Appends a count the sizer has checked to fit a `u16`.
fn put_count(out: &mut Vec<u8>, n: usize) {
    put_u16(out, u16::try_from(n).unwrap_or(u16::MAX));
}

/// Appends `bytes(x)` for an `x` the sizer has checked to fit a `u32` length.
fn put_bytes(out: &mut Vec<u8>, x: &[u8]) {
    put_u32(out, u32::try_from(x.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(x);
}

/// Appends a canonical version vector (ADR 0012 §3), `u16 n ‖ n × (device_id ‖ u64 seq)` in
/// ascending `device_id` order, whose count the sizer has checked. The same bytes as
/// [`VersionVector::encode`], written without a fallible call.
fn put_vv(out: &mut Vec<u8>, vv: &VersionVector) {
    put_count(out, vv.len());
    vv.entries().for_each(|dot| dot.encode(out));
}

/// Appends one entry: `dot ‖ u64 hlc ‖ bytes(value)`.
fn put_entry(out: &mut Vec<u8>, e: &Entry<'_>) {
    e.dot.encode(out);
    put_u64(out, e.hlc.to_u64());
    put_bytes(out, e.value.0);
}

/// Appends a list of registers with its `u16` count.
fn put_registers(out: &mut Vec<u8>, regs: &[Register<'_>]) {
    put_count(out, regs.len());
    for reg in regs {
        put_bytes(out, reg.key.0.as_bytes());
        put_count(out, reg.entries.len());
        reg.entries.iter().for_each(|e| put_entry(out, e));
    }
}

/// Size of op data, checked against `limits`.
pub(super) fn op_len(op: &OpData<'_>, limits: Limits) -> Result<usize, RecordError> {
    let mut s = Sizer { len: 2, limits };
    s.count(op.writes.len(), limits.writes)?;
    for w in &op.writes {
        s.key(w.key)?;
        s.value(w.value)?;
    }
    if s.len > limits.op_data {
        return Err(RecordError::new(K::DataTooLong, 0));
    }
    Ok(s.len)
}

/// Size of snapshot data, checked against `limits`.
pub(super) fn snapshot_len(
    snapshot: &SnapshotData<'_>,
    limits: Limits,
) -> Result<usize, RecordError> {
    let mut s = Sizer { len: 1, limits };
    match snapshot {
        SnapshotData::Live(live) => {
            s.registers(&live.registers)?;
            s.registers(&live.history)?;
        }
        SnapshotData::Tombstone(t) => {
            s.add(Dot::ENCODED_LEN + 8)?;
            s.vv(&t.context)?;
            s.add(16)?;
            s.registers(&t.late)?;
        }
    }
    if s.len > limits.snapshot_data {
        return Err(RecordError::new(K::DataTooLong, 0));
    }
    Ok(s.len)
}

/// Writes op data; the sizer has checked it.
fn put_op(out: &mut Vec<u8>, op: &OpData<'_>) {
    put_u8(out, RecordKind::Op.to_u8());
    put_u8(out, op.lifecycle.to_u8());
    put_count(out, op.writes.len());
    for w in &op.writes {
        put_bytes(out, w.key.0.as_bytes());
        put_bytes(out, w.value.0);
    }
}

/// Writes snapshot data; the sizer has checked it.
fn put_snapshot(out: &mut Vec<u8>, snapshot: &SnapshotData<'_>) {
    put_u8(out, snapshot.kind().to_u8());
    match snapshot {
        SnapshotData::Live(LiveSnapshot { registers, history }) => {
            put_registers(out, registers);
            put_registers(out, history);
        }
        SnapshotData::Tombstone(Tombstone {
            purge_dot,
            purge_hlc,
            context,
            item_key_id,
            late,
        }) => {
            purge_dot.encode(out);
            put_u64(out, purge_hlc.to_u64());
            put_vv(out, context);
            out.extend_from_slice(item_key_id.as_bytes());
            put_registers(out, late);
        }
    }
}

/// Encodes the `data` of an `ITEM_OP` envelope (ADR 0018 §3), for the envelope to frame, pad
/// and encrypt.
///
/// Writes must be strictly ascending by key and empty unless the marker is `Active`; values
/// are written as given.
///
/// # Errors
/// A [`RecordError`] when the op breaks an ADR 0018 §10 limit or any §5 rule, the same errors
/// [`parse_op`](super::parse_op) returns for its encoding. Nothing is returned then, and any
/// bytes written are wiped.
pub fn encode_op(op: &OpData<'_>) -> Result<SecretBytes, RecordError> {
    let len = op_len(op, Limits::V1)?;
    let mut out = Vec::with_capacity(len);
    put_op(&mut out, op);
    let out = SecretBytes::from_vec(out);
    op_with(out.expose_secret(), Limits::V1)?;
    Ok(out)
}

/// Encodes the `data` of an `ITEM_SNAPSHOT` envelope (ADR 0018 §3), a live snapshot or a
/// tombstone, whose header will carry `covered` as its covered VV.
///
/// Registers, history groups and late registers must be strictly ascending by key (a live
/// snapshot's first register `@lifecycle`), and each one's entries strictly ascending by dot.
///
/// # Errors
/// A [`RecordError`] when the snapshot breaks an ADR 0018 §10 limit (the item is then
/// *oversize* and gets no snapshot, §10) or any §5 rule against `covered`, the same errors
/// [`parse_snapshot`](super::parse_snapshot) returns for its encoding. Nothing is returned
/// then, and any bytes written are wiped.
pub fn encode_snapshot(
    covered: &VersionVector,
    snapshot: &SnapshotData<'_>,
) -> Result<SecretBytes, RecordError> {
    let len = snapshot_len(snapshot, Limits::V1)?;
    let mut out = Vec::with_capacity(len);
    put_snapshot(&mut out, snapshot);
    let out = SecretBytes::from_vec(out);
    snapshot_with(covered, out.expose_secret(), Limits::V1)?;
    Ok(out)
}

/// The input of the ADR 0012 §12 state hash (ADR 0018 §4 "Equal states give equal bytes"):
/// `u16 item_schema_version ‖ covered VV ‖ data`, with `data` unframed and encoded without
/// the §10 limits, so that an oversize state has one too. The hash is `SHA-256` of these
/// bytes. For tests only (ADR 0018 §4); a user-visible fingerprint needs its own ADR.
///
/// Every §5 rule other than the §10 limits still applies, and the `u16` counts and `u32`
/// lengths of the layout still bound the state.
///
/// # Errors
/// A [`RecordError`] when the state breaks a §5 rule other than a §10 limit, or a count or
/// length does not fit the layout's `u16` or `u32`.
pub fn canonical_state(
    covered: &VersionVector,
    snapshot: &SnapshotData<'_>,
) -> Result<SecretBytes, RecordError> {
    let limits = Limits::unbounded();
    let data_len = snapshot_len(snapshot, limits)?;
    let mut prefix = Sizer { len: 2, limits };
    prefix.vv(covered)?;
    let prefix = prefix.len;
    let len = prefix
        .checked_add(data_len)
        .ok_or(RecordError::new(K::DataTooLong, 0))?;
    let mut out = Vec::with_capacity(len);
    put_u16(&mut out, ItemSchemaVersion::V1.get());
    // Metadata only: nothing secret is in `out` yet if this fails (the sizer checked it).
    covered
        .encode(&mut out)
        .map_err(|_| RecordError::new(K::CountTooLarge, 2))?;
    put_snapshot(&mut out, snapshot);
    let out = SecretBytes::from_vec(out);
    let data = out.expose_secret().get(prefix..).unwrap_or_default();
    snapshot_with(covered, data, limits)?;
    Ok(out)
}
