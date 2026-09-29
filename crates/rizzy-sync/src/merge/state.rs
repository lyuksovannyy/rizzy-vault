//! The item state the merge keeps, and its conversions to and from the record layer
//! (ADR 0018 §3 layouts, §4 canonical form).
//!
//! A [`State`] is what a live snapshot or a tombstone encodes, owned: the covered VV and either
//! the current registers and history groups of a live item ([`Live`]) or the recorded purge,
//! `c` and late registers of a tombstone ([`Tomb`]). The empty live state, with no register and
//! an empty VV, is the item before any op: *absent* ([`State::is_absent`]).
//!
//! # Owned bytes
//!
//! Field keys and values are item content (ADR 0018 §2 "Secrets"): a tag name is part of its
//! key, and values hold passwords. The merge copies each key and value it keeps, once, into a
//! [`Bytes`]: a zeroizing [`SecretBytes`] behind an `Arc`, so that the state, its history, the
//! newest-snapshot basis and the held ops share one copy, and the bytes are wiped when the last
//! holder drops. `Debug` prints `[REDACTED]` for every key and value.
//!
//! # Canonical order
//!
//! Registers are kept in a `BTreeMap` keyed by the key's bytes, whose order is ADR 0018 §4's
//! "strictly ascending by their raw ASCII bytes ..., a proper prefix first"; `@lifecycle`
//! (`0x40`) sorts before every grammar key, which starts with `a`–`z`. Within a register the
//! values are kept strictly ascending by [`Dot`], `device_id` bytewise then `seq`, with at most
//! one value per dot. So [`State::snapshot_data`] hands the record encoder its input in
//! canonical order, and the encoder, which re-parses its own output, refuses anything else.
//!
//! Ordering keys branches on their bytes, as the record parser's order check does; ordering
//! is what ADR 0018 §4 requires of every replica, and keys are compared nowhere else.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use rizzy_core::ids::SymmetricKeyId;
use rizzy_core::secret::SecretBytes;

use crate::dot::Dot;
use crate::hlc::Hlc;
use crate::record::{
    Entry, FieldKey, LIFECYCLE_KEY, LiveSnapshot, Register, SnapshotData, Tombstone, Value,
};
use crate::vv::VersionVector;

use super::MergeError;

/// The owned bytes of one field key or value, shared without copying and wiped when the last
/// holder drops.
///
/// Equality and order are those of the bytes, which [`State`] uses for keys (ADR 0018 §4).
/// Values are compared only where the merge must: the "one dot in two versions" tie-break,
/// which ranks the lower value first ([`super::join()`]), and the check of a snapshot value
/// against the op body at its dot, which uses [`Bytes::ct_eq`].
#[derive(Clone)]
pub(crate) struct Bytes(Arc<SecretBytes>);

impl Bytes {
    /// Copies `bytes` into a new zeroizing buffer of exactly that size.
    pub(crate) fn copy_from(bytes: &[u8]) -> Self {
        Self(Arc::new(SecretBytes::copy_from_slice(bytes)))
    }

    /// The bytes. Item content: do not log, format or copy them into a plain buffer.
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Whether these are the bytes of the reserved `@lifecycle` key.
    pub(crate) fn is_lifecycle_key(&self) -> bool {
        self.expose() == LIFECYCLE_KEY.as_bytes()
    }

    /// Compares two byte strings without an early exit on the first differing byte (CRYPTO.md
    /// §12.3). Lengths are not secret (an envelope reveals its padded size) and are compared
    /// first.
    pub(crate) fn ct_eq(&self, other: &[u8]) -> bool {
        let a = self.expose();
        if a.len() != other.len() {
            return false;
        }
        let diff = a
            .iter()
            .zip(other)
            .fold(0u8, |acc, (x, y)| core::hint::black_box(acc | (x ^ y)));
        core::hint::black_box(diff) == 0
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl Eq for Bytes {}

impl PartialOrd for Bytes {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bytes {
    /// The canonical key order of ADR 0018 §4: bytewise, a proper prefix first.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.expose().cmp(other.expose())
    }
}

impl core::borrow::Borrow<[u8]> for Bytes {
    /// The bytes, so that a map keyed by [`Bytes`] can be searched by a key's bytes. Consistent
    /// with `Eq` and `Ord`, which compare the same bytes.
    fn borrow(&self) -> &[u8] {
        self.expose()
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// One value in a register, history group or late register: the value, and the dot and HLC
/// of the op that wrote it (ADR 0018 §3 `register` entry).
#[derive(Clone, Debug)]
pub(crate) struct Val {
    /// The dot of the op that wrote the value.
    pub(crate) dot: Dot,
    /// That op's HLC.
    pub(crate) hlc: Hlc,
    /// The value, empty for Cleared.
    pub(crate) value: Bytes,
}

impl Val {
    /// The order of ADR 0012 §5 pruning, ADR 0018 §6 display and the §3 recorded purge:
    /// `(hlc, device_id, seq)`, `hlc` numerically, then the dot (`device_id` bytewise, then
    /// `seq`).
    pub(crate) fn rank(&self) -> (Hlc, Dot) {
        (self.hlc, self.dot)
    }

    /// The record layer's view of this value.
    pub(crate) fn entry(&self) -> Entry<'_> {
        Entry::new(self.dot, self.hlc, Value::new(self.value.expose()))
    }
}

/// Registers keyed by field key, each holding its values strictly ascending by dot.
pub(crate) type Regs = BTreeMap<Bytes, Vec<Val>>;

/// A live item: its current registers and history groups (ADR 0018 §3 "live snapshot data").
#[derive(Clone, Default)]
pub(crate) struct Live {
    /// The current registers, `@lifecycle` among them once an op has written it.
    pub(crate) regs: Regs,
    /// The history groups: values removed from a register (ADR 0012 §5, ADR 0018 §3
    /// "History"), at most [`super::HISTORY_LIMIT`] per key.
    pub(crate) hist: Regs,
}

/// The recorded purge of a tombstone (ADR 0018 §3 "Recorded purge").
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PurgeRec {
    /// The purge op's dot.
    pub(crate) dot: Dot,
    /// Its HLC.
    pub(crate) hlc: Hlc,
    /// The `key_id` in its `ITEM_OP` envelope header.
    pub(crate) key_id: SymmetricKeyId,
}

impl PurgeRec {
    /// The order that picks the recorded purge: the highest `(hlc, device_id, seq)`.
    pub(crate) fn rank(&self) -> (Hlc, Dot) {
        (self.hlc, self.dot)
    }
}

/// A purged item (ADR 0018 §3 "Tombstone (c)"): no value or history of the item, only the
/// recorded purge, the joined purge context `c` and the late registers.
#[derive(Clone)]
pub(crate) struct Tomb {
    /// The recorded purge.
    pub(crate) purge: PurgeRec,
    /// `c`: the join of the causal contexts of every applied purge.
    pub(crate) c: VersionVector,
    /// The late registers: the current values that `c` does not cover, never `@lifecycle`.
    pub(crate) late: Regs,
}

/// A live item or a tombstone.
#[derive(Clone)]
pub(crate) enum Shape {
    /// Record kind `0x02`.
    Live(Live),
    /// Record kind `0x03`.
    Tomb(Tomb),
}

/// One item's state: the covered VV and its shape.
#[derive(Clone)]
pub(crate) struct State {
    /// The covered VV: every op the state includes (ADR 0012 §2 "Per-item version vector").
    pub(crate) vv: VersionVector,
    /// Live or a tombstone.
    pub(crate) shape: Shape,
}

impl Default for State {
    /// The absent item: live, no register, an empty VV.
    fn default() -> Self {
        Self {
            vv: VersionVector::new(),
            shape: Shape::Live(Live::default()),
        }
    }
}

/// Copies registers out of the record layer.
fn regs_from(registers: &[Register<'_>]) -> Regs {
    registers
        .iter()
        .map(|reg| {
            let values = reg
                .entries()
                .iter()
                .map(|e| Val {
                    dot: e.dot(),
                    hlc: e.hlc(),
                    value: Bytes::copy_from(e.value().expose_secret()),
                })
                .collect();
            (
                Bytes::copy_from(reg.key().expose_secret().as_bytes()),
                values,
            )
        })
        .collect()
}

/// The record layer's key for owned key bytes: `@lifecycle`, or a key of the ADR 0018 §7
/// grammar.
///
/// Every key the merge holds came from a parsed record or a [`FieldKey`], so this never fails
/// on a state the merge built; it is checked anyway, and a failure is an error, never a panic.
pub(crate) fn field_key(bytes: &Bytes) -> Result<FieldKey<'_>, MergeError> {
    let text = core::str::from_utf8(bytes.expose()).map_err(|_| MergeError::InvalidKey)?;
    if text == LIFECYCLE_KEY {
        Ok(FieldKey::LIFECYCLE)
    } else {
        FieldKey::new(text).map_err(|_| MergeError::InvalidKey)
    }
}

/// The record layer's registers for owned ones, in the same (canonical) order.
fn regs_to(regs: &Regs) -> Result<Vec<Register<'_>>, MergeError> {
    regs.iter()
        .map(|(key, values)| {
            Ok(Register::new(
                field_key(key)?,
                values.iter().map(Val::entry).collect(),
            ))
        })
        .collect()
}

impl State {
    /// The state a snapshot encodes: its header's covered VV and its data.
    pub(crate) fn from_snapshot(covered: &VersionVector, data: &SnapshotData<'_>) -> Self {
        let shape = match data {
            SnapshotData::Live(live) => Shape::Live(Live {
                regs: regs_from(live.registers()),
                hist: regs_from(live.history()),
            }),
            SnapshotData::Tombstone(t) => Shape::Tomb(Tomb {
                purge: PurgeRec {
                    dot: t.purge_dot(),
                    hlc: t.purge_hlc(),
                    key_id: t.item_key_id(),
                },
                c: t.context().clone(),
                late: regs_from(t.late()),
            }),
        };
        Self {
            vv: covered.clone(),
            shape,
        }
    }

    /// Whether this is the absent item: live with no register and no history. An op always
    /// writes `@lifecycle` or makes a tombstone, so only an item no op reached is absent.
    pub(crate) fn is_absent(&self) -> bool {
        matches!(&self.shape, Shape::Live(l) if l.regs.is_empty() && l.hist.is_empty())
    }

    /// Whether this is a tombstone.
    pub(crate) fn is_tomb(&self) -> bool {
        matches!(self.shape, Shape::Tomb(_))
    }

    /// The record layer's view of the state, borrowing every key and value: `None` for the
    /// absent item, which has no encoding (a live snapshot has at least one register).
    ///
    /// # Errors
    /// [`MergeError::InvalidKey`] if a held key is not a record key, which a state the merge
    /// built never holds.
    pub(crate) fn snapshot_data(&self) -> Result<Option<SnapshotData<'_>>, MergeError> {
        if self.is_absent() {
            return Ok(None);
        }
        Ok(Some(match &self.shape {
            Shape::Live(l) => {
                SnapshotData::Live(LiveSnapshot::new(regs_to(&l.regs)?, regs_to(&l.hist)?))
            }
            Shape::Tomb(t) => SnapshotData::Tombstone(Tombstone::new(
                t.purge.dot,
                t.purge.hlc,
                t.c.clone(),
                t.purge.key_id,
                regs_to(&t.late)?,
            )),
        }))
    }

    /// Every value of the state with its key: current values and history entries of a live
    /// item, late values of a tombstone.
    pub(crate) fn values(&self) -> impl Iterator<Item = (&Bytes, &Val)> {
        let (first, second) = match &self.shape {
            Shape::Live(l) => (&l.regs, Some(&l.hist)),
            Shape::Tomb(t) => (&t.late, None),
        };
        first
            .iter()
            .chain(second.into_iter().flatten())
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k, v)))
    }

    /// The highest HLC the state carries: every current value and history entry of a live
    /// state, the recorded purge and every late value of a tombstone. Absorbing a snapshot is
    /// a receipt of this HLC (ADR 0018 §3 "Absorbing a snapshot").
    pub(crate) fn max_hlc(&self) -> Option<Hlc> {
        let values = self.values().map(|(_, v)| v.hlc);
        match &self.shape {
            Shape::Live(_) => values.max(),
            Shape::Tomb(t) => values.chain([t.purge.hlc]).max(),
        }
    }
}

/// Writes `name([REDACTED])`: whether an item is live or purged, what `@lifecycle` holds and
/// every key and value are decrypted item state (ADR 0012 §5, ADR 0018 §2), so no `Debug`
/// output of the state shows them.
fn redacted(f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
    write!(f, "{name}([REDACTED])")
}

impl fmt::Debug for Live {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "Live")
    }
}

impl fmt::Debug for PurgeRec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "PurgeRec")
    }
}

impl fmt::Debug for Tomb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "Tomb")
    }
}

impl fmt::Debug for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "Shape")
    }
}

impl fmt::Debug for State {
    /// The covered VV, which the snapshot header carries in the clear (ADR 0012 §11), and
    /// nothing of the shape.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("vv", &self.vv)
            .field("shape", &self.shape)
            .finish()
    }
}

/// What a verified op body is, kept for the life of the item as local evidence (ADR 0018 §3
/// "Snapshots are claims": which dots a replica merged from bodies is local state, not frozen).
/// A snapshot that records a write as its purge, or a known purge under another `item_key_id`,
/// contradicts an op body and is refused.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyKind {
    /// A create, edit, trash or restore: marker `Active` or `Trashed`.
    Write,
    /// A purge, with the `key_id` of its `ITEM_OP` envelope header.
    Purge(SymmetricKeyId),
}

impl fmt::Debug for BodyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "BodyKind")
    }
}

/// One op the merge holds: the body of a verified op, owned (ADR 0012 §3; the op data of
/// ADR 0018 §3 with the header's dot, HLC and causal context and the envelope's `key_id`).
///
/// The merge holds the ops since the item's newest snapshot, as clients keep them (ADR 0018
/// §10 "Newest snapshot"), and every body it merged or received with a snapshot, for the life
/// of the item, as evidence against snapshots (ADR 0018 §3 "Snapshots are claims").
#[derive(Clone)]
pub(crate) struct HeldOp {
    /// The op's dot.
    pub(crate) dot: Dot,
    /// Its HLC.
    pub(crate) hlc: Hlc,
    /// Its causal context.
    pub(crate) context: VersionVector,
    /// The `key_id` of its `ITEM_OP` envelope header.
    pub(crate) key_id: SymmetricKeyId,
    /// The lifecycle marker.
    pub(crate) lifecycle: crate::record::Lifecycle,
    /// The field writes, strictly ascending by key, never `@lifecycle` (ADR 0018 §5 rule 5).
    pub(crate) writes: Vec<(Bytes, Bytes)>,
}

impl fmt::Debug for HeldOp {
    /// The dot, HLC, context and `key_id`, which the header and envelope carry in the clear;
    /// never the marker or a write.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeldOp")
            .field("dot", &self.dot)
            .field("hlc", &self.hlc)
            .field("context", &self.context)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl HeldOp {
    /// Copies an op out of its verified header, envelope `key_id` and parsed data.
    pub(crate) fn new(
        header: &crate::header::OpHeader,
        key_id: SymmetricKeyId,
        data: &crate::record::OpData<'_>,
    ) -> Self {
        Self {
            dot: header.dot,
            hlc: header.hlc,
            context: header.causal_context.clone(),
            key_id,
            lifecycle: data.lifecycle(),
            writes: data
                .writes()
                .iter()
                .map(|w| {
                    (
                        Bytes::copy_from(w.key().expose_secret().as_bytes()),
                        Bytes::copy_from(w.value().expose_secret()),
                    )
                })
                .collect(),
        }
    }

    /// What the body is: a write or a purge.
    pub(crate) fn kind(&self) -> BodyKind {
        match self.lifecycle {
            crate::record::Lifecycle::Purge => BodyKind::Purge(self.key_id),
            crate::record::Lifecycle::Active | crate::record::Lifecycle::Trashed => BodyKind::Write,
        }
    }

    /// The op's writes with its marker applied as a write to `@lifecycle` (ADR 0018 §3
    /// "Lifecycle"), in canonical key order: `@lifecycle` sorts before every grammar key, so it
    /// comes first. A Purge writes nothing: it makes a tombstone.
    pub(crate) fn writes_with_lifecycle(&self) -> Vec<(Bytes, Bytes)> {
        let marker = self.lifecycle.register_value().map(|v| {
            (
                Bytes::copy_from(LIFECYCLE_KEY.as_bytes()),
                Bytes::copy_from(v.expose_secret()),
            )
        });
        marker
            .into_iter()
            .chain(self.writes.iter().cloned())
            .collect()
    }
}
