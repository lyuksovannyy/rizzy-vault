//! The per-item merge: multi-value registers with history, trash, purge and tombstones, and
//! snapshot absorption ([ADR 0012] §4–§5, as partially superseded by [ADR 0018] §3, §6 and §10;
//! [ADR 0018] §3, §9, §10; [ADR 0021] §9 client rules).
//!
//! One [`ItemMerge`] holds one item's state on one replica, and every rule that decides it.
//! The merge is generic over field keys and values: it stores and compares them and never
//! interprets them, except `@lifecycle`, whose values the record layer reads (ADR 0012 §13,
//! ADR 0018 §2). The schema layer (`rizzy_core::item`) decides what a key means; the display
//! and time helpers here only pass it the registers.
//!
//! # Input boundary
//!
//! Causal delivery, deduplication across the vault and the chain check (ADR 0012 §4 step 2,
//! §7 "Chain check after compaction") are the `causal` layer's, and verification (signature,
//! certificate, envelope, commitment, reader rule; ADR 0012 §4 step 1, CRYPTO.md §11.6, §11.8)
//! is `rizzy-client`'s through `rizzy-core`. What reaches this module is verified:
//!
//! - an op as an [`OpInput`]: its parsed [`OpHeader`], the `key_id` of its `ITEM_OP` envelope
//!   header, and its [`OpData`] parsed from the zeroizing plaintext, delivered in causal order;
//! - a snapshot as a [`SnapshotInput`]: its [`SnapshotHeader`] and [`SnapshotData`], with the op
//!   bodies of the same Fetch response;
//! - every verified op header of the item, bodied or bodiless ([`ItemMerge::record_header`]):
//!   clients keep them all (ADR 0021 §9 "Headers kept"), and a snapshot is cut to them.
//!
//! Only `item_schema_version` 1 reaches here: a record of another version is parked by the
//! caller (ADR 0018 §11), and one that does reach here is refused
//! ([`MergeError::UnsupportedSchema`]).
//!
//! # Entry points
//!
//! | Call | Who | Rule |
//! |---|---|---|
//! | [`ItemMerge::record_header`] | causal layer, every verified header of the item | ADR 0021 §9 "Headers kept"; ADR 0018 §3 "Each dot's verified header ... local state" |
//! | [`ItemMerge::is_ready`] | causal layer | ADR 0012 §4 step 2, per item: the context is applied, or the dot is covered |
//! | [`ItemMerge::apply_op`] | causal layer, a received op | ADR 0012 §4 step 4, §5; ADR 0018 §3 "Applying", "Covered ops" |
//! | [`ItemMerge::apply_own_op`] | client, an op it just wrote | the same, with the writer rules and the §10 triggers |
//! | [`ItemMerge::absorb_snapshot`] | causal layer, a cover of a bodiless header | ADR 0018 §3 "Absorbing a snapshot", "Snapshots are claims" |
//! | [`ItemMerge::end_fetch`] | causal layer, after a response's ops | ADR 0018 §10 merged-snapshot trigger (owner decision 13) |
//! | [`ItemMerge::write_snapshot`] | client, on a trigger | ADR 0018 §10 "No snapshot", "Newest snapshot" |
//! | [`ItemMerge::reissue_own_op`] | client, after a stale-epoch re-issue | ADR 0018 §3 "Re-issued ops" (owner decision 15); the writer rule's snapshot it calls for |
//! | [`ItemMerge::snapshot_data`], [`ItemMerge::canonical_state`] | client, tests | ADR 0018 §3–§4 |
//! | [`ItemMerge::lifecycle`], [`ItemMerge::field`], [`ItemMerge::times`], [`ItemMerge::purge_due`], [`ItemMerge::late_values_to_surface`] | client, UI | ADR 0018 §6, §9; ADR 0012 §5; ADR 0018 §3 "Surfacing" |
//!
//! # The merge
//!
//! Each field is a multi-value register (ADR 0012 §4). One function, the evidence join
//! (`join`), both applies an op and absorbs a snapshot: a key's current values are the held
//! values that no other held value's verified header context covers, and every other value is
//! history, the newest [`HISTORY_LIMIT`] per field by `(hlc, device_id, seq)` (ADR 0012 §5).
//! An op is joined as a one-op state, which on an honest state is ADR 0012 §4 step 4 exactly:
//! the current values the op's context covers move to history, and the op's values become
//! current. The op's lifecycle marker is a write to `@lifecycle` (ADR 0018 §3 "Lifecycle"), and
//! every field edit writes `Active`, so a concurrent trash and edit leave both values in the
//! register, and "Active wins" at display (ADR 0012 §5, owner decision 1).
//!
//! - **Covered ops** (ADR 0018 §3, owner decision 14; replaces ADR 0012 §4 step 3). An op body
//!   whose dot the item VV already covers still merges; a body already merged changes nothing
//!   ([`ApplyKind::Duplicate`]). A covered body is merged because the snapshot that covered its
//!   dot may lack its value: absence is never evidence.
//! - **Tombstones** (ADR 0018 §3 "Tombstone (c)", owner decisions 8 and 9). The first Purge on
//!   a live item keeps the late values of its current registers and discards everything else;
//!   a Purge is never rejected, whatever `@lifecycle` displays. Later purges join `c`, the
//!   highest `(hlc, device_id, seq)` becomes the recorded purge, and `item_key_id` is the
//!   `key_id` of the recorded purge's own envelope header. Any other op on a tombstone never
//!   resurrects it: it replaces the late values its context covers and adds its own, and its
//!   lifecycle byte writes nothing.
//! - **Snapshots are claims** (ADR 0018 §3, owner decision 14). An absorbed snapshot is cut to
//!   the verified headers, checked against every op body the replica has merged or received
//!   (kept for the life of the item), and joined; disagreements are reported, and no
//!   snapshot of the item is written while one is unresolved (`evidence`). Absorbing is an HLC
//!   receipt of the highest HLC the taken part carries ([`Absorbed::receive_hlc`]).
//!
//! # Snapshots and the ops a client keeps (ADR 0018 §10)
//!
//! - **Triggers** ([`SnapshotTrigger`]): more than [`SNAPSHOT_AFTER_OPS`] ops since the last
//!   snapshot, the first write under a fresh item key (the CRYPTO.md §11.6 writer rule), a
//!   purge, and, after a Fetch in which a concurrent snapshot was absorbed, the merged snapshot
//!   ([`ItemMerge::end_fetch`]).
//! - **No snapshot** ([`NoSnapshot`]) of an oversize item (its encoding breaks a §10 limit), of
//!   an item with an unresolved disagreement, or of an absent item. Its ops stay retained, so
//!   nothing is compacted and nothing is lost.
//! - **Newest snapshot.** [`ItemMerge::retained_ops`] are the ops the client must keep: those
//!   the newest snapshot does not cover. After a concurrent absorption, until the merged
//!   snapshot is written, and for good for an oversize item, the newest snapshot is the pair
//!   of the previous one and the absorbed one ([`ItemMerge::basis_covered`] is the join of
//!   their taken VVs), and the retained ops are those neither covers. A retained op that the
//!   new basis covers is folded into it before it is dropped, so a snapshot that covers an op
//!   without its value never removes the op's only local copy.
//!
//! # Readings where the ADRs leave a choice
//!
//! Each follows the merge spike (`spikes/merge-model`, `integrated` preset; its README
//! "AMBIGUOUS" and "Results" sections), unless marked otherwise:
//!
//! - **Which triggers count.** Triggers are evaluated when this device writes an op: "a
//!   purge" is its own purge, and applying received ops triggers nothing (spike AMBIGUOUS 16).
//!   "The first write under a fresh item key" is the writer-rule case, not a create (spike
//!   AMBIGUOUS 9): the caller passes [`OwnWrite::fresh_item_key`]. The 32-op count includes
//!   every op applied fresh, own or received (spike `ops_since_snap`).
//! - **The cut uses the item's own headers.** The spike models one item; with many, a covered
//!   VV is cut to the highest verified header of *this item* per device ([`ItemMerge`] keeps
//!   the item's headers). An entry above it claims an op of the item nobody verified.
//! - **Held bodies.** "An op body it holds" is read as every op body the replica merged, or
//!   received with a snapshot, for the life of the item: what each wrote (or that it was a
//!   purge, with its `key_id`) is kept as local evidence after the op leaves the retained ops,
//!   as the spike keeps `body_writes`, `writes_seen` and `purges_seen` for the life of the
//!   replica (`replica.rs` `learn_body`). ADR 0012 §6 and ADR 0018 §10 decide only which ops a
//!   client must keep *for sync* (those since the newest snapshot); a narrower reading would
//!   let a snapshot silently replace a value this replica merged from a signed body once a
//!   snapshot covered that body. The evidence is item content: its bytes are the zeroizing
//!   ones the state shares.
//! - **Resolving a disagreement.** No ADR says how a disagreement is resolved, and the spike
//!   never resolves one. So an item with one gets no further snapshot and keeps its ops.
//! - **A dominated snapshot** still goes through the join (which changes nothing on an honest
//!   state), since under "Snapshots are claims" it can carry a value another snapshot omitted.
//! - **"The pair"** is kept as the join of every snapshot absorbed since the last one written;
//!   a snapshot that covers the previous basis replaces it (the spike's `base`).
//!
//! # Secrets and local state
//!
//! Keys and values are item content (ADR 0018 §2): the merge copies each once into a zeroizing
//! buffer shared by the state, its history and the held ops, and `Debug` prints none of them.
//! Whether an item is live, trashed or purged is decrypted state too, so [`ItemLifecycle`],
//! [`SnapshotTrigger`] and [`Refusal`] print `[REDACTED]`, and [`ItemMerge`] prints its item
//! id and covered VV only. Dots, HLCs, version vectors and key ids are the server-visible
//! metadata of headers and envelopes.
//!
//! Besides the state, an [`ItemMerge`] keeps local evidence that no format freezes: the
//! verified header of each dot, which dots it merged from bodies, every op body it merged or
//! received with a snapshot (what each wrote), the retained ops and the newest-snapshot basis, the unresolved disagreements, and which late
//! values it surfaced. `rizzy-client` persists them. A replica rebuilt from its kept records
//! (every item header through [`ItemMerge::record_header`], its newest snapshot or pair through
//! [`ItemMerge::absorb_snapshot`], then its retained ops) reaches the same state bytes.
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0018]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0018-item-record-encoding.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

mod evidence;
mod join;
mod state;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::{DeviceId, ID_LEN, ItemId, SymmetricKeyId};
use rizzy_core::item::display::{
    self as core_display, Candidate, FieldDisplay, Lifecycle as ShownLifecycle, LifecycleDisplay,
};
use rizzy_core::item::schema::{IMPORT_CREATED_MS, ITEM_TYPE};
use rizzy_core::secret::SecretBytes;

use crate::dot::Dot;
use crate::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use crate::hlc::Hlc;
use crate::record::{
    Entry, FieldKey, LIFECYCLE_KEY, Lifecycle, OpData, RecordError, RecordErrorKind, SnapshotData,
    canonical_state, encode_snapshot,
};
use crate::vv::{VersionVector, VvOrdering};

use join::{Evidence, HeaderFacts, join_into, normalize, singleton};
use state::{HeldOp, Shape, State, Val};

/// History kept per field: the newest 50 values by `(hlc, device_id, seq)` (ADR 0012 §5,
/// owner decision 3). One constant for every replica, so pruning never depends on arrival
/// order.
pub const HISTORY_LIMIT: usize = 50;

/// A client writes a snapshot of an item after more than this many ops on it since its last
/// snapshot (ADR 0018 §10 "No snapshot"; ADR 0012 owner decision 3).
pub const SNAPSHOT_AFTER_OPS: u64 = 32;

/// The default trash retention, 30 days in milliseconds, measured from the trash op's HLC
/// (ADR 0012 §5, owner decision 3; ADR 0018 §9). The schema layer's constant.
pub const TRASH_RETENTION_MS: u64 = core_display::DEFAULT_TRASH_RETENTION_MS;

/// A verified op, as the merge receives it.
#[derive(Clone, Copy, Debug)]
pub struct OpInput<'a> {
    /// The op's verified, parsed header.
    pub header: &'a OpHeader,
    /// The `key_id` of the op's `ITEM_OP` envelope header (CRYPTO.md §9.1): the item key the
    /// reader rule matched. A recorded purge's `item_key_id` is this value (ADR 0018 §3).
    pub key_id: SymmetricKeyId,
    /// The op's data, parsed from the decrypted, zeroizing plaintext.
    pub data: &'a OpData<'a>,
}

/// A verified snapshot, as the merge receives it.
///
/// `Debug` prints the header only: whether the data is a live snapshot or a tombstone, and
/// what a tombstone records, is decrypted state (ADR 0012 §5).
#[derive(Clone, Copy)]
pub struct SnapshotInput<'a> {
    /// The snapshot's verified, parsed header: its item, author and covered VV.
    pub header: &'a SnapshotHeader,
    /// Its data, parsed against the header's covered VV (ADR 0018 §5).
    pub data: &'a SnapshotData<'a>,
}

impl fmt::Debug for SnapshotInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotInput")
            .field("header", self.header)
            .finish_non_exhaustive()
    }
}

/// What a write of this device is, beyond its op, for the writer rules and the snapshot
/// triggers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnWrite {
    /// The CRYPTO.md §11.6 writer rule generated a fresh item key for this op, for an item that
    /// already had one (a rotation, not a create). A snapshot is then due (ADR 0018 §10).
    pub fresh_item_key: bool,
    /// The client holds an unapplied record of this item: parked, or waiting for predecessors
    /// or a wrap. It then issues no Purge for the item (ADR 0018 §11 "No purge over an
    /// unapplied record").
    pub holds_unapplied_record: bool,
}

/// How an op body met the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApplyKind {
    /// The op was new to the item: its dot joined the covered VV (ADR 0018 §3 "Applying").
    Applied,
    /// The item VV already covered the op's dot, through a snapshot, and its body merged
    /// (ADR 0018 §3 "Covered ops"). On an honest state this changes nothing.
    CoveredMerged,
    /// This body was merged before; nothing changed.
    Duplicate,
}

/// Why a snapshot of the item is due (ADR 0018 §10 "No snapshot").
///
/// `Debug` prints `[REDACTED]`: a trigger after a purge reveals that the item is purged.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnapshotTrigger {
    /// More than [`SNAPSHOT_AFTER_OPS`] ops since the last snapshot.
    OpCount,
    /// The first write under a fresh item key (the CRYPTO.md §11.6 writer rule).
    FreshItemKey,
    /// This device purged the item.
    AfterPurge,
    /// A Fetch absorbed a snapshot whose covered VV is concurrent with the item's (owner
    /// decision 13): the merged snapshot, once the response's ops are applied.
    MergedAfterConcurrentAbsorption,
    /// A re-issue discarded an unsent snapshot that covered the re-issued op (ADR 0018 §3
    /// "Re-issued ops"), and no fresh item key calls for the writer rule's snapshot: a
    /// replacement is due, because the merge dropped the ops that snapshot covered from
    /// [`ItemMerge::retained_ops`] when it was written. This follows the merge spike
    /// (`replica.rs` `reissue_outbox`, "a replacement for a dropped snapshot").
    ReplacesDiscarded,
}

/// What a re-issue of an own op did beyond the op, for the snapshot it calls for (ADR 0018 §3
/// "Re-issued ops", owner decision 15).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reissue {
    /// The CRYPTO.md §11.6 writer rule generated a fresh item key for the re-issued op: the
    /// writer rule's snapshot is due.
    pub fresh_item_key: bool,
    /// The client discarded an unsent snapshot of the item that covers the re-issued op.
    pub discarded_unsent_snapshot: bool,
}

impl fmt::Debug for SnapshotTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SnapshotTrigger([REDACTED])")
    }
}

/// The result of merging one op body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    /// How the body met the state.
    pub kind: ApplyKind,
    /// The HLC the device clock receives (ADR 0012 §2, with the skew guard of
    /// [`Hlc::receive`]): the op's, for another device's op applied fresh; `None` otherwise.
    pub receive_hlc: Option<Hlc>,
    /// For an own op, the snapshot trigger it fired, if any.
    pub snapshot_due: Option<SnapshotTrigger>,
}

/// A covered-VV entry that a snapshot claims above the item's verified headers: not taken, and
/// reported (ADR 0018 §3 "Snapshots are claims": "reports the cut").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClaimCut {
    /// The device whose entry was cut.
    pub device_id: DeviceId,
    /// The highest `seq` of that device among the item's verified headers.
    pub verified_to: u64,
    /// The `seq` the snapshot claimed.
    pub claimed_to: u64,
    /// The snapshot's author.
    pub author: DeviceId,
}

/// Why a verified snapshot was refused (ADR 0018 §3 "Snapshots are claims"). Nothing of it is
/// taken, and the caller reports it.
///
/// `Debug` prints only the dot involved: the kinds name purges and tombstones, which is
/// decrypted state.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Refusal {
    /// A tombstone whose recorded purge is above the verified headers, or whose `purge_hlc`
    /// is not the purge header's.
    PurgeAboveCut,
    /// A value that the op body at its dot, which the replica merged or received (now or
    /// earlier), did not write.
    ValueNotInBody {
        /// The value's dot.
        dot: Dot,
    },
    /// A value at the dot of a Purge, which writes nothing.
    ValueAtPurgeDot {
        /// The Purge's dot.
        dot: Dot,
    },
    /// A tombstone whose recorded purge is a dot whose body was a write.
    WriteRecordedAsPurge {
        /// The dot.
        dot: Dot,
    },
    /// A tombstone that records a known purge under another `item_key_id` than the one of its
    /// envelope.
    PurgeKeyContradicts {
        /// The purge's dot.
        dot: Dot,
    },
    /// A tombstone whose `c` is not reached by the contexts of the ops it covers that are not
    /// known writes.
    ContextNotFromPurges,
}

impl Refusal {
    /// The dot the refusal names, if any.
    #[must_use]
    pub const fn dot(&self) -> Option<Dot> {
        match self {
            Self::PurgeAboveCut | Self::ContextNotFromPurges => None,
            Self::ValueNotInBody { dot }
            | Self::ValueAtPurgeDot { dot }
            | Self::WriteRecordedAsPurge { dot }
            | Self::PurgeKeyContradicts { dot } => Some(*dot),
        }
    }
}

impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refusal").field("dot", &self.dot()).finish()
    }
}

/// What absorbing a snapshot took and found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absorbed {
    /// The taken part's covered VV against the item's before: `Less` or `Equal` for a
    /// dominated snapshot, `Greater` for a dominating one, `Concurrent` for one that makes the
    /// merged snapshot due.
    pub relation: VvOrdering,
    /// The highest HLC among the taken values, history entries and `purge_hlc`: the device
    /// clock receives it, under the skew guard (ADR 0018 §3 "Absorbing a snapshot").
    pub receive_hlc: Option<Hlc>,
    /// Dots on which the snapshot and the replica disagree and neither can be shown wrong:
    /// reported, never decided, and unresolved from now on ([`ItemMerge::unresolved`]).
    pub disagreements: Vec<Dot>,
    /// Dots of values the cut VV covers but that were not taken, because their HLC is not
    /// their verified header's or no header of the item vouches for them.
    pub ignored_values: Vec<Dot>,
}

/// Absorbed, or refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbsorbOutcome {
    /// The snapshot's taken part joined the state.
    Absorbed(Absorbed),
    /// Nothing was taken.
    Refused(Refusal),
}

/// The result of absorbing a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absorption {
    /// Absorbed or refused.
    pub outcome: AbsorbOutcome,
    /// The covered-VV entries above the item's verified headers, cut and reported, whether or
    /// not the snapshot was absorbed.
    pub claim_cuts: Vec<ClaimCut>,
}

/// Why no snapshot is written (ADR 0018 §10 "No snapshot").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NoSnapshot {
    /// No op has reached the item: there is nothing to snapshot.
    Absent,
    /// A disagreement about the item is unresolved (ADR 0018 §3 "Snapshots are claims").
    Unresolved,
    /// The item is oversize: its encoding breaks an ADR 0018 §10 limit. Its ops stay retained.
    Oversize,
    /// The state breaks another ADR 0018 §5 rule, which only verified records no honest merge
    /// produces can cause (a cycle of verified contexts). Its ops stay retained.
    Unencodable,
}

/// A snapshot the client encrypts and signs: its covered VV, for the header, and its data.
pub struct WrittenSnapshot {
    /// The covered VV of the snapshot header: the item VV.
    pub covered: VersionVector,
    /// The `ITEM_SNAPSHOT` `data` (ADR 0018 §3), zeroizing, for the envelope to frame, pad and
    /// encrypt.
    pub data: SecretBytes,
}

impl fmt::Debug for WrittenSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrittenSnapshot")
            .field("covered", &self.covered)
            .finish_non_exhaustive()
    }
}

/// What the item is: the lifecycle it shows.
///
/// `Debug` prints `[REDACTED]`: which items are trashed or purged is encrypted (ADR 0012 §5).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemLifecycle {
    /// No op has reached the item on this replica.
    Absent,
    /// `@lifecycle` displays Active: listed and editable. Active wins over a concurrent trash.
    Active,
    /// `@lifecycle` displays Trashed: in the trash, restorable until purged.
    Trashed,
    /// A tombstone: purged, possibly with late values to surface.
    Purged,
}

impl fmt::Debug for ItemLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemLifecycle([REDACTED])")
    }
}

/// The item's times from the HLC (ADR 0018 §9), Unix milliseconds. `None` where there is no
/// value to derive one from, and for a tombstone.
///
/// `Debug` prints `[REDACTED]`: a trashed-at time reveals the lifecycle.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemTimes {
    /// Created: `import.created_ms` if it displays a U64, else the lowest HLC among the
    /// `item.type` register's values.
    pub created_ms: Option<u64>,
    /// Modified: the highest HLC among the current values of every register but `@lifecycle`.
    pub modified_ms: Option<u64>,
    /// Trashed at: the highest HLC among the Trashed values, while `@lifecycle` displays
    /// Trashed. The trash retention runs from it.
    pub trashed_at_ms: Option<u64>,
}

impl fmt::Debug for ItemTimes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemTimes([REDACTED])")
    }
}

/// One field of the item, as the record layer shows it, with what it displays (ADR 0018 §6).
#[derive(Clone, Debug)]
pub struct FieldView<'a> {
    /// The field's key.
    pub key: FieldKey<'a>,
    /// Its current values (a tombstone's late values), strictly ascending by dot.
    pub current: Vec<Entry<'a>>,
    /// Its history, strictly ascending by dot; empty on a tombstone.
    pub history: Vec<Entry<'a>>,
    /// What displays: the index in `current` of the displayed value, whether the field is
    /// conflicting, and a cleared value it displays over. `None` without a current value.
    pub display: Option<FieldDisplay>,
}

/// Why the merge refused a call. Nothing changed. Errors name dots, never content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MergeError {
    /// The header names another item than this merge's.
    WrongItem,
    /// The record's `item_schema_version` is not 1: the caller parks it (ADR 0018 §11).
    UnsupportedSchema,
    /// A header for this dot is already held, with another HLC or causal context: the
    /// device signed two versions of one op, which the chain check reports.
    HeaderConflict {
        /// The dot.
        dot: Dot,
    },
    /// The op's context is not applied yet and its dot is not covered (ADR 0012 §4 step 2):
    /// the causal layer holds it.
    NotReady {
        /// The op's dot.
        dot: Dot,
    },
    /// An own op whose causal context is not the item VV, or whose dot the item already
    /// covers (ADR 0012 §2 "Causal context").
    NotCurrent {
        /// The op's dot.
        dot: Dot,
    },
    /// An own Purge that the writer rules forbid: the item does not display Trashed, or the
    /// client holds an unapplied record of it (ADR 0012 §5, ADR 0018 §11).
    WriterRule,
    /// A re-issued op whose dot the merge never merged from a body, or whose HLC or context
    /// differs from the original's (ADR 0018 §3 "Re-issued ops").
    UnknownOp {
        /// The op's dot.
        dot: Dot,
    },
    /// A held key is not a record key, which a state the merge built never holds.
    InvalidKey,
    /// The record layer refused the state (the §4 state-hash input).
    Record(RecordError),
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongItem => f.write_str("record of another item"),
            Self::UnsupportedSchema => f.write_str("unsupported item schema version"),
            Self::HeaderConflict { .. } => f.write_str("two different headers for one dot"),
            Self::NotReady { .. } => f.write_str("op delivered before its causal context"),
            Self::NotCurrent { .. } => f.write_str("own op not written on the current state"),
            Self::WriterRule => f.write_str("own op refused by the writer rules"),
            Self::UnknownOp { .. } => f.write_str("re-issued op does not match a merged op"),
            Self::InvalidKey => f.write_str("held field key is not a record key"),
            Self::Record(e) => write!(f, "state refused by the record layer: {e}"),
        }
    }
}

impl core::error::Error for MergeError {}

/// Whether a record-layer error is an ADR 0018 §10 limit: the item is oversize.
const fn is_limit(kind: RecordErrorKind) -> bool {
    matches!(
        kind,
        RecordErrorKind::DataTooLong
            | RecordErrorKind::CountTooLarge
            | RecordErrorKind::ValueTooLong
            | RecordErrorKind::KeyLength
    )
}

/// The display layer's view of held values.
fn candidates(values: &[Val]) -> Vec<Candidate<'_>> {
    values
        .iter()
        .map(|v| Candidate {
            hlc: v.hlc.to_u64(),
            device_id: v.dot.device_id(),
            seq: v.dot.seq(),
            value: v.value.expose(),
        })
        .collect()
}

/// One item's merge state on one replica. See the [module docs](self).
#[derive(Clone)]
pub struct ItemMerge {
    /// The item.
    item_id: ItemId,
    /// The item state: the covered VV and a live item or a tombstone.
    state: State,
    /// The verified header of every op of the item the replica holds one for.
    headers: BTreeMap<Dot, HeaderFacts>,
    /// Every op body merged or received with a snapshot, kept for the life of the item as
    /// evidence against snapshots ("Held bodies" in the module docs). Shares its bytes with
    /// the state.
    bodies: BTreeMap<Dot, HeldOp>,
    /// The dots whose body merged.
    merged: BTreeSet<Dot>,
    /// The ops since the newest snapshot, which the client keeps (ADR 0018 §10).
    retained: BTreeMap<Dot, HeldOp>,
    /// The newest snapshot's state: the one last written, joined with every snapshot absorbed
    /// since, and with the retained ops it covers folded in.
    base: State,
    /// Ops applied fresh since the last snapshot this replica wrote.
    ops_since_snapshot: u64,
    /// A concurrent snapshot was absorbed in the current Fetch.
    merge_due: bool,
    /// Dots of disagreements reported and not resolved.
    unresolved: BTreeSet<Dot>,
    /// Dots of late values already surfaced to the user.
    surfaced: BTreeSet<Dot>,
    /// The `key_id` of every item key in the item's wrap set.
    wrap_keys: BTreeSet<[u8; ID_LEN]>,
}

impl fmt::Debug for ItemMerge {
    /// The item id and the covered VV, which headers carry in the clear; nothing of the state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemMerge")
            .field("item_id", &self.item_id)
            .field("covered", &self.state.vv)
            .finish_non_exhaustive()
    }
}

impl ItemMerge {
    /// The merge of `item_id`, which no op has reached yet.
    #[must_use]
    pub fn new(item_id: ItemId) -> Self {
        Self {
            item_id,
            state: State::default(),
            headers: BTreeMap::new(),
            bodies: BTreeMap::new(),
            merged: BTreeSet::new(),
            retained: BTreeMap::new(),
            base: State::default(),
            ops_since_snapshot: 0,
            merge_due: false,
            unresolved: BTreeSet::new(),
            surfaced: BTreeSet::new(),
            wrap_keys: BTreeSet::new(),
        }
    }

    /// The item.
    #[must_use]
    pub const fn item_id(&self) -> ItemId {
        self.item_id
    }

    /// The item VV: every op the state includes. It is the causal context of the next op this
    /// device writes (ADR 0012 §2), and the covered VV of a snapshot of the state.
    #[must_use]
    pub const fn covered(&self) -> &VersionVector {
        &self.state.vv
    }

    /// Refuses a record of another item or schema version.
    fn check_record(&self, item_id: ItemId, version: ItemSchemaVersion) -> Result<(), MergeError> {
        if item_id != self.item_id {
            return Err(MergeError::WrongItem);
        }
        if version != ItemSchemaVersion::V1 {
            return Err(MergeError::UnsupportedSchema);
        }
        Ok(())
    }

    /// Records a verified op header of the item, bodied or bodiless (ADR 0021 §9 "Headers
    /// kept"). A snapshot is cut to the recorded headers, and a value's current or history
    /// place is decided by the recorded contexts, so the causal layer records every header of
    /// the item it verifies. Recording one twice is a no-op.
    ///
    /// # Errors
    /// [`MergeError::WrongItem`], [`MergeError::UnsupportedSchema`], or
    /// [`MergeError::HeaderConflict`] when another header with a different HLC or causal
    /// context is held for the dot. A re-issued op keeps both (ADR 0018 §3 "Re-issued ops"),
    /// so it never conflicts with its original.
    pub fn record_header(&mut self, header: &OpHeader) -> Result<(), MergeError> {
        self.check_record(header.item_id, header.item_schema_version)?;
        let facts = HeaderFacts {
            hlc: header.hlc,
            context: header.causal_context.clone(),
        };
        match self.headers.entry(header.dot) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(facts);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(slot) if *slot.get() == facts => Ok(()),
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(MergeError::HeaderConflict { dot: header.dot })
            }
        }
    }

    /// Adds an item key of the item's wrap set, by its `key_id` (CRYPTO.md §11.6 reader rule).
    /// On one purge dot recorded under two `item_key_id`s, which only a dishonest record
    /// carries, the one in the wrap set is taken first (ADR 0018 §3). That choice reads the wrap set
    /// when the two versions meet, so it can depend on whether this key was added before or
    /// after; the case is always reported as a disagreement.
    pub fn add_item_key(&mut self, key_id: SymmetricKeyId) {
        self.wrap_keys.insert(*key_id.as_bytes());
    }

    /// Whether the op with `header` can merge now: the item VV covers its dot, or its causal
    /// context is applied (ADR 0012 §4 step 2, for this item; the chain order across the vault
    /// is the causal layer's).
    #[must_use]
    pub fn is_ready(&self, header: &OpHeader) -> bool {
        self.state.vv.covers(header.dot)
            || matches!(
                header.causal_context.compare(&self.state.vv),
                VvOrdering::Less | VvOrdering::Equal
            )
    }

    /// Merges one verified op body: records its header, then joins it into the state unless
    /// this body merged before.
    fn merge_body(&mut self, op: OpInput<'_>) -> Result<ApplyKind, MergeError> {
        self.record_header(op.header)?;
        let dot = op.header.dot;
        if self.merged.contains(&dot) {
            return Ok(ApplyKind::Duplicate);
        }
        if !self.is_ready(op.header) {
            return Err(MergeError::NotReady { dot });
        }
        let held = HeldOp::new(op.header, op.key_id, op.data);
        let fresh = !self.state.vv.covers(dot);
        let ev = Evidence {
            headers: &self.headers,
            wrap_keys: &self.wrap_keys,
        };
        join_into(&mut self.state, &singleton(&held), ev);
        self.merged.insert(dot);
        self.bodies.insert(dot, held.clone());
        self.retained.insert(dot, held);
        if fresh {
            self.ops_since_snapshot = self.ops_since_snapshot.saturating_add(1);
            Ok(ApplyKind::Applied)
        } else {
            Ok(ApplyKind::CoveredMerged)
        }
    }

    /// Applies a verified op of the item, delivered in causal order (ADR 0012 §4 steps 3–4 as
    /// ADR 0018 §3 restates them, §5).
    ///
    /// The op merges even when the item VV covers its dot ("Covered ops"); a body merged
    /// before changes nothing. Every op merges whatever the item shows: a Purge is never
    /// rejected, and an op on a tombstone never resurrects it (ADR 0018 §3 "Applying").
    ///
    /// # Errors
    /// [`MergeError::WrongItem`], [`MergeError::UnsupportedSchema`],
    /// [`MergeError::HeaderConflict`], or [`MergeError::NotReady`] when the op's context is not
    /// applied and its dot not covered. Nothing changes then, except that a new header is
    /// recorded.
    pub fn apply_op(&mut self, op: OpInput<'_>) -> Result<Applied, MergeError> {
        let kind = self.merge_body(op)?;
        Ok(Applied {
            kind,
            receive_hlc: (kind == ApplyKind::Applied).then_some(op.header.hlc),
            snapshot_due: None,
        })
    }

    /// Applies an op this device just wrote on the current state, after checking the writer
    /// rules, and reports the snapshot trigger it fires (ADR 0018 §10).
    ///
    /// The op's causal context must be the item VV (ADR 0012 §2), and a Purge is allowed only
    /// while the item displays Trashed and the client holds no unapplied record of it
    /// (ADR 0012 §5, ADR 0018 §11). The trigger, if any: the writer rule's fresh item key, this
    /// device's purge, or more than [`SNAPSHOT_AFTER_OPS`] ops since the last snapshot.
    ///
    /// # Errors
    /// [`MergeError::NotCurrent`] for a context other than the item VV or a dot the item
    /// covers, [`MergeError::WriterRule`] for a forbidden Purge, and the errors of
    /// [`ItemMerge::apply_op`]. Nothing changes then.
    pub fn apply_own_op(&mut self, op: OpInput<'_>, own: OwnWrite) -> Result<Applied, MergeError> {
        self.check_record(op.header.item_id, op.header.item_schema_version)?;
        let dot = op.header.dot;
        if op.header.causal_context != self.state.vv || self.state.vv.covers(dot) {
            return Err(MergeError::NotCurrent { dot });
        }
        let purge = op.data.lifecycle() == Lifecycle::Purge;
        if purge && !self.may_purge(own.holds_unapplied_record) {
            return Err(MergeError::WriterRule);
        }
        let kind = self.merge_body(op)?;
        let snapshot_due = if own.fresh_item_key {
            Some(SnapshotTrigger::FreshItemKey)
        } else if purge {
            Some(SnapshotTrigger::AfterPurge)
        } else if self.ops_since_snapshot > SNAPSHOT_AFTER_OPS {
            Some(SnapshotTrigger::OpCount)
        } else {
            None
        };
        Ok(Applied {
            kind,
            receive_hlc: None,
            snapshot_due,
        })
    }

    /// Absorbs a verified snapshot of the item under "Snapshots are claims" (ADR 0018 §3,
    /// owner decision 14), with `with`, the op bodies of the item that came in the same Fetch
    /// response (their headers are recorded, and what they are is kept).
    ///
    /// In Server-mode sync a replica absorbs a snapshot only as the cover of a bodiless header
    /// (ADR 0021 §4); the causal layer decides which. The snapshot is cut to the item's
    /// verified headers, checked against every op body the replica knows, `with` included, and joined
    /// into the state. On every honest state the result is the join of the two states: what
    /// applying every op either covers would give. The covered VV becomes the entrywise
    /// maximum, and a dominated honest snapshot changes nothing. After a concurrent one, the
    /// merged snapshot is due at [`ItemMerge::end_fetch`].
    ///
    /// # Errors
    /// [`MergeError::WrongItem`], [`MergeError::UnsupportedSchema`], or
    /// [`MergeError::HeaderConflict`] for the snapshot or a body in `with`. A refusal under
    /// "Snapshots are claims" is not an error: it is [`AbsorbOutcome::Refused`].
    pub fn absorb_snapshot(
        &mut self,
        snapshot: SnapshotInput<'_>,
        with: &[OpInput<'_>],
    ) -> Result<Absorption, MergeError> {
        let header = snapshot.header;
        self.check_record(header.item_id, header.item_schema_version)?;
        for op in with {
            self.record_header(op.header)?;
            let held = HeldOp::new(op.header, op.key_id, op.data);
            self.bodies.insert(held.dot, held);
        }
        let ev = Evidence {
            headers: &self.headers,
            wrap_keys: &self.wrap_keys,
        };
        let heads = evidence::heads(ev);
        let claim_cuts = evidence::claim_cuts(&header.covered, &heads, header.author);
        let offered = State::from_snapshot(&header.covered, snapshot.data);
        let refused = |refusal| Absorption {
            outcome: AbsorbOutcome::Refused(refusal),
            claim_cuts: claim_cuts.clone(),
        };
        let cut = match evidence::cut(&offered, &heads, ev) {
            Ok(cut) => cut,
            Err(refusal) => return Ok(refused(refusal)),
        };
        if let Some(refusal) = evidence::contradiction(&cut.state, &self.bodies, ev) {
            return Ok(refused(refusal));
        }
        let disagreements = evidence::disagreements(&self.state, &cut.state, &self.bodies, ev);
        let relation = cut.state.vv.compare(&self.state.vv);
        let receive_hlc = cut.state.max_hlc();
        let taken = normalize(&cut.state, ev);
        join_into(&mut self.state, &taken, ev);
        // The newest snapshot (ADR 0018 §10): the previous basis joined with the taken part;
        // the retained ops the new basis covers are folded into it before they are dropped.
        join_into(&mut self.base, &taken, ev);
        let folded: Vec<Dot> = self
            .retained
            .keys()
            .filter(|dot| self.base.vv.covers(**dot))
            .copied()
            .collect();
        for dot in folded {
            if let Some(op) = self.retained.remove(&dot) {
                join_into(&mut self.base, &singleton(&op), ev);
            }
        }
        self.unresolved.extend(disagreements.iter().copied());
        if relation == VvOrdering::Concurrent {
            self.merge_due = true;
        }
        Ok(Absorption {
            outcome: AbsorbOutcome::Absorbed(Absorbed {
                relation,
                receive_hlc,
                disagreements,
                ignored_values: cut.ignored,
            }),
            claim_cuts,
        })
    }

    /// Ends a Fetch for this item, once the response's ops are applied: if a snapshot whose
    /// covered VV was concurrent with the item's was absorbed during it, the merged snapshot is
    /// due (ADR 0018 §10, owner decision 13).
    pub fn end_fetch(&mut self) -> Option<SnapshotTrigger> {
        core::mem::take(&mut self.merge_due)
            .then_some(SnapshotTrigger::MergedAfterConcurrentAbsorption)
    }

    /// The snapshot data of the state, encoded (ADR 0018 §3), or why there is none.
    fn encode(&self) -> Result<SecretBytes, NoSnapshot> {
        let data = self
            .state
            .snapshot_data()
            .map_err(|_| NoSnapshot::Unencodable)?
            .ok_or(NoSnapshot::Absent)?;
        encode_snapshot(&self.state.vv, &data).map_err(|e| {
            if is_limit(e.kind()) {
                NoSnapshot::Oversize
            } else {
                NoSnapshot::Unencodable
            }
        })
    }

    /// Whether the item is oversize: the encoding of its state breaks an ADR 0018 §10 limit.
    /// Replicas with the same state agree on it.
    #[must_use]
    pub fn is_oversize(&self) -> bool {
        matches!(self.encode(), Err(NoSnapshot::Oversize))
    }

    /// Writes a snapshot of the state (ADR 0018 §3, §10): its covered VV and encoded data, for
    /// the client to encrypt under the writer rule's item key and sign. The snapshot becomes the
    /// newest one: the retained ops are dropped and the op count restarts.
    ///
    /// # Errors
    /// A [`NoSnapshot`] reason, and nothing changes: an absent item, an unresolved
    /// disagreement, an oversize item or an unencodable state. The item's ops stay retained.
    pub fn write_snapshot(&mut self) -> Result<WrittenSnapshot, NoSnapshot> {
        if self.state.is_absent() {
            return Err(NoSnapshot::Absent);
        }
        if !self.unresolved.is_empty() {
            return Err(NoSnapshot::Unresolved);
        }
        let data = self.encode()?;
        self.base = self.state.clone();
        self.retained.clear();
        self.ops_since_snapshot = 0;
        Ok(WrittenSnapshot {
            covered: self.state.vv.clone(),
            data,
        })
    }

    /// Holds a re-issued own op in place of the original (ADR 0018 §3 "Re-issued ops", owner
    /// decision 15): same dot, HLC, causal context and data; only `vault_key_epoch`, the item
    /// key (`key_id`), the wrap and the signature change. The only state byte that depends on
    /// the envelope is a tombstone's `item_key_id` when the op is the recorded purge, which
    /// becomes `key_id`. The client discards every unsent snapshot that covers the op and
    /// writes the snapshot this returns: [`SnapshotTrigger::FreshItemKey`] for the writer rule's
    /// snapshot when `reissue` took a fresh item key, else [`SnapshotTrigger::ReplacesDiscarded`]
    /// when it discarded an unsent snapshot, else none. Call it once per re-issued op; the
    /// client writes one snapshot after the last, as the merge spike does.
    ///
    /// # Errors
    /// [`MergeError::WrongItem`], [`MergeError::UnsupportedSchema`], or
    /// [`MergeError::UnknownOp`] when no body with this dot, HLC and context merged. Nothing
    /// changes then.
    pub fn reissue_own_op(
        &mut self,
        header: &OpHeader,
        key_id: SymmetricKeyId,
        reissue: Reissue,
    ) -> Result<Option<SnapshotTrigger>, MergeError> {
        self.check_record(header.item_id, header.item_schema_version)?;
        let dot = header.dot;
        let same = self
            .headers
            .get(&dot)
            .is_some_and(|h| h.hlc == header.hlc && h.context == header.causal_context);
        if !same || !self.merged.contains(&dot) {
            return Err(MergeError::UnknownOp { dot });
        }
        if let Some(op) = self.bodies.get_mut(&dot) {
            op.key_id = key_id;
        }
        if let Some(op) = self.retained.get_mut(&dot) {
            op.key_id = key_id;
        }
        for state in [&mut self.state, &mut self.base] {
            if let Shape::Tomb(t) = &mut state.shape
                && t.purge.dot == dot
            {
                t.purge.key_id = key_id;
            }
        }
        Ok(if reissue.fresh_item_key {
            Some(SnapshotTrigger::FreshItemKey)
        } else if reissue.discarded_unsent_snapshot {
            Some(SnapshotTrigger::ReplacesDiscarded)
        } else {
            None
        })
    }

    /// The state as record data, borrowing every key and value: a live snapshot or a
    /// tombstone. `None` for an absent item.
    ///
    /// # Errors
    /// [`MergeError::InvalidKey`], which a state the merge built never raises.
    pub fn snapshot_data(&self) -> Result<Option<SnapshotData<'_>>, MergeError> {
        self.state.snapshot_data()
    }

    /// The ADR 0012 §12 state-hash input (ADR 0018 §4): `u16 item_schema_version ‖ covered VV
    /// ‖ data`, `data` encoded without the §10 limits, so an oversize state has one too. Equal
    /// states give equal bytes. `None` for an absent item. For tests (ADR 0018 §4).
    ///
    /// # Errors
    /// [`MergeError::Record`] if the state breaks a §5 rule other than a §10 limit, which only
    /// a cycle of verified contexts can cause; [`MergeError::InvalidKey`].
    pub fn canonical_state(&self) -> Result<Option<SecretBytes>, MergeError> {
        let Some(data) = self.state.snapshot_data()? else {
            return Ok(None);
        };
        canonical_state(&self.state.vv, &data)
            .map(Some)
            .map_err(MergeError::Record)
    }

    /// The ops the client keeps: those the newest snapshot, or the pair after a concurrent
    /// absorption, does not cover (ADR 0018 §10 "Newest snapshot"), and the covered bodies
    /// merged since, ascending by dot.
    pub fn retained_ops(&self) -> impl Iterator<Item = Dot> + '_ {
        self.retained.keys().copied()
    }

    /// The covered VV of the newest snapshot, or of the pair after a concurrent absorption
    /// (their join): the ops it covers need not be kept.
    #[must_use]
    pub const fn basis_covered(&self) -> &VersionVector {
        &self.base.vv
    }

    /// The newest-snapshot basis as record data, borrowing every key and value: the state of
    /// the newest snapshot, or of the pair after a concurrent absorption, with the retained ops
    /// it covers folded in. `None` while no snapshot was written or absorbed.
    ///
    /// On honest records it is the join of the kept snapshot records. After a dishonest one it
    /// can hold values no record holds (a folded op whose value the absorbed snapshot lacked),
    /// so a client that drops the ops [`ItemMerge::retained_ops`] no longer lists persists the
    /// basis as local state, encrypted like the rest of its store, and rebuilds the item from
    /// it and the retained ops (the ADR 0012 §6 recomputation).
    ///
    /// # Errors
    /// [`MergeError::InvalidKey`], which a state the merge built never raises.
    pub fn basis_data(&self) -> Result<Option<SnapshotData<'_>>, MergeError> {
        self.base.snapshot_data()
    }

    /// Ops applied fresh since the last snapshot this replica wrote.
    #[must_use]
    pub const fn ops_since_snapshot(&self) -> u64 {
        self.ops_since_snapshot
    }

    /// The dots of reported disagreements, unresolved: while any is, no snapshot of the item is
    /// written (ADR 0018 §3).
    pub fn unresolved(&self) -> impl Iterator<Item = Dot> + '_ {
        self.unresolved.iter().copied()
    }

    /// The current values of `@lifecycle`, empty for a tombstone or an item without one.
    fn lifecycle_values(&self) -> &[Val] {
        match &self.state.shape {
            Shape::Live(l) => l
                .regs
                .get(LIFECYCLE_KEY.as_bytes())
                .map_or(&[], Vec::as_slice),
            Shape::Tomb(_) => &[],
        }
    }

    /// What `@lifecycle` displays, with "Active wins" (ADR 0012 §5): the displayed value and,
    /// when Active wins over a concurrent Trashed value, that value, for "deleted on X while
    /// it was being edited on Y". Indexes are into the `@lifecycle` register of
    /// [`ItemMerge::field`]. `None` for a tombstone or an absent item.
    #[must_use]
    pub fn lifecycle_display(&self) -> Option<LifecycleDisplay> {
        core_display::resolve_lifecycle(&candidates(self.lifecycle_values()))
    }

    /// What the item is: absent, active, trashed or purged.
    #[must_use]
    pub fn lifecycle(&self) -> ItemLifecycle {
        if self.state.is_tomb() {
            return ItemLifecycle::Purged;
        }
        match self.lifecycle_display().map(|d| d.shown) {
            Some(ShownLifecycle::Active) => ItemLifecycle::Active,
            Some(ShownLifecycle::Trashed) => ItemLifecycle::Trashed,
            None => ItemLifecycle::Absent,
        }
    }

    /// One field: its current (or late) values, its history and what it displays (ADR 0018
    /// §6). `None` when the item has no such register.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<FieldView<'_>> {
        let (regs, hist) = match &self.state.shape {
            Shape::Live(l) => (&l.regs, Some(&l.hist)),
            Shape::Tomb(t) => (&t.late, None),
        };
        let (held_key, current) = regs.get_key_value(key.as_bytes())?;
        let history = hist
            .and_then(|h| h.get(key.as_bytes()))
            .map_or(&[][..], Vec::as_slice);
        Some(FieldView {
            key: state::field_key(held_key).ok()?,
            current: current.iter().map(Val::entry).collect(),
            history: history.iter().map(Val::entry).collect(),
            display: core_display::resolve_field(&candidates(current)),
        })
    }

    /// The item's times from the HLC (ADR 0018 §9). All `None` for a tombstone.
    #[must_use]
    pub fn times(&self) -> ItemTimes {
        let Shape::Live(l) = &self.state.shape else {
            return ItemTimes {
                created_ms: None,
                modified_ms: None,
                trashed_at_ms: None,
            };
        };
        let register =
            |key: &str| candidates(l.regs.get(key.as_bytes()).map_or(&[][..], Vec::as_slice));
        let all: Vec<(&[u8], Vec<Candidate<'_>>)> = l
            .regs
            .iter()
            .map(|(k, values)| (k.expose(), candidates(values)))
            .collect();
        ItemTimes {
            created_ms: core_display::created_ms(
                &register(ITEM_TYPE),
                &register(IMPORT_CREATED_MS),
            ),
            modified_ms: core_display::modified_ms(
                all.iter().map(|(k, values)| (*k, values.as_slice())),
            ),
            trashed_at_ms: core_display::trashed_at_ms(&register(LIFECYCLE_KEY)),
        }
    }

    /// Whether this device may write a Purge of the item: it displays Trashed (ADR 0012 §5,
    /// "A Purge op is allowed only on trashed items", which binds the writer) and the client
    /// holds no unapplied record of it (ADR 0018 §11).
    #[must_use]
    pub fn may_purge(&self, holds_unapplied_record: bool) -> bool {
        !holds_unapplied_record && self.lifecycle() == ItemLifecycle::Trashed
    }

    /// Whether the automatic purge is due at `now_ms`: the item may be purged
    /// ([`ItemMerge::may_purge`]) and `retention_ms` ([`TRASH_RETENTION_MS`] by default) has
    /// passed since it was trashed, measured from the trash op's HLC (ADR 0012 §5, ADR 0018
    /// §9). Only clients purge, and only when one is online after the retention period.
    #[must_use]
    pub fn purge_due(&self, now_ms: u64, retention_ms: u64, holds_unapplied_record: bool) -> bool {
        self.may_purge(holds_unapplied_record)
            && self
                .times()
                .trashed_at_ms
                .is_some_and(|at| core_display::purge_due_ms(at, retention_ms) <= now_ms)
    }

    /// The dots of the tombstone's late values not yet surfaced, ascending: "An edit from
    /// Laptop arrived for an item you deleted permanently. Restore it as a new item?" is shown
    /// once for them (ADR 0018 §3 "Surfacing"; local presentation, no state byte). Empty for a
    /// live item.
    #[must_use]
    pub fn late_values_to_surface(&self) -> Vec<Dot> {
        let mut dots: Vec<Dot> = match &self.state.shape {
            Shape::Tomb(t) => t
                .late
                .values()
                .flatten()
                .map(|v| v.dot)
                .filter(|dot| !self.surfaced.contains(dot))
                .collect(),
            Shape::Live(_) => Vec::new(),
        };
        dots.sort_unstable();
        dots.dedup();
        dots
    }

    /// Marks every current late value as surfaced.
    pub fn mark_surfaced(&mut self) {
        let dots = self.late_values_to_surface();
        self.surfaced.extend(dots);
    }
}

#[cfg(test)]
mod testkit;

#[cfg(test)]
mod faults;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes generated fixtures; a panic there fails the test, which CLAUDE.md allows"
)]
mod proptests;
