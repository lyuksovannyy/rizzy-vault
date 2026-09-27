//! Version vectors and causal contexts (ADR 0012 §2 "Per-item version vector" and "Causal
//! context", §3 "Canonical VV encoding").
//!
//! A [`VersionVector`] maps `device_id → seq`. As an item's VV, each entry is the highest
//! `device_seq` applied to the item from that device. A missing entry counts as 0 (ADR 0021
//! §2), and a zero entry is never stored, so each vector has exactly one representation and one
//! encoding.
//!
//! # Coverage and causality
//!
//! A dot `(d, s)` is *covered* by `V` when `V[d] ≥ s` ([`VersionVector::covers`]). Each op
//! carries as its [`CausalContext`] the item VV its author had at write time: op A happened
//! before op B when B's context covers A's dot, and otherwise the two are concurrent (ADR 0012
//! §2). The HLC never decides this.
//!
//! # Lattice operations
//!
//! Vectors are compared entrywise ([`VersionVector::compare`], and `PartialOrd` with the same
//! meaning), so two vectors can be concurrent.
//!
//! - [`join`](VersionVector::join), the entrywise maximum: adding an applied op's dot
//!   ([`add`](VersionVector::add), ADR 0018 §3 "Applying"), the tombstone context `c` as "the
//!   canonical join of the causal contexts of all applied Purge ops", and the covered VV after
//!   absorbing a snapshot, which "becomes the entrywise maximum" (ADR 0018 §3).
//! - [`meet`](VersionVector::meet), the entrywise minimum with zero entries left out: the
//!   server's clamped VV, `clamped(S)[d] = min(covered(S)[d], h(V, d))`, is the meet of the
//!   covered VV with the vault's heads (ADR 0021 §2). The merge spike cuts an absorbed
//!   snapshot's covered VV "to the op headers it has verified" (ADR 0018 §3 "Snapshots are
//!   claims") the same way, as the meet with the verified header heads
//!   (`spikes/merge-model`, `item.rs` `restrict`).
//! - [`compare`](VersionVector::compare): freshness checks refuse a VV lower than one already
//!   accepted (ADR 0012 §7 "Freshness", INV-25), and ADR 0018 §10 acts on a snapshot "whose
//!   covered VV is concurrent with its own".
//!
//! # Canonical encoding
//!
//! `u16 n ‖ n × (device_id ‖ u64 seq)`, entries strictly ascending by `device_id` bytewise
//! (no duplicates) and every `seq` ≥ 1 (ADR 0012 §3). Parsers reject any other encoding. It is
//! the layout of the op header's causal context and the snapshot header's covered VV
//! (ADR 0012 §3), of the tombstone's `c` (ADR 0018 §3), of the covered VV in the ADR 0018 §4
//! state hash, and of the clamped VV the server persists (ADR 0021 §2).
//!
//! **Bounds.** The ADRs set no limit on `n` other than its `u16`, so a vector holds at most
//! 65,535 entries on the wire: [`VersionVector::encode`] refuses a larger one and
//! [`VersionVector::read`] reads at most that many. Before reading any entry the parser checks
//! that `n × 24` bytes remain (CRYPTO.md §9.5 rule 5; ADR 0018 §5 applies the same rule to the
//! record), so a hostile count costs nothing. It never panics, and it leaves the reader
//! untouched on error.

use core::cmp::Ordering;
use core::num::NonZeroU64;
use std::collections::BTreeMap;

use rizzy_core::encoding::{Reader, put_u16};
use rizzy_core::ids::DeviceId;

use crate::dot::Dot;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};

/// The causal context of an op: the item VV its author had at write time (ADR 0012 §2), in the
/// op header in the canonical VV encoding (ADR 0012 §3).
pub type CausalContext = VersionVector;

/// How two version vectors compare, entry by entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VvOrdering {
    /// Every entry of `self` is at most `other`'s, and one is lower.
    Less,
    /// Every entry is equal: the vectors are the same.
    Equal,
    /// Every entry of `self` is at least `other`'s, and one is higher.
    Greater,
    /// Each vector has an entry higher than the other's.
    Concurrent,
}

/// A version vector: `device_id → seq`, zero entries left out (ADR 0012 §2, §3).
///
/// Equality is equality of every entry. Iteration and encoding run in ascending `device_id`
/// order, bytewise.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VersionVector {
    /// The non-zero entries, keyed by device. `DeviceId`'s `Ord` compares its 16 bytes
    /// lexicographically, which is the bytewise order of the canonical encoding.
    entries: BTreeMap<DeviceId, NonZeroU64>,
}

impl VersionVector {
    /// Length of one encoded entry: `device_id (16) ‖ u64 seq`, the layout of a [`Dot`].
    pub const ENTRY_LEN: usize = Dot::ENCODED_LEN;

    /// The most entries the `u16 n` of the encoding can count.
    pub const MAX_ENTRIES: usize = 65_535;

    /// The empty vector: every entry 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// The entry for `device_id`: the highest `seq` covered from that device, 0 if none.
    #[must_use]
    pub fn get(&self, device_id: DeviceId) -> u64 {
        self.entries.get(&device_id).map_or(0, |seq| seq.get())
    }

    /// Whether `dot` is covered: `V[dot.device_id] ≥ dot.seq` (ADR 0012 §2).
    ///
    /// For an op's causal context, `true` means the op with this dot happened before the op
    /// that carries the context.
    #[must_use]
    pub fn covers(&self, dot: Dot) -> bool {
        self.get(dot.device_id()) >= dot.seq()
    }

    /// The number of non-zero entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether every entry is 0.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The non-zero entries in ascending `device_id` order, each as the highest dot it covers
    /// from its device.
    #[must_use]
    pub fn entries(&self) -> impl ExactSizeIterator<Item = Dot> + '_ {
        self.entries
            .iter()
            .map(|(&device_id, &seq)| Dot::from_nonzero(device_id, seq))
    }

    /// Raises the entry of `dot`'s device to at least `dot.seq`; a lower `seq` changes
    /// nothing. The same as joining the vector `{dot.device_id: dot.seq}`.
    ///
    /// An applied op adds its dot to the item VV (ADR 0012 §4 step 4.3; ADR 0018 §3
    /// "Applying"). The vector then covers every lower `seq` of that device too, which is
    /// right because sequences are gap-free and delivery is causal (ADR 0012 §2, §4 step 2).
    pub fn add(&mut self, dot: Dot) {
        self.entries
            .entry(dot.device_id())
            .and_modify(|seq| *seq = (*seq).max(dot.seq_nonzero()))
            .or_insert(dot.seq_nonzero());
    }

    /// Joins `other` into `self`: every entry becomes the maximum of the two.
    ///
    /// Commutative, associative and idempotent; the result is the least vector at least as
    /// high as both.
    pub fn join(&mut self, other: &Self) {
        for dot in other.entries() {
            self.add(dot);
        }
    }

    /// Meets `self` with `other`: every entry becomes the minimum of the two, and entries that
    /// become 0 are removed.
    ///
    /// Commutative, associative and idempotent; the result is the greatest vector at most as
    /// high as both. ADR 0021 §2's clamped VV is `covered.meet(&heads)`.
    pub fn meet(&mut self, other: &Self) {
        self.entries
            .retain(|&device_id, seq| match other.entries.get(&device_id) {
                Some(&bound) => {
                    *seq = (*seq).min(bound);
                    true
                }
                None => false,
            });
    }

    /// Compares the two vectors entry by entry.
    #[must_use]
    pub fn compare(&self, other: &Self) -> VvOrdering {
        let self_higher = self.entries().any(|dot| !other.covers(dot));
        let other_higher = other.entries().any(|dot| !self.covers(dot));
        match (self_higher, other_higher) {
            (false, false) => VvOrdering::Equal,
            (false, true) => VvOrdering::Less,
            (true, false) => VvOrdering::Greater,
            (true, true) => VvOrdering::Concurrent,
        }
    }

    /// The length of the canonical encoding: `2 + 24 n`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.len().saturating_mul(Self::ENTRY_LEN).saturating_add(2)
    }

    /// Appends the canonical encoding (ADR 0012 §3) to `out`.
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`] if the vector has more than [`Self::MAX_ENTRIES`]
    /// entries. Nothing is appended then.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let n = u16::try_from(self.len()).map_err(|_| EncodeError::TooManyEntries)?;
        out.reserve(self.encoded_len());
        put_u16(out, n);
        for dot in self.entries() {
            dot.encode(out);
        }
        Ok(())
    }

    /// The canonical encoding (ADR 0012 §3) as a new vector of bytes.
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`], as [`VersionVector::encode`].
    pub fn to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Reads one canonically encoded vector from `reader` and leaves the reader after it, for
    /// a header or record parser.
    ///
    /// # Errors
    /// A [`DecodeError`] whose offset counts from the reader's position at the call:
    /// - [`DecodeErrorKind::Truncated`] at offset 0 if the count is missing or the input cannot
    ///   hold `n` entries;
    /// - [`DecodeErrorKind::ZeroSeq`] at the `seq` of an entry with `seq` 0;
    /// - [`DecodeErrorKind::NotAscending`] at the `device_id` of an entry that is not strictly
    ///   above the previous one.
    ///
    /// The reader is unchanged on error.
    pub fn read(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mut probe = reader.clone();
        let start = probe.remaining();
        let n = probe
            .u16()
            .map_err(|_| DecodeError::new(DecodeErrorKind::Truncated, 0))?;
        let n = usize::from(n);
        if n.checked_mul(Self::ENTRY_LEN)
            .is_none_or(|needed| needed > probe.remaining())
        {
            return Err(DecodeError::new(DecodeErrorKind::Truncated, 0));
        }
        let mut entries = BTreeMap::new();
        let mut previous: Option<DeviceId> = None;
        for _ in 0..n {
            let offset = start.saturating_sub(probe.remaining());
            let dot = Dot::read(&mut probe).map_err(|e| e.shifted(offset))?;
            if previous.is_some_and(|p| dot.device_id() <= p) {
                return Err(DecodeError::new(DecodeErrorKind::NotAscending, offset));
            }
            previous = Some(dot.device_id());
            entries.insert(dot.device_id(), dot.seq_nonzero());
        }
        *reader = probe;
        Ok(Self { entries })
    }

    /// Parses a canonically encoded vector that fills all of `bytes`, such as a stored clamped
    /// VV (ADR 0021 §2).
    ///
    /// # Errors
    /// As [`VersionVector::read`], plus [`DecodeErrorKind::TrailingBytes`] at the first byte
    /// after the vector.
    pub fn parse(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let vv = Self::read(&mut reader)?;
        if reader.is_empty() {
            Ok(vv)
        } else {
            let offset = bytes.len().saturating_sub(reader.remaining());
            Err(DecodeError::new(DecodeErrorKind::TrailingBytes, offset))
        }
    }
}

impl PartialOrd for VersionVector {
    /// The entrywise order: `None` for concurrent vectors (see [`VersionVector::compare`]).
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.compare(other) {
            VvOrdering::Less => Some(Ordering::Less),
            VvOrdering::Equal => Some(Ordering::Equal),
            VvOrdering::Greater => Some(Ordering::Greater),
            VvOrdering::Concurrent => None,
        }
    }
}

impl FromIterator<Dot> for VersionVector {
    /// The least vector that covers every dot: per device, the highest `seq` among the dots.
    fn from_iter<I: IntoIterator<Item = Dot>>(dots: I) -> Self {
        let mut vv = Self::new();
        for dot in dots {
            vv.add(dot);
        }
        vv
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code edits fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
