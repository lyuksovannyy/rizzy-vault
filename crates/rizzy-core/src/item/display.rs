//! Display rules and item times (ADR 0018 §6 "Display", owner decision 4; ADR 0012 §5
//! "Active wins"; ADR 0018 §9).
//!
//! A field is a multi-value register: it holds one current value, or several after concurrent
//! writes. The merge that builds the register is `rizzy-sync`'s; this module only decides what
//! the user sees, and changes no byte of the converged state (owner decision 4):
//!
//! 1. **One value or a conflict.** Byte-identical current values count as one value. A field
//!    whose current values are not all byte-identical is *conflicting*, and the UI offers "keep
//!    both / pick one". Picking a value, or any new edit, writes a value whose context covers
//!    all of them, which resolves the conflict (ADR 0018 §6).
//! 2. **Which value displays.** The one with the highest `(hlc, device_id, seq)`: `hlc`
//!    numerically, then `device_id` bytewise, then `seq` numerically. This is the order ADR
//!    0012 §5 prunes history by; `seq` breaks the tie two current values of one device can
//!    reach after a faulty context.
//! 3. **A cleared value never displays over a concurrent non-empty one.** The highest non-empty
//!    value displays, with "cleared on X while edited on Y": the field-level counterpart of
//!    "Active wins" ([`FieldDisplay::cleared_by`]).
//!
//! **Lifecycle** ([`resolve_lifecycle`]). The `@lifecycle` register holds `0x01` Active and
//! `0x02` Trashed values. When a delete and an edit are concurrent it holds both, and **Active
//! wins**: the item stays visible, with the notice "deleted on X while it was being edited on
//! Y" (ADR 0012 §5, owner decision 1). Losing an edit to a concurrent delete would be silent
//! data loss.
//!
//! **Times** (ADR 0018 §9). No wall-clock field is written; the HLC is the only time source, so
//! every replica derives the same times. An HLC's top 48 bits are Unix milliseconds
//! ([`hlc_ms`], ADR 0012 §2).
//!
//! - *Created*: the lowest HLC among the values of the `item.type` register, unless
//!   `import.created_ms` is set ([`created_ms`]).
//! - *Modified*: the highest HLC among the current values of every register except `@lifecycle`
//!   ([`modified_ms`]).
//! - *Trashed at*: the highest HLC among the Trashed values, while `@lifecycle` displays Trashed
//!   ([`trashed_at_ms`]). The trash retention (ADR 0012 §5, default 30 days) runs from it.
//!
//! **Inputs.** The caller passes each current value of one register as a [`Candidate`]: its
//! HLC, the `device_id` and `seq` of its dot, and its encoded bytes. The record layer guarantees
//! one dot at most once per key (ADR 0018 §4 "Uniqueness"), so no two candidates of one register
//! tie; if a caller passes a tie anyway, the later one wins, and nothing panics. Values are
//! compared with `subtle::ConstantTimeEq` (CRYPTO.md §12.3); their lengths, which envelopes
//! reveal anyway, may short-circuit the comparison.

use core::fmt;

use subtle::ConstantTimeEq as _;

use crate::ids::DeviceId;

use super::schema::{Expected, read_value};
use super::value::ValueRef;
use super::{LIFECYCLE_ACTIVE, LIFECYCLE_KEY, LIFECYCLE_TRASHED};

/// The default trash retention: 30 days, in milliseconds (ADR 0012 §5, owner decision 3). A
/// device may purge a trashed item once this long has passed since [`trashed_at_ms`], unless it
/// holds an unapplied record for the item (ADR 0018 §11).
pub const DEFAULT_TRASH_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// One current value of a register, with what the display order needs.
///
/// `Debug` prints the HLC and the dot, which the server sees in the op header anyway
/// (ADR 0012 §11), and never the value.
#[derive(Clone, Copy)]
pub struct Candidate<'a> {
    /// The HLC of the op that wrote the value.
    pub hlc: u64,
    /// The `device_id` of the value's dot.
    pub device_id: DeviceId,
    /// The `seq` of the value's dot.
    pub seq: u64,
    /// The encoded value (ADR 0018 §6), empty for Cleared.
    pub value: &'a [u8],
}

impl fmt::Debug for Candidate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("hlc", &self.hlc)
            .field("device_id", &self.device_id)
            .field("seq", &self.seq)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Candidate<'_> {
    /// The display order: `(hlc, device_id, seq)`, compared left to right (ADR 0018 §6).
    #[must_use]
    pub fn rank(&self) -> (u64, DeviceId, u64) {
        (self.hlc, self.device_id, self.seq)
    }
}

/// What a field shows.
///
/// Whether a field conflicts, or was cleared on one device while edited on another, is
/// derived from its values, so `Debug` prints none of it (ADR 0018 §2).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldDisplay {
    /// Index, in the slice passed in, of the displayed value.
    pub displayed: usize,
    /// `true` if the current values are not all byte-identical: the UI marks the field as
    /// conflicting and offers "keep both / pick one".
    pub conflict: bool,
    /// When a non-empty value displays over a concurrent Cleared one: the index of the highest
    /// Cleared value, for "cleared on X while edited on Y" (X is its device, Y the displayed
    /// value's). `None` otherwise.
    pub cleared_by: Option<usize>,
}

impl fmt::Debug for FieldDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldDisplay([REDACTED])")
    }
}

/// Index of the highest-ranked candidate that `keep` selects.
fn highest(values: &[Candidate<'_>], keep: impl Fn(&Candidate<'_>) -> bool) -> Option<usize> {
    values
        .iter()
        .enumerate()
        .filter(|(_, c)| keep(c))
        .max_by(|(_, a), (_, b)| a.rank().cmp(&b.rank()))
        .map(|(i, _)| i)
}

/// Resolves one register for display (ADR 0018 §6). `None` for a register with no value.
#[must_use]
pub fn resolve_field(values: &[Candidate<'_>]) -> Option<FieldDisplay> {
    let best_non_empty = highest(values, |c| !c.value.is_empty());
    let best_cleared = highest(values, |c| c.value.is_empty());
    let displayed = best_non_empty.or(best_cleared)?;
    let shown = values.get(displayed)?.value;
    let conflict = values.iter().any(|c| !bool::from(c.value.ct_eq(shown)));
    Some(FieldDisplay {
        displayed,
        conflict,
        cleared_by: if shown.is_empty() { None } else { best_cleared },
    })
}

/// The value a register displays, read against what its key expects: `None` when the register
/// is empty or the displayed value is unsupported ([`read_value`]).
#[must_use]
pub fn displayed_value<'a>(expected: Expected, values: &[Candidate<'a>]) -> Option<ValueRef<'a>> {
    let shown = values.get(resolve_field(values)?.displayed)?;
    read_value(expected, shown.value)
}

/// The two states `@lifecycle` shows (ADR 0018 §3; purged items are tombstones, which the record
/// layer holds).
///
/// `@lifecycle` is a register of the encrypted item data, like any field (ADR 0012 §11: the
/// server does not see field values), so which items are trashed stays out of `Debug` as well
/// (ADR 0018 §2), here and in [`LifecycleDisplay`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lifecycle {
    /// Active: listed and editable.
    Active,
    /// Trashed: in the trash, restorable until purged.
    Trashed,
}

impl fmt::Debug for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lifecycle([REDACTED])")
    }
}

/// What the `@lifecycle` register shows. `Debug` prints none of it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LifecycleDisplay {
    /// Active if any current value is Active ("Active wins"), else Trashed.
    pub shown: Lifecycle,
    /// Index, in the slice passed in, of the highest-ranked value of the shown state.
    pub displayed: usize,
    /// When Active wins over a concurrent Trashed value: the index of the highest Trashed
    /// value, for "deleted on X while it was being edited on Y". `None` otherwise.
    pub trashed_by: Option<usize>,
}

impl fmt::Debug for LifecycleDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LifecycleDisplay([REDACTED])")
    }
}

/// Resolves the `@lifecycle` register (ADR 0012 §5 "Active wins"). Values other than the one
/// byte `0x01` or `0x02`, which the record layer rejects (ADR 0018 §5 rule 5), are ignored.
/// `None` if no value is left.
#[must_use]
pub fn resolve_lifecycle(values: &[Candidate<'_>]) -> Option<LifecycleDisplay> {
    let active = highest(values, |c| c.value == [LIFECYCLE_ACTIVE]);
    let trashed = highest(values, |c| c.value == [LIFECYCLE_TRASHED]);
    match (active, trashed) {
        (Some(displayed), trashed_by) => Some(LifecycleDisplay {
            shown: Lifecycle::Active,
            displayed,
            trashed_by,
        }),
        (None, Some(displayed)) => Some(LifecycleDisplay {
            shown: Lifecycle::Trashed,
            displayed,
            trashed_by: None,
        }),
        (None, None) => None,
    }
}

/// The Unix milliseconds of an HLC: its top 48 bits (ADR 0012 §2, ADR 0018 §9).
#[must_use]
pub const fn hlc_ms(hlc: u64) -> u64 {
    hlc >> 16
}

/// When the item was created, in Unix milliseconds (ADR 0018 §9): the value
/// `import.created_ms` displays, if it displays a U64, else the lowest HLC among the values of
/// the `item.type` register. `None` if neither gives a time.
///
/// `item_type` and `import_created` are the current values of those two registers (empty if
/// the register does not exist).
#[must_use]
pub fn created_ms(item_type: &[Candidate<'_>], import_created: &[Candidate<'_>]) -> Option<u64> {
    if let Some(ValueRef::U64(ms)) = displayed_value(Expected::U64, import_created) {
        return Some(ms);
    }
    item_type.iter().map(|c| c.hlc).min().map(hlc_ms)
}

/// When the item was last modified, in Unix milliseconds (ADR 0018 §9): the highest HLC among
/// the current values of every register except `@lifecycle`. `None` for no such value.
///
/// `registers` yields each register's key and current values; the record layer's keys, as
/// bytes, so that `@lifecycle` can be passed and skipped.
#[must_use]
pub fn modified_ms<'a>(
    registers: impl IntoIterator<Item = (&'a [u8], &'a [Candidate<'a>])>,
) -> Option<u64> {
    registers
        .into_iter()
        .filter(|(key, _)| *key != LIFECYCLE_KEY.as_bytes())
        .flat_map(|(_, values)| values.iter().map(|c| c.hlc))
        .max()
        .map(hlc_ms)
}

/// When the item was trashed, in Unix milliseconds (ADR 0018 §9): the highest HLC among the
/// Trashed values of `@lifecycle`, while it displays Trashed. `None` while it displays Active,
/// or has no value.
#[must_use]
pub fn trashed_at_ms(lifecycle: &[Candidate<'_>]) -> Option<u64> {
    let shown = resolve_lifecycle(lifecycle)?;
    if shown.shown != Lifecycle::Trashed {
        return None;
    }
    lifecycle
        .iter()
        .filter(|c| c.value == [LIFECYCLE_TRASHED])
        .map(|c| c.hlc)
        .max()
        .map(hlc_ms)
}

/// When the retention of a trashed item ends: `trashed_at_ms + retention_ms`, saturating. A
/// client may purge the item from then on (ADR 0012 §5), unless it holds an unapplied record
/// for it (ADR 0018 §11, "No purge over an unapplied record"). Nothing here reads a clock.
#[must_use]
pub const fn purge_due_ms(trashed_at_ms: u64, retention_ms: u64) -> u64 {
    trashed_at_ms.saturating_add(retention_ms)
}
