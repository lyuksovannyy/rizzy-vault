//! Strict parsing of op and snapshot data (ADR 0018 §5), under the §10 limits.
//!
//! Each function reads one production of the §3 layouts and applies the rules that concern
//! it where it reads it, so a rule is checked in exactly one place: key length and grammar in
//! [`Parser::key`], value length in [`Parser::value`], counts in [`Parser::count`], the
//! `register` production with its dot order, coverage, `@lifecycle` values and the tombstone's
//! rule 8 in [`Parser::register`]. Every element is borrowed from `data`; the only
//! allocations are the element vectors, each sized after its count has been checked against
//! the remaining input, and the tombstone's `c`.

use core::cmp::Ordering;
use core::fmt;

use rizzy_core::ids::{ID_LEN, SymmetricKeyId};

use super::{
    Entry, FieldKey, LIFECYCLE_KEY, Lifecycle, Limits, LiveSnapshot, OpData, RecordError,
    RecordErrorKind as K, RecordKind, Register, SnapshotData, Tombstone, Value, Write, grammar_key,
};
use crate::cursor::Cursor;
use crate::dot::Dot;
use crate::vv::VersionVector;

// The smallest encoding of each counted production, by its layout alone: an empty key, an
// empty value, no entry. A count is refused as running past the end (rule 2) only when that
// many elements cannot fit in the remaining input whatever they hold; an element that fits
// but breaks another rule (an empty key, m = 0) is refused by that rule where it is read.

/// Smallest encoding of an op write, `str(key) ‖ bytes(value)`: two `u32` lengths.
const MIN_WRITE_LEN: usize = 4 + 4;

/// Smallest encoding of an entry, `dot ‖ u64 hlc ‖ bytes(value)`: an empty value.
const MIN_ENTRY_LEN: usize = Dot::ENCODED_LEN + 8 + 4;

/// Smallest encoding of a `register` production, `str(key) ‖ u16 m`: an empty key, m = 0.
const MIN_REGISTER_LEN: usize = 4 + 2;

/// What a register production is, for the rules that depend on it.
///
/// A late register exists only in a tombstone, so the variant says whether the item is purged:
/// `Debug` prints `Group([REDACTED])`, like the record types (see [`SnapshotData`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    /// A current register of a live snapshot: `@lifecycle` allowed, and required first.
    Current,
    /// A history group of a live snapshot: `@lifecycle` allowed.
    History,
    /// A late register of a tombstone: `@lifecycle` refused, values checked against `c`.
    Late,
}

impl fmt::Debug for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Group([REDACTED])")
    }
}

/// A cursor over `data` with the limits in force.
#[derive(Debug)]
struct Parser<'a> {
    /// The bytes being parsed.
    cur: Cursor<'a>,
    /// The limits: ADR 0018 §10's, except when checking [`super::canonical_state`]'s output.
    limits: Limits,
}

impl<'a> Parser<'a> {
    /// Reads `u16` count and checks it against `max` and against the remaining input, at
    /// `min_len` bytes per element.
    fn count(&mut self, max: usize, min_len: usize) -> Result<usize, RecordError> {
        let at = self.cur.offset();
        let n = usize::from(self.cur.u16()?);
        if n > max {
            return Err(RecordError::new(K::CountTooLarge, at));
        }
        if n.checked_mul(min_len)
            .is_none_or(|needed| needed > self.cur.remaining())
        {
            return Err(RecordError::new(K::Truncated, at));
        }
        Ok(n)
    }

    /// Reads `str(field_key)`: 1–160 bytes (rule 2), checked on the length field before the
    /// bytes are taken, then the §7 grammar (rule 3) through [`grammar_key`], the schema
    /// layer's parser, unless it is `@lifecycle`, which the caller places. Either failure is
    /// reported at the offset of the `str` field.
    fn key(&mut self) -> Result<FieldKey<'a>, RecordError> {
        let at = self.cur.offset();
        let len = usize::try_from(self.cur.u32()?).unwrap_or(usize::MAX);
        if len == 0 || len > super::MAX_KEY_LEN {
            return Err(RecordError::new(K::KeyLength, at));
        }
        let bytes = self
            .cur
            .take(len)
            .map_err(|_| RecordError::new(K::Truncated, at))?;
        if bytes == LIFECYCLE_KEY.as_bytes() {
            return Ok(FieldKey::LIFECYCLE);
        }
        grammar_key(bytes).map_err(|kind| RecordError::new(kind, at))
    }

    /// Reads a key that must be strictly above `previous` (rule 3), refusing `@lifecycle`
    /// where rule 5 does.
    fn ordered_key(
        &mut self,
        previous: Option<FieldKey<'a>>,
        lifecycle_allowed: bool,
    ) -> Result<FieldKey<'a>, RecordError> {
        let at = self.cur.offset();
        let key = self.key()?;
        if key.is_lifecycle() && !lifecycle_allowed {
            return Err(RecordError::new(K::MisplacedLifecycle, at));
        }
        if previous.is_some_and(|p| p >= key) {
            return Err(RecordError::new(K::NotAscending, at));
        }
        Ok(key)
    }

    /// Reads `bytes(value)`, at most the value limit (rule 2).
    fn value(&mut self) -> Result<Value<'a>, RecordError> {
        let at = self.cur.offset();
        let len = usize::try_from(self.cur.u32()?).unwrap_or(usize::MAX);
        if len > self.limits.value {
            return Err(RecordError::new(K::ValueTooLong, at));
        }
        let bytes = self
            .cur
            .take(len)
            .map_err(|_| RecordError::new(K::Truncated, at))?;
        Ok(Value(bytes))
    }

    /// Reads one `register` production of `group`: its key (checked against `previous`), then
    /// `u16 m` (1–256) entries, strictly ascending by dot and covered by `covered`
    /// (rules 2, 3, 5, 6). A `@lifecycle` register's values must be `0x01` or `0x02`
    /// (rule 5); a late value must not be covered by `c` (rule 8).
    fn register(
        &mut self,
        group: Group,
        previous: Option<FieldKey<'a>>,
        covered: &VersionVector,
        context: Option<&VersionVector>,
    ) -> Result<Register<'a>, RecordError> {
        let key = self.ordered_key(previous, group != Group::Late)?;
        let at = self.cur.offset();
        let m = self.count(self.limits.values, MIN_ENTRY_LEN)?;
        if m == 0 {
            return Err(RecordError::new(K::EmptyRegister, at));
        }
        let mut entries: Vec<Entry<'a>> = Vec::with_capacity(m);
        for _ in 0..m {
            let at = self.cur.offset();
            let dot = self.cur.dot()?;
            if entries.last().is_some_and(|e| e.dot >= dot) {
                return Err(RecordError::new(K::NotAscending, at));
            }
            if !covered.covers(dot) {
                return Err(RecordError::new(K::NotCovered, at));
            }
            if context.is_some_and(|c| c.covers(dot)) {
                return Err(RecordError::new(K::LateValueCovered, at));
            }
            let hlc = self.cur.hlc()?;
            let value_at = self.cur.offset();
            let value = self.value()?;
            if key.is_lifecycle() && Lifecycle::from_register_value(value).is_none() {
                return Err(RecordError::new(K::InvalidLifecycleValue, value_at));
            }
            entries.push(Entry { dot, hlc, value });
        }
        Ok(Register { key, entries })
    }

    /// Reads op data after its kind byte (ADR 0018 §3 "op data").
    fn op(&mut self) -> Result<OpData<'a>, RecordError> {
        let at = self.cur.offset();
        let lifecycle =
            Lifecycle::from_u8(self.cur.u8()?).ok_or(RecordError::new(K::InvalidLifecycle, at))?;
        let at = self.cur.offset();
        let n = self.count(self.limits.writes, MIN_WRITE_LEN)?;
        if n > 0 && lifecycle != Lifecycle::Active {
            return Err(RecordError::new(K::WritesWithoutActive, at));
        }
        let mut writes: Vec<Write<'a>> = Vec::with_capacity(n);
        for _ in 0..n {
            let key = self.ordered_key(writes.last().map(|w| w.key), false)?;
            let value = self.value()?;
            writes.push(Write { key, value });
        }
        self.cur.finish()?;
        Ok(OpData { lifecycle, writes })
    }

    /// Reads live snapshot data after its kind byte (ADR 0018 §3 "live snapshot data").
    fn live(&mut self, covered: &VersionVector) -> Result<LiveSnapshot<'a>, RecordError> {
        let at = self.cur.offset();
        let r = self.count(self.limits.groups, MIN_REGISTER_LEN)?;
        if r == 0 {
            // `1 ≤ r` (§3). Rule 2, as the merge spike's `validate_snapshot` files it.
            return Err(RecordError::new(K::NoRegister, at));
        }
        let mut registers: Vec<Register<'a>> = Vec::with_capacity(r);
        for _ in 0..r {
            let at = self.cur.offset();
            let reg = self.register(
                Group::Current,
                registers.last().map(|g| g.key),
                covered,
                None,
            )?;
            if registers.is_empty() && !reg.key.is_lifecycle() {
                return Err(RecordError::new(K::MissingLifecycle, at));
            }
            registers.push(reg);
        }
        let h = self.count(self.limits.groups, MIN_REGISTER_LEN)?;
        let mut history: Vec<Register<'a>> = Vec::with_capacity(h);
        for _ in 0..h {
            let at = self.cur.offset();
            let group =
                self.register(Group::History, history.last().map(|g| g.key), covered, None)?;
            // Rule 7: the group's key is a current register's. Both lists are sorted by key.
            let current = registers
                .binary_search_by(|g| g.key.cmp(&group.key))
                .ok()
                .and_then(|i| registers.get(i))
                .ok_or(RecordError::new(K::OrphanHistory, at))?;
            // §4 "Uniqueness": no dot in both the register and its history group.
            if shares_a_dot(&current.entries, &group.entries) {
                return Err(RecordError::new(K::DuplicateDot, at));
            }
            history.push(group);
        }
        self.cur.finish()?;
        Ok(LiveSnapshot { registers, history })
    }

    /// Reads tombstone data after its kind byte (ADR 0018 §3 "tombstone data").
    fn tombstone(&mut self, covered: &VersionVector) -> Result<Tombstone<'a>, RecordError> {
        let at = self.cur.offset();
        let purge_dot = self.cur.dot()?;
        if !covered.covers(purge_dot) {
            return Err(RecordError::new(K::NotCovered, at));
        }
        let purge_hlc = self.cur.hlc()?;
        let at = self.cur.offset();
        let context = self.cur.vv()?;
        // §4 "Coverage": every entry of `c` is covered by the covered VV.
        let uncovered = context.entries().position(|d| !covered.covers(d));
        if let Some(i) = uncovered {
            let entry_at = at + 2 + i * VersionVector::ENTRY_LEN;
            return Err(RecordError::new(K::NotCovered, entry_at));
        }
        let item_key_id = SymmetricKeyId::from_bytes(*self.cur.array::<ID_LEN>()?);
        let l = self.count(self.limits.groups, MIN_REGISTER_LEN)?;
        let mut late: Vec<Register<'a>> = Vec::with_capacity(l);
        for _ in 0..l {
            let reg = self.register(
                Group::Late,
                late.last().map(|g| g.key),
                covered,
                Some(&context),
            )?;
            late.push(reg);
        }
        self.cur.finish()?;
        Ok(Tombstone {
            purge_dot,
            purge_hlc,
            context,
            item_key_id,
            late,
        })
    }
}

/// Whether two lists of entries, each strictly ascending by dot, share a dot. A merge walk.
fn shares_a_dot(a: &[Entry<'_>], b: &[Entry<'_>]) -> bool {
    let (mut i, mut j) = (a.iter().peekable(), b.iter().peekable());
    while let (Some(x), Some(y)) = (i.peek(), j.peek()) {
        match x.dot.cmp(&y.dot) {
            Ordering::Less => {
                i.next();
            }
            Ordering::Greater => {
                j.next();
            }
            Ordering::Equal => return true,
        }
    }
    false
}

/// Parses op data under `limits`.
pub(super) fn op_with(data: &[u8], limits: Limits) -> Result<OpData<'_>, RecordError> {
    if data.len() > limits.op_data {
        return Err(RecordError::new(K::DataTooLong, 0));
    }
    let mut p = Parser {
        cur: Cursor::new(data),
        limits,
    };
    if p.cur.u8()? != RecordKind::Op.to_u8() {
        return Err(RecordError::new(K::WrongKind, 0));
    }
    p.op()
}

/// Parses snapshot data under `limits`.
pub(super) fn snapshot_with<'a>(
    covered: &VersionVector,
    data: &'a [u8],
    limits: Limits,
) -> Result<SnapshotData<'a>, RecordError> {
    if data.len() > limits.snapshot_data {
        return Err(RecordError::new(K::DataTooLong, 0));
    }
    let mut p = Parser {
        cur: Cursor::new(data),
        limits,
    };
    let kind = p.cur.u8()?;
    if kind == RecordKind::LiveSnapshot.to_u8() {
        p.live(covered).map(SnapshotData::Live)
    } else if kind == RecordKind::Tombstone.to_u8() {
        p.tombstone(covered).map(SnapshotData::Tombstone)
    } else {
        Err(RecordError::new(K::WrongKind, 0))
    }
}

/// Parses the `data` of an `ITEM_OP` envelope (ADR 0018 §5 `parse_op`), borrowing every key
/// and value from `data`.
///
/// `data` is the decrypted, unframed plaintext of an envelope whose header and signature the
/// caller has verified, with `item_schema_version` 1.
///
/// # Errors
/// A [`RecordError`] when the data breaks any ADR 0018 §5 rule (listed in the
/// [module docs](super)); the whole op is then rejected and reported, as for a failed
/// decryption (ADR 0012 §4 step 1). Data longer than 1 MiB is refused before decoding.
pub fn parse_op(data: &[u8]) -> Result<OpData<'_>, RecordError> {
    op_with(data, Limits::V1)
}

/// Parses the `data` of an `ITEM_SNAPSHOT` envelope (ADR 0018 §5 `parse_snapshot`): a live
/// snapshot or a tombstone, borrowing every key and value from `data`.
///
/// `covered` is the snapshot header's covered VV, against which rule 6 checks every dot.
/// As for [`parse_op`], `data` is the decrypted, unframed plaintext of a verified envelope with
/// `item_schema_version` 1.
///
/// # Errors
/// A [`RecordError`] when the data breaks any ADR 0018 §5 rule; the whole snapshot is then
/// rejected and reported. Data longer than 12 MiB is refused before decoding.
pub fn parse_snapshot<'a>(
    covered: &VersionVector,
    data: &'a [u8],
) -> Result<SnapshotData<'a>, RecordError> {
    snapshot_with(covered, data, Limits::V1)
}

#[cfg(test)]
mod tests {
    //! The parser's private register marker prints no variant: a late register would say the
    //! item is purged.

    use super::Group;

    #[test]
    fn group_debug_is_redacted() {
        for group in [Group::Current, Group::History, Group::Late] {
            assert_eq!(format!("{group:?}"), "Group([REDACTED])");
        }
    }
}
