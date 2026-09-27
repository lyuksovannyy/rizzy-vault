//! The item-record layer (ADR 0018 §2 "Record"): the `data` of `ITEM_OP` and `ITEM_SNAPSHOT`
//! envelopes, `item_schema_version` 1.
//!
//! `data` is the CRYPTO.md §8.5 `data`, frame and padding removed (the envelope does that). It
//! carries no version and no purpose: the caller has verified the envelope and its header,
//! only [`ItemSchemaVersion::V1`](crate::header::ItemSchemaVersion::V1) reaches this module,
//! and the purpose picks the entry point (ADR 0018 §5).
//!
//! # Layouts (ADR 0018 §3)
//!
//! ```text
//! op data (ITEM_OP)
//!   u8  record_kind = 0x01
//!   u8  lifecycle                          0x01 Active | 0x02 Trashed | 0x03 Purge
//!   u16 n ‖ n × ( str(field_key) ‖ bytes(value) )           field writes, n ≤ 1,024
//!
//! live snapshot data (ITEM_SNAPSHOT)
//!   u8  record_kind = 0x02
//!   u16 r ‖ r × register                   current registers, 1 ≤ r ≤ 4,096; the first is "@lifecycle"
//!   u16 h ‖ h × register                   history groups, h ≤ 4,096; values = history entries
//!
//! tombstone data (ITEM_SNAPSHOT)
//!   u8  record_kind = 0x03
//!   dot purge_dot ‖ u64 purge_hlc          the recorded purge
//!   u16 c ‖ c × ( device_id ‖ u64 seq )    join of the applied purges' contexts, canonical VV
//!   16  item_key_id                        key_id in the recorded purge's ITEM_OP envelope header
//!   u16 l ‖ l × register                   late registers, l ≤ 4,096
//!
//! register = str(field_key) ‖ u16 m ‖ m × ( dot ‖ u64 hlc ‖ bytes(value) )      1 ≤ m ≤ 256
//! dot      = device_id (16) ‖ u64 seq                                         seq ≥ 1
//! ```
//!
//! Record kind `0x04` is reserved for the M5 `SHARE_SNAPSHOT` data; `0x00` and `0x05`–`0xFF` are
//! invalid. The item VV and item id are the snapshot header's and are not repeated
//! (owner decision 3). Types: [`OpData`] (with its [`Lifecycle`] marker and [`Write`]s),
//! [`SnapshotData`], which is a [`LiveSnapshot`] or a [`Tombstone`], and the shared
//! [`Register`] of [`Entry`] values.
//!
//! # Entry points (ADR 0018 §5 "Shape")
//!
//! - [`parse_op`]`(data)` for `ITEM_OP`, [`parse_snapshot`]`(covered_vv, data)` for
//!   `ITEM_SNAPSHOT`, with `covered_vv` the snapshot header's covered VV. The ADR's
//!   `RecordRef` is split into the two result types; what is frozen is that every rule below
//!   runs, with these inputs, on every path that yields a record: sync, a load from the
//!   local store, and the M4 transfers.
//! - [`encode_op`] and [`encode_snapshot`] for writers, which check the same limits and rules
//!   before encrypting (ADR 0018 §10): each sizes and checks the limits, writes, then parses
//!   its own output with the reader's code, so a writer can never emit what a reader
//!   rejects.
//! - [`canonical_state`], the ADR 0018 §4 state-hash input `u16 item_schema_version ‖ covered
//!   VV ‖ data`, with `data` encoded without the §10 limits so that an oversize state has one
//!   too. It is for tests only (ADR 0018 §4).
//!
//! # What is rejected (ADR 0018 §5)
//!
//! The whole op or snapshot is rejected when, and only when:
//!
//! 1. the record kind is not allowed for the purpose: `0x01` for `ITEM_OP`, `0x02` or `0x03`
//!    for `ITEM_SNAPSHOT`;
//! 2. a count or length exceeds §10, runs past the end, or bytes follow the last element
//!    (a live snapshot with no register, below the `1 ≤ r` of its layout, is filed here too,
//!    as the merge spike's `validate_snapshot` files it; rule 5 would also describe it);
//! 3. a key breaks the §7 grammar ([`FieldKey`]), or the record breaks a §4 order or
//!    uniqueness rule;
//! 4. `lifecycle` is outside `0x01`–`0x03`, or writes come with `Trashed` or `Purge`;
//! 5. a live snapshot does not start with `@lifecycle`, a `@lifecycle` value is not the single
//!    byte `0x01` or `0x02`, `@lifecycle` appears in an op or a tombstone, or a register
//!    (current, history group or late) has m = 0;
//! 6. a dot or an entry of `c` has `seq` 0, or is not covered as §4 requires;
//! 7. a live snapshot has a history group whose key is not the key of one of its current
//!    registers;
//! 8. a tombstone has a late value whose dot `c` covers.
//!
//! The §4 rules checked under 3 and 6: field keys strictly ascending by their raw bytes (a
//! proper prefix first, no duplicates) in op writes, registers, history groups and late
//! registers; dots strictly ascending (`device_id` bytewise, then `seq`) within a register;
//! the entries of `c` canonical (ADR 0012 §3); a dot at most once per key across its register
//! and its history group; every dot, `purge_dot` and every entry of `c` covered by the covered
//! VV.
//!
//! **Nothing else rejects a version-1 record** (ADR 0018 §5), and nothing here normalises one.
//! These parse and are carried verbatim: several current values from one device in one
//! register, one dot with different HLCs under different keys, a `purge_dot` that `c` covers,
//! a late value whose dot is `purge_dot`, and any `item_key_id`. Values are opaque bytes; only
//! `@lifecycle`'s are read (ADR 0018 §5 "Values are not checked here"; the schema layer in
//! `rizzy-core` interprets the rest and never rejects a record, §6).
//!
//! # Limits (ADR 0018 §10)
//!
//! | Limit | Value | Constant |
//! |---|---|---|
//! | One value, type byte included | ≤ 65,536 bytes | [`MAX_VALUE_LEN`] |
//! | Field key | 1–160 bytes | [`MAX_KEY_LEN`] |
//! | Writes per op | ≤ 1,024 | [`MAX_WRITES`] |
//! | Op data, checked before decoding | ≤ 1 MiB | [`MAX_OP_DATA_LEN`] |
//! | Registers, history groups, late registers, each per snapshot | ≤ 4,096 | [`MAX_GROUPS`] |
//! | Values per register, history group or late register | ≤ 256 | [`MAX_VALUES`] |
//! | Snapshot data, checked before decoding | ≤ 12 MiB | [`MAX_SNAPSHOT_DATA_LEN`] |
//!
//! The parser never panics. Before it allocates for a count it checks the count against its
//! limit, then that the count times the smallest encoding of the element fits the remaining
//! input (CRYPTO.md §9.5 rule 5, ADR 0018 §5 "Shape"): 8 bytes per write (two empty lengths),
//! 6 per register (an empty key and `u16 m`) and 36 per entry (a dot, an HLC and an empty
//! value). The smallest encoding, not the smallest valid element, so that a count is refused
//! as running past the end only when it does, and an element that breaks another rule is
//! refused by that rule.
//!
//! # Secrets (ADR 0018 §2)
//!
//! Field keys and values are item content; a tag name is part of its key. The parser borrows
//! from the caller's decrypted buffer (the `SecretBytes` an envelope opens into, a
//! `Zeroizing<Vec<u8>>` inside), so it copies no key or value; the encoders write into a buffer
//! allocated once at its final size and return it as zeroizing
//! [`SecretBytes`](rizzy_core::secret::SecretBytes). [`FieldKey`] and [`Value`] print
//! `[REDACTED]` from `Debug`, reach their bytes only through `expose_secret()`, and a
//! [`RecordError`] carries only a kind and a byte offset: local diagnostics outside the frozen
//! format, which the normative vectors do not assert (ADR 0018 §12). An op's [`Lifecycle`]
//! marker is item content too (lifecycle is encrypted, ADR 0012 §5, and in a snapshot the same
//! fact is a `@lifecycle` value), so it also prints `[REDACTED]`. Dots, HLCs, `c` and
//! `item_key_id` are metadata the server also sees in headers and envelopes, and `Debug`
//! prints them.
//!
//! # Frozen
//!
//! These layouts, rules and limits are frozen with the version-1 vectors; any change is a new
//! `item_schema_version` (ADR 0018 §5 "Frozen rules", §11).

mod encode;
mod key;
mod parse;

use core::fmt;

use rizzy_core::ids::SymmetricKeyId;

use crate::dot::Dot;
use crate::hlc::Hlc;
use crate::vv::VersionVector;

pub use encode::{canonical_state, encode_op, encode_snapshot};
pub use parse::{parse_op, parse_snapshot};

/// Largest value, type byte included: 64 KiB (ADR 0018 §10).
pub const MAX_VALUE_LEN: usize = 65_536;

/// Largest field key in bytes (ADR 0018 §10); the smallest is 1.
pub const MAX_KEY_LEN: usize = 160;

/// Most field writes in one op (ADR 0018 §10).
pub const MAX_WRITES: usize = 1_024;

/// Largest op data: 1 MiB, checked before decoding (ADR 0018 §10).
pub const MAX_OP_DATA_LEN: usize = 1 << 20;

/// Most registers, history groups and late registers in one snapshot, each counted
/// separately (ADR 0018 §10).
pub const MAX_GROUPS: usize = 4_096;

/// Most values in one register, history group or late register (ADR 0018 §10).
pub const MAX_VALUES: usize = 256;

/// Largest snapshot data: 12 MiB, so the Padmé-padded plaintext stays under CRYPTO.md §9.1's
/// 16 MiB (ADR 0018 §10). Checked before decoding.
pub const MAX_SNAPSHOT_DATA_LEN: usize = 12 << 20;

/// The reserved key of the lifecycle register (ADR 0018 §3 "Lifecycle"). It is outside the §7
/// grammar and used by the record layer only; `@` sorts before every grammar key, so it is the
/// first register of a live snapshot.
pub const LIFECYCLE_KEY: &str = "@lifecycle";

/// `record_kind` (ADR 0018 §3 "Record kinds").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecordKind {
    /// `0x01`: op data, the only kind an `ITEM_OP` envelope carries.
    Op = 0x01,
    /// `0x02`: live snapshot data.
    LiveSnapshot = 0x02,
    /// `0x03`: tombstone data.
    Tombstone = 0x03,
}

impl RecordKind {
    /// `0x04`, reserved for the M5 `SHARE_SNAPSHOT` data, so that a share never parses as an
    /// item record. Invalid for both item purposes.
    pub const RESERVED_SHARE_SNAPSHOT: u8 = 0x04;

    /// The kind's byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// The `lifecycle` byte of op data (ADR 0018 §3 "Op (a)").
///
/// Create and edit ops carry their writes and `Active`, since every field edit writes `Active`
/// (ADR 0012 §5); trash is `Trashed`, restore `Active` and purge `Purge`, each with no writes.
/// The marker is applied as a write to `@lifecycle`, whose snapshot values are `Active` and
/// `Trashed` only: `Purge` is never a register value; it produces a tombstone.
///
/// The marker is item content: lifecycle is encrypted so that the server cannot see which
/// items are trashed (ADR 0012 §5), and the same fact in a snapshot is a `@lifecycle`
/// [`Value`]. So `Debug` prints `Lifecycle([REDACTED])`, and [`OpData`]'s `Debug` with it;
/// match on the variant, or use [`Lifecycle::to_u8`], where code needs it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Lifecycle {
    /// `0x01`: the item is live.
    Active = 0x01,
    /// `0x02`: the item is in the trash.
    Trashed = 0x02,
    /// `0x03`: the item is purged (op data only).
    Purge = 0x03,
}

impl Lifecycle {
    /// The byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// The marker for `byte`, `None` outside `0x01`–`0x03` (ADR 0018 §5 rule 4).
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Active),
            0x02 => Some(Self::Trashed),
            0x03 => Some(Self::Purge),
            _ => None,
        }
    }

    /// The `@lifecycle` register value this marker writes: the single byte `0x01` or `0x02`.
    /// `None` for `Purge`, which is never a register value.
    #[must_use]
    pub const fn register_value(self) -> Option<Value<'static>> {
        match self {
            Self::Active => Some(Value(&[0x01])),
            Self::Trashed => Some(Value(&[0x02])),
            Self::Purge => None,
        }
    }

    /// Reads an `@lifecycle` register value: `Active` or `Trashed` for the single byte `0x01`
    /// or `0x02`, `None` for anything else (which ADR 0018 §5 rule 5 rejects in a snapshot).
    #[must_use]
    pub fn from_register_value(value: Value<'_>) -> Option<Self> {
        match value.0 {
            [0x01] => Some(Self::Active),
            [0x02] => Some(Self::Trashed),
            _ => None,
        }
    }
}

impl fmt::Debug for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lifecycle([REDACTED])")
    }
}

/// A field key: 1–160 bytes of the ADR 0018 §7 grammar, or the reserved [`LIFECYCLE_KEY`].
///
/// Keys are user content (a tag's name is in its key), so `Debug` prints `[REDACTED]` and the
/// text is reached only through [`FieldKey::expose_secret`]. `Ord` is the canonical key order
/// of ADR 0018 §4: the raw bytes compared lexicographically, a proper prefix first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldKey<'a>(&'a str);

impl<'a> FieldKey<'a> {
    /// The reserved `@lifecycle` key.
    pub const LIFECYCLE: FieldKey<'static> = FieldKey(LIFECYCLE_KEY);

    /// A key a writer or the schema layer names: `key` must be 1–160 bytes and match the
    /// ADR 0018 §7 grammar. `@lifecycle` is not accepted here; use [`FieldKey::LIFECYCLE`].
    ///
    /// # Errors
    /// [`RecordErrorKind::KeyLength`] at offset 0 for an empty or over-long key, and
    /// [`RecordErrorKind::KeyGrammar`] at the offset of the first byte the grammar refuses.
    pub fn new(key: &'a str) -> Result<Self, RecordError> {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(RecordError::new(RecordErrorKind::KeyLength, 0));
        }
        match key::grammar_error(key.as_bytes()) {
            None => Ok(Self(key)),
            Some(at) => Err(RecordError::new(RecordErrorKind::KeyGrammar, at)),
        }
    }

    /// The key's text. Item content: do not log, format or copy it into a plain buffer.
    #[must_use]
    pub const fn expose_secret(&self) -> &'a str {
        self.0
    }

    /// Whether this is the reserved `@lifecycle` key.
    #[must_use]
    pub fn is_lifecycle(&self) -> bool {
        self.0 == LIFECYCLE_KEY
    }

    /// Length of the key in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: a key has at least one byte. Present for `len`'s sake.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for FieldKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldKey([REDACTED])")
    }
}

/// A field value: opaque bytes, empty for the Cleared value (ADR 0018 §6).
///
/// The record layer never reads a value other than `@lifecycle`'s. Values are item content,
/// so `Debug` prints `[REDACTED]` and the bytes are reached only through
/// [`Value::expose_secret`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Value<'a>(&'a [u8]);

impl<'a> Value<'a> {
    /// The Cleared value: zero bytes (ADR 0018 §6).
    pub const CLEARED: Value<'static> = Value(&[]);

    /// Wraps value bytes. Their length is checked against [`MAX_VALUE_LEN`] when the record is
    /// encoded or parsed.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The value's bytes. Item content: do not log, format or copy them into a plain buffer.
    #[must_use]
    pub const fn expose_secret(&self) -> &'a [u8] {
        self.0
    }

    /// Length in bytes. Not treated as secret: the envelope reveals the padded size anyway.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the Cleared value, the only empty one (ADR 0018 §6).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value([REDACTED])")
    }
}

/// One field write of an op: `str(field_key) ‖ bytes(value)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Write<'a> {
    /// The field written. Never `@lifecycle`: the op's [`Lifecycle`] marker writes that.
    key: FieldKey<'a>,
    /// The value written.
    value: Value<'a>,
}

impl<'a> Write<'a> {
    /// A write of `value` to `key`.
    #[must_use]
    pub const fn new(key: FieldKey<'a>, value: Value<'a>) -> Self {
        Self { key, value }
    }

    /// The field written.
    #[must_use]
    pub const fn key(&self) -> FieldKey<'a> {
        self.key
    }

    /// The value written.
    #[must_use]
    pub const fn value(&self) -> Value<'a> {
        self.value
    }
}

/// The `data` of an `ITEM_OP` envelope (ADR 0018 §3 "op data"). The dot, HLC and causal
/// context are the op header's and are not repeated.
///
/// A parsed `OpData` has passed every ADR 0018 §5 rule. One built with [`OpData::new`] is
/// checked when it is encoded.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpData<'a> {
    /// The lifecycle marker.
    lifecycle: Lifecycle,
    /// The field writes, strictly ascending by key; empty unless `lifecycle` is `Active`.
    writes: Vec<Write<'a>>,
}

impl<'a> OpData<'a> {
    /// Op data with `lifecycle` and `writes`, which must be strictly ascending by key.
    #[must_use]
    pub const fn new(lifecycle: Lifecycle, writes: Vec<Write<'a>>) -> Self {
        Self { lifecycle, writes }
    }

    /// The lifecycle marker.
    #[must_use]
    pub const fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }

    /// The field writes, strictly ascending by key.
    #[must_use]
    pub fn writes(&self) -> &[Write<'a>] {
        &self.writes
    }
}

/// One register value, history entry or late value: `dot ‖ u64 hlc ‖ bytes(value)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Entry<'a> {
    /// The dot of the op that wrote the value.
    dot: Dot,
    /// That op's HLC.
    hlc: Hlc,
    /// The value.
    value: Value<'a>,
}

impl<'a> Entry<'a> {
    /// The value `value`, written by the op with `dot` and `hlc`.
    #[must_use]
    pub const fn new(dot: Dot, hlc: Hlc, value: Value<'a>) -> Self {
        Self { dot, hlc, value }
    }

    /// The dot of the op that wrote the value.
    #[must_use]
    pub const fn dot(&self) -> Dot {
        self.dot
    }

    /// That op's HLC.
    #[must_use]
    pub const fn hlc(&self) -> Hlc {
        self.hlc
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> Value<'a> {
        self.value
    }
}

/// A `register` production (ADR 0018 §3): a key and 1–256 entries strictly ascending by dot.
///
/// The same layout serves a current register, a history group (whose entries are history
/// entries) and a tombstone's late register.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Register<'a> {
    /// The field.
    key: FieldKey<'a>,
    /// The entries, strictly ascending by dot.
    entries: Vec<Entry<'a>>,
}

impl<'a> Register<'a> {
    /// A register of `key` holding `entries`, which must be strictly ascending by dot.
    #[must_use]
    pub const fn new(key: FieldKey<'a>, entries: Vec<Entry<'a>>) -> Self {
        Self { key, entries }
    }

    /// The field.
    #[must_use]
    pub const fn key(&self) -> FieldKey<'a> {
        self.key
    }

    /// The entries, strictly ascending by dot.
    #[must_use]
    pub fn entries(&self) -> &[Entry<'a>] {
        &self.entries
    }
}

/// The `data` of a live item's `ITEM_SNAPSHOT` envelope (ADR 0018 §3 "live snapshot data").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LiveSnapshot<'a> {
    /// The current registers, strictly ascending by key, `@lifecycle` first.
    registers: Vec<Register<'a>>,
    /// The history groups, strictly ascending by key, each the key of a current register.
    history: Vec<Register<'a>>,
}

impl<'a> LiveSnapshot<'a> {
    /// A live snapshot of `registers` (strictly ascending by key, `@lifecycle` first) and
    /// `history` groups (strictly ascending by key).
    #[must_use]
    pub const fn new(registers: Vec<Register<'a>>, history: Vec<Register<'a>>) -> Self {
        Self { registers, history }
    }

    /// The current registers, `@lifecycle` first. A register is never dropped, even when it
    /// holds only a Cleared value (ADR 0018 §4).
    #[must_use]
    pub fn registers(&self) -> &[Register<'a>] {
        &self.registers
    }

    /// The history groups: every value removed from a register, with its dot and HLC
    /// (ADR 0018 §3 "History").
    #[must_use]
    pub fn history(&self) -> &[Register<'a>] {
        &self.history
    }
}

/// The `data` of a purged item's `ITEM_SNAPSHOT` envelope (ADR 0018 §3 "Tombstone (c)").
///
/// It holds no value or history of the purged item, only late values. The item id is the
/// snapshot header's. With no late register its encoding is 53 + 24·c bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tombstone<'a> {
    /// The recorded purge's dot: of all applied purges, the one with the highest
    /// `(hlc, device_id, seq)`.
    purge_dot: Dot,
    /// The recorded purge's HLC.
    purge_hlc: Hlc,
    /// `c`: the canonical join of the causal contexts of all applied purges.
    context: VersionVector,
    /// The `key_id` in the recorded purge's `ITEM_OP` envelope header.
    item_key_id: SymmetricKeyId,
    /// The late registers, strictly ascending by key, never `@lifecycle`.
    late: Vec<Register<'a>>,
}

impl<'a> Tombstone<'a> {
    /// A tombstone recording the purge `purge_dot` at `purge_hlc` under `item_key_id`, with the
    /// joined purge context `context` and the `late` registers (strictly ascending by key).
    #[must_use]
    pub const fn new(
        purge_dot: Dot,
        purge_hlc: Hlc,
        context: VersionVector,
        item_key_id: SymmetricKeyId,
        late: Vec<Register<'a>>,
    ) -> Self {
        Self {
            purge_dot,
            purge_hlc,
            context,
            item_key_id,
            late,
        }
    }

    /// The recorded purge's dot.
    #[must_use]
    pub const fn purge_dot(&self) -> Dot {
        self.purge_dot
    }

    /// The recorded purge's HLC.
    #[must_use]
    pub const fn purge_hlc(&self) -> Hlc {
        self.purge_hlc
    }

    /// `c`, the join of the applied purges' causal contexts.
    #[must_use]
    pub const fn context(&self) -> &VersionVector {
        &self.context
    }

    /// The `key_id` of the recorded purge's envelope header.
    #[must_use]
    pub const fn item_key_id(&self) -> SymmetricKeyId {
        self.item_key_id
    }

    /// The late registers: the current values that `c` does not cover, from every applied op
    /// other than a purge (ADR 0018 §3 "Late values").
    #[must_use]
    pub fn late(&self) -> &[Register<'a>] {
        &self.late
    }
}

/// The `data` of an `ITEM_SNAPSHOT` envelope: a live item or a tombstone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SnapshotData<'a> {
    /// Record kind `0x02`.
    Live(LiveSnapshot<'a>),
    /// Record kind `0x03`.
    Tombstone(Tombstone<'a>),
}

impl SnapshotData<'_> {
    /// The record kind.
    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        match self {
            Self::Live(_) => RecordKind::LiveSnapshot,
            Self::Tombstone(_) => RecordKind::Tombstone,
        }
    }
}

/// Why a record was rejected, with the ADR 0018 §5 rule it breaks ([`RecordErrorKind::rule`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordErrorKind {
    /// Rule 1: the record kind is not allowed for the purpose.
    WrongKind,
    /// Rule 2: the data is longer than [`MAX_OP_DATA_LEN`] or [`MAX_SNAPSHOT_DATA_LEN`].
    DataTooLong,
    /// Rule 2: the input ended inside a field, or a count claims more elements than the
    /// remaining input can hold.
    Truncated,
    /// Rule 2: bytes follow the last element.
    TrailingBytes,
    /// Rule 2: a count exceeds its limit: writes, registers, history groups, late registers
    /// or values per register (or, when encoding, its `u16`).
    CountTooLarge,
    /// Rule 2: a live snapshot has no current register, below the `1 ≤ r` of its §3 layout.
    /// Rule 5 ("does not start with `@lifecycle`") also describes it; the merge spike's
    /// `validate_snapshot` files it under rule 2, and so does this crate.
    NoRegister,
    /// Rule 2: a value is longer than [`MAX_VALUE_LEN`] (or, when encoding, its `u32`).
    ValueTooLong,
    /// Rule 2: a key is empty or longer than [`MAX_KEY_LEN`].
    KeyLength,
    /// Rule 3: a key breaks the §7 grammar.
    KeyGrammar,
    /// Rule 3: keys, dots or entries of `c` are not strictly ascending.
    NotAscending,
    /// Rule 3: a dot appears twice under one key, in its register and its history group.
    DuplicateDot,
    /// Rule 4: `lifecycle` is outside `0x01`–`0x03`.
    InvalidLifecycle,
    /// Rule 4: writes come with `Trashed` or `Purge`.
    WritesWithoutActive,
    /// Rule 5: a live snapshot does not start with `@lifecycle`.
    MissingLifecycle,
    /// Rule 5: a `@lifecycle` value is not the single byte `0x01` or `0x02`.
    InvalidLifecycleValue,
    /// Rule 5: `@lifecycle` appears in an op or a tombstone.
    MisplacedLifecycle,
    /// Rule 5: a register, history group or late register has no value (m = 0).
    EmptyRegister,
    /// Rule 6: a dot or an entry of `c` has `seq` 0.
    ZeroSeq,
    /// Rule 6: a dot or an entry of `c` is not covered by the covered VV.
    NotCovered,
    /// Rule 7: a history group's key is not the key of a current register.
    OrphanHistory,
    /// Rule 8: a late value's dot is covered by `c`.
    LateValueCovered,
}

impl RecordErrorKind {
    /// The ADR 0018 §5 rejection rule, 1–8, that this kind belongs to.
    #[must_use]
    pub const fn rule(self) -> u8 {
        match self {
            Self::WrongKind => 1,
            Self::DataTooLong
            | Self::Truncated
            | Self::TrailingBytes
            | Self::CountTooLarge
            | Self::NoRegister
            | Self::ValueTooLong
            | Self::KeyLength => 2,
            Self::KeyGrammar | Self::NotAscending | Self::DuplicateDot => 3,
            Self::InvalidLifecycle | Self::WritesWithoutActive => 4,
            Self::MissingLifecycle
            | Self::InvalidLifecycleValue
            | Self::MisplacedLifecycle
            | Self::EmptyRegister => 5,
            Self::ZeroSeq | Self::NotCovered => 6,
            Self::OrphanHistory => 7,
            Self::LateValueCovered => 8,
        }
    }
}

impl fmt::Display for RecordErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongKind => "record kind not allowed for the purpose",
            Self::DataTooLong => "record data too long",
            Self::Truncated => "record truncated",
            Self::TrailingBytes => "trailing bytes after the record",
            Self::CountTooLarge => "count over its limit",
            Self::NoRegister => "live snapshot with no register",
            Self::ValueTooLong => "value too long",
            Self::KeyLength => "field key length out of range",
            Self::KeyGrammar => "field key breaks the grammar",
            Self::NotAscending => "elements not strictly ascending",
            Self::DuplicateDot => "dot repeated under one field key",
            Self::InvalidLifecycle => "invalid lifecycle byte",
            Self::WritesWithoutActive => "writes with a Trashed or Purge marker",
            Self::MissingLifecycle => "live snapshot does not start with the lifecycle register",
            Self::InvalidLifecycleValue => "invalid lifecycle value",
            Self::MisplacedLifecycle => "lifecycle key in an op or a tombstone",
            Self::EmptyRegister => "register with no value",
            Self::ZeroSeq => "sequence number 0",
            Self::NotCovered => "dot not covered by the covered version vector",
            Self::OrphanHistory => "history group without a current register",
            Self::LateValueCovered => "late value covered by the purge context",
        })
    }
}

/// A rejected record: the kind of failure and the byte offset, within `data`, of the field
/// that failed. Never a key or a value (ADR 0018 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordError {
    /// What was wrong.
    kind: RecordErrorKind,
    /// Where the failing field starts.
    offset: usize,
}

impl RecordError {
    /// An error of `kind` at `offset`.
    const fn new(kind: RecordErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// What was wrong.
    #[must_use]
    pub const fn kind(&self) -> RecordErrorKind {
        self.kind
    }

    /// The byte offset of the failing field within `data` (within the key, for
    /// [`FieldKey::new`]).
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl From<crate::error::DecodeError> for RecordError {
    /// The same failure of a dot, HLC or version-vector read, as a record error.
    fn from(e: crate::error::DecodeError) -> Self {
        use crate::error::DecodeErrorKind as D;
        let kind = match e.kind() {
            D::Truncated => RecordErrorKind::Truncated,
            D::TrailingBytes => RecordErrorKind::TrailingBytes,
            D::ZeroSeq => RecordErrorKind::ZeroSeq,
            D::NotAscending => RecordErrorKind::NotAscending,
        };
        Self::new(kind, e.offset())
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

impl core::error::Error for RecordError {}

/// The limits a parse or an encoding runs under: ADR 0018 §10's, or none but the `u16` counts
/// and `u32` lengths of the layout, for [`canonical_state`].
///
/// The key length is not here: every [`FieldKey`] is 1–160 bytes whichever limits apply,
/// since keys come only from parsed records and from [`FieldKey::new`].
#[derive(Clone, Copy, Debug)]
struct Limits {
    /// Largest op data.
    op_data: usize,
    /// Largest snapshot data.
    snapshot_data: usize,
    /// Largest value.
    value: usize,
    /// Most writes per op.
    writes: usize,
    /// Most registers, history groups and late registers, each.
    groups: usize,
    /// Most values per register.
    values: usize,
}

impl Limits {
    /// The frozen version-1 limits (ADR 0018 §10).
    const V1: Self = Self {
        op_data: MAX_OP_DATA_LEN,
        snapshot_data: MAX_SNAPSHOT_DATA_LEN,
        value: MAX_VALUE_LEN,
        writes: MAX_WRITES,
        groups: MAX_GROUPS,
        values: MAX_VALUES,
    };

    /// No §10 limit: only what the `u16` counts and `u32` lengths can express.
    fn unbounded() -> Self {
        let count = usize::from(u16::MAX);
        Self {
            op_data: usize::MAX,
            snapshot_data: usize::MAX,
            value: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
            writes: count,
            groups: count,
            values: count,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code edits fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code edits fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod vectors;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes generated fixtures; a panic there fails the test, which CLAUDE.md allows"
)]
mod proptests;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes hex digit pairs; a panic there fails the test, which CLAUDE.md allows"
)]
mod testkit;
