//! The item schema: the schema layer of the item record (ADR 0018 §2, "Two layers").
//!
//! ADR 0018 splits the item record in two. The **record layer** (`rizzy-sync`, module `record`)
//! owns the byte layouts of op, snapshot and tombstone data, their canonical form, their parser
//! and the record limits (ADR 0018 §3–§5, §10), and treats field keys and values as opaque
//! bytes, except for `@lifecycle`. This module is the **schema layer**: what a key means and how
//! a value is read, checked and shown (ADR 0018 §6–§9, §11). It never sees a dot, a version
//! vector or a merge; where a display rule needs the order of two values, the caller passes each
//! value's `(hlc, device_id, seq)` ([`display::Candidate`]).
//!
//! **Flow** (ADR 0018 §2). `rizzy-client` validates a write here ([`schema::check_write`]),
//! encodes it through the record layer and encrypts it through [`crate::envelope`]. On the way
//! back it decrypts, parses through the record layer (which checks every key against the
//! grammar of [`key`], ADR 0018 §5 rule 3) and reads values and display rules from here.
//!
//! # Submodules
//!
//! | Module | ADR 0018 | Holds |
//! |---|---|---|
//! | [`key`] | §7, §10 | The field-key grammar: the no-allocation parser, the owned key builder, random element ids |
//! | [`tag`] | §7, owner decision 7 | Tag keys `tag/<hex>` from tag names (NFC, no Cc, 1–64 bytes) and back |
//! | [`value`] | §6, §10 | Value types, the value decoder and encoder, sort keys |
//! | [`types`] | §8 | Item type ids, the M1 types, reserved and system types, the vault-settings item |
//! | [`schema`] | §7, §8, §11 | The key registry (expected value, types, concealment, who writes it), reserved prefixes, custom-field kinds, the writer checks |
//! | [`display`] | §6 "Display", §9 | Displayed value and conflicts of a field, "Active wins" for the lifecycle, created, modified and trashed times |
//! | [`order`] | §6 "List elements", "List order" | Element existence, list order, sort keys between two neighbours and for a rewrite |
//!
//! # Rules this module keeps
//!
//! - **Invalid values never reject anything** (ADR 0018 §6). The value decoder returns an error
//!   for an unknown type, a malformed payload or an oversize value, and that error means only
//!   "show as unsupported value". The record carrying it is kept, merged and snapshotted
//!   verbatim by the record layer, whatever this module thinks of its values; otherwise replicas
//!   that run different schema versions would diverge.
//! - **Keys and values are user content** (ADR 0018 §2 "Secrets", "Keys are user content too").
//!   A tag name is part of its key, and values hold passwords. Owned keys and values live in
//!   zeroizing buffers allocated at their final size, and no `Debug` output, error or `Display`
//!   text here carries a key or value byte: errors are kinds only (CRYPTO.md §12.2). What is
//!   decoded from a value is redacted in `Debug` too: the item type, the custom-field kind, the
//!   lifecycle and what a field or the lifecycle displays.
//! - **No I/O, no clock, no randomness of its own.** Times come from the HLCs the caller passes
//!   (ADR 0018 §9: "The HLC is the only time source"); element ids come from the injected RNG
//!   ([`key::ElementId::generate`]).
//! - **Forward compatibility** (ADR 0018 §11). A key that fits the grammar but that this client
//!   does not know is [`schema::KeyClass::Unknown`] or [`schema::KeyClass::Reserved`]: the
//!   record layer carries it byte for byte, and nothing here rejects it. The writer checks
//!   never let this client invent a value for it: it is written only as Cleared in an edit,
//!   when its list element is removed (§6), or copied verbatim into a restored or duplicated
//!   item ([`schema::check_carried`]). New value types, enum values, list names, keys and item
//!   types need no version bump.
//! - **Side channels** (CRYPTO.md §12.3). Values are compared with `subtle::ConstantTimeEq`
//!   ([`display::resolve_field`]), and tag names are hex-encoded and decoded with arithmetic, not
//!   a table. Validating UTF-8, NFC-normalising a tag name and checking a key against the grammar
//!   branch on their input, as showing a value in a UI does. CRYPTO.md §12.3 accepts a residual
//!   of this kind for the otpauth label and issuer; it does not list these yet.
//!
//! # Where the ambiguous points are resolved
//!
//! Each is documented at the item that resolves it; none changes a byte the record layer
//! freezes:
//!
//! - an absent or unreadable custom-field `kind` displays as hidden, like an unknown kind
//!   ([`schema::CustomFieldKind::from_displayed`]);
//! - a tag register whose displayed value is non-empty but not Bool `0x01` still makes the tag
//!   exist (§6 "List elements" is about emptiness), and the value shows as unsupported
//!   ([`schema::Expected::TagMarker`]);
//! - a `tag/<hex>` key whose hex is not the UTF-8 of an NFC name without Cc is not a tag: it is
//!   [`schema::KeyClass::Unknown`], not shown as a tag ([`tag::tag_name`]) and not written as
//!   one, and it is still carried like any unknown key;
//! - in an edit, Cleared may be written to keys this client does not know, unknown and reserved
//!   alike, since removing a list element clears every attribute of it that the writer holds
//!   (§6); `uri/<id>/match` is still never written, under owner decision 2
//!   ([`schema::check_write`]);
//! - a restore or duplicate as a new item (§3 "Surfacing", §10 "The way out") copies unknown and
//!   reserved keys and unsupported values byte for byte, but not `uri/<id>/match`,
//!   `share/<id>/secret` or `import.created_ms`, which that op may not write
//!   ([`schema::check_carried`]);
//! - an `order` attribute whose displayed value is not a valid `SortKey` sorts as "without order"
//!   ([`order::compare_list_entries`]);
//! - a list element id may have any length the grammar allows; only writers are bound to the
//!   random 16-byte ids of ADR 0018 §7 ([`key::ElementId`]);
//! - "all" in the ADR 0018 §7 table includes the vault-settings type ([`schema::Applies::All`]).

pub mod display;
pub mod key;
pub mod order;
pub mod schema;
pub mod tag;
pub mod types;
pub mod value;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod proptests;
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

/// The `item_schema_version` of the M1 model (ADR 0018 §11, (e)). It is in the `ITEM_OP` and
/// `ITEM_SNAPSHOT` headers and AAD contexts (CRYPTO.md §8.4), and `data` carries no second
/// version number.
pub const ITEM_SCHEMA_VERSION: u16 = 1;

/// What a reader does with an `item_schema_version` (ADR 0018 §11, the registry and the
/// "Reader rule").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemaVersion {
    /// Version 1, the M1 model of ADR 0018: the only version whose data reaches the record
    /// parser.
    Supported,
    /// `0` or `0xFFFF`: invalid or reserved and never assigned. The record is rejected.
    Invalid,
    /// `2`–`0xFFFE`, assigned by a later ADR or not at all. The record is neither applied nor
    /// dropped: the client *parks* it, keeps it unapplied and reports "update required". Causal
    /// delivery then waits for it, a parked record is not part of the item's state and never
    /// raises the persisted version vector, and no Purge is issued for the item while it is
    /// held (ADR 0018 §11, "Parked records", "No purge over an unapplied record").
    Unknown,
}

impl SchemaVersion {
    /// Classifies an `item_schema_version` read from an op or snapshot header.
    #[must_use]
    pub const fn classify(version: u16) -> Self {
        match version {
            ITEM_SCHEMA_VERSION => Self::Supported,
            0 | 0xFFFF => Self::Invalid,
            _ => Self::Unknown,
        }
    }
}

/// The reserved key of the lifecycle register (ADR 0018 §3 "Lifecycle", §7). It is not a
/// [`key`] grammar key (`@` is outside the grammar, and sorts before every grammar key), so
/// [`key::FieldKeyRef::parse`] rejects it; the record layer handles it. Its values are one byte:
/// [`LIFECYCLE_ACTIVE`] or [`LIFECYCLE_TRASHED`].
pub const LIFECYCLE_KEY: &str = "@lifecycle";

/// The `@lifecycle` value, and the op `lifecycle` byte, for Active (ADR 0018 §3). Every field
/// edit writes it (ADR 0012 §5).
pub const LIFECYCLE_ACTIVE: u8 = 0x01;

/// The `@lifecycle` value, and the op `lifecycle` byte, for Trashed (ADR 0018 §3).
pub const LIFECYCLE_TRASHED: u8 = 0x02;
