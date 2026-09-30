//! Item edits and reads through the item schema layer (ADR 0018 §2 "Flow", §3, §6–§9;
//! ADR 0012 §5), and the import path ([ADR 0027] §2 steps 3–5, §6 "Writes").
//!
//! "`rizzy-client` validates a write here ([`check_write`]), encodes it through the record
//! layer and encrypts it through the envelope" (ADR 0018 §2): every write passes the
//! `rizzy-core` schema checks before [`VaultSync`] encodes, seals and signs it. Reads resolve
//! a field's displayed value with the schema layer's display rules, through the merge.
//!
//! | Call | Op written | Allowed when the item displays |
//! |---|---|---|
//! | [`VaultSync::create_item`] | `Active` with `item.type` and the fields | (new item) |
//! | [`VaultSync::import_item`], [`VaultSync::import_item_writes`], [`VaultSync::import_items`] | as create, `WriteMode::Import`; more `Active` ops when one does not hold the writes; `Trashed` last for a trashed item | (new item) |
//! | [`VaultSync::edit_item`] | `Active` with the changed fields | Active |
//! | [`VaultSync::trash_item`] | `Trashed`, no writes | Active |
//! | [`VaultSync::restore_item`] | `Active`, no writes | Trashed |
//! | [`VaultSync::purge_item`] | `Purge`, no writes | Trashed, no unapplied record (writer rules) |
//!
//! # Import
//!
//! `rizzy-import` (ADR 0016 §3) turns an import file into [`ImportedItem`]s;
//! [`VaultSync::import_items`] writes them, and [`VaultSync::import_item_writes`] is the one
//! path every imported item takes, the items of an encrypted export included
//! ([`crate::export::payload`]). Nothing here parses an import format. An imported item is
//! always a **new item**: a new item id and item key, and ops of the importing device only
//! (ADR 0027 §2 step 3: "dots and HLCs of the exporting account are never reused").
//!
//! - **Checks, all before the first op.** The vault is writable; the type is a user item type
//!   this client supports (the vault-settings type is "never imported as an item", ADR 0027
//!   §6); no key twice; every write passes [`check_create`] for [`WriteMode::Import`], as an
//!   entered write ([`check_write`]) or a carried one (`check_carried`), whichever of the
//!   item's ops it lands in (ADR 0027 §6: "Every write passes `check_carried` for
//!   `WriteMode::Import`"); and the item fits what one item's snapshot may hold (ADR 0018
//!   §10: 4,096 registers with `@lifecycle`, 12 MiB of snapshot data), so that no import
//!   creates an item that is oversize from its first op. A refusal is
//!   [`ClientError::InvalidEdit`] and writes nothing.
//! - **Splitting** (ADR 0027 §2 step 5: "If one item's writes exceed an op's ADR 0018 §10
//!   limits, `import_item` splits them into consecutive ops, as §6 'List order' already
//!   allows"). The writes go, in key order, into as few consecutive ops as the limits allow
//!   (1,024 writes and 1 MiB of op data each). `item.type` and `import.created_ms` are always
//!   in the first, the create op: ADR 0018 §7 makes the create op the one that writes
//!   `item.type`, and §9 takes the creation time from it. The later ops are ordinary `Active`
//!   ops of the same device; a list element's attributes may land in two of them, which is
//!   what ADR 0018 §6 "List order" allows for a rewrite.
//! - **Trashed items** (ADR 0027 §2 step 3: "a Trashed item is created, then trashed in a
//!   second op"): one `Trashed` op after the last `Active` one.
//! - **After the first op**, only a failure valid state cannot cause
//!   ([`ClientError::Internal`]) can stop an item half-way; its ops written so far stay, as
//!   any own op does.
//!
//! # Readings
//!
//! - Editing a trashed item is refused ([`ClientError::UnknownItem`]); the user restores it
//!   first. ADR 0012 §5 lets a field edit write `Active`, which would also restore it; the
//!   narrower rule avoids an edit that silently un-trashes.
//! - Values are the encoded bytes of ADR 0018 §6 ([`Value`]); keys are the final keys of the
//!   §7 grammar. Hosts build both with `rizzy_core::item`, re-exported here ([`FieldKey`],
//!   [`Value`], [`ItemType`]) for hosts that link only this crate.
//!
//! [ADR 0027]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0027-export-payload.md

/// The item id [`VaultSync::create_item`] returns, re-exported for hosts (see [`ItemType`]).
pub use rizzy_core::ids::ItemId;
use rizzy_core::item::LIFECYCLE_KEY;
use rizzy_core::item::key::FieldKey as SchemaKey;
/// The field key of [`FieldEdit`], re-exported for hosts (see [`ItemType`]).
pub use rizzy_core::item::key::FieldKey;
/// Where an imported write comes from ([`ImportWrite`]), re-exported for hosts (see
/// [`ItemType`]).
pub use rizzy_core::item::schema::WriteSource;
use rizzy_core::item::schema::{
    IMPORT_CREATED_MS, ITEM_TYPE, WriteMode, check_create, check_write,
};
/// The item type of [`VaultSync::create_item`], re-exported so a host that links only this crate
/// (a binding, or `rizzy-server`'s end-to-end tests, ADR 0016 §4 owner decision 4) can name it.
pub use rizzy_core::item::types::ItemType;
use rizzy_core::item::types::SupportedType;
/// The encoded field value of [`FieldEdit`], re-exported for hosts (see [`ItemType`]).
pub use rizzy_core::item::value::Value;
use rizzy_core::item::value::ValueRef;
use rizzy_core::rng::CryptoRng;
use rizzy_import::ImportedItem;
/// The lifecycle [`VaultSync::item_lifecycle`] returns, re-exported for hosts (see [`ItemType`]).
pub use rizzy_sync::merge::ItemLifecycle;
use rizzy_sync::record::{
    Lifecycle, MAX_GROUPS, MAX_OP_DATA_LEN, MAX_SNAPSHOT_DATA_LEN, MAX_WRITES, SnapshotData,
};
use zeroize::Zeroizing;

use crate::device::UnlockedDevice;
use crate::error::ClientError;
use crate::sync::{OwnChange, VaultSync};

/// One field write: the final key and the encoded value. Both are user content (ADR 0018 §2).
#[derive(Debug)]
pub struct FieldEdit<'a> {
    /// The field key, in the §7 grammar.
    pub key: &'a SchemaKey,
    /// The encoded value; [`Value::cleared`] clears the field in an edit.
    pub value: &'a Value,
}

/// One field write of an imported item: where it comes from, the final key and the encoded
/// value. `Debug` prints neither key nor value (their types redact).
#[derive(Debug)]
pub struct ImportWrite<'a> {
    /// [`WriteSource::Entered`] for a value an importer built (checked as a well-formed value
    /// of the type its key expects), [`WriteSource::Carried`] for a key and value copied byte
    /// for byte from an export of our own (unknown keys and unsupported values included).
    pub source: WriteSource,
    /// The field key, in the §7 grammar.
    pub key: &'a SchemaKey,
    /// The encoded value; never Cleared (a new item writes no blank field, ADR 0018 §6).
    pub value: &'a Value,
}

/// What [`VaultSync::import_items`] did. Item ids and positions only (INV-48).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemsImported {
    /// The new items, in the order of the input.
    pub imported: Vec<ItemId>,
    /// The file positions ([`ImportedItem::entry`]) of the items this vault refused
    /// ([`ClientError::InvalidEdit`]); nothing of them was written.
    pub skipped: Vec<usize>,
}

/// Op data bytes before the writes: `record_kind`, `lifecycle`, `u16 n` (ADR 0018 §3).
const OP_DATA_HEADER_LEN: usize = 4;

/// Op data bytes of one write beyond its key and value: the `str` and `bytes` lengths.
const WRITE_OVERHEAD: usize = 8;

/// Snapshot data bytes of one register of one value beyond its key and value: the `str(key)`
/// length (4), `u16 m` (2), the dot (24), the HLC (8) and the `bytes(value)` length (4)
/// (ADR 0018 §3).
const REGISTER_OVERHEAD: usize = 42;

/// Room kept free in [`MAX_SNAPSHOT_DATA_LEN`] when a new imported item is sized: the
/// `@lifecycle` register, the history the create, split and trash ops leave under it, and the
/// snapshot's counts. (The record kind and two counts are 5 bytes; a `@lifecycle` value is
/// 47 bytes with its register's share, and the merge keeps at most 50 of them as history.)
const SNAPSHOT_MARGIN: usize = 4_096;

/// One write as the own-op writer takes it: the final key and the encoded value.
type RawWrite<'a> = (&'a str, &'a [u8]);

/// Splits the writes of a new item, sorted by key, into consecutive ops within ADR 0018 §10
/// (module docs, "Splitting"): `item.type` and `import.created_ms` first, then the rest in
/// key order, each op filled to its limits. One op at least when there is a write.
fn split_ops<'a>(sorted: &[(WriteSource, &'a str, &'a [u8])]) -> Vec<Vec<RawWrite<'a>>> {
    let first = |key: &str| key == ITEM_TYPE || key == IMPORT_CREATED_MS;
    let ordered = sorted
        .iter()
        .filter(|w| first(w.1))
        .chain(sorted.iter().filter(|w| !first(w.1)));
    let mut ops = Vec::new();
    let mut current: Vec<RawWrite<'a>> = Vec::new();
    let mut bytes = OP_DATA_HEADER_LEN;
    for (_, key, value) in ordered {
        let len = WRITE_OVERHEAD
            .saturating_add(key.len())
            .saturating_add(value.len());
        let full = current.len() >= MAX_WRITES || bytes.saturating_add(len) > MAX_OP_DATA_LEN;
        if full && !current.is_empty() {
            ops.push(core::mem::take(&mut current));
            bytes = OP_DATA_HEADER_LEN;
        }
        current.push((key, value));
        bytes = bytes.saturating_add(len);
    }
    if !current.is_empty() {
        ops.push(current);
    }
    ops
}

/// The checks every imported item passes before its first op (module docs, "Import"), on the
/// writes of the whole item, `item.type` among them: sorts `writes` by key, then refuses a
/// type that is not a supported user item type, a key written twice, a write the schema
/// refuses for an import, and an item larger than one item's snapshot may hold. Pure: it
/// needs no vault, so the preview of an import and its fuzz target run the same checks.
///
/// # Errors
/// [`ClientError::InvalidEdit`].
pub(crate) fn check_import(
    item_type: ItemType,
    writes: &mut [(WriteSource, &str, &[u8])],
) -> Result<(), ClientError> {
    if !item_type
        .supported()
        .is_some_and(SupportedType::is_user_item)
    {
        return Err(ClientError::InvalidEdit);
    }
    writes.sort_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()));
    if writes.windows(2).any(|w| matches!(w, [a, b] if a.1 == b.1)) {
        return Err(ClientError::InvalidEdit);
    }
    check_create(
        item_type,
        WriteMode::Import,
        writes.iter().map(|(s, k, v)| (*s, k.as_bytes(), *v)),
    )
    .map_err(|_| ClientError::InvalidEdit)?;
    // The item must fit one item's snapshot, `@lifecycle` being one of its registers.
    let snapshot_len = writes.iter().fold(SNAPSHOT_MARGIN, |sum, (_, k, v)| {
        sum.saturating_add(REGISTER_OVERHEAD)
            .saturating_add(k.len())
            .saturating_add(v.len())
    });
    if writes.len() >= MAX_GROUPS || snapshot_len > MAX_SNAPSHOT_DATA_LEN {
        return Err(ClientError::InvalidEdit);
    }
    Ok(())
}

impl VaultSync {
    /// Creates a new item of `item_type` with `fields` (ADR 0018 §7: the create op writes
    /// `item.type`). Returns the new item's id.
    ///
    /// # Errors
    /// [`ClientError::InvalidEdit`] for a write the schema refuses; the errors of the own-op
    /// writer ([`ClientError::ReadOnly`] among them).
    pub fn create_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item_type: ItemType,
        fields: &[FieldEdit<'_>],
        now_ms: u64,
    ) -> Result<ItemId, ClientError> {
        let type_value = Value::enumeration(item_type.id());
        let mut writes: Vec<(&str, &[u8])> = Vec::with_capacity(fields.len() + 1);
        writes.push((ITEM_TYPE, type_value.expose_secret()));
        for f in fields {
            writes.push((f.key.as_str(), f.value.expose_secret()));
        }
        check_create(
            item_type,
            WriteMode::Create,
            writes
                .iter()
                .map(|(k, v)| (WriteSource::Entered, k.as_bytes(), *v)),
        )
        .map_err(|_| ClientError::InvalidEdit)?;
        let item = ItemId::generate(rng);
        self.write_op(
            rng,
            unlocked,
            item,
            &OwnChange {
                lifecycle: Lifecycle::Active,
                writes: &writes,
            },
            now_ms,
        )?;
        Ok(item)
    }

    /// Creates a new item from an importer's entered writes (see the module docs, "Import").
    /// As [`VaultSync::import_item_writes`] with every field [`WriteSource::Entered`] and the
    /// item not trashed; `fields` do not hold `item.type`, which is written for `item_type`.
    ///
    /// # Errors
    /// As [`VaultSync::import_item_writes`].
    pub fn import_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item_type: ItemType,
        fields: &[FieldEdit<'_>],
        now_ms: u64,
    ) -> Result<ItemId, ClientError> {
        let writes: Vec<ImportWrite<'_>> = fields
            .iter()
            .map(|f| ImportWrite {
                source: WriteSource::Entered,
                key: f.key,
                value: f.value,
            })
            .collect();
        self.import_item_writes(rng, unlocked, item_type, &writes, false, now_ms)
    }

    /// Creates a new item from imported writes: the one import path (module docs, "Import").
    /// `writes` may hold `item.type`, which must then name `item_type`; if they do not, it is
    /// written. The writes are split over consecutive ops when one op does not hold them, and
    /// a `trashed` item is trashed in one more op. Returns the new item's id.
    ///
    /// # Errors
    /// Before anything is written: [`ClientError::ReadOnly`]; [`ClientError::InvalidInput`] if
    /// `unlocked` is another device's; [`ClientError::InvalidEdit`] for a type that is not a
    /// supported user item type, a key written twice, a write the schema refuses for an
    /// import, or an item larger than one item's snapshot may hold; the other errors of the
    /// own-op writer for the create op. After the create op only [`ClientError::Internal`].
    pub fn import_item_writes<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item_type: ItemType,
        writes: &[ImportWrite<'_>],
        trashed: bool,
        now_ms: u64,
    ) -> Result<ItemId, ClientError> {
        self.check_writable(unlocked)?;
        let type_value = Value::enumeration(item_type.id());
        let mut all: Vec<(WriteSource, &str, &[u8])> = writes
            .iter()
            .map(|w| (w.source, w.key.as_str(), w.value.expose_secret()))
            .collect();
        if !all.iter().any(|w| w.1 == ITEM_TYPE) {
            all.push((WriteSource::Entered, ITEM_TYPE, type_value.expose_secret()));
        }
        check_import(item_type, &mut all)?;
        let item = ItemId::generate(rng);
        for (index, op) in split_ops(&all).iter().enumerate() {
            self.write_op(
                rng,
                unlocked,
                item,
                &OwnChange {
                    lifecycle: Lifecycle::Active,
                    writes: op,
                },
                now_ms,
            )
            // The create op's refusal leaves nothing behind and is reported as it is; a later
            // op cannot be refused for a reason the checks above did not cover.
            .map_err(|e| if index == 0 { e } else { ClientError::Internal })?;
        }
        if trashed {
            self.write_op(
                rng,
                unlocked,
                item,
                &OwnChange {
                    lifecycle: Lifecycle::Trashed,
                    writes: &[],
                },
                now_ms,
            )
            .map_err(|_| ClientError::Internal)?;
        }
        Ok(item)
    }

    /// Writes the items of an import file (`rizzy_import::import`) into this vault, each as a
    /// new item through [`VaultSync::import_item_writes`]: split over ops where needed, and
    /// trashed where the file says so. An item this vault refuses is skipped and reported by
    /// its position; the others are imported (ADR 0027 §2 step 4: "Per-item refusals do not
    /// refuse the file").
    ///
    /// # Errors
    /// [`ClientError::ReadOnly`] or [`ClientError::InvalidInput`] before anything is written;
    /// [`ClientError::Internal`], after which the items written so far stay.
    pub fn import_items<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        items: &[ImportedItem],
        now_ms: u64,
    ) -> Result<ItemsImported, ClientError> {
        self.check_writable(unlocked)?;
        let mut out = ItemsImported::default();
        for item in items {
            let writes: Vec<ImportWrite<'_>> = item
                .writes()
                .iter()
                .map(|w| ImportWrite {
                    source: item.source(),
                    key: w.key(),
                    value: w.value(),
                })
                .collect();
            match self.import_item_writes(
                rng,
                unlocked,
                item.item_type(),
                &writes,
                item.trashed(),
                now_ms,
            ) {
                Ok(id) => out.imported.push(id),
                Err(ClientError::InvalidEdit) => out.skipped.push(item.entry()),
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Edits the fields of an active item (ADR 0018 §6: a cleared field is written as
    /// [`Value::cleared`]).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item is not active; [`ClientError::InvalidEdit`] for
    /// no field, an item type this client does not support, or a write the schema refuses;
    /// the errors of the own-op writer.
    pub fn edit_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        fields: &[FieldEdit<'_>],
        now_ms: u64,
    ) -> Result<(), ClientError> {
        if self.item_lifecycle(item) != ItemLifecycle::Active {
            return Err(ClientError::UnknownItem);
        }
        if fields.is_empty() {
            return Err(ClientError::InvalidEdit);
        }
        let item_type = self.item_type(item).ok_or(ClientError::InvalidEdit)?;
        let mut writes: Vec<(&str, &[u8])> = Vec::with_capacity(fields.len());
        for f in fields {
            check_write(
                item_type,
                WriteMode::Edit,
                f.key.as_bytes(),
                f.value.expose_secret(),
            )
            .map_err(|_| ClientError::InvalidEdit)?;
            writes.push((f.key.as_str(), f.value.expose_secret()));
        }
        self.write_op(
            rng,
            unlocked,
            item,
            &OwnChange {
                lifecycle: Lifecycle::Active,
                writes: &writes,
            },
            now_ms,
        )
        .map(|_| ())
    }

    /// Moves an active item to the trash (ADR 0012 §5).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item is not active; the errors of the own-op writer.
    pub fn trash_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        self.lifecycle_op(
            rng,
            unlocked,
            item,
            ItemLifecycle::Active,
            Lifecycle::Trashed,
            now_ms,
        )
    }

    /// Restores a trashed item (ADR 0012 §5).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item is not trashed; the errors of the own-op
    /// writer.
    pub fn restore_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        self.lifecycle_op(
            rng,
            unlocked,
            item,
            ItemLifecycle::Trashed,
            Lifecycle::Active,
            now_ms,
        )
    }

    /// Purges a trashed item for good (ADR 0012 §5, ADR 0018 §3): allowed only while it
    /// displays Trashed and no record of it waits unapplied (ADR 0018 §11).
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item is not trashed; [`ClientError::InvalidEdit`]
    /// when the writer rules refuse; the errors of the own-op writer.
    pub fn purge_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        self.lifecycle_op(
            rng,
            unlocked,
            item,
            ItemLifecycle::Trashed,
            Lifecycle::Purge,
            now_ms,
        )
    }

    /// An op with no field writes, when the item displays `from`.
    fn lifecycle_op<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        from: ItemLifecycle,
        lifecycle: Lifecycle,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        if self.item_lifecycle(item) != from {
            return Err(ClientError::UnknownItem);
        }
        self.write_op(
            rng,
            unlocked,
            item,
            &OwnChange {
                lifecycle,
                writes: &[],
            },
            now_ms,
        )
        .map(|_| ())
    }

    /// What the item is: absent, active, trashed or purged.
    #[must_use]
    pub fn item_lifecycle(&self, item: ItemId) -> ItemLifecycle {
        self.merge(item).map_or(
            ItemLifecycle::Absent,
            rizzy_sync::merge::ItemMerge::lifecycle,
        )
    }

    /// The item's type, from its displayed `item.type` (ADR 0018 §7, §8). `None` for an item
    /// without a valid type.
    #[must_use]
    pub fn item_type(&self, item: ItemId) -> Option<ItemType> {
        let value = self.field_value(item, ITEM_TYPE)?;
        ItemType::from_displayed(ValueRef::decode(value.expose_secret()).ok())
    }

    /// The displayed value of one field (ADR 0018 §6 "Display"), as encoded bytes in a
    /// zeroizing buffer. `None` when the item has no such register. A secret: reveal it only on
    /// the user's request (ADR 0013 §3 rule 3).
    #[must_use]
    pub fn field_value(&self, item: ItemId, key: &str) -> Option<Value> {
        let view = self.merge(item)?.field(key)?;
        let shown = view.current.get(view.display?.displayed)?;
        Value::copy_from_encoded(shown.value().expose_secret()).ok()
    }

    /// Whether the field's current values conflict (ADR 0018 §6: "keep both / pick one").
    #[must_use]
    pub fn field_conflicts(&self, item: ItemId, key: &str) -> bool {
        self.merge(item)
            .and_then(|m| m.field(key))
            .and_then(|v| v.display)
            .is_some_and(|d| d.conflict)
    }

    /// The keys of the item's current registers, `@lifecycle` left out. Keys are user content
    /// (a tag name is part of its key), so they come in zeroizing buffers.
    #[must_use]
    pub fn field_keys(&self, item: ItemId) -> Vec<Zeroizing<String>> {
        let Some(Ok(Some(SnapshotData::Live(live)))) = self
            .merge(item)
            .map(rizzy_sync::merge::ItemMerge::snapshot_data)
        else {
            return Vec::new();
        };
        live.registers()
            .iter()
            .map(|r| r.key().expose_secret())
            .filter(|k| *k != LIFECYCLE_KEY)
            .map(|k| Zeroizing::new(k.to_owned()))
            .collect()
    }
}
