//! Item edits and reads through the item schema layer (ADR 0018 §2 "Flow", §3, §6–§9;
//! ADR 0012 §5).
//!
//! "`rizzy-client` validates a write here ([`check_write`]), encodes it through the record
//! layer and encrypts it through the envelope" (ADR 0018 §2): every write passes the
//! `rizzy-core` schema checks before [`VaultSync`] encodes, seals and signs it. Reads resolve
//! a field's displayed value with the schema layer's display rules, through the merge.
//!
//! | Call | Op written | Allowed when the item displays |
//! |---|---|---|
//! | [`VaultSync::create_item`] | `Active` with `item.type` and the fields | (new item) |
//! | [`VaultSync::import_item`] | as create, `WriteMode::Import` | (new item) |
//! | [`VaultSync::edit_item`] | `Active` with the changed fields | Active |
//! | [`VaultSync::trash_item`] | `Trashed`, no writes | Active |
//! | [`VaultSync::restore_item`] | `Active`, no writes | Trashed |
//! | [`VaultSync::purge_item`] | `Purge`, no writes | Trashed, no unapplied record (writer rules) |
//!
//! # The `rizzy-import` seam
//!
//! `rizzy-import` (ADR 0016 §3) is written in parallel and is not a dependency yet. Its output
//! reaches the vault through [`VaultSync::import_item`]: an item type and entered field
//! writes, checked with `WriteMode::Import` (the only mode that may write
//! `import.created_ms`). When the crate lands, a thin adapter maps its item type into these
//! calls; nothing here parses an import format.
//!
//! # Readings
//!
//! - Editing a trashed item is refused ([`ClientError::UnknownItem`]); the user restores it
//!   first. ADR 0012 §5 lets a field edit write `Active`, which would also restore it; the
//!   narrower rule avoids an edit that silently un-trashes.
//! - Values are the encoded bytes of ADR 0018 §6 ([`Value`]); keys are the final keys of the
//!   §7 grammar. Hosts build both with `rizzy_core::item`.

use rizzy_core::ids::ItemId;
use rizzy_core::item::LIFECYCLE_KEY;
use rizzy_core::item::key::FieldKey as SchemaKey;
use rizzy_core::item::schema::{ITEM_TYPE, WriteMode, WriteSource, check_create, check_write};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::rng::CryptoRng;
use rizzy_sync::merge::ItemLifecycle;
use rizzy_sync::record::{Lifecycle, SnapshotData};
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
        self.new_item(rng, unlocked, item_type, fields, WriteMode::Create, now_ms)
    }

    /// Creates a new item from an importer's output (see the module docs: the `rizzy-import`
    /// seam). As [`VaultSync::create_item`] with `WriteMode::Import`.
    ///
    /// # Errors
    /// As [`VaultSync::create_item`].
    pub fn import_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item_type: ItemType,
        fields: &[FieldEdit<'_>],
        now_ms: u64,
    ) -> Result<ItemId, ClientError> {
        self.new_item(rng, unlocked, item_type, fields, WriteMode::Import, now_ms)
    }

    /// The create op of a new item.
    fn new_item<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item_type: ItemType,
        fields: &[FieldEdit<'_>],
        mode: WriteMode,
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
            mode,
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
