//! The trash beyond the single-item calls of [`crate::items`]: the automatic purge after the
//! retention period, and the two notices ADR 0012 §5 and ADR 0018 §3 ask a client to show
//! (ADR 0012 §5 "Trash", "Purge", "Late ops after a purge"; ADR 0018 §3 "Surfacing", §9
//! "Trashed at", §11 "No purge over an unapplied record").
//!
//! | Call | What it does |
//! |---|---|
//! | [`VaultSync::purge_expired`] | Writes a `Purge` of every trashed item whose retention has passed |
//! | [`VaultSync::late_edits`] | The tombstones holding late values not yet surfaced, with the devices that wrote them |
//! | [`VaultSync::dismiss_late_edit`] | Marks one tombstone's late values as surfaced |
//! | [`VaultSync::restore_late_edit`] | "Restore it as a new item": a new item from the tombstone's late values |
//! | [`VaultSync::trash_conflict`] | "Deleted on X while it was being edited on Y": an Active that won over a concurrent trash |
//!
//! # Automatic purge
//!
//! "Only clients purge" (ADR 0012 §5; the server worker does not, ADR 0022): a trashed item is
//! purged once [`DEFAULT_TRASH_RETENTION_MS`] (30 days) has passed since the trash op's HLC,
//! which "happens only when some client is online after the retention period" (ADR 0022). The
//! host calls [`VaultSync::purge_expired`] after a sync that completed, with its clock, and
//! uploads the purges with the next one. The rules:
//!
//! - **The writer rules hold** ([`rizzy_sync::merge::ItemMerge::purge_due`]): only an item that
//!   displays Trashed, and never while the client holds an unapplied record of it, such as a
//!   restore of a newer schema version it parked (ADR 0018 §11, §12).
//! - **Never the vault-settings item.** It is never trashed (ADR 0018 §8); the guard is kept
//!   anyway.
//! - **Read-only means no purge.** A read-only vault writes nothing, and the automatic purge is
//!   not an action the user asked for, so it returns no item rather than an error.
//!
//! # Notices
//!
//! Both are local presentation and write nothing (ADR 0018 §3 "Surfacing": "changes no
//! bytes"). Which late values were surfaced is kept in memory only, in each item's merge: the
//! ADR 0026 cache has no place for it, so a device shows a late edit's notice once per unlock
//! rather than once for good. Persisting it is a cache-format change for its own ADR.
//!
//! Item ids and device ids are server-visible metadata, but which items are purged or trashed
//! is not (ADR 0012 §5), so the notice types print nothing from `Debug`.

use core::fmt;

use rizzy_core::ids::DeviceId;
use rizzy_core::item::LIFECYCLE_KEY;
/// The default trash retention (30 days in milliseconds), re-exported for hosts.
pub use rizzy_core::item::display::DEFAULT_TRASH_RETENTION_MS;
use rizzy_core::item::display::hlc_ms;
use rizzy_core::item::schema::{ITEM_TYPE, WriteMode, WriteSource, check_create};
use rizzy_core::item::types::ItemType;
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::rng::CryptoRng;
use rizzy_sync::merge::ItemLifecycle;
use rizzy_sync::record::{Lifecycle, SnapshotData};
use zeroize::Zeroizing;

use crate::device::UnlockedDevice;
use crate::error::ClientError;
use crate::items::ItemId;
use crate::sync::{OwnChange, VaultSync};

/// A tombstone with late values not yet surfaced: "An edit from `<device>` arrived for an
/// item you deleted permanently. Restore it as a new item?" (ADR 0018 §3).
#[derive(Clone, PartialEq, Eq)]
pub struct LateEdit {
    /// The purged item.
    pub item: ItemId,
    /// The devices whose late values are not surfaced yet, ascending, each once.
    pub devices: Vec<DeviceId>,
}

impl fmt::Debug for LateEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LateEdit([REDACTED])")
    }
}

/// An item whose Active won over a concurrent trash: "deleted on `<trashed_by>` while it was
/// being edited on `<edited_by>`" (ADR 0012 §5 "Trash").
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrashConflict {
    /// The device of the concurrent Trashed value that lost.
    pub trashed_by: DeviceId,
    /// The device of the Active value that displays.
    pub edited_by: DeviceId,
    /// When the losing trash was written, Unix milliseconds (its HLC).
    pub trashed_at_ms: u64,
}

impl fmt::Debug for TrashConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrashConflict([REDACTED])")
    }
}

impl VaultSync {
    /// The automatic purge (module docs): writes a `Purge` of every item the writer rules let
    /// this device purge whose `retention_ms` ([`DEFAULT_TRASH_RETENTION_MS`] by default) has
    /// passed at `now_ms`, measured from its trash op's HLC. Returns the purged items, in id
    /// order; none on a read-only vault.
    ///
    /// # Errors
    /// The errors of the own-op writer ([`ClientError::InvalidInput`] if `unlocked` is another
    /// device's). The purges written before an error stay, as any own op does.
    pub fn purge_expired<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        now_ms: u64,
        retention_ms: u64,
    ) -> Result<Vec<ItemId>, ClientError> {
        if self.is_read_only() {
            return Ok(Vec::new());
        }
        let due: Vec<ItemId> = self
            .merges()
            .filter(|(id, merge)| merge.purge_due(now_ms, retention_ms, self.holds_unapplied(*id)))
            .map(|(id, _)| id)
            .filter(|id| self.item_type(*id) != Some(ItemType::VAULT_SETTINGS))
            .collect();
        for item in &due {
            self.purge_item(rng, unlocked, *item, now_ms)?;
        }
        Ok(due)
    }

    /// The tombstones whose late values this device has not surfaced, in item id order (module
    /// docs, "Notices").
    #[must_use]
    pub fn late_edits(&self) -> Vec<LateEdit> {
        self.merges()
            .filter_map(|(item, merge)| {
                let mut devices: Vec<DeviceId> = merge
                    .late_values_to_surface()
                    .iter()
                    .map(|dot| dot.device_id())
                    .collect();
                devices.sort_unstable();
                devices.dedup();
                (!devices.is_empty()).then_some(LateEdit { item, devices })
            })
            .collect()
    }

    /// Marks the late values `item`'s tombstone holds now as surfaced: its notice is not shown
    /// again for them (in memory only, module docs). Later late values are shown again.
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item is not purged.
    pub fn dismiss_late_edit(&mut self, item: ItemId) -> Result<(), ClientError> {
        if self.item_lifecycle(item) != ItemLifecycle::Purged || !self.mark_surfaced(item) {
            return Err(ClientError::UnknownItem);
        }
        Ok(())
    }

    /// "Restore it as a new item" (ADR 0018 §3 "Surfacing", §6): a new item of `item_type`,
    /// the type the user confirmed, whose create op enters `item.type` and carries the
    /// displayed value of each of the tombstone's late registers (a Cleared one carries
    /// nothing). The tombstone stays purged, and its late values are marked surfaced. Returns
    /// the new item's id.
    ///
    /// # Errors
    /// [`ClientError::UnknownItem`] if the item is not purged or holds no late value;
    /// [`ClientError::InvalidEdit`] for a type that is not a supported user item type, or a
    /// late value the schema refuses for it (another type's field: the user picks another
    /// type); the errors of the own-op writer ([`ClientError::ReadOnly`] among them).
    pub fn restore_late_edit<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        item_type: ItemType,
        now_ms: u64,
    ) -> Result<ItemId, ClientError> {
        if self.item_lifecycle(item) != ItemLifecycle::Purged {
            return Err(ClientError::UnknownItem);
        }
        if !item_type
            .supported()
            .is_some_and(rizzy_core::item::types::SupportedType::is_user_item)
        {
            return Err(ClientError::InvalidEdit);
        }
        let mut carried: Vec<(Zeroizing<String>, Value)> = Vec::new();
        for key in self.late_keys(item) {
            if key.as_str() == ITEM_TYPE {
                continue;
            }
            let Some(value) = self.field_value(item, &key) else {
                continue;
            };
            if matches!(value.decode(), Ok(ValueRef::Cleared)) {
                continue;
            }
            carried.push((key, value));
        }
        if carried.is_empty() {
            return Err(ClientError::UnknownItem);
        }
        let type_value = Value::enumeration(item_type.id());
        let mut writes: Vec<(&str, &[u8])> = Vec::with_capacity(carried.len() + 1);
        writes.push((ITEM_TYPE, type_value.expose_secret()));
        for (key, value) in &carried {
            writes.push((key.as_str(), value.expose_secret()));
        }
        check_create(
            item_type,
            WriteMode::Create,
            writes.iter().map(|(k, v)| {
                let source = if *k == ITEM_TYPE {
                    WriteSource::Entered
                } else {
                    WriteSource::Carried
                };
                (source, k.as_bytes(), *v)
            }),
        )
        .map_err(|_| ClientError::InvalidEdit)?;
        let new_item = ItemId::generate(rng);
        self.write_op(
            rng,
            unlocked,
            new_item,
            &OwnChange {
                lifecycle: Lifecycle::Active,
                writes: &writes,
            },
            now_ms,
        )?;
        self.mark_surfaced(item);
        Ok(new_item)
    }

    /// "Deleted on X while it was being edited on Y" (ADR 0012 §5): `Some` while the item
    /// displays Active and its `@lifecycle` register also holds a concurrent Trashed value.
    #[must_use]
    pub fn trash_conflict(&self, item: ItemId) -> Option<TrashConflict> {
        let merge = self.merge(item)?;
        let display = merge.lifecycle_display()?;
        let trashed = display.trashed_by?;
        let view = merge.field(LIFECYCLE_KEY)?;
        let lost = view.current.get(trashed)?;
        let won = view.current.get(display.displayed)?;
        Some(TrashConflict {
            trashed_by: lost.dot().device_id(),
            edited_by: won.dot().device_id(),
            trashed_at_ms: hlc_ms(lost.hlc().to_u64()),
        })
    }

    /// The keys of a tombstone's late registers, ascending. Keys are user content.
    fn late_keys(&self, item: ItemId) -> Vec<Zeroizing<String>> {
        let Some(Ok(Some(SnapshotData::Tombstone(tomb)))) = self
            .merge(item)
            .map(rizzy_sync::merge::ItemMerge::snapshot_data)
        else {
            return Vec::new();
        };
        tomb.late()
            .iter()
            .map(|r| Zeroizing::new(r.key().expose_secret().to_owned()))
            .collect()
    }
}
