// SPDX-License-Identifier: AGPL-3.0-only

//! The vaults of one session, web or durable ([ADR 0081] Part A, §A2, §A7, §A12).
//!
//! A `VaultSet` holds one [`VaultSync`] driver per vault the account's catalog opens
//! ([`VaultCatalog`]: the authenticated vault directory checked against the served
//! self-grants, INV-102), and every driver shares one [`DeviceCounters`], so `device_seq`
//! stays one gap-free counter per device across vaults (§A7). Nothing here decides a
//! format or a check: `rizzy-client` does ([`rizzy_client::vaults`]); this module keeps the
//! drivers in step with the catalog after each account answer:
//!
//! - a vault the directory no longer lists (deleted on another device, §A5) is dropped with its
//!   unsent changes, which are counted and reported once (`VaultSet::take_discarded`); a host
//!   with a cache deletes its rows ([`rizzy_client::store::rows::Write::DropVault`]);
//! - a vault listed and served but not held yet gets a new driver;
//! - a listed vault the server withholds keeps its driver read-only (§A2), and a vault a
//!   `client_too_old` refusal named is shown as needing an update while the others keep
//!   working (§A12).
//!
//! Items are named by `(vault_id, item_id)` ([`crate::items::item_ref`], INV-103).
//!
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

use std::collections::BTreeSet;

use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::items::{ItemId, ItemLifecycle, ItemType};
use rizzy_client::rizzy_core::ids::VaultId;
use rizzy_client::rizzy_core::keys::VaultKey;
use rizzy_client::sync::{DeviceCounters, VaultSync};
use rizzy_client::vaults::{
    DirectoryKind, VaultAlarm, VaultCatalog, VaultLabel, VaultStatus, revoked_cutoff_gaps,
    vault_label,
};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};
use crate::items::{hex, parse_ref, visible};

/// The catalog of `account`; an account whose settings record this build cannot read is
/// checked as one without a directory (so a single served vault still opens, and two raise
/// the alarm), as `rv` does.
pub(crate) fn catalog_of(account: &VerifiedAccount, unlocked: &UnlockedDevice) -> VaultCatalog {
    VaultCatalog::of_account(account, unlocked)
        .unwrap_or_else(|_| VaultCatalog::check(None, &account.served_vault_ids()))
}

/// The user items of `vault` in one of `lifecycles`: never the vault-settings item.
pub(crate) fn user_items(vault: &VaultSync, lifecycles: &[ItemLifecycle]) -> Vec<ItemId> {
    vault
        .item_ids()
        .into_iter()
        .filter(|item| {
            lifecycles.contains(&vault.item_lifecycle(*item))
                && vault.item_type(*item) != Some(ItemType::VAULT_SETTINGS)
        })
        .collect()
}

/// The drivers of a session's vaults (module docs).
#[derive(Debug)]
pub(crate) struct VaultSet {
    /// One driver per held vault, ascending by id.
    vaults: Vec<VaultSync>,
    /// The per-device counters every driver shares.
    counters: DeviceCounters,
    /// The catalog of the last account answer (or of the last vault change).
    catalog: VaultCatalog,
    /// Vaults a `client_too_old` refusal named in this session (§A12).
    too_new: BTreeSet<VaultId>,
    /// Unsent changes of dropped vaults, not reported yet.
    discarded: usize,
    /// Whether new drivers journal their writes (a host with a cache).
    persist: bool,
    /// Whether an account alarm of the durable device is held (`crate::alarms`): every
    /// driver is read-only while one is, new ones included (ADR 0026 §4 step 4).
    alarmed: bool,
}

impl VaultSet {
    /// The set of `vaults` under `catalog`; only the vaults the catalog lists are kept (an
    /// unlisted vault is never opened, INV-102).
    pub(crate) fn new(vaults: Vec<VaultSync>, catalog: VaultCatalog, persist: bool) -> Self {
        let mut set = Self {
            vaults: Vec::with_capacity(vaults.len()),
            counters: DeviceCounters::new(),
            catalog,
            too_new: BTreeSet::new(),
            discarded: 0,
            persist,
            alarmed: false,
        };
        for vault in vaults {
            let id = vault.vault_id();
            if set.catalog.entries().iter().any(|e| e.vault_id == id) {
                set.insert(vault);
            }
        }
        set.update_read_only();
        set
    }

    /// The set of a fresh login or enrolment: a driver for every vault the catalog of
    /// `account` opens, from the keys the answer carried.
    ///
    /// # Errors
    /// `invalid_server_response` if an open vault's key is missing; as [`VaultSync::new`].
    pub(crate) fn open_all(
        account: &mut VerifiedAccount,
        unlocked: &UnlockedDevice,
        persist: bool,
    ) -> CoreResult<Self> {
        let catalog = catalog_of(account, unlocked);
        let mut set = Self::new(Vec::new(), catalog, persist);
        let open: Vec<VaultId> = set.catalog.open_vaults().collect();
        for vault_id in open {
            set.add_from(account, unlocked, vault_id)?;
        }
        set.update_read_only();
        Ok(set)
    }

    /// Every driver, ascending by vault id.
    pub(crate) fn all(&self) -> &[VaultSync] {
        &self.vaults
    }

    /// Every driver, mutably.
    pub(crate) fn all_mut(&mut self) -> &mut [VaultSync] {
        &mut self.vaults
    }

    /// The catalog.
    pub(crate) const fn catalog(&self) -> &VaultCatalog {
        &self.catalog
    }

    /// The driver of `vault_id`.
    ///
    /// # Errors
    /// `unknown_vault` for a vault this session does not hold.
    pub(crate) fn get(&self, vault_id: VaultId) -> CoreResult<&VaultSync> {
        self.vaults
            .iter()
            .find(|v| v.vault_id() == vault_id)
            .ok_or_else(|| ClientError::UnknownVault.into())
    }

    /// The driver of `vault_id`, mutably.
    ///
    /// # Errors
    /// `unknown_vault` for a vault this session does not hold.
    pub(crate) fn get_mut(&mut self, vault_id: VaultId) -> CoreResult<&mut VaultSync> {
        self.vaults
            .iter_mut()
            .find(|v| v.vault_id() == vault_id)
            .ok_or_else(|| ClientError::UnknownVault.into())
    }

    /// Two different drivers, mutably: `(a, b)`.
    ///
    /// # Errors
    /// `unknown_vault` for a vault this session does not hold; `invalid_input` for `a == b`.
    pub(crate) fn pair_mut(
        &mut self,
        a: VaultId,
        b: VaultId,
    ) -> CoreResult<(&mut VaultSync, &mut VaultSync)> {
        if a == b {
            return Err(ClientError::InvalidInput.into());
        }
        let unknown = || CoreError::from(ClientError::UnknownVault);
        let i = self
            .vaults
            .iter()
            .position(|v| v.vault_id() == a)
            .ok_or_else(unknown)?;
        let j = self
            .vaults
            .iter()
            .position(|v| v.vault_id() == b)
            .ok_or_else(unknown)?;
        if i < j {
            let (left, right) = self.vaults.split_at_mut(j);
            Ok((
                left.get_mut(i).ok_or_else(unknown)?,
                right.first_mut().ok_or_else(unknown)?,
            ))
        } else {
            let (left, right) = self.vaults.split_at_mut(i);
            Ok((
                right.first_mut().ok_or_else(unknown)?,
                left.get_mut(j).ok_or_else(unknown)?,
            ))
        }
    }

    /// The catalog and one driver, mutably (a rename needs both).
    ///
    /// # Errors
    /// `unknown_vault` for a vault this session does not hold.
    pub(crate) fn with_catalog_mut(
        &mut self,
        vault_id: VaultId,
    ) -> CoreResult<(&VaultCatalog, &mut VaultSync)> {
        let vault = self
            .vaults
            .iter_mut()
            .find(|v| v.vault_id() == vault_id)
            .ok_or(ClientError::UnknownVault)?;
        Ok((&self.catalog, vault))
    }

    /// The visible item an [`crate::items::item_ref`] names, with its vault's driver.
    ///
    /// # Errors
    /// `invalid_input` for a malformed reference; `unknown_vault`; `unknown_item`.
    pub(crate) fn item(&self, id: &str) -> CoreResult<(&VaultSync, ItemId)> {
        let (vault_id, item) = parse_ref(id)?;
        let vault = self.get(vault_id)?;
        Ok((vault, visible(vault, item)?))
    }

    /// The item an [`crate::items::item_ref`] names (visible or not), with its driver, mutably.
    ///
    /// # Errors
    /// `invalid_input` for a malformed reference; `unknown_vault`.
    pub(crate) fn item_mut(&mut self, id: &str) -> CoreResult<(&mut VaultSync, ItemId)> {
        let (vault_id, item) = parse_ref(id)?;
        Ok((self.get_mut(vault_id)?, item))
    }

    /// The Personal vault, held: the default target of every new item (§A1, §A8).
    ///
    /// # Errors
    /// `vault_set_mismatch` while the catalog cannot name it (no directory and several vaults)
    /// or its driver is not held.
    pub(crate) fn personal(&self) -> CoreResult<VaultId> {
        self.catalog
            .personal()
            .filter(|v| self.vaults.iter().any(|d| d.vault_id() == *v))
            .ok_or_else(|| ClientError::VaultSetMismatch.into())
    }

    /// The Personal vault's driver.
    ///
    /// # Errors
    /// As [`VaultSet::personal`].
    pub(crate) fn personal_vault(&self) -> CoreResult<&VaultSync> {
        self.get(self.personal()?)
    }

    /// The vaults a sync fetches, in order: every held vault the catalog opens and no
    /// `client_too_old` refusal named, the Personal vault first.
    pub(crate) fn sync_order(&self) -> Vec<VaultId> {
        let personal = self.catalog.personal();
        let mut order: Vec<VaultId> = self
            .vaults
            .iter()
            .map(VaultSync::vault_id)
            .filter(|v| self.catalog.is_open(*v) && !self.too_new.contains(v))
            .collect();
        order.sort_by_key(|v| Some(*v) != personal);
        order
    }

    /// Whether `vault_id` is open and writable on this device now.
    pub(crate) fn is_writable(&self, vault_id: VaultId) -> bool {
        self.catalog.is_open(vault_id)
            && !self.too_new.contains(&vault_id)
            && self.get(vault_id).is_ok_and(|v| !v.is_read_only())
    }

    /// Inserts a driver, sharing the counters; read-only while an alarm is held.
    pub(crate) fn insert(&mut self, mut vault: VaultSync) {
        vault.share_counters(&self.counters);
        if self.alarmed {
            vault.set_read_only(true);
        }
        let at = self
            .vaults
            .partition_point(|v| v.vault_id() < vault.vault_id());
        self.vaults.insert(at, vault);
    }

    /// A new driver for `vault_id` from the key `account` carries.
    fn add_from(
        &mut self,
        account: &mut VerifiedAccount,
        unlocked: &UnlockedDevice,
        vault_id: VaultId,
    ) -> CoreResult<()> {
        let key = account
            .take_vault_key(vault_id)
            .ok_or(ClientError::InvalidServerResponse)?;
        self.add_key(key, unlocked)
    }

    /// A new driver for a vault key: the device's next `device_seq`, the shared counters.
    ///
    /// # Errors
    /// As [`VaultSync::new`].
    pub(crate) fn add_key(&mut self, key: VaultKey, unlocked: &UnlockedDevice) -> CoreResult<()> {
        let mut vault = VaultSync::new(key, unlocked, self.next_device_seq())?;
        if self.persist {
            vault.persist();
        }
        self.insert(vault);
        Ok(())
    }

    /// Removes a driver; its unsent changes are counted as discarded.
    pub(crate) fn remove(&mut self, vault_id: VaultId) -> Option<VaultSync> {
        let at = self.vaults.iter().position(|v| v.vault_id() == vault_id)?;
        self.too_new.remove(&vault_id);
        let vault = self.vaults.remove(at);
        self.discarded = self.discarded.saturating_add(vault.unacknowledged().0);
        Some(vault)
    }

    /// Removes a driver whose vault the user deleted on this device: its unsent changes go
    /// with it and are not reported.
    pub(crate) fn forget(&mut self, vault_id: VaultId) {
        if let Some(at) = self.vaults.iter().position(|v| v.vault_id() == vault_id) {
            self.too_new.remove(&vault_id);
            self.vaults.remove(at);
        }
    }

    /// The next `device_seq` of this device.
    fn next_device_seq(&self) -> u64 {
        self.vaults
            .iter()
            .map(VaultSync::next_device_seq)
            .chain(core::iter::once(self.counters.next_device_seq()))
            .max()
            .unwrap_or(1)
            .max(1)
    }

    /// Replaces the catalog (after a vault change the server acknowledged).
    pub(crate) fn set_catalog(&mut self, catalog: VaultCatalog) {
        self.catalog = catalog;
        self.update_read_only();
    }

    /// Raises or lifts the durable device's account alarm (`crate::alarms`): while `alarmed`
    /// every driver is read-only (ADR 0026 §4 step 4; ADR 0095 §C: "every vault of the account
    /// goes read-only"). Lifting it (a resolved rollback, the last alarm held) leaves read-only
    /// only the drivers [`VaultSet::update_read_only`] names.
    pub(crate) fn set_alarmed(&mut self, alarmed: bool) {
        self.alarmed = alarmed;
        if !alarmed {
            for vault in &mut self.vaults {
                vault.set_read_only(false);
            }
        }
        self.update_read_only();
    }

    /// A driver whose vault the catalog does not open, or a `client_too_old` refusal named,
    /// is read-only; while an alarm is held, every driver is.
    pub(crate) fn update_read_only(&mut self) {
        for vault in &mut self.vaults {
            let id = vault.vault_id();
            if self.alarmed || !self.catalog.is_open(id) || self.too_new.contains(&id) {
                vault.set_read_only(true);
            }
        }
    }

    /// A `client_too_old` refusal for one vault (§A12): it is shown as needing an update and
    /// kept read-only; the other vaults keep working.
    pub(crate) fn mark_too_new(&mut self, vault_id: VaultId) {
        self.too_new.insert(vault_id);
        if let Ok(vault) = self.get_mut(vault_id) {
            vault.set_read_only(true);
        }
    }

    /// The unsent changes of dropped vaults since the last call (reported once).
    pub(crate) fn take_discarded(&mut self) -> usize {
        core::mem::take(&mut self.discarded)
    }

    /// The cross-vault revocation cut-off check over every open vault (§0 item 2): how many
    /// revoked devices have ops missing below their cut-off in every vault.
    pub(crate) fn cutoff_gaps(&self) -> usize {
        let open: Vec<&VaultSync> = self
            .vaults
            .iter()
            .filter(|v| self.catalog.is_open(v.vault_id()))
            .collect();
        revoked_cutoff_gaps(&open).len()
    }

    /// After an account answer verified (module docs): the catalog of `account`, the held open
    /// vaults' keys adopted, the dropped vaults removed, new open vaults added. Returns the
    /// dropped vaults (a host with a cache deletes their rows).
    ///
    /// # Errors
    /// `rollback` or `fork` from a vault key (that vault is read-only then); `invalid_server_response`
    /// for a missing key.
    pub(crate) fn reconcile(
        &mut self,
        account: &mut VerifiedAccount,
        unlocked: &UnlockedDevice,
    ) -> CoreResult<Vec<VaultId>> {
        let catalog = catalog_of(account, unlocked);
        // ADR 0025 §4: a second key at a seen epoch is a fork, a key below the held epoch a
        // rollback; either way the vault becomes read-only and the answer is not adopted.
        let held_open: Vec<VaultId> = self
            .vaults
            .iter()
            .map(VaultSync::vault_id)
            .filter(|v| catalog.is_open(*v))
            .collect();
        for vault_id in held_open {
            let key = account
                .take_vault_key(vault_id)
                .ok_or(ClientError::InvalidServerResponse)?;
            let vault = self.get_mut(vault_id)?;
            match vault.adopt_vault_key(key) {
                Ok(()) => {}
                Err(e @ (ClientError::Rollback | ClientError::Fork)) => {
                    vault.set_read_only(true);
                    return Err(e.into());
                }
                Err(e) => return Err(e.into()),
            }
        }
        let mut dropped = Vec::new();
        if catalog.has_directory() {
            let gone: Vec<VaultId> = self
                .vaults
                .iter()
                .map(VaultSync::vault_id)
                .filter(|v| !catalog.entries().iter().any(|e| e.vault_id == *v))
                .collect();
            for vault_id in gone {
                self.remove(vault_id);
                dropped.push(vault_id);
            }
        }
        let new: Vec<VaultId> = catalog
            .open_vaults()
            .filter(|v| !self.vaults.iter().any(|d| d.vault_id() == *v))
            .collect();
        for vault_id in new {
            self.add_from(account, unlocked, vault_id)?;
        }
        self.catalog = catalog;
        self.update_read_only();
        Ok(dropped)
    }

    /// The views of every vault the catalog lists (the vault list, the switcher and the
    /// pickers): the Personal vault first, then the named vaults by name, then the unnamed.
    pub(crate) fn views(&self, bytes_used: impl Fn(VaultId) -> Option<u64>) -> Vec<VaultView> {
        let mut views: Vec<VaultView> = self
            .catalog
            .entries()
            .iter()
            .map(|entry| {
                let driver = self.vaults.iter().find(|v| v.vault_id() == entry.vault_id);
                let kind = match &entry.kind {
                    DirectoryKind::Personal => "personal",
                    DirectoryKind::Owned(None) => "owned",
                    DirectoryKind::Owned(Some(_)) => "shared",
                    DirectoryKind::Joined { .. } => "joined",
                    DirectoryKind::Unknown { .. } => "unknown",
                };
                let status = if self.too_new.contains(&entry.vault_id) {
                    "needs_update"
                } else {
                    match entry.status {
                        VaultStatus::Open => "open",
                        VaultStatus::Withheld => "withheld",
                        VaultStatus::NeedsUpdate => "needs_update",
                    }
                };
                // §A1: the Personal vault's label is the client's, whatever `vault.name` says.
                let name = driver.and_then(|v| match vault_label(&self.catalog, v) {
                    VaultLabel::Named(name) => Some(name),
                    VaultLabel::Personal | VaultLabel::Untitled => None,
                });
                let item_count = driver.map_or(0, |v| {
                    user_items(v, &[ItemLifecycle::Active, ItemLifecycle::Trashed]).len()
                });
                VaultView {
                    id: hex(entry.vault_id.as_bytes()),
                    kind,
                    name,
                    status,
                    read_only: driver.is_none_or(VaultSync::is_read_only),
                    item_count: u32::try_from(item_count).unwrap_or(u32::MAX),
                    bytes_used: bytes_used(entry.vault_id),
                }
            })
            .collect();
        views.sort_by(|a, b| {
            let rank = |v: &VaultView| u8::from(v.kind != "personal");
            rank(a)
                .cmp(&rank(b))
                .then_with(|| a.name.is_none().cmp(&b.name.is_none()))
                .then_with(|| {
                    let an = a.name.as_deref().map(|n| n.to_lowercase());
                    let bn = b.name.as_deref().map(|n| n.to_lowercase());
                    an.cmp(&bn)
                })
                .then_with(|| a.id.cmp(&b.id))
        });
        views
    }

    /// The alarms of the catalog (INV-102), as views.
    pub(crate) fn alarm_views(&self) -> Vec<VaultAlarmView> {
        self.catalog
            .alarms()
            .iter()
            .map(|alarm| match alarm {
                VaultAlarm::Withheld(v) => VaultAlarmView {
                    kind: "withheld",
                    vault_id: Some(hex(v.as_bytes())),
                },
                VaultAlarm::Unlisted(v) => VaultAlarmView {
                    kind: "unlisted",
                    vault_id: Some(hex(v.as_bytes())),
                },
                VaultAlarm::NoDirectory => VaultAlarmView {
                    kind: "no_directory",
                    vault_id: None,
                },
            })
            .collect()
    }
}

/// One vault of the account, for the vault list, the switcher and the pickers. Wiped when
/// freed (the name is user content).
#[wasm_bindgen]
pub struct VaultView {
    /// The vault id, 32 hex digits.
    id: String,
    /// `personal`, `owned`, `shared`, `joined` or `unknown`.
    kind: &'static str,
    /// `vault.name` of an owned vault; `None` for the Personal vault (its label is the
    /// localised "Personal", §A1) and for a vault without a name yet ("Untitled vault").
    name: Option<Zeroizing<String>>,
    /// `open`, `withheld` or `needs_update`.
    status: &'static str,
    /// Whether nothing can be written to it on this device now.
    read_only: bool,
    /// Its items, active and trashed (0 for a vault not opened).
    item_count: u32,
    /// The server's counted bytes of the vault (informational, unsigned), if served.
    bytes_used: Option<u64>,
}

impl core::fmt::Debug for VaultView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultView")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl VaultView {
    /// The vault id, 32 lowercase hex digits.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// `personal`, `owned`, `shared` (Part B), `joined` (Part B) or `unknown` (a kind this
    /// build does not know).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_owned()
    }

    /// The vault's name; `undefined` for the Personal vault (shown as "Personal", localised)
    /// and for an owned vault without one (shown as "Untitled vault").
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.name.as_ref().map(|n| n.as_str().to_owned())
    }

    /// `open`, `withheld` (listed but not served: read-only, an alarm) or `needs_update`
    /// ("This vault needs a newer rizzy-vault", §A12).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn status(&self) -> String {
        self.status.to_owned()
    }

    /// Whether nothing can be written to it now.
    #[wasm_bindgen(getter, js_name = readOnly)]
    #[must_use]
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Its items, active and trashed.
    #[wasm_bindgen(getter, js_name = itemCount)]
    #[must_use]
    pub fn item_count(&self) -> u32 {
        self.item_count
    }

    /// The server's counted bytes of the vault, if served.
    #[wasm_bindgen(getter, js_name = bytesUsed)]
    #[must_use]
    pub fn bytes_used(&self) -> Option<u64> {
        self.bytes_used
    }
}

/// One alarm of the vault completeness check (INV-102).
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct VaultAlarmView {
    /// `withheld`, `unlisted` or `no_directory`.
    kind: &'static str,
    /// The vault it names (none for `no_directory`).
    vault_id: Option<String>,
}

#[wasm_bindgen]
impl VaultAlarmView {
    /// `withheld` (the directory lists the vault, the server served no key: it stays
    /// read-only), `unlisted` (the server served a vault the directory does not list: not
    /// opened) or `no_directory` (several vaults, no directory: none is opened for changes).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_owned()
    }

    /// The vault, 32 hex digits; `undefined` for `no_directory`.
    #[wasm_bindgen(getter, js_name = vaultId)]
    #[must_use]
    pub fn vault_id(&self) -> Option<String> {
        self.vault_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use rizzy_client::vaults::VaultDirectory;

    use super::*;

    fn id(byte: u8) -> VaultId {
        VaultId::from_bytes([byte; 16])
    }

    fn set(owned: &[u8], served: &[u8]) -> VaultSet {
        let mut directory = VaultDirectory::personal_only(id(0x11));
        for o in owned {
            directory = directory.with_owned(id(*o)).unwrap();
        }
        let served: Vec<VaultId> = served.iter().map(|b| id(*b)).collect();
        VaultSet::new(
            Vec::new(),
            VaultCatalog::check(Some(&directory), &served),
            false,
        )
    }

    #[test]
    fn views_list_personal_first_and_flag_withheld_vaults() {
        let set = set(&[0x05, 0x22], &[0x11, 0x22]);
        let views = set.views(|v| (v == id(0x11)).then_some(42));
        assert_eq!(views.len(), 3);
        assert_eq!(views[0].kind(), "personal");
        assert_eq!(views[0].id(), hex(id(0x11).as_bytes()));
        assert_eq!(views[0].name(), None);
        assert_eq!(views[0].bytes_used(), Some(42));
        let withheld = views
            .iter()
            .find(|v| v.id() == hex(id(0x05).as_bytes()))
            .unwrap();
        assert_eq!(withheld.status(), "withheld");
        assert_eq!(withheld.kind(), "owned");
        assert!(withheld.read_only(), "no driver: nothing can be written");
        let alarms = set.alarm_views();
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].kind(), "withheld");
        assert_eq!(alarms[0].vault_id(), Some(hex(id(0x05).as_bytes())));
    }

    #[test]
    fn without_drivers_nothing_resolves() {
        let set = set(&[0x22], &[0x11, 0x22]);
        assert_eq!(
            set.personal().unwrap_err().as_str(),
            "vault_set_mismatch",
            "the Personal vault is named only once its driver is held"
        );
        let r = crate::items::item_ref(id(0x22), ItemId::from_bytes([7; 16]));
        assert_eq!(set.item(&r).unwrap_err().as_str(), "unknown_vault");
        assert_eq!(set.item("not a ref").unwrap_err().as_str(), "invalid_input");
        assert!(set.sync_order().is_empty());
        assert!(!set.is_writable(id(0x22)));
    }

    #[test]
    fn several_vaults_without_a_directory_raise_the_alarm() {
        let set = VaultSet::new(
            Vec::new(),
            VaultCatalog::check(None, &[id(0x11), id(0x22)]),
            false,
        );
        let alarms = set.alarm_views();
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].kind(), "no_directory");
        assert_eq!(alarms[0].vault_id(), None);
        assert!(set.views(|_| None).is_empty());
    }
}
