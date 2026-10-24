// SPDX-License-Identifier: AGPL-3.0-only

//! The device's vaults ([ADR 0081] Part A, §A7): one [`VaultSync`] per vault the account's
//! vault directory lists and the server serves, all sharing one [`DeviceCounters`].
//!
//! - **The catalog.** On open the catalog comes from the cached account; after each online
//!   account refresh it is computed again ([`VaultCatalog::of_account`]). A vault the directory
//!   lists but the server withholds stays read-only from the cache; a vault the server serves
//!   but the directory does not list is never opened; an account with several vaults and no
//!   directory opens none for writing. Each of these is shown as a note.
//! - **New and dropped vaults.** A newly listed vault gets a driver from the refreshed
//!   account's key, persisted and indexed like an enrolment's; a vault the directory no longer
//!   lists is dropped with its cache rows ([`Write::DropVault`]), and unsent changes to it are
//!   reported once.
//! - **Too new for this build** (§A12). A vault whose Fetch or upload the server answers with
//!   `client_too_old` is marked "needs a newer rizzy-vault" for this run: read-only, skipped by
//!   sync, while the other vaults go on.
//! - **Vault changes** (§A3–§A5): create (over the device session), rename (an op on the
//!   vault-settings item) and delete (over a fresh OPAQUE session, after this device's password
//!   re-authenticated it).
//! - **Moves and copies** (§A6): a copy is a new item in the target; a move writes its
//!   `pending_move` row first, copies, uploads the target with every attachment, and only then
//!   trashes and purges the source (INV-104). Rows left by an interrupted run are resumed by
//!   the next sync.
//!
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

use std::collections::BTreeSet;

use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::attachments::AttachmentInfo;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::items::{ItemId, ItemLifecycle, ItemType};
use rizzy_client::rizzy_proto::attachments::{DownloadChunkResponse, GetAttachmentResponse};
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::store::index;
use rizzy_client::store::rows::{Alarm, Changeset, PendingMoveRow, Write};
use rizzy_client::sync::{DeviceCounters, VaultSync};
use rizzy_client::vaults::{
    self, MAX_VAULT_NAME_CHARS, MoveStep, PendingMove, VaultAlarm, VaultCatalog, VaultStatus,
};
use rizzy_core::ids::{AttachmentId, VaultId};
use zeroize::Zeroizing;

use super::{Device, copy_token};
use crate::error::CliError;
use crate::http::Auth;
use crate::paths::hex;
use crate::sys::now_ms;
use crate::ui::Ui;

/// How often a vault change is rebuilt after `state_conflict` before the command gives up.
const COMMIT_ATTEMPTS: usize = 3;

/// How the vault list shows a vault this device holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    /// Open: synced and writable.
    Open,
    /// Listed, but the server withholds its key: read-only from the cache.
    Withheld,
    /// A kind or a server answer this build cannot handle: "needs a newer rizzy-vault".
    NeedsUpdate,
    /// Held here, but not opened (no vault list to say which vault it is).
    Closed,
}

/// The vaults of one device: every driver, ascending by id, the device's shared counters, and
/// the catalog they were opened under.
#[derive(Debug)]
pub struct VaultSet {
    /// One driver per vault this device holds, ascending by id.
    vaults: Vec<VaultSync>,
    /// The device's `device_seq` and HLC, shared by every driver (§A7).
    counters: DeviceCounters,
    /// The account's vaults as last checked.
    catalog: VaultCatalog,
    /// The vaults the server answered `client_too_old` for in this run (§A12).
    too_new: BTreeSet<VaultId>,
}

impl VaultSet {
    /// The set of `vaults` under `catalog`, each joining one new [`DeviceCounters`].
    pub(crate) fn new(vaults: Vec<VaultSync>, catalog: VaultCatalog) -> Self {
        let mut set = Self {
            vaults: Vec::with_capacity(vaults.len()),
            counters: DeviceCounters::new(),
            catalog,
            too_new: BTreeSet::new(),
        };
        for vault in vaults {
            set.insert(vault);
        }
        set
    }

    /// Every driver, ascending by vault id.
    #[must_use]
    pub fn all(&self) -> &[VaultSync] {
        &self.vaults
    }

    /// The driver of `vault_id`, if this device holds it.
    #[must_use]
    pub fn get(&self, vault_id: VaultId) -> Option<&VaultSync> {
        self.vaults.iter().find(|v| v.vault_id() == vault_id)
    }

    /// The driver of `vault_id`, mutably.
    pub(crate) fn get_mut(&mut self, vault_id: VaultId) -> Option<&mut VaultSync> {
        self.vaults.iter_mut().find(|v| v.vault_id() == vault_id)
    }

    /// The driver of `vault_id`, or [`ClientError::UnknownVault`].
    ///
    /// # Errors
    /// [`ClientError::UnknownVault`] for a vault this device does not hold.
    pub fn require(&self, vault_id: VaultId) -> Result<&VaultSync, CliError> {
        self.get(vault_id)
            .ok_or(CliError::Client(ClientError::UnknownVault))
    }

    /// The driver of `vault_id` mutably, or [`ClientError::UnknownVault`].
    pub(crate) fn require_mut(&mut self, vault_id: VaultId) -> Result<&mut VaultSync, CliError> {
        self.get_mut(vault_id)
            .ok_or(CliError::Client(ClientError::UnknownVault))
    }

    /// Two different drivers at once.
    fn pair_mut(
        &mut self,
        a: VaultId,
        b: VaultId,
    ) -> Result<(&mut VaultSync, &mut VaultSync), CliError> {
        let unknown = || CliError::Client(ClientError::UnknownVault);
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
        if i == j {
            return Err(CliError::Client(ClientError::InvalidInput));
        }
        if i < j {
            let (low, high) = self.vaults.split_at_mut(j);
            Ok((&mut low[i], &mut high[0]))
        } else {
            let (low, high) = self.vaults.split_at_mut(i);
            Ok((&mut high[0], &mut low[j]))
        }
    }

    /// The vaults this device syncs and writes: held here, open in the catalog, and not
    /// answered `client_too_old`.
    #[must_use]
    pub fn open_ids(&self) -> Vec<VaultId> {
        self.vaults
            .iter()
            .map(VaultSync::vault_id)
            .filter(|v| self.is_open(*v))
            .collect()
    }

    /// Whether `vault_id` is held here and open for sync and writes.
    #[must_use]
    pub fn is_open(&self, vault_id: VaultId) -> bool {
        self.get(vault_id).is_some()
            && self.catalog.is_open(vault_id)
            && !self.too_new.contains(&vault_id)
    }

    /// How the vault list shows `vault_id`.
    #[must_use]
    pub fn shown(&self, vault_id: VaultId) -> Shown {
        if self.too_new.contains(&vault_id) {
            return Shown::NeedsUpdate;
        }
        match self
            .catalog
            .entries()
            .iter()
            .find(|e| e.vault_id == vault_id)
            .map(|e| e.status)
        {
            Some(VaultStatus::Open) => Shown::Open,
            Some(VaultStatus::Withheld) => Shown::Withheld,
            Some(VaultStatus::NeedsUpdate) => Shown::NeedsUpdate,
            None => Shown::Closed,
        }
    }

    /// The catalog the set was last checked against.
    #[must_use]
    pub const fn catalog(&self) -> &VaultCatalog {
        &self.catalog
    }

    /// The Personal vault, when the catalog knows it and this device holds it.
    #[must_use]
    pub fn personal(&self) -> Option<VaultId> {
        self.catalog.personal().filter(|v| self.get(*v).is_some())
    }

    /// Adds `vault`, joined to the shared counters, in id order.
    fn insert(&mut self, mut vault: VaultSync) {
        vault.share_counters(&self.counters);
        let at = self
            .vaults
            .partition_point(|v| v.vault_id() < vault.vault_id());
        self.vaults.insert(at, vault);
    }

    /// Removes the driver of `vault_id`.
    fn remove(&mut self, vault_id: VaultId) -> Option<VaultSync> {
        let at = self.vaults.iter().position(|v| v.vault_id() == vault_id)?;
        self.too_new.remove(&vault_id);
        Some(self.vaults.remove(at))
    }

    /// The next `device_seq` of this device, for a new driver.
    fn next_device_seq(&self) -> u64 {
        self.vaults
            .iter()
            .map(VaultSync::next_device_seq)
            .chain(core::iter::once(self.counters.next_device_seq()))
            .max()
            .unwrap_or(1)
            .max(1)
    }

    /// What every driver journaled, in one changeset.
    pub(crate) fn take_writes(&mut self) -> Changeset {
        let mut changeset = Changeset::new();
        for vault in &mut self.vaults {
            changeset.append(vault.take_writes());
        }
        changeset
    }

    /// The drivers of the open vaults: what a rotation re-keys (ADR 0081 §A9).
    #[must_use]
    pub fn open_refs(&self) -> Vec<&VaultSync> {
        self.vaults
            .iter()
            .filter(|v| self.is_open(v.vault_id()))
            .collect()
    }

    /// The drivers of the open vaults, mutably (a rotation's finish).
    pub(crate) fn open_mut_refs(&mut self) -> Vec<&mut VaultSync> {
        let open = self.open_ids();
        self.vaults
            .iter_mut()
            .filter(|v| open.contains(&v.vault_id()))
            .collect()
    }

    /// Every driver, mutably (the index rebuild).
    pub(crate) fn as_mut_slice(&mut self) -> &mut [VaultSync] {
        &mut self.vaults
    }

    /// Makes each driver read-only while `alarmed` (an account alarm), or while its vault is
    /// not open (catalog, or `client_too_old`).
    pub(crate) fn update_read_only(&mut self, alarmed: bool) {
        for vault in &mut self.vaults {
            let id = vault.vault_id();
            let open = self.catalog.is_open(id) && !self.too_new.contains(&id);
            vault.set_read_only(alarmed || !open);
        }
    }

    /// Marks `vault_id` "needs a newer rizzy-vault" for this run (§A12): read-only, not synced.
    pub(crate) fn mark_too_new(&mut self, vault_id: VaultId) {
        self.too_new.insert(vault_id);
        if let Some(vault) = self.get_mut(vault_id) {
            vault.set_read_only(true);
        }
    }

    /// The vaults the server answered `client_too_old` for in this run.
    #[must_use]
    pub fn too_new_ids(&self) -> Vec<VaultId> {
        self.too_new.iter().copied().collect()
    }

    /// The vaults held here that `catalog` opens.
    fn open_ids_under(&self, catalog: &VaultCatalog) -> Vec<VaultId> {
        self.vaults
            .iter()
            .map(VaultSync::vault_id)
            .filter(|v| catalog.is_open(*v))
            .collect()
    }

    /// The driver of `vault_id` for a rename, beside the catalog.
    fn with_catalog_mut(
        &mut self,
        vault_id: VaultId,
    ) -> Result<(&VaultCatalog, &mut VaultSync), CliError> {
        let vault = self
            .vaults
            .iter_mut()
            .find(|v| v.vault_id() == vault_id)
            .ok_or(CliError::Client(ClientError::UnknownVault))?;
        Ok((&self.catalog, vault))
    }
}

/// The catalog of `account`. An account whose settings record this build cannot read is taken
/// as having no directory: the legacy rule opens its one vault, and none of several.
pub(crate) fn catalog_of(account: &VerifiedAccount, unlocked: &UnlockedDevice) -> VaultCatalog {
    VaultCatalog::of_account(account, unlocked)
        .unwrap_or_else(|_| VaultCatalog::check(None, &account.served_vault_ids()))
}

/// The note for one completeness-check alarm (INV-102).
fn alarm_note(alarm: VaultAlarm) -> String {
    match alarm {
        VaultAlarm::Withheld(vault) => format!(
            "The server did not send the key of vault {}, which the account's vault list \
             names: it stays read-only on this device, as this device last saw it.",
            hex(vault.as_bytes())
        ),
        VaultAlarm::Unlisted(vault) => format!(
            "The server sent a vault ({}) that the account's vault list does not name: it is \
             not opened.",
            hex(vault.as_bytes())
        ),
        VaultAlarm::NoDirectory => "The account holds several vaults but no vault list: no \
                                    vault is opened for changes."
            .to_owned(),
    }
}

/// The user items of `vault` in one of `lifecycles` (the vault-settings item never counts).
#[must_use]
pub fn user_items(vault: &VaultSync, lifecycles: &[ItemLifecycle]) -> Vec<ItemId> {
    vault
        .item_ids()
        .into_iter()
        .filter(|item| {
            lifecycles.contains(&vault.item_lifecycle(*item))
                && vault.item_type(*item) != Some(ItemType::VAULT_SETTINGS)
        })
        .collect()
}

/// Whether `e` says an attachment is not (completely) on the server.
const fn attachment_missing(e: &CliError) -> bool {
    matches!(
        e,
        CliError::Server(ErrorCode::NotFound) | CliError::Client(ClientError::AttachmentIncomplete)
    )
}

/// Refuses a vault name that is empty or longer than [`MAX_VAULT_NAME_CHARS`].
fn check_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() {
        return Err(CliError::BadInput("a vault name cannot be empty"));
    }
    if name.chars().count() > MAX_VAULT_NAME_CHARS {
        return Err(CliError::BadInput(
            "a vault name is at most 64 characters long",
        ));
    }
    Ok(())
}

impl Device {
    /// The device's vaults.
    #[must_use]
    pub const fn vaults(&self) -> &VaultSet {
        &self.vaults
    }

    /// The Personal vault (§A1), the default target of every new item (§A8).
    ///
    /// # Errors
    /// [`ClientError::VaultSetMismatch`] while the catalog cannot tell which vault it is.
    pub fn personal(&self) -> Result<VaultId, CliError> {
        self.vaults
            .personal()
            .ok_or(CliError::Client(ClientError::VaultSetMismatch))
    }

    /// The counted bytes the server last reported for `vault_id` (display only).
    #[must_use]
    pub fn vault_bytes_used(&self, vault_id: VaultId) -> Option<u64> {
        self.account
            .as_ref()
            .and_then(|a| a.vault_bytes_used(vault_id))
    }

    /// Refuses a write to `vault_id` unless it is held here and open.
    ///
    /// # Errors
    /// [`CliError::Alarm`] under an alarm; [`ClientError::UnknownVault`] for a vault this
    /// device does not hold; [`ClientError::ReadOnly`] for one it does not open.
    pub fn check_vault_writable(&self, vault_id: VaultId) -> Result<(), CliError> {
        self.check_writable()?;
        if self.vaults.get(vault_id).is_none() {
            return Err(CliError::Client(ClientError::UnknownVault));
        }
        if !self.vaults.is_open(vault_id) {
            return Err(CliError::Client(ClientError::ReadOnly));
        }
        Ok(())
    }

    /// After an account answer was verified: checks the vault set against it (module docs),
    /// adopts each open vault's key, builds drivers for newly listed vaults and drops those the
    /// directory no longer lists. Returns the vaults to fetch now (a new key epoch, or new).
    pub(super) async fn reconcile_vaults(
        &mut self,
        ui: &mut dyn Ui,
        account: &mut VerifiedAccount,
        changeset: &mut Changeset,
    ) -> Result<Vec<VaultId>, CliError> {
        let catalog = catalog_of(account, &self.unlocked);
        for alarm in catalog.alarms() {
            ui.note(&alarm_note(*alarm));
        }
        // Dropped: a directory exists and no longer names a vault held here.
        if catalog.has_directory() {
            let listed: Vec<VaultId> = catalog.entries().iter().map(|e| e.vault_id).collect();
            let gone: Vec<VaultId> = self
                .vaults
                .all()
                .iter()
                .map(VaultSync::vault_id)
                .filter(|v| !listed.contains(v))
                .collect();
            let mut discarded = 0;
            for vault_id in gone {
                if let Some(vault) = self.vaults.remove(vault_id) {
                    let (ops, _) = vault.unacknowledged();
                    discarded += ops;
                }
                changeset.push(Write::DropVault {
                    vault_id: vault_id.to_bytes(),
                });
                self.pending_moves
                    .retain(|m| m.source_vault != vault_id && m.target_vault != vault_id);
            }
            if discarded > 0 {
                ui.note(&format!(
                    "{discarded} changes to a deleted vault were discarded."
                ));
            }
        }
        let mut refetch = Vec::new();
        // Held and open: adopt the served key.
        for vault_id in self.vaults.open_ids_under(&catalog) {
            let key = account
                .take_vault_key(vault_id)
                .ok_or(ClientError::InvalidServerResponse)?;
            let vault = self.vaults.require_mut(vault_id)?;
            let epoch = vault.vault_key_epoch();
            match vault.adopt_vault_key(key) {
                Ok(()) => {}
                Err(e @ (ClientError::Fork | ClientError::Rollback)) => {
                    let alarm = if matches!(e, ClientError::Fork) {
                        Alarm::Fork
                    } else {
                        Alarm::Rollback
                    };
                    return Err(self.alarm(alarm, &[]).await);
                }
                Err(e) => return Err(e.into()),
            }
            if vault.vault_key_epoch() != epoch {
                refetch.push(vault_id);
            }
        }
        // Listed, served and new here: a driver like an enrolment's.
        let new: Vec<VaultId> = catalog
            .open_vaults()
            .filter(|v| self.vaults.get(*v).is_none())
            .collect();
        for vault_id in new {
            let key = account
                .take_vault_key(vault_id)
                .ok_or(ClientError::InvalidServerResponse)?;
            let mut vault = VaultSync::new(key, &self.unlocked, self.vaults.next_device_seq())?;
            vault.persist();
            index::track_new(&mut vault);
            self.vaults.insert(vault);
            refetch.push(vault_id);
        }
        self.vaults.catalog = catalog;
        self.vaults.update_read_only(!self.alarms.is_empty());
        changeset.append(self.vaults.take_writes());
        Ok(refetch)
    }

    /// The cross-vault missing-data check after a complete fetch of every vault (ADR 0081 §0
    /// item 2): a note per revoked device whose changes the server lost.
    pub(super) fn report_cutoff_gaps(&self, ui: &mut dyn Ui) {
        let open: Vec<&VaultSync> = self
            .vaults
            .all()
            .iter()
            .filter(|v| self.vaults.is_open(v.vault_id()))
            .collect();
        for (device, head, cutoff) in vaults::revoked_cutoff_gaps(&open) {
            ui.note(&format!(
                "Changes of the removed device {} are missing: the server accepted its changes \
                 up to number {cutoff}, but sent only up to number {head}.",
                hex(device.as_bytes())
            ));
        }
    }

    // --- Vault changes (§A3–§A5) ----------------------------------------------------------------

    /// Creates an owned vault named `name` (§A3): the account change over the device session,
    /// a driver for the new vault, and its name as the vault's first op. Returns its id.
    ///
    /// # Errors
    /// [`CliError::BadInput`] for an empty or too long name; those of
    /// [`rizzy_client::vaults::create_vault`] and of the transport.
    pub async fn create_vault(&mut self, ui: &mut dyn Ui, name: &str) -> Result<VaultId, CliError> {
        check_name(name)?;
        self.sync(ui).await?;
        self.check_writable()?;
        let account = self
            .account
            .as_deref()
            .ok_or(CliError::Client(ClientError::Internal))?;
        let mut pending = vaults::create_vault(&mut self.rng, account, &self.unlocked)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self
                .call_empty(paths::ACCOUNT_COMMIT, pending.commit_request())
                .await
            {
                Ok(()) => break,
                Err(CliError::Server(ErrorCode::StateConflict)) if attempt < COMMIT_ATTEMPTS => {
                    self.refresh(ui).await?;
                    let account = self
                        .account
                        .as_deref()
                        .ok_or(CliError::Client(ClientError::Internal))?;
                    pending = pending.on_state_conflict(&mut self.rng, account, &self.unlocked)?;
                }
                Err(e) => {
                    if e.outcome_unknown() {
                        ui.note(
                            "Whether the server created the vault is unknown. If it did, it \
                             appears as \"Untitled vault\" in `rv vault list` after the next \
                             `rv sync`; name it with `rv vault rename`.",
                        );
                    }
                    return Err(e);
                }
            }
        }
        let account = self
            .account
            .as_deref_mut()
            .ok_or(CliError::Client(ClientError::Internal))?;
        let created = pending
            .finalize(account)?
            .ok_or(CliError::Client(ClientError::Internal))?;
        let vault_id = created.key.vault_id();
        let mut vault = VaultSync::new(created.key, &self.unlocked, self.vaults.next_device_seq())?;
        vault.persist();
        index::track_new(&mut vault);
        self.vaults.insert(vault);
        self.flush().await?;
        // The account answer moves this device's pin and lists the new vault in the catalog.
        self.refresh(ui).await?;
        self.rename_vault(vault_id, name).await?;
        Ok(vault_id)
    }

    /// Writes `name` as the name of `vault_id` (§A4); the Personal vault is refused.
    ///
    /// # Errors
    /// [`ClientError::PersonalVaultProtected`]; [`CliError::BadInput`] for an empty or too
    /// long name; those of [`rizzy_client::vaults::rename_vault`].
    pub async fn rename_vault(&mut self, vault_id: VaultId, name: &str) -> Result<(), CliError> {
        check_name(name)?;
        if self.vaults.catalog().personal() == Some(vault_id) {
            return Err(CliError::Client(ClientError::PersonalVaultProtected));
        }
        self.check_vault_writable(vault_id)?;
        let (catalog, vault) = self.vaults.with_catalog_mut(vault_id)?;
        let done = vaults::rename_vault(
            &mut self.rng,
            &self.unlocked,
            catalog,
            vault,
            name,
            now_ms(),
        );
        self.flush().await?;
        Ok(done?)
    }

    /// Deletes the owned vault `vault_id` (§A5). Unless `with_items`, every item of it, its
    /// trash included, is moved to the Personal vault first; the delete itself goes over a
    /// fresh OPAQUE session this device's password opens. Returns how many items were moved.
    ///
    /// # Errors
    /// [`ClientError::PersonalVaultProtected`]; [`CliError::BadInput`] when a move did not
    /// finish (nothing is deleted then); those of [`rizzy_client::vaults::delete_vault`] and
    /// of the transport.
    pub async fn delete_vault(
        &mut self,
        ui: &mut dyn Ui,
        login_name: &str,
        vault_id: VaultId,
        with_items: bool,
    ) -> Result<usize, CliError> {
        let personal = self.personal()?;
        if personal == vault_id {
            return Err(CliError::Client(ClientError::PersonalVaultProtected));
        }
        self.check_vault_writable(vault_id)?;
        let mut moved = 0;
        if !with_items {
            let items = user_items(
                self.vaults.require(vault_id)?,
                &[ItemLifecycle::Active, ItemLifecycle::Trashed],
            );
            for item in items {
                let (_, done) = self.move_item(ui, vault_id, item, personal).await?;
                if !done {
                    return Err(CliError::BadInput(
                        "an item of the vault is not moved to Personal yet (the server has not \
                         stored its copy); nothing was deleted. Run `rv sync`, then try again",
                    ));
                }
                moved += 1;
            }
        }
        let reauth = self.reauth(ui, login_name).await?;
        let mut token = copy_token(reauth.bearer_token());
        drop(reauth);
        let account = self
            .account
            .as_deref()
            .ok_or(CliError::Client(ClientError::Internal))?;
        let mut pending = vaults::delete_vault(&mut self.rng, account, &self.unlocked, vault_id)?;
        let (mut attempt, mut renewed) = (0, false);
        loop {
            attempt += 1;
            let sent = self
                .http
                .post_empty(
                    paths::ACCOUNT_COMMIT,
                    pending.commit_request(),
                    Auth::Bearer(&token),
                )
                .await;
            match sent {
                Ok(()) => break,
                Err(CliError::Server(ErrorCode::FreshSessionRequired)) if !renewed => {
                    renewed = true;
                    let reauth = self.reauth(ui, login_name).await?;
                    token = copy_token(reauth.bearer_token());
                }
                Err(CliError::Server(ErrorCode::StateConflict)) if attempt < COMMIT_ATTEMPTS => {
                    self.refresh(ui).await?;
                    let account = self
                        .account
                        .as_deref()
                        .ok_or(CliError::Client(ClientError::Internal))?;
                    pending = pending.on_state_conflict(&mut self.rng, account, &self.unlocked)?;
                }
                Err(e) => {
                    if e.outcome_unknown() {
                        ui.note(
                            "Whether the server deleted the vault is unknown; the next \
                             `rv sync` shows it.",
                        );
                    }
                    return Err(e);
                }
            }
        }
        let account = self
            .account
            .as_deref_mut()
            .ok_or(CliError::Client(ClientError::Internal))?;
        pending.finalize(account)?;
        self.vaults.remove(vault_id);
        self.pending_moves
            .retain(|m| m.source_vault != vault_id && m.target_vault != vault_id);
        self.commit(
            core::iter::once(Write::DropVault {
                vault_id: vault_id.to_bytes(),
            })
            .collect(),
        )
        .await?;
        // The account answer moves this device's pin and drops the vault from the catalog.
        self.refresh(ui).await?;
        Ok(moved)
    }

    // --- Moves and copies (§A6) -----------------------------------------------------------------

    /// Copies `item` of `source` to `target` (§A6 step 1), attachments included, and returns
    /// the new item's id. A trashed item stays trashed in the copy.
    ///
    /// # Errors
    /// Those of [`rizzy_client::vaults::copy_item`], of the attachment transfer and of the
    /// transport.
    pub async fn copy_item(
        &mut self,
        ui: &mut dyn Ui,
        source: VaultId,
        item: ItemId,
        target: VaultId,
    ) -> Result<ItemId, CliError> {
        self.check_vault_writable(target)?;
        self.vaults.require(source)?;
        let copied = {
            let (from, to) = self.vaults.pair_mut(source, target)?;
            vaults::copy_item(&mut self.rng, &self.unlocked, from, item, to, now_ms())
        };
        self.flush().await?;
        let copy = copied?;
        self.commit(core::iter::once(copy.index_usage).collect())
            .await?;
        if !copy.attachments.is_empty() {
            self.online(ui).await?;
            self.carry_attachments(source, item, target, copy.item_id, copy.attachments)
                .await?;
        }
        Ok(copy.item_id)
    }

    /// Moves `item` of `source` to `target` (§A6 steps 1–3): the `pending_move` row, the copy,
    /// the target uploaded with every attachment, then the source trashed and purged. Returns
    /// the new id and whether the move finished (`false`: the row stays, and the next sync
    /// resumes it).
    ///
    /// # Errors
    /// Those of [`PendingMove`], of the attachment transfer and of the transport; the row
    /// stays and a later sync resumes the move.
    pub async fn move_item(
        &mut self,
        ui: &mut dyn Ui,
        source: VaultId,
        item: ItemId,
        target: VaultId,
    ) -> Result<(ItemId, bool), CliError> {
        self.check_vault_writable(source)?;
        self.check_vault_writable(target)?;
        let pending = PendingMove::new(&mut self.rng, self.vaults.require(source)?, item, target)?;
        // INV-104: durable before the first op of the copy.
        self.commit(core::iter::once(pending.row_write()).collect())
            .await?;
        self.pending_moves.push(pending);
        self.online(ui).await?;
        let done = self.drive_move(ui, pending, false).await?;
        Ok((pending.target_item, done))
    }

    /// Resumes every move a `pending_move` row holds (INV-104): a target already stored is not
    /// created again, a source not yet purged is purged. Moves whose vaults are not open here
    /// wait.
    pub(super) async fn resume_moves(&mut self, ui: &mut dyn Ui) -> Result<(), CliError> {
        let moves: Vec<PendingMove> = self
            .pending_moves
            .iter()
            .copied()
            .filter(|m| self.vaults.is_open(m.source_vault) && self.vaults.is_open(m.target_vault))
            .collect();
        let mut waiting = 0;
        for pending in moves {
            if !self.drive_move(ui, pending, true).await? {
                waiting += 1;
            }
        }
        if waiting > 0 {
            ui.note(&format!(
                "{waiting} item moves wait for the server to store their copies; the next \
                 `rv sync` goes on with them."
            ));
        }
        Ok(())
    }

    /// One move from wherever it stands. `resumed`: a row an earlier run left, whose copy's
    /// attachments are checked on the server before the source goes.
    async fn drive_move(
        &mut self,
        ui: &mut dyn Ui,
        pending: PendingMove,
        resumed: bool,
    ) -> Result<bool, CliError> {
        let copied = {
            let (source, target) = self
                .vaults
                .pair_mut(pending.source_vault, pending.target_vault)?;
            pending.copy(&mut self.rng, &self.unlocked, source, target, now_ms())
        };
        self.flush().await?;
        let copy = match copied {
            Ok(copy) => copy,
            // The source is gone (purged by this move before an interruption, or elsewhere):
            // only the purge's upload and the row are left.
            Err(ClientError::UnknownItem) if resumed => {
                return self.finish_move(ui, pending).await;
            }
            Err(e) => return Err(e.into()),
        };
        self.commit(core::iter::once(copy.index_usage).collect())
            .await?;
        let mut carry = copy.attachments;
        if resumed && !copy.created {
            carry.extend(self.unstored_attachments(pending, copy.item_id).await?);
        }
        if !carry.is_empty() {
            self.carry_attachments(
                pending.source_vault,
                pending.source_item,
                pending.target_vault,
                copy.item_id,
                carry,
            )
            .await?;
        }
        self.finish_move(ui, pending).await
    }

    /// Step 2 of a move, every attachment of the copy stored: the target uploaded, then the
    /// source trashed and purged, uploaded, and the row dropped. Returns whether the move is
    /// done.
    async fn finish_move(
        &mut self,
        ui: &mut dyn Ui,
        pending: PendingMove,
    ) -> Result<bool, CliError> {
        self.upload_vault(ui, pending.target_vault).await?;
        let step = {
            let (source, target) = self
                .vaults
                .pair_mut(pending.source_vault, pending.target_vault)?;
            pending.finish(
                &mut self.rng,
                &self.unlocked,
                source,
                target,
                true,
                now_ms(),
            )
        };
        self.flush().await?;
        match step? {
            MoveStep::AwaitTarget => Ok(false),
            MoveStep::SourcePurged => {
                self.upload_vault(ui, pending.source_vault).await?;
                self.commit(core::iter::once(pending.done_write()).collect())
                    .await?;
                self.pending_moves.retain(|m| *m != pending);
                Ok(true)
            }
        }
    }

    /// The attachments a resumed copy lists but the server does not hold completely: each is
    /// removed from the copy, and the source's matching attachment is returned to be carried
    /// again.
    async fn unstored_attachments(
        &mut self,
        pending: PendingMove,
        target_item: ItemId,
    ) -> Result<Vec<AttachmentInfo>, CliError> {
        let target = pending.target_vault;
        let listed = self.vaults.require(target)?.attachments(target_item);
        let mut again = Vec::new();
        for attachment in listed {
            match self
                .download_attachment(target, target_item, attachment.attachment_id)
                .await
            {
                Ok(_) => {}
                Err(e) if attachment_missing(&e) => {
                    let removed = self.vaults.require_mut(target)?.remove_attachment(
                        &mut self.rng,
                        &self.unlocked,
                        target_item,
                        attachment.attachment_id,
                        now_ms(),
                    );
                    self.flush().await?;
                    removed?;
                    let source = self.vaults.require(pending.source_vault)?;
                    if let Some(original) = source
                        .attachments(pending.source_item)
                        .into_iter()
                        .find(|a| {
                            a.name == attachment.name
                                && a.mime == attachment.mime
                                && a.size == attachment.size
                        })
                    {
                        again.push(original);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(again)
    }

    /// Downloads each of `attachments` of `source_item` and uploads it again on `target_item`
    /// under a new id and key (§A6 step 1).
    async fn carry_attachments(
        &mut self,
        source: VaultId,
        source_item: ItemId,
        target: VaultId,
        target_item: ItemId,
        attachments: Vec<AttachmentInfo>,
    ) -> Result<(), CliError> {
        for attachment in attachments {
            let data = self
                .download_attachment(source, source_item, attachment.attachment_id)
                .await?;
            let added = self.vaults.require_mut(target)?.add_attachment(
                &mut self.rng,
                &self.unlocked,
                target_item,
                &attachment.name,
                &attachment.mime,
                &data,
                now_ms(),
            );
            self.flush().await?;
            let upload = added?;
            self.call_empty(paths::ATTACHMENTS_CREATE, &upload.create_request())
                .await?;
            for index in 0..upload.chunk_count() {
                let request = upload.chunk_request(index)?;
                self.call_empty(paths::ATTACHMENTS_UPLOAD_CHUNK, &request)
                    .await?;
            }
        }
        Ok(())
    }

    /// Downloads and opens one attachment of `item` in `vault_id` (ADR 0054).
    async fn download_attachment(
        &mut self,
        vault_id: VaultId,
        item: ItemId,
        attachment_id: AttachmentId,
    ) -> Result<Zeroizing<Vec<u8>>, CliError> {
        let mut download = self
            .vaults
            .require(vault_id)?
            .begin_download(item, attachment_id)?;
        let answer: GetAttachmentResponse = self
            .call(paths::ATTACHMENTS_GET, &download.get_request())
            .await?;
        self.vaults
            .require(vault_id)?
            .accept_attachment_key(&mut download, &answer)?;
        for index in 0..download.chunk_count() {
            let request = download.chunk_request(index)?;
            let chunk: DownloadChunkResponse = self
                .call(paths::ATTACHMENTS_DOWNLOAD_CHUNK, &request)
                .await?;
            download.accept_response(index, &chunk)?;
        }
        Ok(download.finish()?)
    }
}

/// The pending moves of the cache rows, for [`Device::open`].
pub(super) fn moves_of(rows: &[PendingMoveRow]) -> Vec<PendingMove> {
    rows.iter().map(PendingMove::of_row).collect()
}
