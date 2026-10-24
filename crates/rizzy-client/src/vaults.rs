// SPDX-License-Identifier: AGPL-3.0-only

//! Several vaults per account, none shared ([ADR 0081] Part A).
//!
//! - **The vault directory** ([`directory`], `ACCOUNT_SETTINGS` tag `0x0002`, §A2): the
//!   account's authenticated list of the vaults it holds and what each is (the Personal vault,
//!   owned vaults; Part B's kinds are parsed and kept, never opened).
//! - **The catalog** ([`VaultCatalog`], §A2 "Completeness check", INV-102): the directory
//!   compared with the self-grants the server served. A listed vault without a self-grant is
//!   being withheld; a served self-grant the directory does not list is not opened; both raise
//!   an alarm. Without a directory (an account from before Part A, §A10) a single served vault
//!   is the Personal vault, and two or more raise the same alarm.
//! - **Creating and deleting** ([`create_vault`], [`delete_vault`], §A3, §A5): one atomic
//!   account change each, `settings_seq + 1` with the directory changed and the new
//!   `vault_create` / `vault_delete` field. The Personal vault is never deleted (INV-101).
//! - **Names** ([`vault_name`], [`rename_vault`], §A4): `vault.name` of the vault-settings
//!   item (`0xF001`), an ordinary op. The Personal vault has none: its client label is
//!   "Personal", localised, and a `vault.name` in it is ignored (§A1).
//! - **Copy and move** ([`copy_item`], [`PendingMove`], §A6, INV-104): a copy is a new item in
//!   the target vault through the importer path; a move is a copy, then, only after the server
//!   acknowledged the target, a `Trash` and a `Purge` op on the source. A pending-move row
//!   written before the copy makes a crash resume instead of lose: the worst case is a duplicate.
//! - **One `device_seq` per device** ([`crate::sync::DeviceCounters`], §A7) and the
//!   revocation cut-off check over every vault ([`revoked_cutoff_gaps`], §0 item 2).
//!
//! Items are identified by `(vault_id, item_id)` in every structure (INV-103): nothing here
//! looks an item up by its id alone.
//!
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

pub mod directory;

use core::fmt;

use rizzy_core::envelope::purpose::VaultKeySelfGrantCtx;
use rizzy_core::ids::{DeviceId, ItemId, VaultId};
use rizzy_core::item::key::FieldKey;
use rizzy_core::item::schema::VAULT_NAME;
use rizzy_core::item::types::{ItemType, effective_vault_settings};
use rizzy_core::item::value::{Value, ValueRef};
use rizzy_core::keys::VaultKey;
use rizzy_core::rng::CryptoRng;
use rizzy_core::sign::{AccountState, CasRetry};
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
use rizzy_proto::wire::Id;
use rizzy_sync::merge::ItemLifecycle;
use zeroize::Zeroizing;

pub use directory::{
    DIRECTORY_FORMAT, DirectoryEntry, DirectoryKind, MembershipPin, TAG_VAULT_DIRECTORY,
    VaultDirectory,
};

use crate::account::{AccountPin, VerifiedAccount};
use crate::attachments::AttachmentInfo;
use crate::device::UnlockedDevice;
use crate::error::{ClientError, internal};
use crate::items::{FieldEdit, ImportWrite};
use crate::settings::{AccountSettingsRecord, account_settings, seal_commit};
use crate::store::rows::{PendingMoveRow, Write};
use crate::sync::VaultSync;

/// The longest vault name the clients accept, in Unicode scalar values ([ADR 0081] §A4, §D).
///
/// [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md
pub const MAX_VAULT_NAME_CHARS: usize = 64;

// --- The catalog: the directory against the served self-grants (§A2, INV-102) ---------------

/// Whether this client opens a vault the account holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultStatus {
    /// Listed (or the legacy Personal vault) and served: open.
    Open,
    /// Listed, but the server served no self-grant for it: being withheld (INV-102). A host
    /// with a cache keeps it read-only from there.
    Withheld,
    /// A kind this build cannot verify: a shared or joined vault (Part B) or an unknown kind.
    /// Never opened; shown as "This vault needs a newer rizzy-vault" (§A12).
    NeedsUpdate,
}

/// One vault of the catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    /// The vault.
    pub vault_id: VaultId,
    /// What the directory says it is (the legacy rule's Personal vault without a directory).
    pub kind: DirectoryKind,
    /// Whether it is opened.
    pub status: VaultStatus,
}

/// What the completeness check found wrong (INV-102). Each is an alarm the host shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultAlarm {
    /// The directory lists this vault, but the server served no self-grant for it.
    Withheld(VaultId),
    /// The server served a self-grant for a vault the directory does not list; not opened.
    Unlisted(VaultId),
    /// No directory, and the server served two or more self-grants: which one is the Personal
    /// vault is unknown, so none is opened for writing.
    NoDirectory,
}

/// The account's vaults as this client sees them: the directory checked against the served
/// self-grants (module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultCatalog {
    /// The Personal vault; `None` only under [`VaultAlarm::NoDirectory`].
    personal: Option<VaultId>,
    /// Every vault the directory lists (or the legacy Personal vault), ascending by id.
    entries: Vec<CatalogEntry>,
    /// The alarms.
    alarms: Vec<VaultAlarm>,
    /// Whether the record holds a directory (§A10: one is written with the next settings
    /// write or vault change otherwise).
    has_directory: bool,
}

impl VaultCatalog {
    /// The completeness check (module docs) of `directory` against `served`, the vaults whose
    /// self-grants the latest account answer carried.
    #[must_use]
    pub fn check(directory: Option<&VaultDirectory>, served: &[VaultId]) -> Self {
        let mut alarms = Vec::new();
        let Some(directory) = directory else {
            return match served {
                [personal] => Self {
                    personal: Some(*personal),
                    entries: vec![CatalogEntry {
                        vault_id: *personal,
                        kind: DirectoryKind::Personal,
                        status: VaultStatus::Open,
                    }],
                    alarms,
                    has_directory: false,
                },
                _ => Self {
                    personal: None,
                    entries: Vec::new(),
                    alarms: vec![VaultAlarm::NoDirectory],
                    has_directory: false,
                },
            };
        };
        let mut entries = Vec::with_capacity(directory.entries().len());
        for entry in directory.entries() {
            let served_here = served.contains(&entry.vault_id);
            let status = if !entry.kind.openable() {
                VaultStatus::NeedsUpdate
            } else if served_here {
                VaultStatus::Open
            } else {
                alarms.push(VaultAlarm::Withheld(entry.vault_id));
                VaultStatus::Withheld
            };
            entries.push(CatalogEntry {
                vault_id: entry.vault_id,
                kind: entry.kind.clone(),
                status,
            });
        }
        for vault_id in served {
            if directory.entry(*vault_id).is_none() {
                alarms.push(VaultAlarm::Unlisted(*vault_id));
            }
        }
        Self {
            personal: directory.personal(),
            entries,
            alarms,
            has_directory: true,
        }
    }

    /// The catalog of a verified account: its settings record's directory against the
    /// self-grants its answer served.
    ///
    /// # Errors
    /// As [`account_settings`]: a record this build cannot read fails the call
    /// ([`ClientError::SettingsUpdateRequired`], [`ClientError::InvalidServerResponse`]).
    pub fn of_account(
        account: &VerifiedAccount,
        unlocked: &UnlockedDevice,
    ) -> Result<Self, ClientError> {
        let record = account_settings(account, unlocked)?;
        Ok(Self::check(
            record.vault_directory(),
            &account.served_vault_ids(),
        ))
    }

    /// The Personal vault, the default target of every new item (§A1, §A8); `None` only under
    /// [`VaultAlarm::NoDirectory`].
    #[must_use]
    pub const fn personal(&self) -> Option<VaultId> {
        self.personal
    }

    /// Every vault the directory lists, ascending by id.
    #[must_use]
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// The vaults this client opens, ascending by id.
    pub fn open_vaults(&self) -> impl Iterator<Item = VaultId> + '_ {
        self.entries
            .iter()
            .filter(|e| e.status == VaultStatus::Open)
            .map(|e| e.vault_id)
    }

    /// Whether `vault_id` is open.
    #[must_use]
    pub fn is_open(&self, vault_id: VaultId) -> bool {
        self.open_vaults().any(|v| v == vault_id)
    }

    /// The alarms (INV-102). Empty for an honest server.
    #[must_use]
    pub fn alarms(&self) -> &[VaultAlarm] {
        &self.alarms
    }

    /// Whether the record holds a directory.
    #[must_use]
    pub const fn has_directory(&self) -> bool {
        self.has_directory
    }

    /// The vaults of `previous` that this catalog no longer lists: deleted on another device
    /// (§A5), whose cache rows and index rows a host drops ([`Write::DropVault`]).
    #[must_use]
    pub fn dropped_since(&self, previous: &Self) -> Vec<VaultId> {
        if !self.has_directory {
            return Vec::new();
        }
        previous
            .entries
            .iter()
            .map(|e| e.vault_id)
            .filter(|v| !self.entries.iter().any(|e| e.vault_id == *v))
            .collect()
    }
}

/// The directory a vault change starts from: the record's, or, for an account without one,
/// the legacy rule's (§A10). Refuses an account whose catalog raises an alarm: no vault change
/// is built on a vault set the server serves inconsistently.
fn current_directory(
    record: &AccountSettingsRecord,
    account: &VerifiedAccount,
) -> Result<VaultDirectory, ClientError> {
    let served = account.served_vault_ids();
    let catalog = VaultCatalog::check(record.vault_directory(), &served);
    if !catalog.alarms().is_empty() {
        return Err(ClientError::VaultSetMismatch);
    }
    match record.vault_directory() {
        Some(d) => Ok(d.clone()),
        None => catalog
            .personal()
            .map(VaultDirectory::personal_only)
            .ok_or(ClientError::VaultSetMismatch),
    }
}

// --- Creating and deleting (§A3, §A5) --------------------------------------------------------

/// What a pending vault change does.
enum VaultOp {
    /// A new owned vault: its key at epoch 0 and its self-grant under the current account key.
    Create {
        /// The vault key.
        key: VaultKey,
        /// The self-grant the commit carries.
        grant: VaultSelfGrant,
    },
    /// Deleting an owned vault.
    Delete(VaultId),
}

/// A vault created by a committed change: the host builds its driver from the key and keeps the
/// self-grant with the account's cache rows.
pub struct CreatedVault {
    /// The vault key at epoch 0.
    pub key: VaultKey,
    /// The vault's self-grant.
    pub grant: VaultSelfGrant,
}

impl fmt::Debug for CreatedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedVault")
            .field("vault_id", &self.key.vault_id())
            .finish_non_exhaustive()
    }
}

/// A vault change waiting for `account/commit` (module docs), built like a settings change
/// ([`crate::settings::PendingSettingsChange`]) with the vault field added.
pub struct PendingVaultChange {
    /// What it does.
    op: VaultOp,
    /// The state it was built on.
    base: AccountState,
    /// The request.
    request: CommitChangeRequest,
    /// The pin the account takes on success.
    pin: AccountPin,
}

impl fmt::Debug for PendingVaultChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingVaultChange")
            .field(
                "op",
                &match &self.op {
                    VaultOp::Create { .. } => "create",
                    VaultOp::Delete(_) => "delete",
                },
            )
            .field("vault_id", &self.vault_id())
            .field("state_seq", &self.pin.state.state_seq)
            .finish_non_exhaustive()
    }
}

/// Builds a change for `op` on the current account: the record with the directory changed,
/// sealed at `settings_seq + 1`, and the vault field.
fn build<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
    op: VaultOp,
) -> Result<PendingVaultChange, ClientError> {
    let mut record = account_settings(account, unlocked)?;
    let directory = current_directory(&record, account)?;
    let directory = match &op {
        VaultOp::Create { key, .. } => directory.with_owned(key.vault_id())?,
        VaultOp::Delete(vault_id) => directory.without(*vault_id)?,
    };
    record.set_vault_directory(directory);
    let plaintext = record.encode()?;
    let (mut request, pin) = seal_commit(rng, account, unlocked, &plaintext)?;
    match &op {
        VaultOp::Create { grant, .. } => request.vault_create = Some(grant.clone()),
        VaultOp::Delete(vault_id) => {
            request.vault_delete = Some(Id::from_bytes(vault_id.to_bytes()));
        }
    }
    Ok(PendingVaultChange {
        op,
        base: account.pin.state.clone(),
        request,
        pin,
    })
}

/// A new owned vault (§A3): a random `vault_id`, a vault key at epoch 0, its
/// `VAULT_KEY_SELF_GRANT` under the current account key (purpose 0x0020, context
/// `account_id ‖ vault_id ‖ u32 account_key_epoch ‖ u32 0`, as signup builds it), and one atomic
/// account change: the directory with the new kind-2 entry at `settings_seq + 1` and
/// `vault_create`. After the commit the host writes the vault's name ([`rename_vault`]) as
/// its first op.
///
/// # Errors
/// [`ClientError::VaultLimitReached`] at 64 owned vaults or 128 directory entries;
/// [`ClientError::VaultSetMismatch`] while the catalog raises an alarm;
/// [`ClientError::AccountKeyRotated`] if `unlocked` holds an older account key; those of
/// [`account_settings`]; [`ClientError::Internal`].
pub fn create_vault<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
) -> Result<PendingVaultChange, ClientError> {
    let state = &account.pin.state;
    if !state.matches_account_key(&unlocked.account_key) {
        return Err(ClientError::AccountKeyRotated);
    }
    let vault_id = VaultId::generate(rng);
    let key = VaultKey::generate(rng, vault_id, 0);
    let envelope = unlocked
        .account_key
        .wrap_vault_key(
            rng,
            &VaultKeySelfGrantCtx {
                account_id: account.account_id,
                vault_id,
                account_key_epoch: state.account_key_epoch,
                vault_key_epoch: 0,
            },
            &key,
        )
        .map_err(internal)?;
    let grant = VaultSelfGrant {
        vault_id: Id::from_bytes(vault_id.to_bytes()),
        account_key_epoch: state.account_key_epoch,
        vault_key_epoch: 0,
        envelope: KeyEnvelope::new(envelope).map_err(internal)?,
    };
    build(rng, account, unlocked, VaultOp::Create { key, grant })
}

/// Deleting an owned vault (§A5): the directory without its entry at `settings_seq + 1` and
/// `vault_delete`. The server needs a fresh OPAQUE session for it; the host asks for the
/// re-authentication first. Items to keep are moved to the Personal vault before
/// ([`PendingMove`]); everything left in the vault, its trash included, goes with it.
///
/// # Errors
/// [`ClientError::PersonalVaultProtected`] for the Personal vault (INV-101);
/// [`ClientError::UnknownVault`] for a vault the directory does not list as an unshared owned
/// vault; as [`create_vault`] otherwise.
pub fn delete_vault<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
    vault_id: VaultId,
) -> Result<PendingVaultChange, ClientError> {
    build(rng, account, unlocked, VaultOp::Delete(vault_id))
}

impl PendingVaultChange {
    /// The `account/commit` request.
    #[must_use]
    pub const fn commit_request(&self) -> &CommitChangeRequest {
        &self.request
    }

    /// The vault the change creates or deletes.
    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        match &self.op {
            VaultOp::Create { key, .. } => key.vault_id(),
            VaultOp::Delete(vault_id) => *vault_id,
        }
    }

    /// After the server acknowledged the commit: `account` takes the new state and settings as
    /// its pin. A creation hands back the new vault's key and self-grant.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if `account` moved since the change was built.
    pub fn finalize(
        self,
        account: &mut VerifiedAccount,
    ) -> Result<Option<CreatedVault>, ClientError> {
        if account.pin.state != self.base {
            return Err(ClientError::InvalidInput);
        }
        account.settings.clone_from(&self.pin.settings);
        account.pin = self.pin;
        Ok(match self.op {
            VaultOp::Create { key, grant } => Some(CreatedVault { key, grant }),
            VaultOp::Delete(_) => None,
        })
    }

    /// After `state_conflict` and a re-fetch whose verified result is `current`: the same
    /// change (the same new vault, or the same vault to delete) rebuilt on the current state.
    ///
    /// # Errors
    /// [`ClientError::Rollback`] or [`ClientError::Fork`] as `CasRetry` decides; as
    /// [`create_vault`] and [`delete_vault`] for the rebuilt change.
    pub fn on_state_conflict<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        current: &VerifiedAccount,
        unlocked: &UnlockedDevice,
    ) -> Result<Self, ClientError> {
        match self.base.cas_retry(&current.pin.state) {
            CasRetry::Rollback => Err(ClientError::Rollback),
            CasRetry::Fork => Err(ClientError::Fork),
            CasRetry::Reapply | CasRetry::Restart => build(rng, current, unlocked, self.op),
        }
    }
}

// --- Names (§A1, §A4) ------------------------------------------------------------------------

/// The vault-settings item of `vault` (ADR 0018 §8): the lowest id among its live items of
/// type `0xF001`.
fn settings_item(vault: &VaultSync) -> Option<ItemId> {
    effective_vault_settings(vault.item_ids().into_iter().filter(|id| {
        vault.item_type(*id) == Some(ItemType::VAULT_SETTINGS)
            && matches!(
                vault.item_lifecycle(*id),
                ItemLifecycle::Active | ItemLifecycle::Trashed
            )
    }))
}

/// The name `vault.name` gives an owned vault, if one was written. `None` for a vault without
/// one ("Untitled vault" in the clients, §A3 step 3); the Personal vault's name is always the
/// client's localised label, so a host never asks for it (§A1).
#[must_use]
pub fn vault_name(vault: &VaultSync) -> Option<Zeroizing<String>> {
    let item = settings_item(vault)?;
    let value = vault.field_value(item, VAULT_NAME)?;
    match value.decode() {
        Ok(ValueRef::Text(text)) if !text.is_empty() => Some(Zeroizing::new(text.to_owned())),
        _ => None,
    }
}

/// How a client labels a vault (§A1, §A3 step 3).
#[derive(Clone, PartialEq, Eq)]
pub enum VaultLabel {
    /// The Personal vault: the client's localised "Personal", whatever `vault.name` says.
    Personal,
    /// An owned vault with a name.
    Named(Zeroizing<String>),
    /// An owned vault without one yet: "Untitled vault".
    Untitled,
}

impl fmt::Debug for VaultLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Personal => "Personal",
            Self::Named(_) => "Named([REDACTED])",
            Self::Untitled => "Untitled",
        })
    }
}

/// The label of `vault` under `catalog`: a `vault.name` in the Personal vault is ignored (§A1).
#[must_use]
pub fn vault_label(catalog: &VaultCatalog, vault: &VaultSync) -> VaultLabel {
    if catalog.personal() == Some(vault.vault_id()) {
        return VaultLabel::Personal;
    }
    vault_name(vault).map_or(VaultLabel::Untitled, VaultLabel::Named)
}

/// Sets an owned vault's name (§A3 step 3, §A4): an edit of `vault.name` in its vault-settings
/// item, or the item itself when the vault has none yet. An ordinary op, synced and merged like
/// any other.
///
/// # Errors
/// [`ClientError::PersonalVaultProtected`] when `catalog` names `vault` the Personal vault;
/// [`ClientError::InvalidInput`] for an empty name (after trimming) or one over
/// [`MAX_VAULT_NAME_CHARS`]; the errors of the own-op writer.
pub fn rename_vault<R: CryptoRng + ?Sized>(
    rng: &mut R,
    unlocked: &UnlockedDevice,
    catalog: &VaultCatalog,
    vault: &mut VaultSync,
    name: &str,
    now_ms: u64,
) -> Result<(), ClientError> {
    if catalog.personal() == Some(vault.vault_id()) {
        return Err(ClientError::PersonalVaultProtected);
    }
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_VAULT_NAME_CHARS {
        return Err(ClientError::InvalidInput);
    }
    let value = Value::text(name).map_err(|_| ClientError::InvalidInput)?;
    let key = FieldKey::parse(VAULT_NAME.as_bytes()).map_err(internal)?;
    let fields = [FieldEdit {
        key: &key,
        value: &value,
    }];
    match settings_item(vault) {
        Some(item) => vault.edit_item(rng, unlocked, item, &fields, now_ms),
        None => vault
            .create_item(rng, unlocked, ItemType::VAULT_SETTINGS, &fields, now_ms)
            .map(|_| ()),
    }
}

// --- Copy and move (§A6, INV-104) ------------------------------------------------------------

/// What a copy wrote, and what the host still carries over: each attachment of the source is
/// downloaded, decrypted and uploaded again under a new id and key in the target
/// ([`VaultSync::add_attachment`] on the new item).
#[derive(Debug)]
pub struct ItemCopy {
    /// The new item in the target vault.
    pub item_id: ItemId,
    /// Whether this call wrote it (`false`: a resumed move found it there already).
    pub created: bool,
    /// The source's attachments the new item does not list yet, by name, type and size.
    pub attachments: Vec<AttachmentInfo>,
    /// The index write that carries the source's `last_used_ms` and `use_count` to the new
    /// item (§A6 step 1), for a host with a local index.
    pub index_usage: Write,
}

/// Copies `item` of `source` into `target` under `target_item` (module docs): the importer
/// path, without the source's `attachment/…` fields (the attachments come again under new ids).
#[expect(
    clippy::too_many_arguments,
    reason = "both vaults, the item on each side, and the writer's rng, device and time"
)]
fn copy_as<R: CryptoRng + ?Sized>(
    rng: &mut R,
    unlocked: &UnlockedDevice,
    source: &VaultSync,
    item: ItemId,
    target: &mut VaultSync,
    target_item: ItemId,
    keep_trashed: bool,
    now_ms: u64,
) -> Result<ItemCopy, ClientError> {
    if source.vault_id() == target.vault_id() {
        return Err(ClientError::InvalidInput);
    }
    let created = if target.merge(target_item).is_some() || target.holds_unapplied(target_item) {
        false
    } else {
        let copy = source.copy_of(item, rng)?;
        let writes: Vec<ImportWrite<'_>> = copy
            .writes
            .iter()
            .filter(|(_, key, _)| !key.as_str().starts_with("attachment/"))
            .map(|(source, key, value)| ImportWrite {
                source: *source,
                key,
                value,
            })
            .collect();
        target.import_item_writes_as(
            rng,
            unlocked,
            target_item,
            copy.item_type,
            &writes,
            keep_trashed && copy.trashed,
            now_ms,
        )?;
        true
    };
    let present = target.attachments(target_item);
    let attachments = source
        .attachments(item)
        .into_iter()
        .filter(|a| {
            !present
                .iter()
                .any(|p| p.name == a.name && p.mime == a.mime && p.size == a.size)
        })
        .collect();
    Ok(ItemCopy {
        item_id: target_item,
        created,
        attachments,
        index_usage: Write::IndexCopyUsage {
            from: (source.vault_id().to_bytes(), item.to_bytes()),
            to: (target.vault_id().to_bytes(), target_item.to_bytes()),
        },
    })
}

/// Copies `item` of `source` into `target` (§A6 step 1): a new item with a new id, its key
/// wrapped under the target's vault key, a create op of this device; field values, element ids,
/// tags, passkeys, TOTP secrets and history travel, dots and HLCs do not. A trashed source stays
/// trashed in the copy.
///
/// # Errors
/// [`ClientError::InvalidInput`] for the same vault on both sides; [`ClientError::UnknownItem`]
/// for an item that is not a live user item of `source`; [`ClientError::ExportOversizeItems`];
/// the errors of the importer path ([`VaultSync::import_item_writes`]).
pub fn copy_item<R: CryptoRng + ?Sized>(
    rng: &mut R,
    unlocked: &UnlockedDevice,
    source: &VaultSync,
    item: ItemId,
    target: &mut VaultSync,
    now_ms: u64,
) -> Result<ItemCopy, ClientError> {
    let target_item = ItemId::generate(rng);
    copy_as(
        rng,
        unlocked,
        source,
        item,
        target,
        target_item,
        true,
        now_ms,
    )
}

/// A move in progress (§A6 steps 2–3, INV-104): the source item, and the target vault with the
/// item's id there, chosen before anything is written so that a restart finds the copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingMove {
    /// The vault the item leaves.
    pub source_vault: VaultId,
    /// The item that leaves it.
    pub source_item: ItemId,
    /// The vault it goes to.
    pub target_vault: VaultId,
    /// Its id there.
    pub target_item: ItemId,
}

/// Where a move stands, for the host's next step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveStep {
    /// The copy is written: upload the target vault and the listed attachments, then call
    /// [`PendingMove::finish`] again.
    AwaitTarget,
    /// The source is trashed and purged (queued in one upload): upload the source vault and
    /// drop the pending-move row ([`PendingMove::done_write`]).
    SourcePurged,
}

impl PendingMove {
    /// A new move of `source_item` of `source` to `target`, with a fresh id there.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for the same vault on both sides;
    /// [`ClientError::UnknownItem`] for an item that is not live in `source`.
    pub fn new<R: CryptoRng + ?Sized>(
        rng: &mut R,
        source: &VaultSync,
        source_item: ItemId,
        target: VaultId,
    ) -> Result<Self, ClientError> {
        if source.vault_id() == target {
            return Err(ClientError::InvalidInput);
        }
        if !matches!(
            source.item_lifecycle(source_item),
            ItemLifecycle::Active | ItemLifecycle::Trashed
        ) || source.item_type(source_item) == Some(ItemType::VAULT_SETTINGS)
        {
            return Err(ClientError::UnknownItem);
        }
        Ok(Self {
            source_vault: source.vault_id(),
            source_item,
            target_vault: target,
            target_item: ItemId::generate(rng),
        })
    }

    /// The move of a stored `pending_move` row.
    #[must_use]
    pub fn of_row(row: &PendingMoveRow) -> Self {
        Self {
            source_vault: VaultId::from_bytes(row.source_vault_id),
            source_item: ItemId::from_bytes(row.source_item_id),
            target_vault: VaultId::from_bytes(row.target_vault_id),
            target_item: ItemId::from_bytes(row.target_item_id),
        }
    }

    /// The row a host writes before the copy (§A6 step 3), in the same transaction as nothing
    /// else: it must be durable before the first op of the copy.
    #[must_use]
    pub fn row_write(&self) -> Write {
        Write::PendingMovePut(PendingMoveRow {
            source_vault_id: self.source_vault.to_bytes(),
            source_item_id: self.source_item.to_bytes(),
            target_vault_id: self.target_vault.to_bytes(),
            target_item_id: self.target_item.to_bytes(),
        })
    }

    /// The write that drops the row once the source's purge is uploaded.
    #[must_use]
    pub fn done_write(&self) -> Write {
        Write::PendingMoveDelete {
            source_vault_id: self.source_vault.to_bytes(),
            source_item_id: self.source_item.to_bytes(),
        }
    }

    /// Step 1 of the move, resumable: the copy under [`PendingMove::target_item`], unless the
    /// target holds it already ("a target already stored is not created again"). The source
    /// item's trash state is not carried: a moved item arrives active.
    ///
    /// # Errors
    /// [`ClientError::UnknownVault`] for vaults that are not this move's; those of
    /// [`copy_item`].
    pub fn copy<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        source: &VaultSync,
        target: &mut VaultSync,
        now_ms: u64,
    ) -> Result<ItemCopy, ClientError> {
        if source.vault_id() != self.source_vault || target.vault_id() != self.target_vault {
            return Err(ClientError::UnknownVault);
        }
        copy_as(
            rng,
            unlocked,
            source,
            self.source_item,
            target,
            self.target_item,
            false,
            now_ms,
        )
    }

    /// Step 2, only after the server acknowledged the target (INV-104): `target` holds the copy
    /// and no own op or snapshot of it is unacknowledged, and the host says every attachment
    /// chunk of the copy is stored (`attachments_stored`). Then a `Trash` op (unless trashed)
    /// and a `Purge` op on the source, queued for one upload. A source already purged, or
    /// gone, needs nothing more.
    ///
    /// # Errors
    /// [`ClientError::UnknownVault`] for vaults that are not this move's; the errors of
    /// [`VaultSync::trash_item`] and [`VaultSync::purge_item`].
    pub fn finish<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        source: &mut VaultSync,
        target: &VaultSync,
        attachments_stored: bool,
        now_ms: u64,
    ) -> Result<MoveStep, ClientError> {
        if source.vault_id() != self.source_vault || target.vault_id() != self.target_vault {
            return Err(ClientError::UnknownVault);
        }
        let acknowledged = attachments_stored
            && target.merge(self.target_item).is_some()
            && target.fully_acknowledged();
        if !acknowledged {
            return Ok(MoveStep::AwaitTarget);
        }
        match source.item_lifecycle(self.source_item) {
            ItemLifecycle::Active => {
                source.trash_item(rng, unlocked, self.source_item, now_ms)?;
                source.purge_item(rng, unlocked, self.source_item, now_ms)?;
            }
            ItemLifecycle::Trashed => {
                source.purge_item(rng, unlocked, self.source_item, now_ms)?;
            }
            _ => {}
        }
        Ok(MoveStep::SourcePurged)
    }
}

// --- Revocation cut-offs over every vault (§0 item 2) ----------------------------------------

/// The cross-vault missing-data check (ADR 0021 §9 as ADR 0081 §0 item 2 replaces it): after a
/// complete Fetch of every vault, each revoked device of the account whose highest head over
/// all those vaults is below its `last_accepted_device_seq`, with that head and the cut-off.
/// Empty when nothing is missing.
#[must_use]
pub fn revoked_cutoff_gaps(vaults: &[&VaultSync]) -> Vec<(DeviceId, u64, u64)> {
    let mut seen: std::collections::BTreeMap<DeviceId, (u64, u64)> =
        std::collections::BTreeMap::new();
    for vault in vaults {
        for (device, head, cut) in vault.revoked_heads() {
            let entry = seen.entry(device).or_insert((head, cut));
            entry.0 = entry.0.max(head);
            entry.1 = entry.1.max(cut);
        }
    }
    seen.into_iter()
        .filter(|(_, (head, cut))| head < cut)
        .map(|(device, (head, cut))| (device, head, cut))
        .collect()
}

#[cfg(test)]
mod tests;
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "vector tests index hex they parse and the bytes they mutate"
)]
mod vectors;
