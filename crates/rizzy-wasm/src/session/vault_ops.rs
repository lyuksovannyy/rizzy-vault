// SPDX-License-Identifier: AGPL-3.0-only

//! The web vault's vault management and moves between vaults ([ADR 0081] §A3–§A6).
//!
//! | Action | Calls |
//! |---|---|
//! | Vault list, switcher, pickers | [`Session::vaults`], [`Session::personal_vault_id`], [`Session::vault_alarms`] |
//! | Create | [`Session::create_vault_request`] → carry → [`Session::vault_respond`] (the name is the new vault's first op) |
//! | Rename | [`Session::rename_vault`] (never the Personal vault) |
//! | Delete | [`Session::delete_vault_request`] → carry → [`Session::vault_respond`]; the server needs a fresh OPAQUE session (`server_fresh_session_required`: [`Session::refresh`], then build the request again) |
//! | Copy | [`Session::copy_item`]; then each listed attachment downloaded from the source and uploaded to the copy |
//! | Move | [`Session::move_item`], the attachments as for a copy, [`Session::move_attachments_stored`], a sync, [`Session::finish_moves`], a sync |
//!
//! A move purges its source only after the server acknowledged the copy and the host said
//! every attachment of it is stored (INV-104). A web session has no cache (CRYPTO.md §11.4):
//! its pending moves live in memory, and a lock before the purge leaves the item in both
//! vaults, a duplicate, never a loss. Deleting a vault with "Move its items to Personal" is
//! these moves into the Personal vault, a sync, then the delete: the vault's deletion removes
//! the sources, so no purge of each is needed.
//!
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

use rizzy_client::ClientError;
use rizzy_client::rizzy_core::ids::VaultId;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::vaults::{
    MAX_VAULT_NAME_CHARS, MoveStep, PendingMove, PendingVaultChange, VaultCatalog, copy_item,
    create_vault, delete_vault, rename_vault,
};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use super::{AttachmentView, Session};
use crate::error::{CoreError, CoreResult, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::items::{self, hex, item_ref, parse_ref};
use crate::vaults::{VaultAlarmView, VaultView};

/// A vault change waiting for `account/commit`.
pub(super) struct PendingVault {
    /// The change.
    change: PendingVaultChange,
    /// The name a creation writes as the vault's first op.
    name: Option<Zeroizing<String>>,
}

/// A move of this session whose source is not purged yet.
pub(super) struct WebMove {
    /// The move.
    mv: PendingMove,
    /// Whether attachments of the copy are still to be uploaded by the host.
    attachments_pending: bool,
}

impl WebMove {
    /// Whether this move touches `vault`.
    fn involves(&self, vault: VaultId) -> bool {
        self.mv.source_vault == vault || self.mv.target_vault == vault
    }
}

/// A vault name as the clients accept it (§A4): trimmed, 1 to 64 Unicode scalar values.
fn check_name(name: &str) -> CoreResult<Zeroizing<String>> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_VAULT_NAME_CHARS {
        return Err(ClientError::InvalidInput.into());
    }
    Ok(Zeroizing::new(name.to_owned()))
}

/// What a copy or move wrote: the new item, and the source's attachments the host carries
/// over (download from the source item, upload to the new one).
#[wasm_bindgen]
#[derive(Debug)]
pub struct ItemCopyView {
    /// The new item's reference.
    id: String,
    /// Whether this call wrote it.
    created: bool,
    /// The source's attachments the copy does not hold yet.
    attachments: Vec<AttachmentView>,
}

#[wasm_bindgen]
impl ItemCopyView {
    /// The new item's reference (`<vault hex>:<item hex>`).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Whether this call wrote the copy (`false`: it was there already).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn created(&self) -> bool {
        self.created
    }

    /// The source item's attachments to carry over, by their ids in the source item.
    #[must_use]
    pub fn attachments(&self) -> Vec<AttachmentView> {
        self.attachments
            .iter()
            .map(AttachmentView::duplicate)
            .collect()
    }
}

#[wasm_bindgen]
impl Session {
    /// Every vault the account's directory lists (or the legacy Personal vault, §A10): the
    /// Personal vault first, then the others by name. The host shows the Personal vault as
    /// "Personal" (localised) and an owned vault without a name as "Untitled vault".
    ///
    /// # Errors
    /// `locked`.
    pub fn vaults(&self) -> Result<Vec<VaultView>, CoreError> {
        let inner = self.inner()?;
        Ok(inner
            .vaults
            .views(|vault| inner.account.vault_bytes_used(vault)))
    }

    /// The Personal vault: the target every new item, import and save prompt preselects (§A1,
    /// §A8); `undefined` while the vault set raises an alarm that hides it.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = personalVaultId)]
    pub fn personal_vault_id(&self) -> Result<Option<String>, CoreError> {
        Ok(self
            .inner()?
            .vaults
            .personal()
            .ok()
            .map(|v| hex(v.as_bytes())))
    }

    /// The vault completeness check's alarms (INV-102): a listed vault withheld, an unlisted
    /// vault served, several vaults without a directory. Empty for an honest server.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = vaultAlarms)]
    pub fn vault_alarms(&self) -> Result<Vec<VaultAlarmView>, CoreError> {
        Ok(self.inner()?.vaults.alarm_views())
    }

    /// How many unsent changes were discarded with vaults deleted on another device since the
    /// last call (reported once).
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = takeDiscardedChanges)]
    pub fn take_discarded_changes(&mut self) -> Result<usize, CoreError> {
        let inner = self.inner_mut()?;
        inner.sync.take_dropped();
        Ok(inner.vaults.take_discarded())
    }

    /// The `account/commit` request that creates an owned vault (§A3). After a 204,
    /// [`Session::vault_respond`] adds it and writes `name` as its first op.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for an empty name or one
    /// over 64 characters; `vault_limit_reached`; `vault_set_mismatch` while the vault set
    /// raises an alarm; `account_key_rotated`.
    #[wasm_bindgen(js_name = createVaultRequest)]
    pub fn create_vault_request(&mut self, name: &str) -> Result<HttpRequest, CoreError> {
        let name = check_name(name)?;
        let inner = self.writable()?;
        let change = create_vault(&mut inner.rng, &inner.account, &inner.unlocked)?;
        let request = HttpRequest::post(
            paths::ACCOUNT_COMMIT,
            change.commit_request(),
            Some(&inner.token),
        )?;
        inner.vault_pending = Some(PendingVault {
            change,
            name: Some(name),
        });
        Ok(request)
    }

    /// The `account/commit` request that deletes an owned vault and everything in it (§A5).
    /// The server needs a fresh OPAQUE session: on `server_fresh_session_required` the host
    /// re-authenticates ([`Session::refresh`]) and builds this request again. To keep the
    /// items, the host moves them to the Personal vault first ([`Session::move_item`]) and
    /// syncs.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for a malformed id;
    /// `personal_vault_protected` for the Personal vault; `unknown_vault`;
    /// `vault_set_mismatch`.
    #[wasm_bindgen(js_name = deleteVaultRequest)]
    pub fn delete_vault_request(&mut self, vault_id: &str) -> Result<HttpRequest, CoreError> {
        let vault_id = items::vault_id(vault_id)?;
        let inner = self.writable()?;
        if inner.vaults.catalog().personal() == Some(vault_id) {
            return Err(ClientError::PersonalVaultProtected.into());
        }
        let change = delete_vault(&mut inner.rng, &inner.account, &inner.unlocked, vault_id)?;
        let request = HttpRequest::post(
            paths::ACCOUNT_COMMIT,
            change.commit_request(),
            Some(&inner.token),
        )?;
        inner.vault_pending = Some(PendingVault { change, name: None });
        Ok(request)
    }

    /// The answer to a vault change's `account/commit`. On success the account takes the new
    /// state; a creation adds the vault and writes its name as its first op (a name that
    /// cannot be written leaves it "Untitled vault" until renamed), and returns its id; a
    /// deletion drops the vault, its unsent changes and its pending moves. On
    /// `server_state_conflict` the change is kept for [`Session::vault_retry_request`] after a
    /// sync.
    ///
    /// # Errors
    /// `locked`; `wrong_state` with no change outstanding; the server's code.
    #[wasm_bindgen(js_name = vaultRespond)]
    pub fn vault_respond(
        &mut self,
        status: u16,
        body: &[u8],
        now_ms: u64,
    ) -> Result<Option<String>, CoreError> {
        let inner = self.inner_mut()?;
        let pending = inner
            .vault_pending
            .take()
            .ok_or(CoreError::new(WRONG_STATE))?;
        if let Err(e) = http::empty(status, body) {
            if http::server_code(status, body) == Some(ErrorCode::StateConflict) {
                inner.vault_pending = Some(pending);
            }
            return Err(e);
        }
        let vault_id = pending.change.vault_id();
        let created = pending.change.finalize(&mut inner.account)?;
        inner.settings.clear();
        // The account answer that lists the vault's self-grant comes with the next sync; the
        // server acknowledged the commit that carries it, so the catalog counts it served now
        // (and a deleted vault no longer served).
        let mut served = inner.account.served_vault_ids();
        if created.is_some() {
            served.push(vault_id);
        } else {
            served.retain(|v| *v != vault_id);
        }
        let record = inner.settings.get(&inner.account, &inner.unlocked)?;
        let catalog = VaultCatalog::check(record.vault_directory(), &served);
        if let Some(created) = created {
            inner.vaults.add_key(created.key, &inner.unlocked)?;
            inner.vaults.set_catalog(catalog);
            if let Some(name) = pending.name {
                let (catalog, vault) = inner.vaults.with_catalog_mut(vault_id)?;
                // §A3 step 3: a failed name write leaves "Untitled vault"; the vault stands.
                let _named = rename_vault(
                    &mut inner.rng,
                    &inner.unlocked,
                    catalog,
                    vault,
                    &name,
                    now_ms,
                );
            }
            Ok(Some(hex(vault_id.as_bytes())))
        } else {
            // The user deleted it here: its unsent changes go with it, not reported.
            inner.vaults.forget(vault_id);
            inner.moves.retain(|m| !m.involves(vault_id));
            inner.vaults.set_catalog(catalog);
            Ok(None)
        }
    }

    /// After `server_state_conflict` and a sync: the vault change rebuilt on the account the
    /// sync verified (a rollback or fork stops it).
    ///
    /// # Errors
    /// `locked`; `wrong_state` with no change kept or while a sync runs; `rollback`, `fork`;
    /// the errors of building the change.
    #[wasm_bindgen(js_name = vaultRetryRequest)]
    pub fn vault_retry_request(&mut self) -> Result<HttpRequest, CoreError> {
        let inner = self.writable()?;
        let pending = inner
            .vault_pending
            .take()
            .ok_or(CoreError::new(WRONG_STATE))?;
        let change =
            pending
                .change
                .on_state_conflict(&mut inner.rng, &inner.account, &inner.unlocked)?;
        let request = HttpRequest::post(
            paths::ACCOUNT_COMMIT,
            change.commit_request(),
            Some(&inner.token),
        )?;
        inner.vault_pending = Some(PendingVault {
            change,
            name: pending.name,
        });
        Ok(request)
    }

    /// Renames an owned vault (§A4): an ordinary op in its vault-settings item, sent with the
    /// next sync.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for a malformed id, an empty
    /// name or one over 64 characters; `personal_vault_protected`; `unknown_vault`;
    /// `read_only`.
    #[wasm_bindgen(js_name = renameVault)]
    pub fn rename_vault(
        &mut self,
        vault_id: &str,
        name: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let vault_id = items::vault_id(vault_id)?;
        let name = check_name(name)?;
        let inner = self.writable()?;
        let (catalog, vault) = inner.vaults.with_catalog_mut(vault_id)?;
        rename_vault(
            &mut inner.rng,
            &inner.unlocked,
            catalog,
            vault,
            &name,
            now_ms,
        )?;
        Ok(())
    }

    /// Copies an item into another vault (§A6 step 1): a new item with a new id; field values,
    /// tags, passkeys, TOTP and history travel. The host then carries each listed attachment
    /// over (download from the source, upload to the copy) and syncs.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for a malformed reference or
    /// the item's own vault; `unknown_vault`; `unknown_item`; `read_only`.
    #[wasm_bindgen(js_name = copyItem)]
    pub fn copy_item(
        &mut self,
        id: &str,
        target_vault: &str,
        now_ms: u64,
    ) -> Result<ItemCopyView, CoreError> {
        let (source_id, item) = parse_ref(id)?;
        let target_id = items::vault_id(target_vault)?;
        let inner = self.writable()?;
        if !inner.vaults.is_writable(target_id) {
            return Err(ClientError::ReadOnly.into());
        }
        let (source, target) = inner.vaults.pair_mut(source_id, target_id)?;
        let copy = copy_item(
            &mut inner.rng,
            &inner.unlocked,
            source,
            item,
            target,
            now_ms,
        )?;
        Ok(ItemCopyView {
            id: item_ref(target_id, copy.item_id),
            created: copy.created,
            attachments: copy.attachments.iter().map(AttachmentView::of).collect(),
        })
    }

    /// Moves an item into another vault (§A6): the copy now; the source is trashed and purged
    /// by [`Session::finish_moves`] once a sync has the copy acknowledged and the host said its
    /// attachments are stored ([`Session::move_attachments_stored`]; at once when it has none).
    ///
    /// # Errors
    /// As [`Session::copy_item`]; `read_only` for a source vault that cannot be written.
    #[wasm_bindgen(js_name = moveItem)]
    pub fn move_item(
        &mut self,
        id: &str,
        target_vault: &str,
        now_ms: u64,
    ) -> Result<ItemCopyView, CoreError> {
        let (source_id, item) = parse_ref(id)?;
        let target_id = items::vault_id(target_vault)?;
        let inner = self.writable()?;
        if !inner.vaults.is_writable(target_id) || !inner.vaults.is_writable(source_id) {
            return Err(ClientError::ReadOnly.into());
        }
        if let Some(existing) = inner
            .moves
            .iter()
            .find(|m| m.mv.source_vault == source_id && m.mv.source_item == item)
        {
            // A second move of the same item while the first is pending: the same copy.
            return Ok(ItemCopyView {
                id: item_ref(existing.mv.target_vault, existing.mv.target_item),
                created: false,
                attachments: Vec::new(),
            });
        }
        let (source, target) = inner.vaults.pair_mut(source_id, target_id)?;
        let mv = PendingMove::new(&mut inner.rng, source, item, target_id)?;
        let copy = mv.copy(&mut inner.rng, &inner.unlocked, source, target, now_ms)?;
        let view = ItemCopyView {
            id: item_ref(target_id, copy.item_id),
            created: copy.created,
            attachments: copy.attachments.iter().map(AttachmentView::of).collect(),
        };
        inner.moves.push(WebMove {
            mv,
            attachments_pending: !view.attachments.is_empty(),
        });
        Ok(view)
    }

    /// The host uploaded every attachment of the moved item `id` (the copy's reference).
    ///
    /// # Errors
    /// `locked`; `invalid_input` for a malformed reference; `unknown_item` for no pending move
    /// to that item.
    #[wasm_bindgen(js_name = moveAttachmentsStored)]
    pub fn move_attachments_stored(&mut self, id: &str) -> Result<(), CoreError> {
        let (vault, item) = parse_ref(id)?;
        let inner = self.inner_mut()?;
        let found = inner
            .moves
            .iter_mut()
            .find(|m| m.mv.target_vault == vault && m.mv.target_item == item)
            .ok_or(ClientError::UnknownItem)?;
        found.attachments_pending = false;
        Ok(())
    }

    /// Step 2 of every pending move whose copy the server acknowledged (INV-104): the source
    /// trashed and purged, sent with the next sync. Returns how many sources were purged;
    /// moves still waiting stay pending. Moves whose vaults are gone are dropped.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; the first error a purge met (its move stays).
    #[wasm_bindgen(js_name = finishMoves)]
    pub fn finish_moves(&mut self, now_ms: u64) -> Result<u32, CoreError> {
        let inner = self.writable()?;
        let mut done = 0_u32;
        let mut first_error = None;
        let mut kept = Vec::new();
        for m in core::mem::take(&mut inner.moves) {
            let Ok((source, target)) = inner.vaults.pair_mut(m.mv.source_vault, m.mv.target_vault)
            else {
                continue;
            };
            match m.mv.finish(
                &mut inner.rng,
                &inner.unlocked,
                source,
                target,
                !m.attachments_pending,
                now_ms,
            ) {
                Ok(MoveStep::SourcePurged) => done = done.saturating_add(1),
                Ok(MoveStep::AwaitTarget) => kept.push(m),
                Err(e) => {
                    first_error.get_or_insert(e);
                    kept.push(m);
                }
            }
        }
        inner.moves = kept;
        match first_error {
            Some(e) => Err(e.into()),
            None => Ok(done),
        }
    }

    /// The revoked devices whose ops are missing below their revocation cut-off in every
    /// vault after the last sync (ADR 0081 §0 item 2, the cross-vault check of ADR 0021 §9):
    /// 0 for an honest server.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = revokedDataMissing)]
    pub fn revoked_data_missing(&self) -> Result<usize, CoreError> {
        Ok(self.inner()?.vaults.cutoff_gaps())
    }

    /// The moves of this session whose source is not purged yet.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = pendingMoves)]
    pub fn pending_moves(&self) -> Result<usize, CoreError> {
        Ok(self.inner()?.moves.len())
    }
}
