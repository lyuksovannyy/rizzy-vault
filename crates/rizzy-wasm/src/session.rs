// SPDX-License-Identifier: AGPL-3.0-only

//! An unlocked web-vault session: the one handle that holds keys (ADR 0013 §3 rule 1, "Hosts
//! hold opaque handles").
//!
//! A [`Session`] is what a finished [`crate::LoginFlow`] returns. It holds, in Rust memory
//! only: the ephemeral kind-4 device's keys and the account key (inside `rizzy-client`'s
//! `UnlockedDevice`), the vault key and the decrypted item data (inside `VaultSync`), the
//! verified device certificates and revocations, and the OPAQUE session's bearer token.
//! [`Session::lock`] drops all of it; every secret type wipes itself on drop. Freeing the
//! JavaScript object (`free()`) does the same.
//!
//! # One call per user action (ADR 0013 §3 rule 6)
//!
//! | Action | Calls |
//! |---|---|
//! | Sync | [`Session::sync_start`], then [`Session::sync_request`] / [`Session::sync_respond`] until no request; [`Session::sync_abort`] when a request cannot be carried |
//! | List, view, reveal | [`Session::items`], [`Session::item`], [`Session::item_fields`], [`Session::reveal_field`] |
//! | Save | [`Session::create_item`], [`Session::edit_item`] with an [`ItemDraft`] |
//! | Trash, restore, purge | [`Session::trash_item`], [`Session::restore_item`], [`Session::purge_item`] |
//! | Password history | [`Session::password_history`] (dates only), [`Session::reveal_password_history`] (one value) |
//! | Item history | [`Session::item_history`] (dates only, every field), [`Session::reveal_field_history`] (one value), [`Session::restore_field_history`] |
//! | Conflict ("keep both / pick one") | [`Session::field_conflict`] (concealed values withheld), [`Session::reveal_conflict_value`] (one value), [`Session::resolve_conflict_pick`], [`Session::resolve_conflict_keep_both`] |
//! | Late-edit and trash notices | [`Session::take_notices`] after a sync; [`Session::restore_late_as_new`] |
//! | TOTP code | [`Session::totp`] |
//! | Breach check (ADR 0053) | [`Session::breach_check_item`] → [`BreachCheck`] (also [`BreachCheck::for_password`] for a typed or generated password) |
//! | Passkey assertion | [`Session::passkey_assertion`] ([`create_passkey`](crate::passkey::create_passkey) is stateless, module docs) |
//! | Export | [`Session::reauth`] + [`Session::confirm_reauth`], then [`Session::export_encrypted`], or [`Session::plaintext_warning_shown`] + [`Session::export_plaintext`] after the hold |
//! | Import | [`detect_import_format`], then [`Session::import_file`] or [`Session::import_encrypted`] |
//! | Devices | [`Session::devices`] |
//! | Sessions (ADR 0075) | [`Session::sessions_list_request`] / [`Session::sessions_list_response`], [`Session::end_session_request`], [`Session::end_other_sessions_request`], [`Session::sign_out_request`] (on lock), [`Session::refresh`] + [`Session::adopt_refresh`] when an end needs a fresh session |
//! | 2FA | [`Session::two_factor_enrol_request`], [`Session::two_factor_enrol_response`], [`Session::two_factor_confirm_request`], [`Session::two_factor_disable_request`] |
//!
//! Every write goes into the vault's memory first; the next sync uploads it. A write is refused
//! while a sync is running (`wrong_state`), so that the host never interleaves an edit with the
//! steps of one sync; the host syncs after a write.
//!
//! # Readings
//!
//! - **Re-authentication before any export** (owner decision 2026-10-05; for plaintext also ADR
//!   0013 §3 rule 2: "an explicit plaintext export, after re-authentication"). The web vault has no local password check, so
//!   the re-authentication is an OPAQUE login of the same account ([`Session::reauth`]),
//!   accepted by [`Session::confirm_reauth`] for [`REAUTH_WINDOW_MS`] (the freshness window
//!   CRYPTO.md §11 "Replacing credentials" gives the server's fresh session) and spent by one
//!   export. The host's clock decides the window; a host that lies to itself only weakens its
//!   own check, as any code on the vault origin could call the same API (ADR 0013 §4, "Honest
//!   limit").
//! - **The hold after the plaintext warning** (owner decision 2026-10-05): the host calls
//!   [`Session::plaintext_warning_shown`] when it shows the warning, shows a countdown of
//!   [`plaintext_export_hold_ms`], and keeps its confirm control disabled until it ends;
//!   [`Session::export_plaintext`] refuses before (`plaintext_export_hold`). The gates live in
//!   `rizzy_client::export::gate`, shared with `rv`.
//! - **Devices** are those of the account answer last verified: the login's, then each sync's
//!   refresh ([`crate::sync`]). The host syncs before it lists them, as `rv device list` reads
//!   `account/state` first.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::attachments::{AttachmentDownload, AttachmentUpload};
use rizzy_client::device::UnlockedDevice;
use rizzy_client::export::cxf::CXF_EXPORT_WARNING;
use rizzy_client::export::detect::{DetectedFormat, detect_format};
use rizzy_client::export::gate::{self, ExportGate, check_export_password};
use rizzy_client::export::plaintext::{
    PLAINTEXT_EXPORT_PHRASE, PLAINTEXT_EXPORT_WARNING, PlaintextExportAck, csv_export_warning,
};
use rizzy_client::items::{Dot, FieldEdit, ItemId, TRASH_RETENTION_MS};
use rizzy_client::login::WebSession;
use rizzy_client::matching::{
    EquivalenceGroup, FrameContext, ItemUri, SavedUri, decide_with_settings,
    global_equivalence_groups, vault_item_uris,
};
use rizzy_client::passkey::{PasskeySigningKey, get_assertion_with};
use rizzy_client::rizzy_core::ids::{AccountId, AttachmentId};
use rizzy_client::rizzy_core::item::key::ElementId;
use rizzy_client::rizzy_core::item::schema::{
    ATTR_ALG, ATTR_CREATED_MS, ATTR_CREDENTIAL_ID, ATTR_PRIVATE_KEY, ATTR_RP_ID, ATTR_USER_HANDLE,
    LIST_PASSKEY, LOGIN_PASSWORD, LOGIN_TOTP,
};
use rizzy_client::rizzy_core::item::value::ValueRef;
use rizzy_client::rizzy_core::sign::DeviceKind;
use rizzy_client::rizzy_core::totp::{OtpAuthUri, TotpParams, TotpSecret};
use rizzy_client::rizzy_import::{self, Format};
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::session::SessionListResponse;
use rizzy_client::rizzy_proto::totp::TotpEnrolStartResponse;
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::sessions::{
    self, ListedSession, OTHERS_ENDED_NOTICE, SESSION_ENDED_BY_YOU_NOTICE, SESSION_ENDED_NOTICE,
    SessionList,
};
use rizzy_client::settings::{PendingSettingsChange, SettingsCache, SettingsEdit, change_settings};
use rizzy_client::sync::{Authors, VaultSync};
use rizzy_client::two_factor::{TotpEnrolment, disable_request};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::breach::BreachCheck;
use crate::error::{CoreError, CoreResult, IMPORT_FAILED, LOCKED, UNKNOWN_FORMAT, WRONG_STATE};
use crate::http::{self, HttpRequest};
use crate::identity::{self, IdentityDefaultsView};
use crate::items::{
    self, ConflictValueView, FieldHistoryView, FieldView, HistoryEntryView, ItemDraft, ItemSummary,
    hex, item_ref, parse_id, type_from_name,
};
use crate::login::{Credentials, LoginFlow, Purpose};
use crate::matching::{self, MatchDecision, MatchSettingsView};
use crate::passkey::{PasskeyAssertion, PasskeyCandidate};
use crate::rng::{Rng, os_rng};
use crate::secret::take_secret;
use crate::sync::{Ctx, Signer, SyncDriver};
use crate::vaults::VaultSet;
use rizzy_client::rizzy_core::ids::VaultId;

mod attachments;
mod vault_ops;
mod webauthn;

pub use attachments::AttachmentView;
pub use vault_ops::ItemCopyView;
use vault_ops::{PendingVault, WebMove};

/// How long a re-authentication allows one export: 5 minutes (module docs;
/// `rizzy_client::export::gate::REAUTH_WINDOW_MS`).
pub const REAUTH_WINDOW_MS: u64 = gate::REAUTH_WINDOW_MS;

/// The largest import file read: the largest input any importer accepts (a 1PUX archive), as
/// `rv` bounds it.
pub const MAX_IMPORT_FILE_LEN: usize = rizzy_import::limits::MAX_ARCHIVE_LEN;

/// Everything an unlocked session holds (module docs).
struct Inner {
    /// The origin the session was opened on.
    origin: String,
    /// The login name as typed, for a re-authentication.
    login_name: String,
    /// The account.
    account_id: AccountId,
    /// The OPAQUE session's bearer token.
    token: SessionToken,
    /// The ephemeral device's keys and the account key.
    unlocked: UnlockedDevice,
    /// The verified account of the login or the last refresh: its pin anchors the next
    /// refresh; its certificates and revocations are the devices.
    account: VerifiedAccount,
    /// The authors, for op verification.
    authors: Authors,
    /// The vaults the account's catalog opens, sharing one device counter (ADR 0081 §A7).
    vaults: VaultSet,
    /// A vault creation or deletion waiting for `account/commit` (ADR 0081 §A3, §A5).
    vault_pending: Option<PendingVault>,
    /// The moves of this session whose source is not purged yet (ADR 0081 §A6, INV-104). A web
    /// session has no cache (CRYPTO.md §11.4), so they live in memory: a closed tab before
    /// the purge leaves the item in both vaults, a duplicate, never a loss.
    moves: Vec<WebMove>,
    /// The sync step driver.
    sync: SyncDriver,
    /// The export gates: the re-authentication every export needs and the hold after the
    /// plaintext warning (`rizzy_client::export::gate`).
    gate: ExportGate,
    /// The RNG.
    rng: Rng,
    /// The "deleted on X while it was being edited on Y" notices already handed to the host
    /// (item, the losing Trashed dot, the displayed Active dot), so that
    /// [`Session::take_notices`] hands each one over once. Keyed on the dots, not just the
    /// device pair: a conflict that resolves and then recurs between the very same two devices
    /// is a new conflict with new dots, and must be handed over too.
    ///
    /// Session memory only, on purpose: it is dropped with the session, so a notice shows again
    /// after the next unlock. Keeping it across sessions would mean a new record in the local
    /// cache, a persistent-format change that needs an ADR 0026 amendment first (gap 02). The
    /// late-edit notices' marks live in the same place for the same reason (`rizzy-client`'s
    /// `VaultSync::mark_late_edits_surfaced`).
    shown_trash_notices: BTreeSet<(VaultId, ItemId, Dot, Dot)>,
    /// The account settings of the verified account, read once per object (ADR 0042 §6).
    settings: SettingsCache,
    /// A settings change sent to `account/commit` and not yet answered, or kept after a
    /// `state_conflict` for a retry.
    settings_pending: Option<PendingSettingsChange>,
    /// The compiled-in global equivalence list's groups, verified once when the session starts
    /// and kept for every decision (ADR 0051 §4). The web vault keeps no cache, so no floor:
    /// it verifies from `highest_accepted_version = 0` every session (ADR 0051 §5).
    global_groups: Vec<EquivalenceGroup>,
    /// The last `sessions/list` answer (ADR 0075), so that an end names only a listed row.
    sessions: Option<SessionList>,
    /// Attachments sealed and not yet fully sent, by id (ADR 0054; [`attachments`]).
    uploads: BTreeMap<AttachmentId, AttachmentUpload>,
    /// Attachments being downloaded and verified, by id.
    downloads: BTreeMap<AttachmentId, (VaultId, AttachmentDownload)>,
}

/// An unlocked web-vault session (module docs). `Debug` shows nothing secret.
#[wasm_bindgen]
pub struct Session {
    /// The unlocked state; `None` once locked.
    inner: Option<Box<Inner>>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("locked", &self.inner.is_none())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The session of a verified web login: a driver for every vault the account's catalog
    /// opens (ADR 0081 §A2, §A7), all sharing one `device_seq` counter from 1 (a new device),
    /// the authors of the verified account.
    ///
    /// # Errors
    /// `invalid_server_response` if the account answer carries no key of an open vault.
    pub(crate) fn from_web(
        web: WebSession,
        origin: String,
        login_name: String,
    ) -> CoreResult<Self> {
        let WebSession {
            unlocked,
            mut account,
            session_token,
            ..
        } = web;
        let vaults = VaultSet::open_all(&mut account, &unlocked, false)?;
        let authors = Authors::from_account(&account)?;
        Ok(Self {
            inner: Some(Box::new(Inner {
                origin,
                login_name,
                account_id: account.account_id(),
                token: session_token,
                unlocked,
                authors,
                account,
                vaults,
                vault_pending: None,
                moves: Vec::new(),
                sync: SyncDriver::default(),
                gate: ExportGate::new(),
                rng: os_rng(),
                shown_trash_notices: BTreeSet::new(),
                settings: SettingsCache::default(),
                settings_pending: None,
                global_groups: global_equivalence_groups(0).0,
                sessions: None,
                uploads: BTreeMap::new(),
                downloads: BTreeMap::new(),
            })),
        })
    }

    /// The unlocked state.
    fn inner(&self) -> CoreResult<&Inner> {
        self.inner.as_deref().ok_or(CoreError::new(LOCKED))
    }

    /// The unlocked state, mutably.
    fn inner_mut(&mut self) -> CoreResult<&mut Inner> {
        self.inner.as_deref_mut().ok_or(CoreError::new(LOCKED))
    }

    /// The unlocked state for a write: refused while a sync runs.
    fn writable(&mut self) -> CoreResult<&mut Inner> {
        let inner = self.inner_mut()?;
        if inner.sync.running() {
            return Err(CoreError::new(WRONG_STATE));
        }
        Ok(inner)
    }

    /// Runs a lifecycle op on an item.
    fn lifecycle(
        &mut self,
        id: &str,
        op: fn(&mut VaultSync, &mut Rng, &UnlockedDevice, ItemId, u64) -> Result<(), ClientError>,
        now_ms: u64,
    ) -> CoreResult<()> {
        let inner = self.writable()?;
        let (vault, item) = inner.vaults.item_mut(id)?;
        op(vault, &mut inner.rng, &inner.unlocked, item, now_ms)?;
        Ok(())
    }
}

#[wasm_bindgen]
impl Session {
    /// Locks the session: drops and wipes every key, the decrypted items and the token. Own
    /// ops not yet uploaded are lost ([`Session::unsent_changes`]).
    pub fn lock(&mut self) {
        self.inner = None;
    }

    /// Whether the session was locked.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn locked(&self) -> bool {
        self.inner.is_none()
    }

    /// The account id, 32 hex digits.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = accountId)]
    pub fn account_id(&self) -> Result<String, CoreError> {
        Ok(hex(self.inner()?.account_id.as_bytes()))
    }

    /// The ephemeral device's id, 32 hex digits.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> Result<String, CoreError> {
        Ok(hex(self.inner()?.unlocked.device_id().as_bytes()))
    }

    /// The origin the session was opened on.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter)]
    pub fn origin(&self) -> Result<String, CoreError> {
        Ok(self.inner()?.origin.clone())
    }

    /// Whether the vault refuses writes (the server is behind this session, or the history
    /// check failed).
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = readOnly)]
    pub fn read_only(&self) -> Result<bool, CoreError> {
        Ok(!self
            .inner()?
            .vaults
            .personal_vault()
            .is_ok_and(|v| !v.is_read_only()))
    }

    /// How many own ops the server has not acknowledged yet: what a lock now would lose.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = unsentChanges)]
    pub fn unsent_changes(&self) -> Result<usize, CoreError> {
        Ok(self
            .inner()?
            .vaults
            .all()
            .iter()
            .map(|v| v.unacknowledged().0)
            .sum())
    }

    /// The account's counted bytes the server reported with the last account answer (ADR 0048
    /// §5), `undefined` when it reported none. The server's word, unverified: for display only.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = storageBytesUsed)]
    pub fn storage_bytes_used(&self) -> Result<Option<u64>, CoreError> {
        Ok(self.inner()?.account.usage().map(|u| u.bytes_used))
    }

    /// The instance's per-account storage quota the server reported with the last account
    /// answer (ADR 0048 §1, §5), `undefined` when it reported none. Unverified, for display.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = storageQuotaBytes)]
    pub fn storage_quota_bytes(&self) -> Result<Option<u64>, CoreError> {
        Ok(self.inner()?.account.usage().map(|u| u.quota_bytes))
    }

    /// Whether a sync is running.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter)]
    pub fn syncing(&self) -> Result<bool, CoreError> {
        Ok(self.inner()?.sync.running())
    }

    /// Starts a sync ([`crate::sync`]).
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs.
    #[wasm_bindgen(js_name = syncStart)]
    pub fn sync_start(&mut self) -> Result<(), CoreError> {
        let inner = self.inner_mut()?;
        let mut ctx = Ctx {
            vaults: &mut inner.vaults,
            account: &mut inner.account,
            authors: &mut inner.authors,
            unlocked: &inner.unlocked,
            signer: Signer::Bearer(&inner.token),
            rng: &mut inner.rng,
        };
        inner.sync.start(&mut ctx)
    }

    /// The sync's outstanding request, or `undefined` when the sync is done.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = syncRequest)]
    pub fn sync_request(&self) -> Result<Option<HttpRequest>, CoreError> {
        Ok(self.inner()?.sync.request())
    }

    /// Passes in the answer to the sync's outstanding request. `now_ms` is the host's clock.
    /// Any error ends the sync.
    ///
    /// # Errors
    /// `locked`; as [`crate::sync`] describes.
    #[wasm_bindgen(js_name = syncRespond)]
    pub fn sync_respond(&mut self, status: u16, body: &[u8], now_ms: u64) -> Result<(), CoreError> {
        let inner = self.inner_mut()?;
        let ctx = Ctx {
            vaults: &mut inner.vaults,
            account: &mut inner.account,
            authors: &mut inner.authors,
            unlocked: &inner.unlocked,
            signer: Signer::Bearer(&inner.token),
            rng: &mut inner.rng,
        };
        inner.sync.respond(ctx, status, body, now_ms)
    }

    /// Ends the running sync when the host could not carry its outstanding request (a
    /// connection failure, an answer too large or broken off). The unsent own changes stay
    /// queued and the next sync sends them again ([`crate::sync`]); writes are accepted again.
    /// A no-op when no sync runs.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = syncAbort)]
    pub fn sync_abort(&mut self) -> Result<(), CoreError> {
        let inner = self.inner_mut()?;
        inner.sync.abort(&mut inner.vaults);
        Ok(())
    }

    /// The active items, or the trashed ones, as summaries (no concealed value).
    ///
    /// # Errors
    /// `locked`.
    pub fn items(&self, trash: bool) -> Result<Vec<ItemSummary>, CoreError> {
        Ok(self
            .inner()?
            .vaults
            .all()
            .iter()
            .flat_map(|v| items::summaries(v, trash))
            .collect())
    }

    /// One item's summary.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id that is not 32 hex digits; `unknown_item`.
    pub fn item(&self, id: &str) -> Result<ItemSummary, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        items::summary(vault, item).ok_or(ClientError::UnknownItem.into())
    }

    /// One item's displayed fields; concealed values are withheld.
    ///
    /// # Errors
    /// As [`Session::item`].
    #[wasm_bindgen(js_name = itemFields)]
    pub fn item_fields(&self, id: &str) -> Result<Vec<FieldView>, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        Ok(items::fields(vault, item))
    }

    /// One field's value as text, concealed or not: call it only on the user's request.
    ///
    /// # Errors
    /// As [`Session::item`]; `unknown_item` for a field the item does not display;
    /// `invalid_input` for a value with no text form (bytes, an order key).
    #[wasm_bindgen(js_name = revealField)]
    pub fn reveal_field(&self, id: &str, key: &str) -> Result<String, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        Ok(items::reveal(vault, item, key)?.as_str().to_owned())
    }

    /// Creates an item of `item_type` (a name of [`crate::items::TYPES`]) with the draft's
    /// writes. Returns the new item's id.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for an unknown type;
    /// `invalid_edit` for a write the schema refuses; `read_only`.
    #[wasm_bindgen(js_name = createItem)]
    pub fn create_item(
        &mut self,
        vault_id: &str,
        item_type: &str,
        draft: &ItemDraft,
        now_ms: u64,
    ) -> Result<String, CoreError> {
        let item_type = type_from_name(item_type)?;
        let target = items::vault_id(vault_id)?;
        let inner = self.writable()?;
        let vault = inner.vaults.get_mut(target)?;
        let writes = items::writes(vault, None, draft)?;
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        let item = vault.create_item(&mut inner.rng, &inner.unlocked, item_type, &edits, now_ms)?;
        Ok(item_ref(target, item))
    }

    /// Edits an active item with the draft's writes, as one op.
    ///
    /// # Errors
    /// As [`Session::create_item`]; `unknown_item` for an item that is not active;
    /// `invalid_edit` for an empty draft.
    #[wasm_bindgen(js_name = editItem)]
    pub fn edit_item(&mut self, id: &str, draft: &ItemDraft, now_ms: u64) -> Result<(), CoreError> {
        if draft.is_empty() {
            return Err(ClientError::InvalidEdit.into());
        }
        let inner = self.writable()?;
        let (vault, item) = inner.vaults.item_mut(id)?;
        let writes = items::writes(&*vault, Some(item), draft)?;
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        vault.edit_item(&mut inner.rng, &inner.unlocked, item, &edits, now_ms)?;
        Ok(())
    }

    /// Moves an active item to the trash.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `unknown_item`; `read_only`.
    #[wasm_bindgen(js_name = trashItem)]
    pub fn trash_item(&mut self, id: &str, now_ms: u64) -> Result<(), CoreError> {
        self.lifecycle(id, VaultSync::trash_item::<Rng>, now_ms)
    }

    /// Restores a trashed item.
    ///
    /// # Errors
    /// As [`Session::trash_item`].
    #[wasm_bindgen(js_name = restoreItem)]
    pub fn restore_item(&mut self, id: &str, now_ms: u64) -> Result<(), CoreError> {
        self.lifecycle(id, VaultSync::restore_item::<Rng>, now_ms)
    }

    /// Purges a trashed item for good.
    ///
    /// # Errors
    /// As [`Session::trash_item`]; `invalid_edit` when the writer rules refuse.
    #[wasm_bindgen(js_name = purgeItem)]
    pub fn purge_item(&mut self, id: &str, now_ms: u64) -> Result<(), CoreError> {
        self.lifecycle(id, VaultSync::purge_item::<Rng>, now_ms)
    }

    /// Purges every trashed item whose retention period has elapsed (gap 00; ADR 0012 §5,
    /// ADR 0018 §9, §11). The host calls this once after a successful sync (module docs of
    /// `rizzy_client::items::VaultSync::auto_purge_due`), while the session is unlocked, so it
    /// runs only when this device is online. Returns the purged items' ids, ascending; empty
    /// when nothing was due.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs.
    #[wasm_bindgen(js_name = autoPurge)]
    pub fn auto_purge(&mut self, now_ms: u64) -> Result<Vec<String>, CoreError> {
        let inner = self.writable()?;
        let mut out = Vec::new();
        for vault in inner.vaults.all_mut() {
            if vault.is_read_only() {
                continue;
            }
            let vault_id = vault.vault_id();
            let purged = vault.auto_purge_due(
                &mut inner.rng,
                &inner.unlocked,
                now_ms,
                TRASH_RETENTION_MS,
            )?;
            out.extend(purged.into_iter().map(|id| item_ref(vault_id, id)));
        }
        Ok(out)
    }

    /// One item's password history without values (gap 01; [`crate::items`] module docs):
    /// source, position and date per entry. Empty when the item has none.
    ///
    /// # Errors
    /// As [`Session::item`].
    #[wasm_bindgen(js_name = passwordHistory)]
    pub fn password_history(&self, id: &str) -> Result<Vec<HistoryEntryView>, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        Ok(items::password_history(vault, item))
    }

    /// The value of one password-history entry, as [`Session::password_history`] listed it:
    /// call it only on the user's request (ADR 0013 §3 rule 3). `entry_id` is the entry's own
    /// id as the listing gave it ([`crate::items::HistoryEntryView::id`]); an entry at `index`
    /// with another id is refused, so a listing made stale by a sync never reveals a value
    /// under another entry's identity.
    ///
    /// # Errors
    /// As [`Session::item`]; `invalid_input` for an unknown source; `unknown_item` for an
    /// entry that is not there (any more) or whose id differs.
    #[wasm_bindgen(js_name = revealPasswordHistory)]
    pub fn reveal_password_history(
        &self,
        id: &str,
        source: &str,
        index: usize,
        entry_id: &str,
    ) -> Result<String, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        Ok(items::reveal_history(vault, item, source, index, entry_id)?
            .as_str()
            .to_owned())
    }

    /// Every field's history without values (gap "item history"; [`crate::items`] module docs;
    /// ROADMAP §4.2 "Item revision history (restore old versions)", M3): generalizes
    /// [`Session::password_history`] to every field. Empty when the item has none.
    ///
    /// # Errors
    /// As [`Session::item`].
    #[wasm_bindgen(js_name = itemHistory)]
    pub fn item_history(&self, id: &str) -> Result<Vec<FieldHistoryView>, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        Ok(items::item_history(vault, item))
    }

    /// The value of one field-history entry, as [`Session::item_history`] listed it: call it
    /// only on the user's request (ADR 0013 §3 rule 3). As [`Session::reveal_password_history`],
    /// generalized to any field; `key` scopes `index`/`entry_id`, so an id from one field's
    /// listing never reveals another field's value even when the two share a dot
    /// ([`crate::items`] module docs).
    ///
    /// # Errors
    /// As [`Session::item`]; `unknown_item` for an entry that is not there (any more) or whose
    /// id differs; `invalid_input` for a value with no text form.
    #[wasm_bindgen(js_name = revealFieldHistory)]
    pub fn reveal_field_history(
        &self,
        id: &str,
        key: &str,
        index: usize,
        entry_id: &str,
    ) -> Result<String, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        Ok(
            items::reveal_field_history(vault, item, key, index, entry_id)?
                .as_str()
                .to_owned(),
        )
    }

    /// Restores one field-history entry as the field's current value (ROADMAP §4.2): an
    /// ordinary edit (`rizzy_client::items::VaultSync::restore_field_history`), so it syncs and
    /// merges like any other. `key`, `index` and `entry_id` name the entry exactly as
    /// [`Session::item_history`] listed it, checked the same way
    /// [`Session::reveal_field_history`] is, so a sync between the listing and this call never
    /// restores a value under the wrong identity.
    ///
    /// # Errors
    /// As [`Session::edit_item`]; `unknown_item` for an entry that is not there (any more) or
    /// whose id differs.
    #[wasm_bindgen(js_name = restoreFieldHistory)]
    pub fn restore_field_history(
        &mut self,
        id: &str,
        key: &str,
        index: usize,
        entry_id: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let inner = self.writable()?;
        let (vault, item) = inner.vaults.item_mut(id)?;
        let dot = items::restore_field_history_dot(&*vault, item, key, index, entry_id)?;
        vault.restore_field_history(&mut inner.rng, &inner.unlocked, item, key, dot, now_ms)?;
        Ok(())
    }

    /// A conflicting field's distinct values (ROADMAP §4.5 "keep both / pick one"; ADR 0018
    /// §6; [`crate::items`] module docs), the displayed one first, concealed values withheld.
    /// Empty when the field does not conflict.
    ///
    /// # Errors
    /// As [`Session::item`]; `invalid_input` for a key outside the grammar.
    #[wasm_bindgen(js_name = fieldConflict)]
    pub fn field_conflict(&self, id: &str, key: &str) -> Result<Vec<ConflictValueView>, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        items::field_conflict(vault, item, key)
    }

    /// One conflicting value as text, concealed or not: call it only on the user's request (ADR
    /// 0013 §3 rule 3). `key`, `index` and `value_id` name the value exactly as
    /// [`Session::field_conflict`] listed it.
    ///
    /// # Errors
    /// As [`Session::item`]; `unknown_item` for a value that is not listed (any more) under
    /// that index and id; `invalid_input` for a Cleared value or one with no text form.
    #[wasm_bindgen(js_name = revealConflictValue)]
    pub fn reveal_conflict_value(
        &self,
        id: &str,
        key: &str,
        index: usize,
        value_id: &str,
    ) -> Result<String, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        Ok(
            items::reveal_conflict_value(vault, item, key, index, value_id)?
                .as_str()
                .to_owned(),
        )
    }

    /// "Pick one": writes the named value back to the field, an ordinary edit whose context
    /// covers every conflicting value, so the conflict ends on every device that syncs it
    /// (`rizzy_client::sync::VaultSync::resolve_conflict_pick`).
    ///
    /// # Errors
    /// As [`Session::edit_item`]; `unknown_item` for a value that is not listed (any more)
    /// under that index and id.
    #[wasm_bindgen(js_name = resolveConflictPick)]
    pub fn resolve_conflict_pick(
        &mut self,
        id: &str,
        key: &str,
        index: usize,
        value_id: &str,
        now_ms: u64,
    ) -> Result<(), CoreError> {
        let inner = self.writable()?;
        let (vault, item) = inner.vaults.item_mut(id)?;
        let dot = items::conflict_value(&*vault, item, key, index, value_id)?.dot;
        vault.resolve_conflict_pick(&mut inner.rng, &inner.unlocked, item, key, dot, now_ms)?;
        Ok(())
    }

    /// "Keep both": keeps the named value in the field and moves every other non-empty value
    /// into a new website (for a website) or a new custom field (hidden when the field is
    /// concealed), labelled `label` or, for a custom field without one, with its own label
    /// (`rizzy_client::sync::VaultSync::resolve_conflict_keep_both`). Returns the new
    /// elements' ids.
    ///
    /// # Errors
    /// As [`Session::edit_item`]; `unknown_item` for a value that is not listed (any more)
    /// under that index and id; `invalid_edit` for a field only "pick one" resolves (not
    /// text, or no second value to keep); `invalid_input` for a fixed field without a label.
    #[wasm_bindgen(js_name = resolveConflictKeepBoth)]
    pub fn resolve_conflict_keep_both(
        &mut self,
        id: &str,
        key: &str,
        index: usize,
        value_id: &str,
        label: Option<String>,
        now_ms: u64,
    ) -> Result<Vec<String>, CoreError> {
        let inner = self.writable()?;
        let (vault, item) = inner.vaults.item_mut(id)?;
        let keep = items::conflict_value(&*vault, item, key, index, value_id)?.dot;
        let label = label.map(Zeroizing::new);
        let elements = vault.resolve_conflict_keep_both(
            &mut inner.rng,
            &inner.unlocked,
            item,
            key,
            keep,
            label.as_ref().map(|l| l.as_str()),
            now_ms,
        )?;
        Ok(elements.iter().map(|e| e.as_str().to_owned()).collect())
    }

    /// The notices not yet handed over in this session (gap 02), each handed over once: an edit
    /// that arrived for an item deleted permanently (ADR 0018 §3 "Surfacing"; the host offers
    /// [`Session::restore_late_as_new`]), and an item deleted on one device while it was being
    /// edited on another (ADR 0012 §5 "Active wins"), with [`Notice::conflict_id`] set so a
    /// second, genuinely distinct race between the same two devices on the same item is not
    /// mistaken for a repeat of the first. Device ids only; the host names them from
    /// [`Session::devices`]. The host calls this after each sync.
    ///
    /// "Handed over once" lasts this session only: the marks live in memory (the late-edit
    /// marks in the vault's merge, the trash notices in this session), so the next unlock shows
    /// the notices again. Persisting them is an ADR 0026 cache-format change (gap 02).
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = takeNotices)]
    pub fn take_notices(&mut self) -> Result<Vec<Notice>, CoreError> {
        let inner = self.inner_mut()?;
        let mut out = Vec::new();
        for vault in inner.vaults.all_mut() {
            let vault_id = vault.vault_id();
            for item in vault.item_ids() {
                let late = vault.late_edit_devices(item);
                if !late.is_empty() {
                    vault.mark_late_edits_surfaced(item);
                    out.push(Notice {
                        kind: NOTICE_LATE_EDIT,
                        item: item_ref(vault_id, item),
                        devices: late.iter().map(|d| hex(d.as_bytes())).collect(),
                        conflict_id: None,
                    });
                }
                if let Some(trash) = vault.concurrent_trash(item)
                    && inner.shown_trash_notices.insert((
                        vault_id,
                        item,
                        trash.trashed_dot,
                        trash.edited_dot,
                    ))
                {
                    out.push(Notice {
                        kind: NOTICE_CONCURRENT_TRASH,
                        item: item_ref(vault_id, item),
                        devices: vec![
                            hex(trash.trashed_by.as_bytes()),
                            hex(trash.edited_by.as_bytes()),
                        ],
                        conflict_id: Some(concurrent_trash_conflict_id(
                            trash.trashed_dot,
                            trash.edited_dot,
                        )),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Restores the late edits of an item deleted permanently as a new item of `item_type`,
    /// the type the user picked (ADR 0018 §3 "Surfacing": never inferred). Returns the new
    /// item's id; the deleted item stays deleted.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for an id that is not 32 hex
    /// digits or an unknown type; `unknown_item` unless the item was deleted permanently;
    /// `read_only`.
    #[wasm_bindgen(js_name = restoreLateAsNew)]
    pub fn restore_late_as_new(
        &mut self,
        id: &str,
        item_type: &str,
        now_ms: u64,
    ) -> Result<String, CoreError> {
        let item_type = type_from_name(item_type)?;
        let inner = self.writable()?;
        let (vault, item) = inner.vaults.item_mut(id)?;
        let restored = vault.restore_late_as_new_item(
            &mut inner.rng,
            &inner.unlocked,
            item,
            item_type,
            now_ms,
        )?;
        Ok(item_ref(vault.vault_id(), restored))
    }

    /// What each custom field's autocomplete id does, in list order (ADR 0076 §2.4–§2.5, §3):
    /// the editor's inline errors and its "also used by" warning.
    ///
    /// # Errors
    /// As [`Session::item`].
    #[wasm_bindgen(js_name = customFieldAutofill)]
    pub fn custom_field_autofill(
        &self,
        id: &str,
    ) -> Result<Vec<crate::autofill::CustomFieldAutofillView>, CoreError> {
        let (vault, _) = self.inner()?.vaults.item(id)?;
        crate::autofill::custom_field_autofill(vault, id)
    }

    /// A breach check of an item's `login.password` (CRYPTO.md §11.16; [`crate::breach`]): the
    /// password is read here and never crosses; `undefined` when the item has no password.
    ///
    /// # Errors
    /// As [`Session::item`].
    #[wasm_bindgen(js_name = breachCheckItem)]
    pub fn breach_check_item(&self, id: &str) -> Result<Option<BreachCheck>, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        if vault
            .field_value(item, LOGIN_PASSWORD)
            .filter(|v| !v.is_cleared())
            .is_none()
        {
            return Ok(None);
        }
        let password = items::reveal(vault, item, LOGIN_PASSWORD)?;
        if password.is_empty() {
            return Ok(None);
        }
        BreachCheck::of(&password).map(Some)
    }

    /// The current TOTP code of an item's `login.totp`, which holds an `otpauth://` URI or a
    /// bare Base32 secret (then SHA-1, 6 digits, 30 s; CRYPTO.md §11.15), at `now_ms`.
    ///
    /// # Errors
    /// As [`Session::item`]; `invalid_input` when the item has no valid time-based secret.
    pub fn totp(&self, id: &str, now_ms: u64) -> Result<TotpCode, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        let bad = || CoreError::from(ClientError::InvalidInput);
        let value = vault.field_value(item, LOGIN_TOTP).ok_or_else(bad)?;
        let stored = match value.decode() {
            Ok(ValueRef::Text(text)) => Zeroizing::new(text.to_owned()),
            _ => return Err(bad()),
        };
        let (params, secret) = if stored.starts_with("otpauth://") {
            let uri = OtpAuthUri::parse(&stored).map_err(|_| bad())?;
            let params = uri.totp_params().ok_or_else(bad)?;
            let secret = TotpSecret::from_slice(uri.secret().expose_secret()).map_err(|_| bad())?;
            (params, secret)
        } else {
            // The UI strips spaces before parsing (§11.15 "Base32 secrets").
            let compact = Zeroizing::new(stored.replace(' ', ""));
            (
                TotpParams::DEFAULT,
                TotpSecret::from_base32(&compact).map_err(|_| bad())?,
            )
        };
        let seconds = now_ms / 1000;
        let code = params.code_at(&secret, seconds).map_err(|_| bad())?;
        let period = u64::from(params.period.get());
        Ok(TotpCode {
            code: code.to_digits(),
            valid_for_s: period - seconds % period,
            period_s: period,
        })
    }

    /// Produces a `WebAuthn` assertion for one stored passkey (`passkey/<passkey_id>/…` on
    /// item `id`, ADR 0039 §1, §2; [`crate::passkey`] module docs). The stored private key is
    /// read and used here, never returned: only the resulting [`PasskeyAssertion`] crosses to
    /// JavaScript, the same pattern [`Session::totp`] uses for a different concealed field.
    /// [`PasskeyAssertion::user_handle`] is read back the same way `credential_id` already was
    /// (gap 35(a) in the M2 gap audit).
    ///
    /// `origin` must be the browser-verified origin
    /// ([`rizzy_client::passkey`]'s `verify_rp_id` scope-boundary docs — this call cannot
    /// establish that itself, [`crate::passkey`] module docs); `rp_id` is the page's requested
    /// `rpId`, already defaulted by the caller to `origin`'s host if the page omitted it.
    ///
    /// This call does **not** check `passkey_id` against the page's `allowCredentials` — that
    /// is the caller's job, done *before* this call, by filtering
    /// [`Session::passkey_candidates`]'s result (gap 35(b); [`crate::passkey`] module docs).
    ///
    /// # Errors
    /// As [`Session::item`]; `invalid_input` when `passkey_id` is not a valid element id, the
    /// item has no such passkey, or its stored `alg` and key are not a valid ES256 scalar or `EdDSA` seed; otherwise
    /// whatever `get_assertion` returns (`rp_id_rejected` for INV-64).
    #[wasm_bindgen(js_name = passkeyAssertion)]
    pub fn passkey_assertion(
        &self,
        id: &str,
        passkey_id: &str,
        origin: &str,
        rp_id: &str,
        challenge: &[u8],
    ) -> Result<PasskeyAssertion, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        let bad = || CoreError::from(ClientError::InvalidInput);
        let element = ElementId::from_bytes(items::parse_id(passkey_id)?);

        let bytes_field = |attr: &str| -> Result<Vec<u8>, CoreError> {
            let key = element.key(LIST_PASSKEY, attr).map_err(|_| bad())?;
            match vault
                .field_value(item, key.as_str())
                .ok_or_else(bad)?
                .decode()
            {
                Ok(ValueRef::Bytes(bytes)) => Ok(bytes.to_vec()),
                _ => Err(bad()),
            }
        };

        let credential_id = bytes_field(ATTR_CREDENTIAL_ID)?;
        let user_handle = bytes_field(ATTR_USER_HANDLE)?;

        // `alg` picks the algorithm (ADR 0039 §1): 1 is ES256, which this project creates; 2 is
        // an `EdDSA` passkey a CXF import brought in (ADR 0074 §3), whose seed must never be
        // read as a P-256 scalar.
        let alg_key = element.key(LIST_PASSKEY, ATTR_ALG).map_err(|_| bad())?;
        let Ok(ValueRef::Enum(alg)) = vault
            .field_value(item, alg_key.as_str())
            .ok_or_else(bad)?
            .decode()
        else {
            return Err(bad());
        };
        let private_key_key = element
            .key(LIST_PASSKEY, ATTR_PRIVATE_KEY)
            .map_err(|_| bad())?;
        let signing_key = match vault
            .field_value(item, private_key_key.as_str())
            .ok_or_else(bad)?
            .decode()
        {
            Ok(ValueRef::Bytes(bytes)) => {
                PasskeySigningKey::from_stored(alg, bytes).map_err(|_| bad())?
            }
            _ => return Err(bad()),
        };

        let assertion = get_assertion_with(
            &signing_key,
            &credential_id,
            &user_handle,
            origin,
            rp_id,
            challenge,
        )?;
        Ok(assertion.into())
    }

    /// Every stored passkey's non-secret metadata on item `id` (`passkey/<id>/…`; ADR 0039
    /// §1), for the host to list `navigator.credentials.get()`/`.create()` candidates (gaps
    /// 35(a)/(b) in the M2 gap audit; [`crate::passkey`] module docs) — never `private_key`,
    /// which stays in Rust and is read only by [`Session::passkey_assertion`].
    ///
    /// # Errors
    /// As [`Session::item`].
    #[wasm_bindgen(js_name = passkeyCandidates)]
    pub fn passkey_candidates(&self, id: &str) -> Result<Vec<PasskeyCandidate>, CoreError> {
        let (vault, item) = self.inner()?.vaults.item(id)?;
        let mut out = Vec::new();
        for element in vault.list_elements(item, LIST_PASSKEY) {
            let element_id = element.element.as_str();
            let key = |attr: &str| format!("{LIST_PASSKEY}/{element_id}/{attr}");
            let text = |attr: &str| match vault.field_value(item, &key(attr))?.decode() {
                Ok(ValueRef::Text(text)) => Some(text.to_owned()),
                _ => None,
            };
            let bytes = |attr: &str| match vault.field_value(item, &key(attr))?.decode() {
                Ok(ValueRef::Bytes(bytes)) => Some(bytes.to_vec()),
                _ => None,
            };
            let enum_value = |attr: &str| match vault.field_value(item, &key(attr))?.decode() {
                Ok(ValueRef::Enum(value)) => Some(value),
                _ => None,
            };
            let u64_value = |attr: &str| match vault.field_value(item, &key(attr))?.decode() {
                Ok(ValueRef::U64(value)) => Some(value),
                _ => None,
            };

            // A passkey element with a missing or mistyped required field is skipped, not an
            // error for the whole list: one malformed element must not hide every other
            // account's candidates (the same "a bad entry must not fail everything else" rule
            // `decide_candidates` already applies to a saved URI that fails to normalise).
            let (Some(rp_id), Some(user_handle), Some(credential_id), Some(alg)) = (
                text(ATTR_RP_ID),
                bytes(ATTR_USER_HANDLE),
                bytes(ATTR_CREDENTIAL_ID),
                enum_value(ATTR_ALG),
            ) else {
                continue;
            };
            out.push(PasskeyCandidate {
                element_id: element_id.to_owned(),
                rp_id,
                user_handle,
                credential_id,
                alg,
                created_ms: u64_value(ATTR_CREATED_MS).unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// The vault as an encrypted export file (CRYPTO.md §11.14; ADR 0027), under a new
    /// password for that file, which is needed to import it. Needs a re-authentication
    /// confirmed within [`REAUTH_WINDOW_MS`] ([`Session::reauth`], [`Session::confirm_reauth`];
    /// owner decision 2026-10-05), and spends it. Ciphertext: the host saves the bytes as a
    /// download.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an empty export password or one with an unassigned code
    /// point (checked first, so it spends nothing); `reauth_required`;
    /// `export_oversize_items`; `export_too_large`. `export_password` is UTF-8 bytes, zeroed
    /// on return ([`crate::secret`]).
    #[wasm_bindgen(js_name = exportEncrypted)]
    pub fn export_encrypted(
        &mut self,
        vault_id: &str,
        export_password: &mut [u8],
        now_ms: u64,
    ) -> Result<EncryptedExport, CoreError> {
        let export_password = take_secret(export_password)?;
        let inner = self.inner_mut()?;
        check_export_password(&export_password)?;
        let auth = inner.gate.authorize_encrypted(now_ms)?;
        let exported = inner
            .vaults
            .get_mut(items::vault_id(vault_id)?)?
            .export_encrypted(&mut inner.rng, auth, &export_password, now_ms)?;
        Ok(EncryptedExport {
            file: exported.file,
            items: exported.items,
            unresolved: exported.unresolved.len(),
        })
    }

    /// The number of passkeys a CXF export would hold now (ADR 0074 §2), for the dialog.
    ///
    /// # Errors
    /// `locked`; `export_oversize_items`.
    #[wasm_bindgen(js_name = cxfExportPasskeys)]
    pub fn cxf_export_passkeys(&self, vault_id: &str) -> Result<usize, CoreError> {
        Ok(self
            .inner()?
            .vaults
            .get(items::vault_id(vault_id)?)?
            .cxf_export_passkeys()?)
    }

    /// The vault's passkeys as a CXF export file (ADR 0074 §2): a CXF document sealed under a
    /// new password for that file (`rizzy-vault-cxf-export`). Gated like a plaintext export:
    /// a re-authentication confirmed within [`REAUTH_WINDOW_MS`], [`cxf_export_warning`] shown
    /// ([`Session::plaintext_warning_shown`]) and its hold over, and `typed_phrase` exactly
    /// [`plaintext_export_phrase`]; spends them. Ciphertext: the host saves the bytes as a
    /// download. No bare, unencrypted CXF export exists (ADR 0074 owner answer 4).
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an empty export password or one with an unassigned code
    /// point (checked first, so it spends nothing); `reauth_required`;
    /// `plaintext_export_not_acknowledged`; `plaintext_export_hold`; `export_oversize_items`;
    /// `export_too_large`. `export_password` is UTF-8 bytes, zeroed on return
    /// ([`crate::secret`]).
    #[wasm_bindgen(js_name = exportCxf)]
    pub fn export_cxf(
        &mut self,
        vault_id: &str,
        typed_phrase: &str,
        export_password: &mut [u8],
        now_ms: u64,
    ) -> Result<CxfExport, CoreError> {
        let export_password = take_secret(export_password)?;
        let inner = self.inner_mut()?;
        check_export_password(&export_password)?;
        if !inner.gate.reauth_fresh(now_ms) {
            return Err(ClientError::ReauthRequired.into());
        }
        let ack = PlaintextExportAck::from_typed_phrase(typed_phrase)?;
        let auth = inner.gate.authorize_plaintext(now_ms)?;
        let exported = inner
            .vaults
            .get_mut(items::vault_id(vault_id)?)?
            .export_cxf(&mut inner.rng, auth, ack, &export_password, now_ms)?;
        Ok(CxfExport {
            file: exported.file,
            passkeys: exported.passkeys,
        })
    }

    /// The ids of the items that stop an export (too large to encode; ADR 0027 §1). Empty
    /// when an export can be written.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = exportBlockers)]
    pub fn export_blockers(&self, vault_id: &str) -> Result<Vec<String>, CoreError> {
        let target = items::vault_id(vault_id)?;
        Ok(self
            .inner()?
            .vaults
            .get(target)?
            .export_blockers()
            .iter()
            .map(|i| item_ref(target, *i))
            .collect())
    }

    /// The warning the host shows before a CSV export, after [`plaintext_export_warning`]: the
    /// frozen text with the number of items that would lose data (ADR 0027 §5).
    ///
    /// # Errors
    /// `locked`; `export_oversize_items`.
    #[wasm_bindgen(js_name = csvExportWarning)]
    pub fn csv_export_warning(&self, vault_id: &str) -> Result<String, CoreError> {
        let loss = self
            .inner()?
            .vaults
            .get(items::vault_id(vault_id)?)?
            .csv_export_loss()?;
        Ok(csv_export_warning(loss.items_losing_data()))
    }

    /// Starts the re-authentication every export needs (owner decision 2026-10-05; for a
    /// plaintext export also ADR 0013 §3 rule 2): an OPAQUE login of this session's account,
    /// with the Secret Key and master password typed again. The host runs the returned flow
    /// to `"done"` and passes it to [`Session::confirm_reauth`].
    ///
    /// # Errors
    /// `locked`; as [`LoginFlow::start`], whose byte-array rules `secret_key` and `password`
    /// follow (both zeroed on return, [`crate::secret`]).
    pub fn reauth(
        &self,
        secret_key: &mut [u8],
        password: &mut [u8],
        totp: Option<String>,
    ) -> Result<LoginFlow, CoreError> {
        // Both are taken, and so wiped, before any error returns.
        let secret_key = take_secret(secret_key);
        let password = take_secret(password);
        let inner = self.inner()?;
        LoginFlow::begin(
            Credentials {
                origin: inner.origin.clone(),
                login_name: inner.login_name.clone(),
                secret_key: secret_key?,
                password: password?,
            },
            totp.map(Zeroizing::new),
            Purpose::Reauth,
        )
    }

    /// Accepts a finished re-authentication of this account, for one export within
    /// [`REAUTH_WINDOW_MS`] of `now_ms`.
    ///
    /// # Errors
    /// `locked`; `wrong_state` unless the flow is a re-authentication in state `"done"`;
    /// `wrong_password_or_secret_key` if it verified another account.
    #[wasm_bindgen(js_name = confirmReauth)]
    pub fn confirm_reauth(&mut self, flow: &LoginFlow, now_ms: u64) -> Result<(), CoreError> {
        let inner = self.inner_mut()?;
        if flow.purpose() != Purpose::Reauth {
            return Err(CoreError::new(WRONG_STATE));
        }
        let account = flow.reauthenticated().ok_or(CoreError::new(WRONG_STATE))?;
        inner
            .gate
            .accept_reauth(account, inner.account_id, now_ms)?;
        Ok(())
    }

    /// Whether an unspent re-authentication allows an export at `now_ms`.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = reauthFresh)]
    pub fn reauth_fresh(&self, now_ms: u64) -> Result<bool, CoreError> {
        Ok(self.inner()?.gate.reauth_fresh(now_ms))
    }

    /// Records that the plaintext-export warning is shown at `now_ms`: the hold of
    /// [`plaintext_export_hold_ms`] starts, or starts over (a dialog opened again). Returns
    /// the hold in milliseconds, for the host's countdown.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = plaintextWarningShown)]
    pub fn plaintext_warning_shown(&mut self, now_ms: u64) -> Result<u32, CoreError> {
        self.inner_mut()?.gate.plaintext_warning_shown(now_ms);
        Ok(plaintext_export_hold_ms())
    }

    /// How much of the hold after the plaintext warning is left at `now_ms`, in milliseconds:
    /// the whole hold when the warning was not shown, 0 once it is over.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = plaintextHoldRemainingMs)]
    pub fn plaintext_hold_remaining_ms(&self, now_ms: u64) -> Result<u32, CoreError> {
        let left = self.inner()?.gate.plaintext_hold_remaining_ms(now_ms);
        Ok(u32::try_from(left).unwrap_or(u32::MAX))
    }

    /// The plaintext export (ADR 0027 §3–§5): `format` is `json` or `csv`; `typed_phrase` is
    /// what the user typed after the warning, which must be exactly
    /// [`plaintext_export_phrase`]. Needs a re-authentication confirmed within
    /// [`REAUTH_WINDOW_MS`] and the hold after [`Session::plaintext_warning_shown`] to be over
    /// (owner decision 2026-10-05), and spends both. The bytes are plaintext: the host hands
    /// them to the user as a download and keeps no copy.
    ///
    /// # Errors
    /// `locked`; `reauth_required`; `unknown_format`; `plaintext_export_not_acknowledged`;
    /// `plaintext_export_hold`; `export_oversize_items`; `export_too_large`.
    #[wasm_bindgen(js_name = exportPlaintext)]
    pub fn export_plaintext(
        &mut self,
        vault_id: &str,
        format: &str,
        typed_phrase: &str,
        now_ms: u64,
    ) -> Result<Vec<u8>, CoreError> {
        let inner = self.inner_mut()?;
        if !inner.gate.reauth_fresh(now_ms) {
            return Err(ClientError::ReauthRequired.into());
        }
        let json = match format {
            "json" => true,
            "csv" => false,
            _ => return Err(CoreError::new(UNKNOWN_FORMAT)),
        };
        let ack = PlaintextExportAck::from_typed_phrase(typed_phrase)?;
        let auth = inner.gate.authorize_plaintext(now_ms)?;
        let bytes = if json {
            inner
                .vaults
                .get_mut(items::vault_id(vault_id)?)?
                .export_plaintext_json(auth, ack, now_ms)?
        } else {
            inner
                .vaults
                .get_mut(items::vault_id(vault_id)?)?
                .export_plaintext_csv(auth, ack)?
        };
        Ok(bytes.expose_secret().to_vec())
    }

    /// Imports a file of another product, or our own plaintext JSON export, as new items.
    /// `format` is one of `bitwarden-json`, `1pux`, `keepass-xml`, `csv`, `chrome-csv`,
    /// `firefox-csv`, `rizzy-json`, `aliasvault-csv`, `aliasvault-avux`, `cxf-json` (a bare
    /// CXF passkey file, ADR 0074 §3). The report has counts only (INV-48).
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `unknown_format`; `invalid_input` for a file
    /// over [`MAX_IMPORT_FILE_LEN`]; `import_failed` when the file as a whole is refused;
    /// `read_only`.
    #[wasm_bindgen(js_name = importFile)]
    pub fn import_file(
        &mut self,
        vault_id: &str,
        format: &str,
        file: &[u8],
        now_ms: u64,
    ) -> Result<ImportReport, CoreError> {
        let format = match format {
            "bitwarden-json" => Format::BitwardenJson,
            "1pux" => Format::OnePux,
            "keepass-xml" => Format::KeePassXml,
            "csv" => Format::GenericCsv,
            "chrome-csv" => Format::ChromeCsv,
            "firefox-csv" => Format::FirefoxCsv,
            "rizzy-json" => Format::RizzyPlaintextJson,
            "aliasvault-csv" => Format::AliasVaultCsv,
            "aliasvault-avux" => Format::AliasVaultAvux,
            "cxf-json" => Format::CxfJson,
            _ => return Err(CoreError::new(UNKNOWN_FORMAT)),
        };
        if file.len() > MAX_IMPORT_FILE_LEN {
            return Err(ClientError::InvalidInput.into());
        }
        let inner = self.writable()?;
        let parsed = rizzy_import::import(format, file, &mut inner.rng)
            .map_err(|_| CoreError::new(IMPORT_FAILED))?;
        let done = inner
            .vaults
            .get_mut(items::vault_id(vault_id)?)?
            .import_items(&mut inner.rng, &inner.unlocked, &parsed.items, now_ms)?;
        let counts = parsed.counts;
        Ok(ImportReport {
            imported: done.imported.len(),
            skipped: done.skipped.len().saturating_add(counts.skipped_items),
            warnings: parsed.warnings.len(),
            collapsed_conflicts: counts.collapsed_conflicts,
            history_not_carried: counts.dropped_history,
            fields_not_carried: counts.dropped_fields,
            credentials_skipped: counts.skipped_credentials,
        })
    }

    /// Imports our own CXF passkey export (`rizzy-vault-cxf-export`, ADR 0074 §2–§3) with its
    /// export password, one new Login item per passkey. The report has counts only (INV-48).
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for a file over
    /// [`MAX_IMPORT_FILE_LEN`]; `invalid_export_file` (another tag or payload version
    /// included); `export_decryption_failed`; `export_update_required`; `read_only`.
    /// `export_password` is UTF-8 bytes, zeroed on return whatever the outcome
    /// ([`crate::secret`]).
    #[wasm_bindgen(js_name = importCxfEncrypted)]
    pub fn import_cxf_encrypted(
        &mut self,
        vault_id: &str,
        file: &[u8],
        export_password: &mut [u8],
        now_ms: u64,
    ) -> Result<ImportReport, CoreError> {
        let export_password = take_secret(export_password)?;
        if file.len() > MAX_IMPORT_FILE_LEN {
            return Err(ClientError::InvalidInput.into());
        }
        let inner = self.writable()?;
        let done = inner
            .vaults
            .get_mut(items::vault_id(vault_id)?)?
            .import_cxf_encrypted(
                &mut inner.rng,
                &inner.unlocked,
                file,
                &export_password,
                now_ms,
            )?;
        Ok(ImportReport {
            imported: done.imported.len(),
            skipped: done.skipped.len().saturating_add(done.counts.skipped_items),
            warnings: done.warnings.len(),
            collapsed_conflicts: done.counts.collapsed_conflicts,
            history_not_carried: done.counts.dropped_history,
            fields_not_carried: done.counts.dropped_fields,
            credentials_skipped: done.counts.skipped_credentials,
        })
    }

    /// Imports our own encrypted export file with its export password, as new items.
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `invalid_input` for a file over
    /// [`MAX_IMPORT_FILE_LEN`]; `invalid_export_file`; `export_decryption_failed`;
    /// `export_update_required`; `read_only`. `export_password` is UTF-8 bytes, zeroed on
    /// return whatever the outcome ([`crate::secret`]).
    #[wasm_bindgen(js_name = importEncrypted)]
    pub fn import_encrypted(
        &mut self,
        vault_id: &str,
        file: &[u8],
        export_password: &mut [u8],
        now_ms: u64,
    ) -> Result<ImportReport, CoreError> {
        let export_password = take_secret(export_password)?;
        if file.len() > MAX_IMPORT_FILE_LEN {
            return Err(ClientError::InvalidInput.into());
        }
        let inner = self.writable()?;
        let done = inner
            .vaults
            .get_mut(items::vault_id(vault_id)?)?
            .import_encrypted(
                &mut inner.rng,
                &inner.unlocked,
                file,
                &export_password,
                now_ms,
            )?;
        Ok(ImportReport {
            imported: done.imported.len(),
            skipped: done.skipped_items,
            warnings: 0,
            collapsed_conflicts: done.collapsed_fields,
            history_not_carried: done.history_not_carried,
            fields_not_carried: done.fields_not_carried,
            credentials_skipped: 0,
        })
    }

    /// The account's durable devices (the signed device set), as the last verified account
    /// answer lists them (the login's, or the last sync's).
    ///
    /// # Errors
    /// `locked`.
    pub fn devices(&self) -> Result<Vec<DeviceView>, CoreError> {
        let inner = self.inner()?;
        let revocations = inner.account.revocations();
        Ok(inner
            .account
            .certificates()
            .iter()
            .filter(|c| c.certificate.in_device_set())
            .map(|c| {
                let certificate = &c.certificate;
                DeviceView {
                    id: hex(certificate.device_id.as_bytes()),
                    kind: kind_name(certificate.device_kind),
                    created_at_ms: certificate.created_at_ms,
                    revoked: revocations
                        .iter()
                        .any(|r| r.revocation.device_id == certificate.device_id),
                }
            })
            .collect())
    }

    /// `sessions/list` ([ADR 0075] R1): the account's live sessions.
    ///
    /// [ADR 0075]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0075-session-listing-and-ending.md
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = sessionsListRequest)]
    pub fn sessions_list_request(&self) -> Result<HttpRequest, CoreError> {
        Ok(HttpRequest::post_empty(
            paths::SESSIONS_LIST,
            Some(&self.inner()?.token),
        ))
    }

    /// Reads the answer to [`Session::sessions_list_request`]: the rows, newest first. The list
    /// is kept, so that [`Session::end_session_request`] names only a row it holds. The list is
    /// the server's word (AR-9), for display: never proof that nothing else is open.
    ///
    /// # Errors
    /// `locked`; the server's code; `invalid_server_response`.
    #[wasm_bindgen(js_name = sessionsListResponse)]
    pub fn sessions_list_response(
        &mut self,
        status: u16,
        body: &[u8],
    ) -> Result<Vec<SessionRow>, CoreError> {
        let inner = self.inner_mut()?;
        let answer: SessionListResponse = http::json(status, body)?;
        let list = SessionList::from_response(answer)?;
        let rows = list.sessions().iter().map(SessionRow::of).collect();
        inner.sessions = Some(list);
        Ok(rows)
    }

    /// Whether the last list stopped short of the account's live sessions (`truncated`).
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = sessionsTruncated)]
    pub fn sessions_truncated(&self) -> Result<bool, CoreError> {
        Ok(self
            .inner()?
            .sessions
            .as_ref()
            .is_some_and(SessionList::truncated))
    }

    /// `sessions/end` (R3) for the row `id` (32 hex digits) of the last list; its answer is
    /// an empty success. Needs a fresh session: on `server_fresh_session_required` the host
    /// runs [`Session::refresh`] and asks again.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id that is not a row of the last list, or a row that may
    /// not be ended (a device row, ADR 0075 §5; the current session, which signs out instead).
    #[wasm_bindgen(js_name = endSessionRequest)]
    pub fn end_session_request(&self, id: &str) -> Result<HttpRequest, CoreError> {
        let inner = self.inner()?;
        let wanted = parse_id(id)?;
        let row = inner
            .sessions
            .as_ref()
            .and_then(|l| l.sessions().iter().find(|s| s.session_id() == wanted))
            .ok_or(CoreError::from(ClientError::InvalidInput))?;
        HttpRequest::post(paths::SESSIONS_END, &row.end_request()?, Some(&inner.token))
    }

    /// `sessions/others/end` (R4): every other password and recovery session; device sessions
    /// stay (ADR 0075 §5). Its answer is an empty success. Needs a fresh session, as
    /// [`Session::end_session_request`].
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = endOtherSessionsRequest)]
    pub fn end_other_sessions_request(&self) -> Result<HttpRequest, CoreError> {
        Ok(HttpRequest::post_empty(
            paths::SESSIONS_OTHERS_END,
            Some(&self.inner()?.token),
        ))
    }

    /// `sessions/current/end` (R2), sign-out: the request a host sends, best effort and never
    /// retried, when it locks (ADR 0075 §6). Build it before [`Session::lock`], which drops the
    /// token.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = signOutRequest)]
    pub fn sign_out_request(&self) -> Result<HttpRequest, CoreError> {
        Ok(HttpRequest::post_empty(
            paths::SESSIONS_CURRENT_END,
            Some(&self.inner()?.token),
        ))
    }

    /// Starts a fresh OPAQUE login of this session's account (ADR 0075 §9: "Without freshness,
    /// the pane first runs a login"), with the Secret Key and master password typed again. The
    /// host runs the returned flow to `"done"` and passes it to [`Session::adopt_refresh`].
    ///
    /// # Errors
    /// `locked`; as [`LoginFlow::start`], whose byte-array rules `secret_key` and `password`
    /// follow (both zeroed on return, [`crate::secret`]).
    pub fn refresh(
        &self,
        secret_key: &mut [u8],
        password: &mut [u8],
        totp: Option<String>,
    ) -> Result<LoginFlow, CoreError> {
        // Both are taken, and so wiped, before any error returns.
        let secret_key = take_secret(secret_key);
        let password = take_secret(password);
        let inner = self.inner()?;
        LoginFlow::begin(
            Credentials {
                origin: inner.origin.clone(),
                login_name: inner.login_name.clone(),
                secret_key: secret_key?,
                password: password?,
            },
            totp.map(Zeroizing::new),
            Purpose::Refresh,
        )
    }

    /// Switches to the fresh session of a finished [`Session::refresh`] and returns the
    /// sign-out (R2) of the old one, for the host to send best effort.
    ///
    /// # Errors
    /// `locked`; `wrong_state` unless the flow is a refresh in state `"done"` (taken once);
    /// `wrong_password_or_secret_key` if it verified another account.
    #[wasm_bindgen(js_name = adoptRefresh)]
    pub fn adopt_refresh(&mut self, flow: &mut LoginFlow) -> Result<HttpRequest, CoreError> {
        let inner = self.inner_mut()?;
        if flow.purpose() != Purpose::Refresh {
            return Err(CoreError::new(WRONG_STATE));
        }
        let (account, token) = flow.take_refreshed().ok_or(CoreError::new(WRONG_STATE))?;
        if account != inner.account_id {
            return Err(ClientError::WrongPasswordOrSecretKey.into());
        }
        let old = core::mem::replace(&mut inner.token, token);
        Ok(HttpRequest::post_empty(
            paths::SESSIONS_CURRENT_END,
            Some(&old),
        ))
    }

    /// `totp/enrol/start` (CRYPTO.md §11.15): the server generates the 2FA secret.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = twoFactorEnrolRequest)]
    pub fn two_factor_enrol_request(&self) -> Result<HttpRequest, CoreError> {
        Ok(HttpRequest::post_empty(
            paths::TOTP_ENROL_START,
            Some(&self.inner()?.token),
        ))
    }

    /// Reads the answer to [`Session::two_factor_enrol_request`]: the enrolment to show once
    /// (QR code or Base32) and confirm.
    ///
    /// # Errors
    /// `locked`; the server's code; `invalid_server_response`.
    #[wasm_bindgen(js_name = twoFactorEnrolResponse)]
    pub fn two_factor_enrol_response(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<TwoFactorEnrolment, CoreError> {
        let inner = self.inner()?;
        let answer: TotpEnrolStartResponse = http::json(status, body)?;
        Ok(TwoFactorEnrolment {
            enrolment: TotpEnrolment::from_response(&answer, &inner.origin, &inner.login_name)?,
        })
    }

    /// `totp/enrol/confirm` with the current code of the user's authenticator; its answer is
    /// an empty success ([`crate::http::expect_no_content`]).
    ///
    /// # Errors
    /// `locked`; `invalid_input` for a code that is not 6–8 digits.
    #[wasm_bindgen(js_name = twoFactorConfirmRequest)]
    pub fn two_factor_confirm_request(
        &self,
        enrolment: &TwoFactorEnrolment,
        code: &str,
    ) -> Result<HttpRequest, CoreError> {
        let request = enrolment.enrolment.confirm_request(code)?;
        HttpRequest::post(
            paths::TOTP_ENROL_CONFIRM,
            &request,
            Some(&self.inner()?.token),
        )
    }

    /// `totp/disable` with a current code; its answer is an empty success.
    ///
    /// # Errors
    /// As [`Session::two_factor_confirm_request`].
    #[wasm_bindgen(js_name = twoFactorDisableRequest)]
    pub fn two_factor_disable_request(&self, code: &str) -> Result<HttpRequest, CoreError> {
        let request = disable_request(code)?;
        HttpRequest::post(paths::TOTP_DISABLE, &request, Some(&self.inner()?.token))
    }
}

/// Account settings: the match default and the equivalence groups (ADR 0037 §6–§7; ADR 0042).
///
/// Reading goes through `rizzy_client::settings::SettingsCache`, so the `ACCOUNT_SETTINGS` of the
/// session's verified account is decrypted and parsed once per object (ADR 0042 §6). A change is
/// one `account/commit` (ADR 0042 §5): one of the `…Request` calls below builds it and returns the
/// request; the host sends it and passes the answer to [`Session::settings_respond`]. On
/// `server_state_conflict` the host syncs (the sync's `account/state` step refreshes the account)
/// and calls [`Session::settings_retry_request`], which lets `CasRetry` decide and redoes the same
/// edit on the current record. The server takes a settings commit only over a fresh OPAQUE
/// session (CRYPTO.md §11 "Replacing credentials"): a web session older than five minutes gets
/// `server_fresh_session_required`, and the host asks the user to log in again.
#[wasm_bindgen]
impl Session {
    /// The account's matching settings, against this build's global list.
    ///
    /// # Errors
    /// `locked`; `settings_update_required` for settings a newer rizzy-vault wrote;
    /// `invalid_server_response` for settings that do not open or parse; `account_key_rotated`.
    #[wasm_bindgen(js_name = matchSettings)]
    pub fn match_settings(&mut self) -> Result<MatchSettingsView, CoreError> {
        let inner = self.inner_mut()?;
        let record = inner.settings.get(&inner.account, &inner.unlocked)?;
        Ok(matching::settings_view(
            record.matching(),
            &inner.global_groups,
        ))
    }

    /// The autofill candidates among this vault's items for `page_url` as a top frame, under the
    /// account's settings (ADR 0037 §4; ADR 0042 §6): what the extension would offer there. The
    /// settings screen uses it to show what a change does.
    ///
    /// # Errors
    /// `locked`; as [`Session::match_settings`]; `invalid_input` if `page_url` does not parse.
    #[wasm_bindgen(js_name = matchCandidates)]
    pub fn match_candidates(&mut self, page_url: &str) -> Result<MatchDecision, CoreError> {
        let inner = self.inner_mut()?;
        let record = inner.settings.get(&inner.account, &inner.unlocked)?;
        // ADR 0081 §A7: every vault's items; the matcher keys by a stand-in id per URI, mapped
        // back to the item reference (`matching::synthetic_id`, INV-103).
        let mut names = Vec::new();
        let mut saved = Vec::new();
        for vault in inner.vaults.all() {
            for mut uri in vault_item_uris(vault) {
                let name = item_ref(vault.vault_id(), ItemId::from_bytes(uri.item_id));
                uri.item_id = matching::synthetic_id(names.len());
                names.push(name);
                saved.push(uri);
            }
        }
        let uris: Vec<ItemUri<'_>> = saved.iter().map(SavedUri::as_item_uri).collect();
        let frame = FrameContext {
            is_top_frame: true,
            frame_origin: page_url,
        };
        let decision = decide_with_settings(page_url, &frame, &uris, record, &inner.global_groups)?;
        Ok(matching::decision_view_named(decision, &names))
    }

    /// The identity generator's synced defaults (`ACCOUNT_SETTINGS` tag `0x0004`, ADR 0079 Open
    /// question 7); `undefined` until first set.
    ///
    /// # Errors
    /// As [`Session::match_settings`].
    #[wasm_bindgen(js_name = identityDefaults)]
    pub fn identity_defaults(&mut self) -> Result<Option<IdentityDefaultsView>, CoreError> {
        let inner = self.inner_mut()?;
        let record = inner.settings.get(&inner.account, &inner.unlocked)?;
        Ok(record
            .identity_defaults()
            .cloned()
            .map(IdentityDefaultsView::new))
    }

    /// Sets the identity generator's defaults: the commit request. `sex` is `male`, `female`
    /// or `random`; `email_style` `name` or `nickname`; an empty or absent `country` or
    /// `email_domain` means none.
    ///
    /// # Errors
    /// The `identity_*` codes of the values (`crate::identity::identity_error`); as the private
    /// `settings_change` (impl docs).
    #[wasm_bindgen(js_name = setIdentityDefaultsRequest)]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "wasm-bindgen passes an optional string by value"
    )]
    pub fn set_identity_defaults_request(
        &mut self,
        sex: &str,
        country: Option<String>,
        age_min: u8,
        age_max: u8,
        email_style: &str,
        email_domain: Option<String>,
    ) -> Result<HttpRequest, CoreError> {
        let defaults = identity::identity_defaults(
            sex,
            country.as_deref(),
            age_min,
            age_max,
            email_style,
            email_domain.as_deref(),
        )?;
        self.settings_change(SettingsEdit::SetIdentityDefaults(defaults))
    }

    /// Sets the account-level match default (`0x0001`–`0x0006`): the commit request.
    ///
    /// # Errors
    /// `invalid_input` for `0x0000` or an unassigned value; as the private `settings_change` (impl docs).
    #[wasm_bindgen(js_name = setMatchDefaultRequest)]
    pub fn set_match_default_request(&mut self, mode: u16) -> Result<HttpRequest, CoreError> {
        let mode = matching::default_mode_of(mode)?;
        self.settings_change(SettingsEdit::SetMatchDefault(mode))
    }

    /// Adds a user-defined equivalence group of `domains` (2 to 64, each a registrable domain):
    /// the commit request.
    ///
    /// # Errors
    /// `equivalence_domain_rejected` for a public suffix or a subdomain; `invalid_input` for a
    /// domain that does not normalise or a bad count; `settings_limit_reached` past 64 groups;
    /// as the private `settings_change` (impl docs).
    #[wasm_bindgen(js_name = addUserGroupRequest)]
    pub fn add_user_group_request(
        &mut self,
        domains: Vec<String>,
    ) -> Result<HttpRequest, CoreError> {
        self.settings_change(SettingsEdit::AddUserGroup(domains))
    }

    /// Removes the user-defined group `id` (hex): the commit request.
    ///
    /// # Errors
    /// `invalid_input` for a malformed id or one no user group has; as
    /// the private `settings_change` (impl docs).
    #[wasm_bindgen(js_name = removeUserGroupRequest)]
    pub fn remove_user_group_request(&mut self, id: &str) -> Result<HttpRequest, CoreError> {
        let id = matching::group_id_of(id)?;
        self.settings_change(SettingsEdit::RemoveUserGroup(id))
    }

    /// Disables the global group `id` (hex): the commit request.
    ///
    /// # Errors
    /// `invalid_input` for a malformed id or one already disabled; `settings_limit_reached`
    /// past 1,024; as the private `settings_change` (impl docs).
    #[wasm_bindgen(js_name = disableGlobalGroupRequest)]
    pub fn disable_global_group_request(&mut self, id: &str) -> Result<HttpRequest, CoreError> {
        let id = matching::group_id_of(id)?;
        self.settings_change(SettingsEdit::DisableGlobalGroup(id))
    }

    /// Enables the global group `id` (hex) again: the commit request.
    ///
    /// # Errors
    /// `invalid_input` for a malformed id or one not disabled; as the private `settings_change` (impl docs).
    #[wasm_bindgen(js_name = enableGlobalGroupRequest)]
    pub fn enable_global_group_request(&mut self, id: &str) -> Result<HttpRequest, CoreError> {
        let id = matching::group_id_of(id)?;
        self.settings_change(SettingsEdit::EnableGlobalGroup(id))
    }

    /// The answer to the settings commit: on success the session takes the new settings.
    ///
    /// # Errors
    /// `locked`; `wrong_state` with no change outstanding; the server's code otherwise. On
    /// `server_state_conflict` the change is kept for [`Session::settings_retry_request`];
    /// after any other error it is dropped.
    #[wasm_bindgen(js_name = settingsRespond)]
    pub fn settings_respond(&mut self, status: u16, body: &[u8]) -> Result<(), CoreError> {
        let inner = self.inner_mut()?;
        let pending = inner
            .settings_pending
            .take()
            .ok_or(CoreError::new(WRONG_STATE))?;
        match http::empty(status, body) {
            Ok(()) => {
                inner.settings.clear();
                Ok(pending.finalize(&mut inner.account)?)
            }
            Err(e) => {
                if http::server_code(status, body) == Some(ErrorCode::StateConflict) {
                    inner.settings_pending = Some(pending);
                }
                Err(e)
            }
        }
    }

    /// After `server_state_conflict` and a sync: the change rebuilt on the account the sync
    /// verified (`CasRetry`: a rollback or fork stops it; otherwise the same edit is redone on the
    /// current record).
    ///
    /// # Errors
    /// `locked`; `wrong_state` with no change kept or while a sync runs; `rollback`, `fork`;
    /// as the private `settings_change` (impl docs).
    #[wasm_bindgen(js_name = settingsRetryRequest)]
    pub fn settings_retry_request(&mut self) -> Result<HttpRequest, CoreError> {
        let inner = self.writable()?;
        let pending = inner
            .settings_pending
            .take()
            .ok_or(CoreError::new(WRONG_STATE))?;
        let retried = pending.on_state_conflict(&mut inner.rng, &inner.account, &inner.unlocked)?;
        let request = HttpRequest::post(
            paths::ACCOUNT_COMMIT,
            retried.commit_request(),
            Some(&inner.token),
        )?;
        inner.settings_pending = Some(retried);
        Ok(request)
    }
}

impl Session {
    /// Builds one settings change and keeps it until [`Session::settings_respond`] (impl docs).
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `read_only` after a rollback or fork;
    /// `settings_update_required` and `invalid_server_response` for settings this build cannot read
    /// (no write is built over them, ADR 0042 §2); `account_key_rotated`.
    fn settings_change(&mut self, edit: SettingsEdit) -> CoreResult<HttpRequest> {
        let inner = self.writable()?;
        if !inner
            .vaults
            .personal_vault()
            .is_ok_and(|v| !v.is_read_only())
        {
            return Err(ClientError::ReadOnly.into());
        }
        let pending = change_settings(&mut inner.rng, &inner.account, &inner.unlocked, edit)?;
        let request = HttpRequest::post(
            paths::ACCOUNT_COMMIT,
            pending.commit_request(),
            Some(&inner.token),
        )?;
        inner.settings_pending = Some(pending);
        Ok(request)
    }
}

/// The name of a device kind.
const fn kind_name(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::DesktopCli => "desktop-cli",
        DeviceKind::Extension => "extension",
        DeviceKind::Mobile => "mobile",
        DeviceKind::WebEphemeral => "web",
    }
}

/// The warning shown before a CXF passkey export (ADR 0074 §2 "Warning": its own text, not
/// [`plaintext_export_warning`]'s), under the same gate: re-authentication, the hold, and the
/// typed [`plaintext_export_phrase`] (owner answer 3).
#[wasm_bindgen(js_name = cxfExportWarning)]
#[must_use]
pub fn cxf_export_warning() -> String {
    CXF_EXPORT_WARNING.to_owned()
}

/// The frozen warning shown before a plaintext export (ADR 0027 §5).
#[wasm_bindgen(js_name = plaintextExportWarning)]
#[must_use]
pub fn plaintext_export_warning() -> String {
    PLAINTEXT_EXPORT_WARNING.to_owned()
}

/// The phrase the user types to allow a plaintext export (ADR 0027 §5).
#[wasm_bindgen(js_name = plaintextExportPhrase)]
#[must_use]
pub fn plaintext_export_phrase() -> String {
    PLAINTEXT_EXPORT_PHRASE.to_owned()
}

/// How long the host holds the user after the plaintext-export warning, in milliseconds: 10
/// seconds (owner decision 2026-10-05; `rizzy_client::export::gate`).
#[wasm_bindgen(js_name = plaintextExportHoldMs)]
#[must_use]
pub fn plaintext_export_hold_ms() -> u32 {
    u32::try_from(gate::PLAINTEXT_EXPORT_HOLD_MS).unwrap_or(u32::MAX)
}

/// The format of an import file, recognised from its bytes (owner decision 2026-10-05;
/// `rizzy_client::export::detect`): `rizzy-encrypted` (open it with
/// [`Session::import_encrypted`] and the file's password), `rizzy-cxf-encrypted` (our CXF
/// passkey export, ADR 0074 §2: open it with [`Session::import_cxf_encrypted`] and the file's
/// password), an [`Session::import_file`] format name (`cxf-json` for a bare CXF file), `rizzy-csv` (our plaintext CSV export, which cannot be imported), or `unknown` (the
/// host asks the user to name the format). A file over [`MAX_IMPORT_FILE_LEN`] is `unknown`.
/// The answer names a kind only, never a byte of the file.
#[wasm_bindgen(js_name = detectImportFormat)]
#[must_use]
pub fn detect_import_format(file: &[u8]) -> String {
    let name = if file.len() > MAX_IMPORT_FILE_LEN {
        "unknown"
    } else {
        match detect_format(file) {
            Some(DetectedFormat::RizzyEncrypted) => "rizzy-encrypted",
            Some(DetectedFormat::RizzyCxfEncrypted) => "rizzy-cxf-encrypted",
            Some(DetectedFormat::RizzyPlaintextCsv) => "rizzy-csv",
            Some(DetectedFormat::Import(format)) => match format {
                Format::BitwardenJson => "bitwarden-json",
                Format::OnePux => "1pux",
                Format::KeePassXml => "keepass-xml",
                Format::GenericCsv => "csv",
                Format::ChromeCsv => "chrome-csv",
                Format::FirefoxCsv => "firefox-csv",
                Format::RizzyPlaintextJson => "rizzy-json",
                Format::AliasVaultCsv => "aliasvault-csv",
                Format::AliasVaultAvux => "aliasvault-avux",
                Format::CxfJson => "cxf-json",
                _ => "unknown",
            },
            _ => "unknown",
        }
    };
    name.to_owned()
}

/// A TOTP code (CRYPTO.md §11.15). The code is wiped when freed.
#[wasm_bindgen]
pub struct TotpCode {
    /// The digits.
    code: Zeroizing<String>,
    /// Seconds until it changes.
    valid_for_s: u64,
    /// The period.
    period_s: u64,
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpCode")
            .field("valid_for_s", &self.valid_for_s)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl TotpCode {
    /// The digits.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn code(&self) -> String {
        self.code.as_str().to_owned()
    }

    /// Seconds until the code changes.
    #[wasm_bindgen(getter, js_name = validForSeconds)]
    #[must_use]
    pub fn valid_for_s(&self) -> u32 {
        u32::try_from(self.valid_for_s).unwrap_or(u32::MAX)
    }

    /// The period in seconds.
    #[wasm_bindgen(getter, js_name = periodSeconds)]
    #[must_use]
    pub fn period_s(&self) -> u32 {
        u32::try_from(self.period_s).unwrap_or(u32::MAX)
    }
}

/// A CXF passkey export (ADR 0074 §2): the file's bytes and how many passkeys it holds.
#[wasm_bindgen]
#[derive(Debug)]
pub struct CxfExport {
    /// The file (ciphertext).
    file: Vec<u8>,
    /// Passkeys exported.
    passkeys: usize,
}

#[wasm_bindgen]
impl CxfExport {
    /// The file's bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn file(&self) -> Vec<u8> {
        self.file.clone()
    }

    /// Passkeys exported.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn passkeys(&self) -> usize {
        self.passkeys
    }
}

/// An encrypted export: the file's bytes and what it holds (counts only).
#[wasm_bindgen]
#[derive(Debug)]
pub struct EncryptedExport {
    /// The file (ciphertext).
    file: Vec<u8>,
    /// Items exported.
    items: usize,
    /// Items exported with conflicting values (their merged state).
    unresolved: usize,
}

#[wasm_bindgen]
impl EncryptedExport {
    /// The file's bytes.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn file(&self) -> Vec<u8> {
        self.file.clone()
    }

    /// Items exported.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn items(&self) -> usize {
        self.items
    }

    /// Items exported with conflicting values, as their merged state.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn unresolved(&self) -> usize {
        self.unresolved
    }
}

/// What an import did, as counts (INV-48: never a name or a value of the file).
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Items imported.
    imported: usize,
    /// Items skipped.
    skipped: usize,
    /// Entries with warnings.
    warnings: usize,
    /// Conflicting values collapsed to the displayed one.
    collapsed_conflicts: usize,
    /// History entries not carried.
    history_not_carried: usize,
    /// Fields not carried.
    fields_not_carried: usize,
    /// CXF credentials not imported: of another type than a passkey, or a passkey that could
    /// not be read (ADR 0074 §1, §3). Zero for the other formats.
    credentials_skipped: usize,
}

#[wasm_bindgen]
impl ImportReport {
    /// CXF credentials not imported (ADR 0074 §1, §3).
    #[wasm_bindgen(getter, js_name = credentialsSkipped)]
    #[must_use]
    pub fn credentials_skipped(&self) -> usize {
        self.credentials_skipped
    }

    /// Items imported.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn imported(&self) -> usize {
        self.imported
    }

    /// Items skipped.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Entries imported with warnings.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn warnings(&self) -> usize {
        self.warnings
    }

    /// Conflicting values collapsed to the displayed one.
    #[wasm_bindgen(getter, js_name = collapsedConflicts)]
    #[must_use]
    pub fn collapsed_conflicts(&self) -> usize {
        self.collapsed_conflicts
    }

    /// Password-history entries not carried.
    #[wasm_bindgen(getter, js_name = historyNotCarried)]
    #[must_use]
    pub fn history_not_carried(&self) -> usize {
        self.history_not_carried
    }

    /// Fields not carried.
    #[wasm_bindgen(getter, js_name = fieldsNotCarried)]
    #[must_use]
    pub fn fields_not_carried(&self) -> usize {
        self.fields_not_carried
    }
}

/// [`Notice::conflict_id`] for a concurrent trash: the hex of both dots, joined, so two
/// distinct conflicts between the same device pair and item (two different races, or the same
/// race re-read) compare equal only when both dots match. Not a persistent or wire format
/// (ADR 0018 §3 "Surfacing"): computed fresh for one in-memory host call, never stored.
fn concurrent_trash_conflict_id(trashed_dot: Dot, edited_dot: Dot) -> String {
    format!(
        "{}:{}",
        items::dot_hex(trashed_dot),
        items::dot_hex(edited_dot)
    )
}

/// [`Notice::kind`] of "An edit from `<device>` arrived for an item you deleted permanently.
/// Restore it as a new item?" (ADR 0018 §3 "Surfacing").
pub const NOTICE_LATE_EDIT: &str = "late-edit";
/// [`Notice::kind`] of "deleted on X while it was being edited on Y" (ADR 0012 §5).
pub const NOTICE_CONCURRENT_TRASH: &str = "concurrent-trash";

/// One notice of [`Session::take_notices`]: ids only, no item data.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Notice {
    /// [`NOTICE_LATE_EDIT`] or [`NOTICE_CONCURRENT_TRASH`].
    kind: &'static str,
    /// The item, hex.
    item: String,
    /// For a late edit, the devices whose edits arrived, ascending; for a concurrent trash,
    /// X (the device that deleted it) then Y (the device whose edit kept it). Hex.
    devices: Vec<String>,
    /// For a concurrent trash, this one conflict's own identity: the two dots, not just the
    /// device pair, so a host-side dedup (the web vault's `noticeKey`) can tell a second,
    /// genuinely distinct race between the same two devices on the same item apart from the
    /// first instead of mistaking it for a duplicate (`ConcurrentTrash` docs, ADR 0012 §2).
    /// `None` for a late edit, which has no per-conflict identity: `late_edit_devices` names
    /// devices, not one op. Not a persistent or wire format (ADR 0018 §3 "Surfacing"):
    /// computed fresh for one in-memory host call, never stored.
    conflict_id: Option<String>,
}

#[wasm_bindgen]
impl Notice {
    /// `late-edit` or `concurrent-trash`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_owned()
    }

    /// The item id, 32 hex digits.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn item(&self) -> String {
        self.item.clone()
    }

    /// The device ids, 32 hex digits each: the late edits' devices, or `[X, Y]` for a
    /// concurrent trash.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn devices(&self) -> Vec<String> {
        self.devices.clone()
    }

    /// This one conflict's own identity, for `concurrent-trash` only (`undefined` for
    /// `late-edit`): fold it into a host-side dedup key alongside `item` and `devices`, so a
    /// second race between the same two devices on the same item is kept, not dropped as a
    /// duplicate of the first.
    #[wasm_bindgen(getter, js_name = conflictId)]
    #[must_use]
    pub fn conflict_id(&self) -> Option<String> {
        self.conflict_id.clone()
    }
}

/// One row of the account's session list ([ADR 0075] §9).
///
/// [ADR 0075]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0075-session-listing-and-ending.md
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct SessionRow {
    /// The `session_id`, hex.
    id: String,
    /// `password-login`, `password-recheck`, `device`, `recovery` or `unknown`.
    kind: &'static str,
    /// The device of a device session or a password re-check, hex.
    device_id: Option<String>,
    /// Creation time.
    created_at_ms: u64,
    /// Expiry.
    expires_at_ms: u64,
    /// Whether this is this browser's session.
    current: bool,
    /// Whether "End" is offered.
    endable: bool,
}

impl SessionRow {
    /// The row of a listed session.
    fn of(session: &ListedSession) -> Self {
        Self {
            id: hex(&session.session_id()),
            kind: session.kind().name(),
            device_id: session.device_id().map(|d| hex(d.as_bytes())),
            created_at_ms: session.created_at_ms(),
            expires_at_ms: session.expires_at_ms(),
            current: session.current(),
            endable: session.endable(),
        }
    }
}

#[wasm_bindgen]
impl SessionRow {
    /// The `session_id`, 32 hex digits: the handle of [`Session::end_session_request`].
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// `password-login` (a web or password login), `password-recheck` (a password re-check
    /// on a device), `device`, `recovery` (an account recovery in progress) or `unknown`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_owned()
    }

    /// The device of a device session or a password re-check, 32 hex digits.
    #[wasm_bindgen(getter, js_name = deviceId)]
    #[must_use]
    pub fn device_id(&self) -> Option<String> {
        self.device_id.clone()
    }

    /// When the session was opened, milliseconds since the Unix epoch (the server's word).
    #[wasm_bindgen(getter, js_name = createdAtMs)]
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// When the session expires, milliseconds since the Unix epoch (the server's word).
    #[wasm_bindgen(getter, js_name = expiresAtMs)]
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Whether this is this browser's own session.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn current(&self) -> bool {
        self.current
    }

    /// Whether "End" is offered: another session's password login, re-check or recovery row,
    /// never a device row (ADR 0075 §5).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn endable(&self) -> bool {
        self.endable
    }
}

/// Whether a `401` answer to a request on `path` means the session has ended ([ADR 0075] §6):
/// every `/api/v1` request but `login/*`, `recovery/*` and the sign-out itself. The host then
/// locks and shows [`session_ended_notice`].
///
/// [ADR 0075]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0075-session-listing-and-ending.md
#[wasm_bindgen(js_name = endsSessionOnUnauthorized)]
#[must_use]
pub fn ends_session_on_unauthorized(path: &str) -> bool {
    sessions::ends_session_on_unauthorized(path)
}

/// What the ended web vault shows (ADR 0075 §6).
#[wasm_bindgen(js_name = sessionEndedNotice)]
#[must_use]
pub fn session_ended_notice() -> String {
    SESSION_ENDED_NOTICE.to_owned()
}

/// The confirmation after ending other sessions (ADR 0075 §8).
#[wasm_bindgen(js_name = othersEndedNotice)]
#[must_use]
pub fn others_ended_notice() -> String {
    OTHERS_ENDED_NOTICE.to_owned()
}

/// The confirmation after ending one session (ADR 0075 §8).
#[wasm_bindgen(js_name = sessionEndedByYouNotice)]
#[must_use]
pub fn session_ended_by_you_notice() -> String {
    SESSION_ENDED_BY_YOU_NOTICE.to_owned()
}

/// One durable device of the account.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct DeviceView {
    /// The device id, hex.
    id: String,
    /// `desktop-cli`, `extension` or `mobile`.
    kind: &'static str,
    /// When its certificate was made.
    created_at_ms: u64,
    /// Whether it is revoked.
    revoked: bool,
}

#[wasm_bindgen]
impl DeviceView {
    /// The device id, 32 hex digits.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// `desktop-cli`, `extension` or `mobile`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.to_owned()
    }

    /// When its certificate was made, milliseconds since the Unix epoch.
    #[wasm_bindgen(getter, js_name = createdAtMs)]
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Whether the device is revoked.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn revoked(&self) -> bool {
        self.revoked
    }
}

/// A started 2FA enrolment: the server's secret, to show once. Wiped when freed.
#[wasm_bindgen]
pub struct TwoFactorEnrolment {
    /// The client core's enrolment.
    enrolment: TotpEnrolment,
}

impl fmt::Debug for TwoFactorEnrolment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TwoFactorEnrolment([REDACTED])")
    }
}

#[wasm_bindgen]
impl TwoFactorEnrolment {
    /// The `otpauth://totp/` URI for the authenticator (a QR code). A secret.
    #[wasm_bindgen(getter, js_name = otpauthUri)]
    #[must_use]
    pub fn otpauth_uri(&self) -> String {
        self.enrolment.otpauth_uri().as_str().to_owned()
    }

    /// The secret as Base32, for manual entry. A secret.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn secret(&self) -> String {
        self.enrolment.secret_base32().as_str().to_owned()
    }
}
