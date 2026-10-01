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
//! | TOTP code | [`Session::totp`] |
//! | Export | [`Session::export_encrypted`]; [`Session::reauth`] + [`Session::confirm_reauth`] + [`Session::export_plaintext`] |
//! | Import | [`Session::import_file`], [`Session::import_encrypted`] |
//! | Devices | [`Session::devices`] |
//! | 2FA | [`Session::two_factor_enrol_request`], [`Session::two_factor_enrol_response`], [`Session::two_factor_confirm_request`], [`Session::two_factor_disable_request`] |
//!
//! Every write goes into the vault's memory first; the next sync uploads it. A write is refused
//! while a sync is running (`wrong_state`), so that the host never interleaves an edit with the
//! steps of one sync; the host syncs after a write.
//!
//! # Readings
//!
//! - **Re-authentication before a plaintext export** (ADR 0013 §3 rule 2: "an explicit
//!   plaintext export, after re-authentication"). The web vault has no local password check, so
//!   the re-authentication is an OPAQUE login of the same account ([`Session::reauth`]),
//!   accepted by [`Session::confirm_reauth`] for [`REAUTH_WINDOW_MS`] (the freshness window
//!   CRYPTO.md §11 "Replacing credentials" gives the server's fresh session) and spent by one
//!   export. The host's clock decides the window; a host that lies to itself only weakens its
//!   own check, as any code on the vault origin could call the same API (ADR 0013 §4, "Honest
//!   limit").
//! - **Devices** are those of the account answer last verified: the login's, then each sync's
//!   refresh ([`crate::sync`]). The host syncs before it lists them, as `rv device list` reads
//!   `account/state` first.

use core::fmt;

use rizzy_client::ClientError;
use rizzy_client::account::VerifiedAccount;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::export::plaintext::{
    PLAINTEXT_EXPORT_PHRASE, PLAINTEXT_EXPORT_WARNING, PlaintextExportAck, csv_export_warning,
};
use rizzy_client::items::{FieldEdit, ItemId};
use rizzy_client::login::WebSession;
use rizzy_client::rizzy_core::ids::AccountId;
use rizzy_client::rizzy_core::item::schema::LOGIN_TOTP;
use rizzy_client::rizzy_core::item::value::ValueRef;
use rizzy_client::rizzy_core::sign::DeviceKind;
use rizzy_client::rizzy_core::totp::{OtpAuthUri, TotpParams, TotpSecret};
use rizzy_client::rizzy_import::{self, Format};
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::rizzy_proto::totp::TotpEnrolStartResponse;
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::sync::{Authors, VaultSync};
use rizzy_client::two_factor::{TotpEnrolment, disable_request};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{
    CoreError, CoreResult, IMPORT_FAILED, LOCKED, REAUTH_REQUIRED, UNKNOWN_FORMAT, WRONG_STATE,
};
use crate::http::{self, HttpRequest};
use crate::items::{self, FieldView, ItemDraft, ItemSummary, hex, type_from_name, visible_item};
use crate::login::{Credentials, LoginFlow, Purpose};
use crate::rng::{Rng, os_rng};
use crate::secret::take_secret;
use crate::sync::{Ctx, SyncDriver};

/// How long a re-authentication allows a plaintext export: 5 minutes (module docs).
pub const REAUTH_WINDOW_MS: u64 = 5 * 60 * 1000;

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
    /// The personal vault.
    vault: VaultSync,
    /// The sync step driver.
    sync: SyncDriver,
    /// When the last accepted re-authentication happened, if it is unspent.
    reauth_at_ms: Option<u64>,
    /// The RNG.
    rng: Rng,
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
    /// The session of a verified web login: the personal vault's driver at `device_seq` 1
    /// (a new device), the authors of the verified account.
    ///
    /// # Errors
    /// `invalid_server_response` if the account answer carries no vault key.
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
        let vault_id = account
            .vault_ids()
            .next()
            .ok_or(ClientError::InvalidServerResponse)?;
        let vault_key = account
            .take_vault_key(vault_id)
            .ok_or(ClientError::InvalidServerResponse)?;
        let vault = VaultSync::new(vault_key, &unlocked, 1)?;
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
                vault,
                sync: SyncDriver::default(),
                reauth_at_ms: None,
                rng: os_rng(),
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
        let item = items::item_id(id)?;
        op(
            &mut inner.vault,
            &mut inner.rng,
            &inner.unlocked,
            item,
            now_ms,
        )?;
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
        Ok(self.inner()?.vault.is_read_only())
    }

    /// How many own ops the server has not acknowledged yet: what a lock now would lose.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(getter, js_name = unsentChanges)]
    pub fn unsent_changes(&self) -> Result<usize, CoreError> {
        Ok(self.inner()?.vault.unacknowledged().0)
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
        let ctx = Ctx {
            vault: &mut inner.vault,
            account: &mut inner.account,
            authors: &mut inner.authors,
            unlocked: &inner.unlocked,
            token: &inner.token,
            rng: &mut inner.rng,
        };
        inner.sync.start(&ctx)
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
            vault: &mut inner.vault,
            account: &mut inner.account,
            authors: &mut inner.authors,
            unlocked: &inner.unlocked,
            token: &inner.token,
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
        inner.sync.abort(&mut inner.vault);
        Ok(())
    }

    /// The active items, or the trashed ones, as summaries (no concealed value).
    ///
    /// # Errors
    /// `locked`.
    pub fn items(&self, trash: bool) -> Result<Vec<ItemSummary>, CoreError> {
        Ok(items::summaries(&self.inner()?.vault, trash))
    }

    /// One item's summary.
    ///
    /// # Errors
    /// `locked`; `invalid_input` for an id that is not 32 hex digits; `unknown_item`.
    pub fn item(&self, id: &str) -> Result<ItemSummary, CoreError> {
        let vault = &self.inner()?.vault;
        let item = visible_item(vault, id)?;
        items::summary(vault, item).ok_or(ClientError::UnknownItem.into())
    }

    /// One item's displayed fields; concealed values are withheld.
    ///
    /// # Errors
    /// As [`Session::item`].
    #[wasm_bindgen(js_name = itemFields)]
    pub fn item_fields(&self, id: &str) -> Result<Vec<FieldView>, CoreError> {
        let vault = &self.inner()?.vault;
        let item = visible_item(vault, id)?;
        Ok(items::fields(vault, item))
    }

    /// One field's value as text, concealed or not: call it only on the user's request.
    ///
    /// # Errors
    /// As [`Session::item`]; `unknown_item` for a field the item does not display;
    /// `invalid_input` for a value with no text form (bytes, an order key).
    #[wasm_bindgen(js_name = revealField)]
    pub fn reveal_field(&self, id: &str, key: &str) -> Result<String, CoreError> {
        let vault = &self.inner()?.vault;
        let item = visible_item(vault, id)?;
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
        item_type: &str,
        draft: &ItemDraft,
        now_ms: u64,
    ) -> Result<String, CoreError> {
        let item_type = type_from_name(item_type)?;
        let inner = self.writable()?;
        let writes = items::writes(&mut inner.rng, &inner.vault, None, draft)?;
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        let item =
            inner
                .vault
                .create_item(&mut inner.rng, &inner.unlocked, item_type, &edits, now_ms)?;
        Ok(hex(item.as_bytes()))
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
        let item = items::item_id(id)?;
        let writes = items::writes(&mut inner.rng, &inner.vault, Some(item), draft)?;
        let edits: Vec<FieldEdit<'_>> = writes
            .iter()
            .map(|(key, value)| FieldEdit { key, value })
            .collect();
        inner
            .vault
            .edit_item(&mut inner.rng, &inner.unlocked, item, &edits, now_ms)?;
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

    /// The current TOTP code of an item's `login.totp`, which holds an `otpauth://` URI or a
    /// bare Base32 secret (then SHA-1, 6 digits, 30 s; CRYPTO.md §11.15), at `now_ms`.
    ///
    /// # Errors
    /// As [`Session::item`]; `invalid_input` when the item has no valid time-based secret.
    pub fn totp(&self, id: &str, now_ms: u64) -> Result<TotpCode, CoreError> {
        let vault = &self.inner()?.vault;
        let item = visible_item(vault, id)?;
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

    /// The vault as an encrypted export file (CRYPTO.md §11.14; ADR 0027), under a new export
    /// password. Ciphertext: the host saves the bytes as a download.
    ///
    /// # Errors
    /// `locked`; `export_oversize_items`; `export_too_large`; `invalid_input` for an empty
    /// export password or one with an unassigned code point. `export_password` is UTF-8 bytes,
    /// zeroed on return ([`crate::secret`]).
    #[wasm_bindgen(js_name = exportEncrypted)]
    pub fn export_encrypted(
        &mut self,
        export_password: &mut [u8],
        now_ms: u64,
    ) -> Result<EncryptedExport, CoreError> {
        let export_password = take_secret(export_password)?;
        let inner = self.inner_mut()?;
        let exported = inner
            .vault
            .export_encrypted(&mut inner.rng, &export_password, now_ms)?;
        Ok(EncryptedExport {
            file: exported.file,
            items: exported.items,
            unresolved: exported.unresolved.len(),
        })
    }

    /// The ids of the items that stop an export (too large to encode; ADR 0027 §1). Empty
    /// when an export can be written.
    ///
    /// # Errors
    /// `locked`.
    #[wasm_bindgen(js_name = exportBlockers)]
    pub fn export_blockers(&self) -> Result<Vec<String>, CoreError> {
        Ok(self
            .inner()?
            .vault
            .export_blockers()
            .iter()
            .map(|i| hex(i.as_bytes()))
            .collect())
    }

    /// The warning the host shows before a CSV export, after [`plaintext_export_warning`]: the
    /// frozen text with the number of items that would lose data (ADR 0027 §5).
    ///
    /// # Errors
    /// `locked`; `export_oversize_items`.
    #[wasm_bindgen(js_name = csvExportWarning)]
    pub fn csv_export_warning(&self) -> Result<String, CoreError> {
        let loss = self.inner()?.vault.csv_export_loss()?;
        Ok(csv_export_warning(loss.items_losing_data()))
    }

    /// Starts the re-authentication a plaintext export needs: an OPAQUE login of this
    /// session's account, with the Secret Key and master password typed again. The host runs
    /// the returned flow to `"done"` and passes it to [`Session::confirm_reauth`].
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

    /// Accepts a finished re-authentication of this account, for one plaintext export within
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
        if account != inner.account_id {
            return Err(ClientError::WrongPasswordOrSecretKey.into());
        }
        inner.reauth_at_ms = Some(now_ms);
        Ok(())
    }

    /// The plaintext export (ADR 0027 §3–§5): `format` is `json` or `csv`; `typed_phrase` is
    /// what the user typed after the warning, which must be exactly
    /// [`plaintext_export_phrase`]. Needs a re-authentication confirmed within
    /// [`REAUTH_WINDOW_MS`], and spends it. The bytes are plaintext: the host hands them to the
    /// user as a download and keeps no copy.
    ///
    /// # Errors
    /// `locked`; `reauth_required`; `plaintext_export_not_acknowledged`; `unknown_format`;
    /// `export_oversize_items`; `export_too_large`.
    #[wasm_bindgen(js_name = exportPlaintext)]
    pub fn export_plaintext(
        &mut self,
        format: &str,
        typed_phrase: &str,
        now_ms: u64,
    ) -> Result<Vec<u8>, CoreError> {
        let inner = self.inner_mut()?;
        let fresh = inner
            .reauth_at_ms
            .is_some_and(|at| now_ms >= at && now_ms - at <= REAUTH_WINDOW_MS);
        if !fresh {
            return Err(CoreError::new(REAUTH_REQUIRED));
        }
        let json = match format {
            "json" => true,
            "csv" => false,
            _ => return Err(CoreError::new(UNKNOWN_FORMAT)),
        };
        let ack = PlaintextExportAck::from_typed_phrase(typed_phrase)?;
        inner.reauth_at_ms = None;
        let bytes = if json {
            inner.vault.export_plaintext_json(ack, now_ms)?
        } else {
            inner.vault.export_plaintext_csv(ack)?
        };
        Ok(bytes.expose_secret().to_vec())
    }

    /// Imports a file of another product, or our own plaintext JSON export, as new items.
    /// `format` is one of `bitwarden-json`, `1pux`, `keepass-xml`, `csv`, `chrome-csv`,
    /// `firefox-csv`, `rizzy-json`. The report has counts only (INV-48).
    ///
    /// # Errors
    /// `locked`; `wrong_state` while a sync runs; `unknown_format`; `invalid_input` for a file
    /// over [`MAX_IMPORT_FILE_LEN`]; `import_failed` when the file as a whole is refused;
    /// `read_only`.
    #[wasm_bindgen(js_name = importFile)]
    pub fn import_file(
        &mut self,
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
            _ => return Err(CoreError::new(UNKNOWN_FORMAT)),
        };
        if file.len() > MAX_IMPORT_FILE_LEN {
            return Err(ClientError::InvalidInput.into());
        }
        let inner = self.writable()?;
        let parsed = rizzy_import::import(format, file, &mut inner.rng)
            .map_err(|_| CoreError::new(IMPORT_FAILED))?;
        let done =
            inner
                .vault
                .import_items(&mut inner.rng, &inner.unlocked, &parsed.items, now_ms)?;
        let counts = parsed.counts;
        Ok(ImportReport {
            imported: done.imported.len(),
            skipped: done.skipped.len().saturating_add(counts.skipped_items),
            warnings: parsed.warnings.len(),
            collapsed_conflicts: counts.collapsed_conflicts,
            history_not_carried: counts.dropped_history,
            fields_not_carried: counts.dropped_fields,
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
        file: &[u8],
        export_password: &mut [u8],
        now_ms: u64,
    ) -> Result<ImportReport, CoreError> {
        let export_password = take_secret(export_password)?;
        if file.len() > MAX_IMPORT_FILE_LEN {
            return Err(ClientError::InvalidInput.into());
        }
        let inner = self.writable()?;
        let done = inner.vault.import_encrypted(
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

/// The name of a device kind.
const fn kind_name(kind: DeviceKind) -> &'static str {
    match kind {
        DeviceKind::DesktopCli => "desktop-cli",
        DeviceKind::Extension => "extension",
        DeviceKind::Mobile => "mobile",
        DeviceKind::WebEphemeral => "web",
    }
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
}

#[wasm_bindgen]
impl ImportReport {
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
