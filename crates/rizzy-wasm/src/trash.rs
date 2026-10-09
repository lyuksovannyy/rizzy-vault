//! The trash notices and the password history across the boundary (`rizzy-client`'s `trash`
//! and `history`; ADR 0012 §5, ADR 0018 §3 "Surfacing", §7; ADR 0013 §3 rule 3).
//!
//! - **Automatic purge**: [`crate::Session::purge_expired`] and its `DeviceSession` twin, which
//!   the host calls after a sync that completed ([`DEFAULT_TRASH_RETENTION_MS`]).
//! - **Password history** ([`PasswordHistoryEntry`]): the source and time of each past
//!   password, never the value; a value crosses only through `revealPasswordHistory`, on the
//!   user's request, as every concealed value does.
//! - **Late edits** ([`LateEditView`]): the purged items with late values to surface, and the
//!   devices that wrote them, for "An edit from `<device>` arrived for an item you deleted
//!   permanently. Restore it as a new item?".
//! - **Trash conflict** ([`TrashConflictView`]): "deleted on `<X>` while it was being edited on
//!   `<Y>`".
//!
//! Device ids cross as 32 hex digits; the host names them from its device list.

use rizzy_client::ClientError;
use rizzy_client::history::HistorySource;
use rizzy_client::sync::VaultSync;
/// The default trash retention, 30 days in milliseconds.
pub use rizzy_client::trash::DEFAULT_TRASH_RETENTION_MS;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::CoreResult;
use crate::items::{hex, item_id, kind_and_text, visible_item};

/// One past password: where it comes from and when. No value (module docs).
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct PasswordHistoryEntry {
    /// `edited` or `imported`.
    source: &'static str,
    /// When it was written or recorded, if known.
    at_ms: Option<u64>,
}

#[wasm_bindgen]
impl PasswordHistoryEntry {
    /// `edited` (a value an edit replaced) or `imported` (from another manager).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn source(&self) -> String {
        self.source.to_owned()
    }

    /// When it was written or recorded, milliseconds since the Unix epoch; `undefined` when
    /// an imported entry carries no time.
    #[wasm_bindgen(getter, js_name = atMs)]
    #[must_use]
    pub fn at_ms(&self) -> Option<u64> {
        self.at_ms
    }
}

/// A purged item with late values not yet surfaced.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct LateEditView {
    /// The purged item's id, hex.
    id: String,
    /// The devices that wrote the late values, hex.
    devices: Vec<String>,
}

#[wasm_bindgen]
impl LateEditView {
    /// The purged item's id, 32 hex digits.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// The ids of the devices whose edits arrived after the purge, 32 hex digits each.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn devices(&self) -> Vec<String> {
        self.devices.clone()
    }
}

/// An item whose edit won over a concurrent trash.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct TrashConflictView {
    /// The device that trashed it, hex.
    trashed_by: String,
    /// The device whose edit kept it, hex.
    edited_by: String,
    /// When the trash was written.
    trashed_at_ms: u64,
}

#[wasm_bindgen]
impl TrashConflictView {
    /// The device that trashed the item, 32 hex digits.
    #[wasm_bindgen(getter, js_name = trashedBy)]
    #[must_use]
    pub fn trashed_by(&self) -> String {
        self.trashed_by.clone()
    }

    /// The device whose edit kept the item, 32 hex digits.
    #[wasm_bindgen(getter, js_name = editedBy)]
    #[must_use]
    pub fn edited_by(&self) -> String {
        self.edited_by.clone()
    }

    /// When the losing trash was written, milliseconds since the Unix epoch.
    #[wasm_bindgen(getter, js_name = trashedAtMs)]
    #[must_use]
    pub fn trashed_at_ms(&self) -> u64 {
        self.trashed_at_ms
    }
}

/// The password history of the item `id` names, newest first, without values.
///
/// # Errors
/// `invalid_input` for an id that is not 32 hex digits; `unknown_item` for an item that is
/// not active or trashed.
pub(crate) fn password_history(
    vault: &VaultSync,
    id: &str,
) -> CoreResult<Vec<PasswordHistoryEntry>> {
    let item = visible_item(vault, id)?;
    Ok(vault
        .password_history(item)
        .iter()
        .map(|e| PasswordHistoryEntry {
            source: match e.source {
                HistorySource::Edited => "edited",
                HistorySource::Imported => "imported",
            },
            at_ms: e.at_ms,
        })
        .collect())
}

/// The value of the `index`th entry of [`password_history`], on the user's request only.
///
/// # Errors
/// As [`password_history`]; `unknown_item` for an index past the last entry.
pub(crate) fn reveal_password_history(
    vault: &VaultSync,
    id: &str,
    index: usize,
) -> CoreResult<Zeroizing<String>> {
    let item = visible_item(vault, id)?;
    let history = vault.password_history(item);
    let entry = history.get(index).ok_or(ClientError::UnknownItem)?;
    kind_and_text(&entry.value)
        .1
        .ok_or(ClientError::InvalidInput.into())
}

/// The late edits to surface, in item id order.
pub(crate) fn late_edits(vault: &VaultSync) -> Vec<LateEditView> {
    vault
        .late_edits()
        .iter()
        .map(|late| LateEditView {
            id: hex(late.item.as_bytes()),
            devices: late.devices.iter().map(|d| hex(d.as_bytes())).collect(),
        })
        .collect()
}

/// The trash conflict of the item `id` names, if any.
///
/// # Errors
/// As [`password_history`].
pub(crate) fn trash_conflict(vault: &VaultSync, id: &str) -> CoreResult<Option<TrashConflictView>> {
    let item = visible_item(vault, id)?;
    Ok(vault.trash_conflict(item).map(|c| TrashConflictView {
        trashed_by: hex(c.trashed_by.as_bytes()),
        edited_by: hex(c.edited_by.as_bytes()),
        trashed_at_ms: c.trashed_at_ms,
    }))
}

/// Dismisses the late-edit notice of the purged item `id` names.
///
/// # Errors
/// `invalid_input` for an id that is not 32 hex digits; `unknown_item` for an item that is
/// not purged.
pub(crate) fn dismiss_late_edit(vault: &mut VaultSync, id: &str) -> CoreResult<()> {
    vault.dismiss_late_edit(item_id(id)?)?;
    Ok(())
}
