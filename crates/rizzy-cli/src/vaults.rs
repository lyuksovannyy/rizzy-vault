// SPDX-License-Identifier: AGPL-3.0-only

//! The vault commands and the vault-aware lookups of every item command ([ADR 0081] Part A,
//! §A7, §A8).
//!
//! - **Items are named by `(vault, item)`** (INV-103). An item id or prefix given on the
//!   command line is looked up in every vault this device holds; a prefix that matches items in
//!   two vaults is refused with each match's vault and id listed.
//! - **Vaults are named by name or id.** `Personal` names the Personal vault (its name is never
//!   stored, §A1); any other name is the vault's own; a full id or a unique id prefix works for
//!   every vault. A name that matches two vaults is refused with the ids listed (§A8).
//! - **Default target.** `item create` and `import` write into the Personal vault unless
//!   `--vault` names another, and `export` exports the Personal vault unless `--vault` names
//!   another: there is no "last used" memory (owner answer 4).
//! - **Deleting** (§A5): the vault's name typed as confirmation, then either every item moved
//!   to Personal first (the default) or `--with-items`, over a fresh login with this device's
//!   password.
//!
//! [ADR 0081]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0081-multiple-vaults-personal-and-shared.md

use rizzy_client::ClientError;
use rizzy_client::items::{ItemId, ItemLifecycle};
use rizzy_client::sync::VaultSync;
use rizzy_client::vaults::{self as client_vaults, VaultLabel};
use rizzy_core::ids::VaultId;

use crate::commands::sync_after_write;
use crate::device::{Device, Env, Shown, user_items};
use crate::error::CliError;
use crate::paths::hex;

/// How the Personal vault is shown and named (§A1, owner answer 3).
pub const PERSONAL: &str = "Personal";

/// How a vault without a name is shown.
pub const UNTITLED: &str = "Untitled vault";

/// The label of `vault_id`: "Personal", the vault's name, or "Untitled vault".
#[must_use]
pub fn vault_label(device: &Device, vault_id: VaultId) -> String {
    let vaults = device.vaults();
    let label = match vaults.get(vault_id) {
        Some(vault) => client_vaults::vault_label(vaults.catalog(), vault),
        None if vaults.catalog().personal() == Some(vault_id) => VaultLabel::Personal,
        None => VaultLabel::Untitled,
    };
    match label {
        VaultLabel::Personal => PERSONAL.to_owned(),
        VaultLabel::Named(name) => name.as_str().to_owned(),
        VaultLabel::Untitled => UNTITLED.to_owned(),
    }
}

/// The vaults this device holds in display order: Personal first, then by label, then by id.
#[must_use]
pub fn ordered_vaults(device: &Device) -> Vec<VaultId> {
    let personal = device.vaults().catalog().personal();
    let mut ids: Vec<(bool, String, VaultId)> = device
        .vaults()
        .all()
        .iter()
        .map(|v| {
            let id = v.vault_id();
            (
                personal != Some(id),
                vault_label(device, id).to_lowercase(),
                id,
            )
        })
        .collect();
    ids.sort();
    ids.into_iter().map(|(_, _, id)| id).collect()
}

/// The vault `text` names (module docs).
///
/// # Errors
/// [`CliError::Refused`] for a name or prefix several vaults match, with their ids;
/// [`ClientError::UnknownVault`] when none matches.
pub fn resolve_vault(device: &Device, text: &str) -> Result<VaultId, CliError> {
    let held: Vec<VaultId> = device
        .vaults()
        .all()
        .iter()
        .map(VaultSync::vault_id)
        .collect();
    let wanted = text.to_ascii_lowercase();
    if let Some(id) = held.iter().find(|v| hex(v.as_bytes()) == wanted) {
        return Ok(*id);
    }
    let named: Vec<VaultId> = held
        .iter()
        .copied()
        .filter(|v| vault_label(device, *v) == text)
        .collect();
    match named.as_slice() {
        [one] => return Ok(*one),
        [] => {}
        several => {
            return Err(CliError::Refused(format!(
                "several vaults are named \"{text}\"; name one by its id: {}",
                id_list(several)
            )));
        }
    }
    if !wanted.is_empty() && wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        let prefixed: Vec<VaultId> = held
            .iter()
            .copied()
            .filter(|v| hex(v.as_bytes()).starts_with(&wanted))
            .collect();
        match prefixed.as_slice() {
            [one] => return Ok(*one),
            [] => {}
            several => {
                return Err(CliError::Refused(format!(
                    "several vaults start with that id: {}",
                    id_list(several)
                )));
            }
        }
    }
    Err(CliError::Client(ClientError::UnknownVault))
}

/// The ids of `vaults`, comma-separated.
fn id_list(vaults: &[VaultId]) -> String {
    vaults
        .iter()
        .map(|v| hex(v.as_bytes()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The target of a new item, an import or an export: the vault `--vault` names, or Personal.
///
/// # Errors
/// Those of [`resolve_vault`] and [`Device::personal`].
pub fn target_vault(device: &Device, vault: Option<&str>) -> Result<VaultId, CliError> {
    match vault {
        Some(text) => resolve_vault(device, text),
        None => device.personal(),
    }
}

/// The item `text` names among the items of every vault for which `candidate` holds (module
/// docs).
///
/// # Errors
/// [`CliError::BadInput`] for text that is not hex, or a prefix of several items of one vault;
/// [`CliError::Refused`] for a prefix of items in several vaults; [`ClientError::UnknownItem`].
pub fn resolve_among(
    device: &Device,
    text: &str,
    candidate: impl Fn(&VaultSync, ItemId) -> bool,
) -> Result<(VaultId, ItemId), CliError> {
    let wanted = text.to_ascii_lowercase();
    if wanted.is_empty() || !wanted.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::BadInput(
            "an item is named by its hex id or a prefix of it",
        ));
    }
    let mut found: Vec<(VaultId, ItemId)> = Vec::new();
    for vault in device.vaults().all() {
        for item in vault.item_ids() {
            if hex(item.as_bytes()).starts_with(&wanted) && candidate(vault, item) {
                found.push((vault.vault_id(), item));
            }
        }
    }
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(CliError::Client(ClientError::UnknownItem)),
        several if several.iter().all(|(v, _)| *v == several[0].0) => {
            Err(CliError::BadInput("several items start with that id"))
        }
        several => Err(CliError::Refused(format!(
            "items in several vaults start with that id; give more of it: {}",
            several
                .iter()
                .map(|(v, i)| format!("{} {}", vault_label(device, *v), hex(i.as_bytes())))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// The live item (active or in the trash) `text` names, in any vault.
///
/// # Errors
/// As [`resolve_among`].
pub fn resolve_item(device: &Device, text: &str) -> Result<(VaultId, ItemId), CliError> {
    resolve_among(device, text, |vault, item| {
        matches!(
            vault.item_lifecycle(item),
            ItemLifecycle::Active | ItemLifecycle::Trashed
        )
    })
}

/// The vault list's line for `vault_id`.
fn list_line(device: &Device, vault_id: VaultId) -> String {
    let label = vault_label(device, vault_id);
    let count = device
        .vaults()
        .get(vault_id)
        .map_or(0, |v| user_items(v, &[ItemLifecycle::Active]).len());
    let plural = if count == 1 { "" } else { "s" };
    let mut line = format!(
        "{}  {label}  {count} item{plural}",
        hex(vault_id.as_bytes())
    );
    if let Some(bytes) = device.vault_bytes_used(vault_id) {
        line = format!("{line}, {bytes} bytes");
    }
    match device.vaults().shown(vault_id) {
        Shown::Open => {}
        Shown::Withheld => line.push_str("  (withheld: read-only)"),
        Shown::NeedsUpdate => line.push_str("  (needs-update: needs a newer rizzy-vault)"),
        Shown::Closed => line.push_str("  (read-only)"),
    }
    line
}

/// `rv vault list`: Personal first, then the other vaults by name, each with its id, item count,
/// bytes used when the server said, and its state. Vaults the account lists that this device
/// does not hold are shown too.
///
/// # Errors
/// As [`Device::open`] and [`Device::sync`] (an unreachable server only notes it); the
/// output's.
pub async fn list(env: &mut Env<'_>) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    if let Err(e) = device.sync(env.ui).await {
        if !matches!(e, CliError::Network) {
            return Err(e);
        }
        env.ui
            .note("The server was not reached; the list is what this device last saw.");
    }
    for vault_id in ordered_vaults(&device) {
        env.ui.print(&list_line(&device, vault_id))?;
    }
    for entry in device.vaults().catalog().entries() {
        if device.vaults().get(entry.vault_id).is_none() {
            let state = match device.vaults().shown(entry.vault_id) {
                Shown::NeedsUpdate => "needs-update: needs a newer rizzy-vault",
                _ => "withheld: not on this device",
            };
            env.ui.print(&format!(
                "{}  {UNTITLED}  ({state})",
                hex(entry.vault_id.as_bytes())
            ))?;
        }
    }
    Ok(())
}

/// `rv vault create <name>` (§A3): prints the new vault's id.
///
/// # Errors
/// As [`Device::create_vault`].
pub async fn create(env: &mut Env<'_>, name: &str) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    let vault_id = Box::pin(device.create_vault(env.ui, name)).await?;
    env.ui.print(&hex(vault_id.as_bytes()))?;
    sync_after_write(&mut device, env.ui).await
}

/// `rv vault rename <vault> <name>` (§A4); the Personal vault is refused.
///
/// # Errors
/// As [`Device::rename_vault`].
pub async fn rename(env: &mut Env<'_>, vault: &str, name: &str) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    let vault_id = resolve_vault(&device, vault)?;
    device.rename_vault(vault_id, name).await?;
    sync_after_write(&mut device, env.ui).await
}

/// `rv vault delete <vault> --name <login> [--with-items]` (§A5).
///
/// # Errors
/// [`CliError::Refused`] when the typed confirmation is not the vault's name; as
/// [`Device::delete_vault`].
pub async fn delete(
    env: &mut Env<'_>,
    vault: &str,
    login_name: &str,
    with_items: bool,
) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    device.sync(env.ui).await?;
    let vault_id = resolve_vault(&device, vault)?;
    if device.vaults().catalog().personal() == Some(vault_id) {
        return Err(CliError::Client(ClientError::PersonalVaultProtected));
    }
    let label = vault_label(&device, vault_id);
    let items = device
        .vaults()
        .require(vault_id)
        .map(|v| user_items(v, &[ItemLifecycle::Active, ItemLifecycle::Trashed]).len())?;
    if with_items {
        env.ui.note(&format!(
            "Deleting the vault \"{label}\" and its {items} items (the trash included), on \
             every device. This cannot be undone."
        ));
    } else {
        env.ui.note(&format!(
            "Moving the {items} items of the vault \"{label}\" (the trash included) to Personal, \
             then deleting the vault on every device."
        ));
    }
    let typed = env
        .ui
        .typed(&format!("Type the vault's name ({label}) to confirm"))?;
    if typed != label {
        return Err(CliError::Refused(
            "the name typed is not the vault's name; nothing was changed".to_owned(),
        ));
    }
    let moved = Box::pin(device.delete_vault(env.ui, login_name, vault_id, with_items)).await?;
    if with_items {
        env.ui.note(&format!(
            "Deleted the vault \"{label}\" and its {items} items."
        ));
    } else {
        env.ui.note(&format!(
            "Moved {moved} items to Personal and deleted the vault \"{label}\"."
        ));
    }
    Ok(())
}

/// `rv item move <item> --to <vault>` and `rv item copy <item> --to <vault>` (§A6): prints the
/// item's id in the target.
///
/// # Errors
/// [`CliError::BadInput`] for the item's own vault as the target; as [`Device::move_item`]
/// and [`Device::copy_item`].
pub async fn move_or_copy(
    env: &mut Env<'_>,
    item: &str,
    to: &str,
    keep_source: bool,
) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    device.sync(env.ui).await?;
    let (source, item) = resolve_item(&device, item)?;
    let target = resolve_vault(&device, to)?;
    if source == target {
        return Err(CliError::BadInput("the item is in that vault already"));
    }
    if keep_source {
        let copy = Box::pin(device.copy_item(env.ui, source, item, target)).await?;
        env.ui.print(&hex(copy.as_bytes()))?;
        return sync_after_write(&mut device, env.ui).await;
    }
    let (moved, done) = Box::pin(device.move_item(env.ui, source, item, target)).await?;
    env.ui.print(&hex(moved.as_bytes()))?;
    if !done {
        env.ui.note(
            "The copy is saved; the original is removed once the server has stored the copy. \
             The next `rv sync` goes on with it.",
        );
    }
    sync_after_write(&mut device, env.ui).await
}
