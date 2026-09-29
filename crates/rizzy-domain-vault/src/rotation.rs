//! The vault half of a key rotation ([ADR 0025] §3, §4; CRYPTO.md §11.6 steps 3 and 9, §11.8
//! step 3, §11.9 step 5; ADR 0012 §6 and ADR 0021 §9 "Rotation cut-off").
//!
//! [`apply_rotation`] runs inside the `auth` domain's commit transaction, under the account lock,
//! after every auth-side check passed and before the compare-and-swap on `state_seq` (ADR 0025
//! §4: `lock_account` → auth checks and writes → vault checks and writes → `cas_state` →
//! commit). `rizzy-server`'s bridge calls it through the `auth` domain's `VaultPort`. Any
//! refusal drops the whole transaction, so nothing is ever half-rotated.
//!
//! # Checks, for every vault of the account (ADR 0025 §3)
//!
//! 1. **Shape** (`invalid_request`): exactly one [`VaultRotation`] per vault the account owns,
//!    none other (the wire form already makes the list strictly ascending).
//! 2. **Self-grant** (`invalid_request`): its `account_key_epoch` is the verified new state's;
//!    its `vault_key_epoch` is **above** the stored `vault_vaults.vault_key_epoch` (not "= + 1":
//!    after a restore the column may be rolled back, and a client that saw a higher epoch must
//!    not reuse it); its envelope parses as a symmetric envelope whose header `key_id` is the
//!    signed `account_key_id` (CRYPTO.md §4.4).
//! 3. **Wraps** (`invalid_request` unless noted): every re-wrap is at the new `vault_key_epoch`,
//!    parses as a symmetric envelope of exactly [`ITEM_KEY_WRAP_ENVELOPE_LEN`] bytes; all their
//!    header `key_id`s are equal and differ from the `key_id` of every stored row (this guards
//!    against a re-wrap under the old key and proves nothing about content); the re-wrapped and
//!    the dropped locators are each free of duplicates, disjoint, and both subsets of the stored
//!    rows. A stored row in neither list is `state_conflict`: the client has not seen it (ADR
//!    0025's reading of "`ITEM_KEY_WRAP` beyond that cursor").
//! 4. **Cut-off** (`state_conflict`): for every device d, `cursor[d]` equals the head h(V, d)
//!    (a missing entry is 0). Below a head is ADR 0012 §6's refusal; above means the server is
//!    behind that client (ADR 0021 §9 "Server behind"), which must stay read-only, so it is
//!    refused too (open question 1, decided: exact). Every retained snapshot's clamped VV is at
//!    most the cursor (implied by the heads, checked anyway).
//!
//! # Writes, after checks 1–4 passed for every vault
//!
//! `vault_key_epoch` set to the uploaded value; the self-grant replaced; each re-wrapped row
//! overwritten (exactly one row each); each dropped row deleted (exactly one row each); the wrap
//! carried with every op and snapshot of the vault set to NULL (the superseded wraps; the signed
//! wrap hashes stay). The cursor is not stored.
//!
//! # What this does not see
//!
//! The server never decrypts: nothing here tells a re-wrap of the right item key from any other
//! 127-byte envelope under one fresh key id. The client's reader rule is the check that matters
//! (CRYPTO.md §11.6); these checks only keep an honest rotation complete and a buggy one out.
//! Every value read is one the server already holds (THREAT_MODEL §3.4): heads, wrap locators,
//! epochs, envelope headers and lengths. No error carries a value (INV-48).
//!
//! **Limit.** A vault with more than [`MAX_ITEM_KEY_WRAPS`] wrap-set rows cannot rotate in M1
//! (its rows do not fit one upload, and its Fetch already fails with `WrapSetTooLarge`); the
//! rotation is refused as `invalid_request` (ADR 0025 "Risks").
//!
//! [ADR 0025]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0025-rotation-vault-half.md

use std::collections::BTreeSet;

use rizzy_core::envelope::parse::{EnvelopeRef, parse as parse_envelope};
use rizzy_core::envelope::symmetric::OVERHEAD;
use rizzy_core::ids::{AccountId, DeviceId, ItemId, VaultId};
use rizzy_proto::change::{VaultRotation, VaultRotationUpload};
use rizzy_proto::limits::MAX_ITEM_KEY_WRAPS;
use rizzy_storage::WriteTx;

use crate::error::VaultError;
use crate::repo::{self, SelfGrantRow, WrapRow};
use crate::to_sql_time;

/// The length of an `ITEM_KEY_WRAP` envelope: the symmetric envelope's overhead (CRYPTO.md
/// §9.1, 90 bytes) around the fixed 37-byte plaintext `u8 wrap_version ‖ u32
/// created_vault_key_epoch ‖ item_key` (§8.4), 127 bytes (ADR 0025 §3 check 3).
pub const ITEM_KEY_WRAP_ENVELOPE_LEN: usize = OVERHEAD + 1 + 4 + 32;

/// One wrap-set row's locator: the item and the wrapped item key's id.
type Locator = (ItemId, [u8; 16]);

/// The checked writes of one vault (module docs, "Writes").
struct VaultPlan {
    /// The vault.
    vault_id: VaultId,
    /// Whether the vault holds a self-grant row to replace.
    has_grant: bool,
    /// The new self-grant.
    grant: SelfGrantRow,
    /// The rows to overwrite.
    rewrapped: Vec<WrapRow>,
    /// The rows to delete.
    dropped: Vec<Locator>,
}

/// The vault half of a rotation, in `tx`, which holds the account lock and the `auth` domain's
/// writes of the same change (module docs). `new_account_key_epoch` and `new_account_key_id`
/// come from the verified new `account-state`.
///
/// # Errors
/// [`VaultError::Invalid`] for a failed check 1, 2 or 3; [`VaultError::StateConflict`] for a
/// stored row in neither list or a failed cut-off (check 4); [`VaultError::Storage`] or
/// [`VaultError::Corrupt`] (a re-wrap or a drop that did not change exactly one row). The
/// caller drops the transaction on any error.
pub async fn apply_rotation(
    tx: &mut WriteTx,
    account_id: AccountId,
    new_account_key_epoch: u32,
    new_account_key_id: &[u8; 16],
    upload: &VaultRotationUpload,
    now_ms: u64,
) -> Result<(), VaultError> {
    let now = to_sql_time(now_ms)?;
    // Check 1: one entry per vault, none other. Both lists are ascending by id.
    let vaults = repo::list_vaults(tx.conn(), account_id).await?;
    let entries = upload.vaults();
    if vaults.len() != entries.len()
        || vaults
            .iter()
            .zip(entries)
            .any(|(v, e)| v.to_bytes() != e.self_grant.vault_id.to_bytes())
    {
        return Err(VaultError::Invalid);
    }
    let mut plans = Vec::with_capacity(entries.len());
    for (vault_id, rotation) in vaults.iter().zip(entries) {
        plans.push(
            check_vault(
                tx,
                account_id,
                *vault_id,
                new_account_key_epoch,
                new_account_key_id,
                rotation,
            )
            .await?,
        );
    }
    for plan in &plans {
        write_vault(tx, plan, now).await?;
    }
    Ok(())
}

/// Checks 2–4 for one vault; the writes they allow.
async fn check_vault(
    tx: &mut WriteTx,
    account_id: AccountId,
    vault_id: VaultId,
    new_account_key_epoch: u32,
    new_account_key_id: &[u8; 16],
    rotation: &VaultRotation,
) -> Result<VaultPlan, VaultError> {
    let vault = repo::vault(tx.conn(), vault_id)
        .await?
        .filter(|v| v.account_id == account_id)
        .ok_or(VaultError::Corrupt {
            what: "a listed vault has no row of this account",
        })?;
    // Check 2: the self-grant.
    let grant = &rotation.self_grant;
    let new_epoch = grant.vault_key_epoch;
    if grant.account_key_epoch != new_account_key_epoch || new_epoch <= vault.vault_key_epoch {
        return Err(VaultError::Invalid);
    }
    match parse_envelope(grant.envelope.as_slice()) {
        Ok(EnvelopeRef::Symmetric(e)) if e.key_id() == new_account_key_id => {}
        _ => return Err(VaultError::Invalid),
    }
    // Check 3: the wraps against the stored wrap set.
    let limit = MAX_ITEM_KEY_WRAPS.saturating_add(1);
    let stored = repo::wraps_after(tx.conn(), vault_id, None, limit).await?;
    let (rewrapped, dropped) = check_wraps(&stored, rotation, new_epoch)?;
    // Check 4: the exact cursor, and every retained snapshot's clamped VV below it.
    check_cutoff(tx, vault_id, rotation).await?;
    let has_grant = repo::self_grant(tx.conn(), vault_id).await?.is_some();
    Ok(VaultPlan {
        vault_id,
        has_grant,
        grant: SelfGrantRow {
            account_key_epoch: grant.account_key_epoch,
            vault_key_epoch: new_epoch,
            envelope: grant.envelope.as_slice().to_vec(),
        },
        rewrapped,
        dropped,
    })
}

/// Check 3 of one vault (module docs) against its `stored` rows: the rows to overwrite and to
/// delete.
fn check_wraps(
    stored: &[WrapRow],
    rotation: &VaultRotation,
    new_epoch: u32,
) -> Result<(Vec<WrapRow>, Vec<Locator>), VaultError> {
    if stored.len() > MAX_ITEM_KEY_WRAPS {
        return Err(VaultError::Invalid);
    }
    let stored_key_ids: BTreeSet<[u8; 16]> = stored
        .iter()
        .filter_map(|row| parse_envelope(&row.envelope).ok().map(|e| *e.key_id()))
        .collect();
    let stored_rows: BTreeSet<Locator> = stored
        .iter()
        .map(|row| (row.item_id, row.item_key_id))
        .collect();
    let mut wrap_key_id: Option<[u8; 16]> = None;
    let mut rewrapped_at: BTreeSet<Locator> = BTreeSet::new();
    let mut rewrapped = Vec::with_capacity(rotation.item_key_wraps.len());
    for wrap in &rotation.item_key_wraps {
        if wrap.vault_key_epoch != new_epoch || wrap.envelope.len() != ITEM_KEY_WRAP_ENVELOPE_LEN {
            return Err(VaultError::Invalid);
        }
        let key_id = match parse_envelope(wrap.envelope.as_slice()) {
            Ok(EnvelopeRef::Symmetric(e)) => *e.key_id(),
            _ => return Err(VaultError::Invalid),
        };
        if *wrap_key_id.get_or_insert(key_id) != key_id || stored_key_ids.contains(&key_id) {
            return Err(VaultError::Invalid);
        }
        let at = (
            ItemId::from_bytes(wrap.item_id.to_bytes()),
            wrap.item_key_id.to_bytes(),
        );
        if !stored_rows.contains(&at) || !rewrapped_at.insert(at) {
            return Err(VaultError::Invalid);
        }
        rewrapped.push(WrapRow {
            item_id: at.0,
            item_key_id: at.1,
            vault_key_epoch: new_epoch,
            envelope: wrap.envelope.as_slice().to_vec(),
        });
    }
    let mut dropped_at: BTreeSet<Locator> = BTreeSet::new();
    for locator in &rotation.dropped {
        let at = (
            ItemId::from_bytes(locator.item_id.to_bytes()),
            locator.item_key_id.to_bytes(),
        );
        if !stored_rows.contains(&at) || rewrapped_at.contains(&at) || !dropped_at.insert(at) {
            return Err(VaultError::Invalid);
        }
    }
    if stored_rows
        .iter()
        .any(|at| !rewrapped_at.contains(at) && !dropped_at.contains(at))
    {
        return Err(VaultError::StateConflict);
    }
    Ok((rewrapped, dropped_at.into_iter().collect()))
}

/// Check 4 of one vault (module docs): the cursor equals the heads, and every retained
/// snapshot's clamped VV is at most the cursor.
async fn check_cutoff(
    tx: &mut WriteTx,
    vault_id: VaultId,
    rotation: &VaultRotation,
) -> Result<(), VaultError> {
    let heads = repo::heads(tx.conn(), vault_id).await?;
    let cursor = &rotation.cursor;
    let cursor_at =
        |device: DeviceId| cursor.get(&rizzy_proto::wire::Id::from_bytes(device.to_bytes()));
    let exact = heads.entries().all(|h| cursor_at(h.device_id()) == h.seq())
        && cursor
            .entries()
            .iter()
            .all(|e| heads.get(DeviceId::from_bytes(e.device_id.to_bytes())) == e.seq);
    if !exact {
        return Err(VaultError::StateConflict);
    }
    for clamped in repo::clamped_vvs(tx.conn(), vault_id).await? {
        if clamped
            .entries()
            .any(|dot| dot.seq() > cursor_at(dot.device_id()))
        {
            return Err(VaultError::StateConflict);
        }
    }
    Ok(())
}

/// The writes of one checked vault (module docs, "Writes").
async fn write_vault(tx: &mut WriteTx, plan: &VaultPlan, now: i64) -> Result<(), VaultError> {
    let vault_id = plan.vault_id;
    repo::set_vault_epoch(tx.conn(), vault_id, plan.grant.vault_key_epoch).await?;
    repo::write_self_grant(tx.conn(), vault_id, &plan.grant, plan.has_grant, now).await?;
    for row in &plan.rewrapped {
        if repo::overwrite_wrap(tx.conn(), vault_id, row, now).await? != 1 {
            return Err(VaultError::Corrupt {
                what: "a re-wrap did not overwrite exactly one wrap-set row",
            });
        }
    }
    for (item_id, item_key_id) in &plan.dropped {
        if repo::delete_wrap(tx.conn(), vault_id, *item_id, item_key_id).await? != 1 {
            return Err(VaultError::Corrupt {
                what: "a dropped row did not delete exactly one wrap-set row",
            });
        }
    }
    repo::clear_record_wraps(tx.conn(), vault_id).await
}

#[cfg(test)]
mod tests {
    //! The fixed wrap length against CRYPTO.md §9.1 and §8.4.

    #[test]
    fn item_key_wrap_envelope_is_127_bytes() {
        assert_eq!(super::ITEM_KEY_WRAP_ENVELOPE_LEN, 127);
    }
}
