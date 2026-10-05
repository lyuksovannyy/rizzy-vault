//! Vault rows, vault self-grants and the item-key wrap set (CRYPTO.md §4.2: "`VAULT_KEY_SELF_GRANT`
//! | Server, `vault` domain"; "`ITEM_KEY_WRAP` | Server, `vault` domain: the current wrap set").
//!
//! - **Vault creation** ([`create_vault`]) runs inside the caller's write transaction (signup,
//!   CRYPTO.md §11.1, one transaction with the `auth` domain's rows): the vault row at
//!   `vault_key_epoch` 0 ("0 when the vault is created", CRYPTO.md §4.4) and its first
//!   self-grant.
//! - **Reading** the self-grant ([`VaultDomain::self_grant`]) and the account's vaults
//!   ([`VaultDomain::vaults`]).
//! - **Healing step 3b** ([ADR 0032] §2–§3, `heal_self_grant`, reached through
//!   [`VaultDomain::heal`] with a request that carries a self-grant): the lag rule. A vault's
//!   self-grant **lags** when its stored `account_key_epoch` is below the held signed
//!   `account-state`'s, which the `auth` domain reports through
//!   [`DeviceDirectory::account_key`]. Lag exists only after a restore. The server repairs a
//!   lagging self-grant, inside or outside the reconciliation epoch, when all of these hold, and
//!   otherwise stores nothing:
//!   - the session is a device session of a durable device of the held device set (active,
//!     not suspended, revoked or expired; a kind-4, OPAQUE-only or recovery session is
//!     refused `unauthorized`);
//!   - the replacement's `account_key_epoch` is the state's, its envelope parses as a
//!     `VAULT_KEY_SELF_GRANT` symmetric envelope whose header `key_id` is the signed
//!     `account_key_id`, and its `vault_key_epoch` is **above** the vault's stored one (ADR 0025
//!     §3 check 2's rule: the column is rolled back, and the vault epoch may have moved further
//!     than the account epoch) and not below any stored wrap row or record of the vault. No
//!     fixed delta: the epochs need not move in lockstep;
//!   - the request has no records, and its wraps pass ADR 0025 §3 check 3 at the new epoch
//!     without the completeness clause (`check_heal_wraps`).
//!
//!   The same transaction then sets the vault's `vault_key_epoch`, replaces the self-grant,
//!   overwrites each stored wrap row the request carries, deletes every stored row below the
//!   new epoch the request does not carry, and drops the carried wrap of every op and snapshot
//!   below the new epoch. Records and rows at exactly the new epoch are kept (genuine uploads by
//!   a device that adopted the healed state). A self-grant that does not lag stores nothing: a
//!   byte-identical or otherwise valid repeat (the stored epochs) is success, anything else
//!   `invalid_request`. The first valid repair wins: the server cannot tell a junk envelope under
//!   a copied `key_id` from a genuine one, and clients reject it when it does not open.
//! - **No other self-grant repair.** Before ADR 0032, healing step 3 (`healing/grants`) stored a
//!   re-published self-grant without raising `vault_key_epoch`. That path is gone: a self-grant
//!   stored that way would no longer lag while the vault epoch and the wrap set stayed behind,
//!   so step 3b could never repair the vault. The `auth` domain now accepts a self-grant in
//!   `healing/grants` only when it is the stored one byte for byte (ADR 0032 §3).
//! - **The wrap set.** A wrap carried inside an op or snapshot, or sent in a healing request,
//!   fills its row (`crate::store`, `crate::upload`): inserted when missing, replacing a row at
//!   a lower `vault_key_epoch`, otherwise kept. Fetch serves the rows (`crate::fetch`).
//!
//! **The key-rotation upload** (CRYPTO.md §11.6 step 9: new self-grants, the re-wrapped wrap set
//! overwriting every row, the superseded wraps deleted, and the rotation cut-off of ADR 0012 §6 /
//! ADR 0021 §9 "Rotation cut-off") is [`crate::rotation`] (ADR 0025): one atomic request with the
//! `auth` domain's `account-state`. With healing step 3b it is one of the two writes that move
//! `vault_key_epoch`, always upwards, above the stored value (ADR 0025 §3 check 2).
//!
//! [ADR 0032]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0032-healing-rotation-after-backup.md

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::envelope::parse::{EnvelopeRef, parse as parse_envelope, parse_for_purpose};
use rizzy_core::envelope::purpose::{PlaintextRule, Purpose};
use rizzy_core::ids::{AccountId, DeviceId, ItemId, VaultId};
use rizzy_proto::limits::MAX_ITEM_KEY_WRAPS;
use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
use rizzy_proto::vault::HealingRequest;
use rizzy_proto::wire::Id;
use rizzy_storage::WriteTx;

use crate::authors::{AccountKeyState, AuthorStatus, DeviceDirectory};
use crate::error::VaultError;
use crate::repo::{self, SelfGrantRow, WrapRow};
use crate::rotation::ITEM_KEY_WRAP_ENVELOPE_LEN;
use crate::store::{Refusal, Session};
use crate::{VaultDomain, to_sql_time};

/// Creates vault `grant.vault_id` for `account_id` with its first self-grant, in the caller's
/// write transaction, which has taken the account's lock (signup, CRYPTO.md §11.1).
///
/// # Errors
/// [`VaultError::Invalid`] when the grant's `vault_key_epoch` is not 0; [`VaultError::Storage`]
/// when the vault exists already or the account row is missing (foreign key), and on any
/// database failure. The caller drops the transaction then.
pub async fn create_vault(
    tx: &mut WriteTx,
    account_id: AccountId,
    grant: &VaultSelfGrant,
    now_ms: u64,
) -> Result<(), VaultError> {
    if grant.vault_key_epoch != 0 {
        return Err(VaultError::Invalid);
    }
    let vault_id = VaultId::from_bytes(grant.vault_id.to_bytes());
    let now = to_sql_time(now_ms)?;
    repo::insert_vault(tx.conn(), vault_id, account_id, 0, now).await?;
    let row = SelfGrantRow {
        account_key_epoch: grant.account_key_epoch,
        vault_key_epoch: 0,
        envelope: grant.envelope.as_slice().to_vec(),
    };
    repo::write_self_grant(tx.conn(), vault_id, &row, false, now).await
}

impl<D: DeviceDirectory> VaultDomain<D> {
    /// The account's vaults, by id.
    ///
    /// # Errors
    /// [`VaultError::Storage`] or [`VaultError::Corrupt`].
    pub async fn vaults(&self, account_id: AccountId) -> Result<Vec<VaultId>, VaultError> {
        let mut tx = self.database().begin_read().await?;
        let vaults = repo::list_vaults(tx.conn(), account_id).await?;
        tx.finish().await?;
        Ok(vaults)
    }

    /// The vault's current self-grant.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for a vault of another account or without a self-grant;
    /// [`VaultError::Storage`] or [`VaultError::Corrupt`].
    pub async fn self_grant(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<VaultSelfGrant, VaultError> {
        let mut tx = self.database().begin_read().await?;
        repo::vault(tx.conn(), vault_id)
            .await?
            .filter(|v| v.account_id == account_id)
            .ok_or(VaultError::NotFound)?;
        let row = repo::self_grant(tx.conn(), vault_id)
            .await?
            .ok_or(VaultError::NotFound)?;
        tx.finish().await?;
        Ok(VaultSelfGrant {
            vault_id: Id::from_bytes(vault_id.to_bytes()),
            account_key_epoch: row.account_key_epoch,
            vault_key_epoch: row.vault_key_epoch,
            envelope: KeyEnvelope::new(row.envelope).map_err(|_| VaultError::Corrupt {
                what: "vault_self_grants.envelope length",
            })?,
        })
    }
}

/// One wrap-set row's locator: the item and the wrapped item key's id.
type Locator = (ItemId, [u8; 16]);

/// Whether `envelope` parses as a symmetric envelope of `purpose` (on the purpose's allow-list,
/// and of exactly its plaintext length when the purpose fixes one) whose header `key_id` is
/// `key_id`. The server cannot open it; clients check the content (CRYPTO.md §11.2 step 6).
fn symmetric_under(envelope: &[u8], purpose: Purpose, key_id: &[u8; 16]) -> bool {
    let Ok(EnvelopeRef::Symmetric(parsed)) =
        parse_for_purpose(envelope, purpose.client_decrypt_allow_list())
    else {
        return false;
    };
    let length_ok = match purpose.plaintext_rule() {
        PlaintextRule::Fixed(len) => parsed.ciphertext().len() == len,
        PlaintextRule::Padded | PlaintextRule::Unpadded | PlaintextRule::Unspecified => true,
    };
    length_ok && parsed.key_id() == key_id
}

/// Healing step 3b ([ADR 0032] §2–§3): the vault's self-grant and its wrap set at that grant's
/// `vault_key_epoch`, in `request` (no records), checked against the held signed state's
/// account key `key` (module docs, "Healing step 3b"). Inside the healing transaction, which
/// holds the account lock; `session` is its store session. `Ok(Err(_))` is a refusal: the
/// caller rolls back.
///
/// [ADR 0032]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0032-healing-rotation-after-backup.md
pub(crate) async fn heal_self_grant(
    tx: &mut WriteTx,
    session: &Session,
    healer: Option<DeviceId>,
    key: Option<AccountKeyState>,
    grant: &VaultSelfGrant,
    request: &HealingRequest,
) -> Result<Result<(), Refusal>, VaultError> {
    let vault_id = session.vault_id;
    let Some(key) = key else {
        return Ok(Err(Refusal::Invalid));
    };
    let shaped = request.records.is_empty()
        && grant.vault_id.to_bytes() == vault_id.to_bytes()
        && grant.account_key_epoch == key.account_key_epoch
        && symmetric_under(
            grant.envelope.as_slice(),
            Purpose::VaultKeySelfGrant,
            &key.account_key_id,
        );
    if !shaped {
        return Ok(Err(Refusal::Invalid));
    }
    let stored = repo::self_grant(tx.conn(), vault_id).await?;
    let lags = stored
        .as_ref()
        .is_none_or(|s| s.account_key_epoch < key.account_key_epoch);
    if !lags {
        // Not lagging: a byte-identical or otherwise valid repeat is success and stores nothing
        // (the first valid repair wins); the wraps are not looked at either.
        let repeat = stored.as_ref().is_some_and(|s| {
            s.account_key_epoch == grant.account_key_epoch
                && s.vault_key_epoch == grant.vault_key_epoch
        });
        return Ok(if repeat {
            Ok(())
        } else {
            Err(Refusal::Invalid)
        });
    }
    // Only a device session of a durable device of the held device set repairs.
    let may_repair = healer
        .and_then(|d| session.authors.get(d))
        .is_some_and(|a| {
            a.device_kind.is_durable()
                && a.status == AuthorStatus::Active
                && !a.expired_at(session.now_ms)
        });
    if !may_repair {
        return Ok(Err(Refusal::Unauthorized));
    }
    // The vault epoch: above the stored one (ADR 0025 §3 check 2's rule), and no stored record or
    // wrap row above it.
    let new_epoch = grant.vault_key_epoch;
    if new_epoch <= session.vault.vault_key_epoch {
        return Ok(Err(Refusal::Invalid));
    }
    if repo::max_record_epoch(tx.conn(), vault_id)
        .await?
        .is_some_and(|e| e > new_epoch)
    {
        return Ok(Err(Refusal::Invalid));
    }
    let limit = MAX_ITEM_KEY_WRAPS.saturating_add(1);
    let rows = repo::wraps_after(tx.conn(), vault_id, None, limit).await?;
    if rows.len() > MAX_ITEM_KEY_WRAPS || rows.iter().any(|r| r.vault_key_epoch > new_epoch) {
        return Ok(Err(Refusal::Invalid));
    }
    let Ok(replaced) = check_heal_wraps(&rows, request, new_epoch) else {
        return Ok(Err(Refusal::Invalid));
    };
    // The writes, in the order of §3.
    let now = session.now_sql;
    repo::set_vault_epoch(tx.conn(), vault_id, new_epoch).await?;
    let row = SelfGrantRow {
        account_key_epoch: grant.account_key_epoch,
        vault_key_epoch: new_epoch,
        envelope: grant.envelope.as_slice().to_vec(),
    };
    repo::write_self_grant(tx.conn(), vault_id, &row, stored.is_some(), now).await?;
    let mut kept: BTreeSet<Locator> = BTreeSet::new();
    for wrap in &replaced {
        if repo::overwrite_wrap(tx.conn(), vault_id, wrap, now).await? != 1 {
            return Err(VaultError::Corrupt {
                what: "a healed wrap did not overwrite exactly one wrap-set row",
            });
        }
        kept.insert((wrap.item_id, wrap.item_key_id));
    }
    for stale in rows
        .iter()
        .filter(|r| r.vault_key_epoch < new_epoch && !kept.contains(&(r.item_id, r.item_key_id)))
    {
        repo::delete_wrap(tx.conn(), vault_id, stale.item_id, &stale.item_key_id).await?;
    }
    repo::clear_record_wraps_below(tx.conn(), vault_id, new_epoch).await?;
    Ok(Ok(()))
}

/// The wraps of a step-3b request (ADR 0032 §3: "checks the wraps as ADR 0025 §3 check 3 does,
/// at the new epoch, without its completeness clause") against the vault's stored `rows`; the
/// rows to overwrite.
///
/// Each wrap is at `new_epoch`, parses as a symmetric envelope of exactly
/// [`ITEM_KEY_WRAP_ENVELOPE_LEN`] bytes, and all of them share one header `key_id`, which
/// differs from that of every stored row below `new_epoch` (a re-wrap under the old key is
/// refused) and equals that of every stored row already at `new_epoch` (written by a device that
/// adopted the healed state; a row under yet another key is refused). No locator twice. A wrap
/// whose locator the server holds no row for is left out, not stored: this crate's reading of
/// "replaces each stored row with the same (`item_id`, `item_key_id`)", the healer re-publishes
/// such a row with its records in step 4 ("every item-key wrap the server lacks").
fn check_heal_wraps(
    rows: &[WrapRow],
    request: &HealingRequest,
    new_epoch: u32,
) -> Result<Vec<WrapRow>, ()> {
    let key_id_of = |envelope: &[u8]| match parse_envelope(envelope) {
        Ok(EnvelopeRef::Symmetric(e)) => Some(*e.key_id()),
        _ => None,
    };
    let stored: BTreeMap<Locator, &WrapRow> = rows
        .iter()
        .map(|r| ((r.item_id, r.item_key_id), r))
        .collect();
    let mut key: Option<[u8; 16]> = None;
    let mut seen: BTreeSet<Locator> = BTreeSet::new();
    let mut replaced = Vec::new();
    for wrap in &request.item_key_wraps {
        if wrap.vault_key_epoch != new_epoch || wrap.envelope.len() != ITEM_KEY_WRAP_ENVELOPE_LEN {
            return Err(());
        }
        let wrap_key = key_id_of(wrap.envelope.as_slice()).ok_or(())?;
        if *key.get_or_insert(wrap_key) != wrap_key {
            return Err(());
        }
        let at = (
            ItemId::from_bytes(wrap.item_id.to_bytes()),
            wrap.item_key_id.to_bytes(),
        );
        if !seen.insert(at) {
            return Err(());
        }
        if stored.contains_key(&at) {
            replaced.push(WrapRow {
                item_id: at.0,
                item_key_id: at.1,
                vault_key_epoch: new_epoch,
                envelope: wrap.envelope.as_slice().to_vec(),
            });
        }
    }
    if let Some(key) = key {
        for row in rows {
            let row_key = key_id_of(&row.envelope);
            let fits = if row.vault_key_epoch < new_epoch {
                row_key != Some(key)
            } else {
                row_key == Some(key)
            };
            if !fits {
                return Err(());
            }
        }
    }
    Ok(replaced)
}
