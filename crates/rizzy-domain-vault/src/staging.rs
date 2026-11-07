// SPDX-License-Identifier: AGPL-3.0-only

//! Rotation staging ([ADR 0092] §4): a rotation's re-wrapped rows sent ahead of its commit,
//! when the inline `account/commit` body would exceed `DEFAULT_UPLOAD_BODY_LEN`.
//!
//! **Staged rows are not state.** No Fetch, recovery read, export, compaction or quota reads
//! them, and they change nothing until the commit applies them: [`crate::rotation`]'s check 3
//! runs over the union of a vault's inline and staged rows (ADR 0092 §0 item 4), its writes
//! apply the union, and the same transaction deletes the staging. The commit stays the single
//! atomic step (CRYPTO.md §11.6 step 9, ADR 0025 §4).
//!
//! # A stage request ([`stage_rotation`], ADR 0092 §4 "Opening")
//!
//! Runs in the caller's write transaction, under the account lock, after the `auth` domain
//! authorised the session as the commit it prepares and found `base_state_seq` equal to the
//! stored `state_seq` (step 1's `state_conflict`). Then:
//!
//! 1. the vault is one the account owns, and the request holds at most
//!    [`ROTATION_STAGE_ROWS`] rows (`invalid_request`);
//! 2. the account holds at most one staging: one under another `rotation_id`, or past its
//!    [`ROTATION_STAGE_TTL_MS`], is deleted first; the `(rotation_id, base_state_seq,
//!    account_key_id)` triple of the open one is fixed, and so, per vault, is the
//!    `vault_key_epoch` of its first stage request (`invalid_request`);
//! 3. per row: a wrap is at `vault_key_epoch`, parses as a symmetric envelope of 127 bytes, and
//!    its header `key_id` equals the vault's other staged wraps' and differs from every stored
//!    row's; every locator names a stored row; the request's wraps and drops are disjoint and
//!    free of duplicates (`invalid_request`);
//! 4. a locator already staged with the identical wrap, or as a drop again, is a no-op; with
//!    another wrap, or wrap versus drop, `invalid_request`;
//! 5. the new rows are inserted, `last_stage_at_ms` set, and the vault's staged row count
//!    returned.
//!
//! The staged rows are bounded by the stored rows (each names a distinct one), so staging needs
//! no cap of its own and is not counted toward quota.
//!
//! # Expiry
//!
//! Any commit that advances `state_seq` deletes the account's staging in its own transaction
//! ([`discard_staging`], called by the `auth` domain through its `VaultPort`); the worker
//! deletes a staging whose last stage request is older than [`ROTATION_STAGE_TTL_MS`]
//! ([`VaultDomain::expire_rotation_stagings`]); a commit naming an expired one is
//! `state_conflict`.
//!
//! Nothing here logs, and no error carries a value (INV-48).
//!
//! [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::envelope::parse::{EnvelopeRef, parse as parse_envelope};
use rizzy_core::ids::{AccountId, ItemId, VaultId};
use rizzy_proto::change::{RotationId, StageRequest, StageResponse};
use rizzy_proto::limits::{MAX_ITEM_KEY_WRAPS, ROTATION_STAGE_ROWS, ROTATION_STAGE_TTL_MS};
use rizzy_storage::convert::{sql_to_u32, sql_to_u64, u32_to_sql, u64_to_sql};
use rizzy_storage::{Conn, WriteTx, lock_account, on_engine};
use sqlx::Row;

use crate::error::VaultError;
use crate::repo;
use crate::rotation::ITEM_KEY_WRAP_ENVELOPE_LEN;
use crate::{VaultDomain, to_sql_time};

/// See `queries/staging_get.sql`.
const STAGING_GET: &str = include_str!("../queries/staging_get.sql");
/// See `queries/staging_insert.sql`.
const STAGING_INSERT: &str = include_str!("../queries/staging_insert.sql");
/// See `queries/staging_touch.sql`.
const STAGING_TOUCH: &str = include_str!("../queries/staging_touch.sql");
/// See `queries/staging_delete_rows.sql`.
const STAGING_DELETE_ROWS: &str = include_str!("../queries/staging_delete_rows.sql");
/// See `queries/staging_delete_vaults.sql`.
const STAGING_DELETE_VAULTS: &str = include_str!("../queries/staging_delete_vaults.sql");
/// See `queries/staging_delete.sql`.
const STAGING_DELETE: &str = include_str!("../queries/staging_delete.sql");
/// See `queries/staging_vault_get.sql`.
const STAGING_VAULT_GET: &str = include_str!("../queries/staging_vault_get.sql");
/// See `queries/staging_vault_insert.sql`.
const STAGING_VAULT_INSERT: &str = include_str!("../queries/staging_vault_insert.sql");
/// See `queries/staging_rows.sql`.
const STAGING_ROWS: &str = include_str!("../queries/staging_rows.sql");
/// See `queries/staging_row_insert.sql`.
const STAGING_ROW_INSERT: &str = include_str!("../queries/staging_row_insert.sql");
/// See `queries/staging_vault_count.sql`.
const STAGING_VAULT_COUNT: &str = include_str!("../queries/staging_vault_count.sql");
/// See `queries/staging_expired.sql`.
const STAGING_EXPIRED: &str = include_str!("../queries/staging_expired.sql");

/// One wrap-set row's locator: the item and the wrapped item key's id.
pub(crate) type Locator = (ItemId, [u8; 16]);

/// The account's staging, as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Staging {
    /// The client's id for it.
    pub(crate) rotation_id: [u8; 16],
    /// The `state_seq` its commit will advance.
    pub(crate) base_state_seq: u64,
    /// The new account key id its commit will sign.
    pub(crate) account_key_id: [u8; 16],
    /// When its last stage request was applied.
    pub(crate) last_stage_at_ms: u64,
}

impl Staging {
    /// Whether the staging is past [`ROTATION_STAGE_TTL_MS`] at `now_ms`.
    pub(crate) const fn expired(&self, now_ms: u64) -> bool {
        self.last_stage_at_ms.saturating_add(ROTATION_STAGE_TTL_MS) <= now_ms
    }
}

/// The columns of a staging row, as read.
type StagingColumns = (Vec<u8>, i64, Vec<u8>, i64);

/// The columns of a staged row, as read: item id, item key id, wrap (NULL for a drop).
type StagedColumns = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// A staged row: its locator and its wrap, `None` for a dropped row.
type StagedRow = (Locator, Option<Vec<u8>>);

/// The account's staging, if one is stored (expired or not).
pub(crate) async fn staging(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Option<Staging>, VaultError> {
    let row: Option<StagingColumns> = on_engine!(conn, |c| sqlx::query_as(STAGING_GET)
        .bind(&account_id.as_bytes()[..])
        .fetch_optional(&mut *c)
        .await)?;
    row.map(|(rotation_id, base, key_id, at)| {
        Ok(Staging {
            rotation_id: id16(&rotation_id, "vault_rotation_stagings.rotation_id")?,
            base_state_seq: sql_to_u64(base, "vault_rotation_stagings.base_state_seq")?,
            account_key_id: id16(&key_id, "vault_rotation_stagings.account_key_id")?,
            last_stage_at_ms: sql_to_u64(at, "vault_rotation_stagings.last_stage_at_ms")?,
        })
    })
    .transpose()
}

/// A 16-byte id read back from a column.
fn id16(bytes: &[u8], what: &'static str) -> Result<[u8; 16], VaultError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| VaultError::Corrupt { what })
}

/// Deletes the account's staging, its per-vault epochs and its rows, if any ([ADR 0092] §4
/// "Expiry": any commit that advances `state_seq` calls this in its own transaction). The
/// caller holds the account lock.
///
/// # Errors
/// [`VaultError::Storage`] on a database failure; the caller drops the transaction.
///
/// [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md
pub async fn discard_staging(tx: &mut WriteTx, account_id: AccountId) -> Result<(), VaultError> {
    for query in [STAGING_DELETE_ROWS, STAGING_DELETE_VAULTS, STAGING_DELETE] {
        on_engine!(tx.conn(), |c| sqlx::query(query)
            .bind(&account_id.as_bytes()[..])
            .execute(&mut *c)
            .await
            .map(|r| r.rows_affected()))?;
    }
    Ok(())
}

/// The `vault_key_epoch` the staging fixed for `vault_id`, if the vault has staged rows.
pub(crate) async fn staged_epoch(
    conn: Conn<'_>,
    account_id: AccountId,
    vault_id: VaultId,
) -> Result<Option<u32>, VaultError> {
    let epoch: Option<i64> = on_engine!(conn, |c| sqlx::query_scalar(STAGING_VAULT_GET)
        .bind(&account_id.as_bytes()[..])
        .bind(&vault_id.as_bytes()[..])
        .fetch_optional(&mut *c)
        .await)?;
    epoch
        .map(|e| {
            Ok(sql_to_u32(
                e,
                "vault_rotation_staging_vaults.vault_key_epoch",
            )?)
        })
        .transpose()
}

/// The rows staged for `vault_id`, by locator: the wrap, or `None` for a dropped row.
pub(crate) async fn staged_rows(
    conn: Conn<'_>,
    account_id: AccountId,
    vault_id: VaultId,
) -> Result<BTreeMap<Locator, Option<Vec<u8>>>, VaultError> {
    let rows: Vec<StagedColumns> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(STAGING_ROWS)
            .bind(&account_id.as_bytes()[..])
            .bind(&vault_id.as_bytes()[..])
            .fetch_all(&mut *c)
            .await?
        {
            out.push((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?));
        }
        out
    });
    rows.into_iter()
        .map(|(item, key, wrap)| {
            Ok((
                (
                    ItemId::from_bytes(id16(&item, "vault_rotation_staging.item_id")?),
                    id16(&key, "vault_rotation_staging.item_key_id")?,
                ),
                wrap,
            ))
        })
        .collect()
}

/// The header `key_id` of an `ITEM_KEY_WRAP` envelope: a symmetric envelope of exactly
/// [`ITEM_KEY_WRAP_ENVELOPE_LEN`] bytes. `None` for anything else.
pub(crate) fn wrap_key_id(envelope: &[u8]) -> Option<[u8; 16]> {
    if envelope.len() != ITEM_KEY_WRAP_ENVELOPE_LEN {
        return None;
    }
    match parse_envelope(envelope) {
        Ok(EnvelopeRef::Symmetric(e)) => Some(*e.key_id()),
        _ => None,
    }
}

/// A stage request (module docs, steps 1–5), in `tx`, which holds the account lock; the
/// caller authorised the session and checked `base_state_seq` against the stored state.
///
/// # Errors
/// [`VaultError::Invalid`] for a failed check of steps 1–4; [`VaultError::Storage`] or
/// [`VaultError::Corrupt`] on a database failure. The caller drops the transaction on any
/// error, so a refused request stages nothing and deletes no older staging.
pub async fn stage_rotation(
    tx: &mut WriteTx,
    account_id: AccountId,
    request: &StageRequest,
    now_ms: u64,
) -> Result<StageResponse, VaultError> {
    let vault_id = VaultId::from_bytes(request.vault_id.to_bytes());
    // Step 1.
    let owned = repo::vault(tx.conn(), vault_id)
        .await?
        .is_some_and(|v| v.account_id == account_id);
    let rows = request
        .item_key_wraps
        .len()
        .saturating_add(request.dropped.len());
    if !owned || rows > ROTATION_STAGE_ROWS {
        return Err(VaultError::Invalid);
    }
    // Step 2.
    open(tx, account_id, request, now_ms).await?;
    // Step 3.
    let stored = repo::wraps_after(
        tx.conn(),
        vault_id,
        None,
        MAX_ITEM_KEY_WRAPS.saturating_add(1),
    )
    .await?;
    if stored.len() > MAX_ITEM_KEY_WRAPS {
        return Err(VaultError::Invalid);
    }
    let staged = staged_rows(tx.conn(), account_id, vault_id).await?;
    let new_rows = check_rows(request, &stored, &staged)?;
    // Steps 4 and 5.
    let now = to_sql_time(now_ms)?;
    for (at, wrap) in &new_rows {
        on_engine!(tx.conn(), |c| sqlx::query(STAGING_ROW_INSERT)
            .bind(&account_id.as_bytes()[..])
            .bind(&request.rotation_id.to_bytes()[..])
            .bind(&vault_id.as_bytes()[..])
            .bind(&at.0.as_bytes()[..])
            .bind(&at.1[..])
            .bind(wrap.as_deref())
            .execute(&mut *c)
            .await
            .map(|r| r.rows_affected()))?;
    }
    on_engine!(tx.conn(), |c| sqlx::query(STAGING_TOUCH)
        .bind(&account_id.as_bytes()[..])
        .bind(now)
        .execute(&mut *c)
        .await
        .map(|r| r.rows_affected()))?;
    let count: i64 = on_engine!(tx.conn(), |c| sqlx::query_scalar(STAGING_VAULT_COUNT)
        .bind(&account_id.as_bytes()[..])
        .bind(&vault_id.as_bytes()[..])
        .fetch_one(&mut *c)
        .await)?;
    let staged_rows =
        u32::try_from(sql_to_u64(count, "a counted staged row number")?).map_err(|_| {
            VaultError::Corrupt {
                what: "more staged rows than a u32",
            }
        })?;
    Ok(StageResponse { staged_rows })
}

/// Step 2: the account's one staging, opened or continued, and the vault's fixed epoch.
async fn open(
    tx: &mut WriteTx,
    account_id: AccountId,
    request: &StageRequest,
    now_ms: u64,
) -> Result<(), VaultError> {
    let rotation_id = request.rotation_id.to_bytes();
    let key_id = request.account_key_id.to_bytes();
    let current = staging(tx.conn(), account_id).await?;
    let continued = match current {
        Some(s) if s.rotation_id == rotation_id && !s.expired(now_ms) => {
            if s.base_state_seq != request.base_state_seq || s.account_key_id != key_id {
                return Err(VaultError::Invalid);
            }
            true
        }
        // Another rotation_id (the newer client wins) or an expired staging: deleted first.
        Some(_) => {
            discard_staging(tx, account_id).await?;
            false
        }
        None => false,
    };
    if !continued {
        let base = u64_to_sql(request.base_state_seq, "base_state_seq")?;
        let now = to_sql_time(now_ms)?;
        on_engine!(tx.conn(), |c| sqlx::query(STAGING_INSERT)
            .bind(&account_id.as_bytes()[..])
            .bind(&rotation_id[..])
            .bind(base)
            .bind(&key_id[..])
            .bind(now)
            .execute(&mut *c)
            .await
            .map(|r| r.rows_affected()))?;
    }
    let vault_id = VaultId::from_bytes(request.vault_id.to_bytes());
    match staged_epoch(tx.conn(), account_id, vault_id).await? {
        Some(epoch) if epoch == request.vault_key_epoch => {}
        Some(_) => return Err(VaultError::Invalid),
        None => {
            on_engine!(tx.conn(), |c| sqlx::query(STAGING_VAULT_INSERT)
                .bind(&account_id.as_bytes()[..])
                .bind(&vault_id.as_bytes()[..])
                .bind(u32_to_sql(request.vault_key_epoch))
                .execute(&mut *c)
                .await
                .map(|r| r.rows_affected()))?;
        }
    }
    Ok(())
}

/// Steps 3 and 4 of one request against the vault's `stored` rows and its `staged` ones: the
/// rows to insert (a repeat of a staged row is left out).
fn check_rows(
    request: &StageRequest,
    stored: &[repo::WrapRow],
    staged: &BTreeMap<Locator, Option<Vec<u8>>>,
) -> Result<Vec<StagedRow>, VaultError> {
    let stored_rows: BTreeSet<Locator> = stored
        .iter()
        .map(|row| (row.item_id, row.item_key_id))
        .collect();
    let stored_key_ids: BTreeSet<[u8; 16]> = stored
        .iter()
        .filter_map(|row| parse_envelope(&row.envelope).ok().map(|e| *e.key_id()))
        .collect();
    let mut key_id = staged.values().flatten().find_map(|w| wrap_key_id(w));
    let mut seen: BTreeSet<Locator> = BTreeSet::new();
    let mut new_rows = Vec::new();
    let mut take = |at: Locator, wrap: Option<Vec<u8>>| -> Result<(), VaultError> {
        if !stored_rows.contains(&at) || !seen.insert(at) {
            return Err(VaultError::Invalid);
        }
        match staged.get(&at) {
            Some(held) if *held == wrap => Ok(()),
            Some(_) => Err(VaultError::Invalid),
            None => {
                new_rows.push((at, wrap));
                Ok(())
            }
        }
    };
    for wrap in &request.item_key_wraps {
        let Some(id) = wrap_key_id(wrap.envelope.as_slice()) else {
            return Err(VaultError::Invalid);
        };
        if wrap.vault_key_epoch != request.vault_key_epoch
            || *key_id.get_or_insert(id) != id
            || stored_key_ids.contains(&id)
        {
            return Err(VaultError::Invalid);
        }
        let at = (
            ItemId::from_bytes(wrap.item_id.to_bytes()),
            wrap.item_key_id.to_bytes(),
        );
        take(at, Some(wrap.envelope.as_slice().to_vec()))?;
    }
    for locator in &request.dropped {
        let at = (
            ItemId::from_bytes(locator.item_id.to_bytes()),
            locator.item_key_id.to_bytes(),
        );
        take(at, None)?;
    }
    Ok(new_rows)
}

/// Checks that `rotation_id` names the account's open staging, opened on `base_state_seq`
/// for `account_key_id` and not expired at `now_ms` ([ADR 0092] §0 item 4: otherwise
/// `state_conflict`).
///
/// [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md
pub(crate) async fn check_named(
    conn: Conn<'_>,
    account_id: AccountId,
    rotation_id: RotationId,
    base_state_seq: u64,
    account_key_id: &[u8; 16],
    now_ms: u64,
) -> Result<(), VaultError> {
    match staging(conn, account_id).await? {
        Some(s)
            if s.rotation_id == rotation_id.to_bytes()
                && s.base_state_seq == base_state_seq
                && s.account_key_id == *account_key_id
                && !s.expired(now_ms) =>
        {
            Ok(())
        }
        _ => Err(VaultError::StateConflict),
    }
}

impl<D> VaultDomain<D> {
    /// The worker's expiry of rotation stagings ([ADR 0092] §4 "Expiry"): deletes every
    /// staging whose last stage request is older than [`ROTATION_STAGE_TTL_MS`] at `now_ms`,
    /// one account at a time under its lock. Returns how many it deleted.
    ///
    /// # Errors
    /// [`VaultError::Storage`] or [`VaultError::Corrupt`] on a database failure; stagings
    /// deleted before it stay deleted.
    ///
    /// [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md
    pub async fn expire_rotation_stagings(&self, now_ms: u64) -> Result<usize, VaultError> {
        let cut = to_sql_time(now_ms.saturating_sub(ROTATION_STAGE_TTL_MS))?;
        let accounts: Vec<Vec<u8>> = {
            let mut r = self.database().begin_read().await?;
            on_engine!(r.conn(), |c| sqlx::query_scalar(STAGING_EXPIRED)
                .bind(cut.saturating_add(1))
                .fetch_all(&mut *c)
                .await)?
        };
        let mut deleted = 0;
        for account in accounts {
            let account_id =
                AccountId::from_bytes(id16(&account, "vault_rotation_stagings.account_id")?);
            let mut tx = self.database().begin_write().await?;
            lock_account(&mut tx, account_id.as_bytes()).await?;
            if staging(tx.conn(), account_id)
                .await?
                .is_some_and(|s| s.expired(now_ms))
            {
                discard_staging(&mut tx, account_id).await?;
                deleted += 1;
            }
            tx.commit().await?;
        }
        Ok(deleted)
    }
}
