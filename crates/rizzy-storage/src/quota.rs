// SPDX-License-Identifier: AGPL-3.0-only

//! The per-account storage counter (ADR 0048 §3, §4): one number per account, the account's
//! counted bytes, which every domain that stores bytes for the account charges.
//!
//! The counter is this crate's, not a domain's, because it spans domains by design (ADR 0048
//! §5): `rizzy-domain-vault` charges it today; mail and shares will charge the same row once
//! they are built. The unit is the domains' (§2): this module only adds, sets and reads.
//!
//! - [`adjust`] adds a signed delta, inside a write transaction that already holds the
//!   account's lock ([`crate::lock_account`]), and returns the new value. An upload charges what
//!   it stored; compaction credits what it deleted.
//! - [`bytes_used`] reads the value, `0` for an account with no row yet.
//! - [`reconcile`] sets the value to the true sum a domain recomputed from its rows, for the
//!   first-startup backfill and `worker`'s daily pass (§4), and reports the drift it corrected.
//! - [`accounts`] lists the accounts that have a row, so a pass also reaches an account whose
//!   domain rows are all gone.
//!
//! **Never below zero.** A credit larger than the stored value can only follow drift (for
//! example a row the backfill has not seeded yet); the value then stops at `0` and the next
//! reconciliation sets the true sum. The column's `CHECK (bytes_used >= 0)` stays satisfied.

use sqlx::Row;

use crate::db::{Conn, WriteTx};
use crate::error::Error;

/// The default per-account quota, `RIZZY_ACCOUNT_QUOTA_BYTES` unset: 5 GiB (ADR 0048 §1).
pub const DEFAULT_QUOTA_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// The smallest quota an operator may set: 256 MiB (ADR 0048 §1). There is no maximum.
pub const MIN_QUOTA_BYTES: u64 = 256 * 1024 * 1024;

/// Reads one account's counter.
const USAGE_GET: &str = include_str!("../queries/storage/usage_get.sql");
/// Sets one account's counter, inserting its row on first use.
const USAGE_PUT: &str = include_str!("../queries/storage/usage_put.sql");
/// Lists the accounts with a counter row.
const USAGE_LIST: &str = include_str!("../queries/storage/usage_list.sql");

/// The counted bytes of `account_id`: `0` while it has no row.
///
/// # Errors
///
/// - [`Error::Corrupt`] when the stored value is negative.
/// - [`Error::Database`] when the query fails.
pub async fn bytes_used(conn: Conn<'_>, account_id: &[u8; 16]) -> Result<u64, Error> {
    let value: Option<i64> = crate::on_engine!(conn, |c| {
        match sqlx::query(USAGE_GET)
            .bind(&account_id[..])
            .fetch_optional(&mut *c)
            .await?
        {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        }
    });
    value.map_or(Ok(0), from_sql)
}

/// Adds `delta` to the counter of `account_id` and returns the new value (ADR 0048 §3), in the
/// caller's write transaction, which has taken the account's lock. Upserts: an account with no
/// row starts from `0`. The result is clamped to `0 ..= i64::MAX` (module docs).
///
/// # Errors
///
/// - [`Error::Corrupt`] when the stored value is negative.
/// - [`Error::Database`] when a statement fails.
pub async fn adjust(
    tx: &mut WriteTx,
    account_id: &[u8; 16],
    delta: i64,
    now_ms: i64,
) -> Result<u64, Error> {
    let current = bytes_used(tx.conn(), account_id).await?;
    let current = i64::try_from(current).unwrap_or(i64::MAX);
    let next = current.saturating_add(delta).max(0);
    put(tx, account_id, next, now_ms).await?;
    from_sql(next)
}

/// A correction [`reconcile`] made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Drift {
    /// The value the counter held (`0` for no row).
    pub was: u64,
    /// The true sum it now holds.
    pub now: u64,
}

/// Sets the counter of `account_id` to `total`, the true sum its domains recomputed from their
/// rows in this same transaction (ADR 0048 §4), which has taken the account's lock. Writes only
/// when the value differs, or when `seed` is set and the account has no row yet (the
/// first-startup backfill seeds every account it reaches, `0` included). Returns the
/// correction, or `None` when the stored value already matched.
///
/// # Errors
///
/// - [`Error::Corrupt`] when the stored value is negative.
/// - [`Error::Database`] when a statement fails.
pub async fn reconcile(
    tx: &mut WriteTx,
    account_id: &[u8; 16],
    total: u64,
    seed: bool,
    now_ms: i64,
) -> Result<Option<Drift>, Error> {
    let stored: Option<i64> = crate::on_engine!(tx.conn(), |c| {
        match sqlx::query(USAGE_GET)
            .bind(&account_id[..])
            .fetch_optional(&mut *c)
            .await?
        {
            Some(row) => Some(row.try_get(0)?),
            None => None,
        }
    });
    let was = stored.map_or(Ok(0), from_sql)?;
    let total_sql = i64::try_from(total).unwrap_or(i64::MAX);
    let total = from_sql(total_sql)?;
    if was == total && (stored.is_some() || !seed) {
        return Ok(None);
    }
    put(tx, account_id, total_sql, now_ms).await?;
    Ok((was != total).then_some(Drift { was, now: total }))
}

/// Every account with a counter row, ascending.
///
/// # Errors
///
/// - [`Error::Corrupt`] when a stored id is not 16 bytes.
/// - [`Error::Database`] when the query fails.
pub async fn accounts(conn: Conn<'_>) -> Result<Vec<[u8; 16]>, Error> {
    let rows: Vec<Vec<u8>> = crate::on_engine!(conn, |c| {
        let mut out = Vec::new();
        for row in sqlx::query(USAGE_LIST).fetch_all(&mut *c).await? {
            out.push(row.try_get(0)?);
        }
        out
    });
    rows.into_iter()
        .map(|id| {
            <[u8; 16]>::try_from(id.as_slice()).map_err(|_| Error::Corrupt {
                what: "storage_account_usage.account_id",
            })
        })
        .collect()
}

/// Writes `value` as the counter of `account_id`.
async fn put(
    tx: &mut WriteTx,
    account_id: &[u8; 16],
    value: i64,
    now_ms: i64,
) -> Result<(), Error> {
    crate::on_engine!(tx.conn(), |c| sqlx::query(USAGE_PUT)
        .bind(&account_id[..])
        .bind(value)
        .bind(now_ms.max(0))
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// A stored value as a count.
fn from_sql(value: i64) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::Corrupt {
        what: "storage_account_usage.bytes_used",
    })
}
