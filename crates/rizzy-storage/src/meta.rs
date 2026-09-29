//! The restore hooks the domain crates use: the restore generation (ADR 0021 §2) and the
//! per-account reconciliation epoch (THREAT_MODEL INV-59, ADR 0012 §7).
//!
//! This crate stores them and changes them only where the ADRs say storage does: the first
//! restore generation when the database is created ([`ensure_restore_generation`]), and a new
//! generation plus an epoch for every account in the restore transaction
//! ([`Database::restore`](crate::Database::restore)). What they mean is domain logic:
//! `rizzy-domain-vault` puts the generation into every upload answer and Fetch response, and
//! `rizzy-domain-auth` accepts out-of-band state adoption and certificate-carrying device
//! authentication only while an account's epoch is open, and ends it
//! ([`end_reconciliation_epoch`]) once a device of the restored set uploads a newer verified
//! state, or `worker` ends it after the admin-set limit.
//!
//! The randomness is injected: callers pass a [`RestoreGeneration`] drawn from the leaf
//! crate's CSPRNG (ADR 0016 R2 (b): a library takes an injected RNG).

use std::fmt;

use sqlx::Row;

use crate::db::{Conn, Database, WriteTx};
use crate::error::Error;

/// Inserts the first restore generation unless one exists.
const RESTORE_GENERATION_INIT: &str =
    include_str!("../queries/storage/restore_generation_init.sql");
/// Reads the restore generation.
const RESTORE_GENERATION_GET: &str = include_str!("../queries/storage/restore_generation_get.sql");
/// Reads one account's reconciliation epoch.
const RECONCILIATION_GET: &str = include_str!("../queries/storage/reconciliation_get.sql");
/// Ends one account's reconciliation epoch.
const RECONCILIATION_END: &str = include_str!("../queries/storage/reconciliation_end.sql");
/// Lists every open reconciliation epoch.
const RECONCILIATION_LIST: &str = include_str!("../queries/storage/reconciliation_list.sql");

/// The restore generation: one random 128-bit value per server database (ADR 0021 §2). Not a
/// secret: every upload answer and Fetch response carries it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RestoreGeneration(pub [u8; 16]);

impl RestoreGeneration {
    /// The 16 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parses a stored value.
    fn from_stored(bytes: &[u8], what: &'static str) -> Result<Self, Error> {
        <[u8; 16]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::Corrupt { what })
    }
}

impl fmt::Debug for RestoreGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RestoreGeneration(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// An open reconciliation epoch of one account (INV-59).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconciliationEpoch {
    /// The restore generation the restore that opened it drew.
    pub restore_generation: RestoreGeneration,
    /// When the restore opened it, in ms since the Unix epoch.
    pub opened_at_ms: i64,
}

/// Draws the database's restore generation if it has none: stores `candidate` in a new
/// database, keeps the stored value otherwise, and returns the value in force. The server
/// calls it at startup, after migrating, with a fresh random `candidate` (ADR 0021 §2: "drawn
/// when the database is created").
///
/// # Errors
///
/// - [`Error::ReadOnly`] on a read-only SQLite handle.
/// - [`Error::Corrupt`] when the stored value is not 16 bytes.
/// - [`Error::Database`] when a query fails.
pub async fn ensure_restore_generation(
    db: &Database,
    candidate: RestoreGeneration,
    now_ms: i64,
) -> Result<RestoreGeneration, Error> {
    let mut tx = db.begin_write().await?;
    crate::on_engine!(tx.conn(), |c| sqlx::query(RESTORE_GENERATION_INIT)
        .bind(&candidate.0[..])
        .bind(now_ms)
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    let stored = restore_generation(tx.conn()).await?;
    tx.commit().await?;
    stored.ok_or(Error::Corrupt {
        what: "storage_meta has no restore generation after it was drawn",
    })
}

/// The restore generation in force, or `None` before [`ensure_restore_generation`] ran on a
/// new database.
///
/// # Errors
///
/// - [`Error::Corrupt`] when the stored value is not 16 bytes.
/// - [`Error::Database`] when the query fails.
pub async fn restore_generation(conn: Conn<'_>) -> Result<Option<RestoreGeneration>, Error> {
    let bytes: Option<Vec<u8>> =
        crate::on_engine!(conn, |c| sqlx::query_scalar(RESTORE_GENERATION_GET)
            .fetch_optional(&mut *c)
            .await)?;
    bytes
        .map(|b| RestoreGeneration::from_stored(&b, "storage_meta.restore_generation"))
        .transpose()
}

/// The open reconciliation epoch of `account_id`, if any.
///
/// # Errors
///
/// - [`Error::Corrupt`] when the stored generation is not 16 bytes.
/// - [`Error::Database`] when the query fails.
pub async fn reconciliation_epoch(
    conn: Conn<'_>,
    account_id: &[u8; 16],
) -> Result<Option<ReconciliationEpoch>, Error> {
    let row: Option<(Vec<u8>, i64)> = crate::on_engine!(conn, |c| {
        match sqlx::query(RECONCILIATION_GET)
            .bind(&account_id[..])
            .fetch_optional(&mut *c)
            .await?
        {
            Some(row) => Some((row.try_get(0)?, row.try_get(1)?)),
            None => None,
        }
    });
    row.map(|(generation, opened_at_ms)| {
        Ok(ReconciliationEpoch {
            restore_generation: RestoreGeneration::from_stored(
                &generation,
                "storage_reconciliation.restore_generation",
            )?,
            opened_at_ms,
        })
    })
    .transpose()
}

/// Every open reconciliation epoch, oldest first, for `worker`'s admin-set limit.
///
/// # Errors
///
/// - [`Error::Corrupt`] when a stored id or generation is not 16 bytes.
/// - [`Error::Database`] when the query fails.
pub async fn reconciliation_epochs(
    conn: Conn<'_>,
) -> Result<Vec<([u8; 16], ReconciliationEpoch)>, Error> {
    let rows: Vec<(Vec<u8>, Vec<u8>, i64)> = crate::on_engine!(conn, |c| {
        let mut out = Vec::new();
        for row in sqlx::query(RECONCILIATION_LIST).fetch_all(&mut *c).await? {
            out.push((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?));
        }
        out
    });
    rows.into_iter()
        .map(|(account_id, generation, opened_at_ms)| {
            let account_id =
                <[u8; 16]>::try_from(account_id.as_slice()).map_err(|_| Error::Corrupt {
                    what: "storage_reconciliation.account_id",
                })?;
            let restore_generation = RestoreGeneration::from_stored(
                &generation,
                "storage_reconciliation.restore_generation",
            )?;
            Ok((
                account_id,
                ReconciliationEpoch {
                    restore_generation,
                    opened_at_ms,
                },
            ))
        })
        .collect()
}

/// Ends the reconciliation epoch of `account_id`, in the caller's write transaction (which has
/// taken the account's lock). Returns whether an epoch was open.
///
/// # Errors
///
/// [`Error::Database`] when the statement fails.
pub async fn end_reconciliation_epoch(
    tx: &mut WriteTx,
    account_id: &[u8; 16],
) -> Result<bool, Error> {
    let affected = crate::on_engine!(tx.conn(), |c| sqlx::query(RECONCILIATION_END)
        .bind(&account_id[..])
        .execute(&mut *c)
        .await
        .map(|r| r.rows_affected()))?;
    Ok(affected > 0)
}
