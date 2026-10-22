// SPDX-License-Identifier: AGPL-3.0-only

//! The per-account storage counter's backfill and reconciliation ([ADR 0048] §4).
//!
//! The counter is `rizzy-storage`'s (`storage_account_usage`, [`rizzy_storage::quota`]); each
//! domain that stores bytes for an account reports the account's true total through its own
//! Rust API, and this module, the one crate that sees every domain, sets the counter from the
//! sum. Today the only such domain is `rizzy-domain-vault` ([`rizzy_domain_vault::usage`]); the
//! mail and share domains join this sum once they exist (§5).
//!
//! Each account is one write transaction under its account lock: the domain totals and the
//! counter are read and written on the same connection, so no upload of the account runs in
//! between.
//!
//! - [`backfill`], at startup, before anything is served (`crate::server::open_services`):
//!   seeds the counter of every account that owns a vault but has no counter row yet. After the
//!   migration that created the table (0006) that is every existing account; later, only an
//!   account that never stored a record (its seed is 0). So no pre-existing account is checked
//!   against an implicit zero.
//! - [`reconcile`], `worker`'s daily pass: recomputes every account's total, those with a
//!   counter row included, and corrects the counter where it drifted. Each correction is
//!   returned and logged by the caller with the account id and the two values, never content.
//!
//! [ADR 0048]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0048-per-account-storage-quota.md

use core::fmt;
use std::collections::BTreeSet;

use rizzy_domain_auth::types::AccountId;
use rizzy_domain_vault::VaultError;
use rizzy_storage::quota::{self, Drift};
use rizzy_storage::{Database, lock_account};

/// Why a pass stopped. `Display` carries no value.
#[derive(Debug)]
pub enum UsageError {
    /// The database.
    Storage(rizzy_storage::Error),
    /// The vault domain's total.
    Vault(VaultError),
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage counter: {e}"),
            Self::Vault(e) => write!(f, "storage counter, vault total: {e}"),
        }
    }
}

impl std::error::Error for UsageError {}

impl From<rizzy_storage::Error> for UsageError {
    fn from(e: rizzy_storage::Error) -> Self {
        Self::Storage(e)
    }
}

impl From<VaultError> for UsageError {
    fn from(e: VaultError) -> Self {
        Self::Vault(e)
    }
}

/// One counter a pass corrected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Correction {
    /// The account.
    pub account_id: [u8; 16],
    /// What the counter held, and the true total it holds now.
    pub drift: Drift,
}

/// The account's true counted bytes: the sum over every domain that stores bytes for it.
async fn true_total(
    tx: &mut rizzy_storage::WriteTx,
    account_id: &[u8; 16],
) -> Result<u64, UsageError> {
    let vault =
        rizzy_domain_vault::usage::counted_bytes(tx.conn(), AccountId::from_bytes(*account_id))
            .await?;
    Ok(vault)
}

/// Sets one account's counter to its true total, under its lock; `seed` writes a row even when
/// the total is 0.
async fn settle_one(
    db: &Database,
    account_id: &[u8; 16],
    seed: bool,
    now_ms: i64,
) -> Result<Option<Drift>, UsageError> {
    let mut tx = db.begin_write().await?;
    lock_account(&mut tx, account_id).await?;
    let total = true_total(&mut tx, account_id).await?;
    let drift = quota::reconcile(&mut tx, account_id, total, seed, now_ms).await?;
    tx.commit().await?;
    Ok(drift)
}

/// The accounts that own a vault, and the accounts with a counter row.
async fn known_accounts(db: &Database) -> Result<(Vec<[u8; 16]>, Vec<[u8; 16]>), UsageError> {
    let mut r = db.begin_read().await?;
    let owners: Vec<[u8; 16]> = rizzy_domain_vault::usage::accounts(r.conn())
        .await?
        .iter()
        .map(|a| a.to_bytes())
        .collect();
    let counted = quota::accounts(r.conn()).await?;
    r.finish().await?;
    Ok((owners, counted))
}

/// Seeds the counter of every account that owns a vault and has no counter row (module docs).
/// Returns how many accounts were seeded.
///
/// # Errors
/// [`UsageError`]; the accounts seeded before it stay seeded, and the next startup seeds the
/// rest.
pub async fn backfill(db: &Database, now_ms: i64) -> Result<usize, UsageError> {
    let (owners, counted) = known_accounts(db).await?;
    let counted: BTreeSet<[u8; 16]> = counted.into_iter().collect();
    let mut seeded = 0usize;
    for account_id in owners.iter().filter(|a| !counted.contains(*a)) {
        settle_one(db, account_id, true, now_ms).await?;
        seeded = seeded.saturating_add(1);
    }
    Ok(seeded)
}

/// Recomputes every account's total and corrects each counter that drifted (module docs).
///
/// # Errors
/// [`UsageError`] for the listing; an account whose pass fails is skipped and reported in the
/// second list, so one damaged account does not stop the others.
pub async fn reconcile(
    db: &Database,
    now_ms: i64,
) -> Result<(Vec<Correction>, Vec<UsageError>), UsageError> {
    let (owners, counted) = known_accounts(db).await?;
    let all: BTreeSet<[u8; 16]> = owners.into_iter().chain(counted).collect();
    let mut corrections = Vec::new();
    let mut failures = Vec::new();
    for account_id in &all {
        match settle_one(db, account_id, false, now_ms).await {
            Ok(Some(drift)) => corrections.push(Correction {
                account_id: *account_id,
                drift,
            }),
            Ok(None) => {}
            Err(e) => failures.push(e),
        }
    }
    Ok((corrections, failures))
}
