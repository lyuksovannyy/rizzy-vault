//! Retiring old OPAQUE setups (CRYPTO.md §5.8 "Rotating `server_setup`" steps 3–4; [ADR 0031]).
//!
//! # What is stored (point 1)
//!
//! `auth_opaque_setups` keeps one row per setup the server ever loaded, with `retired_at_ms`
//! NULL while the setup is accepted. A row is never deleted: it is the tombstone that keeps a
//! retired setup retired, and `auth_credentials.setup_id` references it. A setup's **successor
//! time** is the smallest `created_at_ms` of a row with a higher `setup_id`
//! ([`successor_time`]); the highest row has none.
//!
//! # Selection (points 4–5)
//!
//! `rizzy-vault secrets retire-setups --grace-days N` (default [`DEFAULT_GRACE_DAYS`], range
//! 0–[`MAX_GRACE_DAYS`]) selects every setup that is not the current one, is not retired yet,
//! and whose successor time is at least N days before now ([`select`]). The current setup is
//! the secrets file's highest `setup_id`: a setup at or above it is never selected, and a setup
//! whose successor the database has not recorded yet (a `secrets rotate` not followed by a
//! server start) has no successor time and is not selected either.
//!
//! # The two steps (points 5–6)
//!
//! With every server process shut out (the caller's lock):
//! 1. [`ServerSecrets::retire_in_database`]: one transaction sets `retired_at_ms = now` on the
//!    selected rows where it is still NULL, and deletes every login state.
//! 2. [`ServerSecrets::remove_retired_setups`]: every setup the database marks retired, this
//!    run's and any earlier one's, is removed from the secrets file's contents; the caller
//!    writes the file when anything was removed.
//!
//! The startup check refuses a secrets file that holds a retired setup
//! ([`crate::StartupCheckError::RetiredSetupLoaded`]), so a crash between the steps fails
//! closed, and running the command again with any grace period finishes it: step 2 removes
//! every retired setup, and step 1 never rewrites a retirement time.
//!
//! # At run time (points 2, 3, 7, 10)
//!
//! The server reads only what the secrets file loads: a record whose setup the file lacks takes
//! the fake-record path at login (`login.rs`). A registration's echoed `setup_id` is accepted
//! when the file loads it and the database does not mark it retired
//! (`AuthService::check_echoed_setup`), refused with [`AuthError::SetupRetired`] otherwise.
//! Logins and device authentications against a record on a setup other than the current one
//! answer `reregister = true`. `worker` reports setups past the default grace period
//! ([`AuthService::retirable_setups`]); it never retires one.
//!
//! [ADR 0031]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0031-retiring-old-opaque-setups.md

use std::collections::BTreeMap;

use rizzy_storage::{Conn, Database};

use crate::AuthService;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::secrets::ServerSecrets;
use crate::sql::{self, exec, fetch_all, fetch_opt};

/// The grace period `secrets retire-setups` uses without `--grace-days` (ADR 0031 point 4,
/// owner decision on open question 1), and the age after which `worker` reports a setup
/// (point 10).
pub const DEFAULT_GRACE_DAYS: u32 = 90;

/// The longest grace period `--grace-days` accepts (point 4: "any value 0–3650").
pub const MAX_GRACE_DAYS: u32 = 3650;

/// One day in milliseconds.
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// One recorded OPAQUE setup, as `auth_opaque_setups` holds it (no secret: the public-key hash
/// is not read here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupRow {
    /// The `setup_id`.
    pub setup_id: u32,
    /// When the server first started with it (the startup check records it).
    pub created_at_ms: u64,
    /// When `secrets retire-setups` retired it, if it did.
    pub retired_at_ms: Option<u64>,
}

/// The successor time of `setup_id` (point 1): the smallest `created_at_ms` of a row with a
/// higher `setup_id`. `None` for the highest row.
#[must_use]
pub fn successor_time(rows: &[SetupRow], setup_id: u32) -> Option<u64> {
    rows.iter()
        .filter(|r| r.setup_id > setup_id)
        .map(|r| r.created_at_ms)
        .min()
}

/// Whether `grace_days` is in the range point 4 allows.
#[must_use]
pub const fn grace_days_allowed(grace_days: u32) -> bool {
    grace_days <= MAX_GRACE_DAYS
}

/// The setups `secrets retire-setups --grace-days grace_days` selects at `now_ms` (point 5;
/// module docs), each with its successor time, ascending by `setup_id`: below
/// `current_setup_id`, not retired, and with a successor time at least `grace_days` days
/// before `now_ms` (exactly `grace_days` days is selected). A successor time in the future
/// (a clock that went back) selects nothing.
#[must_use]
pub fn select(
    rows: &[SetupRow],
    current_setup_id: u32,
    now_ms: u64,
    grace_days: u32,
) -> Vec<(u32, u64)> {
    let grace_ms = u64::from(grace_days).saturating_mul(DAY_MS);
    rows.iter()
        .filter(|r| r.setup_id < current_setup_id && r.retired_at_ms.is_none())
        .filter_map(|r| Some((r.setup_id, successor_time(rows, r.setup_id)?)))
        .filter(|(_, successor)| {
            now_ms
                .checked_sub(*successor)
                .is_some_and(|age| age >= grace_ms)
        })
        .collect()
}

/// A setup `secrets retire-setups` selected, with what it prints for it (point 5): ids and
/// counts only, no account names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetirableSetup {
    /// The `setup_id`.
    pub setup_id: u32,
    /// Its successor time (point 1).
    pub successor_at_ms: u64,
    /// How many `auth_credentials` rows still name it: the accounts that lose OPAQUE login and
    /// take the device or recovery path (point 7).
    pub records: u64,
}

/// Every row of `auth_opaque_setups`.
async fn setup_rows(conn: Conn<'_>) -> Result<Vec<SetupRow>, AuthError> {
    let rows: Vec<(i64, i64, Option<i64>)> =
        fetch_all!(conn, (i64, i64, Option<i64>), sql::SETUPS_ALL)?;
    rows.into_iter()
        .map(|(id, created, retired)| {
            Ok(SetupRow {
                setup_id: sql::sql_u32(id, "setup_id")?,
                created_at_ms: sql::sql_u64(created, "created_at_ms")?,
                retired_at_ms: retired
                    .map(|r| sql::sql_u64(r, "retired_at_ms"))
                    .transpose()?,
            })
        })
        .collect()
}

/// How many OPAQUE records name each `setup_id`.
async fn record_counts(conn: Conn<'_>) -> Result<BTreeMap<u32, u64>, AuthError> {
    let rows: Vec<(i64, i64)> = fetch_all!(conn, (i64, i64), sql::CREDENTIAL_SETUP_COUNTS)?;
    rows.into_iter()
        .map(|(id, count)| {
            Ok((
                sql::sql_u32(id, "setup_id")?,
                sql::sql_u64(count, "record count")?,
            ))
        })
        .collect()
}

impl ServerSecrets {
    /// What `secrets retire-setups --grace-days grace_days` selects at `now_ms` (module docs),
    /// with each setup's record count. Reads only. The database must be at this release's
    /// schema.
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for a grace period outside 0–[`MAX_GRACE_DAYS`]; storage
    /// errors.
    pub async fn plan_retirement(
        &self,
        db: &Database,
        now_ms: u64,
        grace_days: u32,
    ) -> Result<Vec<RetirableSetup>, AuthError> {
        if !grace_days_allowed(grace_days) {
            return Err(AuthError::InvalidRequest);
        }
        let mut tx = db.begin_read().await?;
        let rows = setup_rows(tx.conn()).await?;
        let counts = record_counts(tx.conn()).await?;
        tx.finish().await?;
        Ok(select(&rows, self.current_setup_id(), now_ms, grace_days)
            .into_iter()
            .map(|(setup_id, successor_at_ms)| RetirableSetup {
                setup_id,
                successor_at_ms,
                records: counts.get(&setup_id).copied().unwrap_or(0),
            })
            .collect())
    }

    /// Step 1 of point 5, in one transaction: `retired_at_ms = now_ms` on the rows of
    /// `setup_ids` where it is still NULL (an earlier retirement keeps its time), and every
    /// login state deleted (a login started under a retired setup must not finish).
    ///
    /// # Errors
    /// Storage errors; nothing is written then.
    pub async fn retire_in_database(
        db: &Database,
        setup_ids: &[u32],
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let now = sql::u64_sql(now_ms, "now_ms")?;
        let mut tx = db.begin_write().await?;
        for id in setup_ids {
            exec!(tx.conn(), sql::SETUP_RETIRE, i64::from(*id), now)?;
        }
        exec!(tx.conn(), sql::LOGIN_STATES_DELETE_ALL)?;
        tx.commit().await?;
        Ok(())
    }

    /// Step 2 of point 5: removes from these secrets every setup the database marks retired,
    /// this run's and any earlier one's. Returns the removed ids, ascending; the caller writes
    /// the file when there is one (and writes nothing otherwise).
    ///
    /// # Errors
    /// [`AuthError::Internal`] when the database marks the current setup (the file's highest)
    /// retired, which `secrets retire-setups` never does: nothing is removed, as removing it
    /// would leave the file without the setup new registrations use. Storage errors.
    pub async fn remove_retired_setups(&mut self, db: &Database) -> Result<Vec<u32>, AuthError> {
        let mut tx = db.begin_read().await?;
        let rows = setup_rows(tx.conn()).await?;
        tx.finish().await?;
        let current = self.current_setup_id();
        let retired: Vec<u32> = rows
            .iter()
            .filter(|r| r.retired_at_ms.is_some() && self.setup(r.setup_id).is_some())
            .map(|r| r.setup_id)
            .collect();
        if retired.contains(&current) {
            return Err(AuthError::Internal(
                "the database marks the current OPAQUE setup retired",
            ));
        }
        Ok(retired
            .into_iter()
            .filter(|id| self.remove_setup(*id))
            .collect())
    }
}

impl<V: VaultPort> AuthService<V> {
    /// The check of an echoed `setup_id` at a registration's commit (point 3): accepted when
    /// the secrets file loads it and the database records it without a retirement, current or
    /// not; [`AuthError::SetupRetired`] for a retired or unknown one. Runs on the commit's
    /// transaction, after the byte-identical-repeat check.
    pub(crate) async fn check_echoed_setup(
        &self,
        conn: Conn<'_>,
        setup_id: u32,
    ) -> Result<(), AuthError> {
        if self.secrets.setup(setup_id).is_none() {
            return Err(AuthError::SetupRetired);
        }
        let row: Option<(Option<i64>,)> = fetch_opt!(
            conn,
            (Option<i64>,),
            sql::SETUP_RETIRED_AT,
            i64::from(setup_id)
        )?;
        match row {
            Some((None,)) => Ok(()),
            Some((Some(_),)) | None => Err(AuthError::SetupRetired),
        }
    }

    /// Whether a record registered under `setup_id` must move to the current setup (point 2):
    /// it names another one. Only called after KE3 or the device signature verified.
    pub(crate) fn needs_reregistration(&self, setup_id: u32) -> bool {
        setup_id != self.secrets.current_setup_id()
    }

    /// What `worker` reports (point 10), read only: every setup below the current one, not
    /// retired, whose successor time is more than [`DEFAULT_GRACE_DAYS`] days before `now_ms`,
    /// with the number of records that still name it, ascending by `setup_id`. It never
    /// retires a setup or writes the secrets file.
    ///
    /// # Errors
    /// Storage errors.
    pub async fn retirable_setups(&self, now_ms: u64) -> Result<Vec<RetirableSetup>, AuthError> {
        let mut tx = self.db.begin_read().await?;
        let rows = setup_rows(tx.conn()).await?;
        let counts = record_counts(tx.conn()).await?;
        tx.finish().await?;
        // "More than 90 days old": one millisecond past the selection's boundary.
        let grace_ms = u64::from(DEFAULT_GRACE_DAYS).saturating_mul(DAY_MS);
        Ok(rows
            .iter()
            .filter(|r| r.setup_id < self.secrets.current_setup_id() && r.retired_at_ms.is_none())
            .filter_map(|r| Some((r.setup_id, successor_time(&rows, r.setup_id)?)))
            .filter(|(_, successor)| {
                now_ms
                    .checked_sub(*successor)
                    .is_some_and(|age| age > grace_ms)
            })
            .map(|(setup_id, successor_at_ms)| RetirableSetup {
                setup_id,
                successor_at_ms,
                records: counts.get(&setup_id).copied().unwrap_or(0),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    //! Successor time and selection by grace (ADR 0031 point 11, unit).

    use super::*;

    fn row(setup_id: u32, created_at_ms: u64, retired_at_ms: Option<u64>) -> SetupRow {
        SetupRow {
            setup_id,
            created_at_ms,
            retired_at_ms,
        }
    }

    #[test]
    fn successor_time_is_the_earliest_higher_row() {
        let rows = [row(1, 10, None), row(2, 500, None), row(3, 300, None)];
        assert_eq!(successor_time(&rows, 1), Some(300));
        assert_eq!(successor_time(&rows, 2), Some(300));
        assert_eq!(successor_time(&rows, 3), None);
        assert_eq!(successor_time(&[], 1), None);
    }

    #[test]
    fn selection_by_grace() {
        let day = DAY_MS;
        let rows = [
            row(1, 0, None),
            row(2, 10 * day, None),
            row(3, 20 * day, None),
        ];
        let now = 30 * day;
        // 0 days: every non-current setup with a successor.
        assert_eq!(select(&rows, 3, now, 0), vec![(1, 10 * day), (2, 20 * day)]);
        // The exact boundary is selected; one millisecond short is not.
        assert_eq!(select(&rows, 3, now, 20), vec![(1, 10 * day)]);
        assert_eq!(select(&rows, 3, now - 1, 20), vec![]);
        assert_eq!(
            select(&rows, 3, now, 10),
            vec![(1, 10 * day), (2, 20 * day)]
        );
        // The current setup is never selected, nor anything at or above the file's current.
        assert_eq!(select(&rows, 2, now, 0), vec![(1, 10 * day)]);
        assert_eq!(select(&rows, 1, now, 0), vec![]);
        // A setup retired before is not selected again.
        let retired = [row(1, 0, Some(5)), row(2, 10 * day, None)];
        assert_eq!(select(&retired, 2, now, 0), vec![]);
        // A successor in the future (the clock went back) selects nothing.
        assert_eq!(select(&rows, 3, 5 * day, 0), vec![]);
        assert!(grace_days_allowed(0) && grace_days_allowed(MAX_GRACE_DAYS));
        assert!(!grace_days_allowed(MAX_GRACE_DAYS + 1));
    }
}
