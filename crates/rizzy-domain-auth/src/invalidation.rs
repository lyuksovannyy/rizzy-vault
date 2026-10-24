// SPDX-License-Identifier: AGPL-3.0-only

//! The database half of `rizzy-vault secrets invalidate` ([ADR 0047]; CRYPTO.md §5.8 "the
//! admin marks the records invalid"), for the case where the secrets file's OPAQUE setup can
//! no longer be made to match the database and no secrets backup fits.
//!
//! # The two diagnosed cases (step 2)
//!
//! The caller (`rizzy-server`'s `admin`) diagnoses; this module only carries a case out:
//! - [`LossCase::SetupOnly`]: the file loads, and [`ServerSecrets::check_database_dry_run`]
//!   answers `SetupMismatch` or `NoRecordedSetup`. Only the setup is wrong: `enum_key`, the
//!   data keys and the bootstrap token carry forward, so no TOTP row is deleted.
//! - [`LossCase::Whole`]: the file is absent or unparsable. Nothing carries forward, so every
//!   TOTP row (sealed under a lost data key) is deleted.
//!
//! # Step 4, one transaction ([`invalidate_in_database`])
//!
//! 1. Every unretired `auth_opaque_setups` row is retired (`retired_at_ms = now`), the
//!    current one and any an earlier crashed attempt minted included. No row is deleted (ADR
//!    0031 point 1).
//! 2. Every `auth_login_states` row is deleted; on a whole loss every
//!    `auth_totp_credentials` row too. `auth_credentials` stays untouched (ADR 0031 point 7):
//!    every account re-registers through an enrolled device or its recovery code.
//! 3. The new setup is recorded under (the highest `setup_id` recorded, burned ones
//!    included) + 1, never reusing one, so the next start's `check_database` finds it
//!    recorded and matching.
//! 4. The crash marker `auth_invalidate_pending` (case, the new `setup_id`, the diagnosis
//!    time) is written. The caller writes the secrets file, then clears it
//!    ([`clear_pending_invalidation`]). A marker left behind (a crash between the two) makes
//!    the next run resume the recorded case ([`pending_invalidation`]) instead of diagnosing
//!    the file again: after a setup-only loss's step 4 every row is retired, so the unchanged
//!    file now reads as `RetiredSetupLoaded`, which the diagnosis refuses.
//!
//! [ADR 0047]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0047-opaque-secrets-operator-commands.md

use rizzy_storage::Database;

use crate::error::AuthError;
use crate::sql::{self, exec, fetch_opt};

/// What `secrets invalidate` found broken (ADR 0047 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossCase {
    /// The file loads, but its OPAQUE setup does not match the database (`SetupMismatch`) or
    /// none of its setups is recorded there (`NoRecordedSetup`). Everything else carries
    /// forward.
    SetupOnly,
    /// The file is absent or unparsable: nothing carries forward.
    Whole,
}

impl LossCase {
    /// The case's name in the `secrets_invalidated` log line and the command's report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SetupOnly => "setup_only",
            Self::Whole => "whole_loss",
        }
    }

    /// The marker's `loss_case` value.
    const fn code(self) -> i64 {
        match self {
            Self::SetupOnly => 1,
            Self::Whole => 2,
        }
    }

    /// The case a marker's `loss_case` names.
    fn from_code(code: i64) -> Result<Self, AuthError> {
        match code {
            1 => Ok(Self::SetupOnly),
            2 => Ok(Self::Whole),
            _ => Err(AuthError::Internal(
                "unknown loss_case in auth_invalidate_pending",
            )),
        }
    }
}

/// The crash marker of an interrupted `secrets invalidate` (ADR 0047 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingInvalidation {
    /// The case the interrupted run diagnosed.
    pub case: LossCase,
    /// The `setup_id` it minted. Its key lived only in that process, so it is burned unless
    /// the run's secrets file was written.
    pub setup_id: u32,
    /// When it diagnosed the case, ms since the Unix epoch.
    pub diagnosed_at_ms: u64,
}

/// What a case would cost, read before `--confirm` (ADR 0047 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidationCost {
    /// OPAQUE records, one per account: every one re-registers.
    pub accounts: u64,
    /// TOTP enrollments deleted: every one on a whole loss, none on a setup-only loss.
    pub totp_enrolments: u64,
}

/// What step 4 did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalidated {
    /// The case carried out.
    pub case: LossCase,
    /// The new setup's `setup_id`.
    pub setup_id: u32,
    /// How many setup rows this run retired.
    pub setups_retired: u64,
    /// How many TOTP rows this run deleted (0 on a setup-only loss).
    pub totp_rows_deleted: u64,
    /// How many pending login states this run deleted.
    pub login_states_deleted: u64,
    /// How many OPAQUE records, one per account, now name a retired setup and re-register.
    pub accounts: u64,
}

/// Reads the crash marker, if a run left one (ADR 0047 step 2). The database must be at this
/// release's schema.
///
/// # Errors
/// Storage errors; [`AuthError::Internal`] for a marker with a value out of range.
pub async fn pending_invalidation(db: &Database) -> Result<Option<PendingInvalidation>, AuthError> {
    let mut tx = db.begin_read().await?;
    let row: Option<(i64, i64, i64)> =
        fetch_opt!(tx.conn(), (i64, i64, i64), sql::INVALIDATE_PENDING_GET)?;
    tx.finish().await?;
    row.map(|(case, setup_id, at)| {
        Ok(PendingInvalidation {
            case: LossCase::from_code(case)?,
            setup_id: sql::sql_u32(setup_id, "setup_id")?,
            diagnosed_at_ms: sql::sql_u64(at, "diagnosed_at_ms")?,
        })
    })
    .transpose()
}

/// What carrying out `case` would cost now, read only (ADR 0047 step 3).
///
/// # Errors
/// Storage errors.
pub async fn invalidation_cost(
    db: &Database,
    case: LossCase,
) -> Result<InvalidationCost, AuthError> {
    let mut tx = db.begin_read().await?;
    let accounts: Option<(i64,)> = fetch_opt!(tx.conn(), (i64,), sql::CREDENTIALS_COUNT)?;
    let totp: Option<(i64,)> = fetch_opt!(tx.conn(), (i64,), sql::TOTP_COUNT)?;
    tx.finish().await?;
    let count = |row: Option<(i64,)>| sql::sql_u64(row.map_or(0, |(n,)| n), "row count");
    Ok(InvalidationCost {
        accounts: count(accounts)?,
        totp_enrolments: match case {
            LossCase::SetupOnly => 0,
            LossCase::Whole => count(totp)?,
        },
    })
}

/// Step 4 of `secrets invalidate` in one transaction (module docs): retires every setup,
/// deletes the login states (and, on a whole loss, every TOTP row), records the new setup
/// whose AKE public-key hash is `setup_hash` under the next unused `setup_id`, and writes the
/// crash marker with `diagnosed_at_ms` (the original diagnosis time when resuming).
/// `before_commit` sees the outcome before the commit, so a log line it writes records the
/// intent even if the commit then fails (ADR 0047 step 7).
///
/// The caller must have shut every server process out, and the database must be at this
/// release's schema.
///
/// # Errors
/// Storage errors, or [`AuthError::Internal`] when `setup_id` would pass `u32::MAX`; nothing
/// is written then.
pub async fn invalidate_in_database(
    db: &Database,
    case: LossCase,
    setup_hash: &[u8; 32],
    now_ms: u64,
    diagnosed_at_ms: u64,
    before_commit: impl FnOnce(&Invalidated),
) -> Result<Invalidated, AuthError> {
    let now = sql::u64_sql(now_ms, "now_ms")?;
    let diagnosed = sql::u64_sql(diagnosed_at_ms, "diagnosed_at_ms")?;
    let mut tx = db.begin_write().await?;
    let highest: Option<(Option<i64>,)> = fetch_opt!(tx.conn(), (Option<i64>,), sql::SETUP_MAX_ID)?;
    let highest = match highest.and_then(|(max,)| max) {
        Some(max) => sql::sql_u32(max, "setup_id")?,
        None => 0,
    };
    let setup_id = highest
        .checked_add(1)
        .ok_or(AuthError::Internal("setup_id overflow"))?;
    let setups_retired = exec!(tx.conn(), sql::SETUPS_RETIRE_ALL, now)?;
    let login_states_deleted = exec!(tx.conn(), sql::LOGIN_STATES_DELETE_ALL)?;
    let totp_rows_deleted = match case {
        LossCase::SetupOnly => 0,
        LossCase::Whole => exec!(tx.conn(), sql::TOTP_DELETE_EVERY)?,
    };
    let accounts: Option<(i64,)> = fetch_opt!(tx.conn(), (i64,), sql::CREDENTIALS_COUNT)?;
    let accounts = sql::sql_u64(accounts.map_or(0, |(n,)| n), "row count")?;
    exec!(
        tx.conn(),
        sql::SETUP_INSERT,
        i64::from(setup_id),
        &setup_hash[..],
        now
    )?;
    exec!(
        tx.conn(),
        sql::INVALIDATE_PENDING_PUT,
        case.code(),
        i64::from(setup_id),
        diagnosed
    )?;
    let outcome = Invalidated {
        case,
        setup_id,
        setups_retired,
        totp_rows_deleted,
        login_states_deleted,
        accounts,
    };
    before_commit(&outcome);
    tx.commit().await?;
    Ok(outcome)
}

/// Clears the crash marker once the new secrets file is written (ADR 0047 step 6).
///
/// # Errors
/// Storage errors; the marker then stays, and the next run resumes.
pub async fn clear_pending_invalidation(db: &Database) -> Result<(), AuthError> {
    let mut tx = db.begin_write().await?;
    exec!(tx.conn(), sql::INVALIDATE_PENDING_CLEAR)?;
    tx.commit().await?;
    Ok(())
}
