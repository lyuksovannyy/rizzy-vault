//! The `worker` role (ADR 0010 §1 row `worker`, §5; ADR 0011 point 9; ADR 0021 §3, §7).
//!
//! One run ([`run_once`]) does, in order, each step isolated from the others' failures:
//! 1. **Expired auth state** (ADR 0010 §5: "`worker` deletes expired rows"): sessions, sealed
//!    login states, challenges, rate-limit buckets
//!    (`rizzy_domain_auth::AuthService::purge_expired`).
//! 2. **TOTP secrets under an old data key** (CRYPTO.md §5.11 "Rotation": "`worker` re-seals
//!    TOTP rows under the account lock"): after `rizzy-vault secrets rotate --data-key`, every
//!    TOTP row still sealed under another key than the current one is re-sealed under it, in
//!    pages of [`TOTP_RESEAL_BATCH`] accounts, each account its own transaction under the
//!    account lock, until none is left or [`MAX_TOTP_RESEAL_BATCHES`] pages ran
//!    (`rizzy_domain_auth::AuthService::reseal_totp_secrets`). A run with nothing to do costs
//!    one read. An account whose row does not open is counted and skipped; it keeps its old
//!    key in the secrets file. The worker never writes the secrets file (ADR 0010 §4): the old
//!    key is dropped by a later `secrets rotate --data-key`, once no row names it
//!    ([`crate::admin`]).
//! 3. **Stale reconciliation epochs** (ADR 0012 §7: "after an admin-set limit (default 30
//!    days)").
//! 4. **Compaction** (ADR 0021 §3, §7): the durable queue, in batches of [`COMPACTION_BATCH`]
//!    items, until it is empty or [`MAX_COMPACTION_BATCHES`] batches ran. Each item is its own
//!    transaction under the account lock; a failing item is logged by vault and item id and
//!    moved to the back of the queue (`rizzy_domain_vault::VaultDomain::run_compaction`).
//! 5. **`SQLite` space** (ADR 0011 "`SQLite` settings", `auto_vacuum`): `PRAGMA
//!    incremental_vacuum` when step 1 or 4 deleted anything.
//! 6. **The pre-migration copy** (ADR 0011 point 9: "`worker` deletes the copy 24 h after the
//!    migrated server started and passed its startup self-check"): deleted once 24 h have
//!    passed since this process passed its startup self-check ([`PreMigrationCopy`]). The
//!    copy's modification time is not used: it records the migration, which may precede that
//!    self-check by any time. The time is kept in memory only, so every restart starts the 24 h
//!    again; a server restarted more often than daily keeps the copy (the conservative side:
//!    the rollback point stays) until one run lasts 24 h, or the operator deletes it.
//!
//! **When it runs.** Once at startup, then every configured interval, and early when the vault
//! domain publishes `CompactionQueued` on the in-process bus (the durable queue, not the event,
//! is the record of truth: a missed or lagged event only delays the item to the next run).
//! **The worker never purges trash** (ADR 0010 §1): clients purge it with signed ops.
//!
//! **One active worker per database** (ADR 0010 §2). Before its first run the worker takes the
//! leader lock ([`rizzy_storage::WorkerLeader`], from `Database::try_lead_worker`), and it runs
//! jobs only while it holds it:
//! - **`PostgreSQL`:** a session-level advisory lock on a dedicated connection outside the pool.
//!   A worker that does not get it is a hot standby: it runs no job and tries again every
//!   [`LEADER_RETRY`]. The leader checks the lock before every step and every compaction batch
//!   ("before each job batch"); a check that fails, errs or takes longer than
//!   [`LEADER_TIMEOUT`] ends the run at once, drops the lock's connection, and the worker goes
//!   back to trying to take the lock ("stops running jobs as soon as that connection drops").
//!   Taking the lock is bounded by [`LEADER_TIMEOUT`] too.
//! - **`SQLite`:** the writer lock the database holds already makes this process the only
//!   writer, so the leader is always granted and every check passes: the behaviour is the one
//!   the worker had before the leader lock existed.
//!
//! A step already running when the lock is lost finishes (the window `rizzy_storage::leader_lock`
//! describes): the purges are idempotent deletes of expired rows, and each re-sealed account
//! and each compaction item is its own transaction under the per-account lock, so a standby
//! that takes over meanwhile serialises with it per account rather than racing it (a row the
//! other worker already re-sealed is left alone: the update names the key it replaces).
//!
//! Log lines carry counts and value-free error texts only.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rizzy_bus::{RecvError, Subscriber};
use rizzy_storage::{Database, Engine, WorkerLeader, remove_pre_migration_copy};
use tokio::sync::watch;

use crate::http::api::Api;
use crate::log::{self, Field};
use crate::sys::{now_ms, os_rng};

/// Accounts whose TOTP rows are re-sealed per page (module docs, step 2).
pub const TOTP_RESEAL_BATCH: u32 = 256;

/// Re-seal pages per run; the rest waits for the next run, so one run stays bounded.
pub const MAX_TOTP_RESEAL_BATCHES: usize = 64;

/// Items compacted per batch.
pub const COMPACTION_BATCH: usize = 256;

/// Batches per run; the rest waits for the next run, so one run stays bounded.
pub const MAX_COMPACTION_BATCHES: usize = 64;

/// How long the pre-migration copy is kept (ADR 0011 point 9, owner decision 2: 24 h).
pub const PRE_MIGRATION_COPY_TTL: Duration = Duration::from_secs(24 * 3600);

/// How long a worker that does not hold the leader lock (a hot standby, or a leader that lost
/// it) waits before it tries to take the lock again. This crate's choice, reported to the owner.
pub const LEADER_RETRY: Duration = Duration::from_secs(15);

/// The longest the worker waits to take the leader lock (connect and lock) or to check it. A
/// check that takes longer counts as a lost lock. This crate's choice, reported to the owner.
pub const LEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// The shortest time between two runs woken by events, so a burst of uploads costs one run.
const EVENT_DEBOUNCE: Duration = Duration::from_secs(1);

/// What one run did, for the log and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    /// Expired auth rows deleted.
    pub auth_rows_purged: u64,
    /// TOTP rows re-sealed under the current data key.
    pub totp_rows_resealed: u64,
    /// Accounts whose TOTP rows could not be re-sealed (they keep their old data key).
    pub totp_reseal_failures: u64,
    /// Reconciliation epochs ended.
    pub epochs_ended: usize,
    /// Items compacted.
    pub items_compacted: usize,
    /// Op bodies deleted by compaction.
    pub bodies_deleted: usize,
    /// Snapshots dropped by compaction.
    pub snapshots_dropped: usize,
    /// Items whose compaction failed.
    pub compaction_failures: usize,
    /// Whether the pre-migration copy was deleted.
    pub copy_removed: bool,
    /// Whether the run stopped because the leader lock was lost (module docs); the steps after
    /// the failed check did not run.
    pub leadership_lost: bool,
}

/// Runs the worker until `stop` turns true (module docs): takes the leader lock, runs while it
/// holds it, and waits as a standby while it does not.
pub async fn run(
    api: Arc<Api>,
    db: Database,
    events: Subscriber,
    mut stop: watch::Receiver<bool>,
    interval: Duration,
    pre_migration_copy: Option<PreMigrationCopy>,
) {
    let mut events = Some(events);
    let mut leader: Option<WorkerLeader> = None;
    let mut standby_logged = false;
    loop {
        if leader.is_none() {
            leader = take_leadership(&db, &mut standby_logged).await;
        }
        if let Some(held) = leader.as_mut() {
            let report = run_once(&api, &db, pre_migration_copy.as_ref(), held).await;
            log::info(
                "worker_run",
                &[
                    Field::U64("auth_rows_purged", report.auth_rows_purged),
                    Field::U64("totp_rows_resealed", report.totp_rows_resealed),
                    Field::U64("totp_reseal_failures", report.totp_reseal_failures),
                    Field::U64("epochs_ended", count(report.epochs_ended)),
                    Field::U64("items_compacted", count(report.items_compacted)),
                    Field::U64("bodies_deleted", count(report.bodies_deleted)),
                    Field::U64("snapshots_dropped", count(report.snapshots_dropped)),
                    Field::U64("compaction_failures", count(report.compaction_failures)),
                ],
            );
            if report.leadership_lost {
                // Dropping the leader drops its connection: whatever is left of the session
                // and its lock is released by the server.
                leader = None;
            }
        }
        if leader.is_none() {
            tokio::select! {
                _ = stop.changed() => break,
                () = tokio::time::sleep(LEADER_RETRY) => {}
            }
            if *stop.borrow() {
                break;
            }
            continue;
        }
        let woken = async {
            match events.as_mut() {
                Some(subscriber) => match subscriber.recv().await {
                    Ok(_) | Err(RecvError::Lagged { .. }) => true,
                    Err(RecvError::Closed) => false,
                },
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = stop.changed() => break,
            () = tokio::time::sleep(interval) => {}
            woke = woken => {
                if !woke {
                    events = None;
                }
                tokio::select! {
                    _ = stop.changed() => break,
                    () = tokio::time::sleep(EVENT_DEBOUNCE) => {}
                }
            }
        }
        if *stop.borrow() {
            break;
        }
    }
    if let Some(held) = leader {
        release_leadership(held).await;
    }
}

/// Tries once to take the leader lock, within [`LEADER_TIMEOUT`]. Logs the outcome: taking it,
/// an error, and the first refusal after taking it or starting (`standby_logged` keeps a standby
/// from logging every retry).
async fn take_leadership(db: &Database, standby_logged: &mut bool) -> Option<WorkerLeader> {
    match tokio::time::timeout(LEADER_TIMEOUT, db.try_lead_worker()).await {
        Ok(Ok(Some(leader))) => {
            *standby_logged = false;
            log::info("worker_leader_acquired", &[]);
            Some(leader)
        }
        Ok(Ok(None)) => {
            if !*standby_logged {
                *standby_logged = true;
                log::info("worker_standby", &[]);
            }
            None
        }
        Ok(Err(e)) => {
            log::error("worker_leader_failed", &[Field::Error("error", &e)]);
            None
        }
        Err(_elapsed) => {
            log::error(
                "worker_leader_failed",
                &[Field::Str("error", "taking the leader lock timed out")],
            );
            None
        }
    }
}

/// Gives the leader lock up at shutdown, within [`LEADER_TIMEOUT`]; past it, or on an error,
/// the connection is dropped, which releases the lock too.
async fn release_leadership(leader: WorkerLeader) {
    match tokio::time::timeout(LEADER_TIMEOUT, leader.release()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::error("worker_leader_release_failed", &[Field::Error("error", &e)]),
        Err(_elapsed) => log::error(
            "worker_leader_release_failed",
            &[Field::Str("error", "releasing the leader lock timed out")],
        ),
    }
}

/// Whether `leader` still holds the leader lock, asked within [`LEADER_TIMEOUT`] (module docs).
/// A lost lock is logged; the caller stops the run.
async fn still_leader(leader: &mut WorkerLeader) -> bool {
    match tokio::time::timeout(LEADER_TIMEOUT, leader.is_held()).await {
        Ok(Ok(true)) => true,
        Ok(Ok(false)) => {
            log::error(
                "worker_leader_lost",
                &[Field::Str("error", "the leader lock is no longer held")],
            );
            false
        }
        Ok(Err(e)) => {
            log::error("worker_leader_lost", &[Field::Error("error", &e)]);
            false
        }
        Err(_elapsed) => {
            log::error(
                "worker_leader_lost",
                &[Field::Str("error", "checking the leader lock timed out")],
            );
            false
        }
    }
}

/// A count as a log integer.
fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Step 2 of a run (module docs): re-seals, under the current server data key, the TOTP secrets
/// still sealed under another one, page by page, and adds what it did to `report`. It checks
/// the leader lock before every page; `false` means the lock was lost and the run must stop.
/// An error ends the step, is logged and leaves the rest to the next run.
async fn reseal_totp_secrets(api: &Api, leader: &mut WorkerLeader, report: &mut RunReport) -> bool {
    let mut after = None;
    for _ in 0..MAX_TOTP_RESEAL_BATCHES {
        if !still_leader(leader).await {
            return false;
        }
        // The OS CSPRNG draws the new envelopes' nonces (ADR 0009 "RNG rules").
        let mut rng = os_rng();
        match api
            .auth
            .reseal_totp_secrets(&mut rng, after, TOTP_RESEAL_BATCH)
            .await
        {
            Ok(page) => {
                report.totp_rows_resealed = report.totp_rows_resealed.saturating_add(page.rows);
                report.totp_reseal_failures =
                    report.totp_reseal_failures.saturating_add(page.failures);
                after = page.next;
                if after.is_none() {
                    break;
                }
            }
            Err(e) => {
                log::error("worker_totp_reseal_failed", &[Field::Error("error", &e)]);
                break;
            }
        }
    }
    if report.totp_reseal_failures > 0 {
        // Counts only: which accounts is the database's to say, not the log's.
        log::error(
            "worker_totp_reseal_skipped",
            &[Field::U64("accounts", report.totp_reseal_failures)],
        );
    }
    true
}

/// One worker run (module docs), as the holder of `leader`. Never fails: each step's error is
/// logged and the next step runs. Before every step and every compaction batch it checks that
/// `leader` still holds the leader lock; when not, it returns at once with
/// [`RunReport::leadership_lost`] set, and the caller must drop `leader`.
pub async fn run_once(
    api: &Api,
    db: &Database,
    pre_migration_copy: Option<&PreMigrationCopy>,
    leader: &mut WorkerLeader,
) -> RunReport {
    let mut report = RunReport::default();
    let lost = RunReport {
        leadership_lost: true,
        ..RunReport::default()
    };
    let now = now_ms();
    if !still_leader(leader).await {
        return lost;
    }
    match api.auth.purge_expired(now).await {
        Ok(purged) => {
            report.auth_rows_purged = purged
                .sessions
                .saturating_add(purged.login_states)
                .saturating_add(purged.challenges)
                .saturating_add(purged.rate_limits);
        }
        Err(e) => log::error("worker_purge_failed", &[Field::Error("error", &e)]),
    }
    if !reseal_totp_secrets(api, leader, &mut report).await || !still_leader(leader).await {
        return RunReport {
            leadership_lost: true,
            ..report
        };
    }
    match api.auth.end_stale_reconciliation_epochs(now).await {
        Ok(ended) => report.epochs_ended = ended,
        Err(e) => log::error("worker_epochs_failed", &[Field::Error("error", &e)]),
    }
    for _ in 0..MAX_COMPACTION_BATCHES {
        if !still_leader(leader).await {
            return RunReport {
                leadership_lost: true,
                ..report
            };
        }
        match api.vault.run_compaction(COMPACTION_BATCH).await {
            Ok(run) => {
                report.items_compacted = report.items_compacted.saturating_add(run.processed);
                report.bodies_deleted = report
                    .bodies_deleted
                    .saturating_add(run.report.bodies_deleted);
                report.snapshots_dropped = report
                    .snapshots_dropped
                    .saturating_add(run.report.snapshots_dropped);
                report.compaction_failures = report
                    .compaction_failures
                    .saturating_add(run.failures.len());
                for failure in &run.failures {
                    log::error("compaction_item_failed", &[Field::Error("detail", failure)]);
                }
                if run.processed.saturating_add(run.failures.len()) < COMPACTION_BATCH
                    || run.processed == 0
                {
                    break;
                }
            }
            Err(e) => {
                log::error("worker_compaction_failed", &[Field::Error("error", &e)]);
                break;
            }
        }
    }
    let deleted =
        report.auth_rows_purged > 0 || report.bodies_deleted > 0 || report.snapshots_dropped > 0;
    if deleted && db.engine() == Engine::Sqlite {
        // SQLite: the leader is the writer lock, which cannot be lost while `db` lives; no
        // check is needed before this step.
        if let Err(e) = db.incremental_vacuum().await {
            log::error("worker_vacuum_failed", &[Field::Error("error", &e)]);
        }
    }
    if let Some(copy) = pre_migration_copy {
        if !still_leader(leader).await {
            return RunReport {
                leadership_lost: true,
                ..report
            };
        }
        report.copy_removed = remove_old_copy(copy);
    }
    report
}

/// The pre-migration copy (ADR 0011 point 9) and when this server passed its startup
/// self-check, which starts the copy's 24 h.
#[derive(Clone, Debug)]
pub struct PreMigrationCopy {
    /// The copy's path.
    pub path: PathBuf,
    /// When this process passed its startup self-check ([`crate::server`] startup step 5).
    pub self_check_passed: Instant,
}

/// Deletes the pre-migration copy once [`PRE_MIGRATION_COPY_TTL`] has passed since this server
/// passed its startup self-check (module docs). The copy's own modification time plays no part:
/// it records the migration, which can precede the first server that passed its self-check by
/// any time (`rizzy-vault migrate` long before a start, or a start whose self-check failed).
fn remove_old_copy(copy: &PreMigrationCopy) -> bool {
    if copy.self_check_passed.elapsed() < PRE_MIGRATION_COPY_TTL || !copy.path.exists() {
        return false;
    }
    match remove_pre_migration_copy(&copy.path) {
        Ok(()) => {
            log::info("pre_migration_copy_removed", &[]);
            true
        }
        Err(e) => {
            log::error(
                "pre_migration_copy_remove_failed",
                &[Field::Error("error", &e)],
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    //! The pre-migration copy's clock.

    use super::*;

    #[test]
    fn copy_clock_starts_at_the_self_check_not_the_file() {
        let dir =
            std::env::temp_dir().join(format!("rizzy-server-worker-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.pre-migration");
        std::fs::write(&path, b"copy").unwrap();
        // A copy whose file is old (written by a migration long ago) is kept for 24 h after a
        // self-check that has only just passed.
        let old = std::time::SystemTime::now() - (PRE_MIGRATION_COPY_TTL * 2);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let fresh = PreMigrationCopy {
            path: path.clone(),
            self_check_passed: Instant::now(),
        };
        assert!(!remove_old_copy(&fresh));
        assert!(path.exists());
        // 24 h after the self-check it goes (when the monotonic clock reaches that far back).
        if let Some(then) =
            Instant::now().checked_sub(PRE_MIGRATION_COPY_TTL + Duration::from_secs(1))
        {
            let due = PreMigrationCopy {
                path: path.clone(),
                self_check_passed: then,
            };
            assert!(remove_old_copy(&due));
            assert!(!path.exists());
            assert!(!remove_old_copy(&due), "a missing copy is nothing to do");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
