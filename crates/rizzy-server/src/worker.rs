//! The `worker` role (ADR 0010 §1 row `worker`, §5; ADR 0011 point 9; ADR 0021 §3, §7).
//!
//! One run ([`run_once`]) does, in order, each step isolated from the others' failures:
//! 1. **Expired auth state** (ADR 0010 §5: "`worker` deletes expired rows"): sessions, sealed
//!    login states, challenges, rate-limit buckets
//!    (`rizzy_domain_auth::AuthService::purge_expired`).
//! 2. **Stale reconciliation epochs** (ADR 0012 §7: "after an admin-set limit (default 30
//!    days)").
//! 3. **Compaction** (ADR 0021 §3, §7): the durable queue, in batches of [`COMPACTION_BATCH`]
//!    items, until it is empty or [`MAX_COMPACTION_BATCHES`] batches ran. Each item is its own
//!    transaction under the account lock; a failing item is logged by vault and item id and
//!    moved to the back of the queue (`rizzy_domain_vault::VaultDomain::run_compaction`).
//! 4. **`SQLite` space** (ADR 0011 "`SQLite` settings", `auto_vacuum`): `PRAGMA
//!    incremental_vacuum` when step 1 or 3 deleted anything.
//! 5. **The pre-migration copy** (ADR 0011 point 9: "`worker` deletes the copy 24 h after the
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
//! **One active worker per database** (ADR 0010 §2): with `SQLite` the writer lock already makes
//! this process the only writer; with `PostgreSQL` the worker does not start ([`crate::server`]).
//!
//! Log lines carry counts and value-free error texts only.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rizzy_bus::{RecvError, Subscriber};
use rizzy_storage::{Database, Engine, remove_pre_migration_copy};
use tokio::sync::watch;

use crate::http::api::Api;
use crate::log::{self, Field};
use crate::sys::now_ms;

/// Items compacted per batch.
pub const COMPACTION_BATCH: usize = 256;

/// Batches per run; the rest waits for the next run, so one run stays bounded.
pub const MAX_COMPACTION_BATCHES: usize = 64;

/// How long the pre-migration copy is kept (ADR 0011 point 9, owner decision 2: 24 h).
pub const PRE_MIGRATION_COPY_TTL: Duration = Duration::from_secs(24 * 3600);

/// The shortest time between two runs woken by events, so a burst of uploads costs one run.
const EVENT_DEBOUNCE: Duration = Duration::from_secs(1);

/// What one run did, for the log and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    /// Expired auth rows deleted.
    pub auth_rows_purged: u64,
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
}

/// Runs the worker until `stop` turns true (module docs).
pub async fn run(
    api: Arc<Api>,
    db: Database,
    events: Subscriber,
    mut stop: watch::Receiver<bool>,
    interval: Duration,
    pre_migration_copy: Option<PreMigrationCopy>,
) {
    let mut events = Some(events);
    loop {
        let report = run_once(&api, &db, pre_migration_copy.as_ref()).await;
        log::info(
            "worker_run",
            &[
                Field::U64("auth_rows_purged", report.auth_rows_purged),
                Field::U64("epochs_ended", count(report.epochs_ended)),
                Field::U64("items_compacted", count(report.items_compacted)),
                Field::U64("bodies_deleted", count(report.bodies_deleted)),
                Field::U64("snapshots_dropped", count(report.snapshots_dropped)),
                Field::U64("compaction_failures", count(report.compaction_failures)),
            ],
        );
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
            _ = stop.changed() => return,
            () = tokio::time::sleep(interval) => {}
            woke = woken => {
                if !woke {
                    events = None;
                }
                tokio::select! {
                    _ = stop.changed() => return,
                    () = tokio::time::sleep(EVENT_DEBOUNCE) => {}
                }
            }
        }
        if *stop.borrow() {
            return;
        }
    }
}

/// A count as a log integer.
fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// One worker run (module docs). Never fails: each step's error is logged and the next step
/// runs.
pub async fn run_once(
    api: &Api,
    db: &Database,
    pre_migration_copy: Option<&PreMigrationCopy>,
) -> RunReport {
    let mut report = RunReport::default();
    let now = now_ms();
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
    match api.auth.end_stale_reconciliation_epochs(now).await {
        Ok(ended) => report.epochs_ended = ended,
        Err(e) => log::error("worker_epochs_failed", &[Field::Error("error", &e)]),
    }
    for _ in 0..MAX_COMPACTION_BATCHES {
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
    if deleted
        && db.engine() == Engine::Sqlite
        && let Err(e) = db.incremental_vacuum().await
    {
        log::error("worker_vacuum_failed", &[Field::Error("error", &e)]);
    }
    if let Some(copy) = pre_migration_copy {
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
