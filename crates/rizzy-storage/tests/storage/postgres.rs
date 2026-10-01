//! `rizzy-storage` on a real PostgreSQL database.
//!
//! `#[ignore]`d by default: run with `RIZZY_TEST_POSTGRES_URL` set to an **empty** database the
//! tests may fill, for example
//! `RIZZY_TEST_POSTGRES_URL=postgres://rizzy:rizzy@localhost/rizzy_test cargo test -p
//! rizzy-storage -- --ignored postgres`. The test migrates it, so run it on a fresh database
//! each time. ADR 0011 point 3 puts this suite into a PostgreSQL CI job from the first M1
//! migration; that job is not added here (`.github/workflows/` is out of this change's scope).

use std::time::Duration;

use rizzy_storage::instance_lock::INSTANCE_LOCK;
use rizzy_storage::lock::WORKER_LEADER_LOCK;
use rizzy_storage::meta::{reconciliation_epoch, restore_generation};
use rizzy_storage::{
    Conn, Database, Engine, Error, InstanceLock, InstanceLockMode, PostgresOptions,
    RestoreGeneration, StartupMigration, WorkerLeader, lock_account, on_engine, schema_version,
};

use crate::common::{ACCOUNT_1, block_on, fixture, fixture_after_restore, id};

/// Concurrent writers in the serialisation test.
const TASKS: i64 = 16;

/// The database URL, from the environment.
#[expect(
    clippy::expect_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
fn url() -> String {
    std::env::var("RIZZY_TEST_POSTGRES_URL")
        .expect("set RIZZY_TEST_POSTGRES_URL to an empty PostgreSQL database")
}

#[test]
fn remote_postgres_requires_verify_full() {
    for url in [
        "postgres://u:p@db.example.com/x",
        "postgres://u:p@db.example.com/x?sslmode=require",
        "postgres://u:p@10.0.0.5/x?sslmode=verify-ca",
    ] {
        assert!(
            matches!(
                PostgresOptions::from_url(url),
                Err(Error::InsecurePostgresTls)
            ),
            "{url}"
        );
    }
    for url in [
        "postgres://u:p@db.example.com/x?sslmode=verify-full",
        "postgres://u:p@localhost/x",
        "postgres://u:p@127.0.0.1/x?sslmode=disable",
    ] {
        assert!(PostgresOptions::from_url(url).is_ok(), "{url}");
    }
}

#[test]
#[ignore = "needs RIZZY_TEST_POSTGRES_URL: an empty PostgreSQL database"]
fn postgres_migrate_restore_dump_and_lock() {
    block_on(async {
        let db = Database::open_postgres(&PostgresOptions::from_url(&url()).unwrap())
            .await
            .unwrap();

        // Explicit migration only (ADR 0011 point 9).
        let unused = std::path::Path::new("/nonexistent/unused");
        assert!(matches!(
            db.migrate_at_startup(unused).await,
            Err(Error::PendingMigrations { .. })
        ));
        db.migrate().await.unwrap();
        assert_eq!(
            db.migrate_at_startup(unused).await.unwrap(),
            StartupMigration::UpToDate
        );
        assert!(matches!(
            db.vacuum_into(unused).await,
            Err(Error::WrongEngine { .. })
        ));

        // Restore and dump: the shared query files and the typed NULL binds on PostgreSQL.
        let g = RestoreGeneration([0x21; 16]);
        db.restore(&fixture(), g, 7).await.unwrap();
        let dump = db.dump().await.unwrap();
        assert_eq!(dump, fixture_after_restore());
        assert_eq!(dump.schema_version, schema_version());
        let mut r = db.begin_read().await.unwrap();
        assert_eq!(restore_generation(r.conn()).await.unwrap(), Some(g));
        assert!(
            reconciliation_epoch(r.conn(), &id(ACCOUNT_1))
                .await
                .unwrap()
                .is_some()
        );
        r.finish().await.unwrap();

        // The account lock serialises read-then-write under READ COMMITTED: without it, these
        // increments would lose updates.
        let account = id(ACCOUNT_1);
        let before: i64 = {
            let mut r = db.begin_read().await.unwrap();
            let v = on_engine!(r.conn(), |c| sqlx::query_scalar(
                "SELECT state_seq FROM auth_account_states WHERE account_id = $1"
            )
            .bind(&account[..])
            .fetch_one(&mut *c)
            .await
            .unwrap());
            r.finish().await.unwrap();
            v
        };
        let mut handles = Vec::new();
        for _ in 0..TASKS {
            let db = db.clone();
            handles.push(tokio::spawn(async move {
                let mut tx = db.begin_write().await.unwrap();
                lock_account(&mut tx, &account).await.unwrap();
                let seq: i64 = on_engine!(tx.conn(), |c| sqlx::query_scalar(
                    "SELECT state_seq FROM auth_account_states WHERE account_id = $1"
                )
                .bind(&account[..])
                .fetch_one(&mut *c)
                .await
                .unwrap());
                tokio::time::sleep(Duration::from_millis(5)).await;
                on_engine!(tx.conn(), |c| sqlx::query(
                    "UPDATE auth_account_states SET state_seq = $1 WHERE account_id = $2"
                )
                .bind(seq + 1)
                .bind(&account[..])
                .execute(&mut *c)
                .await
                .unwrap()
                .rows_affected());
                tx.commit().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let mut r = db.begin_read().await.unwrap();
        let after: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(
            "SELECT state_seq FROM auth_account_states WHERE account_id = $1"
        )
        .bind(&account[..])
        .fetch_one(&mut *c)
        .await
        .unwrap());
        r.finish().await.unwrap();
        assert_eq!(after, before + TASKS);

        debug_hides_row_values(&db).await;
        db.close().await;
    });
}

/// A CHECK violation's `detail` (`Failing row contains (...)`) and a unique violation's
/// (`Key (login_name)=(...) already exists`) hold row values; `Error`'s `Debug` must show
/// neither (INV-48). Needs `fixture()` restored, for the duplicate login "alice".
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn debug_hides_row_values(db: &Database) {
    let violations: [(&[u8], &str); 2] =
        [(&[0xab; 15], "check-login-7f3a"), (&[0xcd; 16], "alice")];
    for (bad_id, login) in violations {
        let mut w = db.begin_write().await.unwrap();
        let err: Error = on_engine!(w.conn(), |c| sqlx::query(
            "INSERT INTO auth_accounts (id, login_name, created_at_ms) VALUES ($1, $2, 0)"
        )
        .bind(bad_id)
        .bind(login)
        .execute(&mut *c)
        .await
        .map(|_| ())
        .err()
        .map(Error::from))
        .unwrap();
        w.rollback().await.unwrap();
        let debug = format!("{err:?}");
        assert!(!debug.contains("abab") && !debug.contains(login), "{debug}");
    }
}

/// Opens a second, independent handle on the test database, as another server process would.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn open_handle() -> Database {
    Database::open_postgres(&PostgresOptions::from_url(&url()).unwrap())
        .await
        .unwrap()
}

/// Tries to lead from `db` until it does, for up to 10 s: the server releases a session-level
/// lock when it notices the session has ended, which can lag the client's close.
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn lead_eventually(db: &Database) -> WorkerLeader {
    for _ in 0..100 {
        if let Some(leader) = db.try_lead_worker().await.unwrap() {
            return leader;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the leader lock was not released within 10 s");
}

/// One active worker per database (ADR 0010 §2): of two workers (two independent pools, as two
/// processes have), exactly one takes the leader lock on its dedicated connection; dropping that
/// connection, or the server terminating its session, hands the lock to the standby; the lost
/// leader's check fails. Needs no migrated schema.
#[test]
#[ignore = "needs RIZZY_TEST_POSTGRES_URL: an empty PostgreSQL database"]
fn postgres_worker_leader_lock() {
    block_on(async {
        let one = open_handle().await;
        let two = open_handle().await;

        // Only one of two workers leads.
        let mut first = one.try_lead_worker().await.unwrap().unwrap();
        assert_eq!(first.engine(), Engine::Postgres);
        assert!(first.is_held().await.unwrap());
        assert!(two.try_lead_worker().await.unwrap().is_none());
        assert!(
            one.try_lead_worker().await.unwrap().is_none(),
            "a second leader connection of the same process is refused too"
        );
        // The lock is on the dedicated connection, not on a pooled one: closing the leader's
        // own pool, which drops every pooled connection of `one`, leaves it held. A lock taken
        // on a pooled connection would be released here (ADR 0010 §2).
        one.close().await;
        assert!(first.is_held().await.unwrap());
        assert!(two.try_lead_worker().await.unwrap().is_none());
        let one = open_handle().await;

        // Dropping the leader drops its connection, which releases the lock to the standby.
        drop(first);
        let mut second = lead_eventually(&two).await;
        assert!(second.is_held().await.unwrap());
        assert!(one.try_lead_worker().await.unwrap().is_none());

        // The server ends the leader's session: its next check fails, and the lock is free.
        let mut w = one.begin_write().await.unwrap();
        let Conn::Postgres(c) = w.conn() else {
            panic!("a PostgreSQL handle");
        };
        let terminated: Vec<bool> = sqlx::query_scalar(
            "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' \
                 AND granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                 AND classid::int8 = $1 AND objid::int8 = $2 AND objsubid = 2",
        )
        .bind(i64::from(WORKER_LEADER_LOCK.0))
        .bind(i64::from(WORKER_LEADER_LOCK.1))
        .fetch_all(&mut *c)
        .await
        .unwrap();
        w.rollback().await.unwrap();
        assert_eq!(terminated, vec![true]);
        // pg_terminate_backend only signals the backend; wait, for up to 10 s, for it to exit.
        let mut lost = false;
        for _ in 0..100 {
            if !matches!(second.is_held().await, Ok(true)) {
                lost = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            lost,
            "the terminated leader still reports the lock after 10 s"
        );
        drop(second);

        // A graceful release hands it over too.
        let third = lead_eventually(&one).await;
        assert!(two.try_lead_worker().await.unwrap().is_none());
        third.release().await.unwrap();
        let fourth = lead_eventually(&two).await;
        fourth.release().await.unwrap();

        one.close().await;
        two.close().await;
    });
}

/// Tries to take the instance lock from `db` in `mode` until it is granted, for up to 10 s: the
/// server releases a session-level lock when it notices the session has ended, which can lag
/// the client's close.
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn instance_lock_eventually(db: &Database, mode: InstanceLockMode) -> InstanceLock {
    for _ in 0..100 {
        if let Some(lock) = db.try_instance_lock(mode).await.unwrap() {
            return lock;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the instance lock was not released within 10 s");
}

/// The instance lock (ADR 0023 §5 step 1): any number of server processes hold it shared; an
/// admin command's exclusive lock is refused while one of them remains, and refuses them while
/// it is held; the lock is on the dedicated connection, not on a pooled one; a terminated
/// session reads as lost. It does not collide with the worker's leader lock. Needs no migrated
/// schema.
#[test]
#[ignore = "needs RIZZY_TEST_POSTGRES_URL: an empty PostgreSQL database"]
fn postgres_instance_lock() {
    block_on(async {
        let one = open_handle().await;
        let two = open_handle().await;
        let admin = open_handle().await;

        // Two servers hold it together; an admin command is refused while either remains.
        let mut first = instance_lock_eventually(&one, InstanceLockMode::Shared).await;
        let mut second = two
            .try_instance_lock(InstanceLockMode::Shared)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.engine(), Engine::Postgres);
        assert_eq!(first.mode(), InstanceLockMode::Shared);
        assert!(first.is_held().await.unwrap());
        assert!(second.is_held().await.unwrap());
        assert!(
            admin
                .try_instance_lock(InstanceLockMode::Exclusive)
                .await
                .unwrap()
                .is_none()
        );
        // Another key space than the worker's leader lock: a worker still leads.
        let leader = lead_eventually(&one).await;
        leader.release().await.unwrap();
        // The lock is on the dedicated connection: closing the pool leaves it held.
        one.close().await;
        assert!(first.is_held().await.unwrap());
        first.release().await.unwrap();
        assert!(
            admin
                .try_instance_lock(InstanceLockMode::Exclusive)
                .await
                .unwrap()
                .is_none(),
            "one server is left"
        );

        // The server ends that session: its check fails, and the admin command is granted.
        let mut w = admin.begin_write().await.unwrap();
        let Conn::Postgres(c) = w.conn() else {
            panic!("a PostgreSQL handle");
        };
        let terminated: Vec<bool> = sqlx::query_scalar(
            "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' \
                 AND granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                 AND classid::int8 = $1 AND objid::int8 = $2 AND objsubid = 1",
        )
        .bind(INSTANCE_LOCK >> 32)
        .bind(INSTANCE_LOCK & 0xffff_ffff)
        .fetch_all(&mut *c)
        .await
        .unwrap();
        w.rollback().await.unwrap();
        assert_eq!(terminated, vec![true]);
        let mut lost = false;
        for _ in 0..100 {
            if !matches!(second.is_held().await, Ok(true)) {
                lost = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            lost,
            "the terminated server still reports the lock after 10 s"
        );
        drop(second);

        // The exclusive lock refuses a starting server and a second admin command.
        let mut exclusive = instance_lock_eventually(&admin, InstanceLockMode::Exclusive).await;
        assert_eq!(exclusive.mode(), InstanceLockMode::Exclusive);
        assert!(exclusive.is_held().await.unwrap());
        assert!(
            two.try_instance_lock(InstanceLockMode::Shared)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            two.try_instance_lock(InstanceLockMode::Exclusive)
                .await
                .unwrap()
                .is_none()
        );
        // Releasing it lets a server start again.
        exclusive.release().await.unwrap();
        let again = instance_lock_eventually(&two, InstanceLockMode::Shared).await;
        again.release().await.unwrap();

        two.close().await;
        admin.close().await;
    });
}
