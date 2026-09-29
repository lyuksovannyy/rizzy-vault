//! `rizzy-storage` on a real PostgreSQL database.
//!
//! `#[ignore]`d by default: run with `RIZZY_TEST_POSTGRES_URL` set to an **empty** database the
//! tests may fill, for example
//! `RIZZY_TEST_POSTGRES_URL=postgres://rizzy:rizzy@localhost/rizzy_test cargo test -p
//! rizzy-storage -- --ignored postgres`. The test migrates it, so run it on a fresh database
//! each time. ADR 0011 point 3 puts this suite into a PostgreSQL CI job from the first M1
//! migration; that job is not added here (`.github/workflows/` is out of this change's scope).

use std::time::Duration;

use rizzy_storage::meta::{reconciliation_epoch, restore_generation};
use rizzy_storage::{
    Database, Error, PostgresOptions, RestoreGeneration, StartupMigration, lock_account, on_engine,
    schema_version,
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
