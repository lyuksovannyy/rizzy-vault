//! `rizzy-storage` on real SQLite files.

use std::path::Path;
use std::time::Duration;

use rizzy_storage::meta::{
    end_reconciliation_epoch, ensure_restore_generation, reconciliation_epoch,
    reconciliation_epochs, restore_generation,
};
use rizzy_storage::migrate::MIGRATIONS;
use rizzy_storage::tables::{Kind, NOT_BACKED_UP, TABLES};
use rizzy_storage::{
    Conn, Database, Engine, Error, InstanceLockMode, RestoreError, RestoreGeneration,
    SqliteOptions, StartupMigration, Value, WriterLock, lock_account, on_engine,
    remove_pre_migration_copy, schema_version,
};
use sqlx::Row;

use crate::common::{ACCOUNT_1, ACCOUNT_2, TempDir, block_on, fixture, fixture_after_restore, id};

/// Concurrent writers in the serialisation tests.
const TASKS: i64 = 16;

/// Opens (creating) and migrates the database `name` in `dir`; the database owns its writer lock.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn open(dir: &TempDir, name: &str) -> Database {
    let path = dir.join(name);
    let lock = WriterLock::acquire(&path).unwrap();
    let db = Database::open_sqlite(&SqliteOptions::new(&path), lock)
        .await
        .unwrap();
    db.migrate_at_startup(&dir.join(&format!("{name}.pre-migration")))
        .await
        .unwrap();
    db
}

/// A PRAGMA's value, read on the writer.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn pragma(db: &Database, query: &'static str) -> String {
    let mut tx = db.begin_write().await.unwrap();
    let Conn::Sqlite(c) = tx.conn() else {
        unreachable!()
    };
    let row = sqlx::query(query).fetch_one(&mut *c).await.unwrap();
    let value = row
        .try_get::<String, _>(0)
        .or_else(|_| row.try_get::<i64, _>(0).map(|v| v.to_string()))
        .unwrap();
    tx.rollback().await.unwrap();
    value
}

#[test]
fn migrations_apply_once_with_adr_0011_pragmas() {
    block_on(async {
        let dir = TempDir::new();
        let path = dir.join("db.sqlite");
        let copy = dir.join("copy");
        let lock = WriterLock::acquire(&path).unwrap();
        let db = Database::open_sqlite(&SqliteOptions::new(&path), lock)
            .await
            .unwrap();
        let all: Vec<i64> = MIGRATIONS.iter().map(|m| m.version).collect();
        assert_eq!(db.pending_migrations().await.unwrap(), all);
        assert_eq!(
            db.migrate_at_startup(&copy).await.unwrap(),
            StartupMigration::Created
        );
        assert!(!copy.exists(), "a new database gets no pre-migration copy");
        assert_eq!(db.applied_migrations().await.unwrap(), all);
        assert!(db.pending_migrations().await.unwrap().is_empty());
        assert_eq!(
            db.migrate_at_startup(&copy).await.unwrap(),
            StartupMigration::UpToDate
        );
        assert!(!copy.exists());

        // ADR 0011 "SQLite settings".
        assert_eq!(pragma(&db, "PRAGMA journal_mode").await, "wal");
        assert_eq!(pragma(&db, "PRAGMA synchronous").await, "2"); // FULL
        assert_eq!(pragma(&db, "PRAGMA foreign_keys").await, "1");
        assert_eq!(pragma(&db, "PRAGMA busy_timeout").await, "5000");
        assert_eq!(pragma(&db, "PRAGMA secure_delete").await, "1");
        assert_eq!(pragma(&db, "PRAGMA auto_vacuum").await, "2"); // INCREMENTAL
    });
}

#[test]
fn migration_files_on_disk_are_the_embedded_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    for (engine, dir) in [(Engine::Sqlite, "sqlite"), (Engine::Postgres, "postgres")] {
        let mut files: Vec<String> = std::fs::read_dir(root.join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        let expected: Vec<String> = MIGRATIONS
            .iter()
            .map(|m| format!("{:04}_{}.sql", m.version, m.description))
            .collect();
        assert_eq!(files, expected, "{dir}");
        for m in MIGRATIONS {
            let text = std::fs::read_to_string(
                root.join(dir)
                    .join(format!("{:04}_{}.sql", m.version, m.description)),
            )
            .unwrap();
            assert_eq!(text, m.sql(engine), "{dir}/{}", m.description);
        }
    }
}

/// The backup table list, the restore row count and the query files agree with the schema the
/// migrations create: a new table or column cannot be forgotten by the backup.
#[test]
fn backup_list_matches_the_schema() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let mut tx = db.begin_read().await.unwrap();
        let Conn::Sqlite(c) = tx.conn() else {
            unreachable!()
        };
        let mut tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations' ORDER BY name",
        )
        .fetch_all(&mut *c)
        .await
        .unwrap();
        let mut expected: Vec<String> = TABLES
            .iter()
            .map(|t| t.name)
            .chain(NOT_BACKED_UP.iter().copied())
            .map(str::to_owned)
            .collect();
        tables.sort();
        expected.sort();
        assert_eq!(tables, expected);

        let row_count = include_str!("../../queries/storage/restore_row_count.sql");
        for table in &tables {
            assert!(
                row_count.contains(&format!("FROM {table})")),
                "restore_row_count.sql misses {table}"
            );
            let prefix = table.split('_').next().unwrap();
            assert!(["auth", "vault", "storage"].contains(&prefix), "{table}");
        }

        for spec in TABLES {
            let columns: Vec<(String, String, i64)> = sqlx::query(
                "SELECT name, type, \"notnull\" FROM pragma_table_info($1) ORDER BY cid",
            )
            .bind(spec.name)
            .fetch_all(&mut *c)
            .await
            .unwrap()
            .into_iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect();
            let expected: Vec<(String, String, i64)> = spec
                .columns
                .iter()
                .map(|col| {
                    let ty = match col.kind {
                        Kind::Integer => "INTEGER",
                        Kind::Text => "TEXT",
                        Kind::Blob => "BLOB",
                    };
                    (col.name.to_owned(), ty.to_owned(), i64::from(!col.nullable))
                })
                .collect();
            assert_eq!(columns, expected, "{}", spec.name);

            let names: Vec<&str> = spec.columns.iter().map(|c| c.name).collect();
            let list = names.join(", ");
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("queries/backup");
            let select =
                std::fs::read_to_string(dir.join(format!("{}.select.sql", spec.name))).unwrap();
            assert!(select.contains(&format!("SELECT {list}\nFROM {}\n", spec.name)));
            let insert =
                std::fs::read_to_string(dir.join(format!("{}.insert.sql", spec.name))).unwrap();
            let placeholders: Vec<String> = (1..=names.len()).map(|i| format!("${i}")).collect();
            assert!(insert.contains(&format!(
                "INSERT INTO {} ({list})\nVALUES ({})\n",
                spec.name,
                placeholders.join(", ")
            )));
        }
        tx.finish().await.unwrap();
    });
}

#[test]
fn writer_lock_admits_one_writer() {
    block_on(async {
        let dir = TempDir::new();
        let path = dir.join("db.sqlite");
        let lock = WriterLock::acquire(&path).unwrap();
        assert!(matches!(
            WriterLock::acquire(&path),
            Err(Error::WriterLockHeld { .. })
        ));
        let other_path = dir.join("other.sqlite");
        let other = WriterLock::acquire(&other_path).unwrap();
        assert!(matches!(
            Database::open_sqlite(&SqliteOptions::new(&path), other).await,
            Err(Error::WriterLockMismatch)
        ));
        // A refused open drops, and so releases, the lock it was given.
        drop(WriterLock::acquire(&other_path).unwrap());
        drop(lock);
        drop(WriterLock::acquire(&path).unwrap());

        // The database owns its lock: a lock passed as a temporary stays held for as long as
        // any clone of the database lives, and is released with the last one (ADR 0010 §2).
        let db = Database::open_sqlite(
            &SqliteOptions::new(&path),
            WriterLock::acquire(&path).unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            WriterLock::acquire(&path),
            Err(Error::WriterLockHeld { .. })
        ));
        let clone = db.clone();
        db.close().await;
        drop(db);
        assert!(
            matches!(
                WriterLock::acquire(&path),
                Err(Error::WriterLockHeld { .. })
            ),
            "a clone still holds the writer pool, so it still holds the lock"
        );
        drop(clone);
        drop(WriterLock::acquire(&path).unwrap());
    });
}

/// On SQLite the writer lock already makes the process the only worker (ADR 0010 §2): a
/// writable database always leads, and stays leading; a read-only one (the `backup` reader)
/// never runs jobs.
#[test]
fn worker_leader_rides_on_the_writer_lock() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let mut leader = db.try_lead_worker().await.unwrap().unwrap();
        assert_eq!(leader.engine(), Engine::Sqlite);
        assert!(leader.is_held().await.unwrap());
        assert!(leader.is_held().await.unwrap());
        assert!(format!("{leader:?}").contains("Sqlite"));
        // A second leader in the same process changes nothing: the writer lock is the guard.
        assert!(db.try_lead_worker().await.unwrap().is_some());
        leader.release().await.unwrap();

        let ro = Database::open_sqlite_read_only(&SqliteOptions::new(dir.join("db.sqlite")))
            .await
            .unwrap();
        assert!(matches!(ro.try_lead_worker().await, Err(Error::ReadOnly)));
        ro.close().await;
        db.close().await;
    });
}

/// On SQLite the writer lock is the instance lock (ADR 0023 §5 step 1, "SQLite: take the writer
/// lock"): a writable database is granted it in either mode and keeps it; a read-only one (the
/// `backup` reader) excludes nobody and is refused.
#[test]
fn instance_lock_rides_on_the_writer_lock() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        for mode in [InstanceLockMode::Shared, InstanceLockMode::Exclusive] {
            let mut lock = db.try_instance_lock(mode).await.unwrap().unwrap();
            assert_eq!(lock.engine(), Engine::Sqlite);
            assert_eq!(lock.mode(), mode);
            assert!(lock.is_held().await.unwrap());
            assert!(lock.is_held().await.unwrap());
            assert!(format!("{lock:?}").contains("Sqlite"));
            lock.release().await.unwrap();
        }
        // What excludes a second process is the writer lock the database holds.
        assert!(matches!(
            WriterLock::acquire(&dir.join("db.sqlite")),
            Err(Error::WriterLockHeld { .. })
        ));

        let ro = Database::open_sqlite_read_only(&SqliteOptions::new(dir.join("db.sqlite")))
            .await
            .unwrap();
        for mode in [InstanceLockMode::Shared, InstanceLockMode::Exclusive] {
            assert!(matches!(
                ro.try_instance_lock(mode).await,
                Err(Error::ReadOnly)
            ));
        }
        ro.close().await;
        db.close().await;
    });
}

#[test]
fn readers_are_read_only_and_see_committed_snapshots() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let insert = "INSERT INTO auth_accounts (id, login_name, created_at_ms) VALUES ($1, $2, 1)";
        let count = "SELECT COUNT(*) FROM auth_accounts";

        // A reader cannot write.
        let mut r = db.begin_read().await.unwrap();
        let Conn::Sqlite(c) = r.conn() else {
            unreachable!()
        };
        let refused = sqlx::query(insert)
            .bind(&id(1)[..])
            .bind("alice")
            .execute(&mut *c)
            .await;
        assert!(refused.is_err(), "the reader pool must be read-only");
        drop(r);

        // An open write transaction holds the write lock; readers still run, and see only
        // committed data.
        let mut w = db.begin_write().await.unwrap();
        on_engine!(w.conn(), |c| sqlx::query(insert)
            .bind(&id(1)[..])
            .bind("alice")
            .execute(&mut *c)
            .await
            .unwrap()
            .rows_affected());
        let mut r = db.begin_read().await.unwrap();
        let n: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(count)
            .fetch_one(&mut *c)
            .await
            .unwrap());
        assert_eq!(n, 0, "a reader must not see an uncommitted write");
        w.commit().await.unwrap();
        // The reader's snapshot began before the commit.
        let n: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(count)
            .fetch_one(&mut *c)
            .await
            .unwrap());
        assert_eq!(n, 0, "one read transaction is one snapshot");
        r.finish().await.unwrap();
        let mut r = db.begin_read().await.unwrap();
        let n: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(count)
            .fetch_one(&mut *c)
            .await
            .unwrap());
        assert_eq!(n, 1);
        r.finish().await.unwrap();

        // A read-only handle (the backup reader) reads next to the writer and cannot write.
        let ro = Database::open_sqlite_read_only(&SqliteOptions::new(dir.join("db.sqlite")))
            .await
            .unwrap();
        assert!(matches!(ro.begin_write().await, Err(Error::ReadOnly)));
        assert!(matches!(ro.migrate().await, Err(Error::ReadOnly)));
        let mut r = ro.begin_read().await.unwrap();
        let n: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(count)
            .fetch_one(&mut *c)
            .await
            .unwrap());
        assert_eq!(n, 1);
        r.finish().await.unwrap();
    });
}

/// Writes that read and then write are serialised: a second write transaction waits for the
/// first, and concurrent read-increment-write loops lose no update.
#[test]
fn write_transactions_are_serialised() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let account = id(ACCOUNT_1);
        let mut w = db.begin_write().await.unwrap();
        on_engine!(w.conn(), |c| {
            sqlx::query(
                "INSERT INTO auth_accounts (id, login_name, created_at_ms) VALUES ($1, 'a', 0)",
            )
            .bind(&account[..])
            .execute(&mut *c)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO auth_pending_recoveries \
                 (account_id, recovery_epoch, opened_at_ms, available_at_ms) VALUES ($1, 0, 0, 0)",
            )
            .bind(&account[..])
            .execute(&mut *c)
            .await
            .unwrap();
        });
        w.commit().await.unwrap();

        // A second writer waits while the first is open.
        let mut first = db.begin_write().await.unwrap();
        lock_account(&mut first, &account).await.unwrap();
        let second = tokio::time::timeout(Duration::from_millis(300), db.begin_write()).await;
        assert!(
            second.is_err(),
            "a second write transaction started while one was open"
        );
        first.commit().await.unwrap();
        let second = tokio::time::timeout(Duration::from_secs(10), db.begin_write())
            .await
            .expect("the second writer did not start after the first committed")
            .unwrap();
        second.rollback().await.unwrap();

        // Concurrent read-then-write increments of one counter lose nothing.
        let mut handles = Vec::new();
        for _ in 0..TASKS {
            let db = db.clone();
            handles.push(tokio::spawn(async move {
                let mut tx = db.begin_write().await.unwrap();
                lock_account(&mut tx, &account).await.unwrap();
                let current: i64 = on_engine!(tx.conn(), |c| sqlx::query_scalar(
                    "SELECT recovery_epoch FROM auth_pending_recoveries WHERE account_id = $1"
                )
                .bind(&account[..])
                .fetch_one(&mut *c)
                .await
                .unwrap());
                tokio::task::yield_now().await;
                on_engine!(tx.conn(), |c| sqlx::query(
                    "UPDATE auth_pending_recoveries SET recovery_epoch = $1 WHERE account_id = $2"
                )
                .bind(current + 1)
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
        let n: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(
            "SELECT recovery_epoch FROM auth_pending_recoveries WHERE account_id = $1"
        )
        .bind(&account[..])
        .fetch_one(&mut *c)
        .await
        .unwrap());
        assert_eq!(n, TASKS);
        r.finish().await.unwrap();
    });
}

/// A dump restores into an empty database and reads back identical, with the restore hooks
/// applied; the restored database dumps to the same rows again.
#[test]
fn backup_restore_round_trip() {
    block_on(async {
        let dir = TempDir::new();
        let source = open(&dir, "source.sqlite").await;
        let g0 = RestoreGeneration([0x10; 16]);
        let report = source.restore(&fixture(), g0, 5_000).await.unwrap();
        assert_eq!(report.accounts_in_reconciliation, 2);
        let rows: usize = fixture().tables.iter().map(|t| t.rows.len()).sum();
        assert_eq!(report.rows, u64::try_from(rows).unwrap());

        // Short-lived session state is not backed up.
        let mut w = source.begin_write().await.unwrap();
        on_engine!(w.conn(), |c| sqlx::query(
            "INSERT INTO auth_sessions (token_hash, session_id, account_id, session_kind, \
             created_at_ms, expires_at_ms) VALUES ($1, $2, $3, 1, 0, 1)"
        )
        .bind(&[9u8; 32][..])
        .bind(&[8u8; 16][..])
        .bind(&id(ACCOUNT_1)[..])
        .execute(&mut *c)
        .await
        .unwrap()
        .rows_affected());
        w.commit().await.unwrap();

        // Dump on a read-only handle next to the open writer.
        let reader =
            Database::open_sqlite_read_only(&SqliteOptions::new(dir.join("source.sqlite")))
                .await
                .unwrap();
        let dump = reader.dump().await.unwrap();
        assert_eq!(dump, fixture_after_restore());
        assert_eq!(dump.schema_version, schema_version());

        // Through the backup file (ADR 0023): written and parsed back to the same dump.
        let file = rizzy_storage::backup::file::write(&dump, 1_234).unwrap();
        let parsed = rizzy_storage::backup::file::parse(&file).unwrap();
        assert_eq!(parsed.created_at_ms, 1_234);
        let dump = parsed.dump;

        // Restore into a new database: a valid target before and after its migrations.
        let target = {
            let path = dir.join("target.sqlite");
            let lock = WriterLock::acquire(&path).unwrap();
            Database::open_sqlite(&SqliteOptions::new(&path), lock)
                .await
                .unwrap()
        };
        target.check_restore_target().await.unwrap();
        target.migrate().await.unwrap();
        target.check_restore_target().await.unwrap();
        let g1 = RestoreGeneration([0x11; 16]);
        target.restore(&dump, g1, 9_000).await.unwrap();
        assert!(matches!(
            target.check_restore_target().await,
            Err(Error::Restore(RestoreError::TargetNotEmpty))
        ));
        assert_eq!(target.dump().await.unwrap(), dump);

        let mut r = target.begin_read().await.unwrap();
        assert_eq!(restore_generation(r.conn()).await.unwrap(), Some(g1));
        let epoch = reconciliation_epoch(r.conn(), &id(ACCOUNT_1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(epoch.restore_generation, g1);
        assert_eq!(epoch.opened_at_ms, 9_000);
        assert_eq!(reconciliation_epochs(r.conn()).await.unwrap().len(), 2);
        let sessions: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(
            "SELECT COUNT(*) FROM auth_sessions"
        )
        .fetch_one(&mut *c)
        .await
        .unwrap());
        assert_eq!(sessions, 0, "sessions are not restored");
        r.finish().await.unwrap();

        // The domain ends an epoch.
        let mut w = target.begin_write().await.unwrap();
        lock_account(&mut w, &id(ACCOUNT_2)).await.unwrap();
        assert!(
            end_reconciliation_epoch(&mut w, &id(ACCOUNT_2))
                .await
                .unwrap()
        );
        assert!(
            !end_reconciliation_epoch(&mut w, &id(ACCOUNT_2))
                .await
                .unwrap()
        );
        w.commit().await.unwrap();
        let mut r = target.begin_read().await.unwrap();
        assert!(
            reconciliation_epoch(r.conn(), &id(ACCOUNT_2))
                .await
                .unwrap()
                .is_none()
        );
        r.finish().await.unwrap();

        // Restoring again into the now non-empty database is refused.
        assert!(matches!(
            target.restore(&dump, g1, 9_000).await,
            Err(Error::Restore(RestoreError::TargetNotEmpty))
        ));
    });
}

#[test]
fn restore_refuses_bad_input_and_writes_nothing() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let g = RestoreGeneration([1; 16]);

        let mut old = fixture();
        old.schema_version -= 1;
        assert!(matches!(
            db.restore(&old, g, 0).await,
            Err(Error::Restore(RestoreError::SchemaVersion { .. }))
        ));

        let mut bad = fixture();
        bad.tables.last_mut().unwrap().rows[0][2] = Value::Text("not a blob".into());
        assert!(matches!(
            db.restore(&bad, g, 0).await,
            Err(Error::Restore(RestoreError::Row {
                column: Some(2),
                ..
            }))
        ));

        // A row that violates a CHECK constraint (a 15-byte id) fails in the database, and the
        // whole restore rolls back.
        let mut broken = fixture();
        broken.tables.last_mut().unwrap().rows[0][1] = Value::Blob(vec![0; 15]);
        assert!(matches!(
            db.restore(&broken, g, 0).await,
            Err(Error::Database(_))
        ));

        let mut r = db.begin_read().await.unwrap();
        let accounts: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(
            "SELECT COUNT(*) FROM auth_accounts"
        )
        .fetch_one(&mut *c)
        .await
        .unwrap());
        assert_eq!(accounts, 0, "a failed restore must leave nothing behind");
        assert_eq!(restore_generation(r.conn()).await.unwrap(), None);
        r.finish().await.unwrap();

        // The good fixture still restores afterwards.
        db.restore(&fixture(), g, 0).await.unwrap();
    });
}

#[test]
fn restore_generation_is_drawn_once() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let first = RestoreGeneration([1; 16]);
        assert_eq!(
            ensure_restore_generation(&db, first, 1).await.unwrap(),
            first
        );
        let later = RestoreGeneration([2; 16]);
        assert_eq!(
            ensure_restore_generation(&db, later, 2).await.unwrap(),
            first
        );
    });
}

/// `VACUUM INTO` writes a consistent, private copy on the writer, refuses to overwrite, and is
/// refused on a read-only handle; the startup rule writes it only before a pending migration of a database
/// that holds data.
#[test]
fn pre_migration_copy() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        db.restore(&fixture(), RestoreGeneration([3; 16]), 0)
            .await
            .unwrap();

        let copy = dir.join("backup.sqlite");
        let ro = Database::open_sqlite_read_only(&SqliteOptions::new(dir.join("db.sqlite")))
            .await
            .unwrap();
        assert!(matches!(ro.vacuum_into(&copy).await, Err(Error::ReadOnly)));
        assert!(!copy.exists(), "a refused copy creates no file");
        db.vacuum_into(&copy).await.unwrap();
        assert!(matches!(db.vacuum_into(&copy).await, Err(Error::Io { .. })));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&copy).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let copied = Database::open_sqlite_read_only(&SqliteOptions::new(&copy))
            .await
            .unwrap();
        assert_eq!(copied.dump().await.unwrap(), fixture_after_restore());
        copied.close().await;

        // Make the last migration pending again, as a new release would.
        let last = MIGRATIONS.last().unwrap().version;
        let mut w = db.begin_write().await.unwrap();
        on_engine!(w.conn(), |c| {
            // Undo the last migration (0005: one column in each of two tables).
            for undo in [
                "ALTER TABLE auth_credentials DROP COLUMN account_key_epoch",
                "ALTER TABLE auth_recovery DROP COLUMN account_key_epoch",
            ] {
                sqlx::query(undo).execute(&mut *c).await.unwrap();
            }
            sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
                .bind(last)
                .execute(&mut *c)
                .await
                .unwrap();
        });
        w.commit().await.unwrap();
        assert_eq!(db.pending_migrations().await.unwrap(), vec![last]);

        let pre = dir.join("db.sqlite.pre-migration");
        assert_eq!(
            db.migrate_at_startup(&pre).await.unwrap(),
            StartupMigration::MigratedAfterCopy
        );
        assert!(pre.exists());
        let before = Database::open_sqlite_read_only(&SqliteOptions::new(&pre))
            .await
            .unwrap();
        assert_eq!(
            before.applied_migrations().await.unwrap().last(),
            Some(&(last - 1))
        );
        before.close().await;
        remove_pre_migration_copy(&pre).unwrap();
        assert!(!pre.exists());
        remove_pre_migration_copy(&pre).unwrap();
    });
}

/// Runs one statement on the writer and commits it.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn exec(db: &Database, statement: &'static str) {
    let mut w = db.begin_write().await.unwrap();
    on_engine!(w.conn(), |c| sqlx::query(statement)
        .execute(&mut *c)
        .await
        .unwrap()
        .rows_affected());
    w.commit().await.unwrap();
}

/// `dump` reads only a database at exactly this release's schema, so its stamp describes its
/// content; startup, `dump` and `restore` refuse a changed or unknown applied migration even
/// when nothing is pending.
#[test]
fn schema_must_match_this_release() {
    use sqlx::migrate::MigrateError;
    block_on(async {
        let dir = TempDir::new();

        // An older schema (the last migration not applied) is not dumped.
        let db = open(&dir, "old.sqlite").await;
        db.restore(&fixture(), RestoreGeneration([5; 16]), 0)
            .await
            .unwrap();
        exec(
            &db,
            "ALTER TABLE auth_credentials DROP COLUMN account_key_epoch",
        )
        .await;
        exec(
            &db,
            "ALTER TABLE auth_recovery DROP COLUMN account_key_epoch",
        )
        .await;
        exec(
            &db,
            "DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM \
             _sqlx_migrations)",
        )
        .await;
        let last = MIGRATIONS.last().unwrap().version;
        let ro = Database::open_sqlite_read_only(&SqliteOptions::new(dir.join("old.sqlite")))
            .await
            .unwrap();
        match ro.dump().await {
            Err(Error::SchemaNotCurrent { pending }) => assert_eq!(pending, vec![last]),
            other => panic!("{other:?}"),
        }
        ro.close().await;
        // Nor is it a restore target: some release migrated it, but not to this schema.
        assert!(matches!(
            db.check_restore_target().await,
            Err(Error::Restore(RestoreError::TargetNotEmpty))
        ));

        // A changed migration is refused at startup although nothing is pending, and by dump
        // and restore.
        let db = open(&dir, "changed.sqlite").await;
        exec(
            &db,
            "UPDATE _sqlx_migrations SET checksum = X'00' WHERE version = 1",
        )
        .await;
        assert!(matches!(
            db.migrate_at_startup(&dir.join("changed.pre")).await,
            Err(Error::Migrate(MigrateError::VersionMismatch(1)))
        ));
        assert!(!dir.join("changed.pre").exists());
        assert!(matches!(
            db.dump().await,
            Err(Error::Migrate(MigrateError::VersionMismatch(1)))
        ));
        assert!(matches!(
            db.restore(&fixture(), RestoreGeneration([6; 16]), 0).await,
            Err(Error::Migrate(MigrateError::VersionMismatch(1)))
        ));
        assert!(matches!(
            db.check_restore_target().await,
            Err(Error::Migrate(MigrateError::VersionMismatch(1)))
        ));

        // A migration of a newer release is refused the same way.
        let db = open(&dir, "newer.sqlite").await;
        exec(
            &db,
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, \
             execution_time) VALUES (9999, 'storage_future', 1, X'00', 0)",
        )
        .await;
        assert!(matches!(
            db.migrate_at_startup(&dir.join("newer.pre")).await,
            Err(Error::Migrate(MigrateError::VersionMissing(9999)))
        ));
        assert!(matches!(
            db.dump().await,
            Err(Error::Migrate(MigrateError::VersionMissing(9999)))
        ));
    });
}

/// A dump that leaves out a table, even an empty one, is refused and writes nothing.
#[test]
fn restore_refuses_a_dump_missing_a_table() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let mut truncated = fixture();
        let removed = truncated
            .tables
            .iter()
            .position(|t| t.table == "auth_device_revocations")
            .unwrap();
        truncated.tables.remove(removed);
        assert!(matches!(
            db.restore(&truncated, RestoreGeneration([7; 16]), 0).await,
            Err(Error::Restore(RestoreError::MissingTable {
                name: "auth_device_revocations"
            }))
        ));
        let dump = db.dump().await.unwrap();
        assert!(dump.tables.iter().all(|t| t.rows.is_empty()));
        assert_eq!(dump.tables.len(), TABLES.len());
    });
}

/// Deleting an account is one statement: every row of it goes (ADR 0011 point 6).
#[test]
fn account_deletion_cascades() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        db.restore(&fixture(), RestoreGeneration([4; 16]), 0)
            .await
            .unwrap();
        let mut w = db.begin_write().await.unwrap();
        lock_account(&mut w, &id(ACCOUNT_1)).await.unwrap();
        on_engine!(w.conn(), |c| sqlx::query(
            "DELETE FROM auth_accounts WHERE id = $1"
        )
        .bind(&id(ACCOUNT_1)[..])
        .execute(&mut *c)
        .await
        .unwrap()
        .rows_affected());
        w.commit().await.unwrap();
        let dump = db.dump().await.unwrap();
        for table in &dump.tables {
            let keep = matches!(
                table.table.as_str(),
                "auth_accounts"
                    | "auth_opaque_setups"
                    | "auth_rate_limits"
                    | "auth_pending_recoveries"
            );
            assert_eq!(!table.rows.is_empty(), keep, "{}", table.table);
        }
    });
}

/// `auto_vacuum = INCREMENTAL` returns space after a purge once `incremental_vacuum` runs
/// (ADR 0011 "SQLite settings").
#[test]
fn incremental_vacuum_shrinks_the_file() {
    block_on(async {
        let dir = TempDir::new();
        let db = open(&dir, "db.sqlite").await;
        let path = dir.join("db.sqlite");
        let big = vec![7u8; 64 * 1024];
        let mut w = db.begin_write().await.unwrap();
        on_engine!(w.conn(), |c| {
            for i in 0u8..64 {
                sqlx::query(
                    "INSERT INTO auth_rate_limits (bucket, attempts, window_started_at_ms, \
                     blocked_until_ms, expires_at_ms) VALUES ($1, 0, 0, 0, 0)",
                )
                .bind(&[i; 8][..])
                .execute(&mut *c)
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO auth_login_states (login_id, credential_identifier, \
                     data_key_id, sealed_state, expires_at_ms) VALUES ($1, $1, 0, $2, 0)",
                )
                .bind(&[i; 16][..])
                .bind(&big[..])
                .execute(&mut *c)
                .await
                .unwrap();
            }
        });
        w.commit().await.unwrap();
        // A test-only second pool on the same file checkpoints the WAL into the main file, so
        // the file size reflects the pages in use.
        let raw = sqlx::SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
        )
        .await
        .unwrap();
        let checkpoint = "PRAGMA wal_checkpoint(TRUNCATE)";
        sqlx::query(checkpoint).execute(&raw).await.unwrap();
        let full = std::fs::metadata(&path).unwrap().len();

        let mut w = db.begin_write().await.unwrap();
        on_engine!(w.conn(), |c| sqlx::query("DELETE FROM auth_login_states")
            .execute(&mut *c)
            .await
            .unwrap()
            .rows_affected());
        w.commit().await.unwrap();
        db.incremental_vacuum().await.unwrap();
        sqlx::query(checkpoint).execute(&raw).await.unwrap();
        raw.close().await;
        let after = std::fs::metadata(&path).unwrap().len();
        assert!(
            after < full / 2,
            "the file did not shrink: {full} bytes before the purge, {after} after"
        );
    });
}
