//! Backup and restore primitives (ADR 0011 "Backups", point 9).
//!
//! - **Native SQLite copy:** [`Database::vacuum_into`], a consistent copy of the whole file with
//!   `VACUUM INTO`, used for the pre-migration copy and documented as an operator backup
//!   method. On PostgreSQL the native method is `pg_dump`, run by the operator.
//! - **Logical, engine-neutral dump:** [`Database::dump`] reads every backed-up table as rows
//!   ([`TABLES`]) inside one read transaction, stamped with the schema version;
//!   [`Database::restore`] loads such a [`Dump`] into an empty SQLite or PostgreSQL
//!   database. The same pair moves an instance from SQLite to PostgreSQL.
//!
//! - **The backup file** ([ADR 0023]): [`file`](mod@file) writes a [`Dump`] as the versioned,
//!   self-describing, canonical binary file of ADR 0023 §1 and parses it back strictly, with
//!   the size limits of §3 and the trailing SHA-256 checked before anything is parsed. A
//!   [`Dump`] from a file is untrusted input: [`Database::restore`] checks every row against
//!   the schema again, and never panics on a bad one. The commands around it (`rizzy-vault
//!   backup` and `restore`, file creation, the secrets check) are `rizzy-server`'s (ADR 0023
//!   §4).
//!
//! **Before a restore**, [`Database::check_restore_target`] checks the target without changing
//! it (ADR 0023 §5 step 1): no migration applied, or exactly this release's, and no row.
//! [`Database::restore`] checks the same again inside its write transaction.
//!
//! **Restore** runs in one write transaction, so it either happens completely or not at all:
//! 1. it migrates the target to this release's schema and requires the dump to be of that
//!    version, and the target to hold no row at all;
//! 2. it inserts every row, table by table in foreign-key order, checking each row against its
//!    table's columns;
//! 3. it draws the new restore generation (ADR 0021 §2) from the caller's value;
//! 4. it opens a reconciliation epoch for every restored account (INV-59);
//! 5. it sets each vault's store-sequence counter above the highest restored store sequence
//!    (ADR 0021 §2).
//!
//! On SQLite, `restore` and `vacuum_into` need the writer, so they run in the server process or
//! with the server stopped (ADR 0010 §2); `dump` runs on the read-only reader next to it.
//!
//! [ADR 0023]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0023-logical-backup-format.md

pub mod file;

use std::fmt;
use std::fs::OpenOptions;
use std::path::Path;

use sqlx::Row;

use crate::db::{Conn, Database};
use crate::error::{Engine, Error, RestoreError};
use crate::meta::RestoreGeneration;
use crate::migrate::{applied_on, check_applied, schema_version};
use crate::tables::{Kind, TABLES, TableSpec};

/// `VACUUM INTO $1`.
const SQLITE_VACUUM_INTO: &str = include_str!("../queries/sqlite/vacuum_into.sql");
/// `PRAGMA incremental_vacuum`.
const SQLITE_INCREMENTAL_VACUUM: &str = include_str!("../queries/sqlite/incremental_vacuum.sql");
/// The total row count of every application table.
const RESTORE_ROW_COUNT: &str = include_str!("../queries/storage/restore_row_count.sql");
/// Replaces the restore generation.
const RESTORE_GENERATION_SET: &str = include_str!("../queries/storage/restore_generation_set.sql");
/// Opens a reconciliation epoch for every account.
const RECONCILIATION_OPEN_ALL: &str =
    include_str!("../queries/storage/reconciliation_open_all.sql");
/// Raises each vault's store-sequence counter above its restored maximum.
const RESTORE_STORE_SEQ: &str = include_str!("../queries/storage/restore_store_seq.sql");

/// One column value of a dumped row.
///
/// `Debug` shows the kind and length only, never the bytes or the text: rows hold ciphertext,
/// token hashes, sealed server secrets and login names (INV-48).
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// SQL NULL.
    Null,
    /// An integer.
    Integer(i64),
    /// Text.
    Text(String),
    /// Bytes.
    Blob(Vec<u8>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Integer(_) => f.write_str("Integer(..)"),
            Self::Text(t) => write!(f, "Text({} bytes)", t.len()),
            Self::Blob(b) => write!(f, "Blob({} bytes)", b.len()),
        }
    }
}

/// The rows of one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableDump {
    /// The table name, one of [`TABLES`].
    pub table: String,
    /// Its rows, each with one [`Value`] per column in [`TableSpec::columns`] order.
    pub rows: Vec<Vec<Value>>,
}

/// A logical, engine-neutral backup: every backed-up table as rows, stamped with the schema
/// version it was taken at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dump {
    /// The schema version (last applied migration) of the database it was read from.
    pub schema_version: i64,
    /// Every table of [`TABLES`], in that order, each exactly once; a table with no rows is
    /// present with an empty `rows`. [`Database::restore`] refuses a dump that leaves one out.
    pub tables: Vec<TableDump>,
}

/// What a restore did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    /// Rows inserted.
    pub rows: u64,
    /// Accounts put into a reconciliation epoch: every restored account (INV-59). The restore
    /// command tells the operator what that means, and that accounts whose devices never
    /// reconnect stay rolled back (AR-19).
    pub accounts_in_reconciliation: u64,
}

impl Database {
    /// Writes a consistent copy of the whole SQLite database to `dest` with `VACUUM INTO`.
    ///
    /// `dest` must not exist: it is created first, empty, with mode 0600 on Unix (ADR 0011
    /// point 9), and SQLite then fills it. It runs on the writer connection, between write
    /// transactions: SQLite refuses `VACUUM INTO` on a read-only connection (checked with the
    /// bundled SQLite of sqlx 0.9.0), so the read-only `backup` reader next to a running server
    /// takes the logical [`Database::dump`] instead.
    ///
    /// # Errors
    ///
    /// - [`Error::ReadOnly`] on a read-only SQLite handle; nothing is created.
    /// - [`Error::WrongEngine`] on PostgreSQL, whose native backup is `pg_dump`.
    /// - [`Error::Io`] when `dest` exists, cannot be created, or is not valid UTF-8.
    /// - [`Error::Database`] when `VACUUM INTO` fails; the empty or partial file is left for the
    ///   caller to remove.
    pub async fn vacuum_into(&self, dest: &Path) -> Result<(), Error> {
        let writer = self.sqlite_writer()?.ok_or(Error::WrongEngine {
            needed: Engine::Sqlite,
        })?;
        let dest_str = dest.to_str().ok_or_else(|| Error::Io {
            action: "name the backup copy (the path must be valid UTF-8)",
            path: dest.to_path_buf(),
            source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
        })?;
        create_private_file(dest)?;
        sqlx::query(SQLITE_VACUUM_INTO)
            .bind(dest_str)
            .execute(writer)
            .await?;
        Ok(())
    }

    /// Returns every free page of the SQLite file to the filesystem with
    /// `PRAGMA incremental_vacuum` (ADR 0011 "SQLite settings": `worker` runs it after
    /// purges). Runs on the writer, outside any transaction. Deleted content can still sit in
    /// the WAL until the next checkpoint (THREAT_MODEL AR-11).
    ///
    /// # Errors
    ///
    /// - [`Error::ReadOnly`] on a read-only SQLite handle.
    /// - [`Error::WrongEngine`] on PostgreSQL, whose space is returned by its own vacuum.
    /// - [`Error::Database`] when the statement fails.
    pub async fn incremental_vacuum(&self) -> Result<(), Error> {
        let writer = self.sqlite_writer()?.ok_or(Error::WrongEngine {
            needed: Engine::Sqlite,
        })?;
        sqlx::query(SQLITE_INCREMENTAL_VACUUM)
            .execute(writer)
            .await?;
        Ok(())
    }

    /// Reads every backed-up table inside one read transaction (one consistent snapshot, on
    /// the SQLite reader next to the running server, or a PostgreSQL `REPEATABLE READ`
    /// transaction).
    ///
    /// The whole dump is held in memory, which fits M1's personal-scale databases.
    ///
    /// It reads this release's tables and columns ([`TABLES`]) and stamps this release's
    /// [`schema_version`], so it first requires, in the same snapshot, that the database is at
    /// exactly this release's schema: every migration of [`MIGRATIONS`](crate::migrate::MIGRATIONS)
    /// applied, with unchanged checksums, and no other. A backup binary of another release than
    /// the one that migrated the database refuses rather than write a dump whose stamp does not
    /// describe its content.
    ///
    /// # Errors
    ///
    /// - [`Error::SchemaNotCurrent`] when a migration of this release is not applied (an older
    ///   or empty database).
    /// - [`Error::Migrate`] when the database has a migration this release does not know (a
    ///   newer release migrated it) or one whose checksum differs.
    /// - [`Error::DirtyMigration`] when a migration is recorded as failed.
    /// - [`Error::Database`] when a query or a column decode fails.
    pub async fn dump(&self) -> Result<Dump, Error> {
        let mut tx = self.begin_read().await?;
        let applied = applied_on(tx.conn()).await?;
        let pending = check_applied(self.engine(), &applied)?;
        if !pending.is_empty() {
            return Err(Error::SchemaNotCurrent { pending });
        }
        let schema_version = schema_version();
        let mut tables = Vec::with_capacity(TABLES.len());
        for spec in TABLES {
            let rows = dump_table(tx.conn(), spec).await?;
            tables.push(TableDump {
                table: spec.name.to_owned(),
                rows,
            });
        }
        tx.finish().await?;
        Ok(Dump {
            schema_version,
            tables,
        })
    }

    /// Checks, without changing anything, that this database can be a restore target (ADR 0023
    /// §5 step 1): either no migration is applied (a new database), or exactly this release's
    /// migrations are applied and no application table holds a row. `restore` runs it before
    /// reading the backup file, so an operator pointed at the wrong database learns it first;
    /// [`Database::restore`] checks the same again in its own transaction.
    ///
    /// # Errors
    ///
    /// - [`Error::Restore`] ([`RestoreError::TargetNotEmpty`]) when migrations are applied but
    ///   not all of this release's, or a row exists.
    /// - Those of [`Database::pending_migrations`] (an applied migration this release does not
    ///   know, or whose checksum differs, or one recorded as failed).
    /// - [`Error::Database`] when a query fails.
    pub async fn check_restore_target(&self) -> Result<(), Error> {
        if self.applied_migrations().await?.is_empty() {
            return Ok(());
        }
        if !self.pending_migrations().await?.is_empty() {
            return Err(RestoreError::TargetNotEmpty.into());
        }
        let mut tx = self.begin_read().await?;
        let count: i64 = crate::on_engine!(tx.conn(), |c| sqlx::query_scalar(RESTORE_ROW_COUNT)
            .fetch_one(&mut *c)
            .await)?;
        tx.finish().await?;
        if count != 0 {
            return Err(RestoreError::TargetNotEmpty.into());
        }
        Ok(())
    }

    /// Loads `dump` into this database, which must be empty (see the module docs for the
    /// steps). `generation` is the new restore generation, freshly drawn by the caller;
    /// `now_ms` stamps the reconciliation epochs.
    ///
    /// # Errors
    ///
    /// - [`Error::Restore`] when the dump is of another schema version, names an unknown table,
    ///   lists tables out of order, leaves a table out, holds a row that does not fit its
    ///   table, or the target is not empty. Nothing was written.
    /// - [`Error::ReadOnly`] on a read-only SQLite handle.
    /// - Those of [`Database::pending_migrations`] (an applied migration this release does not
    ///   know, or whose checksum differs) and [`Database::migrate`], and [`Error::Database`]
    ///   when an insert fails (a duplicate key or a foreign key the dump does not satisfy);
    ///   nothing was written.
    pub async fn restore(
        &self,
        dump: &Dump,
        generation: RestoreGeneration,
        now_ms: i64,
    ) -> Result<RestoreReport, Error> {
        let current = schema_version();
        if dump.schema_version != current {
            return Err(RestoreError::SchemaVersion {
                dump: dump.schema_version,
                current,
            }
            .into());
        }
        let plan = plan(dump)?;
        // A database some release already migrated, but not to this one's schema, is not a
        // new database: refuse before migrating it rather than change it.
        let pending = self.pending_migrations().await?;
        if !pending.is_empty() && !self.applied_migrations().await?.is_empty() {
            return Err(RestoreError::TargetNotEmpty.into());
        }
        self.migrate().await?;

        let mut tx = self.begin_write().await?;
        let count: i64 = crate::on_engine!(tx.conn(), |c| sqlx::query_scalar(RESTORE_ROW_COUNT)
            .fetch_one(&mut *c)
            .await)?;
        if count != 0 {
            return Err(RestoreError::TargetNotEmpty.into());
        }
        let mut rows = 0u64;
        for (spec, table) in plan {
            for row in &table.rows {
                insert_row(tx.conn(), spec, row).await?;
                rows += 1;
            }
        }
        let accounts_in_reconciliation = crate::on_engine!(tx.conn(), |c| {
            sqlx::query(RESTORE_GENERATION_SET)
                .bind(&generation.as_bytes()[..])
                .bind(now_ms)
                .execute(&mut *c)
                .await?;
            let opened = sqlx::query(RECONCILIATION_OPEN_ALL)
                .bind(&generation.as_bytes()[..])
                .bind(now_ms)
                .execute(&mut *c)
                .await?
                .rows_affected();
            sqlx::query(RESTORE_STORE_SEQ).execute(&mut *c).await?;
            opened
        });
        tx.commit().await?;
        Ok(RestoreReport {
            rows,
            accounts_in_reconciliation,
        })
    }
}

/// Matches each table of `dump` to its spec, requiring every table of [`TABLES`], in that
/// order, exactly once (ADR 0011 "Backups": the dump is "every table as rows"; the
/// conservative reading is that a table with no rows is still present, so a truncated dump is
/// refused), and checks every row's shape before anything is written.
fn plan(dump: &Dump) -> Result<Vec<(&'static TableSpec, &TableDump)>, RestoreError> {
    let mut plan = Vec::with_capacity(TABLES.len());
    let mut next = 0usize;
    for (index, table) in dump.tables.iter().enumerate() {
        let position = TABLES
            .iter()
            .position(|s| s.name == table.table)
            .ok_or(RestoreError::UnknownTable { index })?;
        if position < next {
            return Err(RestoreError::TableOrder { index });
        }
        if let Some(skipped) = TABLES.get(next).filter(|_| position > next) {
            return Err(RestoreError::MissingTable { name: skipped.name });
        }
        next = position + 1;
        let spec = TABLES
            .get(position)
            .ok_or(RestoreError::UnknownTable { index })?;
        for (row_index, row) in table.rows.iter().enumerate() {
            check_row(spec, row_index, row)?;
        }
        plan.push((spec, table));
    }
    if let Some(missing) = TABLES.get(next) {
        return Err(RestoreError::MissingTable { name: missing.name });
    }
    Ok(plan)
}

/// Checks one row against its table: one value per column, each of the column's kind, NULL
/// only where the column allows it.
fn check_row(spec: &TableSpec, row_index: usize, row: &[Value]) -> Result<(), RestoreError> {
    if row.len() != spec.columns.len() {
        return Err(RestoreError::Row {
            table: spec.name,
            row: row_index,
            column: None,
        });
    }
    for (column_index, (column, value)) in spec.columns.iter().zip(row).enumerate() {
        let fits = match value {
            Value::Null => column.nullable,
            Value::Integer(_) => column.kind == Kind::Integer,
            Value::Text(_) => column.kind == Kind::Text,
            Value::Blob(_) => column.kind == Kind::Blob,
        };
        if !fits {
            return Err(RestoreError::Row {
                table: spec.name,
                row: row_index,
                column: Some(column_index),
            });
        }
    }
    Ok(())
}

/// Reads every row of one table.
async fn dump_table(conn: Conn<'_>, spec: &TableSpec) -> Result<Vec<Vec<Value>>, Error> {
    Ok(crate::on_engine!(conn, |c| {
        let mut rows = Vec::new();
        for row in sqlx::query(spec.select).fetch_all(&mut *c).await? {
            let mut values = Vec::with_capacity(spec.columns.len());
            for (i, column) in spec.columns.iter().enumerate() {
                let value = match column.kind {
                    Kind::Integer => row.try_get::<Option<i64>, _>(i)?.map(Value::Integer),
                    Kind::Text => row.try_get::<Option<String>, _>(i)?.map(Value::Text),
                    Kind::Blob => row.try_get::<Option<Vec<u8>>, _>(i)?.map(Value::Blob),
                };
                values.push(value.unwrap_or(Value::Null));
            }
            rows.push(values);
        }
        rows
    }))
}

/// Inserts one checked row. NULL is bound with its column's type, so PostgreSQL gets a typed
/// parameter.
async fn insert_row(conn: Conn<'_>, spec: &TableSpec, row: &[Value]) -> Result<(), Error> {
    crate::on_engine!(conn, |c| {
        let mut query = sqlx::query(spec.insert);
        for (column, value) in spec.columns.iter().zip(row) {
            query = match (value, column.kind) {
                (Value::Integer(v), _) => query.bind(*v),
                (Value::Text(v), _) => query.bind(v.as_str()),
                (Value::Blob(v), _) => query.bind(v.as_slice()),
                (Value::Null, Kind::Integer) => query.bind(None::<i64>),
                (Value::Null, Kind::Text) => query.bind(None::<&str>),
                (Value::Null, Kind::Blob) => query.bind(None::<&[u8]>),
            };
        }
        query.execute(&mut *c).await?;
    });
    Ok(())
}

/// Creates `path` as a new, empty file, mode 0600 on Unix. Fails if it exists.
fn create_private_file(path: &Path) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map(drop).map_err(|source| Error::Io {
        action: "create the backup copy",
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_dump() -> Dump {
        Dump {
            schema_version: schema_version(),
            tables: Vec::new(),
        }
    }

    #[test]
    fn plan_refuses_unknown_repeated_and_misordered_tables() {
        let mut d = empty_dump();
        d.tables.push(TableDump {
            table: "auth_sessions".into(),
            rows: vec![],
        });
        assert_eq!(
            plan(&d).err(),
            Some(RestoreError::UnknownTable { index: 0 })
        );

        let t = |name: &str| TableDump {
            table: name.into(),
            rows: vec![],
        };
        let all = || -> Vec<TableDump> { TABLES.iter().map(|s| t(s.name)).collect() };
        let mut swapped = all();
        swapped.swap(3, 4);
        let d = Dump {
            tables: swapped,
            ..empty_dump()
        };
        let skipped = TABLES[3].name;
        assert_eq!(
            plan(&d).err(),
            Some(RestoreError::MissingTable { name: skipped })
        );
        let mut repeated = all();
        repeated.insert(1, t("auth_accounts"));
        let d = Dump {
            tables: repeated,
            ..empty_dump()
        };
        assert_eq!(plan(&d).err(), Some(RestoreError::TableOrder { index: 1 }));
        let d = Dump {
            tables: all(),
            ..empty_dump()
        };
        assert_eq!(plan(&d).map(|p| p.len()), Ok(TABLES.len()));
    }

    #[test]
    fn plan_refuses_a_dump_that_leaves_a_table_out() {
        assert_eq!(
            plan(&empty_dump()).err(),
            Some(RestoreError::MissingTable {
                name: TABLES[0].name
            })
        );
        let t = |name: &str| TableDump {
            table: name.into(),
            rows: vec![],
        };
        for (leave_out, left_out) in TABLES.iter().enumerate() {
            let d = Dump {
                tables: TABLES
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != leave_out)
                    .map(|(_, s)| t(s.name))
                    .collect(),
                ..empty_dump()
            };
            assert_eq!(
                plan(&d).err(),
                Some(RestoreError::MissingTable {
                    name: left_out.name
                }),
                "{}",
                left_out.name
            );
        }
    }

    #[test]
    fn rows_are_checked_against_their_columns() {
        let accounts = TABLES.first().unwrap();
        assert_eq!(accounts.name, "auth_accounts");
        let good = vec![
            Value::Blob(vec![1; 16]),
            Value::Text("alice".into()),
            Value::Integer(1),
        ];
        assert_eq!(check_row(accounts, 0, &good), Ok(()));
        assert!(check_row(accounts, 0, &good[..2]).is_err());
        let mut null = good.clone();
        null[1] = Value::Null;
        assert_eq!(
            check_row(accounts, 3, &null),
            Err(RestoreError::Row {
                table: "auth_accounts",
                row: 3,
                column: Some(1)
            })
        );
        let mut wrong = good;
        wrong[2] = Value::Text("1".into());
        assert!(check_row(accounts, 0, &wrong).is_err());
    }

    #[test]
    fn value_debug_never_shows_content() {
        let v = [
            Value::Blob(b"secret-bytes".to_vec()),
            Value::Text("alice".into()),
            Value::Integer(4242),
        ];
        let s = format!("{v:?}");
        assert!(
            !s.contains("secret") && !s.contains("alice") && !s.contains("4242"),
            "{s}"
        );
    }
}
