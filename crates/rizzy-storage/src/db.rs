//! The database handle: engine dispatch, pools, PRAGMAs and transactions (ADR 0011 points 1
//! and 3, "Transactions and concurrency", "SQLite settings").
//!
//! # Engine dispatch
//!
//! [`Database`] is an enum over the two engines' pools, and every transaction hands out a
//! [`Conn`], an enum over the two engines' connections (ADR 0011 point 3, owner decision 5: not
//! the sqlx `Any` driver, not code generic over `DB: Database`). A repository method matches on
//! it once with [`on_engine!`](crate::on_engine), which expands one body into both arms, so the
//! same query text (a shared `.sql` file with `$N` placeholders) runs on either engine.
//!
//! # SQLite: one writer, many readers
//!
//! - The **writer pool** has exactly one connection, and every write transaction starts with
//!   `BEGIN IMMEDIATE` ([`Database::begin_write`]). The database write lock is then taken at
//!   `BEGIN`, where `busy_timeout` can wait for it, never at a later read-to-write upgrade,
//!   which fails with `SQLITE_BUSY` or `SQLITE_BUSY_SNAPSHOT` however long the timeout is.
//! - The **reader pool** opens the file read-only ([`Database::begin_read`]); in WAL mode its
//!   readers run next to the writer, each transaction on one snapshot.
//! - The writer pool exists only with a [`WriterLock`] for the same file (ADR 0010 §2), which
//!   the [`Database`] owns for as long as any clone of the pool can write. A
//!   database opened with [`Database::open_sqlite_read_only`] (the `backup` reader) has no
//!   writer pool, and [`Database::begin_write`] fails with [`Error::ReadOnly`].
//!
//! The writer's PRAGMAs are ADR 0011's table: `journal_mode = WAL`, `synchronous = FULL`,
//! `foreign_keys = ON`, `busy_timeout = 5000` ms, `secure_delete = ON`, and
//! `auto_vacuum = INCREMENTAL`, which sqlx issues before `journal_mode` on every connect, so it
//! is in force before the first migration creates a table. Readers set `foreign_keys`,
//! `busy_timeout` and `query_only`, and leave the file-level settings to the writer.
//!
//! # PostgreSQL
//!
//! One pool. Write transactions are plain `BEGIN` (READ COMMITTED) plus the per-account lock
//! ([`lock_account`](crate::lock_account)); ADR 0011 rejects SERIALIZABLE. Read transactions are
//! `REPEATABLE READ READ ONLY`, one snapshot per transaction (ADR 0021 §4). A remote server must
//! be reached with `sslmode=verify-full` ([`PostgresOptions`]).
//!
//! # What is logged
//!
//! Nothing by this crate. sqlx logs statement text (never bound values) at debug level, and
//! every value here is a bound parameter (INV-48, INV-53).

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions, PgSslMode};
use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool,
    SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Postgres, Sqlite, Transaction};

use crate::error::{Engine, Error};
use crate::writer_lock::WriterLock;

/// `BEGIN IMMEDIATE`, the start of every SQLite write transaction.
const SQLITE_BEGIN_IMMEDIATE: &str = include_str!("../queries/sqlite/begin_immediate.sql");
/// `BEGIN DEFERRED`, the start of every SQLite read transaction.
const SQLITE_BEGIN_READ: &str = include_str!("../queries/sqlite/begin_read.sql");
/// `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY`, the start of every PostgreSQL read
/// transaction.
const POSTGRES_BEGIN_READ: &str = include_str!("../queries/postgres/begin_read.sql");

/// SQLite's `busy_timeout` (ADR 0011 "SQLite settings": 5000 ms). It covers waiting for the
/// write lock at `BEGIN IMMEDIATE`.
pub const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_millis(5000);

/// Options for an SQLite database. The PRAGMAs are fixed by ADR 0011 and not configurable.
#[derive(Clone, Debug)]
pub struct SqliteOptions {
    /// The database file. It must not live on a network filesystem (ADR 0011).
    pub path: PathBuf,
    /// Connections in the reader pool (at least 1).
    pub max_readers: u32,
    /// How long a caller waits for a pooled connection before failing. The writer pool has one
    /// connection, so this bounds how long a write waits behind other writes.
    pub acquire_timeout: Duration,
}

impl SqliteOptions {
    /// Options for the database at `path`, with 4 readers and a 30 s acquire timeout.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_readers: 4,
            acquire_timeout: Duration::from_secs(30),
        }
    }
}

/// Options for a PostgreSQL database.
///
/// `Debug` shows the host, port, database, TLS mode and pool settings, never the password or
/// the user name (sqlx's own `PgConnectOptions` prints the password in its `Debug`).
#[derive(Clone)]
pub struct PostgresOptions {
    /// Parsed connection options.
    connect: PgConnectOptions,
    /// Connections in the pool.
    pub max_connections: u32,
    /// How long a caller waits for a pooled connection before failing.
    pub acquire_timeout: Duration,
}

impl PostgresOptions {
    /// Parses a `postgres://` URL (ADR 0011 point 1).
    ///
    /// A remote server must be reached with `sslmode=verify-full`: a server that is neither a
    /// Unix socket nor `localhost`, `127.0.0.1` or `::1` is refused with any weaker mode (the
    /// conservative reading of "Remote databases use `sslmode=verify-full`"). sqlx verifies the
    /// server certificate with rustls against the webpki roots, or against `sslrootcert` when
    /// the URL names one.
    ///
    /// The URL carries the database password; it is never logged or put into an error here, and
    /// [`PostgresOptions`]'s `Debug` leaves it out.
    ///
    /// **Implicit inputs (an accepted exception to the crate's paths rule).** sqlx 0.9.0 parses
    /// the URL on top of libpq-style defaults, so settings the URL does not give come from the
    /// environment: `PGHOST`/`PGHOSTADDR`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGSSLMODE`,
    /// `PGSSLROOTCERT` and the other `PG*` variables sqlx reads. And when the URL has no password,
    /// sqlx reads one from the password file `$PGPASSFILE`, or `~/.pgpass` by default. That file
    /// read happens here, while parsing, on a path the caller did not name. It is the documented
    /// libpq behaviour operators expect, and it cannot weaken TLS: the `sslmode` check below
    /// runs on the final, merged value. An operator who wants neither puts every setting,
    /// the password included, into the URL. sqlx also logs, at `warn`, the key and value of any
    /// query parameter it does not recognise, so a misspelt `password=` parameter would be
    /// logged: spell URL parameters exactly, or put the password in the URL's userinfo.
    ///
    /// # Errors
    ///
    /// - [`Error::Database`] when sqlx cannot parse the URL.
    /// - [`Error::InsecurePostgresTls`] for a remote server without `sslmode=verify-full`.
    pub fn from_url(url: &str) -> Result<Self, Error> {
        let connect = PgConnectOptions::from_str(url)?;
        let local = connect.get_socket().is_some()
            || matches!(
                connect.get_host(),
                "localhost" | "127.0.0.1" | "::1" | "[::1]"
            );
        if !local && !matches!(connect.get_ssl_mode(), PgSslMode::VerifyFull) {
            return Err(Error::InsecurePostgresTls);
        }
        Ok(Self {
            connect,
            max_connections: 10,
            acquire_timeout: Duration::from_secs(30),
        })
    }
}

impl fmt::Debug for PostgresOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresOptions")
            .field("host", &self.connect.get_host())
            .field("socket", &self.connect.get_socket())
            .field("port", &self.connect.get_port())
            .field("database", &self.connect.get_database())
            .field("ssl_mode", &self.connect.get_ssl_mode())
            .field("max_connections", &self.max_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .finish_non_exhaustive()
    }
}

/// The SQLite pools of one database file.
#[derive(Clone, Debug)]
pub struct SqlitePools {
    /// The writer pool of exactly one connection; `None` when opened read-only.
    writer: Option<SqlitePool>,
    /// The writer lock the writer pool was opened under (ADR 0010 §2); `None` when opened
    /// read-only. Every clone of the pools shares it, so the lock is released only when the
    /// last clone of the writer pool is dropped, never while a writer connection can still
    /// write.
    _writer_lock: Option<Arc<WriterLock>>,
    /// The read-only reader pool.
    reader: SqlitePool,
}

/// An open database: SQLite (the M1 default) or PostgreSQL. Cheap to clone; clones share the
/// pools.
#[derive(Clone, Debug)]
pub enum Database {
    /// SQLite, with a writer pool of one connection and a read-only reader pool.
    Sqlite(SqlitePools),
    /// PostgreSQL, one pool.
    Postgres(PgPool),
}

/// A connection inside a transaction, by engine. Repository code matches on it with
/// [`on_engine!`](crate::on_engine).
#[derive(Debug)]
pub enum Conn<'a> {
    /// An SQLite connection.
    Sqlite(&'a mut SqliteConnection),
    /// A PostgreSQL connection.
    Postgres(&'a mut PgConnection),
}

/// A transaction of either engine.
#[derive(Debug)]
enum Tx {
    /// SQLite.
    Sqlite(Transaction<'static, Sqlite>),
    /// PostgreSQL.
    Postgres(Transaction<'static, Postgres>),
}

impl Tx {
    /// The connection inside.
    fn conn(&mut self) -> Conn<'_> {
        match self {
            Self::Sqlite(tx) => Conn::Sqlite(tx),
            Self::Postgres(tx) => Conn::Postgres(tx),
        }
    }

    /// Commits.
    async fn commit(self) -> Result<(), Error> {
        match self {
            Self::Sqlite(tx) => tx.commit().await?,
            Self::Postgres(tx) => tx.commit().await?,
        }
        Ok(())
    }

    /// Rolls back.
    async fn rollback(self) -> Result<(), Error> {
        match self {
            Self::Sqlite(tx) => tx.rollback().await?,
            Self::Postgres(tx) => tx.rollback().await?,
        }
        Ok(())
    }
}

/// A write transaction: `BEGIN IMMEDIATE` on the SQLite writer, `BEGIN` on PostgreSQL.
///
/// Every write transaction that reads state and then writes based on it takes the account's
/// lock first, with [`lock_account`](crate::lock_account) (ADR 0011). Dropping it without
/// [`WriteTx::commit`] rolls it back.
#[derive(Debug)]
pub struct WriteTx {
    /// The transaction.
    tx: Tx,
}

impl WriteTx {
    /// The engine this transaction runs on.
    #[must_use]
    pub fn engine(&self) -> Engine {
        match self.tx {
            Tx::Sqlite(_) => Engine::Sqlite,
            Tx::Postgres(_) => Engine::Postgres,
        }
    }

    /// The connection, for a repository method to run its queries on.
    pub fn conn(&mut self) -> Conn<'_> {
        self.tx.conn()
    }

    /// Commits the transaction, which also releases the PostgreSQL account locks it took.
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the commit fails; nothing was written.
    pub async fn commit(self) -> Result<(), Error> {
        self.tx.commit().await
    }

    /// Rolls the transaction back.
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the rollback statement fails.
    pub async fn rollback(self) -> Result<(), Error> {
        self.tx.rollback().await
    }
}

/// A read transaction: one consistent snapshot (ADR 0021 §4). On SQLite it runs on the
/// read-only reader pool, on PostgreSQL as `REPEATABLE READ READ ONLY`. Dropping it ends it.
#[derive(Debug)]
pub struct ReadTx {
    /// The transaction.
    tx: Tx,
}

impl ReadTx {
    /// The engine this transaction runs on.
    #[must_use]
    pub fn engine(&self) -> Engine {
        match self.tx {
            Tx::Sqlite(_) => Engine::Sqlite,
            Tx::Postgres(_) => Engine::Postgres,
        }
    }

    /// The connection, for a repository method to run its queries on.
    pub fn conn(&mut self) -> Conn<'_> {
        self.tx.conn()
    }

    /// Ends the transaction.
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the closing statement fails.
    pub async fn finish(self) -> Result<(), Error> {
        self.tx.commit().await
    }
}

/// Runs one body on either engine: `on_engine!(conn, |c| body)` expands `body` twice, once with
/// `c: &mut SqliteConnection` and once with `c: &mut PgConnection`, so the two arms stay
/// identical (ADR 0011 point 3). `conn` is a [`Conn`].
///
/// ```ignore
/// const Q: &str = include_str!("../queries/storage/reconciliation_end.sql");
/// let n = on_engine!(tx.conn(), |c| sqlx::query(Q)
///     .bind(&account_id[..])
///     .execute(&mut *c)
///     .await
///     .map(|r| r.rows_affected()))?;
/// ```
#[macro_export]
macro_rules! on_engine {
    ($conn:expr, |$c:ident| $body:expr) => {
        match $conn {
            $crate::Conn::Sqlite($c) => $body,
            $crate::Conn::Postgres($c) => $body,
        }
    };
}

impl Database {
    /// Opens (creating it if missing) the SQLite database at `options.path`, with its writer
    /// pool of one connection and its read-only reader pool. `lock` must be the writer lock
    /// for the same path (ADR 0010 §2). The database takes ownership of it and holds it for as
    /// long as any clone of the returned [`Database`] lives: the lock outlives every writer
    /// connection, so no second process can take it and write the file meanwhile. On an error
    /// the lock is dropped, and so released.
    ///
    /// This does not migrate: call [`Database::migrate_at_startup`] or [`Database::migrate`].
    ///
    /// # Errors
    ///
    /// - [`Error::WriterLockMismatch`] when `lock` is for another file.
    /// - [`Error::Database`] when a connection cannot be opened or a PRAGMA fails.
    pub async fn open_sqlite(options: &SqliteOptions, lock: WriterLock) -> Result<Self, Error> {
        if !lock.is_for(&options.path) {
            return Err(Error::WriterLockMismatch);
        }
        let writer = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .acquire_timeout(options.acquire_timeout)
            .connect_with(writer_options(&options.path))
            .await?;
        let reader = reader_pool(options).await?;
        Ok(Self::Sqlite(SqlitePools {
            writer: Some(writer),
            _writer_lock: Some(Arc::new(lock)),
            reader,
        }))
    }

    /// Opens an existing SQLite database read-only, with a reader pool and no writer: the
    /// `backup` reader, which runs next to the running server and takes no writer lock (ADR
    /// 0010 §2, ADR 0011 "Backups").
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the file does not exist or cannot be opened.
    pub async fn open_sqlite_read_only(options: &SqliteOptions) -> Result<Self, Error> {
        let reader = reader_pool(options).await?;
        Ok(Self::Sqlite(SqlitePools {
            writer: None,
            _writer_lock: None,
            reader,
        }))
    }

    /// Connects to PostgreSQL. Does not migrate: on PostgreSQL migrations run only
    /// explicitly (ADR 0011 point 9).
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the server cannot be reached or refuses the connection.
    pub async fn open_postgres(options: &PostgresOptions) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(options.max_connections.max(1))
            .acquire_timeout(options.acquire_timeout)
            .connect_with(options.connect.clone())
            .await?;
        Ok(Self::Postgres(pool))
    }

    /// The engine.
    #[must_use]
    pub fn engine(&self) -> Engine {
        match self {
            Self::Sqlite(_) => Engine::Sqlite,
            Self::Postgres(_) => Engine::Postgres,
        }
    }

    /// Starts a write transaction: `BEGIN IMMEDIATE` on the SQLite writer (waiting up to
    /// `busy_timeout` for the write lock, and for the one writer connection up to the acquire
    /// timeout), `BEGIN` on PostgreSQL.
    ///
    /// # Errors
    ///
    /// - [`Error::ReadOnly`] on a database opened with [`Database::open_sqlite_read_only`].
    /// - [`Error::Database`] when no connection or no write lock could be had in time.
    pub async fn begin_write(&self) -> Result<WriteTx, Error> {
        let tx = match self {
            Self::Sqlite(pools) => {
                let writer = pools.writer.as_ref().ok_or(Error::ReadOnly)?;
                Tx::Sqlite(writer.begin_with(SQLITE_BEGIN_IMMEDIATE).await?)
            }
            Self::Postgres(pool) => Tx::Postgres(pool.begin().await?),
        };
        Ok(WriteTx { tx })
    }

    /// Starts a read transaction on one consistent snapshot (ADR 0021 §4).
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when no connection could be had in time.
    pub async fn begin_read(&self) -> Result<ReadTx, Error> {
        let tx = match self {
            Self::Sqlite(pools) => Tx::Sqlite(pools.reader.begin_with(SQLITE_BEGIN_READ).await?),
            Self::Postgres(pool) => Tx::Postgres(pool.begin_with(POSTGRES_BEGIN_READ).await?),
        };
        Ok(ReadTx { tx })
    }

    /// Closes every pool, waiting for checked-out connections to return.
    pub async fn close(&self) {
        match self {
            Self::Sqlite(pools) => {
                if let Some(writer) = &pools.writer {
                    writer.close().await;
                }
                pools.reader.close().await;
            }
            Self::Postgres(pool) => pool.close().await,
        }
    }

    /// The SQLite writer pool (`None` on PostgreSQL). For crate-internal statements that
    /// cannot run inside a transaction (`VACUUM INTO`, the migrator).
    pub(crate) fn sqlite_writer(&self) -> Result<Option<&SqlitePool>, Error> {
        match self {
            Self::Sqlite(pools) => pools.writer.as_ref().map(Some).ok_or(Error::ReadOnly),
            Self::Postgres(_) => Ok(None),
        }
    }
}

/// The writer's connect options: ADR 0011's PRAGMA table, and create the file if missing.
fn writer_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .auto_vacuum(SqliteAutoVacuum::Incremental)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .pragma("secure_delete", "ON")
}

/// The reader pool: read-only connections to an existing file, `query_only` on.
async fn reader_pool(options: &SqliteOptions) -> Result<SqlitePool, Error> {
    let connect = SqliteConnectOptions::new()
        .filename(&options.path)
        .read_only(true)
        .create_if_missing(false)
        .foreign_keys(true)
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .pragma("query_only", "ON");
    Ok(SqlitePoolOptions::new()
        .max_connections(options.max_readers.max(1))
        .acquire_timeout(options.acquire_timeout)
        .connect_with(connect)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_options_debug_leaves_out_the_password() {
        let opts = PostgresOptions::from_url("postgres://rv:s3cret@localhost:5433/vault").unwrap();
        let debug = format!("{opts:?}");
        assert!(!debug.contains("s3cret"), "{debug}");
        assert!(
            debug.contains("localhost") && debug.contains("5433"),
            "{debug}"
        );
    }
}
