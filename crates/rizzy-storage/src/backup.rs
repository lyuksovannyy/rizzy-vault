// SPDX-License-Identifier: AGPL-3.0-only

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
//! - **The streaming restore** ([ADR 0094] §3): [`Database::restore_from`] reads a file pass 1
//!   ([`file::Verifier`]) verified, again from the start, through the incremental
//!   [`file::Decoder`], inserting each row as it is decoded, with the caller's pre-commit check
//!   on every row; a file whose bytes changed between the passes is refused
//!   ([`file::FileError::Changed`]) and nothing is written.
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
//! [ADR 0094]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0094-backup-container-limits.md

pub mod file;

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use sqlx::Row;

use crate::db::{Conn, Database, WriteTx};
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

/// What [`Database::dump_to`] wrote.
#[derive(Debug)]
pub struct Dumped<W> {
    /// The output `open` returned, flushed.
    pub out: W,
    /// The format version 1 file's length, `L1`.
    pub len: u64,
    /// The format version 1 file's trailing SHA-256.
    pub digest: [u8; file::DIGEST_LEN],
    /// The schema version the file is stamped with.
    pub schema_version: i64,
}

/// Why [`Database::dump_to`] failed.
#[derive(Debug)]
pub enum DumpError<E> {
    /// Reading the database failed, or it is not at this release's schema.
    Storage(Error),
    /// The encoder refused a value, or the output failed.
    File(file::FileError),
    /// `open` refused after pass 1, before anything was output.
    Open(E),
    /// Pass 2 saw another number of rows or bytes than pass 1: the two passes did not see one
    /// snapshot (ADR 0094 §2 point 3).
    SnapshotChanged,
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

    /// Streams the database as a backup file (format version 1) in two passes over one read
    /// snapshot ([ADR 0094] §2), holding neither the file nor the [`Dump`].
    ///
    /// In the one read transaction [`Database::dump`] uses, and after the same schema checks:
    /// pass 1 runs every row through the [`file::Encoder`] into a discarding sink, recording
    /// each table's row count and the file's length `L1`. Then `open(L1)` is called: it
    /// decides on the output's length (for format version 2, ADR 0071's `sealed_len(L1)`),
    /// refuses one over the limit, and only then creates the output. Pass 2 writes the file to
    /// it with pass 1's row counts and an encoder limit of exactly `L1` bytes.
    ///
    /// # Errors
    ///
    /// - [`DumpError::Storage`] as [`Database::dump`].
    /// - [`DumpError::File`] when the encoder refuses a value, or the output fails
    ///   ([`file::FileError::Write`]).
    /// - [`DumpError::Open`] when `open` refuses: nothing was output.
    /// - [`DumpError::SnapshotChanged`] when pass 2 saw another number of rows or bytes
    ///   than pass 1. The output then holds a partial file the caller must remove or discard.
    ///
    /// [ADR 0094]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0094-backup-container-limits.md
    pub async fn dump_to<W: Write, E>(
        &self,
        created_at_ms: u64,
        open: impl FnOnce(u64) -> Result<W, E>,
    ) -> Result<Dumped<W>, DumpError<E>> {
        let mut tx = self.begin_read().await.map_err(DumpError::Storage)?;
        let applied = applied_on(tx.conn()).await.map_err(DumpError::Storage)?;
        let pending = check_applied(self.engine(), &applied).map_err(DumpError::Storage)?;
        if !pending.is_empty() {
            return Err(DumpError::Storage(Error::SchemaNotCurrent { pending }));
        }
        let schema_version = schema_version();
        // Pass 1 (sizing): no limit here, so the caller learns the exact length it refuses.
        let mut counter =
            file::Encoder::with_limit(std::io::sink(), schema_version, created_at_ms, u64::MAX)
                .map_err(DumpError::File)?;
        let mut counts = Vec::with_capacity(TABLES.len());
        for spec in TABLES {
            counter.table_unsized().map_err(DumpError::File)?;
            each_row(tx.conn(), spec, |row| counter.row(&row))
                .await
                .map_err(DumpError::Storage)?
                .map_err(DumpError::File)?;
            counts.push(counter.table_rows());
        }
        let (_, _, plain_len) = counter.finish().map_err(DumpError::File)?;
        let out = open(plain_len).map_err(DumpError::Open)?;
        // Pass 2 (writing): a row or byte more or less than pass 1 counted is a changed
        // snapshot.
        let changed = |e: file::FileError| match e {
            file::FileError::RowCount { .. } | file::FileError::TooLarge => {
                DumpError::SnapshotChanged
            }
            e => DumpError::File(e),
        };
        let mut encoder = file::Encoder::with_limit(out, schema_version, created_at_ms, plain_len)
            .map_err(changed)?;
        for (spec, &count) in TABLES.iter().zip(&counts) {
            encoder.table(count).map_err(changed)?;
            each_row(tx.conn(), spec, |row| encoder.row(&row))
                .await
                .map_err(DumpError::Storage)?
                .map_err(changed)?;
        }
        let (out, digest, len) = encoder.finish().map_err(changed)?;
        if len != plain_len {
            return Err(DumpError::SnapshotChanged);
        }
        tx.finish().await.map_err(DumpError::Storage)?;
        Ok(Dumped {
            out,
            len,
            digest,
            schema_version,
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
        check_schema(dump.schema_version)?;
        let plan = plan(dump)?;
        let mut tx = self.begin_restore().await?;
        let mut rows = 0u64;
        for (spec, table) in plan {
            for row in &table.rows {
                insert_row(tx.conn(), spec, row).await?;
                rows += 1;
            }
        }
        finish_restore(tx, generation, now_ms, rows).await
    }

    /// Loads a backup file into this database, which must be empty, streaming: pass 2 of the
    /// reader (ADR 0094 §3 point 3; ADR 0023 §5 step 5 as ADR 0094 §5(b) replaces it).
    /// `verified` is pass 1's result over the same file; `read` hands over the format version
    /// 1 file's bytes again from the start, like [`std::io::Read::read`] (0 at the end).
    /// Inside one write transaction, each row is checked by [`file::Decoder`], handed to
    /// `check` (the caller's pre-commit check, ADR 0023 §5 step 4: an error rolls back) and
    /// inserted as it is decoded; then the header bytes and the digest must equal pass 1's,
    /// `read` must have nothing more, and only then are the generation, the reconciliation
    /// epochs and the counters set and the transaction committed. At most one read buffer and
    /// one row are held.
    ///
    /// The bytes read are also hashed as they arrive, so a refusal partway (a malformed row,
    /// a failed insert, a refused check) on bytes other than pass 1's reads the rest and is
    /// reported as [`file::FileError::Changed`], what it is, rather than as its symptom.
    ///
    /// # Errors
    ///
    /// Any error rolls the whole transaction back: nothing was written.
    /// - [`RestoreFromError::Storage`]: those of [`Database::restore`] (the schema version,
    ///   a target that is not empty, a failed insert).
    /// - [`RestoreFromError::File`]: the strict parser's refusals, and
    ///   [`file::FileError::Changed`] when the bytes differ from pass 1's, or there are more or
    ///   fewer of them.
    /// - [`RestoreFromError::Caller`]: what `read` or `check` returned.
    pub async fn restore_from<E>(
        &self,
        verified: &file::Verified,
        read: impl FnMut(&mut [u8]) -> Result<usize, E>,
        mut check: impl FnMut(&'static TableSpec, &[Value]) -> Result<(), E>,
        generation: RestoreGeneration,
        now_ms: i64,
    ) -> Result<RestoreReport, RestoreFromError<E>> {
        use RestoreFromError::{Caller, File, Storage};
        check_schema(verified.schema_version()).map_err(Storage)?;
        let mut tx = self.begin_restore().await.map_err(Storage)?;
        let mut source = Source {
            read,
            hash: file::Verifier::new(verified.file_len()).map_err(File)?,
            len: verified.file_len(),
            received: 0,
            read_failed: false,
        };
        let mut decoder = file::Decoder::new(verified);
        // `buf[start..end]` holds the bytes read and not used yet; it grows only for an item
        // longer than it.
        let mut buf = vec![0u8; READ_LEN];
        let (mut start, mut end) = (0usize, 0usize);
        let mut table = None;
        let mut rows = 0u64;
        let outcome: Result<(), RestoreFromError<E>> = async {
            loop {
                let input = buf.get(start..end).unwrap_or_default();
                let (used, event) = decoder.decode(input).map_err(File)?;
                start += used;
                match event {
                    Some(file::Event::Table { spec, .. }) => table = Some(spec),
                    Some(file::Event::Row(row)) => {
                        let spec = table.ok_or(File(file::FileError::Changed))?;
                        check(spec, &row).map_err(Caller)?;
                        insert_row(tx.conn(), spec, &row).await.map_err(Storage)?;
                        rows += 1;
                    }
                    Some(file::Event::End) => break,
                    None => {
                        // Keep what was not used and read more after it.
                        buf.copy_within(start..end, 0);
                        end -= start;
                        start = 0;
                        if end == buf.len() {
                            buf.resize(end.saturating_mul(2), 0);
                        }
                        let got = source.fill(buf.get_mut(end..).unwrap_or_default())?;
                        if got == 0 {
                            return Err(File(file::FileError::Changed));
                        }
                        end += got;
                    }
                }
            }
            // Nothing may follow the bytes pass 1 verified.
            if start < end || source.fill(&mut [0u8; 1])? != 0 {
                return Err(File(file::FileError::Changed));
            }
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => finish_restore(tx, generation, now_ms, rows)
                .await
                .map_err(Storage),
            Err(e) => Err(source.classify(e, verified)),
        }
    }

    /// The start of a restore: refuses a target some release migrated to another schema,
    /// migrates it, opens the one write transaction and requires the target to hold no row.
    async fn begin_restore(&self) -> Result<WriteTx, Error> {
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
        Ok(tx)
    }
}

/// The read buffer of [`Database::restore_from`].
const READ_LEN: usize = 64 * 1024;

/// [`Database::restore_from`]'s source: the caller's `read`, capped at the verified length,
/// with every byte also hashed ([`file::Verifier`]) to tell a changed file from a bad one.
struct Source<R> {
    /// The caller's `read`.
    read: R,
    /// Pass 1's checks again, over the bytes read.
    hash: file::Verifier,
    /// The verified length.
    len: u64,
    /// The bytes read so far.
    received: u64,
    /// Whether `read` failed: that error is the caller's own, reported as it is.
    read_failed: bool,
}

impl<R, E> Source<R>
where
    R: FnMut(&mut [u8]) -> Result<usize, E>,
{
    /// Reads into `out`, at most up to the verified length and one byte past it (so that a
    /// longer file shows); returns how many bytes it read.
    fn fill(&mut self, out: &mut [u8]) -> Result<usize, RestoreFromError<E>> {
        let left = self.len.saturating_sub(self.received);
        let want = usize::try_from(left).map_or(out.len(), |n| n.max(1).min(out.len()));
        let out = out.get_mut(..want).unwrap_or_default();
        let got = match (self.read)(out) {
            Ok(n) => n.min(want),
            Err(e) => {
                self.read_failed = true;
                return Err(RestoreFromError::Caller(e));
            }
        };
        self.received += u64::try_from(got).unwrap_or(u64::MAX);
        self.hash
            .update(out.get(..got).unwrap_or_default())
            .map_err(RestoreFromError::File)?;
        Ok(got)
    }

    /// The error to report for `e`: [`file::FileError::Changed`] when the bytes are not pass
    /// 1's (read to the end to know), otherwise `e` itself.
    fn classify(
        mut self,
        e: RestoreFromError<E>,
        verified: &file::Verified,
    ) -> RestoreFromError<E> {
        if self.read_failed || matches!(e, RestoreFromError::File(file::FileError::Changed)) {
            return e;
        }
        let mut scratch = vec![0u8; READ_LEN];
        while self.received < self.len {
            match self.fill(&mut scratch) {
                Ok(0) => break,
                Ok(_) => {}
                Err(RestoreFromError::File(changed)) => return RestoreFromError::File(changed),
                Err(_) => return e,
            }
        }
        match self.hash.finish() {
            Ok(again) if again == *verified => e,
            _ => RestoreFromError::File(file::FileError::Changed),
        }
    }
}

/// Why [`Database::restore_from`] failed. The target then holds no application row.
#[derive(Debug)]
pub enum RestoreFromError<E> {
    /// The database refused (see [`Database::restore`]).
    Storage(Error),
    /// The file is refused, or changed between the passes ([`file::FileError::Changed`]).
    File(file::FileError),
    /// The caller's `read` or `check` failed.
    Caller(E),
}

/// Requires a dump or file of this release's schema version (ADR 0023 §5 step 3).
fn check_schema(dump: i64) -> Result<(), Error> {
    let current = schema_version();
    if dump != current {
        return Err(RestoreError::SchemaVersion { dump, current }.into());
    }
    Ok(())
}

/// The end of a restore, in its transaction: the new generation, a reconciliation epoch for
/// every restored account (INV-59), the store-sequence counters; then the commit.
async fn finish_restore(
    mut tx: WriteTx,
    generation: RestoreGeneration,
    now_ms: i64,
    rows: u64,
) -> Result<RestoreReport, Error> {
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
    let mut rows = Vec::new();
    each_row(conn, spec, |row| {
        rows.push(row);
        Ok(())
    })
    .await?
    .unwrap_or_else(|never: core::convert::Infallible| match never {});
    Ok(rows)
}

/// Hands every row of one table, in its `select` order, to `f`, one at a time; stops at the
/// first error `f` returns and returns it as the inner error.
///
/// The rows come from sqlx's row stream (`fetch`), polled through `futures_core::Stream`
/// one row at a time, so neither the driver nor this function holds a whole table
/// (ADR 0094 §2: never `fetch_all`).
async fn each_row<X>(
    conn: Conn<'_>,
    spec: &TableSpec,
    mut f: impl FnMut(Vec<Value>) -> Result<(), X>,
) -> Result<Result<(), X>, Error> {
    Ok(crate::on_engine!(conn, |c| {
        let mut outcome = Ok(());
        let mut stream = sqlx::query(spec.select).fetch(&mut *c);
        while let Some(row) =
            core::future::poll_fn(|cx| futures_core::Stream::poll_next(stream.as_mut(), cx)).await
        {
            let row = row?;
            let mut values = Vec::with_capacity(spec.columns.len());
            for (i, column) in spec.columns.iter().enumerate() {
                let value = match column.kind {
                    Kind::Integer => row.try_get::<Option<i64>, _>(i)?.map(Value::Integer),
                    Kind::Text => row.try_get::<Option<String>, _>(i)?.map(Value::Text),
                    Kind::Blob => row.try_get::<Option<Vec<u8>>, _>(i)?.map(Value::Blob),
                };
                values.push(value.unwrap_or(Value::Null));
            }
            outcome = f(values);
            if outcome.is_err() {
                break;
            }
        }
        outcome
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
            Value::Null,
        ];
        assert_eq!(check_row(accounts, 0, &good), Ok(()));
        assert!(check_row(accounts, 0, &good[..3]).is_err());
        // `last_recovery_at_ms` is nullable (ADR 0045), an integer when set.
        let mut stamped = good.clone();
        stamped[3] = Value::Integer(7);
        assert_eq!(check_row(accounts, 0, &stamped), Ok(()));
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
