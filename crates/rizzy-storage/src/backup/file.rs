// SPDX-License-Identifier: AGPL-3.0-only

//! The logical backup file, format version 1 ([ADR 0023]): the canonical writer and the strict
//! parser of the bytes `rizzy-vault backup` writes and `rizzy-vault restore` reads.
//!
//! # Layout (ADR 0023 §1)
//!
//! Notation of CRYPTO.md §2: big-endian fixed-width integers, `bytes(x) = u32(len(x)) ‖ x`,
//! `str(x) = bytes(UTF-8(x))`; `i64` is two's complement in 8 bytes, big-endian.
//!
//! ```text
//! file    = header ‖ table{table_count} ‖ digest
//! header  = magic ‖ u16(format_version) ‖ u64(schema_version) ‖ u64(created_at_ms) ‖ u16(table_count)
//! magic   = "rizzy-vault-db-backup" ‖ 0x00                      (22 bytes)
//! table   = str(table_name) ‖ u16(column_count) ‖ column{column_count} ‖ u64(row_count) ‖ row{row_count}
//! column  = str(column_name) ‖ u8(kind) ‖ u8(nullable)      kind: 1 integer, 2 text, 3 blob
//! row     = value{column_count}
//! value   = 0x00 (NULL) | 0x01 ‖ i64 | 0x02 ‖ str(text) | 0x03 ‖ bytes(blob)
//! digest  = SHA-256(every preceding byte of the file)          (32 bytes, the last of the file)
//! ```
//!
//! - Tables appear in [`TABLES`] order, each exactly once, an empty one included; the column
//!   descriptors must equal [`TableSpec::columns`] exactly (name, kind, nullability, order).
//! - The encoding is canonical: one [`Dump`] and one `created_at_ms` give exactly one file, and
//!   every file [`parse`] accepts is the one [`write()`] produces from what it returns.
//!
//! # Integrity, not authentication (ADR 0023 §2)
//!
//! [`parse`] checks the magic and the format version, then the trailing SHA-256 over the whole
//! file, **before** it parses anything else. The digest detects truncation and corruption; it
//! is not a MAC, since anyone who can write the file can recompute it. A tampered backup is a
//! malicious server database (threat model A2, A3), which the clients' signature, rollback and
//! chain checks defend against. The file is not encrypted: it holds what the database holds
//! (ciphertext, signed statements, hashes, OPAQUE records, sealed TOTP secrets and the clear
//! metadata of threat model §3.4) and never the server secrets (INV-50).
//!
//! # Limits (ADR 0023 §3)
//!
//! - The whole file: [`MAX_BACKUP_FILE_LEN`], 1 TiB ([ADR 0094] §1), for every file this
//!   release writes and every one it reads from a regular file. [`write()`] refuses to produce
//!   a longer file, so no backup this release writes is one it cannot read from a file. The
//!   in-memory [`parse`] (and so stdin, a path that is not a regular file and the fuzz target)
//!   reads at most [`MAX_IN_MEMORY_BACKUP_LEN`], 2 GiB.
//! - A text value: [`MAX_TEXT_LEN`] (4 KiB). A blob value: [`MAX_BLOB_LEN`] (32 MiB), at least
//!   every `rizzy-proto` limit on a stored value (asserted by a test in `rizzy-domain-vault`,
//!   the crate that sees both). A name: 1–[`MAX_NAME_LEN`] bytes of `[a-z0-9_]`. At most
//!   [`MAX_COLUMNS`] columns.
//! - No allocation is sized by a declared count or length before the bytes are there: a length
//!   is checked against its limit and the remaining input first, and a table's `row_count`
//!   times the smallest encoded row of that table (at least `column_count` bytes) must fit in
//!   the remaining input before its row vector is reserved. That bound is at least as strict
//!   as ADR 0023's `row_count × column_count`; a file the writer produces always meets it.
//!   Memory stays proportional to the file: a decoded [`Value`] is 32 bytes and the smallest
//!   encoded one 1 byte (a NULL), but the smallest encoded row of every backed-up table is at
//!   least a sixteenth of its decoded values (at most 2 nullable columns out of at least 3, or,
//!   for `auth_security_events`, 7 nullable out of 13 beside two blobs and four integers), so a
//!   row decodes to at most 16 times its encoded size.
//!
//! The parser is pure (no I/O), never panics, and its errors name the table index, the row and
//! the column, never a value (INV-48).
//!
//! # Reading in two passes ([ADR 0094] §3)
//!
//! A file need not be held in memory: [`Verifier`] (pass 1) takes its bytes in pieces of any
//! size, checks the magic and format version, streams the digest and keeps only the fixed
//! header and the digest ([`Verified`]); [`Decoder`] (pass 2) is a sans-I/O incremental decoder
//! over the same bytes, read again: it yields each table's descriptor and each row, holds no
//! input itself, and refuses with [`FileError::Changed`] bytes that are not the ones pass 1
//! verified. [`parse`] is the two of them over a buffer, so the fuzz target exercises them.
//!
//! # Tests and fuzzing
//!
//! The unit tests round-trip a populated dump byte for byte, pin the committed known-answer file
//! `tests/vectors/db_backup_v1.bin` (a small dump, every table, a NULL, text and a blob), and
//! refuse every truncation and every single-byte change of it (the digest recomputed, so the
//! structural checks behind it are reached). The fuzz target `db_backup_parse` (`fuzz/`) feeds
//! arbitrary bytes, with and without a valid digest, and round-trips dumps built from them.
//!
//! [ADR 0023]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0023-logical-backup-format.md
//! [ADR 0094]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0094-backup-container-limits.md

use core::fmt;
use std::io::Write;

use sha2::{Digest as _, Sha256};

use super::{Dump, TableDump, Value, check_row, plan};
use crate::error::RestoreError;
use crate::tables::{Column, Kind, TABLES, TableSpec};

/// The 22-byte magic: the ASCII bytes `rizzy-vault-db-backup` and one `0x00` (ADR 0023 §1).
pub const MAGIC: [u8; 22] = *b"rizzy-vault-db-backup\0";

/// The one format version this reader and writer implement. A new layout is a new version,
/// decided by an ADR (ADR 0023 §1).
pub const FORMAT_VERSION: u16 = 1;

/// The longest backup file this release writes, and reads from a regular file: 2^40 bytes
/// (1 TiB), format version 1 or 2 ([ADR 0094] §1, replacing ADR 0023 §3's 2 GiB). A `u64`,
/// since 1 TiB does not fit a 32-bit `usize`; every comparison with a file length or
/// `plaintext_len` is made in `u64`.
pub const MAX_BACKUP_FILE_LEN: u64 = 1 << 40;

/// The longest backup this release holds in memory: 2^31 bytes (2 GiB, ADR 0094 §1). It caps
/// [`parse`], a backup read from stdin or from a path that is not a regular file, and the fuzz
/// target.
pub const MAX_IN_MEMORY_BACKUP_LEN: usize = 1 << 31;

/// The longest text value: 4 KiB. The only text column is `auth_accounts.login_name`, at most
/// 254 bytes (CRYPTO.md §2).
pub const MAX_TEXT_LEN: usize = 4 * 1024;

/// The longest blob value: 32 MiB, at least every `rizzy-proto` limit on a stored value (the
/// largest is an envelope of a 16 MiB plaintext).
pub const MAX_BLOB_LEN: usize = 32 * 1024 * 1024;

/// The longest table or column name, in bytes.
pub const MAX_NAME_LEN: usize = 63;

/// The most columns a table may declare.
pub const MAX_COLUMNS: usize = 64;

/// Length of the trailing SHA-256 digest.
pub const DIGEST_LEN: usize = 32;

/// Length of the header: magic, `format_version`, `schema_version`, `created_at_ms`,
/// `table_count`.
const HEADER_LEN: usize = MAGIC.len() + 2 + 8 + 8 + 2;

/// The value tags (ADR 0023 §1).
mod tag {
    /// SQL NULL.
    pub(super) const NULL: u8 = 0x00;
    /// An `i64`.
    pub(super) const INTEGER: u8 = 0x01;
    /// `str(text)`.
    pub(super) const TEXT: u8 = 0x02;
    /// `bytes(blob)`.
    pub(super) const BLOB: u8 = 0x03;
}

/// A parsed backup file: the dump and the informational creation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupFile {
    /// When `backup` wrote the file, in Unix milliseconds by the writer's clock. Informational
    /// only: never trusted for anything (ADR 0023 §1).
    pub created_at_ms: u64,
    /// The tables and rows, stamped with the schema version.
    pub dump: Dump,
}

/// Where in the file a problem is: the table's index in the file, the row's index in the table,
/// the column's index in the row or the table's column list. Never a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Location {
    /// The table's position in the file (0-based).
    pub table: Option<usize>,
    /// The row's position in its table (0-based).
    pub row: Option<u64>,
    /// The column's position (0-based).
    pub column: Option<usize>,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut part = |f: &mut fmt::Formatter<'_>, name: &str, index: String| {
            let sep = if first { "" } else { ", " };
            first = false;
            write!(f, "{sep}{name} {index}")
        };
        if let Some(t) = self.table {
            part(f, "table", t.to_string())?;
        }
        if let Some(r) = self.row {
            part(f, "row", r.to_string())?;
        }
        if let Some(c) = self.column {
            part(f, "column", c.to_string())?;
        }
        if first {
            f.write_str("header")?;
        }
        Ok(())
    }
}

/// What is wrong at a [`Location`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Problem {
    /// A field or a declared length runs past the end of the tables.
    UnexpectedEnd,
    /// A name is empty, longer than [`MAX_NAME_LEN`], or has a byte outside `[a-z0-9_]`.
    Name,
    /// The table is not the one this release expects at this position.
    Table,
    /// The column count exceeds [`MAX_COLUMNS`] or differs from this release's.
    ColumnCount,
    /// A column descriptor differs from this release's (name, kind or nullability), or has an
    /// unknown kind or nullability byte.
    Column,
    /// The declared row count cannot fit in the remaining bytes.
    RowCount,
    /// A value's tag is unknown, does not match its column's kind, or is NULL in a NOT NULL
    /// column.
    Tag,
    /// A text value is longer than [`MAX_TEXT_LEN`].
    TextTooLong,
    /// A blob value is longer than [`MAX_BLOB_LEN`].
    BlobTooLong,
    /// A text value is not valid UTF-8.
    Utf8,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnexpectedEnd => "unexpected end of data",
            Self::Name => "invalid name",
            Self::Table => "not the table this release expects here",
            Self::ColumnCount => "wrong column count",
            Self::Column => "column descriptor does not match this release's schema",
            Self::RowCount => "row count larger than the remaining data",
            Self::Tag => "value tag does not fit the column",
            Self::TextTooLong => "text value too long",
            Self::BlobTooLong => "blob value too long",
            Self::Utf8 => "text value is not UTF-8",
        })
    }
}

/// Why a backup file could not be read or written. `Display` names what failed and where,
/// never a value (INV-48).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileError {
    /// The file is longer than [`MAX_BACKUP_FILE_LEN`] (or, for the in-memory [`parse`],
    /// [`MAX_IN_MEMORY_BACKUP_LEN`]), or writing it would make it so.
    TooLarge,
    /// The file is shorter than a header and a digest.
    Truncated,
    /// The file does not start with [`MAGIC`]: not a rizzy-vault database backup.
    BadMagic,
    /// The file is of a format version this release does not implement.
    UnsupportedFormat {
        /// The file's format version.
        version: u16,
    },
    /// The trailing SHA-256 does not match the file: it is truncated, corrupted or has bytes
    /// appended.
    DigestMismatch,
    /// The schema version is 0 or above `i64::MAX` (ADR 0023 §1).
    SchemaVersion,
    /// The file declares another number of tables than this release backs up.
    TableCount {
        /// The declared count.
        found: u16,
    },
    /// A structural problem inside the tables.
    Malformed {
        /// Where.
        at: Location,
        /// What.
        problem: Problem,
    },
    /// Bytes remain between the last table and the digest.
    TrailingBytes,
    /// Writing: the dump does not fit this release's tables (see [`RestoreError`]).
    Dump(RestoreError),
    /// Writing: a text or blob value exceeds its limit.
    ValueTooLarge {
        /// Where.
        at: Location,
    },
    /// Writing: a table got another number of rows than its declared `row_count`
    /// ([`Encoder`]).
    RowCount {
        /// The table's position in the file (0-based).
        table: usize,
    },
    /// Writing: the byte sink failed.
    Write(std::io::ErrorKind),
    /// Reading in two passes: the bytes of the second pass differ from those the first
    /// verified, or there are more or fewer of them (ADR 0094 §3 point 4).
    Changed,
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(
                f,
                "the backup file is larger than this release's limit (at most \
                 {MAX_BACKUP_FILE_LEN} bytes from a file, {MAX_IN_MEMORY_BACKUP_LEN} bytes in memory)"
            ),
            Self::Truncated => f.write_str("the backup file is truncated"),
            Self::BadMagic => f.write_str("not a rizzy-vault database backup file"),
            Self::UnsupportedFormat { version } => write!(
                f,
                "backup format version {version} is not supported by this release (it reads \
                 version {FORMAT_VERSION})"
            ),
            Self::DigestMismatch => f.write_str(
                "the backup file's SHA-256 does not match: it is truncated or corrupted",
            ),
            Self::SchemaVersion => f.write_str("the backup's schema version is out of range"),
            Self::TableCount { found } => write!(
                f,
                "the backup has {found} tables, this release backs up {}",
                TABLES.len()
            ),
            Self::Malformed { at, problem } => write!(f, "malformed backup at {at}: {problem}"),
            Self::TrailingBytes => f.write_str("the backup has bytes after its last table"),
            Self::Dump(e) => write!(f, "the dump cannot be written: {e}"),
            Self::ValueTooLarge { at } => {
                write!(f, "the dump cannot be written: value too large at {at}")
            }
            Self::RowCount { table } => write!(
                f,
                "the dump cannot be written: table {table} has another number of rows than it \
                 declared"
            ),
            Self::Write(kind) => write!(f, "writing the backup failed: {kind}"),
            Self::Changed => f.write_str("the backup file changed while it was being read"),
        }
    }
}

impl std::error::Error for FileError {}

/// SHA-256 of `bytes`: the digest the file ends with.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    Sha256::digest(bytes).into()
}

/// The kind byte of a column (ADR 0023 §1).
const fn kind_byte(kind: Kind) -> u8 {
    match kind {
        Kind::Integer => 1,
        Kind::Text => 2,
        Kind::Blob => 3,
    }
}

/// Writes `dump` as a backup file (module docs), stamped with `created_at_ms`.
///
/// The dump is checked first as [`Database::restore`](crate::Database::restore) checks it
/// (every table of [`TABLES`] once, in order; every row fits its columns), and every value
/// against its limit, so that every file this returns parses back to `dump`.
///
/// # Errors
///
/// - [`FileError::SchemaVersion`] when `dump.schema_version` is below 1.
/// - [`FileError::Dump`] when the dump does not fit this release's tables.
/// - [`FileError::ValueTooLarge`] when a text or blob value exceeds its limit.
/// - [`FileError::TooLarge`] when the file would exceed [`MAX_BACKUP_FILE_LEN`].
///
/// A thin wrapper over [`write_to`], which streams the same bytes.
pub fn write(dump: &Dump, created_at_ms: u64) -> Result<Vec<u8>, FileError> {
    let mut out = Vec::new();
    write_to(&mut out, dump, created_at_ms)?;
    Ok(out)
}

/// Streams `dump` as a backup file to `out`, stamped with `created_at_ms`: exactly the bytes
/// [`write()`] returns, through the streaming [`Encoder`] ([ADR 0094] §2). Returns the file's
/// digest and length.
///
/// # Errors
///
/// As [`write()`], and [`FileError::Write`] when `out` fails; `out` may then hold a prefix
/// of the file.
pub fn write_to<W: Write>(
    out: W,
    dump: &Dump,
    created_at_ms: u64,
) -> Result<([u8; DIGEST_LEN], u64), FileError> {
    if u64::try_from(dump.schema_version)
        .ok()
        .filter(|&v| v != 0)
        .is_none()
    {
        return Err(FileError::SchemaVersion);
    }
    let planned = plan(dump).map_err(FileError::Dump)?;
    let mut encoder = Encoder::new(out, dump.schema_version, created_at_ms)?;
    for (_, table) in planned {
        encoder.table(u64::try_from(table.rows.len()).map_err(|_| FileError::TooLarge)?)?;
        for row in &table.rows {
            encoder.row(row)?;
        }
    }
    let (_, sum, len) = encoder.finish()?;
    Ok((sum, len))
}

/// The streaming format version 1 encoder ([ADR 0094] §2): the canonical writer of the module
/// docs, generic over a byte sink.
///
/// [`Encoder::new`] writes the header, [`Encoder::table`] the next table of [`TABLES`] with
/// its declared `row_count`, [`Encoder::row`] one row of it, and [`Encoder::finish`] the
/// digest. It holds the hash state and never the file, and it refuses to write a byte past its
/// file limit ([`MAX_BACKUP_FILE_LEN`] unless [`Encoder::with_limit`] sets another), so every
/// file it finishes is within it. Over [`std::io::sink`] it is the counting sink of pass 1:
/// [`Encoder::written`] and [`Encoder::finish`] give the file's exact length.
pub struct Encoder<W> {
    /// Where the bytes go.
    out: W,
    /// SHA-256 over every byte written so far.
    hasher: Sha256,
    /// The bytes written so far.
    len: u64,
    /// The longest file this encoder writes, digest included.
    limit: u64,
    /// The tables begun so far.
    tables: usize,
    /// The current table's declared `row_count`; `None` for a table begun with
    /// [`Encoder::table_unsized`] (pass 1).
    rows_declared: Option<u64>,
    /// The rows written to the current table.
    rows: u64,
}

impl<W> fmt::Debug for Encoder<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder")
            .field("len", &self.len)
            .field("limit", &self.limit)
            .field("tables", &self.tables)
            .field("rows_declared", &self.rows_declared)
            .field("rows", &self.rows)
            .finish_non_exhaustive()
    }
}

impl<W: Write> Encoder<W> {
    /// Starts a file on `out`: writes its header.
    ///
    /// # Errors
    ///
    /// [`FileError::SchemaVersion`] when `schema_version` is below 1; [`FileError::Write`].
    pub fn new(out: W, schema_version: i64, created_at_ms: u64) -> Result<Self, FileError> {
        Self::with_limit(out, schema_version, created_at_ms, MAX_BACKUP_FILE_LEN)
    }

    /// [`Encoder::new`] with a file limit of `limit` bytes instead of
    /// [`MAX_BACKUP_FILE_LEN`]: the test-only lower limits of ADR 0094 §6 go through here.
    ///
    /// # Errors
    ///
    /// As [`Encoder::new`], and [`FileError::TooLarge`] when the header does not fit `limit`.
    pub fn with_limit(
        out: W,
        schema_version: i64,
        created_at_ms: u64,
        limit: u64,
    ) -> Result<Self, FileError> {
        let schema_version = u64::try_from(schema_version)
            .ok()
            .filter(|&v| v != 0)
            .ok_or(FileError::SchemaVersion)?;
        let table_count = u16::try_from(TABLES.len()).map_err(|_| FileError::TooLarge)?;
        let mut encoder = Self {
            out,
            hasher: Sha256::new(),
            len: 0,
            limit,
            tables: 0,
            rows_declared: Some(0),
            rows: 0,
        };
        encoder.put(&MAGIC)?;
        encoder.put(&FORMAT_VERSION.to_be_bytes())?;
        encoder.put(&schema_version.to_be_bytes())?;
        encoder.put(&created_at_ms.to_be_bytes())?;
        encoder.put(&table_count.to_be_bytes())?;
        Ok(encoder)
    }

    /// The bytes written so far.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.len
    }

    /// Begins the next table of [`TABLES`]: its name, its column descriptors and
    /// `row_count`, the number of [`Encoder::row`] calls that must follow.
    ///
    /// # Errors
    ///
    /// [`FileError::RowCount`] when the previous table got another number of rows than it
    /// declared; [`FileError::Dump`] when every table has been written already;
    /// [`FileError::TooLarge`]; [`FileError::Write`].
    pub fn table(&mut self, row_count: u64) -> Result<(), FileError> {
        self.begin_table(Some(row_count))
    }

    /// Pass 1 of [ADR 0094] §2: begins the next table without knowing its `row_count`,
    /// which takes any number of rows; [`Encoder::table_rows`] then gives the count. The
    /// `row_count` field is written as 0: its length, all pass 1 measures, does not depend on
    /// it, but the bytes are not a valid file, so use this only over a discarding sink.
    ///
    /// # Errors
    ///
    /// As [`Encoder::table`].
    pub fn table_unsized(&mut self) -> Result<(), FileError> {
        self.begin_table(None)
    }

    /// The rows written to the current table so far.
    #[must_use]
    pub const fn table_rows(&self) -> u64 {
        self.rows
    }

    /// [`Encoder::table`] and [`Encoder::table_unsized`].
    fn begin_table(&mut self, row_count: Option<u64>) -> Result<(), FileError> {
        self.end_table()?;
        let table_index = self.tables;
        let spec = TABLES
            .get(table_index)
            .ok_or(FileError::Dump(RestoreError::UnknownTable {
                index: table_index,
            }))?;
        let at = Location {
            table: Some(table_index),
            ..Location::default()
        };
        self.put_bytes(spec.name.as_bytes(), at)?;
        let column_count = u16::try_from(spec.columns.len()).map_err(|_| FileError::Malformed {
            at,
            problem: Problem::ColumnCount,
        })?;
        self.put(&column_count.to_be_bytes())?;
        for column in spec.columns {
            self.put_bytes(column.name.as_bytes(), at)?;
            self.put(&[kind_byte(column.kind), u8::from(column.nullable)])?;
        }
        self.put(&row_count.unwrap_or(0).to_be_bytes())?;
        self.tables = table_index.saturating_add(1);
        self.rows_declared = row_count;
        self.rows = 0;
        Ok(())
    }

    /// Writes one row of the current table, checked first against its columns and every
    /// value against its limit, so nothing of a refused row is written.
    ///
    /// # Errors
    ///
    /// [`FileError::RowCount`] when the table already has its declared rows (or no table has
    /// begun); [`FileError::Dump`] when the row does not fit its columns;
    /// [`FileError::ValueTooLarge`]; [`FileError::TooLarge`]; [`FileError::Write`].
    pub fn row(&mut self, row: &[Value]) -> Result<(), FileError> {
        let table_index = self.tables.saturating_sub(1);
        let spec = TABLES
            .get(table_index)
            .filter(|_| {
                self.tables > 0
                    && match self.rows_declared {
                        Some(declared) => self.rows < declared,
                        None => true,
                    }
            })
            .ok_or(FileError::RowCount { table: table_index })?;
        let row_index = usize::try_from(self.rows).unwrap_or(usize::MAX);
        check_row(spec, row_index, row).map_err(FileError::Dump)?;
        let row_number = self.rows;
        let at = |column: usize| Location {
            table: Some(table_index),
            row: Some(row_number),
            column: Some(column),
        };
        let mut encoded: u64 = 0;
        for (column, value) in row.iter().enumerate() {
            let value_len = match value {
                Value::Null => 0,
                Value::Integer(_) => 8,
                Value::Text(t) if t.len() > MAX_TEXT_LEN => {
                    return Err(FileError::ValueTooLarge { at: at(column) });
                }
                Value::Blob(b) if b.len() > MAX_BLOB_LEN => {
                    return Err(FileError::ValueTooLarge { at: at(column) });
                }
                Value::Text(t) => t.len().saturating_add(4),
                Value::Blob(b) => b.len().saturating_add(4),
            };
            encoded = encoded.saturating_add(u64::try_from(value_len).unwrap_or(u64::MAX));
            encoded = encoded.saturating_add(1);
        }
        if !self.fits(encoded) {
            return Err(FileError::TooLarge);
        }
        for (column, value) in row.iter().enumerate() {
            match value {
                Value::Null => self.put(&[tag::NULL])?,
                Value::Integer(v) => {
                    self.put(&[tag::INTEGER])?;
                    self.put(&v.to_be_bytes())?;
                }
                Value::Text(t) => {
                    self.put(&[tag::TEXT])?;
                    self.put_bytes(t.as_bytes(), at(column))?;
                }
                Value::Blob(b) => {
                    self.put(&[tag::BLOB])?;
                    self.put_bytes(b, at(column))?;
                }
            }
        }
        self.rows = self.rows.saturating_add(1);
        Ok(())
    }

    /// Ends the file: writes the digest and flushes `out`. Returns `out`, the digest and
    /// the file's length.
    ///
    /// # Errors
    ///
    /// [`FileError::RowCount`] when the last table got another number of rows than it
    /// declared; [`FileError::Dump`] when a table was not written; [`FileError::TooLarge`];
    /// [`FileError::Write`].
    pub fn finish(mut self) -> Result<(W, [u8; DIGEST_LEN], u64), FileError> {
        self.end_table()?;
        if let Some(missing) = TABLES.get(self.tables) {
            return Err(FileError::Dump(RestoreError::MissingTable {
                name: missing.name,
            }));
        }
        if !self.fits(0) {
            return Err(FileError::TooLarge);
        }
        let sum: [u8; DIGEST_LEN] = self.hasher.finalize().into();
        self.out
            .write_all(&sum)
            .and_then(|()| self.out.flush())
            .map_err(|e| FileError::Write(e.kind()))?;
        let len = self.len.saturating_add(DIGEST_LEN as u64);
        Ok((self.out, sum, len))
    }

    /// Whether `n` more bytes and the digest fit the limit.
    fn fits(&self, n: u64) -> bool {
        self.len
            .checked_add(n)
            .and_then(|n| n.checked_add(DIGEST_LEN as u64))
            .is_some_and(|n| n <= self.limit)
    }

    /// Requires the current table (if any) to have its declared rows.
    const fn end_table(&self) -> Result<(), FileError> {
        if match self.rows_declared {
            Some(declared) => self.rows == declared,
            None => true,
        } {
            Ok(())
        } else {
            Err(FileError::RowCount {
                table: self.tables.saturating_sub(1),
            })
        }
    }

    /// Writes `bytes`, hashing and counting them; refuses a write past the limit.
    fn put(&mut self, bytes: &[u8]) -> Result<(), FileError> {
        let n = u64::try_from(bytes.len()).map_err(|_| FileError::TooLarge)?;
        if !self.fits(n) {
            return Err(FileError::TooLarge);
        }
        self.out
            .write_all(bytes)
            .map_err(|e| FileError::Write(e.kind()))?;
        self.hasher.update(bytes);
        self.len = self.len.saturating_add(n);
        Ok(())
    }

    /// Writes `u32(len) ‖ bytes` (CRYPTO.md §2 `bytes(x)`).
    fn put_bytes(&mut self, bytes: &[u8], at: Location) -> Result<(), FileError> {
        let len = u32::try_from(bytes.len()).map_err(|_| FileError::ValueTooLarge { at })?;
        self.put(&len.to_be_bytes())?;
        self.put(bytes)
    }
}

/// A `u64` from a buffer length; a `usize` always fits on the targets this crate builds for.
fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Why a [`Cursor`] read stopped.
enum Short {
    /// The field runs past the end of the tables: the file is malformed.
    End,
    /// The field is not in the input yet: the caller must hand over more bytes.
    More,
}

/// Why decoding an item stopped.
enum Pull {
    /// The caller must hand over more bytes.
    More,
    /// The file is refused.
    Fail(FileError),
}

/// Maps a [`Short`] to a [`Pull`], an end of the tables being [`Problem::UnexpectedEnd`] at
/// `at`.
fn need<T>(read: Result<T, Short>, at: Location) -> Result<T, Pull> {
    read.map_err(|short| match short {
        Short::End => Pull::Fail(FileError::Malformed {
            at,
            problem: Problem::UnexpectedEnd,
        }),
        Short::More => Pull::More,
    })
}

/// A cursor over the input of one [`Decoder::decode`] call: `rest` is what the caller handed
/// over, `body_left` how many bytes of the tables region (between the header and the digest)
/// the file still holds from here, known from pass 1. A field past `body_left` is malformed;
/// a field within it but past `rest` needs more input.
struct Cursor<'a> {
    /// The input not read yet.
    rest: &'a [u8],
    /// The bytes of the file before its digest not read yet.
    body_left: u64,
}

impl<'a> Cursor<'a> {
    /// Takes the next `n` bytes of the file before its digest.
    fn take(&mut self, n: usize) -> Result<&'a [u8], Short> {
        let n64 = len64(n);
        if n64 > self.body_left {
            return Err(Short::End);
        }
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Short::More)?;
        self.rest = tail;
        self.body_left -= n64;
        Ok(head)
    }

    /// Takes the next `N` bytes as an array.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Short> {
        self.take(N)
            .and_then(|b| <[u8; N]>::try_from(b).map_err(|_| Short::End))
    }

    /// A `u8`.
    fn u8(&mut self) -> Result<u8, Short> {
        self.array::<1>().map(|[b]| b)
    }

    /// A big-endian `u16`.
    fn u16(&mut self) -> Result<u16, Short> {
        self.array().map(u16::from_be_bytes)
    }

    /// A big-endian `u32`.
    fn u32(&mut self) -> Result<u32, Short> {
        self.array().map(u32::from_be_bytes)
    }

    /// A big-endian `u64`.
    fn u64(&mut self) -> Result<u64, Short> {
        self.array().map(u64::from_be_bytes)
    }

    /// `bytes(x)` with `x` at most `max` long: the length is checked against `max` (`too_long`)
    /// and then against the rest of the tables region (`UnexpectedEnd`) before anything is
    /// taken.
    fn bytes(&mut self, max: usize, too_long: Problem, at: Location) -> Result<&'a [u8], Pull> {
        let len = need(self.u32(), at)?;
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > max {
            return Err(Pull::Fail(FileError::Malformed {
                at,
                problem: too_long,
            }));
        }
        need(self.take(len), at)
    }
}
/// Whether `name` is a valid table or column name: 1–[`MAX_NAME_LEN`] bytes of `[a-z0-9_]`.
fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// The smallest encoded row of `spec`: 1 byte for a nullable column (NULL), otherwise 9 for an
/// integer and 5 for an empty text or blob.
fn min_row_len(columns: &[Column]) -> usize {
    columns
        .iter()
        .map(|c| match (c.nullable, c.kind) {
            (true, _) => 1,
            (false, Kind::Integer) => 1 + 8,
            (false, Kind::Text | Kind::Blob) => 1 + 4,
        })
        .sum()
}

/// What pass 1 ([`Verifier`]) keeps of a verified file (ADR 0094 §3 point 1): its length, the
/// fixed header (magic, `format_version`, `schema_version`, `created_at_ms`, `table_count`)
/// and the digest. Pass 2 ([`Decoder`]) requires the bytes it reads to match it.
#[derive(Clone, PartialEq, Eq)]
pub struct Verified {
    /// The file's length, digest included.
    len: u64,
    /// The fixed header's bytes.
    header: [u8; HEADER_LEN],
    /// The trailing SHA-256, equal to the one recomputed over the file.
    digest: [u8; DIGEST_LEN],
    /// The header's schema version, at least 1.
    schema_version: i64,
    /// The header's creation time (informational only).
    created_at_ms: u64,
}

impl fmt::Debug for Verified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("len", &self.len)
            .field("schema_version", &self.schema_version)
            .field("created_at_ms", &self.created_at_ms)
            .finish_non_exhaustive()
    }
}

impl Verified {
    /// The file's length in bytes, digest included.
    #[must_use]
    pub const fn file_len(&self) -> u64 {
        self.len
    }

    /// The schema version the file is stamped with (ADR 0023 §5 step 3 compares it).
    #[must_use]
    pub const fn schema_version(&self) -> i64 {
        self.schema_version
    }

    /// When the file was written, by the writer's clock; informational only.
    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// The file's trailing SHA-256.
    #[must_use]
    pub const fn digest(&self) -> &[u8; DIGEST_LEN] {
        &self.digest
    }
}

/// Pass 1 of the reader (ADR 0094 §3 point 1), sans I/O: the caller hands it the file's bytes
/// in order, in pieces of any size; it checks the magic and the format version as soon as they
/// are in, streams every byte before the last [`DIGEST_LEN`] through SHA-256 and keeps only the
/// fixed header and the stored digest. [`Verifier::finish`] compares the digest and only then
/// reads the header's fields. Nothing else is parsed.
#[derive(Clone)]
pub struct Verifier {
    /// The file's length, known before its bytes (a regular file's metadata, or the buffer).
    len: u64,
    /// The bytes handed over so far.
    seen: u64,
    /// SHA-256 over the bytes before the digest seen so far.
    hasher: Sha256,
    /// The first [`HEADER_LEN`] bytes.
    head: [u8; HEADER_LEN],
    /// The last [`DIGEST_LEN`] bytes.
    tail: [u8; DIGEST_LEN],
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("len", &self.len)
            .field("seen", &self.seen)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// A verifier for a file of `len` bytes.
    ///
    /// # Errors
    ///
    /// [`FileError::TooLarge`] when `len` exceeds [`MAX_BACKUP_FILE_LEN`].
    pub fn new(len: u64) -> Result<Self, FileError> {
        if len > MAX_BACKUP_FILE_LEN {
            return Err(FileError::TooLarge);
        }
        Ok(Self {
            len,
            seen: 0,
            hasher: Sha256::new(),
            head: [0; HEADER_LEN],
            tail: [0; DIGEST_LEN],
        })
    }

    /// Takes the next bytes of the file.
    ///
    /// # Errors
    ///
    /// [`FileError::BadMagic`] or [`FileError::UnsupportedFormat`] as soon as the first bytes
    /// show it; [`FileError::Changed`] when more bytes arrive than the length given to
    /// [`Verifier::new`].
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), FileError> {
        let start = self.seen;
        let end = start
            .checked_add(len64(bytes.len()))
            .filter(|end| *end <= self.len)
            .ok_or(FileError::Changed)?;
        let body_end = self.len.saturating_sub(len64(DIGEST_LEN));
        let skip = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
        for (slot, b) in self.head.iter_mut().skip(skip(start)).zip(bytes) {
            *slot = *b;
        }
        let hashed = skip(body_end.saturating_sub(start)).min(bytes.len());
        let (body, digest) = bytes.split_at_checked(hashed).unwrap_or((bytes, &[]));
        self.hasher.update(body);
        let into_tail = skip(start.saturating_sub(body_end));
        for (slot, b) in self.tail.iter_mut().skip(into_tail).zip(digest) {
            *slot = *b;
        }
        self.seen = end;
        self.check_start()
    }

    /// The magic and format version checks, once their bytes are in.
    fn check_start(&self) -> Result<(), FileError> {
        let seen = usize::try_from(self.seen).unwrap_or(usize::MAX);
        let magic = self.head.get(..MAGIC.len()).unwrap_or_default();
        if seen >= MAGIC.len() && magic != MAGIC {
            return Err(FileError::BadMagic);
        }
        if seen >= MAGIC.len() + 2 {
            let version = self.field::<2>(MAGIC.len()).map(u16::from_be_bytes);
            if version != Some(FORMAT_VERSION) {
                return Err(FileError::UnsupportedFormat {
                    version: version.unwrap_or_default(),
                });
            }
        }
        Ok(())
    }

    /// The `N` header bytes at `at`.
    fn field<const N: usize>(&self, at: usize) -> Option<[u8; N]> {
        self.head
            .get(at..at.checked_add(N)?)
            .and_then(|b| <[u8; N]>::try_from(b).ok())
    }

    /// Ends pass 1: the magic, the format version, the length, the digest, then the header's
    /// fields, in that order (ADR 0023 §2: the digest before anything else is parsed).
    ///
    /// # Errors
    ///
    /// [`FileError::Changed`] when fewer bytes arrived than the length; otherwise
    /// [`FileError::Truncated`], [`FileError::BadMagic`], [`FileError::UnsupportedFormat`],
    /// [`FileError::DigestMismatch`], [`FileError::SchemaVersion`] or
    /// [`FileError::TableCount`].
    pub fn finish(self) -> Result<Verified, FileError> {
        if self.seen != self.len {
            return Err(FileError::Changed);
        }
        let len = usize::try_from(self.len).unwrap_or(usize::MAX);
        if len < MAGIC.len() {
            let have = self.head.get(..len).unwrap_or_default();
            return Err(if MAGIC.starts_with(have) {
                FileError::Truncated
            } else {
                FileError::BadMagic
            });
        }
        if len < MAGIC.len() + 2 {
            return Err(FileError::Truncated);
        }
        self.check_start()?;
        if len < HEADER_LEN + DIGEST_LEN {
            return Err(FileError::Truncated);
        }
        let digest: [u8; DIGEST_LEN] = self.hasher.clone().finalize().into();
        if digest != self.tail {
            return Err(FileError::DigestMismatch);
        }
        let end = FileError::Malformed {
            at: Location::default(),
            problem: Problem::UnexpectedEnd,
        };
        let at = MAGIC.len() + 2;
        let schema_version = self
            .field::<8>(at)
            .map(u64::from_be_bytes)
            .ok_or_else(|| end.clone())?;
        let schema_version = i64::try_from(schema_version)
            .ok()
            .filter(|v| *v >= 1)
            .ok_or(FileError::SchemaVersion)?;
        let created_at_ms = self
            .field::<8>(at + 8)
            .map(u64::from_be_bytes)
            .ok_or_else(|| end.clone())?;
        let table_count = self
            .field::<2>(at + 16)
            .map(u16::from_be_bytes)
            .ok_or(end)?;
        if usize::from(table_count) != TABLES.len() {
            return Err(FileError::TableCount { found: table_count });
        }
        Ok(Verified {
            len: self.len,
            header: self.head,
            digest,
            schema_version,
            created_at_ms,
        })
    }
}

/// What the [`Decoder`] read.
#[derive(Debug)]
pub enum Event {
    /// A table's descriptor, which matches `spec`; its `row_count` rows follow.
    Table {
        /// The table.
        spec: &'static TableSpec,
        /// The declared row count, already checked to fit the rest of the file.
        row_count: u64,
    },
    /// The next row of the last table, one value per column, already checked against it.
    Row(Vec<Value>),
    /// The digest: every table was read, the file matches pass 1's, and nothing follows.
    End,
}

/// Where the [`Decoder`] is.
#[derive(Clone, Copy, Debug)]
enum State {
    /// Before the fixed header.
    Header,
    /// Before the descriptor of table `TABLES[n]` (or the digest once `n` is past the end).
    Table(usize),
    /// Inside a table: `row` of `count` rows read.
    Rows {
        /// The table's index.
        table: usize,
        /// The rows read.
        row: u64,
        /// The declared row count.
        count: u64,
    },
    /// Before the digest.
    Digest,
    /// After the digest.
    Done,
}

/// Pass 2 of the reader (ADR 0094 §3 point 3): a sans-I/O incremental decoder. The caller
/// hands [`Decoder::decode`] the file's unread bytes, in buffers of any size; it yields each
/// table's descriptor, each row and the end, and says how many bytes it used. It holds no
/// input of its own, only the hash state: the caller keeps what was not used and hands it over
/// again with more. Every rule of the module docs applies; "the remaining input" is the
/// length pass 1 verified minus the bytes used. Before [`Event::End`] it requires the header
/// bytes, the stored digest and the recomputed one to equal pass 1's ([`FileError::Changed`]
/// otherwise, ADR 0094 §3 point 4).
#[derive(Clone)]
pub struct Decoder {
    /// Pass 1's result.
    verified: Verified,
    /// SHA-256 over the bytes used so far.
    hasher: Sha256,
    /// The bytes of the file used so far.
    used: u64,
    /// Where the decoder is.
    state: State,
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("used", &self.used)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Decoder {
    /// A decoder for the file pass 1 verified.
    #[must_use]
    pub fn new(verified: &Verified) -> Self {
        Self {
            verified: verified.clone(),
            hasher: Sha256::new(),
            used: 0,
            state: State::Header,
        }
    }

    /// The bytes of the file used so far.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Reads the next item from `input`, which must start at the first byte not used yet.
    /// Returns how many bytes of `input` it used and what it read; `None` means `input` does
    /// not hold the whole next item yet: hand it over again with more bytes. Once
    /// [`Event::End`] was returned, every call returns it again and uses nothing.
    ///
    /// # Errors
    ///
    /// [`FileError::Malformed`] or [`FileError::TrailingBytes`] for a file the strict parser
    /// refuses; [`FileError::Changed`] when the bytes differ from those pass 1 verified.
    pub fn decode(&mut self, input: &[u8]) -> Result<(usize, Option<Event>), FileError> {
        let mut off = 0usize;
        loop {
            let rest = input.get(off..).unwrap_or_default();
            let body_left = self
                .verified
                .len
                .saturating_sub(len64(DIGEST_LEN))
                .saturating_sub(self.used);
            if let State::Digest | State::Done = self.state {
                return Ok(match self.finish(rest, body_left)? {
                    Some(n) => (off + n, Some(Event::End)),
                    None => (off, None),
                });
            }
            let mut cur = Cursor { rest, body_left };
            let (next, event) = match self.item(&mut cur) {
                Ok(item) => item,
                Err(Pull::More) => return Ok((off, None)),
                Err(Pull::Fail(e)) => return Err(e),
            };
            let n = rest.len() - cur.rest.len();
            self.hasher.update(rest.get(..n).unwrap_or_default());
            self.used += len64(n);
            self.state = next;
            off += n;
            if event.is_some() {
                return Ok((off, event));
            }
        }
    }

    /// The digest: nothing may remain before it, and it, the recomputed one and pass 1's must
    /// be equal. Returns how many bytes it used (`Some`), or `None` when the digest is not all
    /// in `rest` yet.
    fn finish(&mut self, rest: &[u8], body_left: u64) -> Result<Option<usize>, FileError> {
        if let State::Done = self.state {
            return Ok(Some(0));
        }
        if body_left != 0 {
            return Err(FileError::TrailingBytes);
        }
        let Some(stored) = rest.get(..DIGEST_LEN) else {
            return Ok(None);
        };
        let computed: [u8; DIGEST_LEN] = core::mem::take(&mut self.hasher).finalize().into();
        if computed != self.verified.digest || stored != self.verified.digest {
            return Err(FileError::Changed);
        }
        self.used += len64(DIGEST_LEN);
        self.state = State::Done;
        Ok(Some(DIGEST_LEN))
    }

    /// Reads the item at the decoder's state: the next state and what to yield.
    fn item(&self, cur: &mut Cursor<'_>) -> Result<(State, Option<Event>), Pull> {
        match self.state {
            State::Header => {
                let header = need(cur.take(HEADER_LEN), Location::default())?;
                if header != self.verified.header {
                    return Err(Pull::Fail(FileError::Changed));
                }
                Ok((State::Table(0), None))
            }
            State::Table(index) => {
                let Some(spec) = TABLES.get(index) else {
                    return Ok((State::Digest, None));
                };
                let row_count = decode_descriptor(cur, index, spec)?;
                let next = State::Rows {
                    table: index,
                    row: 0,
                    count: row_count,
                };
                Ok((next, Some(Event::Table { spec, row_count })))
            }
            State::Rows { table, row, count } => {
                let Some(spec) = TABLES.get(table).filter(|_| row < count) else {
                    return Ok((State::Table(table + 1), None));
                };
                let values = decode_row(cur, table, row, spec)?;
                let next = State::Rows {
                    table,
                    row: row + 1,
                    count,
                };
                Ok((next, Some(Event::Row(values))))
            }
            State::Digest | State::Done => Ok((self.state, Some(Event::End))),
        }
    }
}

/// Parses a backup file held in memory (module docs): [`Verifier`] (magic, format version and
/// digest first, then the header), then [`Decoder`] over the same bytes, strictly.
///
/// # Errors
///
/// [`FileError`], on any input that is not exactly a file [`write()`] produces; never panics.
pub fn parse(file: &[u8]) -> Result<BackupFile, FileError> {
    if file.len() > MAX_IN_MEMORY_BACKUP_LEN {
        return Err(FileError::TooLarge);
    }
    let mut pass1 = Verifier::new(len64(file.len()))?;
    pass1.update(file)?;
    let verified = pass1.finish()?;
    let mut decoder = Decoder::new(&verified);
    let mut tables: Vec<TableDump> = Vec::with_capacity(TABLES.len());
    let mut at = 0usize;
    loop {
        let (used, event) = decoder.decode(file.get(at..).unwrap_or_default())?;
        at += used;
        match event {
            Some(Event::Table { spec, row_count }) => tables.push(TableDump {
                table: spec.name.to_owned(),
                rows: Vec::with_capacity(usize::try_from(row_count).unwrap_or(0)),
            }),
            Some(Event::Row(row)) => {
                if let Some(table) = tables.last_mut() {
                    table.rows.push(row);
                }
            }
            Some(Event::End) => break,
            // The whole file is in `file`, so the decoder never asks for more.
            None => return Err(FileError::Changed),
        }
    }
    Ok(BackupFile {
        created_at_ms: verified.created_at_ms,
        dump: Dump {
            schema_version: verified.schema_version,
            tables,
        },
    })
}

/// Reads one table's descriptor, which must be `spec`'s, and returns its row count, checked
/// to fit the rest of the file.
fn decode_descriptor(
    cur: &mut Cursor<'_>,
    table_index: usize,
    spec: &TableSpec,
) -> Result<u64, Pull> {
    let at = Location {
        table: Some(table_index),
        ..Location::default()
    };
    let malformed =
        |at: Location, problem: Problem| Pull::Fail(FileError::Malformed { at, problem });
    let name = cur.bytes(MAX_NAME_LEN, Problem::Name, at)?;
    if !valid_name(name) {
        return Err(malformed(at, Problem::Name));
    }
    if name != spec.name.as_bytes() {
        return Err(malformed(at, Problem::Table));
    }
    let column_count = usize::from(need(cur.u16(), at)?);
    if column_count > MAX_COLUMNS || column_count != spec.columns.len() {
        return Err(malformed(at, Problem::ColumnCount));
    }
    for (column_index, column) in spec.columns.iter().enumerate() {
        let at = Location {
            column: Some(column_index),
            ..at
        };
        let name = cur.bytes(MAX_NAME_LEN, Problem::Name, at)?;
        if !valid_name(name) {
            return Err(malformed(at, Problem::Name));
        }
        let kind = need(cur.u8(), at)?;
        let nullable = need(cur.u8(), at)?;
        if name != column.name.as_bytes()
            || kind != kind_byte(column.kind)
            || nullable != u8::from(column.nullable)
        {
            return Err(malformed(at, Problem::Column));
        }
    }
    let row_count = need(cur.u64(), at)?;
    // Each row takes at least `min_row_len` bytes (≥ `column_count`, ADR 0023 §3), so a count
    // the rest of the file cannot hold is refused before any row is read.
    let min_row = len64(min_row_len(spec.columns));
    if row_count
        .checked_mul(min_row)
        .is_none_or(|needed| needed > cur.body_left)
    {
        return Err(malformed(at, Problem::RowCount));
    }
    Ok(row_count)
}

/// Reads one row of `spec`.
fn decode_row(
    cur: &mut Cursor<'_>,
    table_index: usize,
    row_index: u64,
    spec: &TableSpec,
) -> Result<Vec<Value>, Pull> {
    let mut row = Vec::with_capacity(spec.columns.len());
    for (column_index, column) in spec.columns.iter().enumerate() {
        let at = Location {
            table: Some(table_index),
            row: Some(row_index),
            column: Some(column_index),
        };
        row.push(decode_value(cur, column, at)?);
    }
    Ok(row)
}

/// Reads one value of `column`.
fn decode_value(cur: &mut Cursor<'_>, column: &Column, at: Location) -> Result<Value, Pull> {
    let malformed = |problem: Problem| Pull::Fail(FileError::Malformed { at, problem });
    match (need(cur.u8(), at)?, column.kind) {
        (tag::NULL, _) if column.nullable => Ok(Value::Null),
        (tag::INTEGER, Kind::Integer) => Ok(Value::Integer(i64::from_be_bytes(need(
            cur.array::<8>(),
            at,
        )?))),
        (tag::TEXT, Kind::Text) => {
            let bytes = cur.bytes(MAX_TEXT_LEN, Problem::TextTooLong, at)?;
            let text = core::str::from_utf8(bytes).map_err(|_| malformed(Problem::Utf8))?;
            Ok(Value::Text(text.to_owned()))
        }
        (tag::BLOB, Kind::Blob) => {
            let bytes = cur.bytes(MAX_BLOB_LEN, Problem::BlobTooLong, at)?;
            Ok(Value::Blob(bytes.to_vec()))
        }
        _ => Err(malformed(Problem::Tag)),
    }
}

#[cfg(test)]
mod tests {
    //! Round trip, the known-answer file, and refusals of every truncation and byte change.

    use super::*;
    use crate::migrate::schema_version;

    /// The committed known-answer file (ADR 0023 §3): [`kat_dump`] written at
    /// [`KAT_CREATED_AT_MS`].
    const KAT: &[u8] = include_bytes!("../../tests/vectors/db_backup_v1.bin");

    /// The known-answer file's `created_at_ms`.
    const KAT_CREATED_AT_MS: u64 = 1_790_000_000_000;

    /// Every table empty.
    fn empty() -> Dump {
        Dump {
            schema_version: schema_version(),
            tables: TABLES
                .iter()
                .map(|s| TableDump {
                    table: s.name.to_owned(),
                    rows: Vec::new(),
                })
                .collect(),
        }
    }

    /// Sets the rows of `name` in `dump`.
    fn set(dump: &mut Dump, name: &str, rows: Vec<Vec<Value>>) {
        let table = dump.tables.iter_mut().find(|t| t.table == name).unwrap();
        table.rows = rows;
    }

    /// The small dump of the known-answer file: an account with a text login name, its OPAQUE
    /// setup, two device certificates (one with a NULL), and a negative integer.
    fn kat_dump() -> Dump {
        let mut d = empty();
        set(
            &mut d,
            "auth_accounts",
            vec![vec![
                Value::Blob(vec![0xa1; 16]),
                Value::Text("alice".into()),
                Value::Integer(1_000),
                Value::Null,
            ]],
        );
        set(
            &mut d,
            "auth_opaque_setups",
            vec![vec![
                Value::Integer(1),
                Value::Blob((0..32).collect()),
                Value::Integer(-1),
                Value::Null,
            ]],
        );
        set(
            &mut d,
            "auth_device_certificates",
            vec![
                vec![
                    Value::Blob(vec![0xa1; 16]),
                    Value::Blob(vec![0xd1; 16]),
                    Value::Integer(0),
                    Value::Integer(1),
                    Value::Integer(0),
                    Value::Blob(vec![0x0c; 3]),
                    Value::Null,
                    Value::Integer(20),
                ],
                vec![
                    Value::Blob(vec![0xa1; 16]),
                    Value::Blob(vec![0xd2; 16]),
                    Value::Integer(0),
                    Value::Integer(4),
                    Value::Integer(i64::MAX),
                    Value::Blob(Vec::new()),
                    Value::Integer(21),
                    Value::Integer(i64::MIN),
                ],
            ],
        );
        d
    }

    #[test]
    fn known_answer_file() {
        let written = write(&kat_dump(), KAT_CREATED_AT_MS).unwrap();
        assert_eq!(
            written.as_slice(),
            KAT,
            "the writer drifted from the committed file"
        );
        let parsed = parse(KAT).unwrap();
        assert_eq!(parsed.dump, kat_dump());
        assert_eq!(parsed.created_at_ms, KAT_CREATED_AT_MS);
        // The header, spelled out (ADR 0023 §1).
        assert_eq!(&KAT[..22], b"rizzy-vault-db-backup\0");
        assert_eq!(&KAT[22..24], &[0, 1]);
        assert_eq!(&KAT[24..32], &schema_version().to_be_bytes());
        assert_eq!(&KAT[32..40], &KAT_CREATED_AT_MS.to_be_bytes());
        assert_eq!(
            &KAT[40..42],
            &u16::try_from(TABLES.len()).unwrap().to_be_bytes()
        );
        // The first table: `str("auth_accounts")`, 4 columns, `str("id")`, blob, not null.
        assert_eq!(&KAT[42..46], &13u32.to_be_bytes());
        assert_eq!(&KAT[46..59], b"auth_accounts");
        assert_eq!(&KAT[59..61], &4u16.to_be_bytes());
        assert_eq!(&KAT[61..67], b"\0\0\0\x02id");
        assert_eq!(&KAT[67..69], &[3, 0]);
        // The digest is SHA-256 of everything before it.
        let (body, sum) = KAT.split_at(KAT.len() - DIGEST_LEN);
        assert_eq!(Sha256::digest(body).as_slice(), sum);
    }

    /// Streams `dump` through an [`Encoder`] with file limit `limit`, table by table.
    fn stream(dump: &Dump, created_at_ms: u64, limit: u64) -> Result<Vec<u8>, FileError> {
        let mut e = Encoder::with_limit(Vec::new(), dump.schema_version, created_at_ms, limit)?;
        for t in &dump.tables {
            e.table(t.rows.len() as u64)?;
            for r in &t.rows {
                e.row(r)?;
            }
        }
        e.finish().map(|(out, _, _)| out)
    }

    /// ADR 0094 §2 and §6 test 1: the streaming writer gives `write()`'s bytes exactly, and
    /// over a discarding sink (pass 1) the same length and digest.
    #[test]
    fn stream_write_equals_write() {
        for (dump, at) in [(kat_dump(), KAT_CREATED_AT_MS), (empty(), 7)] {
            let bytes = write(&dump, at).unwrap();
            let mut streamed = Vec::new();
            let (sum, len) = write_to(&mut streamed, &dump, at).unwrap();
            assert_eq!(streamed, bytes);
            assert_eq!(len, bytes.len() as u64);
            assert_eq!(sum, digest(&bytes[..bytes.len() - DIGEST_LEN]));
            assert_eq!(write_to(std::io::sink(), &dump, at).unwrap(), (sum, len));
            assert_eq!(stream(&dump, at, MAX_BACKUP_FILE_LEN).unwrap(), bytes);
        }
        let mut streamed = Vec::new();
        write_to(&mut streamed, &kat_dump(), KAT_CREATED_AT_MS).unwrap();
        assert_eq!(streamed, KAT);
    }

    /// Pass 2 as a byte sink: decodes what it is written as it arrives, like
    /// `Database::restore_from`, keeping the tables when `keep`.
    struct DecodeSink {
        decoder: Decoder,
        buf: Vec<u8>,
        rows: u64,
        ended: bool,
        keep: bool,
        tables: Vec<TableDump>,
    }

    impl DecodeSink {
        fn new(verified: &Verified, keep: bool) -> Self {
            Self {
                decoder: Decoder::new(verified),
                buf: Vec::new(),
                rows: 0,
                ended: false,
                keep,
                tables: Vec::new(),
            }
        }
    }

    impl Write for DecodeSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(bytes);
            let mut at = 0;
            loop {
                let (n, event) = self
                    .decoder
                    .decode(&self.buf[at..])
                    .map_err(std::io::Error::other)?;
                at += n;
                match event {
                    Some(Event::Table { spec, .. }) if self.keep => self.tables.push(TableDump {
                        table: spec.name.to_owned(),
                        rows: Vec::new(),
                    }),
                    Some(Event::Table { .. }) => {}
                    Some(Event::Row(row)) => {
                        self.rows += 1;
                        if self.keep {
                            self.tables.last_mut().unwrap().rows.push(row);
                        }
                    }
                    Some(Event::End) => {
                        assert!(!self.ended);
                        self.ended = true;
                        assert_eq!(self.decoder.decode(&[]).unwrap().0, 0);
                        break;
                    }
                    None => break,
                }
            }
            self.buf.drain(..at);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Pass 1 over `bytes` handed over `piece` bytes at a time.
    fn verify_in_pieces(bytes: &[u8], piece: usize) -> Result<Verified, FileError> {
        let mut v = Verifier::new(bytes.len() as u64)?;
        for p in bytes.chunks(piece) {
            v.update(p)?;
        }
        v.finish()
    }

    /// ADR 0094 §3 and §6: the two-pass reader, fed in pieces of any size, reads the
    /// known-answer file back to its dump, as [`parse`] does.
    #[test]
    fn two_pass_reader_reads_the_kat_in_pieces() {
        let whole = verify_in_pieces(KAT, KAT.len()).unwrap();
        assert_eq!(whole.file_len(), KAT.len() as u64);
        assert_eq!(whole.schema_version(), schema_version());
        assert_eq!(whole.created_at_ms(), KAT_CREATED_AT_MS);
        assert_eq!(whole.digest().as_slice(), &KAT[KAT.len() - DIGEST_LEN..]);
        for piece in [1, 2, 7, 64, 4096, KAT.len()] {
            let verified = verify_in_pieces(KAT, piece).unwrap();
            assert_eq!(verified, whole);
            let mut sink = DecodeSink::new(&verified, true);
            for p in KAT.chunks(piece) {
                sink.write_all(p).unwrap();
            }
            assert!(sink.ended, "piece {piece}");
            assert!(sink.buf.is_empty());
            assert_eq!(sink.decoder.used(), KAT.len() as u64);
            let dump = Dump {
                schema_version: verified.schema_version(),
                tables: sink.tables,
            };
            assert_eq!(dump, kat_dump());
        }
    }

    /// ADR 0094 §3 point 4: pass 2 refuses bytes other than pass 1's with `Changed`: another
    /// header, the same header with another body, more bytes or fewer.
    #[test]
    fn two_pass_reader_refuses_a_changed_file() {
        let verified = verify_in_pieces(KAT, KAT.len()).unwrap();
        let decode_all = |file: &[u8]| -> Result<(), FileError> {
            let mut d = Decoder::new(&verified);
            let mut at = 0;
            loop {
                match d.decode(&file[at..])? {
                    (_, Some(Event::End)) => return Ok(()),
                    (n, Some(_)) => at += n,
                    (_, None) => return Err(FileError::Truncated),
                }
            }
        };
        assert_eq!(decode_all(KAT), Ok(()));
        let other_header = write(&kat_dump(), KAT_CREATED_AT_MS + 1).unwrap();
        assert_eq!(decode_all(&other_header), Err(FileError::Changed));
        let mut other_body = kat_dump();
        other_body.tables[0].rows[0][1] = Value::Text("alicf".into());
        let other_body = write(&other_body, KAT_CREATED_AT_MS).unwrap();
        assert_eq!(other_body.len(), KAT.len());
        assert_eq!(decode_all(&other_body), Err(FileError::Changed));
        let mut same_body_other_digest = KAT.to_vec();
        *same_body_other_digest.last_mut().unwrap() ^= 1;
        assert_eq!(decode_all(&same_body_other_digest), Err(FileError::Changed));

        let mut v = Verifier::new(KAT.len() as u64 - 1).unwrap();
        assert_eq!(v.update(KAT), Err(FileError::Changed));
        let mut v = Verifier::new(KAT.len() as u64 + 1).unwrap();
        v.update(KAT).unwrap();
        assert_eq!(v.finish(), Err(FileError::Changed));
        assert_eq!(
            Verifier::new(MAX_BACKUP_FILE_LEN + 1).unwrap_err(),
            FileError::TooLarge
        );
        // The magic is refused as soon as it is in, before the rest is read.
        let mut v = Verifier::new(1 << 30).unwrap();
        assert_eq!(v.update(&[0; MAGIC.len()]), Err(FileError::BadMagic));
    }

    /// ADR 0094 §6: a file over 2 GiB ([`MAX_IN_MEMORY_BACKUP_LEN`]) reads through both
    /// passes, streamed, never held. 66 blobs of 32 MiB; written twice and never stored.
    /// Ignored in the gate (about 4.3 GiB hashed and copied); run with `--ignored`.
    #[test]
    #[ignore = "slow: streams a 2.06 GiB file twice"]
    fn two_pass_reader_reads_a_file_over_2_gib() {
        const ROWS: u64 = 66;
        struct VerifySink(Verifier);
        impl Write for VerifySink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes).map_err(std::io::Error::other)?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let chunks = TABLES
            .iter()
            .position(|s| s.name == "vault_attachment_chunks")
            .unwrap();
        let mut row = vec![
            Value::Blob(vec![0xa7; 16]),
            Value::Integer(0),
            Value::Blob(vec![0x5c; MAX_BLOB_LEN]),
        ];
        let mut encode = |out: &mut dyn Write| {
            let mut e = Encoder::new(out, schema_version(), 1).unwrap();
            for i in 0..TABLES.len() {
                e.table(if i == chunks { ROWS } else { 0 }).unwrap();
                if i == chunks {
                    for r in 0..ROWS {
                        row[1] = Value::Integer(i64::try_from(r).unwrap());
                        e.row(&row).unwrap();
                    }
                }
            }
            e.finish().unwrap().2
        };
        let len = encode(&mut std::io::sink());
        assert!(len > MAX_IN_MEMORY_BACKUP_LEN as u64);
        let mut pass1 = VerifySink(Verifier::new(len).unwrap());
        assert_eq!(encode(&mut pass1), len);
        let verified = pass1.0.finish().unwrap();
        let mut pass2 = DecodeSink::new(&verified, false);
        encode(&mut pass2);
        assert!(pass2.ended);
        assert_eq!(pass2.rows, ROWS);
        assert_eq!(pass2.decoder.used(), len);
    }

    /// The encoder refuses a table with another number of rows than it declared, a missing
    /// table, and any byte past its limit.
    #[test]
    fn encoder_refusals() {
        let v = schema_version();
        let mut e = Encoder::new(Vec::new(), v, 0).unwrap();
        e.table(1).unwrap();
        assert_eq!(e.table(0), Err(FileError::RowCount { table: 0 }));
        let mut e = Encoder::new(Vec::new(), v, 0).unwrap();
        e.table(0).unwrap();
        assert_eq!(e.row(&[]), Err(FileError::RowCount { table: 0 }));
        let mut e = Encoder::new(Vec::new(), v, 0).unwrap();
        assert_eq!(e.row(&[]), Err(FileError::RowCount { table: 0 }));
        assert!(matches!(
            Encoder::new(Vec::new(), v, 0).unwrap().finish(),
            Err(FileError::Dump(RestoreError::MissingTable { .. }))
        ));
        assert_eq!(
            Encoder::new(Vec::new(), 0, 0).unwrap_err(),
            FileError::SchemaVersion
        );
        let len = KAT.len() as u64;
        assert_eq!(stream(&kat_dump(), KAT_CREATED_AT_MS, len).unwrap(), KAT);
        assert_eq!(
            stream(&kat_dump(), KAT_CREATED_AT_MS, len - 1),
            Err(FileError::TooLarge)
        );
    }

    #[test]
    fn round_trip_is_canonical() {
        for dump in [empty(), kat_dump()] {
            let file = write(&dump, 7).unwrap();
            let parsed = parse(&file).unwrap();
            assert_eq!(parsed.dump, dump);
            assert_eq!(write(&parsed.dump, parsed.created_at_ms).unwrap(), file);
        }
    }

    #[test]
    fn every_truncation_and_extension_is_refused() {
        for len in 0..KAT.len() {
            assert!(parse(&KAT[..len]).is_err(), "truncated to {len}");
        }
        let mut longer = KAT.to_vec();
        longer.push(0);
        assert_eq!(parse(&longer), Err(FileError::DigestMismatch));
        // Bytes after the last table, with the digest recomputed over them.
        let mut body = KAT[..KAT.len() - DIGEST_LEN].to_vec();
        body.push(0);
        let sum = digest(&body);
        body.extend_from_slice(&sum);
        assert_eq!(parse(&body), Err(FileError::TrailingBytes));
    }

    #[test]
    fn every_byte_change_is_refused_or_reencodes_exactly() {
        let body = &KAT[..KAT.len() - DIGEST_LEN];
        for i in 0..KAT.len() {
            let mut changed = KAT.to_vec();
            changed[i] ^= 0x01;
            assert!(parse(&changed).is_err(), "byte {i} flipped");
        }
        // With the digest recomputed, the structural checks refuse every change that does not
        // decode to another valid file; the ones that do (a value's bits, `created_at_ms`)
        // re-encode to exactly the changed bytes, so the encoding stays canonical.
        for i in 0..body.len() {
            for flip in [0x01u8, 0x80] {
                let mut changed = body.to_vec();
                changed[i] ^= flip;
                let sum = digest(&changed);
                changed.extend_from_slice(&sum);
                if let Ok(parsed) = parse(&changed) {
                    assert_eq!(
                        write(&parsed.dump, parsed.created_at_ms).unwrap(),
                        changed,
                        "byte {i}"
                    );
                    assert_ne!(parsed.dump.schema_version, 0);
                }
            }
        }
    }

    #[test]
    fn header_refusals() {
        assert_eq!(parse(b""), Err(FileError::Truncated));
        assert_eq!(parse(b"rizzy"), Err(FileError::Truncated));
        assert_eq!(
            parse(b"not a backup at all, clearly"),
            Err(FileError::BadMagic)
        );
        let mut v2 = KAT.to_vec();
        v2[23] = 2;
        assert_eq!(parse(&v2), Err(FileError::UnsupportedFormat { version: 2 }));
        let reseal = |mut body: Vec<u8>| {
            let sum = digest(&body);
            body.extend_from_slice(&sum);
            body
        };
        let body = KAT[..KAT.len() - DIGEST_LEN].to_vec();
        let mut zero_schema = body.clone();
        zero_schema[24..32].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(parse(&reseal(zero_schema)), Err(FileError::SchemaVersion));
        let mut huge_schema = body.clone();
        huge_schema[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(parse(&reseal(huge_schema)), Err(FileError::SchemaVersion));
        let mut tables = body;
        tables[40..42].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse(&reseal(tables)),
            Err(FileError::TableCount { found: 1 })
        );
    }

    #[test]
    fn huge_declared_counts_are_refused_before_allocating() {
        // The first table's row count (after its 4 column descriptors) set to u64::MAX.
        let mut body = KAT[..KAT.len() - DIGEST_LEN].to_vec();
        let rows_at = 42 + 4 + 13 + 2 + (4 + 2 + 2) + (4 + 10 + 2) + (4 + 13 + 2) + (4 + 19 + 2);
        assert_eq!(&body[rows_at..rows_at + 8], &1u64.to_be_bytes());
        body[rows_at..rows_at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        let sum = digest(&body);
        body.extend_from_slice(&sum);
        assert_eq!(
            parse(&body),
            Err(FileError::Malformed {
                at: Location {
                    table: Some(0),
                    ..Location::default()
                },
                problem: Problem::RowCount
            })
        );
    }

    #[test]
    fn writer_refusals() {
        let mut d = kat_dump();
        d.schema_version = 0;
        assert_eq!(write(&d, 0), Err(FileError::SchemaVersion));
        let mut d = kat_dump();
        d.tables.pop();
        assert!(matches!(write(&d, 0), Err(FileError::Dump(_))));
        let mut d = kat_dump();
        set(
            &mut d,
            "auth_accounts",
            vec![vec![
                Value::Blob(vec![1; 16]),
                Value::Text("a".repeat(MAX_TEXT_LEN + 1)),
                Value::Integer(1),
                Value::Null,
            ]],
        );
        assert_eq!(
            write(&d, 0),
            Err(FileError::ValueTooLarge {
                at: Location {
                    table: Some(0),
                    row: Some(0),
                    column: Some(1)
                }
            })
        );
        let mut d = kat_dump();
        set(
            &mut d,
            "auth_accounts",
            vec![vec![
                Value::Blob(vec![1; MAX_BLOB_LEN + 1]),
                Value::Text("a".into()),
                Value::Integer(1),
                Value::Null,
            ]],
        );
        assert!(matches!(write(&d, 0), Err(FileError::ValueTooLarge { .. })));
        // At the limits, it round-trips.
        let mut d = kat_dump();
        set(
            &mut d,
            "auth_accounts",
            vec![vec![
                Value::Blob(vec![1; MAX_BLOB_LEN]),
                Value::Text("é".repeat(MAX_TEXT_LEN / 2)),
                Value::Integer(1),
                Value::Null,
            ]],
        );
        assert_eq!(parse(&write(&d, 0).unwrap()).unwrap().dump, d);
    }

    #[test]
    fn schema_fits_the_format() {
        assert!(u16::try_from(TABLES.len()).is_ok());
        for spec in TABLES {
            assert!(valid_name(spec.name.as_bytes()), "{}", spec.name);
            assert!(!spec.columns.is_empty() && spec.columns.len() <= MAX_COLUMNS);
            assert!(min_row_len(spec.columns) >= spec.columns.len());
            // The memory bound of the module docs: a row decodes to at most 16 times its
            // smallest encoding.
            assert!(
                spec.columns.len() * size_of::<Value>() <= 16 * min_row_len(spec.columns),
                "{}",
                spec.name
            );
            for c in spec.columns {
                assert!(valid_name(c.name.as_bytes()), "{}.{}", spec.name, c.name);
            }
        }
    }

    #[test]
    fn errors_name_places_never_values() {
        let mut d = kat_dump();
        set(
            &mut d,
            "auth_accounts",
            vec![vec![
                Value::Blob(vec![1; 16]),
                Value::Text(format!("secret-{}", "x".repeat(MAX_TEXT_LEN))),
                Value::Integer(1),
                Value::Null,
            ]],
        );
        let e = write(&d, 0).unwrap_err().to_string();
        assert!(!e.contains("secret") && e.contains("row 0"), "{e}");
    }
}
