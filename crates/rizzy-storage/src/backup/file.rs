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
//! - The whole file: [`MAX_BACKUP_FILE_LEN`], 2 GiB, for this in-memory reader. [`write()`]
//!   refuses to produce a longer file, so no backup this release writes is one it cannot read.
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
//!   encoded one 1 byte (a NULL), but every backed-up table has at most 2 nullable columns out
//!   of at least 3, so a row decodes to at most about 8 times its encoded size.
//!
//! The parser is pure (no I/O), never panics, and its errors name the table index, the row and
//! the column, never a value (INV-48).
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

use core::fmt;

use sha2::{Digest as _, Sha256};

use super::{Dump, TableDump, Value, plan};
use crate::error::RestoreError;
use crate::tables::{Column, Kind, TABLES, TableSpec};

/// The 22-byte magic: the ASCII bytes `rizzy-vault-db-backup` and one `0x00` (ADR 0023 §1).
pub const MAGIC: [u8; 22] = *b"rizzy-vault-db-backup\0";

/// The one format version this reader and writer implement. A new layout is a new version,
/// decided by an ADR (ADR 0023 §1).
pub const FORMAT_VERSION: u16 = 1;

/// The longest backup file this release reads and writes: 2 GiB (ADR 0023 §3, open question 2
/// answered as recommended).
pub const MAX_BACKUP_FILE_LEN: usize = 2 * 1024 * 1024 * 1024;

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
    /// The file is longer than [`MAX_BACKUP_FILE_LEN`], or writing it would make it so.
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
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(
                f,
                "the backup file is larger than this release's limit of {MAX_BACKUP_FILE_LEN} bytes"
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
        }
    }
}

impl std::error::Error for FileError {}

/// SHA-256 of `bytes`: the digest the file ends with.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    Sha256::digest(bytes).into()
}

/// Appends `u32(len) ‖ bytes` (CRYPTO.md §2 `bytes(x)`).
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8], at: Location) -> Result<(), FileError> {
    let len = u32::try_from(bytes.len()).map_err(|_| FileError::ValueTooLarge { at })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
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
pub fn write(dump: &Dump, created_at_ms: u64) -> Result<Vec<u8>, FileError> {
    let schema_version =
        u64::try_from(dump.schema_version).map_err(|_| FileError::SchemaVersion)?;
    if schema_version == 0 {
        return Err(FileError::SchemaVersion);
    }
    let planned = plan(dump).map_err(FileError::Dump)?;
    let table_count = u16::try_from(planned.len()).map_err(|_| FileError::TooLarge)?;
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&schema_version.to_be_bytes());
    out.extend_from_slice(&created_at_ms.to_be_bytes());
    out.extend_from_slice(&table_count.to_be_bytes());
    for (table_index, (spec, table)) in planned.into_iter().enumerate() {
        write_table(&mut out, table_index, spec, table)?;
    }
    if out.len().saturating_add(DIGEST_LEN) > MAX_BACKUP_FILE_LEN {
        return Err(FileError::TooLarge);
    }
    let sum = digest(&out);
    out.extend_from_slice(&sum);
    Ok(out)
}

/// Appends one table: its name, its column descriptors and its rows.
fn write_table(
    out: &mut Vec<u8>,
    table_index: usize,
    spec: &TableSpec,
    table: &TableDump,
) -> Result<(), FileError> {
    let at = Location {
        table: Some(table_index),
        ..Location::default()
    };
    put_bytes(out, spec.name.as_bytes(), at)?;
    let column_count = u16::try_from(spec.columns.len()).map_err(|_| FileError::Malformed {
        at,
        problem: Problem::ColumnCount,
    })?;
    out.extend_from_slice(&column_count.to_be_bytes());
    for column in spec.columns {
        put_bytes(out, column.name.as_bytes(), at)?;
        out.push(kind_byte(column.kind));
        out.push(u8::from(column.nullable));
    }
    let row_count = u64::try_from(table.rows.len()).map_err(|_| FileError::TooLarge)?;
    out.extend_from_slice(&row_count.to_be_bytes());
    for (row_index, row) in table.rows.iter().enumerate() {
        for (column_index, value) in row.iter().enumerate() {
            let at = Location {
                table: Some(table_index),
                row: u64::try_from(row_index).ok(),
                column: Some(column_index),
            };
            match value {
                Value::Null => out.push(tag::NULL),
                Value::Integer(v) => {
                    out.push(tag::INTEGER);
                    out.extend_from_slice(&v.to_be_bytes());
                }
                Value::Text(t) => {
                    if t.len() > MAX_TEXT_LEN {
                        return Err(FileError::ValueTooLarge { at });
                    }
                    out.push(tag::TEXT);
                    put_bytes(out, t.as_bytes(), at)?;
                }
                Value::Blob(b) => {
                    if b.len() > MAX_BLOB_LEN {
                        return Err(FileError::ValueTooLarge { at });
                    }
                    out.push(tag::BLOB);
                    put_bytes(out, b, at)?;
                }
            }
        }
        // Checked per row, so a dump far over the limit stops early; one row adds at most
        // `MAX_COLUMNS` values of at most 32 MiB each past the limit before it is noticed.
        if out.len().saturating_add(DIGEST_LEN) > MAX_BACKUP_FILE_LEN {
            return Err(FileError::TooLarge);
        }
    }
    Ok(())
}

/// A cursor over the tables region of the file (between the header and the digest).
struct Reader<'a> {
    /// The bytes still to read.
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Takes the next `n` bytes, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.rest.split_at_checked(n)?;
        self.rest = tail;
        Some(head)
    }

    /// Takes the next `N` bytes as an array.
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).and_then(|b| <[u8; N]>::try_from(b).ok())
    }

    /// A `u8`.
    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    /// A big-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    /// A big-endian `u32`.
    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    /// A big-endian `u64`.
    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// `bytes(x)` with `x` at most `max` long: the length is checked against `max` (`too_long`)
    /// and then against the remaining input (`UnexpectedEnd`) before anything is taken.
    fn bytes(
        &mut self,
        max: usize,
        too_long: Problem,
        at: Location,
    ) -> Result<&'a [u8], FileError> {
        let len = self.u32().ok_or(FileError::Malformed {
            at,
            problem: Problem::UnexpectedEnd,
        })?;
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > max {
            return Err(FileError::Malformed {
                at,
                problem: too_long,
            });
        }
        self.take(len).ok_or(FileError::Malformed {
            at,
            problem: Problem::UnexpectedEnd,
        })
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

/// Parses a backup file (module docs): magic, format version and digest first, then the
/// header and every table, strictly.
///
/// # Errors
///
/// [`FileError`], on any input that is not exactly a file [`write()`] produces; never panics.
pub fn parse(file: &[u8]) -> Result<BackupFile, FileError> {
    if file.len() > MAX_BACKUP_FILE_LEN {
        return Err(FileError::TooLarge);
    }
    if !file.starts_with(&MAGIC) {
        return Err(if MAGIC.starts_with(file) {
            FileError::Truncated
        } else {
            FileError::BadMagic
        });
    }
    let version = file
        .get(MAGIC.len()..MAGIC.len() + 2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_be_bytes)
        .ok_or(FileError::Truncated)?;
    if version != FORMAT_VERSION {
        return Err(FileError::UnsupportedFormat { version });
    }
    let body_len = file
        .len()
        .checked_sub(DIGEST_LEN)
        .filter(|n| *n >= HEADER_LEN)
        .ok_or(FileError::Truncated)?;
    let (body, stored) = file
        .split_at_checked(body_len)
        .ok_or(FileError::Truncated)?;
    if digest(body).as_slice() != stored {
        return Err(FileError::DigestMismatch);
    }

    let header_at = Location::default();
    let end = FileError::Malformed {
        at: header_at,
        problem: Problem::UnexpectedEnd,
    };
    let mut r = Reader {
        rest: body.get(MAGIC.len() + 2..).ok_or(FileError::Truncated)?,
    };
    let schema_version = r.u64().ok_or_else(|| end.clone())?;
    let schema_version = i64::try_from(schema_version)
        .ok()
        .filter(|v| *v >= 1)
        .ok_or(FileError::SchemaVersion)?;
    let created_at_ms = r.u64().ok_or_else(|| end.clone())?;
    let table_count = r.u16().ok_or(end)?;
    if usize::from(table_count) != TABLES.len() {
        return Err(FileError::TableCount { found: table_count });
    }
    let mut tables = Vec::with_capacity(TABLES.len());
    for (table_index, spec) in TABLES.iter().enumerate() {
        tables.push(parse_table(&mut r, table_index, spec)?);
    }
    if !r.rest.is_empty() {
        return Err(FileError::TrailingBytes);
    }
    Ok(BackupFile {
        created_at_ms,
        dump: Dump {
            schema_version,
            tables,
        },
    })
}

/// Parses one table, which must be `spec`.
fn parse_table(
    r: &mut Reader<'_>,
    table_index: usize,
    spec: &TableSpec,
) -> Result<TableDump, FileError> {
    let at = Location {
        table: Some(table_index),
        ..Location::default()
    };
    let malformed = |at: Location, problem: Problem| FileError::Malformed { at, problem };
    let name = r.bytes(MAX_NAME_LEN, Problem::Name, at)?;
    if !valid_name(name) {
        return Err(malformed(at, Problem::Name));
    }
    if name != spec.name.as_bytes() {
        return Err(malformed(at, Problem::Table));
    }
    let column_count = usize::from(
        r.u16()
            .ok_or_else(|| malformed(at, Problem::UnexpectedEnd))?,
    );
    if column_count > MAX_COLUMNS || column_count != spec.columns.len() {
        return Err(malformed(at, Problem::ColumnCount));
    }
    for (column_index, column) in spec.columns.iter().enumerate() {
        let at = Location {
            column: Some(column_index),
            ..at
        };
        let name = r.bytes(MAX_NAME_LEN, Problem::Name, at)?;
        if !valid_name(name) {
            return Err(malformed(at, Problem::Name));
        }
        let kind = r
            .u8()
            .ok_or_else(|| malformed(at, Problem::UnexpectedEnd))?;
        let nullable = r
            .u8()
            .ok_or_else(|| malformed(at, Problem::UnexpectedEnd))?;
        if name != column.name.as_bytes()
            || kind != kind_byte(column.kind)
            || nullable != u8::from(column.nullable)
        {
            return Err(malformed(at, Problem::Column));
        }
    }
    let row_count = r
        .u64()
        .ok_or_else(|| malformed(at, Problem::UnexpectedEnd))?;
    // No row vector is reserved before its rows can be there: each row takes at least
    // `min_row_len` bytes (≥ `column_count`, ADR 0023 §3).
    let min_row = u64::try_from(min_row_len(spec.columns)).unwrap_or(u64::MAX);
    let remaining = u64::try_from(r.rest.len()).unwrap_or(u64::MAX);
    if row_count
        .checked_mul(min_row)
        .is_none_or(|needed| needed > remaining)
    {
        return Err(malformed(at, Problem::RowCount));
    }
    let mut rows = Vec::with_capacity(usize::try_from(row_count).unwrap_or(0));
    for row_index in 0..row_count {
        let mut row = Vec::with_capacity(spec.columns.len());
        for (column_index, column) in spec.columns.iter().enumerate() {
            let at = Location {
                table: Some(table_index),
                row: Some(row_index),
                column: Some(column_index),
            };
            row.push(parse_value(r, column, at)?);
        }
        rows.push(row);
    }
    Ok(TableDump {
        table: spec.name.to_owned(),
        rows,
    })
}

/// Parses one value of `column`.
fn parse_value(r: &mut Reader<'_>, column: &Column, at: Location) -> Result<Value, FileError> {
    let malformed = |problem: Problem| FileError::Malformed { at, problem };
    let tag = r.u8().ok_or_else(|| malformed(Problem::UnexpectedEnd))?;
    match (tag, column.kind) {
        (tag::NULL, _) if column.nullable => Ok(Value::Null),
        (tag::INTEGER, Kind::Integer) => r
            .array::<8>()
            .map(|b| Value::Integer(i64::from_be_bytes(b)))
            .ok_or_else(|| malformed(Problem::UnexpectedEnd)),
        (tag::TEXT, Kind::Text) => {
            let bytes = r.bytes(MAX_TEXT_LEN, Problem::TextTooLong, at)?;
            let text = core::str::from_utf8(bytes).map_err(|_| malformed(Problem::Utf8))?;
            Ok(Value::Text(text.to_owned()))
        }
        (tag::BLOB, Kind::Blob) => {
            let bytes = r.bytes(MAX_BLOB_LEN, Problem::BlobTooLong, at)?;
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
        // The first table: `str("auth_accounts")`, 3 columns, `str("id")`, blob, not null.
        assert_eq!(&KAT[42..46], &13u32.to_be_bytes());
        assert_eq!(&KAT[46..59], b"auth_accounts");
        assert_eq!(&KAT[59..61], &3u16.to_be_bytes());
        assert_eq!(&KAT[61..67], b"\0\0\0\x02id");
        assert_eq!(&KAT[67..69], &[3, 0]);
        // The digest is SHA-256 of everything before it.
        let (body, sum) = KAT.split_at(KAT.len() - DIGEST_LEN);
        assert_eq!(Sha256::digest(body).as_slice(), sum);
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
        // The first table's row count (after its 3 column descriptors) set to u64::MAX.
        let mut body = KAT[..KAT.len() - DIGEST_LEN].to_vec();
        let rows_at = 42 + 4 + 13 + 2 + (4 + 2 + 2) + (4 + 10 + 2) + (4 + 13 + 2);
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
            // The memory bound of the module docs: at most 2 nullable columns of at least 3.
            let nullable = spec.columns.iter().filter(|c| c.nullable).count();
            assert!(nullable <= 2 && spec.columns.len() >= 3, "{}", spec.name);
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
            ]],
        );
        let e = write(&d, 0).unwrap_err().to_string();
        assert!(!e.contains("secret") && e.contains("row 0"), "{e}");
    }
}
