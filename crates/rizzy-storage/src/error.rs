//! The error type of `rizzy-storage`.
//!
//! **What an error may say.** Messages name a table, a column, a migration version, an engine
//! or a path the operator gave; never a bound value, a row, a token, a key or any ciphertext
//! (THREAT_MODEL INV-48). The queries here carry every value as a bound parameter (INV-53), and
//! sqlx never puts a bound parameter into its messages.
//!
//! **Driver errors are not `Debug`-forwarded.** A driver error can carry row contents outside
//! its message: a PostgreSQL error's `detail` field reads `Failing row contains (...)` for a
//! CHECK or NOT NULL violation and `Key (col)=(value) already exists` for a unique one, and
//! sqlx-postgres 0.9.0 prints `detail`, `hint` and `where` in its `Debug`. So [`Error`]'s
//! `Debug` is written by hand: for a database error it shows the error kind, the SQLSTATE code,
//! the constraint and table names and the primary message, and for any other driver or
//! migration error its `Display`, which for PostgreSQL is the primary message only. The driver
//! error stays reachable through [`std::error::Error::source`]; a caller that formats that
//! source with `Debug` bypasses this, so callers log errors with `Display` (and `source` chains
//! with `Display`, as `anyhow` and `tracing`'s `%` do).

use std::fmt;
use std::path::PathBuf;

/// Which database engine an operation ran on, or which one a check was about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// SQLite, the default (ADR 0011 point 1).
    Sqlite,
    /// PostgreSQL, selected with a `postgres://` URL (ADR 0011 point 1).
    Postgres,
}

impl fmt::Display for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sqlite => "SQLite",
            Self::Postgres => "PostgreSQL",
        })
    }
}

/// Everything that can go wrong in `rizzy-storage`.
///
/// `Debug` never shows a driver error's `detail`, `hint` or `where` fields (see the module docs).
#[non_exhaustive]
pub enum Error {
    /// The database driver failed: connecting, running a query, or decoding a column.
    Database(sqlx::Error),
    /// Applying or validating the embedded migrations failed (for example a migration applied
    /// to this database was changed, or the database was migrated by a newer release).
    Migrate(sqlx::migrate::MigrateError),
    /// A file operation on a path the caller gave failed (the writer lock file, a backup copy).
    Io {
        /// What was being done, e.g. "create the backup copy".
        action: &'static str,
        /// The path the caller gave.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Another process holds the SQLite writer lock (ADR 0010 §2: one process writes the
    /// file).
    WriterLockHeld {
        /// The lock file.
        path: PathBuf,
    },
    /// The writer lock passed to an SQLite open was taken for another database file.
    WriterLockMismatch,
    /// A write was asked of a database opened read-only (the `backup` reader, ADR 0010 §2).
    ReadOnly,
    /// The operation exists only on the other engine (e.g. `VACUUM INTO` on PostgreSQL).
    WrongEngine {
        /// The engine the operation needs.
        needed: Engine,
    },
    /// PostgreSQL has migrations this release would apply, and PostgreSQL migrates only
    /// explicitly (ADR 0011 point 9). The operator runs `rizzy-vault migrate`.
    PendingMigrations {
        /// The versions not yet applied, ascending.
        versions: Vec<i64>,
    },
    /// The database is not at this release's schema: migrations this release knows are not
    /// applied to it. [`Database::dump`](crate::Database::dump) refuses it, because it reads
    /// this release's tables and columns and stamps this release's version.
    SchemaNotCurrent {
        /// The versions not applied, ascending.
        pending: Vec<i64>,
    },
    /// A migration is recorded as failed ("dirty"); the database needs the operator.
    DirtyMigration {
        /// The failed version.
        version: i64,
    },
    /// A remote PostgreSQL URL does not ask for `sslmode=verify-full` (ADR 0011 point 1).
    InsecurePostgresTls,
    /// A value does not fit the SQL column type: a `u64` above `i64::MAX`, or a negative
    /// integer read back where the schema allows none.
    OutOfRange {
        /// The column or quantity, e.g. "`device_seq`".
        what: &'static str,
    },
    /// A stored value has the wrong shape, e.g. a restore generation that is not 16 bytes.
    Corrupt {
        /// What was wrong, naming the table and column.
        what: &'static str,
    },
    /// `restore` refused its input or its target (see the message).
    Restore(RestoreError),
}

/// Why `restore` refused (ADR 0011 "Backups").
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestoreError {
    /// The target database already holds rows; `restore` loads only into an empty database.
    TargetNotEmpty,
    /// The dump was written at another schema version than this release's.
    SchemaVersion {
        /// The dump's schema version.
        dump: i64,
        /// This release's schema version.
        current: i64,
    },
    /// The dump names a table this release does not back up.
    UnknownTable {
        /// Its position in the dump.
        index: usize,
    },
    /// The dump holds a table twice, or out of the restore order.
    TableOrder {
        /// Its position in the dump.
        index: usize,
    },
    /// The dump leaves out a table this release backs up. A dump carries every backed-up
    /// table, an empty one included (ADR 0011 "Backups": "every table as rows"), so a
    /// truncated dump is refused rather than restored with a table emptied.
    MissingTable {
        /// The missing table.
        name: &'static str,
    },
    /// A row does not match its table's columns: wrong arity, a value of the wrong kind, or
    /// NULL in a NOT NULL column.
    Row {
        /// The table.
        table: &'static str,
        /// The row's position in the table.
        row: usize,
        /// The column's position, when the problem is one column.
        column: Option<usize>,
    },
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetNotEmpty => f.write_str(
                "the target database is not empty; restore loads only into an empty database",
            ),
            Self::SchemaVersion { dump, current } => write!(
                f,
                "the dump has schema version {dump}, this release has {current}; restore it \
                 with the release that wrote it, then upgrade"
            ),
            Self::UnknownTable { index } => {
                write!(
                    f,
                    "table {index} of the dump is not a table this release backs up"
                )
            }
            Self::TableOrder { index } => {
                write!(f, "table {index} of the dump is repeated or out of order")
            }
            Self::MissingTable { name } => {
                write!(f, "the dump has no `{name}` table; it is incomplete")
            }
            Self::Row { table, row, column } => match column {
                Some(column) => write!(
                    f,
                    "row {row} of `{table}`: column {column} has the wrong kind or is NULL"
                ),
                None => write!(f, "row {row} of `{table}` has the wrong number of columns"),
            },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => write!(f, "database error: {e}"),
            Self::Migrate(e) => write!(f, "migration error: {e}"),
            Self::Io {
                action,
                path,
                source,
            } => {
                write!(f, "cannot {action} at {}: {source}", path.display())
            }
            Self::WriterLockHeld { path } => write!(
                f,
                "another process holds the database writer lock {}; stop it first (one process \
                 writes an SQLite database)",
                path.display()
            ),
            Self::WriterLockMismatch => {
                f.write_str("the writer lock was taken for another database file")
            }
            Self::ReadOnly => f.write_str("the database was opened read-only"),
            Self::WrongEngine { needed } => write!(f, "this operation needs {needed}"),
            Self::PendingMigrations { versions } => write!(
                f,
                "the PostgreSQL database has {} pending migration(s) ({versions:?}); run \
                 `rizzy-vault migrate` before starting the server",
                versions.len()
            ),
            Self::SchemaNotCurrent { pending } => write!(
                f,
                "the database is not at this release's schema ({} migration(s) not applied: \
                 {pending:?}); migrate it first, or use the release that matches it",
                pending.len()
            ),
            Self::DirtyMigration { version } => write!(
                f,
                "migration {version} is recorded as failed; the database needs manual repair"
            ),
            Self::InsecurePostgresTls => {
                f.write_str("a remote PostgreSQL database must be reached with sslmode=verify-full")
            }
            Self::OutOfRange { what } => write!(f, "{what} is out of range for the database"),
            Self::Corrupt { what } => write!(f, "corrupt stored value: {what}"),
            Self::Restore(e) => write!(f, "restore refused: {e}"),
        }
    }
}

/// A driver error, shown without the fields that can carry row contents (see the module docs).
struct RedactedSqlx<'a>(&'a sqlx::Error);

impl fmt::Debug for RedactedSqlx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            sqlx::Error::Database(db) => f
                .debug_struct("DatabaseError")
                .field("kind", &db.kind())
                .field("code", &db.code())
                .field("constraint", &db.constraint())
                .field("table", &db.table())
                .field("message", &db.message())
                .finish(),
            other => f
                .debug_tuple("Driver")
                .field(&format_args!("{other}"))
                .finish(),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(e) => f.debug_tuple("Database").field(&RedactedSqlx(e)).finish(),
            // A migration error can wrap a driver error; its `Display` shows only the driver
            // error's `Display`.
            Self::Migrate(e) => f
                .debug_tuple("Migrate")
                .field(&format_args!("{e}"))
                .finish(),
            Self::Io {
                action,
                path,
                source,
            } => f
                .debug_struct("Io")
                .field("action", action)
                .field("path", path)
                .field("source", source)
                .finish(),
            Self::WriterLockHeld { path } => f
                .debug_struct("WriterLockHeld")
                .field("path", path)
                .finish(),
            Self::WriterLockMismatch => f.write_str("WriterLockMismatch"),
            Self::ReadOnly => f.write_str("ReadOnly"),
            Self::WrongEngine { needed } => f
                .debug_struct("WrongEngine")
                .field("needed", needed)
                .finish(),
            Self::PendingMigrations { versions } => f
                .debug_struct("PendingMigrations")
                .field("versions", versions)
                .finish(),
            Self::SchemaNotCurrent { pending } => f
                .debug_struct("SchemaNotCurrent")
                .field("pending", pending)
                .finish(),
            Self::DirtyMigration { version } => f
                .debug_struct("DirtyMigration")
                .field("version", version)
                .finish(),
            Self::InsecurePostgresTls => f.write_str("InsecurePostgresTls"),
            Self::OutOfRange { what } => f.debug_struct("OutOfRange").field("what", what).finish(),
            Self::Corrupt { what } => f.debug_struct("Corrupt").field("what", what).finish(),
            Self::Restore(e) => f.debug_tuple("Restore").field(e).finish(),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(e) => Some(e),
            Self::Migrate(e) => Some(e),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}

impl From<sqlx::migrate::MigrateError> for Error {
    fn from(e: sqlx::migrate::MigrateError) -> Self {
        Self::Migrate(e)
    }
}

impl From<RestoreError> for Error {
    fn from(e: RestoreError) -> Self {
        Self::Restore(e)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::error::Error as StdError;

    use sqlx::error::{DatabaseError, ErrorKind};

    use super::*;

    /// A driver error whose `Debug` carries a row, as sqlx-postgres's `PgDatabaseError` does
    /// with its `detail` field.
    #[derive(Debug)]
    struct RowCarrying {
        /// Stands in for PostgreSQL's primary message.
        message: &'static str,
        /// Stands in for PostgreSQL's `detail`.
        detail: &'static str,
    }

    impl fmt::Display for RowCarrying {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.message())
        }
    }

    impl StdError for RowCarrying {}

    impl DatabaseError for RowCarrying {
        fn message(&self) -> &str {
            self.message
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed("23514"))
        }
        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }
        fn constraint(&self) -> Option<&str> {
            Some("h_rec_len")
        }
        fn kind(&self) -> ErrorKind {
            ErrorKind::CheckViolation
        }
    }

    #[test]
    fn debug_leaves_out_driver_error_detail() {
        let inner = RowCarrying {
            message: "new row for relation \"vault_ops\" violates check constraint \"h_rec_len\"",
            detail: "Failing row contains (\\xdeadbeefcafe, alice)",
        };
        assert!(format!("{inner:?}").contains("deadbeef") && inner.detail.contains("alice"));
        let e = Error::from(sqlx::Error::Database(Box::new(inner)));
        let debug = format!("{e:?}");
        assert!(
            !debug.contains("deadbeef") && !debug.contains("alice"),
            "{debug}"
        );
        assert!(
            debug.contains("23514") && debug.contains("h_rec_len"),
            "{debug}"
        );
        let display = format!("{e}");
        assert!(!display.contains("deadbeef"), "{display}");
    }
}
