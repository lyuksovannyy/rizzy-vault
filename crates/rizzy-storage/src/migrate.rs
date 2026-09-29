//! Embedded, forward-only migrations, one ordered sequence per engine (ADR 0011 points 8-10).
//!
//! The SQL lives in `migrations/sqlite/` and `migrations/postgres/`, one file per version in
//! each, and is embedded with `include_str!` ([`MIGRATIONS`]). Each file name carries the
//! owning domain (`0002_vault_initial.sql`). There are no down-migrations: a bad migration is
//! fixed by a new one. sqlx's migrator records each applied version with a checksum in
//! `_sqlx_migrations`. [`Database::pending_migrations`], which the startup rule, [`Database::dump`]
//! and [`Database::restore`] run first, refuses a database whose applied migrations were
//! changed (a checksum differs) or that a newer release migrated ([`Error::Migrate`]), whether
//! or not anything is pending; sqlx's migrator checks the same again when it applies one.
//!
//! **When they run** (ADR 0011 point 9, as ADR 0022 amends it):
//! - **SQLite:** automatically at startup, [`Database::migrate_at_startup`]. Only when a
//!   migration is pending and an earlier one was applied (the database holds data), the
//!   server first writes a consistent copy next to the database with `VACUUM INTO`, mode 0600
//!   ([`Database::vacuum_into`]). `worker` deletes it 24 h after the migrated server passed its
//!   startup self-check, and an account deletion deletes it at once
//!   ([`remove_pre_migration_copy`]); both callers are in `rizzy-server`.
//! - **PostgreSQL:** only explicitly, with `rizzy-vault migrate` ([`Database::migrate`]). At
//!   startup, [`Database::migrate_at_startup`] refuses with [`Error::PendingMigrations`], which
//!   names that command.

use std::borrow::Cow;
use std::path::Path;

use sqlx::migrate::{MigrateError, Migration, MigrationType, Migrator};
use sqlx::{Row, SqlStr};

use crate::db::{Conn, Database};
use crate::error::{Engine, Error};

/// One migration version, written once per engine.
#[derive(Clone, Copy, Debug)]
pub struct MigrationFile {
    /// The version, strictly increasing.
    pub version: i64,
    /// The description: the file name after the version, without `.sql`. It starts with the
    /// owning domain (ADR 0011 point 8).
    pub description: &'static str,
    /// The SQLite text.
    sqlite: &'static str,
    /// The PostgreSQL text.
    postgres: &'static str,
}

impl MigrationFile {
    /// The text for `engine`.
    #[must_use]
    pub fn sql(&self, engine: Engine) -> &'static str {
        match engine {
            Engine::Sqlite => self.sqlite,
            Engine::Postgres => self.postgres,
        }
    }
}

/// Every migration, in order. A test checks that the two directories hold exactly these files.
pub const MIGRATIONS: &[MigrationFile] = &[
    MigrationFile {
        version: 1,
        description: "auth_initial",
        sqlite: include_str!("../migrations/sqlite/0001_auth_initial.sql"),
        postgres: include_str!("../migrations/postgres/0001_auth_initial.sql"),
    },
    MigrationFile {
        version: 2,
        description: "vault_initial",
        sqlite: include_str!("../migrations/sqlite/0002_vault_initial.sql"),
        postgres: include_str!("../migrations/postgres/0002_vault_initial.sql"),
    },
    MigrationFile {
        version: 3,
        description: "storage_restore",
        sqlite: include_str!("../migrations/sqlite/0003_storage_restore.sql"),
        postgres: include_str!("../migrations/postgres/0003_storage_restore.sql"),
    },
];

/// This release's schema version: the last migration's version. A logical backup is stamped
/// with it.
#[must_use]
pub fn schema_version() -> i64 {
    MIGRATIONS.last().map_or(0, |m| m.version)
}

/// Whether sqlx's migration table exists (SQLite).
const SQLITE_MIGRATIONS_TABLE_EXISTS: &str =
    include_str!("../queries/sqlite/migrations_table_exists.sql");
/// Whether sqlx's migration table exists (PostgreSQL).
const POSTGRES_MIGRATIONS_TABLE_EXISTS: &str =
    include_str!("../queries/postgres/migrations_table_exists.sql");
/// The applied versions and their success flags.
const APPLIED_MIGRATIONS: &str = include_str!("../queries/storage/applied_migrations.sql");

/// What [`Database::migrate_at_startup`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupMigration {
    /// Nothing was pending.
    UpToDate,
    /// A new database was created: every migration was pending and none had been applied, so
    /// there was nothing to copy.
    Created,
    /// Pending migrations were applied after a pre-migration copy was written.
    MigratedAfterCopy,
}

/// The sqlx migrator for `engine`, built from [`MIGRATIONS`].
fn migrator(engine: Engine) -> Migrator {
    Migrator::with_migrations(
        MIGRATIONS
            .iter()
            .map(|m| {
                Migration::new(
                    m.version,
                    Cow::Borrowed(m.description),
                    MigrationType::Simple,
                    SqlStr::from_static(m.sql(engine)),
                    false,
                )
            })
            .collect(),
    )
}

/// One applied migration as sqlx recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Applied {
    /// The version.
    pub(crate) version: i64,
    /// The SHA-384 checksum of the SQL text that was applied.
    pub(crate) checksum: Vec<u8>,
}

/// The applied migrations, ascending, read on `conn` (empty when no migration ever ran).
///
/// # Errors
///
/// - [`Error::DirtyMigration`] when a migration is recorded as failed.
/// - [`Error::Database`] when the query fails.
pub(crate) async fn applied_on(conn: Conn<'_>) -> Result<Vec<Applied>, Error> {
    let rows = crate::on_engine!(conn, |c| {
        let exists: i64 = sqlx::query_scalar(table_exists_query(&*c))
            .fetch_one(&mut *c)
            .await?;
        if exists == 0 {
            Vec::new()
        } else {
            let mut out = Vec::new();
            for row in sqlx::query(APPLIED_MIGRATIONS).fetch_all(&mut *c).await? {
                let version: i64 = row.try_get(0)?;
                let success: bool = row.try_get(1)?;
                let checksum: Vec<u8> = row.try_get(2)?;
                out.push((version, success, checksum));
            }
            out
        }
    });
    let mut applied = Vec::with_capacity(rows.len());
    for (version, success, checksum) in rows {
        if !success {
            return Err(Error::DirtyMigration { version });
        }
        applied.push(Applied { version, checksum });
    }
    Ok(applied)
}

/// Checks the applied migrations against this release's for `engine`, and returns the pending
/// versions, ascending.
///
/// Every applied version must be one of [`MIGRATIONS`], applied from exactly the text this
/// release embeds (the same SHA-384 checksum sqlx's migrator compares). This runs whether or
/// not anything is pending, so a database whose recorded migrations differ from this build's is
/// refused at startup, before anything else touches it (ADR 0011 point 8: forward-only, a
/// changed migration is never accepted).
///
/// # Errors
///
/// - [`Error::Migrate`] (`VersionMissing`) for an applied version this release does not know:
///   a newer release migrated the database.
/// - [`Error::Migrate`] (`VersionMismatch`) for an applied version whose checksum differs from
///   this release's.
pub(crate) fn check_applied(engine: Engine, applied: &[Applied]) -> Result<Vec<i64>, Error> {
    let migrator = migrator(engine);
    for a in applied {
        let known = migrator
            .iter()
            .find(|m| m.version == a.version)
            .ok_or(MigrateError::VersionMissing(a.version))?;
        if *known.checksum != *a.checksum {
            return Err(MigrateError::VersionMismatch(a.version).into());
        }
    }
    Ok(MIGRATIONS
        .iter()
        .map(|m| m.version)
        .filter(|v| !applied.iter().any(|a| a.version == *v))
        .collect())
}

/// The engine-specific "does `_sqlx_migrations` exist" query, chosen by connection type.
trait TableExistsQuery {
    /// The query text.
    fn query(&self) -> &'static str;
}

impl TableExistsQuery for sqlx::SqliteConnection {
    fn query(&self) -> &'static str {
        SQLITE_MIGRATIONS_TABLE_EXISTS
    }
}

impl TableExistsQuery for sqlx::PgConnection {
    fn query(&self) -> &'static str {
        POSTGRES_MIGRATIONS_TABLE_EXISTS
    }
}

/// [`TableExistsQuery::query`] for a connection of either engine.
fn table_exists_query<C: TableExistsQuery>(conn: &C) -> &'static str {
    conn.query()
}

impl Database {
    /// The applied migration versions, ascending.
    ///
    /// # Errors
    ///
    /// - [`Error::DirtyMigration`] when a migration is recorded as failed.
    /// - [`Error::Database`] when the query fails.
    pub async fn applied_migrations(&self) -> Result<Vec<i64>, Error> {
        let mut tx = self.begin_read().await?;
        let applied = applied_on(tx.conn()).await?;
        tx.finish().await?;
        Ok(applied.into_iter().map(|a| a.version).collect())
    }

    /// The migrations this release would apply, ascending, after checking that every applied
    /// migration is one of this release's with an unchanged checksum.
    ///
    /// # Errors
    ///
    /// - [`Error::Migrate`] (`VersionMissing`) when the database has a version this release
    ///   does not know: a newer release migrated it, and this one must not run against it.
    /// - [`Error::Migrate`] (`VersionMismatch`) when an applied migration's text differs from
    ///   this release's.
    /// - Those of [`Database::applied_migrations`].
    pub async fn pending_migrations(&self) -> Result<Vec<i64>, Error> {
        let mut tx = self.begin_read().await?;
        let applied = applied_on(tx.conn()).await?;
        tx.finish().await?;
        check_applied(self.engine(), &applied)
    }

    /// Applies every pending migration, each in its own transaction. On SQLite it runs on the
    /// writer connection; on PostgreSQL sqlx's migrator holds a session advisory lock while it
    /// runs, so two `migrate` commands do not interleave.
    ///
    /// # Errors
    ///
    /// - [`Error::ReadOnly`] on a read-only SQLite handle.
    /// - [`Error::Migrate`] when a migration fails, or the applied ones do not match this
    ///   release's (changed checksum, unknown version, failed "dirty" version).
    pub async fn migrate(&self) -> Result<(), Error> {
        match self {
            Self::Sqlite(_) => {
                let writer = self.sqlite_writer()?.ok_or(Error::ReadOnly)?;
                migrator(Engine::Sqlite).run(writer).await?;
            }
            Self::Postgres(pool) => migrator(Engine::Postgres).run(pool).await?,
        }
        Ok(())
    }

    /// The startup rule of ADR 0011 point 9.
    ///
    /// - Both engines: first, every applied migration is checked against this release's,
    ///   version and checksum ([`Database::pending_migrations`]), even when nothing is pending,
    ///   so a database migrated by another build is refused here rather than failing later.
    /// - SQLite: if nothing is pending, nothing happens. If migrations are pending and at
    ///   least one was applied before, writes the pre-migration copy to `pre_migration_copy`
    ///   (which must not exist; mode 0600 on Unix) with `VACUUM INTO`, then migrates. A new
    ///   database (nothing applied) is migrated without a copy: it holds nothing to copy.
    /// - PostgreSQL: refuses if anything is pending; `pre_migration_copy` is not used.
    ///
    /// # Errors
    ///
    /// - [`Error::PendingMigrations`] on PostgreSQL with pending migrations.
    /// - [`Error::Io`] when the copy file cannot be created (it exists already, for example).
    /// - Those of [`Database::pending_migrations`], [`Database::vacuum_into`] and
    ///   [`Database::migrate`].
    pub async fn migrate_at_startup(
        &self,
        pre_migration_copy: &Path,
    ) -> Result<StartupMigration, Error> {
        let pending = self.pending_migrations().await?;
        if pending.is_empty() {
            return Ok(StartupMigration::UpToDate);
        }
        match self.engine() {
            Engine::Postgres => Err(Error::PendingMigrations { versions: pending }),
            Engine::Sqlite => {
                let fresh = self.applied_migrations().await?.is_empty();
                if !fresh {
                    self.vacuum_into(pre_migration_copy).await?;
                }
                self.migrate().await?;
                Ok(if fresh {
                    StartupMigration::Created
                } else {
                    StartupMigration::MigratedAfterCopy
                })
            }
        }
    }
}

/// Deletes the pre-migration copy (ADR 0011 point 9: by `worker` after 24 h, and at once on an
/// account deletion). A missing file is not an error.
///
/// `secure_delete` does not reach this file: deleting it unlinks it, and the filesystem may keep
/// its blocks (THREAT_MODEL AR-11).
///
/// # Errors
///
/// [`Error::Io`] when the file exists and cannot be removed.
pub fn remove_pre_migration_copy(path: &Path) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(Error::Io {
            action: "remove the pre-migration copy",
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_strictly_increase_and_name_a_domain() {
        let mut last = 0;
        for m in MIGRATIONS {
            assert!(m.version > last, "{}", m.version);
            last = m.version;
            let domain = m.description.split('_').next().unwrap();
            assert!(
                ["auth", "vault", "storage"].contains(&domain),
                "{}: the name starts with the owning domain",
                m.description
            );
        }
        assert_eq!(schema_version(), last);
    }

    #[test]
    fn migrator_holds_every_version_once() {
        for engine in [Engine::Sqlite, Engine::Postgres] {
            let m = migrator(engine);
            let versions: Vec<i64> = m.iter().map(|m| m.version).collect();
            let expected: Vec<i64> = MIGRATIONS.iter().map(|m| m.version).collect();
            assert_eq!(versions, expected);
        }
    }
}
