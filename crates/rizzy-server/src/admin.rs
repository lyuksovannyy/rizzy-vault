//! The admin subcommands the Accepted ADRs name for M1, as far as they are specified
//! ([ADR 0010] §2, §4; [ADR 0011] "Migrations", "Backups"; CRYPTO.md §5.8, §5.11).
//!
//! | Command | Spec | Lock |
//! |---|---|---|
//! | `secrets init` | ADR 0010 §4: "creates the secrets once, run as a one-off with the secrets mount writable" | none (no database) |
//! | `secrets rotate` | CRYPTO.md §5.8 "Rotating `server_setup`" steps 1–2; ADR 0010 §4 | exclusive |
//! | `secrets rotate --data-key` | CRYPTO.md §5.11 "Rotation" | exclusive |
//! | `backup-secrets` | ADR 0011 "Backups" and owner decision 3; CRYPTO.md §5.11 | none (reads the secrets file only) |
//! | `migrate` | ADR 0011 point 9 | exclusive |
//! | `backup --out <file\|->` | ADR 0011 "Backups"; [ADR 0023] §4, §6 | none: the read-only reader on `SQLite`, a `REPEATABLE READ` transaction on `PostgreSQL` |
//! | `restore --in <file\|->` | ADR 0011 "Backups"; [ADR 0023] §5, §6 | exclusive |
//!
//! **Exclusive** means every server process is shut out while the command runs (ADR 0010 §2:
//! "`restore`, `migrate` and `secrets rotate` take the writer lock. They run only while the
//! server is stopped"; [ADR 0023] §5 step 1 for `PostgreSQL`):
//! - `SQLite`: the writer lock next to the database file, which a running server holds.
//! - `PostgreSQL`: the instance lock, taken exclusively on a dedicated connection outside the
//!   pool (`rizzy_storage::instance_lock`, [`server::take_instance_lock`]). Every server
//!   process holds it shared, whatever its roles, so the command is refused while any replica
//!   runs, and a server refuses to start while the command runs.
//!
//! A refusal is a runtime failure (exit 1): stop the server and run the command again.
//!
//! # `secrets rotate --data-key` and the old key (CRYPTO.md §5.11 "Rotation")
//!
//! "`rizzy-vault secrets rotate --data-key` adds a new current key; `worker` re-seals TOTP rows
//! under the account lock, and the old key is dropped once no row names it."
//! - The command adds the key and marks it current.
//! - The running server's `worker` re-seals the TOTP rows under it ([`crate::worker`] step 2).
//! - **Dropping** is this command's too, on a later run: the server never writes the secrets
//!   file (ADR 0010 §4), and this command is the one that runs with the secrets mount writable
//!   and the server shut out. After it has added the new key it drops every other key that no
//!   sealed row names any more (`ServerSecrets::drop_unused_data_keys`), and reports the ids.
//!   So a key rotated away is removed from the file by the next `secrets rotate --data-key`
//!   after the worker has re-sealed, or at once when no row names it (an instance without 2FA
//!   rows). No Accepted ADR names who drops the key or when; this reading, and the lack of a
//!   way to drop a key without adding one, are reported to the owner.
//! - The drop needs the database at this release's schema; on a database that is new, behind,
//!   or unreadable as such, nothing is dropped and the rotation still happens. With `SQLite`,
//!   when the database file does not exist yet, the command takes the writer lock alone.
//! - A database backup taken before the rows were re-sealed still names the old key:
//!   restoring it needs a secrets backup from before the drop (step 4 below refuses otherwise).
//!
//! # `backup` and `restore` ([ADR 0023])
//!
//! `backup` dumps the database in one read snapshot next to the running server, writes it as
//! the backup file of `rizzy_storage::backup::file` (canonical, with its trailing SHA-256, and
//! never longer than the reader's 2 GiB limit), and prints the file's length and SHA-256 on
//! stderr for the operator to record. `--out -` writes the file to stdout, for piping into
//! `age` or a backup tool, and is refused when stdout is a terminal (usage error). Otherwise
//! the file is created new with mode 0600, never over an existing one, and removed again if
//! writing it fails ([`fsutil::write_new_private`]). The server secrets are never in it
//! (INV-50).
//!
//! `restore` runs the steps of ADR 0023 §5, in order:
//! 1. **Exclude every server process and check the target.** `SQLite`: take the writer lock
//!    (the server must be stopped). `PostgreSQL`: take the instance lock exclusively; it is
//!    refused while any server process holds it. Then require an empty target: no migration
//!    applied, or exactly this release's, and no row
//!    ([`rizzy_storage::Database::check_restore_target`]).
//! 2. **Read the file** (at most 2 GiB, from a path or `-` for stdin) and parse it: magic,
//!    format version and SHA-256 first, then every table strictly.
//! 3. **Require this release's schema version**; an older backup is restored with the release
//!    that wrote it, then upgraded with `migrate` (ADR 0023 open question 4, as recommended).
//! 4. **Check the secrets file against the backup** (CRYPTO.md §5.8, §5.11):
//!    [`ServerSecrets::check_dump`] refuses a setup mismatch, a fresh secrets file, and a TOTP
//!    row sealed under a data key the file lacks, and tells the operator to restore the
//!    secrets first.
//! 5. **Draw a new restore generation** from the OS CSPRNG (ADR 0021 §2), check once more that
//!    the instance lock is still held (reading a large file takes time, and a lock whose
//!    connection dropped meanwhile excludes nobody), and load the rows in one transaction, which opens a reconciliation epoch for every restored account (INV-59)
//!    and raises the store-sequence counters (`rizzy_storage::Database::restore`).
//! 6. **Report**: the caller prints the row count, the number of accounts in reconciliation
//!    and the INV-59 notice with the AR-19 warning ([`RESTORE_NOTICE`]).
//!
//! Any failure leaves the target with no application row; it may be left migrated to this
//! release's schema, and a retry into it is allowed.
//!
//! **Not here, and why** (reported to the owner):
//! - Deleting an old OPAQUE setup after the grace period (CRYPTO.md §5.8 "Rotating
//!   `server_setup`" step 4: "After a grace period set by the admin, delete #1"). The section
//!   names no command, no setting for the grace period, no rule for which setup may go (the
//!   startup check already tolerates records that name a setup the file lacks) and nothing
//!   about the records left behind ("when the admin marks the records invalid" has no
//!   mechanism either). It is not specified concretely enough to implement without inventing
//!   an operator interface, so an old setup stays in the file until the owner decides.
//! - A way to drop an unused data key without adding a new one (section above).
//! - The bootstrap token (INV-69) is generated into the file by `secrets init` and never
//!   printed or logged: its only reader is the M3 admin API, which defines how it is shown once.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md
//! [ADR 0023]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0023-logical-backup-format.md

use core::fmt;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::Path;

use rand_core::Rng as _;
use rizzy_domain_auth::AuthError;
use rizzy_domain_auth::secrets::SecretsError;
use rizzy_domain_auth::{ServerSecrets, StartupCheckError};
use rizzy_storage::backup::file::{
    self as backup_file, DIGEST_LEN, FileError, MAX_BACKUP_FILE_LEN,
};
use rizzy_storage::{
    Database, InstanceLock, InstanceLockMode, PostgresOptions, RestoreError, RestoreGeneration,
    SqliteOptions, StartupMigration, WriterLock, schema_version,
};
use zeroize::Zeroizing;

use crate::config::{Config, DatabaseConfig};
use crate::fsutil::{self, ReadError};
use crate::secrets_backup::{self, BackupError};
use crate::secrets_file::{self, MAX_SECRETS_FILE_LEN, SecretsFileError};
use crate::server::{self, ServeError};
use crate::sys::{now_ms, os_rng};

/// The longest passphrase file read: 4 KiB.
pub const MAX_PASSPHRASE_FILE_LEN: usize = 4096;

/// Why an admin command failed. `Display` names what failed, never a secret.
#[derive(Debug)]
#[non_exhaustive]
pub enum AdminError {
    /// The secrets file resolves inside the data directory, or cannot be resolved.
    SecretsInsideDataDir,
    /// `secrets init` found a file at the path.
    SecretsFileExists,
    /// The secrets file could not be read or parsed.
    Secrets(SecretsFileError),
    /// A rotation would overflow an id.
    Rotation(SecretsError),
    /// A file could not be written.
    Write(std::io::ErrorKind),
    /// The passphrase file could not be read.
    PassphraseFile,
    /// Sealing or the passphrase failed.
    Backup(BackupError),
    /// The database could not be opened or migrated, or its `PostgreSQL` instance lock could
    /// not be taken or was lost (a server process still runs).
    Serve(ServeError),
    /// The writer lock could not be taken: the server is probably running.
    Lock(rizzy_storage::Error),
    /// `secrets rotate --data-key` could not read which data keys the database still names.
    DataKeysInUse(AuthError),
    /// `backup --out -` with a terminal on stdout (ADR 0023 §6). A usage error.
    StdoutIsTerminal,
    /// The database could not be dumped or restored into (the target is not empty, say).
    Storage(rizzy_storage::Error),
    /// The backup file could not be written or parsed.
    BackupFile(FileError),
    /// The backup file could not be read.
    Input(std::io::ErrorKind),
    /// The secrets file does not belong to the backup (ADR 0023 §5 step 4).
    SecretsMismatch(StartupCheckError),
}

impl AdminError {
    /// Whether this is a usage or configuration error (exit code 2) rather than a runtime
    /// failure (exit code 1).
    #[must_use]
    pub const fn is_usage(&self) -> bool {
        matches!(self, Self::StdoutIsTerminal)
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretsInsideDataDir => f.write_str(
                "the secrets file must not be inside the data directory (ADR 0010 §4), or its \
                 location could not be resolved",
            ),
            Self::SecretsFileExists => {
                f.write_str("a secrets file already exists at that path; it is never overwritten")
            }
            Self::Secrets(e) => write!(f, "{e}"),
            Self::Rotation(e) => write!(f, "rotation refused: {e}"),
            Self::Write(kind) => write!(f, "cannot write the file: {kind}"),
            Self::PassphraseFile => f.write_str("cannot read the passphrase file"),
            Self::Backup(e) => write!(f, "{e}"),
            Self::Serve(e) => write!(f, "{e}"),
            Self::DataKeysInUse(e) => write!(
                f,
                "cannot read which data keys the database still names ({e}); nothing was \
                 rotated"
            ),
            Self::Lock(e) => write!(
                f,
                "cannot take the writer lock (is the server running?): {e}"
            ),
            Self::StdoutIsTerminal => f.write_str(
                "refusing to write the backup to a terminal; redirect stdout or name a file with \
                 --out",
            ),
            Self::Storage(e) => write!(f, "database: {e}"),
            Self::BackupFile(e) => write!(f, "{e}"),
            Self::Input(kind) => write!(f, "cannot read the backup file: {kind}"),
            Self::SecretsMismatch(e) => write!(
                f,
                "the secrets file does not belong to this backup ({e}); restore the instance's \
                 secrets file first, never a new one"
            ),
        }
    }
}

impl std::error::Error for AdminError {}

/// Refuses a secrets path inside the data directory.
fn check_location(config: &Config) -> Result<(), AdminError> {
    if fsutil::is_inside(&config.data_dir, &config.secrets_file).unwrap_or(true) {
        return Err(AdminError::SecretsInsideDataDir);
    }
    Ok(())
}

/// `rizzy-vault secrets init`: generates the secrets (setup 1, `enum_key`, data key 1, the
/// bootstrap token) and writes them to a new file with mode 0600. Never overwrites.
///
/// # Errors
/// [`AdminError`].
pub fn secrets_init(config: &Config) -> Result<(), AdminError> {
    check_location(config)?;
    if config.secrets_file.exists() {
        return Err(AdminError::SecretsFileExists);
    }
    let secrets = ServerSecrets::generate(&mut os_rng());
    let bytes = secrets_file::serialize(&secrets).map_err(AdminError::Secrets)?;
    fsutil::write_new_private(&config.secrets_file, &bytes).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => AdminError::SecretsFileExists,
        kind => AdminError::Write(kind),
    })
}

/// What to rotate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotate {
    /// A new `server_setup`, which new registrations use (CRYPTO.md §5.8 steps 1–2).
    Setup,
    /// A new current `server_data_key` (CRYPTO.md §5.11 "Rotation").
    DataKey,
}

/// What `secrets rotate` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotated {
    /// The id of the new setup or data key.
    pub id: u32,
    /// The data keys dropped from the file because no sealed row names them any more
    /// (`--data-key` only; module docs), ascending.
    pub dropped_data_keys: Vec<u32>,
}

/// What shuts every server process out while an exclusive admin command runs (module docs).
enum Exclusion {
    /// The `SQLite` writer lock alone: the database is not opened.
    WriterLock(WriterLock),
    /// The opened database (which owns the `SQLite` writer lock) and its instance lock, taken
    /// exclusively.
    Database(Database, InstanceLock),
}

impl Exclusion {
    /// The opened database, if this exclusion has one.
    const fn database(&self) -> Option<&Database> {
        match self {
            Self::WriterLock(_) => None,
            Self::Database(db, _) => Some(db),
        }
    }

    /// Lets the servers back in: closes the pools, then releases the lock.
    async fn end(self) {
        match self {
            Self::WriterLock(lock) => drop(lock),
            Self::Database(db, lock) => {
                db.close().await;
                server::release_instance_lock(lock).await;
            }
        }
    }
}

/// Opens the database with every server process shut out (module docs): the `SQLite` writer
/// lock, or the `PostgreSQL` instance lock taken exclusively. Migrates nothing.
async fn open_exclusive(config: &Config) -> Result<(Database, InstanceLock), AdminError> {
    let db = server::open_database(config).await.map_err(|e| match e {
        ServeError::Storage(e @ rizzy_storage::Error::WriterLockHeld { .. }) => AdminError::Lock(e),
        e => AdminError::Serve(e),
    })?;
    match server::take_instance_lock(&db, InstanceLockMode::Exclusive).await {
        Ok(lock) => Ok((db, lock)),
        Err(e) => {
            db.close().await;
            Err(AdminError::Serve(e))
        }
    }
}

/// Whether `db` is at exactly this release's schema, so the auth tables can be read. Any doubt
/// (a new database, pending migrations, an error) reads as "no".
async fn schema_is_current(db: &Database) -> bool {
    let applied = db.applied_migrations().await.is_ok_and(|a| !a.is_empty());
    applied && db.pending_migrations().await.is_ok_and(|p| p.is_empty())
}

/// `rizzy-vault secrets rotate [--data-key]`: shuts every server process out (the `SQLite`
/// writer lock, or the `PostgreSQL` instance lock; the server must be stopped), adds the new
/// secret, with `--data-key` drops the data keys no sealed row names any more (module docs),
/// and replaces the file atomically with mode 0600.
///
/// # Errors
/// [`AdminError`]; the secrets file is then unchanged.
pub async fn secrets_rotate(config: &Config, what: Rotate) -> Result<Rotated, AdminError> {
    check_location(config)?;
    let exclusion = match &config.database {
        // The setup rotation reads no row, and a database that does not exist yet has none:
        // the writer lock alone, without creating or opening the file.
        DatabaseConfig::Sqlite(path) if what == Rotate::Setup || !path.exists() => {
            Exclusion::WriterLock(WriterLock::acquire(path).map_err(AdminError::Lock)?)
        }
        DatabaseConfig::Sqlite(_) | DatabaseConfig::Postgres(_) => {
            let (db, lock) = open_exclusive(config).await?;
            Exclusion::Database(db, lock)
        }
    };
    let outcome = rotate_excluded(config, what, exclusion.database()).await;
    exclusion.end().await;
    outcome
}

/// [`secrets_rotate`] with the servers shut out; `db` is the opened database, if any.
async fn rotate_excluded(
    config: &Config,
    what: Rotate,
    db: Option<&Database>,
) -> Result<Rotated, AdminError> {
    let mut secrets = secrets_file::load(&config.secrets_file).map_err(AdminError::Secrets)?;
    let mut rng = os_rng();
    let id = match what {
        Rotate::Setup => secrets.rotate_setup(&mut rng),
        Rotate::DataKey => secrets.rotate_data_key(&mut rng),
    }
    .map_err(AdminError::Rotation)?;
    let dropped_data_keys = match (what, db) {
        (Rotate::DataKey, Some(db)) if schema_is_current(db).await => secrets
            .drop_unused_data_keys(db, now_ms())
            .await
            .map_err(AdminError::DataKeysInUse)?,
        _ => Vec::new(),
    };
    let bytes = secrets_file::serialize(&secrets).map_err(AdminError::Secrets)?;
    fsutil::replace_private(&config.secrets_file, &bytes)
        .map_err(|e| AdminError::Write(e.kind()))?;
    Ok(Rotated {
        id,
        dropped_data_keys,
    })
}

/// Reads the passphrase: from `path`, or from standard input when `path` is `-`. Never from the
/// command line or the environment.
fn read_passphrase(path: &Path) -> Result<zeroize::Zeroizing<String>, AdminError> {
    let bytes = if path.as_os_str() == "-" {
        use std::io::Read as _;
        let mut buf = zeroize::Zeroizing::new(Vec::new());
        let limit = u64::try_from(MAX_PASSPHRASE_FILE_LEN).unwrap_or(u64::MAX) + 1;
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut buf)
            .map_err(|_| AdminError::PassphraseFile)?;
        if buf.len() > MAX_PASSPHRASE_FILE_LEN {
            return Err(AdminError::PassphraseFile);
        }
        buf
    } else {
        fsutil::read_limited(path, MAX_PASSPHRASE_FILE_LEN)
            .map_err(|_| AdminError::PassphraseFile)?
    };
    secrets_backup::passphrase_from_bytes(&bytes).map_err(AdminError::Backup)
}

/// `rizzy-vault backup-secrets --out <file> --passphrase-file <file|->`: encrypts the secrets
/// file under the passphrase ([`secrets_backup`]) and writes a new file with mode 0600. Checks
/// first that the secrets file parses, so a backup never holds a damaged file.
///
/// # Errors
/// [`AdminError`].
pub fn backup_secrets(
    config: &Config,
    out: &Path,
    passphrase_file: &Path,
) -> Result<(), AdminError> {
    let bytes = fsutil::read_limited(&config.secrets_file, MAX_SECRETS_FILE_LEN).map_err(|e| {
        AdminError::Secrets(match e {
            ReadError::TooLarge => SecretsFileError::TooLarge,
            ReadError::Io(e) => SecretsFileError::Io(e.kind()),
        })
    })?;
    secrets_file::parse(&bytes).map_err(AdminError::Secrets)?;
    let passphrase = read_passphrase(passphrase_file)?;
    let file = secrets_backup::seal(&mut os_rng(), &passphrase, &bytes, now_ms())
        .map_err(AdminError::Backup)?;
    fsutil::write_new_private(out, &file).map_err(|e| AdminError::Write(e.kind()))
}

/// `rizzy-vault migrate`: opens the database with every server process shut out (the writer
/// lock on `SQLite`, the exclusive instance lock on `PostgreSQL`) and applies every pending
/// migration; on `SQLite` with the pre-migration copy first (ADR 0011 point 9).
///
/// # Errors
/// [`AdminError::Lock`] or [`AdminError::Serve`].
pub async fn migrate(config: &Config) -> Result<&'static str, AdminError> {
    let (db, lock) = open_exclusive(config).await?;
    let outcome = match &config.database {
        DatabaseConfig::Sqlite(_) => db
            .migrate_at_startup(&config.pre_migration_copy())
            .await
            .map(|m| match m {
                StartupMigration::UpToDate => "nothing to migrate",
                StartupMigration::Created => "database created",
                StartupMigration::MigratedAfterCopy => {
                    "migrated after writing the pre-migration copy"
                }
            }),
        DatabaseConfig::Postgres(_) => db.migrate().await.map(|()| "migrated"),
    };
    Exclusion::Database(db, lock).end().await;
    outcome.map_err(|e| AdminError::Serve(ServeError::Storage(e)))
}

/// The notice `restore` prints after a successful restore (ADR 0023 §5 step 6; the threat model
/// §5.8, INV-59, AR-19).
pub const RESTORE_NOTICE: &str = "\
Every account is rolled back to the backup and is now in a reconciliation epoch (INV-59): \
until a device of an account reconnects, the backup's old passwords, recovery codes and revoked \
devices work again for that account. Accounts whose devices never reconnect stay rolled back \
(AR-19). Tell every user the server was restored and ask them to open each of their devices \
soon.";

/// What `backup` wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupSummary {
    /// The file's length in bytes.
    pub len: usize,
    /// The file's trailing SHA-256 (ADR 0023 §2): not secret, printed for the operator.
    pub digest: [u8; DIGEST_LEN],
}

impl BackupSummary {
    /// The digest in lowercase hex.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        self.digest
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use core::fmt::Write as _;
                // Writing to a `String` cannot fail.
                let _infallible = write!(s, "{b:02x}");
                s
            })
    }
}

/// Whether `path` is `-`: standard input or output.
fn is_stdio(path: &Path) -> bool {
    path.as_os_str() == "-"
}

/// Opens the database for `backup`, taking no writer lock (ADR 0010 §2, ADR 0023 §6): the
/// read-only reader on `SQLite`, the pool on `PostgreSQL` (whose read transaction is
/// `REPEATABLE READ READ ONLY`).
async fn open_backup_reader(config: &Config) -> Result<Database, AdminError> {
    let db = match &config.database {
        DatabaseConfig::Sqlite(path) => {
            Database::open_sqlite_read_only(&SqliteOptions::new(path)).await
        }
        DatabaseConfig::Postgres(url) => match PostgresOptions::from_url(url) {
            Ok(options) => Database::open_postgres(&options).await,
            Err(e) => Err(e),
        },
    };
    db.map_err(AdminError::Storage)
}

/// `rizzy-vault backup --out <file|->`: the logical backup file of ADR 0023 (module docs).
///
/// # Errors
/// [`AdminError`]; with a file target, no file is left behind on a failure.
pub async fn backup(config: &Config, out: &Path) -> Result<BackupSummary, AdminError> {
    let to_stdout = is_stdio(out);
    if to_stdout && std::io::stdout().is_terminal() {
        return Err(AdminError::StdoutIsTerminal);
    }
    let db = open_backup_reader(config).await?;
    let dump = db.dump().await;
    db.close().await;
    let dump = dump.map_err(AdminError::Storage)?;
    let file = backup_file::write(&dump, now_ms()).map_err(AdminError::BackupFile)?;
    drop(dump);
    let digest = file
        .len()
        .checked_sub(DIGEST_LEN)
        .and_then(|start| file.get(start..))
        .and_then(|d| <[u8; DIGEST_LEN]>::try_from(d).ok())
        .ok_or(AdminError::BackupFile(FileError::Truncated))?;
    if to_stdout {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&file)
            .and_then(|()| stdout.flush())
            .map_err(|e| AdminError::Write(e.kind()))?;
    } else {
        fsutil::write_new_private(out, &file).map_err(|e| AdminError::Write(e.kind()))?;
    }
    Ok(BackupSummary {
        len: file.len(),
        digest,
    })
}

/// Reads the backup file from `path`, or from standard input when `path` is `-`, refusing
/// anything longer than [`MAX_BACKUP_FILE_LEN`] without reading past it.
fn read_backup(path: &Path) -> Result<Zeroizing<Vec<u8>>, AdminError> {
    if is_stdio(path) {
        let mut buf = Zeroizing::new(Vec::new());
        let limit = u64::try_from(MAX_BACKUP_FILE_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut buf)
            .map_err(|e| AdminError::Input(e.kind()))?;
        if buf.len() > MAX_BACKUP_FILE_LEN {
            return Err(AdminError::BackupFile(FileError::TooLarge));
        }
        Ok(buf)
    } else {
        fsutil::read_limited(path, MAX_BACKUP_FILE_LEN).map_err(|e| match e {
            ReadError::TooLarge => AdminError::BackupFile(FileError::TooLarge),
            ReadError::Io(e) => AdminError::Input(e.kind()),
        })
    }
}

/// `rizzy-vault restore --in <file|->`: the steps of ADR 0023 §5 (module docs). The caller
/// prints the report and [`RESTORE_NOTICE`].
///
/// # Errors
/// [`AdminError`]; the target then holds no application row.
pub async fn restore(
    config: &Config,
    input: &Path,
) -> Result<rizzy_storage::RestoreReport, AdminError> {
    check_location(config)?;
    // 1. Exclude every server process: the SQLite writer lock, or the PostgreSQL instance lock
    //    taken exclusively (ADR 0023 §5 step 1).
    let (db, mut lock) = open_exclusive(config).await?;
    let outcome = restore_into(&db, &mut lock, config, input).await;
    Exclusion::Database(db, lock).end().await;
    outcome
}

/// Steps 1 (the empty target) to 5 of [`restore`], on the database `lock` excludes every
/// server process from.
async fn restore_into(
    db: &Database,
    lock: &mut InstanceLock,
    config: &Config,
    input: &Path,
) -> Result<rizzy_storage::RestoreReport, AdminError> {
    db.check_restore_target()
        .await
        .map_err(AdminError::Storage)?;
    // 2. Read and parse: magic, format version and digest before anything else.
    let bytes = read_backup(input)?;
    let parsed = backup_file::parse(&bytes).map_err(AdminError::BackupFile)?;
    drop(bytes);
    // 3. This release's schema version only.
    let current = schema_version();
    if parsed.dump.schema_version != current {
        return Err(AdminError::Storage(
            RestoreError::SchemaVersion {
                dump: parsed.dump.schema_version,
                current,
            }
            .into(),
        ));
    }
    // 4. The secrets file must belong to the backup.
    let secrets = secrets_file::load(&config.secrets_file).map_err(AdminError::Secrets)?;
    secrets
        .check_dump(&parsed.dump)
        .map_err(AdminError::SecretsMismatch)?;
    drop(secrets);
    // 5. A new restore generation; the rows, the epochs and the counters in one transaction.
    let mut generation = [0u8; 16];
    os_rng().fill_bytes(&mut generation);
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    // The servers must still be shut out now that the file is read and the write starts.
    if !server::instance_lock_held(lock).await {
        return Err(AdminError::Serve(ServeError::InstanceLockLost));
    }
    db.restore(&parsed.dump, RestoreGeneration(generation), now)
        .await
        .map_err(AdminError::Storage)
}
