//! The admin subcommands the Accepted ADRs name for M1, as far as they are specified
//! ([ADR 0010] §2, §4; [ADR 0011] "Migrations", "Backups"; CRYPTO.md §5.8, §5.11).
//!
//! | Command | Spec | Lock |
//! |---|---|---|
//! | `secrets init` | ADR 0010 §4: "creates the secrets once, run as a one-off with the secrets mount writable" | none (no database) |
//! | `secrets rotate` | CRYPTO.md §5.8 "Rotating `server_setup`" steps 1–2; ADR 0010 §4 | `SQLite` writer lock |
//! | `secrets rotate --data-key` | CRYPTO.md §5.11 "Rotation" | `SQLite` writer lock |
//! | `backup-secrets` | ADR 0011 "Backups" and owner decision 3; CRYPTO.md §5.11 | none (reads the secrets file only) |
//! | `migrate` | ADR 0011 point 9 | `SQLite` writer lock |
//!
//! ADR 0010 §2: "`restore`, `migrate` and `secrets rotate` take the writer lock. They run only
//! while the server is stopped." With `PostgreSQL` there is no writer lock, so `secrets rotate`
//! cannot prove the server is stopped and refuses (`PostgreSQL` is supported from M3).
//!
//! **Not here, and why** (reported to the owner):
//! - `backup` and `restore`: [ADR 0011] calls for "a versioned and documented file format" for
//!   the logical dump, and no Accepted ADR defines its bytes; `rizzy-storage` stops at the
//!   in-memory dump for the same reason. Freezing a persistent format needs an ADR first.
//! - Re-sealing TOTP rows under a new data key (CRYPTO.md §5.11: "`worker` re-seals TOTP rows")
//!   has no domain function yet; after `--data-key` the old key stays in the file and keeps
//!   opening the rows sealed under it.
//! - Deleting an old setup after the grace period (§5.8 step 4) has no command in any ADR.
//! - The bootstrap token (INV-69) is generated into the file by `secrets init` and never
//!   printed or logged: its only reader is the M3 admin API, which defines how it is shown once.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md

use core::fmt;
use std::path::Path;

use rizzy_domain_auth::ServerSecrets;
use rizzy_domain_auth::secrets::SecretsError;
use rizzy_storage::{StartupMigration, WriterLock};

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
    /// `secrets rotate` with `PostgreSQL` (module docs).
    NeedsSqliteLock,
    /// The database could not be opened or migrated.
    Serve(ServeError),
    /// The writer lock could not be taken: the server is probably running.
    Lock(rizzy_storage::Error),
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
            Self::NeedsSqliteLock => f.write_str(
                "secrets rotate needs the SQLite writer lock to prove the server is stopped; \
                 not available with PostgreSQL in this build",
            ),
            Self::Serve(e) => write!(f, "{e}"),
            Self::Lock(e) => write!(
                f,
                "cannot take the writer lock (is the server running?): {e}"
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

/// `rizzy-vault secrets rotate [--data-key]`: takes the `SQLite` writer lock (the server must be
/// stopped), adds the new secret, and replaces the file atomically with mode 0600. Returns the
/// new id.
///
/// # Errors
/// [`AdminError`].
pub fn secrets_rotate(config: &Config, what: Rotate) -> Result<u32, AdminError> {
    check_location(config)?;
    let DatabaseConfig::Sqlite(db_path) = &config.database else {
        return Err(AdminError::NeedsSqliteLock);
    };
    let _lock = WriterLock::acquire(db_path).map_err(AdminError::Lock)?;
    let mut secrets = secrets_file::load(&config.secrets_file).map_err(AdminError::Secrets)?;
    let mut rng = os_rng();
    let id = match what {
        Rotate::Setup => secrets.rotate_setup(&mut rng),
        Rotate::DataKey => secrets.rotate_data_key(&mut rng),
    }
    .map_err(AdminError::Rotation)?;
    let bytes = secrets_file::serialize(&secrets).map_err(AdminError::Secrets)?;
    fsutil::replace_private(&config.secrets_file, &bytes)
        .map_err(|e| AdminError::Write(e.kind()))?;
    Ok(id)
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

/// `rizzy-vault migrate`: opens the database (with the writer lock on `SQLite`) and applies every
/// pending migration; on `SQLite` with the pre-migration copy first (ADR 0011 point 9).
///
/// # Errors
/// [`AdminError::Serve`].
pub async fn migrate(config: &Config) -> Result<&'static str, AdminError> {
    let db = server::open_database(config, false)
        .await
        .map_err(AdminError::Serve)?;
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
    db.close().await;
    outcome.map_err(|e| AdminError::Serve(ServeError::Storage(e)))
}
