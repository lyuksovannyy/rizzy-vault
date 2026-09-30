//! Where `rv` keeps its files, and how it writes files it hands to the user ([ADR 0026] §3,
//! owner decision on open question 4; [ADR 0027] §5; threat model INV-56, INV-61).
//!
//! # The data directory
//!
//! One `SQLite` file per account, `<hex(account_id)>.sqlite3`, in a local, non-roaming
//! directory:
//!
//! | Platform | Directory |
//! |---|---|
//! | any, if set | `$RIZZY_CLI_DATA_DIR` |
//! | Linux and other Unix | `$XDG_DATA_HOME/rizzy-vault`, or `$HOME/.local/share/rizzy-vault` |
//! | macOS | `$HOME/Library/Application Support/rizzy-vault` |
//! | Windows | `%LOCALAPPDATA%\rizzy-vault` |
//!
//! The directory is created with mode 0700 and each file with mode 0600 on Unix (elsewhere
//! the inherited permissions). The file holds the Secret Key and `E_local` (ADR 0026 §2): it
//! **must stay out of backups and sync tools** (INV-61). `rv` cannot mark it excluded without
//! platform calls this crate may not make, so the usage text and `docs/` say so.
//!
//! # One `rv` per account
//!
//! "A second `rv` on the same account fails with 'in use'" (ADR 0026 §3). Next to the cache
//! sits `<hex>.lock`; [`AccountLock`] holds an exclusive advisory lock on it
//! (`std::fs::File::try_lock`) for the life of the process. Two processes that both loaded the
//! cache and then wrote could each sign an op at the same `device_seq`; the lock prevents
//! that, and the SQL of [`crate::db`] refuses it a second time.
//!
//! # Output files
//!
//! [`write_new_file`] is the one way `rv` writes an export: `create_new` (so nothing, a
//! symlink included, is ever overwritten), mode 0600 at creation on Unix, and the partial file
//! removed on failure (ADR 0027 §5; ADR 0023 §4).
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
//! [ADR 0027]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0027-export-payload.md

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use crate::error::{CliError, io_error};

/// The environment variable that overrides the data directory.
pub const DATA_DIR_ENV: &str = "RIZZY_CLI_DATA_DIR";

/// The directory name under the platform's data directory.
const APP_DIR: &str = "rizzy-vault";

/// The extension of a cache file.
const CACHE_EXTENSION: &str = "sqlite3";

/// The length of `hex(account_id)`.
const ACCOUNT_HEX_LEN: usize = 32;

/// The data directory from the environment (module docs). `lookup` reads one variable; `main`
/// passes `std::env::var_os`.
///
/// # Errors
/// [`CliError::Io`] when no variable names a base directory.
pub fn data_dir(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf, CliError> {
    let set = |name: &str| lookup(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(dir) = set(DATA_DIR_ENV) {
        return Ok(dir);
    }
    let base = if cfg!(windows) {
        set("LOCALAPPDATA")
    } else if cfg!(target_os = "macos") {
        set("HOME").map(|home| home.join("Library").join("Application Support"))
    } else {
        set("XDG_DATA_HOME").or_else(|| set("HOME").map(|home| home.join(".local").join("share")))
    };
    base.map(|base| base.join(APP_DIR)).ok_or(CliError::Io(
        "no data directory: set RIZZY_CLI_DATA_DIR",
        io::ErrorKind::NotFound,
    ))
}

/// Creates the data directory if it is missing, mode 0700 on Unix, and makes sure an existing
/// one is private ([`check_data_dir`]).
///
/// # Errors
/// [`CliError::Io`].
pub fn ensure_data_dir(dir: &Path) -> Result<(), CliError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(io_error("cannot create the data directory"))?;
    // `create` succeeds on a directory that already exists, whatever its mode.
    check_data_dir(dir)
}

/// Makes sure the existing data directory is private: "directory 0700" (ADR 0026 §3) also
/// holds for a directory `rv` did not create (`RIZZY_CLI_DATA_DIR` pointing at a pre-made one)
/// or one whose mode was loosened later.
///
/// On Unix, a directory that grants anything to the group or to others is set to 0700. Only
/// its owner (or root) may do that, so a directory this user does not own is refused here:
/// the change fails, and `rv` does not run in a directory someone else controls and others
/// can list. Elsewhere the inherited permissions apply and nothing is checked.
///
/// # Errors
/// [`CliError::Io`] when the directory cannot be inspected or made private.
pub fn check_data_dir(dir: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::metadata(dir).map_err(io_error("cannot inspect the data directory"))?;
        if !metadata.is_dir() {
            return Err(CliError::Io(
                "the data directory is not a directory",
                io::ErrorKind::NotADirectory,
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_error(
                "the data directory is open to other users and cannot be made private (mode 0700)",
            ))?;
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Lower-case hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bytes of a hex string of exactly `N` bytes, either case.
#[must_use]
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = core::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// The cache file of `account_id` in `dir`.
#[must_use]
pub fn cache_path(dir: &Path, account_id: &[u8; 16]) -> PathBuf {
    dir.join(format!("{}.{CACHE_EXTENSION}", hex(account_id)))
}

/// The account ids that have a cache file in `dir`, ascending. A missing directory holds none.
///
/// # Errors
/// [`CliError::Io`].
pub fn enrolled_accounts(dir: &Path) -> Result<Vec<[u8; 16]>, CliError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error("cannot read the data directory")(e)),
    };
    let mut accounts = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(io_error("cannot read the data directory"))?
            .path();
        let is_cache = path.extension().is_some_and(|e| e == CACHE_EXTENSION);
        let stem = path.file_stem().and_then(|s| s.to_str());
        if let Some(stem) = stem.filter(|s| is_cache && s.len() == ACCOUNT_HEX_LEN)
            && let Some(id) = unhex::<16>(stem)
        {
            accounts.push(id);
        }
    }
    accounts.sort_unstable();
    Ok(accounts)
}

/// The exclusive lock of one account's cache (module docs). Released when dropped or when the
/// process exits.
#[derive(Debug)]
pub struct AccountLock {
    /// The locked file; the lock lives as long as the handle.
    _file: File,
}

impl AccountLock {
    /// Locks the cache of `account_id` in `dir`.
    ///
    /// # Errors
    /// [`CliError::InUse`] if another process holds it; [`CliError::Io`].
    pub fn acquire(dir: &Path, account_id: &[u8; 16]) -> Result<Self, CliError> {
        let path = dir.join(format!("{}.lock", hex(account_id)));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(io_error("cannot open the lock file"))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs::TryLockError::WouldBlock) => Err(CliError::InUse),
            Err(fs::TryLockError::Error(e)) => Err(io_error("cannot lock the local data")(e)),
        }
    }
}

/// Creates an empty file at `path` with mode 0600 on Unix, failing if anything exists there.
///
/// # Errors
/// [`CliError::FileExists`]; [`CliError::Io`].
pub fn create_private_file(path: &Path) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            CliError::FileExists
        } else {
            io_error("cannot create the file")(e)
        }
    })
}

/// Writes `bytes` to a new file at `path` (module docs, "Output files"): `create_new`, mode
/// 0600 on Unix, synced, and removed again if the write fails.
///
/// # Errors
/// [`CliError::FileExists`] if anything exists at `path`, a symlink included; [`CliError::Io`].
pub fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = create_private_file(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        // The partial file is ours (we just created it): remove it, keep the first error.
        let _ = fs::remove_file(path);
        return Err(io_error("cannot write the file")(e));
    }
    Ok(())
}

/// Reads a whole file of at most `max` bytes.
///
/// # Errors
/// [`CliError::Io`]; a longer file is [`io::ErrorKind::InvalidData`].
pub fn read_limited(path: &Path, max: usize) -> Result<Vec<u8>, CliError> {
    use std::io::Read as _;
    let file = File::open(path).map_err(io_error("cannot open the file"))?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(io_error("cannot read the file"))?;
    if bytes.len() > max {
        return Err(CliError::Io(
            "the file is too large",
            io::ErrorKind::InvalidData,
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_bad_input() {
        let id = [0xab; 16];
        assert_eq!(hex(&id), "ab".repeat(16));
        assert_eq!(unhex::<16>(&hex(&id)), Some(id));
        assert_eq!(unhex::<16>(&"AB".repeat(16)), Some(id));
        assert_eq!(unhex::<16>("ab"), None);
        assert_eq!(unhex::<16>(&"zz".repeat(16)), None);
        assert_eq!(unhex::<1>("é"), None);
    }

    #[test]
    fn the_data_directory_follows_the_override_then_the_platform() {
        let over = |name: &str| (name == DATA_DIR_ENV).then(|| OsString::from("/custom"));
        assert_eq!(data_dir(&over).unwrap(), PathBuf::from("/custom"));
        let none = |_: &str| None;
        assert!(data_dir(&none).is_err());
        let home = |name: &str| match name {
            "HOME" => Some(OsString::from("/home/u")),
            "LOCALAPPDATA" => Some(OsString::from("/local")),
            _ => None,
        };
        let dir = data_dir(&home).unwrap();
        assert!(dir.ends_with(APP_DIR));
        // An empty override is no override.
        let empty = |name: &str| match name {
            DATA_DIR_ENV => Some(OsString::new()),
            other => home(other),
        };
        assert_eq!(data_dir(&empty).unwrap(), dir);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_data_directory_is_made_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = std::env::temp_dir().join(format!("rv-paths-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // A directory made by someone else's `mkdir`, group- and world-readable.
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_data_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        // Loosened later: fixed at the next open.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        check_data_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        // Something that is no directory, and a missing one, are refused.
        let file = dir.join("file");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(check_data_dir(&file), Err(CliError::Io(..))));
        assert!(matches!(
            check_data_dir(&dir.join("missing")),
            Err(CliError::Io(..))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_file_is_never_an_overwrite() {
        let dir = std::env::temp_dir().join(format!("rv-paths-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        ensure_data_dir(&dir).unwrap();
        let path = dir.join("out.json");
        write_new_file(&path, b"one").unwrap();
        assert!(matches!(
            write_new_file(&path, b"two"),
            Err(CliError::FileExists)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"one");
        assert_eq!(read_limited(&path, 3).unwrap(), b"one");
        assert!(read_limited(&path, 2).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            // A symlink at the path is "file exists" too, and its target is untouched.
            let link = dir.join("link.json");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(matches!(
                write_new_file(&link, b"x"),
                Err(CliError::FileExists)
            ));
            assert_eq!(fs::read(&path).unwrap(), b"one");
        }
        // The lock: a second holder is "in use"; the account list finds cache files only.
        let account = [7u8; 16];
        let lock = AccountLock::acquire(&dir, &account).unwrap();
        assert!(matches!(
            AccountLock::acquire(&dir, &account),
            Err(CliError::InUse)
        ));
        drop(lock);
        AccountLock::acquire(&dir, &account).unwrap();
        create_private_file(&cache_path(&dir, &account)).unwrap();
        assert_eq!(enrolled_accounts(&dir).unwrap(), vec![account]);
        assert!(enrolled_accounts(&dir.join("missing")).unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
