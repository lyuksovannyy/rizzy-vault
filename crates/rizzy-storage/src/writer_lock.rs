//! The SQLite writer lock: one process writes the database file (ADR 0010 §2).
//!
//! "At startup the server takes an exclusive writer lock on a lock file next to the database,
//! and refuses to start if another process holds it." `restore`, `migrate`, `secrets rotate` and `secrets retire-setups`
//! take it too; `backup` does not (it opens the database read-only, next to the running
//! server). [`WriterLock::acquire`] takes the lock on `<database file>.lock`, and
//! [`Database::open_sqlite`](crate::Database::open_sqlite) takes one for the same file and owns
//! it for as long as the database lives, so no SQLite writer pool exists without it or outlives
//! it.
//!
//! The lock is an OS advisory lock on the open file (`std::fs::File::try_lock`), released
//! when the [`WriterLock`] is dropped or the process dies; the lock file itself stays and is
//! empty. It is only as good as the filesystem's locking, one more reason the database must
//! never live on NFS or SMB (ADR 0011 "SQLite settings").

use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// A held writer lock on one SQLite database file. Dropping it releases the lock.
#[derive(Debug)]
pub struct WriterLock {
    /// The database file the lock is for, as the caller gave it.
    database: PathBuf,
    /// The lock file: `database` with `.lock` appended to its file name.
    path: PathBuf,
    /// The open lock file, holding the exclusive lock while it lives.
    _file: File,
}

impl WriterLock {
    /// Takes the exclusive writer lock for the SQLite database at `database`, on the lock file
    /// `<database>.lock` next to it, creating that file if needed. Does not wait: another
    /// holder is an error, so a second server refuses to start.
    ///
    /// # Errors
    ///
    /// - [`Error::WriterLockHeld`] when another process (or another [`WriterLock`] in this
    ///   one) holds the lock.
    /// - [`Error::Io`] when the lock file cannot be opened or locked.
    pub fn acquire(database: &Path) -> Result<Self, Error> {
        let path = lock_path(database);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|source| Error::Io {
                action: "open the writer lock file",
                path: path.clone(),
                source,
            })?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                database: database.to_path_buf(),
                path,
                _file: file,
            }),
            Err(TryLockError::WouldBlock) => Err(Error::WriterLockHeld { path }),
            Err(TryLockError::Error(source)) => Err(Error::Io {
                action: "lock the writer lock file",
                path,
                source,
            }),
        }
    }

    /// The lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this lock was taken for the database file `database` (compared as given, not
    /// canonicalised: pass the same path to both calls).
    #[must_use]
    pub fn is_for(&self, database: &Path) -> bool {
        self.database == database
    }
}

/// `<database>.lock`: the database path with `.lock` appended to its last component.
fn lock_path(database: &Path) -> PathBuf {
    let mut name = OsString::from(database.as_os_str());
    name.push(".lock");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_appends_to_the_file_name() {
        assert_eq!(
            lock_path(Path::new("/data/vault.sqlite")),
            PathBuf::from("/data/vault.sqlite.lock")
        );
    }
}
