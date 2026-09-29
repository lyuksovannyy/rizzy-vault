//! The file-system facts the server is responsible for (ADR 0010 §4; CRYPTO.md §5.8, §5.11):
//! bounded reads, private files (mode 0600), atomic replacement, and whether one path lies
//! inside another.

use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// Why a bounded read failed.
#[derive(Debug)]
pub enum ReadError {
    /// The file is larger than the limit.
    TooLarge,
    /// The file could not be opened or read.
    Io(io::Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("file too large"),
            Self::Io(e) => write!(f, "read failed: {}", e.kind()),
        }
    }
}

impl std::error::Error for ReadError {}

/// Reads at most `max` bytes of `path` into a buffer that is wiped on drop; a longer file is
/// [`ReadError::TooLarge`] and nothing past `max + 1` bytes is read.
///
/// # Errors
/// [`ReadError`].
pub fn read_limited(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let file = File::open(path).map_err(ReadError::Io)?;
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut buf = Zeroizing::new(Vec::new());
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(ReadError::Io)?;
    if buf.len() > max {
        return Err(ReadError::TooLarge);
    }
    Ok(buf)
}

/// Options for a new file readable only by its owner (mode 0600 on Unix; ADR 0011 point 9,
/// CRYPTO.md §5.8). `create_new`: an existing file is never overwritten.
fn private_new() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

/// Writes `bytes` to a new file at `path` with mode 0600, and flushes it to disk. Fails if
/// `path` exists.
///
/// # Errors
/// The I/O error.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = private_new().open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Replaces the file at `path` with `bytes` atomically: writes `<path>.new` with mode 0600,
/// flushes it, renames it over `path`, and flushes the directory on Unix. A crash leaves either
/// the old file or the new one, never a mix.
///
/// A `<path>.new` left behind by an earlier replace that crashed before its rename is removed
/// first (it may hold secret material, and would otherwise block every later replace). The
/// caller must make sure no other process replaces `path` at the same time: the one caller,
/// `rizzy-vault secrets rotate`, holds the `SQLite` writer lock.
///
/// # Errors
/// The I/O error; `<path>.new` is removed again if the rename did not happen.
pub fn replace_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = sibling(path, ".new");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    write_new_private(&tmp, bytes)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _cleanup = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// `path` with `suffix` appended to its file name.
#[must_use]
pub fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The absolute, symlink-free form of `path`, or of its nearest existing ancestor joined with
/// the rest, so that a file that does not exist yet can be compared too.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut rest = Vec::new();
    let mut probe = absolute.as_path();
    loop {
        if let Ok(base) = fs::canonicalize(probe) {
            let mut out = base;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return Ok(out);
        }
        // A `..` or `.` in the part that does not exist cannot be resolved against the file
        // system; refuse rather than compare an unresolved path (fail closed).
        let (Some(parent), Some(name)) = (probe.parent(), probe.file_name()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path cannot be resolved",
            ));
        };
        rest.push(name.to_owned());
        probe = parent;
    }
}

/// Whether `path` resolves to a location inside `dir` (or to `dir` itself), after following
/// symlinks of the parts that exist. The server refuses a secrets file inside the data
/// directory (ADR 0010 §4: "The server refuses to start if the secrets file resolves to a path
/// inside the data directory").
///
/// # Errors
/// The I/O error of reading the current directory, for a relative path; `InvalidInput` for a
/// `..` or `.` below a directory that does not exist, which cannot be resolved (the caller
/// refuses then).
pub fn is_inside(dir: &Path, path: &Path) -> io::Result<bool> {
    Ok(resolve(path)?.starts_with(resolve(dir)?))
}

#[cfg(test)]
mod tests {
    //! Bounded reads, private files and the inside check, in a temporary directory.

    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rizzy-server-fsutil-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bounded_read_and_private_files() {
        let dir = temp_dir("rw");
        let file = dir.join("f");
        write_new_private(&file, b"12345").unwrap();
        assert!(write_new_private(&file, b"x").is_err(), "never overwrites");
        assert_eq!(read_limited(&file, 5).unwrap().as_slice(), b"12345");
        assert!(matches!(read_limited(&file, 4), Err(ReadError::TooLarge)));
        replace_private(&file, b"abc").unwrap();
        assert_eq!(read_limited(&file, 5).unwrap().as_slice(), b"abc");
        assert!(!sibling(&file, ".new").exists());
        // A `.new` left by a crashed replace does not block the next one.
        write_new_private(&sibling(&file, ".new"), b"stale").unwrap();
        replace_private(&file, b"def").unwrap();
        assert_eq!(read_limited(&file, 5).unwrap().as_slice(), b"def");
        assert!(!sibling(&file, ".new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn inside_check_follows_what_exists() {
        let dir = temp_dir("inside");
        let data = dir.join("data");
        fs::create_dir_all(&data).unwrap();
        assert!(is_inside(&data, &data.join("secrets.json")).unwrap());
        // `..` below a missing directory cannot be resolved: an error, never "outside".
        assert!(is_inside(&data, &data.join("missing/../secrets.json")).is_err());
        assert!(!is_inside(&data, &dir.join("secrets.json")).unwrap());
        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&data, &link).unwrap();
            assert!(is_inside(&data, &link.join("secrets.json")).unwrap());
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
