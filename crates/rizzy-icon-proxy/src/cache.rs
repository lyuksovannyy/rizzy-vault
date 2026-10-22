// SPDX-License-Identifier: AGPL-3.0-only

//! The `icons` role's shared on-disk cache ([ADR 0052] point 5; [ADR 0053] item 4; [ADR 0010]
//! §4's cache volume).
//!
//! - **Anonymous and shared.** An entry is keyed by what was fetched (for the breach check,
//!   the prefix: `breach-<PREFIX>.txt`), never by who asked; nothing per request or per user
//!   is written (INV-51, INV-77).
//! - **TTL.** An entry older than the TTL (by its file's modification time) is a miss and is
//!   fetched again.
//! - **Size cap.** Before each write, the whole directory is counted, and the oldest files are
//!   removed until the new entry fits under the cap. The favicon entries ADR 0052 adds share
//!   the directory and the cap.
//! - **Atomic writes.** An entry is written to a temporary file in the same directory and
//!   renamed over the final name, so a reader never sees half an entry.
//! - **Bounded reads.** A file larger than the caller's limit is never read; it is a miss.
//!
//! File names are built only from validated values (`[A-Za-z0-9-]` and one `.` before the
//! extension), so no path separator, `..` or other path syntax can reach the filesystem.
//! File operations run on Tokio's blocking pool.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

use core::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// The default TTL: 14 days (ADR 0052 owner answer 3).
pub const DEFAULT_TTL: Duration = Duration::from_secs(14 * 24 * 3600);

/// The default total size cap: 256 MiB (ADR 0052 owner answer 3).
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// The prefix of a temporary file.
const TEMP_PREFIX: &str = ".tmp-";

/// The cache directory, its TTL and its cap.
#[derive(Clone)]
pub struct Cache {
    /// The cache directory (the `icons` role's cache volume).
    dir: PathBuf,
    /// Entries older than this are misses.
    ttl: Duration,
    /// The directory's total size never passes this after a write.
    max_bytes: u64,
    /// Serialises writes, so two evictions never race.
    write_lock: Arc<Mutex<()>>,
    /// Makes temporary file names unique within the process.
    counter: Arc<AtomicU64>,
}

impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cache")
            .field("dir", &self.dir)
            .field("ttl", &self.ttl)
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

/// Why a cache operation failed. Carries no path or content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheError {
    /// The file name is not one this module builds.
    BadName,
    /// The entry is larger than the cap.
    TooLarge,
    /// A filesystem operation failed.
    Io,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadName => "invalid cache entry name",
            Self::TooLarge => "cache entry larger than the cache",
            Self::Io => "cache I/O failed",
        })
    }
}

impl std::error::Error for CacheError {}

/// Whether `name` is a file name this module builds: 1 to 64 bytes of `[A-Za-z0-9-]` with
/// exactly one `.`, neither first nor last.
fn valid_name(name: &str) -> bool {
    let dots = name.bytes().filter(|b| *b == b'.').count();
    !name.is_empty()
        && name.len() <= 64
        && dots == 1
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

impl Cache {
    /// A cache in `dir`. The directory must exist and be writable by the process.
    #[must_use]
    pub fn new(dir: PathBuf, ttl: Duration, max_bytes: u64) -> Self {
        Self {
            dir,
            ttl,
            max_bytes,
            write_lock: Arc::new(Mutex::new(())),
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The fresh content of entry `name`, if there is one of at most `max_len` bytes.
    pub async fn get(&self, name: &str, max_len: usize) -> Option<Vec<u8>> {
        if !valid_name(name) {
            return None;
        }
        let path = self.dir.join(name);
        let ttl = self.ttl;
        tokio::task::spawn_blocking(move || read_fresh(&path, ttl, max_len))
            .await
            .ok()
            .flatten()
    }

    /// Removes entry `name` (a corrupt one); a missing file is not an error.
    pub async fn remove(&self, name: &str) {
        if !valid_name(name) {
            return;
        }
        let path = self.dir.join(name);
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(path)).await;
    }

    /// Writes entry `name`, evicting the oldest files first until it fits under the cap.
    ///
    /// # Errors
    /// [`CacheError`]; the cache is an optimisation, so callers serve the content anyway.
    pub async fn put(&self, name: &str, content: Vec<u8>) -> Result<(), CacheError> {
        if !valid_name(name) {
            return Err(CacheError::BadName);
        }
        let incoming = u64::try_from(content.len()).map_err(|_| CacheError::TooLarge)?;
        if incoming > self.max_bytes {
            return Err(CacheError::TooLarge);
        }
        let this = self.clone();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || this.put_blocking(&name, &content, incoming))
            .await
            .map_err(|_| CacheError::Io)?
    }

    /// [`Cache::put`] on the blocking pool.
    fn put_blocking(&self, name: &str, content: &[u8], incoming: u64) -> Result<(), CacheError> {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        evict(&self.dir, self.max_bytes.saturating_sub(incoming), name)?;
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .dir
            .join(format!("{TEMP_PREFIX}{}-{n}", std::process::id()));
        let written = (|| {
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(content)?;
            file.sync_all()?;
            std::fs::rename(&temp, self.dir.join(name))
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written.map_err(|_| CacheError::Io)
    }
}

/// Reads `path` if it is a regular file no older than `ttl` and at most `max_len` bytes.
fn read_fresh(path: &Path, ttl: Duration, max_len: usize) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let modified = meta.modified().ok()?;
    // A modification time in the future (a clock step) counts as fresh.
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::ZERO);
    if age > ttl || meta.len() > u64::try_from(max_len).ok()? {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    // One byte past the limit tells a file at the limit from a larger one.
    file.take(u64::try_from(max_len).ok()?.saturating_add(1))
        .read_to_end(&mut out)
        .ok()?;
    (out.len() <= max_len).then_some(out)
}

/// Removes the oldest regular files of `dir` (except `keep`, which the caller replaces)
/// until the rest total at most `budget` bytes.
fn evict(dir: &Path, budget: u64, keep: &str) -> Result<(), CacheError> {
    let mut files: Vec<(SystemTime, u64, PathBuf)> = Vec::new();
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir).map_err(|_| CacheError::Io)? {
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() || entry.file_name() == keep {
            continue;
        }
        total = total.saturating_add(meta.len());
        files.push((
            meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            meta.len(),
            entry.path(),
        ));
    }
    if total <= budget {
        return Ok(());
    }
    files.sort_by_key(|(modified, _, _)| *modified);
    for (_, len, path) in files {
        if total <= budget {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Names, TTL, bounded reads and oldest-first eviction past the cap.

    use super::*;

    /// A temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("rizzy-icon-cache-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn names() {
        for good in [
            "breach-5BAA6.txt",
            "example.com-https-443.png".replace(".com", "-com").as_str(),
        ] {
            assert!(valid_name(good), "{good}");
        }
        for bad in [
            "", ".txt", "a.", "a", "a.b.c", "../x.txt", "a/b.txt", "a\\b.txt", ".tmp-1-2",
            "a b.txt",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn put_get_ttl_and_limits() {
        let dir = TempDir::new("ttl");
        let rt = rt();
        let cache = Cache::new(dir.0.clone(), DEFAULT_TTL, 1024);
        rt.block_on(async {
            assert_eq!(cache.get("breach-AAAAA.txt", 100).await, None);
            cache
                .put("breach-AAAAA.txt", b"hello".to_vec())
                .await
                .unwrap();
            assert_eq!(
                cache.get("breach-AAAAA.txt", 100).await,
                Some(b"hello".to_vec())
            );
            // Larger than the reader's limit: a miss, never read.
            assert_eq!(cache.get("breach-AAAAA.txt", 4).await, None);
            // Invalid names never reach the filesystem.
            assert_eq!(
                cache.put("../breach.txt", b"x".to_vec()).await,
                Err(CacheError::BadName)
            );
            assert_eq!(
                cache.put("big-entry.txt", vec![0; 2048]).await,
                Err(CacheError::TooLarge)
            );
            cache.remove("breach-AAAAA.txt").await;
            assert_eq!(cache.get("breach-AAAAA.txt", 100).await, None);
        });
        // A zero TTL makes every entry stale.
        let stale = Cache::new(dir.0.clone(), Duration::ZERO, 1024);
        rt.block_on(async {
            stale.put("breach-BBBBB.txt", b"x".to_vec()).await.unwrap();
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(stale.get("breach-BBBBB.txt", 100).await, None);
        });
        // No temporary file is left behind.
        let leftovers = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(TEMP_PREFIX))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn writes_past_the_cap_evict_oldest_first() {
        let dir = TempDir::new("evict");
        let rt = rt();
        let cache = Cache::new(dir.0.clone(), DEFAULT_TTL, 300);
        rt.block_on(async {
            for (i, name) in ["a-1.txt", "a-2.txt", "a-3.txt"].iter().enumerate() {
                cache.put(name, vec![b'x'; 100]).await.unwrap();
                // Distinct modification times.
                std::thread::sleep(Duration::from_millis(15 * (i as u64 + 1)));
            }
            cache.put("a-4.txt", vec![b'y'; 150]).await.unwrap();
            assert_eq!(cache.get("a-1.txt", 1000).await, None);
            assert_eq!(cache.get("a-2.txt", 1000).await, None);
            assert!(cache.get("a-3.txt", 1000).await.is_some());
            assert!(cache.get("a-4.txt", 1000).await.is_some());
            // Replacing an entry does not count its old copy.
            cache.put("a-4.txt", vec![b'z'; 200]).await.unwrap();
            assert_eq!(cache.get("a-4.txt", 1000).await, Some(vec![b'z'; 200]));
        });
        let total: u64 = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.metadata().unwrap().len())
            .sum();
        assert!(total <= 300, "{total}");
    }
}
