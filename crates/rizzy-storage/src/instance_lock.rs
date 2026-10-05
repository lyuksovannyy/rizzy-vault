//! The instance lock: no admin command rewrites a database a server process is using
//! (ADR 0023 §5 step 1).
//!
//! ADR 0023 §5 step 1: "every `rizzy-vault` process on PostgreSQL, whatever its roles, holds
//! `pg_advisory_lock_shared(K)` on a dedicated connection outside the sqlx pool for its whole
//! life, checked alive as ADR 0010 §2 does for the worker lock, and exits when that connection
//! drops. `restore` (and `migrate`, `secrets rotate`, `secrets retire-setups`) take `pg_try_advisory_lock(K)` on their
//! own dedicated connection and refuse if any holder remains."
//!
//! [`Database::try_instance_lock`] takes the lock in either mode and returns an
//! [`InstanceLock`], which the caller keeps for as long as it uses the database:
//!
//! - **PostgreSQL:** a new connection, opened with the pool's own connect options (the same
//!   server, credentials and TLS policy, [`PostgresOptions`](crate::PostgresOptions)) but never
//!   part of the pool, takes the session-level advisory lock on [`INSTANCE_LOCK`]. The
//!   [`InstanceLock`] owns that connection, so the lock lives exactly as long as it does:
//!   dropping it closes the connection, and PostgreSQL releases a session-level lock when its
//!   session ends. It is never unlocked explicitly. [`InstanceLock::is_held`] asks the server,
//!   on that connection, whether this session still holds the lock in its mode (`pg_locks`), so
//!   a dropped connection, a terminated backend or a failover all read as "not held" or as an
//!   error, and the caller stops.
//!   - [`InstanceLockMode::Shared`] is what a server process holds. Any number of them hold it
//!     together; it is refused only while an admin command holds the exclusive lock.
//!   - [`InstanceLockMode::Exclusive`] is what `restore`, `migrate`, `secrets rotate` and `secrets retire-setups` take.
//!     It is refused while any server process, or another such command, holds the lock.
//! - **SQLite:** nothing to take. A writable SQLite [`Database`] exists only with the file's
//!   [`WriterLock`](crate::WriterLock) (ADR 0010 §2), which already excludes every other server
//!   process and admin command, so the lock is a marker and [`InstanceLock::is_held`] is always
//!   true. A read-only handle (the `backup` reader) is refused: it holds no writer lock.
//!
//! **Both modes are taken without waiting.** The ADR names `pg_advisory_lock_shared` for the
//! server; this crate uses `pg_try_advisory_lock_shared`, which takes the same lock in the
//! same mode and differs only when an admin command holds the exclusive lock at that moment:
//! the blocking call would wait for the command to finish, the `try` call is refused and the
//! server does not start (as a second SQLite server refuses to start, ADR 0010 §2). This crate
//! reads no clock and cannot bound a wait, and a wait the caller abandons leaves a backend
//! queued for the lock that takes it later for a moment, with no process behind it. This
//! reading is reported to the owner.
//!
//! **The key.** `K` is [`INSTANCE_LOCK`], in PostgreSQL's single-`bigint` advisory key space
//! ("one fixed `i64` chosen by the implementing PR, distinct from the worker lock's key"). The
//! per-account locks and the worker's leader lock use the two-`int4` key space
//! ([`crate::lock`]), which does not overlap it. sqlx's migrator takes a lock in the `bigint`
//! space too, with the key `0x3d32ad9e * crc32(database name)` (sqlx-postgres 0.9.0,
//! `migrate.rs`), which is always even; [`INSTANCE_LOCK`] is odd, so the two never collide, and
//! `migrate` can hold the exclusive instance lock while the migrator holds its own.
//!
//! **What the lock does not cover.** `rizzy-vault backup` takes no lock on either engine (ADR
//! 0023 §6). A process that opens no database (a `web`-only server) holds nothing.
//!
//! **The window between checks.** As for the worker's leader lock
//! ([`crate::leader_lock`]): a check proves the lock was held when the server answered. The
//! caller checks it on a timer and stops the process on a failed check; between the connection
//! dropping and that check, the process still serves. An admin command started in that window
//! is granted the exclusive lock although a server runs. The check interval bounds the window;
//! it is `rizzy-server`'s choice and documented there.
//!
//! **Timeouts.** This crate has no runtime and reads no clock: the connect and the check wait as
//! long as the driver and the network do. The caller bounds them.

use std::fmt;

use sqlx::Connection as _;
use sqlx::postgres::PgConnection;

use crate::db::Database;
use crate::error::{Engine, Error};

/// `K`, the PostgreSQL advisory-lock key of the instance lock (ADR 0023 §5 step 1), in the
/// single-`bigint` key space: `"rv"`, `"a"`, 3 in the high 32 bits (the namespace after the
/// account locks' `…01` and the worker leader's `…02`, [`crate::lock`]) and 1 in the low 32
/// bits. It is odd, so it never equals a key of sqlx's migrator (module docs). The operator
/// guide (`docs/self-hosting.md`) names it, as the ADR requires; changing it would let a new
/// release and an old one run against one database without seeing each other's lock.
pub const INSTANCE_LOCK: i64 = 0x7276_6103_0000_0001;

/// `SELECT pg_try_advisory_lock_shared($1)`.
const POSTGRES_TRY_SHARED: &str = include_str!("../queries/postgres/instance_try_lock_shared.sql");

/// `SELECT pg_try_advisory_lock($1)`.
const POSTGRES_TRY_EXCLUSIVE: &str =
    include_str!("../queries/postgres/instance_try_lock_exclusive.sql");

/// Whether this session holds the instance lock in a given mode, from `pg_locks`.
const POSTGRES_HELD: &str = include_str!("../queries/postgres/instance_lock_held.sql");

/// How the instance lock is held (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceLockMode {
    /// A server process: shared with every other server process, refused while an admin
    /// command holds the exclusive lock.
    Shared,
    /// `restore`, `migrate`, `secrets rotate` or `secrets retire-setups`: refused while anything else holds the lock.
    Exclusive,
}

impl InstanceLockMode {
    /// The mode's name in `pg_locks.mode`.
    const fn pg_mode(self) -> &'static str {
        match self {
            Self::Shared => "ShareLock",
            Self::Exclusive => "ExclusiveLock",
        }
    }
}

/// The high and the low 32 bits of [`INSTANCE_LOCK`], each as a non-negative `i64`, as
/// `pg_locks` shows a `bigint` key (`classid`, `objid`).
const fn key_halves() -> (i64, i64) {
    (
        (INSTANCE_LOCK >> 32) & 0xffff_ffff,
        INSTANCE_LOCK & 0xffff_ffff,
    )
}

/// A held instance lock (module docs). Dropping it gives the lock up: on PostgreSQL the
/// dedicated connection closes and the server releases the lock.
///
/// `Debug` shows the engine and the mode only.
pub struct InstanceLock {
    /// What holds the lock.
    inner: Inner,
    /// The mode it was taken in.
    mode: InstanceLockMode,
}

/// What holds the lock, by engine.
enum Inner {
    /// SQLite: the database's writer lock, held by the [`Database`] itself.
    Sqlite,
    /// PostgreSQL: the dedicated connection that holds the session-level advisory lock.
    Postgres(PgConnection),
}

impl fmt::Debug for InstanceLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstanceLock")
            .field("engine", &self.engine())
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl InstanceLock {
    /// The engine this lock is on.
    #[must_use]
    pub const fn engine(&self) -> Engine {
        match self.inner {
            Inner::Sqlite => Engine::Sqlite,
            Inner::Postgres(_) => Engine::Postgres,
        }
    }

    /// The mode this lock was taken in.
    #[must_use]
    pub const fn mode(&self) -> InstanceLockMode {
        self.mode
    }

    /// Whether the lock is still held: on PostgreSQL, whether the dedicated connection is alive
    /// and its session still holds the lock in this mode, asked of the server; on SQLite,
    /// always true (module docs). On `Ok(false)` or an error a server process must exit, and an
    /// admin command must stop before it writes.
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the dedicated connection is gone or the query fails; the lock
    /// must then be treated as lost.
    pub async fn is_held(&mut self) -> Result<bool, Error> {
        match &mut self.inner {
            Inner::Sqlite => Ok(true),
            Inner::Postgres(conn) => {
                let (high, low) = key_halves();
                Ok(sqlx::query_scalar::<_, bool>(POSTGRES_HELD)
                    .bind(high)
                    .bind(low)
                    .bind(self.mode.pg_mode())
                    .fetch_one(&mut *conn)
                    .await?)
            }
        }
    }

    /// Gives the lock up: on PostgreSQL, closes the dedicated connection gracefully, which ends
    /// the session and so releases the lock at once. Dropping the lock releases it too, once
    /// the server notices the closed socket.
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the graceful close fails; the connection is closed anyway.
    pub async fn release(self) -> Result<(), Error> {
        match self.inner {
            Inner::Sqlite => Ok(()),
            Inner::Postgres(conn) => Ok(conn.close().await?),
        }
    }
}

impl Database {
    /// Tries to take the instance lock in `mode` (module docs), without waiting.
    ///
    /// - PostgreSQL: opens a dedicated connection outside the pool and takes the session-level
    ///   lock on it. `Ok(None)` when it is refused: for [`InstanceLockMode::Shared`], an admin
    ///   command holds the exclusive lock; for [`InstanceLockMode::Exclusive`], a server
    ///   process or another admin command holds the lock. The connection is closed.
    /// - SQLite: `Ok(Some(_))` in either mode, since the writer lock this database holds
    ///   already excludes every other process.
    ///
    /// # Errors
    ///
    /// - [`Error::ReadOnly`] on a database opened with
    ///   [`Database::open_sqlite_read_only`]: it has no writer lock and excludes nobody.
    /// - [`Error::Database`] when the dedicated connection cannot be opened or the lock
    ///   statement fails.
    pub async fn try_instance_lock(
        &self,
        mode: InstanceLockMode,
    ) -> Result<Option<InstanceLock>, Error> {
        match self {
            Self::Sqlite(_) => {
                // A writable SQLite database always holds its writer lock.
                self.sqlite_writer()?;
                Ok(Some(InstanceLock {
                    inner: Inner::Sqlite,
                    mode,
                }))
            }
            Self::Postgres(pool) => {
                let options = pool.connect_options();
                let mut conn = PgConnection::connect_with(&options).await?;
                let statement = match mode {
                    InstanceLockMode::Shared => POSTGRES_TRY_SHARED,
                    InstanceLockMode::Exclusive => POSTGRES_TRY_EXCLUSIVE,
                };
                let taken = sqlx::query_scalar::<_, bool>(statement)
                    .bind(INSTANCE_LOCK)
                    .fetch_one(&mut conn)
                    .await?;
                if taken {
                    Ok(Some(InstanceLock {
                        inner: Inner::Postgres(conn),
                        mode,
                    }))
                } else {
                    // Refused: close the connection now rather than on drop. A failed close
                    // changes nothing, the connection is gone either way.
                    let _closed = conn.close().await;
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{ACCOUNT_LOCK_NAMESPACE, WORKER_LEADER_LOCK};

    #[test]
    fn key_is_positive_odd_and_in_its_own_namespace() {
        // `instance_lock_held.sql` compares the key's halves with `pg_locks`'s oid columns as
        // int8, which holds for the non-negative halves `key_halves` yields.
        const { assert!(INSTANCE_LOCK > 0) };
        let (high, low) = key_halves();
        assert_eq!((high << 32) | low, INSTANCE_LOCK);
        assert!((0..=i64::from(u32::MAX)).contains(&high));
        assert!((0..=i64::from(u32::MAX)).contains(&low));
        // sqlx's migrator key is `0x3d32ad9e * crc32`, always even.
        assert_eq!(INSTANCE_LOCK % 2, 1);
        // "distinct from the worker lock's key": another key space, and another namespace
        // number even when read as two halves.
        assert_ne!(high, i64::from(WORKER_LEADER_LOCK.0));
        assert_ne!(high, i64::from(ACCOUNT_LOCK_NAMESPACE));
    }

    #[test]
    fn modes_name_the_pg_locks_modes() {
        assert_eq!(InstanceLockMode::Shared.pg_mode(), "ShareLock");
        assert_eq!(InstanceLockMode::Exclusive.pg_mode(), "ExclusiveLock");
    }
}
