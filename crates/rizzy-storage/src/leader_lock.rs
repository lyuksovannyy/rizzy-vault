//! The `worker` leader lock: one active worker per database (ADR 0010 §2).
//!
//! ADR 0010 §2: "With PostgreSQL, a `worker` holds a session-level advisory lock on a
//! **dedicated connection outside the sqlx pool**. A session-level lock belongs to one
//! connection, so a lock taken on a pooled connection would be released silently whenever the
//! pool recycles or drops that connection, while the worker kept running jobs. The worker checks
//! that the connection and the lock are still alive before each job batch, and stops running
//! jobs as soon as that connection drops. Extra `worker` replicas are hot standbys."
//!
//! [`Database::try_lead_worker`] takes the lock and returns a [`WorkerLeader`], which the worker
//! keeps for as long as it runs jobs and asks [`WorkerLeader::is_held`] before each job batch.
//!
//! - **PostgreSQL:** a new connection, opened with the pool's own connect options (the same
//!   server, credentials and TLS policy, [`PostgresOptions`](crate::PostgresOptions)) but never
//!   part of the pool, takes `pg_try_advisory_lock` on [`WORKER_LEADER_LOCK`] without waiting.
//!   The [`WorkerLeader`] owns that connection, so the lock lives exactly as long as the leader:
//!   dropping it closes the connection, and PostgreSQL releases a session-level lock when its
//!   session ends. The lock is never unlocked explicitly. [`WorkerLeader::is_held`] asks the
//!   server, on that connection, whether this session still holds the lock (`pg_locks`), so a
//!   dropped connection, a terminated backend or a failover all read as "not held" or as an
//!   error, and the caller stops.
//! - **SQLite:** nothing to take. A writable SQLite [`Database`] exists only with the file's
//!   [`WriterLock`](crate::WriterLock), held for as long as the database lives, so this process
//!   is already the only writer, and so the only worker, of the file. The leader is a marker,
//!   and [`WorkerLeader::is_held`] is always true. This is the behaviour the SQLite worker had
//!   before the leader lock existed.
//!
//! **The window between checks.** A check proves the lock was held when the server answered.
//! If the connection drops after it, the job batch in flight still finishes; each of its writes
//! is its own transaction under the per-account lock ([`lock_account`](crate::lock_account)),
//! so a standby that takes over at that moment serialises with it per account rather than
//! racing it. The conservative reading is kept: the lock is checked before every batch and a
//! failed check ends the leadership (the caller drops the leader and tries to take the lock
//! again later).
//!
//! **Timeouts.** This crate has no runtime and reads no clock: the connect and the check wait as
//! long as the driver and the network do. The caller bounds them (`rizzy-server`'s worker wraps
//! each in a timeout and treats a timeout as a lost lock).

use std::fmt;

use sqlx::Connection as _;
use sqlx::postgres::PgConnection;

use crate::db::Database;
use crate::error::{Engine, Error};
use crate::lock::WORKER_LEADER_LOCK;

/// `SELECT pg_try_advisory_lock($1, $2)`.
const POSTGRES_TRY_LOCK: &str = include_str!("../queries/postgres/worker_leader_try_lock.sql");

/// Whether this session holds the leader lock, from `pg_locks`.
const POSTGRES_HELD: &str = include_str!("../queries/postgres/worker_leader_held.sql");

/// The right to run the `worker` jobs on one database (module docs). Dropping it gives the
/// right up: on PostgreSQL the dedicated connection closes and the server releases the lock.
///
/// `Debug` shows the engine only.
pub struct WorkerLeader {
    /// What holds the leadership.
    inner: Inner,
}

/// What holds the leadership, by engine.
enum Inner {
    /// SQLite: the database's writer lock, held by the [`Database`] itself.
    Sqlite,
    /// PostgreSQL: the dedicated connection that holds the session-level advisory lock.
    Postgres(PgConnection),
}

impl fmt::Debug for WorkerLeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerLeader")
            .field("engine", &self.engine())
            .finish()
    }
}

impl WorkerLeader {
    /// The engine this leadership is on.
    #[must_use]
    pub fn engine(&self) -> Engine {
        match self.inner {
            Inner::Sqlite => Engine::Sqlite,
            Inner::Postgres(_) => Engine::Postgres,
        }
    }

    /// Whether this process still leads: on PostgreSQL, whether the dedicated connection is
    /// alive and its session still holds the leader lock, asked of the server; on SQLite,
    /// always true (module docs). Call it before each job batch; on `Ok(false)` or an error,
    /// stop running jobs and drop the leader.
    ///
    /// # Errors
    ///
    /// [`Error::Database`] when the dedicated connection is gone or the query fails; the
    /// leadership must then be treated as lost.
    pub async fn is_held(&mut self) -> Result<bool, Error> {
        match &mut self.inner {
            Inner::Sqlite => Ok(true),
            Inner::Postgres(conn) => Ok(sqlx::query_scalar::<_, bool>(POSTGRES_HELD)
                .bind(i64::from(WORKER_LEADER_LOCK.0))
                .bind(i64::from(WORKER_LEADER_LOCK.1))
                .fetch_one(&mut *conn)
                .await?),
        }
    }

    /// Gives the leadership up: on PostgreSQL, closes the dedicated connection gracefully,
    /// which ends the session and so releases the lock at once. Dropping the leader releases it
    /// too, once the server notices the closed socket.
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
    /// Tries to become the database's one active worker (module docs), without waiting.
    ///
    /// - PostgreSQL: opens a dedicated connection outside the pool and takes the session-level
    ///   leader lock on it. `Ok(None)` when another session holds it (this worker is then a hot
    ///   standby and tries again later); the connection is closed.
    /// - SQLite: `Ok(Some(_))`, since the writer lock this database holds already makes this
    ///   process the only writer.
    ///
    /// # Errors
    ///
    /// - [`Error::ReadOnly`] on a database opened with
    ///   [`Database::open_sqlite_read_only`]: it has no writer lock and must run no jobs.
    /// - [`Error::Database`] when the dedicated connection cannot be opened or the lock
    ///   statement fails.
    pub async fn try_lead_worker(&self) -> Result<Option<WorkerLeader>, Error> {
        match self {
            Self::Sqlite(_) => {
                // A writable SQLite database always holds its writer lock.
                self.sqlite_writer()?;
                Ok(Some(WorkerLeader {
                    inner: Inner::Sqlite,
                }))
            }
            Self::Postgres(pool) => {
                let options = pool.connect_options();
                let mut conn = PgConnection::connect_with(&options).await?;
                let taken = sqlx::query_scalar::<_, bool>(POSTGRES_TRY_LOCK)
                    .bind(WORKER_LEADER_LOCK.0)
                    .bind(WORKER_LEADER_LOCK.1)
                    .fetch_one(&mut conn)
                    .await?;
                if taken {
                    Ok(Some(WorkerLeader {
                        inner: Inner::Postgres(conn),
                    }))
                } else {
                    // Not the leader: close the connection now rather than on drop. A failed
                    // close changes nothing, the connection is gone either way.
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

    #[test]
    fn leader_keys_are_non_negative() {
        // `worker_leader_held.sql` compares the keys with `pg_locks`'s oid columns as int8,
        // which holds only for non-negative keys.
        assert!(WORKER_LEADER_LOCK.0 >= 0 && WORKER_LEADER_LOCK.1 >= 0);
    }
}
