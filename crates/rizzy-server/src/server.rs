//! Startup, serving and graceful shutdown of `rizzy-vault` ([ADR 0010] §1, §2, §4; [ADR 0011]
//! point 9; CRYPTO.md §5.8, §5.11; [ADR 0021] §2).
//!
//! # Startup, in order
//!
//! For a process with a database role (`api` or `worker`):
//! 1. **The secrets file must not be inside the data directory** ([ADR 0010] §4: "The server
//!    refuses to start if the secrets file resolves to a path inside the data directory"),
//!    following symlinks; a path that cannot be resolved is refused too.
//! 2. **Load the secrets** ([`crate::secrets_file`]). The server never writes the file.
//! 3. **Open the database.** `SQLite`: take the exclusive writer lock next to the file first
//!    ([ADR 0010] §2; a second server refuses to start), open it, then migrate: automatically,
//!    with the `VACUUM INTO` pre-migration copy when migrations are pending on an existing
//!    database ([ADR 0011] point 9). `PostgreSQL`: connect, take the shared instance lock
//!    (below; a server refuses to start while `restore`, `migrate`, `secrets rotate` or `secrets retire-setups` runs),
//!    and refuse to start if a migration is pending, naming `rizzy-vault migrate`.
//! 4. **Draw the restore generation** if the database has none ([ADR 0021] §2), from the OS
//!    CSPRNG.
//! 5. **Check the secrets against the database** (CRYPTO.md §5.8, §5.11: a setup whose public
//!    key hash differs, a restored database next to a fresh secrets file, a sealed row naming a
//!    data key the file lacks): any mismatch refuses to start.
//! 6. **Build the domains**: the auth domain with the configured origin and signup mode, the
//!    vault domain with the in-process event bus ([`rizzy_bus`]). The auth domain first fills
//!    the `account_key_epoch` of every credential and recovery row that has none from the
//!    account's current signed state (ADR 0032 §4; migration 0005 cannot read the state).
//!
//! Then the `worker` task starts ([`crate::worker`]) and, for `api` or `web`, the listener.
//! A `web`-only process opens no database and reads no secrets.
//!
//! **One active `worker` per database** ([ADR 0010] §2). With `PostgreSQL` the worker takes a
//! session-level advisory lock on a dedicated connection outside the pool, through
//! `rizzy-storage` (`rizzy-server` holds no sqlx, [ADR 0016] R5), and runs jobs only while it
//! holds it; other `worker` processes on the same database are hot standbys
//! ([`crate::worker`]). With `SQLite`, the writer lock already makes this process the only one.
//!
//! **The instance lock** ([ADR 0023] §5 step 1). Every process that opens a `PostgreSQL`
//! database holds the instance lock in shared mode on a dedicated connection outside the pool,
//! through `rizzy-storage`, from before it reads anything until its pools are closed
//! ([`take_instance_lock`]). `restore`, `migrate`, `secrets rotate` and `secrets retire-setups` take it exclusively and
//! refuse to run while a server holds it ([`crate::admin`]). The lock is "checked alive as ADR
//! 0010 §2 does for the worker lock", and the process "exits when that connection drops": a
//! watchdog asks the database every [`INSTANCE_LOCK_CHECK`] whether the session still holds the
//! lock; a check that fails, errs or takes longer than [`INSTANCE_LOCK_TIMEOUT`] ends the
//! process at once with [`ServeError::InstanceLockLost`] (exit code 1): the listener and every
//! open connection are dropped without the shutdown grace, and the worker is stopped at its
//! next await point, where an open transaction rolls back. The supervisor (compose's restart
//! policy) starts it again, and it takes the lock anew or is refused. Between the connection
//! dropping and the next check the process still serves; an admin command started in that
//! window is granted the lock. The 15 s interval bounds that window; it is this crate's
//! choice, reported to the owner. With `SQLite` the writer lock is the instance lock and cannot
//! be lost while the database is open, so no watchdog runs. A `web`-only process opens no
//! database and holds nothing.
//!
//! **Core dumps** (threat model INV-60) are already off when this runs: [`crate::cli::main`]
//! disables them first and refuses to start otherwise ([`crate::coredump`], ADR 0024). The
//! release profile keeps `panic = "abort"`.
//!
//! # Shutdown
//!
//! On `SIGINT` or `SIGTERM` the listener stops accepting, in-flight requests finish, the
//! worker finishes its current step, releases its leader lock and stops, and the database pools
//! close (which also releases the `SQLite` writer lock). The wait for in-flight requests is
//! bounded ([`ServeLimits::shutdown_grace`], 30 s): connections still open then are dropped, so
//! a stalled client cannot keep the process from stopping.
//!
//! # Connections
//!
//! [`serve_http`] serves HTTP/1.1 with hyper directly: a header-read timeout (which also ends
//! idle keep-alive connections), a cap on open connections, and the bounded shutdown above
//! ([`ServeLimits`]; threat model §7.6 "D"). Request bodies have their own deadline and size
//! limit ([`crate::http::api`]).
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md
//! [ADR 0023]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0023-logical-backup-format.md

use core::fmt;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rand_core::Rng as _;
use rizzy_bus::Bus;
use rizzy_domain_auth::secrets::StartupCheckError;
use rizzy_domain_auth::{AuthConfig, AuthError, AuthService, ConfigError, SignupPolicy};
use rizzy_domain_vault::VaultDomain;
use rizzy_storage::meta::ensure_restore_generation;
use rizzy_storage::{
    Database, Engine, InstanceLock, InstanceLockMode, PostgresOptions, RestoreGeneration,
    SqliteOptions, StartupMigration, WriterLock,
};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::bridge::{AuthDirectory, VaultBridge};
use crate::config::{Config, DatabaseConfig, SignupMode};
use crate::fsutil;
use crate::http::{self, api::Api};
use crate::log::{self, Field};
use crate::secrets_file::{self, SecretsFileError};
use crate::sys::{now_ms, os_rng};
use crate::worker;

/// How often a server process on `PostgreSQL` checks that it still holds the instance lock
/// (module docs). This crate's choice, reported to the owner.
pub const INSTANCE_LOCK_CHECK: Duration = Duration::from_secs(15);

/// The longest a process waits to take the instance lock (connect and lock), to check it, or to
/// release it. A check that takes longer counts as a lost lock. This crate's choice, reported
/// to the owner.
pub const INSTANCE_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the server did not start, or stopped with an error. `Display` names what failed, never
/// a secret: the storage errors leave out bound values, the secrets errors name fields.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServeError {
    /// A database role runs, but the configuration has no origin.
    NoOrigin,
    /// The secrets file resolves inside the data directory, or its location cannot be resolved.
    SecretsInsideDataDir,
    /// The secrets file could not be loaded.
    Secrets(SecretsFileError),
    /// The database could not be opened, migrated or read.
    Storage(rizzy_storage::Error),
    /// The loaded secrets do not fit the database (CRYPTO.md §5.8, §5.11).
    SecretsMismatch(StartupCheckError),
    /// The auth domain refused its configuration.
    AuthConfig(ConfigError),
    /// The auth domain failed during the startup checks.
    Auth(AuthError),
    /// The listener could not be bound, or serving failed.
    Listener(std::io::ErrorKind),
    /// The `PostgreSQL` instance lock was refused in this mode ([ADR 0023] §5 step 1): a server
    /// found an admin command holding it exclusively, or an admin command found a server
    /// process (or another admin command) holding it.
    ///
    /// [ADR 0023]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0023-logical-backup-format.md
    InstanceLockRefused(InstanceLockMode),
    /// Taking the instance lock took longer than [`INSTANCE_LOCK_TIMEOUT`].
    InstanceLockTimeout,
    /// The instance lock is no longer held (its dedicated connection dropped): a running
    /// server exits (module docs), and an admin command stops before it writes.
    InstanceLockLost,
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOrigin => f.write_str("RIZZY_ORIGIN is required for the api and worker roles"),
            Self::SecretsInsideDataDir => f.write_str(
                "the secrets file must not be inside the data directory (ADR 0010 §4), \
                 or its location could not be resolved",
            ),
            Self::Secrets(e) => write!(f, "{e}"),
            Self::Storage(rizzy_storage::Error::PendingMigrations { .. }) => {
                f.write_str("the database has pending migrations; run `rizzy-vault migrate` first")
            }
            Self::Storage(e) => write!(f, "database: {e}"),
            Self::SecretsMismatch(e) => write!(f, "the secrets do not fit the database: {e}"),
            Self::AuthConfig(e) => write!(f, "auth configuration: {e}"),
            Self::Auth(e) => write!(f, "startup check: {e}"),
            Self::Listener(kind) => write!(f, "listener: {kind}"),
            Self::InstanceLockRefused(InstanceLockMode::Shared) => f.write_str(
                "the database's instance lock is held exclusively: an admin command (restore, \
                 migrate, secrets rotate or secrets retire-setups) is running against it; start \
                 the server when it has finished",
            ),
            Self::InstanceLockRefused(InstanceLockMode::Exclusive) => f.write_str(
                "the database's instance lock is held: a server process (any role, any \
                 replica) or another admin command still uses this database; stop them first",
            ),
            Self::InstanceLockTimeout => {
                f.write_str("taking the database's instance lock timed out")
            }
            Self::InstanceLockLost => f.write_str(
                "the database's instance lock was lost (its connection dropped); stopping",
            ),
        }
    }
}

impl std::error::Error for ServeError {}

impl From<rizzy_storage::Error> for ServeError {
    fn from(e: rizzy_storage::Error) -> Self {
        Self::Storage(e)
    }
}

/// The opened database and the domains over it.
#[derive(Debug)]
pub struct Services {
    /// The database.
    pub db: Database,
    /// The shared instance lock this process holds on the database (module docs); on `SQLite`
    /// a marker over the writer lock `db` owns. `None` once [`serve`] has moved it into its
    /// watchdog. Dropping it releases the lock.
    pub instance_lock: Option<InstanceLock>,
    /// The `api` role's services, which `worker` shares.
    pub api: Arc<Api>,
    /// The in-process event bus the vault domain publishes on; `worker` subscribes to it.
    pub bus: Bus,
    /// When startup steps 1–6 finished: the startup self-check passed. The worker counts the
    /// pre-migration copy's 24 h from it ([`worker::PreMigrationCopy`]).
    pub self_check_passed: Instant,
}

/// Opens the database without migrating it and without the secrets checks: `SQLite` with its
/// writer lock, or the `PostgreSQL` pool (the first half of step 3 of the module docs). It
/// takes no instance lock: the caller does, with [`take_instance_lock`], before it reads or
/// writes anything. Shared with the admin commands.
///
/// # Errors
/// [`ServeError::Storage`].
pub async fn open_database(config: &Config) -> Result<Database, ServeError> {
    match &config.database {
        DatabaseConfig::Sqlite(path) => {
            let lock = WriterLock::acquire(path)?;
            Ok(Database::open_sqlite(&SqliteOptions::new(path), lock).await?)
        }
        DatabaseConfig::Postgres(url) => {
            let options = PostgresOptions::from_url(url)?;
            Ok(Database::open_postgres(&options).await?)
        }
    }
}

/// Takes the instance lock of `db` in `mode`, within [`INSTANCE_LOCK_TIMEOUT`] (module docs):
/// shared for a server process, exclusive for `restore`, `migrate`, `secrets rotate` and `secrets retire-setups`. On
/// `SQLite` it is always granted: the writer lock `db` owns already excludes everyone else.
///
/// # Errors
/// [`ServeError::InstanceLockRefused`] when someone holds it in a conflicting mode,
/// [`ServeError::InstanceLockTimeout`], or [`ServeError::Storage`] when the dedicated
/// connection cannot be opened.
pub async fn take_instance_lock(
    db: &Database,
    mode: InstanceLockMode,
) -> Result<InstanceLock, ServeError> {
    match tokio::time::timeout(INSTANCE_LOCK_TIMEOUT, db.try_instance_lock(mode)).await {
        Ok(Ok(Some(lock))) => Ok(lock),
        Ok(Ok(None)) => Err(ServeError::InstanceLockRefused(mode)),
        Ok(Err(e)) => Err(ServeError::Storage(e)),
        Err(_elapsed) => Err(ServeError::InstanceLockTimeout),
    }
}

/// Gives an instance lock up, within [`INSTANCE_LOCK_TIMEOUT`]; past it, or on an error, the
/// connection is dropped, which releases the lock too.
pub async fn release_instance_lock(lock: InstanceLock) {
    match tokio::time::timeout(INSTANCE_LOCK_TIMEOUT, lock.release()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::error("instance_lock_release_failed", &[Field::Error("error", &e)]),
        Err(_elapsed) => log::error(
            "instance_lock_release_failed",
            &[Field::Str("error", "releasing the instance lock timed out")],
        ),
    }
}

/// The second half of startup step 3: the startup migration rule of ADR 0011 point 9, on a
/// database whose instance lock this process holds.
async fn migrate_at_startup(db: &Database, config: &Config) -> Result<(), ServeError> {
    match db.migrate_at_startup(&config.pre_migration_copy()).await? {
        StartupMigration::UpToDate => {}
        StartupMigration::Created => log::info("database_created", &[]),
        StartupMigration::MigratedAfterCopy => log::info("database_migrated_after_copy", &[]),
    }
    Ok(())
}

/// Whether `lock` is still held, asked within [`INSTANCE_LOCK_TIMEOUT`]. A lost lock is logged.
/// The watchdog asks on a timer; an admin command asks once more before it writes.
pub async fn instance_lock_held(lock: &mut InstanceLock) -> bool {
    match tokio::time::timeout(INSTANCE_LOCK_TIMEOUT, lock.is_held()).await {
        Ok(Ok(true)) => true,
        Ok(Ok(false)) => {
            log::error(
                "instance_lock_lost",
                &[Field::Str("error", "the instance lock is no longer held")],
            );
            false
        }
        Ok(Err(e)) => {
            log::error("instance_lock_lost", &[Field::Error("error", &e)]);
            false
        }
        Err(_elapsed) => {
            log::error(
                "instance_lock_lost",
                &[Field::Str("error", "checking the instance lock timed out")],
            );
            false
        }
    }
}

/// The instance-lock watchdog (module docs): checks `lock` every `every` until `stop` turns
/// true, and then hands the lock back for the caller to release last. If a check fails it
/// sets `lost` and returns `None`; the lock's connection is dropped.
async fn watch_instance_lock(
    mut lock: InstanceLock,
    every: Duration,
    mut stop: watch::Receiver<bool>,
    lost: watch::Sender<bool>,
) -> Option<InstanceLock> {
    loop {
        if *stop.borrow() {
            return Some(lock);
        }
        tokio::select! {
            changed = stop.changed() => {
                // A dropped sender means the server is going away: stop as well.
                if changed.is_err() {
                    return Some(lock);
                }
                continue;
            }
            () = tokio::time::sleep(every) => {}
        }
        if !instance_lock_held(&mut lock).await {
            let _receiver_gone = lost.send(true);
            return None;
        }
    }
}

/// Resolves when the watchdog reports the instance lock lost; never, when it ends without
/// losing it or does not run (`SQLite`, or no database role).
async fn instance_lock_lost(mut lost: watch::Receiver<bool>) {
    if lost.wait_for(|lost| *lost).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Startup steps 1–6 of the module docs.
///
/// # Errors
/// [`ServeError`]; nothing is served then.
pub async fn open_services(config: &Config) -> Result<Services, ServeError> {
    let origin = config.origin.clone().ok_or(ServeError::NoOrigin)?;
    if fsutil::is_inside(&config.data_dir, &config.secrets_file).unwrap_or(true) {
        return Err(ServeError::SecretsInsideDataDir);
    }
    let secrets = Arc::new(secrets_file::load(&config.secrets_file).map_err(ServeError::Secrets)?);
    let db = open_database(config).await?;
    // Before anything is read: from here on no admin command rewrites this database.
    let instance_lock = take_instance_lock(&db, InstanceLockMode::Shared).await?;
    migrate_at_startup(&db, config).await?;
    let mut candidate = [0u8; 16];
    os_rng().fill_bytes(&mut candidate);
    let now = now_ms();
    ensure_restore_generation(
        &db,
        RestoreGeneration(candidate),
        i64::try_from(now).unwrap_or(i64::MAX),
    )
    .await?;
    secrets
        .check_database(&db, now)
        .await
        .map_err(ServeError::Auth)?
        .map_err(ServeError::SecretsMismatch)?;
    let mut auth_config = AuthConfig::new(origin);
    auth_config.signup = match config.signup {
        SignupMode::Closed => SignupPolicy::Closed,
        SignupMode::Open => SignupPolicy::Open,
    };
    auth_config.recovery_wait_ms = config.recovery_wait_ms;
    if config.recovery_wait_ms == 0 {
        // ADR 0008 decision 5 allows 0; the threat model keeps it for single-account
        // instances (Q-15). Nothing enforces that here, so the operator is told.
        log::warn("recovery_wait_zero", &[]);
    }
    let auth = AuthService::new(db.clone(), secrets, auth_config, VaultBridge)
        .map_err(ServeError::AuthConfig)?;
    // ADR 0032 §4: the rows migration 0005 found get their `account_key_epoch` from the
    // current signed state before anything is served.
    let filled = auth
        .fill_credential_epochs()
        .await
        .map_err(ServeError::Auth)?;
    if filled > 0 {
        log::info(
            "credential_epochs_filled",
            &[Field::U64(
                "accounts",
                u64::try_from(filled).unwrap_or(u64::MAX),
            )],
        );
    }
    let bus = Bus::default();
    let vault = VaultDomain::new(db.clone(), AuthDirectory, bus.clone());
    Ok(Services {
        api: Arc::new(Api::new(
            auth,
            vault,
            config.trusted_proxies.clone(),
            config.max_upload_bytes,
        )),
        db,
        instance_lock: Some(instance_lock),
        bus,
        self_check_passed: Instant::now(),
    })
}

/// Resolves on `SIGINT` (Ctrl-C) or, on Unix, `SIGTERM`.
async fn shutdown_signal() {
    let ctrl_c = async {
        // If the handler cannot be installed, the process still stops on SIGTERM or a kill.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    log::info("shutdown_requested", &[]);
}

/// The connection limits of the listener (threat model §7.6 "D": slow clients and floods).
/// [`ServeLimits::default`] holds the values `rizzy-vault` runs with, which ADR 0028 item 9
/// fixes: HTTP/1.1 in clear (TLS is the reverse proxy's), a 10 s header-read and keep-alive idle
/// timeout, at most 1024 connections, a 30 s shutdown grace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeLimits {
    /// How long a client has to send a request's whole header block, and how long an idle
    /// keep-alive connection waits for the next request (hyper's `header_read_timeout`, whose
    /// timer starts when hyper waits for a request head). Default 10 s.
    pub header_read_timeout: Duration,
    /// The most connections open at once; past it the listener stops accepting until one
    /// closes (the kernel's backlog holds the rest). Default 1024.
    pub max_connections: usize,
    /// How long shutdown waits for open connections to finish their in-flight requests before
    /// it drops them. Default 30 s.
    pub shutdown_grace: Duration,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            max_connections: 1024,
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

/// Whether an accept error concerns only the one connection (the next accept can succeed at
/// once), as axum's own `serve` treats them.
fn is_connection_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

/// Serves HTTP/1.1 on `listener` with `app` until `shutdown` resolves, with
/// [`ServeLimits::default`].
pub async fn serve_http<F>(listener: TcpListener, app: Router, shutdown: F)
where
    F: Future<Output = ()>,
{
    serve_http_with(listener, app, shutdown, ServeLimits::default()).await;
}

/// Serves HTTP/1.1 on `listener` with `app` until `shutdown` resolves (module docs,
/// "Shutdown"), within `limits`.
///
/// This replaces `axum::serve`, which sets no hyper timer and so no header-read timeout, bounds
/// neither the number of connections nor the shutdown drain. Each connection is served by
/// hyper's HTTP/1 connection with a Tokio timer and `limits.header_read_timeout`, and the
/// request carries the peer address as `ConnectInfo<SocketAddr>`, as `axum::serve` with
/// `into_make_service_with_connect_info` gives it. Body reads have their own deadline
/// ([`crate::http::api::body_deadline`]).
///
/// On `shutdown`: the listener closes, every connection is asked to finish its in-flight
/// request and close, and after `limits.shutdown_grace` the connections still open are dropped.
pub async fn serve_http_with<F>(
    listener: TcpListener,
    app: Router,
    shutdown: F,
    limits: ServeLimits,
) where
    F: Future<Output = ()>,
{
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let (closing_tx, closing_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut shutdown = pin!(shutdown);
    loop {
        while connections.try_join_next().is_some() {}
        let slot = tokio::select! {
            () = &mut shutdown => break,
            slot = slots.clone().acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_closed) => break,
            },
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) if is_connection_error(&e) => continue,
                Err(e) => {
                    // Out of file descriptors and the like: wait instead of spinning.
                    log::error("accept_failed", &[Field::Error("error", &e)]);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
        };
        let service = TowerToHyperService::new(app.clone().layer(Extension(ConnectInfo(peer))));
        let mut closing = closing_rx.clone();
        let header_read_timeout = limits.header_read_timeout;
        connections.spawn(async move {
            let _slot = slot;
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout);
            let mut connection = pin!(builder.serve_connection(TokioIo::new(stream), service));
            tokio::select! {
                _served = connection.as_mut() => return,
                _closing = closing.wait_for(|closing| *closing) => {}
            }
            connection.as_mut().graceful_shutdown();
            let _served = connection.await;
        });
    }
    drop(listener);
    let _receivers_gone = closing_tx.send(true);
    let drained = tokio::time::timeout(limits.shutdown_grace, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        log::info(
            "shutdown_connections_dropped",
            &[Field::U64(
                "connections",
                u64::try_from(connections.len()).unwrap_or(u64::MAX),
            )],
        );
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

/// Runs the server with `config` until a shutdown signal (module docs).
///
/// # Errors
/// [`ServeError`].
pub async fn serve(config: Config) -> Result<(), ServeError> {
    log::init(config.log_level);
    log::info(
        "starting",
        &[
            Field::Str("roles", config.roles.names()),
            Field::Str("version", env!("CARGO_PKG_VERSION")),
        ],
    );
    let mut services = if config.roles.need_database() {
        Some(open_services(&config).await?)
    } else {
        None
    };

    let (stop_tx, stop_rx) = watch::channel(false);
    // The instance-lock watchdog (module docs). On SQLite the lock is a marker that cannot be
    // lost, so none runs, `lost_tx` is dropped and `lost` never resolves.
    let (lock_stop_tx, lock_stop_rx) = watch::channel(false);
    let (lost_tx, lost_rx) = watch::channel(false);
    let watchdog =
        match services.as_mut().and_then(|s| s.instance_lock.take()) {
            Some(lock) if lock.engine() == Engine::Postgres => Some(tokio::spawn(
                watch_instance_lock(lock, INSTANCE_LOCK_CHECK, lock_stop_rx, lost_tx),
            )),
            _ => None,
        };
    let mut lost = pin!(instance_lock_lost(lost_rx));
    let worker_task = match (&services, config.roles.worker) {
        (Some(services), true) => {
            let copy = match &config.database {
                DatabaseConfig::Sqlite(_) => Some(worker::PreMigrationCopy {
                    path: config.pre_migration_copy(),
                    self_check_passed: services.self_check_passed,
                }),
                DatabaseConfig::Postgres(_) => None,
            };
            Some(tokio::spawn(worker::run(
                services.api.clone(),
                services.db.clone(),
                services.bus.subscribe(),
                stop_rx,
                config.worker_interval,
                copy,
            )))
        }
        _ => None,
    };

    let served = if config.roles.need_listener() {
        let api = if config.roles.api {
            services.as_ref().map(|s| s.api.clone())
        } else {
            None
        };
        let app = http::router(api, config.roles.web);
        match tokio::net::TcpListener::bind(config.listen).await {
            Ok(listener) => {
                let port = listener.local_addr().map_or(0, |a| a.port());
                log::info("listening", &[Field::U64("port", u64::from(port))]);
                tokio::select! {
                    () = serve_http(listener, app, shutdown_signal()) => Ok(()),
                    // Dropping the serving future drops the listener and every connection.
                    () = &mut lost => Err(ServeError::InstanceLockLost),
                }
            }
            Err(e) => Err(ServeError::Listener(e.kind())),
        }
    } else {
        tokio::select! {
            () = shutdown_signal() => Ok(()),
            () = &mut lost => Err(ServeError::InstanceLockLost),
        }
    };

    let _receivers_gone = stop_tx.send(true);
    if matches!(served, Err(ServeError::InstanceLockLost)) {
        // Exit at once (ADR 0023 §5 step 1): nothing of this process may go on using a
        // database an admin command can now rewrite. The worker is not waited for; aborting
        // it rolls back the transaction it may be in.
        if let Some(task) = worker_task {
            task.abort();
        }
        return served;
    }
    if let Some(task) = worker_task
        && task.await.is_err()
    {
        log::error("worker_task_failed", &[]);
    }
    if let Some(services) = services {
        services.db.close().await;
    }
    // The instance lock goes last, after the pools: held for the process's whole life.
    let _receiver_gone = lock_stop_tx.send(true);
    if let Some(task) = watchdog
        && let Ok(Some(lock)) = task.await
    {
        release_instance_lock(lock).await;
    }
    log::info("stopped", &[]);
    served
}

#[cfg(test)]
mod tests {
    //! The instance lock's plumbing on `SQLite`, where the lock is a marker: it is granted in
    //! either mode, the watchdog hands it back when told to stop, and "lost" never fires. The
    //! `PostgreSQL` lock itself is tested in `rizzy-storage` (`tests/storage/postgres.rs`).

    use super::*;

    /// A writable `SQLite` database in a new temporary directory, and that directory.
    async fn sqlite() -> (Database, std::path::PathBuf) {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rizzy-server-instance-lock-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db.sqlite3");
        let lock = WriterLock::acquire(&path).unwrap();
        let db = Database::open_sqlite(&SqliteOptions::new(&path), lock)
            .await
            .unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn sqlite_grants_the_instance_lock_and_the_watchdog_hands_it_back() {
        let (db, dir) = sqlite().await;
        for mode in [InstanceLockMode::Shared, InstanceLockMode::Exclusive] {
            let mut lock = take_instance_lock(&db, mode).await.unwrap();
            assert_eq!(lock.mode(), mode);
            assert!(instance_lock_held(&mut lock).await);
            release_instance_lock(lock).await;
        }

        let lock = take_instance_lock(&db, InstanceLockMode::Shared)
            .await
            .unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let (lost_tx, lost_rx) = watch::channel(false);
        let watchdog = tokio::spawn(watch_instance_lock(
            lock,
            Duration::from_millis(5),
            stop_rx,
            lost_tx,
        ));
        // Several checks pass; nothing is reported lost.
        let lost = tokio::time::timeout(Duration::from_millis(100), instance_lock_lost(lost_rx));
        assert!(lost.await.is_err(), "the lock is held: lost never resolves");
        stop_tx.send(true).unwrap();
        let handed_back = watchdog.await.unwrap();
        assert!(handed_back.is_some(), "a stopped watchdog returns the lock");

        // A watchdog whose server is gone (the sender dropped) stops too.
        let lock = take_instance_lock(&db, InstanceLockMode::Shared)
            .await
            .unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let (lost_tx, lost_rx) = watch::channel(false);
        drop(stop_tx);
        let handed_back =
            watch_instance_lock(lock, Duration::from_secs(3600), stop_rx, lost_tx).await;
        assert!(handed_back.is_some());
        // Its `lost` sender is dropped without a loss: still never resolves.
        let lost = tokio::time::timeout(Duration::from_millis(50), instance_lock_lost(lost_rx));
        assert!(lost.await.is_err());

        db.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn instance_lock_errors_say_what_to_do_and_name_no_value() {
        let shared = ServeError::InstanceLockRefused(InstanceLockMode::Shared).to_string();
        assert!(shared.contains("restore, migrate, secrets rotate or secrets retire-setups"));
        let exclusive = ServeError::InstanceLockRefused(InstanceLockMode::Exclusive).to_string();
        assert!(exclusive.contains("stop them first"));
        assert!(ServeError::InstanceLockLost.to_string().contains("lost"));
        assert!(
            ServeError::InstanceLockTimeout
                .to_string()
                .contains("timed out")
        );
    }
}
