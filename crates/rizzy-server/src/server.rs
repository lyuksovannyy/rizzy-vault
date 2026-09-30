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
//!    database ([ADR 0011] point 9). `PostgreSQL`: connect, and refuse to start if a migration is
//!    pending, naming `rizzy-vault migrate`.
//! 4. **Draw the restore generation** if the database has none ([ADR 0021] §2), from the OS
//!    CSPRNG.
//! 5. **Check the secrets against the database** (CRYPTO.md §5.8, §5.11: a setup whose public
//!    key hash differs, a restored database next to a fresh secrets file, a sealed row naming a
//!    data key the file lacks): any mismatch refuses to start.
//! 6. **Build the domains**: the auth domain with the configured origin and signup mode, the
//!    vault domain with the in-process event bus ([`rizzy_bus`]).
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
    Database, PostgresOptions, RestoreGeneration, SqliteOptions, StartupMigration, WriterLock,
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
    /// The `api` role's services, which `worker` shares.
    pub api: Arc<Api>,
    /// The in-process event bus the vault domain publishes on; `worker` subscribes to it.
    pub bus: Bus,
    /// When startup steps 1–6 finished: the startup self-check passed. The worker counts the
    /// pre-migration copy's 24 h from it ([`worker::PreMigrationCopy`]).
    pub self_check_passed: Instant,
}

/// Opens the database (`SQLite` with its writer lock and startup migration, or `PostgreSQL`),
/// without the secrets checks: steps 3 of the module docs. Shared with `rizzy-vault migrate`.
///
/// # Errors
/// [`ServeError::Storage`].
pub async fn open_database(config: &Config, migrate: bool) -> Result<Database, ServeError> {
    match &config.database {
        DatabaseConfig::Sqlite(path) => {
            let lock = WriterLock::acquire(path)?;
            let db = Database::open_sqlite(&SqliteOptions::new(path), lock).await?;
            if migrate {
                match db.migrate_at_startup(&config.pre_migration_copy()).await? {
                    StartupMigration::UpToDate => {}
                    StartupMigration::Created => log::info("database_created", &[]),
                    StartupMigration::MigratedAfterCopy => {
                        log::info("database_migrated_after_copy", &[]);
                    }
                }
            }
            Ok(db)
        }
        DatabaseConfig::Postgres(url) => {
            let options = PostgresOptions::from_url(url)?;
            let db = Database::open_postgres(&options).await?;
            if migrate {
                db.migrate_at_startup(&config.pre_migration_copy()).await?;
            }
            Ok(db)
        }
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
    let db = open_database(config, true).await?;
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
    let auth = AuthService::new(db.clone(), secrets, auth_config, VaultBridge)
        .map_err(ServeError::AuthConfig)?;
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
    let services = if config.roles.need_database() {
        Some(open_services(&config).await?)
    } else {
        None
    };

    let (stop_tx, stop_rx) = watch::channel(false);
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
                serve_http(listener, app, shutdown_signal()).await;
                Ok(())
            }
            Err(e) => Err(ServeError::Listener(e.kind())),
        }
    } else {
        shutdown_signal().await;
        Ok(())
    };

    let _receivers_gone = stop_tx.send(true);
    if let Some(task) = worker_task
        && task.await.is_err()
    {
        log::error("worker_task_failed", &[]);
    }
    if let Some(services) = services {
        services.db.close().await;
    }
    log::info("stopped", &[]);
    served
}
