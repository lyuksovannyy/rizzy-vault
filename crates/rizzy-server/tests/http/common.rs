//! The harness: a server started the way `rizzy-vault` starts (a secrets file on its own
//! directory, a real `SQLite` database in a data directory, the startup checks), its router driven
//! in-process with `tower::ServiceExt::oneshot`.
//!
//! The end-to-end client (signup → login → device authentication → signed upload → Fetch → key
//! rotation) is `rizzy-client`, the one internal crate ADR 0016 §4 (owner decision 4) lets this
//! crate dev-depend on; `rotation.rs` drives it. `rizzy-core`, `rizzy-proto` and `rizzy-sync`
//! stay out of these tests: the wire types are only received from the client and passed back.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_domain_auth::ServerSecrets;
use rizzy_domain_auth::types::SessionToken;
use rizzy_server::config::{self, Config, Settings, Sources};
use rizzy_server::http::api::Api;
use rizzy_server::server::{Services, open_services};
use rizzy_server::{http, secrets_file};
use serde::de::DeserializeOwned;
use tower::ServiceExt as _;

/// The canonical origin of every test server.
pub(crate) const ORIGIN: &str = "https://vault.example.com";

/// Runs `f` on a current-thread runtime.
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// A temporary directory, removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// A new, empty directory.
    pub(crate) fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rizzy-server-http-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// `name` inside it.
    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The configuration of a test server in `dir`, laid out as the container image is: a data
/// directory and, outside it, a directory for the secrets file (ADR 0010 §4), both created
/// here. Open signup; `extra` adds or replaces settings.
pub(crate) fn config_in(dir: &TempDir, extra: &[(&'static str, &str)]) -> Config {
    let data = dir.join("data");
    let secrets_dir = dir.join("secrets");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&secrets_dir).unwrap();
    let secrets_path = secrets_dir.join("secrets.json");
    let mut env: BTreeMap<&'static str, String> = BTreeMap::new();
    env.insert(config::ORIGIN, ORIGIN.to_owned());
    env.insert(config::SIGNUP, "open".to_owned());
    env.insert(config::DATA_DIR, data.to_str().unwrap().to_owned());
    env.insert(
        config::SECRETS_FILE,
        secrets_path.to_str().unwrap().to_owned(),
    );
    for (k, v) in extra {
        env.insert(k, (*v).to_owned());
    }
    let lookup = move |key: &str| env.get(key).map(OsString::from);
    Config::from_sources(&Sources {
        file: Settings::new(),
        env: &lookup,
        roles_flag: None,
    })
    .unwrap()
}

/// A started server.
pub(crate) struct Server {
    /// Keeps the directories alive.
    pub(crate) dir: TempDir,
    /// The services (the database stays open, and locked, while this lives).
    pub(crate) services: Services,
    /// The router of `api` and `web`.
    pub(crate) router: Router,
}

/// A response, collected.
pub(crate) struct Reply {
    /// The status.
    pub(crate) status: StatusCode,
    /// The headers.
    pub(crate) headers: HeaderMap,
    /// The body.
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// The body as `T`.
    pub(crate) fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).unwrap_or_else(|_| {
            panic!(
                "status {}: {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    /// The error code of an error body.
    pub(crate) fn error(&self) -> String {
        let v: serde_json::Value = serde_json::from_slice(&self.body).unwrap();
        v["error"].as_str().unwrap().to_owned()
    }

    /// A header's value as text.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }
}

impl Server {
    /// A server with open signup (the default roles: `api` and `web`).
    pub(crate) async fn start() -> Self {
        Self::start_with(&[]).await
    }

    /// A server with extra settings.
    pub(crate) async fn start_with(extra: &[(&'static str, &str)]) -> Self {
        Self::start_adjusted(extra, |_| {}).await
    }

    /// A server with extra settings, whose `api` role `adjust` edits before the router is built
    /// (the minimum client versions, which no setting carries).
    pub(crate) async fn start_adjusted(
        extra: &[(&'static str, &str)],
        adjust: impl FnOnce(&mut Api),
    ) -> Self {
        let dir = TempDir::new();
        let config = config_in(&dir, extra);
        let secrets = ServerSecrets::generate(&mut ChaCha20Rng::seed_from_u64(99));
        std::fs::write(
            &config.secrets_file,
            secrets_file::serialize(&secrets).unwrap(),
        )
        .unwrap();
        Self::open(dir, &config, adjust).await
    }

    /// Starts the server of `config`, whose directories are in `dir` and whose secrets file
    /// exists; `adjust` edits its `api` role before the router is built.
    pub(crate) async fn open(dir: TempDir, config: &Config, adjust: impl FnOnce(&mut Api)) -> Self {
        let mut services = open_services(config).await.unwrap();
        // The api role is not shared yet: the router is built below.
        adjust(Arc::get_mut(&mut services.api).unwrap());
        let router = http::router(Some(services.api.clone()), config.roles.web);
        Self {
            dir,
            services,
            router,
        }
    }

    /// Stops the server: closes the pools, which releases the writer lock, and hands back its
    /// directory, so an admin command or a second start can follow.
    pub(crate) async fn stop(self) -> TempDir {
        drop(self.router);
        self.services.db.close().await;
        drop(self.services);
        self.dir
    }

    /// Sends a request with a peer address, as the listener would.
    pub(crate) async fn send(&self, request: Request<Body>) -> Reply {
        send_via(self.router.clone(), request).await
    }

    /// Sends a request whose connection comes from `peer`.
    pub(crate) async fn send_from(&self, peer: IpAddr, request: Request<Body>) -> Reply {
        send_from(self.router.clone(), peer, request).await
    }

    /// `GET path`.
    pub(crate) async fn get(&self, path: &str) -> Reply {
        self.send(Request::get(path).body(Body::empty()).unwrap())
            .await
    }

    /// `POST path` with raw bytes and an optional bearer token.
    pub(crate) async fn post_raw(
        &self,
        path: &str,
        body: Vec<u8>,
        token: Option<&SessionToken>,
    ) -> Reply {
        let mut request = Request::post(path).header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header(
                "authorization",
                format!("Bearer {}", token.to_b64url().as_str()),
            );
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }
}

/// The peer address of [`send_via`]: a client, never a configured proxy.
pub(crate) const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// Sends a request through `router` with a peer address, as the listener would. Owns its
/// router, so a test can run it on a task of its own ([`Server::send`] borrows the server).
pub(crate) async fn send_via(router: Router, request: Request<Body>) -> Reply {
    send_from(router, PEER, request).await
}

/// Sends a request through `router` as a connection from `peer`.
pub(crate) async fn send_from(router: Router, peer: IpAddr, request: Request<Body>) -> Reply {
    let mut request = request;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer, 40000))));
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

impl Server {
    /// A server with open signup whose recovery waiting period is `hours` instead of the
    /// default 72 h (CRYPTO.md §11.9 step 2: "admin-configurable from 0 to 30 days. A
    /// single-user instance may set 0"), set as an operator sets it: through
    /// `RIZZY_RECOVERY_WAIT_HOURS`.
    pub(crate) async fn start_with_recovery_wait(hours: u32) -> Self {
        Self::start_with(&[(config::RECOVERY_WAIT_HOURS, &hours.to_string())]).await
    }
}
