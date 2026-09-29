//! The harness: a server started the way `rizzy-vault` starts (a secrets file on its own
//! directory, a real `SQLite` database in a data directory, the startup checks), its router driven
//! in-process with `tower::ServiceExt::oneshot`.
//!
//! The end-to-end client (signup → login → device authentication → signed upload → Fetch with
//! `rizzy-core`'s client-side functions) is not here: it needs `rizzy-core`, `rizzy-proto` and
//! `rizzy-sync` in this crate's tests, which ADR 0016 §3 and point 4 do not allow
//! (`rizzy-server` may dev-depend on `rizzy-client` only, which does not exist yet). It returns
//! once the owner decides how (an ADR 0016 change, or `rizzy-client`).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_domain_auth::ServerSecrets;
use rizzy_domain_auth::types::SessionToken;
use rizzy_server::config::{self, Config, Sources};
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

/// A started server.
pub(crate) struct Server {
    /// Keeps the directories alive.
    pub(crate) _dir: TempDir,
    /// The services (the database stays open, and locked, while this lives).
    pub(crate) _services: Services,
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
        let dir = TempDir::new();
        let data = dir.join("data");
        let secrets_dir = dir.join("secrets");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let secrets_path = secrets_dir.join("secrets.json");
        let secrets = ServerSecrets::generate(&mut ChaCha20Rng::seed_from_u64(99));
        std::fs::write(&secrets_path, secrets_file::serialize(&secrets).unwrap()).unwrap();
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
        let config = Config::from_sources(&Sources {
            file: BTreeMap::new(),
            env: &lookup,
            roles_flag: None,
        })
        .unwrap();
        let services = open_services(&config).await.unwrap();
        let router = http::router(Some(services.api.clone()), config.roles.web);
        Self {
            _dir: dir,
            _services: services,
            router,
        }
    }

    /// Sends a request with a peer address, as the listener would.
    pub(crate) async fn send(&self, request: Request<Body>) -> Reply {
        let mut request = request;
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((
                Ipv4Addr::new(192, 0, 2, 1),
                40000,
            ))));
        let response = self.router.clone().oneshot(request).await.unwrap();
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
