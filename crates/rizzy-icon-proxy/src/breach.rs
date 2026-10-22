// SPDX-License-Identifier: AGPL-3.0-only

//! The breach-check range query ([ADR 0053]; CRYPTO.md §11.16; INV-77).
//!
//! For a [`HashPrefix`] (5 uppercase hex characters, the only thing a client sends), the
//! service answers the upstream's range response, from the shared cache when it holds a fresh
//! copy and from the upstream otherwise:
//!
//! - **One fixed upstream.** `GET https://api.pwnedpasswords.com/range/<PREFIX>`
//!   ([`UPSTREAM_HOST`], [`RANGE_PATH`]), over HTTPS on port 443 only, through the
//!   [`Connector`] (production: DNS-pinned and allow-listed, INV-51). The host is compiled in,
//!   never taken from a request or a setting (ADR 0053 item 2). Headers: `Host`, a
//!   `User-Agent` (the upstream refuses a request without one), `Add-Padding: true` (the
//!   upstream pads every answer to 800–1,000 lines with count-0 entries, so the answer's size
//!   does not narrow the prefix down further for an observer of the encrypted traffic), and
//!   `Connection: close`. No `Accept-Encoding`: the body comes uncompressed, and a
//!   `Content-Encoding` other than `identity` is refused, so no decompression ever runs.
//!   (Host, path and headers: haveibeenpwned.com/API/v3, "Searching by hash range" and
//!   "Add-Padding", read 2026-10-22; ADR 0053 item 2 left them to this change.)
//! - **Limits.** The whole fetch (connect, TLS, request, body) has [`FETCH_BUDGET`]; at most
//!   [`MAX_CONCURRENT_FETCHES`] run at once; the body is read through a limit of
//!   [`MAX_BREACH_RANGE_LEN`] bytes and refused past it, before it is buffered whole. Only a
//!   `200` is accepted: a redirect is never followed.
//! - **Checked before cached or served.** The body must parse as a range
//!   ([`RangeBody::from_bytes`]); a malformed one is neither cached nor relayed. What is
//!   relayed is the upstream's text unmodified.
//! - **Cached by prefix.** `breach-<PREFIX>.txt` in the shared cache; a cached copy that no
//!   longer parses is removed and fetched again.
//! - **No log, no identity.** This module logs nothing; [`BreachError`] names a cause, never
//!   the prefix or the upstream's answer.
//!
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::body::Bytes;
use hyper::header::{CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, HeaderValue, USER_AGENT};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rizzy_proto::breach::{HashPrefix, RangeBody};
use rizzy_proto::limits::MAX_BREACH_RANGE_LEN;
use tokio::sync::Semaphore;

use crate::cache::Cache;
use crate::connect::{ConnectError, Connector};

/// The upstream range API's host (ADR 0053 item 2: one hardcoded hostname).
pub const UPSTREAM_HOST: &str = "api.pwnedpasswords.com";

/// The path of a range query, before the prefix.
pub const RANGE_PATH: &str = "/range/";

/// The `User-Agent` sent upstream: the application, no version and nothing per instance.
pub const UPSTREAM_USER_AGENT: &str = "rizzy-vault";

/// The padding header (module docs).
pub const ADD_PADDING_HEADER: &str = "add-padding";

/// The time budget of one upstream fetch, connection included (ADR 0052's 10 s per request,
/// INV-76, applied to this fetch too).
pub const FETCH_BUDGET: Duration = Duration::from_secs(10);

/// Upstream fetches running at once, at most; further requests wait, within their budget.
pub const MAX_CONCURRENT_FETCHES: usize = 8;

/// Why no range could be served. Names a cause only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BreachError {
    /// The connection failed ([`ConnectError`]).
    Connect(ConnectError),
    /// The HTTP exchange failed.
    Http,
    /// The upstream answered a status other than `200` (a redirect included).
    Status,
    /// The body was compressed, larger than the limit, or not the range format.
    Malformed,
    /// The fetch took longer than [`FETCH_BUDGET`].
    Timeout,
}

impl BreachError {
    /// A fixed name for the log line of a failed fetch.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Connect(ConnectError::Resolve) => "resolve",
            Self::Connect(ConnectError::Refused) => "refused_address",
            Self::Connect(ConnectError::Connect) => "connect",
            Self::Connect(ConnectError::Tls) => "tls",
            Self::Http => "http",
            Self::Status => "status",
            Self::Malformed => "malformed",
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for BreachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "breach-check upstream failed: {}", self.reason())
    }
}

impl std::error::Error for BreachError {}

impl From<ConnectError> for BreachError {
    fn from(e: ConnectError) -> Self {
        Self::Connect(e)
    }
}

/// The breach-check service of one `icons` process.
pub struct BreachService {
    /// How the upstream is reached.
    connector: Arc<dyn Connector>,
    /// The shared cache.
    cache: Cache,
    /// Upstream fetch slots.
    fetches: Semaphore,
    /// The time budget of one fetch: [`FETCH_BUDGET`] (tests shorten it).
    budget: Duration,
}

impl fmt::Debug for BreachService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BreachService")
            .field("cache", &self.cache)
            .finish_non_exhaustive()
    }
}

/// The cache entry name of `prefix`.
fn cache_name(prefix: HashPrefix) -> String {
    format!("breach-{}.txt", prefix.as_str())
}

impl BreachService {
    /// A service that reaches the upstream through `connector` and caches in `cache`.
    #[must_use]
    pub fn new(connector: Arc<dyn Connector>, cache: Cache) -> Self {
        Self {
            connector,
            cache,
            fetches: Semaphore::new(MAX_CONCURRENT_FETCHES),
            budget: FETCH_BUDGET,
        }
    }

    /// The same service with a shorter fetch budget, for tests of the timeout.
    #[cfg(test)]
    fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// The range of `prefix`: cached when fresh, fetched and cached otherwise.
    ///
    /// # Errors
    /// [`BreachError`] when the upstream cannot be reached or answers anything but a range.
    pub async fn range(&self, prefix: HashPrefix) -> Result<RangeBody, BreachError> {
        let name = cache_name(prefix);
        if let Some(bytes) = self.cache.get(&name, MAX_BREACH_RANGE_LEN).await {
            match RangeBody::from_bytes(&bytes) {
                Ok(body) => return Ok(body),
                Err(_) => self.cache.remove(&name).await,
            }
        }
        let body = tokio::time::timeout(self.budget, async {
            let _slot = self
                .fetches
                .acquire()
                .await
                .map_err(|_| BreachError::Http)?;
            fetch(self.connector.as_ref(), prefix).await
        })
        .await
        .map_err(|_| BreachError::Timeout)??;
        // The cache is an optimisation: a failed write still serves the answer.
        let _ = self
            .cache
            .put(&name, body.as_str().as_bytes().to_vec())
            .await;
        Ok(body)
    }
}

/// One upstream request (module docs).
async fn fetch(connector: &dyn Connector, prefix: HashPrefix) -> Result<RangeBody, BreachError> {
    let io = connector.connect(UPSTREAM_HOST).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| BreachError::Http)?;
    let driver = tokio::spawn(connection);
    let result = async {
        let mut path = String::with_capacity(RANGE_PATH.len() + prefix.as_str().len());
        path.push_str(RANGE_PATH);
        path.push_str(prefix.as_str());
        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(HOST, HeaderValue::from_static(UPSTREAM_HOST))
            .header(USER_AGENT, HeaderValue::from_static(UPSTREAM_USER_AGENT))
            .header(ADD_PADDING_HEADER, HeaderValue::from_static("true"))
            .header(CONNECTION, HeaderValue::from_static("close"))
            .body(Empty::<Bytes>::new())
            .map_err(|_| BreachError::Http)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| BreachError::Http)?;
        if response.status() != StatusCode::OK {
            return Err(BreachError::Status);
        }
        let headers = response.headers();
        if headers
            .get_all(CONTENT_ENCODING)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Err(BreachError::Malformed);
        }
        if let Some(length) = headers.get(CONTENT_LENGTH) {
            let length = length
                .to_str()
                .ok()
                .and_then(|t| t.parse::<u64>().ok())
                .ok_or(BreachError::Malformed)?;
            if length > u64::try_from(MAX_BREACH_RANGE_LEN).unwrap_or(u64::MAX) {
                return Err(BreachError::Malformed);
            }
        }
        let body = Limited::new(response.into_body(), MAX_BREACH_RANGE_LEN)
            .collect()
            .await
            .map_err(|e| {
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    BreachError::Malformed
                } else {
                    BreachError::Http
                }
            })?
            .to_bytes();
        RangeBody::from_bytes(&body).map_err(|_| BreachError::Malformed)
    }
    .await;
    driver.abort();
    result
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! The service against a fake upstream on a local socket, through a test connector (no
    //! network): the request line and headers, caching, and every refusal.

    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::cache::DEFAULT_TTL;
    use crate::connect::{BoxIo, ConnectFuture};

    const HIT: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    /// A connector to a local address, recording the hosts it was asked for.
    struct Local {
        addr: std::net::SocketAddr,
        hosts: Mutex<Vec<String>>,
    }

    impl Connector for Local {
        fn connect<'a>(&'a self, host: &'a str) -> ConnectFuture<'a> {
            Box::pin(async move {
                self.hosts.lock().unwrap().push(host.to_owned());
                let stream = TcpStream::connect(self.addr)
                    .await
                    .map_err(|_| ConnectError::Connect)?;
                Ok(Box::new(stream) as BoxIo)
            })
        }
    }

    /// A fake upstream answering every connection with `response`; returns its address, the
    /// request heads it received and the connection count.
    async fn upstream(
        response: Vec<u8>,
    ) -> (
        std::net::SocketAddr,
        Arc<Mutex<Vec<String>>>,
        Arc<AtomicUsize>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let count = Arc::new(AtomicUsize::new(0));
        let (h, c) = (heads.clone(), count.clone());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                c.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 8192];
                let mut read = 0;
                while !buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf[read..]).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => read += n,
                    }
                }
                h.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..read]).into_owned());
                let _ = socket.write_all(&response).await;
                let _ = socket.shutdown().await;
            }
        });
        (addr, heads, count)
    }

    fn ok_response(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "rizzy-breach-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn prefix() -> HashPrefix {
        HashPrefix::parse("5BAA6").unwrap()
    }

    async fn service(
        response: Vec<u8>,
        dir: &TempDir,
    ) -> (
        BreachService,
        Arc<Local>,
        Arc<Mutex<Vec<String>>>,
        Arc<AtomicUsize>,
    ) {
        let (addr, heads, count) = upstream(response).await;
        let local = Arc::new(Local {
            addr,
            hosts: Mutex::new(Vec::new()),
        });
        let cache = Cache::new(dir.0.clone(), DEFAULT_TTL, 1 << 20);
        (
            BreachService::new(local.clone(), cache),
            local,
            heads,
            count,
        )
    }

    #[tokio::test]
    async fn fetches_relays_unmodified_and_caches_by_prefix() {
        let dir = TempDir::new();
        let body = format!("{HIT}:3\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0");
        let (service, local, heads, count) = service(ok_response(&body), &dir).await;
        let range = service.range(prefix()).await.unwrap();
        assert_eq!(range.as_str(), body);
        // The request: the fixed host, the range path with the prefix, the headers.
        assert_eq!(local.hosts.lock().unwrap().as_slice(), [UPSTREAM_HOST]);
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(head.starts_with("get /range/5baa6 http/1.1\r\n"), "{head}");
        assert!(head.contains("host: api.pwnedpasswords.com\r\n"));
        assert!(head.contains("user-agent: rizzy-vault\r\n"));
        assert!(head.contains("add-padding: true\r\n"));
        assert!(!head.contains("accept-encoding"));
        // A second request is served from the cache.
        assert_eq!(service.range(prefix()).await.unwrap().as_str(), body);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let cached = std::fs::read_to_string(dir.0.join("breach-5BAA6.txt")).unwrap();
        assert_eq!(cached, body);
    }

    #[tokio::test]
    async fn a_corrupt_cache_entry_is_replaced() {
        let dir = TempDir::new();
        std::fs::write(dir.0.join("breach-5BAA6.txt"), "garbage").unwrap();
        let body = format!("{HIT}:1");
        let (service, _, _, count) = service(ok_response(&body), &dir).await;
        assert_eq!(service.range(prefix()).await.unwrap().as_str(), body);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refusals_are_not_cached() {
        let too_long = format!("{HIT}:1\r\n").repeat(MAX_BREACH_RANGE_LEN / 30);
        let cases: Vec<(Vec<u8>, BreachError)> = vec![
            (
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\nContent-Length: 0\r\n\r\n".to_vec(),
                BreachError::Status,
            ),
            (
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec(),
                BreachError::Status,
            ),
            (ok_response("<html>not a range</html>"), BreachError::Malformed),
            (ok_response(&too_long), BreachError::Malformed),
            (
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n{HIT}:1",
                    HIT.len() + 2
                )
                .into_bytes(),
                BreachError::Malformed,
            ),
            // A chunked body past the limit is cut off by the reader, not buffered.
            (
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                    too_long.len(),
                    too_long
                )
                .into_bytes(),
                BreachError::Malformed,
            ),
            (b"not http at all".to_vec(), BreachError::Http),
        ];
        for (response, expected) in cases {
            let dir = TempDir::new();
            let (service, _, _, _) = service(response, &dir).await;
            assert_eq!(service.range(prefix()).await, Err(expected));
            assert!(!dir.0.join("breach-5BAA6.txt").exists());
        }
    }

    #[tokio::test]
    async fn a_silent_upstream_hits_the_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let dir = TempDir::new();
        let local = Arc::new(Local {
            addr,
            hosts: Mutex::new(Vec::new()),
        });
        let service = BreachService::new(local, Cache::new(dir.0.clone(), DEFAULT_TTL, 1 << 20))
            .with_budget(Duration::from_millis(300));
        assert_eq!(service.range(prefix()).await, Err(BreachError::Timeout));
    }

    #[test]
    fn errors_name_no_prefix() {
        for e in [
            BreachError::Http,
            BreachError::Status,
            BreachError::Malformed,
            BreachError::Timeout,
            BreachError::Connect(ConnectError::Refused),
        ] {
            assert!(!e.to_string().contains("5BAA6"));
            assert!(!format!("{e:?}").contains("5BAA6"));
        }
    }
}
