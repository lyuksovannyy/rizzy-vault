// SPDX-License-Identifier: AGPL-3.0-only

//! The `icons` role's breach-check endpoint ([ADR 0053]; CRYPTO.md §11.16; INV-77).
//!
//! `POST /api/v1/icons/breach-range`, body `{"prefix":"<5 uppercase hex>"}`, no session and no
//! bearer token: `200` with `{"range":"<the upstream's SUFFIX:COUNT lines, unmodified>"}`,
//! or the uniform `{"error":"<code>"}` of [ADR 0028] item 3. Steps, in order:
//!
//! 1. **Source** ([ADR 0028] item 11): the peer address, or `X-Forwarded-For` from a trusted
//!    proxy; a trusted proxy without a usable header is `400 invalid_request`.
//! 2. **Rate limit** (ADR 0053 item 8, ADR 0052 owner answer 5): 30 per minute, burst 10, per
//!    source, before any body byte is read; `429 rate_limited` with `Retry-After`.
//! 3. **Body** (item 7): at most 1 MiB, within the body deadline; `413` past it.
//! 4. **Parse**: exactly `{"prefix": …}` with 5 uppercase hex characters, unknown fields
//!    refused (no identifier can ride along); `400 invalid_request` otherwise.
//! 5. **Range** ([`rizzy_icon_proxy::breach`]): from the shared cache or the upstream. An
//!    upstream that cannot be reached, or that answers anything but a range, is
//!    `500 internal` (the closed code table of item 3 has nothing closer; clients show
//!    "unavailable"), with one log line naming the cause.
//!
//! **What is logged** (INV-77: "no per-user log"): the access line (method, route template,
//! status, duration) and, on an upstream failure, `breach_upstream_failed` with a fixed cause.
//! Never the prefix, the body, the range, a header or an address. The prefix, the range and the
//! request types print no content from `Debug` either.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use rizzy_domain_auth::types::ErrorCode;
use rizzy_icon_proxy::breach::BreachService;
use rizzy_icon_proxy::limit::RateLimiter;
use rizzy_icon_proxy::wire::{BreachRangeRequest, BreachRangeResponse, ICONS_BREACH_RANGE};

use super::api::{
    BODY_LIMIT, X_FORWARDED_FOR, error_response, json_response, rate_limited_response, read_body,
};
use super::headers::client_address;
use crate::log::{self, Field};

/// The route of the breach-check endpoint, as the router and the access log name it.
pub const BREACH_RANGE_ROUTE: &str = ICONS_BREACH_RANGE;

/// The source charged when a request has no peer address (only in-process tests): one shared
/// bucket.
const UNKNOWN_SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The state of the `icons` router.
pub struct Icons {
    /// The breach check, when it is on (ADR 0053 item 5).
    breach: Option<BreachService>,
    /// The per-source limit of the role's endpoints.
    limiter: Mutex<RateLimiter>,
    /// The reverse proxies whose `X-Forwarded-For` is read.
    trusted_proxies: Vec<IpAddr>,
}

impl fmt::Debug for Icons {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Icons")
            .field("breach_check", &self.breach.is_some())
            .finish_non_exhaustive()
    }
}

impl Icons {
    /// The router state: `breach` when the breach check is on, the default limiter.
    #[must_use]
    pub fn new(breach: Option<BreachService>, trusted_proxies: Vec<IpAddr>) -> Self {
        Self::with_limiter(breach, trusted_proxies, RateLimiter::default())
    }

    /// As [`Icons::new`], with a given limiter.
    #[must_use]
    pub fn with_limiter(
        breach: Option<BreachService>,
        trusted_proxies: Vec<IpAddr>,
        limiter: RateLimiter,
    ) -> Self {
        Self {
            breach,
            limiter: Mutex::new(limiter),
            trusted_proxies,
        }
    }

    /// Whether the breach-check route is served.
    #[must_use]
    pub const fn breach_check_on(&self) -> bool {
        self.breach.is_some()
    }
}

/// The client address of a request (step 1); [`UNKNOWN_SOURCE`] without a peer address.
fn source(parts: &Parts, trusted: &[IpAddr]) -> Result<IpAddr, ErrorCode> {
    let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
        return Ok(UNKNOWN_SOURCE);
    };
    let forwarded: Vec<&[u8]> = parts
        .headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    client_address(peer.ip(), &forwarded, trusted).map_err(|_| ErrorCode::InvalidRequest)
}

/// Serves `POST /api/v1/icons/breach-range` (module docs).
pub async fn breach_range(State(icons): State<Arc<Icons>>, request: Request) -> Response {
    let route = BREACH_RANGE_ROUTE;
    let (parts, body) = request.into_parts();
    let ip = match source(&parts, &icons.trusted_proxies) {
        Ok(ip) => ip,
        Err(code) => return error_response(code, route),
    };
    let charged = icons
        .limiter
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .check(ip, Instant::now());
    if let Err(wait) = charged {
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        return rate_limited_response(wait_ms, route);
    }
    let body = match read_body(route, &parts, body, BODY_LIMIT).await {
        Ok(body) => body,
        Err(code) => return error_response(code, route),
    };
    // serde_json's message can quote the input; it is dropped (INV-48).
    let Ok(request) = serde_json::from_slice::<BreachRangeRequest>(&body) else {
        return error_response(ErrorCode::InvalidRequest, route);
    };
    let Some(service) = &icons.breach else {
        return error_response(ErrorCode::NotFound, route);
    };
    match service.range(request.prefix).await {
        Ok(range) => match serde_json::to_vec(&BreachRangeResponse { range }) {
            Ok(json) => json_response(StatusCode::OK, json, route),
            Err(_) => error_response(ErrorCode::Internal, route),
        },
        Err(e) => {
            log::warn(
                "breach_upstream_failed",
                &[Field::Str("route", route), Field::Str("reason", e.reason())],
            );
            error_response(ErrorCode::Internal, route)
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! The endpoint against a fake upstream on a local socket, through a test connector (no
    //! network): the answer, the order of checks, the limits, and the log lines, which must
    //! never hold the prefix, a suffix or the range (INV-77).

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
    use rizzy_icon_proxy::cache::{Cache, DEFAULT_TTL};
    use rizzy_icon_proxy::connect::{BoxIo, ConnectError, ConnectFuture, Connector};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tower::ServiceExt as _;

    use super::*;
    use crate::http::icons_router;
    use crate::log::capture::lines_of;

    const PREFIX: &str = "5BAA6";
    const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    /// A connector to a local address (the fake upstream), or to nothing.
    struct Local(Option<SocketAddr>);

    impl Connector for Local {
        fn connect<'a>(&'a self, _host: &'a str) -> ConnectFuture<'a> {
            Box::pin(async move {
                let addr = self.0.ok_or(ConnectError::Refused)?;
                let stream = TcpStream::connect(addr)
                    .await
                    .map_err(|_| ConnectError::Connect)?;
                Ok(Box::new(stream) as BoxIo)
            })
        }
    }

    /// A fake upstream answering every request with `body` as a `200`.
    async fn upstream(body: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let mut read = 0;
                while !buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf[read..]).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => read += n,
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        addr
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "rizzy-icons-http-{}-{}",
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

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn router(upstream: Option<SocketAddr>, dir: &TempDir, trusted: Vec<IpAddr>) -> Router {
        let service = BreachService::new(
            Arc::new(Local(upstream)),
            Cache::new(dir.0.clone(), DEFAULT_TTL, 1 << 20),
        );
        icons_router(Arc::new(Icons::new(Some(service), trusted)))
    }

    fn post(body: &str, peer: Option<&str>, forwarded: Option<&str>) -> axum::http::Request<Body> {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(BREACH_RANGE_ROUTE)
            .header(CONTENT_TYPE, "application/json");
        if let Some(xff) = forwarded {
            request = request.header("x-forwarded-for", xff);
        }
        let mut request = request.body(Body::from(body.to_owned())).unwrap();
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        request
    }

    async fn send(
        router: &Router,
        request: axum::http::Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn assert_clean(lines: &[String]) {
        assert!(!lines.is_empty());
        for line in lines {
            assert!(!line.contains(PREFIX), "{line}");
            assert!(!line.contains(&PREFIX.to_lowercase()), "{line}");
            assert!(!line.contains(&SUFFIX[..10]), "{line}");
            assert!(!line.contains("203.0.113."), "{line}");
        }
    }

    #[test]
    fn serves_the_range_unmodified_and_logs_no_prefix() {
        let dir = TempDir::new();
        let range = format!("{SUFFIX}:52256179\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0");
        let ((status, headers, body), lines) = lines_of(|| {
            block_on(async {
                let addr = upstream(range.clone()).await;
                let router = router(Some(addr), &dir, Vec::new());
                send(
                    &router,
                    post(
                        &format!(r#"{{"prefix":"{PREFIX}"}}"#),
                        Some("203.0.113.7:5000"),
                        None,
                    ),
                )
                .await
            })
        });
        assert_eq!(status, StatusCode::OK, "{body}");
        let answer: BreachRangeResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(answer.range.as_str(), range);
        assert_eq!(headers[CONTENT_TYPE], "application/json");
        assert_eq!(headers[CACHE_CONTROL], "no-store");
        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("strict-transport-security"));
        assert!(!headers.contains_key("access-control-allow-origin"));
        assert_clean(&lines);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("http_request") && l.contains(BREACH_RANGE_ROUTE))
        );
    }

    #[test]
    fn an_unreachable_upstream_is_internal_with_a_fixed_cause() {
        let dir = TempDir::new();
        let ((status, _, body), lines) = lines_of(|| {
            block_on(async {
                let router = router(None, &dir, Vec::new());
                send(
                    &router,
                    post(&format!(r#"{{"prefix":"{PREFIX}"}}"#), None, None),
                )
                .await
            })
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"error":"internal"}"#);
        assert_clean(&lines);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("breach_upstream_failed") && l.contains("refused_address"))
        );
    }

    #[test]
    fn bad_requests() {
        let dir = TempDir::new();
        let (results, lines) = lines_of(|| {
            block_on(async {
                let router = router(None, &dir, Vec::new());
                let mut out = Vec::new();
                for body in [
                    r#"{"prefix":"5baa6"}"#.to_owned(),
                    r#"{"prefix":"5BAA"}"#.to_owned(),
                    r#"{"prefix":"5BAA6","item_id":"x"}"#.to_owned(),
                    "not json".to_owned(),
                    String::new(),
                ] {
                    out.push((send(&router, post(&body, None, None)).await, 400));
                }
                // Past the 1 MiB body limit.
                let big = format!(
                    r#"{{"prefix":"{PREFIX}","pad":"{}"}}"#,
                    "x".repeat(BODY_LIMIT)
                );
                out.push((send(&router, post(&big, None, None)).await, 413));
                // A wrong method, an unknown path under the role.
                let get = axum::http::Request::builder()
                    .method("GET")
                    .uri(BREACH_RANGE_ROUTE)
                    .body(Body::empty())
                    .unwrap();
                out.push((send(&router, get).await, 405));
                let unknown = axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/icons/fetch")
                    .body(Body::empty())
                    .unwrap();
                out.push((send(&router, unknown).await, 404));
                out
            })
        });
        for ((status, _, body), expected) in results {
            assert_eq!(status.as_u16(), expected, "{body}");
            assert!(body.starts_with(r#"{"error":"#), "{body}");
        }
        assert_clean(&lines);
    }

    #[test]
    fn breach_check_off_is_not_found() {
        let router = icons_router(Arc::new(Icons::new(None, Vec::new())));
        let (status, _, body) = block_on(send(
            &router,
            post(&format!(r#"{{"prefix":"{PREFIX}"}}"#), None, None),
        ));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, r#"{"error":"not_found"}"#);
    }

    #[test]
    fn rate_limited_per_source_before_the_body_is_read() {
        let dir = TempDir::new();
        let (results, lines) = lines_of(|| {
            block_on(async {
                let addr = upstream(format!("{SUFFIX}:1")).await;
                let router = router(Some(addr), &dir, Vec::new());
                let ok = format!(r#"{{"prefix":"{PREFIX}"}}"#);
                let mut statuses = Vec::new();
                for _ in 0..rizzy_icon_proxy::limit::BURST {
                    statuses.push(
                        send(&router, post(&ok, Some("203.0.113.9:1"), None))
                            .await
                            .0,
                    );
                }
                // The next one is refused even with a body the parser would refuse: the limit
                // comes first.
                let refused = send(&router, post("not json", Some("203.0.113.9:1"), None)).await;
                // The same /64 is the same source; another address is not.
                let other = send(&router, post(&ok, Some("203.0.113.10:1"), None))
                    .await
                    .0;
                (statuses, refused, other)
            })
        });
        let (statuses, (status, headers, body), other) = results;
        assert!(
            statuses.iter().all(|s| *s == StatusCode::OK),
            "{statuses:?}"
        );
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, r#"{"error":"rate_limited"}"#);
        assert_eq!(headers[RETRY_AFTER], "2");
        assert_eq!(other, StatusCode::OK);
        assert_clean(&lines);
    }

    #[test]
    fn a_trusted_proxy_must_name_the_client() {
        let dir = TempDir::new();
        let proxy: IpAddr = "192.0.2.1".parse().unwrap();
        let (missing, present) = block_on(async {
            let addr = upstream(format!("{SUFFIX}:1")).await;
            let router = router(Some(addr), &dir, vec![proxy]);
            let ok = format!(r#"{{"prefix":"{PREFIX}"}}"#);
            (
                send(&router, post(&ok, Some("192.0.2.1:443"), None))
                    .await
                    .0,
                send(
                    &router,
                    post(&ok, Some("192.0.2.1:443"), Some("203.0.113.5")),
                )
                .await
                .0,
            )
        });
        assert_eq!(missing, StatusCode::BAD_REQUEST);
        assert_eq!(present, StatusCode::OK);
    }
}
