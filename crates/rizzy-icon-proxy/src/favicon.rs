// SPDX-License-Identifier: AGPL-3.0-only

//! The favicon fetch ([ADR 0052] points 2–5; INV-51; INV-76).
//!
//! [`FaviconService::icon`] answers the re-encoded PNG for a hostname, from the shared cache
//! when it holds a fresh copy and from the site otherwise.
//!
//! 1. **Cache** (point 5): `<host>-https-443.png`, then `<host>-http-80.png` (the scheme and
//!    port the fetch that filled it used); a fresh entry is served as it is.
//! 2. **Fetch, DNS-pinned** (point 2): resolve the target's host once ([`Dialer::resolve`]),
//!    take the first address that passes the INV-51 allow-list ([`crate::allow::is_allowed`]),
//!    and connect to exactly that address, never resolving again. `https` targets run TLS 1.3
//!    over it, verified against the hostname. Only when the **TCP connection** to port 443
//!    fails (refused, reset, timed out; never a TLS or certificate failure) is the same address
//!    tried once on plain HTTP, port 80 ([`FaviconService::without_http_fallback`] turns that
//!    off; owner answer 6 leaves it on). The fallback is never taken where it would downgrade a
//!    host already reached over HTTPS in the same chain.
//! 3. **Redirects** (point 2; INV-76): a `301`, `302`, `303`, `307` or `308` with a
//!    `Location` repeats step 2 for the new target ([`Target::resolve`]), at most
//!    [`MAX_REDIRECTS`] times per chain. A redirect from `https` to `http` on the same host,
//!    a `Location` the resolver refuses (another scheme, a port other than 80 and 443, …), a
//!    target whose addresses all fail the allow-list and a chain over the cap all end the
//!    fetch with no icon.
//! 4. **Discovery** (point 3): `GET /favicon.ico` on `https`, port 443 first. If its chain
//!    ends in any status other than `200`, or in a `200` whose body does not decode, `GET /`
//!    at the scheme and port that reached the host, read at most
//!    [`crate::discover::MAX_HTML_SCAN`] bytes of a `text/html` answer, scan them for icon
//!    links ([`crate::discover::icon_hrefs`]), resolve the first usable `href` against that
//!    page's own final request, and fetch it (steps 2–3 again; it may be another host). A
//!    connection failure, a refused redirect or a body past its limit ends the fetch.
//! 5. **Decode and re-encode** (point 4; [`crate::decode::reencode`]) on Tokio's blocking pool.
//!
//! **Limits** (INV-76): an image body is read through a limit of
//! [`crate::decode::MAX_IMAGE_BYTES`] and refused past it (a `Content-Length` over it is
//! refused before any body byte); a page is cut at the scan limit. No `Accept-Encoding` is
//! sent and a `Content-Encoding` other than `identity` is refused, so nothing is decompressed
//! before the image decoder. The whole sequence (cache miss to PNG) has [`FETCH_BUDGET`], and
//! at most [`MAX_CONCURRENT_FETCHES`] run at once.
//!
//! **No identity, no log.** The service gets a hostname only; it logs nothing, and its errors
//! carry no host, path, address or upstream answer.
//!
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md

use core::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper::header::{
    ACCEPT, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue,
    LOCATION, USER_AGENT,
};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rizzy_proto::icons::{IconHost, PNG_SIGNATURE};
use rizzy_proto::limits::MAX_ICON_PNG_LEN;
use tokio::sync::Semaphore;

use crate::allow::{HTTPS_PORT, is_allowed};
use crate::cache::{Cache, MAX_NAME_LEN};
use crate::connect::{BoxIo, CONNECT_TIMEOUT, ConnectError, Dialer};
use crate::decode::{DecodeError, MAX_IMAGE_BYTES, reencode};
use crate::discover::{MAX_HTML_SCAN, icon_hrefs};
use crate::target::{HTTP_PORT, MAX_REFERENCE_LEN, Scheme, Target, TargetError};

/// The time budget of one whole fetch, cache miss to PNG (INV-76; owner answer 2: 10 s).
pub const FETCH_BUDGET: Duration = Duration::from_secs(10);

/// The most redirects followed in one chain (INV-76; owner answer 2: 3).
pub const MAX_REDIRECTS: usize = 3;

/// At most this many fetches run at once; others wait, inside their budget.
pub const MAX_CONCURRENT_FETCHES: usize = 4;

/// The `User-Agent` sent upstream.
pub const UPSTREAM_USER_AGENT: &str = "rizzy-vault";

/// The path tried first (ADR 0052 point 3).
pub const FAVICON_PATH: &str = "/favicon.ico";

/// The longest `Content-Type` value read, in bytes.
const MAX_CONTENT_TYPE_LEN: usize = 256;

/// Why no icon was fetched. Carries no host, path, address or upstream answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FaviconError {
    /// Resolving, the allow-list, TCP or TLS failed.
    Connect(ConnectError),
    /// The HTTP exchange failed.
    Http,
    /// The final answer of a chain was not `200`.
    Status,
    /// A `Content-Encoding` other than `identity`.
    Encoding,
    /// A body past its limit.
    TooLarge,
    /// More than [`MAX_REDIRECTS`] redirects in one chain.
    Redirects,
    /// A redirect (or icon link) from `https` to `http` on the same host.
    Downgrade,
    /// A `Location` the resolver refused.
    Location(TargetError),
    /// The page named no usable icon, or was not HTML.
    NoIcon,
    /// The image did not decode or re-encode.
    Decode(DecodeError),
    /// Past [`FETCH_BUDGET`].
    Timeout,
}

impl FaviconError {
    /// A fixed name for the cause, for a log line.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Connect(ConnectError::Resolve) => "resolve",
            Self::Connect(ConnectError::Refused) => "refused_address",
            Self::Connect(ConnectError::Connect) => "connect",
            Self::Connect(ConnectError::Tls) => "tls",
            Self::Http => "http",
            Self::Status => "status",
            Self::Encoding => "encoding",
            Self::TooLarge => "too_large",
            Self::Redirects => "redirects",
            Self::Downgrade => "downgrade",
            Self::Location(_) => "location",
            Self::NoIcon => "no_icon",
            Self::Decode(e) => e.reason(),
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for FaviconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no icon: {}", self.reason())
    }
}

impl std::error::Error for FaviconError {}

impl From<ConnectError> for FaviconError {
    fn from(e: ConnectError) -> Self {
        Self::Connect(e)
    }
}

/// How a body is read.
#[derive(Clone, Copy, Debug)]
struct BodyLimit {
    /// The most bytes kept.
    max: usize,
    /// Past `max`: keep the first `max` bytes (a page to scan) or fail (an image).
    truncate: bool,
}

/// An image: refused past [`MAX_IMAGE_BYTES`].
const IMAGE_BODY: BodyLimit = BodyLimit {
    max: MAX_IMAGE_BYTES,
    truncate: false,
};

/// A page: cut at [`MAX_HTML_SCAN`].
const PAGE_BODY: BodyLimit = BodyLimit {
    max: MAX_HTML_SCAN,
    truncate: true,
};

/// The answer to one request.
enum Answer {
    /// A `200`: its `Content-Type` (lowercase, possibly empty) and body.
    Body(String, Vec<u8>),
    /// A redirect: its `Location`.
    Redirect(String),
    /// Any other status.
    Status,
}

/// The end of a chain of requests.
struct Chain {
    /// The first request as actually sent (after a port-80 fallback): the scheme and port
    /// that reached the first host.
    first: Target,
    /// The last request as actually sent.
    last: Target,
    /// Its answer (never a redirect).
    answer: Answer,
}

/// The favicon fetch (module docs).
pub struct FaviconService {
    /// Resolves and connects; production passes [`crate::connect::PinnedTls`].
    dialer: Arc<dyn Dialer>,
    /// The shared on-disk cache.
    cache: Cache,
    /// Bounds concurrent fetches.
    fetches: Semaphore,
    /// The budget of one fetch.
    budget: Duration,
    /// Whether a failed TCP connection to port 443 is retried on port 80.
    http_fallback: bool,
}

impl fmt::Debug for FaviconService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FaviconService")
            .field("cache", &self.cache)
            .field("budget", &self.budget)
            .field("http_fallback", &self.http_fallback)
            .finish_non_exhaustive()
    }
}

/// Whether going from `from` to `to` is a scheme downgrade on the same host.
fn downgrades(from: &Target, to: &Target) -> bool {
    from.scheme() == Scheme::Https && to.scheme() == Scheme::Http && from.host() == to.host()
}

/// The cache entry name for an icon of `host` fetched at `scheme` and `port` (ADR 0052
/// point 5), or `None` when it would pass [`MAX_NAME_LEN`] (a host over 241 bytes: such an
/// icon is served but not cached).
#[must_use]
pub fn cache_name(host: &str, scheme: Scheme, port: u16) -> Option<String> {
    let name = format!("{host}-{}-{port}.png", scheme.as_str());
    (name.len() <= MAX_NAME_LEN).then_some(name)
}

impl FaviconService {
    /// A service that connects through `dialer` and caches in `cache`.
    #[must_use]
    pub fn new(dialer: Arc<dyn Dialer>, cache: Cache) -> Self {
        Self {
            dialer,
            cache,
            fetches: Semaphore::new(MAX_CONCURRENT_FETCHES),
            budget: FETCH_BUDGET,
            http_fallback: true,
        }
    }

    /// The same service with another budget (tests).
    #[must_use]
    pub const fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// The same service without the port-80 fallback.
    #[must_use]
    pub const fn without_http_fallback(mut self) -> Self {
        self.http_fallback = false;
        self
    }

    /// The re-encoded PNG icon of `host` (module docs).
    ///
    /// # Errors
    /// [`FaviconError`]: no icon could be fetched or decoded.
    pub async fn icon(&self, host: &IconHost) -> Result<Vec<u8>, FaviconError> {
        for scheme in [Scheme::Https, Scheme::Http] {
            let Some(name) = cache_name(host.as_str(), scheme, scheme.default_port()) else {
                continue;
            };
            if let Some(png) = self.cache.get(&name, MAX_ICON_PNG_LEN).await {
                if png.starts_with(&PNG_SIGNATURE) {
                    return Ok(png);
                }
                self.cache.remove(&name).await;
            }
        }
        let (png, reached) = tokio::time::timeout(self.budget, async {
            let _slot = self
                .fetches
                .acquire()
                .await
                .map_err(|_| FaviconError::Http)?;
            self.walk(host).await
        })
        .await
        .map_err(|_| FaviconError::Timeout)??;
        if let Some(name) = cache_name(host.as_str(), reached.scheme(), reached.port()) {
            // The cache is an optimisation: a failed write still serves the icon.
            let _ = self.cache.put(&name, png.clone()).await;
        }
        Ok(png)
    }

    /// Steps 2–5 of the module docs. Returns the PNG and the request that first reached
    /// `host` (its scheme and port key the cache).
    async fn walk(&self, host: &IconHost) -> Result<(Vec<u8>, Target), FaviconError> {
        let origin = Target::origin(host, Scheme::Https, FAVICON_PATH);
        let chain = self.follow(origin, true, IMAGE_BODY).await?;
        let reached = chain.first;
        if let Answer::Body(_, body) = chain.answer
            && let Ok(png) = decode(body).await
        {
            return Ok((png, reached));
        }
        let page = self
            .follow(reached.with_path("/"), false, PAGE_BODY)
            .await?;
        let Answer::Body(content_type, html) = page.answer else {
            return Err(FaviconError::NoIcon);
        };
        if !content_type.starts_with("text/html") {
            return Err(FaviconError::NoIcon);
        }
        let icon = icon_hrefs(&html)
            .iter()
            .find_map(|href| page.last.resolve(href).ok())
            .ok_or(FaviconError::NoIcon)?;
        if downgrades(&page.last, &icon) {
            return Err(FaviconError::Downgrade);
        }
        let fallback = !(page.last.scheme() == Scheme::Https && page.last.host() == icon.host());
        let chain = self.follow(icon, fallback, IMAGE_BODY).await?;
        match chain.answer {
            Answer::Body(_, body) => Ok((decode(body).await?, reached)),
            Answer::Redirect(_) | Answer::Status => Err(FaviconError::Status),
        }
    }

    /// Requests `target`, following redirects (step 3).
    async fn follow(
        &self,
        target: Target,
        fallback: bool,
        limit: BodyLimit,
    ) -> Result<Chain, FaviconError> {
        let mut current = target;
        let mut fallback = fallback;
        let mut first: Option<Target> = None;
        let mut redirects = 0usize;
        loop {
            let (sent, answer) = self.get(&current, fallback, limit).await?;
            let first_sent = first.get_or_insert_with(|| sent.clone()).clone();
            let Answer::Redirect(location) = answer else {
                return Ok(Chain {
                    first: first_sent,
                    last: sent,
                    answer,
                });
            };
            if redirects >= MAX_REDIRECTS {
                return Err(FaviconError::Redirects);
            }
            redirects += 1;
            let next = sent.resolve(&location).map_err(FaviconError::Location)?;
            if downgrades(&sent, &next) {
                return Err(FaviconError::Downgrade);
            }
            fallback = !(sent.scheme() == Scheme::Https && sent.host() == next.host());
            current = next;
        }
    }

    /// One request (step 2). Returns the request as actually sent and its answer.
    async fn get(
        &self,
        target: &Target,
        fallback: bool,
        limit: BodyLimit,
    ) -> Result<(Target, Answer), FaviconError> {
        let addresses = self.dialer.resolve(target.host()).await?;
        let ip = addresses
            .into_iter()
            .find(|ip| is_allowed(*ip))
            .ok_or(ConnectError::Refused)?;
        let port = target.port();
        if port != HTTPS_PORT && port != HTTP_PORT {
            return Err(ConnectError::Refused.into());
        }
        let (io, sent) = match target.scheme() {
            Scheme::Http => (self.tcp(SocketAddr::new(ip, port)).await?, target.clone()),
            Scheme::Https => match self.tcp(SocketAddr::new(ip, port)).await {
                Ok(tcp) => {
                    let tls =
                        tokio::time::timeout(CONNECT_TIMEOUT, self.dialer.tls(tcp, target.host()))
                            .await
                            .map_err(|_| ConnectError::Tls)??;
                    (tls, target.clone())
                }
                Err(_) if fallback && self.http_fallback && port == HTTPS_PORT => {
                    let plain = target.with_scheme(Scheme::Http, HTTP_PORT);
                    (self.tcp(SocketAddr::new(ip, HTTP_PORT)).await?, plain)
                }
                Err(e) => return Err(e.into()),
            },
        };
        let answer = request(io, &sent, limit).await?;
        Ok((sent, answer))
    }

    /// TCP to exactly `address`, within [`CONNECT_TIMEOUT`].
    async fn tcp(&self, address: SocketAddr) -> Result<BoxIo, ConnectError> {
        tokio::time::timeout(CONNECT_TIMEOUT, self.dialer.tcp(address))
            .await
            .map_err(|_| ConnectError::Connect)?
    }
}

/// Re-encodes `body` on the blocking pool; a panic there is a decode failure.
async fn decode(body: Vec<u8>) -> Result<Vec<u8>, FaviconError> {
    tokio::task::spawn_blocking(move || reencode(&body))
        .await
        .map_err(|_| FaviconError::Decode(DecodeError::Malformed))?
        .map_err(FaviconError::Decode)
}

/// Sends `GET` for `target` over `io` and reads the answer.
async fn request(io: BoxIo, target: &Target, limit: BodyLimit) -> Result<Answer, FaviconError> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| FaviconError::Http)?;
    let driver = tokio::spawn(connection);
    let result = exchange(&mut sender, target, limit).await;
    driver.abort();
    result
}

/// The request and the reading of its answer.
async fn exchange(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    target: &Target,
    limit: BodyLimit,
) -> Result<Answer, FaviconError> {
    let host = HeaderValue::from_str(&target.host_header()).map_err(|_| FaviconError::Http)?;
    let request = Request::builder()
        .method(Method::GET)
        .uri(target.path())
        .header(HOST, host)
        .header(USER_AGENT, HeaderValue::from_static(UPSTREAM_USER_AGENT))
        .header(ACCEPT, HeaderValue::from_static("image/*, text/html;q=0.5"))
        .header(CONNECTION, HeaderValue::from_static("close"))
        .body(Empty::<Bytes>::new())
        .map_err(|_| FaviconError::Http)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| FaviconError::Http)?;
    let status = response.status();
    if matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) {
        let location = response
            .headers()
            .get(LOCATION)
            .ok_or(FaviconError::Status)?
            .to_str()
            .map_err(|_| FaviconError::Location(TargetError::Character))?;
        if location.len() > MAX_REFERENCE_LEN {
            return Err(FaviconError::Location(TargetError::Length));
        }
        return Ok(Answer::Redirect(location.to_owned()));
    }
    if status != StatusCode::OK {
        return Ok(Answer::Status);
    }
    if let Some(encoding) = response.headers().get(CONTENT_ENCODING)
        && !encoding.as_bytes().eq_ignore_ascii_case(b"identity")
    {
        return Err(FaviconError::Encoding);
    }
    let declared = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if !limit.truncate && declared.is_some_and(|n| n > limit.max as u64) {
        return Err(FaviconError::TooLarge);
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= MAX_CONTENT_TYPE_LEN)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let mut body = response.into_body();
    let mut out: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| FaviconError::Http)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let room = limit.max.saturating_sub(out.len());
        if data.len() > room {
            if limit.truncate {
                out.extend_from_slice(data.get(..room).unwrap_or_default());
                break;
            }
            return Err(FaviconError::TooLarge);
        }
        out.extend_from_slice(&data);
    }
    Ok(Answer::Body(content_type, out))
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test assertions index recorded requests; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! The fetch against fake upstreams on local sockets, through a test dialer with its own
    //! name table (no network, no real DNS, no real TLS): discovery, redirects, the allow-list,
    //! the port-80 fallback, limits, hostile images, and the cache.

    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use image::ImageFormat;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::cache::DEFAULT_TTL;
    use crate::connect::{ConnectFuture, ResolveFuture};
    use crate::decode::tests::{encoded, png_claiming};

    const PUBLIC_A: &str = "93.184.216.34";
    const PUBLIC_B: &str = "151.101.1.69";
    const PUBLIC_V6: &str = "2606:4700::6810:84e5";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// One fake server: path to raw response; anything else is a 404.
    type Routes = HashMap<String, Vec<u8>>;

    /// The fake internet: a name table, servers by address and port, and a record of every
    /// step the fetch took.
    #[derive(Default)]
    struct World {
        dns: HashMap<String, Vec<IpAddr>>,
        servers: HashMap<(IpAddr, u16), SocketAddr>,
        tls_fails: Vec<String>,
        log: Mutex<Vec<String>>,
        heads: Arc<Mutex<Vec<String>>>,
    }

    impl World {
        fn name(mut self, host: &str, addresses: &[&str]) -> Self {
            self.dns
                .insert(host.to_owned(), addresses.iter().map(|a| ip(a)).collect());
            self
        }

        async fn serve(mut self, address: &str, port: u16, routes: &[(&str, Vec<u8>)]) -> Self {
            let routes: Routes = routes
                .iter()
                .map(|(p, r)| ((*p).to_owned(), r.clone()))
                .collect();
            let local = server(routes, self.heads.clone()).await;
            self.servers.insert((ip(address), port), local);
            self
        }

        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        fn heads(&self) -> Vec<String> {
            self.heads.lock().unwrap().clone()
        }
    }

    impl Dialer for World {
        fn resolve<'a>(&'a self, host: &'a str) -> ResolveFuture<'a> {
            Box::pin(async move {
                self.log.lock().unwrap().push(format!("resolve {host}"));
                self.dns.get(host).cloned().ok_or(ConnectError::Resolve)
            })
        }

        fn tcp(&self, address: SocketAddr) -> ConnectFuture<'_> {
            Box::pin(async move {
                self.log.lock().unwrap().push(format!("tcp {address}"));
                let local = self
                    .servers
                    .get(&(address.ip(), address.port()))
                    .ok_or(ConnectError::Connect)?;
                let stream = TcpStream::connect(local)
                    .await
                    .map_err(|_| ConnectError::Connect)?;
                Ok(Box::new(stream) as BoxIo)
            })
        }

        fn tls<'a>(&'a self, io: BoxIo, host: &'a str) -> ConnectFuture<'a> {
            Box::pin(async move {
                self.log.lock().unwrap().push(format!("tls {host}"));
                if self.tls_fails.iter().any(|h| h == host) {
                    return Err(ConnectError::Tls);
                }
                Ok(io)
            })
        }
    }

    /// A fake server answering by request path; records every request head.
    async fn server(routes: Routes, heads: Arc<Mutex<Vec<String>>>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let routes = routes.clone();
                let heads = heads.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let mut read = 0;
                    while !buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf[read..]).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => read += n,
                        }
                    }
                    let head = String::from_utf8_lossy(&buf[..read]).into_owned();
                    let path = head.split(' ').nth(1).unwrap_or("").to_owned();
                    heads.lock().unwrap().push(head);
                    let response = routes.get(&path).cloned().unwrap_or_else(|| {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
                    });
                    if response == b"HANG" {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    let _ = socket.write_all(&response).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        addr
    }

    fn ok(content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn redirect(status: u16, location: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status} Moved\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n")
            .into_bytes()
    }

    fn png(width: u32, height: u32) -> Vec<u8> {
        encoded(ImageFormat::Png, width, height)
    }

    fn html(body: &str) -> Vec<u8> {
        ok("text/html; charset=utf-8", body.as_bytes())
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "rizzy-favicon-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn service(world: &Arc<World>, dir: &TempDir) -> FaviconService {
        let cache = Cache::new(dir.0.clone(), DEFAULT_TTL, 1 << 22);
        FaviconService::new(world.clone(), cache)
    }

    fn host(name: &str) -> IconHost {
        IconHost::parse(name).unwrap()
    }

    fn size(png: &[u8]) -> (u32, u32) {
        let image = image::load_from_memory_with_format(png, ImageFormat::Png).unwrap();
        (image.width(), image.height())
    }

    #[tokio::test]
    async fn favicon_ico_over_https_is_reencoded_cached_and_served_from_cache() {
        let ico = encoded(ImageFormat::Ico, 64, 64);
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(PUBLIC_A, 443, &[("/favicon.ico", ok("image/x-icon", &ico))])
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let service = service(&world, &dir);
        let icon = service.icon(&host("example.com")).await.unwrap();
        assert!(icon.starts_with(&PNG_SIGNATURE));
        assert_eq!(size(&icon), (64, 64));
        assert_eq!(
            world.log(),
            [
                "resolve example.com",
                "tcp 93.184.216.34:443",
                "tls example.com"
            ]
        );
        let head = world.heads()[0].to_ascii_lowercase();
        assert!(head.starts_with("get /favicon.ico http/1.1\r\n"), "{head}");
        assert!(head.contains("\r\nhost: example.com\r\n"), "{head}");
        assert!(head.contains("\r\nuser-agent: rizzy-vault\r\n"), "{head}");
        assert!(!head.contains("accept-encoding"), "{head}");
        assert!(!head.contains("cookie"), "{head}");
        assert_eq!(dir.files(), ["example.com-https-443.png"]);
        // Served from the cache: no new step.
        assert_eq!(service.icon(&host("example.com")).await.unwrap(), icon);
        assert_eq!(world.log().len(), 3);
    }

    #[tokio::test]
    async fn large_icons_are_scaled_to_fit_128() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                443,
                &[("/favicon.ico", ok("image/png", &png(600, 300)))],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let icon = service(&world, &dir)
            .icon(&host("example.com"))
            .await
            .unwrap();
        assert_eq!(size(&icon), (128, 64));
    }

    #[tokio::test]
    async fn tcp_failure_on_443_retries_the_same_address_on_80_without_resolving_again() {
        let world = World::default()
            .name("plain.example", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                80,
                &[("/favicon.ico", ok("image/png", &png(16, 16)))],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let icon = service(&world, &dir)
            .icon(&host("plain.example"))
            .await
            .unwrap();
        assert_eq!(size(&icon), (16, 16));
        assert_eq!(
            world.log(),
            [
                "resolve plain.example",
                "tcp 93.184.216.34:443",
                "tcp 93.184.216.34:80"
            ]
        );
        assert_eq!(dir.files(), ["plain.example-http-80.png"]);
        // The http entry is found on the next request.
        let again = service(&world, &dir)
            .icon(&host("plain.example"))
            .await
            .unwrap();
        assert_eq!(again, icon);
        assert_eq!(world.log().len(), 3);
    }

    #[tokio::test]
    async fn tls_failure_never_falls_back_to_http() {
        let mut world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                443,
                &[("/favicon.ico", ok("image/png", &png(16, 16)))],
            )
            .await
            .serve(
                PUBLIC_A,
                80,
                &[("/favicon.ico", ok("image/png", &png(16, 16)))],
            )
            .await;
        world.tls_fails.push("example.com".to_owned());
        let world = Arc::new(world);
        let dir = TempDir::new();
        let got = service(&world, &dir).icon(&host("example.com")).await;
        assert_eq!(got, Err(FaviconError::Connect(ConnectError::Tls)));
        assert!(
            !world.log().iter().any(|l| l.ends_with(":80")),
            "{:?}",
            world.log()
        );
        assert!(dir.files().is_empty());
    }

    #[tokio::test]
    async fn the_http_fallback_can_be_turned_off() {
        let world = World::default()
            .name("plain.example", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                80,
                &[("/favicon.ico", ok("image/png", &png(16, 16)))],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let got = service(&world, &dir)
            .without_http_fallback()
            .icon(&host("plain.example"))
            .await;
        assert_eq!(got, Err(FaviconError::Connect(ConnectError::Connect)));
    }

    #[tokio::test]
    async fn discovery_follows_a_link_to_another_host() {
        let page = r#"<html><head><link rel="icon" type="image/svg+xml" href="/i.svg">
            <link rel="shortcut icon" href="//cdn.example.net/assets/fav.png?v=2&amp;x=1"></head>"#;
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .name("cdn.example.net", &[PUBLIC_B])
            .serve(PUBLIC_A, 443, &[("/", html(page))])
            .await
            .serve(
                PUBLIC_B,
                443,
                &[("/assets/fav.png?v=2&x=1", ok("image/png", &png(32, 32)))],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let icon = service(&world, &dir)
            .icon(&host("example.com"))
            .await
            .unwrap();
        assert_eq!(size(&icon), (32, 32));
        let heads = world.heads();
        assert_eq!(heads.len(), 3);
        assert!(heads[0].starts_with("GET /favicon.ico "));
        assert!(heads[1].starts_with("GET / "));
        assert!(heads[2].starts_with("GET /assets/fav.png?v=2&x=1 "));
        assert!(
            heads[2]
                .to_ascii_lowercase()
                .contains("host: cdn.example.net\r\n")
        );
        assert!(world.log().contains(&"tls cdn.example.net".to_owned()));
        // Keyed by the requested host and the scheme and port that reached it.
        assert_eq!(dir.files(), ["example.com-https-443.png"]);
    }

    #[tokio::test]
    async fn discovery_resolves_a_relative_href_against_the_final_page_request() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .name("www.example.com", &[PUBLIC_B])
            .serve(
                PUBLIC_A,
                443,
                &[("/", redirect(301, "https://www.example.com/home/"))],
            )
            .await
            .serve(
                PUBLIC_B,
                443,
                &[
                    ("/home/", html("<link rel=icon href=img/f.gif>")),
                    (
                        "/home/img/f.gif",
                        ok("image/gif", &encoded(ImageFormat::Gif, 20, 10)),
                    ),
                ],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let icon = service(&world, &dir)
            .icon(&host("example.com"))
            .await
            .unwrap();
        assert_eq!(size(&icon), (20, 10));
    }

    #[tokio::test]
    async fn a_page_that_is_not_html_or_names_no_icon_gives_none() {
        for (page, want) in [
            (
                ok("text/plain", b"<link rel=icon href=/a.png>"),
                FaviconError::NoIcon,
            ),
            (
                html("<link rel=apple-touch-icon href=/a.png>"),
                FaviconError::NoIcon,
            ),
            (html("<link rel=icon href=/only.svg>"), FaviconError::NoIcon),
            (
                html("<link rel=icon href=\"data:image/png;base64,AAAA\">"),
                FaviconError::NoIcon,
            ),
            (
                b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n".to_vec(),
                FaviconError::NoIcon,
            ),
        ] {
            let world = World::default()
                .name("example.com", &[PUBLIC_A])
                .serve(
                    PUBLIC_A,
                    443,
                    &[("/", page), ("/a.png", ok("image/png", &png(8, 8)))],
                )
                .await;
            let world = Arc::new(world);
            let dir = TempDir::new();
            assert_eq!(
                service(&world, &dir).icon(&host("example.com")).await,
                Err(want)
            );
        }
    }

    #[tokio::test]
    async fn redirects_are_followed_up_to_three() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .name("www.example.com", &[PUBLIC_B])
            .serve(
                PUBLIC_A,
                443,
                &[
                    (
                        "/favicon.ico",
                        redirect(301, "https://www.example.com/favicon.ico"),
                    ),
                    ("/x", ok("image/png", &png(8, 8))),
                ],
            )
            .await
            .serve(
                PUBLIC_B,
                443,
                &[
                    ("/favicon.ico", redirect(302, "/a")),
                    ("/a", redirect(307, "https://example.com/x")),
                ],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let icon = service(&world, &dir)
            .icon(&host("example.com"))
            .await
            .unwrap();
        assert_eq!(size(&icon), (8, 8));
        let resolves = world
            .log()
            .iter()
            .filter(|l| l.starts_with("resolve"))
            .count();
        assert_eq!(resolves, 4, "every hop resolves and checks again");
    }

    #[tokio::test]
    async fn a_redirect_loop_ends_with_no_icon() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                443,
                &[
                    ("/favicon.ico", redirect(301, "/a")),
                    ("/a", redirect(301, "/b")),
                    ("/b", redirect(301, "/favicon.ico")),
                ],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let got = service(&world, &dir).icon(&host("example.com")).await;
        assert_eq!(got, Err(FaviconError::Redirects));
        assert_eq!(
            world.heads().len(),
            4,
            "the first request and three redirects"
        );
    }

    #[tokio::test]
    async fn a_scheme_downgrading_redirect_on_the_same_host_is_refused() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                443,
                &[("/favicon.ico", redirect(301, "http://example.com/f.ico"))],
            )
            .await
            .serve(PUBLIC_A, 80, &[("/f.ico", ok("image/png", &png(8, 8)))])
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let got = service(&world, &dir).icon(&host("example.com")).await;
        assert_eq!(got, Err(FaviconError::Downgrade));
        assert!(!world.log().iter().any(|l| l.ends_with(":80")));
    }

    #[tokio::test]
    async fn an_icon_link_downgrading_on_the_same_host_is_refused_but_another_host_is_not() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                443,
                &[("/", html("<link rel=icon href=http://example.com/f.png>"))],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let got = service(&world, &dir).icon(&host("example.com")).await;
        assert_eq!(got, Err(FaviconError::Downgrade));

        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .name("static.example.org", &[PUBLIC_B])
            .serve(
                PUBLIC_A,
                443,
                &[(
                    "/favicon.ico",
                    redirect(302, "http://static.example.org/f.png"),
                )],
            )
            .await
            .serve(PUBLIC_B, 80, &[("/f.png", ok("image/png", &png(8, 8)))])
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        assert!(
            service(&world, &dir)
                .icon(&host("example.com"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn redirects_and_links_to_refused_addresses_are_never_dialled() {
        for private in [
            "127.0.0.1",
            "10.0.0.7",
            "169.254.169.254",
            "::1",
            "::ffff:192.168.1.1",
            "100.64.0.1",
        ] {
            let world = World::default()
                .name("example.com", &[PUBLIC_A])
                .name("internal.example", &[private])
                .serve(
                    PUBLIC_A,
                    443,
                    &[(
                        "/favicon.ico",
                        redirect(302, "https://internal.example/f.png"),
                    )],
                )
                .await
                .serve(private, 443, &[("/f.png", ok("image/png", &png(8, 8)))])
                .await;
            let world = Arc::new(world);
            let dir = TempDir::new();
            let got = service(&world, &dir).icon(&host("example.com")).await;
            assert_eq!(
                got,
                Err(FaviconError::Connect(ConnectError::Refused)),
                "{private}"
            );
            assert!(
                !world
                    .log()
                    .iter()
                    .any(|l| l.starts_with("tcp") && !l.contains(PUBLIC_A)),
                "{private}: {:?}",
                world.log()
            );
        }
        // The requested host itself resolving privately.
        let world = Arc::new(World::default().name("localhost", &["127.0.0.1"]));
        let dir = TempDir::new();
        let got = service(&world, &dir).icon(&host("localhost")).await;
        assert_eq!(got, Err(FaviconError::Connect(ConnectError::Refused)));
        assert_eq!(world.log(), ["resolve localhost"]);
    }

    #[tokio::test]
    async fn the_first_allowed_address_is_the_one_dialled() {
        let world = World::default()
            .name(
                "example.com",
                &["10.0.0.1", "127.0.0.1", PUBLIC_V6, PUBLIC_A],
            )
            .serve(
                PUBLIC_V6,
                443,
                &[("/favicon.ico", ok("image/png", &png(8, 8)))],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        assert!(
            service(&world, &dir)
                .icon(&host("example.com"))
                .await
                .is_ok()
        );
        let tcp: Vec<String> = world
            .log()
            .into_iter()
            .filter(|l| l.starts_with("tcp"))
            .collect();
        assert_eq!(tcp, [format!("tcp [{PUBLIC_V6}]:443")]);
    }

    #[tokio::test]
    async fn redirects_to_other_ports_and_schemes_are_refused() {
        for (location, want) in [
            (
                "https://example.com:8443/f.png",
                FaviconError::Location(TargetError::Port),
            ),
            (
                "http://example.com:22/",
                FaviconError::Location(TargetError::Port),
            ),
            (
                "ftp://example.com/f.png",
                FaviconError::Location(TargetError::Scheme),
            ),
            (
                "file:///etc/passwd",
                FaviconError::Location(TargetError::Scheme),
            ),
            (
                "https://user@example.com/",
                FaviconError::Location(TargetError::Host),
            ),
            ("https://[::1]/", FaviconError::Location(TargetError::Host)),
        ] {
            let world = World::default()
                .name("example.com", &[PUBLIC_A])
                .serve(PUBLIC_A, 443, &[("/favicon.ico", redirect(301, location))])
                .await;
            let world = Arc::new(world);
            let dir = TempDir::new();
            assert_eq!(
                service(&world, &dir).icon(&host("example.com")).await,
                Err(want),
                "{location}"
            );
        }
    }

    #[tokio::test]
    async fn size_and_encoding_limits() {
        let declared =
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 3000000\r\n\r\n"
                .to_vec();
        let mut chunked =
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        for _ in 0..40 {
            chunked.extend_from_slice(b"10000\r\n");
            chunked.extend_from_slice(&vec![0u8; 0x10000]);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");
        let gzip = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nabcd".to_vec();
        for (response, want) in [
            (declared, FaviconError::TooLarge),
            (chunked, FaviconError::TooLarge),
            (gzip, FaviconError::Encoding),
        ] {
            let world = World::default()
                .name("example.com", &[PUBLIC_A])
                .serve(PUBLIC_A, 443, &[("/favicon.ico", response)])
                .await;
            let world = Arc::new(world);
            let dir = TempDir::new();
            assert_eq!(
                service(&world, &dir).icon(&host("example.com")).await,
                Err(want)
            );
        }
    }

    #[tokio::test]
    async fn a_huge_page_is_cut_at_the_scan_limit() {
        let mut page = " ".repeat(MAX_HTML_SCAN);
        page.push_str("<link rel=icon href=/late.png>");
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                443,
                &[
                    ("/", html(&page)),
                    ("/late.png", ok("image/png", &png(8, 8))),
                ],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        assert_eq!(
            service(&world, &dir).icon(&host("example.com")).await,
            Err(FaviconError::NoIcon)
        );
    }

    #[tokio::test]
    async fn hostile_images_give_no_icon_and_nothing_is_cached() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
        for body in [
            png_claiming(100_000, 100_000),
            png_claiming(4096, 4096),
            svg.to_vec(),
            b"GIF89a\xff\xff\xff\xff".to_vec(),
            vec![0xAB; 5000],
            png(64, 64)[..100].to_vec(),
        ] {
            let world = World::default()
                .name("example.com", &[PUBLIC_A])
                .serve(
                    PUBLIC_A,
                    443,
                    &[
                        ("/favicon.ico", ok("image/x-icon", &body)),
                        ("/", html("<link rel=icon href=/icon.png>")),
                        ("/icon.png", ok("image/png", &body)),
                    ],
                )
                .await;
            let world = Arc::new(world);
            let dir = TempDir::new();
            let got = service(&world, &dir).icon(&host("example.com")).await;
            assert!(matches!(got, Err(FaviconError::Decode(_))), "{got:?}");
            assert!(dir.files().is_empty());
        }
    }

    #[tokio::test]
    async fn the_whole_fetch_has_a_budget() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(PUBLIC_A, 443, &[("/favicon.ico", b"HANG".to_vec())])
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        let started = std::time::Instant::now();
        let got = service(&world, &dir)
            .with_budget(Duration::from_millis(300))
            .icon(&host("example.com"))
            .await;
        assert_eq!(got, Err(FaviconError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn an_unresolvable_host_gives_no_icon() {
        let world = Arc::new(World::default());
        let dir = TempDir::new();
        assert_eq!(
            service(&world, &dir).icon(&host("nowhere.example")).await,
            Err(FaviconError::Connect(ConnectError::Resolve))
        );
    }

    #[tokio::test]
    async fn a_corrupt_cache_entry_is_dropped_and_refetched() {
        let world = World::default()
            .name("example.com", &[PUBLIC_A])
            .serve(
                PUBLIC_A,
                443,
                &[("/favicon.ico", ok("image/png", &png(8, 8)))],
            )
            .await;
        let world = Arc::new(world);
        let dir = TempDir::new();
        std::fs::write(dir.0.join("example.com-https-443.png"), b"<svg/>").unwrap();
        let icon = service(&world, &dir)
            .icon(&host("example.com"))
            .await
            .unwrap();
        assert!(icon.starts_with(&PNG_SIGNATURE));
        assert_eq!(
            std::fs::read(dir.0.join("example.com-https-443.png")).unwrap(),
            icon
        );
    }

    #[test]
    fn cache_names_follow_the_adr_and_fit_a_file_name() {
        assert_eq!(
            cache_name("example.com", Scheme::Https, 443).as_deref(),
            Some("example.com-https-443.png")
        );
        assert_eq!(
            cache_name("example.com", Scheme::Http, 80).as_deref(),
            Some("example.com-http-80.png")
        );
        let label = "a".repeat(60);
        let long = [label.as_str(); 4].join(".");
        assert!(cache_name(&long, Scheme::Https, 443).is_none());
        assert!(crate::cache::valid_name(
            &cache_name("a.b", Scheme::Https, 443).unwrap()
        ));
    }

    #[test]
    fn errors_carry_no_host() {
        for e in [
            FaviconError::Connect(ConnectError::Refused),
            FaviconError::Location(TargetError::Port),
            FaviconError::Decode(DecodeError::Limits),
            FaviconError::Timeout,
        ] {
            let text = format!("{e} {e:?}");
            assert!(!text.contains('.'), "{text}");
        }
    }
}
