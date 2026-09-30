//! The HTTP transport of `rv`: the `/api/v1` conventions of [ADR 0028] over hyper's HTTP/1.1
//! client connection (ADR 0013 §2: "HTTP transport … Rust HTTP client, rustls").
//!
//! **TLS is held in this build.** ADR 0009 puts "any other … TLS crate on the client side"
//! under its approval procedure, and no Accepted ADR admits the crates an `https://` dial
//! needs (`tokio-rustls` with a crypto provider, a root set) or decides the protocol versions.
//! Until the owner approves them, an `https://` origin is refused with
//! [`CliError::TlsUnavailable`] before anything is sent, and only loopback `http://` is
//! dialled (reported; CLAUDE.md "The ADR gate").
//!
//! # What it sends (ADR 0028)
//!
//! - **Origin-form targets only**, the literal paths of `rizzy_proto::http::paths`, no query
//!   (item 1, item 5 "Signed bytes"). The path string that is signed is the path string that
//!   is sent; nothing parses, normalises or re-encodes it in between.
//! - `POST` with a JSON body, or an empty body for the body-less endpoints; `GET` only for
//!   `devices/grants` (item 1).
//! - `Rizzy-Client: cli/<version>` on every request (item 14).
//! - `Authorization: Bearer <43 base64url characters>` on a session request (item 4); on a
//!   device session also `Rizzy-Request-Counter` and `Rizzy-Request-Signature`, from
//!   [`DeviceSession::sign_request`] over the method, the path and the exact body bytes
//!   (item 5). Counters start at 1, grow by 1 and are never reused; a retry signs again with
//!   a fresh counter.
//!
//! # What it accepts
//!
//! - `200` with a JSON body of at most [`MAX_RESPONSE_LEN`] bytes, or `204` (item 2).
//! - Any other status is read as `{"error":"<code>"}` (item 3): the **code** decides, never
//!   the status, and an unknown code reads as `unknown`. A `429` keeps its `Retry-After`.
//! - Nothing else: a redirect is not followed, a body over the cap is refused.
//!
//! # Which origins it dials
//!
//! `http://` only to `localhost` or a loopback address, where the listener is the operator's
//! own reverse-proxy hop or a test server ([`CliError::InsecureOrigin`] otherwise: tokens and
//! signed requests never travel in clear to another host). An `https://` origin is parsed and
//! refused ([`CliError::TlsUnavailable`], above).
//!
//! # Secrets
//!
//! The bearer token's text lives in a zeroizing buffer until the request is handed to hyper,
//! and no header value, body or answer is ever logged or put into an error (INV-52, INV-56).
//!
//! # Connections
//!
//! One connection per request (`Connection: close`). An unlock and a sync are a handful of
//! requests, and a connection kept open across a password prompt would outlive the server's
//! 10 s idle timeout anyway (ADR 0028 item 9).
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use std::net::IpAddr;
use std::time::Duration;

use http_body_util::{BodyExt as _, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue, RETRY_AFTER,
};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::rizzy_proto::error::{ErrorCode, ErrorResponse};
use rizzy_client::rizzy_proto::http::{
    BEARER_SCHEME, REQUEST_COUNTER_HEADER, REQUEST_SIGNATURE_HEADER,
};
use rizzy_client::rizzy_proto::limits::MAX_UPLOAD_BODY_LEN;
use rizzy_client::rizzy_proto::meta::CLIENT_HEADER;
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::session::DeviceSession;
use rizzy_core::normalize::{Scheme, ServerOrigin};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::error::CliError;

/// The most bytes of a response body this client reads: the largest body `v1` sizes anything
/// for (ADR 0028 item 7, `MAX_UPLOAD_BODY_LEN`).
pub const MAX_RESPONSE_LEN: usize = MAX_UPLOAD_BODY_LEN;

/// The most bytes of an error body (ADR 0028 item 3: `{"error":"<code>"}`).
const MAX_ERROR_BODY_LEN: usize = 4096;

/// How long a TCP connect may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The fixed part of a request's deadline; the body adds its size over 64 KiB/s, the rate the
/// server's read deadline assumes (ADR 0028 item 8).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The value of the `Rizzy-Client` header (ADR 0028 item 14).
const CLIENT: &str = concat!("cli/", env!("CARGO_PKG_VERSION"));

/// How a request authenticates (ADR 0028 items 4–5).
#[derive(Debug)]
pub enum Auth<'a> {
    /// No session.
    None,
    /// A bearer token alone: an OPAQUE or recovery session.
    Bearer(&'a SessionToken),
    /// A device session: the bearer token and the `device-request` signature.
    Device(&'a mut DeviceSession, &'a UnlockedDevice),
}

/// A response: the status and the collected body.
#[derive(Debug)]
struct Reply {
    /// The status.
    status: StatusCode,
    /// The body, at most the cap the caller set.
    body: Vec<u8>,
    /// `Retry-After` in whole seconds, if the response carried a valid one.
    retry_after: Option<u64>,
}

/// The transport to one server origin.
pub struct Http {
    /// The canonical origin (CRYPTO.md §2): what device requests are signed for.
    origin: ServerOrigin,
    /// The host to connect to, without brackets.
    host: String,
    /// The port.
    port: u16,
    /// The `Host` header: the origin's authority.
    authority: HeaderValue,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// Splits a canonical origin's authority into host (brackets removed) and explicit port.
fn host_and_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
        None => Some((authority, None)),
    }
}

/// Whether `host` is `localhost` or a loopback address.
fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Http {
    /// The transport for `origin`, a server URL as the user typed it or as the device state
    /// holds it.
    ///
    /// # Errors
    /// [`CliError::BadInput`] for a URL that is no origin; [`CliError::InsecureOrigin`] for an
    /// `http://` origin that is not loopback; [`CliError::TlsUnavailable`] for an `https://`
    /// origin (module docs).
    pub fn new(origin: &str) -> Result<Self, CliError> {
        let bad = CliError::BadInput("the server address is not a valid https:// origin");
        let origin = ServerOrigin::parse(origin).map_err(|_| bad)?;
        let bad = || CliError::BadInput("the server address is not a valid https:// origin");
        let (_, authority) = origin.as_str().split_once("://").ok_or_else(bad)?;
        let (host, port) = host_and_port(authority).ok_or_else(bad)?;
        let scheme = origin.scheme();
        match scheme {
            Scheme::Https => return Err(CliError::TlsUnavailable),
            Scheme::Http if is_loopback(host) => {}
            Scheme::Http => return Err(CliError::InsecureOrigin),
        }
        Ok(Self {
            host: host.to_owned(),
            port: port.unwrap_or_else(|| scheme.default_port()),
            authority: HeaderValue::from_str(authority).map_err(|_| bad())?,
            origin,
        })
    }

    /// The canonical origin this transport dials.
    #[must_use]
    pub const fn origin(&self) -> &ServerOrigin {
        &self.origin
    }

    /// `POST path` with `value` as its JSON body; the answer is `200` with a JSON `R`.
    ///
    /// # Errors
    /// [`CliError::Server`] for an error answer; [`CliError::RateLimited`];
    /// [`CliError::BadAnswer`]; [`CliError::Network`].
    pub async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &'static str,
        value: &T,
        auth: Auth<'_>,
    ) -> Result<R, CliError> {
        let body = serde_json::to_vec(value).map_err(|_| CliError::BadAnswer)?;
        self.json(Method::POST, path, body, auth).await
    }

    /// `POST path` with `value` as its JSON body; the answer is the empty success (`204`).
    ///
    /// # Errors
    /// As [`Http::post`].
    pub async fn post_empty<T: Serialize>(
        &self,
        path: &'static str,
        value: &T,
        auth: Auth<'_>,
    ) -> Result<(), CliError> {
        let body = serde_json::to_vec(value).map_err(|_| CliError::BadAnswer)?;
        self.post_bytes_empty(path, body, auth).await
    }

    /// `POST path` with `body`, the exact bytes of a JSON body built earlier (a stored
    /// commit, resent byte for byte); the answer is the empty success.
    ///
    /// # Errors
    /// As [`Http::post`].
    pub async fn post_bytes_empty(
        &self,
        path: &'static str,
        body: Vec<u8>,
        auth: Auth<'_>,
    ) -> Result<(), CliError> {
        let reply = self
            .send(Method::POST, path, body, auth, MAX_ERROR_BODY_LEN)
            .await?;
        match reply.status {
            StatusCode::NO_CONTENT => Ok(()),
            // A success that is not the empty one is not this endpoint's answer.
            StatusCode::OK => Err(CliError::BadAnswer),
            _ => Err(error_of(&reply)),
        }
    }

    /// `POST path` with an empty body; the answer is `200` with a JSON `R`.
    ///
    /// # Errors
    /// As [`Http::post`].
    pub async fn post_no_body<R: DeserializeOwned>(
        &self,
        path: &'static str,
        auth: Auth<'_>,
    ) -> Result<R, CliError> {
        self.json(Method::POST, path, Vec::new(), auth).await
    }

    /// `GET path`; the answer is `200` with a JSON `R`.
    ///
    /// # Errors
    /// As [`Http::post`].
    pub async fn get<R: DeserializeOwned>(
        &self,
        path: &'static str,
        auth: Auth<'_>,
    ) -> Result<R, CliError> {
        self.json(Method::GET, path, Vec::new(), auth).await
    }

    /// Sends a request whose success is `200` with JSON.
    async fn json<R: DeserializeOwned>(
        &self,
        method: Method,
        path: &'static str,
        body: Vec<u8>,
        auth: Auth<'_>,
    ) -> Result<R, CliError> {
        let reply = self
            .send(method, path, body, auth, MAX_RESPONSE_LEN)
            .await?;
        if reply.status != StatusCode::OK {
            return Err(error_of(&reply));
        }
        serde_json::from_slice(&reply.body).map_err(|_| CliError::BadAnswer)
    }

    /// Builds, signs and sends one request, and collects the answer up to `max_body` bytes.
    async fn send(
        &self,
        method: Method,
        path: &'static str,
        body: Vec<u8>,
        auth: Auth<'_>,
        max_body: usize,
    ) -> Result<Reply, CliError> {
        let mut request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(HOST, self.authority.clone())
            .header(CONNECTION, "close")
            .header(CLIENT_HEADER, CLIENT)
            .header(CONTENT_LENGTH, body.len());
        if !body.is_empty() {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        match auth {
            Auth::None => {}
            Auth::Bearer(token) => request = request.header(AUTHORIZATION, bearer(token)?),
            Auth::Device(session, unlocked) => {
                // The path signed is the path sent, byte for byte (ADR 0028 item 5).
                let signature = session.sign_request(unlocked, method.as_str(), path, &body)?;
                request = request
                    .header(AUTHORIZATION, bearer(session.bearer_token())?)
                    .header(REQUEST_COUNTER_HEADER, signature.request_counter)
                    .header(REQUEST_SIGNATURE_HEADER, signature.signature.to_b64url());
            }
        }
        let deadline = REQUEST_TIMEOUT
            + Duration::from_secs(u64::try_from(body.len() / (64 * 1024)).unwrap_or(u64::MAX));
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| CliError::Network)?;
        let exchange = async {
            let tcp = tokio::time::timeout(
                CONNECT_TIMEOUT,
                TcpStream::connect((self.host.as_str(), self.port)),
            )
            .await
            .map_err(|_| CliError::Network)?
            .map_err(|_| CliError::Network)?;
            // A request is small writes and one read: no reason to wait for more bytes.
            let _ = tcp.set_nodelay(true);
            exchange(tcp, request, max_body).await
        };
        tokio::time::timeout(deadline, exchange)
            .await
            .map_err(|_| CliError::Network)?
    }
}

/// The `Authorization` header value of a bearer token, marked sensitive so hyper never prints
/// it in a `Debug` of the request. The token text is wiped when the buffer drops.
fn bearer(token: &SessionToken) -> Result<HeaderValue, CliError> {
    let text = token.to_b64url();
    let mut line = Zeroizing::new(String::with_capacity(BEARER_SCHEME.len() + 1 + text.len()));
    line.push_str(BEARER_SCHEME);
    line.push(' ');
    line.push_str(&text);
    let mut value = HeaderValue::from_str(&line).map_err(|_| CliError::Network)?;
    value.set_sensitive(true);
    Ok(value)
}

/// The error of a response that is not the success its endpoint gives (ADR 0028 item 3): the
/// code of its `{"error":…}` body, or "not an API answer".
fn error_of(reply: &Reply) -> CliError {
    if reply.status.is_success() || reply.body.len() > MAX_ERROR_BODY_LEN {
        return CliError::BadAnswer;
    }
    match serde_json::from_slice::<ErrorResponse>(&reply.body) {
        Ok(answer) if answer.error == ErrorCode::RateLimited => {
            CliError::RateLimited(reply.retry_after)
        }
        Ok(answer) => CliError::Server(answer.error),
        Err(_) => CliError::BadAnswer,
    }
}

/// One request over one connection: the HTTP/1.1 handshake, the request, the answer's body up
/// to `max_body` bytes.
async fn exchange(
    stream: TcpStream,
    request: Request<Full<Bytes>>,
    max_body: usize,
) -> Result<Reply, CliError> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| CliError::Network)?;
    // The connection task moves the bytes; it ends with the connection. Its error, if any,
    // shows as the request's error below.
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| CliError::Network);
    let reply = async {
        let response = response?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        // An error body is small whatever the endpoint's success size is.
        let limit = if status == StatusCode::OK {
            max_body
        } else {
            max_body.min(MAX_ERROR_BODY_LEN)
        };
        let body = Limited::new(response.into_body(), limit)
            .collect()
            .await
            // A body over the cap is no API answer. A read that fails for any other reason
            // (the connection broke mid-answer) is an answer that never arrived: the outcome
            // of the request is unknown (ADR 0028 "Retry after an unknown outcome").
            .map_err(|e| {
                if e.downcast_ref::<LengthLimitError>().is_some() {
                    CliError::BadAnswer
                } else {
                    CliError::Network
                }
            })?
            .to_bytes()
            .to_vec();
        Ok(Reply {
            status,
            body,
            retry_after,
        })
    }
    .await;
    driver.abort();
    reply
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_split_and_insecure_ones_refused() {
        assert_eq!(
            host_and_port("vault.example.com"),
            Some(("vault.example.com", None))
        );
        assert_eq!(
            host_and_port("127.0.0.1:8080"),
            Some(("127.0.0.1", Some(8080)))
        );
        assert_eq!(host_and_port("[::1]:8443"), Some(("::1", Some(8443))));
        assert_eq!(host_and_port("[::1]"), Some(("::1", None)));
        assert_eq!(host_and_port("[::1]x"), None);
        assert!(is_loopback("localhost") && is_loopback("127.0.0.1") && is_loopback("::1"));
        assert!(!is_loopback("vault.example.com") && !is_loopback("192.0.2.1"));

        let local = Http::new("http://127.0.0.1:18080/").unwrap();
        assert_eq!(local.origin().as_str(), "http://127.0.0.1:18080");
        assert_eq!((local.host.as_str(), local.port), ("127.0.0.1", 18080));
        assert!(matches!(
            Http::new("http://vault.example.com"),
            Err(CliError::InsecureOrigin)
        ));
        // TLS is held until its crates are approved (module docs): refused, never dialled.
        assert!(matches!(
            Http::new("HTTPS://Vault.Example.com:443"),
            Err(CliError::TlsUnavailable)
        ));
        assert!(matches!(Http::new("ftp://x"), Err(CliError::BadInput(_))));
        assert_eq!(CLIENT, concat!("cli/", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn error_answers_are_read_by_their_code() {
        let reply = |status: u16, body: &str, retry_after| Reply {
            status: StatusCode::from_u16(status).unwrap(),
            body: body.as_bytes().to_vec(),
            retry_after,
        };
        assert!(matches!(
            error_of(&reply(409, r#"{"error":"state_conflict"}"#, None)),
            CliError::Server(ErrorCode::StateConflict)
        ));
        // The code decides, not the status; an unknown code reads as `unknown`.
        assert!(matches!(
            error_of(&reply(500, r#"{"error":"stale_epoch"}"#, None)),
            CliError::Server(ErrorCode::StaleEpoch)
        ));
        assert!(matches!(
            error_of(&reply(418, r#"{"error":"teapot"}"#, None)),
            CliError::Server(ErrorCode::Unknown)
        ));
        assert!(matches!(
            error_of(&reply(429, r#"{"error":"rate_limited"}"#, Some(7))),
            CliError::RateLimited(Some(7))
        ));
        assert!(matches!(
            error_of(&reply(502, "<html>", None)),
            CliError::BadAnswer
        ));
        assert!(matches!(
            error_of(&reply(200, "{}", None)),
            CliError::BadAnswer
        ));
    }

    #[test]
    fn the_bearer_header_is_sensitive() {
        let token = SessionToken::new(Zeroizing::new([7u8; 32]));
        let value = bearer(&token).unwrap();
        assert!(value.is_sensitive());
        assert_eq!(value.len(), "Bearer ".len() + 43);
        assert!(!format!("{value:?}").contains(token.to_b64url().as_str()));
    }
}
