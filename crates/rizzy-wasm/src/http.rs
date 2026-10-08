//! The `/api/v1` conventions of [ADR 0028] on the Rust side of a JavaScript `fetch` (ADR 0013
//! §2: "Transport … stays in the host").
//!
//! Rust builds every request completely: method, path, the JSON body and the values of the
//! headers. JavaScript sends it as it is and hands back the status and the body bytes. Nothing
//! in JavaScript builds or parses an API body (ADR 0013 §3 rule 5: hosts "never parse" what
//! they carry).
//!
//! # What a request carries ([`HttpRequest`])
//!
//! - **Origin-form paths only**, the literal constants of `rizzy_proto::http::paths` (item 1),
//!   which the host appends to the session's origin. No query, no fragment.
//! - `POST` with a JSON body, or an empty body for the body-less endpoints; `GET` only for
//!   `GET /api/meta` here (item 1, item 14).
//! - `Content-Type: application/json` when there is a body ([`HttpRequest::content_type`]).
//! - `Rizzy-Client: web/<version>` on every request (item 14; [`HttpRequest::client`]).
//! - `Authorization: Bearer <43 base64url characters>` on a session request (item 4;
//!   [`HttpRequest::authorization`]). The web vault holds only OPAQUE sessions, which are
//!   bearer sessions: it never signs requests (item 5 applies to device sessions only).
//!
//! The host must not follow redirects (`redirect: "error"`), must send no cookies
//! (`credentials: "omit"`) and must not cache (`cache: "no-store"`); `packages/core` does all
//! three.
//!
//! # What a response may be (items 2–3)
//!
//! - `200` with a JSON body of at most [`MAX_RESPONSE_LEN`] bytes, parsed into the endpoint's
//!   `rizzy-proto` type (unknown fields are tolerated where the type says so);
//! - `204` with no body, for the "empty success" endpoints;
//! - anything else is read as `{"error":"<code>"}` of at most [`MAX_ERROR_BODY_LEN`] bytes:
//!   the **code** decides, never the status. A body that is not that is
//!   `invalid_server_response`.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use core::fmt;

use rizzy_client::ClientError;
use rizzy_client::device::UnlockedDevice;
use rizzy_client::rizzy_proto::error::{ErrorCode, ErrorResponse};
use rizzy_client::rizzy_proto::http::BEARER_SCHEME;
use rizzy_client::rizzy_proto::limits::MAX_UPLOAD_BODY_LEN;
use rizzy_client::rizzy_proto::meta::{API_V1, CLIENT_HEADER, META_PATH, MetaResponse};
use rizzy_client::rizzy_proto::wire::SessionToken;
use rizzy_client::session::DeviceSession as ClientDeviceSession;
use serde::Serialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult, RESPONSE_TOO_LARGE};

/// The most bytes of a success body this client reads: the largest body `v1` sizes anything
/// for (ADR 0028 item 7, `MAX_UPLOAD_BODY_LEN`), as `rv` does.
pub const MAX_RESPONSE_LEN: usize = MAX_UPLOAD_BODY_LEN;

/// The most bytes of an error body read: `{"error":"<code>"}` is far smaller.
pub const MAX_ERROR_BODY_LEN: usize = 4096;

/// The value of the `Rizzy-Client` header (ADR 0028 item 14): platform `web`.
pub const CLIENT: &str = concat!("web/", env!("CARGO_PKG_VERSION"));

/// One request for the host to send (module docs). The body and the bearer token are wiped
/// when the object is freed; `Debug` shows the method and path only.
#[wasm_bindgen]
pub struct HttpRequest {
    /// `POST` or `GET`.
    method: &'static str,
    /// The origin-form path.
    path: &'static str,
    /// The JSON body; `None` for an empty body.
    body: Option<Zeroizing<Vec<u8>>>,
    /// The `Authorization` header value, if the request needs a session.
    authorization: Option<Zeroizing<String>>,
    /// The `Rizzy-Request-Counter` header value, for a device-authenticated session's signed
    /// request (ADR 0028 item 5). `Some` exactly when [`HttpRequest::request_signature`] is.
    request_counter: Option<u64>,
    /// The `Rizzy-Request-Signature` header value, base64url (ADR 0028 item 5).
    request_signature: Option<Zeroizing<String>>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[wasm_bindgen]
impl HttpRequest {
    /// The method: `POST`, or `GET` for `GET /api/meta`.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn method(&self) -> String {
        self.method.to_owned()
    }

    /// The origin-form path, to append to the server origin as it is.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn path(&self) -> String {
        self.path.to_owned()
    }

    /// The body bytes, or `undefined` for an empty body. A copy: the host sends it and drops
    /// it.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn body(&self) -> Option<Vec<u8>> {
        self.body.as_ref().map(|b| b.to_vec())
    }

    /// `application/json` when there is a body, else `undefined`.
    #[wasm_bindgen(getter, js_name = contentType)]
    #[must_use]
    pub fn content_type(&self) -> Option<String> {
        self.body.as_ref().map(|_| "application/json".to_owned())
    }

    /// The `Authorization` header value (`Bearer <token>`), or `undefined`. A secret: never log
    /// it, never put it anywhere but this header (INV-52).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn authorization(&self) -> Option<String> {
        self.authorization.as_ref().map(|a| a.as_str().to_owned())
    }

    /// The `Rizzy-Request-Counter` header value, or `undefined` for a request that is not
    /// signed with a device key (ADR 0028 item 5; CRYPTO.md §5.10). Present exactly when
    /// [`HttpRequest::request_signature`] is.
    #[wasm_bindgen(getter, js_name = requestCounter)]
    #[must_use]
    pub fn request_counter(&self) -> Option<u64> {
        self.request_counter
    }

    /// The `Rizzy-Request-Signature` header value, base64url, or `undefined` (module docs,
    /// [`HttpRequest::request_counter`]).
    #[wasm_bindgen(getter, js_name = requestSignature)]
    #[must_use]
    pub fn request_signature(&self) -> Option<String> {
        self.request_signature
            .as_ref()
            .map(|s| s.as_str().to_owned())
    }

    /// The `Rizzy-Client` header value.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn client(&self) -> String {
        CLIENT.to_owned()
    }

    /// The name of the client header, `Rizzy-Client`.
    #[wasm_bindgen(js_name = clientHeaderName)]
    #[must_use]
    pub fn client_header_name() -> String {
        CLIENT_HEADER.to_owned()
    }
}

impl HttpRequest {
    /// A `POST` of `body` as JSON to `path`, with the bearer token of `session` if given.
    ///
    /// # Errors
    /// `internal` if the body does not serialise (a typed request always does).
    pub(crate) fn post<T: Serialize>(
        path: &'static str,
        body: &T,
        session: Option<&SessionToken>,
    ) -> CoreResult<Self> {
        let json = serde_json::to_vec(body).map_err(|_| CoreError::from(ClientError::Internal))?;
        Ok(Self {
            method: "POST",
            path,
            body: Some(Zeroizing::new(json)),
            authorization: session.map(bearer),
            request_counter: None,
            request_signature: None,
        })
    }

    /// A `POST` with an empty body (ADR 0028 item 2).
    pub(crate) fn post_empty(path: &'static str, session: Option<&SessionToken>) -> Self {
        Self {
            method: "POST",
            path,
            body: None,
            authorization: session.map(bearer),
            request_counter: None,
            request_signature: None,
        }
    }

    /// A `POST` of `body` as JSON to `path`, signed with `session`'s device key (CRYPTO.md
    /// §5.10 "Request signing"; ADR 0028 item 5): the bearer token and both signature headers,
    /// never a bearer-only request. The path signed is `path` itself, byte for byte, as sent
    /// (as [`crate::device::DeviceSession::sign_request`]'s module docs and `rv`'s
    /// `Auth::Device` already do for a native device).
    ///
    /// # Errors
    /// `internal` if the body does not serialise; as
    /// [`rizzy_client::session::DeviceSession::sign_request`].
    pub(crate) fn post_signed<T: Serialize>(
        path: &'static str,
        body: &T,
        session: &mut ClientDeviceSession,
        unlocked: &UnlockedDevice,
    ) -> CoreResult<Self> {
        let json = serde_json::to_vec(body).map_err(|_| CoreError::from(ClientError::Internal))?;
        let signature = session
            .sign_request(unlocked, "POST", path, &json)
            .map_err(CoreError::from)?;
        Ok(Self {
            method: "POST",
            path,
            body: Some(Zeroizing::new(json)),
            authorization: Some(bearer(session.bearer_token())),
            request_counter: Some(signature.request_counter),
            request_signature: Some(Zeroizing::new(signature.signature.to_b64url())),
        })
    }

    /// A copy, for a host that sends the same request again after an unknown outcome (ADR 0028
    /// "Retry after an unknown outcome"). A signed request is never re-signed: the same
    /// counter and signature go out again, exactly as sent, since the device key would
    /// otherwise have to sign the same method, path and body twice under two counters.
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            method: self.method,
            path: self.path,
            body: self.body.as_ref().map(|b| Zeroizing::new(b.to_vec())),
            authorization: self
                .authorization
                .as_ref()
                .map(|a| Zeroizing::new(a.as_str().to_owned())),
            request_counter: self.request_counter,
            request_signature: self
                .request_signature
                .as_ref()
                .map(|s| Zeroizing::new(s.as_str().to_owned())),
        }
    }

    /// The path, for the tests and the flows' bookkeeping.
    #[must_use]
    pub const fn path_str(&self) -> &'static str {
        self.path
    }

    /// The body bytes, for the tests.
    #[must_use]
    pub fn body_bytes(&self) -> Option<&[u8]> {
        self.body.as_ref().map(|b| b.as_slice())
    }
}

/// `Bearer <token>` in a zeroizing buffer.
fn bearer(token: &SessionToken) -> Zeroizing<String> {
    let text = token.to_b64url();
    let mut line = Zeroizing::new(String::with_capacity(BEARER_SCHEME.len() + 1 + text.len()));
    line.push_str(BEARER_SCHEME);
    line.push(' ');
    line.push_str(&text);
    line
}

/// The error of a response that is not the success its endpoint gives (module docs).
fn error_of(status: u16, body: &[u8]) -> CoreError {
    if (200..300).contains(&status) || body.len() > MAX_ERROR_BODY_LEN {
        return ClientError::InvalidServerResponse.into();
    }
    match serde_json::from_slice::<ErrorResponse>(body) {
        Ok(answer) => CoreError::server(answer.error),
        Err(_) => ClientError::InvalidServerResponse.into(),
    }
}

/// Reads a `200` answer with a JSON body of type `T`.
///
/// # Errors
/// The server's code for an error answer; `response_too_large`; `invalid_server_response` for
/// any other status or a body that does not parse.
pub(crate) fn json<T: DeserializeOwned>(status: u16, body: &[u8]) -> CoreResult<T> {
    if status != 200 {
        return Err(error_of(status, body));
    }
    if body.len() > MAX_RESPONSE_LEN {
        return Err(CoreError::new(RESPONSE_TOO_LARGE));
    }
    serde_json::from_slice(body).map_err(|_| ClientError::InvalidServerResponse.into())
}

/// Reads an empty success (`204`; ADR 0028 item 2).
///
/// # Errors
/// As [`json`].
pub(crate) fn empty(status: u16, body: &[u8]) -> CoreResult<()> {
    if status == 204 && body.is_empty() {
        Ok(())
    } else {
        Err(error_of(status, body))
    }
}

/// The server's error code, if the answer is an `/api/v1` error answer.
pub(crate) fn server_code(status: u16, body: &[u8]) -> Option<ErrorCode> {
    if (200..300).contains(&status) || body.len() > MAX_ERROR_BODY_LEN {
        return None;
    }
    serde_json::from_slice::<ErrorResponse>(body)
        .ok()
        .map(|a| a.error)
}

/// `GET /api/meta` (ADR 0028 item 14): what the host asks before anything secret is typed.
#[wasm_bindgen(js_name = metaRequest)]
#[must_use]
pub fn meta_request() -> HttpRequest {
    HttpRequest {
        method: "GET",
        path: META_PATH,
        body: None,
        authorization: None,
        request_counter: None,
        request_signature: None,
    }
}

/// Whether the answer to [`meta_request`] says the server speaks `v1`, as `rv` checks before
/// a login or signup.
///
/// # Errors
/// The server's code; `invalid_server_response`; `server_api_version_gone` when `v1` is not
/// listed.
#[wasm_bindgen(js_name = checkMeta)]
pub fn check_meta(status: u16, body: &[u8]) -> Result<(), CoreError> {
    let meta: MetaResponse = json(status, body)?;
    if meta.api_versions.iter().any(|v| v.as_str() == API_V1) {
        Ok(())
    } else {
        Err(CoreError::server(ErrorCode::ApiVersionGone))
    }
}

/// Reads an answer that has an empty success (`204`), for the single calls of
/// [`crate::Session`] whose answer carries nothing (2FA confirmation and removal).
///
/// # Errors
/// The server's code for an error answer; `invalid_server_response` for anything but a `204`
/// with an empty body.
#[wasm_bindgen(js_name = expectNoContent)]
pub fn expect_no_content(status: u16, body: &[u8]) -> Result<(), CoreError> {
    empty(status, body)
}

#[cfg(test)]
mod tests {
    use rizzy_client::rizzy_proto::http::paths;

    use super::*;

    #[test]
    fn answers_are_read_by_their_code() {
        assert_eq!(
            empty(429, br#"{"error":"rate_limited"}"#)
                .unwrap_err()
                .as_str(),
            "server_rate_limited"
        );
        assert_eq!(
            empty(409, br#"{"error":"something_new"}"#)
                .unwrap_err()
                .as_str(),
            "server_unknown"
        );
        assert_eq!(
            empty(502, b"<html>bad gateway</html>")
                .unwrap_err()
                .as_str(),
            "invalid_server_response"
        );
        assert_eq!(
            empty(200, b"{}").unwrap_err().as_str(),
            "invalid_server_response"
        );
        assert!(empty(204, b"").is_ok());
        assert_eq!(
            json::<MetaResponse>(200, b"not json").unwrap_err().as_str(),
            "invalid_server_response"
        );
        let big = vec![b' '; MAX_ERROR_BODY_LEN + 1];
        assert_eq!(
            empty(400, &big).unwrap_err().as_str(),
            "invalid_server_response"
        );
    }

    #[test]
    fn meta_is_checked_for_v1() {
        let ok = br#"{"server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[]}"#;
        assert!(check_meta(200, ok).is_ok());
        let gone = br#"{"server_version":"9.0.0","api_versions":["v9"],"min_client_versions":[]}"#;
        assert_eq!(
            check_meta(200, gone).unwrap_err().as_str(),
            "server_api_version_gone"
        );
        let request = meta_request();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.path(), "/api/meta");
        assert!(request.body().is_none() && request.authorization().is_none());
    }

    #[test]
    fn requests_carry_the_bearer_and_the_client_header() {
        let token = SessionToken::from_b64url(&"A".repeat(43)).unwrap();
        let request = HttpRequest::post_empty(paths::TOTP_ENROL_START, Some(&token));
        let auth = request.authorization().unwrap();
        assert!(auth.starts_with("Bearer ") && auth.len() == 7 + 43);
        assert_eq!(request.client(), CLIENT);
        assert!(CLIENT.starts_with("web/"));
        assert!(request.content_type().is_none());
        // Debug never shows the token.
        assert!(!format!("{request:?}").contains("AAAA"));
        let copy = request.duplicate();
        assert_eq!(copy.authorization(), request.authorization());
    }
}
