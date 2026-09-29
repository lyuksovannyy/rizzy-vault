//! The `api` role's endpoints: every M1 message of `rizzy-proto`, over the two domains
//! ([ADR 0002] point 3; [ADR 0010] §1; CRYPTO.md §5.10, §11).
//!
//! # Endpoints
//!
//! [ADR 0002] fixes `/api/v1/` and `GET /api/meta`; CRYPTO.md §11 gives some paths as
//! "illustrative; the API specification owns them"; no Accepted ADR fixes the rest. The paths
//! and methods below follow CRYPTO.md's where it gives one and are this crate's choice
//! otherwise (reported to the owner; pre-v1.0 under ADR 0002 point 5):
//!
//! | Method, path | Request → response | Session |
//! |---|---|---|
//! | `GET /api/meta` | – → `MetaResponse` | none |
//! | `POST /api/v1/register/start` | `RegisterStartRequest` → `RegisterStartResponse` | none |
//! | `POST /api/v1/register/finish` | `RegisterFinishRequest` → 204 | none |
//! | `POST /api/v1/login/start` | `LoginStartRequest` → `LoginStartResponse` | optional (re-authentication) |
//! | `POST /api/v1/login/finish` | `LoginFinishRequest` → `LoginFinishResponse` | optional (re-authentication) |
//! | `POST /api/v1/device-auth/start` | `DeviceAuthStartRequest` → `DeviceAuthStartResponse` | none |
//! | `POST /api/v1/device-auth/finish` | `DeviceAuthFinishRequest` → `DeviceAuthFinishResponse` | none |
//! | `POST /api/v1/account/state` | `AccountStateQuery` → `AccountView` | any |
//! | `POST /api/v1/devices/enrol` | `EnrolDeviceRequest` → 204 | fresh OPAQUE (checked by the domain) |
//! | `POST /api/v1/devices/web-certificate` | `UploadWebDeviceCertificateRequest` → 204 | OPAQUE |
//! | `GET /api/v1/devices/grants` | – → `DeviceGrantsResponse` | device |
//! | `POST /api/v1/devices/grants/ack` | `AckDeviceGrantsRequest` → 204 | device |
//! | `POST /api/v1/healing/bundles` | `PublishBundlesRequest` → 204 | any |
//! | `POST /api/v1/healing/account-state` | `PublishAccountStateRequest` → 204 | any |
//! | `POST /api/v1/healing/grants` | `PublishGrantsRequest` → 204 | any |
//! | `POST /api/v1/vault/upload` | `UploadRequest` → `UploadResponse` | OPAQUE or device |
//! | `POST /api/v1/vault/fetch` | `FetchRequest` → `FetchResponse` | OPAQUE or device |
//! | `POST /api/v1/vault/heal` | `HealingRequest` → `HealingResponse` | OPAQUE or device |
//!
//! "Empty success" (`rizzy-proto`'s tables) is `204 No Content`. The recovery-only session
//! (CRYPTO.md §11.9 step 3) "covers the recovery commit only", so it is refused on the vault
//! endpoints; the auth domain applies its own session rules to the others. Password change,
//! rotation, revocation, recovery and TOTP have no `rizzy-proto` request yet ([`rizzy-proto`]
//! "Left open"), so they have no endpoint in this build.
//!
//! # Every request
//!
//! 1. **The session, from the headers alone** (threat model §7.6 "D"), for every endpoint that
//!    takes one: the bearer token must name an unexpired session whose kind fits the presence of
//!    a signature (`rizzy_domain_auth::AuthService::session_for_token`), and the vault
//!    endpoints refuse the recovery-only session. This runs before a single body byte is read,
//!    so an anonymous client never gets the large upload limit: it is answered
//!    `401 unauthorized` at once.
//! 2. **Body size and time** ([`Endpoint::body_limit`]; threat model §7.6 "D"): a
//!    `Content-Length` above the limit is refused before the body is read, and the body is read
//!    up to the limit and refused past it, with `413 payload_too_large`. The read has a deadline
//!    ([`body_deadline`]); a body that misses it, or that the client stops sending, is answered
//!    `400 invalid_request` and logged as `body_read_timeout` or `client_aborted`. At most
//!    [`MAX_CONCURRENT_LARGE_BODIES`] requests with the upload limit are read and served at once;
//!    one that finds no slot within [`LARGE_BODY_WAIT`] is answered `429 rate_limited`.
//! 3. **Authentication** (CRYPTO.md §5.10): the bearer token again and, for a
//!    device-authenticated session, the `device-request` signature over the method, path and
//!    query, and body as received ([`super::headers`] for the header forms). One
//!    `401 unauthorized` for every failure.
//! 4. **Parsing**: `serde_json` into the `rizzy-proto` type, which bounds every field and
//!    refuses unknown fields. A failure is `400 invalid_request`; `serde_json`'s message, which
//!    can quote the input, is dropped.
//! 5. **The domain call**, with the server clock and the OS RNG.
//! 6. **The answer**: JSON, or the uniform error body `{"error": code}` ([`status`] for the
//!    HTTP status of each code). A storage or internal failure is logged by its `Display`, which
//!    carries no value, and answered `500 internal`.
//!
//! No request or response body, header value or token is ever logged ([`crate::log`]).
//!
//! [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [`rizzy-proto`]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/crates/rizzy-proto/src/lib.rs

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes, HttpBody as _};
use axum::extract::{ConnectInfo, Request};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use rizzy_domain_auth::types::RequestSignature;
use rizzy_domain_auth::types::{API_V1, ApiVersion, MetaResponse, Version};
use rizzy_domain_auth::types::{ErrorCode, ErrorResponse};
use rizzy_domain_auth::types::{List, SessionToken};
use rizzy_domain_auth::{AuthError, AuthService, RequestParts, Session, SessionKind};
use rizzy_domain_vault::{HealingError, VaultDomain, VaultError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{Semaphore, SemaphorePermit};

use super::headers::{
    REQUEST_COUNTER, REQUEST_SIGNATURE, bearer_token, client_address, rate_limit_source,
    request_signature,
};
use super::{RouteName, security};
use crate::bridge::{AuthDirectory, VaultBridge};
use crate::log::{self, Field};
use crate::sys::{now_ms, os_rng};

/// The body limit of every endpoint except upload and healing: 1 MiB. It bounds unauthenticated
/// requests (signup, login, device authentication) and the account requests. A request whose
/// lists stay within `rizzy-proto`'s count limits can still exceed it (4096 statements of up to
/// 1 KiB, as base64url); no personal account comes near that, and the limit is this crate's
/// choice, reported to the owner.
pub const BODY_LIMIT: usize = 1024 * 1024;

/// The rate-limit source of a request without a peer address (only in-process tests): one
/// shared bucket.
const UNKNOWN_SOURCE: &[u8] = b"unknown";

/// The fixed part of a body's read deadline ([`body_deadline`]).
pub const BODY_READ_BASE: Duration = Duration::from_secs(30);

/// The slowest upload rate a body's read deadline allows for ([`body_deadline`]): 64 KiB/s.
pub const BODY_READ_MIN_RATE: usize = 64 * 1024;

/// How many requests with the upload limit (upload, healing) are read and served at once. With
/// the default 32 MiB limit, the bodies held at once stay under 256 MiB. This crate's choice,
/// reported to the owner.
pub const MAX_CONCURRENT_LARGE_BODIES: usize = 8;

/// How long a request with the upload limit waits for a slot before `429 rate_limited`.
pub const LARGE_BODY_WAIT: Duration = Duration::from_secs(10);

/// The deadline for reading a body of at most `limit` bytes: [`BODY_READ_BASE`] plus the time
/// `limit` bytes take at [`BODY_READ_MIN_RATE`]. 46 s for the 1 MiB [`BODY_LIMIT`]; about 9 min
/// for the default 32 MiB upload limit, which only an authenticated session reaches.
#[must_use]
pub fn body_deadline(limit: usize) -> Duration {
    let seconds = u64::try_from(limit / BODY_READ_MIN_RATE).unwrap_or(u64::MAX);
    BODY_READ_BASE.saturating_add(Duration::from_secs(seconds))
}

/// The `api` role's services and settings.
pub struct Api {
    /// The auth domain.
    pub auth: AuthService<VaultBridge>,
    /// The vault domain.
    pub vault: VaultDomain<AuthDirectory>,
    /// Reverse proxies whose `X-Forwarded-For` is trusted.
    pub trusted_proxies: Vec<IpAddr>,
    /// The body limit of upload and healing requests.
    pub max_upload_bytes: usize,
    /// The slots of requests with the upload limit ([`MAX_CONCURRENT_LARGE_BODIES`]).
    large_bodies: Semaphore,
}

impl Api {
    /// The `api` role over the two domains.
    #[must_use]
    pub fn new(
        auth: AuthService<VaultBridge>,
        vault: VaultDomain<AuthDirectory>,
        trusted_proxies: Vec<IpAddr>,
        max_upload_bytes: usize,
    ) -> Self {
        Self {
            auth,
            vault,
            trusted_proxies,
            max_upload_bytes,
            large_bodies: Semaphore::new(MAX_CONCURRENT_LARGE_BODIES),
        }
    }
}

impl core::fmt::Debug for Api {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Api")
            .field("vault", &self.vault)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .finish_non_exhaustive()
    }
}

/// The HTTP method of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    /// `GET` (and `HEAD`).
    Get,
    /// `POST`.
    Post,
}

/// Which session an endpoint needs before the domain call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionNeed {
    /// None; an `Authorization` header is not read.
    None,
    /// None, but one is authenticated if the request carries `Authorization` (login as a
    /// re-authentication, CRYPTO.md §11.5 step 1, §11.8 step 0).
    Optional,
    /// Any session the auth domain accepts; the domain applies the endpoint's own rule.
    Required,
    /// An OPAQUE or device session: not the recovery-only session.
    Vault,
}

/// Every `/api/v1` endpoint (module docs for the table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// Signup, OPAQUE registration start.
    RegisterStart,
    /// Signup commit.
    RegisterFinish,
    /// Login, KE1 → KE2.
    LoginStart,
    /// Login, KE3 → session.
    LoginFinish,
    /// Device authentication, the challenge.
    DeviceAuthStart,
    /// Device authentication, the signature.
    DeviceAuthFinish,
    /// The unlock's account view.
    AccountState,
    /// Enrolment of a durable device.
    EnrolDevice,
    /// The web vault's kind-4 certificate.
    WebCertificate,
    /// Pending device grants.
    DeviceGrants,
    /// Grant acknowledgement.
    AckDeviceGrants,
    /// Healing step 1.
    PublishBundles,
    /// Healing step 2.
    PublishAccountState,
    /// Healing step 3.
    PublishGrants,
    /// Vault upload.
    Upload,
    /// Vault Fetch.
    Fetch,
    /// Vault restore healing.
    Heal,
}

impl Endpoint {
    /// Every endpoint.
    pub const ALL: &[Self] = &[
        Self::RegisterStart,
        Self::RegisterFinish,
        Self::LoginStart,
        Self::LoginFinish,
        Self::DeviceAuthStart,
        Self::DeviceAuthFinish,
        Self::AccountState,
        Self::EnrolDevice,
        Self::WebCertificate,
        Self::DeviceGrants,
        Self::AckDeviceGrants,
        Self::PublishBundles,
        Self::PublishAccountState,
        Self::PublishGrants,
        Self::Upload,
        Self::Fetch,
        Self::Heal,
    ];

    /// The path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::RegisterStart => "/api/v1/register/start",
            Self::RegisterFinish => "/api/v1/register/finish",
            Self::LoginStart => "/api/v1/login/start",
            Self::LoginFinish => "/api/v1/login/finish",
            Self::DeviceAuthStart => "/api/v1/device-auth/start",
            Self::DeviceAuthFinish => "/api/v1/device-auth/finish",
            Self::AccountState => "/api/v1/account/state",
            Self::EnrolDevice => "/api/v1/devices/enrol",
            Self::WebCertificate => "/api/v1/devices/web-certificate",
            Self::DeviceGrants => "/api/v1/devices/grants",
            Self::AckDeviceGrants => "/api/v1/devices/grants/ack",
            Self::PublishBundles => "/api/v1/healing/bundles",
            Self::PublishAccountState => "/api/v1/healing/account-state",
            Self::PublishGrants => "/api/v1/healing/grants",
            Self::Upload => "/api/v1/vault/upload",
            Self::Fetch => "/api/v1/vault/fetch",
            Self::Heal => "/api/v1/vault/heal",
        }
    }

    /// The method.
    #[must_use]
    pub const fn method(self) -> HttpMethod {
        match self {
            Self::DeviceGrants => HttpMethod::Get,
            _ => HttpMethod::Post,
        }
    }

    /// The session the endpoint needs.
    const fn session(self) -> SessionNeed {
        match self {
            Self::RegisterStart
            | Self::RegisterFinish
            | Self::DeviceAuthStart
            | Self::DeviceAuthFinish => SessionNeed::None,
            Self::LoginStart | Self::LoginFinish => SessionNeed::Optional,
            Self::AccountState
            | Self::EnrolDevice
            | Self::WebCertificate
            | Self::DeviceGrants
            | Self::AckDeviceGrants
            | Self::PublishBundles
            | Self::PublishAccountState
            | Self::PublishGrants => SessionNeed::Required,
            Self::Upload | Self::Fetch | Self::Heal => SessionNeed::Vault,
        }
    }

    /// The body-size limit: [`BODY_LIMIT`], the configured upload limit for upload and healing,
    /// and 0 for the `GET` endpoint, which takes no body.
    #[must_use]
    pub const fn body_limit(self, max_upload_bytes: usize) -> usize {
        match self {
            Self::Upload | Self::Heal => max_upload_bytes,
            Self::DeviceGrants => 0,
            _ => BODY_LIMIT,
        }
    }
}

/// The HTTP status of an error code. [ADR 0002] point 3 fixes only `410 Gone` for
/// `api_version_gone`; the rest are this crate's choice (reported to the owner).
///
/// [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
#[must_use]
pub const fn status(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidRequest | ErrorCode::ClientTooOld => StatusCode::BAD_REQUEST,
        ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::Unauthorized | ErrorCode::SecondFactorRequired => StatusCode::UNAUTHORIZED,
        ErrorCode::FreshSessionRequired => StatusCode::FORBIDDEN,
        ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::NotFound => StatusCode::NOT_FOUND,
        ErrorCode::StateConflict
        | ErrorCode::StaleEpoch
        | ErrorCode::RecordConflict
        | ErrorCode::PrevSeqMismatch => StatusCode::CONFLICT,
        ErrorCode::ApiVersionGone => StatusCode::GONE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// A JSON response with `status`, marked `no-store` and with its route name.
fn json_response(status: StatusCode, body: Vec<u8>, route: &'static str) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    security::add_no_store(response.headers_mut());
    response.extensions_mut().insert(RouteName(route));
    response
}

/// The uniform error answer for `code` (ADR 0002 point 3).
#[must_use]
pub fn error_response(code: ErrorCode, route: &'static str) -> Response {
    let body = serde_json::to_vec(&ErrorResponse::new(code))
        .unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
    json_response(status(code), body, route)
}

/// A successful answer.
enum Reply {
    /// A JSON body.
    Json(Vec<u8>),
    /// `204 No Content`.
    Empty,
}

/// Serialises a response value.
fn json<T: Serialize>(value: &T) -> Result<Reply, ErrorCode> {
    serde_json::to_vec(value)
        .map(Reply::Json)
        .map_err(|_| ErrorCode::Internal)
}

/// Parses a request body; `serde_json`'s message is dropped (INV-48).
fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ErrorCode> {
    serde_json::from_slice(body).map_err(|_| ErrorCode::InvalidRequest)
}

/// The code of an auth-domain error; a storage or internal failure is logged first.
fn auth_code(endpoint: Endpoint, e: &AuthError) -> ErrorCode {
    if matches!(e, AuthError::Storage(_) | AuthError::Internal(_)) {
        log::error(
            "auth_failure",
            &[
                Field::Str("route", endpoint.path()),
                Field::Error("error", e),
            ],
        );
    }
    e.code()
}

/// The code of a vault-domain error; a failure other than a refusal is logged first.
fn vault_code(endpoint: Endpoint, e: &VaultError) -> ErrorCode {
    if !matches!(e, VaultError::NotFound | VaultError::Invalid) {
        log::error(
            "vault_failure",
            &[
                Field::Str("route", endpoint.path()),
                Field::Error("error", e),
            ],
        );
    }
    e.code()
}

/// `GET /api/meta` (ADR 0002 point 3, as ADR 0022 amends it): this server's version, the API
/// versions it serves, and no minimum client version (none is configured in M1).
#[must_use]
pub fn meta() -> Response {
    let answer = Version::from_str(env!("CARGO_PKG_VERSION"))
        .ok()
        .zip(ApiVersion::from_str(API_V1).ok())
        .and_then(|(server_version, v1)| {
            Some(MetaResponse {
                server_version,
                api_versions: List::new(vec![v1]).ok()?,
                min_client_versions: List::empty(),
            })
        });
    match answer.map(|m| serde_json::to_vec(&m)) {
        Some(Ok(body)) => json_response(StatusCode::OK, body, "/api/meta"),
        _ => error_response(ErrorCode::Internal, "/api/meta"),
    }
}

/// Serves one request to `endpoint` (module docs).
pub async fn dispatch(api: Arc<Api>, endpoint: Endpoint, request: Request) -> Response {
    match handle(&api, endpoint, request).await {
        Ok(Reply::Json(body)) => json_response(StatusCode::OK, body, endpoint.path()),
        Ok(Reply::Empty) => {
            let mut response = json_response(StatusCode::NO_CONTENT, Vec::new(), endpoint.path());
            response.headers_mut().remove(CONTENT_TYPE);
            response
        }
        Err(code) => error_response(code, endpoint.path()),
    }
}

/// Why a body could not be read.
enum BodyError {
    /// It exceeds the limit.
    TooLarge,
    /// The client stopped sending it (a disconnect, a framing error).
    Aborted,
}

/// Collects `body`, refusing it once it exceeds `limit` bytes. Trailers are ignored.
async fn collect(mut body: Body, limit: usize) -> Result<Bytes, BodyError> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            None => return Ok(Bytes::from(buf)),
            Some(Err(_)) => return Err(BodyError::Aborted),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    if buf.len().saturating_add(data.len()) > limit {
                        return Err(BodyError::TooLarge);
                    }
                    buf.extend_from_slice(&data);
                }
            }
        }
    }
}

/// Reads the body up to `limit` bytes within [`body_deadline`] (step 2 of the module docs).
async fn read_body(
    endpoint: Endpoint,
    parts: &Parts,
    body: Body,
    limit: usize,
) -> Result<Bytes, ErrorCode> {
    if let Some(length) = parts.headers.get(CONTENT_LENGTH) {
        let length = length
            .to_str()
            .ok()
            .and_then(|l| l.parse::<u64>().ok())
            .ok_or(ErrorCode::InvalidRequest)?;
        if length > u64::try_from(limit).unwrap_or(u64::MAX) {
            return Err(ErrorCode::PayloadTooLarge);
        }
    }
    match tokio::time::timeout(body_deadline(limit), collect(body, limit)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(BodyError::TooLarge)) => Err(ErrorCode::PayloadTooLarge),
        Ok(Err(BodyError::Aborted)) => {
            log::info("client_aborted", &[Field::Str("route", endpoint.path())]);
            Err(ErrorCode::InvalidRequest)
        }
        Err(_elapsed) => {
            log::info("body_read_timeout", &[Field::Str("route", endpoint.path())]);
            Err(ErrorCode::InvalidRequest)
        }
    }
}

/// The request's credentials, parsed from its headers.
struct Credentials {
    /// The bearer token.
    token: SessionToken,
    /// The request signature, if the request carries one.
    signature: Option<RequestSignature>,
}

/// Parses the bearer token and the signature headers; any failure is `401`.
fn credentials(parts: &Parts) -> Result<Credentials, ErrorCode> {
    let token = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(ErrorCode::Unauthorized)
        .and_then(|v| bearer_token(v.as_bytes()).map_err(|_| ErrorCode::Unauthorized))?;
    let signature = request_signature(
        parts
            .headers
            .get(REQUEST_COUNTER)
            .map(HeaderValue::as_bytes),
        parts
            .headers
            .get(REQUEST_SIGNATURE)
            .map(HeaderValue::as_bytes),
    )
    .map_err(|_| ErrorCode::Unauthorized)?;
    Ok(Credentials { token, signature })
}

/// The code of an authentication failure: `401` for every refusal, the logged code for a
/// storage or internal failure.
fn refused(endpoint: Endpoint, e: &AuthError) -> ErrorCode {
    match e {
        AuthError::Storage(_) | AuthError::Internal(_) => auth_code(endpoint, e),
        _ => ErrorCode::Unauthorized,
    }
}

/// The header-only session check (step 1 of the module docs).
async fn precheck(
    api: &Api,
    endpoint: Endpoint,
    credentials: &Credentials,
    now: u64,
) -> Result<(), ErrorCode> {
    let session = api
        .auth
        .session_for_token(
            credentials.token.expose_secret(),
            credentials.signature.is_some(),
            now,
        )
        .await
        .map_err(|e| refused(endpoint, &e))?;
    if endpoint.session() == SessionNeed::Vault && session.kind == SessionKind::Recovery {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(())
}

/// Authenticates the request's bearer token and, if present, its signature over the body
/// (step 3 of the module docs).
async fn authenticate(
    api: &Api,
    endpoint: Endpoint,
    parts: &Parts,
    credentials: &Credentials,
    body: &[u8],
    now: u64,
) -> Result<Session, ErrorCode> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |p| p.as_str());
    let request = RequestParts {
        method: parts.method.as_str(),
        path_and_query,
        body,
    };
    let session = api
        .auth
        .authenticate_request(
            credentials.token.expose_secret(),
            credentials.signature.as_ref(),
            request,
            now,
        )
        .await
        .map_err(|e| refused(endpoint, &e))?;
    if endpoint.session() == SessionNeed::Vault && session.kind == SessionKind::Recovery {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(session)
}

/// Waits up to [`LARGE_BODY_WAIT`] for a slot for a request with the upload limit.
async fn large_body_slot(api: &Api) -> Result<SemaphorePermit<'_>, ErrorCode> {
    match tokio::time::timeout(LARGE_BODY_WAIT, api.large_bodies.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_closed)) => Err(ErrorCode::Internal),
        Err(_elapsed) => Err(ErrorCode::RateLimited),
    }
}

/// The rate-limit source of the request (threat model §7.6 "S"), from every
/// `X-Forwarded-For` field line in order ([`client_address`]).
fn source(api: &Api, parts: &Parts) -> Vec<u8> {
    let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
        return UNKNOWN_SOURCE.to_vec();
    };
    let forwarded: Vec<&[u8]> = parts
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    rate_limit_source(client_address(peer.ip(), &forwarded, &api.trusted_proxies))
}

/// Steps 1–5 of the module docs.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per endpoint, in the order of the module docs' table"
)]
async fn handle(api: &Api, endpoint: Endpoint, request: Request) -> Result<Reply, ErrorCode> {
    let (parts, body) = request.into_parts();
    let credentials = match endpoint.session() {
        SessionNeed::None => None,
        SessionNeed::Optional if !parts.headers.contains_key(AUTHORIZATION) => None,
        SessionNeed::Optional | SessionNeed::Required | SessionNeed::Vault => {
            let credentials = credentials(&parts)?;
            precheck(api, endpoint, &credentials, now_ms()).await?;
            Some(credentials)
        }
    };
    let limit = endpoint.body_limit(api.max_upload_bytes);
    let _slot = if limit > BODY_LIMIT {
        Some(large_body_slot(api).await?)
    } else {
        None
    };
    let body = read_body(endpoint, &parts, body, limit).await?;
    let now = now_ms();
    let session = match &credentials {
        Some(credentials) => {
            Some(authenticate(api, endpoint, &parts, credentials, &body, now).await?)
        }
        None => None,
    };
    let mut rng = os_rng();
    let auth = &api.auth;
    let ae = |e: AuthError| auth_code(endpoint, &e);
    let ve = |e: VaultError| vault_code(endpoint, &e);
    // `session` is `Some` for every endpoint whose arm reads it (`SessionNeed` above).
    let need = || session.as_ref().ok_or(ErrorCode::Unauthorized);
    match endpoint {
        Endpoint::RegisterStart => {
            let source = source(api, &parts);
            json(
                &auth
                    .register_start(&parse(&body)?, &source, now)
                    .await
                    .map_err(ae)?,
            )
        }
        Endpoint::RegisterFinish => {
            auth.register_finish(&parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::LoginStart => {
            let source = source(api, &parts);
            json(
                &auth
                    .login_start(&mut rng, &parse(&body)?, &source, session.as_ref(), now)
                    .await
                    .map_err(ae)?,
            )
        }
        Endpoint::LoginFinish => {
            let source = source(api, &parts);
            json(
                &auth
                    .login_finish(&mut rng, &parse(&body)?, &source, session.as_ref(), now)
                    .await
                    .map_err(ae)?,
            )
        }
        Endpoint::DeviceAuthStart => json(
            &auth
                .device_auth_start(&mut rng, &parse(&body)?, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::DeviceAuthFinish => json(
            &auth
                .device_auth_finish(&mut rng, &parse(&body)?, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::AccountState => json(
            &auth
                .account_view(need()?, parse(&body)?, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::EnrolDevice => {
            auth.enrol_device(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::WebCertificate => {
            auth.upload_web_certificate(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::DeviceGrants => json(&auth.device_grants(need()?, now).await.map_err(ae)?),
        Endpoint::AckDeviceGrants => {
            auth.ack_device_grants(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::PublishBundles => {
            auth.publish_bundles(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::PublishAccountState => {
            auth.publish_account_state(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::PublishGrants => {
            auth.publish_grants(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::Upload => json(
            &api.vault
                .upload(need()?.account_id, &parse(&body)?, now)
                .await
                .map_err(ve)?,
        ),
        Endpoint::Fetch => {
            let outcome = api
                .vault
                .fetch(need()?.account_id, &parse(&body)?)
                .await
                .map_err(ve)?;
            // ADR 0021 §4: a bodiless header served without a retained cover is logged,
            // "naming the vault, item and dot, never content".
            for integrity in &outcome.integrity_errors {
                log::error(
                    "fetch_integrity_error",
                    &[Field::Error("detail", integrity)],
                );
            }
            json(&outcome.response)
        }
        Endpoint::Heal => match api
            .vault
            .heal(need()?.account_id, &parse(&body)?, now)
            .await
        {
            Ok(answer) => json(&answer),
            Err(HealingError::Refused(code)) => Err(code),
            Err(HealingError::Failed(e)) => Err(ve(e)),
            Err(e) => Err(e.code()),
        },
    }
}
