//! The `api` role's endpoints: every M1 message of `rizzy-proto`, over the two domains
//! ([ADR 0002] point 3; [ADR 0010] §1; [ADR 0028]; CRYPTO.md §5.10, §11).
//!
//! # Endpoints
//!
//! [ADR 0028] item 1 freezes this table for `v1`: the 27 endpoints under `/api/v1/`, grouped by
//! resource, verb last; `POST` for everything, including reads that carry a body, and `GET`
//! (and `HEAD`) only for `GET /api/v1/devices/grants`. The path strings are `rizzy-proto`'s
//! (`http::paths`), shared with every client. The router matches them byte for byte: a path
//! with a dot segment, `//`, a trailing slash or a percent-encoded octet is `404 not_found`
//! before any session check.
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
//! | `POST /api/v1/account/reregister/start` | `ReregisterStartRequest` → `ReregisterStartResponse` | any (fresh OPAQUE, recovery-only or device; checked by the domain) |
//! | `POST /api/v1/account/commit` | `CommitChangeRequest` → 204 | any (per change; checked by the domain) |
//! | `POST /api/v1/devices/suspend` | `DeviceSuspensionRequest` → `SuspendDeviceResponse` | OPAQUE or device (fresh OPAQUE bound to another device; checked by the domain) |
//! | `POST /api/v1/devices/unsuspend` | `DeviceSuspensionRequest` → 204 | OPAQUE or device (as suspend) |
//! | `POST /api/v1/recovery/start` | `RecoveryRequest` → `RecoveryStartResponse` | none |
//! | `POST /api/v1/recovery/cancel` | no body → `RecoveryCancelResponse` | OPAQUE or device (a device session; checked by the domain) |
//! | `POST /api/v1/recovery/complete` | `RecoveryRequest` → `RecoveryCompleteResponse` | none |
//! | `POST /api/v1/totp/enrol/start` | no body → `TotpEnrolStartResponse` | OPAQUE or device (fresh OPAQUE; checked by the domain) |
//! | `POST /api/v1/totp/enrol/confirm` | `TotpEnrolConfirmRequest` → 204 | OPAQUE or device (fresh OPAQUE; checked by the domain) |
//! | `POST /api/v1/totp/disable` | `TotpDisableRequest` → 204 | OPAQUE or device (fresh OPAQUE; checked by the domain) |
//! | `POST /api/v1/vault/upload` | `UploadRequest` → `UploadResponse` | OPAQUE or device |
//! | `POST /api/v1/vault/fetch` | `FetchRequest` → `FetchResponse` | OPAQUE or device |
//! | `POST /api/v1/vault/heal` | `HealingRequest` → `HealingResponse` | OPAQUE or device |
//!
//! "Empty success" (`rizzy-proto`'s tables) is `204 No Content`; "no body" endpoints take an
//! empty body (limit 0) and are `POST` because they change state. The recovery-only session
//! (CRYPTO.md §11.9 step 3) "covers the recovery commit only", so it is refused here, before the
//! domain, on the "OPAQUE or device" rows: the vault endpoints, suspension, recovery cancel and
//! TOTP, which the auth domain then narrows further. The auth domain applies its own session
//! rules to the "any" rows; re-registration and the commit accept the recovery-only session for
//! the recovery commit of §11.9 step 5. The freshness rules (a fresh OPAQUE session of at
//! most 5 minutes, CRYPTO.md §11 "Replacing credentials", §11.5 step 1, §11.8 step 0) are the
//! domain's, answered `403 fresh_session_required`; a device session signs every request
//! (step 3 below) on these endpoints like on every other.
//!
//! **Key rotation** (ADR 0025) is the account commit with its rotation fields: the standard and
//! full rotation of CRYPTO.md §11.6, the revocation of §11.8 step 3 and the rotating recovery of
//! §11.9 step 5, applied atomically with the vault half under the account lock (the auth domain
//! and `crate::bridge`). A rotation whose vault half the server does not hold as the rotator saw
//! it is answered `409 state_conflict`, and the client fetches and retries (ADR 0025 §2 step 5).
//! The commit takes the upload limit (ADR 0025 §1 "Body limit"), after the session check of
//! step (c) below. `/recovery/complete` keeps the 1 MiB limit for its request body, which is
//! only `{login_name, recovery_auth_token}` and needs no session: the large part is its
//! response (every vault's heads and wrap set), and an anonymous request never gets the upload
//! limit or a large-body slot ([ADR 0028] item 7, owner decision on open question 5).
//!
//! # Every request
//!
//! The order of [ADR 0028] item 6, with the two header checks its items 11 and 14 add:
//!
//! - **(a) Routing** ([`super::router`]): an unknown `/api/` path is `404 not_found`, a method
//!   the route does not serve is `405` with `invalid_request`.
//! - **`Rizzy-Client`** (item 14): a well-formed header whose platform has a minimum above its
//!   version is `400 client_too_old`; a missing or malformed one is served normally until v1.0
//!   ([`super::headers::client_refused`]). `GET /api/meta` is served whatever the header says:
//!   it is where a client reads the minimums.
//! - **The rate-limit source** (item 11): the peer address or, when the peer is a configured
//!   proxy, the client address its `X-Forwarded-For` gives. A configured proxy whose header
//!   gives none is `400 invalid_request`, on every `/api/v1` endpoint: the request is never
//!   counted against the proxy's own address ([`super::headers::client_address`]).
//! - **(b) The credentials, parsed**, on an endpoint that takes a session: `Authorization` and
//!   the two signing headers ([`super::headers`]). A missing, repeated or malformed one is
//!   `401 unauthorized` before any database lookup.
//! - **(c) The session, from the headers alone** (threat model §7.6 "D"): the bearer token must
//!   name an unexpired session whose kind fits the presence of a signature
//!   (`rizzy_domain_auth::AuthService::session_for_token`), and the "OPAQUE or device" rows
//!   refuse the recovery-only session. One read transaction, before a single body byte is
//!   read, so an anonymous client never gets the upload limit: it is answered
//!   `401 unauthorized` at once. `login/start` and `login/finish` run (b) and (c) only when
//!   `Authorization` is present.
//! - **(d) A large-body slot**, only for the three endpoints with the upload limit: at most
//!   [`MAX_CONCURRENT_LARGE_BODIES`] at once per process; a request that waits
//!   [`LARGE_BODY_WAIT`] for one is `429 rate_limited`. The slot is held until the answer is
//!   built.
//! - **(e) Body size and time** ([`Endpoint::body_limit`]): a `Content-Length` that is not a
//!   decimal `u64` is `400 invalid_request`, and one above the limit is `413 payload_too_large`
//!   before a body byte is read; the body, with or without a declared length, is read frame by
//!   frame into a buffer that never grows past the limit, and the first frame that would pass
//!   it ends the read with `413`. The read has a deadline ([`body_deadline`]); a body that
//!   misses it, or that the client stops sending, is `400 invalid_request`, logged as
//!   `body_read_timeout` or `client_aborted` with the route only.
//! - **(f) Authentication** (CRYPTO.md §5.10): the bearer token again and, for a
//!   device-authenticated session, the `device-request` signature over the method, the
//!   request-target's path and query, and the body as received, then the counter
//!   (`authenticate`). The path and query are the bytes sent, with one exception: a fragment,
//!   which is no part of a request-target, is cut off by hyper before routing and verification
//!   (`signed_target`).
//! - **(g) Parsing**: `serde_json` into the `rizzy-proto` type, which bounds every field and
//!   refuses unknown fields. A failure is `400 invalid_request`; `serde_json`'s message, which
//!   can quote the input, is dropped.
//! - **(h) The domain call**, with the server clock and the OS RNG.
//!
//! **One answer** (item 5). A bearer token that is missing, malformed, unknown or expired, a
//! counter or signature that is malformed, replayed, too old or wrong, a signature missing on
//! a device session or present on any other, and a device no longer usable all get the same
//! `401` `{"error":"unauthorized"}`, with no `WWW-Authenticate`, no detail and no
//! per-component log line. Timing is not equalised: header-only failures answer before the
//! body is read, signature and counter failures after it.
//!
//! **The answer** (items 2, 3): `200` with `application/json`, `204` with no body, or the
//! uniform error body `{"error": code}` with the status of [`status`]; a `429` also carries
//! `Retry-After` in whole seconds (`Failure`). A storage or internal failure is logged by its
//! `Display`, which carries no value, and answered `500 internal`. Errors hyper answers before
//! a request reaches the router (a request line or header block it cannot parse) carry no
//! body.
//!
//! No request or response body, header value or token is ever logged ([`crate::log`]).
//!
//! [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [`rizzy-proto`]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/crates/rizzy-proto/src/lib.rs

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes, HttpBody as _};
use axum::extract::{ConnectInfo, Request};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::header::{AsHeaderName, RETRY_AFTER};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use rizzy_domain_auth::types::RequestSignature;
use rizzy_domain_auth::types::paths;
use rizzy_domain_auth::types::{API_V1, ApiVersion, MetaResponse, MinClientVersion, Version};
use rizzy_domain_auth::types::{ErrorCode, ErrorResponse};
use rizzy_domain_auth::types::{List, MAX_BODY_LEN, Platform, SessionToken};
use rizzy_domain_auth::{AuthError, AuthService, RequestParts, Session, SessionKind};
use rizzy_domain_vault::{HealingError, VaultDomain, VaultError};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{Semaphore, SemaphorePermit};

use super::headers::{
    BadHeader, CLIENT_HEADER, REQUEST_COUNTER_HEADER, REQUEST_SIGNATURE_HEADER, bearer_token,
    client_address, client_refused, content_length, rate_limit_source, request_signature,
};
use super::{RouteName, security};
use crate::bridge::{AuthDirectory, VaultBridge};
use crate::log::{self, Field};
use crate::sys::{now_ms, os_rng};

/// The body limit of every endpoint except upload, healing and the account commit: 1 MiB
/// ([ADR 0028] item 7; `rizzy-proto`'s `limits::MAX_BODY_LEN`). It bounds the unauthenticated
/// requests (signup, login, device authentication, recovery) and the account requests. A
/// request whose lists stay within `rizzy-proto`'s count limits can still exceed it (4096
/// statements of up to 1 KiB, as base64url); no personal account comes near that.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const BODY_LIMIT: usize = MAX_BODY_LEN;

/// The rate-limit source of a request without a peer address (only in-process tests): one
/// shared bucket.
const UNKNOWN_SOURCE: &[u8] = b"unknown";

/// The header a configured reverse proxy reports the client address in ([ADR 0028] item 11).
/// `Forwarded` (RFC 7239) is not read.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// The fixed part of a body's read deadline ([`body_deadline`]; [ADR 0028] item 8).
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const BODY_READ_BASE: Duration = Duration::from_secs(30);

/// The slowest upload rate a body's read deadline allows for ([`body_deadline`]): 64 KiB/s.
pub const BODY_READ_MIN_RATE: usize = 64 * 1024;

/// How many requests with the upload limit (upload, healing, the account commit) are read and
/// served at once **per `api` process** ([ADR 0028] item 8): an in-process semaphore, not
/// shared through the database. Worst-case request bodies held by one process: 8 × the upload
/// limit plus 1 MiB for each of the other connections, about 1.25 GiB at the default limit and
/// 3 GiB at the 256 MiB maximum, and more while bodies are parsed (the ADR's estimate, not
/// measured). With several `api` processes the bound is per process.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const MAX_CONCURRENT_LARGE_BODIES: usize = 8;

/// How long a request with the upload limit waits for a slot before `429 rate_limited`.
pub const LARGE_BODY_WAIT: Duration = Duration::from_secs(10);

/// The `Retry-After` of a `429` that comes from no bucket with a backoff: a request that found
/// no large-body slot, and the cap on web-vault certificates. 10 s, the length of the slot wait.
///
/// [ADR 0028] (owner decision on open question 1) sends `Retry-After` on `429` "from the
/// bucket's backoff" and names no value where there is no bucket; every `429` still carries
/// the header, so that a client never has to guess (this crate's reading, reported).
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const RETRY_AFTER_FALLBACK_SECS: u64 = 10;

/// The minimum client version per platform this build serves ([ADR 0028] item 14), as
/// `(platform, version)`: what `GET /api/meta` lists and the `Rizzy-Client` check applies.
/// Empty: no released client is refused yet. No setting changes it ([ADR 0028] item 12 lists
/// none); raising a minimum is a server release (ADR 0002 point 5).
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const MIN_CLIENT_VERSIONS: &[(&str, &str)] = &[];

/// [`MIN_CLIENT_VERSIONS`] in its wire type. An entry that does not fit the wire type is left
/// out (a unit test keeps the list well-formed, so none is).
fn built_in_minimums() -> Vec<MinClientVersion> {
    MIN_CLIENT_VERSIONS
        .iter()
        .filter_map(|(platform, version)| {
            Some(MinClientVersion {
                platform: Platform::from_str(platform).ok()?,
                version: Version::from_str(version).ok()?,
            })
        })
        .collect()
}

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
    /// The body limit of upload, healing and account-commit requests.
    pub max_upload_bytes: usize,
    /// The minimum client version per platform ([`MIN_CLIENT_VERSIONS`]): served by
    /// `GET /api/meta` and applied to the `Rizzy-Client` header of every `/api/v1` request.
    pub min_client_versions: Vec<MinClientVersion>,
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
            min_client_versions: built_in_minimums(),
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
    /// An OPAQUE or device session: not the recovery-only session (the "OPAQUE or device" rows
    /// of the module docs).
    NotRecovery,
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
    /// OPAQUE re-registration start.
    ReregisterStart,
    /// The atomic commit of a credential, settings or device change.
    CommitChange,
    /// Revocation phase 1: suspension.
    SuspendDevice,
    /// Lifting a suspension.
    UnsuspendDevice,
    /// Recovery start.
    RecoveryStart,
    /// Recovery cancel, by a device.
    RecoveryCancel,
    /// Recovery complete.
    RecoveryComplete,
    /// TOTP enrolment start.
    TotpEnrolStart,
    /// TOTP enrolment confirmation.
    TotpEnrolConfirm,
    /// TOTP removal.
    TotpDisable,
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
        Self::ReregisterStart,
        Self::CommitChange,
        Self::SuspendDevice,
        Self::UnsuspendDevice,
        Self::RecoveryStart,
        Self::RecoveryCancel,
        Self::RecoveryComplete,
        Self::TotpEnrolStart,
        Self::TotpEnrolConfirm,
        Self::TotpDisable,
        Self::Upload,
        Self::Fetch,
        Self::Heal,
    ];

    /// The path.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::RegisterStart => paths::REGISTER_START,
            Self::RegisterFinish => paths::REGISTER_FINISH,
            Self::LoginStart => paths::LOGIN_START,
            Self::LoginFinish => paths::LOGIN_FINISH,
            Self::DeviceAuthStart => paths::DEVICE_AUTH_START,
            Self::DeviceAuthFinish => paths::DEVICE_AUTH_FINISH,
            Self::AccountState => paths::ACCOUNT_STATE,
            Self::EnrolDevice => paths::DEVICES_ENROL,
            Self::WebCertificate => paths::DEVICES_WEB_CERTIFICATE,
            Self::DeviceGrants => paths::DEVICES_GRANTS,
            Self::AckDeviceGrants => paths::DEVICES_GRANTS_ACK,
            Self::PublishBundles => paths::HEALING_BUNDLES,
            Self::PublishAccountState => paths::HEALING_ACCOUNT_STATE,
            Self::PublishGrants => paths::HEALING_GRANTS,
            Self::ReregisterStart => paths::ACCOUNT_REREGISTER_START,
            Self::CommitChange => paths::ACCOUNT_COMMIT,
            Self::SuspendDevice => paths::DEVICES_SUSPEND,
            Self::UnsuspendDevice => paths::DEVICES_UNSUSPEND,
            Self::RecoveryStart => paths::RECOVERY_START,
            Self::RecoveryCancel => paths::RECOVERY_CANCEL,
            Self::RecoveryComplete => paths::RECOVERY_COMPLETE,
            Self::TotpEnrolStart => paths::TOTP_ENROL_START,
            Self::TotpEnrolConfirm => paths::TOTP_ENROL_CONFIRM,
            Self::TotpDisable => paths::TOTP_DISABLE,
            Self::Upload => paths::VAULT_UPLOAD,
            Self::Fetch => paths::VAULT_FETCH,
            Self::Heal => paths::VAULT_HEAL,
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
            | Self::DeviceAuthFinish
            | Self::RecoveryStart
            | Self::RecoveryComplete => SessionNeed::None,
            Self::LoginStart | Self::LoginFinish => SessionNeed::Optional,
            Self::AccountState
            | Self::EnrolDevice
            | Self::WebCertificate
            | Self::DeviceGrants
            | Self::AckDeviceGrants
            | Self::PublishBundles
            | Self::PublishAccountState
            | Self::PublishGrants
            | Self::ReregisterStart
            | Self::CommitChange => SessionNeed::Required,
            Self::SuspendDevice
            | Self::UnsuspendDevice
            | Self::RecoveryCancel
            | Self::TotpEnrolStart
            | Self::TotpEnrolConfirm
            | Self::TotpDisable
            | Self::Upload
            | Self::Fetch
            | Self::Heal => SessionNeed::NotRecovery,
        }
    }

    /// The body-size limit: [`BODY_LIMIT`], the configured upload limit for upload, healing and
    /// the account commit (which carries a rotation's re-wrapped wrap set, ADR 0025 §1),
    /// and 0 for the endpoints that take no body (the `GET` endpoint, recovery cancel and TOTP
    /// enrolment start).
    #[must_use]
    pub const fn body_limit(self, max_upload_bytes: usize) -> usize {
        match self {
            Self::Upload | Self::Heal | Self::CommitChange => max_upload_bytes,
            Self::DeviceGrants | Self::RecoveryCancel | Self::TotpEnrolStart => 0,
            _ => BODY_LIMIT,
        }
    }
}

/// The HTTP status of an error code ([ADR 0028] item 3, with `setup_retired` 409 as ADR 0031 point
/// 3 adds it and `credentials_stale` 409 as ADR 0032 adds it). A code this build does not send
/// (`unknown`) maps to `500` like `internal`. Clients branch on the code, never on the status.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
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
        | ErrorCode::PrevSeqMismatch
        | ErrorCode::SetupRetired
        | ErrorCode::CredentialsStale => StatusCode::CONFLICT,
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

/// The uniform error answer for `code` (ADR 0002 point 3; [ADR 0028] item 3): the body
/// `{"error":"<code>"}` with the status of [`status`], no message and no echo of input. A
/// `rate_limited` answer carries `Retry-After` with [`RETRY_AFTER_FALLBACK_SECS`].
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
#[must_use]
pub fn error_response(code: ErrorCode, route: &'static str) -> Response {
    failure_response(Failure::from(code), route)
}

/// The uniform error answer for `failure`: [`error_response`], with the failure's own
/// `Retry-After` when it has one.
fn failure_response(failure: Failure, route: &'static str) -> Response {
    let body = serde_json::to_vec(&ErrorResponse::new(failure.code))
        .unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
    let mut response = json_response(status(failure.code), body, route);
    if failure.code == ErrorCode::RateLimited {
        let seconds = failure
            .retry_after_secs
            .unwrap_or(RETRY_AFTER_FALLBACK_SECS);
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from(seconds));
    }
    response
}

/// Why a request is refused: the error code and, for `rate_limited`, when to try again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Failure {
    /// The code of the uniform error body.
    code: ErrorCode,
    /// The `Retry-After` of a `429`, in whole seconds ([ADR 0028] item 3, owner decision on
    /// open question 1): the refusing bucket's remaining backoff, or the rest of the recovery
    /// waiting period. `None` when the refusal has no such time
    /// ([`RETRY_AFTER_FALLBACK_SECS`] is sent then), and for every other code.
    ///
    /// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
    retry_after_secs: Option<u64>,
}

impl From<ErrorCode> for Failure {
    fn from(code: ErrorCode) -> Self {
        Self {
            code,
            retry_after_secs: None,
        }
    }
}

/// Milliseconds as the whole seconds of a `Retry-After`: rounded up, and at least 1, so that a
/// client told to wait never retries inside the backoff.
const fn retry_after_secs(ms: u64) -> u64 {
    let seconds = ms.div_ceil(1_000);
    if seconds == 0 { 1 } else { seconds }
}

/// A successful answer.
enum Reply {
    /// A JSON body.
    Json(Vec<u8>),
    /// `204 No Content`.
    Empty,
}

/// Serialises a response value.
fn json<T: Serialize>(value: &T) -> Result<Reply, Failure> {
    serde_json::to_vec(value)
        .map(Reply::Json)
        .map_err(|_| ErrorCode::Internal.into())
}

/// Parses a request body; `serde_json`'s message is dropped (INV-48).
fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ErrorCode> {
    serde_json::from_slice(body).map_err(|_| ErrorCode::InvalidRequest)
}

/// The answer to an auth-domain error: its code and, for a rate limit, its retry time. A
/// storage or internal failure is logged first.
fn auth_code(endpoint: Endpoint, e: &AuthError) -> Failure {
    if matches!(e, AuthError::Storage(_) | AuthError::Internal(_)) {
        log::error(
            "auth_failure",
            &[
                Field::Str("route", endpoint.path()),
                Field::Error("error", e),
            ],
        );
    }
    Failure {
        code: e.code(),
        retry_after_secs: e.retry_after_ms().map(retry_after_secs),
    }
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

/// `GET /api/meta` (ADR 0002 point 3, as ADR 0022 amends it; [ADR 0028] item 14): this
/// server's version, the API versions it serves, and the minimum client version per platform
/// (`minimums`; none in this build, [`MIN_CLIENT_VERSIONS`]).
///
/// Unauthenticated and public on purpose: it holds no secret and nothing about any account,
/// and the server version is disclosed so that a client can tell it is too old before it
/// authenticates. It is served whatever `Rizzy-Client` says.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
#[must_use]
pub fn meta(minimums: &[MinClientVersion]) -> Response {
    let answer = Version::from_str(env!("CARGO_PKG_VERSION"))
        .ok()
        .zip(ApiVersion::from_str(API_V1).ok())
        .and_then(|(server_version, v1)| {
            Some(MetaResponse {
                server_version,
                api_versions: List::new(vec![v1]).ok()?,
                min_client_versions: List::new(minimums.to_vec()).ok()?,
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
        Err(failure) => failure_response(failure, endpoint.path()),
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

/// Reads the body up to `limit` bytes within [`body_deadline`] (step (e) of the module docs).
async fn read_body(
    endpoint: Endpoint,
    parts: &Parts,
    body: Body,
    limit: usize,
) -> Result<Bytes, ErrorCode> {
    let declared = single(&parts.headers, CONTENT_LENGTH).map_err(|_| ErrorCode::InvalidRequest)?;
    if let Some(length) = declared {
        let length = content_length(length).map_err(|_| ErrorCode::InvalidRequest)?;
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

/// A header that may appear at most once: its value, or `None` when the request has no such
/// field line.
///
/// # Errors
/// [`BadHeader`] when the request carries the field more than once. Two values of a
/// credential, a counter or a length are never reconciled: one reader (a proxy, a log) could
/// take the other.
fn single<K: AsHeaderName>(headers: &HeaderMap, name: K) -> Result<Option<&[u8]>, BadHeader> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (value, None) => Ok(value.map(HeaderValue::as_bytes)),
        (_, Some(_)) => Err(BadHeader),
    }
}

/// The request's credentials, parsed from its headers.
struct Credentials {
    /// The bearer token.
    token: SessionToken,
    /// The request signature, if the request carries one.
    signature: Option<RequestSignature>,
}

/// Parses the bearer token and the signature headers (step (b) of the module docs); any
/// failure, a repeated header included, is `401`.
fn credentials(parts: &Parts) -> Result<Credentials, ErrorCode> {
    let unauthorized = |_: BadHeader| ErrorCode::Unauthorized;
    let headers = &parts.headers;
    let token = single(headers, AUTHORIZATION)
        .map_err(unauthorized)?
        .ok_or(ErrorCode::Unauthorized)
        .and_then(|value| bearer_token(value).map_err(unauthorized))?;
    let signature = request_signature(
        single(headers, REQUEST_COUNTER_HEADER).map_err(unauthorized)?,
        single(headers, REQUEST_SIGNATURE_HEADER).map_err(unauthorized)?,
    )
    .map_err(unauthorized)?;
    Ok(Credentials { token, signature })
}

/// The code of an authentication failure: `401` for every refusal, the logged code for a
/// storage or internal failure ([ADR 0028] item 5 "One answer").
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
fn refused(endpoint: Endpoint, e: &AuthError) -> ErrorCode {
    match e {
        AuthError::Storage(_) | AuthError::Internal(_) => auth_code(endpoint, e).code,
        _ => ErrorCode::Unauthorized,
    }
}

/// The header-only session check (step (c) of the module docs).
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
    if endpoint.session() == SessionNeed::NotRecovery && session.kind == SessionKind::Recovery {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(())
}

/// The `path_and_query` a `device-request` signature covers ([ADR 0028] item 5 "Signed
/// bytes"): the raw bytes of the request-target's path and, when a `?` is present, the `?` and
/// everything after it, as hyper parsed them off the request line. Nothing is decoded,
/// normalised or re-encoded: percent-encoding and its hex case, dot segments, `//`, a trailing
/// `?`, parameter order and duplicate parameters are verified exactly as sent. For an
/// absolute-form target (`POST http://host/path`) it is that target's path-and-query part; the
/// scheme and authority are not read, and neither is `Host`: the signed origin is the
/// configured one.
///
/// **The one exception: a fragment.** `http::Uri`, the type hyper parses the target into, cuts
/// it at the first `#`, and hyper does not expose the raw request line. So for a target sent as
/// `/path?query#fragment` this returns `/path?query`: the request routes and verifies as if the
/// `#` and everything after it had not been sent, and a signature made over the target with
/// its fragment fails. A fragment is not part of a request-target (RFC 9112 §3.2, RFC 9110
/// §7.1), [ADR 0028] tells clients to send origin-form only, and no `v1` client sends one. The
/// server ignores the dropped bytes everywhere, and the counter still stops a replay, so the
/// cut gives a sender nothing; it is stated here because "the bytes verified are the bytes
/// sent" does not hold for those bytes (`tests/http/signing.rs` pins both directions).
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
fn signed_target(parts: &Parts) -> &str {
    parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |p| p.as_str())
}

/// Authenticates the request's bearer token and, if present, its signature over the body
/// (step (f) of the module docs).
async fn authenticate(
    api: &Api,
    endpoint: Endpoint,
    parts: &Parts,
    credentials: &Credentials,
    body: &[u8],
    now: u64,
) -> Result<Session, ErrorCode> {
    let request = RequestParts {
        method: parts.method.as_str(),
        path_and_query: signed_target(parts),
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
    if endpoint.session() == SessionNeed::NotRecovery && session.kind == SessionKind::Recovery {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(session)
}

/// Waits up to [`LARGE_BODY_WAIT`] for a slot for a request with the upload limit (step (d) of
/// the module docs).
async fn large_body_slot(api: &Api) -> Result<SemaphorePermit<'_>, ErrorCode> {
    match tokio::time::timeout(LARGE_BODY_WAIT, api.large_bodies.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_closed)) => Err(ErrorCode::Internal),
        Err(_elapsed) => Err(ErrorCode::RateLimited),
    }
}

/// The rate-limit source of the request ([ADR 0028] item 11; threat model §7.6 "S"), from the
/// peer address and every `X-Forwarded-For` field line in order ([`client_address`]).
///
/// # Errors
/// `invalid_request` when the peer is a configured proxy and its `X-Forwarded-For` gives no
/// client address: the request is never counted against the proxy's own address.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
fn source(api: &Api, parts: &Parts) -> Result<Vec<u8>, ErrorCode> {
    let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
        return Ok(UNKNOWN_SOURCE.to_vec());
    };
    let forwarded: Vec<&[u8]> = parts
        .headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    client_address(peer.ip(), &forwarded, &api.trusted_proxies)
        .map(rate_limit_source)
        .map_err(|_| ErrorCode::InvalidRequest)
}

/// The module docs' steps for one request, from the `Rizzy-Client` check to the domain call.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per endpoint, in the order of the module docs' table"
)]
async fn handle(api: &Api, endpoint: Endpoint, request: Request) -> Result<Reply, Failure> {
    let (parts, body) = request.into_parts();
    // A repeated `Rizzy-Client` is malformed, and a malformed one is served normally in M1.
    let client = single(&parts.headers, CLIENT_HEADER).ok().flatten();
    if client_refused(client, &api.min_client_versions) {
        return Err(ErrorCode::ClientTooOld.into());
    }
    let source = source(api, &parts)?;
    let credentials = match endpoint.session() {
        SessionNeed::None => None,
        SessionNeed::Optional if !parts.headers.contains_key(AUTHORIZATION) => None,
        SessionNeed::Optional | SessionNeed::Required | SessionNeed::NotRecovery => {
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
    let ve = |e: VaultError| Failure::from(vault_code(endpoint, &e));
    // `session` is `Some` for every endpoint whose arm reads it (`SessionNeed` above).
    let need = || session.as_ref().ok_or(ErrorCode::Unauthorized);
    match endpoint {
        Endpoint::RegisterStart => json(
            &auth
                .register_start(&parse(&body)?, &source, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::RegisterFinish => {
            auth.register_finish(&parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::LoginStart => json(
            &auth
                .login_start(&mut rng, &parse(&body)?, &source, session.as_ref(), now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::LoginFinish => json(
            &auth
                .login_finish(&mut rng, &parse(&body)?, &source, session.as_ref(), now)
                .await
                .map_err(ae)?,
        ),
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
        Endpoint::ReregisterStart => json(
            &auth
                .reregister_start_request(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::CommitChange => {
            auth.commit_change_request(need()?, parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::SuspendDevice => json(
            &auth
                .suspend_device_request(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::UnsuspendDevice => {
            auth.unsuspend_device_request(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::RecoveryStart => json(
            &auth
                .recovery_start_request(&parse(&body)?, &source, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::RecoveryCancel => json(
            &auth
                .recovery_cancel_request(need()?, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::RecoveryComplete => json(
            &auth
                .recovery_complete_request(&mut rng, &parse(&body)?, &source, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::TotpEnrolStart => json(
            &auth
                .totp_enrol_start_request(&mut rng, need()?, now)
                .await
                .map_err(ae)?,
        ),
        Endpoint::TotpEnrolConfirm => {
            auth.totp_enrol_confirm_request(need()?, &parse(&body)?, now)
                .await
                .map_err(ae)?;
            Ok(Reply::Empty)
        }
        Endpoint::TotpDisable => {
            auth.totp_disable_request(need()?, &parse(&body)?, now)
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
            .heal(
                need()?.account_id,
                // ADR 0032 §3: only a device session names a healer that may repair a
                // lagging self-grant (healing step 3b).
                need().ok().and_then(|s| {
                    (s.kind == SessionKind::Device)
                        .then_some(s.device_id)
                        .flatten()
                }),
                &parse(&body)?,
                now,
            )
            .await
        {
            Ok(answer) => json(&answer),
            Err(HealingError::Refused(code)) => Err(code.into()),
            Err(HealingError::Failed(e)) => Err(ve(e)),
            Err(e) => Err(e.code().into()),
        },
    }
}

#[cfg(test)]
mod tests {
    //! The endpoint table (paths, methods, session needs, body limits), the status of every
    //! error code, `Retry-After`, the built-in minimum client versions and the signed
    //! request-target (ADR 0028 items 1, 3, 5, 7, 14). The flows behind a session run in
    //! `tests/http`.

    use std::collections::HashSet;

    use super::*;

    /// A match without a wildcard: adding a variant without listing it in
    /// [`Endpoint::ALL`] fails to compile here, and the length check below catches a
    /// variant missing from `ALL`.
    const fn listed(endpoint: Endpoint) -> bool {
        match endpoint {
            Endpoint::RegisterStart
            | Endpoint::RegisterFinish
            | Endpoint::LoginStart
            | Endpoint::LoginFinish
            | Endpoint::DeviceAuthStart
            | Endpoint::DeviceAuthFinish
            | Endpoint::AccountState
            | Endpoint::EnrolDevice
            | Endpoint::WebCertificate
            | Endpoint::DeviceGrants
            | Endpoint::AckDeviceGrants
            | Endpoint::PublishBundles
            | Endpoint::PublishAccountState
            | Endpoint::PublishGrants
            | Endpoint::ReregisterStart
            | Endpoint::CommitChange
            | Endpoint::SuspendDevice
            | Endpoint::UnsuspendDevice
            | Endpoint::RecoveryStart
            | Endpoint::RecoveryCancel
            | Endpoint::RecoveryComplete
            | Endpoint::TotpEnrolStart
            | Endpoint::TotpEnrolConfirm
            | Endpoint::TotpDisable
            | Endpoint::Upload
            | Endpoint::Fetch
            | Endpoint::Heal => true,
        }
    }

    #[test]
    fn all_is_complete_and_paths_unique() {
        assert_eq!(Endpoint::ALL.len(), 27);
        assert!(Endpoint::ALL.iter().all(|e| listed(*e)));
        let unique: HashSet<_> = Endpoint::ALL.iter().copied().map(Endpoint::path).collect();
        assert_eq!(unique.len(), Endpoint::ALL.len());
        for e in Endpoint::ALL {
            assert!(e.path().starts_with("/api/v1/"), "{e:?}");
        }
    }

    /// ADR 0028 item 1: the router's paths are the ones `rizzy-proto` gives every client.
    #[test]
    fn the_paths_are_the_shared_ones() {
        let served: HashSet<_> = Endpoint::ALL.iter().copied().map(Endpoint::path).collect();
        let shared: HashSet<_> = paths::ALL.into_iter().collect();
        assert_eq!(served, shared);
    }

    /// ADR 0028 item 3: the status of every code.
    #[test]
    fn statuses_follow_adr_0028() {
        for (code, expected) in [
            (ErrorCode::InvalidRequest, 400),
            (ErrorCode::ClientTooOld, 400),
            (ErrorCode::Unauthorized, 401),
            (ErrorCode::SecondFactorRequired, 401),
            (ErrorCode::FreshSessionRequired, 403),
            (ErrorCode::NotFound, 404),
            (ErrorCode::StateConflict, 409),
            (ErrorCode::StaleEpoch, 409),
            (ErrorCode::RecordConflict, 409),
            (ErrorCode::PrevSeqMismatch, 409),
            (ErrorCode::SetupRetired, 409),
            (ErrorCode::CredentialsStale, 409),
            (ErrorCode::ApiVersionGone, 410),
            (ErrorCode::PayloadTooLarge, 413),
            (ErrorCode::RateLimited, 429),
            (ErrorCode::Internal, 500),
            (ErrorCode::Unknown, 500),
        ] {
            assert_eq!(status(code).as_u16(), expected, "{code:?}");
        }
    }

    /// Every error answer is `{"error":"<code>"}` and nothing else; only a `429` carries
    /// `Retry-After`, and every `429` does.
    #[test]
    fn error_answers_are_uniform_and_a_429_carries_retry_after() {
        let plain = error_response(ErrorCode::Unauthorized, "x");
        assert_eq!(plain.status(), StatusCode::UNAUTHORIZED);
        assert!(plain.headers().get(RETRY_AFTER).is_none());
        assert!(plain.headers().get("www-authenticate").is_none());
        assert_eq!(
            plain.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let fallback = error_response(ErrorCode::RateLimited, "x");
        assert_eq!(fallback.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(fallback.headers().get(RETRY_AFTER).unwrap(), "10");

        let timed = failure_response(
            Failure {
                code: ErrorCode::RateLimited,
                retry_after_secs: Some(259_200),
            },
            "x",
        );
        assert_eq!(timed.headers().get(RETRY_AFTER).unwrap(), "259200");

        // A retry time on any other code is not sent.
        let other = failure_response(
            Failure {
                code: ErrorCode::InvalidRequest,
                retry_after_secs: Some(5),
            },
            "x",
        );
        assert!(other.headers().get(RETRY_AFTER).is_none());
    }

    /// Whole seconds, rounded up: a client that waits them is past the backoff.
    #[test]
    fn retry_after_rounds_up_to_whole_seconds() {
        for (ms, secs) in [
            (0, 1),
            (1, 1),
            (999, 1),
            (1_000, 1),
            (1_001, 2),
            (8_000, 8),
            (259_200_000, 259_200),
            (u64::MAX, u64::MAX / 1_000 + 1),
        ] {
            assert_eq!(retry_after_secs(ms), secs, "{ms}");
        }
        let limited = AuthError::RateLimited {
            retry_after_ms: Some(1_500),
        };
        assert_eq!(
            auth_code(Endpoint::LoginStart, &limited),
            Failure {
                code: ErrorCode::RateLimited,
                retry_after_secs: Some(2)
            }
        );
        let capped = AuthError::RateLimited {
            retry_after_ms: None,
        };
        assert_eq!(
            auth_code(Endpoint::WebCertificate, &capped).retry_after_secs,
            None
        );
    }

    /// ADR 0028 item 14: every built-in minimum names a known platform and a `SemVer` version,
    /// so a client at exactly the minimum is served and the list reaches `/api/meta` whole.
    #[test]
    fn built_in_minimums_are_well_formed() {
        let minimums = built_in_minimums();
        assert_eq!(minimums.len(), MIN_CLIENT_VERSIONS.len());
        for (platform, version) in MIN_CLIENT_VERSIONS {
            let value = format!("{platform}/{version}");
            assert!(
                super::super::headers::client_header(value.as_bytes()).is_ok(),
                "{value}"
            );
            assert!(
                !client_refused(Some(value.as_bytes()), &minimums),
                "{value}"
            );
        }
    }

    /// The signed target is the request-target's path and query, byte for byte; an
    /// absolute-form target gives its path-and-query part, and a fragment is cut off.
    #[test]
    fn the_signed_target_is_never_normalised() {
        for (target, signed) in [
            ("/api/v1/vault/fetch", "/api/v1/vault/fetch"),
            ("/api/v1/vault/fetch?", "/api/v1/vault/fetch?"),
            ("/p?a=1&a=2&a=1", "/p?a=1&a=2&a=1"),
            ("/p?q=%2f", "/p?q=%2f"),
            ("/p?q=%2F", "/p?q=%2F"),
            ("/a/./b", "/a/./b"),
            ("/a/../b", "/a/../b"),
            ("//a", "//a"),
            ("/a/", "/a/"),
            ("/%61", "/%61"),
            ("http://other.example/a/../b?x=%2f", "/a/../b?x=%2f"),
            ("https://vault.example.com:8443//a?", "//a?"),
            // The one exception: a fragment. `http::Uri` cuts the target at the first `#`, so
            // the fragment never reaches the signed bytes (see `signed_target`).
            ("/api/v1/account/state#frag", "/api/v1/account/state"),
            ("/api/v1/account/state?#x", "/api/v1/account/state?"),
            ("/api/v1/account/state?a=1#b?c", "/api/v1/account/state?a=1"),
            ("/a/./b#/../c", "/a/./b"),
            (
                "http://h.example/api/v1/account/state#f",
                "/api/v1/account/state",
            ),
        ] {
            let (parts, ()) = Request::builder()
                .uri(target)
                .body(())
                .unwrap()
                .into_parts();
            assert_eq!(signed_target(&parts), signed, "{target}");
        }
    }

    #[test]
    fn only_device_grants_is_get() {
        for e in Endpoint::ALL {
            let expected = if *e == Endpoint::DeviceGrants {
                HttpMethod::Get
            } else {
                HttpMethod::Post
            };
            assert_eq!(e.method(), expected, "{e:?}");
        }
    }

    #[test]
    fn recovery_only_session_refused_on_device_and_vault_rows() {
        for e in [
            Endpoint::SuspendDevice,
            Endpoint::UnsuspendDevice,
            Endpoint::RecoveryCancel,
            Endpoint::TotpEnrolStart,
            Endpoint::TotpEnrolConfirm,
            Endpoint::TotpDisable,
            Endpoint::Upload,
            Endpoint::Fetch,
            Endpoint::Heal,
        ] {
            assert_eq!(e.session(), SessionNeed::NotRecovery, "{e:?}");
        }
        // The recovery commit and re-registration take the recovery-only session; the domain
        // applies their rules (CRYPTO.md §11.9 step 5).
        assert_eq!(Endpoint::CommitChange.session(), SessionNeed::Required);
        assert_eq!(Endpoint::ReregisterStart.session(), SessionNeed::Required);
        for e in [Endpoint::RecoveryStart, Endpoint::RecoveryComplete] {
            assert_eq!(e.session(), SessionNeed::None, "{e:?}");
        }
    }

    #[test]
    fn body_limits() {
        let upload = 7 * BODY_LIMIT;
        for e in Endpoint::ALL {
            let expected = match e {
                Endpoint::Upload | Endpoint::Heal | Endpoint::CommitChange => upload,
                Endpoint::DeviceGrants | Endpoint::RecoveryCancel | Endpoint::TotpEnrolStart => 0,
                _ => BODY_LIMIT,
            };
            assert_eq!(e.body_limit(upload), expected, "{e:?}");
        }
    }

    /// ADR 0028 item 6: no route without a session has the upload limit, so an anonymous
    /// request never gets it, or a large-body slot. `login/*` takes a session only optionally
    /// and `recovery/complete` none, and both stay at 1 MiB.
    #[test]
    fn only_session_gated_endpoints_take_a_large_body() {
        let upload = 32 * BODY_LIMIT;
        for e in Endpoint::ALL {
            if e.body_limit(upload) > BODY_LIMIT {
                assert!(
                    matches!(
                        e.session(),
                        SessionNeed::Required | SessionNeed::NotRecovery
                    ),
                    "{e:?}"
                );
            }
        }
        for e in [
            Endpoint::LoginStart,
            Endpoint::LoginFinish,
            Endpoint::RecoveryComplete,
            Endpoint::RegisterFinish,
        ] {
            assert_eq!(e.body_limit(upload), BODY_LIMIT, "{e:?}");
        }
        assert_eq!(BODY_LIMIT, 1024 * 1024);
        assert_eq!(body_deadline(BODY_LIMIT), Duration::from_secs(46));
        assert_eq!(MAX_CONCURRENT_LARGE_BODIES, 8);
        assert_eq!(LARGE_BODY_WAIT, Duration::from_secs(10));
    }
}
