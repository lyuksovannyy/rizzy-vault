//! Sessions after authentication (CRYPTO.md §5.10; threat model INV-8, INV-52).
//!
//! - **Tokens.** Every session gets a random 32-byte bearer token from the injected CSPRNG.
//!   The database stores only `SHA-256(token)` (INV-8); the token itself goes back to the
//!   caller once, in a zeroizing [`SessionToken`], and is never logged.
//! - **Kinds** (the `session_kind` column, whose encoding is this crate's):
//!   [`SessionKind::Opaque`] after an OPAQUE login, [`SessionKind::Device`] after device
//!   authentication, [`SessionKind::Recovery`] for the recovery-only session of §11.9 step 3.
//! - **Freshness.** An OPAQUE session counts as fresh for [`FRESH_SESSION_MS`] after it was
//!   created (CRYPTO.md §11 "Replacing credentials").
//! - **Request signing** (§5.10, owner decision of 2026-09-25). A device-authenticated session
//!   accepts a request only with a valid `device-request` signature by the session's device
//!   key, rebuilt from the server's canonical origin, the session and the request as received,
//!   and only with a `request_counter` the session has not accepted before, within a sliding
//!   window of 64 ([`RequestWindow`]). The window is updated in the same transaction as the
//!   check, under the account lock, so two replicas cannot both accept one counter.
//!
//! How the token and the signing values travel in HTTP headers is not fixed by any Accepted ADR
//! (`rizzy-proto`'s `RequestSignature` docs); the server's HTTP layer extracts them and calls
//! [`crate::AuthService::authenticate_request`].

use core::fmt;

use rizzy_core::ids::{AccountId, DeviceId, SessionId};
use rizzy_core::rng::CryptoRng;
use rizzy_proto::wire::SessionToken;
use rizzy_storage::Conn;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::config::FRESH_SESSION_MS;
use crate::error::AuthError;
use crate::rules::RequestWindow;
use crate::sql::{self, exec, fetch_opt};

/// Which authentication a session came from. Stored as `session_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionKind {
    /// An OPAQUE login (CRYPTO.md §11.2 step 5, §11.4): a bearer token. When the login was a
    /// re-authentication from a device-authenticated session of the same account (INV-7's own
    /// bucket), the session is bound to that device.
    Opaque,
    /// Device authentication of a durable device (CRYPTO.md §5.10): every request signed.
    Device,
    /// The recovery-only session of CRYPTO.md §11.9 step 3, 10-minute TTL. It covers the
    /// recovery commit only.
    Recovery,
}

impl SessionKind {
    /// The stored `session_kind` value.
    pub(crate) const fn to_sql(self) -> i64 {
        match self {
            Self::Opaque => 1,
            Self::Device => 2,
            Self::Recovery => 3,
        }
    }

    /// Reads a stored `session_kind`.
    fn from_sql(value: i64) -> Result<Self, AuthError> {
        match value {
            1 => Ok(Self::Opaque),
            2 => Ok(Self::Device),
            3 => Ok(Self::Recovery),
            _ => Err(AuthError::Internal("unknown session_kind")),
        }
    }
}

/// An authenticated session, as loaded for one request. Holds no secret: the token is gone,
/// only its hash identifies the row.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    /// `SHA-256(token)`, the row's key.
    pub(crate) token_hash: [u8; 32],
    /// The 16-byte `session_id` of request signing (§5.10).
    pub session_id: SessionId,
    /// The account.
    pub account_id: AccountId,
    /// The device: the authenticated device of a [`SessionKind::Device`] session, or the
    /// device an OPAQUE re-authentication came from.
    pub device_id: Option<DeviceId>,
    /// The kind.
    pub kind: SessionKind,
    /// Creation time, ms since the Unix epoch.
    pub created_at_ms: u64,
    /// Expiry, ms since the Unix epoch.
    pub expires_at_ms: u64,
    /// The request-counter window.
    pub(crate) window: RequestWindow,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("kind", &self.kind)
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Whether this is an OPAQUE session created at most [`FRESH_SESSION_MS`] before `now_ms`
    /// (CRYPTO.md §11 "Replacing credentials", §11.5 step 1).
    #[must_use]
    pub fn is_fresh_opaque(&self, now_ms: u64) -> bool {
        self.kind == SessionKind::Opaque
            && now_ms >= self.created_at_ms
            && now_ms - self.created_at_ms <= FRESH_SESSION_MS
    }

    /// [`AuthError::FreshSessionRequired`] unless [`Session::is_fresh_opaque`].
    pub(crate) fn require_fresh_opaque(&self, now_ms: u64) -> Result<(), AuthError> {
        if self.is_fresh_opaque(now_ms) {
            Ok(())
        } else {
            Err(AuthError::FreshSessionRequired)
        }
    }
}

/// `SHA-256(token)`, the only form of a bearer token the database holds (CRYPTO.md §5.10,
/// §5.11 "Session tokens").
pub(crate) fn token_hash(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

/// A new session: a fresh token and `session_id` from the injected CSPRNG, stored by hash.
/// Returns the token (a secret, for the caller's response only) and the session.
pub(crate) async fn create<R: CryptoRng + ?Sized>(
    conn: Conn<'_>,
    rng: &mut R,
    account_id: AccountId,
    device_id: Option<DeviceId>,
    kind: SessionKind,
    now_ms: u64,
    ttl_ms: u64,
) -> Result<(SessionToken, Session), AuthError> {
    let mut token = Zeroizing::new([0u8; SessionToken::LEN]);
    rng.fill_bytes(token.as_mut_slice());
    let hash = token_hash(token.as_slice());
    let session_id = SessionId::generate(rng);
    let expires_at_ms = now_ms.saturating_add(ttl_ms);
    exec!(
        conn,
        sql::SESSION_INSERT,
        &hash[..],
        &session_id.as_bytes()[..],
        &account_id.as_bytes()[..],
        device_id.as_ref().map(|d| d.as_bytes().to_vec()),
        kind.to_sql(),
        sql::u64_sql(now_ms, "created_at_ms")?,
        sql::u64_sql(expires_at_ms, "expires_at_ms")?,
    )?;
    let session = Session {
        token_hash: hash,
        session_id,
        account_id,
        device_id,
        kind,
        created_at_ms: now_ms,
        expires_at_ms,
        window: RequestWindow::default(),
    };
    Ok((SessionToken::new(token), session))
}

/// The unexpired session whose token is `token`, or [`AuthError::Unauthorized`].
pub(crate) async fn load(conn: Conn<'_>, token: &[u8], now_ms: u64) -> Result<Session, AuthError> {
    load_by_hash(conn, token_hash(token), now_ms).await
}

/// `session` as stored now: still there and unexpired, with its current request window. A
/// flow that changes state calls it inside its own transaction, so a session ended since the
/// request was authenticated (a suspension, a password change) cannot act.
pub(crate) async fn reload(
    conn: Conn<'_>,
    session: &Session,
    now_ms: u64,
) -> Result<Session, AuthError> {
    load_by_hash(conn, session.token_hash, now_ms).await
}

/// The unexpired session whose token hashes to `hash`.
async fn load_by_hash(conn: Conn<'_>, hash: [u8; 32], now_ms: u64) -> Result<Session, AuthError> {
    type Row = (
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        i64,
        i64,
        i64,
        Option<i64>,
        i64,
    );
    let row: Option<Row> = fetch_opt!(conn, Row, sql::SESSION_GET, &hash[..])?;
    let Some((session_id, account_id, device_id, kind, created, expires, max, seen)) = row else {
        return Err(AuthError::Unauthorized);
    };
    let expires_at_ms = sql::sql_u64(expires, "expires_at_ms")?;
    if now_ms >= expires_at_ms {
        return Err(AuthError::Unauthorized);
    }
    Ok(Session {
        token_hash: hash,
        session_id: SessionId::from_bytes(sql::id16(&session_id, "session_id")?),
        account_id: AccountId::from_bytes(sql::id16(&account_id, "account_id")?),
        device_id: device_id
            .map(|d| sql::id16(&d, "device_id").map(DeviceId::from_bytes))
            .transpose()?,
        kind: SessionKind::from_sql(kind)?,
        created_at_ms: sql::sql_u64(created, "created_at_ms")?,
        expires_at_ms,
        window: RequestWindow {
            max: max
                .map(|m| sql::sql_u64(m, "request_counter_max"))
                .transpose()?,
            seen: u64::from_ne_bytes(seen.to_ne_bytes()),
        },
    })
}

/// Stores a session's request-counter window after an accepted request.
pub(crate) async fn store_window(
    conn: Conn<'_>,
    session: &Session,
    window: RequestWindow,
) -> Result<(), AuthError> {
    let max = window
        .max
        .map(|m| sql::u64_sql(m, "request_counter_max"))
        .transpose()?;
    // The bitmap is stored bit for bit in the signed 64-bit column.
    let seen = i64::from_ne_bytes(window.seen.to_ne_bytes());
    exec!(
        conn,
        sql::SESSION_WINDOW_UPDATE,
        &session.token_hash[..],
        max,
        seen
    )?;
    Ok(())
}

/// Ends every session of `account_id`.
pub(crate) async fn end_all(conn: Conn<'_>, account_id: AccountId) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::SESSIONS_DELETE_ACCOUNT,
        &account_id.as_bytes()[..]
    )?;
    Ok(())
}

/// Ends every session of one device of `account_id`.
pub(crate) async fn end_device(
    conn: Conn<'_>,
    account_id: AccountId,
    device_id: DeviceId,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::SESSIONS_DELETE_DEVICE,
        &account_id.as_bytes()[..],
        &device_id.as_bytes()[..]
    )?;
    Ok(())
}

/// Ends every session of one kind of `account_id`.
pub(crate) async fn end_kind(
    conn: Conn<'_>,
    account_id: AccountId,
    kind: SessionKind,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::SESSIONS_DELETE_KIND,
        &account_id.as_bytes()[..],
        kind.to_sql()
    )?;
    Ok(())
}

/// Ends every session of one kind of `account_id` except `keep`, the session doing the change.
pub(crate) async fn end_kind_except(
    conn: Conn<'_>,
    account_id: AccountId,
    kind: SessionKind,
    keep: &Session,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::SESSIONS_DELETE_KIND_EXCEPT,
        &account_id.as_bytes()[..],
        kind.to_sql(),
        &keep.token_hash[..]
    )?;
    Ok(())
}
