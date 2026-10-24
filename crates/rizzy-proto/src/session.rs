// SPDX-License-Identifier: AGPL-3.0-only

//! Listing and ending the account's sessions ([ADR 0075]; CRYPTO.md §5.10).
//!
//! | Endpoint | Request | Response | Caller |
//! |---|---|---|---|
//! | `sessions/list` (R1) | – | [`SessionListResponse`] | OPAQUE or device |
//! | `sessions/current/end` (R2) | – | empty success | any session |
//! | `sessions/end` (R3) | [`EndSessionRequest`] | empty success | fresh OPAQUE or device |
//! | `sessions/others/end` (R4) | – | empty success | fresh OPAQUE or device |
//!
//! - **What a [`SessionView`] carries:** the server's stored metadata of a session, and nothing
//!   derived from its token. No token, no hash, no request-counter window, no source address,
//!   user agent or "last used" time. A `session_id` is not a credential: it is a
//!   request-signing input, useless without the device key, and only the session's own account
//!   sees it.
//! - **Device sessions are never ended by `sessions/end` or `sessions/others/end`** ([ADR 0075]
//!   §5): a device re-authenticates on its next request, so ending its session achieves
//!   nothing. Suspension (`devices/suspend`) is the force logout of a native device.
//! - **The list is the server's word** (AR-9): a malicious server can hide sessions or ignore an
//!   end. A client never presents it as proof.
//!
//! [ADR 0075]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0075-session-listing-and-ending.md

use serde::{Deserialize, Serialize};

use crate::limits::MAX_SESSIONS_LISTED;
use crate::wire::{Id, List};

/// Body of `sessions/end`: the session to end, by its 16-byte `session_id` (R3). The id
/// travels in the body only, never in a path or a query (INV-52).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndSessionRequest {
    /// A `session_id` from [`SessionView::session_id`].
    pub session_id: Id,
}

/// The kind of a listed session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKindView {
    /// `"opaque"`: an OPAQUE login or re-authentication (a bearer token).
    Opaque,
    /// `"device"`: device-authenticated, every request signed.
    Device,
    /// `"recovery"`: the recovery-only session of CRYPTO.md §11.9 step 3.
    Recovery,
    /// A kind this build does not know; only ever produced by parsing a newer server's answer.
    /// The server never sends it.
    #[serde(other)]
    Unknown,
}

/// One live session of the account, as `sessions/list` reports it.
///
/// A response-only object: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    /// The session's 16-byte `session_id`, the handle of [`EndSessionRequest`].
    pub session_id: Id,
    /// The kind.
    pub kind: SessionKindView,
    /// The device of a device session, or the durable device an OPAQUE re-authentication was
    /// bound to. Absent for a plain OPAQUE login (the web vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Id>,
    /// Creation time, ms since the Unix epoch.
    pub created_at_ms: u64,
    /// Expiry, ms since the Unix epoch.
    pub expires_at_ms: u64,
    /// True for exactly one entry: the session that made this request.
    pub current: bool,
}

/// The answer to `sessions/list`: the account's unexpired sessions, newest first
/// (`created_at_ms` descending, then `session_id` bytes ascending).
///
/// A response type: unknown fields are ignored. More than [`MAX_SESSIONS_LISTED`] entries is a
/// parse error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionListResponse {
    /// At most [`MAX_SESSIONS_LISTED`] sessions.
    pub sessions: List<SessionView, MAX_SESSIONS_LISTED>,
    /// True when the account has more live sessions than are listed.
    #[serde(default)]
    pub truncated: bool,
}
