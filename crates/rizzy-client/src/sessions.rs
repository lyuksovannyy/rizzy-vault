// SPDX-License-Identifier: AGPL-3.0-only

//! Listing and ending sessions, the client half ([ADR 0075] §6, §8, §9; `rizzy_proto::session`).
//!
//! ```text
//! host: sessions/list ──SessionListResponse──► SessionList::from_response
//!   ──► rows (ListedSession: kind, device, times, current, endable)
//! ListedSession::end_request ──EndSessionRequest──► host (sessions/end)
//! host: sessions/others/end (no body) ──► OTHERS_ENDED_NOTICE
//! host: sessions/current/end (no body) ──► SignOut::from_status (204 ended, 401 already ended)
//! ```
//!
//! - **Device sessions are never ended here** (§5): a device re-authenticates on its next
//!   request, so ending its session would only look like a logout. [`ListedSession::endable`] is
//!   false for a device row, and [`ListedSession::end_request`] refuses one; suspension is the
//!   control for a native device.
//! - **The list is the server's word** (AR-9): a malicious server can hide sessions or ignore
//!   an end. [`SessionList::from_response`] checks only what a list must hold to be shown
//!   (unique ids, at most one current row), never that it is complete.
//! - **An ended session** answers `401` on its next request ([`ends_session_on_unauthorized`]
//!   says which requests count); a host locks and shows [`SESSION_ENDED_NOTICE`].
//!
//! [ADR 0075]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0075-session-listing-and-ending.md

use std::collections::HashSet;

use rizzy_core::ids::DeviceId;
use rizzy_proto::http::paths;
use rizzy_proto::session::{EndSessionRequest, SessionKindView, SessionListResponse};
use rizzy_proto::wire::Id;

use crate::error::ClientError;

/// The confirmation after ending other sessions (§8): ending a session is no cure for a leaked
/// password.
pub const OTHERS_ENDED_NOTICE: &str = "Other sessions ended. Anyone who knows your master \
     password and Secret Key can log in again: if you think someone does, change your password.";

/// The confirmation after ending one session (§8).
pub const SESSION_ENDED_BY_YOU_NOTICE: &str = "Session ended. Anyone who knows your master \
     password and Secret Key can log in again: if you think someone does, change your password.";

/// What the ended client shows (§6).
pub const SESSION_ENDED_NOTICE: &str = "This session has ended. Log in again.";

/// What a session row is, as §9 names the rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionRowKind {
    /// "Web or password login": an OPAQUE session bound to no device (the web vault).
    PasswordLogin,
    /// "Password re-check on device …": an OPAQUE re-authentication bound to a durable device.
    PasswordRecheck,
    /// "Device …": a device-authenticated session.
    Device,
    /// "Account recovery in progress": the recovery-only session. The real control is
    /// cancelling the recovery from an enrolled device.
    Recovery,
    /// A kind this build does not know (a newer server). Shown, never ended.
    Unknown,
}

impl SessionRowKind {
    /// A stable name for hosts: `password-login`, `password-recheck`, `device`, `recovery`
    /// or `unknown`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PasswordLogin => "password-login",
            Self::PasswordRecheck => "password-recheck",
            Self::Device => "device",
            Self::Recovery => "recovery",
            Self::Unknown => "unknown",
        }
    }
}

/// One listed session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedSession {
    /// The `session_id`.
    session_id: Id,
    /// The row kind.
    kind: SessionRowKind,
    /// The device of a device session or of a password re-check.
    device_id: Option<DeviceId>,
    /// Creation time, ms since the Unix epoch.
    created_at_ms: u64,
    /// Expiry, ms since the Unix epoch.
    expires_at_ms: u64,
    /// Whether this is the session that asked.
    current: bool,
}

impl ListedSession {
    /// The 16-byte `session_id`, for display (hosts print it in hex) and for
    /// [`ListedSession::end_request`]. Not a credential (§3).
    #[must_use]
    pub const fn session_id(&self) -> [u8; 16] {
        self.session_id.to_bytes()
    }

    /// The row kind.
    #[must_use]
    pub const fn kind(&self) -> SessionRowKind {
        self.kind
    }

    /// The device of a device session or of a password re-check.
    #[must_use]
    pub const fn device_id(&self) -> Option<DeviceId> {
        self.device_id
    }

    /// Creation time, ms since the Unix epoch (the server's word).
    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Expiry, ms since the Unix epoch (the server's word).
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Whether this is the session that made the list request.
    #[must_use]
    pub const fn current(&self) -> bool {
        self.current
    }

    /// Whether a client offers "End" on this row (§9): another session's password login,
    /// password re-check or recovery row. Never a device row (§5), never the current one (its
    /// end is sign-out), never an unknown kind.
    #[must_use]
    pub const fn endable(&self) -> bool {
        !self.current
            && matches!(
                self.kind,
                SessionRowKind::PasswordLogin
                    | SessionRowKind::PasswordRecheck
                    | SessionRowKind::Recovery
            )
    }

    /// The `sessions/end` body for this row.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a row that is not [`ListedSession::endable`]: the
    /// server would refuse a device row (`invalid_request`), and the current session signs out
    /// with `sessions/current/end` instead.
    pub fn end_request(&self) -> Result<EndSessionRequest, ClientError> {
        if !self.endable() {
            return Err(ClientError::InvalidInput);
        }
        Ok(EndSessionRequest {
            session_id: self.session_id,
        })
    }
}

/// The account's sessions, as one `sessions/list` answer gives them, newest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionList {
    /// The rows, in the server's order.
    sessions: Vec<ListedSession>,
    /// Whether the account has more live sessions than listed.
    truncated: bool,
}

impl SessionList {
    /// Reads a `sessions/list` answer.
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] for a list with a repeated `session_id`, more than
    /// one current row, or no current row although it is complete (the asking session is always
    /// live).
    pub fn from_response(answer: SessionListResponse) -> Result<Self, ClientError> {
        let truncated = answer.truncated;
        let mut seen = HashSet::new();
        let mut sessions = Vec::with_capacity(answer.sessions.len());
        for view in answer.sessions.into_vec() {
            if !seen.insert(view.session_id) {
                return Err(ClientError::InvalidServerResponse);
            }
            let kind = match (view.kind, view.device_id) {
                (SessionKindView::Opaque, None) => SessionRowKind::PasswordLogin,
                (SessionKindView::Opaque, Some(_)) => SessionRowKind::PasswordRecheck,
                (SessionKindView::Device, _) => SessionRowKind::Device,
                (SessionKindView::Recovery, _) => SessionRowKind::Recovery,
                (SessionKindView::Unknown, _) => SessionRowKind::Unknown,
            };
            sessions.push(ListedSession {
                session_id: view.session_id,
                kind,
                device_id: view.device_id.map(|d| DeviceId::from_bytes(d.to_bytes())),
                created_at_ms: view.created_at_ms,
                expires_at_ms: view.expires_at_ms,
                current: view.current,
            });
        }
        let current = sessions.iter().filter(|s| s.current).count();
        if current > 1 || (current == 0 && !truncated) {
            return Err(ClientError::InvalidServerResponse);
        }
        Ok(Self {
            sessions,
            truncated,
        })
    }

    /// The rows, newest first.
    #[must_use]
    pub fn sessions(&self) -> &[ListedSession] {
        &self.sessions
    }

    /// Whether the account has more live sessions than listed.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// How many listed rows `sessions/others/end` would end: the endable ones.
    #[must_use]
    pub fn others_endable(&self) -> usize {
        self.sessions.iter().filter(|s| s.endable()).count()
    }
}

/// The outcome of a sign-out (`sessions/current/end`, R2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignOut {
    /// `204`: the session ended now.
    Ended,
    /// `401`: the session had already ended (§2 R2: "Clients read `401` on this call as
    /// 'already ended'").
    AlreadyEnded,
}

impl SignOut {
    /// The outcome of a sign-out answer's status, or `None` for any other status (the host
    /// ignores it: sign-out is best effort, never retried, §6).
    #[must_use]
    pub const fn from_status(status: u16) -> Option<Self> {
        match status {
            204 => Some(Self::Ended),
            401 => Some(Self::AlreadyEnded),
            _ => None,
        }
    }
}

/// Whether a `401` answer to a request on `path` means the session has ended (§6): every
/// `/api/v1` request but `login/*`, `recovery/*` and the sign-out itself.
#[must_use]
pub fn ends_session_on_unauthorized(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/v1/") else {
        return false;
    };
    !(rest.starts_with("login/")
        || rest.starts_with("recovery/")
        || path == paths::SESSIONS_CURRENT_END)
}

#[cfg(test)]
mod tests {
    //! The row kinds of §9, the endable rule of §5 and §9, the checks on a list, the sign-out
    //! outcome and the `401` rule of §6.

    use rizzy_proto::session::SessionView;
    use rizzy_proto::wire::List;

    use super::*;

    fn view(byte: u8, kind: SessionKindView, device: bool, current: bool) -> SessionView {
        SessionView {
            session_id: Id::from_bytes([byte; 16]),
            kind,
            device_id: device.then(|| Id::from_bytes([0xd0; 16])),
            created_at_ms: u64::from(byte),
            expires_at_ms: 10_000,
            current,
        }
    }

    fn list(views: Vec<SessionView>, truncated: bool) -> Result<SessionList, ClientError> {
        SessionList::from_response(SessionListResponse {
            sessions: List::new(views).unwrap(),
            truncated,
        })
    }

    #[test]
    fn rows_are_classified_and_only_others_password_and_recovery_rows_are_endable() {
        let rows = list(
            vec![
                view(1, SessionKindView::Device, true, true),
                view(2, SessionKindView::Opaque, false, false),
                view(3, SessionKindView::Opaque, true, false),
                view(4, SessionKindView::Device, true, false),
                view(5, SessionKindView::Recovery, false, false),
                view(6, SessionKindView::Unknown, false, false),
            ],
            false,
        )
        .unwrap();
        let kinds: Vec<_> = rows.sessions().iter().map(ListedSession::kind).collect();
        assert_eq!(
            kinds,
            [
                SessionRowKind::Device,
                SessionRowKind::PasswordLogin,
                SessionRowKind::PasswordRecheck,
                SessionRowKind::Device,
                SessionRowKind::Recovery,
                SessionRowKind::Unknown,
            ]
        );
        let endable: Vec<_> = rows.sessions().iter().map(ListedSession::endable).collect();
        assert_eq!(endable, [false, true, true, false, true, false]);
        assert_eq!(rows.others_endable(), 3);
        for row in rows.sessions() {
            assert_eq!(row.end_request().is_ok(), row.endable());
        }
        let second = rows.sessions().get(1).unwrap();
        let request = second.end_request().unwrap();
        assert_eq!(request.session_id, Id::from_bytes([2; 16]));
        assert_eq!(second.session_id(), [2; 16]);
        assert_eq!(second.created_at_ms(), 2);
        assert_eq!(second.expires_at_ms(), 10_000);
        assert_eq!(
            rows.sessions().get(2).unwrap().device_id(),
            Some(DeviceId::from_bytes([0xd0; 16]))
        );
        // The current web session is not endable: it signs out instead.
        let web = list(vec![view(7, SessionKindView::Opaque, false, true)], false).unwrap();
        let only = web.sessions().first().unwrap();
        assert!(only.current() && !only.endable());
        assert_eq!(only.end_request(), Err(ClientError::InvalidInput));
    }

    #[test]
    fn a_list_must_name_the_asker_once_and_each_id_once() {
        let two_current = list(
            vec![
                view(1, SessionKindView::Opaque, false, true),
                view(2, SessionKindView::Opaque, false, true),
            ],
            false,
        );
        assert_eq!(two_current, Err(ClientError::InvalidServerResponse));
        let none = list(vec![view(1, SessionKindView::Opaque, false, false)], false);
        assert_eq!(none, Err(ClientError::InvalidServerResponse));
        // A truncated list may have cut the asker off.
        let cut = list(vec![view(1, SessionKindView::Opaque, false, false)], true).unwrap();
        assert!(cut.truncated());
        let repeated = list(
            vec![
                view(1, SessionKindView::Opaque, false, true),
                view(1, SessionKindView::Device, true, false),
            ],
            false,
        );
        assert_eq!(repeated, Err(ClientError::InvalidServerResponse));
    }

    #[test]
    fn sign_out_and_the_ended_session_rule() {
        assert_eq!(SignOut::from_status(204), Some(SignOut::Ended));
        assert_eq!(SignOut::from_status(401), Some(SignOut::AlreadyEnded));
        assert_eq!(SignOut::from_status(500), None);
        for path in [
            paths::ACCOUNT_STATE,
            paths::VAULT_FETCH,
            paths::SESSIONS_LIST,
            paths::SESSIONS_END,
            paths::SESSIONS_OTHERS_END,
            paths::TOTP_ENROL_START,
        ] {
            assert!(ends_session_on_unauthorized(path), "{path}");
        }
        for path in [
            paths::LOGIN_START,
            paths::LOGIN_FINISH,
            paths::RECOVERY_START,
            paths::RECOVERY_CANCEL,
            paths::SESSIONS_CURRENT_END,
            "/api/meta",
        ] {
            assert!(!ends_session_on_unauthorized(path), "{path}");
        }
    }
}
