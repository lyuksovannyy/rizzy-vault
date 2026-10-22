// SPDX-License-Identifier: AGPL-3.0-only

//! Listing and ending sessions ([ADR 0075]; CRYPTO.md §5.10).
//!
//! | Method | Rule | Caller |
//! |---|---|---|
//! | [`AuthService::list_sessions`] | R1 | OPAQUE or device; no freshness |
//! | [`AuthService::end_current_session`] | R2 | any kind, no freshness |
//! | [`AuthService::end_session`] | R3 | a fresh OPAQUE session, or a device session of a usable durable device |
//! | [`AuthService::end_other_sessions`] | R4 | as R3 |
//!
//! - **Device sessions are never ended here** (§5): a device re-authenticates on its next
//!   request, so ending its session would only look like a logout. R3 refuses a device target
//!   with [`AuthError::InvalidRequest`], and R4 ends only OPAQUE and recovery-only sessions.
//!   Suspension ([`AuthService::suspend_device`]) is the force logout of a native device. A
//!   device session can still sign itself out with R2.
//! - **Atomicity** (R5): R2–R4 run in one write transaction under the account lock, and re-read
//!   the caller's session inside it, as [`AuthService::suspend_device`] does. A caller whose
//!   session ended concurrently gets [`AuthError::Unauthorized`], and an end serialises with a
//!   concurrent credential change.
//! - **No tombstone** (§6): the row is deleted. The ended token's next request gets
//!   [`AuthError::Unauthorized`] from [`AuthService::authenticate_request`], exactly as an
//!   unknown or expired token does.
//! - **Uniform answers** (§7.6 "I"): an unknown `session_id`, an expired one and another
//!   account's all get [`AuthError::NotFound`]; the lookup is always scoped to the caller's
//!   account.
//!
//! [ADR 0075]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0075-session-listing-and-ending.md

use rizzy_core::ids::SessionId;
use rizzy_proto::limits::MAX_SESSIONS_LISTED;
use rizzy_proto::session::{SessionKindView, SessionListResponse, SessionView};
use rizzy_proto::wire::{Id, List};
use rizzy_storage::{WriteTx, lock_account};

use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::session::{self, Session, SessionKind};
use crate::trust::AccountTrust;
use crate::{AuthService, over_limit};

impl SessionKind {
    /// The wire form of the kind.
    const fn view(self) -> SessionKindView {
        match self {
            Self::Opaque => SessionKindView::Opaque,
            Self::Device => SessionKindView::Device,
            Self::Recovery => SessionKindView::Recovery,
        }
    }
}

impl<V: VaultPort> AuthService<V> {
    /// R1: the account's unexpired sessions, newest first (`created_at_ms` descending, then
    /// `session_id` bytes ascending), at most [`MAX_SESSIONS_LISTED`], with `truncated` set when
    /// there are more and `current` set on the caller's row. Expired rows not yet swept are left
    /// out. No freshness is needed: this reads metadata of the caller's own account.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a recovery-only session (it covers the recovery commit
    /// only); storage errors.
    pub async fn list_sessions(
        &self,
        session: &Session,
        now_ms: u64,
    ) -> Result<SessionListResponse, AuthError> {
        if session.kind == SessionKind::Recovery {
            return Err(AuthError::Unauthorized);
        }
        let mut tx = self.db.begin_read().await?;
        let mut rows = session::list_account(
            tx.conn(),
            session.account_id,
            now_ms,
            MAX_SESSIONS_LISTED.saturating_add(1),
        )
        .await?;
        tx.finish().await?;
        let truncated = rows.len() > MAX_SESSIONS_LISTED;
        rows.truncate(MAX_SESSIONS_LISTED);
        let sessions = rows
            .into_iter()
            .map(|row| SessionView {
                session_id: Id::from_bytes(row.session_id.to_bytes()),
                kind: row.kind.view(),
                device_id: row.device_id.map(|d| Id::from_bytes(d.to_bytes())),
                created_at_ms: row.created_at_ms,
                expires_at_ms: row.expires_at_ms,
                current: row.session_id == session.session_id,
            })
            .collect();
        Ok(SessionListResponse {
            sessions: List::new(sessions).map_err(over_limit)?,
            truncated,
        })
    }

    /// R2, sign-out: ends the caller's own session, of any kind, with no freshness. A repeat
    /// with the same token gets [`AuthError::Unauthorized`], because the token no longer exists.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a session that has already ended; storage errors.
    pub async fn end_current_session(
        &self,
        session: &Session,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        if !session::end_own(tx.conn(), &session).await? {
            return Err(AuthError::Unauthorized);
        }
        tx.commit().await?;
        Ok(())
    }

    /// R3: ends one OPAQUE or recovery-only session of the caller's account. The caller's own
    /// session is ended like R2 ends it.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a recovery-only or ended caller;
    /// [`AuthError::FreshSessionRequired`] for an OPAQUE caller older than
    /// [`crate::config::FRESH_SESSION_MS`] or a device caller whose device is no longer usable;
    /// [`AuthError::NotFound`] for an id that is not an unexpired session of the account (an
    /// unknown, expired or other account's id, alike); [`AuthError::InvalidRequest`] for a
    /// device session (§5); storage errors.
    pub async fn end_session(
        &self,
        session: &Session,
        target: SessionId,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let (mut tx, caller) = self.session_ender(session, now_ms).await?;
        let account = caller.account_id;
        match session::kind_by_id(tx.conn(), account, target, now_ms).await? {
            None => return Err(AuthError::NotFound),
            Some(SessionKind::Device) => return Err(AuthError::InvalidRequest),
            Some(SessionKind::Opaque | SessionKind::Recovery) => {}
        }
        session::end_by_id(tx.conn(), account, target).await?;
        tx.commit().await?;
        Ok(())
    }

    /// R4: ends every OPAQUE and recovery-only session of the caller's account except the
    /// caller's, and no device session (§5). Succeeds when there is nothing to end.
    ///
    /// # Errors
    /// As [`AuthService::end_session`] for the caller; storage errors.
    pub async fn end_other_sessions(
        &self,
        session: &Session,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let (mut tx, caller) = self.session_ender(session, now_ms).await?;
        let account = caller.account_id;
        session::end_kind_except(tx.conn(), account, SessionKind::Opaque, &caller).await?;
        session::end_kind_except(tx.conn(), account, SessionKind::Recovery, &caller).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The caller rule of R3 and R4, inside the write transaction it opens under the account
    /// lock (R5): the caller's session re-read, and either a fresh OPAQUE session or a device
    /// session of a device that [`crate::trust::Devices::usable_durable`] accepts.
    async fn session_ender(
        &self,
        session: &Session,
        now_ms: u64,
    ) -> Result<(WriteTx, Session), AuthError> {
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let caller = session::reload(tx.conn(), session, now_ms).await?;
        match (caller.kind, caller.device_id) {
            (SessionKind::Recovery, _) => return Err(AuthError::Unauthorized),
            (SessionKind::Opaque, _) => caller.require_fresh_opaque(now_ms)?,
            (SessionKind::Device, device) => {
                let device = device.ok_or(AuthError::FreshSessionRequired)?;
                let trust = AccountTrust::load(tx.conn(), caller.account_id).await?;
                let devices = trust.devices(tx.conn()).await?;
                if devices.usable_durable(device, now_ms).is_none() {
                    return Err(AuthError::FreshSessionRequired);
                }
            }
        }
        Ok((tx, caller))
    }
}
