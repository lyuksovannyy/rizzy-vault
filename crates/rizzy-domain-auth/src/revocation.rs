// SPDX-License-Identifier: AGPL-3.0-only

//! The revocation window ([ADR 0091] §2): a bounded, expiring, non-durable freeze of every
//! account write that could change what a revoker's commit is checked against.
//!
//! **State.** At most one `auth_revocation_windows` row per account (migration 0012), with the
//! revoking device R, when the window opened and when it expires. It is ephemeral: the backup
//! leaves it out, so a restore never revives a window. A window is **open** while
//! `now_ms < expires_at_ms`; an expired row counts as absent, and the next write that reads it
//! through [`gate`] deletes it.
//!
//! **Opening and renewing** (`devices/suspend`, [`open_or_renew`]): no open window inserts or
//! replaces the row with R and `now + REVOCATION_WINDOW_MS`; an open window of R moves its
//! expiry to `now + REVOCATION_WINDOW_MS`; an open window of another device refuses the suspend
//! with [`AuthError::RevocationPending`] before anything is suspended.
//!
//! **Closing** ([`close`]): the revocation commit (a `commit_change` that revokes at least one
//! device), a recovery commit, and a `devices/unsuspend` by R that leaves no suspended durable
//! device. Expiry closes it too, and lifts only the freeze: every suspension stays.
//!
//! **The freeze** ([`gate`]): while a window is open, every write of §2's left column from a
//! session whose `device_id` is not R is refused with `revocation_pending`. Each refused write
//! calls [`gate`] first, after `lock_account` and `session::reload`, so the check runs under the
//! account lock and nothing is written. The one check before it is the byte-identical repeat of
//! an applied `account/commit` or `devices/enrol` (CRYPTO.md §11 "Secrets before commit"). The
//! recovery commit is never frozen (INV-7), nor is any read, login or recovery step.
//!
//! The vault domain reads the window through its `DeviceDirectory` port ([`window`], on the
//! vault write transaction's connection, under the same account lock); `vault/upload`,
//! `vault/heal` and the three attachment writes refuse with its own `RevocationPending`.
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_proto::account::RevocationWindowNotice;
use rizzy_proto::wire::Id;
use rizzy_storage::Conn;

use crate::config::REVOCATION_WINDOW_MS;
use crate::error::AuthError;
use crate::session::Session;
use crate::sql::{self, exec, fetch_opt};
use crate::trust::reborrow;

/// An account's revocation window, as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationWindow {
    /// The revoking device R: the only device whose sessions may write while it is open.
    pub revoker: DeviceId,
    /// When the window was opened, ms since the Unix epoch.
    pub opened_at_ms: u64,
    /// When the window expires, ms since the Unix epoch: open while `now_ms < expires_at_ms`.
    pub expires_at_ms: u64,
}

impl RevocationWindow {
    /// Whether the window is open at `now_ms`.
    #[must_use]
    pub const fn is_open(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms
    }

    /// The advisory form an `AccountView` carries (§2 "What clients see").
    #[must_use]
    pub const fn notice(&self) -> RevocationWindowNotice {
        RevocationWindowNotice {
            revoker_device_id: Id::from_bytes(*self.revoker.as_bytes()),
            expires_at_ms: self.expires_at_ms,
        }
    }
}

/// The stored row of `account`, open or expired.
async fn stored(conn: Conn<'_>, account: AccountId) -> Result<Option<RevocationWindow>, AuthError> {
    let row: Option<(Vec<u8>, i64, i64)> = fetch_opt!(
        conn,
        (Vec<u8>, i64, i64),
        sql::REVOCATION_WINDOW_GET,
        &account.as_bytes()[..]
    )?;
    row.map(|(revoker, opened, expires)| {
        Ok(RevocationWindow {
            revoker: DeviceId::from_bytes(sql::id16(
                &revoker,
                "auth_revocation_windows.revoker_device_id",
            )?),
            opened_at_ms: sql::sql_u64(opened, "opened_at_ms")?,
            expires_at_ms: sql::sql_u64(expires, "expires_at_ms")?,
        })
    })
    .transpose()
}

/// The open revocation window of `account` at `now_ms`, read on `conn`; `None` while none is
/// open (an expired row counts as absent and is left in place). For reads and for the vault
/// domain's port; a write that should delete an expired row uses [`gate`].
///
/// # Errors
/// Storage errors; [`AuthError::Internal`] for a stored row of the wrong shape.
pub async fn window(
    conn: Conn<'_>,
    account: AccountId,
    now_ms: u64,
) -> Result<Option<RevocationWindow>, AuthError> {
    Ok(stored(conn, account).await?.filter(|w| w.is_open(now_ms)))
}

/// The open window of `account`, deleting an expired row ("the next write that reads it
/// deletes it"). Runs in a write transaction under the account lock.
async fn current(
    mut conn: Conn<'_>,
    account: AccountId,
    now_ms: u64,
) -> Result<Option<RevocationWindow>, AuthError> {
    match stored(reborrow(&mut conn), account).await? {
        Some(w) if w.is_open(now_ms) => Ok(Some(w)),
        Some(_) => {
            close(conn, account).await?;
            Ok(None)
        }
        None => Ok(None),
    }
}

/// The freeze for a writer that is `device` (the session's `device_id`, or the device of a
/// certificate-carrying device authentication).
///
/// # Errors
/// [`AuthError::RevocationPending`] while a window of another device is open; storage errors.
pub(crate) async fn gate_device(
    conn: Conn<'_>,
    account: AccountId,
    device: Option<DeviceId>,
    now_ms: u64,
) -> Result<(), AuthError> {
    match current(conn, account, now_ms).await? {
        Some(w) if device != Some(w.revoker) => Err(AuthError::RevocationPending),
        _ => Ok(()),
    }
}

/// The freeze of [ADR 0091] §2: refuses a write of the left column from a session whose
/// `device_id` is not the open window's revoker. Call it first in each refused write, after
/// `lock_account` and `session::reload`, on the write transaction's connection. An expired row
/// is deleted on the way.
///
/// # Errors
/// [`AuthError::RevocationPending`] while a window of another device is open; storage errors.
///
/// [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md
pub async fn gate(
    conn: Conn<'_>,
    account_id: AccountId,
    session: &Session,
    now_ms: u64,
) -> Result<(), AuthError> {
    gate_device(conn, account_id, session.device_id, now_ms).await
}

/// Opens or renews the window for `revoker` (§2 "Opening and renewing"), in the transaction of
/// a successful `devices/suspend`, before it suspends anything.
///
/// # Errors
/// [`AuthError::RevocationPending`] while a window of another device is open; storage errors.
pub(crate) async fn open_or_renew(
    mut conn: Conn<'_>,
    account: AccountId,
    revoker: DeviceId,
    now_ms: u64,
) -> Result<(), AuthError> {
    let opened_at_ms = match current(reborrow(&mut conn), account, now_ms).await? {
        Some(w) if w.revoker != revoker => return Err(AuthError::RevocationPending),
        Some(w) => w.opened_at_ms,
        None => now_ms,
    };
    let expires_at_ms = now_ms
        .checked_add(REVOCATION_WINDOW_MS)
        .ok_or(AuthError::InvalidRequest)?;
    exec!(
        conn,
        sql::REVOCATION_WINDOW_PUT,
        &account.as_bytes()[..],
        &revoker.as_bytes()[..],
        sql::u64_sql(opened_at_ms, "opened_at_ms")?,
        sql::u64_sql(expires_at_ms, "expires_at_ms")?,
    )?;
    Ok(())
}

/// Closes the window of `account` (§2 "Closing"), open or expired; a no-op without one.
///
/// # Errors
/// Storage errors.
pub(crate) async fn close(conn: Conn<'_>, account: AccountId) -> Result<(), AuthError> {
    exec!(conn, sql::REVOCATION_WINDOW_DELETE, &account.as_bytes()[..])?;
    Ok(())
}
