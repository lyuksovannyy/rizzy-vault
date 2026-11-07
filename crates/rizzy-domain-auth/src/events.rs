// SPDX-License-Identifier: AGPL-3.0-only

//! The per-account security event log ([ADR 0090]; threat model INV-110, INV-69, INV-83).
//!
//! - **What is recorded.** One row per action of ADR 0090 §3, written by [`record`] in the
//!   transaction of the action, after its own writes and before the commit (§9): a failed insert
//!   fails the action. Refusals write nothing, except codes 3 and 21, which are written in the
//!   refusal's committed transaction (`AuthService::settle_single_use`).
//! - **What is not.** No source address, no user agent, no login name as typed, no token,
//!   token hash or `session_id`, no secret, no admin name (§4). Nothing before KE3 (§3): no
//!   entry depends on whether an unauthenticated request named a real account.
//! - **Cap and age** (§5). After each insert the account's rows of the same class beyond the
//!   [`EVENTS_PER_CLASS`] newest are deleted; the worker's [`AuthService::purge_expired`]
//!   deletes rows older than [`EVENT_RETENTION_MS`] and trims every (account, class) above the
//!   cap. Neither deletes an account's newest code 1 or 24 row, the wait in force that
//!   [`AuthService::check_recovery_wait`] reads.
//! - **Ids.** `event_id` comes from the server's CSPRNG through [`EventIds`], injected into
//!   [`AuthService::new`] (this crate depends on no OS randomness source).
//!
//! [ADR 0090]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0090-per-account-security-event-log.md

use std::fmt;
use std::sync::Arc;

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_proto::limits::{
    ALERT_WINDOW_MS, DEFAULT_SECURITY_EVENTS_LISTED, MAX_SECURITY_EVENTS_LISTED,
};
use rizzy_proto::security_event::{
    SecurityAlertSummary, SecurityEventActor, SecurityEventActorKind, SecurityEventClass,
    SecurityEventKind, SecurityEventListRequest, SecurityEventListResponse, SecurityEventView,
};
use rizzy_proto::webauthn::WebauthnLabel;
use rizzy_proto::wire::{Id, List};
use rizzy_storage::{Conn, WriteTx};

use crate::AuthService;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::session::{Session, SessionKind};
use crate::sql::{self, exec, fetch_all, fetch_opt};
use crate::trust::reborrow;

/// Rows kept per account and class (ADR 0090 §5).
pub const EVENTS_PER_CLASS: u64 = 500;

/// How long a row is kept (ADR 0090 §5): 365 days.
pub const EVENT_RETENTION_MS: u64 = 365 * 86_400_000;

/// The highest kind code this build knows: rows of a newer release are skipped (§7).
const MAX_KNOWN_KIND: i64 = 27;

/// The source of `event_id`s: 16 fresh bytes of the server's CSPRNG on every call (ADR 0090
/// §4).
#[derive(Clone)]
pub struct EventIds(Arc<dyn Fn() -> [u8; 16] + Send + Sync>);

impl EventIds {
    /// Wraps `next`, which must return 16 fresh bytes of a CSPRNG on every call.
    #[must_use]
    pub fn new(next: impl Fn() -> [u8; 16] + Send + Sync + 'static) -> Self {
        Self(Arc::new(next))
    }

    /// A fresh id.
    fn next(&self) -> [u8; 16] {
        (self.0)()
    }
}

impl fmt::Debug for EventIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventIds")
    }
}

/// Who acted (ADR 0090 §4 `actor_kind` and `actor_device_id`; `actor_admin_id` is written by
/// the admin paths, which land with their ADRs, §14 step 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Actor {
    /// The kind.
    kind: SecurityEventActorKind,
    /// The acting durable device.
    device: Option<DeviceId>,
}

impl Actor {
    /// An anonymous request that presented the recovery code (codes 13, 15).
    pub(crate) const RECOVERY_CODE: Self = Self {
        kind: SecurityEventActorKind::RecoveryCode,
        device: None,
    };

    /// The server on its own (code 24 at start, §6 point 2).
    pub(crate) const SERVER: Self = Self {
        kind: SecurityEventActorKind::Server,
        device: None,
    };

    /// The event is the sign-in itself (codes 2, 3, 21); `device` is the durable device a
    /// re-authentication is bound to.
    pub(crate) const fn sign_in(device: Option<DeviceId>) -> Self {
        Self {
            kind: SecurityEventActorKind::SignIn,
            device,
        }
    }

    /// A device session of `device` (a device authentication that carried its certificate).
    pub(crate) const fn device(device: DeviceId) -> Self {
        Self {
            kind: SecurityEventActorKind::DeviceSession,
            device: Some(device),
        }
    }

    /// "Actor of the request" (§3): the session's kind, with its bound or authenticated device.
    pub(crate) const fn of(session: &Session) -> Self {
        match session.kind {
            SessionKind::Opaque => Self {
                kind: SecurityEventActorKind::OpaqueSession,
                device: session.device_id,
            },
            SessionKind::Device => Self {
                kind: SecurityEventActorKind::DeviceSession,
                device: session.device_id,
            },
            SessionKind::Recovery => Self {
                kind: SecurityEventActorKind::RecoverySession,
                device: None,
            },
        }
    }
}

/// One entry to record: a kind of §3, its actor and the fields §3 names for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Event<'a> {
    /// The kind.
    kind: SecurityEventKind,
    /// Who acted.
    actor: Actor,
    /// The device the action was about.
    subject_device: Option<DeviceId>,
    /// A security key's label.
    label: Option<&'a str>,
    /// The value before.
    value_old: Option<u64>,
    /// The value after.
    value_new: Option<u64>,
    /// The `state_seq` an `account-state` commit produced.
    state_seq: Option<u64>,
}

impl<'a> Event<'a> {
    /// An entry of `kind` by `actor` with no other field.
    pub(crate) const fn new(kind: SecurityEventKind, actor: Actor) -> Self {
        Self {
            kind,
            actor,
            subject_device: None,
            label: None,
            value_old: None,
            value_new: None,
            state_seq: None,
        }
    }

    /// Sets `subject_device_id`.
    pub(crate) const fn subject(mut self, device: Option<DeviceId>) -> Self {
        self.subject_device = device;
        self
    }

    /// Sets `label`.
    pub(crate) const fn label(mut self, label: &'a str) -> Self {
        self.label = Some(label);
        self
    }

    /// Sets `value_old`.
    pub(crate) const fn old(mut self, value: Option<u64>) -> Self {
        self.value_old = value;
        self
    }

    /// Sets `value_new`.
    pub(crate) const fn value(mut self, value: u64) -> Self {
        self.value_new = Some(value);
        self
    }

    /// Sets `state_seq`.
    pub(crate) const fn seq(mut self, state_seq: u64) -> Self {
        self.state_seq = Some(state_seq);
        self
    }
}

/// The stored code of a known kind, class or actor kind.
fn code<T: Into<i64>>(value: Option<T>, what: &'static str) -> Result<i64, AuthError> {
    value.map(Into::into).ok_or(AuthError::Internal(what))
}

/// An optional `u64` as an SQL integer.
fn opt_sql(value: Option<u64>, what: &'static str) -> Result<Option<i64>, AuthError> {
    value.map(|v| sql::u64_sql(v, what)).transpose()
}

/// Inserts `event` for `account` at `now_ms`, then trims the account's rows of its class to
/// [`EVENTS_PER_CLASS`] (§5). Runs in the caller's transaction, under the account lock it holds.
///
/// # Errors
/// Storage errors; the caller's action then fails and rolls back (§9).
pub(crate) async fn record(
    tx: &mut WriteTx,
    ids: &EventIds,
    account: AccountId,
    now_ms: u64,
    event: Event<'_>,
) -> Result<(), AuthError> {
    let class = code(
        event.kind.class(event.value_old, event.value_new).code(),
        "event class",
    )?;
    insert(tx.conn(), ids, account, now_ms, &event, class).await?;
    let offset = sql::u64_sql(EVENTS_PER_CLASS - 1, "event cap")?;
    exec!(
        tx.conn(),
        sql::SECURITY_EVENT_TRIM,
        &account.as_bytes()[..],
        class,
        offset
    )?;
    Ok(())
}

/// The insert of [`record`], without the trim (the bulk path of §6).
async fn insert(
    conn: Conn<'_>,
    ids: &EventIds,
    account: AccountId,
    now_ms: u64,
    event: &Event<'_>,
    class: i64,
) -> Result<(), AuthError> {
    let event_id = ids.next();
    exec!(
        conn,
        sql::SECURITY_EVENT_INSERT,
        &event_id[..],
        &account.as_bytes()[..],
        sql::u64_sql(now_ms, "now_ms")?,
        code(event.kind.code(), "event kind")?,
        class,
        code(event.actor.kind.code(), "event actor kind")?,
        event.actor.device.as_ref().map(|d| &d.as_bytes()[..]),
        None::<&[u8]>,
        event.subject_device.as_ref().map(|d| &d.as_bytes()[..]),
        event.label,
        opt_sql(event.value_old, "value_old")?,
        opt_sql(event.value_new, "value_new")?,
        opt_sql(event.state_seq, "state_seq")?,
    )?;
    Ok(())
}

/// The age purge and the bulk trim of §5, in the worker's purge transaction. Returns the
/// number of rows deleted.
pub(crate) async fn purge(tx: &mut WriteTx, now_ms: u64) -> Result<u64, AuthError> {
    let cutoff = sql::u64_sql(now_ms.saturating_sub(EVENT_RETENTION_MS), "event cutoff")?;
    let mut deleted = exec!(tx.conn(), sql::SECURITY_EVENTS_PURGE_AGE, cutoff)?;
    let cap = sql::u64_sql(EVENTS_PER_CLASS, "event cap")?;
    let over = fetch_all!(
        tx.conn(),
        (Vec<u8>, i64),
        sql::SECURITY_EVENTS_OVER_CAP,
        cap
    )?;
    let offset = sql::u64_sql(EVENTS_PER_CLASS - 1, "event cap")?;
    for (account, class) in over {
        let trimmed = exec!(
            tx.conn(),
            sql::SECURITY_EVENT_TRIM,
            &account[..],
            class,
            offset
        )?;
        deleted = deleted.saturating_add(trimmed);
    }
    Ok(deleted)
}

/// One stored row, as [`sql::SECURITY_EVENTS_PAGE`] reads it.
type Row = (
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

/// A stored 16-byte id as a wire id.
fn wire_id(bytes: &[u8], what: &'static str) -> Result<Id, AuthError> {
    Ok(Id::from_bytes(sql::id16(bytes, what)?))
}

/// An optional stored `u64`.
fn opt_u64(value: Option<i64>, what: &'static str) -> Result<Option<u64>, AuthError> {
    value.map(|v| sql::sql_u64(v, what)).transpose()
}

/// A stored row as its view, `None` for a kind, class or actor kind this build does not know.
fn view(row: Row) -> Result<Option<SecurityEventView>, AuthError> {
    let (event_id, at_ms, kind, class, actor, actor_device, subject, label, old, new, seq) = row;
    let kind = u16::try_from(kind)
        .ok()
        .and_then(SecurityEventKind::from_code);
    let class = u8::try_from(class)
        .ok()
        .and_then(SecurityEventClass::from_code);
    let actor = u8::try_from(actor)
        .ok()
        .and_then(SecurityEventActorKind::from_code);
    let (Some(kind), Some(class), Some(actor)) = (kind, class, actor) else {
        return Ok(None);
    };
    let label = label
        .map(WebauthnLabel::new)
        .transpose()
        .map_err(|_| AuthError::Internal("stored event label"))?;
    Ok(Some(SecurityEventView {
        event_id: wire_id(&event_id, "event_id")?,
        at_ms: sql::sql_u64(at_ms, "at_ms")?,
        kind,
        class,
        actor: SecurityEventActor {
            kind: actor,
            device_id: actor_device
                .map(|d| wire_id(&d, "actor_device_id"))
                .transpose()?,
        },
        subject_device_id: subject
            .map(|d| wire_id(&d, "subject_device_id"))
            .transpose()?,
        label,
        value_old: opt_u64(old, "value_old")?,
        value_new: opt_u64(new, "value_new")?,
        state_seq: opt_u64(seq, "state_seq")?,
    }))
}

/// The alert summary of `account` at `now_ms` (§7): alert-class rows younger than
/// [`ALERT_WINDOW_MS`], `None` when there are none.
pub(crate) async fn summary(
    mut conn: Conn<'_>,
    account: AccountId,
    now_ms: u64,
) -> Result<Option<SecurityAlertSummary>, AuthError> {
    let since = sql::u64_sql(now_ms.saturating_sub(ALERT_WINDOW_MS), "alert window")?;
    let account = &account.as_bytes()[..];
    let newest = fetch_opt!(
        reborrow(&mut conn),
        (Vec<u8>, i64, i64),
        sql::SECURITY_ALERTS_NEWEST,
        account,
        MAX_KNOWN_KIND,
        since
    )?;
    let Some((event_id, at_ms, kind)) = newest else {
        return Ok(None);
    };
    let count = fetch_opt!(
        conn,
        (i64,),
        sql::SECURITY_ALERTS_COUNT,
        account,
        MAX_KNOWN_KIND,
        since
    )?
    .map_or(0, |(n,)| n);
    Ok(Some(SecurityAlertSummary {
        count: u32::try_from(count).unwrap_or(u32::MAX),
        newest_event_id: wire_id(&event_id, "event_id")?,
        newest_at_ms: sql::sql_u64(at_ms, "at_ms")?,
        newest_kind: u16::try_from(kind)
            .ok()
            .and_then(SecurityEventKind::from_code)
            .ok_or(AuthError::Internal("stored event kind"))?,
    }))
}

impl<V: VaultPort> AuthService<V> {
    /// `security-events/list` (ADR 0090 §7): the caller's account's entries strictly below
    /// `req.before`, newest first, at most `req.limit` (default
    /// [`DEFAULT_SECURITY_EVENTS_LISTED`]), with `more` set when older ones exist. The account
    /// comes from the session; no request field names one.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a recovery-only session (ADR 0028 item 6(c));
    /// [`AuthError::InvalidRequest`] for a `limit` of 0 or above
    /// [`MAX_SECURITY_EVENTS_LISTED`] (the parser refuses those already); storage errors.
    pub async fn list_security_events(
        &self,
        session: &Session,
        req: &SecurityEventListRequest,
    ) -> Result<SecurityEventListResponse, AuthError> {
        if session.kind == SessionKind::Recovery {
            return Err(AuthError::Unauthorized);
        }
        let limit = match req.limit {
            None => DEFAULT_SECURITY_EVENTS_LISTED,
            Some(n) => usize::try_from(n)
                .ok()
                .filter(|n| (1..=MAX_SECURITY_EVENTS_LISTED).contains(n))
                .ok_or(AuthError::InvalidRequest)?,
        };
        let fetch = i64::try_from(limit.saturating_add(1))
            .map_err(|_| AuthError::Internal("event page size"))?;
        let account = &session.account_id.as_bytes()[..];
        let mut tx = self.db.begin_read().await?;
        let rows = match &req.before {
            None => fetch_all!(
                tx.conn(),
                Row,
                sql::SECURITY_EVENTS_PAGE,
                account,
                MAX_KNOWN_KIND,
                fetch
            )?,
            Some(cursor) => fetch_all!(
                tx.conn(),
                Row,
                sql::SECURITY_EVENTS_PAGE_BEFORE,
                account,
                MAX_KNOWN_KIND,
                fetch,
                sql::u64_sql(cursor.at_ms, "cursor at_ms")?,
                &cursor.event_id.as_bytes()[..]
            )?,
        };
        tx.finish().await?;
        let more = rows.len() > limit;
        let mut events = Vec::with_capacity(rows.len().min(limit));
        for row in rows.into_iter().take(limit) {
            if let Some(event) = view(row)? {
                events.push(event);
            }
        }
        Ok(SecurityEventListResponse {
            events: List::new(events).map_err(|_| AuthError::Internal("event page"))?,
            more,
        })
    }

    /// The start-up check of the recovery wait (ADR 0090 §6 point 2), run by the `api` role
    /// after migrations and before its listener accepts: in one transaction, a code 24 row by
    /// the server for every account whose newest code 1 or 24 row states another wait than
    /// `recovery_wait_ms`, or that has none (`value_old` then `NULL`). Takes no account lock
    /// and does not trim (the worker does). Returns the number of rows written.
    ///
    /// # Errors
    /// Storage errors: the server then refuses to start, so a change of the wait cannot take
    /// effect unlogged.
    pub async fn check_recovery_wait(&self, now_ms: u64) -> Result<u64, AuthError> {
        let wait = self.config.recovery_wait_ms;
        let mut tx = self.db.begin_write().await?;
        let accounts = fetch_all!(tx.conn(), (Vec<u8>, Option<i64>), sql::SECURITY_WAIT_ROWS)?;
        let mut written = 0_u64;
        for (account, stated) in accounts {
            let stated = opt_u64(stated, "stated wait")?;
            if stated == Some(wait) {
                continue;
            }
            let account = AccountId::from_bytes(sql::id16(&account, "account id")?);
            let event = Event::new(SecurityEventKind::RecoveryWaitChanged, Actor::SERVER)
                .old(stated)
                .value(wait);
            let class = code(
                event.kind.class(event.value_old, event.value_new).code(),
                "event class",
            )?;
            insert(tx.conn(), &self.event_ids, account, now_ms, &event, class).await?;
            written = written.saturating_add(1);
        }
        tx.commit().await?;
        Ok(written)
    }
}
