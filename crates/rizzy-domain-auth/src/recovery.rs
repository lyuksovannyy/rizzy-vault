//! Account recovery with the Emergency Kit (CRYPTO.md §11.9; ADR 0008 decisions 3–6, owner
//! decisions 2–3; INV-59).
//!
//! 1. [`AuthService::recovery_start`]: the login name and the recovery auth token. The server
//!    rate-limits, looks the name up, and compares `SHA-256(token)` with `H_rec` in constant
//!    time, comparing against a dummy hash when the name is unknown or has no code, so unknown
//!    names and wrong codes answer the same way (§5.9). A code whose `recovery_epoch` is not the
//!    signed state's current one, or whose state says recovery is off, is refused like a
//!    wrong code (INV-59). On success it opens a pending recovery whose waiting period is the
//!    configured one (default 72 h, 0 to 30 days).
//! 2. Any enrolled durable device with a device session cancels it:
//!    [`AuthService::recovery_cancel`].
//! 3. [`AuthService::recovery_complete`], after the wait: `E_rec` with its epochs, the account
//!    objects, and a recovery-only session with a 10-minute TTL. It may be repeated with the same
//!    token until the recovery commits ([`AuthService::commit_change`] over that session); only
//!    that commit replaces `H_rec` and closes the pending recovery.
//!
//! The wait is server-enforced; it defends against a thief holding the printed kit, not
//! against the server (§11.9 step 3). 2FA is not required (ADR 0008 owner decision 2).
//!
//! **Notification** of every enrolled device and the account email (§11.9 steps 2 and 6) has
//! no M1 channel (the `notify` role and mail are M3): [`RecoveryPending`] tells the server
//! which account to notify when a notifier exists.

use rizzy_core::ids::AccountId;
use rizzy_core::keys::RecoveryAuthToken;
use rizzy_core::normalize::LoginName;
use rizzy_core::rng::CryptoRng;
use rizzy_proto::account::AccountView;
use rizzy_proto::objects::AccountKeyRecoveryWrap;
use rizzy_proto::wire::{Bytes, Id, SessionToken};
use rizzy_storage::{WriteTx, lock_account};

use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::ratelimit::{self, BucketKind, bucket};
use crate::session::{self, Session, SessionKind};
use crate::sql::{self, exec, fetch_opt};
use crate::store::{self, RecoveryRow};
use crate::trust::AccountTrust;
use crate::view::{self, ViewScope};
use crate::{AuthService, over_limit};

/// The hash a dummy comparison runs against for an unknown name or an account without a code
/// (§5.9: "a dummy comparison runs when the name is unknown"). No token hashes to it in
/// practice; the comparison's result is discarded anyway.
const DUMMY_HASH: [u8; 32] = [0x5a; 32];

/// A pending recovery (CRYPTO.md §11.9 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPending {
    /// The account, for notifying its devices and email (not for the response: the caller
    /// already knows the name).
    pub account_id: AccountId,
    /// When `E_rec` becomes available, ms since the Unix epoch.
    pub available_at_ms: u64,
    /// Whether this call opened it (`false` for a repeat while it was already pending).
    pub opened: bool,
}

/// What [`AuthService::recovery_complete`] releases (CRYPTO.md §11.9 step 3).
pub struct RecoveryRelease {
    /// The bearer token of the recovery-only session (10 minutes). A secret.
    pub session_token: SessionToken,
    /// The account.
    pub account_id: Id,
    /// `E_rec` with the epochs of its context.
    pub recovery_wrap: AccountKeyRecoveryWrap,
    /// The account objects: the whole bundle chain, the state, the certificates and
    /// revocations, `E_id`, `ACCOUNT_SETTINGS` and the self-grants.
    ///
    /// The item-key wraps that §11.9 step 3 also lists are **not** released in this build.
    /// They serve only the rotation of §11.9 step 5, whose vault half no Accepted ADR shapes
    /// yet; how the recovery-only session reaches them is left open with that rotation's wire
    /// form. The server refuses the recovery-only session on every vault endpoint (Fetch
    /// included); opening one to it needs an Accepted ADR first.
    pub account: AccountView,
}

impl core::fmt::Debug for RecoveryRelease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryRelease")
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

/// The pending recovery of `account`: its `recovery_epoch`, opening time and availability.
pub(crate) async fn pending(
    tx: &mut WriteTx,
    account: AccountId,
) -> Result<Option<(u32, u64, u64)>, AuthError> {
    let row: Option<(i64, i64, i64)> = fetch_opt!(
        tx.conn(),
        (i64, i64, i64),
        sql::PENDING_RECOVERY_GET,
        &account.as_bytes()[..]
    )?;
    row.map(|(epoch, opened, available)| {
        Ok((
            sql::sql_u32(epoch, "recovery_epoch")?,
            sql::sql_u64(opened, "opened_at_ms")?,
            sql::sql_u64(available, "available_at_ms")?,
        ))
    })
    .transpose()
}

impl<V: VaultPort> AuthService<V> {
    /// Checks a recovery code in constant time; the same path for unknown names. Returns the
    /// account and its recovery row when the code is valid now.
    ///
    /// Takes the account lock right after the name lookup (on the all-zero id for an unknown
    /// name, so both paths lock), before the recovery row and the signed state are read: the
    /// check and the caller's writes then see one state, and a concurrent commit that replaces
    /// the code or switches recovery off (ADR 0011 "Transactions and concurrency") lands wholly
    /// before or after them.
    async fn check_recovery_code(
        &self,
        tx: &mut WriteTx,
        name: &LoginName,
        token: &[u8],
    ) -> Result<Option<(AccountId, RecoveryRow)>, AuthError> {
        let account = store::account_by_name(tx.conn(), name.as_str()).await?;
        // The recovery row is read on both paths (under an all-zero id for an unknown name, which
        // no client-chosen id is in practice), so both run the same queries.
        let lookup = account.unwrap_or(AccountId::from_bytes([0; 16]));
        lock_account(tx, lookup.as_bytes()).await?;
        let row = store::recovery(tx.conn(), lookup)
            .await?
            .filter(|_| account.is_some());
        let stored = row.as_ref().map_or(DUMMY_HASH, |r| r.h_rec);
        let matches = RecoveryAuthToken::matches_server_hash(token, &stored);
        let (Some(account), Some(row), true) = (account, row, matches) else {
            return Ok(None);
        };
        // The code matched: only now load the signed state (nothing that differs between
        // accounts runs for a wrong code). INV-59: the code must be the state's current one.
        let trust = AccountTrust::load(tx.conn(), account).await?;
        if !trust.state.recovery_enabled || trust.state.recovery_epoch != row.recovery_epoch {
            return Ok(None);
        }
        Ok(Some((account, row)))
    }

    /// Counts a recovery attempt against the per-(name, source) and per-name buckets.
    async fn hit_recovery(
        &self,
        name: &LoginName,
        source: &[u8],
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let limits = &self.config.rate_limits;
        let buckets = [
            (
                bucket(
                    BucketKind::RecoveryNameSource,
                    &[name.as_str().as_bytes(), source],
                ),
                limits.recovery_per_name_source,
            ),
            (
                bucket(BucketKind::RecoveryName, &[name.as_str().as_bytes()]),
                limits.recovery_per_name,
            ),
        ];
        ratelimit::hit_all(&self.db, &buckets, now_ms).await
    }

    /// Recovery start (CRYPTO.md §11.9 step 2): with a valid code, opens a pending recovery
    /// with the configured waiting period, or returns the one already pending.
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for a login name outside §2's rules;
    /// [`AuthError::RateLimited`]; [`AuthError::Unauthorized`] for an unknown name or a wrong,
    /// replaced or disabled code (one answer, §5.9); storage errors.
    pub async fn recovery_start(
        &self,
        login_name: &str,
        token: &[u8],
        source: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryPending, AuthError> {
        let name = LoginName::parse(login_name).map_err(|_| AuthError::InvalidRequest)?;
        self.hit_recovery(&name, source, now_ms).await?;
        let mut tx = self.db.begin_write().await?;
        let Some((account, row)) = self.check_recovery_code(&mut tx, &name, token).await? else {
            return Err(AuthError::Unauthorized);
        };
        if let Some((epoch, _, available_at_ms)) = pending(&mut tx, account).await? {
            if epoch == row.recovery_epoch {
                tx.commit().await?;
                return Ok(RecoveryPending {
                    account_id: account,
                    available_at_ms,
                    opened: false,
                });
            }
            // A pending recovery for a code since replaced: close it.
            exec!(
                tx.conn(),
                sql::PENDING_RECOVERY_DELETE,
                &account.as_bytes()[..]
            )?;
        }
        let available_at_ms = now_ms.saturating_add(self.config.recovery_wait_ms);
        exec!(
            tx.conn(),
            sql::PENDING_RECOVERY_INSERT,
            &account.as_bytes()[..],
            i64::from(row.recovery_epoch),
            sql::u64_sql(now_ms, "opened_at_ms")?,
            sql::u64_sql(available_at_ms, "available_at_ms")?,
        )?;
        tx.commit().await?;
        Ok(RecoveryPending {
            account_id: account,
            available_at_ms,
            opened: true,
        })
    }

    /// Cancels the account's pending recovery (CRYPTO.md §11.9 step 2: "Any enrolled device
    /// with a device-authenticated session can cancel"), and ends any recovery-only session
    /// already released for it. Returns whether one was pending.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] unless the session is a device session of a usable durable
    /// device; storage errors.
    pub async fn recovery_cancel(&self, session: &Session, now_ms: u64) -> Result<bool, AuthError> {
        let account = session.account_id;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        let trust = AccountTrust::load(tx.conn(), account).await?;
        let devices = trust.devices(tx.conn()).await?;
        let usable = session.kind == SessionKind::Device
            && session
                .device_id
                .is_some_and(|d| devices.usable_durable(d, now_ms).is_some());
        if !usable {
            return Err(AuthError::Unauthorized);
        }
        let deleted = exec!(
            tx.conn(),
            sql::PENDING_RECOVERY_DELETE,
            &account.as_bytes()[..]
        )?;
        session::end_kind(tx.conn(), account, SessionKind::Recovery).await?;
        tx.commit().await?;
        Ok(deleted > 0)
    }

    /// Recovery complete (CRYPTO.md §11.9 step 3): after the waiting period, with the same
    /// valid code, releases `E_rec`, the account objects and a recovery-only session.
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for a login name outside §2's rules;
    /// [`AuthError::RateLimited`]; [`AuthError::Unauthorized`] for an unknown name, a wrong
    /// code, or no pending recovery for this code; [`AuthError::RecoveryWaiting`] before the
    /// waiting period ends; storage errors.
    pub async fn recovery_complete<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        login_name: &str,
        token: &[u8],
        source: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryRelease, AuthError> {
        let name = LoginName::parse(login_name).map_err(|_| AuthError::InvalidRequest)?;
        self.hit_recovery(&name, source, now_ms).await?;
        let mut tx = self.db.begin_write().await?;
        let Some((account, row)) = self.check_recovery_code(&mut tx, &name, token).await? else {
            return Err(AuthError::Unauthorized);
        };
        match pending(&mut tx, account).await? {
            Some((epoch, _, available)) if epoch == row.recovery_epoch => {
                if now_ms < available {
                    return Err(AuthError::RecoveryWaiting);
                }
            }
            _ => return Err(AuthError::Unauthorized),
        }
        let trust = AccountTrust::load(tx.conn(), account).await?;
        let devices = trust.devices(tx.conn()).await?;
        let (token, _) = session::create(
            tx.conn(),
            rng,
            account,
            None,
            SessionKind::Recovery,
            now_ms,
            crate::config::RECOVERY_SESSION_TTL_MS,
        )
        .await?;
        let view = view::build(&self.vault, tx.conn(), &trust, &devices, ViewScope::Chain).await?;
        tx.commit().await?;
        Ok(RecoveryRelease {
            session_token: token,
            account_id: Id::from_bytes(account.to_bytes()),
            recovery_wrap: AccountKeyRecoveryWrap {
                account_key_epoch: trust.state.account_key_epoch,
                recovery_epoch: row.recovery_epoch,
                envelope: Bytes::new(row.e_rec).map_err(over_limit)?,
            },
            account: view,
        })
    }
}
