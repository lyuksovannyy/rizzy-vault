//! Server-side 2FA with TOTP (CRYPTO.md §5.10 "Server-side 2FA", §5.11, §11.15; INV-8).
//!
//! - **Secrets.** rizzy-vault issues them: 20 random bytes from the injected CSPRNG
//!   ([`TotpSecret::generate`]), sealed as `SERVER_TOTP_SECRET` under the current server data
//!   key with ctx `account_id ‖ u32 totp_credential_seq`, so a database writer cannot move one
//!   account's sealed secret into another's row. The secret itself goes back to the caller
//!   once, in a zeroizing [`TotpSecret`], for the otpauth URI; it is never stored in the clear
//!   or logged.
//! - **Enrolment is two steps.** [`AuthService::totp_enrol_start`] stores a pending enrolment
//!   (no accepted step yet); [`AuthService::totp_enrol_confirm`] checks a code from the user's
//!   authenticator against it, records the accepted step, and deletes every other enrolment.
//!   Only confirmed enrolments (with an accepted step) gate a login, so an abandoned enrolment
//!   never locks anyone out.
//! - **Verification** is `rizzy-core`'s [`TotpParams::verify`]: steps −1, 0, +1, compared in
//!   constant time, accepted only above the last accepted step, which is stored in the same
//!   transaction as the login.
//! - **`totp_credential_seq`** is one more than the highest held, counting from 1. After a
//!   removal it can repeat an earlier value; a database writer who could exploit that could
//!   delete the rows outright and switch 2FA off anyway, which the threat model leaves to the
//!   server's integrity (A2).
//! - **2FA gates server access only** (§5.10). It never enters key derivation, and recovery
//!   does not require it (ADR 0008 owner decision 2).

use rizzy_core::envelope::purpose::ServerTotpSecretCtx;
use rizzy_core::ids::AccountId;
use rizzy_core::rng::CryptoRng;
use rizzy_core::totp::{TotpParams, TotpSecret};
use rizzy_storage::{WriteTx, lock_account};

use crate::AuthService;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::ratelimit::{self, BucketKind, bucket};
use crate::session::{self, Session};
use crate::sql::{self, exec, fetch_all};

/// A new, unconfirmed TOTP enrolment: the secret for the user's authenticator, once.
///
/// `Debug` shows the sequence number only; the secret is wiped on drop.
pub struct TotpEnrolment {
    /// The enrolment's `totp_credential_seq`, to pass to [`AuthService::totp_enrol_confirm`].
    pub totp_credential_seq: u32,
    /// The secret, for the otpauth URI (`rizzy_core::totp::OtpAuthUri`) the client renders.
    pub secret: TotpSecret,
}

impl core::fmt::Debug for TotpEnrolment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TotpEnrolment")
            .field("totp_credential_seq", &self.totp_credential_seq)
            .finish_non_exhaustive()
    }
}

/// One stored TOTP enrolment.
pub(crate) struct Stored {
    /// Its `totp_credential_seq`.
    pub(crate) seq: u32,
    /// The data key it is sealed under.
    pub(crate) data_key_id: u32,
    /// The sealed secret.
    pub(crate) sealed: Vec<u8>,
    /// The last accepted time step; `None` while unconfirmed.
    pub(crate) last_step: Option<u64>,
}

/// Every TOTP enrolment of `account_id`, oldest first.
pub(crate) async fn list(
    tx: &mut WriteTx,
    account_id: AccountId,
) -> Result<Vec<Stored>, AuthError> {
    let rows: Vec<(i64, i64, Vec<u8>, Option<i64>)> = fetch_all!(
        tx.conn(),
        (i64, i64, Vec<u8>, Option<i64>),
        sql::TOTP_LIST,
        &account_id.as_bytes()[..]
    )?;
    rows.into_iter()
        .map(|(seq, key, sealed, step)| {
            Ok(Stored {
                seq: sql::sql_u32(seq, "totp_credential_seq")?,
                data_key_id: sql::sql_u32(key, "data_key_id")?,
                sealed,
                last_step: step
                    .map(|s| sql::sql_u64(s, "last_accepted_step"))
                    .transpose()?,
            })
        })
        .collect()
}

/// The current TOTP time step at `now_ms`, for the server's parameters (§11.15: 30 s, 6
/// digits, SHA-1).
fn current_step(now_ms: u64) -> u64 {
    TotpParams::DEFAULT.time_step(now_ms / 1000)
}

impl<V: VaultPort> AuthService<V> {
    /// Counts one TOTP check against the account's bucket, in `tx`.
    async fn hit_totp(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let key = bucket(BucketKind::Totp, &[account_id.as_bytes()]);
        ratelimit::hit(
            tx.conn(),
            &key,
            &self.config.rate_limits.totp_per_account,
            now_ms,
        )
        .await
    }

    /// Checks `code` against `stored` and records the accepted step. `Ok(false)` for a wrong,
    /// replayed or malformed code.
    async fn verify_stored(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        stored: &Stored,
        code: &str,
        now_ms: u64,
    ) -> Result<bool, AuthError> {
        let ctx = ServerTotpSecretCtx {
            account_id,
            totp_credential_seq: stored.seq,
        };
        let secret = self
            .secrets
            .data_key(stored.data_key_id)?
            .open_totp_secret(&ctx, &stored.sealed)
            .map_err(|_| AuthError::Internal("a sealed TOTP secret does not open"))?;
        let Ok(step) =
            TotpParams::DEFAULT.verify(&secret, code, current_step(now_ms), stored.last_step)
        else {
            return Ok(false);
        };
        exec!(
            tx.conn(),
            sql::TOTP_SET_STEP,
            &account_id.as_bytes()[..],
            i64::from(stored.seq),
            sql::u64_sql(step, "last_accepted_step")?,
        )?;
        Ok(true)
    }

    /// The second factor of a login whose KE3 verified (CRYPTO.md §11.2 step 5, §11.15), in the
    /// login's transaction: `true` when the account has no confirmed enrolment, or `code`
    /// matches one (its step is then stored).
    pub(crate) async fn check_second_factor(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        code: Option<&str>,
        now_ms: u64,
    ) -> Result<bool, AuthError> {
        let confirmed: Vec<Stored> = list(tx, account_id)
            .await?
            .into_iter()
            .filter(|s| s.last_step.is_some())
            .collect();
        if confirmed.is_empty() {
            return Ok(true);
        }
        let Some(code) = code else {
            return Ok(false);
        };
        self.hit_totp(tx, account_id, now_ms).await?;
        for stored in &confirmed {
            if self
                .verify_stored(tx, account_id, stored, code, now_ms)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Starts a TOTP enrolment over a fresh OPAQUE session (a security-relevant change needs a
    /// re-authentication, CRYPTO.md §11 "Replacing credentials" by analogy): draws a 20-byte
    /// secret, seals it under the current data key, and stores it unconfirmed, replacing any
    /// earlier unconfirmed enrolment.
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`]; [`AuthError::Unauthorized`] for an ended session;
    /// storage errors.
    pub async fn totp_enrol_start<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        session: &Session,
        now_ms: u64,
    ) -> Result<TotpEnrolment, AuthError> {
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        session.require_fresh_opaque(now_ms)?;
        let account = session.account_id;
        exec!(tx.conn(), sql::TOTP_DELETE_PENDING, &account.as_bytes()[..])?;
        let seq = list(&mut tx, account)
            .await?
            .iter()
            .map(|s| s.seq)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(AuthError::Internal("totp_credential_seq overflow"))?;
        let secret = TotpSecret::generate(rng);
        let key = self.secrets.current_data_key()?;
        let ctx = ServerTotpSecretCtx {
            account_id: account,
            totp_credential_seq: seq,
        };
        let sealed = key
            .seal_totp_secret(rng, &ctx, &secret)
            .map_err(|_| AuthError::Internal("sealing a TOTP secret failed"))?;
        exec!(
            tx.conn(),
            sql::TOTP_INSERT,
            &account.as_bytes()[..],
            i64::from(seq),
            i64::from(key.data_key_id()),
            &sealed[..],
            sql::u64_sql(now_ms, "created_at_ms")?,
        )?;
        tx.commit().await?;
        Ok(TotpEnrolment {
            totp_credential_seq: seq,
            secret,
        })
    }

    /// Confirms the pending enrolment `totp_credential_seq` with a code from the user's
    /// authenticator, over a fresh OPAQUE session. From then on it is the account's only TOTP
    /// credential and every login needs a code.
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`]; [`AuthError::NotFound`] when no such pending
    /// enrolment exists; [`AuthError::Unauthorized`] for a wrong code; storage errors.
    pub async fn totp_enrol_confirm(
        &self,
        session: &Session,
        totp_credential_seq: u32,
        code: &str,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        session.require_fresh_opaque(now_ms)?;
        let account = session.account_id;
        let pending = list(&mut tx, account)
            .await?
            .into_iter()
            .find(|s| s.seq == totp_credential_seq && s.last_step.is_none())
            .ok_or(AuthError::NotFound)?;
        // Commit the count on every failure, so a refused guess still counts.
        if let Err(e) = self.hit_totp(&mut tx, account, now_ms).await {
            tx.commit().await?;
            return Err(e);
        }
        if !self
            .verify_stored(&mut tx, account, &pending, code, now_ms)
            .await?
        {
            tx.commit().await?;
            return Err(AuthError::Unauthorized);
        }
        exec!(
            tx.conn(),
            sql::TOTP_DELETE_EXCEPT,
            &account.as_bytes()[..],
            i64::from(totp_credential_seq),
        )?;
        tx.commit().await?;
        Ok(())
    }

    /// Switches 2FA off over a fresh OPAQUE session and with a current code, and deletes every
    /// enrolment. (Losing the authenticator is the admin's logged 2FA reset, INV-69, M3.)
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`]; [`AuthError::Unauthorized`] for a wrong code or
    /// no confirmed enrolment; storage errors.
    pub async fn totp_disable(
        &self,
        session: &Session,
        code: &str,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        session.require_fresh_opaque(now_ms)?;
        let account = session.account_id;
        let confirmed: Vec<Stored> = list(&mut tx, account)
            .await?
            .into_iter()
            .filter(|s| s.last_step.is_some())
            .collect();
        if confirmed.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        // Commit the count on every failure, so a refused guess still counts.
        if let Err(e) = self.hit_totp(&mut tx, account, now_ms).await {
            tx.commit().await?;
            return Err(e);
        }
        let mut ok = false;
        for stored in &confirmed {
            if self
                .verify_stored(&mut tx, account, stored, code, now_ms)
                .await?
            {
                ok = true;
                break;
            }
        }
        if !ok {
            tx.commit().await?;
            return Err(AuthError::Unauthorized);
        }
        exec!(tx.conn(), sql::TOTP_DELETE_ALL, &account.as_bytes()[..])?;
        tx.commit().await?;
        Ok(())
    }
}
