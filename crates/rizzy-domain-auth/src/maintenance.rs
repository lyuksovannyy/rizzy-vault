//! What `worker` runs for the auth domain (ADR 0010 §1 row `worker`, §5: "`worker` deletes
//! expired rows"; ADR 0012 §7 "End of the reconciliation epoch"; CRYPTO.md §5.11 "Rotation":
//! "`worker` re-seals TOTP rows under the account lock").
//!
//! Every expiry is also enforced where the row is read (a session, a challenge, a login state
//! or a rate-limit window past its time is refused or restarted), so a late or missed purge
//! never extends a lifetime; it only frees space.
//!
//! # Re-sealing after a data-key rotation
//!
//! `rizzy-vault secrets rotate --data-key` adds a new `server_data_key` and marks it current
//! ([`crate::ServerSecrets::rotate_data_key`]). From then on new rows are sealed under it, and
//! [`AuthService::reseal_totp_secrets`] moves the old ones: for each account that holds a TOTP
//! row naming another `data_key_id`, in one transaction under the account lock, it opens every
//! such row with the key the row names and seals the same secret under the current key, with
//! the same context (`account_id ‖ u32 totp_credential_seq`) and a fresh nonce from the
//! injected CSPRNG. The enrolment number and the last accepted step do not change, so a code
//! that was already used stays used. The secret exists in the clear only inside
//! `rizzy-core`'s zeroizing `TotpSecret`, between the open and the seal.
//!
//! Login states, the other sealed rows (§5.11), are not re-sealed: they live 60 s, and the ones
//! under an old key expire and are purged.
//!
//! An account whose row does not open, or names a data key the secrets file lacks, is counted
//! as a failure and skipped, and the next account is tried; its rows stay as they were. (The
//! startup check refuses a database that names a missing key, so this is reached only if a row
//! changed underneath the running server.) The old key is dropped from the secrets file only
//! once no row names it ([`crate::ServerSecrets::drop_unused_data_keys`]), so a skipped account
//! keeps its key in the file.

use rizzy_core::envelope::purpose::ServerTotpSecretCtx;
use rizzy_core::ids::AccountId;
use rizzy_core::rng::CryptoRng;
use rizzy_storage::{WriteTx, lock_account, meta};

use crate::AuthService;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::sql::{self, exec, fetch_all};
use crate::totp;

/// How many rows one purge deleted, per table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Purged {
    /// Expired sessions.
    pub sessions: u64,
    /// Expired sealed login states.
    pub login_states: u64,
    /// Expired device-auth challenges.
    pub challenges: u64,
    /// Expired rate-limit buckets.
    pub rate_limits: u64,
}

/// What one page of [`AuthService::reseal_totp_secrets`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resealed {
    /// TOTP rows now sealed under the current data key.
    pub rows: u64,
    /// Accounts skipped because a row of theirs could not be opened or sealed (module docs).
    /// Their rows are unchanged.
    pub failures: u64,
    /// The account to continue after, when this page was full: pass it as `after` to read the
    /// next page. `None` when no account is left.
    pub next: Option<AccountId>,
}

impl<V: VaultPort> AuthService<V> {
    /// Deletes the short-lived auth state expired at `now_ms` (ADR 0010 §5), in one
    /// transaction.
    ///
    /// # Errors
    /// Storage errors.
    pub async fn purge_expired(&self, now_ms: u64) -> Result<Purged, AuthError> {
        let now = sql::u64_sql(now_ms, "now_ms")?;
        let mut tx = self.db.begin_write().await?;
        let purged = Purged {
            sessions: exec!(tx.conn(), sql::SESSIONS_DELETE_EXPIRED, now)?,
            login_states: exec!(tx.conn(), sql::LOGIN_STATES_DELETE_EXPIRED, now)?,
            challenges: exec!(tx.conn(), sql::CHALLENGES_DELETE_EXPIRED, now)?,
            rate_limits: exec!(tx.conn(), sql::RATE_DELETE_EXPIRED, now)?,
        };
        tx.commit().await?;
        Ok(purged)
    }

    /// Ends every reconciliation epoch opened at least the admin-set limit before `now_ms`
    /// (ADR 0012 §7: "or after an admin-set limit (default 30 days)"). Returns how many ended.
    ///
    /// # Errors
    /// Storage errors.
    pub async fn end_stale_reconciliation_epochs(&self, now_ms: u64) -> Result<usize, AuthError> {
        let mut tx = self.db.begin_write().await?;
        let epochs = meta::reconciliation_epochs(tx.conn()).await?;
        let mut ended = 0;
        for (account, epoch) in epochs {
            let opened = u64::try_from(epoch.opened_at_ms).unwrap_or(0);
            if now_ms.saturating_sub(opened) >= self.config.reconciliation_limit_ms {
                rizzy_storage::lock_account(&mut tx, &account).await?;
                if meta::end_reconciliation_epoch(&mut tx, &account).await? {
                    ended += 1;
                }
            }
        }
        tx.commit().await?;
        Ok(ended)
    }

    /// Re-seals, under the current server data key, the TOTP secrets still sealed under another
    /// one (CRYPTO.md §5.11 "Rotation"; module docs): one page of at most `max_accounts`
    /// accounts, in account-id order, starting after `after` (`None` for the first page). Each
    /// account is its own transaction under the account lock.
    ///
    /// It is idempotent: a row already under the current key is not touched, and a run with
    /// nothing to do reads one page and writes nothing. `rng` draws the new envelopes' nonces.
    ///
    /// # Errors
    /// Storage errors, which end the page (the accounts done so far stay done). A row that
    /// does not open or names an unknown data key is not an error: its account is counted in
    /// [`Resealed::failures`].
    pub async fn reseal_totp_secrets<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        after: Option<AccountId>,
        max_accounts: u32,
    ) -> Result<Resealed, AuthError> {
        let current = i64::from(self.secrets.current_data_key_id());
        let cursor: &[u8] = after.as_ref().map_or(&[], |a| &a.as_bytes()[..]);
        let mut read = self.db.begin_read().await?;
        let accounts: Vec<(Vec<u8>,)> = fetch_all!(
            read.conn(),
            (Vec<u8>,),
            sql::TOTP_STALE_ACCOUNTS,
            current,
            cursor,
            i64::from(max_accounts)
        )?;
        read.finish().await?;

        let mut done = Resealed::default();
        let full = u64::try_from(accounts.len()).unwrap_or(u64::MAX) >= u64::from(max_accounts);
        let mut last = None;
        for (id,) in accounts {
            let account =
                AccountId::from_bytes(sql::id16(&id, "auth_totp_credentials.account_id")?);
            last = Some(account);
            let mut tx = self.db.begin_write().await?;
            lock_account(&mut tx, account.as_bytes()).await?;
            match self.reseal_account(&mut tx, rng, account).await {
                Ok(rows) => {
                    tx.commit().await?;
                    done.rows = done.rows.saturating_add(rows);
                }
                // The account's rows are inconsistent with the secrets: leave them, go on.
                Err(AuthError::Internal(_)) => {
                    tx.rollback().await?;
                    done.failures = done.failures.saturating_add(1);
                }
                Err(e) => {
                    // The storage error is the one to report; a failed rollback adds nothing.
                    let _rolled_back = tx.rollback().await;
                    return Err(e);
                }
            }
        }
        if full && max_accounts > 0 {
            done.next = last;
        }
        Ok(done)
    }

    /// Re-seals every TOTP row of `account` that names another data key than the current one,
    /// in `tx`, which holds the account's lock. Returns how many rows it re-sealed.
    async fn reseal_account<R: CryptoRng + Send + ?Sized>(
        &self,
        tx: &mut WriteTx,
        rng: &mut R,
        account: AccountId,
    ) -> Result<u64, AuthError> {
        let current = self.secrets.current_data_key()?;
        let mut rows = 0u64;
        for stored in totp::list(tx, account).await? {
            if stored.data_key_id == current.data_key_id() {
                continue;
            }
            let ctx = ServerTotpSecretCtx {
                account_id: account,
                totp_credential_seq: stored.seq,
            };
            let secret = self
                .secrets
                .data_key(stored.data_key_id)?
                .open_totp_secret(&ctx, &stored.sealed)
                .map_err(|_| AuthError::Internal("a sealed TOTP secret does not open"))?;
            let sealed = current
                .seal_totp_secret(rng, &ctx, &secret)
                .map_err(|_| AuthError::Internal("sealing a TOTP secret failed"))?;
            let changed = exec!(
                tx.conn(),
                sql::TOTP_RESEAL,
                &account.as_bytes()[..],
                i64::from(stored.seq),
                i64::from(current.data_key_id()),
                &sealed[..],
                i64::from(stored.data_key_id),
            )?;
            rows = rows.saturating_add(changed);
        }
        Ok(rows)
    }
}
