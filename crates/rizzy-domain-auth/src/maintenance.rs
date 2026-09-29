//! What `worker` runs for the auth domain (ADR 0010 §1 row `worker`, §5: "`worker` deletes
//! expired rows"; ADR 0012 §7 "End of the reconciliation epoch").
//!
//! Every expiry is also enforced where the row is read (a session, a challenge, a login state
//! or a rate-limit window past its time is refused or restarted), so a late or missed purge
//! never extends a lifetime; it only frees space.

use rizzy_storage::meta;

use crate::AuthService;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::sql::{self, exec};

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
}
