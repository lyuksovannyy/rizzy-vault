//! Rate limits and backoff, kept in the database (ADR 0010 §5; CRYPTO.md §5.9; INV-7).
//!
//! "Unauthenticated login and registration attempts get exponential backoff per (account
//! identifier, source IP) and a per-account cap on their rate, never a hard lockout. OPAQUE
//! re-authentication from a device-authenticated session uses a separate bucket that
//! unauthenticated attempts cannot exhaust." (INV-7.)
//!
//! **Buckets.** A bucket key is one kind byte followed by `SHA-256` of the fields it counts
//! by, each as `bytes(x)` (CRYPTO.md §2), so keys of different kinds or field splits never
//! collide and no login name or address is stored in clear. The hash is only a lookup key, not
//! a security mechanism: the login names of real accounts are stored in clear anyway.
//!
//! **Counting.** A bucket counts attempts in a window. Up to the rule's `max_attempts` every
//! attempt passes; each attempt beyond that sets a backoff that doubles from the rule's base up
//! to its cap. A blocked bucket refuses attempts until the backoff ends, then counts again.
//! The counters restart after a quiet `window_ms`: that long since the window began and since
//! the last backoff ended. A success clears the per-source
//! bucket, never the per-account cap. Rows expire and `worker` deletes them.
//!
//! **Source.** The caller passes the client's source address as opaque bytes. Which address
//! that is behind a reverse proxy (X-Forwarded-For trusted only from configured proxies, threat
//! model §7.6 "S") is the HTTP layer's decision.

use rizzy_storage::{Conn, Database, lock_account};
use sha2::{Digest as _, Sha256};

use crate::config::RateRule;
use crate::error::AuthError;
use crate::sql::{self, exec, fetch_opt};
use crate::trust::reborrow;

/// What a bucket counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BucketKind {
    /// Login attempts per (login name, source).
    LoginNameSource = 1,
    /// Login attempts per login name.
    LoginName = 2,
    /// Re-authentication attempts per (account, device).
    Reauth = 3,
    /// Signup attempts per source.
    SignupSource = 4,
    /// Recovery attempts per (login name, source).
    RecoveryNameSource = 5,
    /// Recovery attempts per login name.
    RecoveryName = 6,
    /// TOTP code checks per account.
    Totp = 7,
    /// Signup attempts per (login name, source) (INV-7).
    SignupNameSource = 8,
    /// Signup attempts per login name from every source (INV-7).
    SignupName = 9,
}

/// A bucket key: the kind byte and `SHA-256` over the fields, each length-prefixed.
pub(crate) fn bucket(kind: BucketKind, fields: &[&[u8]]) -> [u8; 33] {
    let mut hasher = Sha256::new();
    for field in fields {
        // A field longer than u32::MAX bytes cannot reach here (every input is bounded); the
        // saturated length would still be distinct per field count.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        hasher.update(len.to_be_bytes());
        hasher.update(field);
    }
    let digest = hasher.finalize();
    let mut key = [kind as u8; 33];
    for (dst, src) in key.iter_mut().skip(1).zip(digest.iter()) {
        *dst = *src;
    }
    key
}

/// The stored counters of one bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct Counters {
    /// Attempts counted in the current window.
    attempts: u64,
    /// When the current window started.
    window_started_at_ms: u64,
    /// Attempts are refused before this time.
    blocked_until_ms: u64,
}

/// The pure step of one attempt: `None` when the bucket refuses it at `now_ms`, otherwise the
/// counters after counting it.
fn step(rule: &RateRule, current: Option<Counters>, now_ms: u64) -> Option<Counters> {
    let mut c = current.unwrap_or(Counters {
        attempts: 0,
        window_started_at_ms: now_ms,
        blocked_until_ms: 0,
    });
    if now_ms < c.blocked_until_ms {
        return None;
    }
    // The counters restart only after a whole quiet window: `window_ms` since the window began
    // and since the last backoff ended. A client that keeps trying while blocked never resets
    // its backoff, which then stays at the cap (INV-7: a delay, never a lockout).
    if now_ms.saturating_sub(c.window_started_at_ms.max(c.blocked_until_ms)) >= rule.window_ms {
        c = Counters {
            attempts: 0,
            window_started_at_ms: now_ms,
            blocked_until_ms: 0,
        };
    }
    c.attempts = c.attempts.saturating_add(1);
    let over = c.attempts.saturating_sub(u64::from(rule.max_attempts));
    if over > 0 {
        let shift = u32::try_from(over - 1).unwrap_or(u32::MAX).min(40);
        let delay = rule
            .backoff_base_ms
            .saturating_mul(1u64 << shift)
            .min(rule.backoff_max_ms);
        c.blocked_until_ms = now_ms.saturating_add(delay);
    }
    Some(c)
}

/// Counts one attempt against `key` under `rule`, in the caller's write transaction.
///
/// # Errors
/// [`AuthError::RateLimited`] when the bucket is blocked; storage errors.
pub(crate) async fn hit(
    mut conn: Conn<'_>,
    key: &[u8],
    rule: &RateRule,
    now_ms: u64,
) -> Result<(), AuthError> {
    let row: Option<(i64, i64, i64)> =
        fetch_opt!(reborrow(&mut conn), (i64, i64, i64), sql::RATE_GET, key)?;
    let current = row
        .map(|(a, w, b)| -> Result<Counters, AuthError> {
            Ok(Counters {
                attempts: sql::sql_u64(a, "attempts")?,
                window_started_at_ms: sql::sql_u64(w, "window_started_at_ms")?,
                blocked_until_ms: sql::sql_u64(b, "blocked_until_ms")?,
            })
        })
        .transpose()?;
    let next = step(rule, current, now_ms).ok_or(AuthError::RateLimited)?;
    let expires = next
        .window_started_at_ms
        .max(next.blocked_until_ms)
        .saturating_add(rule.window_ms)
        .min(i64::MAX.unsigned_abs());
    exec!(
        conn,
        sql::RATE_UPSERT,
        key,
        sql::u64_sql(next.attempts.min(i64::MAX.unsigned_abs()), "attempts")?,
        sql::u64_sql(next.window_started_at_ms, "window_started_at_ms")?,
        sql::u64_sql(
            next.blocked_until_ms.min(i64::MAX.unsigned_abs()),
            "blocked_until_ms"
        )?,
        sql::u64_sql(expires, "expires_at_ms")?,
    )?;
    Ok(())
}

/// Clears `key` after a success.
pub(crate) async fn clear(conn: Conn<'_>, key: &[u8]) -> Result<(), AuthError> {
    exec!(conn, sql::RATE_DELETE, key)?;
    Ok(())
}

/// Counts one attempt against every bucket in `buckets`, in one write transaction, and
/// commits the counts even when a bucket refuses, so a refused attempt still counts where it
/// was counted.
///
/// Each bucket's read-and-update runs under the per-account lock of ADR 0011 keyed by the
/// bucket's hash (ADR 0010 §5), so two `api` replicas cannot both read the old counters.
///
/// # Errors
/// [`AuthError::RateLimited`] when a bucket is blocked; storage errors.
pub(crate) async fn hit_all(
    db: &Database,
    buckets: &[([u8; 33], RateRule)],
    now_ms: u64,
) -> Result<(), AuthError> {
    let mut tx = db.begin_write().await?;
    for (key, rule) in buckets {
        lock_account(&mut tx, &lock_key(key)).await?;
        match hit(tx.conn(), key, rule, now_ms).await {
            Ok(()) => {}
            Err(AuthError::RateLimited) => {
                tx.commit().await?;
                return Err(AuthError::RateLimited);
            }
            Err(e) => return Err(e),
        }
    }
    tx.commit().await?;
    Ok(())
}

/// The lock key of a bucket: 16 bytes of its hash.
fn lock_key(key: &[u8; 33]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (dst, src) in out.iter_mut().zip(key.iter().skip(1)) {
        *dst = *src;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: RateRule = RateRule {
        max_attempts: 3,
        window_ms: 10_000,
        backoff_base_ms: 1_000,
        backoff_max_ms: 8_000,
    };

    #[test]
    fn backoff_doubles_and_is_capped_never_a_lockout() {
        let mut c = None;
        let mut now = 0;
        for _ in 0..3 {
            c = step(&RULE, c, now);
            assert_eq!(c.unwrap().blocked_until_ms, 0);
        }
        let mut delays = Vec::new();
        for _ in 0..6 {
            let next = step(&RULE, c, now).unwrap();
            delays.push(next.blocked_until_ms - now);
            assert!(step(&RULE, Some(next), now).is_none(), "blocked");
            now = next.blocked_until_ms;
            c = Some(next);
        }
        assert_eq!(delays, [1_000, 2_000, 4_000, 8_000, 8_000, 8_000]);
    }

    #[test]
    fn window_restarts() {
        let mut c = None;
        for _ in 0..3 {
            c = step(&RULE, c, 0);
        }
        let later = step(&RULE, c, 10_000).unwrap();
        assert_eq!(later.attempts, 1);
    }

    #[test]
    fn bucket_keys_separate_kinds_and_fields() {
        let a = bucket(BucketKind::LoginNameSource, &[b"ab", b"c"]);
        let b = bucket(BucketKind::LoginNameSource, &[b"a", b"bc"]);
        let c = bucket(BucketKind::RecoveryNameSource, &[b"ab", b"c"]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 33);
    }
}
