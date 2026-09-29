//! The per-account lock (ADR 0011 "Transactions and concurrency").
//!
//! Every write transaction that reads state and then writes based on it first takes the
//! account's lock, through this one call, [`lock_account`]. That serialises exactly the writes
//! that can conflict: the revocation cut-off (ADR 0012 §6), the `vault_prev_seq` head check and
//! the store sequence (ADR 0012 §7, ADR 0021 §2), the `state_seq` compare-and-swap (CRYPTO.md
//! §10.2), and every read-and-update of short-lived auth state (ADR 0010 §5). A cross-domain
//! operation (revocation, account deletion) is one transaction that takes the lock once.
//!
//! - **PostgreSQL:** `pg_advisory_xact_lock(namespace, key)`, a transaction-level lock released
//!   at commit or rollback, so pool recycling can neither leak nor drop it. It uses
//!   PostgreSQL's two-`int4` key space with [`ACCOUNT_LOCK_NAMESPACE`] as the first key. That
//!   space does not overlap the single-`bigint` space (PostgreSQL documentation, "Advisory
//!   Locks"; not re-read for this crate), which sqlx's migrator uses, and `worker`'s leader
//!   lock (ADR 0010 §2) uses [`WORKER_LEADER_LOCK`], a different namespace, so the account locks
//!   are in "a key space distinct from `worker`'s leader lock".
//! - **SQLite:** nothing to do. A [`WriteTx`] exists only as `BEGIN IMMEDIATE` on the single
//!   writer connection, so it already holds the database write lock, which covers every
//!   account.
//!
//! **The key.** The second key is the four 32-bit words of the 16-byte account id, combined
//! with `^` (XOR). Account ids are chosen by clients (CRYPTO.md §11.1), so two accounts can share a
//! key, by chance or on purpose. That only makes their writes wait for each other; it never lets
//! two writes of one account run at once, which is the property the lock exists for.

use crate::db::{Conn, WriteTx};
use crate::error::Error;

/// The PostgreSQL advisory-lock namespace (first `int4` key) of the per-account locks: `"rva"`
/// followed by 1.
pub const ACCOUNT_LOCK_NAMESPACE: i32 = 0x7276_6101;

/// The PostgreSQL advisory-lock key (both `int4` keys) reserved for `worker`'s session-level
/// leader lock (ADR 0010 §2): namespace `"rva"` followed by 2, key 0. `rizzy-server` takes it on
/// its dedicated connection; it is here so that every advisory key of the project is defined in
/// one place and cannot collide with [`ACCOUNT_LOCK_NAMESPACE`].
pub const WORKER_LEADER_LOCK: (i32, i32) = (0x7276_6102, 0);

/// `SELECT pg_advisory_xact_lock($1, $2)`.
const POSTGRES_LOCK_ACCOUNT: &str = include_str!("../queries/postgres/lock_account.sql");

/// Takes the lock of account `account_id` for the rest of `tx`. Taking it twice in one
/// transaction is harmless (PostgreSQL advisory locks are re-entrant).
///
/// # Errors
///
/// [`Error::Database`] when the lock statement fails (PostgreSQL only; the transaction is then
/// unusable and must be dropped).
pub async fn lock_account(tx: &mut WriteTx, account_id: &[u8; 16]) -> Result<(), Error> {
    match tx.conn() {
        // `BEGIN IMMEDIATE` on the one writer connection already holds the write lock.
        Conn::Sqlite(_) => Ok(()),
        Conn::Postgres(c) => {
            sqlx::query(POSTGRES_LOCK_ACCOUNT)
                .bind(ACCOUNT_LOCK_NAMESPACE)
                .bind(account_lock_key(account_id))
                .execute(&mut *c)
                .await?;
            Ok(())
        }
    }
}

/// The second advisory-lock key of an account: its four big-endian 32-bit words, combined with XOR.
#[must_use]
pub fn account_lock_key(account_id: &[u8; 16]) -> i32 {
    account_id
        .chunks_exact(4)
        // `chunks_exact(4)` yields only 4-byte words, so the conversion never fails.
        .map(|w| <[u8; 4]>::try_from(w).map_or(0, i32::from_be_bytes))
        .fold(0, |acc, w| acc ^ w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_spaces_are_distinct() {
        assert_ne!(ACCOUNT_LOCK_NAMESPACE, WORKER_LEADER_LOCK.0);
    }

    #[test]
    fn lock_key_mixes_every_word() {
        let zero = [0u8; 16];
        assert_eq!(account_lock_key(&zero), 0);
        for i in 0..16 {
            let mut id = zero;
            id[i] = 1;
            assert_ne!(account_lock_key(&id), 0, "byte {i} is ignored");
        }
        let id: [u8; 16] = *b"0123456789abcdef";
        assert_eq!(account_lock_key(&id), account_lock_key(&id));
    }
}
