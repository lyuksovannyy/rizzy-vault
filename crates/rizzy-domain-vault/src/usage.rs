// SPDX-License-Identifier: AGPL-3.0-only

//! The vault domain's part of the per-account storage quota ([ADR 0048]).
//!
//! **The unit** (§2) is the portable wire size a Fetch page already counts: for an op,
//! the statement framing (74 bytes: three length prefixes and the two signed hashes, CRYPTO.md
//! §9.6) plus its header, signature container, body and carried wrap; for a
//! snapshot, the same framing plus its header, container, envelope and carried wrap. It is the
//! same on both engines, unlike an engine's row encoding, and it is only what THREAT_MODEL §3.4
//! already marks Visible: lengths, never contents. The counted rows are every row of every
//! table this crate owns that holds bytes: `vault_ops`, `vault_snapshots`, and since [ADR 0054]
//! `vault_attachments` with `vault_attachment_chunks`. An attachment counts its wrap plus every
//! chunk envelope its declared size implies (`total_plaintext_len + 90` per chunk), charged in
//! full at `attachments/create` and released at `attachments/delete` or by the 24 h sweep
//! ([`crate::attachments`]).
//!
//! **Where it is charged** (§3): the counter is `rizzy-storage`'s
//! ([`rizzy_storage::quota`]); this crate charges it inside the account-locked transactions it
//! already opens:
//! - an ordinary upload refuses a record with [`ErrorCode::QuotaExceeded`] when the account's
//!   counted bytes plus the record would pass [`Quota::limit`] (the quota plus the instance's
//!   upload limit as headroom), checked once per record, in request order, after the
//!   stale-epoch check and before the insert (`crate::store`); the stored bytes are written
//!   once, at commit;
//! - a healing request is never refused for quota, and its stored bytes are charged the same
//!   way;
//! - compaction credits each body it deletes (R1) and each snapshot it drops (R3), read before
//!   the delete, in the same transaction, before the item is dequeued; the header, hashes and
//!   signature of an op stay and keep counting;
//! - a key rotation and healing step 3b credit the carried wraps they clear (this crate's
//!   reading of §2: the counter stays the sum the rows define, so the daily reconciliation does
//!   not report every rotation as drift).
//!
//! **Backfill and reconciliation** (§4): [`counted_bytes`] recomputes one account's true total
//! from the rows and [`accounts`] lists the accounts that own a vault, on the caller's
//! transaction; `rizzy-server` seeds and corrects `rizzy-storage`'s counter from them.
//!
//! [ADR 0048]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0048-per-account-storage-quota.md
//! [ADR 0054]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0054-attachments-envelope-and-api.md
//! [`ErrorCode::QuotaExceeded`]: rizzy_proto::error::ErrorCode::QuotaExceeded

use rizzy_core::ids::AccountId;
use rizzy_proto::limits::DEFAULT_UPLOAD_BODY_LEN;
use rizzy_storage::quota::DEFAULT_QUOTA_BYTES;
use rizzy_storage::{Conn, WriteTx};

use crate::error::VaultError;
use crate::intake::{VerifiedOp, VerifiedSnapshot};
use crate::repo;

/// The framing a served statement adds to its header and signature container: the statement
/// length, version and header length prefixes and the two signed hashes (CRYPTO.md §9.6).
pub(crate) const STATEMENT_FRAME: usize = 4 + 2 + 4 + 64;

/// The instance's quota and the headroom an ordinary upload may use past it (ADR 0048 §1, §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// `RIZZY_ACCOUNT_QUOTA_BYTES`.
    pub quota_bytes: u64,
    /// `RIZZY_MAX_UPLOAD_BYTES`: one request's raw records always fit in it, so a request that
    /// starts at or under the quota stores all of its records.
    pub headroom_bytes: u64,
}

impl Default for Quota {
    /// The defaults of both settings: 5 GiB and 32 MiB.
    fn default() -> Self {
        Self {
            quota_bytes: DEFAULT_QUOTA_BYTES,
            headroom_bytes: u64::try_from(DEFAULT_UPLOAD_BODY_LEN).unwrap_or(u64::MAX),
        }
    }
}

impl Quota {
    /// The most counted bytes an ordinary upload may leave an account with: the quota plus the
    /// headroom.
    #[must_use]
    pub const fn limit(self) -> u64 {
        self.quota_bytes.saturating_add(self.headroom_bytes)
    }
}

/// A length as a count.
fn len(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The counted bytes of an op as it is stored (its wrap included only if it is kept).
pub(crate) fn op_bytes(op: &VerifiedOp, keeps_wrap: bool) -> u64 {
    len(STATEMENT_FRAME + op.signed.header.len() + op.signed.container.len())
        .saturating_add(op.body.as_ref().map_or(0, |b| len(b.len())))
        .saturating_add(if keeps_wrap {
            op.key_wrap.as_ref().map_or(0, |w| len(w.envelope.len()))
        } else {
            0
        })
}

/// The counted bytes of a snapshot as it is stored (its wrap included only if it is kept).
pub(crate) fn snapshot_bytes(snapshot: &VerifiedSnapshot, keeps_wrap: bool) -> u64 {
    len(STATEMENT_FRAME + snapshot.signed.header.len() + snapshot.signed.container.len())
        .saturating_add(len(snapshot.envelope.len()))
        .saturating_add(if keeps_wrap {
            snapshot
                .key_wrap
                .as_ref()
                .map_or(0, |w| len(w.envelope.len()))
        } else {
            0
        })
}

/// Charges `delta` counted bytes to `account_id` in `tx`, which holds the account lock. A zero
/// delta writes nothing.
pub(crate) async fn charge(
    tx: &mut WriteTx,
    account_id: AccountId,
    delta: i64,
    now_sql: i64,
) -> Result<(), VaultError> {
    if delta != 0 {
        rizzy_storage::quota::adjust(tx, account_id.as_bytes(), delta, now_sql).await?;
    }
    Ok(())
}

/// A count of freed bytes as a negative delta.
pub(crate) fn credit(freed: u64) -> i64 {
    i64::try_from(freed).map_or(i64::MIN, |f| -f)
}

/// The true counted bytes of `account_id`, summed over every row this crate stores for it
/// (ADR 0048 §2, §4), on the caller's connection: the figure the first-startup backfill seeds
/// and the daily reconciliation compares.
///
/// # Errors
/// [`VaultError::Storage`]; [`VaultError::Corrupt`] for a negative count.
pub async fn counted_bytes(mut conn: Conn<'_>, account_id: AccountId) -> Result<u64, VaultError> {
    let reborrowed = match &mut conn {
        Conn::Sqlite(c) => Conn::Sqlite(c),
        Conn::Postgres(c) => Conn::Postgres(c),
    };
    let tables = repo::account_row_lengths(reborrowed, account_id).await?;
    let records = tables.iter().fold(0u64, |total, t| {
        total
            .saturating_add(t.rows.saturating_mul(len(STATEMENT_FRAME)))
            .saturating_add(t.bytes)
    });
    // ADR 0054 §5–§6: each attachment counts its wrap and every chunk envelope its declared size
    // implies, the figure `attachments/create` charged (crate::attachments).
    let attachments = crate::attachments::account_attachment_bytes(conn, account_id).await?;
    Ok(records.saturating_add(attachments))
}

/// Every account that owns a vault, ascending, on the caller's connection.
///
/// # Errors
/// [`VaultError::Storage`]; [`VaultError::Corrupt`] for a damaged account id.
pub async fn accounts(conn: Conn<'_>) -> Result<Vec<AccountId>, VaultError> {
    repo::vault_accounts(conn).await
}
