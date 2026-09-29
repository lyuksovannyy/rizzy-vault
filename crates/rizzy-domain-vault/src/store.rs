//! The store transaction's rules, shared by upload and restore healing (ADR 0012 §7 "Upload" as
//! ADR 0021 §9 supersedes it in part; ADR 0021 §2, §3 "Where it runs").
//!
//! Everything here runs inside one write transaction that holds the account lock
//! (`rizzy_storage::lock_account`, ADR 0011 "Transactions and concurrency"), on a [`Session`]
//! loaded at its start: the vault row, the heads and the account's certificates. Storing an op
//! advances the session's heads, so a later record of the same request sees them, and a
//! snapshot's clamp and acceptance checks use the heads at its point in the transaction.
//!
//! **Order of the checks for one record** (§9 "Already stored": "answered 'already stored'
//! before the `vault_prev_seq` and stale-epoch checks"):
//! 1. verification ([`crate::intake`]): statement, header, hashes;
//! 2. "Already stored": byte-identical to the record stored at that dot or `snapshot_id` →
//!    acknowledged, nothing stored; a different record there → conflict;
//! 3. the author's revocation, suspension and expiry rules;
//! 4. ops: the `vault_prev_seq` chain check; snapshots: [`check_snapshot`];
//! 5. the stale-epoch check with its exemptions;
//! 6. the insert, with the clamped VV and store sequence for a snapshot, and the item queued for
//!    `worker`.

use std::collections::BTreeSet;

use rizzy_core::ids::{ItemId, VaultId};
use rizzy_proto::error::ErrorCode;
use rizzy_storage::WriteTx;
use rizzy_sync::compaction::{CertificateExpiry, VaultChains, check_snapshot, clamp};
use rizzy_sync::vv::VersionVector;

use crate::authors::{AuthorStatus, Authors};
use crate::error::VaultError;
use crate::intake::{Signed, VerifiedOp, VerifiedSnapshot};
use crate::repo::{self, StoredRecord, VaultRow, WrapRow};

/// Why one record is refused. Each maps to one [`ErrorCode`] ([`Refusal::code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Verification, an author rule, or a snapshot's claims failed.
    Invalid,
    /// A different record is stored at the dot or `snapshot_id` (§9 "Already stored").
    Conflict,
    /// The op's `vault_prev_seq` is not the last op the server holds from the device in the
    /// vault (§9 "Already stored", last sentence).
    PrevSeq,
    /// The record's `vault_key_epoch` is below the vault's (§9 "Stale epoch").
    Stale,
}

impl Refusal {
    /// The wire code.
    pub(crate) const fn code(self) -> ErrorCode {
        match self {
            Self::Invalid => ErrorCode::InvalidRequest,
            Self::Conflict => ErrorCode::RecordConflict,
            Self::PrevSeq => ErrorCode::PrevSeqMismatch,
            Self::Stale => ErrorCode::StaleEpoch,
        }
    }
}

/// The state one store transaction works on.
#[derive(Debug)]
pub(crate) struct Session {
    /// The vault.
    pub(crate) vault_id: VaultId,
    /// Its row, read under the account lock.
    pub(crate) vault: VaultRow,
    /// Every head h(V, d), advanced as ops are stored.
    pub(crate) heads: VersionVector,
    /// The account's certificates, read under the account lock.
    pub(crate) authors: Authors,
    /// The server's clock, for certificate expiry.
    pub(crate) now_ms: u64,
    /// The same clock as an SQL integer, for the `*_at_ms` columns.
    pub(crate) now_sql: i64,
    /// The items whose snapshots were stored, to publish after commit.
    pub(crate) queued: BTreeSet<ItemId>,
}

/// The answer of "Already stored" (ADR 0021 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Existing {
    /// Nothing is stored at the dot or `snapshot_id`.
    New,
    /// The same record is stored: acknowledge, store nothing.
    Same,
    /// A different record is stored there.
    Different,
}

/// Whether an uploaded record is byte-identical to the stored one. The statement must be
/// identical; an envelope or wrap held on both sides must be too. One held on one side only is
/// no difference: the server may have deleted a body (R1) or stopped serving a superseded wrap
/// (CRYPTO.md §4.2), and both are bound by the identical signed hashes.
fn same_record(
    stored: &StoredRecord,
    signed: &Signed,
    body: Option<&[u8]>,
    wrap: Option<&[u8]>,
) -> bool {
    let agree = |a: Option<&[u8]>, b: Option<&[u8]>| match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    stored.signed == *signed
        && agree(stored.body.as_deref(), body)
        && agree(stored.key_wrap.as_deref(), wrap)
}

/// "Already stored" for an op, by (`vault_id`, `device_id`, `device_seq`).
pub(crate) async fn existing_op(
    tx: &mut WriteTx,
    session: &Session,
    op: &VerifiedOp,
) -> Result<Existing, VaultError> {
    let stored = repo::get_op(tx.conn(), session.vault_id, op.header.dot).await?;
    Ok(match stored {
        None => Existing::New,
        Some(s)
            if same_record(
                &s,
                &op.signed,
                op.body.as_deref(),
                op.key_wrap.as_ref().map(|w| w.envelope.as_slice()),
            ) =>
        {
            Existing::Same
        }
        Some(_) => Existing::Different,
    })
}

/// "Already stored" for a snapshot, by (`vault_id`, `snapshot_id`).
pub(crate) async fn existing_snapshot(
    tx: &mut WriteTx,
    session: &Session,
    snapshot: &VerifiedSnapshot,
) -> Result<Existing, VaultError> {
    let stored =
        repo::get_snapshot(tx.conn(), session.vault_id, snapshot.header.snapshot_id).await?;
    Ok(match stored {
        None => Existing::New,
        Some(s)
            if same_record(
                &s,
                &snapshot.signed,
                Some(&snapshot.envelope),
                snapshot.key_wrap.as_ref().map(|w| w.envelope.as_slice()),
            ) =>
        {
            Existing::Same
        }
        Some(_) => Existing::Different,
    })
}

/// The author rules for an op (ADR 0012 §7 "Upload"; CRYPTO.md §10.2 rule (c), §11.8 step 4):
/// a suspended author's records are refused; a revoked author's op only up to its
/// `last_accepted_device_seq`; an op whose HLC is past the certificate's expiry is refused.
pub(crate) fn op_author_allows(op: &VerifiedOp) -> bool {
    let seq = op.header.dot.seq();
    let status_allows = match op.author.status {
        AuthorStatus::Active => true,
        AuthorStatus::Suspended => false,
        AuthorStatus::Revoked {
            last_accepted_device_seq,
        } => seq <= last_accepted_device_seq,
    };
    status_allows && op.author.permits_hlc(op.header.hlc.to_u64())
}

/// ADR 0021 §9 "Stale epoch" exemption of a normal upload: "a revoked device's op with
/// `device_seq` ≤ `last_accepted_device_seq`, whoever uploads it".
pub(crate) fn op_stale_exempt(op: &VerifiedOp) -> bool {
    matches!(op.author.status, AuthorStatus::Revoked { last_accepted_device_seq }
        if op.header.dot.seq() <= last_accepted_device_seq)
}

/// The chain check (ADR 0012 §7; ADR 0021 §9 "Already stored", last sentence): the op's
/// `vault_prev_seq` must be the last op the server holds from its device in the vault. An op
/// whose `device_seq` does not exceed its own `vault_prev_seq` breaks the chain's definition
/// (ADR 0012 §2) and is refused as invalid.
pub(crate) fn chain_check(session: &Session, op: &VerifiedOp) -> Result<(), Refusal> {
    let h = &op.header;
    if h.dot.seq() <= h.vault_prev_seq {
        return Err(Refusal::Invalid);
    }
    if h.vault_prev_seq != session.heads.get(h.dot.device_id()) {
        return Err(Refusal::PrevSeq);
    }
    Ok(())
}

/// ADR 0021 §9 "Server acceptance" (second sentence) and "Revoked and kind-4 authors", through
/// `rizzy_sync::compaction::check_snapshot`, against the session's heads at this point; and a
/// suspended author's snapshots are refused like its ops.
pub(crate) fn snapshot_allowed(session: &Session, snapshot: &VerifiedSnapshot) -> bool {
    if snapshot.author.status == AuthorStatus::Suspended {
        return false;
    }
    let cutoffs = session.authors.cutoffs();
    let expiry = if snapshot.author.expired_at(session.now_ms) {
        CertificateExpiry::Expired
    } else {
        CertificateExpiry::Unexpired
    };
    check_snapshot(
        snapshot.header.author,
        &snapshot.header.covered,
        VaultChains {
            heads: &session.heads,
            cutoffs: &cutoffs,
        },
        expiry,
    )
    .is_ok()
}

/// Fills the wrap-set row of a record's carried wrap (CRYPTO.md §4.2: "A wrap that arrives
/// inside an op or snapshot record fills that row and is also kept with the record"), at the
/// record's `vault_key_epoch`, the epoch of the vault key its author wrapped under.
///
/// A record below the vault's current `vault_key_epoch` reaches here without its wrap
/// ([`current_wrap`]): such a wrap is under a superseded vault key and never fills a row.
async fn fill_wrap(
    tx: &mut WriteTx,
    session: &Session,
    item_id: ItemId,
    epoch: u32,
    wrap: Option<&crate::intake::CarriedWrap>,
) -> Result<(), VaultError> {
    if let Some(w) = wrap {
        let row = WrapRow {
            item_id,
            item_key_id: w.item_key_id,
            vault_key_epoch: epoch,
            envelope: w.envelope.clone(),
        };
        repo::put_wrap(tx.conn(), session.vault_id, &row, session.now_sql).await?;
    }
    Ok(())
}

/// Whether a record at `epoch` may keep its carried wrap: only at or above the vault's current
/// `vault_key_epoch`. A record below it can still be stored (a stale-exempt op of a revoked
/// device, or a record a healing request re-publishes), but its carried wrap is under a
/// superseded vault key, which a revoked device may know. ADR 0025 open question 4, decided ("no
/// healing below the current epoch"), and CRYPTO.md §4.2 and §11.6 step 9 (superseded wraps are
/// deleted) apply to it as to a wrap-set entry: the wrap fills no row and is not kept with the
/// record. The record keeps its signed wrap hash, as after a rotation's `clear_record_wraps`, so
/// "Already stored" still matches a later re-publication that carries the wrap.
pub(crate) const fn current_wrap(session: &Session, epoch: u32) -> bool {
    epoch >= session.vault.vault_key_epoch
}

/// Stores an op that passed every check, and advances the head of its chain. A wrap carried by
/// an op below the vault's current epoch is dropped ([`current_wrap`]).
pub(crate) async fn store_op(
    tx: &mut WriteTx,
    session: &mut Session,
    op: &VerifiedOp,
) -> Result<(), VaultError> {
    let stripped;
    let op = if op.key_wrap.is_some() && !current_wrap(session, op.header.vault_key_epoch) {
        stripped = VerifiedOp {
            key_wrap: None,
            ..op.clone()
        };
        &stripped
    } else {
        op
    };
    repo::insert_op(tx.conn(), session.vault_id, op, session.now_sql).await?;
    session.heads.add(op.header.dot);
    fill_wrap(
        tx,
        session,
        op.header.item_id,
        op.header.vault_key_epoch,
        op.key_wrap.as_ref(),
    )
    .await
}

/// Stores a snapshot that passed every check (ADR 0021 §2, §3 "Where it runs"): its clamped VV
/// `min(covered, heads)` from the session's heads at this point, persisted in the canonical VV
/// encoding and never sent; the next store sequence, and the counter advanced; the item queued
/// for `worker`. Returns the store sequence. A wrap carried by a snapshot below the vault's
/// current epoch is dropped ([`current_wrap`]).
pub(crate) async fn store_snapshot(
    tx: &mut WriteTx,
    session: &mut Session,
    snapshot: &VerifiedSnapshot,
) -> Result<u64, VaultError> {
    let stripped;
    let snapshot =
        if snapshot.key_wrap.is_some() && !current_wrap(session, snapshot.header.vault_key_epoch) {
            stripped = VerifiedSnapshot {
                key_wrap: None,
                ..snapshot.clone()
            };
            &stripped
        } else {
            snapshot
        };
    let clamped = clamp(&snapshot.header.covered, &session.heads)
        .to_vec()
        .map_err(|_| VaultError::Corrupt {
            what: "a clamped VV does not encode",
        })?;
    let store_seq = session.vault.next_store_seq;
    repo::insert_snapshot(
        tx.conn(),
        session.vault_id,
        snapshot,
        &clamped,
        store_seq,
        session.now_sql,
    )
    .await?;
    repo::advance_store_seq(tx.conn(), session.vault_id).await?;
    session.vault.next_store_seq = store_seq.checked_add(1).ok_or(VaultError::Corrupt {
        what: "vault_vaults.next_store_seq overflows",
    })?;
    repo::enqueue(
        tx.conn(),
        session.vault_id,
        snapshot.header.item_id,
        session.now_sql,
    )
    .await?;
    session.queued.insert(snapshot.header.item_id);
    fill_wrap(
        tx,
        session,
        snapshot.header.item_id,
        snapshot.header.vault_key_epoch,
        snapshot.key_wrap.as_ref(),
    )
    .await?;
    Ok(store_seq)
}
