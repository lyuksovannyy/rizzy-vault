//! Op and snapshot upload (ADR 0012 §7 "Upload" as ADR 0021 §9 supersedes it in part) and the
//! restore-healing request (ADR 0021 §9 "Healing request", "Server acceptance").
//!
//! # Upload
//!
//! One write transaction under the account lock for the whole request. Records are handled in
//! request order with the checks of `crate::store`, and answered one by one
//! ([`UploadResult`]). `rizzy-proto`'s batch reading applies: after the first rejected record
//! nothing further is stored and the rest are answered `not_processed`. The records stored
//! before the rejection are committed. Outside a healing request an op must carry its body
//! (§9 "Server acceptance": "The server stores a bodiless header only inside a healing
//! request"), and a signed key wrap must be carried.
//!
//! # Healing request
//!
//! One write transaction under the account lock, atomic: any refusal rolls every part back and
//! the whole request is refused (§9: "else it refuses the whole request"). In order:
//! 1. the item-key wraps, each filling its wrap-set row when the server lacks it (or holds it at
//!    a lower epoch);
//! 2. every op record, in request order: the same verification, "Already stored", author and
//!    chain checks as an upload; a header may come without its body. Records "Already stored"
//!    are skipped, not refused;
//! 3. every snapshot record, in request order, checked and clamped against the heads **after
//!    all the request's headers** (§9: "clamped after the request's headers"). Ops are stored
//!    before snapshots whatever their positions in the request; a snapshot placed before the
//!    headers it covers is thus treated as the ADR's wording reads;
//! 4. for every item with a header stored without a body, `rizzy_sync::compaction::
//!    check_healing_request` over the item's retained snapshots: a bodiless header without a
//!    cover refuses the request.
//!
//! **Stale epoch inside a healing request** (§9 "Stale epoch": "except a bodiless header or a
//! record re-published verbatim in a healing request"). The server cannot tell a record it
//! stored before a restore from a new one, and the request carries only re-publications ("with
//! its body if it holds the body of a record the server stored before") and the healer's fresh
//! snapshots, which the healer writes at its own current epoch. So no record of a healing
//! request gets the stale-epoch check. This is the reading under which a held snapshot "sent
//! verbatim" (oversize items, ADR 0018 owner decision 12) can be re-published at all.

use std::collections::BTreeMap;

use rizzy_core::ids::{AccountId, ItemId, VaultId};
use rizzy_proto::vault::{
    HealingRequest, HealingResponse, OpRecord, Record, SnapshotRecord, UploadRequest,
    UploadResponse, UploadResult,
};
use rizzy_proto::wire::List;
use rizzy_storage::{WriteTx, lock_account};
use rizzy_sync::compaction::check_healing_request;
use rizzy_sync::dot::Dot;

use crate::authors::DeviceDirectory;
use crate::error::{HealingError, VaultError};
use crate::intake::{WrapRule, verify_op, verify_snapshot};
use crate::repo::{self, WrapRow};
use crate::store::{
    Existing, Refusal, Session, chain_check, existing_op, existing_snapshot, op_author_allows,
    op_stale_exempt, snapshot_allowed, store_op, store_snapshot,
};
use crate::{VaultDomain, restore_generation, to_sql_time};

/// Opens the store session of `vault_id` for `account_id` in `tx`: checks the vault's owner,
/// takes the account lock, and reads the vault row, the heads and the certificates under it.
pub(crate) async fn open_session<D: DeviceDirectory>(
    tx: &mut WriteTx,
    directory: &D,
    account_id: AccountId,
    vault_id: VaultId,
    now_ms: u64,
) -> Result<Session, VaultError> {
    lock_account(tx, account_id.as_bytes()).await?;
    let vault = repo::vault(tx.conn(), vault_id)
        .await?
        .filter(|v| v.account_id == account_id)
        .ok_or(VaultError::NotFound)?;
    let heads = repo::heads(tx.conn(), vault_id).await?;
    let authors = directory.authors(tx.conn(), account_id).await?;
    Ok(Session {
        vault_id,
        vault,
        heads,
        authors,
        now_ms,
        now_sql: to_sql_time(now_ms)?,
        queued: std::collections::BTreeSet::new(),
    })
}

/// One op of a normal upload.
async fn upload_op(
    tx: &mut WriteTx,
    session: &mut Session,
    record: &OpRecord,
) -> Result<Result<UploadResult, Refusal>, VaultError> {
    let Ok(op) = verify_op(
        record,
        session.vault_id,
        &session.authors,
        true,
        WrapRule::Required,
    ) else {
        return Ok(Err(Refusal::Invalid));
    };
    match existing_op(tx, session, &op).await? {
        Existing::Same => return Ok(Ok(UploadResult::AlreadyStored)),
        Existing::Different => return Ok(Err(Refusal::Conflict)),
        Existing::New => {}
    }
    if !op_author_allows(&op) {
        return Ok(Err(Refusal::Invalid));
    }
    if let Err(refusal) = chain_check(session, &op) {
        return Ok(Err(refusal));
    }
    if op.header.vault_key_epoch < session.vault.vault_key_epoch && !op_stale_exempt(&op) {
        return Ok(Err(Refusal::Stale));
    }
    store_op(tx, session, &op).await?;
    Ok(Ok(UploadResult::Stored))
}

/// One snapshot of a normal upload.
async fn upload_snapshot(
    tx: &mut WriteTx,
    session: &mut Session,
    record: &SnapshotRecord,
) -> Result<Result<UploadResult, Refusal>, VaultError> {
    let Ok(snapshot) = verify_snapshot(
        record,
        session.vault_id,
        &session.authors,
        WrapRule::Required,
    ) else {
        return Ok(Err(Refusal::Invalid));
    };
    match existing_snapshot(tx, session, &snapshot).await? {
        Existing::Same => return Ok(Ok(UploadResult::AlreadyStored)),
        Existing::Different => return Ok(Err(Refusal::Conflict)),
        Existing::New => {}
    }
    if !snapshot_allowed(session, &snapshot) {
        return Ok(Err(Refusal::Invalid));
    }
    if snapshot.header.vault_key_epoch < session.vault.vault_key_epoch {
        return Ok(Err(Refusal::Stale));
    }
    store_snapshot(tx, session, &snapshot).await?;
    Ok(Ok(UploadResult::Stored))
}

/// Publishes one `CompactionQueued` per item whose snapshot was stored. Called after commit
/// only (`rizzy-bus`: "Publish after commit").
fn publish_queued<D>(domain: &VaultDomain<D>, account_id: AccountId, session: &Session) {
    for item in &session.queued {
        domain.publish_compaction_queued(account_id, session.vault_id, *item);
    }
}

impl<D: DeviceDirectory> VaultDomain<D> {
    /// Stores an upload for the session's account (ADR 0012 §7 "Upload"; ADR 0021 §9). See the
    /// module docs for the rules and their order. `now_ms` is the server's clock, used for
    /// certificate expiry and the `stored_at_ms` columns.
    ///
    /// The response carries the restore generation (ADR 0021 §2) and one result per record.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for a vault that does not exist or belongs to another account;
    /// [`VaultError::Storage`], [`VaultError::Directory`], [`VaultError::NoRestoreGeneration`]
    /// or [`VaultError::Corrupt`] when the request cannot be served at all, in which case
    /// nothing was stored.
    pub async fn upload(
        &self,
        account_id: AccountId,
        request: &UploadRequest,
        now_ms: u64,
    ) -> Result<UploadResponse, VaultError> {
        let vault_id = VaultId::from_bytes(request.vault_id.to_bytes());
        let mut tx = self.database().begin_write().await?;
        let mut session =
            open_session(&mut tx, self.directory(), account_id, vault_id, now_ms).await?;
        let generation = restore_generation(tx.conn()).await?;
        let mut results = Vec::with_capacity(request.records.len());
        let mut rejected = false;
        for record in &request.records {
            if rejected {
                results.push(UploadResult::NotProcessed);
                continue;
            }
            let outcome = match record {
                Record::Op(op) => upload_op(&mut tx, &mut session, op).await?,
                Record::Snapshot(snapshot) => {
                    upload_snapshot(&mut tx, &mut session, snapshot).await?
                }
            };
            results.push(match outcome {
                Ok(result) => result,
                Err(refusal) => {
                    rejected = true;
                    UploadResult::Rejected {
                        error: refusal.code(),
                    }
                }
            });
        }
        tx.commit().await?;
        publish_queued(self, account_id, &session);
        Ok(UploadResponse {
            restore_generation: generation,
            results: List::new(results).map_err(|_| VaultError::Corrupt {
                what: "more results than records",
            })?,
        })
    }

    /// Stores a restore-healing request atomically, or refuses all of it (ADR 0021 §9
    /// "Healing request", "Server acceptance"). See the module docs.
    ///
    /// # Errors
    /// [`HealingError::Refused`] with the reason when a rule refuses the request;
    /// [`HealingError::Failed`] when it cannot be served at all ([`VaultError::NotFound`] for a
    /// vault of another account). Nothing is stored in either case.
    pub async fn heal(
        &self,
        account_id: AccountId,
        request: &HealingRequest,
        now_ms: u64,
    ) -> Result<HealingResponse, HealingError> {
        let vault_id = VaultId::from_bytes(request.vault_id.to_bytes());
        let mut tx = self.database().begin_write().await?;
        let mut session =
            open_session(&mut tx, self.directory(), account_id, vault_id, now_ms).await?;
        let generation = restore_generation(tx.conn()).await?;
        match heal_in(&mut tx, &mut session, request).await? {
            Ok(()) => {}
            Err(refusal) => {
                tx.rollback().await?;
                return Err(HealingError::Refused(refusal.code()));
            }
        }
        tx.commit().await?;
        publish_queued(self, account_id, &session);
        Ok(HealingResponse {
            restore_generation: generation,
        })
    }
}

/// The healing request's steps inside the transaction. `Ok(Err(_))` is a refusal: the caller
/// rolls back.
async fn heal_in(
    tx: &mut WriteTx,
    session: &mut Session,
    request: &HealingRequest,
) -> Result<Result<(), Refusal>, VaultError> {
    for wrap in &request.item_key_wraps {
        let row = WrapRow {
            item_id: ItemId::from_bytes(wrap.item_id.to_bytes()),
            item_key_id: wrap.item_key_id.to_bytes(),
            vault_key_epoch: wrap.vault_key_epoch,
            envelope: wrap.envelope.as_slice().to_vec(),
        };
        repo::put_wrap(tx.conn(), session.vault_id, &row, session.now_sql).await?;
    }
    let mut bodiless: BTreeMap<ItemId, Vec<Dot>> = BTreeMap::new();
    for record in &request.records {
        let Record::Op(record) = record else { continue };
        let Ok(op) = verify_op(
            record,
            session.vault_id,
            &session.authors,
            false,
            WrapRule::Optional,
        ) else {
            return Ok(Err(Refusal::Invalid));
        };
        match existing_op(tx, session, &op).await? {
            Existing::Same => continue,
            Existing::Different => return Ok(Err(Refusal::Conflict)),
            Existing::New => {}
        }
        if !op_author_allows(&op) {
            return Ok(Err(Refusal::Invalid));
        }
        if let Err(refusal) = chain_check(session, &op) {
            return Ok(Err(refusal));
        }
        store_op(tx, session, &op).await?;
        if op.body.is_none() {
            bodiless
                .entry(op.header.item_id)
                .or_default()
                .push(op.header.dot);
        }
    }
    for record in &request.records {
        let Record::Snapshot(record) = record else {
            continue;
        };
        let Ok(snapshot) = verify_snapshot(
            record,
            session.vault_id,
            &session.authors,
            WrapRule::Optional,
        ) else {
            return Ok(Err(Refusal::Invalid));
        };
        match existing_snapshot(tx, session, &snapshot).await? {
            Existing::Same => continue,
            Existing::Different => return Ok(Err(Refusal::Conflict)),
            Existing::New => {}
        }
        if !snapshot_allowed(session, &snapshot) {
            return Ok(Err(Refusal::Invalid));
        }
        store_snapshot(tx, session, &snapshot).await?;
    }
    for (item_id, dots) in &bodiless {
        let retained = repo::item_snapshots(tx.conn(), session.vault_id, *item_id).await?;
        if check_healing_request(&retained, dots).is_err() {
            return Ok(Err(Refusal::Invalid));
        }
    }
    Ok(Ok(()))
}
