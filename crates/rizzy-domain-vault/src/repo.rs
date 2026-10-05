//! The vault domain's queries over its own tables (`vault_`, ADR 0011 point 5), run on a
//! connection of a `rizzy-storage` transaction with [`on_engine!`].
//!
//! Every query text is a `&'static str` from a `.sql` file under `queries/`, shared by both
//! engines with `$N` placeholders, and every value is a bound parameter (ADR 0011 point 2,
//! INV-53). Integers go through `rizzy_storage::convert`, which refuses a `u64` above
//! `i64::MAX` instead of storing it negative. Nothing here logs, and no error carries a bound
//! value.
//!
//! Stored rows are this domain's own writes, but a damaged database is possible: every column
//! read back is checked for its shape and reported as [`VaultError::Corrupt`], never trusted into
//! a panic.

use rizzy_core::ids::{AccountId, DeviceId, ItemId, SnapshotId, VaultId};
use rizzy_core::sign::CONTAINER_LEN;
use rizzy_storage::Conn;
use rizzy_storage::convert::{sql_to_u32, sql_to_u64, u32_to_sql, u64_to_sql};
use rizzy_storage::on_engine;
use rizzy_sync::compaction::{Body, OpDot, RetainedSnapshot};
use rizzy_sync::dot::Dot;
use rizzy_sync::vv::VersionVector;
use sqlx::Row;

use crate::error::VaultError;
use crate::intake::{HASH_LEN, Signed, VerifiedOp, VerifiedSnapshot};

/// See `queries/vault_get.sql`.
const VAULT_GET: &str = include_str!("../queries/vault_get.sql");
/// See `queries/vault_insert.sql`.
const VAULT_INSERT: &str = include_str!("../queries/vault_insert.sql");
/// See `queries/vault_list.sql`.
const VAULT_LIST: &str = include_str!("../queries/vault_list.sql");
/// See `queries/vault_max_record_epoch.sql`.
const VAULT_MAX_RECORD_EPOCH: &str = include_str!("../queries/vault_max_record_epoch.sql");
/// See `queries/vault_store_seq_next.sql`.
const VAULT_STORE_SEQ_NEXT: &str = include_str!("../queries/vault_store_seq_next.sql");
/// See `queries/heads.sql`.
const HEADS: &str = include_str!("../queries/heads.sql");
/// See `queries/op_get.sql`.
const OP_GET: &str = include_str!("../queries/op_get.sql");
/// See `queries/op_insert.sql`.
const OP_INSERT: &str = include_str!("../queries/op_insert.sql");
/// See `queries/ops_after.sql`.
const OPS_AFTER: &str = include_str!("../queries/ops_after.sql");
/// See `queries/item_op_dots.sql`.
const ITEM_OP_DOTS: &str = include_str!("../queries/item_op_dots.sql");
/// See `queries/op_delete_body.sql`.
const OP_DELETE_BODY: &str = include_str!("../queries/op_delete_body.sql");
/// See `queries/snapshot_get.sql`.
const SNAPSHOT_GET: &str = include_str!("../queries/snapshot_get.sql");
/// See `queries/snapshot_insert.sql`.
const SNAPSHOT_INSERT: &str = include_str!("../queries/snapshot_insert.sql");
/// See `queries/item_snapshots.sql`.
const ITEM_SNAPSHOTS: &str = include_str!("../queries/item_snapshots.sql");
/// See `queries/snapshot_by_store_seq.sql`.
const SNAPSHOT_BY_STORE_SEQ: &str = include_str!("../queries/snapshot_by_store_seq.sql");
/// See `queries/snapshot_delete.sql`.
const SNAPSHOT_DELETE: &str = include_str!("../queries/snapshot_delete.sql");
/// See `queries/compaction_enqueue.sql`.
const COMPACTION_ENQUEUE: &str = include_str!("../queries/compaction_enqueue.sql");
/// See `queries/compaction_dequeue.sql`.
const COMPACTION_DEQUEUE: &str = include_str!("../queries/compaction_dequeue.sql");
/// See `queries/compaction_defer.sql`.
const COMPACTION_DEFER: &str = include_str!("../queries/compaction_defer.sql");
/// See `queries/item_snapshot_sizes.sql`.
const ITEM_SNAPSHOT_SIZES: &str = include_str!("../queries/item_snapshot_sizes.sql");
/// See `queries/compaction_list.sql`.
const COMPACTION_LIST: &str = include_str!("../queries/compaction_list.sql");
/// See `queries/wrap_get.sql`.
const WRAP_GET: &str = include_str!("../queries/wrap_get.sql");
/// See `queries/wrap_insert.sql`.
const WRAP_INSERT: &str = include_str!("../queries/wrap_insert.sql");
/// See `queries/wrap_replace.sql`.
const WRAP_REPLACE: &str = include_str!("../queries/wrap_replace.sql");
/// See `queries/wrap_by_envelope.sql`.
const WRAP_BY_ENVELOPE: &str = include_str!("../queries/wrap_by_envelope.sql");
/// See `queries/wraps_after.sql`.
const WRAPS_AFTER: &str = include_str!("../queries/wraps_after.sql");
/// See `queries/self_grant_get.sql`.
const SELF_GRANT_GET: &str = include_str!("../queries/self_grant_get.sql");
/// See `queries/self_grant_insert.sql`.
const SELF_GRANT_INSERT: &str = include_str!("../queries/self_grant_insert.sql");
/// See `queries/self_grant_replace.sql`.
const SELF_GRANT_REPLACE: &str = include_str!("../queries/self_grant_replace.sql");
/// See `queries/vault_set_epoch.sql`.
const VAULT_SET_EPOCH: &str = include_str!("../queries/vault_set_epoch.sql");
/// See `queries/vault_clamped_vvs.sql`.
const VAULT_CLAMPED_VVS: &str = include_str!("../queries/vault_clamped_vvs.sql");
/// See `queries/wrap_overwrite.sql`.
const WRAP_OVERWRITE: &str = include_str!("../queries/wrap_overwrite.sql");
/// See `queries/wrap_delete.sql`.
const WRAP_DELETE: &str = include_str!("../queries/wrap_delete.sql");
/// See `queries/ops_clear_wraps.sql`.
const OPS_CLEAR_WRAPS: &str = include_str!("../queries/ops_clear_wraps.sql");
/// See `queries/snapshots_clear_wraps.sql`.
const SNAPSHOTS_CLEAR_WRAPS: &str = include_str!("../queries/snapshots_clear_wraps.sql");
/// See `queries/ops_clear_wraps_below.sql`.
const OPS_CLEAR_WRAPS_BELOW: &str = include_str!("../queries/ops_clear_wraps_below.sql");
/// See `queries/snapshots_clear_wraps_below.sql`.
const SNAPSHOTS_CLEAR_WRAPS_BELOW: &str =
    include_str!("../queries/snapshots_clear_wraps_below.sql");

/// A 16-byte id read back from a column.
fn id16(bytes: &[u8], what: &'static str) -> Result<[u8; 16], VaultError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| VaultError::Corrupt { what })
}

/// A 32-byte hash read back from a column.
fn hash32(bytes: &[u8], what: &'static str) -> Result<[u8; HASH_LEN], VaultError> {
    <[u8; HASH_LEN]>::try_from(bytes).map_err(|_| VaultError::Corrupt { what })
}

/// A signature container read back from a column.
fn container(bytes: &[u8], what: &'static str) -> Result<[u8; CONTAINER_LEN], VaultError> {
    <[u8; CONTAINER_LEN]>::try_from(bytes).map_err(|_| VaultError::Corrupt { what })
}

/// One vault's row.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VaultRow {
    /// The owning account.
    pub(crate) account_id: AccountId,
    /// The current `vault_key_epoch`.
    pub(crate) vault_key_epoch: u32,
    /// The next store sequence to assign (ADR 0021 §2).
    pub(crate) next_store_seq: u64,
}

/// The vault's row, if it exists.
pub(crate) async fn vault(
    conn: Conn<'_>,
    vault_id: VaultId,
) -> Result<Option<VaultRow>, VaultError> {
    let row: Option<(Vec<u8>, i64, i64)> = on_engine!(conn, |c| {
        match sqlx::query(VAULT_GET)
            .bind(&vault_id.as_bytes()[..])
            .fetch_optional(&mut *c)
            .await?
        {
            Some(r) => Some((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?)),
            None => None,
        }
    });
    row.map(|(account, epoch, next)| {
        Ok(VaultRow {
            account_id: AccountId::from_bytes(id16(&account, "vault_vaults.account_id")?),
            vault_key_epoch: sql_to_u32(epoch, "vault_vaults.vault_key_epoch")?,
            next_store_seq: sql_to_u64(next, "vault_vaults.next_store_seq")?,
        })
    })
    .transpose()
}

/// Inserts a vault row.
pub(crate) async fn insert_vault(
    conn: Conn<'_>,
    vault_id: VaultId,
    account_id: AccountId,
    vault_key_epoch: u32,
    now_ms: i64,
) -> Result<(), VaultError> {
    on_engine!(conn, |c| sqlx::query(VAULT_INSERT)
        .bind(&vault_id.as_bytes()[..])
        .bind(&account_id.as_bytes()[..])
        .bind(u32_to_sql(vault_key_epoch))
        .bind(now_ms)
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// The vaults of an account, by id.
pub(crate) async fn list_vaults(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Vec<VaultId>, VaultError> {
    let rows: Vec<Vec<u8>> = on_engine!(conn, |c| sqlx::query_scalar(VAULT_LIST)
        .bind(&account_id.as_bytes()[..])
        .fetch_all(&mut *c)
        .await)?;
    rows.iter()
        .map(|id| Ok(VaultId::from_bytes(id16(id, "vault_vaults.id")?)))
        .collect()
}

/// The highest `vault_key_epoch` among the vault's stored op and snapshot headers (signed
/// statements the server verified on upload), or `None` when it holds none.
pub(crate) async fn max_record_epoch(
    conn: Conn<'_>,
    vault_id: VaultId,
) -> Result<Option<u32>, VaultError> {
    let max: Option<i64> = on_engine!(conn, |c| sqlx::query_scalar(VAULT_MAX_RECORD_EPOCH)
        .bind(&vault_id.as_bytes()[..])
        .fetch_one(&mut *c)
        .await)?;
    max.map(|e| sql_to_u32(e, "vault_key_epoch of a stored header"))
        .transpose()
        .map_err(Into::into)
}

/// Advances the vault's store-sequence counter by one.
pub(crate) async fn advance_store_seq(conn: Conn<'_>, vault_id: VaultId) -> Result<(), VaultError> {
    on_engine!(conn, |c| sqlx::query(VAULT_STORE_SEQ_NEXT)
        .bind(&vault_id.as_bytes()[..])
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// Every head h(V, d) of the vault, as one vector (ADR 0021 §2).
pub(crate) async fn heads(conn: Conn<'_>, vault_id: VaultId) -> Result<VersionVector, VaultError> {
    let rows: Vec<(Vec<u8>, i64)> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(HEADS)
            .bind(&vault_id.as_bytes()[..])
            .fetch_all(&mut *c)
            .await?
        {
            out.push((r.try_get(0)?, r.try_get(1)?));
        }
        out
    });
    rows.into_iter()
        .map(|(device, seq)| {
            let device = DeviceId::from_bytes(id16(&device, "vault_ops.device_id")?);
            let seq = sql_to_u64(seq, "vault_ops.device_seq")?;
            Dot::new(device, seq).ok_or(VaultError::Corrupt {
                what: "vault_ops.device_seq is 0",
            })
        })
        .collect()
}

/// A stored op or snapshot, as the server keeps it: the signed parts, and the attachments it
/// still holds.
#[derive(Clone, Debug)]
pub(crate) struct StoredRecord {
    /// The signed parts; the statement is rebuilt from them.
    pub(crate) signed: Signed,
    /// The op body or snapshot envelope, if held.
    pub(crate) body: Option<Vec<u8>>,
    /// The carried `ITEM_KEY_WRAP`, if held.
    pub(crate) key_wrap: Option<Vec<u8>>,
}

/// The columns of a stored op, as read.
type OpColumns = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// Rebuilds a stored op from its columns.
fn stored_op(cols: OpColumns) -> Result<StoredRecord, VaultError> {
    let (header, body_hash, wrap_hash, signature, body, key_wrap) = cols;
    Ok(StoredRecord {
        signed: Signed {
            header,
            envelope_hash: hash32(&body_hash, "vault_ops.body_hash")?,
            wrap_hash: hash32(&wrap_hash, "vault_ops.wrap_hash")?,
            container: container(&signature, "vault_ops.signature")?,
        },
        body,
        key_wrap,
    })
}

/// The op stored at `dot`, if any.
pub(crate) async fn get_op(
    conn: Conn<'_>,
    vault_id: VaultId,
    dot: Dot,
) -> Result<Option<StoredRecord>, VaultError> {
    let seq = u64_to_sql(dot.seq(), "vault_ops.device_seq")?;
    let row: Option<OpColumns> = on_engine!(conn, |c| {
        match sqlx::query(OP_GET)
            .bind(&vault_id.as_bytes()[..])
            .bind(&dot.device_id().as_bytes()[..])
            .bind(seq)
            .fetch_optional(&mut *c)
            .await?
        {
            Some(r) => Some((
                r.try_get(0)?,
                r.try_get(1)?,
                r.try_get(2)?,
                r.try_get(3)?,
                r.try_get(4)?,
                r.try_get(5)?,
            )),
            None => None,
        }
    });
    row.map(stored_op).transpose()
}

/// Stores a verified op; its body is stored as carried (`None` for a bodiless header).
pub(crate) async fn insert_op(
    conn: Conn<'_>,
    vault_id: VaultId,
    op: &VerifiedOp,
    now_ms: i64,
) -> Result<(), VaultError> {
    let h = &op.header;
    let seq = u64_to_sql(h.dot.seq(), "vault_ops.device_seq")?;
    let prev = u64_to_sql(h.vault_prev_seq, "vault_ops.vault_prev_seq")?;
    let hlc = u64_to_sql(h.hlc.to_u64(), "vault_ops.hlc")?;
    let wrap = op.key_wrap.as_ref().map(|w| w.envelope.as_slice());
    on_engine!(conn, |c| sqlx::query(OP_INSERT)
        .bind(&vault_id.as_bytes()[..])
        .bind(&h.dot.device_id().as_bytes()[..])
        .bind(seq)
        .bind(&h.item_id.as_bytes()[..])
        .bind(&h.op_id.as_bytes()[..])
        .bind(prev)
        .bind(hlc)
        .bind(i64::from(h.item_schema_version.get()))
        .bind(u32_to_sql(h.vault_key_epoch))
        .bind(op.signed.header.as_slice())
        .bind(&op.signed.envelope_hash[..])
        .bind(&op.signed.wrap_hash[..])
        .bind(&op.signed.container[..])
        .bind(op.body.as_deref())
        .bind(wrap)
        .bind(now_ms)
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// One op read for a Fetch.
#[derive(Clone, Debug)]
pub(crate) struct FetchedOp {
    /// Its dot.
    pub(crate) dot: Dot,
    /// Its item.
    pub(crate) item_id: ItemId,
    /// The stored record.
    pub(crate) record: StoredRecord,
}

/// `device`'s ops in the vault with `device_seq` above `after`, in chain order, at most
/// `limit`.
pub(crate) async fn ops_after(
    conn: Conn<'_>,
    vault_id: VaultId,
    device: DeviceId,
    after: u64,
    limit: usize,
) -> Result<Vec<FetchedOp>, VaultError> {
    // A cursor at or above `i64::MAX` has nothing after it: no stored seq exceeds it.
    let after = i64::try_from(after).unwrap_or(i64::MAX);
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows: Vec<(i64, Vec<u8>, OpColumns)> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(OPS_AFTER)
            .bind(&vault_id.as_bytes()[..])
            .bind(&device.as_bytes()[..])
            .bind(after)
            .bind(limit)
            .fetch_all(&mut *c)
            .await?
        {
            out.push((
                r.try_get(0)?,
                r.try_get(1)?,
                (
                    r.try_get(2)?,
                    r.try_get(3)?,
                    r.try_get(4)?,
                    r.try_get(5)?,
                    r.try_get(6)?,
                    r.try_get(7)?,
                ),
            ));
        }
        out
    });
    rows.into_iter()
        .map(|(seq, item, cols)| {
            let seq = sql_to_u64(seq, "vault_ops.device_seq")?;
            Ok(FetchedOp {
                dot: Dot::new(device, seq).ok_or(VaultError::Corrupt {
                    what: "vault_ops.device_seq is 0",
                })?,
                item_id: ItemId::from_bytes(id16(&item, "vault_ops.item_id")?),
                record: stored_op(cols)?,
            })
        })
        .collect()
}

/// The item's op dots with their body flags (ADR 0021 §7 input).
pub(crate) async fn item_op_dots(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
) -> Result<Vec<OpDot>, VaultError> {
    let rows: Vec<(Vec<u8>, i64, i64)> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(ITEM_OP_DOTS)
            .bind(&vault_id.as_bytes()[..])
            .bind(&item_id.as_bytes()[..])
            .fetch_all(&mut *c)
            .await?
        {
            out.push((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?));
        }
        out
    });
    rows.into_iter()
        .map(|(device, seq, held)| {
            let device = DeviceId::from_bytes(id16(&device, "vault_ops.device_id")?);
            let seq = sql_to_u64(seq, "vault_ops.device_seq")?;
            Ok(OpDot {
                dot: Dot::new(device, seq).ok_or(VaultError::Corrupt {
                    what: "vault_ops.device_seq is 0",
                })?,
                body: if held == 0 { Body::Absent } else { Body::Held },
            })
        })
        .collect()
}

/// Deletes the body of the item's op at `dot` (R1).
pub(crate) async fn delete_body(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
    dot: Dot,
) -> Result<(), VaultError> {
    let seq = u64_to_sql(dot.seq(), "vault_ops.device_seq")?;
    on_engine!(conn, |c| sqlx::query(OP_DELETE_BODY)
        .bind(&vault_id.as_bytes()[..])
        .bind(&dot.device_id().as_bytes()[..])
        .bind(seq)
        .bind(&item_id.as_bytes()[..])
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// The columns of a stored snapshot, as read.
type SnapshotColumns = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// Rebuilds a stored snapshot from its columns.
fn stored_snapshot(cols: SnapshotColumns) -> Result<StoredRecord, VaultError> {
    let (header, envelope, wrap_hash, signature, key_wrap) = cols;
    let envelope_hash =
        crate::intake::snapshot_envelope_hash(&header, &envelope).map_err(|_| {
            VaultError::Corrupt {
                what: "vault_snapshots.header length",
            }
        })?;
    Ok(StoredRecord {
        signed: Signed {
            header,
            envelope_hash,
            wrap_hash: hash32(&wrap_hash, "vault_snapshots.wrap_hash")?,
            container: container(&signature, "vault_snapshots.signature")?,
        },
        body: Some(envelope),
        key_wrap,
    })
}

/// The snapshot stored under `snapshot_id`, if any.
pub(crate) async fn get_snapshot(
    conn: Conn<'_>,
    vault_id: VaultId,
    snapshot_id: SnapshotId,
) -> Result<Option<StoredRecord>, VaultError> {
    let row: Option<SnapshotColumns> = on_engine!(conn, |c| {
        match sqlx::query(SNAPSHOT_GET)
            .bind(&vault_id.as_bytes()[..])
            .bind(&snapshot_id.as_bytes()[..])
            .fetch_optional(&mut *c)
            .await?
        {
            Some(r) => Some((
                r.try_get(0)?,
                r.try_get(1)?,
                r.try_get(2)?,
                r.try_get(3)?,
                r.try_get(4)?,
            )),
            None => None,
        }
    });
    row.map(stored_snapshot).transpose()
}

/// Stores a verified snapshot with its clamped VV (canonical encoding) and store sequence.
pub(crate) async fn insert_snapshot(
    conn: Conn<'_>,
    vault_id: VaultId,
    snapshot: &VerifiedSnapshot,
    clamped: &[u8],
    store_seq: u64,
    now_ms: i64,
) -> Result<(), VaultError> {
    let h = &snapshot.header;
    let store_seq = u64_to_sql(store_seq, "vault_snapshots.store_seq")?;
    let wrap = snapshot.key_wrap.as_ref().map(|w| w.envelope.as_slice());
    on_engine!(conn, |c| sqlx::query(SNAPSHOT_INSERT)
        .bind(&vault_id.as_bytes()[..])
        .bind(&h.snapshot_id.as_bytes()[..])
        .bind(&h.item_id.as_bytes()[..])
        .bind(&h.author.as_bytes()[..])
        .bind(i64::from(h.item_schema_version.get()))
        .bind(u32_to_sql(h.vault_key_epoch))
        .bind(snapshot.signed.header.as_slice())
        .bind(snapshot.envelope.as_slice())
        .bind(&snapshot.signed.wrap_hash[..])
        .bind(&snapshot.signed.container[..])
        .bind(wrap)
        .bind(clamped)
        .bind(store_seq)
        .bind(now_ms)
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// The item's retained snapshots as the compaction rules see them, oldest first.
pub(crate) async fn item_snapshots(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
) -> Result<Vec<RetainedSnapshot>, VaultError> {
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(ITEM_SNAPSHOTS)
            .bind(&vault_id.as_bytes()[..])
            .bind(&item_id.as_bytes()[..])
            .fetch_all(&mut *c)
            .await?
        {
            out.push((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?));
        }
        out
    });
    rows.into_iter()
        .map(|(store_seq, author, clamped)| {
            Ok(RetainedSnapshot {
                store_seq: sql_to_u64(store_seq, "vault_snapshots.store_seq")?,
                clamped: VersionVector::parse(&clamped).map_err(|_| VaultError::Corrupt {
                    what: "vault_snapshots.clamped_vv",
                })?,
                author: DeviceId::from_bytes(id16(&author, "vault_snapshots.author_device_id")?),
            })
        })
        .collect()
}

/// The full record of the item's snapshot with `store_seq`, if retained.
pub(crate) async fn snapshot_record(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
    store_seq: u64,
) -> Result<Option<StoredRecord>, VaultError> {
    let store_seq = u64_to_sql(store_seq, "vault_snapshots.store_seq")?;
    let row: Option<SnapshotColumns> = on_engine!(conn, |c| {
        match sqlx::query(SNAPSHOT_BY_STORE_SEQ)
            .bind(&vault_id.as_bytes()[..])
            .bind(&item_id.as_bytes()[..])
            .bind(store_seq)
            .fetch_optional(&mut *c)
            .await?
        {
            Some(r) => Some((
                r.try_get(0)?,
                r.try_get(1)?,
                r.try_get(2)?,
                r.try_get(3)?,
                r.try_get(4)?,
            )),
            None => None,
        }
    });
    row.map(stored_snapshot).transpose()
}

/// Drops the item's snapshot with `store_seq` (R3).
pub(crate) async fn delete_snapshot(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
    store_seq: u64,
) -> Result<(), VaultError> {
    let store_seq = u64_to_sql(store_seq, "vault_snapshots.store_seq")?;
    on_engine!(conn, |c| sqlx::query(SNAPSHOT_DELETE)
        .bind(&vault_id.as_bytes()[..])
        .bind(&item_id.as_bytes()[..])
        .bind(store_seq)
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// Queues the item for the compaction job; an item already queued keeps its place.
pub(crate) async fn enqueue(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
    now_ms: i64,
) -> Result<(), VaultError> {
    on_engine!(conn, |c| sqlx::query(COMPACTION_ENQUEUE)
        .bind(&vault_id.as_bytes()[..])
        .bind(&item_id.as_bytes()[..])
        .bind(now_ms)
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// Removes the item from the compaction queue.
pub(crate) async fn dequeue(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
) -> Result<(), VaultError> {
    on_engine!(conn, |c| sqlx::query(COMPACTION_DEQUEUE)
        .bind(&vault_id.as_bytes()[..])
        .bind(&item_id.as_bytes()[..])
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// Moves the queued item behind every other queued item (a failed compaction). No-op for an
/// item that is not queued.
pub(crate) async fn defer(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
) -> Result<(), VaultError> {
    on_engine!(conn, |c| sqlx::query(COMPACTION_DEFER)
        .bind(&vault_id.as_bytes()[..])
        .bind(&item_id.as_bytes()[..])
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// The stored size in bytes of each of the item's retained snapshots, by store sequence.
pub(crate) async fn item_snapshot_sizes(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
) -> Result<std::collections::BTreeMap<u64, usize>, VaultError> {
    let rows: Vec<(i64, i64)> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(ITEM_SNAPSHOT_SIZES)
            .bind(&vault_id.as_bytes()[..])
            .bind(&item_id.as_bytes()[..])
            .fetch_all(&mut *c)
            .await?
        {
            out.push((r.try_get(0)?, r.try_get(1)?));
        }
        out
    });
    rows.into_iter()
        .map(|(store_seq, size)| {
            let store_seq = sql_to_u64(store_seq, "vault_snapshots.store_seq")?;
            let size = usize::try_from(size).map_err(|_| VaultError::Corrupt {
                what: "a vault_snapshots row's size",
            })?;
            Ok((store_seq, size))
        })
        .collect()
}

/// The oldest queued items, at most `limit`.
pub(crate) async fn queued(
    conn: Conn<'_>,
    limit: usize,
) -> Result<Vec<(VaultId, ItemId)>, VaultError> {
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows: Vec<(Vec<u8>, Vec<u8>)> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(COMPACTION_LIST)
            .bind(limit)
            .fetch_all(&mut *c)
            .await?
        {
            out.push((r.try_get(0)?, r.try_get(1)?));
        }
        out
    });
    rows.into_iter()
        .map(|(vault, item)| {
            Ok((
                VaultId::from_bytes(id16(&vault, "vault_compaction_queue.vault_id")?),
                ItemId::from_bytes(id16(&item, "vault_compaction_queue.item_id")?),
            ))
        })
        .collect()
}

/// One wrap-set row (CRYPTO.md §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WrapRow {
    /// The item.
    pub(crate) item_id: ItemId,
    /// The wrapped item key's id.
    pub(crate) item_key_id: [u8; 16],
    /// The wrapping vault key's epoch.
    pub(crate) vault_key_epoch: u32,
    /// The envelope.
    pub(crate) envelope: Vec<u8>,
}

/// What [`put_wrap`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WrapPut {
    /// The row was missing and is now stored.
    Inserted,
    /// A row at a lower epoch was replaced.
    Replaced,
    /// A row at the same or a higher epoch is kept.
    Kept,
}

/// Fills the wrap-set row of `wrap` (CRYPTO.md §4.2): inserts it when the server lacks the row,
/// replaces a row at a lower `vault_key_epoch`, and otherwise keeps the stored row. The row's
/// locator is never trusted: readers rebuild the AAD context and check the key id.
pub(crate) async fn put_wrap(
    conn: Conn<'_>,
    vault_id: VaultId,
    wrap: &WrapRow,
    now_ms: i64,
) -> Result<WrapPut, VaultError> {
    let epoch = u32_to_sql(wrap.vault_key_epoch);
    on_engine!(conn, |c| {
        let stored: Option<i64> = sqlx::query_scalar(WRAP_GET)
            .bind(&vault_id.as_bytes()[..])
            .bind(&wrap.item_id.as_bytes()[..])
            .bind(&wrap.item_key_id[..])
            .fetch_optional(&mut *c)
            .await?;
        match stored {
            None => {
                sqlx::query(WRAP_INSERT)
                    .bind(&vault_id.as_bytes()[..])
                    .bind(&wrap.item_id.as_bytes()[..])
                    .bind(&wrap.item_key_id[..])
                    .bind(epoch)
                    .bind(wrap.envelope.as_slice())
                    .bind(now_ms)
                    .execute(&mut *c)
                    .await?;
                Ok(WrapPut::Inserted)
            }
            Some(stored) if stored < epoch => {
                sqlx::query(WRAP_REPLACE)
                    .bind(&vault_id.as_bytes()[..])
                    .bind(&wrap.item_id.as_bytes()[..])
                    .bind(&wrap.item_key_id[..])
                    .bind(epoch)
                    .bind(wrap.envelope.as_slice())
                    .bind(now_ms)
                    .execute(&mut *c)
                    .await?;
                Ok(WrapPut::Replaced)
            }
            Some(_) => Ok(WrapPut::Kept),
        }
    })
}

/// The item key id of the wrap-set row holding exactly `envelope`, if the row is still current.
pub(crate) async fn wrap_by_envelope(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
    envelope: &[u8],
) -> Result<Option<[u8; 16]>, VaultError> {
    let id: Option<Vec<u8>> = on_engine!(conn, |c| sqlx::query_scalar(WRAP_BY_ENVELOPE)
        .bind(&vault_id.as_bytes()[..])
        .bind(&item_id.as_bytes()[..])
        .bind(envelope)
        .fetch_optional(&mut *c)
        .await)?;
    id.map(|id| id16(&id, "vault_item_key_wraps.item_key_id"))
        .transpose()
}

/// The columns of a wrap-set row, as read: item id, item key id, epoch, envelope.
type WrapColumns = (Vec<u8>, Vec<u8>, i64, Vec<u8>);

/// The wrap-set rows with `vault_key_epoch` above `after` (all when `None`), at most `limit`.
pub(crate) async fn wraps_after(
    conn: Conn<'_>,
    vault_id: VaultId,
    after: Option<u32>,
    limit: usize,
) -> Result<Vec<WrapRow>, VaultError> {
    let after = after.map_or(-1, u32_to_sql);
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows: Vec<WrapColumns> = on_engine!(conn, |c| {
        let mut out = Vec::new();
        for r in sqlx::query(WRAPS_AFTER)
            .bind(&vault_id.as_bytes()[..])
            .bind(after)
            .bind(limit)
            .fetch_all(&mut *c)
            .await?
        {
            out.push((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?, r.try_get(3)?));
        }
        out
    });
    rows.into_iter()
        .map(|(item, key, epoch, envelope)| {
            Ok(WrapRow {
                item_id: ItemId::from_bytes(id16(&item, "vault_item_key_wraps.item_id")?),
                item_key_id: id16(&key, "vault_item_key_wraps.item_key_id")?,
                vault_key_epoch: sql_to_u32(epoch, "vault_item_key_wraps.vault_key_epoch")?,
                envelope,
            })
        })
        .collect()
}

/// A vault self-grant row (CRYPTO.md §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelfGrantRow {
    /// `account_key_epoch` of its context.
    pub(crate) account_key_epoch: u32,
    /// `vault_key_epoch` of its context.
    pub(crate) vault_key_epoch: u32,
    /// The envelope.
    pub(crate) envelope: Vec<u8>,
}

/// The vault's current self-grant, if any.
pub(crate) async fn self_grant(
    conn: Conn<'_>,
    vault_id: VaultId,
) -> Result<Option<SelfGrantRow>, VaultError> {
    let row: Option<(i64, i64, Vec<u8>)> = on_engine!(conn, |c| {
        match sqlx::query(SELF_GRANT_GET)
            .bind(&vault_id.as_bytes()[..])
            .fetch_optional(&mut *c)
            .await?
        {
            Some(r) => Some((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?)),
            None => None,
        }
    });
    row.map(|(account_epoch, vault_epoch, envelope)| {
        Ok(SelfGrantRow {
            account_key_epoch: sql_to_u32(account_epoch, "vault_self_grants.account_key_epoch")?,
            vault_key_epoch: sql_to_u32(vault_epoch, "vault_self_grants.vault_key_epoch")?,
            envelope,
        })
    })
    .transpose()
}

/// Inserts (`replace` false) or replaces (`replace` true) the vault's self-grant.
pub(crate) async fn write_self_grant(
    conn: Conn<'_>,
    vault_id: VaultId,
    grant: &SelfGrantRow,
    replace: bool,
    now_ms: i64,
) -> Result<(), VaultError> {
    let query = if replace {
        SELF_GRANT_REPLACE
    } else {
        SELF_GRANT_INSERT
    };
    on_engine!(conn, |c| sqlx::query(query)
        .bind(&vault_id.as_bytes()[..])
        .bind(u32_to_sql(grant.account_key_epoch))
        .bind(u32_to_sql(grant.vault_key_epoch))
        .bind(grant.envelope.as_slice())
        .bind(now_ms)
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// Sets the vault's current `vault_key_epoch` (a rotation, ADR 0025 §3 step 5).
pub(crate) async fn set_vault_epoch(
    conn: Conn<'_>,
    vault_id: VaultId,
    vault_key_epoch: u32,
) -> Result<(), VaultError> {
    on_engine!(conn, |c| sqlx::query(VAULT_SET_EPOCH)
        .bind(&vault_id.as_bytes()[..])
        .bind(u32_to_sql(vault_key_epoch))
        .execute(&mut *c)
        .await
        .map(|_| ()))?;
    Ok(())
}

/// The clamped VV of every retained snapshot of the vault.
pub(crate) async fn clamped_vvs(
    conn: Conn<'_>,
    vault_id: VaultId,
) -> Result<Vec<VersionVector>, VaultError> {
    let rows: Vec<Vec<u8>> = on_engine!(conn, |c| sqlx::query_scalar(VAULT_CLAMPED_VVS)
        .bind(&vault_id.as_bytes()[..])
        .fetch_all(&mut *c)
        .await)?;
    rows.iter()
        .map(|v| {
            VersionVector::parse(v).map_err(|_| VaultError::Corrupt {
                what: "vault_snapshots.clamped_vv",
            })
        })
        .collect()
}

/// Overwrites the wrap-set row `(wrap.item_id, wrap.item_key_id)` with `wrap`'s epoch and
/// envelope, whatever the stored epoch (a rotation's re-wrap, ADR 0025 §3 step 5). Returns the
/// number of rows changed.
pub(crate) async fn overwrite_wrap(
    conn: Conn<'_>,
    vault_id: VaultId,
    wrap: &WrapRow,
    now_ms: i64,
) -> Result<u64, VaultError> {
    Ok(on_engine!(conn, |c| sqlx::query(WRAP_OVERWRITE)
        .bind(&vault_id.as_bytes()[..])
        .bind(&wrap.item_id.as_bytes()[..])
        .bind(&wrap.item_key_id[..])
        .bind(u32_to_sql(wrap.vault_key_epoch))
        .bind(wrap.envelope.as_slice())
        .bind(now_ms)
        .execute(&mut *c)
        .await
        .map(|r| r.rows_affected()))?)
}

/// Deletes the wrap-set row `(item_id, item_key_id)`. Returns the number of rows deleted.
pub(crate) async fn delete_wrap(
    conn: Conn<'_>,
    vault_id: VaultId,
    item_id: ItemId,
    item_key_id: &[u8; 16],
) -> Result<u64, VaultError> {
    Ok(on_engine!(conn, |c| sqlx::query(WRAP_DELETE)
        .bind(&vault_id.as_bytes()[..])
        .bind(&item_id.as_bytes()[..])
        .bind(&item_key_id[..])
        .execute(&mut *c)
        .await
        .map(|r| r.rows_affected()))?)
}

/// Drops the wrap carried with every op and snapshot of the vault (the superseded wraps of a
/// rotation, ADR 0025 §3 step 5). The signed wrap hashes stay.
pub(crate) async fn clear_record_wraps(
    mut conn: Conn<'_>,
    vault_id: VaultId,
) -> Result<(), VaultError> {
    for query in [OPS_CLEAR_WRAPS, SNAPSHOTS_CLEAR_WRAPS] {
        let c = match &mut conn {
            Conn::Sqlite(c) => Conn::Sqlite(c),
            Conn::Postgres(c) => Conn::Postgres(c),
        };
        on_engine!(c, |c| sqlx::query(query)
            .bind(&vault_id.as_bytes()[..])
            .execute(&mut *c)
            .await
            .map(|_| ()))?;
    }
    Ok(())
}

/// Drops the wrap carried with every op and snapshot of the vault whose header names a
/// `vault_key_epoch` below `epoch` (healing step 3b, ADR 0032 §3): those wraps are under a vault
/// key the healed rotation superseded. Records at `epoch` keep theirs. The signed wrap hashes
/// stay.
pub(crate) async fn clear_record_wraps_below(
    mut conn: Conn<'_>,
    vault_id: VaultId,
    epoch: u32,
) -> Result<(), VaultError> {
    for query in [OPS_CLEAR_WRAPS_BELOW, SNAPSHOTS_CLEAR_WRAPS_BELOW] {
        let c = match &mut conn {
            Conn::Sqlite(c) => Conn::Sqlite(c),
            Conn::Postgres(c) => Conn::Postgres(c),
        };
        on_engine!(c, |c| sqlx::query(query)
            .bind(&vault_id.as_bytes()[..])
            .bind(u32_to_sql(epoch))
            .execute(&mut *c)
            .await
            .map(|_| ()))?;
    }
    Ok(())
}
