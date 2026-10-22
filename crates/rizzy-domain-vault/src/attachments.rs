// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted attachments on the server: declare, fetch the wrap, store and serve chunks, delete,
//! and the 24 h sweep of unfinished uploads ([ADR 0054] §5–§7).
//!
//! **What the server sees.** An attachment row holds the opaque `ATTACHMENT_KEY_WRAP`, the
//! vault and item it belongs to, the plaintext size the client declared in the clear, and the
//! chunk count derived from it; a chunk row holds one opaque `ATTACHMENT_CHUNK` envelope. The
//! server never opens either, and its chunk count never enters an AAD: the client derives its
//! own from the item's `attachment/<id>/size` field (ADR 0054 §1).
//!
//! **Ownership** (ADR 0054 §6). Every call resolves the attachment through its vault's owner:
//! an id of another account is [`VaultError::NotFound`], exactly as an unknown one, so no call
//! is an IDOR surface (threat model A15).
//!
//! **Checks, per call.**
//! - [`VaultDomain::create_attachment`]: a declared size over the 25 MiB cap, or one whose
//!   counted bytes pass the account's remaining quota, is [`VaultError::QuotaExceeded`] (ADR
//!   0054 "Owner answers" 5, ADR 0048 §5); a wrap of any length but 122 bytes is
//!   [`VaultError::Invalid`]; the vault must be the account's. The quota is charged in the same
//!   account-locked transaction as the insert. A byte-identical repeat is a no-op success,
//!   anything else under the same id [`VaultError::RecordConflict`].
//! - [`VaultDomain::upload_attachment_chunk`]: an index at or past the chunk count is
//!   [`VaultError::NotFound`]; an envelope whose length is not exactly what the declared size
//!   implies for that index (`CHUNK_SIZE + 90`, or the remainder plus 90 for the last) is
//!   [`VaultError::Invalid`] — without this, the cap and the quota would be advisory. A
//!   byte-identical repeat is a no-op success, another envelope at a stored index
//!   [`VaultError::RecordConflict`].
//! - [`VaultDomain::download_attachment_chunk`] and [`VaultDomain::attachment_key_wrap`]: a chunk
//!   not stored is [`VaultError::NotFound`]. The wrap is answered alone, never with the size or
//!   the count.
//! - [`VaultDomain::delete_attachment`]: both tables' rows and the counted bytes, in one
//!   transaction.
//!
//! **Counted bytes** (ADR 0048 §2, ADR 0054 §6). An attachment counts its wrap's length plus
//! every chunk envelope its declared size implies, `total_plaintext_len + 90 × chunk_count`,
//! from `create` until `delete` or the sweep, whether its chunks are stored yet or not: `create`
//! reserves what the upload will store, so a chunk upload never changes the counter, and
//! [`crate::usage::counted_bytes`] recomputes the same figure from the attachment rows alone.
//!
//! **The sweep** (ADR 0054 §7). [`VaultDomain::sweep_attachments`], run by `worker`, deletes an
//! attachment created more than [`SWEEP_AGE_MS`] ago whose stored chunks are still fewer than its
//! chunk count, and releases its counted bytes. A complete attachment is never swept, even if no
//! item references it any more: that residual is accepted for M3 (ADR 0054 "Owner answers" 3).
//!
//! [ADR 0054]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0054-attachments-envelope-and-api.md

use rizzy_core::attachment::{ATTACHMENT_KEY_WRAP_LEN, AttachmentLayout};
use rizzy_core::ids::{AccountId, AttachmentId, ItemId, VaultId};
use rizzy_proto::attachments::{
    AttachmentRequest, CreateAttachmentRequest, DownloadChunkRequest, DownloadChunkResponse,
    GetAttachmentResponse, UploadChunkRequest,
};
use rizzy_proto::limits::ATTACHMENT_KEY_WRAP_LEN as WIRE_WRAP_LEN;
use rizzy_proto::wire::{Bytes, Fixed, Id};
use rizzy_storage::convert::{sql_to_u32, sql_to_u64, u32_to_sql, u64_to_sql};
use rizzy_storage::{Conn, lock_account, on_engine};
use sqlx::Row;

use crate::error::VaultError;
use crate::usage::{charge, credit};
use crate::{VaultDomain, repo, to_sql_time};

/// One attachment with its vault's owner.
const ATTACHMENT_GET: &str = include_str!("../queries/attachment_get.sql");
/// A new attachment row.
const ATTACHMENT_INSERT: &str = include_str!("../queries/attachment_insert.sql");
/// Deletes an attachment row.
const ATTACHMENT_DELETE: &str = include_str!("../queries/attachment_delete.sql");
/// Deletes every chunk of an attachment.
const ATTACHMENT_CHUNKS_DELETE: &str = include_str!("../queries/attachment_chunks_delete.sql");
/// One chunk envelope.
const ATTACHMENT_CHUNK_GET: &str = include_str!("../queries/attachment_chunk_get.sql");
/// A new chunk row.
const ATTACHMENT_CHUNK_INSERT: &str = include_str!("../queries/attachment_chunk_insert.sql");
/// Unfinished attachments older than a cutoff.
const ATTACHMENT_SWEEP_LIST: &str = include_str!("../queries/attachment_sweep_list.sql");
/// One account's attachment rows for the storage counter.
const USAGE_ATTACHMENTS: &str = include_str!("../queries/usage_attachments.sql");

/// How old an unfinished upload must be before the sweep deletes it: 24 h (ADR 0054 §7).
pub const SWEEP_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// The most attachments one sweep pass deletes; the next pass continues.
const SWEEP_BATCH: i64 = 256;

/// An `attachments/create` declaration, its ids already parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAttachment {
    /// The attachment's id.
    pub attachment_id: AttachmentId,
    /// The vault holding the item.
    pub vault_id: VaultId,
    /// The item.
    pub item_id: ItemId,
    /// The opaque `ATTACHMENT_KEY_WRAP` envelope.
    pub attachment_key_wrap: Vec<u8>,
    /// The declared plaintext size.
    pub total_plaintext_len: u64,
}

/// A stored attachment row, with its vault's owner and its stored chunk count.
#[derive(Debug)]
struct Stored {
    /// The vault.
    vault_id: VaultId,
    /// The item.
    item_id: ItemId,
    /// The wrap envelope.
    wrap: Vec<u8>,
    /// The layout the declared size gives; its count matched the stored `chunk_count`.
    layout: AttachmentLayout,
    /// Creation time, ms.
    created_at_ms: u64,
    /// The vault's owner.
    account_id: AccountId,
    /// Chunks stored so far.
    chunks_present: u64,
}

impl Stored {
    /// The attachment's counted bytes (module docs).
    fn counted(&self) -> u64 {
        counted_bytes(self.wrap.len(), self.layout)
    }

    /// Whether every chunk is stored.
    fn complete(&self) -> bool {
        self.chunks_present >= u64::from(self.layout.chunk_count())
    }
}

/// The counted bytes of an attachment with a `wrap_len`-byte wrap laid out as `layout`.
fn counted_bytes(wrap_len: usize, layout: AttachmentLayout) -> u64 {
    u64::try_from(wrap_len)
        .unwrap_or(u64::MAX)
        .saturating_add(layout.envelopes_len())
}

/// A 16-byte id read back from a column.
fn id16(bytes: &[u8], what: &'static str) -> Result<[u8; 16], VaultError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| VaultError::Corrupt { what })
}

/// A counted delta as an `i64` charge.
fn as_charge(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

/// The attachment `attachment_id`, if it exists.
async fn get(conn: Conn<'_>, attachment_id: AttachmentId) -> Result<Option<Stored>, VaultError> {
    type Raw = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>, i64);
    let raw: Option<Raw> = on_engine!(conn, |c| {
        match sqlx::query(ATTACHMENT_GET)
            .bind(&attachment_id.as_bytes()[..])
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
                r.try_get(6)?,
                r.try_get(7)?,
            )),
            None => None,
        }
    });
    let Some((vault, item, wrap, total, count, created, account, stored)) = raw else {
        return Ok(None);
    };
    let total = sql_to_u64(total, "vault_attachments.total_plaintext_len")?;
    let count = sql_to_u32(count, "vault_attachments.chunk_count")?;
    let layout = AttachmentLayout::new(total)
        .ok()
        .filter(|l| l.chunk_count() == count)
        .ok_or(VaultError::Corrupt {
            what: "vault_attachments.chunk_count",
        })?;
    Ok(Some(Stored {
        vault_id: VaultId::from_bytes(id16(&vault, "vault_attachments.vault_id")?),
        item_id: ItemId::from_bytes(id16(&item, "vault_attachments.item_id")?),
        wrap,
        layout,
        created_at_ms: sql_to_u64(created, "vault_attachments.created_at_ms")?,
        account_id: AccountId::from_bytes(id16(&account, "vault_vaults.account_id")?),
        chunks_present: sql_to_u64(stored, "vault_attachment_chunks count")?,
    }))
}

/// The attachment, when it exists and belongs to `account_id`; [`VaultError::NotFound`] otherwise.
async fn owned(
    conn: Conn<'_>,
    attachment_id: AttachmentId,
    account_id: AccountId,
) -> Result<Stored, VaultError> {
    get(conn, attachment_id)
        .await?
        .filter(|a| a.account_id == account_id)
        .ok_or(VaultError::NotFound)
}

/// One stored chunk envelope.
async fn chunk(
    conn: Conn<'_>,
    attachment_id: AttachmentId,
    chunk_index: u32,
) -> Result<Option<Vec<u8>>, VaultError> {
    Ok(on_engine!(conn, |c| sqlx::query_scalar(
        ATTACHMENT_CHUNK_GET
    )
    .bind(&attachment_id.as_bytes()[..])
    .bind(u32_to_sql(chunk_index))
    .fetch_optional(&mut *c)
    .await)?)
}

/// Deletes the attachment's chunks and row.
async fn delete_rows(conn: &mut Conn<'_>, attachment_id: AttachmentId) -> Result<(), VaultError> {
    for query in [ATTACHMENT_CHUNKS_DELETE, ATTACHMENT_DELETE] {
        on_engine!(reborrow(conn), |c| sqlx::query(query)
            .bind(&attachment_id.as_bytes()[..])
            .execute(&mut *c)
            .await
            .map(|_| ()))?;
    }
    Ok(())
}

/// A shorter-lived view of the same connection.
fn reborrow<'a>(conn: &'a mut Conn<'_>) -> Conn<'a> {
    match conn {
        Conn::Sqlite(c) => Conn::Sqlite(c),
        Conn::Postgres(c) => Conn::Postgres(c),
    }
}

/// One account's attachment rows: their number and counted bytes (module docs), for
/// [`crate::usage::counted_bytes`].
pub(crate) async fn account_attachment_bytes(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<u64, VaultError> {
    let (_rows, bytes): (i64, i64) = on_engine!(conn, |c| sqlx::query(USAGE_ATTACHMENTS)
        .bind(&account_id.as_bytes()[..])
        .fetch_one(&mut *c)
        .await
        .and_then(|row| Ok::<_, sqlx::Error>((row.try_get(0)?, row.try_get(1)?))))?;
    Ok(sql_to_u64(bytes, "a counted attachment length")?)
}

/// An attachment id from the wire.
const fn attachment_id(id: &Id) -> AttachmentId {
    AttachmentId::from_bytes(id.to_bytes())
}

/// The endpoint forms of the calls below, as `rizzy-server` maps `/api/v1/attachments/*` onto
/// them: the `rizzy-proto` request in, the response out.
impl<D> VaultDomain<D> {
    /// `attachments/create`: [`VaultDomain::create_attachment`].
    ///
    /// # Errors
    /// As [`VaultDomain::create_attachment`].
    pub async fn attachments_create(
        &self,
        account_id: AccountId,
        request: &CreateAttachmentRequest,
        now_ms: u64,
    ) -> Result<(), VaultError> {
        let new = NewAttachment {
            attachment_id: attachment_id(&request.attachment_id),
            vault_id: VaultId::from_bytes(request.vault_id.to_bytes()),
            item_id: ItemId::from_bytes(request.item_id.to_bytes()),
            attachment_key_wrap: request.attachment_key_wrap.as_bytes().to_vec(),
            total_plaintext_len: request.total_plaintext_len,
        };
        self.create_attachment(account_id, &new, now_ms).await
    }

    /// `attachments/get`: [`VaultDomain::attachment_key_wrap`].
    ///
    /// # Errors
    /// As [`VaultDomain::attachment_key_wrap`]; [`VaultError::Corrupt`] for a stored wrap of
    /// another length.
    pub async fn attachments_get(
        &self,
        account_id: AccountId,
        request: &AttachmentRequest,
    ) -> Result<GetAttachmentResponse, VaultError> {
        let wrap = self
            .attachment_key_wrap(account_id, attachment_id(&request.attachment_id))
            .await?;
        let wrap =
            <[u8; WIRE_WRAP_LEN]>::try_from(wrap.as_slice()).map_err(|_| VaultError::Corrupt {
                what: "vault_attachments.attachment_key_wrap",
            })?;
        Ok(GetAttachmentResponse {
            attachment_key_wrap: Fixed::from_bytes(wrap),
        })
    }

    /// `attachments/upload-chunk`: [`VaultDomain::upload_attachment_chunk`].
    ///
    /// # Errors
    /// As [`VaultDomain::upload_attachment_chunk`].
    pub async fn attachments_upload_chunk(
        &self,
        account_id: AccountId,
        request: &UploadChunkRequest,
    ) -> Result<(), VaultError> {
        self.upload_attachment_chunk(
            account_id,
            attachment_id(&request.attachment_id),
            request.chunk_index,
            request.envelope.as_slice(),
        )
        .await
    }

    /// `attachments/download-chunk`: [`VaultDomain::download_attachment_chunk`].
    ///
    /// # Errors
    /// As [`VaultDomain::download_attachment_chunk`]; [`VaultError::Corrupt`] for a stored
    /// envelope over the wire limit.
    pub async fn attachments_download_chunk(
        &self,
        account_id: AccountId,
        request: &DownloadChunkRequest,
    ) -> Result<DownloadChunkResponse, VaultError> {
        let envelope = self
            .download_attachment_chunk(
                account_id,
                attachment_id(&request.attachment_id),
                request.chunk_index,
            )
            .await?;
        Ok(DownloadChunkResponse {
            envelope: Bytes::new(envelope).map_err(|_| VaultError::Corrupt {
                what: "vault_attachment_chunks.chunk_envelope",
            })?,
        })
    }

    /// `attachments/delete`: [`VaultDomain::delete_attachment`].
    ///
    /// # Errors
    /// As [`VaultDomain::delete_attachment`].
    pub async fn attachments_delete(
        &self,
        account_id: AccountId,
        request: &AttachmentRequest,
        now_ms: u64,
    ) -> Result<(), VaultError> {
        self.delete_attachment(account_id, attachment_id(&request.attachment_id), now_ms)
            .await
    }
}

impl<D> VaultDomain<D> {
    /// `attachments/create` (ADR 0054 §6): declares an attachment and charges its counted bytes.
    ///
    /// # Errors
    /// [`VaultError::QuotaExceeded`] over the 25 MiB cap or the account's remaining quota;
    /// [`VaultError::Invalid`] for a wrap of the wrong length; [`VaultError::NotFound`] for a vault
    /// or an attachment id of another account; [`VaultError::RecordConflict`] for another
    /// declaration under a stored id; storage errors.
    pub async fn create_attachment(
        &self,
        account_id: AccountId,
        new: &NewAttachment,
        now_ms: u64,
    ) -> Result<(), VaultError> {
        let layout = AttachmentLayout::new(new.total_plaintext_len)
            .map_err(|_| VaultError::QuotaExceeded)?;
        if new.attachment_key_wrap.len() != ATTACHMENT_KEY_WRAP_LEN {
            return Err(VaultError::Invalid);
        }
        let now_sql = to_sql_time(now_ms)?;
        let mut tx = self.database().begin_write().await?;
        lock_account(&mut tx, account_id.as_bytes()).await?;
        repo::vault(tx.conn(), new.vault_id)
            .await?
            .filter(|v| v.account_id == account_id)
            .ok_or(VaultError::NotFound)?;
        if let Some(stored) = get(tx.conn(), new.attachment_id).await? {
            if stored.account_id != account_id {
                return Err(VaultError::NotFound);
            }
            let same = stored.vault_id == new.vault_id
                && stored.item_id == new.item_id
                && stored.wrap == new.attachment_key_wrap
                && stored.layout.size() == new.total_plaintext_len;
            return if same {
                Ok(())
            } else {
                Err(VaultError::RecordConflict)
            };
        }
        let counted = counted_bytes(new.attachment_key_wrap.len(), layout);
        let used = rizzy_storage::quota::bytes_used(tx.conn(), account_id.as_bytes()).await?;
        if used.saturating_add(counted) > self.quota.quota_bytes {
            return Err(VaultError::QuotaExceeded);
        }
        on_engine!(tx.conn(), |c| sqlx::query(ATTACHMENT_INSERT)
            .bind(&new.attachment_id.as_bytes()[..])
            .bind(&new.vault_id.as_bytes()[..])
            .bind(&new.item_id.as_bytes()[..])
            .bind(new.attachment_key_wrap.as_slice())
            .bind(u64_to_sql(layout.size(), "total_plaintext_len")?)
            .bind(u32_to_sql(layout.chunk_count()))
            .bind(now_sql)
            .execute(&mut *c)
            .await
            .map(|_| ()))?;
        charge(&mut tx, account_id, as_charge(counted), now_sql).await?;
        tx.commit().await?;
        Ok(())
    }

    /// `attachments/get` (ADR 0054 §6): the attachment's key wrap, and nothing else.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown or foreign id; storage errors.
    pub async fn attachment_key_wrap(
        &self,
        account_id: AccountId,
        attachment_id: AttachmentId,
    ) -> Result<Vec<u8>, VaultError> {
        let mut read = self.database().begin_read().await?;
        let stored = owned(read.conn(), attachment_id, account_id).await?;
        read.finish().await?;
        Ok(stored.wrap)
    }

    /// `attachments/upload-chunk` (ADR 0054 §6): stores one chunk envelope.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown or foreign id or an index past the chunk count;
    /// [`VaultError::Invalid`] for an envelope of another length than the index's;
    /// [`VaultError::RecordConflict`] for another envelope at a stored index; storage errors.
    pub async fn upload_attachment_chunk(
        &self,
        account_id: AccountId,
        attachment_id: AttachmentId,
        chunk_index: u32,
        envelope: &[u8],
    ) -> Result<(), VaultError> {
        let mut tx = self.database().begin_write().await?;
        lock_account(&mut tx, account_id.as_bytes()).await?;
        let stored = owned(tx.conn(), attachment_id, account_id).await?;
        let expected = stored
            .layout
            .chunk_envelope_len(chunk_index)
            .ok_or(VaultError::NotFound)?;
        if envelope.len() != expected {
            return Err(VaultError::Invalid);
        }
        if let Some(existing) = chunk(tx.conn(), attachment_id, chunk_index).await? {
            return if existing == envelope {
                Ok(())
            } else {
                Err(VaultError::RecordConflict)
            };
        }
        on_engine!(tx.conn(), |c| sqlx::query(ATTACHMENT_CHUNK_INSERT)
            .bind(&attachment_id.as_bytes()[..])
            .bind(u32_to_sql(chunk_index))
            .bind(envelope)
            .execute(&mut *c)
            .await
            .map(|_| ()))?;
        tx.commit().await?;
        Ok(())
    }

    /// `attachments/download-chunk` (ADR 0054 §6): one stored chunk envelope.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown or foreign id, or a chunk not stored; storage
    /// errors.
    pub async fn download_attachment_chunk(
        &self,
        account_id: AccountId,
        attachment_id: AttachmentId,
        chunk_index: u32,
    ) -> Result<Vec<u8>, VaultError> {
        let mut read = self.database().begin_read().await?;
        let stored = owned(read.conn(), attachment_id, account_id).await?;
        if chunk_index >= stored.layout.chunk_count() {
            return Err(VaultError::NotFound);
        }
        let envelope = chunk(read.conn(), attachment_id, chunk_index)
            .await?
            .ok_or(VaultError::NotFound)?;
        read.finish().await?;
        Ok(envelope)
    }

    /// `attachments/delete` (ADR 0054 §7): deletes the attachment and its chunks, and releases its
    /// counted bytes, in one transaction.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for an unknown or foreign id (a repeated delete included); storage
    /// errors.
    pub async fn delete_attachment(
        &self,
        account_id: AccountId,
        attachment_id: AttachmentId,
        now_ms: u64,
    ) -> Result<(), VaultError> {
        let now_sql = to_sql_time(now_ms)?;
        let mut tx = self.database().begin_write().await?;
        lock_account(&mut tx, account_id.as_bytes()).await?;
        let stored = owned(tx.conn(), attachment_id, account_id).await?;
        delete_rows(&mut tx.conn(), attachment_id).await?;
        charge(&mut tx, account_id, credit(stored.counted()), now_sql).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The `worker` sweep of ADR 0054 §7: deletes up to 256 attachments created more than
    /// [`SWEEP_AGE_MS`] before `now_ms` whose upload never finished, each in its own
    /// account-locked transaction that releases its counted bytes. Returns how many it deleted.
    ///
    /// # Errors
    /// Storage errors; the attachments deleted before the failure stay deleted.
    pub async fn sweep_attachments(&self, now_ms: u64) -> Result<u64, VaultError> {
        let cutoff = now_ms.saturating_sub(SWEEP_AGE_MS);
        let cutoff_sql = to_sql_time(cutoff)?;
        let now_sql = to_sql_time(now_ms)?;
        let mut read = self.database().begin_read().await?;
        let rows: Vec<(Vec<u8>, Vec<u8>)> = on_engine!(read.conn(), |c| {
            let mut out = Vec::new();
            for row in sqlx::query(ATTACHMENT_SWEEP_LIST)
                .bind(cutoff_sql)
                .bind(SWEEP_BATCH)
                .fetch_all(&mut *c)
                .await?
            {
                out.push((row.try_get(0)?, row.try_get(1)?));
            }
            out
        });
        read.finish().await?;
        let mut swept = 0u64;
        for (attachment, account) in rows {
            let attachment_id =
                AttachmentId::from_bytes(id16(&attachment, "vault_attachments.attachment_id")?);
            let account_id = AccountId::from_bytes(id16(&account, "vault_vaults.account_id")?);
            let mut tx = self.database().begin_write().await?;
            lock_account(&mut tx, account_id.as_bytes()).await?;
            // Re-read under the lock: a chunk may have landed, or a delete run, since the list.
            let Some(stored) = get(tx.conn(), attachment_id).await?.filter(|a| {
                a.account_id == account_id && !a.complete() && a.created_at_ms < cutoff
            }) else {
                tx.rollback().await?;
                continue;
            };
            delete_rows(&mut tx.conn(), attachment_id).await?;
            charge(&mut tx, account_id, credit(stored.counted()), now_sql).await?;
            tx.commit().await?;
            swept = swept.saturating_add(1);
        }
        Ok(swept)
    }
}
