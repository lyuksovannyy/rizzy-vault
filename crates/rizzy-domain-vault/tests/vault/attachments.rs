// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted attachments on the server (ADR 0054 §5–§7): the lifecycle, the exact chunk
//! lengths, retries and conflicts, the 25 MiB cap and the quota charged at `create`, ownership
//! (another account's id is `not_found`), and the 24 h sweep. The server never opens an
//! envelope, so the chunks here are opaque bytes of the lengths the declared size implies.

#![expect(
    clippy::unwrap_used,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use rizzy_core::attachment::{CHUNK_SIZE, MAX_ATTACHMENT_LEN};
use rizzy_core::ids::{AttachmentId, VaultId};
use rizzy_domain_vault::attachments::SWEEP_AGE_MS;
use rizzy_domain_vault::{NewAttachment, Quota, VaultError, VaultKind, create_vault};
use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
use rizzy_proto::wire::Id;
use rizzy_storage::lock_account;

use crate::common::{ACCOUNT, Env, NOW, OTHER_ACCOUNT, VAULT, block_on, item};

const OTHER_VAULT: VaultId = VaultId::from_bytes([0xb2; 16]);
const WRAP_LEN: usize = 122;

fn attachment(n: u8) -> AttachmentId {
    AttachmentId::from_bytes([0xc0 | n; 16])
}

fn new(n: u8, size: u64) -> NewAttachment {
    NewAttachment {
        attachment_id: attachment(n),
        vault_id: VAULT,
        item_id: item(1),
        attachment_key_wrap: vec![n; WRAP_LEN],
        total_plaintext_len: size,
    }
}

/// The counted bytes of an attachment of `size` bytes (ADR 0048 §2 as `attachments` counts it).
fn counted(size: u64) -> u64 {
    let chunks = size.div_ceil(CHUNK_SIZE as u64);
    WRAP_LEN as u64 + size + 90 * chunks
}

/// Opaque chunk bytes of the exact envelope length of chunk `index`.
fn envelope(size: u64, index: u32, tag: u8) -> Vec<u8> {
    let chunk = CHUNK_SIZE as u64;
    let offset = u64::from(index) * chunk;
    let len = (size - offset).min(chunk) + 90;
    vec![tag; usize::try_from(len).unwrap()]
}

/// A vault for the other account, so its requests are well formed.
async fn other_vault(env: &Env) {
    let mut tx = env.db.begin_write().await.unwrap();
    lock_account(&mut tx, OTHER_ACCOUNT.as_bytes())
        .await
        .unwrap();
    let grant = VaultSelfGrant {
        vault_id: Id::from_bytes(OTHER_VAULT.to_bytes()),
        account_key_epoch: 0,
        vault_key_epoch: 0,
        envelope: KeyEnvelope::new(vec![0x5b; 98]).unwrap(),
    };
    create_vault(&mut tx, OTHER_ACCOUNT, &grant, VaultKind::Personal, NOW)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

#[test]
fn an_attachment_is_declared_uploaded_downloaded_and_deleted() {
    block_on(async {
        let env = Env::new(1).await;
        let d = &env.domain;
        let size = CHUNK_SIZE as u64 + 10;
        let a = new(1, size);
        d.create_attachment(ACCOUNT, None, &a, NOW).await.unwrap();
        assert_eq!(env.counted().await, counted(size));
        // A byte-identical repeat is a no-op; any other declaration under the id conflicts.
        d.create_attachment(ACCOUNT, None, &a, NOW + 1)
            .await
            .unwrap();
        assert_eq!(env.counted().await, counted(size));
        for changed in [
            NewAttachment {
                total_plaintext_len: size + 1,
                ..a.clone()
            },
            NewAttachment {
                item_id: item(2),
                ..a.clone()
            },
            NewAttachment {
                attachment_key_wrap: vec![9; WRAP_LEN],
                ..a.clone()
            },
        ] {
            assert!(matches!(
                d.create_attachment(ACCOUNT, None, &changed, NOW).await,
                Err(VaultError::RecordConflict)
            ));
        }
        assert_eq!(
            d.attachment_key_wrap(ACCOUNT, a.attachment_id)
                .await
                .unwrap(),
            a.attachment_key_wrap
        );

        let id = a.attachment_id;
        // Only the exact length of each index is accepted, and only indices below the count.
        let full = envelope(size, 0, 0x11);
        let last = envelope(size, 1, 0x22);
        assert_eq!(full.len(), CHUNK_SIZE + 90);
        assert_eq!(last.len(), 100);
        for (index, bad) in [(0, &last), (1, &full), (1, &last[..99].to_vec())] {
            assert!(matches!(
                d.upload_attachment_chunk(ACCOUNT, None, id, index, bad, NOW)
                    .await,
                Err(VaultError::Invalid)
            ));
        }
        assert!(matches!(
            d.upload_attachment_chunk(ACCOUNT, None, id, 2, &last, NOW)
                .await,
            Err(VaultError::NotFound)
        ));
        // Downloads before the upload: not found.
        assert!(matches!(
            d.download_attachment_chunk(ACCOUNT, id, 0).await,
            Err(VaultError::NotFound)
        ));
        d.upload_attachment_chunk(ACCOUNT, None, id, 1, &last, NOW)
            .await
            .unwrap();
        d.upload_attachment_chunk(ACCOUNT, None, id, 0, &full, NOW)
            .await
            .unwrap();
        // A byte-identical retry is a no-op; another envelope at a stored index conflicts.
        d.upload_attachment_chunk(ACCOUNT, None, id, 0, &full, NOW)
            .await
            .unwrap();
        assert!(matches!(
            d.upload_attachment_chunk(ACCOUNT, None, id, 0, &envelope(size, 0, 0x33), NOW)
                .await,
            Err(VaultError::RecordConflict)
        ));
        // Chunk uploads never move the counter: create reserved them.
        assert_eq!(env.counted().await, counted(size));
        assert_eq!(
            d.download_attachment_chunk(ACCOUNT, id, 0).await.unwrap(),
            full
        );
        assert_eq!(
            d.download_attachment_chunk(ACCOUNT, id, 1).await.unwrap(),
            last
        );
        assert!(matches!(
            d.download_attachment_chunk(ACCOUNT, id, 2).await,
            Err(VaultError::NotFound)
        ));

        d.delete_attachment(ACCOUNT, None, id, NOW).await.unwrap();
        assert_eq!(env.counted().await, 0);
        assert!(matches!(
            d.delete_attachment(ACCOUNT, None, id, NOW).await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            d.attachment_key_wrap(ACCOUNT, id).await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            d.download_attachment_chunk(ACCOUNT, id, 0).await,
            Err(VaultError::NotFound)
        ));
    });
}

#[test]
fn the_cap_and_the_quota_are_checked_at_create() {
    block_on(async {
        let env = Env::new(1).await;
        // Over 25 MiB: quota_exceeded, whatever the quota (ADR 0054 "Owner answers" 5).
        assert!(matches!(
            env.domain
                .create_attachment(ACCOUNT, None, &new(1, MAX_ATTACHMENT_LEN + 1), NOW)
                .await,
            Err(VaultError::QuotaExceeded)
        ));
        // A wrap of another length is refused.
        let mut short = new(1, 10);
        short.attachment_key_wrap.pop();
        assert!(matches!(
            env.domain
                .create_attachment(ACCOUNT, None, &short, NOW)
                .await,
            Err(VaultError::Invalid)
        ));
        // Exactly at the quota passes; one byte over is refused and charges nothing. The
        // upload headroom of ADR 0048 §3 does not apply: create is checked against the quota.
        let size = 3 * CHUNK_SIZE as u64 + 7;
        let quota = Quota {
            quota_bytes: counted(size) + counted(1) - 1,
            headroom_bytes: 1 << 30,
        };
        let d = env.domain_with_quota(quota);
        d.create_attachment(ACCOUNT, None, &new(2, size), NOW)
            .await
            .unwrap();
        assert_eq!(env.counted().await, counted(size));
        assert!(matches!(
            d.create_attachment(ACCOUNT, None, &new(3, 1), NOW).await,
            Err(VaultError::QuotaExceeded)
        ));
        assert_eq!(env.counted().await, counted(size));
        // The largest attachment is accepted under the default quota: 50 chunks.
        env.domain
            .create_attachment(ACCOUNT, None, &new(4, MAX_ATTACHMENT_LEN), NOW)
            .await
            .unwrap();
        assert!(matches!(
            env.domain
                .upload_attachment_chunk(ACCOUNT, None, attachment(4), 50, &[0; 90], NOW)
                .await,
            Err(VaultError::NotFound)
        ));
        env.domain
            .upload_attachment_chunk(
                ACCOUNT,
                None,
                attachment(4),
                49,
                &envelope(MAX_ATTACHMENT_LEN, 49, 1),
                NOW,
            )
            .await
            .unwrap();
        // Deleting releases exactly what create charged.
        d.delete_attachment(ACCOUNT, None, attachment(2), NOW)
            .await
            .unwrap();
        assert_eq!(env.counted().await, counted(MAX_ATTACHMENT_LEN));
    });
}

#[test]
fn another_accounts_attachment_is_not_found() {
    block_on(async {
        let env = Env::new(1).await;
        other_vault(&env).await;
        let d = &env.domain;
        let a = new(1, 1000);
        d.create_attachment(ACCOUNT, None, &a, NOW).await.unwrap();
        d.upload_attachment_chunk(
            ACCOUNT,
            None,
            a.attachment_id,
            0,
            &envelope(1000, 0, 1),
            NOW,
        )
        .await
        .unwrap();
        let id = a.attachment_id;
        // Every call of the other account on this id answers not_found.
        assert!(matches!(
            d.attachment_key_wrap(OTHER_ACCOUNT, id).await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            d.download_attachment_chunk(OTHER_ACCOUNT, id, 0).await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            d.upload_attachment_chunk(OTHER_ACCOUNT, None, id, 0, &envelope(1000, 0, 2), NOW)
                .await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            d.delete_attachment(OTHER_ACCOUNT, None, id, NOW).await,
            Err(VaultError::NotFound)
        ));
        // Declaring the same id in its own vault, or anything in this account's vault.
        let mut theirs = a.clone();
        theirs.vault_id = OTHER_VAULT;
        assert!(matches!(
            d.create_attachment(OTHER_ACCOUNT, None, &theirs, NOW).await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            d.create_attachment(OTHER_ACCOUNT, None, &new(2, 10), NOW)
                .await,
            Err(VaultError::NotFound)
        ));
        // Nothing moved.
        assert_eq!(
            d.download_attachment_chunk(ACCOUNT, id, 0).await.unwrap(),
            envelope(1000, 0, 1)
        );
        assert_eq!(env.counted().await, counted(1000));
    });
}

#[test]
fn the_sweep_deletes_only_old_unfinished_uploads() {
    block_on(async {
        let env = Env::new(1).await;
        let d = &env.domain;
        let old = NOW - SWEEP_AGE_MS - 1;
        // 1: old and unfinished; 2: old and complete; 3: recent and unfinished; 4: old and empty.
        d.create_attachment(ACCOUNT, None, &new(1, 2000), old)
            .await
            .unwrap();
        d.create_attachment(ACCOUNT, None, &new(2, 2000), old)
            .await
            .unwrap();
        d.upload_attachment_chunk(ACCOUNT, None, attachment(2), 0, &envelope(2000, 0, 2), NOW)
            .await
            .unwrap();
        d.create_attachment(ACCOUNT, None, &new(3, 2000), NOW - 10)
            .await
            .unwrap();
        d.create_attachment(ACCOUNT, None, &new(4, 0), old)
            .await
            .unwrap();
        assert_eq!(env.counted().await, 3 * counted(2000) + counted(0));
        assert_eq!(d.sweep_attachments(NOW).await.unwrap(), 1);
        assert!(matches!(
            d.attachment_key_wrap(ACCOUNT, attachment(1)).await,
            Err(VaultError::NotFound)
        ));
        for kept in [2, 3, 4] {
            d.attachment_key_wrap(ACCOUNT, attachment(kept))
                .await
                .unwrap();
        }
        assert_eq!(env.counted().await, 2 * counted(2000) + counted(0));
        assert_eq!(d.sweep_attachments(NOW).await.unwrap(), 0);
        // An empty attachment has no chunk to fetch.
        assert!(matches!(
            d.download_attachment_chunk(ACCOUNT, attachment(4), 0).await,
            Err(VaultError::NotFound)
        ));
    });
}

/// `attachments/delete-item` (ADR 0093 §1.1, §5): every attachment of one item, complete or
/// not, with its chunks and its counted bytes, in batches of 16; another item's are untouched.
#[test]
fn delete_item_removes_one_items_attachments_in_batches() {
    block_on(async {
        let env = Env::new(1).await;
        let d = &env.domain;
        // Item 1: 17 attachments, the first complete, the rest declared only.
        for n in 0..17u8 {
            let mut a = new(n, 1000);
            a.attachment_id =
                AttachmentId::from_bytes([0xe0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            d.create_attachment(ACCOUNT, None, &a, NOW).await.unwrap();
            if n == 0 {
                d.upload_attachment_chunk(
                    ACCOUNT,
                    None,
                    a.attachment_id,
                    0,
                    &envelope(1000, 0, 1),
                    NOW,
                )
                .await
                .unwrap();
            }
        }
        // Item 2 in the same vault: one attachment that must stay.
        let mut keep = new(1, 2000);
        keep.item_id = item(2);
        d.create_attachment(ACCOUNT, None, &keep, NOW)
            .await
            .unwrap();
        assert_eq!(env.counted().await, 17 * counted(1000) + counted(2000));

        // The first call deletes 16 and says one is left; the counter drops in the same
        // transaction (`counted` checks the counter against the rows).
        assert!(
            d.delete_item_attachments(ACCOUNT, None, VAULT, item(1), NOW)
                .await
                .unwrap()
        );
        assert_eq!(env.counted().await, counted(1000) + counted(2000));
        assert!(
            !d.delete_item_attachments(ACCOUNT, None, VAULT, item(1), NOW)
                .await
                .unwrap()
        );
        assert_eq!(env.counted().await, counted(2000));
        for n in 0..17u8 {
            let id = AttachmentId::from_bytes([0xe0, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert!(matches!(
                d.attachment_key_wrap(ACCOUNT, id).await,
                Err(VaultError::NotFound)
            ));
        }
        let mut r = env.db.begin_read().await.unwrap();
        let chunks: i64 = rizzy_storage::on_engine!(r.conn(), |c| sqlx::query_scalar(
            "SELECT CAST(COUNT(*) AS BIGINT) FROM vault_attachment_chunks"
        )
        .fetch_one(&mut *c)
        .await
        .unwrap());
        r.finish().await.unwrap();
        assert_eq!(chunks, 0, "the complete attachment's chunk went with it");
        d.attachment_key_wrap(ACCOUNT, keep.attachment_id)
            .await
            .unwrap();

        // Idempotent: an item with no rows left, or one that never had any, is a success.
        assert!(
            !d.delete_item_attachments(ACCOUNT, None, VAULT, item(1), NOW)
                .await
                .unwrap()
        );
        assert!(
            !d.delete_item_attachments(ACCOUNT, None, VAULT, item(9), NOW)
                .await
                .unwrap()
        );
        assert_eq!(env.counted().await, counted(2000));
    });
}

/// `attachments/delete-item` on another account's vault, an unknown vault and a deleted vault
/// is `not_found`, and deletes nothing (ADR 0093 §1.1 "Access").
#[test]
fn delete_item_of_a_foreign_or_missing_vault_is_not_found() {
    block_on(async {
        let env = Env::new(1).await;
        other_vault(&env).await;
        let d = &env.domain;
        let a = new(1, 1000);
        d.create_attachment(ACCOUNT, None, &a, NOW).await.unwrap();
        assert!(matches!(
            d.delete_item_attachments(OTHER_ACCOUNT, None, VAULT, item(1), NOW)
                .await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            d.delete_item_attachments(ACCOUNT, None, OTHER_VAULT, item(1), NOW)
                .await,
            Err(VaultError::NotFound)
        ));
        let unknown = VaultId::from_bytes([0xb9; 16]);
        assert!(matches!(
            d.delete_item_attachments(ACCOUNT, None, unknown, item(1), NOW)
                .await,
            Err(VaultError::NotFound)
        ));
        d.attachment_key_wrap(ACCOUNT, a.attachment_id)
            .await
            .unwrap();
        assert_eq!(env.counted().await, counted(1000));

        // A deleted vault: its row is gone, so the call is not_found as for an unknown one.
        let mut tx = env.db.begin_write().await.unwrap();
        lock_account(&mut tx, OTHER_ACCOUNT.as_bytes())
            .await
            .unwrap();
        rizzy_storage::on_engine!(tx.conn(), |c| sqlx::query(
            "DELETE FROM vault_vaults WHERE id = $1"
        )
        .bind(&OTHER_VAULT.as_bytes()[..])
        .execute(&mut *c)
        .await
        .map(|_| ())
        .unwrap());
        tx.commit().await.unwrap();
        assert!(matches!(
            d.delete_item_attachments(OTHER_ACCOUNT, None, OTHER_VAULT, item(1), NOW)
                .await,
            Err(VaultError::NotFound)
        ));
    });
}

/// The migration's index exists on the engine under test (ADR 0093 §1.1 "Storage").
#[test]
fn the_per_item_attachment_index_exists() {
    block_on(async {
        let env = Env::new(1).await;
        let mut r = env.db.begin_read().await.unwrap();
        let found: i64 = match r.conn() {
            rizzy_storage::Conn::Sqlite(c) => sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
                 AND name = 'vault_attachments_by_item' AND tbl_name = 'vault_attachments'",
            )
            .fetch_one(&mut *c)
            .await
            .unwrap(),
            rizzy_storage::Conn::Postgres(c) => sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_indexes WHERE indexname = 'vault_attachments_by_item' \
                 AND tablename = 'vault_attachments'",
            )
            .fetch_one(&mut *c)
            .await
            .unwrap(),
        };
        r.finish().await.unwrap();
        assert_eq!(found, 1);
    });
}
