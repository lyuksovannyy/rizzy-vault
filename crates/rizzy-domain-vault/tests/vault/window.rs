// SPDX-License-Identifier: AGPL-3.0-only

//! The revocation window's freeze in the vault domain (ADR 0091 §2): while the account's window
//! is open, `vault/upload`, `vault/heal` and the three attachment writes refuse every writer
//! that is not the window's revoker R, before anything else, and write nothing; R writes; reads
//! are never frozen; the window is open while `now_ms < expires_at_ms`.

#![expect(
    clippy::unwrap_used,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use rizzy_core::attachment::CHUNK_SIZE;
use rizzy_core::ids::{AttachmentId, DeviceId};
use rizzy_domain_vault::{HealingError, NewAttachment, RevocationWindow, VaultError};
use rizzy_proto::vault::{HealingRequest, Record, UploadRequest, UploadResult};
use rizzy_proto::wire::{Id, List};

use crate::common::{ACCOUNT, Device, Env, NOW, VAULT, block_on, chain, item};

/// An upload request of `records` to the test vault.
fn upload(records: Vec<Record>) -> UploadRequest {
    UploadRequest {
        vault_id: Id::from_bytes(VAULT.to_bytes()),
        records: List::new(records).unwrap(),
    }
}

/// A healing request of `records` to the test vault.
fn heal(records: Vec<Record>) -> HealingRequest {
    HealingRequest {
        vault_id: Id::from_bytes(VAULT.to_bytes()),
        item_key_wraps: List::empty(),
        records: List::new(records).unwrap(),
        self_grant: None,
    }
}

/// A one-chunk attachment declaration.
fn attachment(n: u8) -> NewAttachment {
    NewAttachment {
        attachment_id: AttachmentId::from_bytes([0xc0 | n; 16]),
        vault_id: VAULT,
        item_id: item(1),
        attachment_key_wrap: vec![n; 122],
        total_plaintext_len: 10,
    }
}

/// The exact envelope of a 10-byte attachment's only chunk: opaque bytes of its length.
fn chunk() -> Vec<u8> {
    assert!(10 < CHUNK_SIZE);
    vec![0x5a; 10 + 90]
}

/// How many ops the server holds in the test vault.
async fn ops(env: &Env) -> usize {
    env.fetch_all(&[])
        .await
        .iter()
        .map(|p| p.response.ops.len())
        .sum()
}

#[test]
fn vault_writes_are_frozen_for_every_writer_but_the_revoker() {
    block_on(async {
        let env = Env::new(1).await;
        let (r, other) = (Device::new(1), Device::new(2));
        env.enrol(&[&r, &other]);
        let d = &env.domain;
        // R's attachment, declared before the window, so the frozen chunk upload and delete
        // have a target.
        let before = attachment(1);
        d.create_attachment(ACCOUNT, Some(r.id), &before, NOW)
            .await
            .unwrap();
        env.directory.set_window(Some(RevocationWindow {
            revoker: r.id,
            expires_at_ms: NOW + 1,
        }));
        let counted = env.counted().await;

        // Every writer but R is refused: another device, and a session bound to no device.
        for writer in [Some(other.id), None, Some(DeviceId::from_bytes([0xee; 16]))] {
            assert!(matches!(
                d.upload(ACCOUNT, writer, &upload(chain(&other, item(1), 1, 1)), NOW)
                    .await,
                Err(VaultError::RevocationPending)
            ));
            assert!(matches!(
                d.heal(ACCOUNT, writer, writer, &heal(chain(&other, item(1), 1, 1)), NOW)
                    .await,
                Err(HealingError::Failed(VaultError::RevocationPending))
            ));
            assert!(matches!(
                d.create_attachment(ACCOUNT, writer, &attachment(2), NOW).await,
                Err(VaultError::RevocationPending)
            ));
            assert!(matches!(
                d.upload_attachment_chunk(ACCOUNT, writer, before.attachment_id, 0, &chunk(), NOW)
                    .await,
                Err(VaultError::RevocationPending)
            ));
            assert!(matches!(
                d.delete_attachment(ACCOUNT, writer, before.attachment_id, NOW)
                    .await,
                Err(VaultError::RevocationPending)
            ));
        }
        // Nothing was written: no op, no attachment, no counted byte.
        assert_eq!(ops(&env).await, 0);
        assert_eq!(env.counted().await, counted);
        assert!(matches!(
            d.attachment_key_wrap(ACCOUNT, attachment(2).attachment_id).await,
            Err(VaultError::NotFound)
        ));

        // Reads are never frozen.
        assert_eq!(
            d.attachment_key_wrap(ACCOUNT, before.attachment_id)
                .await
                .unwrap(),
            before.attachment_key_wrap
        );

        // R writes during its own window.
        let answer = d
            .upload(ACCOUNT, Some(r.id), &upload(chain(&r, item(1), 1, 1)), NOW)
            .await
            .unwrap();
        assert_eq!(answer.results.into_vec(), vec![UploadResult::Stored]);
        d.upload_attachment_chunk(ACCOUNT, Some(r.id), before.attachment_id, 0, &chunk(), NOW)
            .await
            .unwrap();
        assert_eq!(
            d.download_attachment_chunk(ACCOUNT, before.attachment_id, 0)
                .await
                .unwrap(),
            chunk()
        );

        // At `expires_at_ms - 1` the window is open (above); at `expires_at_ms` it is not.
        let at = NOW + 1;
        let answer = d
            .upload(ACCOUNT, Some(other.id), &upload(chain(&other, item(2), 1, 1)), at)
            .await
            .unwrap();
        assert_eq!(answer.results.into_vec(), vec![UploadResult::Stored]);
        d.delete_attachment(ACCOUNT, None, before.attachment_id, at)
            .await
            .unwrap();
        assert_eq!(ops(&env).await, 2);
    });
}
