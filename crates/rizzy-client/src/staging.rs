// SPDX-License-Identifier: AGPL-3.0-only

//! Staged rotation ([ADR 0092] §0 item 3, §4), on the client side: whether a rotation commit
//! goes inline or through `POST /api/v1/account/rotation/stage`, and the stage requests.
//!
//! ```text
//! host encodes commit_request() ──► stage_requests(rng, encoded_len)
//!   ├─ encoded_len ≤ DEFAULT_UPLOAD_BODY_LEN ─► [] : the commit stays inline
//!   └─ otherwise ─► every row of every vault in requests of ≤ ROTATION_STAGE_ROWS rows;
//!                   commit_request() is now the staged form (empty lists, `staging` set)
//! host POSTs each StageRequest in order (a lost answer: resend the same request; it is
//! idempotent), then re-encodes and sends the commit
//! ```
//!
//! **When.** Exactly when the inline body would exceed [`DEFAULT_UPLOAD_BODY_LEN`], the floor
//! every instance accepts; the instance's configured limit is never read. The host passes the
//! length of the JSON it would send, so the choice is made on the exact bytes.
//!
//! **Retries** (the §4 "Crash and retry" table):
//! - a lost stage answer: the host resends the same request (step 4: an identical row is a
//!   no-op);
//! - a lost commit answer, or a crash during the commit: the host resends the same commit body;
//!   the staging is intact;
//! - `state_conflict` from the commit: the host runs the rotation's retry rule, which rebuilds
//!   the inline request; the next plan then reuses the `rotation_id` and sends only rows not
//!   staged yet, when the commit still advances the same `state_seq` under the same account
//!   key and every staged row is still in the rebuilt set (the staged wraps are under the same
//!   new vault keys, so they stay valid); otherwise it opens a new `rotation_id` (the server
//!   deletes the older staging) and stages every row again;
//! - a host that could not send every stage request discards the staging, so the next plan
//!   starts again under a new `rotation_id` instead of trusting rows that never arrived.
//!
//! [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md

use std::collections::BTreeMap;

use rizzy_core::ids::ItemId;
use rizzy_core::rng::CryptoRng;
use rizzy_proto::change::{
    CommitChangeRequest, RotationId, StageRequest, VaultRotation, VaultRotationUpload, WrapLocator,
};
use rizzy_proto::limits::{DEFAULT_UPLOAD_BODY_LEN, ROTATION_STAGE_ROWS};
use rizzy_proto::objects::ItemKeyWrap;
use rizzy_proto::wire::{Id, List};

use crate::ClientError;
use crate::error::internal;

/// Whether a rotation commit whose JSON body is `encoded_len` bytes goes through staging
/// ([ADR 0092] §0 item 3): exactly when it exceeds [`DEFAULT_UPLOAD_BODY_LEN`].
///
/// [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md
#[must_use]
pub const fn needs_staging(encoded_len: usize) -> bool {
    encoded_len > DEFAULT_UPLOAD_BODY_LEN
}

/// The rows staged under one `rotation_id`: per `(vault_id, locator)`, the wrap staged or
/// `None` for a drop.
type StagedRows = BTreeMap<(Id, WrapLocator), Option<ItemKeyWrap>>;

/// One vault's batch of a stage request: the vault, its wraps and its drops.
type Batch = (Id, Vec<ItemKeyWrap>, Vec<WrapLocator>);

/// The staging this rotation opened on the server, as far as this client sent it.
struct Open {
    /// The id the client chose.
    rotation_id: RotationId,
    /// The `state_seq` the commit advances.
    base_state_seq: u64,
    /// The new account key's id.
    account_key_id: Id,
    /// Each vault's new `vault_key_epoch`, fixed by its first stage request.
    epochs: BTreeMap<Id, u32>,
    /// The rows sent.
    rows: StagedRows,
}

/// The staging state of one pending rotation (module docs). Holds no secret: wraps are
/// ciphertext.
#[derive(Default)]
pub(crate) struct Stager {
    /// The open staging, if any.
    open: Option<Open>,
}

impl Stager {
    /// Forgets the open staging: the next plan uses a new `rotation_id`.
    pub(crate) fn discard(&mut self) {
        self.open = None;
    }

    /// Plans the upload of `request` (module docs): `[]` and `request` unchanged when it is
    /// already staged, carries no vault half, or fits inline; otherwise the stage requests to
    /// send, in order, and `request` turned into its staged form. `base_state_seq` is the
    /// `state_seq` the commit advances and `account_key_id` the new account key's id.
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub(crate) fn plan<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        request: &mut CommitChangeRequest,
        base_state_seq: u64,
        account_key_id: Id,
        encoded_len: usize,
    ) -> Result<Vec<StageRequest>, ClientError> {
        let Some(upload) = request.vault_rotation.as_ref() else {
            return Ok(Vec::new());
        };
        if upload.staging().is_some() || !needs_staging(encoded_len) {
            return Ok(Vec::new());
        }
        let wanted = rows_of(upload.vaults());
        let epochs: BTreeMap<Id, u32> = upload
            .vaults()
            .iter()
            .map(|v| (v.self_grant.vault_id, v.self_grant.vault_key_epoch))
            .collect();
        let reusable = self.open.as_ref().is_some_and(|open| {
            open.base_state_seq == base_state_seq
                && open.account_key_id == account_key_id
                && open
                    .epochs
                    .iter()
                    .all(|(vault, epoch)| epochs.get(vault) == Some(epoch))
                && open.rows.iter().all(|(at, staged)| {
                    wanted
                        .get(at)
                        .is_some_and(|row| row.is_some() == staged.is_some())
                })
        });
        if !reusable {
            self.open = Some(Open {
                rotation_id: Id::from_bytes(ItemId::generate(rng).to_bytes()),
                base_state_seq,
                account_key_id,
                epochs: BTreeMap::new(),
                rows: BTreeMap::new(),
            });
        }
        let open = self.open.as_mut().ok_or(ClientError::Internal)?;
        let mut batches: Vec<Batch> = Vec::new();
        for ((vault_id, at), row) in wanted {
            if open.rows.contains_key(&(vault_id, at)) {
                continue;
            }
            let fits = batches.last().is_some_and(|(id, wraps, drops)| {
                *id == vault_id && wraps.len().saturating_add(drops.len()) < ROTATION_STAGE_ROWS
            });
            if !fits {
                batches.push((vault_id, Vec::new(), Vec::new()));
            }
            let (_, wraps, drops) = batches.last_mut().ok_or(ClientError::Internal)?;
            match &row {
                Some(wrap) => wraps.push(wrap.clone()),
                None => drops.push(at),
            }
            open.rows.insert((vault_id, at), row);
        }
        let mut requests = Vec::with_capacity(batches.len());
        for (vault_id, wraps, drops) in batches {
            let vault_key_epoch = *epochs.get(&vault_id).ok_or(ClientError::Internal)?;
            open.epochs.insert(vault_id, vault_key_epoch);
            requests.push(StageRequest {
                rotation_id: open.rotation_id,
                base_state_seq: open.base_state_seq,
                account_key_id: open.account_key_id,
                vault_id,
                vault_key_epoch,
                item_key_wraps: List::new(wraps).map_err(internal)?,
                dropped: List::new(drops).map_err(internal)?,
            });
        }
        let staged = upload
            .vaults()
            .iter()
            .map(|v| VaultRotation {
                self_grant: v.self_grant.clone(),
                cursor: v.cursor.clone(),
                item_key_wraps: List::default(),
                dropped: List::default(),
            })
            .collect();
        let rotation_id = open.rotation_id;
        request.vault_rotation = Some(
            VaultRotationUpload::with_regrants(staged, upload.regrants().to_vec())
                .map_err(internal)?
                .with_staging(rotation_id),
        );
        Ok(requests)
    }
}

/// Every row of `vaults`, keyed by vault and locator: the wrap, or `None` for a drop.
fn rows_of(vaults: &[VaultRotation]) -> StagedRows {
    let mut rows = BTreeMap::new();
    for vault in vaults {
        let vault_id = vault.self_grant.vault_id;
        for wrap in vault.item_key_wraps.as_slice() {
            let at = WrapLocator {
                item_id: wrap.item_id,
                item_key_id: wrap.item_key_id,
            };
            rows.insert((vault_id, at), Some(wrap.clone()));
        }
        for at in vault.dropped.as_slice() {
            rows.insert((vault_id, *at), None);
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    //! [ADR 0092] §8 test 9 at the client: the choice by encoded length, the batches, the
    //! staged commit form and the reuse rules.
    //!
    //! [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md

    use chacha20::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
    use rizzy_proto::vault::SeqVector;
    use rizzy_proto::wire::Bytes;

    use super::*;

    fn id(n: u32) -> Id {
        let mut bytes = [0u8; 16];
        for (to, from) in bytes.iter_mut().zip(n.to_be_bytes()) {
            *to = from;
        }
        Id::from_bytes(bytes)
    }

    /// A vault half of `wraps` re-wrapped rows and `drops` dropped ones.
    fn vault(n: u32, wraps: u32, drops: u32) -> VaultRotation {
        VaultRotation {
            self_grant: VaultSelfGrant {
                vault_id: id(n),
                account_key_epoch: 2,
                vault_key_epoch: 3,
                envelope: KeyEnvelope::new(vec![1; 127]).unwrap(),
            },
            cursor: SeqVector::default(),
            item_key_wraps: List::new(
                (0..wraps)
                    .map(|i| ItemKeyWrap {
                        item_id: id(i),
                        item_key_id: id(1),
                        vault_key_epoch: 3,
                        envelope: KeyEnvelope::new(vec![2; 127]).unwrap(),
                    })
                    .collect(),
            )
            .unwrap(),
            dropped: List::new(
                (0..drops)
                    .map(|i| WrapLocator {
                        item_id: id(wraps + i),
                        item_key_id: id(1),
                    })
                    .collect(),
            )
            .unwrap(),
        }
    }

    fn request(vaults: Vec<VaultRotation>) -> CommitChangeRequest {
        CommitChangeRequest {
            account_state: Bytes::new(vec![0; 8]).unwrap(),
            registration_upload: None,
            setup_id: None,
            account_key_server_wrap: None,
            recovery: None,
            account_settings: None,
            device_certificates: List::empty(),
            device_revocations: List::empty(),
            bundle: None,
            identity_secret_keys: None,
            retired_secret_keys: List::empty(),
            device_grants: List::empty(),
            recovery_rewrap: None,
            vault_rotation: Some(VaultRotationUpload::new(vaults).unwrap()),
            vault_create: None,
            vault_delete: None,
        }
    }

    const OVER: usize = DEFAULT_UPLOAD_BODY_LEN + 1;

    fn id_of(requests: &[StageRequest]) -> Id {
        requests.first().unwrap().rotation_id
    }

    fn rows(requests: &[StageRequest]) -> usize {
        requests
            .iter()
            .map(|r| r.item_key_wraps.len() + r.dropped.len())
            .sum()
    }

    #[test]
    fn stages_exactly_above_the_floor() {
        assert!(!needs_staging(0));
        assert!(!needs_staging(DEFAULT_UPLOAD_BODY_LEN));
        assert!(needs_staging(OVER));
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut staging = Stager::default();
        let mut inline = request(vec![vault(1, 3, 1)]);
        let before = inline.clone();
        let none = staging
            .plan(&mut rng, &mut inline, 7, id(9), DEFAULT_UPLOAD_BODY_LEN)
            .unwrap();
        assert!(none.is_empty());
        assert_eq!(inline, before, "a body that fits stays inline");
    }

    #[test]
    fn a_staged_commit_carries_every_row_in_bounded_requests() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut staging = Stager::default();
        let big = u32::try_from(ROTATION_STAGE_ROWS).unwrap() + 5;
        let mut commit = request(vec![vault(1, big, 2), vault(2, 4, 0), vault(3, 0, 0)]);
        let stages = staging.plan(&mut rng, &mut commit, 7, id(9), OVER).unwrap();
        assert_eq!(rows(&stages), ROTATION_STAGE_ROWS + 5 + 2 + 4);
        assert!(stages.iter().all(|s| {
            s.item_key_wraps.len() + s.dropped.len() <= ROTATION_STAGE_ROWS
                && s.base_state_seq == 7
                && s.account_key_id == id(9)
                && s.vault_key_epoch == 3
                && s.rotation_id == id_of(&stages)
        }));
        // Vault 1 needs two requests, vault 2 one, the empty vault 3 none.
        let vaults: Vec<Id> = stages.iter().map(|s| s.vault_id).collect();
        assert_eq!(vaults, vec![id(1), id(1), id(2)]);
        let upload = commit.vault_rotation.as_ref().unwrap();
        assert_eq!(upload.staging(), Some(id_of(&stages)));
        assert_eq!(upload.vaults().len(), 3);
        assert!(
            upload
                .vaults()
                .iter()
                .all(|v| v.item_key_wraps.is_empty() && v.dropped.is_empty())
        );
        // Planned again, a staged commit sends nothing more.
        let again = staging.plan(&mut rng, &mut commit, 7, id(9), OVER).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn a_rebuild_stages_only_new_rows_or_starts_again() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut staging = Stager::default();
        let mut first = request(vec![vault(1, 10, 0)]);
        let stages = staging.plan(&mut rng, &mut first, 7, id(9), OVER).unwrap();
        let rotation_id = id_of(&stages);
        // A row added since: the same staging, only the new row.
        let mut grown = request(vec![vault(1, 11, 0)]);
        let delta = staging.plan(&mut rng, &mut grown, 7, id(9), OVER).unwrap();
        assert_eq!(rows(&delta), 1);
        assert_eq!(id_of(&delta), rotation_id);
        // A staged row gone (purged): a new staging with every row.
        let mut shrunk = request(vec![vault(1, 5, 0)]);
        let fresh = staging.plan(&mut rng, &mut shrunk, 7, id(9), OVER).unwrap();
        assert_eq!(rows(&fresh), 5);
        assert_ne!(id_of(&fresh), rotation_id);
        // Another base state_seq: a new staging again.
        let mut moved = request(vec![vault(1, 5, 0)]);
        let next = staging.plan(&mut rng, &mut moved, 8, id(9), OVER).unwrap();
        assert_eq!(rows(&next), 5);
        assert_ne!(id_of(&next), id_of(&fresh));
        // Discarded: everything again under a new id.
        staging.discard();
        let mut again = request(vec![vault(1, 5, 0)]);
        let all = staging.plan(&mut rng, &mut again, 8, id(9), OVER).unwrap();
        assert_eq!(rows(&all), 5);
        assert_ne!(id_of(&all), id_of(&next));
    }
}
