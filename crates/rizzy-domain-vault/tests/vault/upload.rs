//! Upload and Fetch: round trips, "Already stored", conflicts, chain gaps, forged authors,
//! stale epochs, and the author rules (ADR 0012 §7 "Upload" as ADR 0021 §9 supersedes it).

use rizzy_domain_vault::{AuthorStatus, VaultError};
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{Envelope, KeyEnvelope, VaultSelfGrant};
use rizzy_proto::vault::{FetchRequest, Record, SeqVector, UploadRequest, UploadResult};
use rizzy_proto::wire::{Id, List};
use rizzy_storage::on_engine;

use crate::common::{
    ACCOUNT, Device, Env, ITEM_KEY_ID, NOW, OTHER_ACCOUNT, OpSpec, VAULT, block_on, chain, item,
    op_dot, ops_of, sign_op, sign_snapshot,
};

/// A rejection with `code`.
const fn rejected(code: ErrorCode) -> UploadResult {
    UploadResult::Rejected { error: code }
}

#[test]
fn upload_then_fetch_round_trips_every_record() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        let mut first = OpSpec::new(item(1), 1, 0);
        first.wrap = Some(vec![0x77; 98]);
        let mut records = vec![Record::Op(sign_op(&a, VAULT, &first))];
        records.extend(chain(&a, item(1), 2, 3));
        records.extend(chain(&b, item(2), 1, 2));
        let uploaded: Vec<_> = records
            .iter()
            .map(|r| match r {
                Record::Op(op) => op.clone(),
                Record::Snapshot(_) => unreachable!(),
            })
            .collect();
        env.store(records).await;

        let pages = env.fetch_all(&[]).await;
        assert_eq!(pages.len(), 1);
        let page = &pages[0].response;
        assert_eq!(page.restore_generation.as_bytes(), &[1; 16]);
        assert!(page.complete);
        assert!(page.covers.is_empty());
        // Devices ascend by id, each chain in order: exactly what was uploaded, byte for byte.
        let served: Vec<_> = page.ops.iter().cloned().collect();
        assert_eq!(served, uploaded);
        assert_eq!(page.heads.get(&Id::from_bytes(a.id.to_bytes())), 3);
        assert_eq!(page.heads.get(&Id::from_bytes(b.id.to_bytes())), 2);
        // The carried wrap filled its wrap-set row.
        assert_eq!(page.item_key_wraps.len(), 1);
        let row = &page.item_key_wraps.as_slice()[0];
        assert_eq!(row.item_key_id.to_bytes(), ITEM_KEY_ID);
        assert_eq!(row.envelope.as_slice(), &[0x77; 98]);

        // From the advanced cursor nothing is left; from a partial cursor only the rest.
        let rest = env.fetch_all(&[(&a, 3), (&b, 2)]).await;
        assert!(ops_of(&rest).is_empty());
        let rest = env.fetch_all(&[(&a, 2)]).await;
        let dots: Vec<_> = ops_of(&rest).into_iter().map(|op| op_dot(op).1).collect();
        assert_eq!(dots.len(), 3);
        assert_eq!((dots[0].device_id(), dots[0].seq()), (a.id, 3));
        assert_eq!((dots[1].device_id(), dots[1].seq()), (b.id, 1));
    });
}

#[test]
fn already_stored_is_answered_before_the_chain_and_epoch_checks() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        let ops = chain(&a, item(1), 1, 3);
        let snapshot = Record::Snapshot(sign_snapshot(&a, item(1), 9, &[(&a, 3)], 0));
        let mut records = ops.clone();
        records.push(snapshot.clone());
        env.store(records).await;

        // Re-uploads of old records: their `vault_prev_seq` is no longer the head, yet each is
        // acknowledged, and nothing is stored.
        let mut again = ops.clone();
        again.push(snapshot);
        assert_eq!(
            env.upload(again).await,
            vec![UploadResult::AlreadyStored; 4]
        );

        // A different record at a stored dot, or under a stored snapshot id, is a conflict.
        let mut other = OpSpec::new(item(1), 2, 1);
        other.tag = 1;
        assert_eq!(
            env.upload(vec![Record::Op(sign_op(&a, VAULT, &other))])
                .await,
            vec![rejected(ErrorCode::RecordConflict)]
        );
        let other_snapshot = sign_snapshot(&a, item(1), 9, &[(&a, 2)], 0);
        assert_eq!(
            env.upload(vec![Record::Snapshot(other_snapshot)]).await,
            vec![rejected(ErrorCode::RecordConflict)]
        );

        // The same statement with a different body is not the stored record either: the body
        // no longer matches the signed hash, so it is refused before anything else.
        let mut forged = match &ops[0] {
            Record::Op(op) => op.clone(),
            Record::Snapshot(_) => unreachable!(),
        };
        forged.body = Some(Envelope::new(vec![1; 48]).unwrap());
        assert_eq!(
            env.upload(vec![Record::Op(forged)]).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
    });
}

#[test]
fn chain_gaps_are_rejected_and_the_rest_of_the_batch_is_not_processed() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        let mut records = chain(&a, item(1), 1, 2);
        // seq 4 claims prev 3, which the server does not hold.
        records.push(Record::Op(sign_op(&a, VAULT, &OpSpec::new(item(1), 4, 3))));
        records.extend(chain(&a, item(1), 3, 3));
        assert_eq!(
            env.upload(records).await,
            vec![
                UploadResult::Stored,
                UploadResult::Stored,
                rejected(ErrorCode::PrevSeqMismatch),
                UploadResult::NotProcessed,
            ]
        );
        // The records before the rejection were committed; the chain continues from them.
        env.store(chain(&a, item(1), 3, 4)).await;
        // An op whose seq does not exceed its own prev breaks the chain's definition.
        assert_eq!(
            env.upload(vec![Record::Op(sign_op(
                &a,
                VAULT,
                &OpSpec::new(item(1), 5, 5)
            ))])
            .await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
        // A skipped link is a gap, not a fresh chain.
        assert_eq!(
            env.upload(vec![Record::Op(sign_op(
                &a,
                VAULT,
                &OpSpec::new(item(1), 6, 5)
            ))])
            .await,
            vec![rejected(ErrorCode::PrevSeqMismatch)]
        );
    });
}

#[test]
fn records_that_fail_verification_are_rejected() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b, stranger) = (Device::new(1), Device::new(2), Device::new(3));
        env.enrol(&[&a, &b]);

        // ADR 0012 §7 test: a session of device A uploads an op claiming device B → rejected,
        // and B's next genuine op is accepted.
        let forged = Device {
            id: b.id,
            ..Device::new(1)
        };
        assert_eq!(
            env.upload(chain(&forged, item(1), 1, 1)).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
        env.store(chain(&b, item(1), 1, 1)).await;

        // A device the account does not hold.
        assert_eq!(
            env.upload(chain(&stranger, item(1), 1, 1)).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );

        // A header naming another vault.
        let Record::Op(mut other_vault) = chain(&a, item(1), 1, 1).remove(0) else {
            unreachable!()
        };
        other_vault.statement = sign_op(
            &a,
            rizzy_core::ids::VaultId::from_bytes([0xb2; 16]),
            &OpSpec::new(item(1), 1, 0),
        )
        .statement;
        assert_eq!(
            env.upload(vec![Record::Op(other_vault.clone())]).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );

        // A bodiless header outside a healing request.
        let Record::Op(mut bodiless) = chain(&a, item(1), 1, 1).remove(0) else {
            unreachable!()
        };
        bodiless.body = None;
        assert_eq!(
            env.upload(vec![Record::Op(bodiless)]).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );

        // A signed wrap that is not carried, and a carried wrap that was not signed.
        let mut with_wrap = OpSpec::new(item(1), 1, 0);
        with_wrap.wrap = Some(vec![0x77; 98]);
        let mut missing = sign_op(&a, VAULT, &with_wrap);
        missing.key_wrap = None;
        assert_eq!(
            env.upload(vec![Record::Op(missing)]).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
        let mut unsigned = sign_op(&a, VAULT, &OpSpec::new(item(1), 1, 0));
        unsigned.key_wrap = sign_op(&a, VAULT, &with_wrap).key_wrap;
        assert_eq!(
            env.upload(vec![Record::Op(unsigned)]).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );

        // A flipped signature byte.
        let Record::Op(mut tampered) = chain(&a, item(1), 1, 1).remove(0) else {
            unreachable!()
        };
        let mut wire = tampered.statement.as_slice().to_vec();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        tampered.statement = rizzy_proto::objects::OpStatement::new(wire).unwrap();
        assert_eq!(
            env.upload(vec![Record::Op(tampered)]).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );

        // Nothing of A was stored by any of these.
        env.store(chain(&a, item(1), 1, 1)).await;
    });
}

/// Raises the vault's epoch to 1 as the key-rotation upload does (CRYPTO.md §11.6 step 9). That
/// upload is not part of this crate yet, and a re-published self-grant never moves the epoch,
/// so the test writes the vault row directly.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn raise_epoch(env: &Env) {
    let mut tx = env.db.begin_write().await.unwrap();
    on_engine!(tx.conn(), |c| sqlx::query(
        "UPDATE vault_vaults SET vault_key_epoch = 1 WHERE id = $1"
    )
    .bind(&VAULT.as_bytes()[..])
    .execute(&mut *c)
    .await
    .map(|_| ())
    .unwrap());
    tx.commit().await.unwrap();
}

#[test]
fn stale_epochs_are_rejected_with_their_exemptions() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, r) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &r]);
        env.store(chain(&a, item(1), 1, 1)).await;
        env.store(chain(&r, item(1), 1, 2)).await;
        raise_epoch(&env).await;

        // A record at epoch 0 is now stale: an op and a snapshot.
        assert_eq!(
            env.upload(chain(&a, item(1), 2, 2)).await,
            vec![rejected(ErrorCode::StaleEpoch)]
        );
        assert_eq!(
            env.upload(vec![Record::Snapshot(sign_snapshot(
                &a,
                item(1),
                7,
                &[(&a, 1)],
                0
            ))])
            .await,
            vec![rejected(ErrorCode::StaleEpoch)]
        );
        // "Already stored" comes first: the old op is acknowledged, not called stale.
        assert_eq!(
            env.upload(chain(&a, item(1), 1, 1)).await,
            vec![UploadResult::AlreadyStored]
        );
        // The re-issued op, same seq, at the new epoch.
        let mut reissued = OpSpec::new(item(1), 2, 1);
        reissued.epoch = 1;
        env.store(vec![Record::Op(sign_op(&a, VAULT, &reissued))])
            .await;

        // A revoked device's op up to its cut-off is exempt, whoever uploads it; one past it
        // is refused as invalid.
        env.directory.set(
            &r,
            AuthorStatus::Revoked {
                last_accepted_device_seq: 3,
            },
        );
        env.store(chain(&r, item(1), 3, 3)).await;
        assert_eq!(
            env.upload(chain(&r, item(1), 4, 4)).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
    });
}

#[test]
fn revoked_suspended_and_kind4_authors() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, r, s) = (Device::new(1), Device::new(2), Device::new(3));
        let web = Device::web(4, NOW - 1_000);
        env.enrol(&[&a, &r, &s, &web]);
        env.store(chain(&r, item(1), 1, 3)).await;
        env.store(chain(&s, item(1), 1, 1)).await;

        env.directory.set(
            &r,
            AuthorStatus::Revoked {
                last_accepted_device_seq: 3,
            },
        );
        env.directory.set(&s, AuthorStatus::Suspended);

        // A revoked author's snapshots are refused, even one within its cut-off.
        assert_eq!(
            env.upload(vec![Record::Snapshot(sign_snapshot(
                &r,
                item(1),
                1,
                &[(&r, 3)],
                0
            ))])
            .await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
        // Another device's snapshot may count the revoked device's entry up to its cut-off.
        env.store(vec![Record::Snapshot(sign_snapshot(
            &a,
            item(1),
            2,
            &[(&r, 3), (&s, 1)],
            0,
        ))])
        .await;
        // A suspended author's records are refused, ops and snapshots.
        assert_eq!(
            env.upload(chain(&s, item(1), 2, 2)).await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
        assert_eq!(
            env.upload(vec![Record::Snapshot(sign_snapshot(
                &s,
                item(1),
                3,
                &[(&s, 1)],
                0
            ))])
            .await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );

        // Kind 4: an op whose HLC is at or before the expiry is accepted; one after it is not.
        let mut early = OpSpec::new(item(2), 1, 0);
        early.hlc_ms = NOW - 1_000;
        env.store(vec![Record::Op(sign_op(&web, VAULT, &early))])
            .await;
        let mut late = OpSpec::new(item(2), 2, 1);
        late.hlc_ms = NOW - 999;
        assert_eq!(
            env.upload(vec![Record::Op(sign_op(&web, VAULT, &late))])
                .await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
        // Its certificate has expired at the server's clock: no new snapshot from it.
        assert_eq!(
            env.upload(vec![Record::Snapshot(sign_snapshot(
                &web,
                item(2),
                4,
                &[(&web, 1)],
                0
            ))])
            .await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
    });
}

#[test]
fn snapshots_that_claim_unheld_dots_are_refused() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        env.store(chain(&a, item(1), 1, 2)).await;
        env.store(chain(&b, item(1), 1, 1)).await;
        // Its own entry above its head.
        assert_eq!(
            env.upload(vec![Record::Snapshot(sign_snapshot(
                &b,
                item(1),
                1,
                &[(&b, 2)],
                0
            ))])
            .await,
            vec![rejected(ErrorCode::InvalidRequest)]
        );
        // Another device's entry above that device's head, up to u64::MAX.
        for claim in [3, u64::MAX] {
            assert_eq!(
                env.upload(vec![Record::Snapshot(sign_snapshot(
                    &b,
                    item(1),
                    2,
                    &[(&a, claim), (&b, 1)],
                    0
                ))])
                .await,
                vec![rejected(ErrorCode::InvalidRequest)]
            );
        }
        env.store(vec![Record::Snapshot(sign_snapshot(
            &b,
            item(1),
            2,
            &[(&a, 2), (&b, 1)],
            0,
        ))])
        .await;
    });
}

#[test]
fn other_accounts_see_no_vault() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        let request = FetchRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            cursor: SeqVector::default(),
            wraps_after_epoch: None,
        };
        assert!(matches!(
            env.domain.fetch(OTHER_ACCOUNT, &request).await,
            Err(VaultError::NotFound)
        ));
        let upload = UploadRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            records: List::new(chain(&a, item(1), 1, 1)).unwrap(),
        };
        assert!(matches!(
            env.domain.upload(OTHER_ACCOUNT, &upload, NOW).await,
            Err(VaultError::NotFound)
        ));
        assert!(matches!(
            env.domain.self_grant(OTHER_ACCOUNT, VAULT).await,
            Err(VaultError::NotFound)
        ));
        assert_eq!(env.domain.vaults(ACCOUNT).await.unwrap(), vec![VAULT]);
        assert!(env.domain.vaults(OTHER_ACCOUNT).await.unwrap().is_empty());
    });
}

/// A self-grant of the test vault with the given epochs.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
fn grant(account_key_epoch: u32, vault_key_epoch: u32, fill: u8) -> VaultSelfGrant {
    VaultSelfGrant {
        vault_id: Id::from_bytes(VAULT.to_bytes()),
        account_key_epoch,
        vault_key_epoch,
        envelope: KeyEnvelope::new(vec![fill; 98]).unwrap(),
    }
}

#[test]
fn self_grants_are_republished_only_in_the_reconciliation_epoch() {
    block_on(async {
        let env = Env::new(1).await;
        // Not newer: kept, answered false.
        let same = env.domain.self_grant(ACCOUNT, VAULT).await.unwrap();
        assert!(
            !env.domain
                .republish_self_grant(ACCOUNT, &same, NOW)
                .await
                .unwrap()
        );
        // Newer in the account epoch only: stored.
        let newer = grant(1, 0, 0x5b);
        assert!(
            env.domain
                .republish_self_grant(ACCOUNT, &newer, NOW)
                .await
                .unwrap()
        );
        assert_eq!(env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(), newer);
        // Once the epoch ends, a re-publication is refused.
        let mut tx = env.db.begin_write().await.unwrap();
        rizzy_storage::lock_account(&mut tx, ACCOUNT.as_bytes())
            .await
            .unwrap();
        assert!(
            rizzy_storage::meta::end_reconciliation_epoch(&mut tx, ACCOUNT.as_bytes())
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();
        assert!(matches!(
            env.domain
                .republish_self_grant(ACCOUNT, &grant(2, 0, 0x5c), NOW)
                .await,
            Err(VaultError::Invalid)
        ));
        assert_eq!(env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(), newer);
    });
}

/// A re-published self-grant carries unsigned epochs (CRYPTO.md §4.2). It must never lock the
/// vault: its `vault_key_epoch` is bounded by what the server verified, it never goes down, and
/// it never moves the vault's stale-epoch reference.
#[test]
fn a_bogus_self_grant_epoch_cannot_lock_the_vault() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        env.store(chain(&a, item(1), 1, 1)).await;
        let original = env.domain.self_grant(ACCOUNT, VAULT).await.unwrap();

        // Above every epoch the server verified (the vault's 0, the stored headers' 0).
        for bogus in [grant(0, u32::MAX, 0x66), grant(u32::MAX, 1, 0x67)] {
            assert!(matches!(
                env.domain.republish_self_grant(ACCOUNT, &bogus, NOW).await,
                Err(VaultError::Invalid)
            ));
        }
        assert_eq!(
            env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(),
            original
        );

        // A signed op at epoch 1 justifies a grant at epoch 1, which is stored; the vault's
        // own epoch stays 0, so an epoch-0 op is still accepted.
        let mut at_one = OpSpec::new(item(1), 2, 1);
        at_one.epoch = 1;
        env.store(vec![Record::Op(sign_op(&a, VAULT, &at_one))])
            .await;
        let rotated = grant(1, 1, 0x68);
        assert!(
            env.domain
                .republish_self_grant(ACCOUNT, &rotated, NOW)
                .await
                .unwrap()
        );
        assert_eq!(
            env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(),
            rotated
        );
        env.store(chain(&a, item(1), 3, 3)).await;

        // Component-wise: a higher account epoch with a lower vault epoch is left out.
        assert!(
            !env.domain
                .republish_self_grant(ACCOUNT, &grant(2, 0, 0x69), NOW)
                .await
                .unwrap()
        );
        assert_eq!(
            env.domain.self_grant(ACCOUNT, VAULT).await.unwrap(),
            rotated
        );
    });
}
