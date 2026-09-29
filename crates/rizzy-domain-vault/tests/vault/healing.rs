//! Restore healing (ADR 0021 §9 "Healing request", "Server acceptance"; ADR 0012 §7 "Healing a
//! server rollback" step 4 as §9 replaces it), after a real `rizzy-storage` backup and restore.

use rizzy_domain_vault::HealingError;
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{ItemKeyWrap, KeyEnvelope};
use rizzy_proto::vault::{HealingRequest, Record, UploadResult};
use rizzy_proto::wire::{Id, List};

use crate::common::{
    ACCOUNT, Device, Env, NOW, VAULT, block_on, chain, covers_of, item, op_dot, ops_of,
    sign_snapshot,
};

/// A server that stored A's ops 1–5 on item 1, then was restored from a backup taken after op 2,
/// with restore generation 2 (the original has 1). Returns the restored server and A's records
/// 3–5 as A holds them.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn restored(a: &Device) -> (Env, Vec<Record>) {
    let original = Env::new(1).await;
    original.enrol(&[a]);
    original.store(chain(a, item(1), 1, 2)).await;
    let dump = original.db.dump().await.unwrap();
    let later = chain(a, item(1), 3, 5);
    original.store(later.clone()).await;

    // A fresh database of the same slot (on PostgreSQL, the same database wiped).
    let mut slot = original.into_slot();
    let db = slot.fresh_db().await;
    db.restore(&dump, rizzy_storage::RestoreGeneration([2; 16]), 2)
        .await
        .unwrap();
    let env = Env::over(slot, db);
    env.enrol(&[a]);
    (env, later)
}

/// The record with its body removed: a header the healer holds without a body.
fn without_body(record: &Record) -> Record {
    let Record::Op(op) = record else {
        unreachable!()
    };
    let mut op = op.clone();
    op.body = None;
    Record::Op(op)
}

/// The wrap the healer re-publishes.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
fn lost_wrap() -> ItemKeyWrap {
    ItemKeyWrap {
        item_id: Id::from_bytes(item(1).to_bytes()),
        item_key_id: Id::from_bytes([0x4c; 16]),
        vault_key_epoch: 0,
        envelope: KeyEnvelope::new(vec![0x78; 98]).unwrap(),
    }
}

/// A healing request for the test vault.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
fn request(wraps: Vec<ItemKeyWrap>, records: Vec<Record>) -> HealingRequest {
    HealingRequest {
        vault_id: Id::from_bytes(VAULT.to_bytes()),
        item_key_wraps: List::new(wraps).unwrap(),
        records: List::new(records).unwrap(),
    }
}

#[test]
fn a_healing_request_restores_headers_behind_a_fresh_snapshot() {
    block_on(async {
        let a = Device::new(1);
        let (env, later) = restored(&a).await;
        // The restored server is behind: heads at 2, a new restore generation.
        let pages = env.fetch_all(&[]).await;
        assert_eq!(pages[0].response.restore_generation.as_bytes(), &[2; 16]);
        assert_eq!(ops_of(&pages).len(), 2);

        // A no longer holds the bodies of 3 and 4 (compacted locally), so it sends them as
        // bodiless headers behind a fresh snapshot, and 5 with its body.
        let heal = request(
            vec![lost_wrap()],
            vec![
                without_body(&later[0]),
                without_body(&later[1]),
                later[2].clone(),
                Record::Snapshot(sign_snapshot(&a, item(1), 7, &[(&a, 5)], 0)),
            ],
        );
        let answer = env.domain.heal(ACCOUNT, &heal, NOW).await.unwrap();
        assert_eq!(answer.restore_generation.as_bytes(), &[2; 16]);

        let pages = env.fetch_all(&[]).await;
        let ops = ops_of(&pages);
        assert_eq!(ops.len(), 5);
        let bodiless: Vec<u64> = ops
            .iter()
            .filter(|op| op.body.is_none())
            .map(|op| op_dot(op).1.seq())
            .collect();
        assert_eq!(bodiless, vec![3, 4]);
        // Served with the healer's snapshot as their cover (checked by `check_page`).
        assert_eq!(covers_of(&pages).len(), 1);
        assert_eq!(pages[0].response.item_key_wraps.len(), 1);

        // The same request again changes nothing and is accepted: every part is already stored.
        env.domain.heal(ACCOUNT, &heal, NOW).await.unwrap();
        assert_eq!(ops_of(&env.fetch_all(&[]).await).len(), 5);
        // Normal uploads continue the healed chain.
        env.store(chain(&a, item(1), 6, 6)).await;
        // And a normal upload answers with the restored generation.
        assert_eq!(
            env.upload(chain(&a, item(1), 6, 6)).await,
            vec![UploadResult::AlreadyStored]
        );
    });
}

#[test]
fn a_healing_request_is_refused_whole() {
    block_on(async {
        let a = Device::new(1);
        let (env, later) = restored(&a).await;

        // Bodiless headers without any snapshot covering them.
        let uncovered = request(
            vec![lost_wrap()],
            vec![
                without_body(&later[0]),
                without_body(&later[1]),
                later[2].clone(),
            ],
        );
        // A snapshot that covers only the first of them.
        let partly = request(
            vec![lost_wrap()],
            vec![
                without_body(&later[0]),
                without_body(&later[1]),
                Record::Snapshot(sign_snapshot(&a, item(1), 7, &[(&a, 3)], 0)),
            ],
        );
        // A gap in the chain: 4 without 3.
        let gap = request(
            vec![lost_wrap()],
            vec![
                later[1].clone(),
                Record::Snapshot(sign_snapshot(&a, item(1), 7, &[(&a, 4)], 0)),
            ],
        );
        for (heal, code) in [
            (uncovered, ErrorCode::InvalidRequest),
            (partly, ErrorCode::InvalidRequest),
            (gap, ErrorCode::PrevSeqMismatch),
        ] {
            match env.domain.heal(ACCOUNT, &heal, NOW).await {
                Err(HealingError::Refused(got)) => assert_eq!(got, code),
                other => panic!("expected a refusal, got {other:?}"),
            }
            // Nothing of the request was stored: no header, no wrap, no snapshot.
            let pages = env.fetch_all(&[]).await;
            assert_eq!(ops_of(&pages).len(), 2);
            assert!(pages[0].response.item_key_wraps.is_empty());
            assert!(covers_of(&pages).is_empty());
        }
        // A snapshot claiming dots the healed chain does not reach is refused too.
        let claims = request(
            Vec::new(),
            vec![
                later[0].clone(),
                Record::Snapshot(sign_snapshot(&a, item(1), 8, &[(&a, 9)], 0)),
            ],
        );
        assert!(matches!(
            env.domain.heal(ACCOUNT, &claims, NOW).await,
            Err(HealingError::Refused(ErrorCode::InvalidRequest))
        ));
        assert_eq!(ops_of(&env.fetch_all(&[]).await).len(), 2);
    });
}
