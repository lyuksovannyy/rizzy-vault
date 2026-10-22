// SPDX-License-Identifier: AGPL-3.0-only

//! The per-account storage quota (ADR 0048 §2–§4): the counted unit, the refusal at the exact
//! boundary, the headroom, the healing exemption, compaction's credit, and the per-domain total
//! the backfill and reconciliation use.

use rizzy_domain_vault::Quota;
use rizzy_proto::error::ErrorCode;
use rizzy_proto::objects::{ItemKeyWrap, KeyEnvelope};
use rizzy_proto::vault::{HealingRequest, Record, UploadResult};
use rizzy_proto::wire::{Id, List};

use crate::common::{
    ACCOUNT, Device, Env, NOW, OpSpec, VAULT, block_on, chain, item, sign_op, sign_snapshot,
};

/// A record's counted bytes from the wire (ADR 0048 §2): the statement as served (its framing,
/// header and container), the body or envelope, and the carried wrap.
fn wire_bytes(record: &Record) -> u64 {
    let n = match record {
        Record::Op(op) => {
            op.statement.len()
                + op.body.as_ref().map_or(0, rizzy_proto::wire::Bytes::len)
                + op.key_wrap.as_ref().map_or(0, |w| w.envelope.len())
        }
        Record::Snapshot(s) => {
            s.statement.len()
                + s.envelope.len()
                + s.key_wrap.as_ref().map_or(0, |w| w.envelope.len())
        }
    };
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// A quota with no headroom, so the limit is exactly `bytes`.
const fn exactly(bytes: u64) -> Quota {
    Quota {
        quota_bytes: bytes,
        headroom_bytes: 0,
    }
}

#[test]
fn the_counter_is_the_portable_wire_size() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        assert_eq!(env.counted().await, 0);
        let mut records = chain(&a, item(1), 1, 2);
        let mut spec = OpSpec::new(item(2), 3, 2);
        spec.wrap = Some(vec![0x77; 98]);
        records.push(Record::Op(sign_op(&a, VAULT, &spec)));
        records.push(Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, 2)], 0)));
        let expected: u64 = records.iter().map(wire_bytes).sum();
        env.store(records.clone()).await;
        assert_eq!(env.counted().await, expected);
        // "Already stored" stores nothing and charges nothing.
        assert_eq!(
            env.upload(records).await,
            vec![UploadResult::AlreadyStored; 4]
        );
        assert_eq!(env.counted().await, expected);
        let mut r = env.db.begin_read().await.unwrap();
        assert_eq!(
            rizzy_domain_vault::usage::accounts(r.conn()).await.unwrap(),
            vec![ACCOUNT]
        );
        r.finish().await.unwrap();
    });
}

#[test]
fn a_record_past_the_limit_is_refused_at_the_exact_boundary() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        let records = chain(&a, item(1), 1, 4);
        env.store(records[..1].to_vec()).await;
        let at_start = env.counted().await;
        let second = wire_bytes(&records[1]);

        // One byte short of the second record: it is refused, the rest is not looked at, and
        // nothing is charged.
        let tight = env.domain_with_quota(exactly(at_start + second - 1));
        let request = rizzy_proto::vault::UploadRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            records: List::new(records[1..].to_vec()).unwrap(),
        };
        let answer = tight.upload(ACCOUNT, &request, NOW).await.unwrap();
        assert_eq!(
            answer.results.into_vec(),
            vec![
                UploadResult::Rejected {
                    error: ErrorCode::QuotaExceeded
                },
                UploadResult::NotProcessed,
                UploadResult::NotProcessed,
            ]
        );
        assert_eq!(env.counted().await, at_start);

        // Exactly at the limit: stored (the refusal is "past", not "at"). The next record of the
        // same request is refused, and the one stored before it stays (ADR 0048 §3).
        let exact = env.domain_with_quota(exactly(at_start + second));
        let answer = exact.upload(ACCOUNT, &request, NOW).await.unwrap();
        assert_eq!(
            answer.results.into_vec(),
            vec![
                UploadResult::Stored,
                UploadResult::Rejected {
                    error: ErrorCode::QuotaExceeded
                },
                UploadResult::NotProcessed,
            ]
        );
        assert_eq!(env.counted().await, at_start + second);

        // A record already stored is acknowledged even with the account at its limit.
        let answer = exact.upload(ACCOUNT, &request, NOW).await.unwrap();
        assert_eq!(answer.results.as_slice()[0], UploadResult::AlreadyStored);
    });
}

#[test]
fn the_headroom_lets_a_request_that_starts_at_the_quota_finish() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        let records = chain(&a, item(1), 1, 3);
        env.store(records[..1].to_vec()).await;
        let at_quota = env.counted().await;
        let rest: u64 = records[1..].iter().map(wire_bytes).sum();
        // The account is exactly at its quota; the request's raw size fits the headroom.
        let quota = Quota {
            quota_bytes: at_quota,
            headroom_bytes: rest,
        };
        assert_eq!(quota.limit(), at_quota + rest);
        let domain = env.domain_with_quota(quota);
        let request = rizzy_proto::vault::UploadRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            records: List::new(records[1..].to_vec()).unwrap(),
        };
        let answer = domain.upload(ACCOUNT, &request, NOW).await.unwrap();
        assert_eq!(answer.results.into_vec(), vec![UploadResult::Stored; 2]);
        assert_eq!(env.counted().await, at_quota + rest);
        // Past the quota and its headroom now: the next record is refused.
        let next = vec![chain(&a, item(1), 4, 4).remove(0)];
        let request = rizzy_proto::vault::UploadRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            records: List::new(next).unwrap(),
        };
        let answer = domain.upload(ACCOUNT, &request, NOW).await.unwrap();
        assert_eq!(
            answer.results.into_vec(),
            vec![UploadResult::Rejected {
                error: ErrorCode::QuotaExceeded
            }]
        );
    });
}

#[test]
fn a_healing_request_is_never_refused_for_quota_and_is_charged() {
    block_on(async {
        let a = Device::new(1);
        let original = Env::new(1).await;
        original.enrol(&[&a]);
        original.store(chain(&a, item(1), 1, 2)).await;
        let dump = original.db.dump().await.unwrap();
        let before = original.counted().await;
        let later = chain(&a, item(1), 3, 4);
        original.store(later.clone()).await;

        // The restore brings the counter back with its rows (ADR 0048 §4: backed up).
        let mut slot = original.into_slot();
        let db = slot.fresh_db().await;
        db.restore(&dump, rizzy_storage::RestoreGeneration([2; 16]), 2)
            .await
            .unwrap();
        let env = Env::over(slot, db);
        env.enrol(&[&a]);
        assert_eq!(env.counted().await, before);

        // A quota of zero: the healing request still goes through, and its bytes are charged.
        let none = env.domain_with_quota(exactly(0));
        let mut records = later.clone();
        records.push(Record::Snapshot(sign_snapshot(&a, item(1), 7, &[(&a, 4)], 0)));
        let added: u64 = records.iter().map(wire_bytes).sum();
        let heal = HealingRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            item_key_wraps: List::new(vec![ItemKeyWrap {
                item_id: Id::from_bytes(item(1).to_bytes()),
                item_key_id: Id::from_bytes([0x4c; 16]),
                vault_key_epoch: 0,
                envelope: KeyEnvelope::new(vec![0x78; 98]).unwrap(),
            }])
            .unwrap(),
            records: List::new(records).unwrap(),
            self_grant: None,
        };
        none.heal(ACCOUNT, None, &heal, NOW).await.unwrap();
        assert_eq!(env.counted().await, before + added);
        // An ordinary upload is refused at once.
        let request = rizzy_proto::vault::UploadRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            records: List::new(chain(&a, item(1), 5, 5)).unwrap(),
        };
        let answer = none.upload(ACCOUNT, &request, NOW).await.unwrap();
        assert_eq!(
            answer.results.into_vec(),
            vec![UploadResult::Rejected {
                error: ErrorCode::QuotaExceeded
            }]
        );
    });
}

#[test]
fn compaction_credits_the_bodies_and_snapshots_it_deletes() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        env.store(chain(&a, item(1), 1, 3)).await;
        let first = Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, 2)], 0));
        env.store(vec![first.clone()]).await;
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, item(1), 2, &[(&a, 3)], 0)),
            Record::Snapshot(sign_snapshot(&b, item(1), 3, &[(&a, 3)], 0)),
        ])
        .await;
        let full = env.counted().await;
        let report = env.domain.run_compaction(16, NOW).await.unwrap().report;
        assert!(report.bodies_deleted > 0 && report.snapshots_dropped > 0);
        // The counter follows the rows exactly: headers stay, bodies and dropped snapshots go.
        let after = env.counted().await;
        assert!(after < full);
        assert!(full - after >= wire_bytes(&first));
    });
}
