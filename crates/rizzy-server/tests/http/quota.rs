// SPDX-License-Identifier: AGPL-3.0-only

//! The per-account storage quota over HTTP ([ADR 0048]): a real client uploads through the
//! router to a server configured with `RIZZY_ACCOUNT_QUOTA_BYTES` at its 256 MiB minimum.
//! Filling 288 MiB through the API would take minutes, so the test moves the account's counter
//! next to the limit through `rizzy-storage` (the one writer of it) and then uploads real
//! records across it:
//!
//! - every account answer carries `bytes_used` and `quota_bytes` (§5);
//! - a request whose records land exactly on the quota plus the upload limit is stored; the next
//!   record is answered `{"result":"rejected","error":"quota_exceeded"}` on the wire, and
//!   `rizzy-client` surfaces the code (§3, §5);
//! - `worker`'s reconciliation corrects the moved counter back to the rows' sum, and the
//!   startup backfill seeds an account that lost its row (§4).
//!
//! [ADR 0048]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0048-per-account-storage-quota.md

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::rizzy_proto::vault::{Record, UploadRequest};
use rizzy_domain_auth::types::ErrorCode;
use rizzy_server::config;
use rizzy_storage::{Database, lock_account};

use crate::common::{Server, block_on};
use crate::rotation::{Auth, Client, post, signup, signup_named};

/// `RIZZY_ACCOUNT_QUOTA_BYTES` at its minimum.
const QUOTA: u64 = 256 << 20;

/// The default `RIZZY_MAX_UPLOAD_BYTES`, the headroom (§3).
const HEADROOM: u64 = 32 << 20;

/// A record's counted bytes (§2): the statement as served, the body or envelope, the wrap.
fn counted(record: &Record) -> u64 {
    let n = match record {
        Record::Op(op) => {
            op.statement.len()
                + op.body.as_ref().map_or(0, |b| b.as_slice().len())
                + op.key_wrap.as_ref().map_or(0, |w| w.envelope.len())
        }
        Record::Snapshot(s) => {
            s.statement.len()
                + s.envelope.len()
                + s.key_wrap.as_ref().map_or(0, |w| w.envelope.len())
        }
    };
    u64::try_from(n).unwrap()
}

/// The account's counter and the true sum of its vault rows.
async fn usage(db: &Database, account: [u8; 16]) -> (u64, u64) {
    let mut r = db.begin_read().await.unwrap();
    let counter = rizzy_storage::quota::bytes_used(r.conn(), &account)
        .await
        .unwrap();
    let truth = rizzy_domain_vault::usage::counted_bytes(
        r.conn(),
        rizzy_domain_auth::types::AccountId::from_bytes(account),
    )
    .await
    .unwrap();
    r.finish().await.unwrap();
    (counter, truth)
}

/// Moves the account's counter to `value`, as only `rizzy-storage` may.
async fn set_counter(db: &Database, account: [u8; 16], value: u64) {
    let mut w = db.begin_write().await.unwrap();
    lock_account(&mut w, &account).await.unwrap();
    rizzy_storage::quota::reconcile(&mut w, &account, value, true, 1)
        .await
        .unwrap();
    w.commit().await.unwrap();
}

#[test]
fn uploads_stop_exactly_at_the_quota_and_its_headroom() {
    block_on(async {
        let quota = QUOTA.to_string();
        let server = Server::start_with(&[(config::ACCOUNT_QUOTA_BYTES, quota.as_str())]).await;
        let db = server.services.db.clone();
        let mut rng = ChaCha20Rng::seed_from_u64(48);
        let (up, _sk, _code) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        let account = a.state.account_id().to_bytes();

        // §5: the account answer carries the counter and the quota.
        a.create(&mut rng, "one");
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let (counter, truth) = usage(&db, account).await;
        assert!(counter > 0);
        assert_eq!(counter, truth);
        let view = a.account_view(&server).await;
        assert_eq!(view["bytes_used"], counter);
        assert_eq!(view["quota_bytes"], QUOTA);

        // A request whose records end exactly on the limit: every record is stored.
        a.create(&mut rng, "two");
        let request: UploadRequest = a
            .vault
            .upload_request(&mut rng, &a.unlocked)
            .unwrap()
            .unwrap();
        let size: u64 = request.records.as_slice().iter().map(counted).sum();
        set_counter(&db, account, QUOTA + HEADROOM - size).await;
        let reply = post(
            &server,
            "/api/v1/vault/upload",
            &request,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        let answer: serde_json::Value = reply.json();
        for result in answer["results"].as_array().unwrap() {
            assert_eq!(result["result"], "stored");
        }
        let outcome = a.vault.apply_upload_response(&reply.json()).unwrap();
        assert!(outcome.rejected.is_empty());
        assert_eq!(usage(&db, account).await.0, QUOTA + HEADROOM);

        // One more record: refused per record with `quota_exceeded`, in a 200 answer.
        a.create(&mut rng, "three");
        let request: UploadRequest = a
            .vault
            .upload_request(&mut rng, &a.unlocked)
            .unwrap()
            .unwrap();
        let reply = post(
            &server,
            "/api/v1/vault/upload",
            &request,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        assert_eq!(reply.status.as_u16(), 200);
        let answer: serde_json::Value = reply.json();
        assert_eq!(
            answer["results"][0],
            serde_json::json!({"result": "rejected", "error": "quota_exceeded"})
        );
        let outcome = a.vault.apply_upload_response(&reply.json()).unwrap();
        assert_eq!(outcome.rejected, vec![ErrorCode::QuotaExceeded]);
        assert_eq!(
            usage(&db, account).await.0,
            QUOTA + HEADROOM,
            "nothing charged"
        );
        // The client's sync stops on it, the op still unsent.
        assert_eq!(
            a.sync(&server, &mut rng).await,
            vec![ErrorCode::QuotaExceeded]
        );
        assert_eq!(a.vault.unacknowledged().0, 1);
        let view = a.account_view(&server).await;
        assert_eq!(view["bytes_used"], QUOTA + HEADROOM);

        // §4: the daily reconciliation puts the counter back to the rows' sum, after which the
        // unsent op fits again.
        let mut last = None;
        assert_eq!(
            rizzy_server::worker::reconcile_usage(&db, &mut last).await,
            Some(1)
        );
        assert!(last.is_some());
        assert_eq!(
            rizzy_server::worker::reconcile_usage(&db, &mut last).await,
            None,
            "at most once a day"
        );
        let (counter, truth) = usage(&db, account).await;
        assert_eq!(counter, truth);
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert_eq!(a.vault.unacknowledged().0, 0);
        let (counter, truth) = usage(&db, account).await;
        assert_eq!(counter, truth);

        // §4: an account that owns a vault and has no counter row (signed up after the startup
        // backfill, nothing uploaded yet) is seeded by the next backfill, with 0, and a second
        // backfill finds nothing to do. The first account keeps its counter.
        let (other, _, _) = signup_named(&server, &mut rng, "bob", false).await;
        let mut b = Client::signed_up(&server, other).await;
        let bob = b.state.account_id().to_bytes();
        assert_eq!(b.account_view(&server).await["bytes_used"], 0);
        assert_eq!(rizzy_server::usage::backfill(&db, 2).await.unwrap(), 1);
        assert_eq!(usage(&db, bob).await, (0, 0));
        assert_eq!(rizzy_server::usage::backfill(&db, 3).await.unwrap(), 0);
        assert_eq!(usage(&db, account).await, (truth, truth));
    });
}
