// SPDX-License-Identifier: AGPL-3.0-only

//! ADR 0092 §4, §5 and §8 tests 9–10 over HTTP, through the client core against the real
//! server: a revocation whose rotation goes through `account/rotation/stage`, and a recovery
//! whose wrap sets are read page by page through `recovery/wraps` and whose rotation is staged.
//!
//! The account sizes that make staging and paging necessary (a commit above 32 MiB, more than
//! 65,536 rows) are too slow for the gate, so: the host passes the client an encoded length
//! above the floor (the client's choice by length itself is tested in `rizzy_client::staging`),
//! and the server's paged read runs with lower limits (`RecoveryPaging`, as the write caps'
//! `VaultDomain::with_wrap_caps`). Everything else is the production path.

use axum::http::StatusCode;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::recovery::{RecoveryInput, RecoveryOptions, start_recovery};
use rizzy_client::rizzy_proto::change::{StageRequest, StageResponse};
use rizzy_client::rizzy_proto::limits::ROTATION_STAGE_ROWS;
use rizzy_client::rizzy_proto::recovery::RecoveryWrapsResponse;
use rizzy_client::rotation::{RevokeDevice, RotationLevel, RotationOptions, start_rotation};
use rizzy_client::signup::DeviceKind;
use rizzy_domain_vault::port::RecoveryPaging;

use crate::common::{ORIGIN, Server, block_on};
use crate::recovery::{NEW_PASSWORD, read_as_recovered};
use crate::rotation::{
    Auth, Client, NAME, copy_token, device_session, enrol, login, now_ms, post, post_empty, signup,
};

/// An encoded length above the 32 MiB floor: the host's word that the inline body is too large.
const TOO_LARGE: usize = usize::MAX;

const STAGE: &str = "/api/v1/account/rotation/stage";
const COMMIT: &str = "/api/v1/account/commit";
const WRAPS: &str = "/api/v1/recovery/wraps";

/// Sends every stage request; asserts each is accepted and bounded, and that a resend of the
/// first is a no-op (§4 step 4). Returns the rows staged.
async fn stage_all(
    server: &Server,
    token: &rizzy_client::rizzy_proto::wire::SessionToken,
    stages: &[StageRequest],
) -> usize {
    assert!(!stages.is_empty());
    let mut rows = 0;
    for stage in stages {
        let n = stage.item_key_wraps.len() + stage.dropped.len();
        assert!(n <= ROTATION_STAGE_ROWS);
        rows += n;
        let reply = post(server, STAGE, stage, Auth::Bearer(token)).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.error());
    }
    let first = stages.first().unwrap();
    let before: StageResponse = post(server, STAGE, first, Auth::Bearer(token)).await.json();
    let again: StageResponse = post(server, STAGE, first, Auth::Bearer(token)).await.json();
    assert_eq!(before, again, "an identical stage request is a no-op");
    rows
}

/// §8 tests 9–10 (revocation half): a device revocation with a full rotation, staged, over HTTP.
/// The stage route refuses another session and a stale `base_state_seq`; the commit names the
/// staging with empty lists; the revoked device is locked out and a new device reads every item.
#[test]
fn a_revocation_commits_through_staging_over_http() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(92);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        let items: Vec<_> = (0..5)
            .map(|i| a.create(&mut rng, &format!("item {i}")))
            .collect();
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let mut b = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert!(b.sync(&server, &mut rng).await.is_empty());
        a.refresh(&server).await;
        assert!(a.sync(&server, &mut rng).await.is_empty());

        // Phase 1 (§11.8 step 0): A suspends B.
        let reauth = login(&server, &mut rng, &sk, Some((&mut a.session, &a.unlocked))).await;
        let b_id = Base64UrlUnpadded::encode_string(&b.state.device_id().to_bytes());
        let reply = post(
            &server,
            "/api/v1/devices/suspend",
            &serde_json::json!({ "device_id": b_id }),
            Auth::Bearer(reauth.bearer_token()),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let head = reply.json::<serde_json::Value>()["last_accepted_device_seq"]
            .as_u64()
            .unwrap();
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let options = RotationOptions {
            level: RotationLevel::Full,
            revoke: &[RevokeDevice {
                device_id: b.state.device_id(),
                last_accepted_device_seq: head,
            }],
            recovery_code: None,
            now_ms: now_ms(),
        };
        let mut pending = start_rotation(
            &mut rng,
            reauth,
            &a.state,
            &a.unlocked,
            &[&a.vault],
            &options,
        )
        .unwrap();
        let token = copy_token(pending.bearer_token());

        // A body that fits stays inline; one that does not is staged.
        assert!(pending.stage_requests(&mut rng, 1_000).unwrap().is_empty());
        let stages = pending.stage_requests(&mut rng, TOO_LARGE).unwrap();
        let upload = pending.commit_request().vault_rotation.as_ref().unwrap();
        let rotation_id = upload.staging().unwrap();
        assert!(
            upload
                .vaults()
                .iter()
                .all(|v| v.item_key_wraps.is_empty() && v.dropped.is_empty())
        );
        assert!(stages.iter().all(|s| s.rotation_id == rotation_id));

        // The route: no session, and a stale base state_seq, are refused.
        let first = stages.first().unwrap();
        let none = post(&server, STAGE, first, Auth::None).await;
        assert_eq!(none.status, StatusCode::UNAUTHORIZED);
        let mut stale = first.clone();
        stale.base_state_seq += 1;
        let refused = post(&server, STAGE, &stale, Auth::Bearer(&token)).await;
        assert_eq!(refused.status, StatusCode::CONFLICT);
        assert_eq!(refused.error(), "state_conflict");

        // Every row once (5 items), then the commit.
        assert_eq!(stage_all(&server, &token, &stages).await, items.len());
        post_empty(
            &server,
            COMMIT,
            pending.commit_request(),
            Auth::Bearer(&token),
        )
        .await;
        let done = pending
            .finalize(&mut rng, &mut a.state, &mut a.unlocked, &mut [&mut a.vault])
            .unwrap();
        a.authors = done.authors;
        assert!(done.dropped_items.is_empty());
        // The staging is gone with the commit: a stage request under it is now stale.
        let late = post(&server, STAGE, first, Auth::Bearer(&token)).await;
        assert_ne!(late.status, StatusCode::OK);

        // B is locked out; A and a new device read every item at the new epoch.
        assert_eq!(
            device_session(&server, &b.state, &b.unlocked)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert_eq!(a.vault.vault_key_epoch(), 1);
        let mut d = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert!(d.sync(&server, &mut rng).await.is_empty());
        for item in &items {
            assert_eq!(d.read(*item), a.read(*item));
        }
    });
}

/// §8 tests 9–10 (recovery half): an account above the (lowered) paging threshold answers
/// `wraps_paged`; the client reads every row once, page by page, then stages its rotation and
/// commits; the recovered device reads the items. No `rotation_limit` anywhere.
#[test]
fn a_paged_recovery_reads_every_row_and_commits_staged() {
    block_on(async {
        let server = Server::start_with_recovery_paging(RecoveryPaging {
            paged_above: 3,
            page_rows: 2,
        })
        .await;
        let mut rng = ChaCha20Rng::seed_from_u64(93);
        let (up, _sk, code) = signup(&server, &mut rng, true).await;
        let code = code.unwrap();
        let mut a = Client::signed_up(&server, up).await;
        let items: Vec<_> = (0..5)
            .map(|i| a.create(&mut rng, &format!("item {i}")))
            .collect();
        assert!(a.sync(&server, &mut rng).await.is_empty());

        let started = start_recovery(&RecoveryInput {
            server_origin: ORIGIN,
            login_name: NAME,
            recovery_code: &code,
        })
        .unwrap();
        let request = started.request().unwrap();
        let reply = post(&server, "/api/v1/recovery/start", &request, Auth::None).await;
        assert_eq!(reply.status, StatusCode::OK);
        let reply = post(&server, "/api/v1/recovery/complete", &request, Auth::None).await;
        assert_eq!(reply.status, StatusCode::OK);
        let answer: serde_json::Value = reply.json();
        assert_eq!(answer["wraps_paged"], true);
        let mut recovered = started.open(reply.json()).unwrap();
        let token = copy_token(recovered.bearer_token());

        // The route takes the recovery-only session only.
        let first = recovered.wraps_request().unwrap();
        assert_eq!(first.after, None);
        let none = post(&server, WRAPS, &first, Auth::None).await;
        assert_eq!(none.status, StatusCode::UNAUTHORIZED);

        // Every row once, ascending, in pages of at most two.
        let mut pages = 0;
        let mut rows = 0;
        while let Some(next) = recovered.wraps_request() {
            let reply = post(&server, WRAPS, &next, Auth::Bearer(&token)).await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.error());
            let page: RecoveryWrapsResponse = reply.json();
            assert!(page.item_key_wraps.len() <= 2);
            rows += page.item_key_wraps.len();
            pages += 1;
            recovered.add_wraps(page).unwrap();
        }
        assert_eq!(rows, items.len());
        assert_eq!(pages, 3);

        // The rotating recovery, staged.
        let (reregistering, request) = recovered
            .start_commit(
                &mut rng,
                &RecoveryOptions {
                    new_password: NEW_PASSWORD,
                    rotate: true,
                    device_kind: DeviceKind::DesktopCli,
                    now_ms: now_ms(),
                },
            )
            .unwrap();
        let reply = post(
            &server,
            "/api/v1/account/reregister/start",
            &request,
            Auth::Bearer(&token),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let mut pending = reregistering.finish(&mut rng, &reply.json()).unwrap();
        let secret_key = pending.emergency_kit().secret_key().to_owned();
        let last = secret_key.rsplit('-').next().unwrap().to_owned();
        pending.confirm_kit(&last).unwrap();
        let stages = pending.stage_requests(&mut rng, TOO_LARGE).unwrap();
        assert_eq!(stage_all(&server, &token, &stages).await, items.len());
        post_empty(
            &server,
            COMMIT,
            pending.commit_request().unwrap(),
            Auth::Bearer(&token),
        )
        .await;
        let done = pending.finalize().unwrap();
        let first = items.first().copied().unwrap();
        assert_eq!(read_as_recovered(&server, done, first).await, a.read(first));
    });
}
