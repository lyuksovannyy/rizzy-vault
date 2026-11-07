// SPDX-License-Identifier: AGPL-3.0-only

//! The revocation window through the router and the real bridge ([ADR 0091] §1, §2; §7 tests 1
//! and 2 for `vault/upload`): real clients (`rizzy-client`) A, B and the stolen device D.
//!
//! - [`a_window_freezes_other_devices_uploads`]: A, re-authenticated over its own device,
//!   suspends D over `POST /api/v1/devices/suspend`; `account/state` carries
//!   `revocation_window` and `suspended_devices`; B's `vault/upload` answers
//!   `409 {"error":"revocation_pending"}` and stores nothing, A's own upload is stored; an op D
//!   signed before the suspension is refused over A's session during the window and over B's
//!   session after the revocation commit closed it (§7 test 1's op case); B's byte-identical
//!   retry is no longer refused by the window once it closed.
//!
//! The window's expiry is not driven here: the server reads the wall clock, and the expiry is
//! covered in `rizzy-domain-auth`'s and `rizzy-domain-vault`'s tests with an injected clock.
//!
//! [ADR 0091]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0091-revoked-device-rotation-race.md

use axum::http::StatusCode;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::rotation::{RevokeDevice, RotationLevel, RotationOptions, start_rotation};

use crate::common::{Reply, Server, block_on};
use crate::rotation::{Auth, Client, copy_token, enrol, login, now_ms, post, post_empty, signup};

/// Asserts that an upload of D's op was answered with its first record refused for its author
/// (`invalid_request`: the vault store answers an author rule's refusal as `Refusal::Invalid`)
/// and nothing stored.
fn refused_for_its_author(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::OK);
    let answer: serde_json::Value = reply.json();
    let results = answer["results"].as_array().unwrap();
    assert_eq!(
        results[0],
        serde_json::json!({ "result": "rejected", "error": "invalid_request" }),
        "{answer}"
    );
    assert!(
        results
            .iter()
            .all(|r| !matches!(r["result"].as_str(), Some("stored" | "already_stored"))),
        "{answer}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario read top to bottom: setup, suspension, the window, the revocation, after it"
)]
fn a_window_freezes_other_devices_uploads() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(91);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut a = Client::signed_up(&server, up).await;
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let mut b = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert!(b.sync(&server, &mut rng).await.is_empty());
        let mut d = Client::enrolled(&server, enrol(&server, &mut rng, &sk).await).await;
        assert!(d.sync(&server, &mut rng).await.is_empty());
        a.refresh(&server).await;
        b.refresh(&server).await;

        // Control: an op D signed, uploaded over B's session before the suspension, is stored,
        // so the refusals below are the author rule, not the upload path.
        let first = d.create(&mut rng, "d1");
        let d_up = d
            .vault
            .upload_request(&mut rng, &d.unlocked)
            .unwrap()
            .unwrap();
        let reply = post(
            &server,
            "/api/v1/vault/upload",
            &d_up,
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let outcome = d.vault.apply_upload_response(&reply.json()).unwrap();
        assert!(outcome.rejected.is_empty());
        // D signs its next op before the theft is noticed; it never reaches the server.
        let stolen = d.create(&mut rng, "d2");
        let d_up = d
            .vault
            .upload_request(&mut rng, &d.unlocked)
            .unwrap()
            .unwrap();

        // A, re-authenticated over its own device, suspends D: the window opens for A.
        let reauth = login(&server, &mut rng, &sk, Some((&mut a.session, &a.unlocked))).await;
        let a_id = Base64UrlUnpadded::encode_string(&a.state.device_id().to_bytes());
        let d_id = Base64UrlUnpadded::encode_string(&d.state.device_id().to_bytes());
        let reply = post(
            &server,
            "/api/v1/devices/suspend",
            &serde_json::json!({ "device_id": d_id }),
            Auth::Bearer(reauth.bearer_token()),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let head = reply.json::<serde_json::Value>()["last_accepted_device_seq"]
            .as_u64()
            .unwrap();
        let view = a.account_view(&server).await;
        assert_eq!(
            view["revocation_window"]["revoker_device_id"],
            a_id.as_str()
        );
        let expires = view["revocation_window"]["expires_at_ms"].as_u64().unwrap();
        assert!(expires > now_ms());
        assert_eq!(view["suspended_devices"], serde_json::json!([d_id]));

        // B's upload: 409 revocation_pending, nothing stored.
        let theirs = b.create(&mut rng, "b");
        let b_up = b
            .vault
            .upload_request(&mut rng, &b.unlocked)
            .unwrap()
            .unwrap();
        let refused = post(
            &server,
            "/api/v1/vault/upload",
            &b_up,
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(refused.status, StatusCode::CONFLICT);
        assert_eq!(refused.error(), "revocation_pending");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&refused.body).unwrap(),
            serde_json::json!({ "error": "revocation_pending" })
        );
        // The same from A, the revoker, is stored, and B's op is not on the server.
        let own = a.create(&mut rng, "a");
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert!(!a.vault.item_ids().contains(&theirs));
        assert!(a.vault.item_ids().contains(&own));

        // D's op over A's session, inside the window: R passes the freeze, the author rule
        // refuses a suspended author's record whatever session uploads it.
        let reply = post(
            &server,
            "/api/v1/vault/upload",
            &d_up,
            Auth::Device(&mut a.session, &a.unlocked),
        )
        .await;
        refused_for_its_author(&reply);

        // The revocation commit (a full rotation) closes the window.
        assert!(a.sync(&server, &mut rng).await.is_empty());
        let options = RotationOptions {
            level: RotationLevel::Full,
            revoke: &[RevokeDevice {
                device_id: d.state.device_id(),
                last_accepted_device_seq: head,
            }],
            recovery_code: None,
            now_ms: now_ms(),
        };
        let pending = start_rotation(
            &mut rng,
            reauth,
            &a.state,
            &a.unlocked,
            &[&a.vault],
            &options,
        )
        .unwrap();
        let token = copy_token(pending.bearer_token());
        post_empty(
            &server,
            "/api/v1/account/commit",
            pending.commit_request(),
            Auth::Bearer(&token),
        )
        .await;
        let done = pending
            .finalize(&mut rng, &mut a.state, &mut a.unlocked, &mut [&mut a.vault])
            .unwrap();
        drop(done);
        let view = a.account_view(&server).await;
        assert!(view["revocation_window"].is_null());
        assert_eq!(view["suspended_devices"], serde_json::json!([]));

        // After the window, D's op uploaded over B's session is still refused.
        let reply = post(
            &server,
            "/api/v1/vault/upload",
            &d_up,
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        refused_for_its_author(&reply);
        assert!(a.sync(&server, &mut rng).await.is_empty());
        assert!(!a.vault.item_ids().contains(&stolen));
        assert!(a.vault.item_ids().contains(&first));
        // B's byte-identical retry is no longer frozen (its op, at the old account-key epoch,
        // now meets the rotation's own rules instead).
        let retried = post(
            &server,
            "/api/v1/vault/upload",
            &b_up,
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(retried.status, StatusCode::OK);
    });
}
