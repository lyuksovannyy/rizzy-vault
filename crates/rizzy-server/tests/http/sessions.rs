// SPDX-License-Identifier: AGPL-3.0-only

//! The `sessions` endpoints over HTTP ([ADR 0075] §2, §4–§6, §11 "HTTP"), with real clients
//! (`rizzy-client`) as in [`crate::rotation`]: the method and session gating of each route, the
//! strict body of `sessions/end`, the ended token's `401` byte for byte, and the rules end to
//! end (a device lists and ends a web session, sign-out, the others, another account's id).
//! The freshness and recovery-only rules, the race and INV-7 run in `rizzy-domain-auth`'s
//! `tests/auth/sessions.rs`, which controls the clock.
//!
//! [ADR 0075]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0075-session-listing-and-ending.md

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::rizzy_proto::session::{EndSessionRequest, SessionKindView, SessionListResponse};
use rizzy_client::rizzy_proto::wire::Id;
use rizzy_domain_auth::types::{SessionToken, paths};
use zeroize::Zeroizing;

use crate::common::{Reply, Server, block_on};
use crate::rotation::{
    Auth, Client, call, copy_token, login, login_named, post, signup, signup_named,
};

/// The four routes, with a body each accepts.
const ROUTES: &[(&str, &str)] = &[
    (paths::SESSIONS_LIST, ""),
    (paths::SESSIONS_CURRENT_END, ""),
    (
        paths::SESSIONS_END,
        r#"{"session_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ),
    (paths::SESSIONS_OTHERS_END, ""),
];

/// The status, headers and body of an answer, for a byte-for-byte comparison.
fn answer(reply: &Reply) -> (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let mut headers: Vec<(String, Vec<u8>)> = reply
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
        .collect();
    headers.sort();
    (reply.status, headers, reply.body.clone())
}

/// `sessions/list` with `auth`, parsed.
async fn list(server: &Server, auth: Auth<'_>) -> SessionListResponse {
    let reply = call(server, "POST", paths::SESSIONS_LIST, Vec::new(), auth).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.error());
    reply.json()
}

/// The `session_id` of the session behind a bearer token: its own `current` row.
async fn own_id(server: &Server, token: &SessionToken) -> Id {
    let rows = list(server, Auth::Bearer(token)).await;
    rows.sessions
        .iter()
        .find(|s| s.current)
        .map(|s| s.session_id)
        .unwrap()
}

/// `POST path` with no body.
async fn empty(server: &Server, path: &str, auth: Auth<'_>) -> Reply {
    call(server, "POST", path, Vec::new(), auth).await
}

/// `GET` gets `405 invalid_request`; no session or an unknown token gets `401`; a device
/// session's bearer token without its signature gets `401`; an oversized body `413`; an unknown
/// field or a bad id in `sessions/end` `400`.
#[test]
fn routes_are_gated_and_strict() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(7510);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut device = Client::signed_up(&server, up).await;
        let web = login(&server, &mut rng, &sk, None).await;
        let web_token = copy_token(web.bearer_token());
        let unknown = SessionToken::new(Zeroizing::new([0x42; 32]));

        for &(path, body) in ROUTES {
            let get = server
                .send(Request::get(path).body(Body::empty()).unwrap())
                .await;
            assert_eq!(get.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
            assert_eq!(get.error(), "invalid_request", "{path}");

            let none = call(&server, "POST", path, body.as_bytes().to_vec(), Auth::None).await;
            assert_eq!(none.status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(none.error(), "unauthorized", "{path}");
            let forged = call(
                &server,
                "POST",
                path,
                body.as_bytes().to_vec(),
                Auth::Bearer(&unknown),
            )
            .await;
            assert_eq!(forged.status, StatusCode::UNAUTHORIZED, "{path}");

            // The device session's token alone: every request over it must be signed.
            let bare = copy_token(device.session.bearer_token());
            let unsigned = call(
                &server,
                "POST",
                path,
                body.as_bytes().to_vec(),
                Auth::Bearer(&bare),
            )
            .await;
            assert_eq!(unsigned.status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(answer(&unsigned), answer(&forged), "{path}");

            // Past the default body limit (MAX_BODY_LEN, ADR 0075 §2), over a live session.
            let big = server
                .post_raw(path, vec![b' '; 1024 * 1024 + 1], Some(&web_token))
                .await;
            assert_eq!(big.status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
            assert_eq!(big.error(), "payload_too_large", "{path}");
        }

        // sessions/end is strict: an unknown field, a short id, no id.
        for body in [
            r#"{"session_id":"AAAAAAAAAAAAAAAAAAAAAA","extra":true}"#,
            r#"{"session_id":"AAAA"}"#,
            "{}",
            "",
        ] {
            let reply = call(
                &server,
                "POST",
                paths::SESSIONS_END,
                body.as_bytes().to_vec(),
                Auth::Device(&mut device.session, &device.unlocked),
            )
            .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(reply.error(), "invalid_request", "{body}");
        }
        // A well-formed id that names no session of the account.
        let reply = call(
            &server,
            "POST",
            paths::SESSIONS_END,
            ROUTES[2].1.as_bytes().to_vec(),
            Auth::Device(&mut device.session, &device.unlocked),
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.error(), "not_found");
    });
}

/// A device lists the account's sessions, ends a web session by id, and that token's next
/// request gets the `401` of an unknown token, byte for byte (§6). Sign-out (R2), then a repeat;
/// the others (R4) leave every device session.
#[test]
fn a_device_ends_web_sessions() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(7511);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut device = Client::signed_up(&server, up).await;
        let web = login(&server, &mut rng, &sk, None).await;
        let web_token = copy_token(web.bearer_token());
        let unknown = SessionToken::new(Zeroizing::new([0x42; 32]));

        // The list, from the device: two rows, the device's marked current.
        let rows = list(&server, Auth::Device(&mut device.session, &device.unlocked)).await;
        assert!(!rows.truncated);
        assert_eq!(rows.sessions.len(), 2);
        let mine: Vec<_> = rows.sessions.iter().filter(|s| s.current).collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].kind, SessionKindView::Device);
        let web_id = own_id(&server, &web_token).await;
        let web_row = rows
            .sessions
            .iter()
            .find(|s| s.session_id == web_id)
            .unwrap();
        assert_eq!(web_row.kind, SessionKindView::Opaque);
        assert_eq!(web_row.device_id, None);

        // The device's own session is a device target: refused (§5).
        let refused = post(
            &server,
            paths::SESSIONS_END,
            &EndSessionRequest {
                session_id: mine[0].session_id,
            },
            Auth::Device(&mut device.session, &device.unlocked),
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(refused.error(), "invalid_request");

        // End the web session; its next request answers exactly like an unknown token.
        let ended = post(
            &server,
            paths::SESSIONS_END,
            &EndSessionRequest { session_id: web_id },
            Auth::Device(&mut device.session, &device.unlocked),
        )
        .await;
        assert_eq!(ended.status, StatusCode::NO_CONTENT);
        for &(path, body) in ROUTES {
            let ended = call(
                &server,
                "POST",
                path,
                body.as_bytes().to_vec(),
                Auth::Bearer(&web_token),
            )
            .await;
            let never = call(
                &server,
                "POST",
                path,
                body.as_bytes().to_vec(),
                Auth::Bearer(&unknown),
            )
            .await;
            assert_eq!(ended.status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(answer(&ended), answer(&never), "{path}");
        }
        let state = call(
            &server,
            "POST",
            paths::ACCOUNT_STATE,
            br#"{"known_bundle_seq":0,"known_settings_seq":0}"#.to_vec(),
            Auth::Bearer(&web_token),
        )
        .await;
        assert_eq!(state.status, StatusCode::UNAUTHORIZED);

        // Sign-out of another web session (R2), and its repeat.
        let second = login(&server, &mut rng, &sk, None).await;
        let second_token = copy_token(second.bearer_token());
        let out = empty(
            &server,
            paths::SESSIONS_CURRENT_END,
            Auth::Bearer(&second_token),
        )
        .await;
        assert_eq!(out.status, StatusCode::NO_CONTENT);
        let again = empty(
            &server,
            paths::SESSIONS_CURRENT_END,
            Auth::Bearer(&second_token),
        )
        .await;
        assert_eq!(again.status, StatusCode::UNAUTHORIZED);

        // R4 from a fresh web session: the other web session ends, the device's stays.
        let third = login(&server, &mut rng, &sk, None).await;
        let fourth = login(&server, &mut rng, &sk, None).await;
        let (third_token, fourth_token) = (
            copy_token(third.bearer_token()),
            copy_token(fourth.bearer_token()),
        );
        let others = empty(
            &server,
            paths::SESSIONS_OTHERS_END,
            Auth::Bearer(&third_token),
        )
        .await;
        assert_eq!(others.status, StatusCode::NO_CONTENT);
        let gone = empty(&server, paths::SESSIONS_LIST, Auth::Bearer(&fourth_token)).await;
        assert_eq!(gone.status, StatusCode::UNAUTHORIZED);
        let rows = list(&server, Auth::Bearer(&third_token)).await;
        assert_eq!(rows.sessions.len(), 2);
        assert!(
            rows.sessions
                .iter()
                .any(|s| s.kind == SessionKindView::Device && !s.current)
        );
        // The device still works.
        list(&server, Auth::Device(&mut device.session, &device.unlocked)).await;

        // And a device ends its own session with R2: its next signed request is refused.
        let out = empty(
            &server,
            paths::SESSIONS_CURRENT_END,
            Auth::Device(&mut device.session, &device.unlocked),
        )
        .await;
        assert_eq!(out.status, StatusCode::NO_CONTENT);
        let after = empty(
            &server,
            paths::SESSIONS_LIST,
            Auth::Device(&mut device.session, &device.unlocked),
        )
        .await;
        assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    });
}

/// §7.6 "I": another account's `session_id` answers like an unknown one and ends nothing, and
/// R4 never reaches across accounts.
#[test]
fn another_accounts_session_is_not_found() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(7512);
        let (up_a, sk_a, _) = signup_named(&server, &mut rng, "alice", false).await;
        let (up_b, _, _) = signup_named(&server, &mut rng, "bob", false).await;
        let _a = Client::signed_up(&server, up_a).await;
        let mut b = Client::signed_up(&server, up_b).await;
        let victim = login_named(&server, &mut rng, "alice", &sk_a, None).await;
        let victim_token = copy_token(victim.bearer_token());
        let victim_id = own_id(&server, &victim_token).await;

        let foreign = post(
            &server,
            paths::SESSIONS_END,
            &EndSessionRequest {
                session_id: victim_id,
            },
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        let unknown = post(
            &server,
            paths::SESSIONS_END,
            &EndSessionRequest {
                session_id: Id::from_bytes([0x5a; 16]),
            },
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(foreign.status, StatusCode::NOT_FOUND);
        assert_eq!(answer(&foreign), answer(&unknown));
        let others = empty(
            &server,
            paths::SESSIONS_OTHERS_END,
            Auth::Device(&mut b.session, &b.unlocked),
        )
        .await;
        assert_eq!(others.status, StatusCode::NO_CONTENT);
        // Alice's session lives, and Bob's list holds only Bob's session.
        assert_eq!(own_id(&server, &victim_token).await, victim_id);
        let rows = list(&server, Auth::Device(&mut b.session, &b.unlocked)).await;
        assert_eq!(rows.sessions.len(), 1);
        assert!(rows.sessions.iter().all(|s| s.session_id != victim_id));
    });
}
