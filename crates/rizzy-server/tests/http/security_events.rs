// SPDX-License-Identifier: AGPL-3.0-only

//! `security-events/list` over HTTP ([ADR 0090] §7, §14 step 4): the method and session gating,
//! the strict body and its limits, the caller's own rows only (IDOR), and the wire shape (no
//! admin id, no address). Paging, the caps, retention, the recovery-only refusal and every
//! kind's row run in `rizzy-domain-auth`'s `tests/auth/events.rs`.
//!
//! [ADR 0090]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0090-per-account-security-event-log.md

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::rizzy_proto::security_event::{
    SecurityEventActorKind, SecurityEventClass, SecurityEventKind, SecurityEventListResponse,
};
use rizzy_domain_auth::types::paths;

use crate::common::{Server, block_on, config_in};
use crate::rotation::{Auth, call, copy_token, login, login_named, signup, signup_named};

/// ADR 0090 §13 (INV-69's configuration path): a restart with another
/// `RIZZY_RECOVERY_WAIT_HOURS` logs old -> new to every account before anything is served, a
/// shorter wait as an alert; an unchanged restart logs nothing.
#[test]
fn a_changed_wait_setting_is_logged_at_start() {
    block_on(async {
        let dir = crate::common::TempDir::new();
        let config = config_in(&dir, &[]);
        let secrets =
            rizzy_domain_auth::ServerSecrets::generate(&mut ChaCha20Rng::seed_from_u64(9));
        std::fs::write(
            &config.secrets_file,
            rizzy_server::secrets_file::serialize(&secrets).unwrap(),
        )
        .unwrap();
        let server = Server::open(dir, &config, |_| {}).await;
        let mut rng = ChaCha20Rng::seed_from_u64(9091);
        let (_, sk, _) = signup(&server, &mut rng, false).await;
        let dir = server.stop().await;
        // Unchanged: nothing new.
        let server = Server::open(dir, &config, |_| {}).await;
        let dir = server.stop().await;
        let shorter = config_in(&dir, &[(rizzy_server::config::RECOVERY_WAIT_HOURS, "1")]);
        let server = Server::open(dir, &shorter, |_| {}).await;
        let web = login(&server, &mut rng, &sk, None).await;
        let token = copy_token(web.bearer_token());
        let reply = call(
            &server,
            "POST",
            paths::SECURITY_EVENTS_LIST,
            b"{}".to_vec(),
            Auth::Bearer(&token),
        )
        .await;
        let list: SecurityEventListResponse = reply.json();
        let kinds: Vec<SecurityEventKind> = list.events.as_slice().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                SecurityEventKind::PasswordLogin,
                SecurityEventKind::RecoveryWaitChanged,
                SecurityEventKind::AccountCreated
            ]
        );
        let changed = &list.events.as_slice()[1];
        assert_eq!(changed.class, SecurityEventClass::Alert);
        assert_eq!(changed.actor.kind, SecurityEventActorKind::Server);
        assert_eq!(changed.value_old, Some(72 * 3_600_000));
        assert_eq!(changed.value_new, Some(3_600_000));
    });
}

#[test]
fn security_events_are_gated_strict_and_the_callers_own() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(9090);
        let path = paths::SECURITY_EVENTS_LIST;
        let (_, sk, _) = signup(&server, &mut rng, false).await;
        let web = login(&server, &mut rng, &sk, None).await;
        let token = copy_token(web.bearer_token());

        let get = server
            .send(Request::get(path).body(Body::empty()).unwrap())
            .await;
        assert_eq!(get.status, StatusCode::METHOD_NOT_ALLOWED);
        let none = call(&server, "POST", path, b"{}".to_vec(), Auth::None).await;
        assert_eq!(none.status, StatusCode::UNAUTHORIZED);
        for bad in [
            &br#"{"limit":0}"#[..],
            br#"{"limit":101}"#,
            br#"{"account_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
            b"not json",
        ] {
            let reply = call(&server, "POST", path, bad.to_vec(), Auth::Bearer(&token)).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            assert_eq!(reply.error(), "invalid_request");
        }

        // The signup and the login, newest first.
        let reply = call(&server, "POST", path, b"{}".to_vec(), Auth::Bearer(&token)).await;
        assert_eq!(reply.status, StatusCode::OK);
        let text = String::from_utf8(reply.body.clone()).unwrap();
        assert!(!text.contains("admin"), "{text}");
        let list: SecurityEventListResponse = reply.json();
        let kinds: Vec<SecurityEventKind> = list.events.as_slice().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                SecurityEventKind::PasswordLogin,
                SecurityEventKind::AccountCreated
            ]
        );
        assert!(!list.more);
        let created = &list.events.as_slice()[1];
        assert_eq!(created.class, SecurityEventClass::Info);
        assert_eq!(created.actor.kind, SecurityEventActorKind::SignIn);
        assert_eq!(created.value_new, Some(72 * 3_600_000));
        // A page of one says there is more.
        let reply = call(
            &server,
            "POST",
            path,
            br#"{"limit":1}"#.to_vec(),
            Auth::Bearer(&token),
        )
        .await;
        let one: SecurityEventListResponse = reply.json();
        assert_eq!(one.events.as_slice().len(), 1);
        assert!(one.more);

        // Another account sees only its own two rows.
        let (_, other_sk, _) = signup_named(&server, &mut rng, "other", false).await;
        let theirs = login_named(&server, &mut rng, "other", &other_sk, None).await;
        let theirs = copy_token(theirs.bearer_token());
        let reply = call(&server, "POST", path, b"{}".to_vec(), Auth::Bearer(&theirs)).await;
        let list: SecurityEventListResponse = reply.json();
        assert_eq!(list.events.as_slice().len(), 2);
        assert!(list.events.as_slice().iter().all(|e| {
            !one.events
                .as_slice()
                .iter()
                .any(|o| o.event_id == e.event_id)
        }));
    });
}
