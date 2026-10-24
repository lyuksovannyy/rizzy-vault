// SPDX-License-Identifier: AGPL-3.0-only

//! The admin listener's boundary ([ADR 0060] §1, §2; threat model §7.19, INV-69).
//!
//! The admin router is a separate `Router`, never merged into the public one: an `/admin/...`
//! path on the public listener is that listener's plain `404`, and the public API does not
//! exist on the admin listener, so a vault session (an OPAQUE web session's bearer token, or a
//! device session's signed request) reaches nothing there. Every answer of the admin listener
//! carries ADR 0060 §1's `ADMIN_CSP` and the common headers. No screen is served yet: ADR 0060's
//! owner answer 5 holds every screen until the admin-login ADR is Accepted.
//!
//! [ADR 0060]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0060-admin-panel-stack-boundary.md

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_domain_auth::types::{META_PATH, paths};
use rizzy_server::config;
use rizzy_server::http::admin_panel;
use rizzy_server::http::security::{ADMIN_CSP, API_CSP, HSTS, WEB_CSP};

use crate::common::{Reply, Server, block_on, send_via};
use crate::rotation::{Auth, Client, copy_token, login, request, signup};

/// Paths a caller might try on either listener.
const PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/admin",
    "/admin/",
    "/admin/users",
    "/admin/login",
    "/admin/signup",
    "/admin/smtp",
    "/metrics",
    META_PATH,
    paths::SESSIONS_LIST,
    paths::ACCOUNT_STATE,
    "/api/v1/admin/users",
];

/// The headers every response carries.
fn assert_common(reply: &Reply) {
    assert_eq!(reply.header("strict-transport-security"), Some(HSTS));
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
}

/// The admin listener's one answer at M3: a plain-text `404` under the admin CSP, carrying no
/// cookie and nothing of the public API's error body.
fn assert_admin_not_found(reply: &Reply, what: &str) {
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{what}");
    assert_eq!(
        reply.header("content-security-policy"),
        Some(ADMIN_CSP),
        "{what}"
    );
    assert_common(reply);
    assert!(reply.header("set-cookie").is_none(), "{what}");
    assert!(
        reply.header("access-control-allow-origin").is_none(),
        "{what}"
    );
    assert_eq!(reply.body, b"not found\n", "{what}");
}

/// Sends `method path` to the admin router.
async fn admin(method: Method, path: &str) -> Reply {
    send_via(
        admin_panel::router(),
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

#[test]
fn the_admin_listener_answers_every_path_with_a_plain_404_under_its_csp() {
    block_on(async {
        for &path in PATHS {
            for method in [
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ] {
                let reply = admin(method.clone(), path).await;
                if method == Method::HEAD {
                    assert_eq!(reply.status, StatusCode::NOT_FOUND, "HEAD {path}");
                    assert_eq!(reply.header("content-security-policy"), Some(ADMIN_CSP));
                    assert_common(&reply);
                } else {
                    assert_admin_not_found(&reply, &format!("{method} {path}"));
                }
            }
        }
    });
}

/// A vault session is never an admin credential: the bearer token of a web (OPAQUE) session and
/// a device session's signed request both answer on the public listener and reach nothing on the
/// admin one.
#[test]
fn a_vault_session_reaches_nothing_on_the_admin_listener() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(6001);
        let (up, sk, _) = signup(&server, &mut rng, false).await;
        let mut device = Client::signed_up(&server, up).await;
        let web = login(&server, &mut rng, &sk, None).await;
        let token = copy_token(web.bearer_token());

        // On the public listener the session works.
        let public = server
            .send(request(
                "POST",
                paths::SESSIONS_LIST,
                Vec::new(),
                Auth::Bearer(&token),
            ))
            .await;
        assert_eq!(public.status, StatusCode::OK, "{}", public.error());

        for &path in PATHS {
            let bearer = send_via(
                admin_panel::router(),
                request("POST", path, Vec::new(), Auth::Bearer(&token)),
            )
            .await;
            assert_admin_not_found(&bearer, &format!("bearer {path}"));
            let signed = send_via(
                admin_panel::router(),
                request(
                    "POST",
                    path,
                    Vec::new(),
                    Auth::Device(&mut device.session, &device.unlocked),
                ),
            )
            .await;
            assert_admin_not_found(&signed, &format!("device {path}"));
            let cookie = send_via(
                admin_panel::router(),
                Request::get(path)
                    .header("cookie", format!("session={}", token.to_b64url().as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_admin_not_found(&cookie, &format!("cookie {path}"));
        }

        // The session is still live on the public listener: the admin listener consumed nothing.
        let again = server
            .send(request(
                "POST",
                paths::SESSIONS_LIST,
                Vec::new(),
                Auth::Bearer(&token),
            ))
            .await;
        assert_eq!(again.status, StatusCode::OK, "{}", again.error());
    });
}

/// The public listener never reaches the admin router: `/admin/...` is the web role's `404`
/// under the web CSP, or a plain `404` when no `web` role runs; never the admin CSP.
#[test]
fn admin_paths_on_the_public_listener_are_a_plain_404() {
    block_on(async {
        let admin_paths = PATHS.iter().filter(|p| p.starts_with("/admin"));
        let with_web = Server::start().await;
        for &path in admin_paths.clone() {
            for method in [Method::GET, Method::POST] {
                let reply = with_web
                    .send(
                        Request::builder()
                            .method(method.clone())
                            .uri(path)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await;
                assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
                assert_eq!(
                    reply.header("content-security-policy"),
                    Some(WEB_CSP),
                    "{path}"
                );
                assert_common(&reply);
            }
        }

        let api_only = Server::start_with(&[(config::ROLES, "api,worker")]).await;
        for &path in admin_paths {
            let reply = api_only.get(path).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(
                reply.header("content-security-policy"),
                Some(API_CSP),
                "{path}"
            );
            assert_eq!(reply.body, b"not found\n", "{path}");
            assert_common(&reply);
        }
    });
}
