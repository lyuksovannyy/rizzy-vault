//! The account endpoints of password and Secret Key change, settings, self-revocation,
//! suspension, recovery and TOTP (CRYPTO.md §11 "Replacing credentials", §11.5, §11.8 step 0,
//! §11.9, §11.15): routing, session gating before the body, strict bodies, and the recovery
//! flow's enumeration-safe refusals and rate limit.
//!
//! What these tests cannot reach: every happy path past a session needs a signed-up account,
//! which needs `rizzy-core`'s client-side OPAQUE and signing, and ADR 0016 §3 keeps
//! `rizzy-core` out of this crate's tests ([`crate::common`] module docs). The domain half of
//! each happy path, from the same `rizzy-proto` request types these endpoints parse, runs in
//! `rizzy-domain-auth`'s `tests/auth/requests.rs`. Key rotation and revocation run end to end,
//! with `rizzy-client`, in [`crate::rotation`].

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rizzy_domain_auth::types::SessionToken;
use zeroize::Zeroizing;

use crate::common::{Server, block_on};

/// The endpoints that need a session, with a body each would accept.
const WITH_SESSION: &[(&str, &str)] = &[
    (
        "/api/v1/account/reregister/start",
        r#"{"registration_request":"Zm9v"}"#,
    ),
    (
        "/api/v1/account/commit",
        r#"{"account_state":"Zm9v","device_certificates":[],"device_revocations":[]}"#,
    ),
    (
        "/api/v1/devices/suspend",
        r#"{"device_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ),
    (
        "/api/v1/devices/unsuspend",
        r#"{"device_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    ),
    ("/api/v1/recovery/cancel", ""),
    ("/api/v1/totp/enrol/start", ""),
    (
        "/api/v1/totp/enrol/confirm",
        r#"{"totp_credential_seq":1,"code":"123456"}"#,
    ),
    ("/api/v1/totp/disable", r#"{"code":"123456"}"#),
];

/// A well-formed recovery body for `name`, with a token of 32 `byte`s.
fn recovery_body(name: &str, byte: char) -> Vec<u8> {
    let token: String = core::iter::repeat_n(byte, 43).collect();
    format!(r#"{{"login_name":"{name}","recovery_auth_token":"{token}"}}"#).into_bytes()
}

#[test]
fn account_endpoints_refuse_without_a_valid_session() {
    block_on(async {
        let server = Server::start().await;
        let unknown = SessionToken::new(Zeroizing::new([7; 32]));
        for (path, body) in WITH_SESSION {
            // No `Authorization`, an unknown token, a malformed header: one answer, 401.
            let reply = server.post_raw(path, body.as_bytes().to_vec(), None).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(reply.body, br#"{"error":"unauthorized"}"#, "{path}");
            let reply = server
                .post_raw(path, body.as_bytes().to_vec(), Some(&unknown))
                .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
            let malformed = Request::post(*path)
                .header("authorization", "Bearer not-a-token")
                .body(Body::from(body.as_bytes().to_vec()))
                .unwrap();
            assert_eq!(
                server.send(malformed).await.status,
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
            // A signed request over an unknown token, and a half-signed one.
            let signed = Request::post(*path)
                .header(
                    "authorization",
                    format!("Bearer {}", unknown.to_b64url().as_str()),
                )
                .header("rizzy-request-counter", "1")
                .header("rizzy-request-signature", "A".repeat(110))
                .body(Body::from(body.as_bytes().to_vec()))
                .unwrap();
            assert_eq!(
                server.send(signed).await.status,
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
            let half = Request::post(*path)
                .header(
                    "authorization",
                    format!("Bearer {}", unknown.to_b64url().as_str()),
                )
                .header("rizzy-request-counter", "1")
                .body(Body::from(body.as_bytes().to_vec()))
                .unwrap();
            assert_eq!(
                server.send(half).await.status,
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
            // The session is checked before the body: an oversized body without a session is
            // still 401, not 413.
            let big = Request::post(*path)
                .header("content-length", "100000000")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                server.send(big).await.status,
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
        }
    });
}

#[test]
fn account_endpoints_are_post_only() {
    block_on(async {
        let server = Server::start().await;
        let paths = WITH_SESSION
            .iter()
            .map(|(path, _)| *path)
            .chain(["/api/v1/recovery/start", "/api/v1/recovery/complete"]);
        for path in paths {
            let reply = server.get(path).await;
            assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
            assert_eq!(reply.error(), "invalid_request", "{path}");
        }
    });
}

#[test]
fn recovery_answers_unknown_names_like_wrong_codes() {
    block_on(async {
        let server = Server::start().await;
        for path in ["/api/v1/recovery/start", "/api/v1/recovery/complete"] {
            // An unknown name with a well-formed token: the answer of a wrong code (CRYPTO.md
            // §5.9), with nothing else in it.
            let reply = server
                .post_raw(path, recovery_body("nobody", 'A'), None)
                .await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(reply.body, br#"{"error":"unauthorized"}"#, "{path}");
            // Malformed bodies: a short token, a long token, a name outside §2, an unknown
            // field, a missing field. The answer never echoes the input.
            let short = r#"{"login_name":"nobody","recovery_auth_token":"AAAA"}"#;
            let long = format!(
                r#"{{"login_name":"nobody","recovery_auth_token":"{}"}}"#,
                "A".repeat(44)
            );
            let extra = format!(
                r#"{{"login_name":"nobody","recovery_auth_token":"{}","recovery_code":"x"}}"#,
                "A".repeat(43)
            );
            for body in [
                short.as_bytes().to_vec(),
                long.into_bytes(),
                recovery_body("no body", 'A'),
                extra.into_bytes(),
                br#"{"login_name":"nobody"}"#.to_vec(),
            ] {
                let reply = server.post_raw(path, body, None).await;
                assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
                assert_eq!(reply.body, br#"{"error":"invalid_request"}"#, "{path}");
            }
        }
    });
}

#[test]
fn recovery_attempts_are_rate_limited_per_name() {
    block_on(async {
        let server = Server::start().await;
        let mut statuses = Vec::new();
        for i in 0..8 {
            let byte = if i % 2 == 0 { 'A' } else { 'Q' };
            let reply = server
                .post_raw(
                    "/api/v1/recovery/start",
                    recovery_body("target", byte),
                    None,
                )
                .await;
            statuses.push(reply.status);
        }
        // The first attempts are refused as wrong codes, then the bucket answers 429.
        assert_eq!(statuses[0], StatusCode::UNAUTHORIZED);
        assert_eq!(statuses[7], StatusCode::TOO_MANY_REQUESTS);
        let reply = server
            .post_raw(
                "/api/v1/recovery/complete",
                recovery_body("target", 'A'),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(reply.error(), "rate_limited");
        // Another name is not affected.
        let reply = server
            .post_raw("/api/v1/recovery/start", recovery_body("other", 'A'), None)
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    });
}
