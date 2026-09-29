//! Security headers and CSP (threat model INV-49, §7.7), body limits (§7.6 "D"), and the
//! uniform error answers (ADR 0002 point 3).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rizzy_domain_auth::types::MetaResponse;
use rizzy_server::http::api::BODY_LIMIT;
use rizzy_server::http::security::{API_CSP, HSTS, WEB_CSP};

use crate::common::{Reply, Server, block_on};

/// The headers every response carries.
fn assert_common(reply: &Reply) {
    assert_eq!(reply.header("strict-transport-security"), Some(HSTS));
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
}

#[test]
fn web_role_serves_the_placeholder_under_its_csp() {
    block_on(async {
        let server = Server::start().await;
        let page = server.get("/").await;
        assert_eq!(page.status, StatusCode::OK);
        assert_common(&page);
        assert_eq!(page.header("content-security-policy"), Some(WEB_CSP));
        assert!(
            page.header("content-type")
                .unwrap()
                .starts_with("text/html")
        );
        let text = String::from_utf8(page.body.clone()).unwrap();
        assert!(text.contains("no web vault"));
        assert!(!text.contains("<script") && !text.contains("style"));

        let missing = server.get("/../../etc/passwd").await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        assert_eq!(missing.header("content-security-policy"), Some(WEB_CSP));
        assert_common(&missing);

        let post = server
            .send(Request::post("/").body(Body::empty()).unwrap())
            .await;
        assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
    });
}

#[test]
fn api_answers_carry_the_strict_csp_and_no_store() {
    block_on(async {
        let server = Server::start().await;
        let meta = server.get("/api/meta").await;
        assert_eq!(meta.status, StatusCode::OK);
        assert_common(&meta);
        assert_eq!(meta.header("content-security-policy"), Some(API_CSP));
        assert_eq!(meta.header("cache-control"), Some("no-store"));
        let meta: MetaResponse = meta.json();
        assert_eq!(meta.api_versions.as_slice()[0].as_str(), "v1");
        assert_eq!(meta.server_version.as_str(), env!("CARGO_PKG_VERSION"));

        let unknown = server.get("/api/v1/nothing-here").await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
        assert_eq!(unknown.error(), "not_found");
        assert_common(&unknown);
        assert_eq!(unknown.header("content-security-policy"), Some(API_CSP));

        let wrong_method = server.get("/api/v1/login/start").await;
        assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(wrong_method.error(), "invalid_request");
        assert_common(&wrong_method);
    });
}

#[test]
fn oversized_bodies_are_refused_before_parsing() {
    block_on(async {
        let server = Server::start().await;
        let big = vec![b' '; BODY_LIMIT + 1];
        // With a Content-Length above the limit.
        let request = Request::post("/api/v1/login/start")
            .header("content-length", big.len().to_string())
            .body(Body::from(big.clone()))
            .unwrap();
        let reply = server.send(request).await;
        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(reply.error(), "payload_too_large");
        assert_common(&reply);
        // Without a Content-Length: read up to the limit and refused past it.
        let stream = Body::from(big);
        let request = Request::post("/api/v1/register/start")
            .body(stream)
            .unwrap();
        let reply = server.send(request).await;
        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
        // Exactly at the limit, the body is read and then refused as JSON.
        let at_limit = vec![b' '; BODY_LIMIT];
        let reply = server.post_raw("/api/v1/login/start", at_limit, None).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.error(), "invalid_request");
    });
}

#[test]
fn malformed_and_unknown_fields_answer_invalid_request() {
    block_on(async {
        let server = Server::start().await;
        for body in [
            &b"{"[..],
            b"{\"login_name\":\"a\",\"ke1\":\"AA\",\"extra\":1}",
            b"{\"login_name\":\"\\u0000\",\"ke1\":\"AA\"}",
            b"[]",
        ] {
            let reply = server
                .post_raw("/api/v1/login/start", body.to_vec(), None)
                .await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST);
            // The answer never echoes the input.
            assert_eq!(reply.body, br#"{"error":"invalid_request"}"#);
        }
    });
}

#[test]
fn a_router_without_web_answers_404_outside_the_api() {
    block_on(async {
        let server = Server::start_with(&[(rizzy_server::config::ROLES, "api,worker")]).await;
        let reply = server.get("/").await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_common(&reply);
        assert_eq!(server.get("/api/meta").await.status, StatusCode::OK);
    });
}
