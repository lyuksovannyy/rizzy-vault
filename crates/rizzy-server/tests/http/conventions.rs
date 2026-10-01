//! The `/api/v1` HTTP conventions of [ADR 0028], pinned through the router: the error table
//! and `Retry-After` (item 3), the credential header forms and the one `401` (items 4, 5), the
//! `Content-Length` rule (item 7), the response headers (item 10), the trusted-proxy rule (item
//! 11), `GET /api/meta` and `Rizzy-Client` (item 14), and the web role's paths (item 15).
//!
//! The signed request-target and the replay window are in [`crate::signing`].
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use std::net::{IpAddr, Ipv4Addr};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rizzy_domain_auth::types::{MinClientVersion, Platform, SessionToken, Version};
use rizzy_server::config::TRUSTED_PROXIES;
use rizzy_server::http::api::Endpoint;
use zeroize::Zeroizing;

use crate::common::{Reply, Server, block_on};

/// A well-formed recovery body for `name`.
fn recovery_body(name: &str) -> Vec<u8> {
    let token = "A".repeat(43);
    format!(r#"{{"login_name":"{name}","recovery_auth_token":"{token}"}}"#).into_bytes()
}

/// `POST /api/v1/recovery/start` for `name`, with extra headers.
fn recovery_start(name: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut request = Request::post("/api/v1/recovery/start");
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    request.body(Body::from(recovery_body(name))).unwrap()
}

/// Asserts the uniform error answer: the status, exactly `{"error":"<code>"}`, JSON,
/// `no-store`, and nothing that says more.
fn assert_error(reply: &Reply, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status);
    assert_eq!(
        String::from_utf8_lossy(&reply.body),
        format!(r#"{{"error":"{code}"}}"#)
    );
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert!(reply.header("www-authenticate").is_none());
    assert_eq!(
        reply.header("retry-after").is_some(),
        code == "rate_limited"
    );
}

/// Item 3: a `429` carries `Retry-After` in whole seconds, from the bucket's backoff.
#[test]
fn a_rate_limited_answer_carries_retry_after() {
    block_on(async {
        let server = Server::start().await;
        let mut limited = None;
        for _ in 0..12 {
            let reply = server.send(recovery_start("target", &[])).await;
            if reply.status == StatusCode::TOO_MANY_REQUESTS {
                limited = Some(reply);
                break;
            }
            assert_error(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
        }
        // Twelve attempts are far past the five the (name, source) bucket lets through.
        let limited = limited.unwrap();
        assert_error(&limited, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        // Whole seconds in decimal, nothing else. The first backoff is one second, of which a
        // part is left, rounded up; on a slow machine a later, longer backoff may be the one
        // that refuses, and none is longer than 15 minutes.
        let value = limited.header("retry-after").unwrap();
        let seconds: u64 = value.parse().unwrap();
        assert_eq!(value, seconds.to_string());
        assert!((1..=900).contains(&seconds), "{seconds}");
    });
}

/// Item 3: the uniform body on every error class the router and the header checks produce.
#[test]
fn errors_are_one_body_shape() {
    block_on(async {
        let server = Server::start().await;
        // An unknown path under /api/, of any version, and `/api` itself.
        for path in ["/api/v1/nope", "/api/v2/login/start", "/api", "/api/"] {
            assert_error(&server.get(path).await, StatusCode::NOT_FOUND, "not_found");
        }
        // A method the route does not serve: every endpoint, and /api/meta.
        for endpoint in Endpoint::ALL {
            let reply = server
                .send(Request::put(endpoint.path()).body(Body::empty()).unwrap())
                .await;
            assert_error(&reply, StatusCode::METHOD_NOT_ALLOWED, "invalid_request");
        }
        let reply = server
            .send(Request::post("/api/meta").body(Body::empty()).unwrap())
            .await;
        assert_error(&reply, StatusCode::METHOD_NOT_ALLOWED, "invalid_request");
        // Only `devices/grants` is GET (and HEAD); it needs a session.
        let reply = server.get("/api/v1/devices/grants").await;
        assert_error(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
        let head = server
            .send(
                Request::head("/api/v1/devices/grants")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(head.status, StatusCode::UNAUTHORIZED);
        let post = server
            .post_raw("/api/v1/devices/grants", Vec::new(), None)
            .await;
        assert_error(&post, StatusCode::METHOD_NOT_ALLOWED, "invalid_request");
    });
}

/// Items 1 and 5: the router matches the literal paths byte for byte. A trailing slash, `//`, a
/// dot segment, a percent-encoded octet or another case is `404` before any session check.
#[test]
fn paths_are_matched_byte_for_byte() {
    block_on(async {
        let server = Server::start().await;
        for path in [
            "/api/v1/login/start/",
            "/api/v1//login/start",
            "/api/v1/login/./start",
            "/api/v1/login/../login/start",
            "/api/v1/login/%73tart",
            "/api/v1/login/START",
            "/api/V1/login/start",
            "/api/v1/login/start;x=1",
        ] {
            let reply = server
                .post_raw(path, br#"{"login_name":"a","ke1":"AA"}"#.to_vec(), None)
                .await;
            assert_error(&reply, StatusCode::NOT_FOUND, "not_found");
        }
        // The query is no part of the match: the route is found, and the body is judged.
        for path in ["/api/v1/login/start?", "/api/v1/login/start?x=%2F&x=1"] {
            let reply = server.post_raw(path, b"{".to_vec(), None).await;
            assert_error(&reply, StatusCode::BAD_REQUEST, "invalid_request");
        }
        // Outside /api/ the same targets are the web role's plain 404.
        let outside = server.get("//api/v1/login/start").await;
        assert_eq!(outside.status, StatusCode::NOT_FOUND);
    });
}

/// Items 4 and 5 "One answer": every unusable credential is the same `401`, decided from the
/// headers, before the body.
#[test]
fn every_bad_credential_is_the_same_401() {
    block_on(async {
        let server = Server::start().await;
        let unknown = SessionToken::new(Zeroizing::new([9; 32]));
        let bearer = format!("Bearer {}", unknown.to_b64url().as_str());
        let signature = "A".repeat(110);
        let cases: Vec<Vec<(&str, String)>> = vec![
            // No credential at all.
            vec![],
            // Another scheme, a short token, a padded one, a trailing space, a cookie.
            vec![("authorization", format!("Basic {}", "A".repeat(43)))],
            vec![("authorization", format!("Bearer {}", "A".repeat(42)))],
            vec![("authorization", format!("Bearer {}=", "A".repeat(43)))],
            vec![("authorization", format!("{bearer} "))],
            vec![("cookie", format!("session={}", "A".repeat(43)))],
            // An unknown token, in either scheme case.
            vec![("authorization", bearer.clone())],
            vec![("authorization", bearer.replace("Bearer", "bearer"))],
            // Two Authorization field lines.
            vec![
                ("authorization", bearer.clone()),
                ("authorization", bearer.clone()),
            ],
            // Signing headers: one without the other, malformed counters, a malformed
            // signature, a repeated header.
            vec![
                ("authorization", bearer.clone()),
                ("rizzy-request-counter", "1".to_owned()),
            ],
            vec![
                ("authorization", bearer.clone()),
                ("rizzy-request-signature", signature.clone()),
            ],
            vec![
                ("authorization", bearer.clone()),
                ("rizzy-request-counter", "01".to_owned()),
                ("rizzy-request-signature", signature.clone()),
            ],
            vec![
                ("authorization", bearer.clone()),
                ("rizzy-request-counter", "+1".to_owned()),
                ("rizzy-request-signature", signature.clone()),
            ],
            vec![
                ("authorization", bearer.clone()),
                ("rizzy-request-counter", "18446744073709551616".to_owned()),
                ("rizzy-request-signature", signature.clone()),
            ],
            vec![
                ("authorization", bearer.clone()),
                ("rizzy-request-counter", "1".to_owned()),
                ("rizzy-request-signature", "A".repeat(109)),
            ],
            vec![
                ("authorization", bearer.clone()),
                ("rizzy-request-counter", "1".to_owned()),
                ("rizzy-request-counter", "2".to_owned()),
                ("rizzy-request-signature", signature.clone()),
            ],
            // Well-formed and signed, over an unknown token; the header names in any case.
            vec![
                ("Authorization", bearer.clone()),
                ("Rizzy-Request-Counter", "0".to_owned()),
                ("Rizzy-Request-Signature", signature.clone()),
            ],
        ];
        for headers in &cases {
            for path in ["/api/v1/account/state", "/api/v1/vault/upload"] {
                // A body far over any limit, never sent in full: the answer comes first.
                let mut request = Request::post(path).header("content-length", "999999999999");
                for (k, v) in headers {
                    request = request.header(*k, v.as_str());
                }
                let reply = server.send(request.body(Body::empty()).unwrap()).await;
                assert_error(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
            }
        }
        // The token is never read from the URL.
        let in_query = format!(
            "/api/v1/account/state?access_token={}",
            unknown.to_b64url().as_str()
        );
        let reply = server.post_raw(&in_query, b"{}".to_vec(), None).await;
        assert_error(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
    });
}

/// Item 7: a `Content-Length` that is not a decimal `u64` is `400`; one above the limit is
/// `413` before a body byte is read.
#[test]
fn content_length_is_decimal_or_refused() {
    block_on(async {
        let server = Server::start().await;
        for bad in ["+5", "-1", "5 ", "0x10", "1e3", "18446744073709551616", ""] {
            let request = Request::post("/api/v1/login/start")
                .header("content-length", bad)
                .body(Body::from("12345"))
                .unwrap();
            let reply = server.send(request).await;
            assert_error(&reply, StatusCode::BAD_REQUEST, "invalid_request");
        }
        // Two field lines are never reconciled.
        let request = Request::post("/api/v1/login/start")
            .header("content-length", "2")
            .header("content-length", "2")
            .body(Body::from("{}"))
            .unwrap();
        assert_error(
            &server.send(request).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
        // Above the limit, and the largest `u64`: refused without reading.
        for over in ["1048577", "18446744073709551615"] {
            let request = Request::post("/api/v1/login/start")
                .header("content-length", over)
                .body(Body::empty())
                .unwrap();
            let reply = server.send(request).await;
            assert_error(&reply, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
        }
        // The body-less endpoints take no byte: `recovery/complete` keeps the 1 MiB limit
        // although its answer is large, and needs no session for it.
        let request = Request::post("/api/v1/recovery/complete")
            .header("content-length", "1048577")
            .body(Body::empty())
            .unwrap();
        assert_error(
            &server.send(request).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
        );
    });
}

/// Item 10: no CORS header, no compression, and `no-store` on every API answer.
#[test]
fn no_cors_and_no_compression() {
    block_on(async {
        let server = Server::start().await;
        let request = Request::get("/api/meta")
            .header("origin", "https://evil.example")
            .header("accept-encoding", "gzip, br, zstd")
            .body(Body::empty())
            .unwrap();
        let reply = server.send(request).await;
        assert_eq!(reply.status, StatusCode::OK);
        for absent in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "content-encoding",
            "set-cookie",
        ] {
            assert!(reply.header(absent).is_none(), "{absent}");
        }
        assert_eq!(reply.header("cache-control"), Some("no-store"));
        // A preflight gets no permission either.
        let preflight = Request::options("/api/v1/login/start")
            .header("origin", "https://evil.example")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap();
        let reply = server.send(preflight).await;
        assert_error(&reply, StatusCode::METHOD_NOT_ALLOWED, "invalid_request");
        assert!(reply.header("access-control-allow-origin").is_none());
    });
}

/// The trusted proxy of the item 11 tests.
const PROXY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

/// Item 11, amended: a request from a configured proxy whose `X-Forwarded-For` gives no client
/// address is `400`, on every `/api/v1` endpoint; it is never counted against the proxy.
#[test]
fn a_trusted_proxy_without_a_client_address_is_refused() {
    block_on(async {
        let server = Server::start_with(&[(TRUSTED_PROXIES, "10.0.0.2")]).await;
        // Missing, empty, malformed, or naming only the proxy itself.
        for forwarded in [
            None,
            Some(""),
            Some("unknown"),
            Some("198.51.100.7:4711"),
            Some("10.0.0.2"),
        ] {
            let headers: Vec<(&str, &str)> = forwarded
                .map(|v| ("x-forwarded-for", v))
                .into_iter()
                .collect();
            // Five of each: 25 requests, more than the 20 the per-name bucket lets through.
            for _ in 0..5 {
                let reply = server
                    .send_from(PROXY, recovery_start("target", &headers))
                    .await;
                assert_error(&reply, StatusCode::BAD_REQUEST, "invalid_request");
            }
        }
        // Every endpoint, before its session check: a session endpoint answers 400, not 401.
        for endpoint in Endpoint::ALL {
            let method = if *endpoint == Endpoint::DeviceGrants {
                "GET"
            } else {
                "POST"
            };
            let request = Request::builder()
                .method(method)
                .uri(endpoint.path())
                .body(Body::empty())
                .unwrap();
            let reply = server.send_from(PROXY, request).await;
            assert_error(&reply, StatusCode::BAD_REQUEST, "invalid_request");
        }
        // `GET /api/meta` and the web page count against no bucket and are served.
        let meta = Request::get("/api/meta").body(Body::empty()).unwrap();
        assert_eq!(server.send_from(PROXY, meta).await.status, StatusCode::OK);
        let page = Request::get("/").body(Body::empty()).unwrap();
        assert_eq!(server.send_from(PROXY, page).await.status, StatusCode::OK);
        // None of those refusals was counted: the first real attempt is judged, not limited.
        let reply = server
            .send_from(
                PROXY,
                recovery_start("target", &[("x-forwarded-for", "198.51.100.7")]),
            )
            .await;
        assert_error(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
    });
}

/// Item 11: behind the proxy, each client address has its own bucket, read from the right of
/// `X-Forwarded-For`; a peer that is not the proxy cannot name a source.
#[test]
fn the_rate_limit_source_is_the_forwarded_client() {
    block_on(async {
        let server = Server::start_with(&[(TRUSTED_PROXIES, "10.0.0.2")]).await;
        // One client exhausts its (name, source) bucket. What it wrote left of the address
        // the proxy appended changes nothing.
        let mut limited = false;
        for i in 0..12 {
            let forwarded = format!("203.0.113.{i}, 198.51.100.7");
            let reply = server
                .send_from(
                    PROXY,
                    recovery_start("victim", &[("x-forwarded-for", &forwarded)]),
                )
                .await;
            if reply.status == StatusCode::TOO_MANY_REQUESTS {
                limited = true;
                break;
            }
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }
        assert!(limited, "the client's own bucket fills");
        // Another client behind the same proxy has a bucket of its own for that name.
        let neighbour = server
            .send_from(
                PROXY,
                recovery_start("victim", &[("x-forwarded-for", "198.51.100.8")]),
            )
            .await;
        assert_error(&neighbour, StatusCode::UNAUTHORIZED, "unauthorized");
        // A peer that is not the proxy is counted by its own address, whatever it claims:
        // naming the limited client's address does not put it in that client's bucket.
        let direct = server
            .send(recovery_start(
                "victim",
                &[("x-forwarded-for", "198.51.100.7")],
            ))
            .await;
        assert_error(&direct, StatusCode::UNAUTHORIZED, "unauthorized");
    });
}

/// A minimum for `platform`.
fn minimum(platform: &str, version: &str) -> MinClientVersion {
    MinClientVersion {
        platform: Platform::from_str(platform).unwrap(),
        version: Version::from_str(version).unwrap(),
    }
}

/// Item 14: `GET /api/meta` lists the minimums, and a `Rizzy-Client` below its platform's
/// minimum is `400 client_too_old` on every `/api/v1` endpoint; a missing or malformed header
/// is served normally.
#[test]
fn rizzy_client_below_the_minimum_is_refused() {
    block_on(async {
        let server = Server::start_adjusted(&[], |api| {
            api.min_client_versions = vec![minimum("cli", "0.3.0"), minimum("ios", "2.0.0")];
        })
        .await;
        let meta = server.get("/api/meta").await;
        assert_eq!(meta.status, StatusCode::OK);
        let expected = format!(
            r#"{{"server_version":"{}","api_versions":["v1"],"min_client_versions":[{{"platform":"cli","version":"0.3.0"}},{{"platform":"ios","version":"2.0.0"}}]}}"#,
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(String::from_utf8_lossy(&meta.body), expected);

        for old in ["cli/0.2.9", "cli/0.3.0-rc.1", "cli/0.3", "ios/1.99.0"] {
            let reply = server
                .send(recovery_start("target", &[("rizzy-client", old)]))
                .await;
            assert_error(&reply, StatusCode::BAD_REQUEST, "client_too_old");
        }
        // Before the session check, on every endpoint.
        for endpoint in Endpoint::ALL {
            let method = if *endpoint == Endpoint::DeviceGrants {
                "GET"
            } else {
                "POST"
            };
            let request = Request::builder()
                .method(method)
                .uri(endpoint.path())
                .header("Rizzy-Client", "cli/0.1.0")
                .body(Body::empty())
                .unwrap();
            assert_error(
                &server.send(request).await,
                StatusCode::BAD_REQUEST,
                "client_too_old",
            );
        }
        // At or above the minimum, another platform, no header, a malformed or repeated one:
        // served (here: judged as a wrong recovery code).
        let served_cases = [
            vec![("rizzy-client", "cli/0.3.0")],
            vec![("rizzy-client", "cli/1.0.0+build.7")],
            vec![("rizzy-client", "web/0.0.1")],
            vec![],
            vec![("rizzy-client", "curl/8.5.0")],
            vec![("rizzy-client", "cli")],
            vec![("rizzy-client", "cli/0.1.0"), ("rizzy-client", "cli/9.0.0")],
        ];
        for (i, served) in served_cases.iter().enumerate() {
            // A name of its own per case, so that no bucket fills.
            let name = format!("name{i}");
            let reply = server.send(recovery_start(&name, served)).await;
            assert_error(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
        }
        // The too-old client still reads the minimums.
        let request = Request::get("/api/meta")
            .header("rizzy-client", "cli/0.1.0")
            .body(Body::empty())
            .unwrap();
        assert_eq!(server.send(request).await.status, StatusCode::OK);
    });
}

/// Item 14: this build has no minimum, so its meta answer lists none and no client is refused.
#[test]
fn this_build_refuses_no_client_version() {
    block_on(async {
        let server = Server::start().await;
        let meta = server.get("/api/meta").await;
        let expected = format!(
            r#"{{"server_version":"{}","api_versions":["v1"],"min_client_versions":[]}}"#,
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(String::from_utf8_lossy(&meta.body), expected);
        let reply = server
            .send(recovery_start("target", &[("rizzy-client", "cli/0.0.1")]))
            .await;
        assert_error(&reply, StatusCode::UNAUTHORIZED, "unauthorized");
    });
}

/// Item 15: `/` and `/index.html` for `GET` and `HEAD`; every other path outside `/api/` is a
/// plain-text `404`, whatever the method. With `embed-web`, the web vault's fixed asset paths
/// are served too (`http::web` module docs), so `/assets/app.js` is not probed there.
#[test]
fn the_web_role_serves_two_paths() {
    block_on(async {
        let server = Server::start().await;
        for path in ["/", "/index.html"] {
            let page = server.get(path).await;
            assert_eq!(page.status, StatusCode::OK, "{path}");
            let head = server
                .send(Request::head(path).body(Body::empty()).unwrap())
                .await;
            assert_eq!(head.status, StatusCode::OK, "{path}");
            assert!(head.body.is_empty());
        }
        for (method, path) in [
            ("GET", "/favicon.ico"),
            ("GET", "/index.htm"),
            ("GET", "/INDEX.HTML"),
            ("GET", "/assets/app.js"),
            ("GET", "/apiv1"),
            ("POST", "/nothing"),
            ("PUT", "/index.html/"),
            ("DELETE", "/x"),
            ("GET", "/assets/../index.html"),
            ("GET", "/assets/"),
        ] {
            if path == "/assets/app.js" && cfg!(feature = "embed-web") {
                continue;
            }
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            let reply = server.send(request).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
            assert_eq!(reply.body, b"not found\n", "{method} {path}");
            assert!(
                reply
                    .header("content-type")
                    .unwrap()
                    .starts_with("text/plain")
            );
        }
    });
}
