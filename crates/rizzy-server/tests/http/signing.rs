//! Request signing over HTTP ([ADR 0028] item 5; CRYPTO.md §5.10): the bytes verified are the
//! bytes sent, and the replay window.
//!
//! - [`the_listener_verifies_the_request_target_bytes_as_sent`]: a real client (`rizzy-client`)
//!   signs up and authenticates its device, then raw HTTP/1.1 requests go over a real socket to
//!   the listener (`serve_http_with`, hyper's parser included). For each request-target a URL
//!   library or a proxy would "tidy" (an empty query, duplicate parameters, parameter order,
//!   the hex case of a percent-encoding, dot segments, `//`, a trailing slash, an encoded
//!   octet) and for an absolute-form target, the signature verifies exactly when it was made
//!   over the path-and-query bytes on the request line, and a path that is not one of the 27
//!   literal ones is `404` whatever was signed. The one exception is pinned too: a fragment,
//!   which is no part of a request-target, is cut off by hyper before routing and verification,
//!   so a target sent with one verifies under a signature over the bytes before the `#` and
//!   never under a signature over the bytes sent.
//! - [`a_counter_is_spent_once_and_the_window_is_64_wide`]: a repeated signed request is
//!   refused, also when the first one failed after it authenticated; a request held back 63
//!   counters is still accepted once, one held back 64 is not.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_client::unlock::account_state_query;
use rizzy_server::server::{ServeLimits, serve_http_with};

use crate::common::{Reply, Server, block_on};
use crate::rotation::{Client, signup};

/// The endpoint every request of these tests goes to: any session, a small JSON body.
const ENDPOINT: &str = "/api/v1/account/state";

/// A signed request, ready to send: the target on the request line and the three credential
/// header values.
struct Signed {
    /// The request-target as sent.
    target: String,
    /// `Authorization`.
    authorization: String,
    /// `Rizzy-Request-Counter`.
    counter: String,
    /// `Rizzy-Request-Signature`.
    signature: String,
    /// The body as sent.
    body: Vec<u8>,
}

impl Signed {
    /// Signs `method signed_target` over `signed_body` with the session's next counter, for a
    /// request that will carry `target` and `body`.
    fn new(
        client: &mut Client,
        method: &str,
        signed_target: &str,
        signed_body: &[u8],
        target: &str,
        body: &[u8],
    ) -> Self {
        let signature = client
            .session
            .sign_request(&client.unlocked, method, signed_target, signed_body)
            .unwrap();
        Self {
            target: target.to_owned(),
            authorization: format!(
                "Bearer {}",
                client.session.bearer_token().to_b64url().as_str()
            ),
            counter: signature.request_counter.to_string(),
            signature: signature.signature.to_b64url(),
            body: body.to_vec(),
        }
    }

    /// A request signed over exactly what it sends.
    fn honest(client: &mut Client, target: &str, body: &[u8]) -> Self {
        Self::new(client, "POST", target, body, target, body)
    }

    /// The bytes of the HTTP/1.1 request, as a client writes them on the wire. `Host` names
    /// another server on purpose: it is not read into the signed message.
    fn wire(&self) -> Vec<u8> {
        let mut out = format!(
            "POST {} HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: {}\r\n\
             Rizzy-Request-Counter: {}\r\nRizzy-Request-Signature: {}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.target,
            self.authorization,
            self.counter,
            self.signature,
            self.body.len()
        )
        .into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    /// The same request for the in-process router.
    fn request(&self) -> Request<Body> {
        Request::post(self.target.as_str())
            .header("authorization", self.authorization.as_str())
            .header("rizzy-request-counter", self.counter.as_str())
            .header("rizzy-request-signature", self.signature.as_str())
            .header("content-type", "application/json")
            .body(Body::from(self.body.clone()))
            .unwrap()
    }
}

/// Writes `request` to a new connection to `addr` and returns the answer's status code and
/// body.
fn exchange(addr: SocketAddr, request: &[u8]) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let status = answer
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP/1.1 answer: {answer:?}"));
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

/// The listener's limits for the test.
const LIMITS: ServeLimits = ServeLimits {
    header_read_timeout: Duration::from_secs(10),
    max_connections: 8,
    shutdown_grace: Duration::from_secs(2),
};

/// One case of the listener test: what is signed, what is sent, and the answer.
struct Case {
    /// The `path_and_query` the client signs.
    signed: &'static str,
    /// The request-target it sends.
    sent: &'static str,
    /// The expected status.
    status: u16,
}

/// A case signed over exactly what is sent.
const fn same(target: &'static str, status: u16) -> Case {
    Case {
        signed: target,
        sent: target,
        status,
    }
}

/// A case whose signature covers other bytes than the ones sent.
const fn differs(signed: &'static str, sent: &'static str, status: u16) -> Case {
    Case {
        signed,
        sent,
        status,
    }
}

/// The request-targets of the listener test (module docs).
const CASES: &[Case] = &[
    // The plain target.
    same("/api/v1/account/state", 200),
    // An empty query is not "no query": the `?` is signed.
    same("/api/v1/account/state?", 200),
    differs("/api/v1/account/state", "/api/v1/account/state?", 401),
    differs("/api/v1/account/state?", "/api/v1/account/state", 401),
    // Duplicate parameters and their order, exactly as sent.
    same("/api/v1/account/state?a=1&a=2&a=1", 200),
    differs(
        "/api/v1/account/state?a=1&a=2",
        "/api/v1/account/state?a=1&a=2&a=1",
        401,
    ),
    differs(
        "/api/v1/account/state?a=1&a=2",
        "/api/v1/account/state?a=2&a=1",
        401,
    ),
    // The same octet percent-encoded in lower and in upper case: two different targets.
    same("/api/v1/account/state?q=%2f", 200),
    same("/api/v1/account/state?q=%2F", 200),
    differs(
        "/api/v1/account/state?q=%2f",
        "/api/v1/account/state?q=%2F",
        401,
    ),
    differs(
        "/api/v1/account/state?q=%2F",
        "/api/v1/account/state?q=%2f",
        401,
    ),
    differs(
        "/api/v1/account/state?q=/",
        "/api/v1/account/state?q=%2F",
        401,
    ),
    // A path that is not the literal one is never resolved onto the endpoint, whether the
    // client signed what it sent or the path a normaliser would make of it.
    same("/api/v1/account/./state", 404),
    same("/api/v1/account/../account/state", 404),
    same("//api/v1/account/state", 404),
    same("/api/v1//account/state", 404),
    same("/api/v1/account/state/", 404),
    same("/api/v1/account/%73tate", 404),
    differs("/api/v1/account/state", "/api/v1/account/./state", 404),
    differs(
        "/api/v1/account/state",
        "/api/v1/account/../account/state",
        404,
    ),
    differs("/api/v1/account/state", "//api/v1/account/state", 404),
    differs("/api/v1/account/state", "/api/v1/account/%73tate", 404),
    // And the literal path is not verified under a signature over a spelling of it.
    differs("/api/v1/account/./state", "/api/v1/account/state", 401),
    differs("//api/v1/account/state", "/api/v1/account/state", 401),
    differs("/api/v1/account/%73tate", "/api/v1/account/state", 401),
    // The targets of the `device-request` vectors (`rizzy-core`, statements.json), as sent.
    same("/p?", 404),
    same("/p?a=1&a=2&a=1", 404),
    same("/p?q=%2f", 404),
    same("/p?q=%2F", 404),
    same("/a/./b", 404),
    same("/a/../b", 404),
    same("//a", 404),
    // An absolute-form target: its path-and-query part is what is verified; the scheme and
    // the authority are not read, whatever they name.
    differs(
        "/api/v1/account/state",
        "http://other.example:81/api/v1/account/state",
        200,
    ),
    differs(
        "/api/v1/account/state?x=%2f",
        "https://vault.example.com/api/v1/account/state?x=%2f",
        200,
    ),
    same("http://other.example:81/api/v1/account/state", 401),
    differs(
        "/api/v1/account/state",
        "http://other.example:81/api/v1/account/state?",
        401,
    ),
    differs(
        "/api/v1/account/state",
        "http://other.example:81/api/v1/account/./state",
        404,
    ),
    // The one exception to "the bytes verified are the bytes sent": a fragment. It is not part
    // of a request-target (RFC 9112 §3.2), clients never send one, and hyper cuts the target at
    // the first `#` before routing and verification. So a target sent with a fragment verifies
    // under a signature over the bytes before the `#`, and never under one over the bytes sent.
    differs("/api/v1/account/state", "/api/v1/account/state#frag", 200),
    same("/api/v1/account/state#frag", 401),
    differs("/api/v1/account/state?", "/api/v1/account/state?#x", 200),
    differs("/api/v1/account/state", "/api/v1/account/state?#x", 401),
    same("/api/v1/account/state?#x", 401),
    differs(
        "/api/v1/account/state?a=1",
        "/api/v1/account/state?a=1#b?c",
        200,
    ),
    same("/api/v1/account/state?a=1#b?c", 401),
    differs(
        "/api/v1/account/state",
        "http://other.example:81/api/v1/account/state#f",
        200,
    ),
    // The cut does not resolve a path onto an endpoint: what is left is still matched literally.
    differs("/api/v1/account/state", "/api/v1/account/./state#f", 404),
    differs("/api/v1/account/state", "/api/v1/account/state/#f", 404),
];

/// The label of the two requests whose body or method is not the signed one.
static TAMPERED: Case = same(ENDPOINT, 401);

#[test]
fn the_listener_verifies_the_request_target_bytes_as_sent() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(0x0028);
        let (up, _secret_key, _code) = signup(&server, &mut rng, false).await;
        let mut client = Client::signed_up(&server, up).await;
        let body = serde_json::to_vec(&account_state_query(&client.state)).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve_http_with(
            listener,
            server.router.clone(),
            async {
                let _stopped = stop_rx.await;
            },
            LIMITS,
        ));

        // Every request is signed before any is sent: each has a counter of its own, and a
        // refused one spends none.
        let mut requests: Vec<(&Case, Vec<u8>)> = CASES
            .iter()
            .map(|case| {
                let signed = Signed::new(&mut client, "POST", case.signed, &body, case.sent, &body);
                (case, signed.wire())
            })
            .collect();
        // The body and the method are signed too: a byte changed in either is refused.
        let other_body = Signed::new(&mut client, "POST", ENDPOINT, b"{}", ENDPOINT, &body);
        let other_method = Signed::new(&mut client, "post", ENDPOINT, &body, ENDPOINT, &body);
        requests.push((&TAMPERED, other_body.wire()));
        requests.push((&TAMPERED, other_method.wire()));

        let answers = tokio::task::spawn_blocking(move || {
            requests
                .iter()
                .map(|(case, wire)| {
                    let (status, body) = exchange(addr, wire);
                    (case.signed, case.sent, case.status, status, body)
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
        for (signed, sent, expected, status, body) in answers {
            assert_eq!(status, expected, "signed {signed:?}, sent {sent:?}: {body}");
            match status {
                200 => assert!(body.contains("\"account_state\""), "{sent}: {body}"),
                401 => assert_eq!(body, r#"{"error":"unauthorized"}"#, "{sent}"),
                _ => {}
            }
        }

        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .unwrap()
            .unwrap();
    });
}

/// Sends `signed` through the router.
async fn send(server: &Server, signed: &Signed) -> Reply {
    server.send(signed.request()).await
}

#[test]
fn a_counter_is_spent_once_and_the_window_is_64_wide() {
    block_on(async {
        let server = Server::start().await;
        let mut rng = ChaCha20Rng::seed_from_u64(0x2805);
        let (up, _secret_key, _code) = signup(&server, &mut rng, false).await;
        let mut client = Client::signed_up(&server, up).await;
        let body = serde_json::to_vec(&account_state_query(&client.state)).unwrap();

        // Accepted once; the identical request again is a replay.
        let first = Signed::honest(&mut client, ENDPOINT, &body);
        assert_eq!(send(&server, &first).await.status, StatusCode::OK);
        let replay = send(&server, &first).await;
        assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
        assert_eq!(replay.body, br#"{"error":"unauthorized"}"#);
        assert!(replay.header("www-authenticate").is_none());

        // A counter is spent once the request authenticates, even if the request then fails:
        // this body is signed correctly and is not the endpoint's JSON.
        let failing = Signed::honest(&mut client, ENDPOINT, b"{");
        assert_eq!(
            send(&server, &failing).await.status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(&server, &failing).await.status,
            StatusCode::UNAUTHORIZED
        );

        // A request refused for its signature spends nothing: the same counter, signed
        // properly, is still open. (The client signs the forgery and the real request with
        // consecutive counters, so the forgery is sent with the real request's counter.)
        let mut forged = Signed::new(&mut client, "POST", ENDPOINT, b"other", ENDPOINT, &body);
        let real = Signed::honest(&mut client, ENDPOINT, &body);
        forged.counter.clone_from(&real.counter);
        assert_eq!(
            send(&server, &forged).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(send(&server, &real).await.status, StatusCode::OK);

        // Two requests held back while 63 later ones are sent. The window covers
        // `max − 63 ..= max`: the one 63 behind is accepted, once; the one 64 behind is not.
        let held_64_behind = Signed::honest(&mut client, ENDPOINT, &body);
        let held_63_behind = Signed::honest(&mut client, ENDPOINT, &body);
        for _ in 0..63 {
            let next = Signed::honest(&mut client, ENDPOINT, &body);
            assert_eq!(send(&server, &next).await.status, StatusCode::OK);
        }
        assert_eq!(
            send(&server, &held_64_behind).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(send(&server, &held_63_behind).await.status, StatusCode::OK);
        assert_eq!(
            send(&server, &held_63_behind).await.status,
            StatusCode::UNAUTHORIZED
        );

        // Without its signature, or with only half of it, a device session is refused.
        let unsigned = Request::post(ENDPOINT)
            .header("authorization", first.authorization.as_str())
            .body(Body::from(body.clone()))
            .unwrap();
        assert_eq!(server.send(unsigned).await.status, StatusCode::UNAUTHORIZED);
        // The session itself still works.
        let after = Signed::honest(&mut client, ENDPOINT, &body);
        assert_eq!(send(&server, &after).await.status, StatusCode::OK);
    });
}
