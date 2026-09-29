//! Slow and anonymous clients (threat model §7.6 "D"): the session is checked before a large
//! body is read, the listener's header-read timeout, and a shutdown that a stalled client
//! cannot hold open.

use std::convert::Infallible;
use std::io::{Read as _, Write as _};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes, HttpBody};
use axum::http::{Request, StatusCode};
use rizzy_server::http::api::{BODY_LIMIT, body_deadline};
use rizzy_server::server::{ServeLimits, serve_http_with};

use crate::common::{Server, block_on};

/// A body that never sends a byte.
struct Stalled;

impl HttpBody for Stalled {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        Poll::Pending
    }
}

/// A POST to `path` whose 10 MiB body never arrives, with `authorization` if given.
fn stalled_post(path: &str, authorization: Option<&str>) -> Request<Body> {
    let mut request = Request::post(path)
        .header("content-type", "application/json")
        .header("content-length", (10 * 1024 * 1024).to_string());
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    request.body(Body::new(Stalled)).unwrap()
}

#[test]
fn large_body_endpoints_refuse_without_a_session_before_reading() {
    block_on(async {
        let server = Server::start().await;
        let forged = format!("Bearer {}", "A".repeat(43));
        for path in ["/api/v1/vault/upload", "/api/v1/vault/heal"] {
            for authorization in [None, Some("Bearer x"), Some(forged.as_str())] {
                // The body never arrives: an answer at all shows it was not waited for.
                let reply = tokio::time::timeout(
                    Duration::from_secs(5),
                    server.send(stalled_post(path, authorization)),
                )
                .await
                .expect("answered without reading the body");
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
                assert_eq!(reply.error(), "unauthorized");
            }
        }
        // The same holds for the small-body endpoints that need a session.
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            server.send(stalled_post("/api/v1/account/state", None)),
        )
        .await
        .expect("answered without reading the body");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn body_deadlines_scale_with_the_limit() {
    assert_eq!(body_deadline(BODY_LIMIT), Duration::from_secs(46));
    assert_eq!(body_deadline(32 * 1024 * 1024), Duration::from_secs(542));
    assert!(body_deadline(usize::MAX) >= Duration::from_secs(30));
}

/// The test limits: short enough to run in a test.
const LIMITS: ServeLimits = ServeLimits {
    header_read_timeout: Duration::from_millis(300),
    max_connections: 8,
    shutdown_grace: Duration::from_millis(500),
};

#[test]
fn the_listener_serves_times_out_headers_and_bounds_shutdown() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let server = Server::start().await;
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

        let (ok, timed_out, stalled) = tokio::task::spawn_blocking(move || {
            // A whole request is served, with the security headers.
            let mut ok = std::net::TcpStream::connect(addr).unwrap();
            ok.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            ok.write_all(b"GET /api/meta HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
                .unwrap();
            let mut answer = String::new();
            ok.read_to_string(&mut answer).unwrap();

            // Half a header block: the connection is closed after the header-read timeout.
            let mut slow = std::net::TcpStream::connect(addr).unwrap();
            slow.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            slow.write_all(b"GET /api/meta HTTP/1.1\r\nhost: x\r\n")
                .unwrap();
            let start = Instant::now();
            let mut buf = [0u8; 256];
            let closed = matches!(slow.read(&mut buf), Ok(0) | Err(_));
            let timed_out = closed && start.elapsed() < Duration::from_secs(4);

            // A request whose body stalls, held open across the shutdown below.
            let mut stalled = std::net::TcpStream::connect(addr).unwrap();
            stalled
                .write_all(
                    b"POST /api/v1/login/start HTTP/1.1\r\nhost: x\r\n\
                      content-type: application/json\r\ncontent-length: 1000\r\n\r\n{\"a",
                )
                .unwrap();
            (answer, timed_out, stalled)
        })
        .await
        .unwrap();
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains("content-security-policy"), "{ok}");
        assert!(timed_out, "a half header block is cut off");

        // Shutdown finishes within the grace period although the stalled request never ends.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let start = Instant::now();
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("shutdown is bounded")
            .unwrap();
        assert!(start.elapsed() >= LIMITS.shutdown_grace / 2);
        drop(stalled);
    });
}
