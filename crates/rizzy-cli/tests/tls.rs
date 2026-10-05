//! `rv`'s TLS client against loopback `tokio-rustls` test servers (ADR 0030 Decision 7).
//!
//! Each test starts a TLS server on a free loopback port with a committed test certificate
//! (`tests/fixtures/tls/`, README there) and dials it through [`Http`], the transport every
//! command uses:
//!
//! - the handshake succeeds with `--ca-file` naming the test CA, over TLS 1.3 with ALPN
//!   `http/1.1` and SNI, by host name and by IP address;
//! - it is refused for an unknown CA (the public roots, or another CA file), a wrong host
//!   name, an expired certificate, a server limited to TLS 1.2, a self-signed `cA=true`
//!   server certificate placed in the CA file, and (before any connection) a CA file holding
//!   a self-signed `cA=false` certificate or the server certificate itself (Decision 5);
//! - a CA file over the PEM limits stops the transport before any connection.
//!
//! A refused handshake never lets a request through: the server counts the requests it read.
//! rustls' own test vectors are upstream's; none are run here.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: a failure fails the test, which CLAUDE.md allows"
)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rizzy_cli::CliError;
use rizzy_cli::error::TlsFailure;
use rizzy_cli::http::{Auth, Http};
use rizzy_cli::tls::{MAX_CA_CERTIFICATES, MAX_CA_FILE_LEN, Trust};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ProtocolVersion, ServerConfig, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The fixture directory.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// The negotiated protocol version, ALPN protocol and SNI name of one handshake.
type Handshake = (Option<ProtocolVersion>, Option<Vec<u8>>, Option<String>);

/// What the test server saw of the connections that completed a handshake.
#[derive(Default, Debug)]
struct Seen {
    /// Requests read after a handshake.
    requests: AtomicUsize,
    /// The negotiated protocol version, ALPN protocol and SNI name of the last handshake.
    last: Mutex<Option<Handshake>>,
}

/// A loopback TLS server answering every request with `200 {"ok":true}`.
struct TestServer {
    /// Its port.
    port: u16,
    /// What it saw.
    seen: Arc<Seen>,
}

impl TestServer {
    /// Serves `cert` (PEM, the chain the server presents) with `key`, offering `versions`.
    async fn start(cert: &str, key: &str, versions: &[&'static SupportedProtocolVersion]) -> Self {
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(fixture(cert))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(fixture(key)).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        // The client must pick http/1.1 even when h2 is offered first.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Seen::default());
        let task_seen = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                // A refused handshake ends here; the client reports why.
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                {
                    let (_, connection) = tls.get_ref();
                    *task_seen.last.lock().unwrap() = Some((
                        connection.protocol_version(),
                        connection.alpn_protocol().map(<[u8]>::to_vec),
                        connection.server_name().map(str::to_owned),
                    ));
                }
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    task_seen.requests.fetch_add(1, Ordering::SeqCst);
                    let body = br#"{"ok":true}"#;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = tls.write_all(head.as_bytes()).await;
                    let _ = tls.write_all(body).await;
                    let _ = tls.shutdown().await;
                }
            }
        });
        Self { port, seen }
    }

    /// TLS 1.3 only, as Caddy offers it.
    async fn tls13(cert: &str, key: &str) -> Self {
        Self::start(cert, key, &[&rustls::version::TLS13]).await
    }

    /// Requests read so far.
    fn requests(&self) -> usize {
        self.seen.requests.load(Ordering::SeqCst)
    }
}

/// One `GET` through `rv`'s transport.
async fn get(origin: &str, trust: &Trust) -> Result<serde_json::Value, CliError> {
    let http = Http::new(origin, trust)?;
    http.get::<serde_json::Value>("/tls-test", Auth::None).await
}

/// Runs `test` on a current-thread runtime, as `rv` does.
fn block_on<F: std::future::Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

/// The failure kind of a [`CliError::Tls`] naming `origin`.
fn tls_failure(result: Result<serde_json::Value, CliError>, origin: &str) -> TlsFailure {
    match result {
        Err(CliError::Tls {
            origin: named,
            failure,
        }) => {
            assert_eq!(named, origin);
            failure
        }
        other => panic!("expected a TLS failure, got {other:?}"),
    }
}

#[test]
fn the_handshake_succeeds_with_the_private_ca() {
    block_on(async {
        let server = TestServer::tls13("leaf.pem", "leaf.key").await;
        let trust = Trust::ca_file(fixture("ca.pem"));
        let origin = format!("https://localhost:{}", server.port);
        let answer = get(&origin, &trust).await.unwrap();
        assert_eq!(answer, serde_json::json!({"ok": true}));
        let last = server.seen.last.lock().unwrap().clone().unwrap();
        assert_eq!(
            last,
            (
                Some(ProtocolVersion::TLSv1_3),
                Some(b"http/1.1".to_vec()),
                Some("localhost".to_owned())
            )
        );
        // By IP address: the certificate names 127.0.0.1, and no SNI is sent for an IP.
        let by_ip = format!("https://127.0.0.1:{}", server.port);
        assert_eq!(
            get(&by_ip, &trust).await.unwrap(),
            serde_json::json!({"ok": true})
        );
        let last = server.seen.last.lock().unwrap().clone().unwrap();
        assert_eq!(last.2, None);
        assert_eq!(server.requests(), 2);
    });
}

#[test]
fn the_test_certificate_is_refused_under_the_public_roots() {
    block_on(async {
        let server = TestServer::tls13("leaf.pem", "leaf.key").await;
        let origin = format!("https://localhost:{}", server.port);
        let failure = tls_failure(get(&origin, &Trust::public_roots()).await, &origin);
        assert_eq!(failure, TlsFailure::UnknownIssuer);
        assert_eq!(server.requests(), 0);
    });
}

#[test]
fn a_certificate_from_another_ca_is_refused() {
    block_on(async {
        let server = TestServer::tls13("leaf.pem", "leaf.key").await;
        let origin = format!("https://localhost:{}", server.port);
        // A CA file naming another CA replaces the roots: the test CA is not among them.
        let other = Trust::ca_file(fixture("self-signed.pem"));
        let failure = tls_failure(get(&origin, &other).await, &origin);
        assert_eq!(failure, TlsFailure::UnknownIssuer);
        assert_eq!(server.requests(), 0);
    });
}

#[test]
fn a_wrong_host_name_is_refused() {
    block_on(async {
        let server = TestServer::tls13("wrong-host.pem", "leaf.key").await;
        let origin = format!("https://localhost:{}", server.port);
        let trust = Trust::ca_file(fixture("ca.pem"));
        let failure = tls_failure(get(&origin, &trust).await, &origin);
        assert_eq!(failure, TlsFailure::WrongName);
        assert_eq!(server.requests(), 0);
    });
}

#[test]
fn an_expired_certificate_is_refused() {
    block_on(async {
        let server = TestServer::tls13("expired.pem", "leaf.key").await;
        let origin = format!("https://localhost:{}", server.port);
        let trust = Trust::ca_file(fixture("ca.pem"));
        let failure = tls_failure(get(&origin, &trust).await, &origin);
        assert_eq!(failure, TlsFailure::Expired);
        assert_eq!(server.requests(), 0);
    });
}

#[test]
fn a_server_limited_to_tls_1_2_is_refused() {
    block_on(async {
        let server = TestServer::start("leaf.pem", "leaf.key", &[&rustls::version::TLS12]).await;
        let origin = format!("https://localhost:{}", server.port);
        let trust = Trust::ca_file(fixture("ca.pem"));
        let failure = tls_failure(get(&origin, &trust).await, &origin);
        assert_eq!(failure, TlsFailure::Incompatible);
        assert_eq!(server.requests(), 0);
    });
}

#[test]
fn a_self_signed_server_certificate_in_the_ca_file_is_refused() {
    block_on(async {
        // ADR 0030 Decision 5: the CA file is no pin. The self-signed cA=true certificate is a
        // valid trust anchor, but rustls-webpki refuses a CA certificate as the end entity.
        let server = TestServer::tls13("self-signed.pem", "self-signed.key").await;
        let origin = format!("https://localhost:{}", server.port);
        let trust = Trust::ca_file(fixture("self-signed.pem"));
        let failure = tls_failure(get(&origin, &trust).await, &origin);
        assert_eq!(failure, TlsFailure::BadCertificate);
        assert_eq!(server.requests(), 0);
    });
}

#[test]
fn a_self_signed_ca_false_certificate_in_the_ca_file_is_refused() {
    block_on(async {
        // ADR 0030 Decision 5: rustls-webpki would accept a self-signed cA=false certificate as
        // both trust anchor and end entity, a pin in effect. The CA file reader refuses any
        // certificate that is not cA=true, before any connection.
        let server = TestServer::tls13("self-signed-leaf.pem", "self-signed-leaf.key").await;
        let origin = format!("https://localhost:{}", server.port);
        let trust = Trust::ca_file(fixture("self-signed-leaf.pem"));
        assert!(
            matches!(
                get(&origin, &trust).await,
                Err(CliError::BadInput(what)) if what.contains("not a CA certificate")
            ),
            "a self-signed cA=false certificate in the CA file must be refused"
        );
        // So is the CA's own server certificate.
        let trust = Trust::ca_file(fixture("leaf.pem"));
        assert!(matches!(
            get(&origin, &trust).await,
            Err(CliError::BadInput(what)) if what.contains("not a CA certificate")
        ));
        assert_eq!(server.requests(), 0);
    });
}

#[test]
fn a_ca_file_over_the_limits_stops_before_any_connection() {
    block_on(async {
        let server = TestServer::tls13("leaf.pem", "leaf.key").await;
        let origin = format!("https://localhost:{}", server.port);
        let dir = std::env::temp_dir().join(format!("rv-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = std::fs::read_to_string(fixture("ca.pem")).unwrap();
        let cases = [
            ("too-large.pem", {
                let mut big = ca.clone().into_bytes();
                big.resize(MAX_CA_FILE_LEN + 1, b'\n');
                big
            }),
            (
                "too-many.pem",
                ca.repeat(MAX_CA_CERTIFICATES + 1).into_bytes(),
            ),
            ("key-only.pem", std::fs::read(fixture("leaf.key")).unwrap()),
            ("empty.pem", Vec::new()),
        ];
        for (name, bytes) in cases {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            assert!(
                matches!(
                    get(&origin, &Trust::ca_file(path)).await,
                    Err(CliError::BadInput(_))
                ),
                "{name}"
            );
        }
        assert!(server.seen.last.lock().unwrap().is_none(), "no handshake");
        assert_eq!(server.requests(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    });
}
