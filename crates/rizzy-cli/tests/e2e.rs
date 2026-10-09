//! `rv` end to end against a real `rizzy-vault` server: signup → login on a second device →
//! items → sync on two devices → a conflict → export → import → TOTP and the generator →
//! offline reads and queued writes → key rotation and its follower → device revocation with a
//! full rotation and the identity-change confirmation → removal of a device.
//!
//! # How the server runs
//!
//! `rizzy-cli` may not depend on `rizzy-server`, not even for tests: ADR 0016 §3 lists
//! `rizzy-core` and `rizzy-client` as its only internal dependencies, §4 admits one dev-only
//! edge (`rizzy-server` → `rizzy-client`), and `cargo xtask check-deps` enforces both. So the
//! tests **spawn the built `rizzy-vault` binary** on a loopback port with a temporary `SQLite`
//! database and a fresh secrets file, exactly as an operator starts it. The binary is the one
//! next to this test's executable (`cargo test --workspace` builds it before any test runs,
//! because `rizzy-server`'s own tests need it); if it is not there, the test builds it with
//! the `cargo` that runs the tests.
//!
//! Some tests put a small loopback reverse proxy ([`Proxy`]) in front of it, as an operator's
//! would be, to lose or replace one answer: a gateway's `502` page on a commit (the outcome is
//! unknown, so nothing saved for the commit may be dropped), and an older `account-state` on a
//! rotation's retry (a possible rollback).
//!
//! # How `rv` runs
//!
//! Through its library: [`rizzy_cli::args::parse`] and [`rizzy_cli::commands::run`], with a
//! scripted [`Ui`] in place of the terminal. Every command opens the cache file anew, as a
//! new process would: the device state and the encrypted cache of ADR 0026 carry everything
//! from one command to the next.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: a failure fails the test, which CLAUDE.md allows"
)]

use std::collections::VecDeque;
use std::ffi::OsString;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rizzy_cli::CliError;
use rizzy_cli::args::parse;
use rizzy_cli::commands::run;
use rizzy_cli::device::Env;
use rizzy_cli::ui::Ui;
use rizzy_client::ClientError;
use rizzy_client::export::plaintext::PLAINTEXT_EXPORT_WARNING;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::store::rows::Alarm;
use zeroize::Zeroizing;

/// The master password of the test account.
const PASSWORD: &str = "correct horse battery staple";

/// A fresh temporary directory.
fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rv-e2e-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The `rizzy-vault` binary (module docs).
fn server_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/<test> → target/<profile>/rizzy-vault
    let profile_dir = exe.parent().and_then(Path::parent).unwrap();
    let binary = profile_dir.join(format!("rizzy-vault{}", std::env::consts::EXE_SUFFIX));
    // Always through cargo: it does nothing when the binary is fresh, and a stale one (a
    // `cargo test -p rizzy-cli` after a server change) would test the wrong server.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut build = Command::new(cargo);
    build.args([
        "build",
        "--locked",
        "--quiet",
        "-p",
        "rizzy-server",
        "--bin",
        "rizzy-vault",
    ]);
    if profile_dir.file_name().is_some_and(|n| n == "release") {
        build.arg("--release");
    }
    let status = build.status().expect("cargo builds rizzy-vault");
    assert!(status.success(), "building rizzy-vault failed");
    assert!(
        binary.is_file(),
        "no rizzy-vault binary at {}",
        binary.display()
    );
    binary
}

/// A running `rizzy-vault` on a loopback port. Killed on drop.
struct Server {
    /// The process.
    child: Child,
    /// Its directories.
    dir: PathBuf,
    /// Its loopback port.
    port: u16,
    /// Its public origin (`RIZZY_ORIGIN`): its own loopback port, or the [`Proxy`] or
    /// [`TlsProxy`] in front of it.
    origin: String,
}

impl Server {
    /// A new server: `secrets init`, then serve with open signup.
    fn start() -> Self {
        Self::start_behind(None)
    }

    /// A new server whose public origin is `origin_port` on loopback (a [`Proxy`] in front of
    /// it), or its own port.
    fn start_behind(origin_port: Option<u16>) -> Self {
        Self::start_at(origin_port.map(|p| format!("http://127.0.0.1:{p}")))
    }

    /// A new server whose public origin is `origin` (a proxy in front of it), or
    /// `http://127.0.0.1:<its own port>`.
    fn start_at(origin: Option<String>) -> Self {
        let dir = temp_dir("server");
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let origin = origin.unwrap_or_else(|| format!("http://127.0.0.1:{port}"));
        let init = Self::command(&dir, port, &origin)
            .args(["secrets", "init"])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let child = Self::spawn(&dir, port, &origin);
        Self {
            child,
            dir,
            port,
            origin,
        }
    }

    /// The server's command with its settings.
    fn command(dir: &Path, port: u16, origin: &str) -> Command {
        let mut command = Command::new(server_binary());
        command
            .env_clear()
            .env("RIZZY_ORIGIN", origin)
            .env("RIZZY_LISTEN", format!("127.0.0.1:{port}"))
            .env("RIZZY_SIGNUP", "open")
            .env("RIZZY_DATA_DIR", dir.join("data"))
            .env(
                "RIZZY_SECRETS_FILE",
                dir.join("secrets").join("secrets.json"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    /// Spawns the serving process and waits until it accepts connections.
    fn spawn(dir: &Path, port: u16, origin: &str) -> Child {
        let mut child = Self::command(dir, port, origin).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return child;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("rizzy-vault exited at start: {status}");
            }
            assert!(Instant::now() < deadline, "rizzy-vault did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The origin `rv` dials.
    fn origin(&self) -> String {
        self.origin.clone()
    }

    /// Stops the server (the data stays).
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Starts it again on the same data and port.
    fn restart(&mut self) {
        self.stop();
        self.child = Self::spawn(&self.dir, self.port, &self.origin);
    }

    /// Stops the server, runs the operator's command `args` on its data, and starts it again.
    fn admin(&mut self, args: &[&str]) {
        self.stop();
        let out = Self::command(&self.dir, self.port, &self.origin)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "rizzy-vault {args:?} failed");
        self.child = Self::spawn(&self.dir, self.port, &self.origin);
    }

    /// ADR 0031 as an operator runs it after a leak: `secrets rotate`, a start (which records
    /// the new setup's time), then `secrets retire-setups --grace-days 0`, which retires the
    /// first setup at once, and a start.
    fn retire_first_setup(&mut self) {
        self.admin(&["secrets", "rotate"]);
        self.admin(&["secrets", "retire-setups", "--grace-days", "0"]);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the [`Proxy`] does to the next request for a path, once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    /// The request reaches the server, and its answer is replaced by a gateway's `502` page:
    /// the server acted, the client cannot know.
    AnswerLost,
    /// The request never reaches the server; the client gets the same `502` page.
    NeverSent,
    /// The request never reaches the server; the client gets `409 state_conflict`, and the
    /// next `account/state` answer is the first one the proxy ever saw (an older state).
    ConflictThenOldState,
}

/// What the proxy is told to do, and what it has seen.
#[derive(Default)]
struct ProxyState {
    /// The fault armed for the next request to a path.
    fault: Option<(&'static str, Fault)>,
    /// Whether the next `account/state` answer is replaced by `first_state`.
    replay_state: bool,
    /// The body of the first `account/state` answer that passed through.
    first_state: Option<Vec<u8>>,
    /// The paths requested, in order.
    seen: Vec<String>,
}

/// A loopback reverse proxy in front of a [`Server`], as an operator's would be, that can
/// lose or replace one answer: the answers a client cannot take for a refusal (ADR 0028
/// "Retry after an unknown outcome"), and a server that shows an older `account-state`.
struct Proxy {
    /// Its port: the public origin's.
    port: u16,
    /// Shared with the accepting thread.
    state: std::sync::Arc<std::sync::Mutex<ProxyState>>,
    /// Set on drop.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Proxy {
    /// A proxy on a free loopback port and the server behind it.
    fn start() -> (Self, Server) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = Server::start_behind(Some(port));
        let upstream = server.port;
        let state = std::sync::Arc::new(std::sync::Mutex::new(ProxyState::default()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (thread_state, thread_stop) = (state.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(stream) = stream {
                    // One request per connection, one connection at a time: `rv` sends
                    // `Connection: close` and runs its requests in sequence.
                    let _ = Self::serve(stream, upstream, &thread_state);
                }
            }
        });
        (Self { port, state, stop }, server)
    }

    /// Arms `fault` for the next request to `path`.
    fn arm(&self, path: &'static str, fault: Fault) {
        self.state.lock().unwrap().fault = Some((path, fault));
    }

    /// Whether the armed fault was used.
    fn fired(&self) -> bool {
        self.state.lock().unwrap().fault.is_none()
    }

    /// How many requests for `path` were seen.
    fn count(&self, path: &str) -> usize {
        let state = self.state.lock().unwrap();
        state.seen.iter().filter(|p| *p == path).count()
    }

    /// A whole HTTP/1.1 message with a `Content-Length` (or none) from `stream`: the head
    /// and the body.
    fn read_message(stream: &mut std::net::TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 8192];
        let head_end = loop {
            if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            bytes.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&bytes[..head_end]).to_ascii_lowercase();
        assert!(!head.contains("transfer-encoding"), "chunked: {head}");
        let length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map_or(0, |v| v.trim().parse().unwrap());
        while bytes.len() < head_end + length {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        let body = bytes.split_off(head_end);
        Ok((bytes, body))
    }

    /// An answer with `status` and `body`, closing the connection.
    fn answer(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// Serves one request.
    fn serve(
        mut client: std::net::TcpStream,
        upstream: u16,
        state: &std::sync::Mutex<ProxyState>,
    ) -> std::io::Result<()> {
        use rizzy_client::rizzy_proto::http::paths;
        use std::io::Write as _;

        client.set_read_timeout(Some(Duration::from_secs(30)))?;
        let (head, body) = Self::read_message(&mut client)?;
        let path = String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let (fault, old_state) = {
            let mut state = state.lock().unwrap();
            state.seen.push(path.clone());
            let fault = match state.fault {
                Some((armed, fault)) if armed == path => {
                    state.fault = None;
                    Some(fault)
                }
                _ => None,
            };
            if fault == Some(Fault::ConflictThenOldState) {
                state.replay_state = true;
            }
            let old_state = if fault.is_none() && state.replay_state && path == paths::ACCOUNT_STATE
            {
                state.replay_state = false;
                state.first_state.clone()
            } else {
                None
            };
            (fault, old_state)
        };
        let bad_gateway = || {
            Self::answer(
                "502 Bad Gateway",
                "text/html",
                b"<html><body><h1>502 Bad Gateway</h1></body></html>",
            )
        };
        let reply = if let Some(old) = old_state {
            Self::answer("200 OK", "application/json", &old)
        } else if fault == Some(Fault::NeverSent) {
            bad_gateway()
        } else if fault == Some(Fault::ConflictThenOldState) {
            Self::answer(
                "409 Conflict",
                "application/json",
                br#"{"error":"state_conflict"}"#,
            )
        } else {
            let mut server = std::net::TcpStream::connect(("127.0.0.1", upstream))?;
            server.set_read_timeout(Some(Duration::from_secs(30)))?;
            server.write_all(&head)?;
            server.write_all(&body)?;
            let (answer_head, answer_body) = Self::read_message(&mut server)?;
            if path == paths::ACCOUNT_STATE && answer_head.starts_with(b"HTTP/1.1 200") {
                let mut state = state.lock().unwrap();
                if state.first_state.is_none() {
                    state.first_state = Some(answer_body.clone());
                }
            }
            if fault == Some(Fault::AnswerLost) {
                bad_gateway()
            } else {
                [answer_head, answer_body].concat()
            }
        };
        client.write_all(&reply)?;
        client.flush()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wakes the accepting thread so it sees the flag.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// The committed TLS test fixture `name` (`tests/fixtures/tls/README.md`).
fn tls_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// A loopback TLS-terminating reverse proxy in front of a [`Server`], as an operator's Caddy
/// would be (ADR 0010 §4): TLS 1.3 with the committed test certificate for `localhost`
/// (issued by the test CA), the plaintext bytes forwarded to the server's loopback listener
/// unchanged. The server's public origin is `https://localhost:<port>`.
struct TlsProxy {
    /// Its port.
    port: u16,
    /// Set on drop.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl TlsProxy {
    /// A TLS proxy on a free loopback port and the server behind it.
    fn start() -> (Self, Server) {
        use rustls::pki_types::pem::PemObject as _;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = Server::start_at(Some(format!("https://localhost:{port}")));
        let upstream = server.port;
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(tls_fixture("leaf.pem"))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_file(tls_fixture("leaf.key")).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = stop.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    let Ok((client, _)) = listener.accept().await else {
                        break;
                    };
                    if thread_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(client).await else {
                            return;
                        };
                        let Ok(mut server) =
                            tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await
                        else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut server).await;
                    });
                }
            });
        });
        (Self { port, stop }, server)
    }
}

impl Drop for TlsProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wakes the accepting task so it sees the flag.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// The scripted user: answers in order, and everything `rv` printed.
#[derive(Default)]
struct Script {
    /// Answers to secret prompts.
    secrets: VecDeque<String>,
    /// Answers to line prompts.
    lines: VecDeque<String>,
    /// Answers to phrases that must be typed at a terminal.
    typed: VecDeque<String>,
    /// Standard output.
    out: Vec<String>,
    /// Standard error.
    notes: Vec<String>,
    /// The holds `rv` asked for, recorded instead of slept (the test seam of `Ui::hold`).
    holds: Vec<Duration>,
    /// How many notes there were at each hold.
    notes_at_hold: Vec<usize>,
    /// How many holds there had been at each phrase prompt.
    holds_at_typed: Vec<usize>,
}

impl Ui for Script {
    fn secret(&mut self, _prompt: &str) -> Result<Zeroizing<String>, CliError> {
        self.secrets
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(CliError::InputEnded)
    }

    fn line(&mut self, prompt: &str) -> Result<String, CliError> {
        if prompt.starts_with("Type the last four characters") {
            // The Emergency Kit was just printed: the user reads the Secret Key off it.
            let kit = self.printed("Secret Key:");
            return Ok(kit.rsplit('-').next().unwrap().to_owned());
        }
        self.lines.pop_front().ok_or(CliError::InputEnded)
    }

    fn typed(&mut self, _prompt: &str) -> Result<String, CliError> {
        self.holds_at_typed.push(self.holds.len());
        self.typed.pop_front().ok_or(CliError::NoTerminal)
    }

    fn print(&mut self, text: &str) -> Result<(), CliError> {
        self.out.push(text.to_owned());
        Ok(())
    }

    fn note(&mut self, text: &str) {
        self.notes.push(text.to_owned());
    }

    fn hold(&mut self, duration: Duration) -> Duration {
        self.notes_at_hold.push(self.notes.len());
        self.holds.push(duration);
        duration
    }
}

impl Script {
    /// The rest of the printed line that starts with `label`.
    fn printed(&self, label: &str) -> String {
        self.out
            .iter()
            .find_map(|line| line.strip_prefix(label))
            .unwrap_or_else(|| panic!("no line {label:?} in {:?}", self.out))
            .trim()
            .to_owned()
    }

    /// Whether any note holds `text`.
    fn noted(&self, text: &str) -> bool {
        self.notes.iter().any(|n| n.contains(text))
    }
}

/// One device's `rv`: its data directory.
struct Rv {
    /// `RIZZY_CLI_DATA_DIR`.
    dir: PathBuf,
    /// The runtime commands run on.
    runtime: tokio::runtime::Runtime,
    /// The private CA file this device trusts, as `RIZZY_CLI_CA_FILE` would name it; `None`
    /// for the public roots.
    ca_file: Option<PathBuf>,
}

impl Rv {
    fn new(tag: &str) -> Self {
        Self {
            // Not created here: `rv` creates its data directory itself, with mode 0700.
            dir: temp_dir(tag).join("rv"),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            ca_file: None,
        }
    }

    /// Runs one command with scripted answers; the master password is not implied.
    fn try_run(
        &self,
        args: &[&str],
        secrets: &[&str],
        lines: &[&str],
        typed: &[&str],
    ) -> (Result<(), CliError>, Script) {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        let mut script = Script {
            secrets: own(secrets),
            lines: own(lines),
            typed: own(typed),
            ..Script::default()
        };
        let invocation = parse(args.iter().map(OsString::from).collect());
        let outcome = match invocation {
            Ok(invocation) => {
                let mut env = Env {
                    data_dir: self.dir.clone(),
                    account: None,
                    trust: rizzy_cli::tls::Trust::from_settings(None, &|name| {
                        (name == rizzy_cli::tls::CA_FILE_ENV)
                            .then(|| self.ca_file.clone().map(OsString::from))
                            .flatten()
                    }),
                    ui: &mut script,
                };
                self.runtime.block_on(run(invocation, &mut env))
            }
            Err(e) => Err(e),
        };
        (outcome, script)
    }

    /// Runs a command that must succeed; the first secret is the master password.
    fn ok(&self, args: &[&str], secrets: &[&str]) -> Script {
        let mut all = vec![PASSWORD];
        all.extend_from_slice(secrets);
        let (outcome, script) = self.try_run(args, &all, &[], &[]);
        if let Err(e) = outcome {
            panic!("rv {args:?} failed: {e} ({e:?}); notes: {:?}", script.notes);
        }
        script
    }

    /// The ids `item list` prints, with the rest of each line.
    fn items(&self) -> Vec<(String, String)> {
        self.ok(&["item", "list"], &[])
            .out
            .iter()
            .map(|line| {
                let (id, rest) = line.split_once("  ").unwrap();
                (id.to_owned(), rest.to_owned())
            })
            .collect()
    }

    /// The value `item show --reveal` prints for `key`.
    fn field(&self, item: &str, key: &str) -> String {
        self.ok(&["item", "show", item, "--reveal"], &[])
            .printed(&format!("{key}:"))
    }
}

impl Drop for Rv {
    fn drop(&mut self) {
        if let Some(parent) = self.dir.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

/// The whole story (module docs). One test: every step needs the state the steps before it
/// left on the server and in the two caches.
#[test]
#[expect(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "one end-to-end story over one server, in the order a user lives it"
)]
fn rv_end_to_end() {
    let mut server = Server::start();
    let origin = server.origin();
    let a = Rv::new("a");
    let b = Rv::new("b");

    // Nothing is enrolled yet.
    let (outcome, _) = a.try_run(&["item", "list"], &[PASSWORD], &[], &[]);
    assert!(matches!(outcome, Err(CliError::NotEnrolled)));
    // A public http origin is never dialled: tokens would travel in clear.
    let (outcome, _) = a.try_run(
        &[
            "signup",
            "--server",
            "http://vault.example.com",
            "--name",
            "alice",
        ],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::InsecureOrigin)));
    // A CA file that cannot be used stops an https signup before anything is asked or sent
    // (ADR 0030 Decision 4).
    let (outcome, asked) = a.try_run(
        &[
            "signup",
            "--server",
            "https://vault.example.com",
            "--name",
            "alice",
            "--ca-file",
            "/nonexistent/rv-e2e-ca.pem",
        ],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadInput(_))));
    assert!(asked.out.is_empty());

    // Signup on A: the kit is shown once, confirmed, and the device is enrolled and synced.
    let (outcome, signup) = a.try_run(
        &["signup", "--server", &origin, "--name", "Alice"],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap();
    let secret_key = signup.printed("Secret Key:");
    let recovery_code = signup.printed("Recovery code:");
    assert!(secret_key.starts_with("RV1-") && recovery_code.starts_with("RVR1-"));
    assert_eq!(signup.printed("Login name:"), "alice");
    // The cache file: one per account, private.
    let files: Vec<PathBuf> = std::fs::read_dir(&a.dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sqlite3"))
        .collect();
    assert_eq!(files.len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&files[0]), 0o600);
        assert_eq!(mode(&a.dir), 0o700);
    }
    // The file holds no plaintext of what the user typed, and no bearer token survives a run.
    let raw = std::fs::read(&files[0]).unwrap();
    let contains = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(PASSWORD.as_bytes()));
    assert!(!contains(secret_key.as_bytes()));
    assert!(!contains(recovery_code.as_bytes()));
    // A second signup of the same name is refused by the server, uniformly.
    let (outcome, _) = Rv::new("dup").try_run(
        &["signup", "--server", &origin, "--name", "alice"],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    assert!(outcome.is_err());

    // Recovery with the kit, as far as a server with the default 72 h wait lets it go: the
    // request is accepted, completing it is refused until the wait is over, and the enrolled
    // device cancels it. (The commit itself runs against the real domains, with a zero wait,
    // in `rizzy-server`'s `tests/http/recovery.rs`.)
    let r = Rv::new("r");
    let (outcome, _) = r.try_run(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &["RVR1-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"],
        &[],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Client(ClientError::InvalidInput))),
        "a mistyped code fails its check characters before anything is sent"
    );
    let (outcome, requested) = r.try_run(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
        &[],
    );
    outcome.unwrap();
    assert!(requested.noted("Recovery requested"));
    let available_at: u64 = requested.out[0].parse().unwrap();
    assert!(available_at > rizzy_cli::sys::now_ms() + 71 * 3_600_000);
    let (outcome, _) = r.try_run(
        &[
            "recovery", "complete", "--server", &origin, "--name", "alice",
        ],
        &[&recovery_code],
        &[],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::RateLimited(Some(seconds))) if seconds > 71 * 3600),
        "{outcome:?}"
    );
    let (outcome, cancelled) = a.try_run(&["recovery", "cancel"], &[PASSWORD], &[], &[]);
    outcome.unwrap();
    assert!(cancelled.noted("was cancelled"));
    let (outcome, cancelled) = a.try_run(&["recovery", "cancel"], &[PASSWORD], &[], &[]);
    outcome.unwrap();
    assert!(cancelled.noted("No recovery was pending"));

    // A wrong master password is "wrong password", offline.
    let (outcome, _) = a.try_run(&["item", "list"], &["not the password"], &[], &[]);
    assert!(matches!(
        outcome,
        Err(CliError::Client(ClientError::WrongPasswordOrSecretKey))
    ));

    // An item: a concealed field is never taken from the command line.
    let (outcome, _) = a.try_run(
        &[
            "item",
            "create",
            "--type",
            "login",
            "--field",
            "login.password=hunter2",
        ],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Usage(_))));
    let created = a.ok(
        &[
            "item",
            "create",
            "--type",
            "login",
            "--field",
            "item.name=Mail",
            "--field",
            "login.username=alice@example.com",
            "--secret",
            "login.password",
            "--secret",
            "login.totp",
            "--uri",
            "https://mail.example.com",
            "--tag",
            "work",
        ],
        &["hunter2", "JBSWY3DPEHPK3PXP"],
    );
    let mail = created.out[0].clone();
    assert_eq!(mail.len(), 32);
    assert_eq!(
        a.items(),
        vec![(mail.clone(), "login             Mail".to_owned())]
    );
    // Shown without the secret unless asked; a unique prefix names the item.
    let shown = a.ok(&["item", "show", &mail[..6]], &[]);
    assert_eq!(shown.printed("login.password:"), "********");
    assert_eq!(shown.printed("login.username:"), "alice@example.com");
    assert!(shown.out.iter().any(|l| l == "tag work: true"));
    assert!(!shown.out.iter().any(|l| l.contains("hunter2")));
    assert_eq!(a.field(&mail, "login.password"), "hunter2");

    // TOTP of the item, and the generator.
    let code = a.ok(&["totp", &mail], &[]);
    assert_eq!(code.out.len(), 1);
    assert!(code.out[0].len() == 6 && code.out[0].bytes().all(|b| b.is_ascii_digit()));
    let (outcome, generated) = a.try_run(&["generate", "--length", "24"], &[], &[], &[]);
    outcome.unwrap();
    assert_eq!(generated.out[0].len(), 24);
    let (outcome, phrase) = a.try_run(&["generate", "--words", "5"], &[], &[], &[]);
    outcome.unwrap();
    assert_eq!(phrase.out[0].split('.').count(), 5);

    // A second device logs in with the Secret Key, enrols, and reads the item.
    let (outcome, _) = b.try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, "wrong password"],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Client(ClientError::WrongPasswordOrSecretKey))
    ));
    let (outcome, _) = b.try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap();
    assert_eq!(b.field(&mail, "login.password"), "hunter2");
    // Logging in again on an enrolled device is refused before anything is enrolled.
    let (outcome, _) = b.try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::AlreadyEnrolled)));
    let devices = a.ok(&["device", "list"], &[]);
    assert_eq!(devices.out.len(), 2);
    let b_device = devices
        .out
        .iter()
        .find(|l| !l.contains("this device"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();

    // Sync on two devices: B's new item reaches A.
    let note = b.ok(
        &[
            "item",
            "create",
            "--type",
            "note",
            "--field",
            "item.name=Plan",
            "--secret",
            "item.notes",
        ],
        &["the plan"],
    );
    let plan = note.out[0].clone();
    a.ok(&["sync"], &[]);
    assert_eq!(a.items().len(), 2);
    assert_eq!(a.field(&plan, "item.notes"), "the plan");

    // A conflict: both edit the same field before either sees the other's edit. B's edit is
    // written while the server is down, so it cannot have seen A's.
    a.ok(
        &["item", "edit", &mail, "--secret", "login.password"],
        &["from-a"],
    );
    server.stop();
    // Offline: reads work from the cache, a write is queued, and the command says so.
    assert_eq!(b.field(&mail, "login.password"), "hunter2");
    let offline = b.ok(
        &["item", "edit", &mail, "--secret", "login.password"],
        &["from-b"],
    );
    assert!(offline.noted("Saved on this device"));
    assert_eq!(b.field(&mail, "login.password"), "from-b");
    let (outcome, _) = b.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(matches!(outcome, Err(CliError::Network)));
    server.restart();
    b.ok(&["sync"], &[]);
    a.ok(&["sync"], &[]);
    let on_a = a.ok(&["item", "show", &mail, "--reveal"], &[]);
    let on_b = b.ok(&["item", "show", &mail, "--reveal"], &[]);
    let password_line = |s: &Script| {
        s.out
            .iter()
            .find(|l| l.starts_with("login.password:"))
            .unwrap()
            .clone()
    };
    // Both devices show the same value and both know it conflicts.
    assert_eq!(password_line(&on_a), password_line(&on_b));
    assert!(password_line(&on_a).contains("conflicting values"));
    // Resolving it: a new edit on top of both.
    a.ok(
        &["item", "edit", &mail, "--secret", "login.password"],
        &["settled"],
    );
    b.ok(&["sync"], &[]);
    assert_eq!(b.field(&mail, "login.password"), "settled");

    // Trash, restore, purge.
    a.ok(&["item", "trash", &plan], &[]);
    assert_eq!(a.items().len(), 1);
    assert_eq!(a.ok(&["item", "list", "--trash"], &[]).out.len(), 1);
    a.ok(&["item", "restore", &plan], &[]);
    assert_eq!(a.items().len(), 2);
    let (outcome, _) = a.try_run(&["item", "purge", &plan], &[PASSWORD], &[], &[]);
    assert!(outcome.is_err(), "only a trashed item is purged");

    // Export (owner decision 2026-10-05): every export first re-authenticates with the master
    // password, and a wrong one refuses the export and writes nothing; the encrypted export is
    // under a new password for the file, typed twice; the plaintext export comes after the
    // warning, a 10-second hold and the typed phrase; never an overwrite.
    let out = temp_dir("out");
    let encrypted = out.join("vault.rvexport");
    let enc = encrypted.to_str().unwrap();
    let (outcome, refused) = a.try_run(
        &["export", "--out", enc, "--name", "alice"],
        &[
            PASSWORD,
            "not the master password",
            "export password",
            "export password",
        ],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Client(ClientError::WrongPasswordOrSecretKey))
    ));
    assert!(!encrypted.exists());
    // The file's password was never asked for.
    assert_eq!(refused.secrets.len(), 2);
    let (outcome, _) = a.try_run(
        &["export", "--out", enc, "--name", "alice"],
        &[PASSWORD, PASSWORD, "export password", "export passwrod"],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadInput(_))));
    assert!(!encrypted.exists());
    let exported = a.ok(
        &["export", "--out", enc, "--name", "alice"],
        &[PASSWORD, "export password", "export password"],
    );
    assert!(exported.noted("needed to import the file"));
    assert!(exported.holds.is_empty());
    let file = std::fs::read(&encrypted).unwrap();
    assert!(file.starts_with(br#"{"format":"rizzy-vault-export""#));
    assert!(!file.windows(7).any(|w| w == b"settled"));
    let (outcome, _) = a.try_run(
        &["export", "--out", enc, "--name", "alice"],
        &[PASSWORD, PASSWORD, "x", "x"],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::FileExists)));
    assert_eq!(std::fs::read(&encrypted).unwrap(), file);
    let json = out.join("vault.json");
    let plaintext_args = |path: &Path, format: &'static str| {
        [
            "export".to_owned(),
            "--out".to_owned(),
            path.to_str().unwrap().to_owned(),
            "--name".to_owned(),
            "alice".to_owned(),
            "--format".to_owned(),
            format.to_owned(),
        ]
    };
    let json_args = plaintext_args(&json, "json");
    let json_args: Vec<&str> = json_args.iter().map(String::as_str).collect();
    // A wrong master password: no warning, no hold, nothing written.
    let (outcome, refused) =
        a.try_run(&json_args, &[PASSWORD, "wrong"], &[], &["EXPORT PLAINTEXT"]);
    assert!(matches!(
        outcome,
        Err(CliError::Client(ClientError::WrongPasswordOrSecretKey))
    ));
    assert!(!refused.noted("unencrypted") && refused.holds.is_empty());
    assert!(!json.exists());
    // Without a terminal, or with anything but the phrase, nothing is written; the hold runs
    // after the warning and before the phrase is asked for, whatever comes next.
    let (outcome, held) = a.try_run(&json_args, &[PASSWORD, PASSWORD], &[], &[]);
    assert!(matches!(outcome, Err(CliError::NoTerminal)));
    assert_eq!(held.holds, [Duration::from_secs(10)]);
    let (outcome, warned) = a.try_run(
        &json_args,
        &[PASSWORD, PASSWORD],
        &[],
        &["export plaintext"],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Client(
            ClientError::PlaintextExportNotAcknowledged
        ))
    ));
    assert!(warned.noted("unencrypted"));
    assert!(!json.exists());
    let (outcome, written) = a.try_run(
        &json_args,
        &[PASSWORD, PASSWORD],
        &[],
        &["EXPORT PLAINTEXT"],
    );
    outcome.unwrap();
    // The warning, verbatim, then the 10-second hold, then the phrase.
    assert_eq!(written.holds, [Duration::from_secs(10)]);
    let warning_at = written
        .notes
        .iter()
        .position(|n| n == PLAINTEXT_EXPORT_WARNING)
        .unwrap();
    assert!(warning_at < written.notes_at_hold[0]);
    assert_eq!(written.holds_at_typed, [1]);
    assert!(std::fs::read_to_string(&json).unwrap().contains("settled"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&json).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let csv = out.join("vault.csv");
    let csv_args = plaintext_args(&csv, "csv");
    let csv_args: Vec<&str> = csv_args.iter().map(String::as_str).collect();
    let (outcome, warned) = a.try_run(&csv_args, &[PASSWORD, PASSWORD], &[], &["EXPORT PLAINTEXT"]);
    outcome.unwrap();
    assert!(warned.noted("spreadsheet"));
    assert_eq!(warned.holds, [Duration::from_secs(10)]);
    assert!(std::fs::read_to_string(&csv).unwrap().contains("settled"));

    // Import: the format is recognised from the file. Our encrypted export asks for the file's
    // own password (a wrong one imports nothing); our plaintext JSON and another product's
    // file need nothing more; our CSV export and a file of no known format are refused before
    // the cache is unlocked. `--format` still overrides. Each item arrives as a new item.
    let (outcome, asked) = b.try_run(
        &["import", "--in", enc],
        &[PASSWORD, "not the export password"],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Client(ClientError::ExportDecryptionFailed))
    ));
    assert!(asked.noted("Recognised: a rizzy-vault encrypted export"));
    assert_eq!(b.items().len(), 2);
    let imported = b.ok(&["import", "--in", enc], &["export password"]);
    assert!(imported.noted("Imported 2 items"));
    assert_eq!(b.items().len(), 4);
    let imported = b.ok(&["import", "--in", json.to_str().unwrap()], &[]);
    assert!(imported.noted("Recognised: a rizzy-vault plaintext JSON export"));
    assert_eq!(b.items().len(), 6);
    let (outcome, asked) = b.try_run(&["import", "--in", csv.to_str().unwrap()], &[], &[], &[]);
    assert!(matches!(outcome, Err(CliError::BadInput(_))));
    assert!(asked.secrets.is_empty() || asked.notes.is_empty());
    let unknown = out.join("notes.txt");
    std::fs::write(&unknown, "just some text\n").unwrap();
    let (outcome, _) = b.try_run(
        &["import", "--in", unknown.to_str().unwrap()],
        &[],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadInput(_))));
    let bitwarden = out.join("bitwarden.json");
    std::fs::write(
        &bitwarden,
        r#"{"encrypted":false,"items":[{"type":1,"name":"From Bitwarden","login":{"username":"bw","password":"bw-secret"}}]}"#,
    )
    .unwrap();
    b.ok(
        &[
            "import",
            "--format",
            "bitwarden-json",
            "--in",
            bitwarden.to_str().unwrap(),
        ],
        &[],
    );
    a.ok(&["sync"], &[]);
    let all = a.items();
    assert_eq!(all.len(), 7);
    let from_bitwarden = &all
        .iter()
        .find(|(_, rest)| rest.ends_with("From Bitwarden"))
        .unwrap()
        .0;
    assert_eq!(a.field(from_bitwarden, "login.password"), "bw-secret");
    assert_eq!(
        all.iter()
            .filter(|(_, rest)| rest.ends_with("Mail"))
            .count(),
        3
    );

    // A standard rotation on A (the recovery code is kept); B follows through its grant and
    // keeps reading and writing.
    let (outcome, rotated) = a.try_run(
        &["rotate", "--name", "alice"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("rotate failed: {e:?}; {:?}", rotated.notes));
    assert!(rotated.noted("rotated"));
    assert_eq!(a.field(&mail, "login.password"), "settled");
    b.ok(
        &[
            "item",
            "edit",
            &mail,
            "--field",
            "login.username=after-rotation",
        ],
        &[],
    );
    a.ok(&["sync"], &[]);
    assert_eq!(a.field(&mail, "login.username"), "after-rotation");
    assert_eq!(b.field(&plan, "item.notes"), "the plan");

    // A third device, then A revokes B with a full rotation: B is locked out, and C must
    // confirm the new identity fingerprint before it follows.
    let c = Rv::new("c");
    let (outcome, _) = c.try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap();
    assert_eq!(c.items().len(), 7);
    let (outcome, revoked) = a.try_run(
        &["device", "revoke", &b_device, "--name", "alice"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("revoke failed: {e:?}; {:?}", revoked.notes));
    assert!(revoked.noted("revoked"));
    let listed = a.ok(&["device", "list"], &[]);
    assert!(
        listed
            .out
            .iter()
            .any(|l| l.starts_with(&b_device) && l.ends_with("revoked"))
    );
    // B still reads what it has, offline, but the server refuses it.
    assert_eq!(b.field(&mail, "login.password"), "settled");
    let (outcome, _) = b.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(matches!(
        outcome,
        Err(CliError::Server(ErrorCode::Unauthorized))
    ));
    // C declines the new identity: the alarm is raised and survives the restart.
    let (outcome, asked) = c.try_run(&["sync"], &[PASSWORD], &["no"], &[]);
    assert!(matches!(
        outcome,
        Err(CliError::Alarm(Alarm::UnconfirmedIdentityChange))
    ));
    assert!(
        asked
            .notes
            .iter()
            .any(|n| n.len() == 30 && n.bytes().all(|b| b.is_ascii_digit()))
    );
    let (outcome, _) = c.try_run(
        &["item", "create", "--type", "note", "--field", "item.name=x"],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Alarm(Alarm::UnconfirmedIdentityChange))
    ));
    assert_eq!(c.items().len(), 7, "reads still work under the alarm");
    // C confirms: the alarm is resolved, and it follows the rotation.
    let (outcome, _) = c.try_run(&["sync"], &[PASSWORD], &["CONFIRM"], &[]);
    outcome.unwrap();
    a.ok(
        &[
            "item",
            "edit",
            &mail,
            "--field",
            "login.username=after-revocation",
        ],
        &[],
    );
    c.ok(&["sync"], &[]);
    assert_eq!(c.field(&mail, "login.username"), "after-revocation");
    c.ok(
        &[
            "item",
            "create",
            "--type",
            "note",
            "--field",
            "item.name=From C",
        ],
        &[],
    );
    a.ok(&["sync"], &[]);
    assert_eq!(a.items().len(), 8);

    // One `rv` per account: a second process on the same cache is "in use".
    {
        let mut script = Script {
            secrets: VecDeque::from([PASSWORD.to_owned()]),
            ..Script::default()
        };
        let mut env = Env {
            data_dir: a.dir.clone(),
            account: None,
            trust: rizzy_cli::tls::Trust::default(),
            ui: &mut script,
        };
        let held = a
            .runtime
            .block_on(rizzy_cli::device::Device::open(&mut env))
            .unwrap();
        let (outcome, _) = a.try_run(&["item", "list"], &[PASSWORD], &[], &[]);
        assert!(matches!(outcome, Err(CliError::InUse)));
        drop(held);
    }

    // B removes itself: confirmed by the word, and then nothing is enrolled there.
    let (outcome, _) = b.try_run(&["device", "forget"], &[PASSWORD], &["no"], &[]);
    assert!(matches!(outcome, Err(CliError::BadInput(_))));
    assert_eq!(b.items().len(), 7);
    let (outcome, forgot) = b.try_run(&["device", "forget"], &[PASSWORD], &["FORGET"], &[]);
    outcome.unwrap();
    assert!(forgot.noted("Removed"));
    let (outcome, _) = b.try_run(&["item", "list"], &[PASSWORD], &[], &[]);
    assert!(matches!(outcome, Err(CliError::NotEnrolled)));
    assert!(std::fs::read_dir(&b.dir).unwrap().next().is_none());

    let _ = std::fs::remove_dir_all(out);
}

/// Opens `rv`'s device through the library, as a command does, with scripted answers.
fn open_device(rv: &Rv, script: &mut Script) -> rizzy_cli::device::Device {
    let mut env = Env {
        data_dir: rv.dir.clone(),
        account: None,
        trust: rizzy_cli::tls::Trust::default(),
        ui: script,
    };
    rv.runtime
        .block_on(rizzy_cli::device::Device::open(&mut env))
        .unwrap()
}

/// Crashes between "secrets before commit" step 3 and step 5 (CRYPTO.md §11; ADR 0026 §2
/// "Signup pending", §4 step 3): a signup whose commit was never sent, a rotation whose
/// commit was never sent, one whose acknowledgement never arrived, and one the account moved
/// past. The process is "killed" by dropping the flow after the step under test; the next
/// command finds the pending state in the cache and settles it.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "four interrupted commits on one account, each settled by the next command"
)]
fn interrupted_commits_are_settled_by_the_next_run() {
    use rizzy_client::rotation::RotationLevel;

    let server = Server::start();
    let origin = server.origin();
    let a = Rv::new("pa");

    // A signup interrupted after the stage-2 cache was written, before the commit was sent.
    let mut script = Script {
        secrets: VecDeque::from([PASSWORD.to_owned(), PASSWORD.to_owned()]),
        ..Script::default()
    };
    {
        let mut env = Env {
            data_dir: a.dir.clone(),
            account: None,
            trust: rizzy_cli::tls::Trust::default(),
            ui: &mut script,
        };
        let prepared = a
            .runtime
            .block_on(rizzy_cli::enrol::prepare_signup(
                &mut env, &origin, "alice", true, false,
            ))
            .unwrap();
        drop(prepared);
    }
    let secret_key = script.printed("Secret Key:");
    let recovery_code = script.printed("Recovery code:");
    // The next command resends the stored body, finalises, and runs.
    let (outcome, listed) = a.try_run(&["item", "list"], &[PASSWORD], &[], &[]);
    outcome.unwrap();
    assert!(listed.noted("Finishing the signup"));
    assert!(listed.out.is_empty());
    // Finished for good: no note the second time, and the device works.
    let created = a.ok(
        &[
            "item",
            "create",
            "--type",
            "note",
            "--field",
            "item.name=First",
        ],
        &[],
    );
    assert!(!created.noted("Finishing the signup"));
    let first = created.out[0].clone();
    let b = Rv::new("pb");
    let (outcome, _) = b.try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap();
    a.ok(&["sync"], &[]);

    // A rotation interrupted after the pending record and the body were written, before the
    // commit was sent: the next run resends the same bytes over a fresh re-authentication.
    let answers = || Script {
        secrets: VecDeque::from([PASSWORD.to_owned(), recovery_code.clone()]),
        ..Script::default()
    };
    {
        let mut script = answers();
        let mut device = open_device(&a, &mut script);
        let flight = a
            .runtime
            .block_on(device.begin_rotation(&mut script, "alice", RotationLevel::Standard, None))
            .unwrap();
        a.runtime
            .block_on(device.persist_rotation(&flight))
            .unwrap();
    }
    // Offline commands still read with the old keys.
    assert_eq!(a.items().len(), 1);
    let (outcome, settled) = a.try_run(&["sync"], &[PASSWORD], &["alice"], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", settled.notes));
    assert!(settled.noted("interrupted"));
    // Settled: the next run asks nothing, and the other device follows the rotation.
    a.ok(&["sync"], &[]);
    b.ok(
        &["item", "edit", &first, "--field", "item.name=After one"],
        &[],
    );
    a.ok(&["sync"], &[]);
    assert_eq!(a.field(&first, "item.name"), "After one");

    // A rotation whose commit the server applied, but whose answer this device never saw:
    // the next run finds the new state and finalises, without sending anything again.
    {
        let mut script = answers();
        let mut device = open_device(&a, &mut script);
        let mut flight = a
            .runtime
            .block_on(device.begin_rotation(&mut script, "alice", RotationLevel::Standard, None))
            .unwrap();
        a.runtime
            .block_on(device.send_rotation(&mut flight))
            .unwrap();
    }
    let (outcome, settled) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", settled.notes));
    b.ok(
        &["item", "edit", &first, "--field", "item.name=After two"],
        &[],
    );
    a.ok(&["sync"], &[]);
    assert_eq!(a.field(&first, "item.name"), "After two");

    // A rotation that was never sent, on an account that then moved on (a new device
    // enrolled): the resend is refused, the pending keys are dropped, nothing was rotated,
    // and a new rotation runs.
    {
        let mut script = answers();
        let mut device = open_device(&a, &mut script);
        let flight = a
            .runtime
            .block_on(device.begin_rotation(&mut script, "alice", RotationLevel::Standard, None))
            .unwrap();
        a.runtime
            .block_on(device.persist_rotation(&flight))
            .unwrap();
    }
    let c = Rv::new("pc");
    let (outcome, _) = c.try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap();
    let (outcome, dropped) = a.try_run(&["sync"], &[PASSWORD], &["alice"], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", dropped.notes));
    assert!(dropped.noted("Nothing was rotated"));
    a.ok(&["sync"], &[]);
    assert_eq!(a.ok(&["device", "list"], &[]).out.len(), 3);
    let (outcome, rotated) = a.try_run(
        &["rotate", "--name", "alice"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", rotated.notes));
    c.ok(
        &["item", "edit", &first, "--field", "item.name=After three"],
        &[],
    );
    b.ok(&["sync"], &[]);
    assert_eq!(b.field(&first, "item.name"), "After three");
}

/// ADR 0031 point 8 for an `rv` signup: a signup interrupted after the stage-2 cache was
/// written, the setup it registered under retired at once (`--grace-days 0`) and the server
/// restarted. The next run resends the stored body, gets `setup_retired`, asks for the
/// password, the login name and the invite, registers again under the current setup, and
/// finishes the signup; the kit it showed is the account's.
#[test]
fn an_interrupted_signup_is_registered_again_after_its_setup_was_retired() {
    let mut server = Server::start();
    let origin = server.origin();
    let a = Rv::new("ra");
    let mut script = Script {
        secrets: VecDeque::from([PASSWORD.to_owned(), PASSWORD.to_owned()]),
        ..Script::default()
    };
    {
        let mut env = Env {
            data_dir: a.dir.clone(),
            account: None,
            trust: rizzy_cli::tls::Trust::default(),
            ui: &mut script,
        };
        let prepared = a
            .runtime
            .block_on(rizzy_cli::enrol::prepare_signup(
                &mut env, &origin, "alice", true, false,
            ))
            .unwrap();
        drop(prepared);
    }
    let secret_key = script.printed("Secret Key:");
    server.retire_first_setup();

    // The password, then an empty invite; the login name is a line.
    let (outcome, listed) = a.try_run(&["item", "list"], &[PASSWORD, ""], &["alice"], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", listed.notes));
    assert!(listed.noted("Finishing the signup"), "{:?}", listed.notes);
    assert!(
        listed.noted("retired the login setup"),
        "{:?}",
        listed.notes
    );
    // Finished for good, and the record is on the current setup: a second device logs in
    // with the kit the interrupted signup showed.
    let created = a.ok(
        &[
            "item",
            "create",
            "--type",
            "note",
            "--field",
            "item.name=One",
        ],
        &[],
    );
    assert!(!created.noted("Finishing the signup"));
    let b = Rv::new("rb");
    log_in(&b, &origin, "alice", &secret_key);
    assert_eq!(b.items().len(), 1);
}

/// The new master password of an interrupted password change.
const NEW_PASSWORD: &str = "tremble lantern orbit vintage";

/// The credential change [`interrupt_change`] leaves pending.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Interrupted {
    /// `rv password` (no rotation): a new master password.
    Password,
    /// `rv secret-key` (with its default rotation): a new Secret Key.
    SecretKey,
}

impl Interrupted {
    /// The master password once the change is applied.
    const fn new_password(self) -> &'static str {
        match self {
            Self::Password => NEW_PASSWORD,
            Self::SecretKey => PASSWORD,
        }
    }
}

/// Signs `name` up on `rv` with one note, then runs `change` with its commit lost on the way
/// to the server (`Fault::NeverSent`: a gateway's `502`, so the outcome is unknown and the
/// pending record and the commit body stay saved). Returns the Secret Key that logs in once the
/// change is applied.
fn interrupt_change(
    rv: &Rv,
    proxy: &Proxy,
    origin: &str,
    name: &str,
    change: Interrupted,
) -> String {
    use rizzy_client::rizzy_proto::http::paths;

    let (secret_key, _) = sign_up(rv, origin, name);
    create_note(rv, "Kept");
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::NeverSent);
    let (outcome, lost) = match change {
        Interrupted::Password => rv.try_run(
            &["password", "--name", name],
            &[PASSWORD, NEW_PASSWORD, NEW_PASSWORD],
            &[],
            &[],
        ),
        Interrupted::SecretKey => {
            rv.try_run(&["secret-key", "--name", name], &[PASSWORD], &[], &[])
        }
    };
    assert!(proxy.fired());
    assert!(outcome.is_err(), "{outcome:?}");
    assert!(lost.noted("stays saved"), "{:?}", lost.notes);
    match change {
        Interrupted::Password => secret_key,
        Interrupted::SecretKey => lost.printed("Secret Key:"),
    }
}

/// ADR 0031 point 8 and CRYPTO.md §11 "Secrets before commit" for `rv`: an interrupted password
/// change and an interrupted Secret Key change, then `secrets rotate` and a restart. Each
/// device's record is still on the old, accepted setup, so its device authentication answers
/// `reregister`. The next run settles the pending change **first**: it logs in on the old setup
/// and resends the stored commit byte for byte, which the server takes (its echoed setup is
/// loaded and not retired). Only then, with nothing pending, does the same-password
/// re-registration of point 2 move the record to the current setup, with the new credentials.
/// Re-registering first would take the `state_seq + 1` the stored commit was signed for, and the
/// change would be refused and dropped. Proven by retiring the old setup afterwards: a new
/// device still logs in with the changed credentials.
#[test]
fn interrupted_credential_changes_are_resent_before_the_record_moves_to_a_new_setup() {
    let (proxy, mut server) = Proxy::start();
    let origin = server.origin();
    let accounts = [
        (Rv::new("sa"), "alice", Interrupted::Password),
        (Rv::new("sb"), "bob", Interrupted::SecretKey),
    ];
    let keys: Vec<String> = accounts
        .iter()
        .map(|(rv, name, change)| interrupt_change(rv, &proxy, &origin, name, *change))
        .collect();
    server.admin(&["secrets", "rotate"]);

    for (rv, name, change) in &accounts {
        let new_password = change.new_password();
        let (outcome, settled) = rv.try_run(&["sync"], &[PASSWORD, new_password], &[name], &[]);
        outcome.unwrap_or_else(|e| panic!("{change:?}: {e:?}: {:?}", settled.notes));
        assert!(settled.noted("was interrupted"), "{:?}", settled.notes);
        assert!(!settled.noted("NOT made"), "{:?}", settled.notes);
        assert!(!settled.noted("did not work"), "{:?}", settled.notes);
        // Settled for good: the device opens with the new password and asks nothing more.
        let (outcome, again) = rv.try_run(&["sync"], &[new_password], &[], &[]);
        outcome.unwrap_or_else(|e| panic!("{change:?}: {e:?}: {:?}", again.notes));
        let (outcome, listed) = rv.try_run(&["item", "list"], &[new_password], &[], &[]);
        outcome.unwrap_or_else(|e| panic!("{change:?}: {e:?}: {:?}", listed.notes));
        assert_eq!(listed.out.len(), 1);
    }

    // The old setup goes; a record still on it would answer every login like an unknown name.
    server.admin(&["secrets", "retire-setups", "--grace-days", "0"]);
    for ((_, name, change), secret_key) in accounts.iter().zip(&keys) {
        let fresh = Rv::new("sn");
        let (outcome, login) = fresh.try_run(
            &["login", "--server", &origin, "--name", name],
            &[secret_key, change.new_password()],
            &[],
            &[],
        );
        outcome.unwrap_or_else(|e| panic!("{change:?}: login: {e:?}: {:?}", login.notes));
    }
}

/// ADR 0031 points 7 and 8 for an interrupted password change and an interrupted Secret Key
/// change in `rv`, after the accounts' own setup was retired at once and the server restarted:
/// neither change was applied, and neither can be resent, because a credential change needs a
/// fresh OPAQUE session and the retired record no longer answers a login. Moving the record
/// first with the same-password re-registration (allowed over the device session) would take
/// the `state_seq + 1` the stored commit was signed for, so the commit would be refused and the
/// change dropped. The change is therefore kept untouched, every run says so, nothing moves the
/// record, and the device still opens with the current password. (The case is reported to the
/// owner: ADR 0031 has no rule that settles it.)
#[test]
fn interrupted_credential_changes_on_a_retired_setup_are_kept() {
    let (proxy, mut server) = Proxy::start();
    let origin = server.origin();
    let accounts = [
        (Rv::new("rc"), "alice", Interrupted::Password),
        (Rv::new("rd"), "bob", Interrupted::SecretKey),
    ];
    for (rv, name, change) in &accounts {
        interrupt_change(rv, &proxy, &origin, name, *change);
    }
    server.retire_first_setup();

    for (rv, name, change) in &accounts {
        for _ in 0..2 {
            let (outcome, kept) =
                rv.try_run(&["sync"], &[PASSWORD, change.new_password()], &[name], &[]);
            assert!(
                matches!(outcome, Err(CliError::Server(ErrorCode::SetupRetired))),
                "{change:?}: {outcome:?}: {:?}",
                kept.notes
            );
            assert!(kept.noted("cannot be sent"), "{:?}", kept.notes);
            assert!(!kept.noted("NOT made"), "{:?}", kept.notes);
        }
        // Nothing was dropped or moved: the device still opens offline with the current
        // password, and the pending change is still there for the next run.
        assert_eq!(rv.items().len(), 1);
    }
}

/// The cache file of the one account enrolled in `rv`'s data directory.
fn cache_file(rv: &Rv) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(&rv.dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sqlite3"))
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    files.remove(0)
}

/// Signs `name` up on `rv` and returns the Secret Key and the recovery code of its kit.
fn sign_up(rv: &Rv, origin: &str, name: &str) -> (String, String) {
    let (outcome, signup) = rv.try_run(
        &["signup", "--server", origin, "--name", name],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("signup failed: {e:?}; {:?}", signup.notes));
    (
        signup.printed("Secret Key:"),
        signup.printed("Recovery code:"),
    )
}

/// Logs a new device in.
fn log_in(rv: &Rv, origin: &str, name: &str, secret_key: &str) {
    let (outcome, login) = rv.try_run(
        &["login", "--server", origin, "--name", name],
        &[secret_key, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("login failed: {e:?}; {:?}", login.notes));
}

/// Creates a note named `name` and returns its id.
fn create_note(rv: &Rv, name: &str) -> String {
    let field = format!("item.name={name}");
    rv.ok(
        &["item", "create", "--type", "note", "--field", &field],
        &[],
    )
    .out[0]
        .clone()
}

/// ADR 0026 §4 step 7 and the owner's decision on open question 5, through `rv`: a cache file
/// put back from an older copy (a restored image, a copied profile) raises the alarm at the
/// next Fetch, the alarm survives a restart, nothing is written or signed under it, and the
/// only way on is `rv device forget` (allowed under this one alarm) and a new login.
#[test]
fn an_older_copy_of_the_device_state_raises_the_alarm_and_ends_in_re_enrolment() {
    let server = Server::start();
    let origin = server.origin();
    let a = Rv::new("oa");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    let first = create_note(&a, "First");

    // The copy, then more of this device's own history on the server.
    let file = cache_file(&a);
    let older = std::fs::read(&file).unwrap();
    let second = create_note(&a, "Second");
    assert_eq!(a.items().len(), 2);
    std::fs::write(&file, &older).unwrap();

    // Offline, the older copy reads as what it is.
    assert_eq!(a.items().len(), 1);
    // Online, the server holds own dots the file lacks: alarm 4, read-only.
    let (outcome, _) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(
        matches!(outcome, Err(CliError::Alarm(Alarm::DeviceStateOutdated))),
        "{outcome:?}"
    );
    // The alarm is in the file: the next run is read-only too, before any request.
    let (outcome, _) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(matches!(
        outcome,
        Err(CliError::Alarm(Alarm::DeviceStateOutdated))
    ));
    let (outcome, _) = a.try_run(
        &["item", "create", "--type", "note", "--field", "item.name=x"],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Alarm(Alarm::DeviceStateOutdated))
    ));
    let (outcome, _) = a.try_run(
        &["item", "edit", &first, "--field", "item.name=y"],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Alarm(Alarm::DeviceStateOutdated))
    ));
    assert_eq!(a.items().len(), 1, "reads still work under the alarm");

    // Removal is this alarm's one resolution: allowed, behind the word.
    let (outcome, _) = a.try_run(&["device", "forget"], &[PASSWORD], &["no"], &[]);
    assert!(matches!(outcome, Err(CliError::BadInput(_))));
    assert!(file.exists());
    let (outcome, forgot) = a.try_run(&["device", "forget"], &[PASSWORD], &["FORGET"], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", forgot.notes));
    assert!(forgot.noted("Removed"));
    assert!(!file.exists());

    // Re-enrolment: a new device, which holds everything the old one had uploaded.
    log_in(&a, &origin, "alice", &secret_key);
    let items = a.items();
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|(id, _)| *id == second));
    create_note(&a, "Third");
    assert_eq!(a.items().len(), 3);
}

/// ADR 0026 §5 and the owner's decision on open question 6, through `rv`: `device forget` on
/// a device that is still enrolled uploads its unsent own ops before the file is deleted, so
/// another device sees the edit; and it is refused while a rollback or fork alarm is raised,
/// also when the cache does not unlock (a wrong password is not a way to delete the evidence).
#[test]
fn forget_uploads_unsent_edits_first_and_is_refused_under_an_alarm() {
    use rizzy_client::store::rows::Changeset;

    let mut server = Server::start();
    let origin = server.origin();
    let a = Rv::new("fa");
    let b = Rv::new("fb");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    log_in(&b, &origin, "alice", &secret_key);

    // An edit made on B while the server is away: queued in B's cache only.
    server.stop();
    let (outcome, offline) = b.try_run(
        &[
            "item",
            "create",
            "--type",
            "note",
            "--field",
            "item.name=Written offline",
        ],
        &[PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap();
    assert!(offline.noted("Saved on this device"));
    let queued = offline.out[0].clone();
    server.restart();

    // B removes itself: the queued op is uploaded, as signed, before the file goes.
    let (outcome, forgot) = b.try_run(&["device", "forget"], &[PASSWORD], &["FORGET"], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", forgot.notes));
    assert!(
        forgot.noted("Every change made on this device is on the server"),
        "{:?}",
        forgot.notes
    );
    assert!(std::fs::read_dir(&b.dir).unwrap().next().is_none());
    a.ok(&["sync"], &[]);
    let items = a.items();
    assert_eq!(
        items,
        vec![(queued, "note              Written offline".to_owned())]
    );

    // A fork alarm in A's cache, written as the flow that detects one writes it.
    let file = cache_file(&a);
    a.runtime.block_on(async {
        let mut db = rizzy_cli::db::Db::open(&file).await.unwrap();
        let alarm: Changeset =
            [rizzy_client::store::alarm_write(Alarm::Fork, &[b"one state", b"another"]).unwrap()]
                .into_iter()
                .collect();
        db.write(&alarm).await.unwrap();
        db.close().await;
    });
    let (outcome, _) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(matches!(outcome, Err(CliError::Alarm(Alarm::Fork))));
    assert_eq!(a.items().len(), 1, "reads still work under the alarm");
    // Removal is refused and names the alarm: with the password…
    let (outcome, _) = a.try_run(&["device", "forget"], &[PASSWORD], &["FORGET"], &[]);
    assert!(matches!(outcome, Err(CliError::Alarm(Alarm::Fork))));
    // …and without it. The alarm rows are cleartext; no key is needed to see them.
    let (outcome, refused) = a.try_run(
        &["device", "forget"],
        &["not the password"],
        &["FORGET"],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Alarm(Alarm::Fork))),
        "{outcome:?}"
    );
    assert!(refused.noted("could not be opened"));
    assert!(!refused.noted("Removed"));
    assert!(file.exists());
    assert_eq!(a.items().len(), 1);
}

/// CRYPTO.md §11 "Secrets before commit" and ADR 0028 "Retry after an unknown outcome",
/// behind a reverse proxy that answers `502` to a commit: the answer is no refusal, so the
/// stage-2 signup and the pending rotation stay in the cache, whether the server applied the
/// commit or never saw it, and the next run settles them. Nothing is dropped, and the kit is
/// not called void.
#[test]
fn a_gateway_error_on_a_commit_keeps_what_was_saved_for_it() {
    use rizzy_client::rizzy_proto::http::paths;

    let (proxy, server) = Proxy::start();
    let origin = server.origin();

    // A signup the server registered, whose answer a gateway replaced.
    let a = Rv::new("ga");
    proxy.arm(paths::REGISTER_FINISH, Fault::AnswerLost);
    let (outcome, signup) = a.try_run(
        &["signup", "--server", &origin, "--name", "alice"],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadAnswer)), "{outcome:?}");
    assert!(proxy.fired());
    assert!(signup.noted("stays valid") && !signup.noted("void"));
    let secret_key = signup.printed("Secret Key:");
    let recovery_code = signup.printed("Recovery code:");
    assert!(cache_file(&a).exists());
    // The next command resends the stored body; the repeat is a success, and the device works.
    let (outcome, listed) = a.try_run(&["item", "list"], &[PASSWORD], &[], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", listed.notes));
    assert!(listed.noted("Finishing the signup"));
    let first = create_note(&a, "First");
    // The kit that was shown is the account's: a second device logs in with it.
    let b = Rv::new("gb");
    log_in(&b, &origin, "alice", &secret_key);
    assert_eq!(b.items().len(), 1);

    // A signup the server never saw: the same answer, the same rule, and the resend registers.
    let c = Rv::new("gc");
    proxy.arm(paths::REGISTER_FINISH, Fault::NeverSent);
    let (outcome, signup) = c.try_run(
        &["signup", "--server", &origin, "--name", "carol"],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadAnswer)), "{outcome:?}");
    assert!(signup.noted("stays valid"));
    let (outcome, listed) = c.try_run(&["item", "list"], &[PASSWORD], &[], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", listed.notes));
    assert!(listed.noted("Finishing the signup"));
    create_note(&c, "Carol's");

    // A rotation the server applied, whose answer a gateway replaced: the pending record
    // stays, and the next run finds the new state and finalises without sending again.
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, rotated) = a.try_run(
        &["rotate", "--name", "alice"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadAnswer)), "{outcome:?}");
    assert!(proxy.fired());
    assert!(rotated.noted("stays saved"), "{:?}", rotated.notes);
    assert_eq!(a.items().len(), 1, "offline reads go on with the old keys");
    let commits = proxy.count(paths::ACCOUNT_COMMIT);
    let (outcome, settled) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", settled.notes));
    assert_eq!(proxy.count(paths::ACCOUNT_COMMIT), commits);
    // The rotator holds the new account key: it reads what the follower writes after it.
    b.ok(
        &["item", "edit", &first, "--field", "item.name=After one"],
        &[],
    );
    a.ok(&["sync"], &[]);
    assert_eq!(a.field(&first, "item.name"), "After one");

    // A rotation the server never saw: the pending record stays, and the next run sends the
    // same bytes again over a fresh re-authentication.
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::NeverSent);
    let (outcome, rotated) = a.try_run(
        &["rotate", "--name", "alice"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadAnswer)), "{outcome:?}");
    assert!(rotated.noted("stays saved"));
    let commits = proxy.count(paths::ACCOUNT_COMMIT);
    let (outcome, settled) = a.try_run(&["sync"], &[PASSWORD], &["alice"], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", settled.notes));
    assert!(settled.noted("sending it again"));
    assert_eq!(proxy.count(paths::ACCOUNT_COMMIT), commits + 1);
    b.ok(
        &["item", "edit", &first, "--field", "item.name=After two"],
        &[],
    );
    a.ok(&["sync"], &[]);
    assert_eq!(a.field(&first, "item.name"), "After two");
}

/// ADR 0025 §2 step 5 and ADR 0026 §4 step 4, through `rv`: a server that answers a
/// rotation's commit with `state_conflict` and then shows an older `account-state` on the
/// retry rule's query is a possible rollback. The alarm is written when it is detected, the
/// device is read-only across restarts, and the file (the evidence) cannot be removed.
#[test]
fn a_rollback_shown_during_a_rotation_retry_raises_the_alarm() {
    use rizzy_client::rizzy_proto::http::paths;

    let (proxy, server) = Proxy::start();
    let origin = server.origin();
    let a = Rv::new("ra");
    // The signup's first sync fetches `account/state`: the proxy keeps that answer.
    let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");
    create_note(&a, "First");
    // The account moves on (a second device enrols), and A pins the newer state.
    let b = Rv::new("rb");
    log_in(&b, &origin, "alice", &secret_key);
    a.ok(&["sync"], &[]);

    proxy.arm(paths::ACCOUNT_COMMIT, Fault::ConflictThenOldState);
    let (outcome, rotated) = a.try_run(
        &["rotate", "--name", "alice"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Alarm(Alarm::Rollback))),
        "{outcome:?}: {:?}",
        rotated.notes
    );
    assert!(proxy.fired());

    // A restart does not lift it: read-only before any request, reads still work.
    let (outcome, _) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(matches!(outcome, Err(CliError::Alarm(Alarm::Rollback))));
    let (outcome, _) = a.try_run(
        &["item", "create", "--type", "note", "--field", "item.name=x"],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Alarm(Alarm::Rollback))));
    assert_eq!(a.items().len(), 1);
    // The file is the evidence: not removed, with or without the password.
    let file = cache_file(&a);
    for password in [PASSWORD, "not the password"] {
        let (outcome, _) = a.try_run(&["device", "forget"], &[password], &["FORGET"], &[]);
        assert!(
            matches!(outcome, Err(CliError::Alarm(Alarm::Rollback))),
            "{outcome:?}"
        );
        assert!(file.exists());
    }
    // The other device, which was shown no rollback, is untouched.
    b.ok(&["sync"], &[]);
    assert_eq!(b.items().len(), 1);
}

/// CRYPTO.md §11.3 step 3.2 while a pending rotation is settled: this device's standard
/// rotation was applied and its answer lost, and another device then made a full rotation.
/// The pending keys are finalised (the account is built on them), but the identity change in
/// the answer is the other device's, not this rotation's own: its fingerprint is shown and
/// must be confirmed here, as at any other unlock.
#[test]
fn settling_a_pending_rotation_does_not_confirm_another_devices_identity_change() {
    use rizzy_client::rizzy_proto::http::paths;

    let (proxy, server) = Proxy::start();
    let origin = server.origin();
    let a = Rv::new("ia");
    let b = Rv::new("ib");
    let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");
    let first = create_note(&a, "First");
    log_in(&b, &origin, "alice", &secret_key);
    a.ok(&["sync"], &[]);

    // A's standard rotation: applied by the server, the answer lost.
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, _) = a.try_run(
        &["rotate", "--name", "alice"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadAnswer)), "{outcome:?}");
    // B follows it through its grant, then rotates the identity keys too.
    b.ok(&["sync"], &[]);
    let (outcome, rotated) = b.try_run(
        &["rotate", "--name", "alice", "--full"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", rotated.notes));

    // A restarts with its pending record. Declining the fingerprint raises the alarm…
    let (outcome, asked) = a.try_run(&["sync"], &[PASSWORD], &["no"], &[]);
    assert!(
        matches!(
            outcome,
            Err(CliError::Alarm(Alarm::UnconfirmedIdentityChange))
        ),
        "{outcome:?}: {:?}",
        asked.notes
    );
    assert!(
        asked
            .notes
            .iter()
            .any(|n| n.len() == 30 && n.bytes().all(|b| b.is_ascii_digit())),
        "the new fingerprint is shown: {:?}",
        asked.notes
    );
    let (outcome, _) = a.try_run(
        &["item", "create", "--type", "note", "--field", "item.name=x"],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Alarm(Alarm::UnconfirmedIdentityChange))
    ));
    // …and confirming it settles the rotation and follows the other one.
    let (outcome, settled) = a.try_run(&["sync"], &[PASSWORD], &["CONFIRM"], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", settled.notes));
    b.ok(
        &["item", "edit", &first, "--field", "item.name=After both"],
        &[],
    );
    a.ok(&["sync"], &[]);
    assert_eq!(a.field(&first, "item.name"), "After both");

    // A's own full rotation, applied with the answer lost: the served state is the stored
    // commit's, so the identity change is provably this device's and is not asked about
    // (the script holds no answer; a prompt would fail the run).
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, _) = a.try_run(
        &["rotate", "--name", "alice", "--full"],
        &[PASSWORD, &recovery_code],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadAnswer)), "{outcome:?}");
    let (outcome, settled) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
    outcome.unwrap_or_else(|e| panic!("{e:?}: {:?}", settled.notes));
    // The other device is asked, as for any identity change it did not make.
    let (outcome, _) = b.try_run(&["sync"], &[PASSWORD], &["CONFIRM"], &[]);
    outcome.unwrap();
    a.ok(
        &["item", "edit", &first, "--field", "item.name=After three"],
        &[],
    );
    b.ok(&["sync"], &[]);
    assert_eq!(b.field(&first, "item.name"), "After three");
}

impl Server {
    /// `rizzy-vault backup` next to the running server, into a new file in its directory.
    fn backup(&self, name: &str) -> PathBuf {
        let file = self.dir.join(name);
        let backup = Self::command(&self.dir, self.port, &self.origin)
            .args(["backup", "--out"])
            .arg(&file)
            .output()
            .unwrap();
        assert!(
            backup.status.success(),
            "{}",
            String::from_utf8_lossy(&backup.stderr)
        );
        file
    }

    /// The operator's restore (self-hosting.md §9): stop the server, empty the database,
    /// `rizzy-vault restore` the backup (a new restore generation, a reconciliation epoch),
    /// start the server again.
    fn restore_from(&mut self, backup: &Path) {
        self.stop();
        let data = self.dir.join("data");
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let restore = Self::command(&self.dir, self.port, &self.origin)
            .args(["restore", "--in"])
            .arg(backup)
            .output()
            .unwrap();
        assert!(
            restore.status.success(),
            "{}",
            String::from_utf8_lossy(&restore.stderr)
        );
        self.child = Self::spawn(&self.dir, self.port, &self.origin);
    }
}

/// ADR 0021 §9 "Server behind", "Healing request" through `rv`, against a real server restored
/// from an older backup: the edits made after the backup are lost on the server, the device
/// that made them finds the server behind at its next sync, heals it with one request, and
/// writes again; another device then reads every edit.
#[test]
fn a_server_restored_from_an_older_backup_is_healed_by_the_next_sync() {
    let mut server = Server::start();
    let origin = server.origin();
    let a = Rv::new("ha");
    let b = Rv::new("hb");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    log_in(&b, &origin, "alice", &secret_key);
    let first = create_note(&a, "First");
    b.ok(&["sync"], &[]);
    let backup = server.backup("before.rvbackup");

    // After the backup: an edit and a new item (a new item key), both uploaded.
    a.ok(
        &["item", "edit", &first, "--field", "item.name=First, edited"],
        &[],
    );
    let second = create_note(&a, "Second");
    server.restore_from(&backup);

    // A's next sync finds the server behind (its acknowledged own ops and an item-key wrap
    // are gone), heals it and syncs on.
    let healed = a.ok(&["sync"], &[]);
    assert!(healed.noted("Sending them back"), "{:?}", healed.notes);
    assert!(
        healed.noted("has the lost changes again"),
        "{:?}",
        healed.notes
    );
    // Writable again: a third item goes up on top of the healed chain.
    let third = create_note(&a, "Third");
    let synced = a.ok(&["sync"], &[]);
    assert!(!synced.noted("Sending them back"));

    // B reads everything, the edit included, from the healed server.
    b.ok(&["sync"], &[]);
    let items = b.items();
    assert_eq!(items.len(), 3, "{items:?}");
    for id in [&first, &second, &third] {
        assert!(items.iter().any(|(i, _)| i == id), "{id} in {items:?}");
    }
    assert_eq!(b.field(&first, "item.name"), "First, edited");
}

impl Server {
    /// The operator's native copy (self-hosting.md: the fallback for disk loss): the server
    /// stopped, its data directory copied aside, the server started again.
    fn native_copy(&mut self, name: &str) -> PathBuf {
        self.stop();
        let copy = self.dir.join(name);
        copy_tree(&self.dir.join("data"), &copy);
        self.child = Self::spawn(&self.dir, self.port, &self.origin);
        copy
    }

    /// Puts a native copy back in place: no `rizzy-vault restore`, so no new restore
    /// generation and no reconciliation epoch (the drill's step 8 in `rizzy-server`).
    fn native_restore(&mut self, copy: &Path) {
        self.stop();
        let data = self.dir.join("data");
        std::fs::remove_dir_all(&data).unwrap();
        copy_tree(copy, &data);
        self.child = Self::spawn(&self.dir, self.port, &self.origin);
    }
}

/// Copies the files of `from` into a new directory `to`, recursively.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// ADR 0012 §7 "Healing a server rollback" steps 1–3 and "A device enrolled after the backup"
/// through `rv`, against a server put back with `rizzy-vault restore` (a reconciliation epoch,
/// INV-59): after the backup a second device enrols (a newer `account-state`) and both devices
/// write. The device the restored server does not know authenticates with its certificate, the
/// account state, the bundle chain and the device set, re-publishes the newer state and its
/// edits, and leaves the rollback alarm; the first device then finds its state on the server
/// again and heals its vault. Both keep working and read each other's edits.
#[test]
fn a_restored_server_takes_back_the_account_state_and_a_device_enrolled_after_the_backup() {
    let mut server = Server::start();
    let origin = server.origin();
    let a = Rv::new("raa");
    let b = Rv::new("rab");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    let first = create_note(&a, "First");
    let backup = server.backup("before.rvbackup");

    // After the backup: B enrols (the account state moves on), both write, both sync.
    log_in(&b, &origin, "alice", &secret_key);
    let from_b = create_note(&b, "From B");
    a.ok(&["sync"], &[]);
    let from_a = create_note(&a, "From A");
    b.ok(&["sync"], &[]);
    assert_eq!(b.items().len(), 3);
    server.restore_from(&backup);

    // B is unknown to the restored server and its state is behind B's: B authenticates with
    // its certificate, re-publishes the account state, and heals the vault.
    let healed = b.ok(&["sync"], &[]);
    for note in [
        "did not know this device",
        "Sending the newer one back",
        "holds this device's account state again",
        "has the lost changes again",
    ] {
        assert!(healed.noted(note), "{note}: {:?}", healed.notes);
    }
    // A is in the restored device set and finds the newest state again (B re-published it);
    // its own lost edit goes back with the vault healing.
    let synced = a.ok(&["sync"], &[]);
    assert!(
        !synced.noted("Sending the newer one back"),
        "{:?}",
        synced.notes
    );

    // Both write on the healed server and read each other.
    let after_a = create_note(&a, "After, from A");
    b.ok(
        &["item", "edit", &first, "--field", "item.name=First, from B"],
        &[],
    );
    a.ok(&["sync"], &[]);
    b.ok(&["sync"], &[]);
    for rv in [&a, &b] {
        let items = rv.items();
        assert_eq!(items.len(), 4, "{items:?}");
        for id in [&first, &from_a, &from_b, &after_a] {
            assert!(items.iter().any(|(i, _)| i == id), "{id} in {items:?}");
        }
        assert_eq!(rv.field(&first, "item.name"), "First, from B");
    }
    // A sync on each finds nothing left to heal.
    for rv in [&a, &b] {
        let quiet = rv.ok(&["sync"], &[]);
        assert!(!quiet.noted("Sending"), "{:?}", quiet.notes);
    }
}

/// The other order: the device of the restored set heals first, which ends the reconciliation
/// epoch (ADR 0012 §7 "End of the reconciliation epoch"); the certificates it re-published let
/// the device enrolled after the backup authenticate as any known device.
#[test]
fn a_restored_server_healed_first_by_a_device_of_the_restored_set() {
    let mut server = Server::start();
    let origin = server.origin();
    let a = Rv::new("rfa");
    let b = Rv::new("rfb");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    let backup = server.backup("before.rvbackup");
    log_in(&b, &origin, "alice", &secret_key);
    let from_b = create_note(&b, "From B");
    a.ok(&["sync"], &[]);
    server.restore_from(&backup);

    let healed = a.ok(&["sync"], &[]);
    assert!(
        healed.noted("holds this device's account state again"),
        "{:?}",
        healed.notes
    );
    // B is known again: no certificate shown; its lost edit goes back with the vault.
    let synced = b.ok(&["sync"], &[]);
    assert!(
        !synced.noted("did not know this device"),
        "{:?}",
        synced.notes
    );
    let after_b = create_note(&b, "After, from B");
    a.ok(&["sync"], &[]);
    let items = a.items();
    for id in [&from_b, &after_b] {
        assert!(items.iter().any(|(i, _)| i == id), "{id} in {items:?}");
    }
}

/// The negative of the test above: the server is put back from a native copy, so it opens no
/// reconciliation epoch, and the older account state it serves is, for the devices, a genuine
/// rollback. The device holding the newer state raises the alarm and re-publishes, the server
/// refuses it, and the alarm stays across runs (read-only, reads still work); the device
/// enrolled after the copy gets no session from its certificate.
#[test]
fn a_rollback_outside_a_reconciliation_epoch_stays_an_alarm() {
    let mut server = Server::start();
    let origin = server.origin();
    let a = Rv::new("rna");
    let b = Rv::new("rnb");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    create_note(&a, "First");
    let copy = server.native_copy("native-copy");
    log_in(&b, &origin, "alice", &secret_key);
    a.ok(&["sync"], &[]);
    server.native_restore(&copy);

    for _ in 0..2 {
        let (outcome, run) = a.try_run(&["sync"], &[PASSWORD], &[], &[]);
        assert!(
            matches!(outcome, Err(CliError::Alarm(Alarm::Rollback))),
            "{outcome:?}: {:?}",
            run.notes
        );
        assert!(run.noted("refused"), "{:?}", run.notes);
    }
    let (outcome, _) = a.try_run(
        &["item", "create", "--type", "note", "--field", "item.name=x"],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Alarm(Alarm::Rollback))));
    assert_eq!(a.items().len(), 1);

    let (outcome, run) = b.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}: {:?}",
        run.notes
    );
}

/// ADR 0018 §6 "List elements" through `rv item edit`: URIs and custom fields of an existing
/// item are added, changed and removed (removal clears every attribute the item holds), tags
/// added and removed; a hidden custom field's value is asked for and never taken from the
/// command line; another device sees the result.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one item through every list option of item edit, then a second device"
)]
fn item_edit_adds_changes_and_removes_uris_custom_fields_and_tags() {
    let server = Server::start();
    let origin = server.origin();
    let a = Rv::new("la");
    let b = Rv::new("lb");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    let item = a
        .ok(
            &[
                "item",
                "create",
                "--type",
                "login",
                "--field",
                "item.name=Mail",
                "--uri",
                "https://one.example",
                "--custom",
                "Account=1234",
                "--tag",
                "work",
            ],
            &[],
        )
        .out[0]
        .clone();
    // The element ids, as `item show` prints them in the keys.
    let element = |rv: &Rv, list: &str, attribute: &str, value: &str| -> Option<String> {
        rv.ok(&["item", "show", &item, "--reveal"], &[])
            .out
            .iter()
            .find_map(|line| {
                let rest = line.strip_prefix(&format!("{list}/"))?;
                let (id, tail) = rest.split_once('/')?;
                (tail == format!("{attribute}: {value}")).then(|| id.to_owned())
            })
    };
    let one = element(&a, "uri", "value", "https://one.example").unwrap();
    let account = element(&a, "field", "label", "Account").unwrap();

    // Add a URI and a hidden field, change the first URI and the text field, untag.
    a.ok(
        &[
            "item",
            "edit",
            &item,
            "--uri",
            "https://two.example",
            "--set-uri",
            &format!("{}=https://one.example/login", &one[..6]),
            "--set-custom",
            &format!("{account}=5678"),
            "--custom-secret",
            "PIN",
            "--untag",
            "work",
            "--tag",
            "home",
        ],
        &["0000"],
    );
    let shown = a.ok(&["item", "show", &item, "--reveal"], &[]);
    let pin = element(&a, "field", "label", "PIN").unwrap();
    assert!(
        shown
            .out
            .iter()
            .any(|l| l == &format!("field/{pin}/value: 0000"))
    );
    assert!(
        shown
            .out
            .iter()
            .any(|l| l == &format!("field/{account}/value: 5678"))
    );
    assert!(shown.out.iter().any(|l| l == "tag home: true"));
    assert!(!shown.out.iter().any(|l| l.starts_with("tag work")));
    assert!(element(&a, "uri", "value", "https://one.example/login").is_some());
    let two = element(&a, "uri", "value", "https://two.example").unwrap();
    // Concealed without --reveal.
    let hidden = a.ok(&["item", "show", &item], &[]);
    assert!(
        hidden
            .out
            .iter()
            .any(|l| l == &format!("field/{pin}/value: ********"))
    );

    // A hidden field's value never comes from the command line.
    let (outcome, _) = a.try_run(
        &["item", "edit", &item, "--set-custom", &format!("{pin}=1")],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Usage(_))), "{outcome:?}");
    a.ok(
        &["item", "edit", &item, "--set-custom-secret", &pin],
        &["9999"],
    );
    assert!(
        a.ok(&["item", "show", &item, "--reveal"], &[])
            .out
            .iter()
            .any(|l| l == &format!("field/{pin}/value: 9999"))
    );

    // Remove the first URI and the text field: every attribute is cleared, so neither shows.
    a.ok(
        &[
            "item",
            "edit",
            &item,
            "--remove-uri",
            &one,
            "--remove-custom",
            &account,
        ],
        &[],
    );
    let shown = a.ok(&["item", "show", &item, "--reveal"], &[]);
    assert!(
        !shown.out.iter().any(|l| l.contains(&one)),
        "{:?}",
        shown.out
    );
    assert!(
        !shown.out.iter().any(|l| l.contains(&account)),
        "{:?}",
        shown.out
    );
    assert!(shown.out.iter().any(|l| l.contains(&two)));
    // Removing it again names no element.
    let (outcome, _) = a.try_run(
        &["item", "edit", &item, "--remove-uri", &one],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadInput(_))), "{outcome:?}");
    // The edit-only options are refused on create.
    let (outcome, _) = a.try_run(
        &["item", "create", "--type", "login", "--remove-uri", "ab"],
        &[],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Usage(_))), "{outcome:?}");

    // Another device sees the same item.
    log_in(&b, &origin, "alice", &secret_key);
    let on_b = b.ok(&["item", "show", &item, "--reveal"], &[]);
    let on_a = a.ok(&["item", "show", &item, "--reveal"], &[]);
    assert_eq!(on_b.out, on_a.out);
}

/// ADR 0018 §6 "List order" through `rv item edit --move-uri` and `--move-custom`: moves to
/// the first or last place and next to another element, several in one command with an
/// addition and a removal; two devices that move different URIs to the same place write equal
/// keys, and a move between those two rewrites the list's `order` keys evenly; the refusals;
/// another device sees the same order.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one item through every move, then a concurrent move and the rewrite"
)]
fn item_edit_moves_uris_and_custom_fields() {
    let server = Server::start();
    let origin = server.origin();
    let a = Rv::new("ma");
    let b = Rv::new("mb");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    let item = a
        .ok(
            &[
                "item",
                "create",
                "--type",
                "login",
                "--field",
                "item.name=Mail",
                "--uri",
                "https://one.example",
                "--uri",
                "https://two.example",
                "--uri",
                "https://three.example",
                "--custom",
                "A=1",
                "--custom",
                "B=2",
            ],
            &[],
        )
        .out[0]
        .clone();
    log_in(&b, &origin, "alice", &secret_key);
    // A list in order, as `item show` prints it: the element ids, each with its value (URIs) or
    // label (custom fields).
    let listed = |rv: &Rv, list: &str| -> Vec<(String, String)> {
        let shown = rv.ok(&["item", "show", &item, "--reveal"], &[]);
        let attribute = if list == "uri" { "value" } else { "label" };
        shown
            .printed(&format!("order of {list}:"))
            .split(' ')
            .map(|id| {
                let text = shown.printed(&format!("{list}/{id}/{attribute}:"));
                (id.to_owned(), text)
            })
            .collect()
    };
    let texts = |rv: &Rv, list: &str| -> Vec<String> {
        listed(rv, list).into_iter().map(|(_, t)| t).collect()
    };
    let id_of = |rv: &Rv, list: &str, text: &str| -> String {
        listed(rv, list)
            .into_iter()
            .find(|(_, t)| t == text)
            .map(|(id, _)| id)
            .unwrap()
    };
    let one = id_of(&a, "uri", "https://one.example");
    let two = id_of(&a, "uri", "https://two.example");
    let three = id_of(&a, "uri", "https://three.example");
    assert_eq!(
        texts(&a, "uri"),
        [
            "https://one.example",
            "https://two.example",
            "https://three.example"
        ]
    );

    // First, after a neighbour named by a prefix, before one, last.
    let edit = |args: &[&str]| {
        let mut all = vec!["item", "edit", item.as_str()];
        all.extend_from_slice(args);
        a.ok(&all, &[]);
    };
    edit(&["--move-uri", &format!("{}=first", &three[..8])]);
    assert_eq!(
        texts(&a, "uri"),
        [
            "https://three.example",
            "https://one.example",
            "https://two.example"
        ]
    );
    edit(&["--move-uri", &format!("{one}=after:{}", &two[..8])]);
    assert_eq!(
        texts(&a, "uri"),
        [
            "https://three.example",
            "https://two.example",
            "https://one.example"
        ]
    );
    let first_field = id_of(&a, "field", "A");
    let second_field = id_of(&a, "field", "B");
    edit(&[
        "--move-custom",
        &format!("{second_field}=before:{first_field}"),
    ]);
    assert_eq!(texts(&a, "field"), ["B", "A"]);
    edit(&["--move-custom", &format!("{second_field}=last")]);
    assert_eq!(texts(&a, "field"), ["A", "B"]);

    // Several in one command, after its removal and its addition: two goes, four is added
    // last, then one moves first and three after four.
    edit(&[
        "--remove-uri",
        &two,
        "--uri",
        "https://four.example",
        "--move-uri",
        &format!("{one}=first"),
        "--move-uri",
        &format!("{three}=last"),
    ]);
    assert_eq!(
        texts(&a, "uri"),
        [
            "https://one.example",
            "https://four.example",
            "https://three.example"
        ]
    );

    // Refusals: a place that is none, a removed element, itself as the neighbour, on create.
    let refused = |args: &[&str]| {
        let mut all = vec!["item", "edit", item.as_str()];
        all.extend_from_slice(args);
        a.try_run(&all, &[PASSWORD], &[], &[]).0
    };
    let middle = format!("{one}=middle");
    assert!(matches!(
        refused(&["--move-uri", &middle]),
        Err(CliError::Usage(_))
    ));
    let moved_away = format!("{one}=first");
    assert!(matches!(
        refused(&["--remove-uri", &one, "--move-uri", &moved_away]),
        Err(CliError::BadInput(_))
    ));
    let itself = format!("{one}=after:{one}");
    assert!(matches!(
        refused(&["--move-uri", &itself]),
        Err(CliError::Client(_))
    ));
    let (outcome, _) = a.try_run(
        &[
            "item",
            "create",
            "--type",
            "login",
            "--move-uri",
            "ab=first",
        ],
        &[],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Usage(_))), "{outcome:?}");

    // Concurrent moves: B (before syncing A's next edit) and A each move a different URI to
    // the first place, so both write the same key.
    b.ok(&["sync"], &[]);
    let four = id_of(&a, "uri", "https://four.example");
    edit(&["--move-uri", &format!("{four}=first")]);
    b.ok(
        &[
            "item",
            "edit",
            &item,
            "--move-uri",
            &format!("{three}=first"),
        ],
        &[],
    );
    a.ok(&["sync"], &[]);
    let key_of = |rv: &Rv, id: &str| rv.field(&item, &format!("uri/{id}/order"));
    assert_eq!(key_of(&a, &four), key_of(&a, &three), "equal keys");
    // A move between the two: no key fits, so the list's keys are rewritten evenly.
    let (low, high) = if four < three {
        (&four, &three)
    } else {
        (&three, &four)
    };
    edit(&["--move-uri", &format!("{one}=after:{low}")]);
    let order: Vec<String> = listed(&a, "uri").into_iter().map(|(id, _)| id).collect();
    assert_eq!(order, [low.clone(), one.clone(), high.clone()]);
    let keys: Vec<String> = order.iter().map(|id| key_of(&a, id)).collect();
    assert_eq!(keys, ["(order 40)", "(order 80)", "(order c0)"]);

    // Another device sees the same item and order.
    b.ok(&["sync"], &[]);
    let on_b = b.ok(&["item", "show", &item, "--reveal"], &[]);
    let on_a = a.ok(&["item", "show", &item, "--reveal"], &[]);
    assert_eq!(on_b.out, on_a.out);
}

/// ADR 0030 through `rv` against the real `rizzy-vault` behind a loopback TLS-terminating
/// proxy ([`TlsProxy`]): the test certificate is refused under the public roots before
/// anything is asked; with the test CA (`--ca-file` once, then `RIZZY_CLI_CA_FILE` as the
/// device's setting) a signup, an item, a login on a second device and a sync all go over TLS
/// 1.3, and the device requests signed for the `https://` origin verify on the server.
#[test]
fn rv_reaches_the_server_through_a_tls_proxy() {
    let (_proxy, server) = TlsProxy::start();
    let origin = server.origin();
    assert!(origin.starts_with("https://localhost:"), "{origin}");
    let ca = tls_fixture("ca.pem");
    let ca_text = ca.to_str().unwrap();

    // The public roots do not hold the test CA: refused before anything is asked or sent.
    let mut a = Rv::new("tls-a");
    let (outcome, asked) = a.try_run(
        &["signup", "--server", &origin, "--name", "alice"],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    match outcome {
        Err(CliError::Tls {
            origin: named,
            failure,
        }) => {
            assert_eq!(named, origin);
            assert_eq!(failure, rizzy_cli::error::TlsFailure::UnknownIssuer);
        }
        other => panic!("expected a TLS failure, got {other:?}"),
    }
    assert!(asked.out.is_empty());

    // With the flag: signup over TLS.
    let (outcome, signup) = a.try_run(
        &[
            "signup",
            "--server",
            &origin,
            "--name",
            "alice",
            "--ca-file",
            ca_text,
        ],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("signup failed: {e:?}; {:?}", signup.notes));
    let secret_key = signup.printed("Secret Key:");

    // From here on, the CA file is the device's setting, as `RIZZY_CLI_CA_FILE` would set it.
    a.ca_file = Some(ca.clone());
    let id = create_note(&a, "Over TLS");
    a.ok(&["sync"], &[]);

    let mut b = Rv::new("tls-b");
    b.ca_file = Some(ca);
    log_in(&b, &origin, "alice", &secret_key);
    b.ok(&["sync"], &[]);
    assert_eq!(b.field(&id, "item.name"), "Over TLS");

    // Without the CA, the enrolled device's next online step is refused as well.
    b.ca_file = None;
    let (outcome, _) = b.try_run(&["sync"], &[PASSWORD], &[], &[]);
    assert!(matches!(outcome, Err(CliError::Tls { .. })), "{outcome:?}");
}

/// `item show` lists password history (gap 01; ADR 0012 §5 "Password history is the history
/// of `login.password`"): concealed unless `--reveal`, newest first, never through the
/// generic field loop.
#[test]
fn item_show_lists_password_history() {
    let server = Server::start();
    let origin = server.origin();
    let a = Rv::new("pwhist");
    sign_up(&a, &origin, "alice");
    let item = a
        .ok(
            &[
                "item",
                "create",
                "--type",
                "login",
                "--field",
                "item.name=Mail",
                "--secret",
                "login.password",
            ],
            &["first-password"],
        )
        .out[0]
        .clone();

    // No history yet: the item has only ever held one value.
    let shown = a.ok(&["item", "show", &item], &[]);
    assert!(
        !shown.out.iter().any(|l| l.starts_with("password history")),
        "{:?}",
        shown.out
    );

    a.ok(
        &["item", "edit", &item, "--secret", "login.password"],
        &["second-password"],
    );
    a.ok(
        &["item", "edit", &item, "--secret", "login.password"],
        &["third-password"],
    );

    // Concealed without --reveal: the heading names the count, the entries do not leak the
    // old values.
    let hidden = a.ok(&["item", "show", &item], &[]);
    assert!(
        hidden
            .out
            .iter()
            .any(|l| l == "password history (2 older values, newest first):"),
        "{:?}",
        hidden.out
    );
    assert!(!hidden.out.iter().any(|l| l.contains("first-password")));
    assert!(!hidden.out.iter().any(|l| l.contains("second-password")));
    assert!(hidden.out.iter().any(|l| l.ends_with(": ********")));

    // Revealed: both older values, newest (second-password) first; the current value
    // (third-password) is not a history entry.
    let revealed = a.ok(&["item", "show", &item, "--reveal"], &[]);
    let history_lines: Vec<&String> = revealed
        .out
        .iter()
        .skip_while(|l| !l.starts_with("password history"))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .collect();
    assert_eq!(history_lines.len(), 2, "{:?}", revealed.out);
    assert!(
        history_lines[0].ends_with(": second-password"),
        "{history_lines:?}"
    );
    assert!(
        history_lines[1].ends_with(": first-password"),
        "{history_lines:?}"
    );
    assert!(!history_lines.iter().any(|l| l.contains("third-password")));
    assert_eq!(a.field(&item, "login.password"), "third-password");
}
