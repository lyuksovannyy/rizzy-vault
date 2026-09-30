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
    /// The port of its public origin: its own, or the port of the [`Proxy`] in front of it.
    origin_port: u16,
}

impl Server {
    /// A new server: `secrets init`, then serve with open signup.
    fn start() -> Self {
        Self::start_behind(None)
    }

    /// A new server whose public origin is `origin_port` on loopback (a [`Proxy`] in front of
    /// it), or its own port.
    fn start_behind(origin_port: Option<u16>) -> Self {
        let dir = temp_dir("server");
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let origin_port = origin_port.unwrap_or(port);
        let init = Self::command(&dir, port, origin_port)
            .args(["secrets", "init"])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let child = Self::spawn(&dir, port, origin_port);
        Self {
            child,
            dir,
            port,
            origin_port,
        }
    }

    /// The server's command with its settings.
    fn command(dir: &Path, port: u16, origin_port: u16) -> Command {
        let mut command = Command::new(server_binary());
        command
            .env_clear()
            .env("RIZZY_ORIGIN", format!("http://127.0.0.1:{origin_port}"))
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
    fn spawn(dir: &Path, port: u16, origin_port: u16) -> Child {
        let mut child = Self::command(dir, port, origin_port).spawn().unwrap();
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
        format!("http://127.0.0.1:{}", self.origin_port)
    }

    /// Stops the server (the data stays).
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Starts it again on the same data and port.
    fn restart(&mut self) {
        self.stop();
        self.child = Self::spawn(&self.dir, self.port, self.origin_port);
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
        self.typed.pop_front().ok_or(CliError::NoTerminal)
    }

    fn print(&mut self, text: &str) -> Result<(), CliError> {
        self.out.push(text.to_owned());
        Ok(())
    }

    fn note(&mut self, text: &str) {
        self.notes.push(text.to_owned());
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
    // An https origin is refused too in this build, before anything is asked or sent: the
    // client-side TLS crates await approval under ADR 0009.
    let (outcome, asked) = a.try_run(
        &[
            "signup",
            "--server",
            "https://vault.example.com",
            "--name",
            "alice",
        ],
        &[PASSWORD, PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::TlsUnavailable)));
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

    // Export: encrypted, then plaintext behind the typed phrase; never an overwrite.
    let out = temp_dir("out");
    let encrypted = out.join("vault.rvexport");
    a.ok(
        &["export", "--out", encrypted.to_str().unwrap()],
        &["export password", "export password"],
    );
    let file = std::fs::read(&encrypted).unwrap();
    assert!(file.starts_with(br#"{"format":"rizzy-vault-export""#));
    assert!(!file.windows(7).any(|w| w == b"settled"));
    let (outcome, _) = a.try_run(
        &["export", "--out", encrypted.to_str().unwrap()],
        &[PASSWORD, "x", "x"],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::FileExists)));
    assert_eq!(std::fs::read(&encrypted).unwrap(), file);
    let json = out.join("vault.json");
    // Without a terminal, or with anything but the phrase, nothing is written.
    let (outcome, _) = a.try_run(
        &[
            "export",
            "--out",
            json.to_str().unwrap(),
            "--format",
            "json",
        ],
        &[PASSWORD],
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::NoTerminal)));
    let (outcome, warned) = a.try_run(
        &[
            "export",
            "--out",
            json.to_str().unwrap(),
            "--format",
            "json",
        ],
        &[PASSWORD],
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
    let (outcome, _) = a.try_run(
        &[
            "export",
            "--out",
            json.to_str().unwrap(),
            "--format",
            "json",
        ],
        &[PASSWORD],
        &[],
        &["EXPORT PLAINTEXT"],
    );
    outcome.unwrap();
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
    let (outcome, warned) = a.try_run(
        &["export", "--out", csv.to_str().unwrap(), "--format", "csv"],
        &[PASSWORD],
        &[],
        &["EXPORT PLAINTEXT"],
    );
    outcome.unwrap();
    assert!(warned.noted("spreadsheet"));
    assert!(std::fs::read_to_string(&csv).unwrap().contains("settled"));

    // Import: our encrypted export (a wrong password imports nothing), our plaintext JSON,
    // and another product's file. Each item arrives as a new item.
    let (outcome, _) = b.try_run(
        &[
            "import",
            "--format",
            "rizzy-encrypted",
            "--in",
            encrypted.to_str().unwrap(),
        ],
        &[PASSWORD, "not the export password"],
        &[],
        &[],
    );
    assert!(matches!(
        outcome,
        Err(CliError::Client(ClientError::ExportDecryptionFailed))
    ));
    assert_eq!(b.items().len(), 2);
    let imported = b.ok(
        &[
            "import",
            "--format",
            "rizzy-encrypted",
            "--in",
            encrypted.to_str().unwrap(),
        ],
        &["export password"],
    );
    assert!(imported.noted("Imported 2 items"));
    assert_eq!(b.items().len(), 4);
    b.ok(
        &[
            "import",
            "--format",
            "rizzy-json",
            "--in",
            json.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(b.items().len(), 6);
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
