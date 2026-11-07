// SPDX-License-Identifier: AGPL-3.0-only

//! `rv`'s account flows end to end against a real `rizzy-vault` server: a master password
//! change and a Secret Key change, also with a full rotation, with the other device following
//! them (CRYPTO.md §11.5, §11.6, §11.3 step 5), an interrupted change settled by the next
//! run, server-side 2FA (§5.10, §11.15), and a recovery with the Emergency Kit completed
//! through the binaries on a server with a zero waiting period (§11.9), also when it is
//! interrupted after its pre-commit write or loses its answer and the next run settles the
//! recovery-pending record (ADR 0046 §3, §5; threat model INV-71), or `rv recovery abandon`
//! leaves it, in every case of ADR 0108 §3, including a commit still in transit before and
//! after a new attempt's `recovery/complete` (INV-122) and crashes before and inside the
//! removal. Device removal (ADR 0091
//! §3): one or several devices, the three reasons, a crash at each point of §7 test 5, a write
//! from another device paused by the window and sent once it closes, a removal finished or
//! cancelled after a crash, and a removed device that drops its pending commit unsent.
//!
//! The harness is `tests/e2e.rs`'s, cut down: the built `rizzy-vault` binary on a loopback
//! port with a temporary `SQLite` database (ADR 0016 §3 forbids a dependency on
//! `rizzy-server`), a loopback reverse proxy that loses one answer, and `rv` run through its
//! library with a scripted user. It lives in its own file so the two suites stay independent.

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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rizzy_cli::CliError;
use rizzy_cli::args::parse;
use rizzy_cli::commands::run;
use rizzy_cli::device::{Env, SignOuts};
use rizzy_cli::ui::{Checkpoint, Ui};
use rizzy_client::ClientError;
use rizzy_client::revocation::REVOCATION_PENDING_MESSAGE;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
use rizzy_client::store::load;
use rizzy_client::store::record::Stage;
use rizzy_core::totp::{TotpParams, TotpSecret};
use zeroize::Zeroizing;

/// The master password at signup.
const PASSWORD: &str = "correct horse battery staple";
/// The master password after the change.
const NEW_PASSWORD: &str = "tremble lantern orbit vintage";
/// The master password a recovery sets.
const RECOVERED_PASSWORD: &str = "quiet meadow copper whistle";

/// A fresh temporary directory.
fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rv-acct-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The variables a `rizzy-vault` process needs from the OS to run at all, kept when its
/// environment is cleared ([`clear_env`]). None on Unix. On Windows, `SystemRoot`: Winsock
/// loads its service provider from a registry path written as
/// `%SystemRoot%\System32\mswsock.dll`, so a process without the variable cannot create a
/// socket (`WSAEPROVIDERFAILEDINIT`, error 10106) and `rizzy-vault` exits 1 when it binds its
/// listener. Go's `os/exec` adds `SYSTEMROOT` to every child's environment for this reason;
/// Rust's `env_clear` does not. Also `PATH` on Windows: `rizzy-vault` links OpenSSL as a DLL
/// (webauthn-rs, ADR 0077), and a non-system DLL is found through `PATH`; without it the process
/// cannot load (`STATUS_DLL_NOT_FOUND`) and writes nothing. Nothing else is needed: the
/// temporary directory falls back from `TMP`, `TEMP` and `USERPROFILE` to the Windows directory.
const OS_ENV: &[&str] = if cfg!(windows) {
    &["SystemRoot", "PATH"]
} else {
    &[]
};

/// Clears `command`'s environment, so no `RIZZY_*` variable of the developer leaks in, and
/// puts back [`OS_ENV`] from this process's.
fn clear_env(command: &mut Command) -> &mut Command {
    command.env_clear();
    for name in OS_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

/// The `rizzy-vault` binary next to this test's executable, built through cargo (a no-op when
/// it is fresh).
fn server_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().and_then(Path::parent).unwrap();
    let binary = profile_dir.join(format!("rizzy-vault{}", std::env::consts::EXE_SUFFIX));
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
    assert!(
        build.status().expect("cargo builds rizzy-vault").success(),
        "building rizzy-vault failed"
    );
    binary
}

/// Where the `rizzy-vault` processes of a server write their standard error, in its directory:
/// their log lines and error messages, for the failure report ([`log_tail`]).
const STDERR_LOG: &str = "stderr.log";

/// How long a `rizzy-vault` process may take to start listening: long, since a debug build on
/// a loaded host can take long to start.
const START_TIMEOUT: Duration = Duration::from_secs(120);

/// How many free ports a new server tries before the test gives up.
const START_ATTEMPTS: usize = 10;

/// A loopback port that was free a moment ago ([`listening`] detects a process that bound it
/// since).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The text of `log` from byte `from` on (empty if there is none yet).
fn log_text(log: &Path, from: u64) -> String {
    let bytes = std::fs::read(log).unwrap_or_default();
    let from = usize::try_from(from).unwrap().min(bytes.len());
    String::from_utf8_lossy(&bytes[from..]).into_owned()
}

/// The last lines of the log of the server in `dir`, for a failure report.
fn log_tail(dir: &Path) -> String {
    const LINES: usize = 40;
    let log = dir.join(STDERR_LOG);
    let text = log_text(&log, 0);
    let lines: Vec<&str> = text.lines().collect();
    format!(
        "last {} lines of {}:\n{}",
        LINES.min(lines.len()),
        log.display(),
        lines[lines.len().saturating_sub(LINES)..].join("\n")
    )
}

/// Waits until the serving process `child` of the server in `dir`, started when its log had
/// `from` bytes, logs that it listens on `port`; `false` if the port is taken.
///
/// Ready means the process's own `listening` line, never a connection to the port: another
/// process (a parallel test's server or proxy) may have bound the port since it was probed.
/// This one then exits with `listener: address in use` while a connection reaches the other,
/// and `rv` would go on against a stranger's server (whose answer to a signup for a name taken
/// there is `invalid_request`).
fn listening(child: &mut Child, dir: &Path, from: u64, port: u16) -> bool {
    let log = dir.join(STDERR_LOG);
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        let says = |line: &str| {
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|event| {
                event["event"] == "listening" && event["port"] == u64::from(port)
            })
        };
        if log_text(&log, from).lines().any(says) {
            return true;
        }
        if let Some(status) = child.try_wait().unwrap() {
            if log_text(&log, from).contains("listener: address in use") {
                return false;
            }
            panic!("rizzy-vault exited at start: {status}; {}", log_tail(dir));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "rizzy-vault did not listen within {START_TIMEOUT:?}; {}",
                log_tail(dir)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A running `rizzy-vault`. Killed on drop.
struct Server {
    /// The process.
    child: Child,
    /// Its directories.
    dir: PathBuf,
    /// The port of its public origin: its own, or the [`Proxy`]'s.
    origin_port: u16,
    /// Its own port.
    port: u16,
}

impl Server {
    /// A new server with open signup, `extra` settings, and its public origin on
    /// `origin_port` (a proxy's) or its own port.
    fn start(extra: &[(&str, &str)], origin_port: Option<u16>) -> Self {
        let dir = temp_dir("server");
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        let command = |dir: &Path, port: u16| {
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(STDERR_LOG))
                .unwrap();
            let mut command = Command::new(server_binary());
            clear_env(&mut command)
                .env(
                    "RIZZY_ORIGIN",
                    format!("http://127.0.0.1:{}", origin_port.unwrap_or(port)),
                )
                .env("RIZZY_LISTEN", format!("127.0.0.1:{port}"))
                // An ephemeral admin port, so parallel servers never collide on 8081 (ADR 0060 §2).
                .env("RIZZY_ADMIN_LISTEN", "127.0.0.1:0")
                .env("RIZZY_SIGNUP", "open")
                .env("RIZZY_DATA_DIR", dir.join("data"))
                .env(
                    "RIZZY_SECRETS_FILE",
                    dir.join("secrets").join("secrets.json"),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log);
            for (name, value) in extra {
                command.env(name, value);
            }
            command
        };
        // The secrets file does not depend on the port.
        let init = command(&dir, free_port())
            .args(["secrets", "init"])
            .status()
            .unwrap();
        assert!(init.success(), "secrets init failed; {}", log_tail(&dir));
        for _ in 0..START_ATTEMPTS {
            let port = free_port();
            let from = std::fs::metadata(dir.join(STDERR_LOG)).map_or(0, |m| m.len());
            let mut child = command(&dir, port).spawn().unwrap();
            if listening(&mut child, &dir, from, port) {
                return Self {
                    child,
                    dir,
                    origin_port: origin_port.unwrap_or(port),
                    port,
                };
            }
        }
        panic!(
            "rizzy-vault found every port it tried taken; {}",
            log_tail(&dir)
        );
    }

    /// The origin `rv` dials.
    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.origin_port)
    }
}

impl Drop for Server {
    #[expect(
        clippy::print_stderr,
        reason = "the server's log in a failed test's output, which the test harness captures"
    )]
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("rizzy-vault on port {}: {}", self.port, log_tail(&self.dir));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the [`Proxy`] does to the next request for a path, once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    /// The request reaches the server; its answer is replaced by a gateway's `502` page.
    AnswerLost,
    /// The request never reaches the server; the client gets the same `502` page.
    NeverSent,
    /// The request never reaches the server; the client gets a definite refusal,
    /// `403 fresh_session_required` (what a commit sent too long after its login gets).
    Refused,
}

/// The path and body of every request a [`Proxy`] received, in arrival order.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A loopback reverse proxy in front of a [`Server`] that loses one answer (`tests/e2e.rs`).
struct Proxy {
    /// Its port.
    port: u16,
    /// The armed fault.
    fault: Arc<Mutex<Option<(&'static str, Fault)>>>,
    /// The path and body of every request, in arrival order.
    seen: Seen,
    /// The path and the server's answer body of every request it answered, in arrival order.
    answers: Seen,
    /// Set on drop.
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Proxy {
    /// A proxy and the server behind it.
    fn start(extra: &[(&str, &str)]) -> (Self, Server) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = Server::start(extra, Some(port));
        let upstream = server.port;
        let fault = Arc::new(Mutex::new(None));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let answers = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (thread_fault, thread_seen, thread_stop) = (fault.clone(), seen.clone(), stop.clone());
        let thread_answers = answers.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(stream) = stream {
                    let _ = Self::serve(
                        stream,
                        upstream,
                        &thread_fault,
                        (&thread_seen, &thread_answers),
                    );
                }
            }
        });
        (
            Self {
                port,
                fault,
                seen,
                answers,
                stop,
            },
            server,
        )
    }

    /// The paths of the requests so far, in arrival order.
    fn paths(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// The bodies of the requests to `path` so far, in arrival order.
    fn bodies(&self, path: &str) -> Vec<Vec<u8>> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, body)| body.clone())
            .collect()
    }

    /// The bearer token of the recovery-only session the latest `recovery/complete` answer
    /// issued.
    fn recovery_session(&self) -> rizzy_client::rizzy_proto::wire::SessionToken {
        let answers = self.answers.lock().unwrap();
        let (_, body) = answers
            .iter()
            .rev()
            .find(|(p, _)| p == paths::RECOVERY_COMPLETE)
            .unwrap();
        let answer: serde_json::Value = serde_json::from_slice(body).unwrap();
        serde_json::from_value(answer["session_token"].clone()).unwrap()
    }

    /// Arms `fault` for the next request to `path`.
    fn arm(&self, path: &'static str, fault: Fault) {
        *self.fault.lock().unwrap() = Some((path, fault));
    }

    /// Whether the armed fault was used.
    fn fired(&self) -> bool {
        self.fault.lock().unwrap().is_none()
    }

    /// One HTTP/1.1 message with a `Content-Length` (or none): head and body.
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

    /// Serves one request.
    fn serve(
        mut client: std::net::TcpStream,
        upstream: u16,
        armed: &Mutex<Option<(&'static str, Fault)>>,
        (seen, answers): (&Seen, &Seen),
    ) -> std::io::Result<()> {
        use std::io::Write as _;
        client.set_read_timeout(Some(Duration::from_secs(30)))?;
        let (head, body) = Self::read_message(&mut client)?;
        let path = String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        seen.lock().unwrap().push((path.clone(), body.clone()));
        let fault = {
            let mut armed = armed.lock().unwrap();
            match *armed {
                Some((p, fault)) if p == path => {
                    *armed = None;
                    Some(fault)
                }
                _ => None,
            }
        };
        let bad_gateway = b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/html\r\n\
            content-length: 15\r\nconnection: close\r\n\r\n502 Bad Gateway"
            .to_vec();
        let refusal = b"HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\n\
            content-length: 34\r\nconnection: close\r\n\r\n{\"error\":\"fresh_session_required\"}"
            .to_vec();
        let reply = if fault == Some(Fault::NeverSent) {
            bad_gateway
        } else if fault == Some(Fault::Refused) {
            refusal
        } else {
            let mut server = std::net::TcpStream::connect(("127.0.0.1", upstream))?;
            server.set_read_timeout(Some(Duration::from_secs(30)))?;
            server.write_all(&head)?;
            server.write_all(&body)?;
            let (answer_head, answer_body) = Self::read_message(&mut server)?;
            answers
                .lock()
                .unwrap()
                .push((path.clone(), answer_body.clone()));
            if fault == Some(Fault::AnswerLost) {
                bad_gateway
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
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// An authenticator app: the 2FA secret and the last time step it gave a code for.
#[derive(Default)]
struct Authenticator {
    /// The Base32 secret, once enrolled.
    secret: Option<String>,
    /// The highest step a code was given for.
    last_step: Option<u64>,
}

impl Authenticator {
    /// A code the server takes: for the lowest step within one step of now (§11.15: the
    /// server accepts −1, 0, +1) and above every step used before, waiting for the clock when
    /// the window holds none.
    fn code(&mut self) -> Option<String> {
        let params = TotpParams::DEFAULT;
        let secret = TotpSecret::from_base32(self.secret.as_deref()?).unwrap();
        loop {
            let now = params.time_step(rizzy_cli::sys::now_ms() / 1000);
            let step = self
                .last_step
                .map_or(now.saturating_sub(1), |last| (last + 1).max(now - 1));
            if step <= now + 1 {
                self.last_step = Some(step);
                return Some(
                    params
                        .code_at_step(&secret, step)
                        .unwrap()
                        .to_digits()
                        .to_string(),
                );
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// The scripted user.
#[derive(Default)]
struct Script {
    /// Answers to secret prompts other than one-time codes.
    secrets: VecDeque<String>,
    /// Answers to line prompts.
    lines: VecDeque<String>,
    /// The authenticator app, which answers the code prompts.
    authenticator: Option<Authenticator>,
    /// Standard output.
    out: Vec<String>,
    /// Standard error.
    notes: Vec<String>,
    /// Where the flow "crashes" (ADR 0091 §7 test 5): [`Ui::checkpoint`] fails there.
    crash_at: Option<Checkpoint>,
}

/// The error a scripted crash returns.
const CRASHED: &str = "crash injected by the test";

impl Ui for Script {
    fn checkpoint(&mut self, point: Checkpoint) -> Result<(), CliError> {
        if self.crash_at == Some(point) {
            return Err(CliError::Refused(CRASHED.to_owned()));
        }
        Ok(())
    }

    fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>, CliError> {
        let one_time = prompt.starts_with("Two-factor code")
            || prompt.contains("code from your authenticator app");
        if one_time {
            let printed = self.out.iter().find_map(|l| l.strip_prefix("Secret:"));
            let authenticator = self
                .authenticator
                .get_or_insert_with(Authenticator::default);
            if let Some(secret) = printed {
                authenticator.secret = Some(secret.trim().to_owned());
            }
            return authenticator
                .code()
                .map(Zeroizing::new)
                .ok_or(CliError::InputEnded);
        }
        self.secrets
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(CliError::InputEnded)
    }

    fn line(&mut self, prompt: &str) -> Result<String, CliError> {
        if prompt.starts_with("Type the last four characters") {
            let kit = self.printed("Secret Key:");
            return Ok(kit.rsplit('-').next().unwrap().to_owned());
        }
        self.lines.pop_front().ok_or(CliError::InputEnded)
    }

    fn typed(&mut self, _prompt: &str) -> Result<String, CliError> {
        Err(CliError::NoTerminal)
    }

    fn print(&mut self, text: &str) -> Result<(), CliError> {
        self.out.push(text.to_owned());
        Ok(())
    }

    fn note(&mut self, text: &str) {
        self.notes.push(text.to_owned());
    }

    fn hold(&mut self, duration: Duration) -> Duration {
        // No export runs here; a hold is recorded as served at once.
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

/// One device's `rv`.
struct Rv {
    /// `RIZZY_CLI_DATA_DIR`.
    dir: PathBuf,
    /// The runtime commands run on.
    runtime: tokio::runtime::Runtime,
    /// The pauses of a `revocation_pending` retry: no real wait, the note recorded.
    pause: Arc<TestPause>,
}

/// [`rizzy_cli::http::Pause`] for the tests: a retry waits for nothing (or for the hook of
/// its first wait), and the pause note is recorded.
#[derive(Default)]
struct TestPause {
    /// The notes shown.
    notes: Mutex<Vec<String>>,
    /// The waits asked for.
    waits: Mutex<Vec<Duration>>,
    /// Run (once) at the first wait.
    on_first_wait: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl rizzy_cli::http::Pause for TestPause {
    fn note(&self, text: &str) {
        self.notes.lock().unwrap().push(text.to_owned());
    }

    fn wait(&self, duration: Duration) {
        self.waits.lock().unwrap().push(duration);
        let hook = self.on_first_wait.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}

impl Rv {
    fn new(tag: &str) -> Self {
        Self {
            dir: temp_dir(tag).join("rv"),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            pause: Arc::new(TestPause::default()),
        }
    }

    /// How many times a request of this device was refused `revocation_pending` and waited.
    fn paused(&self) -> usize {
        self.pause.waits.lock().unwrap().len()
    }

    /// Runs one command with scripted answers and, for code prompts, `authenticator`.
    fn run_with(
        &self,
        args: &[&str],
        secrets: &[&str],
        lines: &[&str],
        authenticator: Option<Authenticator>,
    ) -> (Result<(), CliError>, Script) {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        self.run_script(
            args,
            Script {
                secrets: own(secrets),
                lines: own(lines),
                authenticator,
                ..Script::default()
            },
        )
    }

    /// Runs one command that "crashes" at `point` (when it gets there).
    fn run_crashing(
        &self,
        args: &[&str],
        secrets: &[&str],
        lines: &[&str],
        point: Checkpoint,
    ) -> (Result<(), CliError>, Script) {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        self.run_script(
            args,
            Script {
                secrets: own(secrets),
                lines: own(lines),
                crash_at: Some(point),
                ..Script::default()
            },
        )
    }

    /// Runs one command with `script` as the user.
    fn run_script(&self, args: &[&str], mut script: Script) -> (Result<(), CliError>, Script) {
        let outcome = match parse(args.iter().map(OsString::from).collect()) {
            Ok(invocation) => {
                let mut env = Env {
                    data_dir: self.dir.clone(),
                    account: None,
                    trust: rizzy_cli::tls::Trust::default(),
                    ui: &mut script,
                    sign_outs: SignOuts::default(),
                    pauses: rizzy_cli::http::Pauses::with(self.pause.clone()),
                };
                self.runtime.block_on(run(invocation, &mut env))
            }
            Err(e) => Err(e),
        };
        (outcome, script)
    }

    /// Runs one command with scripted answers.
    fn try_run(
        &self,
        args: &[&str],
        secrets: &[&str],
        lines: &[&str],
    ) -> (Result<(), CliError>, Script) {
        self.run_with(args, secrets, lines, None)
    }

    /// Runs a command that must succeed.
    fn ok(&self, args: &[&str], secrets: &[&str], lines: &[&str]) -> Script {
        let (outcome, script) = self.try_run(args, secrets, lines);
        if let Err(e) = outcome {
            panic!("rv {args:?} failed: {e} ({e:?}); notes: {:?}", script.notes);
        }
        script
    }

    /// The names `item list` prints, unlocked with `password`.
    fn item_names(&self, password: &str) -> Vec<String> {
        self.ok(&["item", "list"], &[password], &[])
            .out
            .iter()
            .map(|line| line.rsplit("  ").next().unwrap().trim().to_owned())
            .collect()
    }
}

impl Drop for Rv {
    fn drop(&mut self) {
        if let Some(parent) = self.dir.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

/// Signs `name` up and returns the kit's Secret Key and recovery code.
fn sign_up(rv: &Rv, origin: &str, name: &str) -> (String, String) {
    let signup = rv.ok(
        &["signup", "--server", origin, "--name", name],
        &[PASSWORD, PASSWORD],
        &[],
    );
    (
        signup.printed("Secret Key:"),
        signup.printed("Recovery code:"),
    )
}

/// Logs a new device in with `secret_key` and `password`.
fn log_in(
    rv: &Rv,
    origin: &str,
    secret_key: &str,
    password: &str,
) -> (Result<(), CliError>, Script) {
    rv.try_run(
        &["login", "--server", origin, "--name", "alice"],
        &[secret_key, password],
        &[],
    )
}

/// Creates a note named `name`, unlocked with `password`.
fn create_note(rv: &Rv, password: &str, name: &str) {
    let field = format!("item.name={name}");
    rv.ok(
        &["item", "create", "--type", "note", "--field", &field],
        &[password],
        &[],
    );
}

/// Whether `outcome` is the one answer to a wrong password or Secret Key.
fn wrong_credentials(outcome: &Result<(), CliError>) -> bool {
    matches!(
        outcome,
        Err(CliError::Client(ClientError::WrongPasswordOrSecretKey))
    )
}

/// CRYPTO.md §11.5 and §11.3 step 5 through `rv`: a password change on A, which B follows at
/// its next sync; then a Secret Key change on A with its default rotation and new recovery
/// code, which B follows through the device grant and the new kit; new devices log in with the
/// new credentials only.
#[test]
#[expect(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "one story over one server, in the order a user lives it; one letter per device"
)]
fn password_and_secret_key_changes_end_to_end() {
    let server = Server::start(&[], None);
    let origin = server.origin();
    let a = Rv::new("a");
    let b = Rv::new("b");
    let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");
    let (outcome, login) = log_in(&b, &origin, &secret_key, PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    create_note(&a, PASSWORD, "Before");

    // Usage: no secret on the command line, nothing that changes nothing.
    let (outcome, _) = a.try_run(
        &["password", "--name", "alice"],
        &[PASSWORD, PASSWORD, PASSWORD],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Client(ClientError::InvalidInput))),
        "the same password and Secret Key again is refused: {outcome:?}"
    );
    let (outcome, _) = a.try_run(
        &["password", "--name", "alice"],
        &[PASSWORD, NEW_PASSWORD, "something else entirely"],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::BadInput(_))));

    // The password change on A: re-authentication, re-registration, commit, finalisation.
    let changed = a.ok(
        &["password", "--name", "alice"],
        &[PASSWORD, NEW_PASSWORD, NEW_PASSWORD],
        &[],
    );
    assert!(
        changed.noted("master password was changed"),
        "{:?}",
        changed.notes
    );
    assert!(changed.out.is_empty(), "no kit for a password change");
    // A unlocks with the new password only, offline and online.
    let (outcome, _) = a.try_run(&["item", "list"], &[PASSWORD], &[]);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    assert_eq!(a.item_names(NEW_PASSWORD), ["Before"]);
    a.ok(&["sync"], &[NEW_PASSWORD], &[]);

    // B follows at its next sync (§11.3 step 5): it opens with the old password, is asked for
    // the new one, and from then on opens with the new one.
    let followed = b.ok(&["sync"], &[PASSWORD, NEW_PASSWORD], &["alice"]);
    assert!(
        followed.noted("changed on another device"),
        "{:?}",
        followed.notes
    );
    let (outcome, _) = b.try_run(&["item", "list"], &[PASSWORD], &[]);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    assert_eq!(b.item_names(NEW_PASSWORD), ["Before"]);

    // A new device: the old password no longer logs in; the new one does.
    let c = Rv::new("c");
    let (outcome, _) = log_in(&c, &origin, &secret_key, PASSWORD);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    let (outcome, login) = log_in(&c, &origin, &secret_key, NEW_PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));

    // The Secret Key change on A: a new kit with a new recovery code, and a rotation.
    create_note(&b, NEW_PASSWORD, "From B");
    let changed = a.ok(&["secret-key", "--name", "alice"], &[NEW_PASSWORD], &[]);
    let new_secret_key = changed.printed("Secret Key:");
    let new_recovery_code = changed.printed("Recovery code:");
    assert!(new_secret_key.starts_with("RV1-") && new_secret_key != secret_key);
    assert!(new_recovery_code.starts_with("RVR1-") && new_recovery_code != recovery_code);
    assert!(changed.noted("were rotated"), "{:?}", changed.notes);
    let mut names = a.item_names(NEW_PASSWORD);
    names.sort();
    assert_eq!(names, ["Before", "From B"]);
    // The cache holds neither the new Secret Key's text nor the recovery code.
    for entry in std::fs::read_dir(&a.dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "sqlite3") {
            let raw = std::fs::read(&path).unwrap();
            for needle in [new_secret_key.as_bytes(), new_recovery_code.as_bytes()] {
                assert!(!raw.windows(needle.len()).any(|w| w == needle));
            }
        }
    }

    // B follows the rotation (its grant) and the new Secret Key, typed from the new kit.
    let followed = b.ok(
        &["sync"],
        &[NEW_PASSWORD, NEW_PASSWORD, &new_secret_key],
        &["alice"],
    );
    assert!(
        followed.noted("changed on another device"),
        "{:?}",
        followed.notes
    );
    let mut names = b.item_names(NEW_PASSWORD);
    names.sort();
    assert_eq!(names, ["Before", "From B"]);
    create_note(&b, NEW_PASSWORD, "After");
    a.ok(&["sync"], &[NEW_PASSWORD], &[]);
    assert_eq!(a.item_names(NEW_PASSWORD).len(), 3);

    // New devices: the old Secret Key no longer logs in; the new one does.
    let d = Rv::new("d");
    let (outcome, _) = log_in(&d, &origin, &secret_key, NEW_PASSWORD);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    let (outcome, login) = log_in(&d, &origin, &new_secret_key, NEW_PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    assert_eq!(d.item_names(NEW_PASSWORD).len(), 3);

    // The old recovery code is void; the new one is the account's (then cancelled).
    let r = Rv::new("r");
    let (outcome, _) = r.try_run(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&new_recovery_code],
        &[],
    );
    let cancelled = a.ok(&["recovery", "cancel"], &[NEW_PASSWORD], &[]);
    assert!(cancelled.noted("was cancelled"));

    // A Secret Key change without the rotation: a kit without a recovery code, whose earlier
    // code stays valid.
    let changed = a.ok(
        &["secret-key", "--name", "alice", "--skip-rotation"],
        &[NEW_PASSWORD],
        &[],
    );
    let third_secret_key = changed.printed("Secret Key:");
    assert!(!changed.out.iter().any(|l| l.starts_with("Recovery code:")));
    assert!(changed.noted("stays valid"), "{:?}", changed.notes);
    // Nothing tells the user to drop the old kit, which holds the only recovery code.
    assert!(
        changed.out[0].contains("recovery code stays valid"),
        "{:?}",
        changed.out
    );
    assert!(changed.noted("is the only copy"), "{:?}", changed.notes);
    assert!(
        !changed.noted("only the new Emergency Kit works"),
        "{:?}",
        changed.notes
    );
    assert!(
        changed.noted("Skipping the key rotation"),
        "{:?}",
        changed.notes
    );
    let e = Rv::new("e");
    let (outcome, login) = log_in(&e, &origin, &third_secret_key, NEW_PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&new_recovery_code],
        &[],
    );
}

/// CRYPTO.md §11 "Secrets before commit" for a password change: the commit is lost on the way
/// (nothing applied), and the next run resends it; then the answer is lost after the server
/// applied it and another device enrolled in between, and the next run finds that out with a
/// login under the new credentials. Nothing is dropped while the outcome is unknown.
#[test]
fn an_interrupted_password_change_is_settled_by_the_next_run() {
    let (proxy, server) = Proxy::start(&[]);
    let origin = server.origin();
    let a = Rv::new("a");
    let (secret_key, _) = sign_up(&a, &origin, "alice");
    create_note(&a, PASSWORD, "Kept");

    // The commit never reaches the server: the change stays pending on A.
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::NeverSent);
    let (outcome, lost) = a.try_run(
        &["password", "--name", "alice"],
        &[PASSWORD, NEW_PASSWORD, NEW_PASSWORD],
        &[],
    );
    assert!(proxy.fired());
    assert!(outcome.is_err());
    assert!(lost.noted("stays saved"), "{:?}", lost.notes);
    // The server still has the old password, and A still opens with it; the next run that
    // goes online asks for the new one and resends the stored commit.
    let settled = a.ok(&["sync"], &[PASSWORD, NEW_PASSWORD], &["alice"]);
    assert!(settled.noted("interrupted"), "{:?}", settled.notes);
    assert_eq!(a.item_names(NEW_PASSWORD), ["Kept"]);
    let c = Rv::new("c");
    let (outcome, _) = log_in(&c, &origin, &secret_key, PASSWORD);
    assert!(wrong_credentials(&outcome), "{outcome:?}");

    // The answer is lost after the server applied the next change, and a new device enrols
    // before A runs again (the state moves past the commit's).
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, _) = a.try_run(
        &["password", "--name", "alice"],
        &[NEW_PASSWORD, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    assert!(proxy.fired());
    assert!(outcome.is_err());
    let (outcome, login) = log_in(&c, &origin, &secret_key, RECOVERED_PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    let settled = a.ok(&["sync"], &[NEW_PASSWORD, RECOVERED_PASSWORD], &["alice"]);
    assert!(settled.noted("interrupted"), "{:?}", settled.notes);
    assert_eq!(a.item_names(RECOVERED_PASSWORD), ["Kept"]);
    let (outcome, _) = a.try_run(&["item", "list"], &[NEW_PASSWORD], &[]);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
}

/// A Secret Key change whose commit the server refuses for good after the new kit was shown
/// and confirmed: the user is told the new kit is void and the old one valid, nothing stays
/// pending, and the old credentials are indeed the account's.
#[test]
fn a_refused_secret_key_change_says_the_new_kit_is_void() {
    let (proxy, server) = Proxy::start(&[]);
    let origin = server.origin();
    let a = Rv::new("a");
    let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");

    proxy.arm(paths::ACCOUNT_COMMIT, Fault::Refused);
    let (outcome, refused) = a.try_run(&["secret-key", "--name", "alice"], &[PASSWORD], &[]);
    assert!(proxy.fired());
    assert!(
        matches!(
            outcome,
            Err(CliError::Server(ErrorCode::FreshSessionRequired))
        ),
        "{outcome:?}"
    );
    let void_key = refused.printed("Secret Key:");
    assert!(refused.noted("NOT made"), "{:?}", refused.notes);
    assert!(refused.noted("is void"), "{:?}", refused.notes);
    assert!(!refused.noted("stays saved"), "{:?}", refused.notes);

    // Nothing is pending: the next run asks for no new password and settles nothing.
    let synced = a.ok(&["sync"], &[PASSWORD], &[]);
    assert!(!synced.noted("interrupted"), "{:?}", synced.notes);
    // The old kit is the account's; the void one logs in nowhere.
    let c = Rv::new("c");
    let (outcome, _) = log_in(&c, &origin, &void_key, PASSWORD);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    let (outcome, login) = log_in(&c, &origin, &secret_key, PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    let r = Rv::new("r");
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );
}

/// CRYPTO.md §11 "On restart with a pending record … if the server holds the new state it
/// finalises": a password change applied with its answer lost, then followed by another
/// device that makes a full rotation before this one runs again. The settling run finds the
/// change applied with a login under the new credentials (the old ones no longer log in), and
/// follows the rotation.
#[test]
fn an_applied_change_followed_by_a_rotation_elsewhere_is_settled() {
    let (proxy, server) = Proxy::start(&[]);
    let origin = server.origin();
    let a = Rv::new("a");
    let c = Rv::new("c");
    let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");
    let (outcome, login) = log_in(&c, &origin, &secret_key, PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    create_note(&a, PASSWORD, "Kept");

    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, _) = a.try_run(
        &["password", "--name", "alice"],
        &[PASSWORD, NEW_PASSWORD, NEW_PASSWORD],
        &[],
    );
    assert!(proxy.fired());
    assert!(outcome.is_err());

    // C follows the change, then rotates the account key and the identity keys.
    c.ok(&["sync"], &[PASSWORD, NEW_PASSWORD], &["alice"]);
    c.ok(
        &["rotate", "--name", "alice", "--full"],
        &[NEW_PASSWORD, &recovery_code],
        &[],
    );

    // A settles: applied, then the rotation's identity change is confirmed.
    let (outcome, settled) = a.try_run(&["sync"], &[PASSWORD, NEW_PASSWORD], &["alice", "CONFIRM"]);
    outcome.unwrap_or_else(|e| panic!("settle: {e:?} {:?}", settled.notes));
    assert!(settled.noted("interrupted"), "{:?}", settled.notes);
    assert!(!settled.noted("NOT made"), "{:?}", settled.notes);
    assert_eq!(a.item_names(NEW_PASSWORD), ["Kept"]);
    let (outcome, _) = a.try_run(&["item", "list"], &[PASSWORD], &[]);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    create_note(&a, NEW_PASSWORD, "After");
    c.ok(&["sync"], &[NEW_PASSWORD], &[]);
    let mut names = c.item_names(NEW_PASSWORD);
    names.sort();
    assert_eq!(names, ["After", "Kept"]);
}

/// CRYPTO.md §11.5 "SK change" with §11.6 "Full" through `rv secret-key --full-rotation` (the
/// "kit was stolen" choice): a new kit with a new recovery code, the account key, the vault key
/// and the identity keys rotated; the other device confirms the new identity, opens its grant
/// and takes the new Secret Key; only the new kit works afterwards.
#[test]
fn a_secret_key_change_with_a_full_rotation_end_to_end() {
    let server = Server::start(&[], None);
    let origin = server.origin();
    let a = Rv::new("fa");
    let b = Rv::new("fb");
    let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");
    let (outcome, login) = log_in(&b, &origin, &secret_key, PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    create_note(&a, PASSWORD, "Before");

    // The two rotation flags contradict each other.
    let (outcome, _) = a.try_run(
        &[
            "secret-key",
            "--name",
            "alice",
            "--skip-rotation",
            "--full-rotation",
        ],
        &[PASSWORD],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Usage(_))), "{outcome:?}");

    let changed = a.ok(
        &["secret-key", "--name", "alice", "--full-rotation"],
        &[PASSWORD],
        &[],
    );
    let new_secret_key = changed.printed("Secret Key:");
    let new_recovery_code = changed.printed("Recovery code:");
    assert!(new_secret_key.starts_with("RV1-") && new_secret_key != secret_key);
    assert!(new_recovery_code.starts_with("RVR1-") && new_recovery_code != recovery_code);
    assert!(
        changed.noted("the identity keys were rotated"),
        "{:?}",
        changed.notes
    );
    assert!(
        changed.noted("only the new Emergency Kit works"),
        "{:?}",
        changed.notes
    );
    assert_eq!(a.item_names(PASSWORD), ["Before"]);
    a.ok(&["sync"], &[PASSWORD], &[]);

    // B: the identity change is confirmed, the rotation followed through B's grant, and the
    // new Secret Key typed from the new kit.
    let (outcome, followed) = b.try_run(
        &["sync"],
        &[PASSWORD, PASSWORD, &new_secret_key],
        &["CONFIRM", "alice"],
    );
    outcome.unwrap_or_else(|e| panic!("follow: {e:?} {:?}", followed.notes));
    assert!(
        followed.noted("identity keys changed"),
        "{:?}",
        followed.notes
    );
    assert!(
        followed.noted("changed on another device"),
        "{:?}",
        followed.notes
    );
    create_note(&b, PASSWORD, "From B");
    a.ok(&["sync"], &[PASSWORD], &[]);
    let mut names = a.item_names(PASSWORD);
    names.sort();
    assert_eq!(names, ["Before", "From B"]);

    // New devices: the old Secret Key no longer logs in; the new one does, and reads all.
    let c = Rv::new("fc");
    let (outcome, _) = log_in(&c, &origin, &secret_key, PASSWORD);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    let (outcome, login) = log_in(&c, &origin, &new_secret_key, PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    assert_eq!(c.item_names(PASSWORD).len(), 2);

    // The old recovery code is void; the new one is the account's (then cancelled).
    let r = Rv::new("fr");
    let (outcome, _) = r.try_run(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&new_recovery_code],
        &[],
    );
    let cancelled = a.ok(&["recovery", "cancel"], &[PASSWORD], &[]);
    assert!(cancelled.noted("was cancelled"));
}

/// Server-side 2FA through `rv` (CRYPTO.md §5.10, §11.15): enrolment with the code from the
/// authenticator, a login on a new device that is asked for a code (a wrong one refused), a
/// re-authentication that needs one, and removal with a current code.
#[test]
fn two_factor_enrolment_login_and_removal() {
    let server = Server::start(&[], None);
    let origin = server.origin();
    let a = Rv::new("a");
    let (secret_key, _) = sign_up(&a, &origin, "alice");

    // Enrolment: the secret is printed once, as a URI and in Base32; the app's code confirms.
    let (outcome, mut enrolled) = a.run_with(
        &["2fa", "enable", "--name", "alice"],
        &[PASSWORD],
        &[],
        None,
    );
    outcome.unwrap_or_else(|e| panic!("2fa enable: {e:?} {:?}", enrolled.notes));
    let uri = enrolled.printed("otpauth URI:");
    let secret = enrolled.printed("Secret:");
    assert!(uri.starts_with("otpauth://totp/"), "{uri}");
    assert!(
        uri.contains("issuer=rizzy-vault") && uri.contains(&secret),
        "{uri}"
    );
    assert_eq!(
        TotpSecret::from_base32(&secret)
            .unwrap()
            .expose_secret()
            .len(),
        20
    );
    let app = enrolled.authenticator.take().unwrap();

    // A new device without the right code is not let in, and nothing is enrolled there.
    let b = Rv::new("b");
    let wrong = Authenticator {
        secret: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
        last_step: None,
    };
    let (outcome, refused) = b.run_with(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
        &[],
        Some(wrong),
    );
    assert!(outcome.is_err(), "{:?}", refused.notes);
    assert!(!b.dir.exists() || std::fs::read_dir(&b.dir).unwrap().next().is_none());
    // With the app's code it logs in.
    let (outcome, mut logged_in) = b.run_with(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
        &[],
        Some(app),
    );
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", logged_in.notes));
    let app = logged_in.authenticator.take().unwrap();

    // Removal: the re-authentication needs a code, and the removal a newer one.
    let (outcome, disabled) = a.run_with(
        &["2fa", "disable", "--name", "alice"],
        &[PASSWORD],
        &[],
        Some(app),
    );
    outcome.unwrap_or_else(|e| panic!("2fa disable: {e:?} {:?}", disabled.notes));
    assert!(disabled.noted("Two-factor login is off"));
    // A login asks for no code any more.
    let c = Rv::new("c");
    let (outcome, login) = log_in(&c, &origin, &secret_key, PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
}

/// CRYPTO.md §11.9 through the binaries: `rv recovery start` and `rv recovery complete` on a
/// computer that holds nothing, against a server whose waiting period is 0 hours
/// (`RIZZY_RECOVERY_WAIT_HOURS=0`): the new kit, the rotation, the new device; then the old
/// device follows (its grant, the new password, the new Secret Key), and only the new
/// credentials and the new recovery code work.
#[test]
fn recovery_completes_through_the_binaries() {
    let server = Server::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")], None);
    let origin = server.origin();
    let a = Rv::new("a");
    let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");
    create_note(&a, PASSWORD, "Before");

    let r = Rv::new("r");
    let started = r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );
    let available_at: u64 = started.out[0].parse().unwrap();
    assert!(available_at <= rizzy_cli::sys::now_ms());
    let (outcome, done) = r.try_run(
        &[
            "recovery", "complete", "--server", &origin, "--name", "alice",
        ],
        &[&recovery_code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("recovery complete: {e:?} {:?}", done.notes));
    assert!(done.noted("account is recovered"), "{:?}", done.notes);
    let new_secret_key = done.printed("Secret Key:");
    let new_recovery_code = done.printed("Recovery code:");
    assert_ne!(new_secret_key, secret_key);
    assert_ne!(new_recovery_code, recovery_code);
    // The recovered computer is a device of the account and reads the vault.
    assert_eq!(r.item_names(RECOVERED_PASSWORD), ["Before"]);
    create_note(&r, RECOVERED_PASSWORD, "Recovered");

    // The old device follows: the rotation's grant, then the new password and Secret Key.
    let followed = a.ok(
        &["sync"],
        &[PASSWORD, RECOVERED_PASSWORD, &new_secret_key],
        &["alice"],
    );
    assert!(
        followed.noted("changed on another device"),
        "{:?}",
        followed.notes
    );
    let mut names = a.item_names(RECOVERED_PASSWORD);
    names.sort();
    assert_eq!(names, ["Before", "Recovered"]);

    // Only the new credentials log in, and only the new code starts a recovery.
    let c = Rv::new("c");
    let (outcome, _) = log_in(&c, &origin, &secret_key, PASSWORD);
    assert!(wrong_credentials(&outcome), "{outcome:?}");
    let (outcome, login) = log_in(&c, &origin, &new_secret_key, RECOVERED_PASSWORD);
    outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
    let (outcome, _) = Rv::new("r2").try_run(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
    Rv::new("r3").ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&new_recovery_code],
        &[],
    );
}

/// What `rv`'s data directory holds for its one account, read without unlocking.
struct CacheState {
    /// The device-state record's stage.
    stage: Stage,
    /// The stored commit.
    pending_commit: Option<Vec<u8>>,
    /// This device's id, in hex.
    device: String,
}

/// The cache of the one account in `rv`'s data directory; `None` if there is no cache file.
fn cache_state(rv: &Rv) -> Option<CacheState> {
    use std::fmt::Write as _;
    let accounts = rizzy_cli::paths::enrolled_accounts(&rv.dir).unwrap();
    let account = match accounts.as_slice() {
        [] => return None,
        [one] => *one,
        more => panic!("{} caches", more.len()),
    };
    rv.runtime.block_on(async {
        let path = rizzy_cli::paths::cache_path(&rv.dir, &account);
        let mut db = rizzy_cli::db::Db::open(&path).await.unwrap();
        let rows = db.read().await.unwrap();
        db.close().await;
        let record = load::open(&rows, false).unwrap();
        let device = record
            .device_id()
            .to_bytes()
            .iter()
            .fold(String::new(), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            });
        Some(CacheState {
            stage: record.stage(),
            pending_commit: rows.pending_commit.clone(),
            device,
        })
    })
}

/// How many Emergency Kits a run printed.
fn kits(script: &Script) -> usize {
    script
        .out
        .iter()
        .filter(|l| l.starts_with("Secret Key:"))
        .count()
}

/// A new recovery attempt of alice's run to its pre-commit write, then "killed": the flow is
/// dropped before the commit is sent (ADR 0046 §5's crash point). Returns the outcome, the
/// body the attempt stored, and the run's output.
fn recovery_until_the_commit(
    rv: &Rv,
    origin: &str,
    code: &str,
) -> (Result<Vec<u8>, CliError>, Script) {
    let mut script = Script {
        secrets: VecDeque::from([
            code.to_owned(),
            RECOVERED_PASSWORD.to_owned(),
            RECOVERED_PASSWORD.to_owned(),
        ]),
        ..Script::default()
    };
    let outcome = {
        let mut env = Env {
            data_dir: rv.dir.clone(),
            account: None,
            trust: rizzy_cli::tls::Trust::default(),
            ui: &mut script,
            sign_outs: SignOuts::default(),
            pauses: rizzy_cli::http::Pauses::default(),
        };
        rv.runtime
            .block_on(rizzy_cli::recover::prepare(&mut env, origin, "alice", true))
            .map(|prepared| {
                let body = prepared.body().to_vec();
                drop(prepared);
                body
            })
    };
    (outcome, script)
}

/// `rv recovery complete --server origin --name alice`.
fn complete_args(origin: &str) -> [&str; 6] {
    [
        "recovery", "complete", "--server", origin, "--name", "alice",
    ]
}

/// ADR 0046 §5, the first crash-injection case: a recovery killed after its pre-commit write.
/// The stage-3 record is on disk with the exact commit; while it is unsettled no second kit is
/// made (INV-71), no other command opens it and `device forget` does not remove it. Another
/// device's write then makes the stored commit stale; the next `recovery complete` asks for no
/// new credentials, tries device authentication (refused), the OPAQUE-login probe (the old
/// credentials still hold), then resends the stored body byte for byte over a fresh recovery
/// session. The server refuses it (`state_conflict`), and the record is abandoned with no
/// row left behind, so a new attempt starts from nothing and succeeds.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one interrupted recovery, settled step by step"
)]
fn an_interrupted_recovery_is_resent_and_abandoned_when_its_commit_went_stale() {
    let (proxy, server) = Proxy::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")]);
    let origin = server.origin();
    let a = Rv::new("a");
    let (_, recovery_code) = sign_up(&a, &origin, "alice");
    create_note(&a, PASSWORD, "Before");
    let r = Rv::new("r");
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );

    // Killed after the pre-commit write: nothing was sent, the stage-3 record is on disk.
    let (outcome, crashed) = recovery_until_the_commit(&r, &origin, &recovery_code);
    let stored = outcome.unwrap_or_else(|e| panic!("prepare: {e:?} {:?}", crashed.notes));
    assert_eq!(kits(&crashed), 1);
    assert!(proxy.bodies(paths::ACCOUNT_COMMIT).is_empty());
    let cache = cache_state(&r).unwrap();
    assert_eq!(cache.stage, Stage::RecoveryPending);
    assert_eq!(cache.pending_commit.as_deref(), Some(stored.as_slice()));

    // INV-71: no second kit while the record is unsettled, and it is not removed unsettled.
    let (outcome, again) = recovery_until_the_commit(&r, &origin, &recovery_code);
    assert!(
        matches!(outcome, Err(CliError::AlreadyEnrolled)),
        "{outcome:?}"
    );
    assert_eq!(kits(&again), 0);
    let (outcome, listed) = r.try_run(&["item", "list"], &[], &[]);
    assert!(
        matches!(outcome, Err(CliError::Client(ClientError::RecoveryPending))),
        "{outcome:?}"
    );
    assert!(listed.noted("rv recovery"), "{:?}", listed.notes);
    let (outcome, _) = r.try_run(&["device", "forget"], &[], &["FORGET"]);
    assert!(
        matches!(outcome, Err(CliError::Client(ClientError::RecoveryPending))),
        "{outcome:?}"
    );
    assert_eq!(cache_state(&r).unwrap().stage, Stage::RecoveryPending);

    // Another device writes to the vault: the stored rotation's cursor is stale now.
    create_note(&a, PASSWORD, "Meanwhile");

    // The next run settles the record: the new password, then (once device authentication and
    // the probe ruled out "it landed") the recovery code; no new kit.
    let mark = proxy.paths().len();
    let (outcome, settled) = r.try_run(
        &complete_args(&origin),
        &[RECOVERED_PASSWORD, &recovery_code],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::StateConflict))),
        "{outcome:?} {:?}",
        settled.notes
    );
    assert!(
        settled.noted("did not reach the server and was discarded"),
        "{:?}",
        settled.notes
    );
    assert_eq!(kits(&settled), 0);
    assert!(settled.secrets.is_empty());
    let steps: Vec<String> = proxy.paths()[mark..]
        .iter()
        .filter(|p| {
            [
                paths::DEVICE_AUTH_START,
                paths::LOGIN_START,
                paths::RECOVERY_COMPLETE,
                paths::ACCOUNT_COMMIT,
                paths::ACCOUNT_REREGISTER_START,
            ]
            .contains(&p.as_str())
        })
        .cloned()
        .collect();
    assert_eq!(
        steps,
        [
            paths::DEVICE_AUTH_START,
            paths::LOGIN_START,
            paths::RECOVERY_COMPLETE,
            paths::ACCOUNT_COMMIT,
        ]
    );
    // The resend is the stored body, byte for byte, and the only commit sent.
    assert_eq!(proxy.bodies(paths::ACCOUNT_COMMIT), [stored]);
    // Abandoned: no cache file, so no row, and no lock file.
    assert!(cache_state(&r).is_none());
    assert!(
        std::fs::read_dir(&r.dir).unwrap().all(|e| e
            .unwrap()
            .path()
            .extension()
            .is_none_or(|x| x != "lock")),
    );

    // A new attempt starts from nothing (no `AlreadyEnrolled`) and recovers the account.
    let (outcome, done) = r.try_run(
        &complete_args(&origin),
        &[&recovery_code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("recovery complete: {e:?} {:?}", done.notes));
    assert!(done.noted("account is recovered"), "{:?}", done.notes);
    assert_eq!(kits(&done), 1);
    let cache = cache_state(&r).unwrap();
    assert_eq!(cache.stage, Stage::Committed);
    assert!(cache.pending_commit.is_none());
    let mut names = r.item_names(RECOVERED_PASSWORD);
    names.sort();
    assert_eq!(names, ["Before", "Meanwhile"]);
}

/// ADR 0046 §3 step 2: the server applied the recovery but its answer was lost. The stage-3
/// record stays; the next `recovery complete` asks for the new password only, device
/// authentication succeeds, and the record is finalised with no probe, no recovery code and no
/// resend.
#[test]
fn a_recovery_whose_answer_was_lost_is_finished_by_device_authentication() {
    let (proxy, server) = Proxy::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")]);
    let origin = server.origin();
    let a = Rv::new("a");
    let (_, recovery_code) = sign_up(&a, &origin, "alice");
    create_note(&a, PASSWORD, "Before");
    let r = Rv::new("r");
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, lost) = r.try_run(
        &complete_args(&origin),
        &[&recovery_code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    assert!(proxy.fired());
    assert!(outcome.is_err());
    assert!(lost.noted("is unknown"), "{:?}", lost.notes);
    assert_eq!(kits(&lost), 1);
    assert_eq!(cache_state(&r).unwrap().stage, Stage::RecoveryPending);

    let mark = proxy.paths().len();
    let (outcome, finished) = r.try_run(&complete_args(&origin), &[RECOVERED_PASSWORD], &[]);
    outcome.unwrap_or_else(|e| panic!("resume: {e:?} {:?}", finished.notes));
    assert!(
        finished.noted("had applied the recovery"),
        "{:?}",
        finished.notes
    );
    assert!(
        finished.noted("account is recovered"),
        "{:?}",
        finished.notes
    );
    assert_eq!(kits(&finished), 0);
    let since = &proxy.paths()[mark..];
    for path in [
        paths::LOGIN_START,
        paths::RECOVERY_COMPLETE,
        paths::ACCOUNT_COMMIT,
    ] {
        assert!(!since.iter().any(|p| p == path), "{path} in {since:?}");
    }
    let cache = cache_state(&r).unwrap();
    assert_eq!(cache.stage, Stage::Committed);
    assert!(cache.pending_commit.is_none());
    assert_eq!(r.item_names(RECOVERED_PASSWORD), ["Before"]);
}

/// ADR 0046 §5, the second crash-injection case: the recovery landed (its answer was lost),
/// then another device revoked the recovering computer's device. Device authentication is
/// refused, the OPAQUE-login probe succeeds: the record is finalised, nothing is removed or
/// resent, no recovery code is asked for, and the user is told to enrol again.
#[test]
fn a_landed_recovery_whose_device_was_revoked_is_finalised_not_abandoned() {
    let (proxy, server) = Proxy::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")]);
    let origin = server.origin();
    let a = Rv::new("a");
    let (_, recovery_code) = sign_up(&a, &origin, "alice");
    create_note(&a, PASSWORD, "Before");
    let r = Rv::new("r");
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&recovery_code],
        &[],
    );
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, lost) = r.try_run(
        &complete_args(&origin),
        &[&recovery_code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    assert!(proxy.fired() && outcome.is_err());
    let new_secret_key = lost.printed("Secret Key:");
    let new_recovery_code = lost.printed("Recovery code:");

    // A follows the recovery, then revokes the recovering computer's device.
    a.ok(
        &["sync"],
        &[PASSWORD, RECOVERED_PASSWORD, &new_secret_key],
        &["alice"],
    );
    let device = cache_state(&r).unwrap().device;
    let (outcome, revoked) = a.try_run(
        &["device", "revoke", &device, "--name", "alice", "--standard"],
        &[RECOVERED_PASSWORD, &new_recovery_code],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("revoke: {e:?} {:?}", revoked.notes));

    let commits = proxy.bodies(paths::ACCOUNT_COMMIT).len();
    let recoveries = proxy.bodies(paths::RECOVERY_COMPLETE).len();
    let (outcome, settled) = r.try_run(&complete_args(&origin), &[RECOVERED_PASSWORD], &[]);
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?} {:?}",
        settled.notes
    );
    assert!(
        settled.noted("had applied the recovery"),
        "{:?}",
        settled.notes
    );
    assert!(settled.noted("rv device forget"), "{:?}", settled.notes);
    assert_eq!(kits(&settled), 0);
    assert!(settled.secrets.is_empty());
    assert_eq!(proxy.bodies(paths::ACCOUNT_COMMIT).len(), commits);
    assert_eq!(proxy.bodies(paths::RECOVERY_COMPLETE).len(), recoveries);
    // Finalised, not removed.
    let cache = cache_state(&r).unwrap();
    assert_eq!(cache.stage, Stage::Committed);
    assert!(cache.pending_commit.is_none());
}

// ADR 0108: leaving an interrupted recovery whose new master password is lost.

/// `rv recovery abandon --server origin --name alice --confirm`.
fn abandon_args(origin: &str) -> [&str; 7] {
    [
        "recovery",
        "abandon",
        "--server",
        origin,
        "--name",
        "alice",
        "--confirm",
    ]
}

/// alice signed up on `a`, a recovery started on `r` with her code R, and `r`'s attempt killed
/// after its pre-commit write (ADR 0046 §5). Returns R, the new kit's code R′ and the stored
/// commit body.
fn interrupted(origin: &str, a: &Rv, r: &Rv) -> (String, String, Vec<u8>) {
    let (_, code) = sign_up(a, origin, "alice");
    r.ok(
        &["recovery", "start", "--server", origin, "--name", "alice"],
        &[&code],
        &[],
    );
    let (outcome, crashed) = recovery_until_the_commit(r, origin, &code);
    let stored = outcome.unwrap_or_else(|e| panic!("prepare: {e:?} {:?}", crashed.notes));
    let new_code = crashed.printed("Recovery code:");
    assert_eq!(cache_state(r).unwrap().stage, Stage::RecoveryPending);
    (code, new_code, stored)
}

/// An `Env` over `rv`'s data directory with `script` as the user.
fn env_of<'a>(rv: &Rv, script: &'a mut Script) -> Env<'a> {
    Env {
        data_dir: rv.dir.clone(),
        account: None,
        trust: rizzy_cli::tls::Trust::default(),
        ui: script,
        sign_outs: SignOuts::default(),
        pauses: rizzy_cli::http::Pauses::default(),
    }
}

/// A script that answers the secret prompts with `secrets`, in order.
fn answering(secrets: &[&str]) -> Script {
    Script {
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        ..Script::default()
    }
}

/// Neither recovery code appears on standard output, standard error or in the outcome's
/// `Debug` (CLAUDE.md "Never log secrets").
fn no_code_shown(outcome: &Result<(), CliError>, script: &Script, codes: &[&str]) {
    let debug = format!("{outcome:?}");
    for code in codes {
        assert!(!debug.contains(code));
        assert!(
            script
                .out
                .iter()
                .chain(&script.notes)
                .all(|l| !l.contains(code))
        );
    }
}

/// The bytes of `rv`'s one cache file.
fn cache_bytes(rv: &Rv) -> Vec<u8> {
    let accounts = rizzy_cli::paths::enrolled_accounts(&rv.dir).unwrap();
    std::fs::read(rizzy_cli::paths::cache_path(&rv.dir, &accounts[0])).unwrap()
}

/// Sends `body` to `account/commit` over the recovery-only session `token`, as a copy of a
/// commit still in transit would arrive.
fn commit_over(
    rv: &Rv,
    origin: &str,
    token: &rizzy_client::rizzy_proto::wire::SessionToken,
    body: &[u8],
) -> Result<(), CliError> {
    let http = rizzy_cli::http::Http::new(origin, &rizzy_cli::tls::Trust::default()).unwrap();
    rv.runtime.block_on(http.post_bytes_empty(
        paths::ACCOUNT_COMMIT,
        body.to_vec(),
        rizzy_cli::http::Auth::Bearer(token),
    ))
}

/// The `<ms>` of a removal's one standard-output line `<word> <ms>`.
fn removal_line(script: &Script, word: &str) -> u64 {
    assert_eq!(script.out.len(), 1, "{:?}", script.out);
    script.out[0]
        .strip_prefix(word)
        .and_then(|rest| rest.strip_prefix(' '))
        .unwrap_or_else(|| panic!("{:?}", script.out))
        .parse()
        .unwrap()
}

/// ADR 0108 §2, the commit never landed and R′ is lost: an empty R′, then R, which the server
/// accepts. A crash after that probe and before the removal leaves the record, and the rerun
/// repeats the same probe (the same pending recovery, `available_at_ms` unchanged) and
/// removes it. A fresh `rv recovery complete` then succeeds, and K1's code is refused.
#[test]
fn abandon_when_the_commit_never_landed_and_its_kit_is_lost() {
    let (proxy, server) = Proxy::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")]);
    let origin = server.origin();
    let (a, r) = (Rv::new("a"), Rv::new("r"));
    let (code, new_code, _) = interrupted(&origin, &a, &r);

    // Crash before the removal: the deciding probe answered, nothing was removed.
    let mark = proxy.paths().len();
    let mut script = answering(&["", &code]);
    let decided = r
        .runtime
        .block_on(rizzy_cli::recover::abandon_until_the_removal(
            &mut env_of(&r, &mut script),
            &origin,
            "alice",
        ))
        .unwrap();
    assert_eq!(
        decided.outcome(),
        rizzy_cli::recover::AbandonOutcome::NotLanded
    );
    let available_at = decided.available_at_ms();
    drop(decided);
    assert_eq!(cache_state(&r).unwrap().stage, Stage::RecoveryPending);

    // The rerun: the same probe, the same pending recovery, then the removal.
    let (outcome, removed) = r.try_run(&abandon_args(&origin), &["", &code], &[]);
    outcome.unwrap_or_else(|e| panic!("abandon: {e:?} {:?}", removed.notes));
    no_code_shown(&Ok(()), &removed, &[&code, &new_code]);
    assert_eq!(removal_line(&removed, "not-landed"), available_at);
    assert!(
        removed.noted("had not reached the server"),
        "{:?}",
        removed.notes
    );
    assert!(cache_state(&r).is_none());
    assert_eq!(
        proxy.paths()[mark..],
        [paths::RECOVERY_START, paths::RECOVERY_START]
    );

    // A fresh recovery succeeds; the abandoned kit's code is refused.
    let (outcome, fresh) = r.try_run(
        &complete_args(&origin),
        &[&code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("complete: {e:?} {:?}", fresh.notes));
    assert_eq!(kits(&fresh), 1);
    let (outcome, _) = Rv::new("r2").try_run(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&new_code],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
}

/// ADR 0108 §2, the commit landed but its answer was lost. Without R′, R is refused:
/// `RecoveryNotSettled`, exit 1, nothing on standard output, the cache file byte-identical.
/// With R′, probe A answers `200`: the record is removed and no R is asked; `rv recovery
/// complete` with R′ then succeeds.
#[test]
fn abandon_with_the_new_kit_after_the_commit_landed() {
    let (proxy, server) = Proxy::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")]);
    let origin = server.origin();
    let (a, r) = (Rv::new("a"), Rv::new("r"));
    let (_, code) = sign_up(&a, &origin, "alice");
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&code],
        &[],
    );
    proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
    let (outcome, lost) = r.try_run(
        &complete_args(&origin),
        &[&code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    assert!(proxy.fired());
    assert!(outcome.is_err());
    let new_code = lost.printed("Recovery code:");
    assert_eq!(cache_state(&r).unwrap().stage, Stage::RecoveryPending);

    // Landed, no R′: R is no longer the server's code.
    let before = cache_bytes(&r);
    let (outcome, refused) = r.try_run(&abandon_args(&origin), &["", &code], &[]);
    assert!(
        matches!(outcome, Err(CliError::RecoveryNotSettled)),
        "{outcome:?}"
    );
    assert_eq!(outcome.as_ref().unwrap_err().exit_code(), 1);
    assert!(refused.out.is_empty());
    no_code_shown(&outcome, &refused, &[&code, &new_code]);
    assert_eq!(cache_bytes(&r), before);

    // Landed, R′: probe A decides; probe B never runs.
    let mark = proxy.paths().len();
    let (outcome, removed) = r.try_run(&abandon_args(&origin), &[&new_code], &[]);
    outcome.unwrap_or_else(|e| panic!("abandon: {e:?} {:?}", removed.notes));
    removal_line(&removed, "landed");
    assert!(
        removed.noted("had reached the server"),
        "{:?}",
        removed.notes
    );
    no_code_shown(&Ok(()), &removed, &[&code, &new_code]);
    assert_eq!(proxy.paths()[mark..], [paths::RECOVERY_START]);
    assert!(cache_state(&r).is_none());

    // The pending recovery for R′ completes.
    let (outcome, fresh) = r.try_run(
        &complete_args(&origin),
        &[
            &new_code,
            "a third master password",
            "a third master password",
        ],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("complete: {e:?} {:?}", fresh.notes));
}

/// ADR 0108 §2, the refusals: no stage-3 record (a stage-1 record is never touched), a lock
/// held by another `rv`, and with the server stopped: a wrong R′ is `BadInput`, not
/// `Network` (no round trip), probe A and probe B are `Network`, and no `--confirm` is the
/// usage error, exit 2. The cache file stays byte-identical, and nothing is printed on
/// standard output.
#[test]
fn abandon_refusals_keep_the_record() {
    let server = Server::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")], None);
    let origin = server.origin();
    let (a, r) = (Rv::new("a"), Rv::new("r"));
    let (code, new_code, _) = interrupted(&origin, &a, &r);
    let before = cache_bytes(&r);
    let codes = [code.as_str(), new_code.as_str()];

    let (outcome, script) = a.try_run(&abandon_args(&origin), &[&new_code], &[]);
    assert!(
        matches!(outcome, Err(CliError::NoUnfinishedRecovery)),
        "{outcome:?}"
    );
    assert!(script.out.is_empty());
    assert_eq!(script.secrets.len(), 1, "nothing was asked");
    assert_eq!(cache_state(&a).unwrap().stage, Stage::Committed);

    let account = rizzy_cli::paths::enrolled_accounts(&r.dir).unwrap()[0];
    let held = rizzy_cli::paths::AccountLock::acquire(&r.dir, &account).unwrap();
    let (outcome, script) = r.try_run(&abandon_args(&origin), &[&new_code], &[]);
    assert!(matches!(outcome, Err(CliError::InUse)), "{outcome:?}");
    assert!(script.out.is_empty());
    drop(held);

    drop(server);
    let (outcome, script) = r.try_run(&abandon_args(&origin), &[&code], &[]);
    assert!(matches!(outcome, Err(CliError::BadInput(_))), "{outcome:?}");
    assert!(script.out.is_empty());
    no_code_shown(&outcome, &script, &codes);
    let (outcome, script) = r.try_run(&abandon_args(&origin), &[&new_code], &[]);
    assert!(matches!(outcome, Err(CliError::Network)), "{outcome:?}");
    assert!(
        script.noted("still saved on this computer"),
        "{:?}",
        script.notes
    );
    assert!(script.out.is_empty());
    no_code_shown(&outcome, &script, &codes);
    let (outcome, script) = r.try_run(&abandon_args(&origin), &["", &code], &[]);
    assert!(matches!(outcome, Err(CliError::Network)), "{outcome:?}");
    assert!(script.out.is_empty());
    no_code_shown(&outcome, &script, &codes);
    let (outcome, script) = r.try_run(&abandon_args(&origin)[..6], &[&new_code], &[]);
    assert!(matches!(outcome, Err(CliError::Usage(_))), "{outcome:?}");
    assert_eq!(outcome.as_ref().unwrap_err().exit_code(), 2);
    assert!(script.out.is_empty());
    assert_eq!(script.secrets.len(), 1, "nothing was asked");

    assert_eq!(cache_bytes(&r), before);
    assert_eq!(cache_state(&r).unwrap().stage, Stage::RecoveryPending);
}

/// ADR 0108 §3, C1 in transit and landing after probe B's `200`: it is applied over its own
/// session, so the old code is no longer current; a fresh `rv recovery complete` with R is
/// refused `unauthorized` before any kit is made, and creates no cache file.
#[test]
fn a_commit_in_transit_that_lands_after_the_abandon_voids_the_old_code() {
    let (proxy, server) = Proxy::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")]);
    let origin = server.origin();
    let (a, r) = (Rv::new("a"), Rv::new("r"));
    let (code, _, stored) = interrupted(&origin, &a, &r);
    let first = proxy.recovery_session();
    let (outcome, removed) = r.try_run(&abandon_args(&origin), &["", &code], &[]);
    outcome.unwrap_or_else(|e| panic!("abandon: {e:?} {:?}", removed.notes));
    removal_line(&removed, "not-landed");

    commit_over(&r, &origin, &first, &stored).unwrap();
    let (outcome, fresh) = r.try_run(
        &complete_args(&origin),
        &[&code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
    assert_eq!(kits(&fresh), 0);
    assert!(cache_state(&r).is_none());
}

/// ADR 0108 §3 and INV-122, C1 in transit and arriving after the new attempt's
/// `recovery/complete` was answered: it is refused `unauthorized`, since that answer ended the
/// session C1 rides; the new attempt then commits, and its kit is the live one.
#[test]
fn a_commit_in_transit_that_arrives_after_a_new_complete_is_refused() {
    let (proxy, server) = Proxy::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")]);
    let origin = server.origin();
    let (a, r) = (Rv::new("a"), Rv::new("r"));
    let (code, _, stored) = interrupted(&origin, &a, &r);
    let first = proxy.recovery_session();
    let (outcome, removed) = r.try_run(&abandon_args(&origin), &["", &code], &[]);
    outcome.unwrap_or_else(|e| panic!("abandon: {e:?} {:?}", removed.notes));

    // The new attempt, up to its pre-commit write: its `recovery/complete` was answered.
    let mut script = answering(&[&code, RECOVERED_PASSWORD, RECOVERED_PASSWORD]);
    let prepared = r
        .runtime
        .block_on(rizzy_cli::recover::prepare(
            &mut env_of(&r, &mut script),
            &origin,
            "alice",
            true,
        ))
        .unwrap();
    let live_code = script.printed("Recovery code:");
    assert!(matches!(
        commit_over(&r, &origin, &first, &stored),
        Err(CliError::Server(ErrorCode::Unauthorized))
    ));
    r.runtime
        .block_on(prepared.commit(&mut env_of(&r, &mut script)))
        .unwrap_or_else(|e| panic!("commit: {e:?} {:?}", script.notes));
    assert_eq!(cache_state(&r).unwrap().stage, Stage::Committed);
    Rv::new("r2").ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&live_code],
        &[],
    );
}

/// ADR 0108 §2 "Crash and retry": a removal that crashed after its first unlink left no cache
/// file, only the rollback journal and the lock file. `rv recovery abandon` then finds no
/// record, and a fresh `rv recovery complete` is not refused `AlreadyEnrolled`.
#[test]
fn an_abandon_that_crashed_after_its_first_unlink_is_complete() {
    let server = Server::start(&[("RIZZY_RECOVERY_WAIT_HOURS", "0")], None);
    let origin = server.origin();
    let (a, r) = (Rv::new("a"), Rv::new("r"));
    let (code, _, _) = interrupted(&origin, &a, &r);
    let account = rizzy_cli::paths::enrolled_accounts(&r.dir).unwrap()[0];
    let cache = rizzy_cli::paths::cache_path(&r.dir, &account);
    let mut journal = cache.clone().into_os_string();
    journal.push("-journal");
    std::fs::remove_file(&cache).unwrap();
    std::fs::write(&journal, b"").unwrap();
    assert!(
        std::fs::read_dir(&r.dir).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".lock"))
    );

    let (outcome, script) = r.try_run(&abandon_args(&origin), &["", &code], &[]);
    assert!(
        matches!(outcome, Err(CliError::NoUnfinishedRecovery)),
        "{outcome:?}"
    );
    assert!(script.out.is_empty());
    let (outcome, fresh) = r.try_run(
        &complete_args(&origin),
        &[&code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
        &[],
    );
    outcome.unwrap_or_else(|e| panic!("complete: {e:?} {:?}", fresh.notes));
    assert_eq!(cache_state(&r).unwrap().stage, Stage::Committed);
}

// ADR 0091: removing devices.

/// This device's id in hex, as `device list` prints it.
fn own_device(rv: &Rv, password: &str) -> String {
    let listed = rv.ok(&["device", "list"], &[password], &[]);
    listed
        .out
        .iter()
        .find(|l| l.contains("this device"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_owned()
}

/// `rv device revoke <devices> --name alice` with `extra` options.
fn revoke_args<'a>(devices: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["device", "revoke"];
    args.extend_from_slice(devices);
    args.extend_from_slice(&["--name", "alice"]);
    args.extend_from_slice(extra);
    args
}

/// Whether `outcome` is the scripted crash.
fn crashed(outcome: &Result<(), CliError>) -> bool {
    matches!(outcome, Err(CliError::Refused(text)) if text == CRASHED)
}

/// An account on a server behind a [`Proxy`], with device A and `others` more devices.
struct Removal {
    /// The proxy (and the server behind it).
    proxy: Proxy,
    /// The server.
    _server: Server,
    /// The origin `rv` dials.
    origin: String,
    /// The revoking device.
    a: Rv,
    /// The other devices, with their ids.
    others: Vec<(Rv, String)>,
    /// The Secret Key at signup.
    secret_key: String,
    /// The recovery code at signup.
    recovery_code: String,
    /// The tag of the test, for new devices' directories.
    tag: &'static str,
}

impl Removal {
    fn start(tag: &'static str, others: usize) -> Self {
        let (proxy, server) = Proxy::start(&[]);
        let origin = server.origin();
        let a = Rv::new(&format!("{tag}-a"));
        let (secret_key, recovery_code) = sign_up(&a, &origin, "alice");
        create_note(&a, PASSWORD, "Before");
        let others = (0..others)
            .map(|i| {
                let rv = Rv::new(&format!("{tag}-d{i}"));
                let (outcome, login) = log_in(&rv, &origin, &secret_key, PASSWORD);
                outcome.unwrap_or_else(|e| panic!("login: {e:?} {:?}", login.notes));
                let id = own_device(&rv, PASSWORD);
                (rv, id)
            })
            .collect();
        Self {
            proxy,
            _server: server,
            origin,
            a,
            others,
            secret_key,
            recovery_code,
            tag,
        }
    }

    /// The id of other device `i`.
    fn id(&self, i: usize) -> &str {
        &self.others[i].1
    }

    /// A new device that logs in with `secret_key`; its outcome and how often it was paused.
    fn new_login(&self, secret_key: &str) -> (Result<(), CliError>, usize) {
        let rv = Rv::new(&format!("{}-new", self.tag));
        let (outcome, _) = log_in(&rv, &self.origin, secret_key, PASSWORD);
        (outcome, rv.paused())
    }

    /// ADR 0091 §7 test 5's end state, after the removal of the first `removed` other devices
    /// with the new Secret Key `new_secret_key` (`None`: the Secret Key was kept): each is
    /// listed once, revoked, and refused by the server; A holds no pending record; the new
    /// Secret Key logs in and the old one does not; and no revocation window is left open, so
    /// a new device enrols at once, never paused.
    fn assert_removed(&self, removed: usize, new_secret_key: Option<&str>) {
        let cache = cache_state(&self.a).unwrap();
        assert!(cache.pending_commit.is_none() && cache.stage == Stage::Committed);
        let listed = self.a.ok(&["device", "list"], &[PASSWORD], &[]);
        for (rv, id) in &self.others[..removed] {
            let lines: Vec<&String> = listed.out.iter().filter(|l| l.starts_with(id)).collect();
            assert_eq!(lines.len(), 1, "{:?}", listed.out);
            assert!(lines[0].ends_with("revoked"), "{:?}", listed.out);
            let (outcome, refused) = rv.try_run(&["sync"], &[PASSWORD], &[]);
            assert!(
                matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
                "{outcome:?}"
            );
            assert!(refused.noted("rv device forget"), "{:?}", refused.notes);
        }
        let current = new_secret_key.unwrap_or(&self.secret_key);
        let (outcome, paused) = self.new_login(current);
        outcome.unwrap_or_else(|e| panic!("login with the current Secret Key: {e:?}"));
        assert_eq!(paused, 0, "a revocation window was still open");
        if new_secret_key.is_some() {
            let (outcome, _) = self.new_login(&self.secret_key);
            assert!(wrong_credentials(&outcome), "{outcome:?}");
        }
        // Nothing is left half removed.
        let synced = self.a.ok(&["sync"], &[PASSWORD], &[]);
        assert!(!synced.noted("not finished"), "{:?}", synced.notes);
        assert!(self.a.item_names(PASSWORD).contains(&"Before".to_owned()));
    }
}

/// ADR 0091 §3, the default: two devices removed in one commit, with a new Secret Key and kit
/// (and a new recovery code: recovery is on); the list showed each with its enrolment time,
/// marked recent.
#[test]
fn two_devices_are_removed_at_once_with_a_new_secret_key() {
    let r = Removal::start("two", 3);
    let listed = r.a.ok(&["device", "list"], &[PASSWORD], &[]);
    assert!(
        listed.out.iter().filter(|l| l.contains("recent")).count() == 4,
        "{:?}",
        listed.out
    );
    let removed =
        r.a.ok(&revoke_args(&[r.id(1), r.id(0)], &[]), &[PASSWORD], &[]);
    assert_eq!(kits(&removed), 1);
    let new_secret_key = removed.printed("Secret Key:");
    let new_recovery_code = removed.printed("Recovery code:");
    assert!(new_secret_key != r.secret_key && new_recovery_code != r.recovery_code);
    for text in [
        "enrolled in the last 30 days",
        "The devices were revoked",
        "only the new Emergency Kit works",
        "the identity keys were rotated",
    ] {
        assert!(removed.noted(text), "{text}: {:?}", removed.notes);
    }
    // The revocation is one commit.
    assert_eq!(r.proxy.bodies(paths::ACCOUNT_COMMIT).len(), 1);
    r.assert_removed(2, Some(&new_secret_key));
    // The third device stays: it follows the change (the new identity confirmed, the new
    // Secret Key typed from the kit) and reads the account.
    let (third, _) = &r.others[2];
    let (outcome, followed) = third.try_run(
        &["sync"],
        &[PASSWORD, PASSWORD, &new_secret_key],
        &["CONFIRM", "alice"],
    );
    outcome.unwrap_or_else(|e| panic!("follow: {e:?} {:?}", followed.notes));
    assert_eq!(third.item_names(PASSWORD), ["Before"]);
}

/// `--keep-secret-key` (a full rotation, the Secret Key kept) and `--standard` (wiped and
/// handed over: a standard rotation, the Secret Key kept). Both ask for the recovery code,
/// which stays valid.
#[test]
fn a_removal_can_keep_the_secret_key_or_be_standard() {
    let r = Removal::start("keep", 2);
    let kept = r.a.ok(
        &revoke_args(&[r.id(0)], &["--keep-secret-key"]),
        &[PASSWORD, &r.recovery_code],
        &[],
    );
    assert_eq!(kits(&kept), 0);
    assert!(kept.noted("The device was revoked"), "{:?}", kept.notes);
    assert!(
        kept.noted("the identity keys were rotated"),
        "{:?}",
        kept.notes
    );
    assert!(!kept.noted("Secret Key was changed"), "{:?}", kept.notes);
    r.assert_removed(1, None);
    let standard = r.a.ok(
        &revoke_args(&[r.id(1)], &["--standard"]),
        &[PASSWORD, &r.recovery_code],
        &[],
    );
    assert_eq!(kits(&standard), 0);
    assert!(
        standard.noted("The device was revoked"),
        "{:?}",
        standard.notes
    );
    assert!(!standard.noted("identity keys"), "{:?}", standard.notes);
    r.assert_removed(2, None);
    // The two options do not combine.
    let (outcome, _) = r.a.try_run(
        &revoke_args(&[r.id(1)], &["--standard", "--keep-secret-key"]),
        &[],
        &[],
    );
    assert!(matches!(outcome, Err(CliError::Usage(_))), "{outcome:?}");
}

/// ADR 0091 §7 test 5, the first two points: a crash after the suspension and before the kit,
/// and after the kit and before the pending record. Nothing is saved: the next command names
/// the half-done removal with "Finish removing" and "Cancel"; running `device revoke` again
/// finishes it, with a new kit (the one shown before the crash is void).
#[test]
fn a_removal_that_crashed_before_its_pending_record_is_finished() {
    for (i, point) in [Checkpoint::Suspended, Checkpoint::KitConfirmed]
        .into_iter()
        .enumerate()
    {
        let r = Removal::start(if i == 0 { "crash1" } else { "crash2" }, 1);
        let (outcome, crash) =
            r.a.run_crashing(&revoke_args(&[r.id(0)], &[]), &[PASSWORD], &[], point);
        assert!(crashed(&outcome), "{point:?}: {outcome:?}");
        assert_eq!(kits(&crash), usize::from(point == Checkpoint::KitConfirmed));
        assert!(cache_state(&r.a).unwrap().pending_commit.is_none());
        assert!(r.proxy.bodies(paths::ACCOUNT_COMMIT).is_empty());
        // The device is suspended already: the server refuses it.
        let (outcome, _) = r.others[0].0.try_run(&["sync"], &[PASSWORD], &[]);
        assert!(
            matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
            "{outcome:?}"
        );
        // The restart: "Finish removing" and "Cancel".
        let restarted = r.a.ok(&["sync"], &[PASSWORD], &[]);
        for text in [
            format!("rv device revoke {}", r.id(0)),
            format!("rv device unsuspend {}", r.id(0)),
        ] {
            assert!(restarted.noted(&text), "{text}: {:?}", restarted.notes);
        }
        let finished = r.a.ok(&revoke_args(&[r.id(0)], &[]), &[PASSWORD], &[]);
        let new_secret_key = finished.printed("Secret Key:");
        r.assert_removed(1, Some(&new_secret_key));
        if point == Checkpoint::KitConfirmed {
            let (outcome, _) = r.new_login(&crash.printed("Secret Key:"));
            assert!(wrong_credentials(&outcome), "{outcome:?}");
        }
    }
}

/// ADR 0091 §7 test 5, the last three points: a crash after the pending record is written and
/// before sending; the answer lost after the server applied it; a crash after the answer and
/// before finalising. The next run settles the pending record (asking for the login name and
/// the master password of the change, which is the same), resending it only in the first case,
/// and the kit shown before the crash is the one that works.
#[test]
fn a_removal_that_crashed_after_its_pending_record_is_settled() {
    for (i, point) in [
        Some(Checkpoint::Persisted),
        None,
        Some(Checkpoint::Acknowledged),
    ]
    .into_iter()
    .enumerate()
    {
        let r = Removal::start(["crash3", "crash4", "crash5"][i], 1);
        let args = revoke_args(&[r.id(0)], &[]);
        let (outcome, crash) = if let Some(point) = point {
            r.a.run_crashing(&args, &[PASSWORD], &[], point)
        } else {
            r.proxy.arm(paths::ACCOUNT_COMMIT, Fault::AnswerLost);
            let run = r.a.try_run(&args, &[PASSWORD], &[]);
            assert!(r.proxy.fired());
            assert!(matches!(run.0, Err(CliError::BadAnswer)), "{:?}", run.0);
            run
        };
        if point.is_some() {
            assert!(crashed(&outcome), "{point:?}: {outcome:?}");
        }
        let new_secret_key = crash.printed("Secret Key:");
        assert!(
            cache_state(&r.a).unwrap().pending_commit.is_some(),
            "{point:?}"
        );
        let sent = r.proxy.bodies(paths::ACCOUNT_COMMIT).len();
        assert_eq!(sent, usize::from(point != Some(Checkpoint::Persisted)));
        let settled = r.a.ok(&["sync"], &[PASSWORD, PASSWORD], &["alice"]);
        assert!(settled.noted("interrupted"), "{:?}", settled.notes);
        // Resent only when it had never left.
        assert_eq!(r.proxy.bodies(paths::ACCOUNT_COMMIT).len(), 1, "{point:?}");
        r.assert_removed(1, Some(&new_secret_key));
    }
}

/// ADR 0091 §2: while A's window is open, B's upload is refused `revocation_pending`; B shows
/// the pause note once, waits, and sends the same upload again after A's revocation committed.
#[test]
fn a_write_paused_by_another_devices_removal_is_sent_once_it_commits() {
    let r = Removal::start("paused", 2);
    let (b, _) = &r.others[1];
    let args = revoke_args(&[r.id(0)], &["--standard"]);
    // A's removal stops after the suspension: its window is open.
    let (outcome, _) = r.a.run_crashing(
        &args,
        &[PASSWORD, &r.recovery_code],
        &[],
        Checkpoint::Suspended,
    );
    assert!(crashed(&outcome), "{outcome:?}");
    let (refused_tx, refused_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    *b.pause.on_first_wait.lock().unwrap() = Some(Box::new(move || {
        refused_tx.send(()).unwrap();
        go_rx.recv().unwrap();
    }));
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            b.try_run(
                &[
                    "item",
                    "create",
                    "--type",
                    "note",
                    "--field",
                    "item.name=From B",
                ],
                &[PASSWORD],
                &[],
            )
        });
        refused_rx
            .recv_timeout(Duration::from_secs(300))
            .expect("B's write was never refused revocation_pending");
        // A finishes the removal while B waits; its commit closes the window.
        r.a.ok(&args, &[PASSWORD, &r.recovery_code], &[]);
        go_tx.send(()).unwrap();
        let (outcome, wrote) = writer.join().unwrap();
        outcome.unwrap_or_else(|e| panic!("B: {e:?} {:?}", wrote.notes));
    });
    assert_eq!(
        *b.pause.notes.lock().unwrap(),
        [REVOCATION_PENDING_MESSAGE.to_owned()]
    );
    let waits = b.pause.waits.lock().unwrap().clone();
    assert!(
        !waits.is_empty() && waits.iter().all(|w| *w <= Duration::from_secs(15)),
        "{waits:?}"
    );
    r.a.ok(&["sync"], &[PASSWORD], &[]);
    let mut names = r.a.item_names(PASSWORD);
    names.sort();
    assert_eq!(names, ["Before", "From B"]);
    r.assert_removed(1, None);
}

/// ADR 0091 §3 step 8, "Cancel": a removal left after the suspension is cancelled with
/// `device unsuspend`; the device syncs again, the window is closed and nothing is named
/// half done any more.
#[test]
fn a_half_done_removal_is_cancelled() {
    let r = Removal::start("cancel", 1);
    let (d, d_id) = &r.others[0];
    let (outcome, _) = r.a.run_crashing(
        &revoke_args(&[d_id], &[]),
        &[PASSWORD],
        &[],
        Checkpoint::Suspended,
    );
    assert!(crashed(&outcome), "{outcome:?}");
    let (outcome, _) = d.try_run(&["sync"], &[PASSWORD], &[]);
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
    let listed = r.a.ok(&["device", "list"], &[PASSWORD], &[]);
    assert!(
        listed
            .out
            .iter()
            .any(|l| l.starts_with(d_id.as_str()) && l.ends_with("suspended")),
        "{:?}",
        listed.out
    );
    let cancelled = r.a.ok(
        &["device", "unsuspend", d_id, "--name", "alice"],
        &[PASSWORD],
        &[],
    );
    assert!(cancelled.noted("cancelled"), "{:?}", cancelled.notes);
    d.ok(&["sync"], &[PASSWORD], &[]);
    let (outcome, paused) = r.new_login(&r.secret_key);
    outcome.unwrap();
    assert_eq!(paused, 0);
    let synced = r.a.ok(&["sync"], &[PASSWORD], &[]);
    assert!(!synced.noted("not finished"), "{:?}", synced.notes);
}

/// ADR 0091 §3 "A revoked device with a pending commit": D saved a rotation and died before
/// sending it; A removes D (keeping the Secret Key, so D's credentials still log in). D's
/// next run is refused at device authentication, logs in over OPAQUE, finds its own
/// revocation in the verified answer and deletes the pending record without sending it.
#[test]
fn a_removed_device_drops_its_pending_commit_unsent() {
    let r = Removal::start("own", 1);
    let (d, d_id) = &r.others[0];
    let (outcome, _) = d.run_crashing(
        &["rotate", "--name", "alice"],
        &[PASSWORD, &r.recovery_code],
        &[],
        Checkpoint::Persisted,
    );
    assert!(crashed(&outcome), "{outcome:?}");
    assert!(cache_state(d).unwrap().pending_commit.is_some());
    r.a.ok(
        &revoke_args(&[d_id], &["--keep-secret-key"]),
        &[PASSWORD, &r.recovery_code],
        &[],
    );
    let commits = r.proxy.bodies(paths::ACCOUNT_COMMIT).len();
    let (outcome, dropped) = d.try_run(&["sync"], &[PASSWORD], &["alice", "CONFIRM"]);
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
    assert!(
        dropped.noted("deleted without being sent"),
        "{:?}",
        dropped.notes
    );
    assert!(dropped.noted("rv device forget"), "{:?}", dropped.notes);
    assert!(cache_state(d).unwrap().pending_commit.is_none());
    assert_eq!(r.proxy.bodies(paths::ACCOUNT_COMMIT).len(), commits);
    // From then on the device is refused and asks nothing.
    let (outcome, again) = d.try_run(&["sync"], &[PASSWORD], &[]);
    assert!(
        matches!(outcome, Err(CliError::Server(ErrorCode::Unauthorized))),
        "{outcome:?}"
    );
    assert!(again.noted("rv device forget"), "{:?}", again.notes);
}
