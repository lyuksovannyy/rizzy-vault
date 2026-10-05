//! `rv`'s account flows end to end against a real `rizzy-vault` server: a master password
//! change and a Secret Key change, also with a full rotation, with the other device following
//! them (CRYPTO.md §11.5, §11.6, §11.3 step 5), an interrupted change settled by the next
//! run, server-side 2FA (§5.10, §11.15), and a recovery with the Emergency Kit completed
//! through the binaries on a server with a zero waiting period (§11.9).
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
use rizzy_cli::device::Env;
use rizzy_cli::ui::Ui;
use rizzy_client::ClientError;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::rizzy_proto::http::paths;
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
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let origin_port = origin_port.unwrap_or(port);
        let command = |dir: &Path| {
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
            for (name, value) in extra {
                command.env(name, value);
            }
            command
        };
        let init = command(&dir).args(["secrets", "init"]).output().unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let mut child = command(&dir).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("rizzy-vault exited at start: {status}");
            }
            assert!(Instant::now() < deadline, "rizzy-vault did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        Self {
            child,
            dir,
            origin_port,
            port,
        }
    }

    /// The origin `rv` dials.
    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.origin_port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

/// A loopback reverse proxy in front of a [`Server`] that loses one answer (`tests/e2e.rs`).
struct Proxy {
    /// Its port.
    port: u16,
    /// The armed fault.
    fault: Arc<Mutex<Option<(&'static str, Fault)>>>,
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
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (thread_fault, thread_stop) = (fault.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(stream) = stream {
                    let _ = Self::serve(stream, upstream, &thread_fault);
                }
            }
        });
        (Self { port, fault, stop }, server)
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
    ) -> std::io::Result<()> {
        use std::io::Write as _;
        client.set_read_timeout(Some(Duration::from_secs(30)))?;
        let (head, body) = Self::read_message(&mut client)?;
        let path = String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
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
}

impl Ui for Script {
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
}

impl Rv {
    fn new(tag: &str) -> Self {
        Self {
            dir: temp_dir(tag).join("rv"),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        }
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
        let mut script = Script {
            secrets: own(secrets),
            lines: own(lines),
            authenticator,
            ..Script::default()
        };
        let outcome = match parse(args.iter().map(OsString::from).collect()) {
            Ok(invocation) => {
                let mut env = Env {
                    data_dir: self.dir.clone(),
                    account: None,
                    trust: rizzy_cli::tls::Trust::default(),
                    ui: &mut script,
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
