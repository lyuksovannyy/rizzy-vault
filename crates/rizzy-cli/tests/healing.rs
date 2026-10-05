//! ADR 0032 "Healing a key rotation made after a backup" end to end: `rv` against the real
//! `rizzy-vault` binary, put back with `rizzy-vault restore` after a backup that predates a
//! standard rotation, a revocation with a full rotation, a Secret Key change and a full
//! rotation. Both devices heal and keep reading and writing; a device that missed the rotation
//! catches up by password; new logins wait for the same-password re-registration (step 5);
//! recovery waits for the user's repair (step 6), which offers only a new code when the code
//! changed after the backup and takes the re-typed code when it did not. The negatives: a
//! revoked device stays refused, and a rollback with nothing to heal it (a native copy put
//! back, no reconciliation epoch) stays an alarm, also across a full rotation.
//!
//! The harness is `tests/account.rs`'s, cut down (ADR 0016 §3 forbids a dependency on
//! `rizzy-server`): the built binary on a loopback port with a temporary `SQLite` database, a
//! loopback reverse proxy that can withhold one request, and `rv` run through its library
//! with a scripted user. It lives in its own file so the suites stay independent.

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
use rizzy_client::store::rows::Alarm;
use zeroize::Zeroizing;

/// The master password at signup.
const PASSWORD: &str = "correct horse battery staple";
/// The master password after a change.
const NEW_PASSWORD: &str = "tremble lantern orbit vintage";
/// The master password a recovery sets.
const RECOVERED_PASSWORD: &str = "quiet meadow copper whistle";

/// A fresh temporary directory.
fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rv-heal-{tag}-{}-{}",
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
    /// The process, while it runs.
    child: Option<Child>,
    /// Its directories.
    dir: PathBuf,
    /// The port of its public origin: its own, or the [`Proxy`]'s.
    origin_port: u16,
    /// Its own port.
    port: u16,
    /// Extra settings.
    extra: Vec<(String, String)>,
}

impl Server {
    /// A new server with open signup, a zero recovery wait, and its public origin on
    /// `origin_port` (a proxy's) or its own port.
    fn start(origin_port: Option<u16>) -> Self {
        let dir = temp_dir("server");
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut server = Self {
            child: None,
            dir,
            origin_port: origin_port.unwrap_or(port),
            port,
            extra: vec![("RIZZY_RECOVERY_WAIT_HOURS".into(), "0".into())],
        };
        let init = server.command().args(["secrets", "init"]).output().unwrap();
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        server.spawn();
        server
    }

    /// The server's command with its settings.
    fn command(&self) -> Command {
        let mut command = Command::new(server_binary());
        command
            .env_clear()
            .env("RIZZY_ORIGIN", self.origin())
            .env("RIZZY_LISTEN", format!("127.0.0.1:{}", self.port))
            .env("RIZZY_SIGNUP", "open")
            .env("RIZZY_DATA_DIR", self.dir.join("data"))
            .env(
                "RIZZY_SECRETS_FILE",
                self.dir.join("secrets").join("secrets.json"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (name, value) in &self.extra {
            command.env(name, value);
        }
        command
    }

    /// Starts the serving process and waits until it accepts connections.
    fn spawn(&mut self) {
        let child = self.child.insert(self.command().spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(60);
        while std::net::TcpStream::connect(("127.0.0.1", self.port)).is_err() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("rizzy-vault exited at start: {status}");
            }
            assert!(Instant::now() < deadline, "rizzy-vault did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Stops the server (the data stays).
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// The origin `rv` dials.
    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.origin_port)
    }

    /// The operator's logical backup (self-hosting.md §9), taken while the server runs.
    fn backup(&self, name: &str) -> PathBuf {
        let file = self.dir.join(name);
        let backup = self
            .command()
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
        let restore = self
            .command()
            .args(["restore", "--in"])
            .arg(backup)
            .output()
            .unwrap();
        assert!(
            restore.status.success(),
            "{}",
            String::from_utf8_lossy(&restore.stderr)
        );
        self.spawn();
    }

    /// The operator's native copy: the server stopped, its data directory copied aside, the
    /// server started again.
    fn native_copy(&mut self, name: &str) -> PathBuf {
        self.stop();
        let copy = self.dir.join(name);
        copy_tree(&self.dir.join("data"), &copy);
        self.spawn();
        copy
    }

    /// Puts a native copy back: no `rizzy-vault restore`, so no reconciliation epoch.
    fn native_restore(&mut self, copy: &Path) {
        self.stop();
        let data = self.dir.join("data");
        std::fs::remove_dir_all(&data).unwrap();
        copy_tree(copy, &data);
        self.spawn();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
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

/// A loopback reverse proxy in front of a [`Server`] that can withhold one request: it never
/// reaches the server, and the client gets a gateway's `502` page.
struct Proxy {
    /// Its port.
    port: u16,
    /// The path whose next request is withheld.
    withheld: Arc<Mutex<Option<&'static str>>>,
    /// Set on drop.
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Proxy {
    /// A proxy and the server behind it.
    fn start() -> (Self, Server) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = Server::start(Some(port));
        let upstream = server.port;
        let withheld = Arc::new(Mutex::new(None));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (thread_withheld, thread_stop) = (withheld.clone(), stop.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(stream) = stream {
                    let _ = Self::serve(stream, upstream, &thread_withheld);
                }
            }
        });
        (
            Self {
                port,
                withheld,
                stop,
            },
            server,
        )
    }

    /// Withholds the next request to `path`.
    fn withhold(&self, path: &'static str) {
        *self.withheld.lock().unwrap() = Some(path);
    }

    /// Whether the withheld request was seen.
    fn fired(&self) -> bool {
        self.withheld.lock().unwrap().is_none()
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
        withheld: &Mutex<Option<&'static str>>,
    ) -> std::io::Result<()> {
        use std::io::Write as _;
        client.set_read_timeout(Some(Duration::from_secs(30)))?;
        let (head, body) = Self::read_message(&mut client)?;
        let path = String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let drop_it = {
            let mut armed = withheld.lock().unwrap();
            if armed.is_some_and(|p| p == path) {
                *armed = None;
                true
            } else {
                false
            }
        };
        let reply = if drop_it {
            b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/html\r\n\
              content-length: 15\r\nconnection: close\r\n\r\n502 Bad Gateway"
                .to_vec()
        } else {
            let mut server = std::net::TcpStream::connect(("127.0.0.1", upstream))?;
            server.set_read_timeout(Some(Duration::from_secs(30)))?;
            server.write_all(&head)?;
            server.write_all(&body)?;
            let (answer_head, answer_body) = Self::read_message(&mut server)?;
            [answer_head, answer_body].concat()
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

/// The scripted user.
#[derive(Default)]
struct Script {
    /// Answers to secret prompts.
    secrets: VecDeque<String>,
    /// Answers to line prompts.
    lines: VecDeque<String>,
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
            // A kit was just printed: the user reads the last group off it.
            let label = if prompt.contains("recovery code") {
                "Recovery code:"
            } else {
                "Secret Key:"
            };
            let kit = self.printed(label);
            return Ok(kit.rsplit('-').next().unwrap().to_owned());
        }
        if prompt.starts_with("Login name") {
            return Ok("alice".to_owned());
        }
        if prompt.starts_with("Type CONFIRM") {
            return Ok("CONFIRM".to_owned());
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
        duration
    }
}

impl Script {
    /// The rest of the last printed line that starts with `label`.
    fn printed(&self, label: &str) -> String {
        self.out
            .iter()
            .rev()
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

    /// Runs one command with scripted answers.
    fn try_run(&self, args: &[&str], secrets: &[&str]) -> (Result<(), CliError>, Script) {
        let mut script = Script {
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
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

    /// Runs a command that must succeed.
    fn ok(&self, args: &[&str], secrets: &[&str]) -> Script {
        let (outcome, script) = self.try_run(args, secrets);
        if let Err(e) = outcome {
            panic!("rv {args:?} failed: {e} ({e:?}); notes: {:?}", script.notes);
        }
        script
    }

    /// The names `item list` prints, unlocked with `password`, sorted.
    fn names(&self, password: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .ok(&["item", "list"], &[password])
            .out
            .iter()
            .map(|line| line.rsplit("  ").next().unwrap().trim().to_owned())
            .collect();
        names.sort();
        names
    }

    /// The hex id `device list` prints first: this device's own, marked `(this device)`.
    fn own_device(&self, password: &str) -> String {
        let listed = self.ok(&["device", "list"], &[password]);
        listed
            .out
            .iter()
            .find(|l| l.contains("this device"))
            .unwrap_or_else(|| panic!("{:?}", listed.out))
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    }
}

impl Drop for Rv {
    fn drop(&mut self) {
        if let Some(parent) = self.dir.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

/// Signs `alice` up and returns the kit's Secret Key and recovery code.
fn sign_up(rv: &Rv, origin: &str) -> (String, String) {
    let signup = rv.ok(
        &["signup", "--server", origin, "--name", "alice"],
        &[PASSWORD, PASSWORD],
    );
    (
        signup.printed("Secret Key:"),
        signup.printed("Recovery code:"),
    )
}

/// Logs a new device in.
fn log_in(rv: &Rv, origin: &str, secret_key: &str, password: &str) -> Result<(), CliError> {
    rv.try_run(
        &["login", "--server", origin, "--name", "alice"],
        &[secret_key, password],
    )
    .0
}

/// Creates a note named `name`, unlocked with `password`.
fn note(rv: &Rv, password: &str, name: &str) {
    let field = format!("item.name={name}");
    rv.ok(
        &["item", "create", "--type", "note", "--field", &field],
        &[password],
    );
}

/// `recovery start` with `code` from a computer that holds nothing.
fn recovery_start(origin: &str, code: &str) -> Result<(), CliError> {
    Rv::new("rs")
        .try_run(
            &["recovery", "start", "--server", origin, "--name", "alice"],
            &[code],
        )
        .0
}

/// Whether `outcome` is the server's refusal `code`.
fn refused(outcome: &Result<(), CliError>, code: ErrorCode) -> bool {
    matches!(outcome, Err(CliError::Server(c)) if *c == code)
}

/// A standard rotation made after the backup (`rv rotate`, the recovery code kept): after the
/// restore, the device that rotated heals the account (steps 1–3b) and its vault (step 4), and
/// re-registers the login record with the typed password (step 5); the other device, which
/// followed the rotation before the restore, reads and writes on the healed server; a new login
/// works; the vault's epoch is the rotated one again (an upload under the old key is refused
/// `stale_epoch`, which the client follows). Recovery is refused until the repair, and the
/// re-typed code, unchanged since the backup, repairs it; a different code does not.
#[test]
fn a_standard_rotation_after_the_backup_is_healed() {
    let mut server = Server::start(None);
    let origin = server.origin();
    let a = Rv::new("sa");
    let b = Rv::new("sb");
    let (secret_key, code) = sign_up(&a, &origin);
    assert!(log_in(&b, &origin, &secret_key, PASSWORD).is_ok());
    note(&a, PASSWORD, "Before");
    b.ok(&["sync"], &[PASSWORD]);
    let backup = server.backup("before.rvbackup");

    // After the backup: a rotation on A, which B follows; both write.
    let rotated = a.ok(&["rotate", "--name", "alice"], &[PASSWORD, &code]);
    assert!(rotated.noted("rotated"), "{:?}", rotated.notes);
    note(&a, PASSWORD, "After rotation, from A");
    b.ok(&["sync"], &[PASSWORD]);
    note(&b, PASSWORD, "After rotation, from B");
    server.restore_from(&backup);

    // A heals: the newer state with `E_id`, the vault's self-grant and wrap set, its records,
    // then the login record with its typed password.
    let healed = a.ok(&["sync"], &[PASSWORD]);
    for text in [
        "Sending the newer one back",
        "holds this device's account state again",
        "has the lost changes again",
    ] {
        assert!(healed.noted(text), "{text}: {:?}", healed.notes);
    }
    assert!(
        !healed.noted("did not work this time"),
        "{:?}",
        healed.notes
    );
    // B reads the healed account, sends its own lost edit back and writes on.
    b.ok(&["sync"], &[PASSWORD]);
    note(&b, PASSWORD, "Healed, from B");
    a.ok(&["sync"], &[PASSWORD]);
    let expected = [
        "After rotation, from A",
        "After rotation, from B",
        "Before",
        "Healed, from B",
    ];
    assert_eq!(a.names(PASSWORD), expected);
    b.ok(&["sync"], &[PASSWORD]);
    assert_eq!(b.names(PASSWORD), expected);
    // A new device logs in on the healed record and reads everything.
    let c = Rv::new("sc");
    assert!(log_in(&c, &origin, &secret_key, PASSWORD).is_ok());
    assert_eq!(c.names(PASSWORD), expected);

    // Recovery: refused until the repair (the restored `E_rec` is under the old account key).
    assert!(refused(
        &recovery_start(&origin, &code),
        ErrorCode::Unauthorized
    ));
    // The code did not change since the backup: a different code is refused, the re-typed
    // current one repairs.
    let other = Rv::new("other");
    let (_, other_code) = sign_up(&other, &Server::start(None).origin());
    let (outcome, script) = a.try_run(
        &["recovery", "repair", "--retype", "--name", "alice"],
        &[PASSWORD, &other_code],
    );
    assert!(
        refused(&outcome, ErrorCode::InvalidRequest),
        "{outcome:?}: {:?}",
        script.notes
    );
    let repaired = a.ok(
        &["recovery", "repair", "--retype", "--name", "alice"],
        &[PASSWORD, &code],
    );
    assert!(repaired.noted("works again"), "{:?}", repaired.notes);
    assert!(recovery_start(&origin, &code).is_ok());
}

/// Step 5 waits for an enrolled device, and a device that missed the rotation catches up by
/// password (ADR 0032 §4): the healer's re-registration is lost on its way (the proxy withholds
/// `account/reregister/start`), so the server's record lags the healed state. A new login is
/// refused with `credentials_stale` after the password verified, and the device that missed the
/// rotation, which finds no grant, is told to open a device that saw the change. The healer's
/// next run re-registers; then the new login works, and the other device logs in with its
/// password, opens `E_srv` to the current key and reads and writes again.
#[test]
fn a_device_that_missed_the_rotation_catches_up_once_the_record_is_re_registered() {
    let (proxy, mut server) = Proxy::start();
    let origin = server.origin();
    let a = Rv::new("ma");
    let b = Rv::new("mb");
    let (secret_key, code) = sign_up(&a, &origin);
    assert!(log_in(&b, &origin, &secret_key, PASSWORD).is_ok());
    note(&b, PASSWORD, "From B");
    a.ok(&["sync"], &[PASSWORD]);
    let backup = server.backup("before.rvbackup");
    a.ok(&["rotate", "--name", "alice"], &[PASSWORD, &code]);
    note(&a, PASSWORD, "After rotation");
    // B does not run before the restore: its grant is lost with it.
    server.restore_from(&backup);

    proxy.withhold(paths::ACCOUNT_REREGISTER_START);
    let healed = a.ok(&["sync"], &[PASSWORD]);
    assert!(proxy.fired());
    assert!(
        healed.noted("holds this device's account state again"),
        "{:?}",
        healed.notes
    );
    assert!(healed.noted("did not work this time"), "{:?}", healed.notes);
    // The record lags: a new login is refused after KE3, and says why.
    let c = Rv::new("mc");
    let (outcome, login) = c.try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, PASSWORD],
    );
    assert!(
        refused(&outcome, ErrorCode::CredentialsStale),
        "{outcome:?}"
    );
    assert!(login.noted("restored from a backup"), "{:?}", login.notes);
    // A wrong password still gets the one answer of §5.9.
    let (outcome, _) = Rv::new("mw").try_run(
        &["login", "--server", &origin, "--name", "alice"],
        &[&secret_key, "not the password at all"],
    );
    assert!(
        matches!(
            outcome,
            Err(CliError::Client(ClientError::WrongPasswordOrSecretKey))
        ),
        "{outcome:?}"
    );
    // B missed the rotation and finds no grant: it adopts nothing yet.
    let (outcome, missed) = b.try_run(&["sync"], &[PASSWORD]);
    assert!(
        refused(&outcome, ErrorCode::CredentialsStale),
        "{outcome:?}: {:?}",
        missed.notes
    );
    assert!(
        missed.noted("Open a device that saw the change"),
        "{:?}",
        missed.notes
    );

    // A's next run re-registers the record with the typed password.
    let reregistered = a.ok(&["sync"], &[PASSWORD]);
    assert!(
        !reregistered.noted("did not work this time"),
        "{:?}",
        reregistered.notes
    );
    assert!(log_in(&c, &origin, &secret_key, PASSWORD).is_ok());
    // B catches up by password and reads and writes again.
    let caught_up = b.ok(&["sync"], &[PASSWORD]);
    assert!(
        caught_up.noted("holds the account's current key again"),
        "{:?}",
        caught_up.notes
    );
    note(&b, PASSWORD, "Caught up, from B");
    a.ok(&["sync"], &[PASSWORD]);
    let expected = ["After rotation", "Caught up, from B", "From B"];
    assert_eq!(a.names(PASSWORD), expected);
    assert_eq!(b.names(PASSWORD), expected);
    c.ok(&["sync"], &[PASSWORD]);
    assert_eq!(c.names(PASSWORD), expected);
}

/// A revocation with a full rotation after the backup (`rv device revoke`): the restored
/// server serves a state the older identity key signed, which the devices that saw the
/// rotation take for a rollback only after comparing the older chain with the bundles they
/// hold (ADR 0032 §1). The revoker heals the chain, the state with the re-issued certificates
/// and revocation, `E_id`, the self-grant and its vault; the device that confirmed the new
/// identity reads and writes on; the revoked device, whose session the restore had brought
/// back, is refused again.
#[test]
fn a_revocation_with_a_full_rotation_after_the_backup_is_healed() {
    let mut server = Server::start(None);
    let origin = server.origin();
    let a = Rv::new("fa");
    let b = Rv::new("fb");
    let c = Rv::new("fc");
    let (secret_key, code) = sign_up(&a, &origin);
    assert!(log_in(&b, &origin, &secret_key, PASSWORD).is_ok());
    assert!(log_in(&c, &origin, &secret_key, PASSWORD).is_ok());
    note(&a, PASSWORD, "Before");
    let c_device = c.own_device(PASSWORD);
    let backup = server.backup("before.rvbackup");

    let revoked = a.ok(
        &["device", "revoke", &c_device, "--name", "alice"],
        &[PASSWORD, &code],
    );
    assert!(revoked.noted("revoked"), "{:?}", revoked.notes);
    // B confirms the new identity and follows; then it writes.
    b.ok(&["sync"], &[PASSWORD]);
    note(&b, PASSWORD, "After revocation, from B");
    server.restore_from(&backup);

    let healed = a.ok(&["sync"], &[PASSWORD]);
    for text in [
        "Sending the newer one back",
        "holds this device's account state again",
    ] {
        assert!(healed.noted(text), "{text}: {:?}", healed.notes);
    }
    note(&a, PASSWORD, "Healed, from A");
    b.ok(&["sync"], &[PASSWORD]);
    a.ok(&["sync"], &[PASSWORD]);
    let expected = ["After revocation, from B", "Before", "Healed, from A"];
    assert_eq!(a.names(PASSWORD), expected);
    assert_eq!(b.names(PASSWORD), expected);
    // The revoked device is refused again.
    let (outcome, _) = c.try_run(&["sync"], &[PASSWORD]);
    assert!(refused(&outcome, ErrorCode::Unauthorized), "{outcome:?}");
    // A new device logs in on the healed account.
    let d = Rv::new("fd");
    assert!(log_in(&d, &origin, &secret_key, PASSWORD).is_ok());
    assert_eq!(d.names(PASSWORD), expected);
}

/// A password change and a Secret Key change with a full rotation after the backup, each of
/// which also changed the recovery code's standing: after the restore the healer re-registers
/// with its current password and Secret Key, so only the new credentials log in. Recovery is
/// refused for every code until the repair; the code issued after the backup cannot be
/// re-typed (the restored `H_rec` is an older code's), the repair issues a new code and kit,
/// and afterwards the pre-backup code stays refused while the new one recovers the account.
#[test]
fn credential_changes_after_the_backup_are_healed_and_recovery_needs_a_new_code() {
    let mut server = Server::start(None);
    let origin = server.origin();
    let a = Rv::new("ka");
    let (secret_key, code) = sign_up(&a, &origin);
    note(&a, PASSWORD, "Before");
    let backup = server.backup("before.rvbackup");

    a.ok(
        &["password", "--name", "alice"],
        &[PASSWORD, NEW_PASSWORD, NEW_PASSWORD],
    );
    let changed = a.ok(
        &["secret-key", "--name", "alice", "--full-rotation"],
        &[NEW_PASSWORD],
    );
    let new_secret_key = changed.printed("Secret Key:");
    let new_code = changed.printed("Recovery code:");
    note(&a, NEW_PASSWORD, "After the changes");
    server.restore_from(&backup);

    let healed = a.ok(&["sync"], &[NEW_PASSWORD]);
    assert!(
        healed.noted("holds this device's account state again"),
        "{:?}",
        healed.notes
    );
    assert!(healed.noted("recovery repair"), "{:?}", healed.notes);
    // Only the new password and Secret Key log in.
    let old = Rv::new("kold");
    assert!(matches!(
        log_in(&old, &origin, &secret_key, PASSWORD),
        Err(CliError::Client(ClientError::WrongPasswordOrSecretKey))
    ));
    let d = Rv::new("kd");
    assert!(log_in(&d, &origin, &new_secret_key, NEW_PASSWORD).is_ok());
    assert_eq!(d.names(NEW_PASSWORD), ["After the changes", "Before"]);

    // Recovery: refused for both codes until the repair; re-typing is refused.
    for typed in [&code, &new_code] {
        assert!(refused(
            &recovery_start(&origin, typed),
            ErrorCode::Unauthorized
        ));
        let (outcome, _) = a.try_run(
            &["recovery", "repair", "--retype", "--name", "alice"],
            &[NEW_PASSWORD, typed],
        );
        assert!(refused(&outcome, ErrorCode::InvalidRequest), "{outcome:?}");
    }
    let repaired = a.ok(&["recovery", "repair", "--name", "alice"], &[NEW_PASSWORD]);
    let repaired_code = repaired.printed("Recovery code:");
    assert!(repaired_code != code && repaired_code != new_code);
    for typed in [&code, &new_code] {
        assert!(refused(
            &recovery_start(&origin, typed),
            ErrorCode::Unauthorized
        ));
    }
    // The new code recovers the account on a computer that holds nothing.
    let r = Rv::new("kr");
    r.ok(
        &["recovery", "start", "--server", &origin, "--name", "alice"],
        &[&repaired_code],
    );
    let done = r.ok(
        &[
            "recovery", "complete", "--server", &origin, "--name", "alice",
        ],
        &[&repaired_code, RECOVERED_PASSWORD, RECOVERED_PASSWORD],
    );
    assert!(done.noted("account is recovered"), "{:?}", done.notes);
    assert_eq!(r.names(RECOVERED_PASSWORD), ["After the changes", "Before"]);
}

/// The negative of the tests above: a native copy put back after a full rotation opens no
/// reconciliation epoch. The device that rotated recognises the older chain as a rollback, the
/// server refuses its newer chain and state outside the epoch, and the alarm stays across runs.
#[test]
fn a_genuine_rollback_across_a_full_rotation_stays_an_alarm() {
    let mut server = Server::start(None);
    let origin = server.origin();
    let a = Rv::new("na");
    let (_, code) = sign_up(&a, &origin);
    note(&a, PASSWORD, "Before");
    let copy = server.native_copy("native-copy");
    a.ok(&["rotate", "--name", "alice", "--full"], &[PASSWORD, &code]);
    server.native_restore(&copy);

    for _ in 0..2 {
        let (outcome, run) = a.try_run(&["sync"], &[PASSWORD]);
        assert!(
            matches!(outcome, Err(CliError::Alarm(Alarm::Rollback))),
            "{outcome:?}: {:?}",
            run.notes
        );
        assert!(run.noted("refused"), "{:?}", run.notes);
    }
    assert_eq!(a.names(PASSWORD), ["Before"]);
}
