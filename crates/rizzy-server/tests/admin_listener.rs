// SPDX-License-Identifier: AGPL-3.0-only

//! The admin listener as a real process ([ADR 0060] §2): `rizzy-vault` with the `api` role binds
//! `RIZZY_ADMIN_LISTEN` beside `RIZZY_LISTEN` and serves the admin router there only; a start
//! whose admin address is taken fails, naming the setting; a `web`-only process binds no admin
//! listener.
//!
//! [ADR 0060]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0060-admin-panel-stack-boundary.md

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code: a failure fails the test, which CLAUDE.md allows"
)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rizzy_server::http::security::{ADMIN_CSP, WEB_CSP};

const BIN: &str = env!("CARGO_BIN_EXE_rizzy-vault");

/// The variables a `rizzy-vault` process needs from the OS to run at all, kept when its
/// environment is cleared ([`clear_env`]). None on Unix. On Windows, `SystemRoot`: Winsock
/// loads its service provider from a registry path written as
/// `%SystemRoot%\System32\mswsock.dll`, so a process without the variable cannot create a
/// socket (`WSAEPROVIDERFAILEDINIT`, error 10106) and `rizzy-vault` exits 1 when it binds its
/// listener. Go's `os/exec` adds `SYSTEMROOT` to every child's environment for this reason;
/// Rust's `env_clear` does not. Nothing else is needed: system DLLs load from the system
/// directory, not through `PATH`, and the temporary directory falls back from `TMP`, `TEMP`
/// and `USERPROFILE` to the Windows directory.
const OS_ENV: &[&str] = if cfg!(windows) { &["SystemRoot"] } else { &[] };

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

/// A free loopback port (bound, read, released).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A fresh temporary directory holding `data/` and `secrets/`.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rizzy-server-admin-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::create_dir_all(dir.join("secrets")).unwrap();
    dir
}

/// The environment of a server in `dir` whose public listener is `port`.
fn env(dir: &std::path::Path, port: u16, admin: &str) -> Vec<(&'static str, String)> {
    vec![
        ("RIZZY_ORIGIN", format!("http://127.0.0.1:{port}")),
        ("RIZZY_LISTEN", format!("127.0.0.1:{port}")),
        ("RIZZY_ADMIN_LISTEN", admin.to_owned()),
        ("RIZZY_SIGNUP", "open".to_owned()),
        (
            "RIZZY_DATA_DIR",
            dir.join("data").to_str().unwrap().to_owned(),
        ),
        (
            "RIZZY_SECRETS_FILE",
            dir.join("secrets/secrets.json")
                .to_str()
                .unwrap()
                .to_owned(),
        ),
    ]
}

/// `rizzy-vault args` with exactly `env`.
fn command(args: &[&str], env: &[(&'static str, String)]) -> Command {
    let mut command = Command::new(BIN);
    clear_env(&mut command).args(args);
    for (k, v) in env {
        command.env(k, v);
    }
    command
}

/// A running server, killed on drop.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits until `port` accepts a connection, or fails if the server exits first.
fn wait_for(port: u16, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("rizzy-vault exited: {status}");
        }
        assert!(Instant::now() < deadline, "rizzy-vault did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `GET path` over a fresh connection to `port`: the status line and the lower-cased header
/// block, and the body.
fn get(port: u16, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let (head, body) = answer.split_once("\r\n\r\n").unwrap();
    (head.to_ascii_lowercase(), body.to_owned())
}

fn secrets_init(env: &[(&'static str, String)]) {
    let out = command(&["secrets", "init"], env).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_api_role_serves_the_admin_router_on_its_own_listener_only() {
    let dir = temp_dir("serve");
    let port = free_port();
    let admin_port = free_port();
    let env = env(&dir, port, &format!("127.0.0.1:{admin_port}"));
    secrets_init(&env);
    let child = command(&[], &env)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut running = Running(child);
    wait_for(port, &mut running.0);
    wait_for(admin_port, &mut running.0);

    // The public listener: the API answers, `/admin` is the web role's 404.
    let (head, body) = get(port, "/api/meta");
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(body.contains("\"api_versions\""), "{body}");
    for path in ["/admin", "/admin/users"] {
        let (head, _) = get(port, path);
        assert!(head.starts_with("http/1.1 404"), "{path}: {head}");
        assert!(
            head.contains(&format!("content-security-policy: {WEB_CSP}").to_ascii_lowercase()),
            "{path}: {head}"
        );
    }

    // The admin listener: every path is a plain 404 under the admin CSP; no API there.
    for path in [
        "/",
        "/admin",
        "/api/meta",
        "/api/v1/sessions/list",
        "/metrics",
    ] {
        let (head, body) = get(admin_port, path);
        assert!(head.starts_with("http/1.1 404"), "{path}: {head}");
        assert!(
            head.contains(&format!("content-security-policy: {ADMIN_CSP}").to_ascii_lowercase()),
            "{path}: {head}"
        );
        assert_eq!(body, "not found\n", "{path}");
    }

    // One SIGTERM stops both listeners and the process exits cleanly.
    #[cfg(unix)]
    {
        let pid = running.0.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-TERM", &pid])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = running.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "rizzy-vault did not stop");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(status.success(), "{status}");
        assert!(TcpStream::connect(("127.0.0.1", admin_port)).is_err());
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }
    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_taken_admin_address_refuses_the_start() {
    let dir = temp_dir("taken");
    let port = free_port();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let admin = taken.local_addr().unwrap().to_string();
    let env = env(&dir, port, &admin);
    secrets_init(&env);
    let out = command(&[], &env).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("admin listener (RIZZY_ADMIN_LISTEN)"),
        "{stderr}"
    );
    drop(taken);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_admin_address_is_a_configuration_error() {
    let dir = temp_dir("bad");
    let env = env(&dir, free_port(), "localhost:8081");
    let out = command(&[], &env).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("RIZZY_ADMIN_LISTEN"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `web`-only process has no `api` role, so it binds no admin listener: a taken admin
/// address does not stop it.
#[test]
fn a_web_only_process_binds_no_admin_listener() {
    let dir = temp_dir("web");
    let port = free_port();
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let admin = taken.local_addr().unwrap().to_string();
    let env = vec![
        ("RIZZY_LISTEN", format!("127.0.0.1:{port}")),
        ("RIZZY_ADMIN_LISTEN", admin),
    ];
    let child = command(&["--roles", "web"], &env)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut running = Running(child);
    wait_for(port, &mut running.0);
    let (head, _) = get(port, "/admin");
    assert!(head.starts_with("http/1.1 404"), "{head}");
    assert!(running.0.try_wait().unwrap().is_none());
    drop(running);
    drop(taken);
    let _ = std::fs::remove_dir_all(&dir);
}
