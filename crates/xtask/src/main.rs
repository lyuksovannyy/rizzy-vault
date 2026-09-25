//! `cargo xtask`: repository checks for rizzy-vault (ADR 0016 §5). Never shipped.
//!
//! ```text
//! cargo xtask check-deps
//! ```
//!
//! `check-deps` enforces the crate-boundary rules of ADR 0016 (R1–R8) and the dependency rules
//! of ADR 0009 on the resolved graph and the manifests:
//!
//! - **R1** no-I/O crates (`rizzy-core`, `rizzy-sync`, and the planned `rizzy-proto`,
//!   `rizzy-client`, `rizzy-import`, `rizzy-match`): only allow-listed external crates over
//!   normal and build dependencies; nothing from the I/O denylist (tokio, sqlx, HTTP clients,
//!   TLS, JavaScript bindings); no direct `rand` or getrandom; `rand` 0.8 only under opaque-ke
//!   with no features; getrandom never in the closure, checked on every target and separately
//!   on `wasm32-unknown-unknown` and the host.
//! - **R2** getrandom is a direct dependency of leaf crates only; `wasm_js` only in
//!   `rizzy-wasm`.
//! - **R3** the ingress crates reach no storage, bus, domain or sqlx crate.
//! - **R4** no domain crate depends on another.
//! - **R5** sqlx only in its holders, sqlite only in client leaf crates; only `rizzy-server`
//!   depends on the domain and ingress crates.
//! - **R6** client-side and server-side crates never reach each other, with the one
//!   dev-dependency exception `rizzy-server` → `rizzy-client`.
//! - **§3** every internal edge is in the crate's "May depend on" column; every member has a
//!   row in the rules table and sits in `crates/<name>`.
//! - **R7/R8** every manifest inherits `[lints]`, `publish`, `license` and `rust-version`.
//! - **§5** the `check-wasm` alias covers every no-I/O crate.
//! - **ADR 0009** `openssl` only under `rizzy-server` and `rizzy-domain-auth`.
//!
//! R3, R5 and R6 cover dev-dependencies too. The rules table is in `rules.rs`.

mod check;
mod manifest;
mod metadata;
mod rules;

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use check::Inputs;
use manifest::Manifest;
use metadata::Graph;

const USAGE: &str = "\
cargo xtask — rizzy-vault repository checks (ADR 0016 §5)

USAGE:
    cargo xtask <COMMAND>

COMMANDS:
    check-deps    Check the crate-boundary and dependency rules (ADR 0016 R1–R8, ADR 0009)
";

/// The second target the getrandom rule is checked on, besides the host (ADR 0016 R1).
const WASM_TARGET: &str = "wasm32-unknown-unknown";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check-deps"] => check_deps(),
        ["-h" | "--help"] => {
            let _ = write!(io::stdout().lock(), "{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            let _ = write!(io::stderr().lock(), "{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn check_deps() -> ExitCode {
    let mut err = io::stderr().lock();
    let inputs = match load() {
        Ok(inputs) => inputs,
        Err(e) => {
            let _ = writeln!(err, "check-deps: error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let violations = check::run(&inputs);
    if violations.is_empty() {
        let members = inputs.all_targets.members().count();
        let _ = writeln!(
            io::stdout().lock(),
            "check-deps: ok ({members} workspace crates; ADR 0016 R1–R8, ADR 0009)"
        );
        return ExitCode::SUCCESS;
    }
    for v in &violations {
        let _ = writeln!(err, "error: {v}");
    }
    let _ = writeln!(
        err,
        "check-deps: {} violation(s) of the crate-boundary rules (ADR 0016 §4, ADR 0009). \
         The rules table is crates/xtask/src/rules.rs; changing it is a security review.",
        violations.len()
    );
    ExitCode::FAILURE
}

/// The workspace root: two levels above this crate's manifest directory.
fn workspace_root() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .and_then(Path::parent)
        .map_or_else(|| here.to_path_buf(), Path::to_path_buf)
}

fn load() -> Result<Inputs, String> {
    let root = workspace_root();
    let host = host_target(&root)?;
    let all_targets = metadata(&root, None)?;
    let per_target = vec![
        (WASM_TARGET.to_owned(), metadata(&root, Some(WASM_TARGET))?),
        (host.clone(), metadata(&root, Some(&host))?),
    ];
    let mut manifests = Vec::new();
    for i in all_targets.members() {
        let Some(p) = all_targets.package(i) else {
            continue;
        };
        manifests.push((
            p.name.clone(),
            Manifest::parse(&read(Path::new(&p.manifest_path))?),
        ));
    }
    Ok(Inputs {
        workspace_manifest: Manifest::parse(&read(&root.join("Cargo.toml"))?),
        cargo_config: Manifest::parse(&read(&root.join(".cargo").join("config.toml"))?),
        all_targets,
        per_target,
        manifests,
    })
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

/// The cargo that runs us (`cargo xtask` sets `CARGO`), or `cargo` from `PATH`.
fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// `cargo metadata --format-version 1 --all-features --locked`, optionally with
/// `--filter-platform`.
fn metadata(root: &Path, target: Option<&str>) -> Result<Graph, String> {
    let mut cmd = Command::new(cargo());
    cmd.current_dir(root).args([
        "metadata",
        "--format-version",
        "1",
        "--all-features",
        "--locked",
        "--manifest-path",
    ]);
    cmd.arg(root.join("Cargo.toml"));
    if let Some(t) = target {
        cmd.args(["--filter-platform", t]);
    }
    let stdout = run(&mut cmd)?;
    Graph::from_json(&stdout)
}

/// The host target triple, from `rustc -vV`.
fn host_target(root: &Path) -> Result<String, String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let out = run(Command::new(rustc).current_dir(root).arg("-vV"))?;
    out.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|h| h.trim().to_owned())
        .ok_or_else(|| "rustc -vV printed no host triple".to_owned())
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("running {cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("{cmd:?} printed invalid UTF-8: {e}"))
}
