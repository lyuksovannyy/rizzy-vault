//! `cargo xtask`: repository checks for rizzy-vault (ADR 0016 §5). Never shipped.
//!
//! ```text
//! cargo xtask check-deps
//! cargo xtask check-clippy
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
//! - **R7/R8** every manifest inherits `[lints]`, `publish`, `license` and `rust-version`;
//!   the workspace lint table sets `unsafe_code = "forbid"`.
//! - **§5** the `check-wasm` alias covers every no-I/O crate; every no-I/O crate has a
//!   `clippy.toml` that repeats the root one and carries the R1 disallowed-types and
//!   disallowed-methods lists (R1, API side).
//! - **ADR 0009** `openssl` only under `rizzy-server` and `rizzy-domain-auth`; the required
//!   feature sets of the crypto crates in `rizzy-core`'s closure, `zeroize` above all, turned on
//!   by `rizzy-core`'s own dependency entries, and none of the forbidden ones anywhere.
//!
//! R3, R5 and R6 cover dev-dependencies too. The rules table is in `rules.rs`.
//!
//! `check-clippy` runs clippy as `cargo lint` does and fails when its output reports a problem
//! with a `clippy.toml` entry, such as "found a module" (ADR 0016 §5, R1 API side). Clippy then
//! ignores the entry, and `-D warnings` does not turn that warning into an error. Run it after
//! `cargo lint`, which it reuses the results of.
//!
//! # How `check-deps` works
//!
//! 1. [`load`] gathers every input: `cargo metadata --all-features --locked` three times (all
//!    targets, then filtered to `wasm32-unknown-unknown` and to the host triple from
//!    `rustc -vV`), every member's `Cargo.toml`, the root `Cargo.toml`, `.cargo/config.toml`,
//!    the root `clippy.toml`, each no-I/O crate's `clippy.toml`, and any `.clippy.toml` that
//!    would shadow one of those.
//! 2. [`check::run`] evaluates every rule as a pure function of those inputs and returns the
//!    sorted, de-duplicated violations. The rules themselves are data in [`rules`].
//! 3. Each violation is printed as `error: [rule] crate: message`.
//!
//! Every reader fails closed: JSON it cannot read ([`mod@metadata`]) and TOML lines it cannot
//! read ([`mod@manifest`]) are errors or violations, never skipped. `--locked` makes a stale
//! `Cargo.lock` fail instead of being rewritten before it is checked (threat model INV-57).
//!
//! # Exit codes
//!
//! `0` when every check passes (and for `-h`/`--help`), `1` on a violation or when an input
//! cannot be read or a command fails, `2` on a usage error (no command, an unknown command, an
//! extra argument, or an argument that is not UTF-8). Both commands are CI steps; xtask is
//! never shipped and never reads secrets.

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

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

/// The help text, printed on `--help` (stdout) and on a usage error (stderr).
const USAGE: &str = "\
cargo xtask — rizzy-vault repository checks (ADR 0016 §5)

USAGE:
    cargo xtask <COMMAND>

COMMANDS:
    check-deps      Check the crate-boundary and dependency rules (ADR 0016 R1–R8, ADR 0009)
    check-clippy    Run clippy as `cargo lint` does; fail on any warning about a clippy.toml
                    entry, such as \"found a module\" (ADR 0016 §5, R1 API side)
";

/// The second target the getrandom rule is checked on, besides the host (ADR 0016 R1).
const WASM_TARGET: &str = "wasm32-unknown-unknown";

/// Dispatches on the one command-line argument. Exactly one argument is accepted; anything
/// else is a usage error with exit code 2.
fn main() -> ExitCode {
    // `args_os`, not `args`: `args` panics on an argument that is not UTF-8. Such an argument
    // is no command, so it gets the usage error.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args
        .iter()
        .map(|a| a.to_str())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [Some("check-deps")] => check_deps(),
        [Some("check-clippy")] => check_clippy(),
        [Some("-h" | "--help")] => {
            let _ = write!(io::stdout().lock(), "{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            let _ = write!(io::stderr().lock(), "{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// `cargo xtask check-deps`: loads the inputs, runs every rule and prints the result.
///
/// Prints `check-deps: ok (...)` to stdout and exits 0 when there is no violation. Otherwise
/// prints each violation and a summary to stderr and exits 1; an input that cannot be loaded
/// also exits 1, with the reason.
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

/// `cargo xtask check-clippy`: runs `cargo clippy` with `cargo lint`'s arguments and scans its
/// stderr for problems with `clippy.toml` entries ([`check::clippy_config_warnings`]).
///
/// Exits 1 if clippy itself fails (fix what `cargo lint` reports first) or if any entry warning
/// is found, and 0 otherwise. `CLIPPY_CONF_DIR` is removed from the child's environment, so
/// clippy reads each crate's own `clippy.toml`, the files `check-deps` checks.
fn check_clippy() -> ExitCode {
    let mut err = io::stderr().lock();
    let root = workspace_root();
    let mut cmd = Command::new(cargo());
    // `cargo lint`'s invocation, so a run after it reuses its results; `--color never` keeps
    // the output scannable. `CLIPPY_CONF_DIR` would point clippy away from the crate files.
    cmd.current_dir(&root)
        .env_remove("CLIPPY_CONF_DIR")
        .args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--color",
            "never",
        ])
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .args(["--", "-D", "warnings"]);
    let out = match cmd.output() {
        Ok(out) => out,
        Err(e) => {
            let _ = writeln!(err, "check-clippy: error: running {cmd:?}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let _ = writeln!(
            err,
            "{}\ncheck-clippy: clippy failed ({}); fix what `cargo lint` reports first",
            stderr.trim_end(),
            out.status
        );
        return ExitCode::FAILURE;
    }
    let warnings = check::clippy_config_warnings(&stderr);
    if warnings.is_empty() {
        let _ = writeln!(
            io::stdout().lock(),
            "check-clippy: ok (no clippy.toml entry warnings; ADR 0016 §5, R1 API side)"
        );
        return ExitCode::SUCCESS;
    }
    for w in &warnings {
        let _ = writeln!(err, "error: [ADR 0016 §5] {w}");
    }
    let _ = writeln!(
        err,
        "check-clippy: {} clippy.toml entry warning(s). Clippy ignores such an entry, so the \
         R1 API-side lists do not hold: name items (`std::fs::read`), never modules (`std::fs`).",
        warnings.len()
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

/// Reads every input the checks need ([`Inputs`]).
///
/// The per-target graphs are wasm32 (the target ADR 0016 §5 names for the getrandom rule) and
/// the host; R1 forbids getrandom on any target. A `clippy.toml` is read only for members whose
/// row is a no-I/O crate; a missing one is recorded as `None` and reported by the checks. A
/// `.clippy.toml` is looked for at the workspace root and in each of those crates' directories,
/// because clippy would read it instead of `clippy.toml`.
///
/// # Errors
///
/// Returns a message when a `cargo metadata` or `rustc` run fails, when its output cannot be
/// read, or when a required file cannot be read. The root `clippy.toml` is optional.
fn load() -> Result<Inputs, String> {
    let root = workspace_root();
    let host = host_target(&root)?;
    let all_targets = metadata(&root, None)?;
    let per_target = vec![
        (WASM_TARGET.to_owned(), metadata(&root, Some(WASM_TARGET))?),
        (host.clone(), metadata(&root, Some(&host))?),
    ];
    let mut manifests = Vec::new();
    let mut clippy_configs = Vec::new();
    let mut hidden_clippy_configs = Vec::new();
    let mut clippy_dirs = vec![root.clone()];
    for i in all_targets.members() {
        let Some(p) = all_targets.package(i) else {
            continue;
        };
        let manifest_path = Path::new(&p.manifest_path);
        manifests.push((p.name.clone(), Manifest::parse(&read(manifest_path)?)));
        if rules::rule(&p.name).is_some_and(|r| r.no_io) {
            let dir = manifest_path.parent().unwrap_or(&root);
            let config = read_optional(&dir.join("clippy.toml"))?;
            clippy_configs.push((p.name.clone(), config.as_deref().map(Manifest::parse)));
            clippy_dirs.push(dir.to_path_buf());
        }
    }
    for dir in &clippy_dirs {
        let hidden = dir.join(".clippy.toml");
        if read_optional(&hidden)?.is_some() {
            hidden_clippy_configs.push(hidden.display().to_string());
        }
    }
    Ok(Inputs {
        workspace_manifest: Manifest::parse(&read(&root.join("Cargo.toml"))?),
        cargo_config: Manifest::parse(&read(&root.join(".cargo").join("config.toml"))?),
        root_clippy: Manifest::parse(
            &read_optional(&root.join("clippy.toml"))?.unwrap_or_default(),
        ),
        clippy_configs,
        hidden_clippy_configs,
        all_targets,
        per_target,
        manifests,
    })
}

/// The file's contents.
///
/// # Errors
///
/// Returns a message naming the path when the file cannot be read, including when it is
/// missing.
fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

/// The file's contents, or `None` if it does not exist.
///
/// # Errors
///
/// Returns a message naming the path for any read error other than "not found".
fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// The cargo that runs us (`cargo xtask` sets `CARGO`), or `cargo` from `PATH`.
fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// `cargo metadata --format-version 1 --all-features --locked`, optionally with
/// `--filter-platform`.
///
/// `--all-features` gives the workspace-unified graph, a superset of any single build, which
/// is what the checks rely on (see the `check` module docs).
///
/// # Errors
///
/// Returns a message when cargo fails (for example on a stale `Cargo.lock`) or when its JSON
/// cannot be read ([`Graph::from_json`]).
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

/// The host target triple, from `rustc -vV` (`RUSTC` if set, else `rustc` from `PATH`).
///
/// # Errors
///
/// Returns a message when rustc fails or prints no `host:` line.
fn host_target(root: &Path) -> Result<String, String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let out = run(Command::new(rustc).current_dir(root).arg("-vV"))?;
    out.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|h| h.trim().to_owned())
        .ok_or_else(|| "rustc -vV printed no host triple".to_owned())
}

/// Runs `cmd` and returns its stdout.
///
/// # Errors
///
/// Returns a message when the command cannot be started, exits unsuccessfully (with its
/// trimmed stderr), or prints stdout that is not UTF-8.
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
