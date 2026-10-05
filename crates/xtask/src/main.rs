//! `cargo xtask`: repository checks for rizzy-vault (ADR 0016 §5). Never shipped.
//!
//! ```text
//! cargo xtask check-deps
//! cargo xtask check-clippy
//! cargo xtask check-signoff <base>..<head>
//! cargo xtask check-signoff --squash <before>..<after>
//! cargo xtask expand-bindings [--write]
//! cargo xtask build-wasm
//! cargo xtask check-js
//! ```
//!
//! `check-deps` enforces the crate-boundary rules of ADR 0016 (R1–R8) and the dependency rules
//! of ADR 0009 on the resolved graph and the manifests, as ADR 0022 and ADR 0019 partially
//! supersede them, and runs the `unsafe` token scan of ADR 0019 §4.1 and the rustls `dangerous()`
//! token scan of ADR 0030 Decision 3 on the sources:
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
//!   by `rizzy-core`'s own dependency entries, and none of the forbidden ones anywhere; every
//!   member declares those crypto crates, `blake2` and `poly1305` included, with
//!   `default-features = false` in every dependency kind, and never turns `default` back on.
//! - **ADR 0024** `rustix` (core dumps off, INV-60) only as a direct dependency of the leaf
//!   crates `rizzy-server`, `rizzy-cli`, `rizzy-ffi` and `rizzy-ffi-cpp`, and in no other
//!   member's normal or build closure.
//! - **ADR 0019 §4.1** no `unsafe` keyword token in any first-party `.rs` file, comments and
//!   literals excluded, including `unsafe` that `forbid(unsafe_code)` can miss in a macro's
//!   input ([`mod@unsafe_scan`]).
//! - **ADR 0030 Decision 3** no `dangerous` or `danger` word token (the rustls APIs that
//!   replace or disable certificate verification) in any `.rs` file under `crates/*/src`,
//!   comments and literals excluded (`rules::DANGER_WORDS`).
//! - **ADR 0019 §4.1 (b)** the committed expansion baseline of `rizzy-wasm` exists, records the
//!   `wasm-bindgen` version of `Cargo.lock`, and its `unsafe`/`extern`/`no_mangle`/`export_name`
//!   counts are those of the committed expansion ([`mod@bindings`]).
//!
//! R3, R5 and R6 cover dev-dependencies too. The rules table is in `rules.rs`.
//!
//! `check-clippy` runs clippy as `cargo lint` does and fails when its output reports a problem
//! with a `clippy.toml` entry, such as "found a module" (ADR 0016 §5, R1 API side). Clippy then
//! ignores the entry, and `-D warnings` does not turn that warning into an error. Run it after
//! `cargo lint`, which it reuses the results of.
//!
//! `check-signoff` checks the DCO sign-off of ADR 0017 Decision 4 ([`mod@signoff`]). Without a
//! flag, every commit in `<base>..<head>` must carry a `Signed-off-by:` trailer naming its
//! author; CI runs that on each pull request's commits. With `--squash`, every commit in the
//! range must keep at least one well-formed `Signed-off-by:` line anywhere in its message; CI
//! runs that on each push to `main`, where the commit is GitHub's squash commit. It reads
//! `git rev-list` and `git log`, so it needs a checkout that holds both revisions.
//!
//! `expand-bindings` and `build-wasm` are the binding generator's two other controls
//! ([`mod@bindings`]): the regeneration of the expansion baseline (a job on a toolchain that
//! accepts `-Z` options) and the build of the wasm module into `packages/core` with exactly the
//! locked `wasm-bindgen-cli` (ADR 0013 §4).
//!
//! `check-js` checks the JavaScript dependency policy of ADR 0014 §3 ([`mod@js`]).
//!
//! # How `check-deps` works
//!
//! 1. [`load`] gathers every input: `cargo metadata --all-features --locked` three times (all
//!    targets, then filtered to `wasm32-unknown-unknown` and to the host triple from
//!    `rustc -vV`), every member's `Cargo.toml`, the root `Cargo.toml`, `.cargo/config.toml`,
//!    the root `clippy.toml`, each no-I/O crate's `clippy.toml`, any `.clippy.toml` that
//!    would shadow one of those, and every first-party `.rs` file that
//!    `git ls-files --cached --others --exclude-standard` lists, so `check-deps` needs a git
//!    checkout.
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
//! cannot be read or a command fails, `2` on a usage error (no command, an unknown command, a
//! missing or extra argument, an argument that is not UTF-8, or a `check-signoff` range that
//! [`signoff::check_range`] rejects). Every command is a CI step; xtask is never shipped and
//! never reads secrets.

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

mod bindings;
mod check;
mod js;
mod manifest;
mod metadata;
mod rules;
mod signoff;
mod unsafe_scan;

use std::collections::BTreeSet;
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
    check-deps      Check the crate-boundary and dependency rules (ADR 0016 R1–R8, ADR 0009),
                    and scan first-party .rs files for the `unsafe` keyword (ADR 0019 §4.1)
                    and crate sources for the rustls `dangerous()` APIs (ADR 0030)
    check-clippy    Run clippy as `cargo lint` does; fail on any warning about a clippy.toml
                    entry, such as \"found a module\" (ADR 0016 §5, R1 API side)
    check-signoff <base>..<head>
                    Check that every commit in the range has a Signed-off-by trailer
                    naming its author (DCO 1.1, ADR 0017 Decision 4)
    check-signoff --squash <before>..<after>
                    Check that every commit in the range (squash commits on main) keeps
                    a well-formed Signed-off-by line anywhere in its message
    expand-bindings [--write]
                    Regenerate the macro expansion of rizzy-wasm and compare it with the
                    committed baseline, or replace it (ADR 0019 §4.1 (b)); needs a rustc
                    that accepts -Z options
    build-wasm      Build rizzy-wasm for wasm32 and run wasm-bindgen-cli (exactly the locked
                    version) into packages/core/generated (ADR 0013 §4)
    check-js        Check the JavaScript dependency policy: exact versions, pinned pnpm,
                    empty install-script allow-list, deny.toml licences, pnpm audit
                    (ADR 0014 §3)
";

/// The second target the getrandom rule is checked on, besides the host (ADR 0016 R1).
const WASM_TARGET: &str = "wasm32-unknown-unknown";

/// Dispatches on the command-line arguments: one command, plus the range (and `--squash`) for
/// `check-signoff`.
/// Anything else is a usage error with exit code 2.
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
        [Some("check-signoff"), Some(range)] => check_signoff(range, SignoffMode::PullRequest),
        [Some("check-signoff"), Some("--squash"), Some(range)] => {
            check_signoff(range, SignoffMode::Squash)
        }
        [Some("expand-bindings")] => report(bindings::expand_bindings(&workspace_root(), false)),
        [Some("expand-bindings"), Some("--write")] => {
            report(bindings::expand_bindings(&workspace_root(), true))
        }
        [Some("build-wasm")] => report(bindings::build_wasm(&workspace_root())),
        [Some("check-js")] => report(js::check_js(&workspace_root())),
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

/// Prints the report of a command that returns one ([`mod@bindings`]): `Ok` to stdout with exit
/// code 0, `Err` to stderr with exit code 1.
fn report(result: Result<String, String>) -> ExitCode {
    match result {
        Ok(text) => {
            let _ = writeln!(io::stdout().lock(), "{text}");
            ExitCode::SUCCESS
        }
        Err(text) => {
            let _ = writeln!(io::stderr().lock(), "{text}");
            ExitCode::FAILURE
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
        let sources = inputs.rust_sources.len();
        let _ = writeln!(
            io::stdout().lock(),
            "check-deps: ok ({members} workspace crates, {sources} first-party .rs files; \
             ADR 0016 R1–R8, ADR 0009, ADR 0019 §4.1, ADR 0024, ADR 0030)"
        );
        return ExitCode::SUCCESS;
    }
    for v in &violations {
        let _ = writeln!(err, "error: {v}");
    }
    let _ = writeln!(
        err,
        "check-deps: {} violation(s) of the crate-boundary rules (ADR 0016 §4, ADR 0009) or \
         the token scans (`unsafe`: ADR 0019 §4.1; rustls `dangerous()`: ADR 0030). The rules \
         table is crates/xtask/src/rules.rs; \
         changing it is a security review.",
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
/// because clippy would read it instead of `clippy.toml`. The first-party `.rs` files come from
/// [`rust_sources`].
///
/// # Errors
///
/// Returns a message when a `cargo metadata`, `rustc` or `git` run fails, when its output cannot
/// be read, or when a required file cannot be read. The root `clippy.toml` is optional.
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
    let bindings = baseline_input(&root, &all_targets)?;
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
        rust_sources: rust_sources(&root)?,
        bindings,
    })
}

/// The inputs of the baseline check ([`bindings::check`]): whether `rizzy-wasm` is a member,
/// the two baseline files if present, the locked wasm-bindgen version, the pinned toolchain
/// channel, and the fingerprint of the current `rizzy-wasm` sources.
///
/// # Errors
///
/// Returns a message when `Cargo.lock` or a present baseline file cannot be read.
fn baseline_input(root: &Path, graph: &Graph) -> Result<bindings::BaselineInput, String> {
    let member = graph
        .members()
        .filter_map(|i| graph.package(i))
        .any(|p| p.name == bindings::WASM_CRATE);
    let dir = root.join(bindings::BASELINE_DIR);
    Ok(bindings::BaselineInput {
        member,
        expanded: read_optional(&dir.join(bindings::EXPANDED))?,
        counts: read_optional(&dir.join(bindings::COUNTS))?,
        locked_wasm_bindgen: bindings::lock_version(
            &read(&root.join("Cargo.lock"))?,
            "wasm-bindgen",
        ),
        toolchain_channel: bindings::toolchain_channel(&read(&root.join("rust-toolchain.toml"))?),
        // Only a member has sources to fingerprint; the check skips a non-member.
        sources: if member {
            bindings::fingerprint(&bindings::source_files(root)?)
        } else {
            String::new()
        },
    })
}

/// Every first-party `.rs` file under `root`, as (path relative to `root`, text), for the
/// `unsafe` token scan of ADR 0019 §4.1 ([`mod@unsafe_scan`]).
///
/// The candidates are what `git ls-files --cached --others --exclude-standard` lists: tracked
/// files, and untracked files that are not ignored, so a new file is scanned before it is
/// committed and build output under `target/` is not. [`unsafe_scan::first_party`] keeps the
/// `.rs` files outside [`rules::GENERATED_RUST`]. A tracked file deleted from the working tree
/// is skipped: there is nothing left to compile.
///
/// # Errors
///
/// Returns a message when git fails (for example outside a git checkout), when it lists a path
/// that is not UTF-8, or when a listed file cannot be read, including one that is not UTF-8.
fn rust_sources(root: &Path) -> Result<Vec<(String, String)>, String> {
    let listing = run(Command::new("git").current_dir(root).args([
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ]))?;
    // A path is listed once per index stage during a merge conflict.
    let paths: BTreeSet<&str> = listing
        .split('\0')
        .filter(|path| unsafe_scan::first_party(path, rules::GENERATED_RUST))
        .collect();
    let mut sources = Vec::new();
    for path in paths {
        if let Some(text) = read_optional(&root.join(path))? {
            sources.push((path.to_owned(), text));
        }
    }
    Ok(sources)
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

/// Which rule `check-signoff` applies ([`mod@signoff`], "Pull-request mode" and "Squash mode").
#[derive(Clone, Copy, PartialEq, Eq)]
enum SignoffMode {
    /// Every commit carries a `Signed-off-by:` trailer naming its author.
    PullRequest,
    /// Every commit's message holds at least one well-formed `Signed-off-by:` line.
    Squash,
}

/// A `git` command in the workspace root with the options every `check-signoff` call shares:
/// `--no-show-signature` and `--no-color` keep a user's git configuration out of the output.
/// The caller appends `--end-of-options` and the revision.
fn git_log_cmd(sub: &str) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(workspace_root()).arg(sub);
    if sub == "log" {
        cmd.args(["--no-show-signature", "--no-color"]);
    }
    cmd
}

/// The commits in `range`, from `git rev-list --end-of-options <range>` ([`signoff::parse_rev_list`]).
///
/// # Errors
///
/// Returns a message when git fails or prints output the parser rejects.
fn rev_list(range: &str) -> Result<Vec<String>, String> {
    let out = run(git_log_cmd("rev-list").args(["--end-of-options", range]))?;
    signoff::parse_rev_list(&out)
}

/// `cargo xtask check-signoff [--squash] <base>..<head>`: checks the DCO sign-off of every
/// commit in the range ([`mod@signoff`], ADR 0017 Decision 4).
///
/// Exits 2 when [`signoff::check_range`] rejects the range. Lists the range with `git rev-list`
/// in the workspace root, always after `--end-of-options`, so the range is never read as an
/// option; an empty range, a git failure or output the parsers cannot read exits 1. Then
/// [`check_pull_request`] or [`check_squash`] applies the mode's rule.
fn check_signoff(range: &str, mode: SignoffMode) -> ExitCode {
    let mut err = io::stderr().lock();
    if let Err(e) = signoff::check_range(range) {
        let _ = writeln!(err, "check-signoff: {e}\n\n{USAGE}");
        return ExitCode::from(2);
    }
    let listed = match rev_list(range) {
        Ok(listed) => listed,
        Err(e) => {
            let _ = writeln!(err, "check-signoff: error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if listed.is_empty() {
        let _ = writeln!(
            err,
            "check-signoff: error: {range} holds no commits, so nothing would be checked; \
             check the range (a pull request or a push always has a commit)"
        );
        return ExitCode::FAILURE;
    }
    let result = match mode {
        SignoffMode::PullRequest => check_pull_request(range, &listed),
        SignoffMode::Squash => check_squash(&listed),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            let _ = writeln!(err, "check-signoff: error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The pull-request mode: runs `git log` with [`signoff::LOG_FORMAT`] over `range`, requires
/// the records to be exactly the `listed` commits ([`signoff::same_commits`]), and checks that
/// each is signed off by its author. Prints `check-signoff: ok (...)` and returns `true` when
/// every commit is; otherwise prints each unsigned commit and how to fix it to stderr and
/// returns `false`.
///
/// # Errors
///
/// Returns a message when git fails or its output cannot be read or does not match `listed`.
fn check_pull_request(range: &str, listed: &[String]) -> Result<bool, String> {
    let format = format!("--format={}", signoff::LOG_FORMAT);
    let out = run(git_log_cmd("log").args([format.as_str(), "--end-of-options", range]))?;
    let commits = signoff::parse_log(&out)?;
    signoff::same_commits(&commits, listed)?;
    let missing = signoff::missing(&commits);
    if missing.is_empty() {
        let _ = writeln!(
            io::stdout().lock(),
            "check-signoff: ok ({} commit(s) signed off by their authors; DCO 1.1, ADR 0017 \
             Decision 4)",
            commits.len()
        );
        return Ok(true);
    }
    let mut err = io::stderr().lock();
    for m in &missing {
        let _ = writeln!(err, "error: [DCO] {m}");
    }
    let _ = writeln!(
        err,
        "check-signoff: {} of {} commit(s) lack a Signed-off-by trailer with the author's name \
         and email (DCO 1.1, ADR 0017 Decision 4; CONTRIBUTING.md, \"Sign-off\"). The author \
         certifies the DCO by signing off: `git commit --amend -s` for the last commit, or \
         `git rebase --signoff <base>` for all of them, then force-push. AI coding agents \
         never sign off; the human who opens the pull request does, after review.",
        missing.len(),
        commits.len()
    );
    Ok(false)
}

/// The squash mode: reads each `listed` commit's message with its own
/// `git log -1 --format=%B` call and requires at least one well-formed `Signed-off-by:` line
/// in it ([`signoff::squash_signoffs`]). Prints `check-signoff: ok (...)` and returns `true`
/// when every commit has one; otherwise names each commit without one on stderr and returns
/// `false`.
///
/// # Errors
///
/// Returns a message when git fails or a message is too large.
fn check_squash(listed: &[String]) -> Result<bool, String> {
    let mut bad = Vec::new();
    for sha in listed {
        let message =
            run(git_log_cmd("log").args(["-1", "--format=%B", "--end-of-options", sha.as_str()]))?;
        if signoff::squash_signoffs(&message)?.is_empty() {
            bad.push(sha.as_str());
        }
    }
    if bad.is_empty() {
        let _ = writeln!(
            io::stdout().lock(),
            "check-signoff: ok ({} commit(s) keep Signed-off-by lines; squash mode, ADR 0017 \
             Decision 4)",
            listed.len()
        );
        return Ok(true);
    }
    let mut err = io::stderr().lock();
    for sha in &bad {
        let _ = writeln!(
            err,
            "error: [DCO] {}: the commit message holds no well-formed `Signed-off-by: Name \
             <email>` line",
            signoff::short(sha)
        );
    }
    let _ = writeln!(
        err,
        "check-signoff: {} of {} commit(s) on main lost the DCO record (ADR 0017 Decision 4). \
         Squash-merge with \"Pull request title and commit details\", which keeps the commits' \
         Signed-off-by lines; never \"Pull request title\" or \"Pull request title and \
         description\", and never a merge commit (CONTRIBUTING.md, \"Review\").",
        bad.len(),
        listed.len()
    );
    Ok(false)
}
