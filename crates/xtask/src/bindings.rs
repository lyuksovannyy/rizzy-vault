//! The binding generator's controls for `rizzy-wasm` (ADR 0019 §4.1, owner decision 7; ADR
//! 0013 §4 "Build"): the committed expansion baseline, its `unsafe`/`extern`/`no_mangle`
//! counts, and the build of the wasm module into `packages/core`.
//!
//! # The baseline (`crates/rizzy-wasm/generated/`)
//!
//! - `expanded.rs`: the macro-expanded `rizzy-wasm` library for `wasm32-unknown-unknown`, as
//!   `rustc -Zunpretty=expanded` prints it. wasm-bindgen's generated glue is in it, `unsafe`
//!   included; it is third-party code under review (owner decision 7), so the first-party
//!   `unsafe` token scan skips the directory ([`crate::rules::GENERATED_RUST`]).
//! - `counts.txt`: the wasm-bindgen version and rustc version the expansion was made with, the
//!   fingerprint of the `rizzy-wasm` sources it was made from ([`fingerprint`]), and
//!   the counts of the `unsafe` and `extern` keyword tokens and of the `no_mangle` and
//!   `export_name` attribute names in `expanded.rs` (comments and literals excluded; the lexer
//!   of [`crate::unsafe_scan`]). A bump PR shows the before and after of these lines next to
//!   the diff of `expanded.rs` (§4.1 (b)).
//!
//! # Who checks what
//!
//! - `cargo xtask check-deps` (every push, stable toolchain): the baseline exists, `counts.txt`
//!   parses, its wasm-bindgen version is the one in `Cargo.lock`, its rustc is the channel of
//!   `rust-toolchain.toml`, its source fingerprint is the fingerprint of the current
//!   `rizzy-wasm` sources, and its counts are the counts of the committed `expanded.rs`
//!   ([`check`]). A wasm-bindgen bump, a toolchain bump, or any edit to `rizzy-wasm`'s
//!   `Cargo.toml` or `src/` without a regenerated baseline fails here, so the PR that changes
//!   the generated glue carries its reviewed diff and counts (§4.1 (b)). This is a staleness
//!   signal on the stable toolchain, not the regeneration itself: check-deps cannot expand the
//!   crate, so a baseline edited by hand to match the fingerprint passes it, and only
//!   `expand-bindings` (below) proves the expansion; CI runs it in the `bindings-baseline` job
//!   (`.github/workflows/ci.yml`), which meets §4.1's "CI regenerates and fails on any difference".
//! - `cargo xtask expand-bindings` (a separate job, like fuzzing): regenerates the expansion
//!   and fails on any difference from the committed one; `--write` replaces both files. The
//!   expansion needs `-Zunpretty=expanded`, which a stable rustc refuses. xtask never switches
//!   toolchains or sets `RUSTC_BOOTSTRAP` itself: the job runs it under the toolchain it pins
//!   (ADR 0019 §4.1, "it runs in a separate job on its own toolchain"): CI uses the
//!   pinned rustc 1.94.1 with `RUSTC_BOOTSTRAP=1` in that job only, the toolchain the
//!   committed baseline was made with (recorded in `counts.txt`).
//! - `cargo xtask build-wasm`: the release build of `rizzy-wasm`, then `wasm-bindgen-cli` into
//!   `packages/core/generated/` (not committed, ADR 0013 §4). It refuses a `wasm-bindgen`
//!   CLI whose version is not exactly the `wasm-bindgen` crate's in `Cargo.lock` ("the two
//!   must match"), and prints the module's size for the size budget, which is set after this
//!   first measurement (ADR 0013 §4 "Size budget"; reported).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::unsafe_scan::word_tokens;

/// The binding crate the baseline covers.
pub(crate) const WASM_CRATE: &str = "rizzy-wasm";

/// The baseline directory, relative to the workspace root.
pub(crate) const BASELINE_DIR: &str = "crates/rizzy-wasm/generated";

/// The expanded crate's file name.
pub(crate) const EXPANDED: &str = "expanded.rs";

/// The counts file's name.
pub(crate) const COUNTS: &str = "counts.txt";

/// The words counted, in the order of [`Counts`]'s fields and of `counts.txt`.
const COUNTED: [&str; 4] = ["unsafe", "extern", "no_mangle", "export_name"];

/// The target the expansion and the module are built for.
const TARGET: &str = "wasm32-unknown-unknown";

/// Where `build-wasm` writes the generated JavaScript and wasm, relative to the root.
pub(crate) const PACKAGE_OUT: &str = "packages/core/generated";

/// The name `wasm-bindgen-cli` gives the outputs (`rizzy_core.js`, `rizzy_core_bg.wasm`).
const OUT_NAME: &str = "rizzy_core";

/// The binding crate's directory, relative to the workspace root: its `Cargo.toml` and `src/`
/// are what the fingerprint covers.
pub(crate) const WASM_CRATE_DIR: &str = "crates/rizzy-wasm";

/// The fingerprint's scheme, the prefix of its value in `counts.txt`.
const FINGERPRINT_SCHEME: &str = "fnv1a64";

/// The files of `rizzy-wasm` whose text the expansion depends on: `Cargo.toml` and every file
/// under `src/`, as (path relative to the crate directory with `/` separators, contents),
/// sorted by path.
///
/// Every file under `src/` counts, test modules included: the expansion leaves out
/// `#[cfg(test)]` code, so an edit to a test alone also asks for a regenerated (and then
/// identical) baseline. That is the conservative side of a check that cannot expand.
///
/// # Errors
///
/// Returns a message when a directory or file cannot be read, or a path is not UTF-8.
pub(crate) fn source_files(root: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let dir = root.join(WASM_CRATE_DIR);
    let mut out = Vec::new();
    let manifest = dir.join("Cargo.toml");
    out.push((
        "Cargo.toml".to_owned(),
        std::fs::read(&manifest).map_err(|e| format!("reading {}: {e}", manifest.display()))?,
    ));
    let mut pending = vec![(dir.join("src"), "src".to_owned())];
    while let Some((path, relative)) = pending.pop() {
        let entries =
            std::fs::read_dir(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("reading {}: {e}", path.display()))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| format!("{}: a file name that is not UTF-8", path.display()))?;
            let child = format!("{relative}/{name}");
            let kind = entry
                .file_type()
                .map_err(|e| format!("reading {child}: {e}"))?;
            if kind.is_dir() {
                pending.push((entry.path(), child));
            } else {
                let bytes =
                    std::fs::read(entry.path()).map_err(|e| format!("reading {child}: {e}"))?;
                out.push((child, bytes));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The fingerprint of `files` ([`source_files`]), as `counts.txt` records it:
/// `fnv1a64:` and 16 hex digits.
///
/// FNV-1a over, for each file in order, its path, a NUL, its length as 8 little-endian bytes
/// and its contents, with every CRLF read as LF so a checkout's line endings do not matter
/// (the length is that of the normalised contents). This is a change detector for honest
/// edits, not a security control: it guards nothing against a forger, who could as well edit
/// `expanded.rs` by hand (module docs); no cryptographic hash is needed or added (ADR 0009).
pub(crate) fn fingerprint(files: &[(String, Vec<u8>)]) -> String {
    /// The FNV-1a 64-bit offset basis.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    /// The FNV-1a 64-bit prime.
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };
    for (path, contents) in files {
        let normalised: Vec<u8> = contents
            .iter()
            .enumerate()
            .filter(|&(i, &byte)| !(byte == b'\r' && contents.get(i + 1) == Some(&b'\n')))
            .map(|(_, &byte)| byte)
            .collect();
        feed(path.as_bytes());
        feed(&[0]);
        let length = u64::try_from(normalised.len()).unwrap_or(u64::MAX);
        feed(&length.to_le_bytes());
        feed(&normalised);
    }
    format!("{FINGERPRINT_SCHEME}:{hash:016x}")
}

/// The `channel` of `rust-toolchain.toml` text, if it has exactly one `channel = "…"` line.
pub(crate) fn toolchain_channel(text: &str) -> Option<String> {
    let mut found = text.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_owned())
    });
    let channel = found.next()?;
    found.next().is_none().then_some(channel)
}

/// Whether `rustc -V` text names `channel`: `rustc 1.94.1 (…)` for channel `1.94.1`.
fn rustc_is(rustc: &str, channel: &str) -> bool {
    rustc.split_whitespace().nth(1) == Some(channel)
}

/// The counts of [`COUNTED`] in an expansion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    /// `unsafe` keyword tokens: blocks, functions, impls, `unsafe(...)` attributes.
    pub(crate) unsafe_: usize,
    /// `extern` keyword tokens.
    pub(crate) extern_: usize,
    /// `no_mangle` attribute names.
    pub(crate) no_mangle: usize,
    /// `export_name` attribute names.
    pub(crate) export_name: usize,
}

impl Counts {
    /// The counts as (word, count) pairs, in file order.
    fn pairs(self) -> [(&'static str, usize); 4] {
        [
            (COUNTED[0], self.unsafe_),
            (COUNTED[1], self.extern_),
            (COUNTED[2], self.no_mangle),
            (COUNTED[3], self.export_name),
        ]
    }
}

/// Counts [`COUNTED`] in `source`.
///
/// # Errors
///
/// As [`word_tokens`]: an unterminated comment or literal.
pub(crate) fn count(source: &str) -> Result<Counts, String> {
    let mut counts = Counts::default();
    for (index, _) in word_tokens(source, &COUNTED)? {
        let slot = match index {
            0 => &mut counts.unsafe_,
            1 => &mut counts.extern_,
            2 => &mut counts.no_mangle,
            _ => &mut counts.export_name,
        };
        *slot += 1;
    }
    Ok(counts)
}

/// What `counts.txt` records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    /// The wasm-bindgen version the expansion was made with.
    pub(crate) wasm_bindgen: String,
    /// The rustc that expanded it (`rustc -V`), free text.
    pub(crate) rustc: String,
    /// The [`fingerprint`] of the sources it was expanded from.
    pub(crate) sources: String,
    /// The counts.
    pub(crate) counts: Counts,
}

/// Renders `counts.txt`.
pub(crate) fn render(record: &Record) -> String {
    let mut out = String::from(
        "# ADR 0019 §4.1 (b): the baseline of crates/rizzy-wasm/generated/expanded.rs.\n\
         # Written by `cargo xtask expand-bindings --write`; checked by `cargo xtask check-deps`.\n\
         # Counts are keyword tokens and attribute names outside comments and literals.\n",
    );
    let mut lines = vec![
        format!("wasm-bindgen = {}", record.wasm_bindgen),
        format!("rustc = {}", record.rustc),
        format!("sources = {}", record.sources),
        format!("target = {TARGET}"),
    ];
    lines.extend(
        record
            .counts
            .pairs()
            .iter()
            .map(|(word, n)| format!("{word} = {n}")),
    );
    out.push_str(&lines.join("\n"));
    out.push('\n');
    out
}

/// Parses `counts.txt`: `key = value` lines, `#` comments, every key once, nothing else.
///
/// # Errors
///
/// Returns a message for an unknown, repeated or missing key, a line that is not `key =
/// value`, a count that is not a decimal number, or a target other than wasm32.
pub(crate) fn parse(text: &str) -> Result<Record, String> {
    let mut wasm_bindgen = None;
    let mut rustc = None;
    let mut sources = None;
    let mut target = None;
    let mut counts = [None::<usize>; 4];
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .map(|(k, v)| (k.trim(), v.trim()))
            .ok_or_else(|| format!("line {}: not `key = value`", n + 1))?;
        let slot = match key {
            "wasm-bindgen" => &mut wasm_bindgen,
            "rustc" => &mut rustc,
            "sources" => &mut sources,
            "target" => &mut target,
            _ => {
                let index = COUNTED
                    .iter()
                    .position(|w| *w == key)
                    .ok_or_else(|| format!("line {}: unknown key `{key}`", n + 1))?;
                let number = value
                    .parse()
                    .map_err(|_| format!("line {}: `{key}` is not a count", n + 1))?;
                let count = counts
                    .get_mut(index)
                    .ok_or_else(|| format!("line {}: unknown key `{key}`", n + 1))?;
                if count.replace(number).is_some() {
                    return Err(format!("line {}: `{key}` repeated", n + 1));
                }
                continue;
            }
        };
        if slot.replace(value.to_owned()).is_some() {
            return Err(format!("line {}: `{key}` repeated", n + 1));
        }
    }
    let missing = |key: &str| format!("`{key}` missing");
    if target.as_deref() != Some(TARGET) {
        return Err(format!("`target` must be {TARGET}"));
    }
    let [
        Some(unsafe_),
        Some(extern_),
        Some(no_mangle),
        Some(export_name),
    ] = counts
    else {
        return Err(missing("a count"));
    };
    Ok(Record {
        wasm_bindgen: wasm_bindgen.ok_or_else(|| missing("wasm-bindgen"))?,
        rustc: rustc.ok_or_else(|| missing("rustc"))?,
        sources: sources.ok_or_else(|| missing("sources"))?,
        counts: Counts {
            unsafe_,
            extern_,
            no_mangle,
            export_name,
        },
    })
}

/// The version of package `name` in `Cargo.lock` text, if exactly one is locked.
pub(crate) fn lock_version(lock: &str, name: &str) -> Option<String> {
    let wanted = format!("name = \"{name}\"");
    let mut lines = lock.lines();
    let mut found = Vec::new();
    while let Some(line) = lines.next() {
        if line.trim() == wanted {
            let version = lines
                .next()
                .and_then(|l| l.trim().strip_prefix("version = \""))
                .and_then(|v| v.strip_suffix('"'))?;
            found.push(version.to_owned());
        }
    }
    match found.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// What `check-deps` reads for the baseline check.
#[derive(Debug, Clone, Default)]
pub(crate) struct BaselineInput {
    /// Whether `rizzy-wasm` is a workspace member.
    pub(crate) member: bool,
    /// `expanded.rs`, if present.
    pub(crate) expanded: Option<String>,
    /// `counts.txt`, if present.
    pub(crate) counts: Option<String>,
    /// The `wasm-bindgen` version in `Cargo.lock`, if exactly one is locked.
    pub(crate) locked_wasm_bindgen: Option<String>,
    /// The `channel` of `rust-toolchain.toml`, if it names exactly one.
    pub(crate) toolchain_channel: Option<String>,
    /// The [`fingerprint`] of the current `rizzy-wasm` sources.
    pub(crate) sources: String,
}

/// The baseline check of `check-deps` (module docs, "Who checks what"). Each message is one
/// violation.
pub(crate) fn check(input: &BaselineInput) -> Vec<String> {
    if !input.member {
        return Vec::new();
    }
    let (Some(expanded), Some(counts)) = (&input.expanded, &input.counts) else {
        return vec![format!(
            "the expansion baseline is missing: commit {BASELINE_DIR}/{EXPANDED} and \
             {BASELINE_DIR}/{COUNTS} (`cargo xtask expand-bindings --write`)"
        )];
    };
    let record = match parse(counts) {
        Ok(record) => record,
        Err(e) => return vec![format!("{BASELINE_DIR}/{COUNTS}: {e}")],
    };
    let mut out = Vec::new();
    match &input.locked_wasm_bindgen {
        Some(locked) if *locked == record.wasm_bindgen => {}
        Some(locked) => out.push(format!(
            "{BASELINE_DIR}/{COUNTS} records wasm-bindgen {} but Cargo.lock has {locked}: \
             regenerate the baseline in the bump's PR (`cargo xtask expand-bindings --write`) \
             and review its diff and counts",
            record.wasm_bindgen
        )),
        None => out.push("Cargo.lock must lock exactly one wasm-bindgen".to_owned()),
    }
    match &input.toolchain_channel {
        Some(channel) if rustc_is(&record.rustc, channel) => {}
        Some(channel) => out.push(format!(
            "{BASELINE_DIR}/{COUNTS} records `{}` but rust-toolchain.toml pins {channel}: \
             regenerate the baseline with the pinned rustc in the bump's PR (`cargo xtask \
             expand-bindings --write`) and review its diff and counts",
            record.rustc
        )),
        None => out.push("rust-toolchain.toml must name exactly one `channel`".to_owned()),
    }
    if record.sources != input.sources {
        out.push(format!(
            "{BASELINE_DIR}/{COUNTS} was made from other {WASM_CRATE} sources ({}, now {}): \
             the generated glue may have changed; regenerate the baseline in this PR \
             (`cargo xtask expand-bindings --write`) and review its diff and counts",
            record.sources, input.sources
        ));
    }
    match count(expanded) {
        Ok(actual) if actual == record.counts => {}
        Ok(actual) => out.push(format!(
            "{BASELINE_DIR}/{COUNTS} does not match {EXPANDED}: recorded {:?}, counted {:?}",
            record.counts, actual
        )),
        Err(e) => out.push(format!("{BASELINE_DIR}/{EXPANDED}: {e}")),
    }
    out
}

/// The cargo that runs us, or `cargo`.
fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// Runs `cmd`, returning stdout, or a message with stderr.
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

/// The locked wasm-bindgen version of the workspace at `root`.
fn locked(root: &Path) -> Result<String, String> {
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|e| format!("reading Cargo.lock: {e}"))?;
    lock_version(&lock, "wasm-bindgen")
        .ok_or_else(|| "Cargo.lock must lock exactly one wasm-bindgen".to_owned())
}

/// The expansion of `rizzy-wasm` for wasm32, from the rustc in effect (module docs).
fn expand(root: &Path) -> Result<String, String> {
    let mut cmd = Command::new(cargo());
    cmd.current_dir(root)
        .args(["rustc", "-p", WASM_CRATE, "--lib", "--target", TARGET])
        .args(["--locked", "--profile", "check", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .args(["--", "-Zunpretty=expanded"]);
    run(&mut cmd).map_err(|e| {
        format!(
            "{e}\nexpand-bindings: `-Zunpretty=expanded` needs a toolchain that accepts `-Z` \
             options; run this job under its own pinned toolchain (ADR 0019 §4.1)"
        )
    })
}

/// `rustc -V` of the rustc in effect.
fn rustc_version(root: &Path) -> Result<String, String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    Ok(run(Command::new(rustc).current_dir(root).arg("-V"))?
        .trim()
        .to_owned())
}

/// `cargo xtask expand-bindings [--write]` (module docs). Returns the report to print, or a
/// message: a difference from the baseline without `--write` is an error that shows both
/// counts.
///
/// # Errors
///
/// When a command fails, a file cannot be read or written, or the baseline differs.
pub(crate) fn expand_bindings(root: &Path, write: bool) -> Result<String, String> {
    let expanded = expand(root)?;
    let record = Record {
        wasm_bindgen: locked(root)?,
        rustc: rustc_version(root)?,
        sources: fingerprint(&source_files(root)?),
        counts: count(&expanded)?,
    };
    let dir = root.join(BASELINE_DIR);
    let old_expanded = std::fs::read_to_string(dir.join(EXPANDED)).ok();
    let old_record = std::fs::read_to_string(dir.join(COUNTS))
        .ok()
        .and_then(|t| parse(&t).ok());
    let before = old_record
        .as_ref()
        .map_or_else(|| "none".to_owned(), |r| format!("{:?}", r.counts));
    let report = format!(
        "expand-bindings: wasm-bindgen {}, {}\n  before: {before}\n  after:  {:?}",
        record.wasm_bindgen, record.rustc, record.counts
    );
    if write {
        std::fs::create_dir_all(&dir).map_err(|e| format!("creating {BASELINE_DIR}: {e}"))?;
        std::fs::write(dir.join(EXPANDED), &expanded)
            .map_err(|e| format!("writing {EXPANDED}: {e}"))?;
        std::fs::write(dir.join(COUNTS), render(&record))
            .map_err(|e| format!("writing {COUNTS}: {e}"))?;
        return Ok(format!("{report}\n  written to {BASELINE_DIR}"));
    }
    if old_expanded.as_deref() == Some(expanded.as_str()) && old_record.as_ref() == Some(&record) {
        Ok(format!("{report}\n  the baseline is current"))
    } else {
        Err(format!(
            "{report}\n  the expansion differs from {BASELINE_DIR}: review the diff and counts, \
             then commit them with `cargo xtask expand-bindings --write`"
        ))
    }
}

/// The target directory cargo builds into: `CARGO_TARGET_DIR`, else `<root>/target`.
fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from)
}

/// `cargo xtask build-wasm` (module docs). Returns the report to print.
///
/// # Errors
///
/// When the CLI's version is not the locked one, or a command or file operation fails.
pub(crate) fn build_wasm(root: &Path) -> Result<String, String> {
    let version = locked(root)?;
    let cli = std::env::var_os("WASM_BINDGEN").unwrap_or_else(|| OsString::from("wasm-bindgen"));
    // ADR 0019 §4.1 "Pinned and vetted" wants the CLI built from a repository-owned lockfile,
    // under an approval record; neither exists yet (reported). The hint below builds it from
    // its upstream lockfile; the version check here is all this command can vouch for.
    let reported = run(Command::new(&cli).arg("--version")).map_err(|e| {
        format!(
            "{e}\nbuild-wasm: install the CLI with `cargo install wasm-bindgen-cli --version \
             {version} --locked` (upstream lockfile; ADR 0019 §4.1's repository-owned lockfile \
             for the CLI does not exist yet)"
        )
    })?;
    if reported.trim() != format!("wasm-bindgen {version}") {
        return Err(format!(
            "build-wasm: the CLI says `{}` but Cargo.lock has wasm-bindgen {version}; ADR 0013 \
             §4: the two must match (`cargo install wasm-bindgen-cli --version {version} \
             --locked`)",
            reported.trim()
        ));
    }
    let mut build = Command::new(cargo());
    build
        .current_dir(root)
        .args(["build", "-p", WASM_CRATE, "--lib", "--target", TARGET])
        .args(["--release", "--locked", "--manifest-path"])
        .arg(root.join("Cargo.toml"));
    run(&mut build)?;
    let module = target_dir(root)
        .join(TARGET)
        .join("release")
        .join("rizzy_wasm.wasm");
    let out = root.join(PACKAGE_OUT);
    std::fs::create_dir_all(&out).map_err(|e| format!("creating {PACKAGE_OUT}: {e}"))?;
    let mut bindgen = Command::new(&cli);
    bindgen
        .args(["--target", "web", "--out-name", OUT_NAME, "--out-dir"])
        .arg(&out)
        .arg(&module);
    run(&mut bindgen)?;
    let wasm = out.join(format!("{OUT_NAME}_bg.wasm"));
    let size = std::fs::metadata(&wasm)
        .map_err(|e| format!("reading {}: {e}", wasm.display()))?
        .len();
    Ok(format!(
        "build-wasm: {PACKAGE_OUT}/{OUT_NAME}_bg.wasm is {size} bytes (wasm-bindgen {version}, \
         release profile)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_skip_comments_and_literals() {
        let source = r#"
            // unsafe extern no_mangle
            /* export_name */
            const S: &str = "unsafe extern";
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn f() {}
            #[unsafe(export_name = "g")]
            fn g() { unsafe { } }
        "#;
        assert_eq!(
            count(source).unwrap(),
            Counts {
                unsafe_: 4,
                extern_: 1,
                no_mangle: 1,
                export_name: 1,
            }
        );
        assert!(count("/* open").is_err());
    }

    #[test]
    fn the_counts_file_round_trips_and_is_strict() {
        let record = Record {
            wasm_bindgen: "0.2.129".to_owned(),
            rustc: "rustc 1.94.1 (e408947bf 2026-03-25)".to_owned(),
            sources: "fnv1a64:0123456789abcdef".to_owned(),
            counts: Counts {
                unsafe_: 3,
                extern_: 2,
                no_mangle: 0,
                export_name: 5,
            },
        };
        assert_eq!(parse(&render(&record)).unwrap(), record);
        let text = render(&record);
        assert!(parse(&format!("{text}unsafe = 4\n")).is_err(), "repeated");
        assert!(parse(&format!("{text}color = red\n")).is_err(), "unknown");
        assert!(parse(&text.replace("unsafe = 3", "unsafe = x")).is_err());
        assert!(parse(&text.replace("unsafe = 3\n", "")).is_err(), "missing");
        assert!(parse(&text.replace(TARGET, "x86_64")).is_err());
        assert!(parse(&text.replace("rustc = ", "rustc ")).is_err());
        assert!(
            parse(&text.replace("sources = ", "# sources = ")).is_err(),
            "no sources"
        );
    }

    #[test]
    fn the_locked_version_is_read_once() {
        let lock = "[[package]]\nname = \"wasm-bindgen\"\nversion = \"0.2.129\"\n\n\
                    [[package]]\nname = \"wasm-bindgen-shared\"\nversion = \"0.2.129\"\n";
        assert_eq!(
            lock_version(lock, "wasm-bindgen").as_deref(),
            Some("0.2.129")
        );
        let twice = format!("{lock}[[package]]\nname = \"wasm-bindgen\"\nversion = \"0.2.1\"\n");
        assert_eq!(lock_version(&twice, "wasm-bindgen"), None);
        assert_eq!(lock_version(lock, "js-sys"), None);
    }

    #[test]
    fn the_check_compares_versions_and_counts() {
        let expanded = "#[unsafe(export_name = \"f\")] pub unsafe extern \"C\" fn f() {}";
        let record = Record {
            wasm_bindgen: "0.2.129".to_owned(),
            rustc: "rustc 1.94.1 (e408947bf 2026-03-25)".to_owned(),
            sources: "fnv1a64:0123456789abcdef".to_owned(),
            counts: count(expanded).unwrap(),
        };
        let good = BaselineInput {
            member: true,
            expanded: Some(expanded.to_owned()),
            counts: Some(render(&record)),
            locked_wasm_bindgen: Some("0.2.129".to_owned()),
            toolchain_channel: Some("1.94.1".to_owned()),
            sources: "fnv1a64:0123456789abcdef".to_owned(),
        };
        assert!(check(&good).is_empty());
        assert!(check(&BaselineInput::default()).is_empty(), "no member");
        let bumped = BaselineInput {
            locked_wasm_bindgen: Some("0.2.130".to_owned()),
            ..good.clone()
        };
        assert_eq!(check(&bumped).len(), 1);
        let edited = BaselineInput {
            expanded: Some(format!("{expanded} unsafe fn g() {{}}")),
            ..good.clone()
        };
        assert_eq!(check(&edited).len(), 1);
        let toolchain_bump = BaselineInput {
            toolchain_channel: Some("1.95.0".to_owned()),
            ..good.clone()
        };
        assert_eq!(check(&toolchain_bump).len(), 1);
        let no_channel = BaselineInput {
            toolchain_channel: None,
            ..good.clone()
        };
        assert_eq!(check(&no_channel).len(), 1);
        let source_edit = BaselineInput {
            sources: "fnv1a64:fedcba9876543210".to_owned(),
            ..good.clone()
        };
        assert_eq!(check(&source_edit).len(), 1);
        let missing = BaselineInput {
            expanded: None,
            ..good
        };
        assert_eq!(check(&missing).len(), 1);
    }

    #[test]
    fn the_fingerprint_sees_every_edit_but_not_line_endings() {
        let files = vec![
            ("Cargo.toml".to_owned(), b"[package]\n".to_vec()),
            ("src/lib.rs".to_owned(), b"pub fn f() {}\n".to_vec()),
        ];
        let base = fingerprint(&files);
        assert!(base.starts_with("fnv1a64:") && base.len() == "fnv1a64:".len() + 16);
        // FNV-1a 64 of nothing is the offset basis.
        assert_eq!(fingerprint(&[]), "fnv1a64:cbf29ce484222325");
        let crlf = vec![
            ("Cargo.toml".to_owned(), b"[package]\r\n".to_vec()),
            ("src/lib.rs".to_owned(), b"pub fn f() {}\r\n".to_vec()),
        ];
        assert_eq!(fingerprint(&crlf), base);
        let mut edited = files.clone();
        edited[1].1 = b"pub fn g() {}\n".to_vec();
        assert_ne!(fingerprint(&edited), base);
        let mut renamed = files.clone();
        renamed[1].0 = "src/other.rs".to_owned();
        assert_ne!(fingerprint(&renamed), base);
        // Moving bytes across a file boundary changes it (the lengths are hashed).
        let shifted = vec![
            ("Cargo.toml".to_owned(), b"[package]\npub".to_vec()),
            ("src/lib.rs".to_owned(), b" fn f() {}\n".to_vec()),
        ];
        assert_ne!(fingerprint(&shifted), base);
    }

    #[test]
    fn the_toolchain_channel_is_read_once() {
        let text = "[toolchain]\nchannel = \"1.94.1\"\ncomponents = [\"rustfmt\"]\n";
        assert_eq!(toolchain_channel(text).as_deref(), Some("1.94.1"));
        assert_eq!(toolchain_channel("[toolchain]\n"), None);
        assert_eq!(
            toolchain_channel(&format!("{text}channel = \"nightly\"\n")),
            None
        );
        assert!(rustc_is("rustc 1.94.1 (e408947bf 2026-03-25)", "1.94.1"));
        assert!(!rustc_is("rustc 1.94.10 (x 2026-01-01)", "1.94.1"));
        assert!(!rustc_is("rustc", "1.94.1"));
    }
}
