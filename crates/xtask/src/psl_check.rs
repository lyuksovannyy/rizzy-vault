//! `cargo xtask check-deps`'s PSL-snapshot integrity check (ADR 0037 §3, "Verification"):
//! hashes the resolved `psl` package's `data/rules.txt` and `src/list.rs` on disk and asserts
//! them against the constants pinned in `rizzy_match::suffix`
//! (`PSL_RULES_TXT_SHA256`, `PSL_LIST_RS_SHA256`).
//!
//! `rizzy-match` is a no-I/O crate (ADR 0016 R1) and cannot read these files itself
//! (`rizzy_match::suffix`'s own module docs); this tool/leaf crate (ADR 0016 R6 "Tool") does
//! the reading, from the path `cargo metadata --locked` already resolved. Every failure mode —
//! the package missing from the graph, its version drifting from the pin, a checked file
//! missing or unreadable, or a hash not matching — is a violation, never a silent pass
//! ([`crate::check`]'s module docs, "fails closed"): a `psl` bump that forgets to update the
//! hash constants fails `cargo xtask check-deps` loudly.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::metadata::Graph;

/// `psl`'s package name in the resolved graph.
const PSL_PACKAGE: &str = "psl";

/// The files this check hashes, relative to the `psl` package's manifest directory, and the
/// pinned constant each is checked against: `data/rules.txt` (the human-reviewable source a
/// reviewer diffs on a version bump) and `src/list.rs` (the generated Rust that actually
/// compiles into `rizzy-match`'s dependency closure).
const CHECKED_FILES: &[(&str, &str)] = &[
    ("data/rules.txt", rizzy_match::suffix::PSL_RULES_TXT_SHA256),
    ("src/list.rs", rizzy_match::suffix::PSL_LIST_RS_SHA256),
];

/// Runs the check against `graph` (any of `cargo metadata --locked`'s graphs; the resolved
/// `psl` package and its manifest path are the same regardless of `--filter-platform`).
///
/// # Errors
/// One message per problem found, so a run reports every mismatch instead of stopping at the
/// first: `psl` missing from the graph, its version not [`rizzy_match::suffix::PSL_VERSION`],
/// a checked file missing or unreadable, or its hash not matching the pinned constant.
pub(crate) fn check(graph: &Graph) -> Result<(), Vec<String>> {
    let Some(pkg) = graph.packages.iter().find(|p| p.name == PSL_PACKAGE) else {
        return Err(vec![format!(
            "{PSL_PACKAGE} is not in the resolved dependency graph; the PSL snapshot check \
             (ADR 0037 §3) cannot run"
        )]);
    };
    let mut violations = Vec::new();
    if pkg.version != rizzy_match::suffix::PSL_VERSION {
        violations.push(format!(
            "{PSL_PACKAGE} is pinned to {}, but crates/rizzy-match/src/suffix.rs's hash \
             constants were computed against PSL_VERSION = {:?}; update PSL_VERSION, \
             PSL_RULES_TXT_SHA256 and PSL_LIST_RS_SHA256 together on a version bump \
             (ADR 0037 §3)",
            pkg.version,
            rizzy_match::suffix::PSL_VERSION
        ));
    }
    let Some(manifest_dir) = Path::new(&pkg.manifest_path).parent() else {
        violations.push(format!(
            "{PSL_PACKAGE}'s manifest path {} has no parent directory",
            pkg.manifest_path
        ));
        return Err(violations);
    };
    for (rel, expected) in CHECKED_FILES {
        if let Err(e) = verify_file(&manifest_dir.join(rel), expected) {
            violations.push(e);
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Reads `path` and checks its SHA-256 against `expected_hex` (lower-case hex).
///
/// # Errors
/// A message naming the path when it cannot be read (including when missing), or when its hash
/// does not match `expected_hex`.
fn verify_file(path: &Path, expected_hex: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let got = hex_sha256(&bytes);
    if got == expected_hex {
        Ok(())
    } else {
        Err(format!(
            "{} sha256 is {got}, expected {expected_hex} (crates/rizzy-match/src/suffix.rs); \
             the embedded PSL snapshot changed without updating the pinned hash (ADR 0037 §3)",
            path.display()
        ))
    }
}

/// Lower-case hex SHA-256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    // `fold` + `write!` rather than `.map(...).collect()` (clippy's `format_collect`: a
    // `format!` call per byte allocates a throwaway `String` each time). `write!` to a `String`
    // is infallible (`core::fmt::Write` for `String` never returns `Err`), so discarding the
    // `Result` here is not the kind of `unwrap`/`expect` CLAUDE.md's "no unwrap/expect/panic in
    // non-test code" rule exists to catch — there is no error path to swallow.
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{check, hex_sha256, verify_file};
    use crate::metadata::{Graph, Package};

    /// A one-package graph holding `psl` at `version`, with its manifest at
    /// `dir/Cargo.toml` (so `dir` is the manifest directory `check` reads files from).
    fn graph_with_psl(dir: &std::path::Path, version: &str) -> Graph {
        Graph {
            packages: vec![Package {
                id: "psl".to_owned(),
                name: "psl".to_owned(),
                version: version.to_owned(),
                manifest_path: dir.join("Cargo.toml").display().to_string(),
                is_member: false,
                features: Vec::new(),
                deps: Vec::new(),
                declared: Vec::new(),
                feature_table: Vec::new(),
            }],
            workspace_root: String::new(),
        }
    }

    /// A fresh scratch directory under the OS temp dir, removed by the caller.
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rizzy-xtask-psl-check-test-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn verify_file_accepts_a_matching_hash() {
        let dir = scratch_dir("accepts");
        let path = dir.join("rules.txt");
        fs::write(&path, b"hello psl").unwrap();
        let expected = hex_sha256(b"hello psl");
        assert_eq!(verify_file(&path, &expected), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_file_rejects_a_changed_snapshot() {
        // This is the regression the gap describes: the snapshot changed but the pinned
        // constant did not, so the check must fail rather than silently pass.
        let dir = scratch_dir("rejects");
        let path = dir.join("rules.txt");
        fs::write(&path, b"a tampered or upgraded snapshot").unwrap();
        let stale_expected = hex_sha256(b"hello psl");
        let err = verify_file(&path, &stale_expected).unwrap_err();
        assert!(err.contains("sha256 is"));
        assert!(err.contains("ADR 0037"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_file_reports_a_missing_file() {
        let dir = scratch_dir("missing");
        let path = dir.join("does-not-exist.txt");
        let err = verify_file(&path, "deadbeef").unwrap_err();
        assert!(err.contains("reading"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_fails_when_the_psl_package_is_absent() {
        let graph = Graph::default();
        let err = check(&graph).unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(err[0].contains("not in the resolved dependency graph"));
    }

    #[test]
    fn check_reports_a_version_drift_separately_from_a_hash_mismatch() {
        let dir = scratch_dir("version-drift");
        fs::create_dir_all(dir.join("data")).unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        // Deliberately wrong contents: this test is only about the version-mismatch message
        // appearing, not about also tripping the file hashes (both will fail here too, and
        // that is fine: `check` collects every violation instead of stopping at the first).
        fs::write(dir.join("data/rules.txt"), b"not the real list").unwrap();
        fs::write(dir.join("src/list.rs"), b"not the real source").unwrap();
        let graph = graph_with_psl(&dir, "9.9.9");
        let violations = check(&graph).unwrap_err();
        assert!(violations.iter().any(|v| v.contains("is pinned to 9.9.9")));
        let _ = fs::remove_dir_all(&dir);
    }
}
