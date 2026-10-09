//! The compiled-in Public Suffix List snapshot and registrable-domain (eTLD+1) computation
//! (ADR 0037 §3).
//!
//! The `psl` crate ships Mozilla's Public Suffix List compiled into its own binary at publish
//! time (`src/list.rs`, generated from `data/rules.txt`; no build script, no runtime fetch).
//! `rizzy-match` is a no-I/O crate (ADR 0016 R1) and never reads either file itself — a
//! previous version of this comment claimed `psl` "has none to hash" and relied on the exact
//! version pin in `[workspace.dependencies]` alone, but that is wrong: the published `psl`
//! package does ship both files, and a reviewer can and should diff them on a version bump.
//! ADR 0037 §3's "build step that embeds the PSL snapshot computes its SHA-256 and asserts it
//! against a constant in the source" runs as `cargo xtask check-deps`
//! (`crates/xtask/src/psl_check.rs`): it locates the resolved `psl` package from `cargo
//! metadata --locked`, hashes `data/rules.txt` (what a reviewer diffs) and `src/list.rs` (what
//! actually compiles in), and asserts both against [`PSL_RULES_TXT_SHA256`] and
//! [`PSL_LIST_RS_SHA256`] below. `rizzy-match` itself stays no-I/O: it only *declares* the
//! constants a separate tool crate checks against the dependency on disk, the same split
//! `rizzy-match` already has with the equivalence-list signing tool (`compiled.rs`,
//! `crates/xtask/src/equivalence_list.rs`). A `psl` version bump is reviewed like any other
//! change to compiled-in security data: the PR updates the version pin in the root
//! `Cargo.toml` *and* both hash constants together, and the reviewer diffs `rules.txt`.

/// The exact `psl` version this build's hash constants below were computed against
/// (`[workspace.dependencies]` in the root `Cargo.toml`). `cargo xtask check-deps`
/// (`psl_check`) asserts the resolved `psl` package is exactly this version, so a dependency
/// bump that forgets to update [`PSL_RULES_TXT_SHA256`] and [`PSL_LIST_RS_SHA256`] fails loudly
/// instead of silently shipping a re-hashed snapshot under the old constants (ADR 0037 §3).
pub const PSL_VERSION: &str = "2.1.240";

/// SHA-256 of the `psl` crate's `data/rules.txt` (the human-reviewable Public Suffix List
/// source a reviewer diffs on a version bump), lower-case hex, computed 2026-10-09 against
/// `psl` [`PSL_VERSION`] (ADR 0037 §3 "Verification").
pub const PSL_RULES_TXT_SHA256: &str =
    "247183557802158c3f0168b2deeaf4f9c5672c7313a34bacefef73235f0e6686";

/// SHA-256 of the `psl` crate's `src/list.rs` (the generated Rust source that actually compiles
/// into this crate's dependency closure), lower-case hex, computed 2026-10-09 against `psl`
/// [`PSL_VERSION`] (ADR 0037 §3 "Verification").
pub const PSL_LIST_RS_SHA256: &str =
    "17efdc541e7b56c5bdfb4bb5fe02bfda8fe600dd52544bfc549c48003ab74f7c";

/// The registrable domain (eTLD+1) of an already-normalised host (lower-case A-label, no
/// trailing dot — [`crate::normalize::NormalizedUrl::parse`] guarantees this for every host it
/// produces).
///
/// `None` when `host` is itself a public suffix or above one (`co.uk`, `github.io`, a bare
/// `com`): there is no label registrable beneath it, so it can never satisfy the
/// registrable-domain gate (ADR 0037 §4, INV-38), including against another occurrence of the
/// same bare suffix — two logins both (mis)configured against the literal string `co.uk` must
/// not be treated as matching each other.
#[must_use]
pub fn registrable_domain(host: &str) -> Option<String> {
    psl::domain_str(host).map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{PSL_LIST_RS_SHA256, PSL_RULES_TXT_SHA256, PSL_VERSION, registrable_domain};

    /// Guards against a hand-edit typo in the pinned hash constants: each is exactly 64
    /// lower-case hex digits (32 bytes). This cannot catch a snapshot that actually changed
    /// (that needs the real file bytes, read by `cargo xtask check-deps`'s `psl_check`, a
    /// no-I/O-crate boundary this test does not cross), only a malformed constant.
    #[test]
    fn pinned_hashes_are_well_formed_sha256_hex() {
        for hash in [PSL_RULES_TXT_SHA256, PSL_LIST_RS_SHA256] {
            assert_eq!(hash.len(), 64, "{hash:?} is not 64 hex characters");
            assert!(
                hash.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{hash:?} is not lower-case hex"
            );
        }
        assert!(!PSL_VERSION.is_empty());
    }

    #[test]
    fn simple_domain() {
        assert_eq!(
            registrable_domain("example.com"),
            Some("example.com".into())
        );
    }

    #[test]
    fn subdomain_strips_to_registrable_domain() {
        assert_eq!(
            registrable_domain("a.b.example.co.uk"),
            Some("example.co.uk".into())
        );
    }

    #[test]
    fn bare_icann_suffix_has_no_registrable_domain() {
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("com"), None);
    }

    #[test]
    fn bare_private_suffix_has_no_registrable_domain() {
        // github.io is a PSL "private" entry: the suffix itself is not registrable, but a
        // label beneath it is (ADR 0037 §3's PSL-based computation treats ICANN and private
        // entries alike, per the ADR's description of eTLD+1 against "the compiled-in PSL
        // snapshot" without distinguishing sections).
        assert_eq!(registrable_domain("github.io"), None);
        assert_eq!(
            registrable_domain("foo.github.io"),
            Some("foo.github.io".into())
        );
    }

    #[test]
    fn unknown_tld_has_no_registrable_domain_judgement_beyond_the_snapshot() {
        // Not in the PSL at all: `psl` treats the last label as an implicit suffix (the common
        // "unlisted TLD" fallback every PSL-based implementation applies), so this still
        // produces a registrable domain rather than `None`.
        assert_eq!(
            registrable_domain("example.doesnotexist"),
            Some("example.doesnotexist".into())
        );
    }
}
