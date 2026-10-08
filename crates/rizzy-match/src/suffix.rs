//! The compiled-in Public Suffix List snapshot and registrable-domain (eTLD+1) computation
//! (ADR 0037 §3).
//!
//! The `psl` crate ships Mozilla's Public Suffix List compiled into its own binary at publish
//! time (`src/list.rs`, generated from `data/rules.txt`; no build script, no runtime fetch).
//! There is no separate data file for `rizzy-match` to `include_bytes!` and hash the way ADR
//! 0037 §3 describes for a typical compiled-in snapshot: the exact `psl` version pinned in
//! `[workspace.dependencies]` of the root `Cargo.toml` (`=2.1.240`, fetched 2026-10-07) *is*
//! the snapshot pin, and a PSL update is an ordinary version-bump PR on that one line,
//! reviewed like any other change to compiled-in security data (ADR 0037 §3's own description
//! of the review, applied to the version pin instead of a file diff).

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
    use super::registrable_domain;

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
