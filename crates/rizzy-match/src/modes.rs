// SPDX-License-Identifier: AGPL-3.0-only

//! Per-URI match modes and the match decision (ADR 0037 §4; INV-38).
//!
//! [`decide`] is the one function that combines a page's [`NormalizedUrl`], an item URI's
//! [`NormalizedUrl`], its [`MatchMode`] and an [`EquivalenceView`] into a [`MatchOutcome`]. The
//! registrable-domain gate (ADR 0037 §4 "Narrowing only"; INV-38) and the HTTPS→HTTP rule (ADR
//! 0037 §5; INV-37) sit outside the per-mode dispatch, so a new mode added later cannot
//! accidentally widen past either: every mode above *Never* goes through both before its own
//! rule runs.

use crate::equivalence::{EquivalenceView, GroupId};
use crate::normalize::NormalizedUrl;
use crate::pattern::{RegexEvaluation, RegexSession};
use crate::security::https_downgrade_blocks;

/// The wire value of `uri/<id>/match` (ADR 0018 §7; ADR 0037 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MatchMode {
    /// `0x0000`: absent, or explicitly set to the account default.
    AccountDefault,
    /// `0x0001`: the fallback default.
    BaseDomain,
    /// `0x0002`: no equivalence-group widening.
    Host,
    /// `0x0003`: path-prefix, gated the same as every other mode.
    StartsWith,
    /// `0x0004`: byte-equal full normalised URL.
    Exact,
    /// `0x0005`: the URI's `pattern` searched in the page's normalised URL, after the same gates
    /// as every mode (ADR 0097 §3).
    Regex,
    /// `0x0006`: never offered for autofill matching.
    Never,
}

impl MatchMode {
    /// Decodes a wire value. `None` for `0x0007`–`0xFFFF` (ADR 0037 §4: unassigned, needs an
    /// ADR update to add a row).
    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::AccountDefault),
            0x0001 => Some(Self::BaseDomain),
            0x0002 => Some(Self::Host),
            0x0003 => Some(Self::StartsWith),
            0x0004 => Some(Self::Exact),
            0x0005 => Some(Self::Regex),
            0x0006 => Some(Self::Never),
            _ => None,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::AccountDefault => 0x0000,
            Self::BaseDomain => 0x0001,
            Self::Host => 0x0002,
            Self::StartsWith => 0x0003,
            Self::Exact => 0x0004,
            Self::Regex => 0x0005,
            Self::Never => 0x0006,
        }
    }

    /// Resolves `AccountDefault` against the account's own default mode (ADR 0037 §6:
    /// "Defaults to *Base domain* (`0x0001`) when the account has never set one"). A URI mode
    /// that is not `AccountDefault` is returned unchanged; an account default that is itself
    /// `AccountDefault` (never set, or round-tripped incorrectly) resolves to *Base domain*,
    /// never left unresolved.
    #[must_use]
    pub const fn resolve(self, account_default: Self) -> EffectiveMode {
        let mode = match self {
            Self::AccountDefault => account_default,
            other => other,
        };
        match mode {
            Self::AccountDefault | Self::BaseDomain => EffectiveMode::BaseDomain,
            Self::Host => EffectiveMode::Host,
            Self::StartsWith => EffectiveMode::StartsWith,
            Self::Exact => EffectiveMode::Exact,
            Self::Regex => EffectiveMode::Regex,
            Self::Never => EffectiveMode::Never,
        }
    }
}

/// A [`MatchMode`] with `AccountDefault` already resolved: the shape [`decide`] actually
/// dispatches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectiveMode {
    /// Registrable-domain or equivalence-group match (the gate itself).
    BaseDomain,
    /// Full host, no equivalence widening.
    Host,
    /// Byte prefix of the full normalised URL, query and fragment dropped (ADR 0097 §2).
    StartsWith,
    /// Byte-equal full normalised URL, query and fragment dropped (ADR 0097 §2).
    Exact,
    /// The URI's `pattern` searched in the page's normalised URL (ADR 0097 §3), after the
    /// HTTPS→HTTP rule and the registrable-domain gate.
    Regex,
    /// Never offered for autofill matching.
    Never,
}

/// Why a candidate matched (ADR 0037 §5 "Equivalence-only match warning").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MatchedVia {
    /// The page and the URI share the same registrable domain.
    RegistrableDomain,
    /// The page and the URI are in the same equivalence group, named by its id, but do not
    /// share a registrable domain.
    Equivalence(GroupId),
}

impl MatchedVia {
    /// Whether the fill UI must show the equivalence-only warning (ADR 0037 §5): "the saved
    /// site and the matched site" notice, before the user confirms the fill.
    #[must_use]
    pub const fn needs_warning(self) -> bool {
        matches!(self, Self::Equivalence(_))
    }
}

/// [`EffectiveMode`] narrowed to the five modes that reach the per-mode dispatch in [`decide`]:
/// every variant except [`EffectiveMode::Never`], which `decide` already returns for before the
/// registrable-domain gate runs. A value of this type cannot hold `Never` at all, so the dispatch match in [`decide`] is exhaustive with
/// no catch-all arm and no panic path, unlike matching [`EffectiveMode`] directly there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum GatedMode {
    /// Registrable-domain or equivalence-group match (the gate itself; always passes once the
    /// gate above it has).
    BaseDomain,
    /// Full host and port, no equivalence widening.
    Host,
    /// Path-prefix of the full normalised URL (host, port and path).
    StartsWith,
    /// Byte-equal full normalised URL.
    Exact,
    /// The pattern searched in the page's normalised URL (ADR 0097 §3.2 steps 4–7).
    Regex,
}

/// The result of [`decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MatchOutcome {
    /// A candidate, and why it matched.
    Match(MatchedVia),
    /// Checked; does not match (including *Never* and the HTTPS→HTTP rule).
    NoMatch,
    /// *Regex* mode: the gates passed, but the URI's pattern is not valid
    /// ([`crate::pattern::compile`]; ADR 0097 §3.3). The pattern was not searched.
    InvalidPattern,
    /// *Regex* mode: the gates passed, but this call's [`RegexSession`] already evaluated
    /// [`crate::error::MAX_REGEX_EVALUATIONS`] URIs (ADR 0097 §3.4). Not evaluated.
    RegexBudgetExceeded,
}

/// The registrable-domain gate (ADR 0037 §4 "Narrowing only"; INV-38): the page and the URI
/// must share a registrable domain, or be in the same equivalence group. A side with no
/// registrable domain at all (a bare public suffix, `co.uk`) never passes, even against
/// another occurrence of the same bare suffix.
fn registrable_gate(
    page: &NormalizedUrl,
    uri: &NormalizedUrl,
    equivalence: &EquivalenceView<'_>,
) -> Option<MatchedVia> {
    let page_domain = page.registrable_domain()?;
    let uri_domain = uri.registrable_domain()?;
    if page_domain == uri_domain {
        return Some(MatchedVia::RegistrableDomain);
    }
    equivalence
        .same_group(page_domain, uri_domain)
        .map(MatchedVia::Equivalence)
}

/// Decides whether `uri` is a match candidate for `page`.
///
/// Order, deliberately, so a future mode cannot widen past either rule: *Never* and the
/// HTTPS→HTTP rule, both unconditional; only then the registrable-domain gate, which every
/// remaining mode must pass before its own rule runs.
///
/// `pattern` (the URI's raw `uri/<id>/pattern`, `None` when absent or `Cleared`) and `regex`
/// (the call's budget) are used by *Regex* only and ignored by every other mode. *Regex* runs
/// ADR 0097 §3.2 steps 2–7 here, so the pattern is never compiled for a page that has not
/// passed both gates: a page on another registrable domain costs nothing and never consults
/// the pattern (INV-38).
#[must_use]
pub fn decide(
    page: &NormalizedUrl,
    uri: &NormalizedUrl,
    mode: MatchMode,
    account_default: MatchMode,
    equivalence: &EquivalenceView<'_>,
    pattern: Option<&str>,
    regex: &mut RegexSession,
) -> MatchOutcome {
    let effective = mode.resolve(account_default);
    // One exhaustive match narrows `effective` to `GatedMode` (module docs, `GatedMode`) and
    // returns early for *Never*, the one mode that never reaches the gates below. `GatedMode`
    // cannot hold it, so the per-mode dispatch further down is exhaustive with no catch-all arm
    // and no panic path.
    let gated = match effective {
        EffectiveMode::Regex => GatedMode::Regex,
        EffectiveMode::Never => return MatchOutcome::NoMatch,
        EffectiveMode::BaseDomain => GatedMode::BaseDomain,
        EffectiveMode::Host => GatedMode::Host,
        EffectiveMode::StartsWith => GatedMode::StartsWith,
        EffectiveMode::Exact => GatedMode::Exact,
    };
    if https_downgrade_blocks(uri.scheme(), page.scheme()) {
        return MatchOutcome::NoMatch;
    }
    let Some(matched_via) = registrable_gate(page, uri, equivalence) else {
        return MatchOutcome::NoMatch;
    };
    let passes_mode_rule = match gated {
        GatedMode::BaseDomain => true,
        // ADR 0037 §2 rule 5: a non-default port "is part of the comparison for Host... mode".
        // `NormalizedUrl::port` already omits each scheme's own default, so two different
        // default ports (http 80 vs https 443) still compare equal (both `None`), and only a
        // genuinely different explicit port fails this check.
        GatedMode::Host => page.host() == uri.host() && page.port() == uri.port(),
        GatedMode::StartsWith => page
            .normalized_string()
            .starts_with(&uri.normalized_string()),
        GatedMode::Exact => page.normalized_string() == uri.normalized_string(),
        GatedMode::Regex => match regex.evaluate(pattern, &page.normalized_string()) {
            RegexEvaluation::Match => true,
            RegexEvaluation::NoMatch => false,
            RegexEvaluation::InvalidPattern => return MatchOutcome::InvalidPattern,
            RegexEvaluation::BudgetExceeded => return MatchOutcome::RegexBudgetExceeded,
        },
    };
    if passes_mode_rule {
        MatchOutcome::Match(matched_via)
    } else {
        MatchOutcome::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::equivalence::EquivalenceGroup;
    use std::collections::BTreeSet;

    fn url(s: &str) -> NormalizedUrl {
        NormalizedUrl::parse(s).unwrap()
    }

    fn no_equivalence() -> EquivalenceView<'static> {
        EquivalenceView::empty()
    }

    /// [`super::decide`] for the modes that ignore `pattern` and `regex`: no pattern, a fresh
    /// session. Shadows the glob import, so the non-*Regex* tests read as before ADR 0097.
    fn decide(
        page: &NormalizedUrl,
        uri: &NormalizedUrl,
        mode: MatchMode,
        account_default: MatchMode,
        equivalence: &EquivalenceView<'_>,
    ) -> MatchOutcome {
        super::decide(
            page,
            uri,
            mode,
            account_default,
            equivalence,
            None,
            &mut RegexSession::new(),
        )
    }

    fn decide_regex(page: &str, value: &str, pattern: &str) -> MatchOutcome {
        super::decide(
            &url(page),
            &url(value),
            MatchMode::Regex,
            MatchMode::BaseDomain,
            &no_equivalence(),
            Some(pattern),
            &mut RegexSession::new(),
        )
    }

    #[test]
    fn wire_values_round_trip() {
        for mode in [
            MatchMode::AccountDefault,
            MatchMode::BaseDomain,
            MatchMode::Host,
            MatchMode::StartsWith,
            MatchMode::Exact,
            MatchMode::Regex,
            MatchMode::Never,
        ] {
            assert_eq!(MatchMode::from_wire(mode.to_wire()), Some(mode));
        }
        assert_eq!(MatchMode::from_wire(0x0007), None);
        assert_eq!(MatchMode::from_wire(0xFFFF), None);
    }

    #[test]
    fn evil_lookalike_never_matches_base_domain() {
        let page = url("https://evil-youtube.com/login");
        let uri = url("https://youtube.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::BaseDomain,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn base_domain_matches_same_registrable_domain() {
        let page = url("https://accounts.example.com/login");
        let uri = url("https://example.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::BaseDomain,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn base_domain_matches_via_equivalence_group_and_flags_the_warning() {
        let page = url("https://youtu.be/");
        let uri = url("https://youtube.com/");
        let group = EquivalenceGroup::new(
            GroupId::from_bytes([1; 16]),
            ["youtube.com", "youtu.be"],
            false,
        )
        .unwrap();
        let global = vec![group];
        let disabled = BTreeSet::new();
        let user = vec![];
        let view = EquivalenceView::new(&global, &disabled, &user);
        let outcome = decide(
            &page,
            &uri,
            MatchMode::BaseDomain,
            MatchMode::BaseDomain,
            &view,
        );
        let MatchOutcome::Match(via) = outcome else {
            panic!("expected a match, got {outcome:?}");
        };
        assert!(via.needs_warning());
    }

    #[test]
    fn host_mode_requires_equal_ports() {
        // ADR 0037 §2 rule 5: a non-default port "is part of the comparison for Host... mode".
        // Equal explicit ports still match.
        let page = url("https://example.com:8443/");
        let uri = url("https://example.com:8443/login");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Host,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn host_mode_rejects_a_different_explicit_port() {
        // Regression: `https://example.com:8443` must never match a URI saved for
        // `https://example.com:9000` just because the hosts are equal (ADR 0037 §2 rule 5).
        let page = url("https://example.com:8443/");
        let uri = url("https://example.com:9000/login");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Host,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn host_mode_treats_an_explicit_default_port_the_same_as_an_omitted_one() {
        // `https://example.com:443` normalises to the same (portless) form as
        // `https://example.com` (ADR 0037 §2 rule 5: default ports are omitted before any mode
        // compares them), so Host mode must still match.
        let page = url("https://example.com:443/");
        let uri = url("https://example.com/login");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Host,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn host_mode_does_not_confuse_differing_http_and_https_default_ports() {
        // `http://example.com` (default port 80, omitted) and `https://example.com` (default
        // port 443, also omitted) must compare as the same (absent) port, never as "80 != 443":
        // `NormalizedUrl::port` already strips the scheme's own default before Host mode ever
        // sees it. An HTTP-saved URI may still match an HTTPS page (ADR 0037 §5).
        let https_page = url("https://example.com/");
        let http_uri = url("http://example.com/login");
        assert_eq!(
            decide(
                &https_page,
                &http_uri,
                MatchMode::Host,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn host_mode_requires_exact_host() {
        let page = url("https://sub.example.com/");
        let uri = url("https://example.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Host,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
        let same_host_uri = url("https://sub.example.com/anything");
        assert_eq!(
            decide(
                &page,
                &same_host_uri,
                MatchMode::Host,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn starts_with_requires_the_registrable_domain_gate_first() {
        // `https://bank.com` must never match `https://bank.com.evil.example/`: the gate fails
        // before the prefix check ever runs (ADR 0037 §4).
        let page = url("https://bank.com.evil.example/anything");
        let uri = url("https://bank.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::StartsWith,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn starts_with_matches_a_path_prefix_within_the_gate() {
        let page = url("https://example.com/account/settings");
        let uri = url("https://example.com/account");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::StartsWith,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn starts_with_matches_when_ports_are_equal() {
        let page = url("https://example.com:8443/account/settings");
        let uri = url("https://example.com:8443/account");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::StartsWith,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn starts_with_rejects_a_different_explicit_port() {
        // ADR 0037 §2 rule 5: the port is part of *Starts with*'s comparison too (via the full
        // normalised URL). `https://example.com:8443/account` must not be treated as a prefix
        // match for a page on a different explicit port.
        let page = url("https://example.com:9000/account/settings");
        let uri = url("https://example.com:8443/account");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::StartsWith,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn exact_rejects_a_different_explicit_port() {
        // ADR 0037 §2 rule 5: the port is part of *Exact*'s comparison too (via the full
        // normalised URL).
        let page = url("https://example.com:8443/login");
        let uri = url("https://example.com:9000/login");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Exact,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn exact_requires_byte_equality() {
        let page = url("https://example.com/login");
        let uri = url("https://example.com/login/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Exact,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
        let same = url("https://example.com/login");
        assert_eq!(
            decide(
                &page,
                &same,
                MatchMode::Exact,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    /// A *Regex* URI without a pattern never matches (ADR 0097 §3.1).
    #[test]
    fn regex_without_a_pattern_is_invalid() {
        let page = url("https://example.com/");
        let uri = url("https://example.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Regex,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::InvalidPattern
        );
    }

    #[test]
    fn never_mode_never_matches_even_itself() {
        let page = url("https://example.com/");
        let uri = url("https://example.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Never,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn https_saved_never_fills_http_page() {
        let http_page = url("http://example.com/");
        let https_uri = url("https://example.com/");
        assert_eq!(
            decide(
                &http_page,
                &https_uri,
                MatchMode::BaseDomain,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn http_saved_matches_https_page() {
        let https_page = url("https://example.com/");
        let http_uri = url("http://example.com/");
        assert_eq!(
            decide(
                &https_page,
                &http_uri,
                MatchMode::BaseDomain,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn account_default_resolves_to_base_domain_when_unset() {
        assert_eq!(
            MatchMode::AccountDefault.resolve(MatchMode::AccountDefault),
            EffectiveMode::BaseDomain
        );
    }

    #[test]
    fn ip_literal_page_never_matches_a_uri_saved_at_a_different_ip() {
        // Regression for the `psl`-on-an-IP collision: a page at one IP-literal host must never
        // match a URI saved at a different IP-literal host under the default BaseDomain mode,
        // even when their last two octets happen to coincide.
        let page = url("https://10.0.1.1/");
        let uri = url("https://192.168.1.1/login");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::BaseDomain,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn host_mode_works_for_an_identical_ipv6_literal_uri() {
        let page = url("https://[::1]:8443/admin");
        let uri = url("https://[::1]:8443/admin");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Host,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn exact_mode_works_for_an_identical_bare_hostname_uri() {
        let page = url("https://localhost:8443/admin");
        let uri = url("https://localhost:8443/admin");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::Exact,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    #[test]
    fn idn_homograph_never_matches_the_real_domain_under_base_domain_mode() {
        let page = url("https://\u{0430}pple.com/");
        let uri = url("https://apple.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::BaseDomain,
                MatchMode::BaseDomain,
                &no_equivalence()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn account_default_resolves_to_the_account_setting() {
        assert_eq!(
            MatchMode::AccountDefault.resolve(MatchMode::Host),
            EffectiveMode::Host
        );
    }

    fn decide_plain(page: &str, uri: &str, mode: MatchMode) -> MatchOutcome {
        decide(
            &url(page),
            &url(uri),
            mode,
            MatchMode::BaseDomain,
            &no_equivalence(),
        )
    }

    /// ADR 0097 §6 step 1: *Exact* ignores the query on both sides, but not the path.
    #[test]
    fn exact_compares_the_normalised_url_without_query_adr0097() {
        let saved = "https://example.com/login?x=1";
        assert_eq!(
            decide_plain("https://example.com/login?y=2", saved, MatchMode::Exact),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
        assert_eq!(
            decide_plain("https://example.com/login/", saved, MatchMode::Exact),
            MatchOutcome::NoMatch
        );
        assert_eq!(
            decide_plain("https://example.com/login#top", saved, MatchMode::Exact),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    /// ADR 0097 §6 step 1: *Starts with* is a byte prefix of the normalised URL, query
    /// dropped, not a path-segment prefix (documented).
    #[test]
    fn starts_with_is_a_byte_prefix_without_query_adr0097() {
        assert_eq!(
            decide_plain(
                "https://example.com/login/step?z",
                "https://example.com/login?x=1",
                MatchMode::StartsWith
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
        assert_eq!(
            decide_plain(
                "https://example.com/login",
                "https://example.com/log",
                MatchMode::StartsWith
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    /// ADR 0097 §6 step 1: *Regex* never sees the query; an anchored pattern on the path does.
    #[test]
    fn regex_searches_the_normalised_url_without_query_adr0097() {
        let page = "https://example.com/login?x=1";
        let value = "https://example.com/";
        assert_eq!(decide_regex(page, value, "x=1"), MatchOutcome::NoMatch);
        assert_eq!(
            decide_regex(page, value, r"^https://example\.com/login$"),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
    }

    /// ADR 0097 §6 step 3, INV-38: a match-everything pattern never escapes the gate.
    #[test]
    fn regex_never_matches_another_registrable_domain_inv38() {
        assert_eq!(
            decide_regex("https://evil.example/", "https://example.com/", ".*"),
            MatchOutcome::NoMatch
        );
    }

    /// ADR 0097 §6 step 3, order: the gate runs before the pattern is compiled.
    #[test]
    fn regex_gate_runs_before_compilation() {
        let mut session = RegexSession::new();
        let outcome = super::decide(
            &url("https://evil.example/"),
            &url("https://example.com/"),
            MatchMode::Regex,
            MatchMode::BaseDomain,
            &no_equivalence(),
            Some("("),
            &mut session,
        );
        assert_eq!(outcome, MatchOutcome::NoMatch);
        assert_eq!(session.evaluations(), 0);
        assert_eq!(
            decide_regex("https://example.com/", "https://example.com/", "("),
            MatchOutcome::InvalidPattern
        );
    }

    /// ADR 0097 §6 step 3: the HTTPS→HTTP rule applies to *Regex* too.
    #[test]
    fn regex_obeys_the_https_downgrade_rule() {
        assert_eq!(
            decide_regex("http://example.com/", "https://example.com/", ".*"),
            MatchOutcome::NoMatch
        );
    }

    /// ADR 0097 §6 step 3: equivalence groups widen the gate for *Regex* as for every mode.
    #[test]
    fn regex_matches_through_an_equivalence_group() {
        let group = EquivalenceGroup::new(
            GroupId::from_bytes([1; 16]),
            ["youtube.com", "youtu.be"],
            false,
        )
        .unwrap();
        let global = vec![group];
        let disabled = BTreeSet::new();
        let user = vec![];
        let view = EquivalenceView::new(&global, &disabled, &user);
        let outcome = super::decide(
            &url("https://youtu.be/x"),
            &url("https://youtube.com/"),
            MatchMode::Regex,
            MatchMode::BaseDomain,
            &view,
            Some(r"^https://youtu\.be/"),
            &mut RegexSession::new(),
        );
        assert!(matches!(
            outcome,
            MatchOutcome::Match(MatchedVia::Equivalence(_))
        ));
    }

    /// ADR 0097 §6 step 3: limits, refusals and case.
    #[test]
    fn regex_limits_and_case() {
        let page = "https://example.com/";
        let ok = format!("(?-i){}", "a".repeat(crate::error::MAX_PATTERN_LEN - 5));
        assert_eq!(ok.len(), crate::error::MAX_PATTERN_LEN);
        assert_eq!(decide_regex(page, page, &ok), MatchOutcome::NoMatch);
        let long = "a".repeat(crate::error::MAX_PATTERN_LEN + 1);
        assert_eq!(
            decide_regex(page, page, &long),
            MatchOutcome::InvalidPattern
        );
        let nested = format!("{}a{}", "(".repeat(40), ")".repeat(40));
        for invalid in [
            "",
            "caf\u{e9}",
            r"\p{L}",
            r"a(?=b)",
            r"(a)\1",
            "[a-z]{5000}",
            nested.as_str(),
        ] {
            assert_eq!(
                decide_regex(page, page, invalid),
                MatchOutcome::InvalidPattern,
                "{invalid}"
            );
        }
        assert_eq!(
            decide_regex(page, page, r"^HTTPS://EXAMPLE\.COM/"),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
        assert_eq!(
            decide_regex(page, page, r"(?-i)^HTTPS://"),
            MatchOutcome::NoMatch
        );
        // An absent pattern never matches (ADR 0097 §3.1).
        let absent = super::decide(
            &url(page),
            &url(page),
            MatchMode::Regex,
            MatchMode::BaseDomain,
            &no_equivalence(),
            None,
            &mut RegexSession::new(),
        );
        assert_eq!(absent, MatchOutcome::InvalidPattern);
    }

    /// ADR 0097 §6 step 3: a page URL over 4,096 bytes is `NoMatch`, never compiled.
    #[test]
    fn regex_oversize_haystack_is_no_match() {
        // Under MAX_URL_LEN as typed; over it once each `é` is percent-encoded.
        let page = format!("https://example.com/{}", "\u{e9}".repeat(1_400));
        let page = NormalizedUrl::parse(&page).unwrap();
        assert!(page.normalized_string().len() > crate::error::MAX_URL_LEN);
        let mut session = RegexSession::new();
        let outcome = super::decide(
            &page,
            &url("https://example.com/"),
            MatchMode::Regex,
            MatchMode::BaseDomain,
            &no_equivalence(),
            Some(".*"),
            &mut session,
        );
        assert_eq!(outcome, MatchOutcome::NoMatch);
        assert_eq!(session.evaluations(), 0);
    }

    /// ADR 0097 §3.1: an account default of *Regex* applies the URI's own pattern.
    #[test]
    fn regex_account_default_uses_the_uri_pattern() {
        let outcome = super::decide(
            &url("https://example.com/login"),
            &url("https://example.com/"),
            MatchMode::AccountDefault,
            MatchMode::Regex,
            &no_equivalence(),
            Some("/login$"),
            &mut RegexSession::new(),
        );
        assert_eq!(outcome, MatchOutcome::Match(MatchedVia::RegistrableDomain));
    }

    proptest::proptest! {
        /// ADR 0097 §6 step 3, property: `decide` never panics on an arbitrary pattern and
        /// page, and a *Regex* `Match` implies both gates passed.
        #[test]
        fn regex_never_panics_and_a_match_implies_the_gate(
            pattern in proptest::prop_oneof![
                proptest::string::string_regex(r"[\^$.*+?()\[\]{}|a-z0-9\\/:=-]{0,48}").unwrap(),
                proptest::prelude::any::<String>(),
            ],
            page in r"https?://(a|b|example)\.(com|co\.uk|github\.io)(:[0-9]{1,4})?/[ -~]{0,40}",
            value in r"https?://(a|b|example)\.(com|co\.uk|github\.io)/[a-z]{0,8}",
        ) {
            let (Ok(page), Ok(value)) = (NormalizedUrl::parse(&page), NormalizedUrl::parse(&value))
            else {
                return Ok(());
            };
            let mut session = RegexSession::new();
            let outcome = super::decide(
                &page,
                &value,
                MatchMode::Regex,
                MatchMode::BaseDomain,
                &no_equivalence(),
                Some(&pattern),
                &mut session,
            );
            if outcome != MatchOutcome::NoMatch {
                proptest::prop_assert!(page.registrable_domain().is_some());
                proptest::prop_assert_eq!(page.registrable_domain(), value.registrable_domain());
                proptest::prop_assert!(!https_downgrade_blocks(value.scheme(), page.scheme()));
            }
            if matches!(outcome, MatchOutcome::Match(_)) {
                proptest::prop_assert!(crate::pattern::compile(&pattern)
                    .is_ok_and(|p| p.is_match(&page.normalized_string())));
            }
        }
    }

    /// ADR 0097 §3.4: the 33rd gated *Regex* URI of one session is over budget.
    #[test]
    fn regex_budget_is_per_session() {
        let mut session = RegexSession::new();
        let page = url("https://example.com/");
        for _ in 0..crate::error::MAX_REGEX_EVALUATIONS {
            let outcome = super::decide(
                &page,
                &page,
                MatchMode::Regex,
                MatchMode::BaseDomain,
                &no_equivalence(),
                Some("example"),
                &mut session,
            );
            assert_eq!(outcome, MatchOutcome::Match(MatchedVia::RegistrableDomain));
        }
        let outcome = super::decide(
            &page,
            &page,
            MatchMode::Regex,
            MatchMode::BaseDomain,
            &no_equivalence(),
            Some("example"),
            &mut session,
        );
        assert_eq!(outcome, MatchOutcome::RegexBudgetExceeded);
    }

    /// ADR 0097 §2: dot segments are resolved before comparing, on both sides.
    #[test]
    fn exact_compares_after_dot_segments_are_resolved_adr0097() {
        assert_eq!(
            decide_plain(
                "https://example.com/a/../login",
                "https://example.com/login",
                MatchMode::Exact
            ),
            MatchOutcome::Match(MatchedVia::RegistrableDomain)
        );
        // Existing escapes are kept as written: no decoding and no case change.
        assert_eq!(
            decide_plain(
                "https://example.com/%7elogin",
                "https://example.com/%7Elogin",
                MatchMode::Exact
            ),
            MatchOutcome::NoMatch
        );
    }
}
