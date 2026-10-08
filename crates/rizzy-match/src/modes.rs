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
    /// `0x0005`: not implemented by this build (see [`EffectiveMode::Regex`]).
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
    /// Path-prefix of the full normalised URL.
    StartsWith,
    /// Byte-equal full normalised URL.
    Exact,
    /// No regex crate is named by ADR 0037; this build implements
    /// Never/Exact/Host/`StartsWith`/`BaseDomain` only. [`decide`] returns
    /// [`MatchOutcome::NotSupported`] unconditionally for this mode, so a caller can tell "not
    /// implemented" apart from "checked, does not match" (ADR 0037 §4 row `0x0005`).
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

/// The result of [`decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MatchOutcome {
    /// A candidate, and why it matched.
    Match(MatchedVia),
    /// Checked; does not match (including *Never* and the HTTPS→HTTP rule).
    NoMatch,
    /// *Regex* mode: this build cannot evaluate it (ADR 0037 §4 row `0x0005`).
    NotSupported,
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
/// Order, deliberately, so a future mode cannot widen past either rule: *Regex* is reported
/// [`MatchOutcome::NotSupported`] before anything else (this build cannot evaluate it at all);
/// then *Never* and the HTTPS→HTTP rule, both unconditional; only then the registrable-domain
/// gate, which every remaining mode must pass before its own rule runs.
#[must_use]
pub fn decide(
    page: &NormalizedUrl,
    uri: &NormalizedUrl,
    mode: MatchMode,
    account_default: MatchMode,
    equivalence: &EquivalenceView<'_>,
) -> MatchOutcome {
    let effective = mode.resolve(account_default);
    if effective == EffectiveMode::Regex {
        return MatchOutcome::NotSupported;
    }
    if effective == EffectiveMode::Never {
        return MatchOutcome::NoMatch;
    }
    if https_downgrade_blocks(uri.scheme(), page.scheme()) {
        return MatchOutcome::NoMatch;
    }
    let Some(matched_via) = registrable_gate(page, uri, equivalence) else {
        return MatchOutcome::NoMatch;
    };
    let passes_mode_rule = match effective {
        EffectiveMode::BaseDomain => true,
        EffectiveMode::Host => page.host() == uri.host(),
        EffectiveMode::StartsWith => page
            .normalized_string()
            .starts_with(&uri.normalized_string()),
        EffectiveMode::Exact => page.normalized_string() == uri.normalized_string(),
        EffectiveMode::Regex | EffectiveMode::Never => unreachable!("handled above"),
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

    #[test]
    fn regex_is_not_supported() {
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
            MatchOutcome::NotSupported
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
}
