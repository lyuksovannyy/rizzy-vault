// SPDX-License-Identifier: AGPL-3.0-only

//! The independent oracle and case generator for `adr0037_differential.rs`'s value layer (see
//! that file's module docs for the scope boundary: ASCII/A-label hosts only, no punycode
//! encoder, the `psl` crate used directly for public-suffix lookup only).
//!
//! Every decision in [`decide`] is re-derived from ADR 0037 §2, §4, §5 and INV-36 to INV-39's
//! text, not from `rizzy-match`'s own `normalize.rs`/`modes.rs`/`security.rs`. The one exception
//! both this oracle and the implementation must make is the single-label and IP-literal
//! registrable-domain carve-out: INV-38's own purpose (stopping a *shared-suffix* collision
//! between unrelated tenants) does not apply to a dotless host or a literal IP address, since
//! neither can ever be "the same suffix as someone else's registrable domain" the way
//! `co.uk`/`other.co.uk` can. [`registrable_domain_of_named`]'s doc comment below spells out
//! that reasoning independently, rather than citing `normalize.rs`'s own comment for it.

use std::collections::BTreeSet;

use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use rizzy_match::MatchMode;

// ---------------------------------------------------------------------------------------------
// The generated shape.
// ---------------------------------------------------------------------------------------------

/// A generated host: either domain labels (always ASCII in the combinatorial generator — see
/// `adr0037_differential.rs`'s `relational` module for genuine Unicode/IDN coverage) or an IPv4
/// literal in plain dotted-decimal form (alternate notations are covered separately too, in
/// `relational::ipv4_notations_of_the_same_address_agree_when_both_parse`, since comparing them
/// needs no oracle math at all — just two calls to the real implementation).
#[derive(Clone, Debug)]
pub(crate) enum GenHost {
    Domain {
        labels: Vec<String>,
        /// A trailing run of 0..=3 dots on the rendered host (mirrors
        /// `rizzy_match::normalize`'s own `registrable_domain_is_invariant_under_trailing_dot_runs`
        /// and `normalize_domain_output_is_idempotent` proptests): a plain `bool` could only
        /// ever render zero or one dot, so this generator could never have reached the
        /// two-or-more shape the ADR 0037 trailing-dot-run fix exists for.
        trailing_dot_count: usize,
        upper_mask: u8,
    },
    /// The fourth field is the same trailing-dot-run count as [`GenHost::Domain`]'s: without it,
    /// this generator could never reach an IP-literal host with 2+ trailing dots — exactly the
    /// shape `rizzy_match::normalize`'s `ip_literal_registrable_domain_does_not_collide_across_trailing_dot_runs`
    /// regression test pins at the unit level, but this independent-oracle layer would stay
    /// blind to on its own.
    Ipv4(u8, u8, u8, u8, usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SchemeKind {
    Http,
    Https,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PortKind {
    Omitted,
    ExplicitDefaultForScheme,
    ExplicitOtherSchemeDefault,
    Custom(u16),
}

#[derive(Clone, Debug)]
pub(crate) struct GenUrl {
    pub scheme: SchemeKind,
    pub host: GenHost,
    pub port: PortKind,
    pub userinfo: Option<(String, String)>,
    pub path: String,
}

#[derive(Clone, Debug)]
pub(crate) struct EquivGroupSpec {
    pub is_global: bool,
    pub disabled: bool,
    pub domains: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Case {
    pub page: GenUrl,
    pub uri: GenUrl,
    pub mode: MatchMode,
    pub account_default: MatchMode,
    pub groups: Vec<EquivGroupSpec>,
}

// ---------------------------------------------------------------------------------------------
// The oracle's own decision, independent of `rizzy_match::decide`.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    NoMatch,
    /// ADR 0037 §4 row `0x0005`: this build does not evaluate *Regex* at all (no regex crate is
    /// named by the ADR); see `adr0037_differential.rs`'s module docs for why the oracle takes
    /// this as given rather than independently re-deriving it.
    NotSupported,
    /// A match whose gate passed by plain registrable-domain equality.
    MatchExact,
    /// A match whose gate passed only through an equivalence group (ADR 0037 §5's warning case).
    MatchEquivalence,
}

#[derive(Clone, Debug)]
pub(crate) struct PerUrl {
    pub registrable_domain: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Outcome {
    pub decision: Decision,
    pub page_oracle: PerUrl,
    pub uri_oracle: PerUrl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Effective {
    BaseDomain,
    Host,
    StartsWith,
    Exact,
    Regex,
    Never,
}

/// ADR 0037 §6: `AccountDefault` resolves against the account's own default, itself defaulting
/// to *Base domain* if never set — mirrors `MatchMode::resolve`'s documented contract exactly,
/// independently re-derived from the same ADR text rather than calling it.
fn resolve(mode: MatchMode, account_default: MatchMode) -> Effective {
    let m = if mode == MatchMode::AccountDefault {
        account_default
    } else {
        mode
    };
    match m {
        MatchMode::AccountDefault | MatchMode::BaseDomain => Effective::BaseDomain,
        MatchMode::Host => Effective::Host,
        MatchMode::StartsWith => Effective::StartsWith,
        MatchMode::Exact => Effective::Exact,
        MatchMode::Regex => Effective::Regex,
        MatchMode::Never => Effective::Never,
    }
}

/// ADR 0037 §2 point 7; §4; INV-38. The registrable domain of a *named* (non-IP) host, via the
/// `psl` crate directly (the one crate this oracle shares with the implementation, for
/// public-suffix lookup only — never for the surrounding decision).
///
/// A host with no PSL-registrable domain and containing no dot at all (`localhost`, an internal
/// hostname) has no shared-suffix collision risk — INV-38's registrable-domain gate exists to
/// stop two *different* tenants of the same suffix (`tenant.co.uk`, `other.co.uk`) from being
/// treated as the same login; a dotless host has no suffix for another tenant to share — so it
/// is its own registrable domain. A bare *multi-label* public suffix (`co.uk`, `github.io`)
/// stays without one: INV-38 names exactly this case ("a bare public suffix... must not be
/// treated as matching... another occurrence of the same bare suffix").
fn registrable_domain_of_named(host: &str) -> Option<String> {
    if let Some(d) = psl::domain_str(host) {
        return Some(d.to_owned());
    }
    if host.contains('.') {
        None
    } else {
        Some(host.to_owned())
    }
}

/// The normalised host string and registrable domain of a generated host, independent of
/// `NormalizedUrl`. An IP literal is its own registrable domain (ADR 0037 §2's note on the
/// `psl`-on-an-IP collision risk; the same reasoning `registrable_domain_of_named`'s doc comment
/// gives for a dotless host applies even more directly to an IP literal, which can never be a
/// multi-tenant suffix at all).
fn host_and_domain(host: &GenHost) -> (String, Option<String>) {
    match host {
        GenHost::Domain { labels, .. } => {
            let norm = labels.join(".");
            let domain = registrable_domain_of_named(&norm);
            (norm, domain)
        }
        GenHost::Ipv4(a, b, c, d, _) => {
            let norm = format!("{a}.{b}.{c}.{d}");
            (norm.clone(), Some(norm))
        }
    }
}

/// ADR 0037 §2 point 5: the default port for the scheme is omitted; any other port is kept.
fn port_norm(scheme: SchemeKind, port: PortKind) -> Option<u16> {
    let default = match scheme {
        SchemeKind::Http => 80,
        SchemeKind::Https => 443,
    };
    let raw = match port {
        PortKind::Omitted => return None,
        PortKind::ExplicitDefaultForScheme => default,
        PortKind::ExplicitOtherSchemeDefault => match scheme {
            SchemeKind::Http => 443,
            SchemeKind::Https => 80,
        },
        PortKind::Custom(p) => p,
    };
    if raw == default { None } else { Some(raw) }
}

/// ADR 0037 §2 point 6: `scheme://host[:port]path`, query and fragment always dropped, empty
/// path defaulting to `/`.
fn normalized_string(host_norm: &str, scheme: SchemeKind, port: Option<u16>, path: &str) -> String {
    let scheme_s = match scheme {
        SchemeKind::Http => "http",
        SchemeKind::Https => "https",
    };
    let path = if path.is_empty() { "/" } else { path };
    match port {
        Some(p) => format!("{scheme_s}://{host_norm}:{p}{path}"),
        None => format!("{scheme_s}://{host_norm}{path}"),
    }
}

/// ADR 0037 §5; INV-37: a URI saved as `https://…` is never offered against a plain `http://`
/// page.
fn https_downgrade_blocks(uri_scheme: SchemeKind, page_scheme: SchemeKind) -> bool {
    matches!(
        (uri_scheme, page_scheme),
        (SchemeKind::Https, SchemeKind::Http)
    )
}

struct GroupData {
    active: bool,
    domains: BTreeSet<String>,
}

/// ADR 0037 §6–§7; ADR 0038 §5: every global group not disabled by the account, plus every
/// user-defined group — but first, ADR 0038 §1's own construction rule: two or more domains,
/// and "two domains normalise to the same value" is a hard error for the *whole* group, not a
/// silent collapse to fewer members (`EquivalenceGroup::new`'s doc comment states this
/// explicitly: "a duplicate after normalisation is an error, not a silent drop"). A spec whose
/// domains collide below two distinct members is therefore not a one-member or deduplicated
/// group; it is no group at all, exactly as `rizzy-match`'s own constructor would refuse to
/// build it.
fn active_groups(specs: &[EquivGroupSpec]) -> Vec<GroupData> {
    specs
        .iter()
        .filter_map(|s| {
            let mut domains = s.domains.clone();
            let supplied_len = domains.len();
            domains.sort();
            domains.dedup();
            if domains.len() != supplied_len || domains.len() < 2 {
                return None;
            }
            Some(GroupData {
                active: !(s.is_global && s.disabled),
                domains: domains.into_iter().collect(),
            })
        })
        .collect()
}

fn same_group(groups: &[GroupData], a: &str, b: &str) -> bool {
    groups
        .iter()
        .any(|g| g.active && g.domains.contains(a) && g.domains.contains(b))
}

/// The oracle's decision for one [`Case`], independent of `rizzy_match::decide`.
pub(crate) fn decide(case: &Case) -> Outcome {
    let (page_host, page_domain) = host_and_domain(&case.page.host);
    let (uri_host, uri_domain) = host_and_domain(&case.uri.host);
    let page_port = port_norm(case.page.scheme, case.page.port);
    let uri_port = port_norm(case.uri.scheme, case.uri.port);
    let page_str = normalized_string(&page_host, case.page.scheme, page_port, &case.page.path);
    let uri_str = normalized_string(&uri_host, case.uri.scheme, uri_port, &case.uri.path);

    let page_oracle = PerUrl {
        registrable_domain: page_domain.clone(),
    };
    let uri_oracle = PerUrl {
        registrable_domain: uri_domain.clone(),
    };

    let effective = resolve(case.mode, case.account_default);

    let outcome = if effective == Effective::Regex {
        Decision::NotSupported
    } else if effective == Effective::Never
        || https_downgrade_blocks(case.uri.scheme, case.page.scheme)
    {
        Decision::NoMatch
    } else {
        let groups = active_groups(&case.groups);
        let gate = match (&page_domain, &uri_domain) {
            (Some(p), Some(u)) if p == u => Some(false),
            (Some(p), Some(u)) if same_group(&groups, p, u) => Some(true),
            _ => None,
        };
        match gate {
            None => Decision::NoMatch,
            Some(via_equivalence) => {
                let mode_ok = match effective {
                    Effective::BaseDomain => true,
                    Effective::Host => page_host == uri_host && page_port == uri_port,
                    Effective::StartsWith => page_str.starts_with(&uri_str),
                    Effective::Exact => page_str == uri_str,
                    Effective::Regex | Effective::Never => {
                        unreachable!("handled above")
                    }
                };
                match (mode_ok, via_equivalence) {
                    (true, false) => Decision::MatchExact,
                    (true, true) => Decision::MatchEquivalence,
                    (false, _) => Decision::NoMatch,
                }
            }
        }
    };

    Outcome {
        decision: outcome,
        page_oracle,
        uri_oracle,
    }
}

// ---------------------------------------------------------------------------------------------
// The generator.
// ---------------------------------------------------------------------------------------------

/// A small, shared label pool: plain words and real PSL fragments (`co`, `uk`, `github`, `io`,
/// `amazonaws`), so the combinatorial generator naturally builds both ordinary domains and
/// ICANN/private bare-suffix and multi-level-suffix shapes (ADR 0037 §3; §2 point 7's own
/// example, `a.b.example.co.uk`).
const LABELS: &[&str] = &[
    "example",
    "bank",
    "accounts",
    "evil",
    "login",
    "shop",
    "checkout",
    "pay",
    "sub",
    "mail",
    "com",
    "net",
    "org",
    "co",
    "uk",
    "io",
    "github",
    "amazonaws",
    "app",
    "de",
];

fn label_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(LABELS).prop_map(str::to_owned)
}

fn domain_host_strategy() -> impl Strategy<Value = GenHost> {
    (
        prop::collection::vec(label_strategy(), 1..=4),
        0usize..=3,
        any::<u8>(),
    )
        .prop_map(|(labels, trailing_dot_count, upper_mask)| GenHost::Domain {
            labels,
            trailing_dot_count,
            upper_mask,
        })
}

fn ipv4_host_strategy() -> impl Strategy<Value = GenHost> {
    (
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        0usize..=3,
    )
        .prop_map(|(a, b, c, d, trailing_dot_count)| GenHost::Ipv4(a, b, c, d, trailing_dot_count))
}

fn host_strategy() -> impl Strategy<Value = GenHost> {
    prop_oneof![4 => domain_host_strategy(), 1 => ipv4_host_strategy()]
}

fn scheme_strategy() -> impl Strategy<Value = SchemeKind> {
    prop_oneof![Just(SchemeKind::Http), Just(SchemeKind::Https)]
}

fn port_strategy() -> impl Strategy<Value = PortKind> {
    prop_oneof![
        3 => Just(PortKind::Omitted),
        1 => Just(PortKind::ExplicitDefaultForScheme),
        1 => Just(PortKind::ExplicitOtherSchemeDefault),
        2 => (1u16..=65535).prop_map(PortKind::Custom),
    ]
}

fn userinfo_strategy() -> impl Strategy<Value = Option<(String, String)>> {
    prop_oneof![
        3 => Just(None),
        1 => Just(Some(("user".to_owned(), "pass".to_owned()))),
    ]
}

const PATHS: &[&str] = &[
    "",
    "/",
    "/login",
    "/account",
    "/account/settings",
    "/account/settings/x",
    "/a/b/c",
];

fn path_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(PATHS).prop_map(str::to_owned)
}

fn gen_url_strategy() -> impl Strategy<Value = GenUrl> {
    (
        scheme_strategy(),
        host_strategy(),
        port_strategy(),
        userinfo_strategy(),
        path_strategy(),
    )
        .prop_map(|(scheme, host, port, userinfo, path)| GenUrl {
            scheme,
            host,
            port,
            userinfo,
            path,
        })
}

fn mode_strategy() -> impl Strategy<Value = MatchMode> {
    prop_oneof![
        Just(MatchMode::AccountDefault),
        Just(MatchMode::BaseDomain),
        Just(MatchMode::Host),
        Just(MatchMode::StartsWith),
        Just(MatchMode::Exact),
        Just(MatchMode::Regex),
        Just(MatchMode::Never),
    ]
}

fn account_default_strategy() -> impl Strategy<Value = MatchMode> {
    prop_oneof![
        Just(MatchMode::BaseDomain),
        Just(MatchMode::Host),
        Just(MatchMode::StartsWith),
        Just(MatchMode::Exact),
        Just(MatchMode::Never),
    ]
}

/// Equivalence-group domains are drawn from the same label pool as hosts, 1..=3 labels, so a
/// meaningful fraction of generated groups actually name a page's or a URI's registrable domain
/// (`the_generator_reaches_every_decision_kind` checks this isn't vacuous).
fn equiv_domain_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(label_strategy(), 1..=3).prop_map(|labels| labels.join("."))
}

fn equiv_group_spec_strategy() -> impl Strategy<Value = EquivGroupSpec> {
    (
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(equiv_domain_strategy(), 2..=3),
    )
        .prop_map(|(is_global, disabled, domains)| EquivGroupSpec {
            is_global,
            disabled,
            domains,
        })
}

/// Groups biased toward actually naming the page's and the URI's own registrable domains: with
/// unbiased-random domain strings alone, the chance that an independently drawn group happens to
/// contain *both* a case's page and URI registrable domain (while they differ) is low enough
/// that `MatchEquivalence` was never reached in 6000 draws. When both domains exist and differ,
/// one branch always builds a group naming exactly the two of them (plus, sometimes, one more
/// independent domain), so the equivalence path is exercised at a predictable rate; the other
/// branch keeps the original fully independent generation, so ordinary non-matching groups are
/// still covered too.
fn groups_strategy(
    page_domain: Option<String>,
    uri_domain: Option<String>,
) -> BoxedStrategy<Vec<EquivGroupSpec>> {
    let independent = || prop::collection::vec(equiv_group_spec_strategy(), 0..=2);
    match (page_domain, uri_domain) {
        (Some(p), Some(u)) if p != u => {
            let biased = (any::<bool>(), any::<bool>()).prop_map(move |(is_global, disabled)| {
                EquivGroupSpec {
                    is_global,
                    disabled,
                    domains: vec![p.clone(), u.clone()],
                }
            });
            prop_oneof![
                3 => independent(),
                2 => (biased, prop::collection::vec(equiv_group_spec_strategy(), 0..=1))
                    .prop_map(|(b, mut rest)| {
                        rest.push(b);
                        rest
                    }),
            ]
            .boxed()
        }
        _ => independent().boxed(),
    }
}

/// The top-level case strategy `adr0037_differential.rs` runs its batches over.
pub(crate) fn case_strategy() -> impl Strategy<Value = Case> {
    (
        gen_url_strategy(),
        gen_url_strategy(),
        mode_strategy(),
        account_default_strategy(),
    )
        .prop_flat_map(|(page, uri, mode, account_default)| {
            let (_, page_domain) = host_and_domain(&page.host);
            let (_, uri_domain) = host_and_domain(&uri.host);
            groups_strategy(page_domain, uri_domain).prop_map(move |groups| Case {
                page: page.clone(),
                uri: uri.clone(),
                mode,
                account_default,
                groups,
            })
        })
}

#[cfg(test)]
mod reach {
    use std::collections::BTreeSet;

    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::{Config, TestRunner};

    use super::{
        Decision, GenHost, case_strategy, decide, host_and_domain, normalized_string, port_norm,
    };

    /// What `cases` draws of the generator reached, beyond the four [`Decision`] kinds: the
    /// specific attack shapes ADR 0037 and this harness's write-up name. A generator that
    /// reaches `NoMatch` overwhelmingly because most random label pairs simply differ (the
    /// trivial case) would make a "no violations in N cases" headline claim mean far less than
    /// it looks like; these counters measure whether it also reaches the shapes that matter.
    #[derive(Default, Debug)]
    struct Reach {
        decision_kinds: BTreeSet<&'static str>,
        /// `uri`'s host labels are a strict, label-respecting prefix of `page`'s (the
        /// `bank.com` / `bank.com.evil.example` shape ADR 0037 §4 names), with the two sides'
        /// registrable domains differing — the one case the registrable-domain gate exists for.
        prefix_shape: u64,
        /// Either side's registrable domain is `None` (a bare public suffix reached).
        bare_suffix: u64,
        /// A disabled *global* group whose members would otherwise have bridged the two sides
        /// (ADR 0037 §6: a disabled global group must not re-widen a match).
        disabled_group_would_have_matched: u64,
        /// `page`'s full normalised string is a byte-prefix of `uri`'s... no — the other way:
        /// `page`'s normalised string starts with `uri`'s, while the two sides' registrable
        /// domains differ. Measured, not just asserted in a doc comment: this must stay zero,
        /// and is only meaningful because `prefix_shape` above is reached at all.
        starts_with_byte_prefix_despite_different_domain: u64,
    }

    fn reach(cases: u32) -> Reach {
        let mut r = Reach::default();
        let mut runner = TestRunner::new(Config {
            cases,
            ..Config::default()
        });
        let strategy = case_strategy();
        for _ in 0..cases {
            let Ok(tree) = strategy.new_tree(&mut runner) else {
                continue;
            };
            let case = tree.current();
            let outcome = decide(&case);
            r.decision_kinds.insert(match outcome.decision {
                Decision::NoMatch => "NoMatch",
                Decision::NotSupported => "NotSupported",
                Decision::MatchExact => "MatchExact",
                Decision::MatchEquivalence => "MatchEquivalence",
            });

            let (page_host, page_domain) = host_and_domain(&case.page.host);
            let (uri_host, uri_domain) = host_and_domain(&case.uri.host);

            if let (
                GenHost::Domain {
                    labels: page_labels,
                    ..
                },
                GenHost::Domain {
                    labels: uri_labels, ..
                },
            ) = (&case.page.host, &case.uri.host)
                && uri_labels.len() < page_labels.len()
                && page_labels[..uri_labels.len()] == uri_labels[..]
                && page_domain != uri_domain
            {
                r.prefix_shape += 1;
            }
            if page_domain.is_none() || uri_domain.is_none() {
                r.bare_suffix += 1;
            }
            if page_domain.as_deref() != uri_domain.as_deref()
                && let (Some(p), Some(u)) = (&page_domain, &uri_domain)
                && case.groups.iter().any(|g| {
                    g.is_global && g.disabled && g.domains.contains(p) && g.domains.contains(u)
                })
            {
                r.disabled_group_would_have_matched += 1;
            }
            let page_port = port_norm(case.page.scheme, case.page.port);
            let uri_port = port_norm(case.uri.scheme, case.uri.port);
            let page_str =
                normalized_string(&page_host, case.page.scheme, page_port, &case.page.path);
            let uri_str = normalized_string(&uri_host, case.uri.scheme, uri_port, &case.uri.path);
            if page_str.starts_with(&uri_str) && page_domain != uri_domain {
                r.starts_with_byte_prefix_despite_different_domain += 1;
            }
        }
        r
    }

    /// A generator that silently stopped reaching one decision kind, or one of the named
    /// attack/edge shapes, would make the differential property vacuous there (mirrors
    /// `crates/rizzy-sync/src/convergence/generate.rs`'s `the_families_reach_their_rules`).
    #[test]
    fn the_generator_reaches_every_decision_kind_and_attack_shape() {
        let r = reach(10_000);
        for kind in ["NoMatch", "NotSupported", "MatchExact", "MatchEquivalence"] {
            assert!(
                r.decision_kinds.contains(kind),
                "the generator never produced {kind:?} in 10000 draws: {r:?}"
            );
        }
        assert!(
            r.prefix_shape > 0,
            "the bank.com / bank.com.evil.example shape was never reached: {r:?}"
        );
        assert!(
            r.bare_suffix > 0,
            "a bare-public-suffix side was never reached: {r:?}"
        );
        assert!(
            r.disabled_group_would_have_matched > 0,
            "a disabled global group that would otherwise have bridged the two sides was never \
             reached: {r:?}"
        );
        // Measured, not assumed: given the prefix shape above is reached at all, a byte-level
        // `starts_with` of the full normalised strings never crosses a registrable-domain
        // boundary, because `normalized_string`'s path always defaults to a non-empty `/`
        // (module docs; this is the fact `mutants::mutant_no_gate_at_all` is demonstrated under
        // *Base domain* rather than *Starts with* for).
        assert_eq!(
            r.starts_with_byte_prefix_despite_different_domain, 0,
            "a byte-prefix match crossed a registrable-domain boundary: {r:?}"
        );
    }
}
