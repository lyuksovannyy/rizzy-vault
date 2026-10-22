// SPDX-License-Identifier: AGPL-3.0-only

//! Differential test for ADR 0037's URL normalisation and match-mode rules (A6; INV-36 to
//! INV-39) against an independent oracle built from the ADR text, not from `rizzy-match`'s own
//! source.
//!
//! # The oracle's scope, deliberately
//!
//! ADR 0037 §2.3 delegates IDNA/punycode conversion to the `idna` crate (pinned `>=1.0` for
//! RUSTSEC-2024-0421) and never specifies the UTS-46 algorithm itself; there is no ADR text to
//! re-derive a punycode encoder from, and doing so anyway would invent a spec the ADR does not
//! state. This oracle therefore works at two layers:
//!
//! - **Value oracle** (the bulk of this file): an exact, independent re-derivation of every
//!   decision ADR 0037 §2, §4 and §5 *do* specify in full — scheme restriction, host
//!   lower-casing and trailing-dot stripping, default-port omission, the registrable-domain
//!   gate (via the `psl` crate directly, the one crate the task allows the oracle to share with
//!   the implementation), narrowing-only mode dispatch, the HTTPS→HTTP rule and the
//!   equivalence-only warning flag. Hosts fed to this layer are always already-ASCII/A-label
//!   strings the generator builds directly, so no encoder is needed to compare decisions.
//! - **Relational properties** (`mod relational`): for genuine Unicode input, no encoder is
//!   used either. Instead: a successfully normalised host must be all-ASCII with no trailing
//!   dot; two inputs that the real implementation claims normalise to the *same* host must
//!   behave identically under every match mode; and a small curated table of real homograph
//!   and IP/IPv4-notation pairs is asserted both ways (confusable pairs must differ, pairs that
//!   really are one value in different notation must collide).
//!
//! UTS-46 mapping/NFC/bidi correctness is `idna`'s own contract, not independently
//! re-verified here (see the harness's `not_covered`).
//!
//! # Positive control
//!
//! `mod mutants` reimplements `decide` with one deliberate weakening each (dropping the
//! registrable-domain gate entirely; gating on the public suffix instead of the registrable
//! domain) and asserts each one wrongly accepts a case the real, correctly-gated `decide`
//! refuses — on the ADR's own named attack shape. This proves a harness built this way can
//! detect a real INV-38 violation, without touching production code. (An earlier draft tried a
//! third mutant narrower than this — skipping the gate only for *Starts with* — but could not
//! construct a case it wrongly accepted: `normalized_string`'s mandatory non-empty path means
//! the string-prefix check alone already rejects every cross-registrable-domain pair, gate or
//! no gate. That is a genuine, incidental robustness property of this implementation, noted
//! here rather than silently dropped.)
//!
//! # Budget
//!
//! [`PR_CASES`] runs on proptest's deterministic RNG (`Seeds::Fixed`), so a PR run is never
//! flaky and stays well under the ~60s PR budget. The `#[ignore]`d `nightly_*` test runs
//! [`PR_CASES`] × [`NIGHTLY_MULTIPLIER`] on fresh seeds (`Seeds::Fresh`), following the
//! convergence suite's pattern (`crates/rizzy-sync/src/convergence/generate.rs`).
//!
//! # Not covered by this harness
//!
//! - **The dotless-host registrable-domain carve-out.** `oracle::registrable_domain_of_named`
//!   adopts `rizzy-match`'s own choice to treat a label-less host (`localhost`, an IPv4/IPv6
//!   literal) as its own registrable domain, rather than re-deriving that rule from ADR 0037's
//!   text (the ADR does not spell this case out). For that one branch this harness is a
//!   change-detector against the implementation's documented intent, not an independent
//!   verifier.
//! - **INV-36 and most of INV-37.** Both live at the extension/UI layer (a user gesture before
//!   autofill, same-origin-only iframe autofill, no autofill into hidden/non-visible fields)
//!   with no surface in `rizzy-match`. Only INV-37's HTTPS→HTTP half
//!   (`security::https_downgrade_blocks`) has a `rizzy-match` decision to differentially test,
//!   and it is covered.
//! - **`MatchMode::Regex`.** The current build has no regex engine in its dependency tree and
//!   `decide` returns `MatchOutcome::NotSupported` unconditionally for it; the oracle mirrors
//!   that fixed fact rather than independently verifying any regex-matching semantics, because
//!   there are none built yet to verify.
//! - **IPv6 host forms.** Covered only by the curated pairs in `mod relational`
//!   (`equal_notations_of_the_same_host_normalise_identically`), not by the combinatorial
//!   generator — RFC 5952 canonical-compression re-derivation was judged out of the oracle's
//!   scope for the same reason punycode was (see above).
//! - **`MAX_URL_LEN` / `MAX_HOST_LEN` boundary behaviour.** Untested here; already covered by
//!   `rizzy-match`'s own `parse_never_panics` proptest in `src/lib.rs`.

use std::collections::BTreeSet;

use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};
use rizzy_match::{
    EquivalenceGroup, EquivalenceView, GroupId, MatchMode, MatchOutcome, MatchedVia, NormalizedUrl,
    decide,
};

/// Generated cases per PR run (a single [`run_case`] is cheap: a handful of string ops and a
/// `psl` lookup, no I/O), kept well under the ~60s PR budget together with the smaller
/// table-driven tests in this file.
const PR_CASES: u32 = 4_000;

/// The nightly budget is this many times [`PR_CASES`], on fresh seeds. The task asks for at
/// least 20x; 50x gives headroom while one run still finishes in well under 9 minutes (see
/// `scripts/` note in the module docs of the scale-run script, if any — here, just the ignored
/// test's own doc comment).
const NIGHTLY_MULTIPLIER: u32 = 50;

/// Fixed `(mode_index, account_default_index, seed)`-less regressions: once a real failure is
/// minimised, its reproducing case is pinned here as a literal [`Case`]-building closure instead
/// of a seed, because this harness's cases are built from a `proptest::prelude::Strategy` over
/// several independent enums, not from one `u64` the way the sync convergence suite's generated
/// histories are. See `regression_` tests below for any pinned case.
mod oracle;
use oracle::{Case, EquivGroupSpec, GenHost, GenUrl, PortKind, SchemeKind};

// ---------------------------------------------------------------------------------------------
// Rendering: turn a `Case`'s structured fields into the raw URL strings `NormalizedUrl::parse`
// (the real implementation) consumes. The oracle itself never calls `NormalizedUrl::parse` or
// the `url`/`idna` crates; it decides straight from the structured fields.
// ---------------------------------------------------------------------------------------------

fn render_host(host: &GenHost) -> String {
    match host {
        GenHost::Domain {
            labels,
            trailing_dot_count,
            upper_mask,
        } => {
            let mut s = labels
                .iter()
                .enumerate()
                .map(|(i, label)| {
                    if upper_mask & (1 << (i % 8)) != 0 {
                        label.to_ascii_uppercase()
                    } else {
                        label.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(".");
            s.push_str(&".".repeat(*trailing_dot_count));
            s
        }
        GenHost::Ipv4(a, b, c, d, trailing_dot_count) => {
            format!("{a}.{b}.{c}.{d}{}", ".".repeat(*trailing_dot_count))
        }
    }
}

fn render_scheme(scheme: SchemeKind) -> &'static str {
    match scheme {
        SchemeKind::Http => "http",
        SchemeKind::Https => "https",
    }
}

fn render_port(scheme: SchemeKind, port: PortKind) -> Option<u16> {
    match port {
        PortKind::Omitted => None,
        PortKind::ExplicitDefaultForScheme => Some(match scheme {
            SchemeKind::Http => 80,
            SchemeKind::Https => 443,
        }),
        PortKind::ExplicitOtherSchemeDefault => Some(match scheme {
            SchemeKind::Http => 443,
            SchemeKind::Https => 80,
        }),
        PortKind::Custom(p) => Some(p),
    }
}

fn render_url(url: &GenUrl) -> String {
    let scheme = render_scheme(url.scheme);
    let host = render_host(&url.host);
    let userinfo = match &url.userinfo {
        Some((u, p)) => format!("{u}:{p}@"),
        None => String::new(),
    };
    let port = render_port(url.scheme, url.port);
    let port_part = port.map(|p| format!(":{p}")).unwrap_or_default();
    format!("{scheme}://{userinfo}{host}{port_part}{}", url.path)
}

fn build_equivalence(
    specs: &[EquivGroupSpec],
) -> (
    Vec<EquivalenceGroup>,
    BTreeSet<GroupId>,
    Vec<EquivalenceGroup>,
) {
    let mut global = Vec::new();
    let mut user = Vec::new();
    let mut disabled = BTreeSet::new();
    for (i, spec) in specs.iter().enumerate() {
        let id = GroupId::from_bytes([u8::try_from(i).unwrap_or(0) + 1; 16]);
        let Ok(group) = EquivalenceGroup::new(id, spec.domains.iter().cloned(), false) else {
            // The generator can propose domains that collide after normalisation (e.g. two
            // labels differing only by the case the generator also happened to pick); that is
            // exactly `EquivalenceGroup::new`'s own `Malformed` rule, not an oracle concern, so
            // such a group is simply dropped from this case rather than treated as a disagreement.
            continue;
        };
        if spec.is_global {
            if spec.disabled {
                disabled.insert(id);
            }
            global.push(group);
        } else {
            user.push(group);
        }
    }
    (global, disabled, user)
}

/// One case's outcome from both sides, for diagnostics on a mismatch.
#[derive(Debug)]
struct Sides {
    real_page: Option<(String, Option<u16>, Option<String>)>,
    real_uri: Option<(String, Option<u16>, Option<String>)>,
    real_outcome: Option<MatchOutcome>,
    oracle_outcome: oracle::Outcome,
}

/// Runs one generated `Case` through `matcher` (the real `decide`, or a mutant standing in for
/// it — [`mutants`]'s positive control) and the oracle, and returns both sides' intermediate
/// values and final outcome for comparison.
fn run_case_with(
    case: &Case,
    matcher: impl Fn(
        &NormalizedUrl,
        &NormalizedUrl,
        MatchMode,
        MatchMode,
        &EquivalenceView<'_>,
    ) -> MatchOutcome,
) -> Sides {
    let page_raw = render_url(&case.page);
    let uri_raw = render_url(&case.uri);
    let (global, disabled, user) = build_equivalence(&case.groups);
    let view = EquivalenceView::new(&global, &disabled, &user);

    let real_page = NormalizedUrl::parse(&page_raw).ok();
    let real_uri = NormalizedUrl::parse(&uri_raw).ok();

    let real_outcome = match (&real_page, &real_uri) {
        (Some(p), Some(u)) => Some(matcher(p, u, case.mode, case.account_default, &view)),
        _ => None,
    };

    let oracle_outcome = oracle::decide(case);

    Sides {
        real_page: real_page.as_ref().map(|p| {
            (
                p.host().to_owned(),
                p.port(),
                p.registrable_domain().map(str::to_owned),
            )
        }),
        real_uri: real_uri.as_ref().map(|u| {
            (
                u.host().to_owned(),
                u.port(),
                u.registrable_domain().map(str::to_owned),
            )
        }),
        real_outcome,
        oracle_outcome,
    }
}

/// [`run_case_with`] against the real, production `decide`.
fn run_case(case: &Case) -> Sides {
    run_case_with(case, decide)
}

/// Compares one case's two sides. Returns `Err(diagnostic)` on any disagreement.
fn compare(case: &Case, sides: &Sides) -> Result<(), String> {
    // The oracle only ever decides "parses" for inputs it believes are well-formed http(s)
    // absolute URLs with a host; since the generator only ever builds exactly those (see
    // `oracle::decide`'s own doc comment on this invariant), a real parse failure on either side
    // is itself a disagreement worth seeing, not a silent skip.
    let (Some(real_page), Some(real_uri), Some(real_outcome)) =
        (&sides.real_page, &sides.real_uri, sides.real_outcome)
    else {
        return Err(format!(
            "real NormalizedUrl::parse failed on a case the oracle expected to parse: \
             page_raw={:?} uri_raw={:?} sides={sides:?}",
            render_url(&case.page),
            render_url(&case.uri)
        ));
    };

    let oracle_page_domain = &sides.oracle_outcome.page_oracle.registrable_domain;
    if &real_page.2 != oracle_page_domain {
        return Err(format!(
            "page registrable_domain disagreement: real={:?} oracle={oracle_page_domain:?} \
             (page host {:?})",
            real_page.2, real_page.0
        ));
    }
    let oracle_uri_domain = &sides.oracle_outcome.uri_oracle.registrable_domain;
    if &real_uri.2 != oracle_uri_domain {
        return Err(format!(
            "uri registrable_domain disagreement: real={:?} oracle={oracle_uri_domain:?} \
             (uri host {:?})",
            real_uri.2, real_uri.0
        ));
    }

    let outcomes_agree = matches!(
        (real_outcome, &sides.oracle_outcome.decision),
        (MatchOutcome::NoMatch, oracle::Decision::NoMatch)
            | (MatchOutcome::NotSupported, oracle::Decision::NotSupported)
            | (
                MatchOutcome::Match(MatchedVia::RegistrableDomain),
                oracle::Decision::MatchExact
            )
            | (
                MatchOutcome::Match(MatchedVia::Equivalence(_)),
                oracle::Decision::MatchEquivalence
            )
    );
    if !outcomes_agree {
        return Err(format!(
            "outcome disagreement: real={real_outcome:?} oracle={:?}\n\
             case={case:?}\n\
             page_raw={:?} uri_raw={:?}\n\
             real_page(host,port,domain)={real_page:?} real_uri(host,port,domain)={real_uri:?}",
            sides.oracle_outcome.decision,
            render_url(&case.page),
            render_url(&case.uri),
        ));
    }
    Ok(())
}

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Where a batch's randomness comes from (mirrors
/// `crates/rizzy-sync/src/convergence/generate.rs`'s `Seeds`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seeds {
    /// Proptest's deterministic RNG: the same cases every run, so PR runs are never flaky.
    Fixed,
    /// Fresh randomness per run, for the nightly budget.
    Fresh,
}

#[expect(
    clippy::panic,
    reason = "test harness: this is the one place a #[test] function's own failure is reported; \
              clippy's test-code exemption only recognises a #[test]-attributed function body \
              itself, not a plain helper it calls"
)]
fn run_batch(cases: u32, seeds: Seeds) {
    let cfg = config(cases);
    let mut runner = match seeds {
        Seeds::Fixed => {
            TestRunner::new_with_rng(cfg.clone(), TestRng::deterministic_rng(cfg.rng_algorithm))
        }
        Seeds::Fresh => TestRunner::new(cfg.clone()),
    };
    let result = runner.run(&oracle::case_strategy(), |case| {
        let sides = run_case(&case);
        compare(&case, &sides).map_err(TestCaseError::fail)
    });
    if let Err(e) = result {
        panic!("{e} (batch rng_seed {:?})", cfg.rng_seed);
    }
}

/// Runs a fixed-seed batch against `matcher` instead of the real `decide`, and asserts the
/// harness actually flags a disagreement somewhere in `cases` draws — the positive control
/// `mod mutants` needs: proof that generator → oracle → [`compare`] catches a real weakening
/// end to end, not just that a hand-picked example disagrees with a hand-typed expectation.
fn run_batch_expect_a_disagreement(
    cases: u32,
    matcher: impl Fn(
        &NormalizedUrl,
        &NormalizedUrl,
        MatchMode,
        MatchMode,
        &EquivalenceView<'_>,
    ) -> MatchOutcome
    + Copy,
) {
    let cfg = config(cases);
    let mut runner =
        TestRunner::new_with_rng(cfg.clone(), TestRng::deterministic_rng(cfg.rng_algorithm));
    let result = runner.run(&oracle::case_strategy(), |case| {
        let sides = run_case_with(&case, matcher);
        compare(&case, &sides).map_err(TestCaseError::fail)
    });
    assert!(
        result.is_err(),
        "expected the harness to flag at least one disagreement against this mutant within \
         {cases} fixed-seed cases, but it found none — either the mutant does not actually \
         weaken anything the generator reaches, or the generator does not reach the shape it \
         weakens"
    );
}

/// The main differential property, PR budget, fixed seeds.
#[test]
fn adr0037_oracle_agrees_with_rizzy_match() {
    run_batch(PR_CASES, Seeds::Fixed);
}

/// The nightly budget: [`PR_CASES`] × [`NIGHTLY_MULTIPLIER`] on fresh seeds. Not wired into any
/// CI job (`.github/workflows/` is the owner's to change, CLAUDE.md); run manually with
/// `cargo test -p rizzy-match --test adr0037_differential -- --ignored`, or split into several
/// `PROPTEST_CASES`-style manual batches for the scale run this task asks for (each such batch
/// is just this same test run again with a fresh process, since proptest's own RNG re-seeds
/// per run under `Seeds::Fresh`).
#[test]
#[ignore = "nightly budget: 50x the PR cases on fresh seeds"]
fn nightly_adr0037_oracle_agrees_with_rizzy_match() {
    run_batch(PR_CASES * NIGHTLY_MULTIPLIER, Seeds::Fresh);
}

/// A pinned regression for a harness bug a scale run on fresh seeds found (not a `rizzy-match`
/// violation): the oracle's `active_groups` originally deduplicated a group's domains before
/// checking membership, instead of rejecting the whole group the way
/// `EquivalenceGroup::new` does when two of its domains normalise to the same value ("a
/// duplicate after normalisation is an error, not a silent drop", `equivalence.rs`). A group
/// spec of `["shop", "co", "co"]` therefore looked, to the old oracle, like a valid two-member
/// active group `{"co", "shop"}` — giving `MatchEquivalence` — while the real
/// `EquivalenceGroup::new` refused to construct it at all, leaving the view empty and `decide`
/// returning `NoMatch`. Fixed in `oracle::active_groups`; pinned here so the exact minimised
/// case stays green.
#[test]
fn regression_duplicate_domain_in_an_equivalence_group_spec_builds_no_group() {
    let case = oracle::Case {
        page: oracle::GenUrl {
            scheme: oracle::SchemeKind::Http,
            host: oracle::GenHost::Domain {
                labels: vec!["co".to_owned()],
                trailing_dot_count: 0,
                upper_mask: 139,
            },
            port: oracle::PortKind::ExplicitOtherSchemeDefault,
            userinfo: Some(("user".to_owned(), "pass".to_owned())),
            path: "/account".to_owned(),
        },
        uri: oracle::GenUrl {
            scheme: oracle::SchemeKind::Http,
            host: oracle::GenHost::Domain {
                labels: vec!["shop".to_owned()],
                trailing_dot_count: 1,
                upper_mask: 0,
            },
            port: oracle::PortKind::ExplicitDefaultForScheme,
            userinfo: None,
            path: "/account/settings/x".to_owned(),
        },
        mode: MatchMode::BaseDomain,
        account_default: MatchMode::BaseDomain,
        groups: vec![oracle::EquivGroupSpec {
            is_global: false,
            disabled: false,
            domains: vec!["shop".to_owned(), "co".to_owned(), "co".to_owned()],
        }],
    };
    let sides = run_case(&case);
    compare(&case, &sides).unwrap_or_else(|e| panic!("{e}"));
}

// ---------------------------------------------------------------------------------------------
// Golden cases lifted straight from ADR 0037's own prose, as a sanity baseline independent of
// the generator.
// ---------------------------------------------------------------------------------------------

mod golden {
    use super::*;

    #[expect(
        clippy::panic,
        reason = "test helper: reports a golden-case setup failure, not reachable from a #[test] \
                  function body directly"
    )]
    fn url(s: &str) -> NormalizedUrl {
        NormalizedUrl::parse(s).unwrap_or_else(|e| panic!("{s:?} must parse: {e:?}"))
    }

    #[test]
    fn evil_youtube_never_matches_base_domain() {
        // ADR 0037 Context, quoting ROADMAP §4.4 verbatim.
        let page = url("https://evil-youtube.com/");
        let uri = url("https://youtube.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::BaseDomain,
                MatchMode::BaseDomain,
                &EquivalenceView::empty()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn starts_with_bank_com_never_matches_bank_com_evil_example() {
        // ADR 0037 §4 "Narrowing only", the exact example.
        let page = url("https://bank.com.evil.example/");
        let uri = url("https://bank.com/");
        assert_eq!(
            decide(
                &page,
                &uri,
                MatchMode::StartsWith,
                MatchMode::BaseDomain,
                &EquivalenceView::empty()
            ),
            MatchOutcome::NoMatch
        );
    }

    #[test]
    fn a_b_example_co_uk_registrable_domain_is_example_co_uk() {
        // ADR 0037 §2 point 7, the exact example.
        let u = url("https://a.b.example.co.uk/");
        assert_eq!(u.registrable_domain(), Some("example.co.uk"));
    }
}

// ---------------------------------------------------------------------------------------------
// Relational properties over genuine Unicode input: no punycode encoder, per the module docs.
// ---------------------------------------------------------------------------------------------

mod relational {
    use super::*;

    /// A successfully normalised host is always all-ASCII with no trailing dot (ADR 0037 §2
    /// points 3–4): mixed-script input is "never stored or displayed as decoded Unicode".
    fn assert_ascii_no_trailing_dot(raw: &str) {
        if let Ok(u) = NormalizedUrl::parse(raw) {
            assert!(
                u.host().is_ascii(),
                "{raw:?} normalised to a non-ASCII host {:?}",
                u.host()
            );
            assert!(
                !u.host().ends_with('.'),
                "{raw:?} normalised to a host with a trailing dot {:?}",
                u.host()
            );
        }
    }

    /// Curated confusable pairs that must be treated as genuinely *different* registrable
    /// domains (`THREAT_MODEL` A6; INV-38 "Verified by": IDN homographs).
    #[test]
    fn confusable_pairs_never_collide_with_the_real_domain() {
        let pairs = [
            // Cyrillic а (U+0430) for Latin a.
            ("https://\u{0430}pple.com/", "https://apple.com/"),
            // Cyrillic е (U+0435) for Latin e.
            ("https://gmail\u{0435}.com/", "https://gmaile.com/"),
            // Cyrillic о (U+043E) for Latin o.
            ("https://g\u{043E}ogle.com/", "https://google.com/"),
            // Cyrillic р (U+0440) for Latin p.
            ("https://\u{0440}aypal.com/", "https://paypal.com/"),
            // Cyrillic с (U+0441) for Latin c.
            ("https://micro\u{0441}oft.com/", "https://microsoft.com/"),
            // Greek alpha (U+03B1) for Latin a.
            ("https://b\u{03B1}nk.com/", "https://bank.com/"),
        ];
        for (homograph, real) in pairs {
            assert_ascii_no_trailing_dot(homograph);
            let Ok(h) = NormalizedUrl::parse(homograph) else {
                continue;
            };
            let r = NormalizedUrl::parse(real).unwrap();
            assert_ne!(
                h.host(),
                r.host(),
                "{homograph:?} must not share a host with {real:?}"
            );
            assert_ne!(
                h.registrable_domain(),
                r.registrable_domain(),
                "{homograph:?} must not share a registrable domain with {real:?}"
            );
            assert_eq!(
                decide(
                    &h,
                    &r,
                    MatchMode::BaseDomain,
                    MatchMode::BaseDomain,
                    &EquivalenceView::empty()
                ),
                MatchOutcome::NoMatch,
                "{homograph:?} must never match {real:?} under Base domain"
            );
        }
    }

    /// Curated pairs that really are *one* value in two different notations and must normalise
    /// identically: case folding, a trailing dot, and the Unicode/punycode form of the same IDN
    /// host (ADR 0037 §2 points 3–4).
    #[test]
    fn equal_notations_of_the_same_host_normalise_identically() {
        let pairs = [
            ("https://EXAMPLE.com/path", "https://example.com/path"),
            ("https://example.com./path", "https://example.com/path"),
            ("https://xn--mnchen-3ya.de/", "https://m\u{00FC}nchen.de/"),
            ("https://M\u{00DC}NCHEN.de/", "https://m\u{00FC}nchen.de/"),
        ];
        for (a, b) in pairs {
            let ua = NormalizedUrl::parse(a).unwrap_or_else(|e| panic!("{a:?}: {e:?}"));
            let ub = NormalizedUrl::parse(b).unwrap_or_else(|e| panic!("{b:?}: {e:?}"));
            assert_eq!(
                ua.host(),
                ub.host(),
                "{a:?} and {b:?} must normalise to the same host"
            );
            assert_eq!(ua, ub);
        }
    }

    /// Same IPv4 address, four different textual notations (decimal, octal, hex, short forms):
    /// if the real implementation accepts a form at all, it must normalise to the same host as
    /// the plain dotted-decimal form (ADR 0037 §2's registrable-domain rule has no separate
    /// notion of "notation", only of host identity).
    #[test]
    fn ipv4_notations_of_the_same_address_agree_when_both_parse() {
        let groups: [[&str; 2]; 4] = [
            ["https://127.0.0.1/", "https://2130706433/"],
            ["https://127.0.0.1/", "https://0x7f.0.0.1/"],
            ["https://127.0.0.1/", "https://0177.0.0.1/"],
            ["https://127.0.0.1/", "https://127.1/"],
        ];
        for [canon, alt] in groups {
            let c = NormalizedUrl::parse(canon).unwrap();
            let Ok(a) = NormalizedUrl::parse(alt) else {
                // Not every alternate notation needs to be accepted; only consistency when it
                // is. See `not_covered`.
                continue;
            };
            assert_eq!(
                c.host(),
                a.host(),
                "{canon:?} and {alt:?} denote the same address and must normalise identically"
            );
            assert_eq!(c.registrable_domain(), a.registrable_domain());
        }
    }

    /// IPv6 literal forms of the same address must agree, and the IPv4-mapped form must agree
    /// with the plain IPv4 literal's own normalisation only insofar as both are internally
    /// consistent (they are different registrable "domains" by design — an IPv4 and an IPv6
    /// literal are never the same host string — so only same-family pairs are asserted equal
    /// here).
    #[test]
    fn ipv6_notations_of_the_same_address_agree() {
        let pairs = [
            ("https://[::1]/", "https://[0:0:0:0:0:0:0:1]/"),
            ("https://[::1]/", "https://[0:0::1]/"),
        ];
        for (a, b) in pairs {
            let ua = NormalizedUrl::parse(a).unwrap_or_else(|e| panic!("{a:?}: {e:?}"));
            let ub = NormalizedUrl::parse(b).unwrap_or_else(|e| panic!("{b:?}: {e:?}"));
            assert_eq!(
                ua.host(),
                ub.host(),
                "{a:?} and {b:?} must normalise to the same host"
            );
        }
    }

    /// INV-42: only `http`/`https` ever normalise; every other scheme ADR 0037 §2 point 2 and
    /// INV-42 name is refused, regardless of how well-formed its own authority would be.
    #[test]
    fn forbidden_schemes_never_normalise() {
        for raw in [
            "ftp://example.com/",
            "javascript:alert(1)",
            "data:text/plain,hello",
            "file:///etc/passwd",
            "blob:https://example.com/00000000-0000-0000-0000-000000000000",
            "about:blank",
        ] {
            let err = NormalizedUrl::parse(raw)
                .expect_err(&format!("{raw:?} must not normalise to a matchable URL"));
            assert_eq!(
                err,
                rizzy_match::NormalizeError::UnsupportedScheme,
                "{raw:?} must be refused specifically for its scheme"
            );
        }
    }

    /// Userinfo must never leak into the host, the registrable domain or the normalised string
    /// (ADR 0037 §2 computes all three from `url::Url::host_str`/`host`, which never includes
    /// userinfo; a page is reached at the *host*, never at whatever precedes `@`).
    #[test]
    fn userinfo_never_substitutes_for_the_host() {
        let u = NormalizedUrl::parse("https://bank.com@evil.example/x").unwrap();
        assert_eq!(u.host(), "evil.example");
        assert_eq!(u.registrable_domain(), Some("evil.example"));
        assert!(!u.normalized_string().contains("bank.com@"));
        assert!(!u.normalized_string().contains("bank.com"));
    }
}

// ---------------------------------------------------------------------------------------------
// Formerly a pinned spec-gap probe: ADR 0037/0038's text never said an equivalence-group domain
// string must not look like an IP literal, and `EquivalenceGroup::new` accepted one. ADR 0044
// (Accepted) closes it: every member must be a domain (never an IP literal) equal to its own
// registrable domain. Both probes are un-ignored and flipped, as ADR 0044 "Tests required" asks.
// ---------------------------------------------------------------------------------------------

mod equivalence_ip_probe {
    use super::*;

    /// ADR 0044 rule 1: an IP literal is never a group member, in any IPv4 notation the WHATWG
    /// host parser reads as one, nor as an IPv6 literal.
    #[test]
    fn equivalence_group_refuses_an_ip_literal_member() {
        for literal in ["192.168.1.1", "2130706433", "0x7f.1", "[::1]", "::1"] {
            let built = EquivalenceGroup::new(
                GroupId::from_bytes([0xAA; 16]),
                [literal, "evil.example"],
                false,
            );
            assert!(
                built.is_err(),
                "EquivalenceGroup::new must refuse the IP literal {literal:?} (ADR 0044 rule 1)"
            );
        }
    }

    /// The consequence the old probe demonstrated: a page reached by an IP literal matching a
    /// URI saved at an unrelated domain through a group bridging the two. No such group can be
    /// built any more, so under every view that can exist the pair is `NoMatch`.
    #[test]
    fn no_group_lets_an_ip_literal_page_match_an_unrelated_domain_uri() {
        let group = EquivalenceGroup::new(
            GroupId::from_bytes([0xAA; 16]),
            ["192.168.1.1", "evil.example"],
            false,
        );
        assert!(
            group.is_err(),
            "the bridging group must not be constructible"
        );
        let global: Vec<EquivalenceGroup> = group.into_iter().collect();
        let disabled = BTreeSet::new();
        let user = vec![];
        let view = EquivalenceView::new(&global, &disabled, &user);

        let page = NormalizedUrl::parse("https://192.168.1.1/admin").unwrap();
        let uri = NormalizedUrl::parse("https://evil.example/").unwrap();
        let outcome = decide(
            &page,
            &uri,
            MatchMode::BaseDomain,
            MatchMode::BaseDomain,
            &view,
        );
        assert_eq!(outcome, MatchOutcome::NoMatch);
    }
}

// ---------------------------------------------------------------------------------------------
// Positive control: deliberate weakenings of `decide`, reimplemented in test code only. The
// independent oracle must catch each one on the ADR's own named attack shape, proving the
// harness can detect a real INV-38 violation.
// ---------------------------------------------------------------------------------------------

mod mutants {
    use rizzy_match::security::https_downgrade_blocks;
    use rizzy_match::{
        EffectiveMode, EquivalenceView, MatchMode, MatchOutcome, MatchedVia, NormalizedUrl,
    };

    /// Mutant 1: the registrable-domain gate is skipped entirely (ADR 0037 §4's "Alternatives
    /// considered" names exactly this, for *Starts with* and *Regex*, as rejected). Demonstrated
    /// under *Base domain*, whose own per-mode rule is the gate and nothing else, so removing
    /// the gate leaves no narrowing at all — unlike *Starts with*, whose own string check still
    /// requires the page's normalised URL to literally start with the URI's, and that string
    /// always ends its host component in a `:` or `/` delimiter the attacker cannot forge across
    /// a host boundary, so a byte-prefix bypass of *Starts with* specifically turns out not to
    /// be constructible against this crate's `normalized_string` (every path defaults to a
    /// non-empty `/`); *Base domain* carries no such incidental protection.
    fn mutant_no_gate_at_all(
        page: &NormalizedUrl,
        uri: &NormalizedUrl,
        mode: MatchMode,
        account_default: MatchMode,
        equivalence: &EquivalenceView<'_>,
    ) -> MatchOutcome {
        let effective = mode.resolve(account_default);
        if matches!(effective, EffectiveMode::BaseDomain) {
            if https_downgrade_blocks(uri.scheme(), page.scheme()) {
                return MatchOutcome::NoMatch;
            }
            return MatchOutcome::Match(MatchedVia::RegistrableDomain);
        }
        rizzy_match::decide(page, uri, mode, account_default, equivalence)
    }

    /// Mutant 2: the gate compares the *public suffix* instead of the registrable domain (eTLD+1)
    /// — `evil-youtube.com` and `youtube.com` share the public suffix `com`. Takes the same
    /// five-argument shape as `rizzy_match::decide` (the `equivalence` parameter unused) so it
    /// can be passed to [`super::run_batch_expect_a_disagreement`] like `mutant_no_gate_at_all`.
    fn mutant_gate_on_public_suffix(
        page: &NormalizedUrl,
        uri: &NormalizedUrl,
        mode: MatchMode,
        account_default: MatchMode,
        _equivalence: &EquivalenceView<'_>,
    ) -> MatchOutcome {
        let effective = mode.resolve(account_default);
        if matches!(effective, EffectiveMode::Regex) {
            return MatchOutcome::NotSupported;
        }
        if matches!(effective, EffectiveMode::Never) {
            return MatchOutcome::NoMatch;
        }
        if https_downgrade_blocks(uri.scheme(), page.scheme()) {
            return MatchOutcome::NoMatch;
        }
        let page_suffix = psl::suffix_str(page.host());
        let uri_suffix = psl::suffix_str(uri.host());
        if page_suffix.is_none() || page_suffix != uri_suffix {
            return MatchOutcome::NoMatch;
        }
        match effective {
            EffectiveMode::BaseDomain => MatchOutcome::Match(MatchedVia::RegistrableDomain),
            EffectiveMode::Host => {
                if page.host() == uri.host() && page.port() == uri.port() {
                    MatchOutcome::Match(MatchedVia::RegistrableDomain)
                } else {
                    MatchOutcome::NoMatch
                }
            }
            EffectiveMode::StartsWith => {
                if page
                    .normalized_string()
                    .starts_with(&uri.normalized_string())
                {
                    MatchOutcome::Match(MatchedVia::RegistrableDomain)
                } else {
                    MatchOutcome::NoMatch
                }
            }
            EffectiveMode::Exact => {
                if page.normalized_string() == uri.normalized_string() {
                    MatchOutcome::Match(MatchedVia::RegistrableDomain)
                } else {
                    MatchOutcome::NoMatch
                }
            }
            EffectiveMode::Regex | EffectiveMode::Never => unreachable!("handled above"),
        }
    }

    // Worked examples: a concrete, hand-picked case each mutant wrongly accepts. These show
    // *what* is being caught; they do not by themselves prove the harness's generator →
    // oracle → compare pipeline is what catches it (a hardcoded expected value could agree
    // with the mutant by coincidence of this one example). The batch-based tests below are
    // the actual positive control.

    #[test]
    fn worked_example_a_fully_skipped_gate() {
        let page = NormalizedUrl::parse("https://totally-unrelated.example/").unwrap();
        let uri = NormalizedUrl::parse("https://bank.com/").unwrap();

        let real = rizzy_match::decide(
            &page,
            &uri,
            MatchMode::BaseDomain,
            MatchMode::BaseDomain,
            &EquivalenceView::empty(),
        );
        assert_eq!(
            real,
            MatchOutcome::NoMatch,
            "the real, correctly-gated decide must refuse"
        );

        let mutated = mutant_no_gate_at_all(
            &page,
            &uri,
            MatchMode::BaseDomain,
            MatchMode::BaseDomain,
            &EquivalenceView::empty(),
        );
        assert_eq!(
            mutated,
            MatchOutcome::Match(MatchedVia::RegistrableDomain),
            "the mutant must wrongly accept this case — if it does not, the mutant is not \
             exercising the weakening it claims to, and this positive control is not testing \
             anything"
        );
    }

    #[test]
    fn worked_example_the_public_suffix_gate() {
        let page = NormalizedUrl::parse("https://evil-youtube.com/").unwrap();
        let uri = NormalizedUrl::parse("https://youtube.com/").unwrap();
        let real = rizzy_match::decide(
            &page,
            &uri,
            MatchMode::BaseDomain,
            MatchMode::BaseDomain,
            &EquivalenceView::empty(),
        );
        assert_eq!(real, MatchOutcome::NoMatch);
        let mutated = mutant_gate_on_public_suffix(
            &page,
            &uri,
            MatchMode::BaseDomain,
            MatchMode::BaseDomain,
            &EquivalenceView::empty(),
        );
        assert_eq!(
            mutated,
            MatchOutcome::Match(MatchedVia::RegistrableDomain),
            "the public-suffix mutant must wrongly accept evil-youtube.com against youtube.com"
        );
    }

    // The actual positive control: the full generator → oracle → `compare` pipeline, run
    // against each mutant in place of the real `decide`, must itself report a disagreement —
    // not just a hand-picked example compared to a hand-typed expectation.

    #[test]
    fn harness_catches_a_fully_skipped_gate_end_to_end() {
        super::run_batch_expect_a_disagreement(2_000, mutant_no_gate_at_all);
    }

    #[test]
    fn harness_catches_the_public_suffix_gate_end_to_end() {
        super::run_batch_expect_a_disagreement(2_000, mutant_gate_on_public_suffix);
    }
}
