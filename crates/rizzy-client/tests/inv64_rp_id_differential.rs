// SPDX-License-Identifier: AGPL-3.0-only

//! Differential test for INV-64's `rpId` validation (`THREAT_MODEL.md` §8 INV-64; ADR 0039 §2)
//! against an independent oracle built from that text and the `WebAuthn` rule it names (`rpId`
//! must be a registrable suffix of the effective domain, never a public suffix, HTTPS only),
//! not from `rizzy-client`'s own `passkey.rs` (`verify_rp_id` is `pub(crate)` and unreachable
//! from this black-box test anyway; only the public [`create_credential`] is called).
//!
//! # Scope
//!
//! The oracle works at the same ASCII/A-label layer as the ADR 0037 differential
//! (`crates/rizzy-match/tests/adr0037_differential/`): generated hosts and `rpId` strings are
//! always already-ASCII, so no punycode encoder is needed, and the `psl` crate is used directly
//! for public-suffix lookup, the one crate this oracle shares with the implementation.
//! Genuinely non-ASCII `rpId`/origin input and origin ports are out of scope here (see this
//! harness's `not_covered`): INV-64's text gives no port rule at all, and the IDN/punycode
//! layer is the ADR 0037 differential's job, reused unchanged by ADR 0039 §2's own words
//! ("the PSL [ADR 0037] §3").
//!
//! INV-64's text names no exception for `localhost` over plain HTTP; `golden::no_localhost_http_exception`
//! checks that reading against the implementation directly, as a named finding rather than an
//! assumption.
//!
//! # Not covered by this harness
//!
//! - **Non-ASCII origin/`rpId` input.** Delegated entirely to the ADR 0037 differential, which
//!   owns IDNA/punycode scope; this file only ever generates already-ASCII hosts.
//! - **The P-256/ES256 ceremony itself.** Key generation, the CBOR `attestationObject`, and the
//!   signature are exercised (every accepted case runs a real keygen) but never independently
//!   re-verified byte-for-byte against the `WebAuthn` spec; only the `rpId`/origin accept-or-reject
//!   decision and `clientDataJSON`'s `origin` field are differentially checked.
//! - **Non-default-port `rpId` validation itself.** `client_data_json_origin_keeps_a_non_default_port`
//!   checks only that `create_credential` preserves the origin's port into `clientDataJSON`; it
//!   is a single golden case, not a generator property, because INV-64's text gives no port rule
//!   to build an oracle from.

use chacha20::ChaCha20Rng;
use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};
use rand_core::SeedableRng as _;
use rizzy_client::ClientError;
use rizzy_client::passkey::create_credential;

/// Generated cases per PR run. `create_credential` runs a real (cheap) P-256 keygen on every
/// *accepted* case, so this stays smaller than the ADR 0037 differential's case count while
/// still comfortably exercising the decision space within the ~60s PR budget.
const PR_CASES: u32 = 1_500;

/// The nightly budget is this many times [`PR_CASES`], on fresh seeds.
const NIGHTLY_MULTIPLIER: u32 = 40;

// ---------------------------------------------------------------------------------------------
// The independent oracle (ASCII/A-label layer; see module docs for the scope boundary).
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    RejectRpId,
    InvalidInput,
}

/// ADR 0037 §2 point 3 applied to a bare domain string (ADR 0038 §1's own normalisation
/// contract, minus the full IDNA table this oracle deliberately does not re-derive — see module
/// docs): lower-case, every trailing dot stripped (not just one — a run of two or more must
/// collapse the same way a single dot does, the same invariant
/// `rizzy_match::normalize::normalize_domain` fixes for the real implementation), empty after
/// that is invalid.
fn oracle_normalize_bare(raw: &str) -> Option<String> {
    let s = raw.trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() { None } else { Some(s) }
}

/// ADR 0037 §2 point 7; §4; INV-38 (reused by ADR 0039 §2 for INV-64 unchanged): the
/// registrable domain of a named (non-IP) host. See the ADR 0037 differential's
/// `registrable_domain_of_named` for the same independent reasoning about the dotless-host
/// carve-out; restated here rather than imported, since this file is a separate, standalone
/// differential harness.
fn oracle_registrable_domain(host: &str, is_ip: bool) -> Option<String> {
    if is_ip {
        return Some(host.to_owned());
    }
    if let Some(d) = psl::domain_str(host) {
        return Some(d.to_owned());
    }
    if host.contains('.') {
        None
    } else {
        Some(host.to_owned())
    }
}

/// INV-64 / ADR 0039 §2: "never a public suffix" applies to `rp_id` itself, and `WebAuthn` never
/// accepts an IP-literal `rpId` at all.
fn oracle_rp_id_is_valid_leaf(rp_id: &str) -> bool {
    if rp_id.parse::<core::net::IpAddr>().is_ok() {
        return false;
    }
    if !rp_id.contains('.') {
        return true;
    }
    psl::domain_str(rp_id) == Some(rp_id)
}

/// The oracle's verdict, independent of `rizzy_client::passkey::verify_rp_id`.
///
/// INV-64's text: "the origin is HTTPS; the requested `rpId` equals the origin's host or is a
/// registrable-domain suffix of it, checked against the PSL, and is never a public suffix
/// (private PSL entries included)." ADR 0039 §2 adds the IP-literal refusal explicitly for
/// `rpId` (the origin side's own IP-literal carve-out, ADR 0037 §2's, "must never leak into
/// what `rpId` is allowed to claim" — independently re-derived the same way here, by simply
/// never treating an IP-literal `rp_id` as acceptable regardless of the origin).
fn oracle_decide(
    origin_is_https: bool,
    origin_host: &str,
    origin_is_ip: bool,
    raw_rp_id: &str,
) -> Verdict {
    let Some(rp_id) = oracle_normalize_bare(raw_rp_id) else {
        return Verdict::InvalidInput;
    };
    if !origin_is_https {
        return Verdict::RejectRpId;
    }
    if !oracle_rp_id_is_valid_leaf(&rp_id) {
        return Verdict::RejectRpId;
    }
    if rp_id == origin_host {
        return Verdict::Accept;
    }
    if oracle_registrable_domain(origin_host, origin_is_ip).as_deref() == Some(rp_id.as_str()) {
        return Verdict::Accept;
    }
    Verdict::RejectRpId
}

// ---------------------------------------------------------------------------------------------
// The generated shape.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchemeKind {
    Https,
    Http,
}

#[derive(Clone, Debug)]
enum HostShape {
    Domain(Vec<String>),
    Ipv4(u8, u8, u8, u8),
}

#[derive(Clone, Debug)]
enum RpIdChoice {
    /// Exactly the origin's own host.
    EqualsHost,
    /// The origin host's registrable domain (meaningful when the host has an extra label).
    EqualsRegistrableDomain,
    /// A domain unrelated to the origin.
    Unrelated(Vec<String>),
    /// A known bare public suffix, ICANN or private, regardless of the origin.
    BarePublicSuffix(&'static str),
    /// An IP-literal string.
    IpLiteral(u8, u8, u8, u8),
    /// Empty (INV-64's own `InvalidInput` boundary).
    Empty,
}

#[derive(Clone, Debug)]
struct Case {
    scheme: SchemeKind,
    host: HostShape,
    rp_id: RpIdChoice,
    rp_id_uppercase: bool,
    /// A trailing run of 0..=3 dots on the rendered `rp_id` (mirrors
    /// `rizzy_match::normalize`'s own `registrable_domain_is_invariant_under_trailing_dot_runs`
    /// and `normalize_domain_output_is_idempotent` proptests, which cover a run of this length):
    /// a plain `bool` could only ever render zero or one dot, so this generator could never have
    /// reached the two-or-more-trailing-dot shape the ADR 0037/0039 trailing-dot-run fix exists
    /// for.
    rp_id_trailing_dot_count: usize,
}

const LABELS: &[&str] = &[
    "example", "bank", "accounts", "evil", "login", "pay", "sub", "a", "b", "com", "net", "org",
    "co", "uk", "io", "github", "de",
];

fn label_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(LABELS).prop_map(str::to_owned)
}

fn domain_host_strategy() -> impl Strategy<Value = HostShape> {
    prop::collection::vec(label_strategy(), 1..=4).prop_map(HostShape::Domain)
}

fn ipv4_host_strategy() -> impl Strategy<Value = HostShape> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(a, b, c, d)| HostShape::Ipv4(a, b, c, d))
}

fn host_strategy() -> impl Strategy<Value = HostShape> {
    prop_oneof![5 => domain_host_strategy(), 1 => ipv4_host_strategy()]
}

fn unrelated_domain_strategy() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(label_strategy(), 1..=3)
}

const BARE_SUFFIXES: &[&str] = &["co.uk", "github.io", "com", "co", "uk", "io"];

fn rp_id_choice_strategy() -> impl Strategy<Value = RpIdChoice> {
    prop_oneof![
        4 => Just(RpIdChoice::EqualsHost),
        3 => Just(RpIdChoice::EqualsRegistrableDomain),
        3 => unrelated_domain_strategy().prop_map(RpIdChoice::Unrelated),
        2 => prop::sample::select(BARE_SUFFIXES).prop_map(RpIdChoice::BarePublicSuffix),
        2 => (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| RpIdChoice::IpLiteral(a, b, c, d)),
        1 => Just(RpIdChoice::Empty),
    ]
}

fn scheme_strategy() -> impl Strategy<Value = SchemeKind> {
    prop_oneof![3 => Just(SchemeKind::Https), 1 => Just(SchemeKind::Http)]
}

fn case_strategy() -> impl Strategy<Value = Case> {
    (
        scheme_strategy(),
        host_strategy(),
        rp_id_choice_strategy(),
        any::<bool>(),
        0usize..=3,
    )
        .prop_map(
            |(scheme, host, rp_id, rp_id_uppercase, rp_id_trailing_dot_count)| Case {
                scheme,
                host,
                rp_id,
                rp_id_uppercase,
                rp_id_trailing_dot_count,
            },
        )
}

// ---------------------------------------------------------------------------------------------
// Rendering and running.
// ---------------------------------------------------------------------------------------------

fn render_host(host: &HostShape) -> (String, bool) {
    match host {
        HostShape::Domain(labels) => (labels.join("."), false),
        HostShape::Ipv4(a, b, c, d) => (format!("{a}.{b}.{c}.{d}"), true),
    }
}

fn render_rp_id(case: &Case, origin_host: &str, origin_is_ip: bool) -> String {
    let base = match &case.rp_id {
        RpIdChoice::EqualsHost => origin_host.to_owned(),
        RpIdChoice::EqualsRegistrableDomain => oracle_registrable_domain(origin_host, origin_is_ip)
            .unwrap_or_else(|| origin_host.to_owned()),
        RpIdChoice::Unrelated(labels) => labels.join("."),
        RpIdChoice::BarePublicSuffix(s) => (*s).to_owned(),
        RpIdChoice::IpLiteral(a, b, c, d) => format!("{a}.{b}.{c}.{d}"),
        RpIdChoice::Empty => return String::new(),
    };
    let base = if case.rp_id_uppercase {
        base.to_ascii_uppercase()
    } else {
        base
    };
    format!("{base}{}", ".".repeat(case.rp_id_trailing_dot_count))
}

fn render_origin(scheme: SchemeKind, host: &str) -> String {
    let s = match scheme {
        SchemeKind::Https => "https",
        SchemeKind::Http => "http",
    };
    format!("{s}://{host}")
}

/// Runs one generated `Case` through the real implementation (via the public
/// [`create_credential`]) and the oracle, returning both verdicts for comparison.
#[expect(
    clippy::panic,
    reason = "test helper: reports an unexpected error variant from a plain function, not a \
              #[test]-attributed one, which is the only shape clippy's test-code exemption \
              recognises"
)]
fn run_case(case: &Case) -> (Verdict, Verdict, String, String) {
    let (origin_host, origin_is_ip) = render_host(&case.host);
    let rp_id_raw = render_rp_id(case, &origin_host, origin_is_ip);
    let origin_raw = render_origin(case.scheme, &origin_host);

    let oracle_verdict = oracle_decide(
        case.scheme == SchemeKind::Https,
        &origin_host,
        origin_is_ip,
        &rp_id_raw,
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0x5151);
    let real_verdict = match create_credential(&mut rng, &origin_raw, &rp_id_raw, b"challenge") {
        Ok(_) => Verdict::Accept,
        Err(ClientError::RpIdRejected) => Verdict::RejectRpId,
        Err(ClientError::InvalidInput) => Verdict::InvalidInput,
        Err(other) => panic!(
            "unexpected error variant {other:?} for origin={origin_raw:?} rp_id={rp_id_raw:?}"
        ),
    };

    (oracle_verdict, real_verdict, origin_raw, rp_id_raw)
}

fn compare(
    case: &Case,
    oracle_verdict: Verdict,
    real_verdict: Verdict,
    origin_raw: &str,
    rp_id_raw: &str,
) -> Result<(), String> {
    if oracle_verdict != real_verdict {
        return Err(format!(
            "verdict disagreement: oracle={oracle_verdict:?} real={real_verdict:?} \
             origin={origin_raw:?} rp_id={rp_id_raw:?} case={case:?}"
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seeds {
    Fixed,
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
    let result = runner.run(&case_strategy(), |case| {
        let (oracle_verdict, real_verdict, origin_raw, rp_id_raw) = run_case(&case);
        compare(&case, oracle_verdict, real_verdict, &origin_raw, &rp_id_raw)
            .map_err(TestCaseError::fail)
    });
    if let Err(e) = result {
        panic!("{e} (batch rng_seed {:?})", cfg.rng_seed);
    }
}

/// A generator that silently stopped reaching one verdict kind would make the differential
/// property vacuous there (mirrors the ADR 0037 differential's own
/// `the_generator_reaches_every_decision_kind`).
#[test]
fn the_generator_reaches_every_verdict_kind() {
    use proptest::strategy::{Strategy, ValueTree};
    use std::collections::BTreeSet;

    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 3_000,
        ..ProptestConfig::default()
    });
    let strategy = case_strategy();
    for _ in 0..3_000 {
        let Ok(tree) = strategy.new_tree(&mut runner) else {
            continue;
        };
        let case = tree.current();
        let (origin_host, origin_is_ip) = render_host(&case.host);
        let rp_id_raw = render_rp_id(&case, &origin_host, origin_is_ip);
        let verdict = oracle_decide(
            case.scheme == SchemeKind::Https,
            &origin_host,
            origin_is_ip,
            &rp_id_raw,
        );
        seen.insert(match verdict {
            Verdict::Accept => "Accept",
            Verdict::RejectRpId => "RejectRpId",
            Verdict::InvalidInput => "InvalidInput",
        });
    }
    for kind in ["Accept", "RejectRpId", "InvalidInput"] {
        assert!(
            seen.contains(kind),
            "the generator never produced {kind:?} in 3000 draws: {seen:?}"
        );
    }
}

/// The main differential property, PR budget, fixed seeds.
#[test]
fn inv64_oracle_agrees_with_verify_rp_id() {
    run_batch(PR_CASES, Seeds::Fixed);
}

/// The nightly budget: [`PR_CASES`] × [`NIGHTLY_MULTIPLIER`] on fresh seeds (mirrors
/// `crates/rizzy-sync/src/convergence/generate.rs`'s pattern; not wired into any CI job).
#[test]
#[ignore = "nightly budget: 40x the PR cases on fresh seeds"]
fn nightly_inv64_oracle_agrees_with_verify_rp_id() {
    run_batch(PR_CASES * NIGHTLY_MULTIPLIER, Seeds::Fresh);
}

// ---------------------------------------------------------------------------------------------
// Golden cases lifted from INV-64's and ADR 0039 §2's own prose, and one named-finding probe.
// ---------------------------------------------------------------------------------------------

mod golden {
    use chacha20::ChaCha20Rng;
    use rand_core::SeedableRng as _;
    use rizzy_client::ClientError;
    use rizzy_client::passkey::create_credential;

    fn verdict(origin: &str, rp_id: &str) -> Result<(), ClientError> {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        create_credential(&mut rng, origin, rp_id, b"c").map(|_| ())
    }

    /// Not a security property (INV-64 says nothing about ports), but `clientDataJSON`'s
    /// `"origin"` is a relying party's own exact-origin comparison surface: a ported origin
    /// whose port gets silently dropped would make `create_credential` write a `clientDataJSON`
    /// the RP's own check could reject. Cheap to check directly here since
    /// `created_credential_client_data_json_origin_has_no_path_or_query` in `passkey.rs`'s own
    /// unit tests only covers path/query stripping, never a non-default port.
    #[test]
    fn client_data_json_origin_keeps_a_non_default_port() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let created = create_credential(&mut rng, "https://example.com:8443", "example.com", b"c")
            .expect("origin and rp_id are valid for INV-64");
        let text = core::str::from_utf8(&created.client_data_json).expect("ASCII JSON");
        assert!(
            text.contains(r#""origin":"https://example.com:8443""#),
            "clientDataJSON must keep the origin's non-default port verbatim: {text}"
        );
    }

    #[test]
    fn evil_example_cannot_claim_bank_com() {
        assert_eq!(
            verdict("https://evil.example", "bank.com"),
            Err(ClientError::RpIdRejected)
        );
    }

    #[test]
    fn bare_suffix_co_uk_and_github_io_are_rejected() {
        assert_eq!(
            verdict("https://attacker.co.uk", "co.uk"),
            Err(ClientError::RpIdRejected)
        );
        assert_eq!(
            verdict("https://someuser.github.io", "github.io"),
            Err(ClientError::RpIdRejected)
        );
    }

    /// INV-64's text and ADR 0039 §2 both say "the origin is HTTPS"/"It requires HTTPS" with no
    /// stated exception. The task that commissioned this harness described the `WebAuthn` rule
    /// informally as "https only except localhost" (a real `W3C` `WebAuthn` secure-context
    /// convention), but that exception is not in the ADR/INV-64 text this project's `rizzy-core`
    /// repo governs, and the implementation does not carve one out either: this is a documented,
    /// intentional match between the two, not a deviation. Asserted here as the harness's own
    /// record that it checked, rather than silently assumed the stricter reading.
    #[test]
    fn no_localhost_exception_over_plain_http() {
        assert_eq!(
            verdict("http://localhost", "localhost"),
            Err(ClientError::RpIdRejected),
            "ADR 0039 §2 and INV-64 require HTTPS unconditionally; if this ever starts \
             accepting a plain-HTTP localhost origin, that is a new, undocumented exception \
             and this assertion should change only alongside an ADR update"
        );
    }

    #[test]
    fn dotless_localhost_is_accepted_over_https() {
        assert_eq!(verdict("https://localhost", "localhost"), Ok(()));
    }

    #[test]
    fn ip_literal_rp_id_rejected_even_matching_an_ip_literal_origin() {
        assert_eq!(
            verdict("https://192.168.1.1", "192.168.1.1"),
            Err(ClientError::RpIdRejected)
        );
    }
}
