//! Scenario-family runs (quick variants) that pin the spike's findings as regression checks.
//! `cargo test --release --manifest-path spikes/merge-model/Cargo.toml`.
//!
//! "holds" means no checked schedule showed the property's violation; "fails" means at least one
//! did. The full (non-quick) runs and their traces come from the explorer CLI (README.md).
#![forbid(unsafe_code)]

use merge_model::config::Config;
use merge_model::explore::{Report, run_exhaustive, run_random};
use merge_model::random::Flavor;
use merge_model::scenarios::family;

fn cfg(preset: &str, sets: &[(&str, &str)]) -> Config {
    let mut c = Config::preset(preset, 2).expect("preset");
    for (k, v) in sets {
        assert!(c.set(k, v), "{k}={v}");
    }
    c
}

fn run_with(fam: &str, c: &Config) -> Report {
    let f = family(fam).expect("family");
    run_exhaustive(fam, f(true), c)
}

fn run(fam: &str, preset: &str) -> Report {
    run_with(fam, &cfg(preset, &[]))
}

fn run_filtered(fam: &str, c: &Config, name: &str) -> Report {
    let f = family(fam).expect("family");
    let mut s = f(true);
    s.retain(|x| x.name.contains(name));
    assert!(!s.is_empty(), "{fam}/{name}");
    run_exhaustive(fam, s, c)
}

fn fails(r: &Report, prop: &str) -> u64 {
    r.prop_leaves.get(prop).copied().unwrap_or(0)
}

fn has_kind(r: &Report, prop: &str, needle: &str) -> bool {
    r.found.keys().any(|(p, k)| p == prop && k.contains(needle))
}

const CORE: &[&str] = &["P1", "P1-ref", "P2", "P3", "P3-mixed", "P3-faulty"];

fn assert_core_holds(r: &Report) {
    for p in CORE {
        assert_eq!(
            fails(r, p),
            0,
            "{} / {}: {p} failed in {} schedules",
            r.family,
            r.config,
            fails(r, p)
        );
    }
    assert!(r.leaves > 0);
}

/// Every P1-P3 violation of the report is on the ADR 0012 §6 path (a replica holds an op past a
/// revocation cut-off after a restore; answers 2 and 5 leave it open).
fn only_s6(r: &Report) -> bool {
    r.found
        .iter()
        .filter(|((p, _), _)| CORE.contains(&p.as_str()))
        .all(|((_, k), _)| k.contains("ADR 0012 §6 path"))
}

/// The op-based merge (ADR 0012 §4-§5 with ADR 0018 §3 tombstones, and the evidence merge on op
/// bodies) is order-independent in every family: P3 over ops alone never fails.
#[test]
fn op_merge_is_permutation_independent_everywhere() {
    for fam in [
        "concurrent-edits",
        "purges",
        "edit-purge",
        "trash-restore",
        "snapshots",
        "rotation",
        "restore",
        "faulty",
        "revocation",
        "oversize",
    ] {
        for c in ["literal", "integrated"] {
            let r = run(fam, c);
            assert_eq!(fails(&r, "P3"), 0, "{fam}/{c}");
        }
    }
}

/// Without snapshots absorbed, the literal reading converges with no silent loss.
#[test]
fn literal_holds_for_ops_only_families() {
    for fam in ["concurrent-edits", "edit-purge", "trash-restore"] {
        assert_core_holds(&run(fam, "literal"));
    }
}

/// ADR 0012 §7 "Freshness" / INV-25 is enforced: no replica ever accepts a lower item VV.
#[test]
fn item_vv_never_goes_backwards() {
    for fam in ["snapshots", "restore", "rotation", "faulty", "oversize"] {
        for c in [
            "literal",
            "literal-dominate",
            "join",
            "candidate",
            "integrated",
        ] {
            let r = run(fam, c);
            assert_eq!(fails(&r, "P4"), 0, "{fam}/{c}");
        }
    }
}

/// The integrated rules hold on every honest family without a restore: P1-P3, no false gap, no
/// liveness failure, the RECOMP and HLC conditions, and the re-issue checks.
#[test]
fn integrated_holds_on_honest_families() {
    for fam in [
        "concurrent-edits",
        "purges",
        "edit-purge",
        "trash-restore",
        "snapshots",
        "absorb",
        "rotation",
        "revocation",
        "rev-covers",
        "rev-unsent",
    ] {
        let r = run(fam, "integrated");
        assert_core_holds(&r);
        for p in ["GAP", "LIVE", "RECOMP", "HLC", "RT", "FORK", "KEY", "SRV"] {
            assert_eq!(fails(&r, p), 0, "{fam}: {p}");
        }
    }
}

// Answer 1: absorption.

/// The literal readings of absorption diverge on concurrent snapshots, with false gaps against an
/// honest server; the join converges but the item can no longer be rebuilt from the newest
/// snapshot and the retained ops (ADR 0012 §6) and the clock condition breaks; the integrated
/// rules (merged snapshot, HLC receipt) keep both.
#[test]
fn answer1_absorption() {
    for c in ["literal", "literal-dominate"] {
        let r = run("absorb", c);
        assert!(fails(&r, "P1") > 0 && fails(&r, "GAP") > 0, "{c}");
        assert_eq!(fails(&r, "P2"), 0, "{c}");
    }
    let j = run("absorb", "join");
    assert_core_holds(&j);
    assert!(fails(&j, "RECOMP") > 0);
    let jm = run_with(
        "absorb",
        &cfg("join", &[("merged", "yes"), ("hlc-absorb", "yes")]),
    );
    assert_core_holds(&jm);
    assert_eq!(fails(&jm, "RECOMP"), 0);
    assert_eq!(fails(&jm, "PIN"), 0);
    let i = run("absorb", "integrated");
    assert_core_holds(&i);
    assert_eq!(fails(&i, "RECOMP"), 0);
    assert!(i.cov.merged_written > 0);
    assert!(
        i.cov.conc_cases.iter().all(|&n| n > 0),
        "{:?}",
        i.cov.conc_cases
    );
    let s = run("snapshots", "join");
    assert!(fails(&s, "HLC") > 0);
    assert_eq!(fails(&run("snapshots", "integrated"), "HLC"), 0);
}

// Answer 2: restore healing.

/// Literal healing loses values silently; the integrated rules hold on every restore scenario
/// outside the ADR 0012 §6 path, and inside it nothing is lost silently.
#[test]
fn answer2_restore_healing() {
    let l = run("restore", "join");
    assert!(fails(&l, "P1") > 0 && fails(&l, "P2") > 0);
    for fam in ["restore", "healing", "oversize"] {
        let r = run(fam, "integrated");
        assert!(only_s6(&r), "{fam}");
        assert_eq!(fails(&r, "P2"), 0, "{fam}");
        assert!(!has_kind(&r, "LIVE", "read-only"), "{fam}");
        assert_eq!(fails(&r, "GAP"), 0, "{fam}");
    }
    // The earlier candidate (retained ops, cursor) misses a lost author's op that survives only
    // inside the healer's snapshot.
    assert!(fails(&run("healing", "candidate"), "P2") > 0);
}

// Answer 3: re-issued ops.

/// The integrated rules: every re-issue schedule converges, the re-issue changes nothing but
/// `item_key_id` (RT), no dot is stored in two versions (FORK), no never-stored op gets past the
/// stale-epoch check (KEY). The literal author (keep the original) diverges on `item_key_id`.
#[test]
fn answer3_reissue() {
    let r = run("reissue", "integrated");
    assert_core_holds(&r);
    for p in ["RT", "FORK", "KEY"] {
        assert_eq!(fails(&r, p), 0, "{p}");
    }
    let k = run_with("reissue", &cfg("integrated", &[("reissue", "keep")]));
    assert!(has_kind(&k, "P1", "item_key_id differs"));
    // Literal upload order without dedup: a lost response blocks the chain for good.
    let d = run_with("reissue", &cfg("integrated", &[("dedup", "none")]));
    assert!(fails(&d, "P2") > 0);
}

/// The conflict between answers 2 and 3 and its resolution: without a restore, answer 2's
/// re-publication of a sent-but-unanswered op stores bodiless headers behind one author's
/// snapshot (breaking answer 4's two-author property); the integrated rule re-issues it instead,
/// because "not stored" is authoritative while the restore generation is unchanged.
#[test]
fn stale_sent_resolution() {
    let g = run_filtered("reissue", &cfg("integrated", &[]), "purge D0:P-lost");
    assert_core_holds(&g);
    assert!(!has_kind(&g, "SRV", "healing request stored bodiless"));
    let h = run_filtered(
        "reissue",
        &cfg("integrated", &[("stale-sent", "republish")]),
        "purge D0:P-lost",
    );
    assert_core_holds(&h);
    assert!(has_kind(&h, "SRV", "healing request stored bodiless"));
}

// Answer 4: faulty snapshots.

/// Under the ADR readings a faulty cover loses data silently; under the integrated rules nothing
/// is lost, the merge is a function of the set of records, and every divergence left is reported
/// and comes from an undetectable fabrication (a lie about a compacted op's content).
#[test]
fn answer4_faulty_snapshots() {
    let c = run("faulty-kinds", "candidate");
    assert!(fails(&c, "P2") > 0);
    assert!(has_kind(&c, "P1", "[silent]"));
    let i = run("faulty-kinds", "integrated");
    assert_eq!(fails(&i, "P2"), 0);
    assert_eq!(fails(&i, "P3-faulty"), 0);
    assert_eq!(fails(&i, "P3-mixed"), 0);
    assert!(
        i.found
            .keys()
            .filter(|(p, _)| p == "P1" || p == "P1-ref")
            .all(|(_, k)| k.contains("[reported]") && k.contains("undetectable fabrication"))
    );
    assert_core_holds(&run("faulty", "integrated"));
}

// Answer 5: revocation.

/// The literal rejection of a revoked author's snapshot gives false gaps and divergence under
/// ADR 0021's server (Fetch serves only the newest cover); two-author covers happen to mask it.
/// The integrated rules hold on the honest revocation families, and a restore around a revocation
/// leaves only reported divergence on the ADR 0012 §6 path.
#[test]
fn answer5_revocation() {
    let l = run_with(
        "rev-covers",
        &cfg(
            "integrated",
            &[("revoked-snap", "reject"), ("server", "adr")],
        ),
    );
    assert!(fails(&l, "P1") > 0 && fails(&l, "GAP") > 0);
    assert_core_holds(&run("rev-named", "integrated"));
    let r = run("rev-restore", "integrated");
    assert!(only_s6(&r));
    assert_eq!(fails(&r, "P2"), 0);
    assert!(!has_kind(&r, "P1", "[silent]"));
}

/// ADR 0021 §8 server properties 1-5 hold under ADR 0021's rule; under the two-author rule the
/// only server finding is the healing request's single-author bodiless headers (answers 2 and 4).
#[test]
fn server_properties() {
    for fam in ["snapshots", "compaction", "faulty", "oversize"] {
        let r = run(fam, "join");
        assert_eq!(fails(&r, "SRV"), 0, "{fam}");
    }
    for fam in ["snapshots", "compaction", "faulty", "restore", "healing"] {
        let r = run(fam, "integrated");
        assert!(
            r.found
                .keys()
                .filter(|(p, _)| p == "SRV")
                .all(|(_, k)| k.contains("healing request stored bodiless")),
            "{fam}"
        );
    }
}

/// Every explored schedule reaches quiescence before the drain's round cap.
#[test]
fn drain_reaches_quiescence() {
    for fam in ["snapshots", "restore", "rotation", "revocation", "oversize"] {
        for c in ["literal", "integrated"] {
            let r = run(fam, c);
            assert!(
                !r.found.keys().any(|(_, k)| k.contains("round cap")),
                "{fam}/{c}"
            );
        }
    }
}

/// Seeded random schedules: the integrated rules hold on the merge, absorption, re-issue (no
/// restore), revocation (honest) and decidable-fault flavours.
#[test]
fn integrated_holds_on_random_schedules() {
    let c = cfg("integrated", &[]);
    for flavor in [
        Flavor::Merge,
        Flavor::Absorb,
        Flavor::ReissueNoRestore,
        Flavor::Rev,
        Flavor::RevCompromised,
    ] {
        let r = run_random(flavor, 1..201, &c);
        assert_core_holds(&r);
    }
    let d = run_random(
        Flavor::FaultsOnly,
        1..201,
        &cfg("integrated", &[("faults", "decidable")]),
    );
    assert_core_holds(&d);
}

/// The conflict between answers 2 and 4 and its partial resolution: a healing request that sends
/// a header without its body although the healer holds the body makes the healer's snapshots the
/// only cover of that op, so a faulty healer's later snapshot silently replaces it (random seed
/// 6327: a faulty device restores its own edit behind its own omitting snapshot). Preferring
/// bodies removes that case; a header whose body nobody holds any more stays single-author.
#[test]
fn heal_prefers_bodies_against_faulty_sole_covers() {
    let lit = run_random(
        Flavor::FaultsOps,
        6327..6328,
        &cfg("integrated", &[("bodyfirst", "no")]),
    );
    assert!(fails(&lit, "P2") > 0);
    let i = run_random(Flavor::FaultsOps, 6327..6328, &cfg("integrated", &[]));
    assert_core_holds(&i);
}
