//! Generated histories (ADR 0012 §12 "Generated histories", ADR 0021 §8) and the budget.
//!
//! A history is drawn from a seed and a *family*, after the merge spike's scenario families
//! and random flavours (`scenarios.rs`, `random.rs`): each family weights the steps a device or
//! the server may take. The scheduler picks, step by step, a step kind by the family's
//! weights, then its device and item; a step that is not possible (a write by a read-only
//! device, a purge the writer rules refuse) does nothing, as in the spike. Then the network
//! goes quiet ([`World::drain`]) and the quiescent properties are checked.
//!
//! | Family | Spike families it follows | What it stresses |
//! |---|---|---|
//! | `edits` | `concurrent-edits`, `random` | concurrent edits of one field, offline devices |
//! | `purges` | `purges`, `edit-purge`, `trash-restore` | trash, restore, concurrent purges, late edits from offline devices |
//! | `snapshots` | `snapshots`, `absorb`, `compaction`, `random-absorb` | snapshots from several devices, absorption, `worker` paused and resumed, snapshots uploaded before the ops they cover, a device enrolled late |
//! | `long` | the 32-op trigger, history pruning | many edits of one key: the §10 trigger and the 50-value history |
//! | `restore` | `restore`, `healing`, `random-heal` | backups, restores, healing requests with bodiless headers, re-uploads, own ops sent without an answer across a restore |
//! | `revocation` | `revocation`, `rev-*`, `random-rev` | revocations at any point, offline revoked devices |
//! | `faults` | the delivery shuffles of `random` | pages, shuffled and duplicated records and pages, lost answers |
//! | `mixed` | `random-ops` | all of the above, restores and revocations in separate runs |
//! | `faulty` | `faulty`, `faulty-kinds`, `random-faults` | one faulty device writing the lies of [`super::faults`] (claims of held and unheld dots up to `u64::MAX`, omissions, a known write recorded as the purge); a device parked across a first drain and a device enrolled after it, which meet the lies as covers |
//!
//! In every family but `long`, one write in eight writes several keys in one op; the key pool
//! ([`super::KEYS`]) holds list elements with prefix-related keys.
//!
//! **Budget** (ADR 0012 §12): every PR runs [`PR_CASES`] generated histories of the main test
//! and [`PR_GAP_CASES`] of the gap-detection test; the `#[ignore]`d `nightly_*` tests run 100
//! times more on fresh seeds (`cargo test --release -p rizzy-sync -- --ignored`; no CI job runs
//! them yet). PR runs draw fixed `(family, seed)` pairs, so they are never flaky. Every failure
//! prints its family and seed, which reproduce the history; a fixed failing pair goes into
//! [`REGRESSIONS`]. Each run checks properties 1, 2, 3, 4, 6 and 7 and the ADR 0021 §8 server
//! properties together, so a case counts for each of them.

use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};

use super::faults::Fault;
use super::oracle::Rng;
use super::world::{Faults, Step, World};
use crate::causal::Report;
use crate::merge::ItemLifecycle;

/// The families, by index.
const FAMILIES: [&str; 9] = [
    "edits",
    "purges",
    "snapshots",
    "long",
    "restore",
    "revocation",
    "faults",
    "mixed",
    "faulty",
];

/// Generated histories per PR run of the main test (ADR 0012 §12: "starting at 1,000").
const PR_CASES: u32 = 1_000;

/// Generated histories per PR run of the gap-detection test.
const PR_GAP_CASES: u32 = 1_000;

/// Fixed seeds that once failed, run on every PR: `(family, seed)`.
const REGRESSIONS: [(usize, u64); 3] = [
    // A restore to an empty backup: own acknowledged ops without bodies need a fresh snapshot
    // that covers own unacknowledged ops too (the healing closure in `device`).
    (4, 11_895_903_307_134_407_466),
    // A paged response splits a tombstone cover from its recorded purge (`World::drain`; the named finding test pins it).
    (7, 8_380_964_389_207_079_218),
    (7, 16_352_471_332_150_547_450),
];

/// The step kinds a family weights.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// A field write (sometimes of several keys in one op).
    Write,
    /// A trash.
    Trash,
    /// A restore.
    Restore,
    /// A purge, preferably of an item the device shows trashed.
    Purge,
    /// An explicit snapshot.
    Snapshot,
    /// A dishonest snapshot by the faulty device.
    Lie,
    /// An upload.
    Upload,
    /// An upload that sends the unsent snapshots before the ops.
    UploadEarly,
    /// A Fetch.
    Fetch,
    /// Offline or back.
    Toggle,
    /// `worker`.
    Worker,
    /// A backup.
    Backup,
    /// A restore of the server.
    RestoreServer,
    /// A revocation.
    Revoke,
}

/// The weights of a family.
fn weights(family: &str) -> Vec<(Kind, u64)> {
    use Kind::{
        Backup, Fetch, Lie, Purge, Restore, RestoreServer, Revoke, Snapshot, Toggle, Trash, Upload,
        UploadEarly, Worker, Write,
    };
    match family {
        "edits" | "faults" => vec![
            (Write, 50),
            (Upload, 15),
            (Fetch, 20),
            (Toggle, 5),
            (Snapshot, 3),
            (Worker, 3),
            (Trash, 2),
            (Restore, 2),
        ],
        "purges" => vec![
            (Write, 25),
            (Trash, 12),
            (Restore, 5),
            (Purge, 12),
            (Upload, 15),
            (Fetch, 18),
            (Toggle, 8),
            (Snapshot, 3),
            (Worker, 3),
        ],
        "snapshots" => vec![
            (Write, 30),
            (Snapshot, 15),
            (UploadEarly, 5),
            (Worker, 12),
            (Upload, 15),
            (Fetch, 20),
            (Toggle, 3),
            (Trash, 2),
            (Purge, 3),
        ],
        "long" => vec![
            (Write, 70),
            (Upload, 10),
            (Fetch, 12),
            (Snapshot, 2),
            (Worker, 5),
        ],
        "restore" => vec![
            (Write, 30),
            (Upload, 15),
            (Fetch, 20),
            (Snapshot, 8),
            (Worker, 8),
            (UploadEarly, 2),
            (Backup, 3),
            (RestoreServer, 3),
            (Toggle, 3),
            (Trash, 2),
            (Purge, 2),
        ],
        "revocation" => vec![
            (Write, 35),
            (Upload, 15),
            (Fetch, 20),
            (Toggle, 5),
            (Snapshot, 10),
            (Worker, 5),
            (Revoke, 4),
            (Trash, 3),
            (Purge, 3),
        ],
        "faulty" => vec![
            (Write, 30),
            (Upload, 15),
            (Fetch, 20),
            (Snapshot, 8),
            (Lie, 10),
            (Worker, 8),
            (Toggle, 6),
            (Trash, 3),
            (Restore, 2),
            (Purge, 3),
            (UploadEarly, 1),
        ],
        _ => vec![
            (Write, 30),
            (Trash, 5),
            (Restore, 3),
            (Purge, 5),
            (Upload, 15),
            (Fetch, 18),
            (Toggle, 5),
            (Snapshot, 6),
            (Worker, 6),
            (UploadEarly, 2),
            (Backup, 1),
            (RestoreServer, 1),
            (Revoke, 1),
        ],
    }
}

/// Picks the next step of `family` for `world`. `restores` says whether this run may restore
/// the server (then it may not revoke).
fn pick(world: &World, family: &str, rng: &mut Rng, restores: bool) -> Step {
    let table = weights(family);
    let total: u64 = table.iter().map(|(_, w)| w).sum();
    let mut roll = rng.next() % total.max(1);
    let mut kind = Kind::Write;
    for (k, w) in table {
        if roll < w {
            kind = k;
            break;
        }
        roll -= w;
    }
    let n = world.len();
    // "long": two writers, one key, one item, most of the time.
    let d = if family == "long" && matches!(kind, Kind::Write) {
        rng.below(2.min(n))
    } else {
        rng.below(n)
    };
    let i = if family == "long" && rng.chance(9, 10) {
        0
    } else {
        rng.below(world.items.len())
    };
    let k = if family == "long" && rng.chance(9, 10) {
        0
    } else {
        rng.below(super::KEYS.len())
    };
    match kind {
        // One write in eight writes several keys in one op, list elements among them.
        Kind::Write if family != "long" && rng.chance(1, 8) => {
            let all = (1_u16 << super::KEYS.len()) - 1;
            let bits = u16::try_from(rng.next() % u64::from(all)).unwrap_or(0) + 1;
            Step::WriteMany {
                d,
                i,
                mask: u8::try_from(bits & all).unwrap_or(1),
            }
        }
        Kind::Write => Step::Write { d, i, k },
        Kind::Lie => Step::Lie {
            d: world.faulty().unwrap_or(d),
            i,
            fault: rng.below(super::faults::ALL.len()),
        },
        Kind::Trash => Step::Trash { d, i },
        Kind::Restore => Step::Restore { d, i },
        Kind::Purge => {
            // Prefer an item this device shows trashed, so that the writer rules allow it.
            let trashed =
                (0..world.items.len()).find(|&j| world.lifecycle(d, j) == ItemLifecycle::Trashed);
            Step::Purge {
                d,
                i: trashed.unwrap_or(i),
            }
        }
        Kind::Snapshot => Step::Snapshot { d, i },
        Kind::Upload => Step::Upload {
            d,
            // Lost answers, also where the server may then be restored: an own op sent
            // without an answer across a restore (the spike's `stale_sent_resolution`).
            lose: matches!(family, "faults" | "restore" | "mixed") && rng.chance(1, 3),
        },
        Kind::UploadEarly => Step::UploadEarly { d },
        Kind::Toggle => Step::Toggle { d },
        Kind::Worker => Step::Worker,
        Kind::Backup if restores => Step::Backup,
        Kind::RestoreServer if restores => Step::RestoreServer,
        Kind::Revoke if !restores => Step::Revoke { d },
        // A restore and a revocation are not combined in one run (see [`super::world`]).
        Kind::Backup | Kind::RestoreServer | Kind::Revoke | Kind::Fetch => Step::Fetch { d },
    }
}

/// Runs one generated history of `family` from `seed` and checks every property.
///
/// # Errors
/// The first violation, with the run's coverage.
pub(super) fn run(family: usize, seed: u64) -> Result<(), String> {
    history(family, seed).verdict()
}

/// The world of one generated history of `family` from `seed`, run to quiescence and checked.
fn history(family: usize, seed: u64) -> World {
    let name = FAMILIES.get(family).copied().unwrap_or("mixed");
    let mut rng = Rng::new(seed);
    let devices = 3 + rng.below(5);
    let late = matches!(
        name,
        "snapshots" | "restore" | "purges" | "mixed" | "faulty"
    ) && rng.chance(1, 2);
    let joined = if late { devices - 1 } else { devices };
    let faults = if matches!(name, "faults" | "mixed") {
        Faults {
            page_len: rng.below(4),
            shuffle: rng.chance(1, 2),
            duplicate: rng.chance(1, 2),
            page_in_drain: false,
        }
    } else {
        Faults::default()
    };
    let restores = match name {
        "restore" => true,
        "mixed" => rng.chance(1, 2),
        _ => false,
    };
    let steps = if name == "long" {
        90 + rng.below(60)
    } else {
        20 + rng.below(50)
    };
    let join_at = rng.below(steps);
    let mut world = World::new(devices, joined, 2, rng.next(), faults);
    if name == "faulty" {
        // One faulty device (ADR 0021 §3: "One faulty device never holds the only server
        // copy"; f faulty devices need f + 1 authors, beyond this harness's one).
        let d = rng.below(joined);
        world.set_faulty(d, None);
    }
    if restores {
        world.step(Step::Backup);
    }
    // In the `faulty` family the late device enrols after a first drain, once `worker` has
    // compacted behind the lies: a new device that must take everything from covers (ADR 0021
    // §8 "then a new device").
    let fresh_after = late && name == "faulty";
    // And a device other than the faulty one may sit out the first drain, holding the bodies
    // it merged, so that it meets the lies about them as covers.
    let parked = if name == "faulty" && rng.chance(1, 2) {
        (0..joined).find(|&d| Some(d) != world.faulty())
    } else {
        None
    };
    let park_at = rng.below(steps);
    for s in 0..steps {
        if late && !fresh_after && s == join_at {
            world.join(devices - 1);
        }
        if let Some(p) = parked
            && s == park_at
        {
            world.park(p, true);
        }
        let step = pick(&world, name, &mut rng, restores);
        world.step(step);
    }
    if (fresh_after || parked.is_some())
        && let Some(f) = world.faulty()
    {
        // The faulty device's last snapshots are lies the server stores, so that they are the
        // newest covers when the parked or new device fetches.
        world.step(Step::Fetch { d: f });
        for i in 0..world.items.len() {
            let stored = [Fault::ClaimHeld, Fault::OmitValue, Fault::FakeTomb];
            let fault = stored.get(rng.below(stored.len())).copied();
            let index = super::faults::ALL
                .iter()
                .position(|k| Some(*k) == fault)
                .unwrap_or(0);
            world.step(Step::Lie {
                d: f,
                i,
                fault: index,
            });
        }
        world.step(Step::Upload { d: f, lose: false });
    }
    if (fresh_after || parked.is_some()) && !world.drain() {
        world
            .violations
            .push("the first drain did not reach quiescence".to_owned());
    }
    if let Some(p) = parked {
        world.park(p, false);
    }
    if late {
        world.join(devices - 1);
    }
    if !world.drain() {
        world
            .violations
            .push("the drain did not reach quiescence".to_owned());
    }
    world.check_quiescent(2);
    world
}

/// Runs one gap-detection history (property 7, ADR 0012 §12 "a server that withholds an op on
/// one item while serving a compacted snapshot of another"): a writer edits two items, the
/// others snapshot and compact, then the server withholds one of the writer's ops, with a later
/// op of the same chain, from a device that was offline. That device must report the gap on the
/// writer's chain and settle nothing of it at or past the withheld op, on any item, whether or
/// not other items were compacted. Then the server stops withholding, and the run must converge.
///
/// # Errors
/// The first violation.
pub(super) fn run_gap(seed: u64) -> Result<(), String> {
    let mut rng = Rng::new(seed);
    let devices = 3 + rng.below(3);
    let mut world = World::new(devices, devices, 2, rng.next(), Faults::default());
    let victim = devices - 1;
    world.step(Step::Toggle { d: victim });
    let writes = 3 + rng.below(12);
    for _ in 0..writes {
        let i = usize::from(rng.chance(1, 4));
        let k = rng.below(super::KEYS.len());
        world.step(Step::Write { d: 0, i, k });
        if rng.chance(1, 3) {
            world.step(Step::Upload { d: 0, lose: false });
        }
    }
    world.step(Step::Upload { d: 0, lose: false });
    // Two authors snapshot item 0, and `worker` compacts it (ADR 0021 §3).
    for d in 0..2 {
        world.step(Step::Fetch { d });
        if rng.chance(3, 4) {
            world.step(Step::Snapshot { d, i: 0 });
        }
        world.step(Step::Upload { d, lose: false });
    }
    if rng.chance(3, 4) {
        world.step(Step::Worker);
    }
    let chain: Vec<crate::dot::Dot> = {
        let mut all = world.dots_of(0, 0);
        all.extend(world.dots_of(0, 1));
        all.sort();
        all
    };
    // A withheld op with a later link, so the chain check can see the gap.
    let Some(&withheld) = chain.get(rng.below(chain.len().saturating_sub(1))) else {
        return Ok(());
    };
    if chain.last() == Some(&withheld) {
        return Ok(());
    }
    world.withhold(victim, Some(withheld));
    world.step(Step::Toggle { d: victim });
    world.step(Step::Fetch { d: victim });
    let author = world.id(0);
    let Some(dev) = world.devices.get(victim) else {
        return Err("no victim".to_owned());
    };
    let reported = dev
        .reports
        .iter()
        .chain(&dev.last_complete)
        .any(|r| matches!(r, Report::Gap { device, .. } if Some(*device) == author));
    if !reported {
        return Err(format!(
            "property 7: the withheld op {withheld:?} was not reported"
        ));
    }
    let head = author.map_or(0, |w| dev.log.head(w));
    if head >= withheld.seq() {
        return Err(format!(
            "property 7: the chain went past the withheld op {withheld:?}"
        ));
    }
    if let Some(item) = world.item_of(withheld) {
        let in_merge = dev
            .items
            .get(&item)
            .is_some_and(|m| m.covered().covers(withheld));
        if in_merge || dev.log.settled(item).covers(withheld) {
            return Err(format!("property 7: {withheld:?} counted as settled"));
        }
    }
    world.withhold(victim, None);
    if !world.drain() {
        world
            .violations
            .push("the drain did not reach quiescence".to_owned());
    }
    // The victim reported a gap during the fault; the quiescent checks must not count it.
    if let Some(dev) = world.devices.get_mut(victim) {
        dev.reports.clear();
    }
    world.check_quiescent(1);
    world.verdict()
}

/// The proptest configuration for `cases` cases, with no failure file (the no-I/O crate's
/// clippy lists forbid filesystem access; failing seeds go into [`REGRESSIONS`]). Its
/// `rng_seed` is proptest's default: `PROPTEST_RNG_SEED` if set, else a fresh random seed,
/// read by proptest itself.
fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Where the `(family, seed)` pairs of a batch come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seeds {
    /// Proptest's deterministic RNG: the same pairs on every run, so a PR run is never flaky.
    Fixed,
    /// The configuration's `rng_seed` ([`config`]): the nightly job explores fresh pairs every
    /// night, or the pairs of `PROPTEST_RNG_SEED` when the job sets it (for example from the
    /// date), so that 30 green nights test 30 different batches (ADR 0012 open question 5).
    Fresh,
}

/// Runs `cases` cases of `test` on `(family, seed)` pairs drawn as `seeds` says. Every failure
/// names its `(family, seed)`, which reproduces the history exactly (`run(family, seed)`), and
/// the batch's `rng_seed`; a fixed failing pair goes into [`REGRESSIONS`] (ADR 0012 §12
/// "Budget": "Every failure prints its seed").
fn run_cases(
    cases: u32,
    families: usize,
    seeds: Seeds,
    test: impl Fn(usize, u64) -> Result<(), String>,
) {
    let cfg = config(cases);
    let mut runner = match seeds {
        Seeds::Fixed => {
            TestRunner::new_with_rng(cfg.clone(), TestRng::deterministic_rng(cfg.rng_algorithm))
        }
        Seeds::Fresh => TestRunner::new(cfg.clone()),
    };
    let result = runner.run(&(0..families.max(1), any::<u64>()), |(family, seed)| {
        test(family, seed)
            .map_err(|e| TestCaseError::fail(format!("family {family} seed {seed:#x}: {e}")))
    });
    if let Err(e) = result {
        panic!("{e} (batch rng_seed {:?})", cfg.rng_seed);
    }
}

/// Properties 1, 2, 3, 4, 6 and 7 on [`PR_CASES`] generated histories of every family.
#[test]
fn generated_histories_hold_the_properties() {
    run_cases(PR_CASES, FAMILIES.len(), Seeds::Fixed, run);
}

/// Property 7 on [`PR_GAP_CASES`] withholding histories ([`run_gap`]).
#[test]
fn withheld_ops_are_reported() {
    run_cases(PR_GAP_CASES, 1, Seeds::Fixed, |_, seed| run_gap(seed));
}

/// The fixed seeds of [`REGRESSIONS`].
#[test]
fn regression_seeds() {
    for (family, seed) in REGRESSIONS {
        if let Err(e) = run(family, seed) {
            panic!("family {family} seed {seed:#x}: {e}");
        }
    }
}

/// The nightly budget of [`generated_histories_hold_the_properties`], on fresh seeds.
///
/// No CI job runs it yet: `.github/workflows/` is the owner's to change (CLAUDE.md). The job
/// it needs: `cargo test --release -p rizzy-sync -- --ignored`, on a schedule, with
/// `PROPTEST_RNG_SEED` set per night if the batch should be reproducible as a whole.
#[test]
#[ignore = "nightly budget: 100 times the PR cases on fresh seeds (ADR 0012 §12)"]
fn nightly_generated_histories_hold_the_properties() {
    run_cases(PR_CASES * 100, FAMILIES.len(), Seeds::Fresh, run);
}

/// The nightly budget of [`withheld_ops_are_reported`], on fresh seeds.
#[test]
#[ignore = "nightly budget: 100 times the PR cases on fresh seeds (ADR 0012 §12)"]
fn nightly_withheld_ops_are_reported() {
    run_cases(PR_GAP_CASES * 100, 1, Seeds::Fresh, |_, seed| run_gap(seed));
}

/// What a batch of histories of one family reached, summed over its runs.
#[derive(Clone, Copy, Debug, Default)]
struct Reach {
    /// Runs.
    runs: u64,
    /// Bodies `worker` deleted.
    compacted: u64,
    /// Covers absorbed.
    absorbed: u64,
    /// Healing requests stored.
    heals: u64,
    /// "Already stored" answers.
    already_stored: u64,
    /// Tombstones with late values (ADR 0018 §12: "The generator must reach l > 0").
    late: u64,
    /// Revoked devices' snapshots the server refused.
    revoked_refused: u64,
    /// Own snapshots the server refused because they reached it before the ops they cover.
    early_refused: u64,
    /// Runs whose "no gap against the honest server" check was skipped for the paging
    /// finding ([`World::gap_check_skipped`]).
    gap_skipped: u64,
    /// Snapshots the property 3 replays absorbed.
    replay_absorbed: u64,
    /// Older retained snapshots checked by server property 4.
    older_kept: u64,
    /// `worker` runs on a linear item, checked by server property 5.
    linear: u64,
    /// Dishonest snapshots written.
    lies_written: u64,
    /// Tainted covers absorbed.
    lies_absorbed: u64,
    /// Tainted covers refused.
    lies_refused: u64,
    /// Items whose property 1 was excused for a reported lie.
    excused: u64,
}

/// Sums what `seeds` histories of `family` reached; every run must also pass.
fn reach(family: usize, seeds: u64) -> Reach {
    let mut r = Reach::default();
    for seed in 0..seeds {
        let w = history(family, seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        if let Err(e) = w.verdict() {
            panic!("family {family} seed {seed}: {e}");
        }
        r.runs += 1;
        r.compacted += w.server.stats.bodies_deleted;
        r.heals += w.server.stats.heals_stored;
        r.already_stored += w.server.stats.already_stored;
        r.revoked_refused += w.server.stats.revoked_refused;
        r.gap_skipped += u64::from(w.gap_check_skipped());
        r.replay_absorbed += w.replay_absorbed;
        r.older_kept += w.server.stats.worker_checks.older_kept;
        r.linear += w.server.stats.worker_checks.linear;
        r.excused += w.excused_items;
        for dev in &w.devices {
            r.absorbed += dev.stats.absorbed;
            r.early_refused += dev.stats.snapshots_refused;
            r.lies_written += dev.stats.lies_written;
            r.lies_absorbed += dev.stats.lies_absorbed;
            r.lies_refused += dev.stats.lie_refused;
            for merge in dev.items.values() {
                if let Ok(super::oracle::State::Tombstone { late, .. }) = super::oracle::held(merge)
                    && !late.is_empty()
                {
                    r.late += 1;
                }
            }
        }
    }
    r
}

/// The families reach the rules they are for: compaction and absorption, restores with
/// healing requests, re-uploads answered "already stored", late values on tombstones, revoked
/// authors' snapshots refused, the server properties 4 and 5, property 3 with absorptions,
/// and lies written, absorbed and refused. A generator that silently stopped reaching one
/// would make the property tests vacuous there. The paging finding may skip the "no gap"
/// check only in a small minority of the paged families' runs.
#[test]
fn the_families_reach_their_rules() {
    let index = |name: &str| FAMILIES.iter().position(|f| *f == name).unwrap();
    let purges = reach(index("purges"), 30);
    assert!(purges.late > 0, "{purges:?}");
    let snapshots = reach(index("snapshots"), 30);
    assert!(
        snapshots.compacted > 0
            && snapshots.early_refused > 0
            && snapshots.replay_absorbed > 0
            && snapshots.older_kept > 0,
        "{snapshots:?}"
    );
    let long = reach(index("long"), 10);
    assert!(
        long.compacted > 0 && long.absorbed > 0 && long.linear > 0,
        "{long:?}"
    );
    let restore = reach(index("restore"), 30);
    assert!(restore.heals > 0 && restore.absorbed > 0, "{restore:?}");
    let revocation = reach(index("revocation"), 60);
    assert!(revocation.revoked_refused > 0, "{revocation:?}");
    for name in ["faults", "mixed"] {
        let paged = reach(index(name), 60);
        assert!(paged.gap_skipped * 10 <= paged.runs, "{name}: {paged:?}");
        if name == "faults" {
            assert!(paged.already_stored > 0, "{paged:?}");
        }
    }
    let faulty = reach(index("faulty"), 60);
    assert!(
        faulty.lies_written > 0 && faulty.lies_absorbed > 0 && faulty.lies_refused > 0,
        "{faulty:?}"
    );
}
