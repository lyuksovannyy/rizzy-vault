//! Seeded random scenarios for the random explorer, one generator per flavour. Each answer's
//! flavour is kept as its spike copy built it, so a seed reproduces the same scenario.

use crate::config::FaultFilter;
use crate::explore::{Scenario, Schedule};
use crate::replica::Fault;
use crate::rng::XorShift;
use crate::world::Act;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    /// Edits, trash, restore, purge, snapshots, compaction.
    Merge,
    /// Also rotation, lost responses, revocation and a server restore (all honest).
    Ops,
    /// Also faulty snapshots (omission and claims only).
    Faulty,
    /// Answer 1: absorption-heavy merge schedules, many snapshots and `worker` runs, concurrent
    /// purges, a fresh device that learns the item only through bodiless headers and covers.
    Absorb,
    /// Answer 2: a backup at a random point and one or two restores in every run, lost devices, a
    /// fresh device, rotation, lost responses and revocation (all honest).
    Heal,
    /// Answer 3: offline purges, trash and edits across rotations, lost responses (some on a
    /// re-issued version), snapshots, compaction, a restore and a revocation in some runs.
    Reissue,
    /// `Reissue` without restore and revocation.
    ReissueNoRestore,
    /// Answer 4: faulty snapshots of every kind from one faulty device, a fresh device.
    FaultsOnly,
    /// `FaultsOnly` plus rotation, lost responses, revocation and a server restore.
    FaultsOps,
    /// `FaultsOnly` with every device allowed to write faulty snapshots.
    FaultsMulti,
    /// Answer 5: one revocation at a random point, sometimes of a lost device; snapshots uploaded
    /// before their ops; a fresh device.
    Rev,
    /// `Rev`, and the device to be revoked uploads snapshots that claim its own next dot.
    RevCompromised,
    /// `Rev` with a server restore before or after the revocation.
    RevRestore,
}

pub const FLAVORS: &[Flavor] = &[
    Flavor::Merge,
    Flavor::Ops,
    Flavor::Faulty,
    Flavor::Absorb,
    Flavor::Heal,
    Flavor::Reissue,
    Flavor::ReissueNoRestore,
    Flavor::FaultsOnly,
    Flavor::FaultsOps,
    Flavor::FaultsMulti,
    Flavor::Rev,
    Flavor::RevCompromised,
    Flavor::RevRestore,
];

impl Flavor {
    pub fn family(self) -> &'static str {
        match self {
            Flavor::Merge => "random",
            Flavor::Ops => "random-ops",
            Flavor::Faulty => "random-faulty",
            Flavor::Absorb => "random-absorb",
            Flavor::Heal => "random-heal",
            Flavor::Reissue => "random-reissue",
            Flavor::ReissueNoRestore => "random-reissue-norestore",
            Flavor::FaultsOnly => "random-faults",
            Flavor::FaultsOps => "random-faults-ops",
            Flavor::FaultsMulti => "random-faults-multi",
            Flavor::Rev => "random-rev",
            Flavor::RevCompromised => "random-rev-compromised",
            Flavor::RevRestore => "random-rev-restore",
        }
    }

    pub fn by_name(name: &str) -> Option<Flavor> {
        FLAVORS.iter().copied().find(|f| f.family() == name)
    }
}

/// Build the random scenario of `seed` for `flavor`.
pub fn random_scenario(
    rng: &mut XorShift,
    flavor: Flavor,
    seed: u64,
    filter: FaultFilter,
) -> Scenario {
    match flavor {
        Flavor::Merge | Flavor::Ops | Flavor::Faulty => random_base_scenario(rng, flavor, seed),
        Flavor::Absorb => random_absorb_scenario(rng, seed),
        Flavor::Heal => random_heal_scenario(rng, seed),
        Flavor::Reissue => random_reissue_scenario(rng, seed, false),
        Flavor::ReissueNoRestore => random_reissue_scenario(rng, seed, true),
        Flavor::FaultsOnly | Flavor::FaultsOps | Flavor::FaultsMulti => {
            random_scenario_faults(rng, flavor, seed, filter)
        }
        Flavor::Rev | Flavor::RevCompromised | Flavor::RevRestore => {
            random_rev_scenario(rng, flavor, seed)
        }
    }
}

fn random_base_scenario(rng: &mut XorShift, flavor: Flavor, seed: u64) -> Scenario {
    let n_dev = 3 + rng.below(2);
    let mut setup = vec![(0, Act::Write(vec![("a", 1), ("b", 2)])), (0, Act::Sync)];
    for d in 1..n_dev {
        setup.push((d, Act::Sync));
    }
    if flavor != Flavor::Merge {
        setup.push((n_dev, Act::Checkpoint(0)));
    }
    let mut val = 10u32;
    let mut programs = Vec::new();
    let mut revoked = false;
    for d in 0..n_dev {
        let len = 3 + rng.below(6);
        let mut p = Vec::new();
        for _ in 0..len {
            let r = rng.below(100);
            let act = match r {
                0..=29 => {
                    val += 1;
                    let k = if rng.chance(60) { "a" } else { "b" };
                    Act::Write(vec![(k, val + 100 * d as u32)])
                }
                30..=37 => Act::Trash,
                38..=42 => Act::Restore,
                43..=51 => Act::Purge,
                52..=59 => Act::Snapshot,
                60..=69 => Act::Upload,
                70..=79 => Act::Fetch,
                _ => Act::Sync,
            };
            p.push(act);
            if flavor != Flavor::Merge {
                let x = rng.below(100);
                if x < 3 {
                    p.push(Act::Rotate);
                } else if x < 6 {
                    p.push(Act::SyncLost);
                } else if x < 9 && flavor == Flavor::Faulty {
                    let f = if rng.chance(50) {
                        Fault::OmitValue
                    } else {
                        Fault::ClaimNext(rng.below(n_dev) as u8)
                    };
                    p.push(Act::Faulty(f));
                } else if x < 11 && !revoked {
                    let t = (d + 1 + rng.below(n_dev - 1)) % n_dev;
                    p.push(Act::Revoke(t as u8));
                    revoked = true;
                }
            }
        }
        programs.push(p);
    }
    let mut sp = Vec::new();
    for _ in 0..rng.below(3) {
        sp.push(Act::Worker);
    }
    if flavor != Flavor::Merge && rng.chance(25) {
        let at = rng.below(sp.len() + 1);
        sp.insert(at, Act::RestoreServer(0));
    }
    programs.push(sp);
    let family = flavor.family();
    Scenario {
        family,
        name: format!("seed-{seed}"),
        n_dev,
        skew: vec![0; n_dev],
        setup,
        programs,
        max_values: None,
    }
}

/// `Flavor::Absorb`: 2-3 writers that snapshot often, a fresh device (the last one) that fetches
/// only at the end of its program, and 2-5 `worker` runs.
fn random_absorb_scenario(rng: &mut XorShift, seed: u64) -> Scenario {
    let writers = 2 + rng.below(2);
    let n_dev = writers + 1;
    let mut setup = vec![(0, Act::Write(vec![("a", 1), ("b", 2)])), (0, Act::Sync)];
    for d in 1..writers {
        setup.push((d, Act::Sync));
    }
    if rng.chance(50) {
        // Trashed: purges are possible from the start.
        setup.push((0, Act::Trash));
        setup.push((0, Act::Sync));
        for d in 1..writers {
            setup.push((d, Act::Sync));
        }
    }
    let mut val = 10u32;
    let mut programs = Vec::new();
    for d in 0..writers {
        let len = 4 + rng.below(6);
        let mut p = Vec::new();
        for _ in 0..len {
            let act = match rng.below(100) {
                0..=31 => {
                    val += 1;
                    let k = if rng.chance(60) { "a" } else { "b" };
                    Act::Write(vec![(k, val + 100 * d as u32)])
                }
                32..=38 => Act::Trash,
                39..=42 => Act::Restore,
                43..=51 => Act::Purge,
                52..=69 => Act::Snapshot,
                70..=79 => Act::Upload,
                80..=89 => Act::Fetch,
                _ => Act::Sync,
            };
            p.push(act);
        }
        programs.push(p);
    }
    // The fresh device.
    let fresh = if rng.chance(50) {
        vec![Act::Fetch]
    } else {
        vec![Act::Fetch, Act::Fetch]
    };
    programs.push(fresh);
    let mut sp = Vec::new();
    for _ in 0..2 + rng.below(4) {
        sp.push(Act::Worker);
    }
    programs.push(sp);
    Scenario {
        family: "random-absorb",
        name: format!("seed-{seed}"),
        n_dev,
        skew: vec![0; n_dev],
        setup,
        programs,
        max_values: None,
    }
}

/// `random-heal`: 3-5 devices, one of them possibly fresh (never synced in the setup); device
/// programs of edits, trash, restore, purge, snapshots, uploads and fetches, with rare rotations,
/// lost responses and one revocation; up to n-2 devices lost at the end of their program. The
/// server takes the backup at a random point of the interleaving and restores it once or twice,
/// with `worker` runs around.
fn random_heal_scenario(rng: &mut XorShift, seed: u64) -> Scenario {
    let n_dev = 3 + rng.below(3);
    let fresh = if rng.chance(40) {
        Some(1 + rng.below(n_dev - 1))
    } else {
        None
    };
    let mut setup = vec![(0, Act::Write(vec![("a", 1), ("b", 2)])), (0, Act::Sync)];
    for d in 1..n_dev {
        if Some(d) != fresh {
            setup.push((d, Act::Sync));
        }
    }
    if rng.chance(30) {
        setup.push((0, Act::Snapshot));
        setup.push((0, Act::Upload));
    }
    let mut val = 10u32;
    let mut programs = Vec::new();
    let mut revoked = false;
    let mut lost = 0usize;
    for d in 0..n_dev {
        let len = 2 + rng.below(6);
        let mut p = Vec::new();
        for _ in 0..len {
            let act = match rng.below(100) {
                0..=29 => {
                    val += 1;
                    let k = if rng.chance(60) { "a" } else { "b" };
                    Act::Write(vec![(k, val + 100 * d as u32)])
                }
                30..=36 => Act::Trash,
                37..=40 => Act::Restore,
                41..=48 => Act::Purge,
                49..=58 => Act::Snapshot,
                59..=68 => Act::Upload,
                69..=79 => Act::Fetch,
                _ => Act::Sync,
            };
            p.push(act);
            let x = rng.below(100);
            if x < 3 {
                p.push(Act::Rotate);
            } else if x < 6 {
                p.push(Act::SyncLost);
            } else if x < 8 && !revoked {
                let t = (d + 1 + rng.below(n_dev - 1)) % n_dev;
                p.push(Act::Revoke(t as u8));
                revoked = true;
            }
        }
        if lost + 2 < n_dev && rng.chance(30) {
            p.push(Act::Sync);
            p.push(Act::Lose);
            lost += 1;
        }
        programs.push(p);
    }
    let mut sp = Vec::new();
    for _ in 0..rng.below(3) {
        sp.push(Act::Worker);
    }
    let at = rng.below(sp.len() + 1);
    sp.insert(at, Act::Checkpoint(0));
    let at = at + 1 + rng.below(sp.len() - at);
    sp.insert(at, Act::RestoreServer(0));
    if rng.chance(25) {
        sp.push(Act::Worker);
        sp.push(Act::RestoreServer(0));
    }
    programs.push(sp);
    Scenario {
        family: "random-heal",
        name: format!("seed-{seed}"),
        n_dev,
        skew: vec![0; n_dev],
        setup,
        programs,
        max_values: None,
    }
}

/// `random-reissue`: every device writes offline, purges and rotates, with lost responses (some
/// on a re-issued version, through `UploadOnce`), snapshots, compaction and sometimes a restore.
fn random_reissue_scenario(rng: &mut XorShift, seed: u64, no_restore: bool) -> Scenario {
    let no_revoke = no_restore;
    let n_dev = 3 + rng.below(2);
    let trashed = rng.chance(60);
    let mut setup = vec![(0, Act::Write(vec![("a", 1), ("b", 2)])), (0, Act::Sync)];
    for d in 1..n_dev {
        setup.push((d, Act::Sync));
    }
    if trashed {
        setup.push((0, Act::Trash));
        setup.push((0, Act::Sync));
        for d in 1..n_dev {
            setup.push((d, Act::Sync));
        }
    }
    let restore = rng.chance(30) && !no_restore;
    if restore {
        setup.push((n_dev, Act::Checkpoint(0)));
    }
    let mut val = 10u32;
    let mut programs = Vec::new();
    let mut revoked = false;
    for d in 0..n_dev {
        let len = 3 + rng.below(6);
        let mut p = Vec::new();
        for _ in 0..len {
            let r = rng.below(100);
            let act = match r {
                0..=19 => {
                    val += 1;
                    let k = if rng.chance(60) { "a" } else { "b" };
                    Act::Write(vec![(k, val + 100 * d as u32)])
                }
                20..=27 => Act::Trash,
                28..=31 => Act::Restore,
                32..=46 => Act::Purge,
                47..=53 => Act::Snapshot,
                54..=61 => Act::Upload,
                62..=65 => Act::UploadOnce,
                66..=73 => Act::Fetch,
                74..=81 => Act::Sync,
                82..=89 => Act::SyncLost,
                90..=96 => Act::Rotate,
                _ => {
                    if !revoked && !no_revoke && rng.chance(40) {
                        revoked = true;
                        Act::Revoke(((d + 1 + rng.below(n_dev - 1)) % n_dev) as u8)
                    } else {
                        Act::Rotate
                    }
                }
            };
            p.push(act);
        }
        programs.push(p);
    }
    let mut sp = Vec::new();
    for _ in 0..rng.below(3) {
        sp.push(Act::Worker);
    }
    if restore {
        let at = rng.below(sp.len() + 1);
        sp.insert(at, Act::RestoreServer(0));
    }
    programs.push(sp);
    Scenario {
        family: if no_restore {
            "random-reissue-norestore"
        } else {
            "random-reissue"
        },
        name: format!("seed-{seed}"),
        n_dev,
        skew: vec![0; n_dev],
        setup,
        programs,
        max_values: None,
    }
}

/// The faulty-snapshot flavors: every `Fault` kind, and a fresh device (never synced in the
/// setup) that learns the item through bodiless headers and covers. One device writes the faulty
/// snapshots (`FaultsMulti`: any device). `FaultsOnly` has no rotation, restore or revocation
/// (their honest residues belong to other questions); `FaultyAll` adds them.
fn random_scenario_faults(
    rng: &mut XorShift,
    flavor: Flavor,
    seed: u64,
    filter: FaultFilter,
) -> Scenario {
    let kinds: Vec<Fault> = crate::replica::ALL_FAULTS
        .iter()
        .copied()
        .filter(|f| match filter {
            FaultFilter::All => true,
            FaultFilter::Decidable => f.class() != "undetectable fabrication",
            FaultFilter::Undetectable => f.class() == "undetectable fabrication",
        })
        .collect();
    let ops = flavor == Flavor::FaultsOps;
    let n_dev = 3 + rng.below(2);
    let faulty_dev = rng.below(n_dev);
    let n_all = n_dev + 1;
    let mut setup = vec![(0, Act::Write(vec![("a", 1), ("b", 2)])), (0, Act::Sync)];
    for d in 1..n_dev {
        setup.push((d, Act::Sync));
    }
    if ops {
        setup.push((n_all, Act::Checkpoint(0)));
    }
    let mut val = 10u32;
    let mut programs = Vec::new();
    let mut revoked = false;
    for d in 0..n_dev {
        let len = 3 + rng.below(6);
        let mut p = Vec::new();
        for _ in 0..len {
            let r = rng.below(100);
            // More snapshots than the merge flavor, so that compaction has two (or two
            // authors') covers and the fresh device meets bodiless headers.
            let act = match r {
                0..=29 => {
                    val += 1;
                    let k = if rng.chance(60) { "a" } else { "b" };
                    Act::Write(vec![(k, val + 100 * d as u32)])
                }
                30..=35 => Act::Trash,
                36..=38 => Act::Restore,
                39..=45 => Act::Purge,
                46..=62 => Act::Snapshot,
                63..=70 => Act::Upload,
                71..=78 => Act::Fetch,
                _ => Act::Sync,
            };
            p.push(act);
            let x = rng.below(100);
            if ops && x < 3 {
                p.push(Act::Rotate);
            } else if ops && x < 6 {
                p.push(Act::SyncLost);
            } else if (6..16).contains(&x) && (flavor == Flavor::FaultsMulti || d == faulty_dev) {
                let f = match kinds[rng.below(kinds.len())] {
                    Fault::ClaimNext(_) => Fault::ClaimNext(rng.below(n_dev) as u8),
                    Fault::ClaimValue(_) => Fault::ClaimValue(rng.below(n_dev) as u8),
                    k => k,
                };
                p.push(Act::Faulty(f));
            } else if ops && (16..18).contains(&x) && !revoked {
                let t = (d + 1 + rng.below(n_dev - 1)) % n_dev;
                p.push(Act::Revoke(t as u8));
                revoked = true;
            }
        }
        programs.push(p);
    }
    // The fresh device fetches at most once before the drain (so it often first meets the item
    // after compaction); the server runs `worker` two to four times.
    let mut p = Vec::new();
    if rng.chance(40) {
        p.push(Act::Fetch);
    }
    programs.push(p);
    let mut sp = Vec::new();
    for _ in 0..2 + rng.below(3) {
        sp.push(Act::Worker);
    }
    if ops && rng.chance(25) {
        let at = rng.below(sp.len() + 1);
        sp.insert(at, Act::RestoreServer(0));
    }
    programs.push(sp);
    Scenario {
        family: flavor.family(),
        name: format!("seed-{seed}"),
        n_dev: n_all,
        skew: vec![0; n_all],
        setup,
        programs,
        max_values: None,
    }
}

/// The revocation flavors: one device `t` is revoked by another device `r` at a random point.
fn random_rev_scenario(rng: &mut XorShift, flavor: Flavor, seed: u64) -> Scenario {
    let n_dev = 3 + rng.below(2);
    // Sometimes the last device is fresh: it never synced and fetches once, at a random point, so
    // it often learns the item only from bodiless headers and covers after the revocation.
    let fresh = n_dev == 4 && rng.chance(60);
    let mut setup = vec![(0, Act::Write(vec![("a", 1), ("b", 2)])), (0, Act::Sync)];
    for d in 1..n_dev {
        if fresh && d + 1 == n_dev {
            continue;
        }
        setup.push((d, Act::Sync));
    }
    if flavor == Flavor::RevRestore {
        setup.push((n_dev, Act::Checkpoint(0)));
    }
    let t = 1 + rng.below(n_dev - 1);
    let mut r = rng.below(n_dev - 1);
    if r >= t {
        r += 1;
    }
    let mut val = 10u32;
    let mut programs = Vec::new();
    for d in 0..n_dev {
        if fresh && d + 1 == n_dev && d != r {
            // Half the time its first fetch is in the drain, after every scheduled `worker`.
            programs.push(if rng.chance(50) {
                vec![Act::Fetch]
            } else {
                Vec::new()
            });
            continue;
        }
        let len = 3 + rng.below(6);
        let mut p = Vec::new();
        for _ in 0..len {
            let x = rng.below(100);
            let act = match x {
                0..=29 => {
                    val += 1;
                    let k = if rng.chance(60) { "a" } else { "b" };
                    Act::Write(vec![(k, val + 100 * d as u32)])
                }
                30..=36 => Act::Trash,
                37..=40 => Act::Restore,
                41..=47 => Act::Purge,
                48..=59 => Act::Snapshot,
                60..=67 => Act::Upload,
                68..=71 => Act::UploadSnaps,
                72..=81 => Act::Fetch,
                _ => Act::Sync,
            };
            let wrote = matches!(act, Act::Write(_));
            p.push(act);
            // The device to be revoked snapshots often, so that its snapshots become covers.
            if d == t && wrote && rng.chance(40) {
                p.push(Act::Snapshot);
                p.push(Act::Upload);
            }
            if flavor == Flavor::RevCompromised && d == t && rng.chance(25) {
                p.push(Act::Faulty(Fault::ClaimNext(t as u8)));
                p.push(if rng.chance(50) {
                    Act::UploadSnaps
                } else {
                    Act::Upload
                });
            }
        }
        if d == t && rng.chance(35) {
            p.push(Act::Lose);
        }
        if d == r {
            let at = rng.below(p.len() + 1);
            p.insert(at, Act::Revoke(t as u8));
        }
        programs.push(p);
    }
    let mut sp = Vec::new();
    for _ in 0..2 + rng.below(3) {
        sp.push(Act::Worker);
    }
    if flavor == Flavor::RevRestore {
        let at = rng.below(sp.len() + 1);
        sp.insert(at, Act::RestoreServer(0));
    }
    programs.push(sp);
    Scenario {
        family: flavor.family(),
        name: format!("seed-{seed} (D{r} revokes D{t})"),
        n_dev,
        skew: vec![0; n_dev],
        setup,
        programs,
        max_values: None,
    }
}

pub fn random_schedule(rng: &mut XorShift, scn: &Scenario) -> Schedule {
    let mut pos = vec![0usize; scn.programs.len()];
    let mut sched = Vec::new();
    loop {
        let avail: Vec<usize> = (0..scn.programs.len())
            .filter(|&a| pos[a] < scn.programs[a].len())
            .collect();
        if avail.is_empty() {
            break;
        }
        let a = avail[rng.below(avail.len())];
        sched.push((a, scn.programs[a][pos[a]].clone()));
        pos[a] += 1;
    }
    sched
}
