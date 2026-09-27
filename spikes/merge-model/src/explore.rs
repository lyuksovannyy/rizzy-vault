//! Exhaustive and seeded-random exploration, trace minimisation and rendering.
//!
//! **Exhaustive.** A scenario is a setup prefix plus one program per actor (devices, then the
//! server). The explorer runs every interleaving of the programs, at the granularity of *blocks*:
//! a block is a maximal run of local actions (Write, Trash, Restore, Purge, Snapshot, Faulty)
//! followed by one communicating action. Local actions touch only their own device (its wall
//! clock is per device), so moving them to just before that device's next communicating action
//! changes no outcome; block interleavings therefore reach every outcome of the action-level
//! interleavings, which are also counted and reported. Every interleaving ends with the
//! quiescence drain and the property checks. The interleaving tree is split into subtrees at a
//! shallow depth and the subtrees run on all cores; the parts are merged in a fixed order.
//!
//! **Random.** Seeded (xorshift) scenarios, a seeded action-level interleaving and seeded
//! delivery shuffles with duplicates inside each Fetch. Every seed is reproducible on its own.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::check::{
    ANSWER_CHECKS, CORE_PROPS, CheckCtx, Violation, check_world, is_answer_check, is_core,
};
use crate::config::Config;
use crate::random::{Flavor, random_scenario, random_schedule};
use crate::replica::Status;
use crate::rng::XorShift;
use crate::world::{Act, World, actor_name};

#[derive(Clone, Debug)]
pub struct Scenario {
    pub family: &'static str,
    pub name: String,
    pub n_dev: usize,
    pub skew: Vec<u64>,
    pub setup: Vec<(usize, Act)>,
    /// One program per device, then the server's.
    pub programs: Vec<Vec<Act>>,
    /// Scenario override of `Config::max_values` (ADR 0018 §10 oversize).
    pub max_values: Option<usize>,
}

impl Scenario {
    /// Replace one device's program (scenario builders).
    pub fn with_program(mut self, dev: usize, prog: Vec<Act>) -> Self {
        self.programs[dev] = prog;
        self
    }
}

pub type Schedule = Vec<(usize, Act)>;

#[derive(Clone, Debug)]
pub struct Found {
    pub prop: &'static str,
    pub kind: String,
    /// Number of checked schedules showing it.
    pub leaves: u64,
    /// Exhaustive: index into `Report::scenarios`.
    pub scenario: usize,
    /// Random runs keep the scenario itself (the report does not keep every random scenario).
    pub scn: Option<Scenario>,
    pub schedule: Schedule,
    pub seed: Option<u64>,
    pub detail: String,
}

#[derive(Default)]
pub struct Report {
    pub family: String,
    pub config: String,
    pub scenarios: Vec<Scenario>,
    /// Schedules executed, drained and checked.
    pub leaves: u64,
    /// Action-level interleavings those schedules stand for (exhaustive families).
    pub raw_interleavings: u128,
    pub leaves_with_core_violation: u64,
    /// Schedules with a P1-P3 violation, by what the schedule contained.
    pub core_by_cause: BTreeMap<String, u64>,
    /// Random runs: the seeds with a P1-P3 violation, with their violation kinds.
    pub seed_violations: Vec<(u64, Vec<String>)>,
    pub p3_sets: u64,
    pub p3_runs: u64,
    pub found: BTreeMap<(String, String), Found>,
    /// Schedules showing each property's violation (any kind).
    pub prop_leaves: BTreeMap<String, u64>,
    /// Coverage counters summed over all checked schedules.
    pub cov: Coverage,
    /// Per scenario: (schedules checked, schedules with a P1-P3 violation). Exhaustive only.
    pub per_scenario: BTreeMap<usize, (u64, u64)>,
}

#[derive(Default, Debug, Clone)]
pub struct Coverage {
    pub bodies_deleted: u64,
    pub snapshots_dropped: u64,
    pub bodiless_served: u64,
    pub multi_cover_responses: u64,
    pub absorbed_dominating: u64,
    pub absorbed_concurrent: u64,
    pub absorb_rejected_inv25: u64,
    pub join_pruned: u64,
    pub values_pruned_at_end: u64,
    pub tombstones_at_end: u64,
    pub late_values_at_end: u64,
    /// Answer 1.
    pub conc_cases: [u64; 4],
    pub merged_written: u64,
    pub snapshots_written: u64,
    pub retained_gt2_at_end: u64,
    pub max_retained_at_end: u64,
    /// Answer 2.
    pub restores: u64,
    pub heal_requests: u64,
    pub heal_refused: u64,
    pub heal_bodiless: u64,
    pub heal_with_body: u64,
    pub heal_verbatim_snaps: u64,
    pub heal_stale_exempted: u64,
    pub claims_refused: u64,
    pub unheld_claims_stored: u64,
    /// Answer 3.
    pub reissued_ops: u64,
    pub reissued_purges: u64,
    pub recorded_purge_reissued: u64,
    pub already_stored: u64,
    pub conflicts: u64,
    pub republished_stored: u64,
    /// Answer 4.
    pub faulty_stored: u64,
    pub em_refused: u64,
    pub em_disputes: u64,
    /// Answer 5.
    pub revocations: u64,
    pub revoked_ops_only_in_snapshots: u64,
    pub revoked_bodiless_served: u64,
    pub revoked_author_covers_served: u64,
    pub revoked_snaps_accepted: u64,
    pub revoked_snaps_rejected: u64,
    pub snaps_refused_author_head: u64,
    pub revoked_stale_exempted: u64,
    pub past_cutoff_recomputed: u64,
    pub past_cutoff_flagged: u64,
    pub recompute_base_mismatch: u64,
}

impl Coverage {
    pub fn add(&mut self, q: &Coverage) {
        macro_rules! sum {
            ($($f:ident),*) => { $( self.$f += q.$f; )* };
        }
        sum!(
            bodies_deleted,
            snapshots_dropped,
            bodiless_served,
            multi_cover_responses,
            absorbed_dominating,
            absorbed_concurrent,
            absorb_rejected_inv25,
            join_pruned,
            values_pruned_at_end,
            tombstones_at_end,
            late_values_at_end,
            merged_written,
            snapshots_written,
            retained_gt2_at_end,
            restores,
            heal_requests,
            heal_refused,
            heal_bodiless,
            heal_with_body,
            heal_verbatim_snaps,
            heal_stale_exempted,
            claims_refused,
            unheld_claims_stored,
            reissued_ops,
            reissued_purges,
            recorded_purge_reissued,
            already_stored,
            conflicts,
            republished_stored,
            faulty_stored,
            em_refused,
            em_disputes,
            revocations,
            revoked_ops_only_in_snapshots,
            revoked_bodiless_served,
            revoked_author_covers_served,
            revoked_snaps_accepted,
            revoked_snaps_rejected,
            snaps_refused_author_head,
            revoked_stale_exempted,
            past_cutoff_recomputed,
            past_cutoff_flagged,
            recompute_base_mismatch
        );
        for i in 0..4 {
            self.conc_cases[i] += q.conc_cases[i];
        }
        self.max_retained_at_end = self.max_retained_at_end.max(q.max_retained_at_end);
    }
}

fn add_coverage(c: &mut Coverage, w: &World) {
    let st = &w.server.stats;
    c.bodies_deleted += st.bodies_deleted;
    c.snapshots_dropped += st.snapshots_dropped;
    c.bodiless_served += st.bodiless_served;
    c.multi_cover_responses += st.multi_cover_responses;
    c.heal_requests += st.heal_requests;
    c.heal_refused += st.heal_refused;
    c.heal_bodiless += st.heal_bodiless;
    c.heal_with_body += st.heal_with_body;
    c.heal_verbatim_snaps += st.heal_verbatim_snaps;
    c.heal_stale_exempted += st.heal_stale_exempted;
    c.claims_refused += st.claims_refused;
    c.unheld_claims_stored += st.unheld_claims_stored;
    c.snaps_refused_author_head += st.snaps_refused_author_head;
    c.revoked_bodiless_served += st.revoked_bodiless_served;
    c.revoked_author_covers_served += st.revoked_author_covers_served;
    c.revoked_stale_exempted += st.revoked_stale_exempted;
    c.restores += w.restores;
    for d in &w.devs {
        c.absorbed_dominating += d.absorbed_dominating;
        c.absorbed_concurrent += d.absorbed_concurrent;
        c.absorb_rejected_inv25 += d.absorb_rejected_inv25;
        c.join_pruned += d.join_pruned;
        for i in 0..4 {
            c.conc_cases[i] += d.conc_cases[i];
        }
        c.merged_written += d.merged_written;
        c.em_refused += d.em_refused;
        c.em_disputes += d.em_disputes;
        c.revoked_snaps_accepted += d.revoked_snaps_accepted;
        c.revoked_snaps_rejected += d.revoked_snaps_rejected;
        c.past_cutoff_recomputed += d.past_cutoff_recomputed;
        c.recompute_base_mismatch += d.recompute_base_mismatch;
        c.past_cutoff_flagged += d
            .notices
            .iter()
            .filter(|n| matches!(n, crate::replica::Notice::PastCutoff { .. }))
            .count() as u64;
    }
    c.snapshots_written += w.snaps.len() as u64;
    let n = w.server.snaps.len() as u64;
    if n > 2 {
        c.retained_gt2_at_end += 1;
    }
    c.max_retained_at_end = c.max_retained_at_end.max(n);
    c.values_pruned_at_end += crate::check::pruned_values(w);
    if let Some(d) = w.devs.iter().find(|d| d.status == Status::Active)
        && let crate::item::Item::Tomb(t) = &d.item
    {
        c.tombstones_at_end += 1;
        if !t.late.is_empty() {
            c.late_values_at_end += 1;
        }
        if w.originals.contains_key(&t.purge.dot) {
            c.recorded_purge_reissued += 1;
        }
    }
    c.reissued_ops += w.originals.len() as u64;
    c.reissued_purges += w
        .originals
        .values()
        .filter(|o| o.b.marker == crate::types::Marker::Purge)
        .count() as u64;
    c.already_stored += w.already_stored;
    c.conflicts += w.conflicts;
    c.republished_stored += w.republished_stored;
    c.faulty_stored += w
        .snaps
        .iter()
        .filter(|s| !s.honest && w.stored_snaps.contains(&s.id))
        .count() as u64;
    c.revocations += w.server.revocations.len() as u64;
    if w.server
        .ops
        .iter()
        .any(|(dot, so)| so.b.is_none() && w.server.revocations.contains_key(&dot.dev))
    {
        c.revoked_ops_only_in_snapshots += 1;
    }
}

/// What a schedule contained, for `Report::core_by_cause`: failures of one answer's rules can
/// then be told apart from residues of another question.
pub fn cause_tag(w: &World) -> String {
    let yn = |b: bool| if b { "yes" } else { "no" };
    let revoked =
        !w.server.revocations.is_empty() || w.devs.iter().any(|d| d.status == Status::Revoked);
    let faulty = w.snaps.iter().any(|s| s.fault.is_some());
    format!(
        "restore {} | revocation {} | faulty snapshot {} | re-issue {}",
        yn(w.restores > 0),
        yn(revoked),
        yn(faulty),
        yn(!w.originals.is_empty())
    )
}

pub fn blocks(prog: &[Act]) -> Vec<Vec<Act>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for a in prog {
        cur.push(a.clone());
        if !a.is_local() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn multinomial(lens: &[usize]) -> u128 {
    let mut total: u128 = 0;
    let mut r: u128 = 1;
    for &l in lens {
        for i in 1..=l as u128 {
            total += 1;
            r = r * total / i;
        }
    }
    r
}

pub fn build_world(scn: &Scenario, cfg: &Config) -> World {
    let mut cfg = cfg.clone();
    if scn.max_values.is_some() {
        cfg.max_values = scn.max_values;
    }
    let mut w = World::new(cfg, scn.n_dev, &scn.skew);
    for (a, act) in &scn.setup {
        w.exec(*a, act);
    }
    w
}

fn record(
    report: &mut Report,
    vs: Vec<Violation>,
    scn: usize,
    sched: &Schedule,
    seed: Option<u64>,
    rscn: Option<&Scenario>,
    cause: String,
) {
    let mut any_core = false;
    let mut seen = BTreeSet::new();
    let props: BTreeSet<&str> = vs.iter().map(|v| v.prop).collect();
    for p in props {
        *report.prop_leaves.entry(p.to_string()).or_default() += 1;
    }
    let mut core_kinds: Vec<String> = Vec::new();
    for v in vs {
        if is_core(v.prop) {
            any_core = true;
            core_kinds.push(format!("[{}] {}", v.prop, v.kind));
        }
        let key = (v.prop.to_string(), v.kind.clone());
        if !seen.insert(key.clone()) {
            continue;
        }
        let e = report.found.entry(key).or_insert_with(|| Found {
            prop: v.prop,
            kind: v.kind.clone(),
            leaves: 0,
            scenario: scn,
            scn: rscn.cloned(),
            schedule: sched.clone(),
            seed,
            detail: v.detail.clone(),
        });
        e.leaves += 1;
        if sched.len() < e.schedule.len() {
            e.scenario = scn;
            e.scn = rscn.cloned();
            e.schedule = sched.clone();
            e.seed = seed;
            e.detail = v.detail;
        }
    }
    if any_core {
        report.leaves_with_core_violation += 1;
        *report.core_by_cause.entry(cause).or_default() += 1;
        if let Some(sd) = seed {
            core_kinds.sort();
            core_kinds.dedup();
            report.seed_violations.push((sd, core_kinds));
        }
    }
    if seed.is_none() {
        let e = report.per_scenario.entry(scn).or_default();
        e.0 += 1;
        if any_core {
            e.1 += 1;
        }
    }
}

/// Merge `p` into `out` (`p` comes later in the fixed merge order).
fn merge_report(out: &mut Report, p: Report) {
    out.leaves += p.leaves;
    out.leaves_with_core_violation += p.leaves_with_core_violation;
    out.p3_sets += p.p3_sets;
    out.p3_runs += p.p3_runs;
    out.seed_violations.extend(p.seed_violations);
    for (k, v) in p.prop_leaves {
        *out.prop_leaves.entry(k).or_default() += v;
    }
    for (k, v) in p.core_by_cause {
        *out.core_by_cause.entry(k).or_default() += v;
    }
    for (k, (a, b)) in p.per_scenario {
        let e = out.per_scenario.entry(k).or_default();
        e.0 += a;
        e.1 += b;
    }
    out.cov.add(&p.cov);
    for (k, f) in p.found {
        match out.found.get_mut(&k) {
            None => {
                out.found.insert(k, f);
            }
            Some(e) => {
                let leaves = e.leaves + f.leaves;
                if f.schedule.len() < e.schedule.len() {
                    *e = f;
                }
                e.leaves = leaves;
            }
        }
    }
}

struct Dfs<'a> {
    scn_idx: usize,
    blocks: &'a [Vec<Vec<Act>>],
    ctx: &'a mut CheckCtx,
    report: &'a mut Report,
}

impl Dfs<'_> {
    fn go(&mut self, w: World, pos: &mut Vec<usize>, sched: &mut Schedule) {
        let actors: Vec<usize> = (0..self.blocks.len())
            .filter(|&a| pos[a] < self.blocks[a].len())
            .collect();
        if actors.is_empty() {
            let mut w = w;
            w.drain();
            let vs = check_world(&w, self.ctx);
            add_coverage(&mut self.report.cov, &w);
            self.report.leaves += 1;
            let cause = cause_tag(&w);
            record(self.report, vs, self.scn_idx, sched, None, None, cause);
            return;
        }
        let last = actors.len() - 1;
        let mut base = Some(w);
        for (i, &a) in actors.iter().enumerate() {
            let mut w2 = if i == last {
                base.take().expect("base world")
            } else {
                base.as_ref().expect("base world").clone()
            };
            let blk = self.blocks[a][pos[a]].clone();
            for act in &blk {
                w2.exec(a, act);
                sched.push((a, act.clone()));
            }
            pos[a] += 1;
            self.go(w2, pos, sched);
            pos[a] -= 1;
            for _ in &blk {
                sched.pop();
            }
        }
    }
}

/// Block-order prefixes (the actor of each block in turn) that split the interleaving tree of
/// `bl` into at least `want` subtrees, or into its leaves.
fn prefixes(bl: &[Vec<Vec<Act>>], want: usize) -> Vec<Vec<usize>> {
    let mut cur: Vec<Vec<usize>> = vec![Vec::new()];
    for _depth in 0..6 {
        if cur.len() >= want {
            break;
        }
        let mut next = Vec::new();
        let mut grew = false;
        for p in &cur {
            let mut pos = vec![0usize; bl.len()];
            for &a in p {
                pos[a] += 1;
            }
            let actors: Vec<usize> = (0..bl.len()).filter(|&a| pos[a] < bl[a].len()).collect();
            if actors.is_empty() {
                next.push(p.clone());
                continue;
            }
            grew = true;
            for a in actors {
                let mut q = p.clone();
                q.push(a);
                next.push(q);
            }
        }
        cur = next;
        if !grew {
            break;
        }
    }
    cur
}

pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

pub fn run_exhaustive(family: &str, scenarios: Vec<Scenario>, cfg: &Config) -> Report {
    run_exhaustive_par(family, scenarios, cfg, default_threads())
}

pub fn run_exhaustive_par(
    family: &str,
    scenarios: Vec<Scenario>,
    cfg: &Config,
    threads: usize,
) -> Report {
    let mut report = Report {
        family: family.to_string(),
        config: cfg.name.to_string(),
        ..Default::default()
    };
    let bls: Vec<Vec<Vec<Vec<Act>>>> = scenarios
        .iter()
        .map(|s| s.programs.iter().map(|p| blocks(p)).collect())
        .collect();
    let want = (threads * 4).max(1);
    let mut items: Vec<(usize, Vec<usize>)> = Vec::new();
    for (idx, scn) in scenarios.iter().enumerate() {
        let raw: Vec<usize> = scn.programs.iter().map(|p| p.len()).collect();
        report.raw_interleavings += multinomial(&raw);
        for p in prefixes(&bls[idx], want / scenarios.len().max(1) + 1) {
            items.push((idx, p));
        }
    }
    let next = AtomicUsize::new(0);
    let parts: Mutex<Vec<(usize, Report)>> = Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..threads.max(1) {
            sc.spawn(|| {
                let mut ctx = CheckCtx::new(true, 60);
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((idx, prefix)) = items.get(i) else {
                        break;
                    };
                    let scn = &scenarios[*idx];
                    let bl = &bls[*idx];
                    let mut part = Report::default();
                    let mut w = build_world(scn, cfg);
                    let mut pos = vec![0usize; bl.len()];
                    let mut sched: Schedule = Vec::new();
                    for &a in prefix {
                        for act in &bl[a][pos[a]] {
                            w.exec(a, act);
                            sched.push((a, act.clone()));
                        }
                        pos[a] += 1;
                    }
                    let (s0, r0) = (ctx.p3_sets, ctx.p3_runs);
                    {
                        let mut dfs = Dfs {
                            scn_idx: *idx,
                            blocks: bl,
                            ctx: &mut ctx,
                            report: &mut part,
                        };
                        dfs.go(w, &mut pos, &mut sched);
                    }
                    part.p3_sets = ctx.p3_sets - s0;
                    part.p3_runs = ctx.p3_runs - r0;
                    parts.lock().expect("parts").push((i, part));
                }
            });
        }
    });
    let mut parts = parts.into_inner().expect("parts");
    parts.sort_by_key(|(i, _)| *i);
    for (_, p) in parts {
        merge_report(&mut report, p);
    }
    report.scenarios = scenarios;
    report
}

/// Replay one schedule from scratch (optionally recording events).
pub fn replay(
    scn: &Scenario,
    cfg: &Config,
    sched: &Schedule,
    seed: Option<u64>,
    rec: bool,
) -> (World, Vec<Violation>) {
    let mut w = build_world(scn, cfg);
    w.set_rec(rec);
    if let Some(s) = seed {
        w.rng = Some(XorShift::new(s ^ 0xD15C_0DE5));
    }
    for (a, act) in sched {
        if rec {
            w.events.push(format!(
                ">> {} {}",
                actor_name(*a, scn.n_dev),
                act.describe()
            ));
        }
        w.exec(*a, act);
    }
    if rec {
        w.events
            .push(">> drain: every active device syncs, worker runs, until quiet".to_string());
    }
    w.drain();
    let mut ctx = CheckCtx::new(true, 40);
    let vs = check_world(&w, &mut ctx);
    (w, vs)
}

/// Debugging aid (`--order`): run one block interleaving, given as the actor of each block in
/// turn, and print its event log, final states and violations.
pub fn show_order(scn: &Scenario, cfg: &Config, order: &[usize]) -> String {
    let bl: Vec<Vec<Vec<Act>>> = scn.programs.iter().map(|p| blocks(p)).collect();
    let mut pos = vec![0usize; bl.len()];
    let mut sched: Schedule = Vec::new();
    for &a in order {
        if a < bl.len() && pos[a] < bl[a].len() {
            for act in &bl[a][pos[a]] {
                sched.push((a, act.clone()));
            }
            pos[a] += 1;
        }
    }
    let (w, vs) = replay(scn, cfg, &sched, None, true);
    let mut s = String::new();
    let start = w
        .events
        .iter()
        .position(|e| e.starts_with(">>"))
        .unwrap_or(w.events.len());
    for e in &w.events[start..] {
        let _ = writeln!(s, "  {e}");
    }
    for d in &w.devs {
        let ro = if d.read_only { ", read-only" } else { "" };
        let _ = writeln!(s, "  D{} [{:?}{ro}]: {}", d.id, d.status, d.item.canon());
    }
    for v in vs {
        let _ = writeln!(s, "  [{}] {}", v.prop, v.kind);
    }
    s
}

/// Greedy one-step deletion minimiser: drop schedule steps while the same (property, kind)
/// violation still reproduces.
pub fn minimize(scn: &Scenario, cfg: &Config, f: &Found) -> Schedule {
    let holds = |s: &Schedule| {
        replay(scn, cfg, s, f.seed, false)
            .1
            .iter()
            .any(|v| v.prop == f.prop && v.kind == f.kind)
    };
    let mut cur = f.schedule.clone();
    if !holds(&cur) {
        return cur;
    }
    loop {
        let mut improved = false;
        for i in 0..cur.len() {
            let mut cand = cur.clone();
            cand.remove(i);
            if holds(&cand) {
                cur = cand;
                improved = true;
                break;
            }
        }
        if !improved {
            break;
        }
    }
    cur
}

pub fn render(scn: &Scenario, cfg: &Config, sched: &Schedule, f: &Found) -> String {
    let (w, vs) = replay(scn, cfg, sched, f.seed, true);
    let mut s = String::new();
    let setup: Vec<String> = scn
        .setup
        .iter()
        .map(|(a, act)| format!("{} {}", actor_name(*a, scn.n_dev), act.describe()))
        .collect();
    let _ = writeln!(
        s,
        "    scenario {}/{} (config {}, N={})",
        scn.family, scn.name, cfg.name, cfg.n_hist
    );
    let _ = writeln!(s, "    setup: {}", setup.join("; "));
    let seed = f
        .seed
        .map(|x| format!(", delivery seed {x}"))
        .unwrap_or_default();
    let steps: Vec<String> = sched
        .iter()
        .map(|(a, act)| format!("{} {}", actor_name(*a, scn.n_dev), act.describe()))
        .collect();
    let _ = writeln!(
        s,
        "    minimal schedule ({} steps{seed}): {}",
        sched.len(),
        steps.join("; ")
    );
    let _ = writeln!(s, "    events:");
    let start = w
        .events
        .iter()
        .position(|e| e.starts_with(">>"))
        .unwrap_or(w.events.len());
    for e in &w.events[start..] {
        let _ = writeln!(s, "      {e}");
    }
    let _ = writeln!(s, "    final states:");
    for d in &w.devs {
        let ro = if d.read_only { ", read-only" } else { "" };
        let _ = writeln!(
            s,
            "      D{} [{:?}{ro}]: {}",
            d.id,
            d.status,
            d.item.canon()
        );
    }
    if let Some(v) = vs.iter().find(|v| v.prop == f.prop && v.kind == f.kind) {
        let _ = writeln!(s, "    violation: [{}] {}", v.prop, v.kind);
        for line in v.detail.lines() {
            let _ = writeln!(s, "      {line}");
        }
    } else {
        let _ = writeln!(
            s,
            "    (did not reproduce on replay; original detail below)"
        );
        for line in f.detail.lines() {
            let _ = writeln!(s, "      {line}");
        }
    }
    s
}

fn run_random_chunk(flavor: Flavor, seeds: std::ops::Range<u64>, cfg: &Config) -> Report {
    let mut report = Report {
        family: flavor.family().to_string(),
        config: cfg.name.to_string(),
        ..Default::default()
    };
    let mut ctx = CheckCtx::new(true, 30);
    for seed in seeds {
        let mut rng = XorShift::new(seed);
        let scn = random_scenario(&mut rng, flavor, seed, cfg.faults);
        let sched = random_schedule(&mut rng, &scn);
        let mut w = build_world(&scn, cfg);
        w.rng = Some(XorShift::new(seed ^ 0xD15C_0DE5));
        for (a, act) in &sched {
            w.exec(*a, act);
        }
        w.drain();
        let vs = check_world(&w, &mut ctx);
        add_coverage(&mut report.cov, &w);
        report.leaves += 1;
        let cause = cause_tag(&w);
        record(&mut report, vs, 0, &sched, Some(seed), Some(&scn), cause);
    }
    report.p3_sets = ctx.p3_sets;
    report.p3_runs = ctx.p3_runs;
    report
}

/// Seeded random runs, split over `threads` threads (each seed is independent and reproducible
/// on its own); the parts are merged in seed order.
pub fn run_random(flavor: Flavor, seeds: std::ops::Range<u64>, cfg: &Config) -> Report {
    run_random_par(flavor, seeds, cfg, default_threads())
}

pub fn run_random_par(
    flavor: Flavor,
    seeds: std::ops::Range<u64>,
    cfg: &Config,
    threads: usize,
) -> Report {
    let n = seeds.end.saturating_sub(seeds.start);
    let chunks = (threads.max(1) as u64 * 8).min(n.max(1));
    let chunk = n.div_ceil(chunks).max(1);
    let ranges: Vec<std::ops::Range<u64>> = (0..chunks)
        .map(|i| {
            let a = seeds.start + i * chunk;
            a.min(seeds.end)..(a + chunk).min(seeds.end)
        })
        .filter(|r| !r.is_empty())
        .collect();
    let next = AtomicUsize::new(0);
    let parts: Mutex<Vec<(usize, Report)>> = Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..threads.max(1) {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(r) = ranges.get(i) else { break };
                    let part = run_random_chunk(flavor, r.clone(), cfg);
                    parts.lock().expect("parts").push((i, part));
                }
            });
        }
    });
    let mut parts = parts.into_inner().expect("parts");
    parts.sort_by_key(|(i, _)| *i);
    let mut report = Report {
        family: flavor.family().to_string(),
        config: cfg.name.to_string(),
        ..Default::default()
    };
    for (_, p) in parts {
        merge_report(&mut report, p);
    }
    report.seed_violations.sort_by_key(|(s, _)| *s);
    report
}

/// The full event log of one random seed (not minimised).
pub fn seed_events(flavor: Flavor, seed: u64, cfg: &Config) -> String {
    let mut rng = XorShift::new(seed);
    let scn = random_scenario(&mut rng, flavor, seed, cfg.faults);
    let sched = random_schedule(&mut rng, &scn);
    let (w, vs) = replay(&scn, cfg, &sched, Some(seed), true);
    let mut s = String::new();
    let _ = writeln!(s, "seed {seed} (config {}): {}", cfg.name, scn.name);
    for e in &w.events {
        let _ = writeln!(s, "  {e}");
    }
    for d in &w.devs {
        let _ = writeln!(s, "  final D{} [{:?}]: {}", d.id, d.status, d.item.canon());
    }
    for v in vs.iter().filter(|v| v.prop != "NOTE") {
        let _ = writeln!(s, "  violation [{}] {}", v.prop, v.kind);
    }
    s
}

/// Print a report: counts, then one minimised trace per distinct (property, kind).
pub fn print_report(
    r: &Report,
    cfg: &Config,
    traces: bool,
    max_traces: usize,
    only: Option<&str>,
    seed_list: bool,
) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "=== family {} | config {} | N={} ===",
        r.family, r.config, cfg.n_hist
    );
    let _ = writeln!(
        s,
        "scenarios: {}  schedules checked: {}  action-level interleavings covered: {}  schedules with a P1-P3 violation: {}",
        if r.scenarios.is_empty() {
            r.leaves as usize
        } else {
            r.scenarios.len()
        },
        r.leaves,
        if r.raw_interleavings > 0 {
            r.raw_interleavings.to_string()
        } else {
            "n/a (random)".to_string()
        },
        r.leaves_with_core_violation
    );
    let _ = writeln!(
        s,
        "P3: {} distinct op/snapshot sets, {} fresh-replica replays",
        r.p3_sets, r.p3_runs
    );
    let c = &r.cov;
    let _ = writeln!(
        s,
        "coverage: bodies deleted {} | snapshots dropped (R3) {} | bodiless headers served {} | multi-cover responses {} | absorbed dominating {} / concurrent {} | absorptions rejected by INV-25 {} | history entries pruned in a join {} | values accounted for by pruning at end {} | tombstone at end {} (with late values {})",
        c.bodies_deleted,
        c.snapshots_dropped,
        c.bodiless_served,
        c.multi_cover_responses,
        c.absorbed_dominating,
        c.absorbed_concurrent,
        c.absorb_rejected_inv25,
        c.join_pruned,
        c.values_pruned_at_end,
        c.tombstones_at_end,
        c.late_values_at_end,
    );
    let _ = writeln!(
        s,
        "  absorption: concurrent live<-live {} | live<-tomb {} | tomb<-live {} | tomb<-tomb {} | snapshots written {} (merged {}) | schedules ending with > 2 retained snapshots {} (max {})",
        c.conc_cases[0],
        c.conc_cases[1],
        c.conc_cases[2],
        c.conc_cases[3],
        c.snapshots_written,
        c.merged_written,
        c.retained_gt2_at_end,
        c.max_retained_at_end
    );
    let _ = writeln!(
        s,
        "  healing: restores {} | healing requests stored {} / refused {} | headers stored bodiless {} / with body {} | held snapshots verbatim {} | stale-epoch records exempted {} | unheld claims stored {} / refused {}",
        c.restores,
        c.heal_requests,
        c.heal_refused,
        c.heal_bodiless,
        c.heal_with_body,
        c.heal_verbatim_snaps,
        c.heal_stale_exempted,
        c.unheld_claims_stored,
        c.claims_refused
    );
    let _ = writeln!(
        s,
        "  re-issue: re-issued ops {} (Purge {}) | final tombstone records a re-issued purge {} | already-stored answers {} | conflicts {} | once-stored ops re-published past a stale epoch {}",
        c.reissued_ops,
        c.reissued_purges,
        c.recorded_purge_reissued,
        c.already_stored,
        c.conflicts,
        c.republished_stored
    );
    let _ = writeln!(
        s,
        "  faulty: faulty snapshots stored {} | evidence absorptions refused {} / with a dispute {}",
        c.faulty_stored, c.em_refused, c.em_disputes
    );
    let _ = writeln!(
        s,
        "  revocation: revocations {} | ending with a revoked device's ops only in snapshots {} | its bodiless headers served {} | revoked-author covers served {} | revoked-author snapshots accepted {} / rejected {} | author-head refusals {} | revoked stale ops exempted {} | ADR 0012 §6 recomputed {} / flagged {} | recompute self-check mismatches {}",
        c.revocations,
        c.revoked_ops_only_in_snapshots,
        c.revoked_bodiless_served,
        c.revoked_author_covers_served,
        c.revoked_snaps_accepted,
        c.revoked_snaps_rejected,
        c.snaps_refused_author_head,
        c.revoked_stale_exempted,
        c.past_cutoff_recomputed,
        c.past_cutoff_flagged,
        c.recompute_base_mismatch
    );
    for (cause, n) in &r.core_by_cause {
        let _ = writeln!(s, "  schedules with a P1-P3 violation, {cause}: {n}");
    }
    let failing: Vec<(&usize, &(u64, u64))> =
        r.per_scenario.iter().filter(|(_, (_, f))| *f > 0).collect();
    if !failing.is_empty() {
        let _ = writeln!(
            s,
            "scenarios with a P1-P3 violation: {} of {}",
            failing.len(),
            r.scenarios.len()
        );
        for (i, (n, f)) in failing.iter().take(12) {
            let _ = writeln!(s, "  {}: {f} of {n} schedules", r.scenarios[**i].name);
        }
        if failing.len() > 12 {
            let _ = writeln!(s, "  ...");
        }
    }
    if seed_list && !r.seed_violations.is_empty() {
        let seeds: Vec<String> = r
            .seed_violations
            .iter()
            .map(|(sd, _)| sd.to_string())
            .collect();
        let _ = writeln!(s, "violating seeds: [{}]", seeds.join(","));
    }
    let core: Vec<&Found> = r
        .found
        .values()
        .filter(|f| is_core(f.prop) || is_answer_check(f.prop))
        .collect();
    let side: Vec<&Found> = r
        .found
        .values()
        .filter(|f| !is_core(f.prop) && !is_answer_check(f.prop))
        .collect();
    for p in CORE_PROPS.iter().chain(ANSWER_CHECKS) {
        let n: u64 = r.prop_leaves.get(*p).copied().unwrap_or(0);
        let status = if n == 0 {
            "holds".to_string()
        } else {
            format!("FAILS (in {n} schedules)")
        };
        let _ = writeln!(s, "  {p:<9} {status}");
    }
    for f in &core {
        let _ = writeln!(s, "  - [{}] {} ({} schedules)", f.prop, f.kind, f.leaves);
    }
    if !side.is_empty() {
        let _ = writeln!(s, "  side conditions:");
        for f in &side {
            let _ = writeln!(s, "  - [{}] {} ({} schedules)", f.prop, f.kind, f.leaves);
        }
    }
    if traces {
        let mut shown = 0;
        let p1_kinds: Vec<&str> = core
            .iter()
            .filter(|f| f.prop == "P1")
            .map(|f| f.kind.as_str())
            .collect();
        for f in core.iter().chain(side.iter().filter(|f| f.prop != "NOTE")) {
            // A P1-ref trace that repeats a P1 trace of the same kind adds nothing.
            if f.prop == "P1-ref" && p1_kinds.iter().any(|k| f.kind.ends_with(k)) && only.is_none()
            {
                continue;
            }
            if only.is_some_and(|o| !format!("[{}] {}", f.prop, f.kind).contains(o)) {
                continue;
            }
            if shown >= max_traces {
                let _ = writeln!(s, "  (more traces omitted; raise --max-traces)");
                break;
            }
            let scn = match &f.scn {
                Some(x) => x,
                None => &r.scenarios[f.scenario],
            };
            let min = minimize(scn, cfg, f);
            let _ = writeln!(s, "\n  TRACE [{}] {}", f.prop, f.kind);
            s.push_str(&render(scn, cfg, &min, f));
            shown += 1;
        }
    }
    s
}
