//! Property checks at quiescence: ADR 0012 §12 properties 1-3 (with ADR 0018 §12's tombstone
//! form of property 2), plus the answers' own checks and observed side conditions.
//!
//! Universe of ops U (what "ever written" means here): the version the server stored last of every
//! op the server stored at some point, plus every op authored by a device that is still active
//! (its latest version). Ops a revoked device wrote past its cut-off, and ops a lost device never
//! uploaded, are outside U. The cut-offs come from the server and the active devices only.
//!
//! - **P1 convergence:** every active device holds the same canonical state (ADR 0018 §4). The kind
//!   carries "[silent]" when some device that differs from the op-based state raised no report,
//!   "[reported]" otherwise, and the fault classes stored when faulty snapshots were stored.
//!   **P1-ref:** and that state equals the state a fresh replica reaches from U alone (without
//!   unrecoverable ops, below), by ops, in causal order.
//! - **P2 no silent loss** (ADR 0012 §12 item 2; ADR 0018 §12 "no silent loss"). For every active
//!   device X and every value w written by a recoverable op in U (the `@lifecycle` marker
//!   included), w is *accounted for* at X when one of these holds; otherwise it is lost silently:
//!   1. X's item VV covers w's dot, X is live, and w is a current value or a history entry;
//!   2. X is live, w was superseded (an op in U writing w's key has a context covering w's dot,
//!      and X's VV covers that op), and w's history group holds N entries all ranked above w
//!      (ADR 0012 §5 deterministic pruning);
//!   3. X is a tombstone and w is a late value; or, through a real Purge in U that X covers, c
//!      covers w's dot, or w was superseded as in 2, or w's key is `@lifecycle` (a tombstone no
//!      Purge justifies, which only a faulty snapshot makes, accounts for nothing but its late
//!      values);
//!   4. X reported w missing: w's op is in X's causal buffer, or an op held there names w's dot in
//!      its context (ADR 0012 §4 step 2 "missing ops from device X"), or a Gap at or below w's seq,
//!      a rejection, a Dispute or a ClaimCut names it, or a Dispute names the tombstone's purge.
//! - **LOSS:** an op of U that no surviving party can supply (only lost devices and a restored-away
//!   server state had it) is unrecoverable by any rule; it is reported apart and left out of P2 and
//!   P1-ref, with the ops that causally depend on it (answer 2).
//! - **P3 permutation independence** (ADR 0012 §12 item 3): a fresh replica fed U in any order,
//!   with duplicates, reaches one state (P3-ops). **P3-mixed** extends it to U plus every honest,
//!   untainted snapshot the server stored, and requires the same state as P3-ops. **P3-faulty**
//!   (answer 4): U plus *every* stored snapshot, faulty ones included, in any order, reaches one
//!   state (not necessarily the P3 state).
//! - **RT, FORK, KEY** (answer 3): the ops as stored produce the state of the ops as authored (a
//!   re-issue changes only the envelope); no dot was stored in two signed versions; no op the
//!   server never stored got past the stale-epoch check.
//!
//! Side conditions reported (not ADR 0012 §12 properties 1-3): P4 (INV-25 VV monotonicity), GAP,
//! DISPUTE, LIVE, SRV (ADR 0021 §8 server properties), RECOMP (the newest snapshot plus the
//! retained ops no longer rebuild the item, ADR 0012 §6), HLC (the clock condition of ADR 0012
//! §2), PIN (more than two snapshots retained at quiescence under ADR 0021's rule; informational).

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};

use crate::config::{Config, ServerRule};
use crate::item::Item;
use crate::replica::{Notice, Out, Replica, Snapshot, Status};
use crate::rng::XorShift;
use crate::types::{Dot, Entry, Key, KeyId, LIFECYCLE, Marker, Op};
use crate::world::World;

#[derive(Clone, Debug)]
pub struct Violation {
    pub prop: &'static str,
    pub kind: String,
    pub detail: String,
}

impl Violation {
    fn new(prop: &'static str, kind: impl Into<String>, detail: impl Into<String>) -> Self {
        Violation {
            prop,
            kind: kind.into(),
            detail: detail.into(),
        }
    }
}

/// Is this property one of ADR 0012 §12 properties 1-3 (a real violation) or a side condition?
pub fn is_core(prop: &str) -> bool {
    matches!(
        prop,
        "P1" | "P1-ref" | "P2" | "P3" | "P3-mixed" | "P3-faulty"
    )
}

/// The answers' own checks, printed next to properties 1-3.
pub fn is_answer_check(prop: &str) -> bool {
    matches!(prop, "RT" | "FORK" | "KEY" | "LOSS" | "RECOMP" | "HLC")
}

pub const CORE_PROPS: &[&str] = &["P1", "P1-ref", "P2", "P3", "P3-mixed", "P3-faulty"];
pub const ANSWER_CHECKS: &[&str] = &["RT", "FORK", "KEY", "LOSS", "RECOMP", "HLC"];

#[derive(Default)]
pub struct CheckCtx {
    pub p3_cache: HashMap<u64, Vec<Violation>>,
    pub p3_sets: u64,
    pub p3_runs: u64,
    pub do_p3: bool,
    /// Permutations per set when the set is too large for all of them.
    pub p3_samples: usize,
}

impl CheckCtx {
    pub fn new(do_p3: bool, p3_samples: usize) -> Self {
        CheckCtx {
            do_p3,
            p3_samples,
            ..Default::default()
        }
    }
}

/// The revocation cut-offs: ops of a revoked device past `last_accepted_device_seq` are refused
/// by every replica (ADR 0012 §6, CRYPTO.md §11.8 step 4). Only revocations the server or an
/// active device holds count: one held only by a lost device and a restored-away server exists
/// nowhere any more, and no replica enforces it (THREAT_MODEL AR-19).
pub fn cutoffs(w: &World) -> BTreeMap<u8, u64> {
    let mut cut: BTreeMap<u8, u64> = w.server.revocations.clone();
    for d in w.devs.iter().filter(|d| d.status == Status::Active) {
        for (&t, &h) in &d.revocations {
            let e = cut.entry(t).or_insert(h);
            *e = (*e).min(h);
        }
    }
    cut
}

pub fn universe_ops(w: &World) -> Vec<Op> {
    let cut = cutoffs(w);
    w.authored
        .values()
        .filter(|op| {
            let a = op.dot().dev as usize;
            let past_cut = cut.get(&op.dot().dev).is_some_and(|&h| op.dot().seq > h);
            !past_cut
                && (w.ever_stored.contains(&op.dot())
                    || w.devs.get(a).is_some_and(|d| d.status == Status::Active))
        })
        // The version receivers get is the one the server stored (last); the author's latest
        // version counts only for an op the server never stored.
        .map(|op| w.stored_version.get(&op.dot()).unwrap_or(op))
        .cloned()
        .collect()
}

/// Can some surviving party still supply `dot`: the server (its op, or a retained snapshot whose
/// covered VV claims it), or an active device (its item VV covers it, or it holds the op in its
/// outbox, retained ops or causal buffer)?
pub fn recoverable(w: &World, dot: Dot) -> bool {
    w.server.ops.contains_key(&dot)
        || w.server.snaps.iter().any(|s| s.snap.state.vv().covers(dot))
        || w.devs
            .iter()
            .filter(|d| d.status == Status::Active)
            .any(|d| {
                d.item.vv().covers(dot)
                    || d.pending.iter().any(|o| o.dot() == dot)
                    || d.retained.iter().any(|o| o.dot() == dot)
                    || d.outbox
                        .iter()
                        .any(|o| matches!(o, Out::Op(p) if p.dot() == dot))
            })
}

/// U without the unrecoverable ops and without the ops that causally depend on one (their context
/// covers it, or it precedes them in their author's chain).
pub fn universe_core(w: &World) -> Vec<Op> {
    let u = universe_ops(w);
    let mut gone: Vec<Dot> = u
        .iter()
        .map(|o| o.dot())
        .filter(|d| !recoverable(w, *d))
        .collect();
    loop {
        let more: Vec<Dot> = u
            .iter()
            .filter(|o| !gone.contains(&o.dot()))
            .filter(|o| {
                gone.iter()
                    .any(|g| o.h.ctx.covers(*g) || (g.dev == o.dot().dev && g.seq < o.dot().seq))
            })
            .map(|o| o.dot())
            .collect();
        if more.is_empty() {
            break;
        }
        gone.extend(more);
    }
    u.into_iter().filter(|o| !gone.contains(&o.dot())).collect()
}

/// The universe with every re-issued op put back as authored: the original's HLC, causal context
/// and data, with the key id of the version receivers get. RT requires the converged state to
/// equal the state these ops produce.
pub fn universe_as_authored(w: &World) -> Vec<Op> {
    universe_core(w)
        .into_iter()
        .map(|op| match w.originals.get(&op.dot()) {
            Some(orig) => {
                let mut o = orig.clone();
                o.b.key_id = op.b.key_id;
                o.b.wrap = op.b.wrap;
                o.h.epoch = op.h.epoch;
                o
            }
            None => op,
        })
        .collect()
}

/// Every snapshot the server stored at some point.
pub fn all_stored_snaps(w: &World) -> Vec<Snapshot> {
    w.snaps
        .iter()
        .filter(|s| w.stored_snaps.contains(&s.id))
        .cloned()
        .collect()
}

/// Honest snapshots the server stored at some point whose author never absorbed a faulty or
/// tainted one, except those that cover an op past a revocation cut-off (U leaves such ops out).
pub fn honest_stored_snaps(w: &World) -> Vec<Snapshot> {
    let cut = cutoffs(w);
    w.snaps
        .iter()
        .filter(|s| s.honest && !s.tainted && w.stored_snaps.contains(&s.id))
        .filter(|s| cut.iter().all(|(&d, &h)| s.state.vv().get(d) <= h))
        .cloned()
        .collect()
}

pub enum Msg {
    Op(Op),
    Snap(Snapshot),
}

/// Feed messages to a fresh replica; returns its state and the dots left in its causal buffer.
/// The fresh replica knows the final revocations (so it applies the configured revocation rules to
/// snapshots), has verified the signed header of every op it is fed, and knows the kind of every
/// op body in the set: under the protocol a replica reads every body a cover could contradict
/// before absorbing the cover (`process_response`), so the result is a function of the set.
pub fn replay_fresh_item(
    msgs: &[&Msg],
    cfg: &Config,
    all_keys: &BTreeSet<KeyId>,
    revs: &BTreeMap<u8, u64>,
) -> (Item, Vec<Dot>) {
    let mut r = Replica::new(250, 0);
    r.keys = all_keys.clone();
    r.revocations = revs.clone();
    for m in msgs {
        if let Msg::Op(op) = m {
            r.headers.insert(op.dot(), op.h.clone());
            r.learn_body(op);
        }
    }
    for m in msgs {
        match m {
            Msg::Op(op) => r.deliver(op.clone(), cfg),
            Msg::Snap(s) => {
                r.absorb(s, cfg);
            }
        }
    }
    let p = r.pending.iter().map(|o| o.dot()).collect();
    (r.item, p)
}

/// Canonical state of a fresh replica fed `msgs` (+ a stuck marker).
pub fn replay_fresh(
    msgs: &[&Msg],
    cfg: &Config,
    all_keys: &BTreeSet<KeyId>,
    revs: &BTreeMap<u8, u64>,
) -> String {
    let (item, pending) = replay_fresh_item(msgs, cfg, all_keys, revs);
    let mut c = item.canon();
    if !pending.is_empty() {
        let p: Vec<String> = pending.iter().map(|d| d.to_string()).collect();
        c.push_str(&format!(" STUCK[{}]", p.join(",")));
    }
    c
}

fn all_keys(ops: &[Op], snaps: &[Snapshot]) -> BTreeSet<KeyId> {
    let mut k = BTreeSet::new();
    for o in ops {
        k.insert(o.b.key_id);
        if let Some(w) = o.b.wrap {
            k.insert(w);
        }
    }
    for s in snaps {
        k.insert(s.key_id);
        if let Some(w) = s.wrap {
            k.insert(w);
        }
    }
    k
}

fn reference_of(mut ops: Vec<Op>, w: &World) -> String {
    ops.sort_by_key(|o| o.dot());
    let keys = all_keys(&ops, &[]);
    let msgs: Vec<Msg> = ops.into_iter().map(Msg::Op).collect();
    let refs: Vec<&Msg> = msgs.iter().collect();
    replay_fresh(&refs, &w.cfg, &keys, &cutoffs(w))
}

fn reference_item(mut ops: Vec<Op>, w: &World) -> Item {
    ops.sort_by_key(|o| o.dot());
    let keys = all_keys(&ops, &[]);
    let msgs: Vec<Msg> = ops.into_iter().map(Msg::Op).collect();
    replay_fresh_item(&msgs.iter().collect::<Vec<_>>(), &w.cfg, &keys, &cutoffs(w)).0
}

pub fn reference_state(w: &World) -> String {
    reference_of(universe_core(w), w)
}

/// Why two canonical states differ, coarsely (used to group violations).
pub fn classify(a: &Item, b: &Item) -> String {
    match (a, b) {
        (Item::Live(_), Item::Tomb(_)) | (Item::Tomb(_), Item::Live(_)) => {
            "live vs tombstone".into()
        }
        (Item::Tomb(x), Item::Tomb(y)) => {
            if x.purge.dot != y.purge.dot {
                "recorded purge differs".into()
            } else if x.purge.hlc != y.purge.hlc {
                "recorded purge HLC differs".into()
            } else if x.purge.key_id != y.purge.key_id {
                "item_key_id differs".into()
            } else if x.c != y.c {
                "c differs".into()
            } else if x.late != y.late {
                "late registers differ".into()
            } else {
                "covered VV differs".into()
            }
        }
        (Item::Live(x), Item::Live(y)) => {
            if x.regs.is_empty() != y.regs.is_empty() {
                "absent vs present".into()
            } else if x.regs != y.regs {
                "registers differ".into()
            } else if x.hist != y.hist {
                "history differs".into()
            } else {
                "covered VV differs".into()
            }
        }
    }
}

fn find_entry(es: Option<&Vec<Entry>>, dot: Dot) -> bool {
    es.is_some_and(|v| v.iter().any(|e| e.dot == dot))
}

fn superseded(u: &[Op], key: Key, dot: Dot, x: &Replica) -> bool {
    u.iter().any(|o| {
        o.dot() != dot
            && o.h.ctx.covers(dot)
            && x.item.vv().covers(o.dot())
            && o.writes_with_lifecycle().iter().any(|(k, _)| *k == key)
    })
}

fn reported(x: &Replica, dot: Dot) -> bool {
    x.pending.iter().any(|p| p.dot() == dot)
        // ADR 0012 §4 step 2: an op held because its causal context names a dot the replica never
        // applied reports "missing ops from device X" for that dot.
        || x.pending.iter().any(|p| p.h.ctx.covers(dot))
        || x.notices.iter().any(|n| match n {
            Notice::Gap { dev, seq } => *dev == dot.dev && *seq <= dot.seq,
            Notice::Rejected { dot: d, .. } => *d == dot,
            Notice::Dispute { dot: d, .. } => *d == dot,
            Notice::ClaimCut { dev, from, to, .. } => {
                *dev == dot.dev && *from < dot.seq && dot.seq <= *to
            }
            _ => false,
        })
}

/// Did the device raise any report that its data may be incomplete or wrong?
fn any_report(x: &Replica) -> bool {
    !x.pending.is_empty()
        || x.notices.iter().any(|n| {
            matches!(
                n,
                Notice::Gap { .. }
                    | Notice::Dispute { .. }
                    | Notice::ClaimCut { .. }
                    | Notice::SnapRejected { .. }
                    | Notice::Rejected { .. }
                    | Notice::PastCutoff { .. }
            )
        })
}

pub fn check_world(w: &World, ctx: &mut CheckCtx) -> Vec<Violation> {
    let mut out = Vec::new();
    let active: Vec<&Replica> = w
        .devs
        .iter()
        .filter(|d| d.status == Status::Active)
        .collect();
    let states_detail = || -> String {
        w.devs
            .iter()
            .map(|d| {
                format!(
                    "D{} [{:?}{}]: {}",
                    d.id,
                    d.status,
                    if d.read_only { ", read-only" } else { "" },
                    d.item.canon()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    // P1.
    let reference = reference_state(w);
    let deviants_report = active
        .iter()
        .filter(|d| d.item.canon() != reference)
        .all(|d| any_report(d));
    // Which fault classes were stored in this schedule (see `Fault::class`).
    let classes: BTreeSet<&str> = w
        .snaps
        .iter()
        .filter(|s| !s.honest && w.stored_snaps.contains(&s.id))
        .filter_map(|s| s.fault.map(|f| f.class()))
        .collect();
    let fclass = if classes.is_empty() {
        ""
    } else if classes.contains("undetectable fabrication") {
        " {undetectable fabrication stored}"
    } else {
        " {decidable faults only}"
    };
    let tag = if deviants_report {
        format!(" [reported]{fclass}")
    } else {
        format!(" [silent]{fclass}")
    };
    if let Some(first) = active.first() {
        let c0 = first.item.canon();
        if let Some(other) = active.iter().find(|d| d.item.canon() != c0) {
            out.push(Violation::new(
                "P1",
                format!("{}{tag}", classify(&first.item, &other.item)),
                states_detail(),
            ));
        }
    }
    // P1-ref.
    for d in &active {
        if d.item.canon() != reference {
            let kind = if reference.contains("STUCK") {
                "reference replica stuck".to_string()
            } else {
                format!(
                    "device state is not the op-based state: {}{tag}",
                    classify(&d.item, &reference_item(universe_core(w), w))
                )
            };
            out.push(Violation::new(
                "P1-ref",
                kind,
                format!("reference: {reference}\n{}", states_detail()),
            ));
            break;
        }
    }

    // RT (answer 3): a re-issue may change the envelope (key_id, epoch, wrap) and nothing else.
    if !w.originals.is_empty() {
        let as_authored = universe_as_authored(w);
        let rt = reference_of(as_authored.clone(), w);
        if rt != reference {
            let kind = if rt.contains("STUCK") || reference.contains("STUCK") {
                "re-issue: a reference replica is stuck".to_string()
            } else {
                format!(
                    "re-issue changed what the ops produce: {}",
                    classify(
                        &reference_item(universe_core(w), w),
                        &reference_item(as_authored, w)
                    )
                )
            };
            out.push(Violation::new(
                "RT",
                kind,
                format!(
                    "as stored:   {reference}\nas authored: {rt}\n{}",
                    states_detail()
                ),
            ));
        }
    }

    // P2.
    let u = universe_ops(w);
    let lost: Vec<Dot> = u
        .iter()
        .map(|o| o.dot())
        .filter(|d| !recoverable(w, *d))
        .collect();
    if !lost.is_empty() {
        let l: Vec<String> = lost.iter().map(|d| d.to_string()).collect();
        out.push(Violation::new(
            "LOSS",
            "unrecoverable: only lost devices and a restored-away server state held the op",
            format!("[{}]\n{}", l.join(","), states_detail()),
        ));
    }
    'dev: for x in &active {
        for op in u.iter().filter(|o| !lost.contains(&o.dot())) {
            let dot = op.dot();
            for (key, _) in op.writes_with_lifecycle() {
                let ok = if !x.item.vv().covers(dot) {
                    if reported(x, dot) {
                        true
                    } else {
                        out.push(Violation::new(
                            "P2",
                            "value never received and not reported",
                            format!(
                                "D{} lacks {} ({key}) with no notice; {}\n{}",
                                x.id,
                                dot,
                                op.describe(),
                                states_detail()
                            ),
                        ));
                        false
                    }
                } else {
                    match &x.item {
                        Item::Live(l) => {
                            if find_entry(l.regs.get(key), dot) || find_entry(l.hist.get(key), dot)
                            {
                                true
                            } else {
                                let entry = Entry {
                                    dot,
                                    hlc: op.h.hlc,
                                    val: 0,
                                };
                                let pruned = superseded(&u, key, dot, x)
                                    && l.hist.get(key).is_some_and(|h| {
                                        h.len() >= w.cfg.n_hist
                                            && h.iter().all(|e| e.rank() > entry.rank())
                                    });
                                let pruned = pruned || reported(x, dot);
                                if !pruned {
                                    out.push(Violation::new(
                                        "P2",
                                        "live: covered by the VV but not current, not in history, not pruned",
                                        format!("D{} lost {} ({key}); {}\n{}", x.id, dot, op.describe(), states_detail()),
                                    ));
                                }
                                pruned
                            }
                        }
                        Item::Tomb(t) => {
                            // Only a real Purge in U that X covers justifies the tombstone, the
                            // discarded values (c) and the dropped superseded late values.
                            let purges: Vec<&Op> = u
                                .iter()
                                .filter(|p| {
                                    p.b.marker == Marker::Purge && x.item.vv().covers(p.dot())
                                })
                                .collect();
                            let justified = !purges.is_empty();
                            let c_ok =
                                t.c.covers(dot) && purges.iter().any(|p| p.h.ctx.covers(dot));
                            // A dispute about the recorded purge reports the whole tombstone.
                            let disputed = x.notices.iter().any(|n| {
                                matches!(n, Notice::Dispute { dot: d, .. } if *d == t.purge.dot)
                            });
                            let ok = (key == LIFECYCLE && justified)
                                || disputed
                                || find_entry(t.late.get(key), dot)
                                || c_ok
                                || (justified && superseded(&u, key, dot, x))
                                || reported(x, dot);
                            if !ok {
                                out.push(Violation::new(
                                    "P2",
                                    "tombstone: covered by the VV but not late, not covered by c, not superseded",
                                    format!("D{} lost {} ({key}); {}\n{}", x.id, dot, op.describe(), states_detail()),
                                ));
                            }
                            ok
                        }
                    }
                };
                if !ok {
                    continue 'dev;
                }
            }
        }
    }

    // P3.
    if ctx.do_p3 {
        out.extend(check_p3(w, ctx));
    }

    // Side conditions.
    for x in &active {
        for n in &x.notices {
            match n {
                Notice::VvBackwards { old, new } => {
                    out.push(Violation::new(
                        "P4",
                        "item VV went backwards (INV-25)",
                        format!("D{}: {old} -> {new}", x.id),
                    ));
                }
                Notice::Gap { dev, seq } => {
                    out.push(Violation::new(
                        "GAP",
                        "missing data reported by the chain check",
                        format!("D{}: gap D{dev} seq {seq}", x.id),
                    ));
                }
                Notice::Dispute { dot, author } => {
                    out.push(Violation::new(
                        "DISPUTE",
                        "sources disagree about a value (reported)",
                        format!("D{}: {dot} vs snapshot by D{author}", x.id),
                    ));
                }
                Notice::SnapIgnored { why } => {
                    out.push(Violation::new(
                        "NOTE",
                        format!("snapshot not absorbed: {why}"),
                        format!("D{}", x.id),
                    ));
                }
                Notice::SnapRejected { why } => {
                    out.push(Violation::new(
                        "NOTE",
                        format!("snapshot rejected: {why}"),
                        format!("D{}", x.id),
                    ));
                }
                Notice::SnapRefused { why } => {
                    out.push(Violation::new(
                        "NOTE",
                        format!("snapshot refused by the server: {why}"),
                        format!("D{}", x.id),
                    ));
                }
                Notice::UploadConflict { dot } => {
                    out.push(Violation::new(
                        "NOTE",
                        "upload conflict at a stored dot",
                        format!("D{} {dot}", x.id),
                    ));
                }
                Notice::PastCutoff { dev, cut } => {
                    out.push(Violation::new(
                        "LIVE",
                        "replica holds ops past a revocation cut-off (item flagged: ADR 0012 §6 recomputation impossible or not configured)",
                        format!("D{}: D{dev} cut-off {cut}", x.id),
                    ));
                }
                // Transient blocks that a later heal resolved are not reported.
                Notice::HealBlocked { dot, .. } if w.server.ops.contains_key(dot) => {}
                Notice::HealBlocked { dot, why } => {
                    out.push(Violation::new(
                        "LIVE",
                        format!("heal re-publish blocked: {why}"),
                        format!("D{} {dot}", x.id),
                    ));
                }
                _ => {}
            }
        }
        if !x.pending.is_empty() {
            let p: Vec<String> = x.pending.iter().map(|o| o.dot().to_string()).collect();
            out.push(Violation::new(
                "LIVE",
                "ops stuck in causal delivery at quiescence",
                format!("D{}: [{}]", x.id, p.join(",")),
            ));
        }
        if !x.outbox.is_empty() {
            let why = x
                .notices
                .iter()
                .rev()
                .find_map(|n| {
                    if let Notice::UploadBlocked { why, .. } = n {
                        Some(*why)
                    } else {
                        None
                    }
                })
                .unwrap_or("unknown");
            out.push(Violation::new(
                "LIVE",
                format!("upload blocked at quiescence: {why}"),
                format!("D{}", x.id),
            ));
        }
        if x.read_only {
            out.push(Violation::new(
                "LIVE",
                "device still read-only at quiescence",
                format!("D{}", x.id),
            ));
        }
    }
    // RECOMP: ADR 0012 §6 recomputation from the newest snapshot and the retained ops.
    for x in &active {
        let r = x.recompute(&w.cfg);
        if r.canon() != x.item.canon() {
            out.push(Violation::new(
                "RECOMP",
                "newest snapshot + retained ops do not rebuild the item (ADR 0012 §6)",
                format!(
                    "D{}: item {}\n  newest snapshot + retained ops: {}",
                    x.id,
                    x.item.canon(),
                    r.canon()
                ),
            ));
            break;
        }
    }
    // HLC: the clock condition (ADR 0012 §2 "The standard update rules apply on local events and
    // on receipt"), over U, for ops whose authors' clocks are not skewed.
    {
        let skewed = |d: u8| w.devs.get(d as usize).is_some_and(|x| x.skew > 0);
        let mut bad: Option<String> = None;
        'o: for o in &u {
            if skewed(o.dot().dev) {
                continue;
            }
            for p in &u {
                if p.dot() != o.dot()
                    && !skewed(p.dot().dev)
                    && o.h.ctx.covers(p.dot())
                    && o.h.hlc <= p.h.hlc
                {
                    bad = Some(format!(
                        "{} (hlc {}) has a context covering {} (hlc {})",
                        o.dot(),
                        crate::types::fmt_hlc(o.h.hlc),
                        p.dot(),
                        crate::types::fmt_hlc(p.h.hlc)
                    ));
                    break 'o;
                }
            }
        }
        if let Some(b) = bad {
            out.push(Violation::new(
                "HLC",
                "an op's HLC is not above an op its causal context covers",
                b,
            ));
        }
    }
    // PIN: at quiescence the server still retains more than two snapshots of the item under
    // ADR 0021's rule (§6: "an honest race adds one per concurrent writer until a later snapshot
    // covers its ops"). Not checked under the two-author rule, which retains more by design.
    if w.server.rule == ServerRule::Adr0021 && w.server.snaps.len() > 2 {
        let v: Vec<String> = w
            .server
            .snaps
            .iter()
            .map(|s| format!("{} clamped={}", s.snap.name(), s.clamped))
            .collect();
        let vvs: Vec<&crate::types::VV> =
            w.server.snaps.iter().map(|s| s.snap.state.vv()).collect();
        let chain = vvs.iter().all(|a| vvs.iter().all(|b| a.leq(b) || b.leq(a)));
        let kind = if chain {
            "more than two snapshots retained at quiescence: covered VVs form a chain (a stale snapshot stored after a newer one)"
        } else {
            "more than two snapshots retained at quiescence: two retained covered VVs are concurrent"
        };
        out.push(Violation::new("PIN", kind, v.join(", ")));
    }
    if w.drain_capped {
        out.push(Violation::new(
            "LIVE",
            "drain did not reach quiescence within its round cap",
            String::new(),
        ));
    }
    for v in &w.server.violations {
        out.push(Violation::new("SRV", v.clone(), String::new()));
    }
    // FORK: two signed versions of one dot were stored (a restore, then a re-issue of an op that
    // had been stored before it): receivers can hold either.
    if !w.second_versions.is_empty() {
        let ds: Vec<String> = w.second_versions.iter().map(|d| d.to_string()).collect();
        let purge = w.second_versions.iter().any(|d| {
            w.stored_version
                .get(d)
                .is_some_and(|o| o.b.marker == Marker::Purge)
        });
        let kind = if purge {
            "two signed versions of one Purge were stored"
        } else {
            "two signed versions of one non-Purge op were stored (no state byte differs)"
        };
        out.push(Violation::new("FORK", kind, ds.join(",")));
    }
    // KEY: an op accepted through a stale-epoch exemption although the server had never stored it:
    // it stays under a pre-rotation item key (CRYPTO.md §11.6 writer rule bypassed).
    if !w.stale_exposed.is_empty() {
        let ds: Vec<String> = w.stale_exposed.iter().map(|d| d.to_string()).collect();
        let purge_only = w.stale_exposed.iter().all(|d| {
            w.stored_version
                .get(d)
                .is_some_and(|o| o.b.marker == Marker::Purge)
        });
        let kind = if purge_only {
            "never-stored Purge accepted under a stale epoch (no field value)"
        } else {
            "never-stored op with field values accepted under a stale epoch"
        };
        out.push(Violation::new("KEY", kind, ds.join(",")));
    }
    // Keep the ADR 0012 §6 path apart: a replica holds (or flagged) an op past a revocation
    // cut-off, or some op's context covers such a dot (after a restore, a revocation signed against
    // the rolled-back server can cut off ops other devices already applied). Every P1-P3, LIVE and
    // GAP kind of such a run gets a suffix, so that each kind's minimal trace is one of its class.
    let cut = cutoffs(w);
    let past = |d: Dot| cut.get(&d.dev).is_some_and(|&h| d.seq > h);
    let s6 = w.devs.iter().any(|d| {
        d.notices
            .iter()
            .any(|n| matches!(n, Notice::PastCutoff { .. }))
    }) || w.authored.values().any(|o| {
        o.h.ctx
            .0
            .iter()
            .any(|(&x, &s)| s > 0 && past(Dot::new(x, s)))
    });
    // The conflict of answers 2 and 4: a header a healing request stored without its body whose
    // every retained cover was written by a device that wrote a faulty snapshot. That device is
    // then the server's only source for the op, which two-author covers exist to prevent. Every
    // P1-P3 kind of such a run gets a suffix.
    let faulty_authors: BTreeSet<u8> = w
        .snaps
        .iter()
        .filter(|s| !s.honest)
        .map(|s| s.author)
        .collect();
    let faulty_sole_cover = w.faulty_sole_cover_served
        || !faulty_authors.is_empty()
            && w.server.stored_bodiless.iter().any(|d| {
                let covers: Vec<u8> = w
                    .server
                    .snaps
                    .iter()
                    .filter(|x| x.clamped.covers(*d))
                    .map(|x| x.snap.author)
                    .collect();
                w.server.ops.get(d).is_some_and(|o| o.b.is_none())
                    && !covers.is_empty()
                    && covers.iter().all(|a| faulty_authors.contains(a))
            });
    // Two or more devices stored faulty snapshots: beyond the bound two-author covers are built
    // for (f faulty devices need f + 1 authors, answer 4).
    let stored_faulty_authors: BTreeSet<u8> = w
        .snaps
        .iter()
        .filter(|s| !s.honest && w.stored_snaps.contains(&s.id))
        .map(|s| s.author)
        .collect();
    if stored_faulty_authors.len() >= 2 {
        for v in out.iter_mut().filter(|v| is_core(v.prop)) {
            v.kind.push_str(" [two or more faulty authors]");
        }
    }
    if faulty_sole_cover {
        for v in out.iter_mut().filter(|v| is_core(v.prop)) {
            v.kind
                .push_str(" [a healed header's only covers are by a faulty author]");
        }
    }
    if s6 {
        for v in out
            .iter_mut()
            .filter(|v| is_core(v.prop) || matches!(v.prop, "LIVE" | "GAP"))
        {
            v.kind
                .push_str(" [with an op past a revocation cut-off: ADR 0012 §6 path]");
        }
    }
    out
}

/// Coverage: (active device, value) pairs that P2 accounts for only by ADR 0012 §5 deterministic
/// pruning, so that a run can show pruning was reached.
pub fn pruned_values(w: &World) -> u64 {
    let u = universe_ops(w);
    let mut n = 0;
    for x in w.devs.iter().filter(|d| d.status == Status::Active) {
        let Item::Live(l) = &x.item else { continue };
        for op in &u {
            let dot = op.dot();
            if !x.item.vv().covers(dot) {
                continue;
            }
            for (key, _) in op.writes_with_lifecycle() {
                if !find_entry(l.regs.get(key), dot) && !find_entry(l.hist.get(key), dot) {
                    let rank = (op.h.hlc, dot.dev, dot.seq);
                    let pruned = superseded(&u, key, dot, x)
                        && l.hist.get(key).is_some_and(|h| {
                            h.len() >= w.cfg.n_hist && h.iter().all(|e| e.rank() > rank)
                        });
                    if pruned {
                        n += 1;
                    }
                }
            }
        }
    }
    n
}

fn next_permutation(p: &mut [usize]) -> bool {
    if p.len() < 2 {
        return false;
    }
    let mut i = p.len() - 1;
    while i > 0 && p[i - 1] >= p[i] {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    let mut j = p.len() - 1;
    while p[j] <= p[i - 1] {
        j -= 1;
    }
    p.swap(i - 1, j);
    p[i..].reverse();
    true
}

/// Orders to test: all permutations for n <= 6, else `samples` seeded ones (plus identity).
fn orders(n: usize, samples: usize, seed: u64) -> Vec<Vec<usize>> {
    let mut v = Vec::new();
    let mut p: Vec<usize> = (0..n).collect();
    if n <= 6 {
        loop {
            v.push(p.clone());
            if !next_permutation(&mut p) {
                break;
            }
        }
    } else {
        let mut rng = XorShift::new(seed);
        v.push(p.clone());
        for _ in 0..samples {
            rng.shuffle(&mut p);
            v.push(p.clone());
        }
    }
    v
}

/// With duplicates: re-deliver one element right after itself and the first again at the end.
fn with_dups<'a>(msgs: &'a [Msg], order: &[usize]) -> Vec<&'a Msg> {
    let mut seq: Vec<&Msg> = Vec::with_capacity(order.len() + 2);
    let mid = order.len() / 2;
    for (i, &k) in order.iter().enumerate() {
        seq.push(&msgs[k]);
        if i == mid {
            seq.push(&msgs[k]);
        }
    }
    if let Some(&f) = order.first() {
        seq.push(&msgs[f]);
    }
    seq
}

pub fn check_p3(w: &World, ctx: &mut CheckCtx) -> Vec<Violation> {
    let mut ops = universe_ops(w);
    ops.sort_by_key(|o| o.dot());
    let snaps = honest_stored_snaps(w);
    let all = all_stored_snaps(w);
    let revs = cutoffs(w);
    let mut h = DefaultHasher::new();
    for o in &ops {
        o.hash(&mut h);
    }
    for s in &all {
        s.id.hash(&mut h);
        s.state.hash(&mut h);
        s.honest.hash(&mut h);
        s.tainted.hash(&mut h);
    }
    w.cfg.name.hash(&mut h);
    revs.hash(&mut h);
    let fp = h.finish();
    if let Some(v) = ctx.p3_cache.get(&fp) {
        return v.clone();
    }
    ctx.p3_sets += 1;
    let keys = all_keys(&ops, &all);
    let mut out = Vec::new();

    let op_msgs: Vec<Msg> = ops.iter().cloned().map(Msg::Op).collect();
    let reference = replay_fresh(&op_msgs.iter().collect::<Vec<_>>(), &w.cfg, &keys, &revs);
    for order in orders(op_msgs.len(), ctx.p3_samples, fp) {
        ctx.p3_runs += 1;
        let r = replay_fresh(&with_dups(&op_msgs, &order), &w.cfg, &keys, &revs);
        if r != reference {
            let names: Vec<String> = order.iter().map(|&i| ops[i].dot().to_string()).collect();
            out.push(Violation::new(
                "P3",
                "op delivery order changes the state",
                format!(
                    "order [{}]\n  got:       {r}\n  canonical: {reference}",
                    names.join(" ")
                ),
            ));
            break;
        }
    }

    if !snaps.is_empty() {
        let mut mixed: Vec<Msg> = ops.iter().cloned().map(Msg::Op).collect();
        mixed.extend(snaps.iter().cloned().map(Msg::Snap));
        let name = |m: &Msg| match m {
            Msg::Op(o) => o.dot().to_string(),
            Msg::Snap(s) => format!("{}{{vv={}}}", s.name(), s.state.vv()),
        };
        for order in orders(mixed.len(), ctx.p3_samples, fp ^ 0x5eed) {
            ctx.p3_runs += 1;
            let r = replay_fresh(&with_dups(&mixed, &order), &w.cfg, &keys, &revs);
            if r != reference {
                let names: Vec<String> = order.iter().map(|&i| name(&mixed[i])).collect();
                let kind = if r.contains("STUCK") {
                    "ops stuck behind an absorbed snapshot".to_string()
                } else {
                    let seq = with_dups(&mixed, &order);
                    let (ri, _) = replay_fresh_item(&seq, &w.cfg, &keys, &revs);
                    let (refi, _) = replay_fresh_item(
                        &op_msgs.iter().collect::<Vec<_>>(),
                        &w.cfg,
                        &keys,
                        &revs,
                    );
                    format!(
                        "absorbing honest snapshots changes the state: {}",
                        classify(&ri, &refi)
                    )
                };
                out.push(Violation::new(
                    "P3-mixed",
                    kind,
                    format!(
                        "order [{}]\n  got:        {r}\n  ops alone:  {reference}",
                        names.join(" ")
                    ),
                ));
                break;
            }
        }
    }
    // P3-faulty: every stored snapshot, faulty ones included, mixed with U in any order.
    if all.iter().any(|s| !s.honest || s.tainted) {
        let mut mixed: Vec<Msg> = ops.iter().cloned().map(Msg::Op).collect();
        mixed.extend(all.iter().cloned().map(Msg::Snap));
        let name = |m: &Msg| match m {
            Msg::Op(o) => o.dot().to_string(),
            Msg::Snap(s) => format!(
                "{}{}{{vv={}}}",
                s.name(),
                if s.honest { "" } else { "*" },
                s.state.vv()
            ),
        };
        let mut first: Option<String> = None;
        for order in orders(mixed.len(), ctx.p3_samples, fp ^ 0xfa17) {
            ctx.p3_runs += 1;
            let r = replay_fresh(&with_dups(&mixed, &order), &w.cfg, &keys, &revs);
            match &first {
                None => first = Some(r),
                Some(f) if *f != r => {
                    let names: Vec<String> = order.iter().map(|&i| name(&mixed[i])).collect();
                    out.push(Violation::new(
                        "P3-faulty",
                        "absorbing the stored snapshots (faulty included) depends on the order",
                        format!("order [{}]\n  got:   {r}\n  first: {f}", names.join(" ")),
                    ));
                    break;
                }
                _ => {}
            }
        }
    }
    ctx.p3_cache.insert(fp, out.clone());
    out
}
