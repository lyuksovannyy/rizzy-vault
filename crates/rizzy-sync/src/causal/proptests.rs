//! Property tests of the chain check and causal delivery over generated histories (ADR 0012
//! §12 "Generated histories" and properties 3 and 7; ADR 0021 §8 "fetches from cursors behind
//! the head at every step" with compaction on).
//!
//! # The model
//!
//! Three authors write ops on three items of one vault. Each author keeps the set of ops it has
//! applied, closed under causality: it learns another author's op together with that op's
//! causal past. An op's causal context is the author's item VV of that set (ADR 0012 §2), its
//! `vault_prev_seq` the author's previous op in the vault, and its `device_seq` sometimes skips
//! one (an op in another vault). Honest snapshots record an author's item VV at a point of the
//! history. With compaction on, the server serves an op bodiless when some snapshot of its item
//! covers it (a coin decides), with every snapshot that covers it as covers.
//!
//! A receiver that writes nothing fetches in a generated schedule: pages that take a few headers
//! of each chain from its cursor, headers withheld, covers left out, the head served again as a
//! duplicate, bodies that wait for their key and are released later in any order, deliveries
//! taken at any point, and, in one property, a revocation learned at any point. After each
//! response the harness checks the commit against an oracle written from ADR 0012 §7 over the
//! model, not over the log's state; after each batch of deliveries it checks every delivery.
//! Then an honest server serves everything left.
//!
//! # Properties
//!
//! 1. **Every gap is reported, and nothing past it is accepted** (ADR 0012 §12 property 7,
//!    INV-27): each commit accepts exactly the oracle's links and reports exactly its gaps,
//!    duplicates and rejections.
//! 2. **Delivery respects causality** (ADR 0012 §4 step 2): when an op is delivered fresh, every
//!    earlier op of its chain is settled, and so is every op of its item that its causal context
//!    covers; an op delivered as covered is covered by what the receiver absorbed. No body is
//!    delivered twice or delivered bodiless, and no op past a known cut-off is delivered.
//! 3. **Nothing is held silently:** after each batch, every accepted op that is not settled,
//!    and not past a cut-off, is listed by [`VaultLog::waiting`].
//! 4. **The end state does not depend on the schedule** (ADR 0012 §12 property 3): once the
//!    honest server has served everything, every body has been delivered exactly once, every
//!    bodiless op is covered, the cursor is every chain's head and each item's settled VV is the
//!    item VV of the whole history, whatever the schedule was. With a revocation, what is left
//!    is reported: waiting ops, their missing predecessors, and a chain below its cut-off.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use rizzy_core::ids::{OpId, SnapshotId};

use super::*;
use crate::header::ItemSchemaVersion;

/// The vault of every history.
const VAULT: VaultId = VaultId::from_bytes([0x11; 16]);
/// The authors' id bytes, ascending, so the device order is the index order.
const AUTHORS: [u8; 3] = [0xa1, 0xb2, 0xc3];
/// The items' id bytes.
const ITEMS: [u8; 3] = [0x58, 0x59, 0x5a];
/// The receiver.
const RECEIVER: u8 = 0xee;

fn device(i: usize) -> DeviceId {
    DeviceId::from_bytes([AUTHORS[i]; 16])
}

fn item(i: usize) -> ItemId {
    ItemId::from_bytes([ITEMS[i]; 16])
}

/// One step of a generated history.
#[derive(Clone, Debug)]
enum Step {
    /// `device` saves `item`; `skip` spends one `device_seq` in another vault first.
    Write {
        device: usize,
        item: usize,
        skip: bool,
    },
    /// `device` learns one of `from`'s ops and its causal past.
    Learn {
        device: usize,
        from: usize,
        pick: usize,
    },
    /// `device` writes an honest snapshot of `item`.
    Snapshot { device: usize, item: usize },
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (0..3usize, 0..3usize, prop::bool::weighted(0.2))
            .prop_map(|(device, item, skip)| Step::Write { device, item, skip }),
        3 => (0..3usize, 0..3usize, any::<usize>())
            .prop_map(|(device, from, pick)| Step::Learn { device, from, pick }),
        1 => (0..3usize, 0..3usize).prop_map(|(device, item)| Step::Snapshot { device, item }),
    ]
}

/// A generated history: every op, each author's chain, the honest snapshots.
#[derive(Debug)]
struct History {
    /// Every op's header, by dot.
    ops: BTreeMap<Dot, OpHeader>,
    /// Each author's ops in chain order.
    chains: [Vec<Dot>; 3],
    /// Honest snapshots, oldest first.
    snapshots: Vec<SnapshotHeader>,
}

/// The item VV of a set of applied ops: per device, the highest seq among them on `x`.
fn item_vv(ops: &BTreeMap<Dot, OpHeader>, applied: &BTreeSet<Dot>, x: ItemId) -> VersionVector {
    applied
        .iter()
        .copied()
        .filter(|d| ops[d].item_id == x)
        .collect()
}

impl History {
    fn build(steps: &[Step]) -> Self {
        let mut ops: BTreeMap<Dot, OpHeader> = BTreeMap::new();
        let mut past: BTreeMap<Dot, BTreeSet<Dot>> = BTreeMap::new();
        let mut chains: [Vec<Dot>; 3] = Default::default();
        let mut applied: [BTreeSet<Dot>; 3] = Default::default();
        let mut last_seq = [0u64; 3];
        let mut snapshots = Vec::new();
        for (t, step) in steps.iter().enumerate() {
            match *step {
                Step::Write {
                    device: d,
                    item: x,
                    skip,
                } => {
                    let seq = last_seq[d] + 1 + u64::from(skip);
                    let dot = Dot::new(device(d), seq).unwrap();
                    let mut op_id = [AUTHORS[d]; 16];
                    op_id[8..].copy_from_slice(&seq.to_be_bytes());
                    let header = OpHeader {
                        vault_id: VAULT,
                        item_id: item(x),
                        op_id: OpId::from_bytes(op_id),
                        dot,
                        vault_prev_seq: chains[d].last().map_or(0, |p| p.seq()),
                        hlc: Hlc::from_parts(u64::try_from(t).unwrap() + 1, 0).unwrap(),
                        item_schema_version: ItemSchemaVersion::V1,
                        vault_key_epoch: 1,
                        causal_context: item_vv(&ops, &applied[d], item(x)),
                    };
                    past.insert(dot, applied[d].clone());
                    applied[d].insert(dot);
                    ops.insert(dot, header);
                    chains[d].push(dot);
                    last_seq[d] = seq;
                }
                Step::Learn {
                    device: d,
                    from,
                    pick,
                } => {
                    if d != from && !chains[from].is_empty() {
                        let dot = chains[from][pick % chains[from].len()];
                        let learned = past[&dot].clone();
                        applied[d].extend(learned);
                        applied[d].insert(dot);
                    }
                }
                Step::Snapshot { device: d, item: x } => {
                    let covered = item_vv(&ops, &applied[d], item(x));
                    if !covered.is_empty() {
                        let n = u8::try_from(snapshots.len() % 256).unwrap();
                        snapshots.push(SnapshotHeader {
                            vault_id: VAULT,
                            item_id: item(x),
                            snapshot_id: SnapshotId::from_bytes([n; 16]),
                            author: device(d),
                            item_schema_version: ItemSchemaVersion::V1,
                            vault_key_epoch: 1,
                            covered,
                        });
                    }
                }
            }
        }
        Self {
            ops,
            chains,
            snapshots,
        }
    }

    /// The item VV of the whole history.
    fn full_vv(&self, x: ItemId) -> VersionVector {
        let all: BTreeSet<Dot> = self.ops.keys().copied().collect();
        item_vv(&self.ops, &all, x)
    }

    /// The ops the server serves bodiless: with compaction on, those some snapshot of their item
    /// covers, when the coin for their index says so.
    fn bodiless(&self, compact: bool, coins: u64) -> BTreeSet<Dot> {
        self.ops
            .iter()
            .enumerate()
            .filter(|&(i, (&dot, h))| {
                compact
                    && (coins >> (i % 64)) & 1 == 1
                    && self
                        .snapshots
                        .iter()
                        .any(|s| s.item_id == h.item_id && s.covered.covers(dot))
            })
            .map(|(_, (&dot, _))| dot)
            .collect()
    }
}

/// One Fetch response or page.
#[derive(Clone, Debug)]
struct Fetch {
    /// How many headers of each chain to serve from the receiver's cursor.
    take: [usize; 3],
    /// A header left out: (author, index in the served slice).
    withhold: Option<(usize, usize)>,
    /// Bit i: the i-th body served waits for its key.
    waiting: u64,
    /// Serve covers for the bodiless headers.
    covers: bool,
    /// Serve each chain's head again.
    dup: bool,
    /// Serve the records in reverse order.
    reverse: bool,
}

/// One action of a receiver's schedule.
#[derive(Clone, Debug)]
enum Action {
    Fetch(Fetch),
    /// Release a waiting body: the one at this index, modulo their count.
    Release(usize),
    Deliver,
    /// Learn that author 0 is revoked with this cut-off.
    Revoke(u64),
}

fn fetch() -> impl Strategy<Value = Fetch> {
    (
        [0usize..4, 0..4, 0..4],
        proptest::option::weighted(0.3, (0usize..3, 0usize..4)),
        any::<u64>(),
        prop::bool::weighted(0.85),
        prop::bool::weighted(0.2),
        any::<bool>(),
    )
        .prop_map(|(take, withhold, waiting, covers, dup, reverse)| Fetch {
            take,
            withhold,
            waiting,
            covers,
            dup,
            reverse,
        })
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        5 => fetch().prop_map(Action::Fetch),
        2 => any::<usize>().prop_map(Action::Release),
        2 => Just(Action::Deliver),
    ]
}

/// One response and what the oracle expects of it.
#[derive(Default)]
struct Expected {
    /// The records served.
    served: Vec<ServedOp>,
    /// The links the commit must accept, per device in chain order.
    accepted: Vec<Dot>,
    /// The reports the commit must make, in order.
    reports: Vec<Report>,
    /// The accepted links served bodiless.
    bodiless: Vec<Dot>,
    /// The accepted links whose body waits for its key.
    waiting: Vec<Dot>,
}

/// A receiver running a schedule against a history, with the model's view beside the log's.
struct Run<'h> {
    h: &'h History,
    /// The ops the server serves bodiless.
    bodiless: BTreeSet<Dot>,
    log: VaultLog,
    /// Every dot delivered so far.
    delivered: BTreeSet<Dot>,
    /// Per item, the join of the covers the receiver absorbed.
    absorbed: BTreeMap<ItemId, VersionVector>,
    /// Accepted links whose body waits for its key.
    waiting: Vec<Dot>,
    /// Author 0's cut-off, once learned.
    cut: Option<u64>,
}

impl<'h> Run<'h> {
    fn new(h: &'h History, bodiless: BTreeSet<Dot>) -> Self {
        Self {
            h,
            bodiless,
            log: VaultLog::new(VAULT, DeviceId::from_bytes([RECEIVER; 16])),
            delivered: BTreeSet::new(),
            absorbed: BTreeMap::new(),
            waiting: Vec::new(),
            cut: None,
        }
    }

    /// Whether the receiver has settled `dot`, by the model: delivered, or covered by a cover it
    /// absorbed.
    fn settled(&self, dot: Dot) -> bool {
        self.delivered.contains(&dot)
            || self
                .absorbed
                .get(&self.h.ops[&dot].item_id)
                .is_some_and(|vv| vv.covers(dot))
    }

    fn past_cut(&self, dot: Dot) -> bool {
        dot.device_id() == device(0) && self.cut.is_some_and(|c| dot.seq() > c)
    }

    fn act(&mut self, action: &Action) -> Result<(), TestCaseError> {
        match action {
            Action::Fetch(f) => self.fetch(f),
            Action::Release(i) => {
                if !self.waiting.is_empty() {
                    let dot = self.waiting.remove(i % self.waiting.len());
                    let released = self.log.body_verified(dot);
                    if self.past_cut(dot) {
                        prop_assert_eq!(released, Err(BodyError::NotWaiting));
                    } else {
                        prop_assert_eq!(released, Ok(()));
                    }
                }
                Ok(())
            }
            Action::Deliver => self.deliver(),
            Action::Revoke(cut) => self.revoke(*cut),
        }
    }

    /// Whether the receiver refuses snapshot `s` for its author: author 0, revoked, with a
    /// covered-VV entry for itself above its cut-off (CRYPTO.md §11.8 step 4).
    fn refused(&self, s: &SnapshotHeader) -> bool {
        s.author == device(0) && self.cut.is_some_and(|c| s.covered.get(device(0)) > c)
    }

    /// Serves one response and checks the plan and the commit against the oracle.
    fn fetch(&mut self, f: &Fetch) -> Result<(), TestCaseError> {
        let cursor = self.log.cursor();
        let mut e = Expected::default();
        let mut bit = 0usize;
        for d in 0..3 {
            self.serve_chain(d, cursor.get(device(d)), f, &mut bit, &mut e);
        }
        if f.reverse {
            e.served.reverse();
        }
        // Covers: every snapshot that covers a served bodiless header, newest first.
        let covers: Vec<SnapshotHeader> = if f.covers {
            self.h
                .snapshots
                .iter()
                .rev()
                .filter(|s| {
                    e.served.iter().any(|o| {
                        o.body == BodyStatus::Bodiless
                            && o.header.item_id == s.item_id
                            && s.covered.covers(o.header.dot)
                    })
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        let expected_absorb: Vec<usize> = covers
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                !self.refused(s)
                    && e.bodiless
                        .iter()
                        .any(|&dot| self.h.ops[&dot].item_id == s.item_id && s.covered.covers(dot))
            })
            .map(|(i, _)| i)
            .collect();
        let expected_refused: Vec<usize> = covers
            .iter()
            .enumerate()
            .filter(|(_, s)| self.refused(s))
            .map(|(i, _)| i)
            .collect();
        // Reading 7's cut, by the model: each chain's head or last header the oracle accepts.
        let mut expected_cut: VersionVector = (0..3)
            .filter_map(|d| Dot::new(device(d), self.log.head(device(d))))
            .collect();
        for &dot in &e.accepted {
            expected_cut.add(dot);
        }
        let plan = self.log.plan_covers(&e.served, &covers);
        prop_assert_eq!(&plan.absorb, &expected_absorb);
        prop_assert_eq!(&plan.refused, &expected_refused);
        prop_assert_eq!(&plan.links, &e.accepted);
        prop_assert_eq!(&plan.cut, &expected_cut);
        for &i in &plan.absorb {
            let mut taken = covers[i].covered.clone();
            taken.meet(&expected_cut);
            let recorded = self
                .log
                .record_absorbed(&plan, covers[i].item_id, &covers[i].covered);
            prop_assert_eq!(&recorded, &taken);
            self.absorbed
                .entry(covers[i].item_id)
                .or_default()
                .join(&taken);
        }
        let commit = self.log.commit(&e.served);
        prop_assert_eq!(&commit.accepted, &e.accepted);
        prop_assert_eq!(&commit.reports, &e.reports);
        self.waiting.extend(e.waiting);
        // INV-27: with every cover accepted, no item holds a device past its chain's head.
        for x in (0..3).map(item) {
            for entry in self.log.settled(x).entries() {
                prop_assert!(
                    entry.seq() <= self.log.head(entry.device_id()),
                    "{:?} settled past the head",
                    entry
                );
            }
        }
        Ok(())
    }

    /// Serves up to `f.take[d]` headers of author `d`'s chain after `head`, and walks them with
    /// the oracle: ADR 0012 §7 over the model. `bit` counts the bodies served so far.
    fn serve_chain(&self, d: usize, head: u64, f: &Fetch, bit: &mut usize, e: &mut Expected) {
        let chain = &self.h.chains[d];
        let start = chain
            .iter()
            .position(|dot| dot.seq() > head)
            .unwrap_or(chain.len());
        let end = (start + f.take[d]).min(chain.len());
        let mut chain_ops: Vec<ServedOp> = Vec::new();
        if f.dup && head > 0 {
            let dot = Dot::new(device(d), head).unwrap();
            chain_ops.push(ServedOp {
                header: self.h.ops[&dot].clone(),
                body: BodyStatus::Verified,
            });
            e.reports.push(Report::Duplicate { dot });
        }
        let mut prev = Some(head);
        for (j, &dot) in chain[start..end].iter().enumerate() {
            if f.withhold == Some((d, j)) {
                continue;
            }
            let body = if self.bodiless.contains(&dot) {
                BodyStatus::Bodiless
            } else if (f.waiting >> (*bit % 64)) & 1 == 1 {
                BodyStatus::Waiting
            } else {
                BodyStatus::Verified
            };
            *bit += 1;
            let op = ServedOp {
                header: self.h.ops[&dot].clone(),
                body,
            };
            if let Some(p) = prev {
                prev = self
                    .oracle_step(d, p, &op, f.covers, e)
                    .then_some(dot.seq());
            }
            chain_ops.push(op);
        }
        if f.reverse {
            chain_ops.reverse();
        }
        e.served.extend(chain_ops);
    }

    /// One header of the oracle's walk, after `prev`: whether it becomes a link, with what is
    /// expected recorded in `e`. `covers` says whether the response serves covers.
    fn oracle_step(
        &self,
        d: usize,
        prev: u64,
        op: &ServedOp,
        covers: bool,
        e: &mut Expected,
    ) -> bool {
        let h = &op.header;
        let dot = h.dot;
        let covered =
            self.absorbed
                .get(&h.item_id)
                .is_some_and(|vv| vv.covers(dot))
                || (covers
                    && self.h.snapshots.iter().any(|s| {
                        !self.refused(s) && s.item_id == h.item_id && s.covered.covers(dot)
                    }));
        let report = if let Some(cut) = self.cut
            && d == 0
            && dot.seq() > cut
        {
            Some(Report::PastCutoff {
                dot,
                last_accepted: cut,
            })
        } else if h.vault_prev_seq != prev {
            Some(Report::Gap {
                device: device(d),
                after: prev,
                cause: GapCause::Unlinked {
                    next: dot,
                    vault_prev_seq: h.vault_prev_seq,
                },
            })
        } else if op.body == BodyStatus::Bodiless && !covered {
            Some(Report::Gap {
                device: device(d),
                after: prev,
                cause: GapCause::Uncovered { dot },
            })
        } else {
            None
        };
        if let Some(report) = report {
            e.reports.push(report);
            return false;
        }
        e.accepted.push(dot);
        match op.body {
            BodyStatus::Bodiless => e.bodiless.push(dot),
            BodyStatus::Waiting => e.waiting.push(dot),
            BodyStatus::Verified | BodyStatus::Rejected => {}
        }
        true
    }

    /// Takes the deliveries and checks each one, then checks that nothing is held silently.
    fn deliver(&mut self) -> Result<(), TestCaseError> {
        for delivery in self.log.take_deliveries() {
            let dot = delivery.dot;
            let op = &self.h.ops[&dot];
            prop_assert_eq!(delivery.item_id, op.item_id);
            prop_assert_eq!(delivery.hlc, op.hlc);
            prop_assert!(
                !self.bodiless.contains(&dot),
                "bodiless {:?} delivered",
                dot
            );
            prop_assert!(!self.past_cut(dot), "{:?} past the cut-off delivered", dot);
            if delivery.covered {
                prop_assert!(self.settled(dot), "covered {:?} not covered", dot);
            } else {
                // Every earlier op of its chain is settled.
                let chain = &self.h.chains[AUTHORS
                    .iter()
                    .position(|&b| device_of(b) == dot.device_id())
                    .unwrap()];
                for &earlier in chain.iter().take_while(|&&e| e != dot) {
                    prop_assert!(self.settled(earlier), "{:?} before {:?}", dot, earlier);
                }
                // Every op of its item its causal context covers is settled.
                for (&other, h) in &self.h.ops {
                    if h.item_id == op.item_id && op.causal_context.covers(other) {
                        prop_assert!(self.settled(other), "{:?} before {:?}", dot, other);
                    }
                }
            }
            prop_assert!(self.delivered.insert(dot), "{:?} delivered twice", dot);
        }
        self.check_no_silent_hold()
    }

    /// Every accepted op that is not settled, and not past the cut-off, is listed as waiting.
    fn check_no_silent_hold(&self) -> Result<(), TestCaseError> {
        let listed: BTreeSet<Dot> = self.log.waiting().iter().map(|w| w.dot).collect();
        for (d, chain) in self.h.chains.iter().enumerate() {
            let head = self.log.head(device(d));
            for &dot in chain.iter().take_while(|dot| dot.seq() <= head) {
                if !self.settled(dot) && !self.past_cut(dot) {
                    prop_assert!(listed.contains(&dot), "{:?} held silently", dot);
                }
            }
        }
        Ok(())
    }

    fn revoke(&mut self, cut: u64) -> Result<(), TestCaseError> {
        if self.cut.is_some() {
            return Ok(());
        }
        let head = self.log.head(device(0));
        let expected_rejected: Vec<Dot> = self.h.chains[0]
            .iter()
            .copied()
            .filter(|dot| dot.seq() > cut && dot.seq() <= head && !self.delivered.contains(dot))
            .collect();
        let settled_vv = |x: ItemId| {
            let mut vv = self.absorbed.get(&x).cloned().unwrap_or_default();
            for &dot in &self.delivered {
                if self.h.ops[&dot].item_id == x {
                    vv.add(dot);
                }
            }
            vv
        };
        let expected_held: Vec<ItemId> = (0..3)
            .map(item)
            .filter(|&x| settled_vv(x).get(device(0)) > cut)
            .collect();
        let revocation = self.log.learn_revocation(device(0), cut);
        prop_assert_eq!(&revocation.rejected, &expected_rejected);
        prop_assert_eq!(&revocation.held_past_cutoff, &expected_held);
        self.cut = Some(cut);
        Ok(())
    }

    /// An honest server serves everything left; every waiting body is released.
    fn finish(&mut self) -> Result<(), TestCaseError> {
        let all = Fetch {
            take: [usize::MAX / 4; 3],
            withhold: None,
            waiting: 0,
            covers: true,
            dup: false,
            reverse: false,
        };
        self.fetch(&all)?;
        for dot in std::mem::take(&mut self.waiting) {
            let released = self.log.body_verified(dot);
            prop_assert_eq!(released.is_ok(), !self.past_cut(dot));
        }
        self.deliver()
    }

    /// The end state after [`Run::finish`] when no op was cut: every chain complete, every body
    /// delivered, every bodiless op covered, the settled VVs those of the whole history, and
    /// `reports` exactly what a complete Fetch reports.
    fn check_end(&mut self, reports: &[Report]) -> Result<(), TestCaseError> {
        for (d, chain) in self.h.chains.iter().enumerate() {
            prop_assert_eq!(
                self.log.head(device(d)),
                chain.last().map_or(0, |dot| dot.seq())
            );
        }
        for &dot in self.h.ops.keys() {
            if self.bodiless.contains(&dot) {
                prop_assert!(self.settled(dot));
            } else {
                prop_assert!(self.delivered.contains(&dot), "{:?} never delivered", dot);
            }
        }
        for x in (0..3).map(item) {
            prop_assert_eq!(self.log.settled(x), self.h.full_vv(x));
        }
        prop_assert!(self.log.waiting().is_empty());
        prop_assert_eq!(self.log.complete_fetch_reports(), reports);
        prop_assert!(self.log.take_deliveries().is_empty());
        Ok(())
    }
}

fn device_of(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

/// Runs a schedule against a history and returns the final settled VVs and cursor.
fn run(
    h: &History,
    bodiless: &BTreeSet<Dot>,
    actions: &[Action],
) -> Result<(Vec<VersionVector>, VersionVector), TestCaseError> {
    let mut r = Run::new(h, bodiless.clone());
    for action in actions {
        r.act(action)?;
    }
    r.finish()?;
    r.check_end(&[])?;
    Ok((
        (0..3).map(|x| r.log.settled(item(x))).collect(),
        r.log.cursor(),
    ))
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Properties 1–4 without compaction: the same ops in two random arrival schedules, with
    /// withheld headers, duplicates, reordered records and bodies released in any order.
    #[test]
    fn delivery_is_causal_and_gaps_are_reported(
        steps in prop::collection::vec(step(), 1..40),
        first in prop::collection::vec(action(), 0..30),
        second in prop::collection::vec(action(), 0..30),
    ) {
        let h = History::build(&steps);
        let none = BTreeSet::new();
        let a = run(&h, &none, &first)?;
        let b = run(&h, &none, &second)?;
        prop_assert_eq!(a, b);
    }

    /// Properties 1–4 with compaction on: bodiless headers served behind covers by one or more
    /// authors, sometimes without their covers, in two random arrival schedules.
    #[test]
    fn delivery_is_causal_and_gaps_are_reported_with_compaction(
        steps in prop::collection::vec(step(), 1..40),
        coins in any::<u64>(),
        first in prop::collection::vec(action(), 0..30),
        second in prop::collection::vec(action(), 0..30),
    ) {
        let h = History::build(&steps);
        let bodiless = h.bodiless(true, coins);
        let a = run(&h, &bodiless, &first)?;
        let b = run(&h, &bodiless, &second)?;
        prop_assert_eq!(a, b);
    }

    /// Properties 1–3 with a revocation of author 0 learned at a random point, with a random
    /// cut-off: nothing past it is delivered, held links past it are rejected, items already
    /// holding it are reported, and what stays undelivered at the end is reported.
    #[test]
    fn a_revocation_is_enforced_and_reported(
        steps in prop::collection::vec(step(), 1..40),
        coins in any::<u64>(),
        compact in any::<bool>(),
        mut actions in prop::collection::vec(action(), 0..30),
        at in any::<usize>(),
        cut in 0u64..12,
    ) {
        let h = History::build(&steps);
        let bodiless = h.bodiless(compact, coins);
        let at = at % (actions.len() + 1);
        actions.insert(at, Action::Revoke(cut));
        let mut r = Run::new(&h, bodiless);
        for action in &actions {
            r.act(action)?;
        }
        r.finish()?;
        r.check_no_silent_hold()?;
        let reports = r.log.complete_fetch_reports();
        let head = r.log.head(device(0));
        let below = Report::Gap {
            device: device(0),
            after: head,
            cause: GapCause::BelowCutoff { last_accepted: cut },
        };
        prop_assert_eq!(reports.contains(&below), head < cut);
        // Every other chain is complete, unless it stops at a bodiless op whose only covers are
        // author 0's snapshots claiming author 0's ops past the cut-off: those are refused
        // (CRYPTO.md §11.8 step 4), and the commit reported the gap.
        for d in 1..3 {
            let head_d = r.log.head(device(d));
            let last = h.chains[d].last().map_or(0, |dot| dot.seq());
            if head_d != last {
                let next = h.chains[d].iter().copied().find(|dot| dot.seq() > head_d);
                let blocked = next.is_some_and(|dot| {
                    r.bodiless.contains(&dot)
                        && h.snapshots
                            .iter()
                            .filter(|s| s.item_id == h.ops[&dot].item_id && s.covered.covers(dot))
                            .all(|s| r.refused(s))
                });
                prop_assert!(blocked, "chain {} stops at {} below {}", d, head_d, last);
            }
        }
        // Nothing waits silently after the complete Fetch, whether the revocation came before or
        // after the ops it cuts: an op left waiting for a predecessor is reported as missing,
        // unless an op of the predecessor's device on that item, at or above it, is itself
        // listed as waiting (and so reported in turn, down to the op the cut-off rejected).
        let waiting = r.log.waiting();
        for w in &waiting {
            if let WaitReason::Context { missing } = w.reason {
                let missing_report = Report::MissingPredecessor {
                    waiting: w.dot,
                    missing,
                };
                let behind_a_waiting_op = waiting.iter().any(|o| {
                    o.item_id == w.item_id
                        && o.dot.device_id() == missing.device_id()
                        && o.dot.seq() >= missing.seq()
                });
                prop_assert!(
                    reports.contains(&missing_report) || behind_a_waiting_op,
                    "{:?} waits silently",
                    w
                );
                if missing.seq() > r.log.head(missing.device_id()) {
                    prop_assert!(reports.contains(&missing_report));
                }
            }
        }
        // When the revocation cuts nothing, everything is delivered, and only a chain below its
        // cut-off is reported: the server holds nothing up to it.
        if h.chains[0].iter().all(|dot| dot.seq() <= cut) {
            let expected: Vec<Report> = (head < cut).then_some(below).into_iter().collect();
            r.check_end(&expected)?;
        }
    }
}
