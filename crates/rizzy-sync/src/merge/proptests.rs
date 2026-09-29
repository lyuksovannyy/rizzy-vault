//! Property tests: ADR 0012 §12 properties 1–3 in miniature, with ADR 0018 §12's tombstone,
//! absorption and no-silent-loss properties.
//!
//! A generated history runs on three simulated devices ([`super::testkit::Device`]): creates
//! and edits of three keys (Cleared values included), trash, restore and purge under the writer
//! rules, snapshots on demand and on the ADR 0018 §10 triggers, clock skew, and Fetch-like
//! syncs in which the receiver records the sender's headers, absorbs the sender's snapshots as
//! covers, delivers the bodies causally and writes the merged snapshot when one is due. Then:
//!
//! - **P1, convergence.** After every device has fetched from every other, all hold
//!   byte-identical state (the ADR 0018 §4 state-hash input), equal to a fresh replica fed the
//!   ops alone.
//! - **P3, order independence.** A fresh replica fed the set of ops in random orders, with
//!   duplicates, reaches the same bytes; and so does one fed the ops and every snapshot written
//!   in the run, interleaved at random (the merge spike's P3-mixed and `absorb` family: an
//!   honest snapshot absorbed as a join changes nothing the ops would not).
//! - **P2, no silent loss** (ADR 0018 §12). On a live item every value an op wrote is a
//!   current value or in history, or was pruned below [`HISTORY_LIMIT`] entries that rank
//!   above it; on a tombstone every non-`@lifecycle` value is late, or `c` covers it, or a
//!   later write of the same key superseded it.
//!
//! A second property drives many concurrent writes of one key, so that history passes
//! [`HISTORY_LIMIT`] and pruning runs under every delivery order. Two more take dishonest
//! snapshots (the fault kinds of [`super::faults`]): one state in any order when every body
//! comes with each snapshot, and P2 under faults for a replica that merged every body and may
//! have written a snapshot since, absorbing snapshots with no body at all: its state does not
//! change.

use std::collections::BTreeMap;

use proptest::prelude::*;

use super::testkit::{
    Device, Edit, Op, Snap, absorb, deliver, item, key_id, record_headers, reference, state_bytes,
    text,
};
use super::*;

/// The keys the generated histories write.
const KEYS: [&str; 3] = ["item.name", "item.notes", "login.password"];

/// One step of a generated history.
#[derive(Clone, Debug)]
enum Action {
    /// Device `dev` writes `KEYS[key]`: a Text value, or Cleared when `value` is 0.
    Write { dev: usize, key: usize, value: u8 },
    /// Device `dev` trashes the item, if it shows Active.
    Trash { dev: usize },
    /// Device `dev` restores the item, if it shows Trashed.
    Restore { dev: usize },
    /// Device `dev` purges the item, if it shows Trashed.
    Purge { dev: usize },
    /// Device `dev` trashes the item if it shows Active, then purges it: a purge that is
    /// often concurrent with another device's.
    TrashAndPurge { dev: usize },
    /// Device `dev` fetches everything device `from` holds.
    Sync { dev: usize, from: usize },
    /// Device `dev` writes a snapshot, if it can.
    Snapshot { dev: usize },
    /// Device `dev`'s wall clock jumps ahead.
    Tick { dev: usize, ms: u16 },
}

/// A generated step.
fn action() -> impl Strategy<Value = Action> {
    let dev = 0..3usize;
    prop_oneof![
        5 => (dev.clone(), 0..KEYS.len(), 0..4u8)
            .prop_map(|(dev, key, value)| Action::Write { dev, key, value }),
        2 => dev.clone().prop_map(|dev| Action::Trash { dev }),
        1 => dev.clone().prop_map(|dev| Action::Restore { dev }),
        2 => dev.clone().prop_map(|dev| Action::Purge { dev }),
        2 => dev.clone().prop_map(|dev| Action::TrashAndPurge { dev }),
        4 => (dev.clone(), dev.clone()).prop_map(|(dev, from)| Action::Sync { dev, from }),
        1 => dev.clone().prop_map(|dev| Action::Snapshot { dev }),
        1 => (dev, 1..5_000u16).prop_map(|(dev, ms)| Action::Tick { dev, ms }),
    ]
}

/// Three devices and what each holds.
struct World {
    /// The devices.
    devices: Vec<Device>,
    /// Every op each device holds, by dot.
    known: Vec<BTreeMap<Dot, Op>>,
    /// Every snapshot each device holds (written or absorbed), by id.
    snaps: Vec<BTreeMap<[u8; 16], Snap>>,
    /// Every snapshot written in the run.
    written: Vec<Snap>,
    /// A counter that makes each written value distinct.
    counter: u32,
    /// Absorptions of a snapshot concurrent with the receiver's state.
    concurrent: usize,
    /// Merged snapshots written after one.
    merged: usize,
}

impl World {
    /// Three devices with skewed clocks.
    fn new() -> Self {
        Self {
            devices: (0..3u8)
                .map(|i| Device::new(i + 1, u64::from(i) * 7))
                .collect(),
            known: vec![BTreeMap::new(); 3],
            snaps: vec![BTreeMap::new(); 3],
            written: Vec::new(),
            counter: 0,
            concurrent: 0,
            merged: 0,
        }
    }

    /// Keeps a snapshot device `dev` wrote.
    fn keep_snapshot(&mut self, dev: usize, s: Snap) {
        self.snaps[dev].insert(*s.header.snapshot_id.as_bytes(), s.clone());
        self.written.push(s);
    }

    /// Device `dev` writes `edit` if the writer rules allow it; a due snapshot follows.
    fn write(&mut self, dev: usize, edit: &Edit) {
        let d = &mut self.devices[dev];
        let Ok((op, applied)) = d.try_write(edit, OwnWrite::default()) else {
            return;
        };
        self.known[dev].insert(op.dot(), op);
        if applied.snapshot_due.is_some()
            && let Some(s) = self.devices[dev].snapshot()
        {
            self.keep_snapshot(dev, s);
        }
    }

    /// One step.
    fn step(&mut self, a: &Action) {
        match *a {
            Action::Write { dev, key, value } => {
                let lifecycle = self.devices[dev].merge.lifecycle();
                // Only device 1 creates; the others edit an item they hold (a write on a
                // tombstone models an editor open when the purge arrived).
                if lifecycle == ItemLifecycle::Absent && dev != 0 {
                    return;
                }
                self.counter += 1;
                let v = if value == 0 {
                    Vec::new()
                } else {
                    text(&format!("v{}-{value}", self.counter))
                };
                self.write(dev, &Edit::write(&[(KEYS[key], &v)]));
            }
            Action::Trash { dev } => {
                if self.devices[dev].merge.lifecycle() == ItemLifecycle::Active {
                    self.write(dev, &Edit::Trash);
                }
            }
            Action::Restore { dev } => {
                if self.devices[dev].merge.lifecycle() == ItemLifecycle::Trashed {
                    self.write(dev, &Edit::Restore);
                }
            }
            Action::Purge { dev } => self.write(dev, &Edit::Purge),
            Action::TrashAndPurge { dev } => {
                self.step(&Action::Trash { dev });
                self.write(dev, &Edit::Purge);
            }
            Action::Sync { dev, from } => self.sync(dev, from),
            Action::Snapshot { dev } => {
                if let Some(s) = self.devices[dev].snapshot() {
                    self.keep_snapshot(dev, s);
                }
            }
            Action::Tick { dev, ms } => self.devices[dev].now_ms += u64::from(ms),
        }
    }

    /// Device `dev` fetches from `from`: headers, then the snapshots as covers with the
    /// response's bodies, then the bodies, then the merged snapshot if one is due.
    fn sync(&mut self, dev: usize, from: usize) {
        if dev == from {
            return;
        }
        let ops: Vec<Op> = self.known[from]
            .iter()
            .filter(|(d, _)| !self.known[dev].contains_key(d))
            .map(|(_, op)| op.clone())
            .collect();
        let snaps: Vec<Snap> = self.snaps[from]
            .iter()
            .filter(|(id, _)| !self.snaps[dev].contains_key(*id))
            .map(|(_, s)| s.clone())
            .collect();
        let d = &mut self.devices[dev];
        record_headers(&mut d.merge, &ops);
        for s in &snaps {
            let got = d.absorb(s, &ops);
            // Every snapshot here is honest: none is refused, none disagrees.
            let AbsorbOutcome::Absorbed(x) = &got.outcome else {
                panic!("honest snapshot refused");
            };
            assert!(x.disagreements.is_empty());
            assert!(got.claim_cuts.is_empty());
            if x.relation == VvOrdering::Concurrent {
                self.concurrent += 1;
            }
        }
        let stuck = d.receive(&ops);
        assert!(stuck.is_empty(), "ops stuck after a sync");
        let merged = d.merge.end_fetch().and_then(|_| d.snapshot());
        for op in ops {
            self.known[dev].insert(op.dot(), op);
        }
        for s in snaps {
            self.snaps[dev].insert(*s.header.snapshot_id.as_bytes(), s);
        }
        if let Some(s) = merged {
            self.merged += 1;
            self.keep_snapshot(dev, s);
        }
    }

    /// Every device fetches from every other, twice.
    fn quiesce(&mut self) {
        for _ in 0..2 {
            for dev in 0..3 {
                for from in 0..3 {
                    self.sync(dev, from);
                }
            }
        }
    }

    /// Every op written in the run.
    fn universe(&self) -> Vec<Op> {
        let mut all: BTreeMap<Dot, Op> = BTreeMap::new();
        for k in &self.known {
            all.extend(k.iter().map(|(d, o)| (*d, o.clone())));
        }
        all.into_values().collect()
    }
}

/// A message of a replay.
#[derive(Clone, Debug)]
enum Msg {
    /// An op body.
    Op(Op),
    /// A snapshot.
    Snap(Snap),
}

/// A small deterministic generator for shuffles.
struct XorShift(u64);

impl XorShift {
    /// The next value.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Shuffles `v` (Fisher–Yates), then duplicates one element.
    fn shuffle_with_duplicate<T: Clone>(&mut self, v: &mut Vec<T>) {
        for i in (1..v.len()).rev() {
            let j = usize::try_from(self.next() % (i as u64 + 1)).unwrap();
            v.swap(i, j);
        }
        if !v.is_empty() {
            let i = usize::try_from(self.next() % v.len() as u64).unwrap();
            let dup = v[i].clone();
            let j = usize::try_from(self.next() % (v.len() as u64 + 1)).unwrap();
            v.insert(j, dup);
        }
    }
}

/// A fresh replica that has verified every header of `ops`, fed `msgs` in order. Each snapshot is
/// absorbed with `with` as the bodies of its response; when `honest`, none may be refused.
fn replay_with(ops: &[Op], msgs: &[Msg], with: &[Op], honest: bool) -> ItemMerge {
    let mut m = ItemMerge::new(item());
    m.add_item_key(key_id(0x40));
    record_headers(&mut m, ops);
    let mut pending: Vec<Op> = Vec::new();
    for msg in msgs {
        match msg {
            Msg::Op(op) => pending.push(op.clone()),
            Msg::Snap(s) => {
                let got = absorb(&mut m, s, with);
                assert!(!honest || matches!(got.outcome, AbsorbOutcome::Absorbed(_)));
            }
        }
        pending = deliver(&mut m, &pending);
    }
    assert!(pending.is_empty(), "ops left waiting");
    m
}

/// The entries of the register of `key` among `regs`, empty if there is none.
fn entries_of<'a>(
    regs: &[crate::record::Register<'a>],
    key: &str,
) -> Vec<crate::record::Entry<'a>> {
    regs.iter()
        .find(|r| r.key().expose_secret() == key)
        .map(|r| r.entries().to_vec())
        .unwrap_or_default()
}

/// A fresh replica fed `msgs`, every snapshot absorbed as a cover without bodies: honest
/// snapshots are never refused.
fn replay(ops: &[Op], msgs: &[Msg]) -> ItemMerge {
    replay_with(ops, msgs, &[], true)
}

/// ADR 0018 §12 "no silent loss", checked on `m` against every op of `ops`.
fn no_silent_loss(m: &ItemMerge, ops: &[Op]) {
    let data = m.snapshot_data().unwrap().unwrap();
    for op in ops {
        let parsed = crate::record::parse_op(&op.data).unwrap();
        let marker = parsed.lifecycle().register_value();
        let writes: Vec<(&str, &[u8])> = marker
            .map(|v| (LIFECYCLE_KEY, v.expose_secret()))
            .into_iter()
            .chain(
                parsed
                    .writes()
                    .iter()
                    .map(|w| (w.key().expose_secret(), w.value().expose_secret())),
            )
            .collect();
        for (key, _) in writes {
            let d = op.dot();
            match &data {
                SnapshotData::Live(l) => {
                    let (cur, hist) =
                        (entries_of(l.registers(), key), entries_of(l.history(), key));
                    let held = cur.iter().chain(&hist).any(|e| e.dot() == d);
                    let pruned = hist.len() == HISTORY_LIMIT
                        && hist.iter().all(|e| (e.hlc(), e.dot()) > (op.header.hlc, d));
                    assert!(held || pruned, "value at {d:?} lost");
                }
                SnapshotData::Tombstone(t) => {
                    if key == LIFECYCLE_KEY || t.context().covers(d) {
                        continue;
                    }
                    let late = t
                        .late()
                        .iter()
                        .filter(|r| r.key().expose_secret() == key)
                        .flat_map(|r| r.entries().iter())
                        .any(|e| e.dot() == d);
                    let superseded = ops.iter().any(|o| {
                        o.header.causal_context.covers(d)
                            && crate::record::parse_op(&o.data)
                                .unwrap()
                                .writes()
                                .iter()
                                .any(|w| w.key().expose_secret() == key)
                    });
                    assert!(late || superseded, "late value at {d:?} lost");
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn generated_histories_converge_in_any_order(
        actions in prop::collection::vec(action(), 1..40),
        seed in any::<u64>(),
    ) {
        let mut w = World::new();
        for a in &actions {
            w.step(a);
        }
        w.quiesce();
        let ops = w.universe();
        prop_assume!(!ops.is_empty());
        // P1: every device holds the state of the ops alone.
        let expected = state_bytes(&reference(&ops));
        for d in &w.devices {
            prop_assert_eq!(&state_bytes(&d.merge), &expected);
        }
        // P2.
        no_silent_loss(&reference(&ops), &ops);
        let mut rng = XorShift(seed | 1);
        // P3: the ops in random orders, with a duplicate.
        for _ in 0..8 {
            let mut msgs: Vec<Msg> = ops.iter().cloned().map(Msg::Op).collect();
            rng.shuffle_with_duplicate(&mut msgs);
            prop_assert_eq!(&state_bytes(&replay(&ops, &msgs)), &expected);
        }
        // P3-mixed: the ops and every snapshot written, interleaved at random.
        if !w.written.is_empty() {
            for _ in 0..8 {
                let mut msgs: Vec<Msg> = ops.iter().cloned().map(Msg::Op).collect();
                msgs.extend(w.written.iter().cloned().map(Msg::Snap));
                rng.shuffle_with_duplicate(&mut msgs);
                prop_assert_eq!(&state_bytes(&replay(&ops, &msgs)), &expected);
            }
        }
    }

    #[test]
    fn pruning_does_not_depend_on_the_order(
        writers in prop::collection::vec((0..3usize, any::<bool>()), 55..90),
        seed in any::<u64>(),
    ) {
        let mut w = World::new();
        w.step(&Action::Write { dev: 0, key: 0, value: 1 });
        for (dev, sync) in &writers {
            if *sync {
                w.sync(*dev, (*dev + 1) % 3);
            }
            w.step(&Action::Write { dev: *dev, key: 0, value: 1 });
        }
        w.quiesce();
        let ops = w.universe();
        let expected = state_bytes(&reference(&ops));
        let m = reference(&ops);
        let f = m.field(KEYS[0]).unwrap();
        prop_assert!(f.history.len() <= HISTORY_LIMIT);
        prop_assert_eq!(f.history.len(), (ops.len() - f.current.len()).min(HISTORY_LIMIT));
        let mut rng = XorShift(seed | 1);
        for _ in 0..4 {
            let mut msgs: Vec<Msg> = ops.iter().cloned().map(Msg::Op).collect();
            rng.shuffle_with_duplicate(&mut msgs);
            prop_assert_eq!(&state_bytes(&replay(&ops, &msgs)), &expected);
        }
        for d in &w.devices {
            prop_assert_eq!(&state_bytes(&d.merge), &expected);
        }
    }
}

/// The generator reaches the cases the properties are about (ADR 0018 §12: "The generator must
/// reach l > 0"): tombstones with late values, conflicts, concurrent absorptions and merged
/// snapshots. Deterministic, so it cannot pass by luck on one run and fail on the next.
#[test]
fn the_generator_reaches_every_case() {
    use proptest::strategy::ValueTree as _;
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let histories = prop::collection::vec(action(), 1..40);
    let (mut tombs, mut late, mut conflicts, mut concurrent, mut merged, mut purges) =
        (0, 0, 0, 0, 0, 0);
    for _ in 0..300 {
        let actions = histories.new_tree(&mut runner).unwrap().current();
        let mut w = World::new();
        for a in &actions {
            w.step(a);
        }
        w.quiesce();
        concurrent += w.concurrent;
        let purge_ops = w
            .universe()
            .iter()
            .filter(|o| crate::record::parse_op(&o.data).unwrap().lifecycle() == Lifecycle::Purge)
            .count();
        if purge_ops > 1 {
            purges += 1;
        }
        merged += w.merged;
        let m = &w.devices[0].merge;
        if m.lifecycle() == ItemLifecycle::Purged {
            tombs += 1;
            if !m.late_values_to_surface().is_empty() {
                late += 1;
            }
        }
        if KEYS.iter().any(|k| {
            m.field(k)
                .and_then(|f| f.display)
                .is_some_and(|d| d.conflict)
        }) {
            conflicts += 1;
        }
    }
    assert!(
        tombs > 0 && late > 0 && conflicts > 0 && concurrent > 0 && merged > 0 && purges > 0,
        "tombstones {tombs}, with late values {late}, conflicts {conflicts}, \
         concurrent absorptions {concurrent}, merged snapshots {merged}, \
         histories with several purges {purges}"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    /// The merge spike's P3-faulty (ADR 0018 §3 "Snapshots are claims", owner decision 14):
    /// the ops and every snapshot written in a run, plus dishonest variants of those snapshots
    /// (the spike's fault kinds), reach one state in any order, whether the dishonest ones are
    /// taken, refused or reported. Every snapshot comes with every op body, as a Fetch
    /// response that carries the bodies a cover could contradict.
    #[test]
    fn dishonest_snapshots_give_one_state_in_any_order(
        actions in prop::collection::vec(action(), 1..30),
        faults in prop::collection::vec((any::<prop::sample::Index>(), 0..super::faults::ALL.len()), 1..4),
        seed in any::<u64>(),
    ) {
        let mut w = World::new();
        for a in &actions {
            w.step(a);
        }
        w.quiesce();
        let ops = w.universe();
        prop_assume!(!w.written.is_empty());
        let mut snaps = w.written.clone();
        for (n, (pick, kind)) in (100u8..).zip(&faults) {
            let honest = pick.get(&w.written);
            if let Some(s) = super::faults::faulty(honest, super::faults::ALL[*kind], n) {
                snaps.push(s);
            }
        }
        let mut rng = XorShift(seed | 1);
        let mut first: Option<Vec<u8>> = None;
        for _ in 0..6 {
            let mut msgs: Vec<Msg> = ops.iter().cloned().map(Msg::Op).collect();
            msgs.extend(snaps.iter().cloned().map(Msg::Snap));
            rng.shuffle_with_duplicate(&mut msgs);
            let got = state_bytes(&replay_with(&ops, &msgs, &ops, false));
            match &first {
                None => first = Some(got),
                Some(f) => prop_assert_eq!(&got, f),
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// P2 under faults (ADR 0018 §12 "no silent loss"; §3 "Snapshots are claims"): a replica
    /// that merged every op body, and wrote a snapshot or not (so that the bodies are, or are no
    /// longer, retained ops), absorbs every snapshot of the run and dishonest variants of them,
    /// in random order, with no body in the response. The bodies it merged stay evidence for
    /// the life of the item: no snapshot changes its state, and nothing is lost.
    #[test]
    fn merged_bodies_stay_evidence_after_a_snapshot(
        actions in prop::collection::vec(action(), 1..30),
        faults in prop::collection::vec((any::<prop::sample::Index>(), 0..super::faults::ALL.len()), 1..6),
        write_first in any::<bool>(),
        seed in any::<u64>(),
    ) {
        let mut w = World::new();
        for a in &actions {
            w.step(a);
        }
        w.quiesce();
        let ops = w.universe();
        prop_assume!(!w.written.is_empty());
        let mut snaps = w.written.clone();
        for (n, (pick, kind)) in (100u8..).zip(&faults) {
            if let Some(s) = super::faults::faulty(pick.get(&w.written), super::faults::ALL[*kind], n) {
                snaps.push(s);
            }
        }
        let mut m = reference(&ops);
        let expected = state_bytes(&m);
        if write_first && m.write_snapshot().is_ok() {
            prop_assert_eq!(m.retained_ops().count(), 0);
        }
        let mut rng = XorShift(seed | 1);
        rng.shuffle_with_duplicate(&mut snaps);
        for s in &snaps {
            absorb(&mut m, s, &[]);
            prop_assert_eq!(&state_bytes(&m), &expected);
        }
        no_silent_loss(&m, &ops);
    }
}

/// Every fault kind applies to some snapshot the generator writes, and absorbing the results
/// exercises both refusals and reported disagreements. Deterministic.
#[test]
fn every_fault_kind_is_reached() {
    use proptest::strategy::ValueTree as _;
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let histories = prop::collection::vec(action(), 1..30);
    let mut built = [0usize; super::faults::ALL.len()];
    let (mut refused, mut disputed) = (0usize, 0usize);
    for _ in 0..200 {
        let actions = histories.new_tree(&mut runner).unwrap().current();
        let mut w = World::new();
        for a in &actions {
            w.step(a);
        }
        w.quiesce();
        let ops = w.universe();
        for honest in &w.written {
            for (i, kind) in super::faults::ALL.iter().enumerate() {
                let Some(s) = super::faults::faulty(honest, *kind, 200) else {
                    continue;
                };
                built[i] += 1;
                let mut m = reference(&ops);
                match absorb(&mut m, &s, &ops).outcome {
                    AbsorbOutcome::Refused(_) => refused += 1,
                    AbsorbOutcome::Absorbed(x) if !x.disagreements.is_empty() => disputed += 1,
                    AbsorbOutcome::Absorbed(_) => {}
                }
            }
        }
    }
    assert!(
        built.iter().all(|&n| n > 0) && refused > 0 && disputed > 0,
        "built {built:?}, refused {refused}, disputed {disputed}"
    );
}
