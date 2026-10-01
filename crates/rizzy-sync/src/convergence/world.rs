//! The simulated world: devices, the server, the ledger of every op written, a seeded
//! scheduler, the drain to quiescence and the property checks of ADR 0012 §12 (as ADR 0018 §12,
//! ADR 0021 §8 and ADR 0022 leave them).
//!
//! # Properties
//!
//! Checked after every step:
//! - **4, monotonicity** (INV-25): no device's item VV (the merge's covered VV) or settled VV
//!   (the causal layer's) ever goes lower or sideways. `account-state` is not modelled.
//! - The server's ADR 0021 §8 properties, by the independent [`super::checker`]: 1 and 2 after
//!   every step, 3 and the §4 selection rule on every page of every Fetch, 4 and 5 after every
//!   `worker` run ([`Server::check_stored`], [`Server::fetch`], [`Server::worker`]); and no
//!   integrity error (§4) or inconsistent row.
//! - No call the harness makes fails unexpectedly (a merge or causal error on honest input).
//!
//! Checked at quiescence, after [`World::drain`]:
//! - **1, convergence**: all active devices hold byte-identical canonical state per item
//!   (ADR 0018 §4), and it is the state the ops define directly ([`super::oracle`]): the item
//!   VV is that of every op in U, and the registers, history or tombstone are the oracle's.
//! - **2, no silent loss** (ADR 0018 §12): [`super::oracle::silent_losses`] on every device.
//! - **3, idempotence and order-independence**: [`super::oracle::replay`] of U with duplicates,
//!   in several causal orders, with the honest, untainted snapshots the server retains and the
//!   devices hold absorbed at random points, reaches the state of U; none of them is refused
//!   or disagrees, and at least one is absorbed when any exists
//!   ([`World::replay_absorbed`]). Where the devices converged, it also reaches their bytes.
//! - **6, revocation**, the part the sync engine decides: no active device holds or has
//!   delivered an op of a revoked device past its cut-off, and learning a revocation never
//!   finds one held (ADR 0021 §9 "Restored-server revocation" names the only way, a restored
//!   server, which the generator does not combine with revocations).
//! - **7, gap detection** against the honest server: after a complete Fetch, no active device
//!   reports missing data or waits for anything (ADR 0021 §8 client properties); and, unless
//!   the server was restored or a device met the paging finding ([`World::drain`]), no device
//!   ever reported a gap. The withholding test checks the other half.
//! - No merge refusal of an untainted cover (other than the paging finding), no disagreement
//!   between untainted sources, and no held-past-cut-off report.
//!
//! # A faulty device
//!
//! In the `faulty` family one device writes dishonest snapshots ([`super::faults`]); its own
//! state and ops stay honest. A snapshot is *tainted* when that device lied in it, or its
//! author had absorbed a tainted snapshot before writing it ([`SnapRecord::tainted`], the
//! merge spike's `honest` and `tainted`). ADR 0018 §3 "Snapshots are claims" lets a lie be
//! refused or reported, and the spike shows a lie about a compacted op's content cannot be
//! decided (README, answer 4: "Always reported; P2 and P3-faulty hold"). So, following the
//! spike's P1, P2, P3-mixed and P3-faulty:
//! - refusals and disagreements are allowed where a tainted record or device is involved;
//! - property 1 is excused on an item some active device reported a disagreement on (the lie
//!   was reported, never silent), and required everywhere else;
//! - property 2 is excused on a device's item only where that device reported a disagreement
//!   on it;
//! - property 3 runs on the untainted snapshots, strict, and compares with the state of U;
//! - **P3-faulty**: every snapshot, tainted ones included, in two random orders, reaches one
//!   state: the merge is a function of the set of records.
//!
//! **U, the universe of ops,** is every op a device wrote, except a revoked device's ops past its
//! cut-off (which no honest server stores). Devices are never lost here, so every op of U
//! survives with its author (the spike's LOSS condition cannot arise).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rizzy_core::ids::{DeviceId, ItemId};

use super::device::{Device, Edit};
use super::faults::{self, Fault};
use super::oracle::{LedgerOp, Rng, State, expected, held, replay, silent_losses};
use super::server::{Page, Server, SnapRecord, Withhold};
use super::{KEYS, T0, device_id, item_id, value};
use crate::causal::Report;
use crate::dot::Dot;
use crate::merge::ItemLifecycle;
use crate::vv::{VersionVector, VvOrdering};

/// One scheduled step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// Device `d` writes key `KEYS[k]` of item `i` (a fresh value).
    Write {
        /// The device.
        d: usize,
        /// The item.
        i: usize,
        /// The key's index in [`KEYS`].
        k: usize,
    },
    /// Device `d` writes, in one op, a fresh value to each key of item `i` whose index in
    /// [`KEYS`] is a set bit of `mask`.
    WriteMany {
        /// The device.
        d: usize,
        /// The item.
        i: usize,
        /// The keys, as bits of their indices in [`KEYS`].
        mask: u8,
    },
    /// Device `d` trashes item `i`.
    Trash {
        /// The device.
        d: usize,
        /// The item.
        i: usize,
    },
    /// Device `d` restores item `i`.
    Restore {
        /// The device.
        d: usize,
        /// The item.
        i: usize,
    },
    /// Device `d` purges item `i` (the writer rules may refuse it).
    Purge {
        /// The device.
        d: usize,
        /// The item.
        i: usize,
    },
    /// Device `d` writes a snapshot of item `i`, if it can.
    Snapshot {
        /// The device.
        d: usize,
        /// The item.
        i: usize,
    },
    /// Device `d` writes a snapshot of item `i` telling the lie `faults::ALL[fault]`, if it is
    /// the faulty device; any other device writes an honest one.
    Lie {
        /// The device.
        d: usize,
        /// The item.
        i: usize,
        /// The lie's index in [`faults::ALL`].
        fault: usize,
    },
    /// Device `d` uploads; with `lose`, the answer to its first op is lost.
    Upload {
        /// The device.
        d: usize,
        /// Whether the first answer is lost.
        lose: bool,
    },
    /// Device `d` uploads every unsent snapshot first, then its ops: a snapshot can reach the
    /// server before the own ops it covers (ADR 0021 §8: "a snapshot uploaded before ops it
    /// covers").
    UploadEarly {
        /// The device.
        d: usize,
    },
    /// Device `d` fetches.
    Fetch {
        /// The device.
        d: usize,
    },
    /// Device `d` goes offline or comes back.
    Toggle {
        /// The device.
        d: usize,
    },
    /// The server runs `worker`.
    Worker,
    /// The server takes a backup.
    Backup,
    /// The server is restored from its last backup.
    RestoreServer,
    /// Device `d` is revoked.
    Revoke {
        /// The device.
        d: usize,
    },
}

/// Delivery faults of a run: how Fetch responses reach the devices.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Faults {
    /// Records per page (0: one page).
    pub(super) page_len: usize,
    /// Shuffle the records of each page.
    pub(super) shuffle: bool,
    /// Duplicate records inside pages, and whole pages.
    pub(super) duplicate: bool,
    /// Keep paging during [`World::drain`] too (only the finding test of `named` sets it).
    pub(super) page_in_drain: bool,
}

/// The per-device, per-item VVs last seen, for monotonicity.
type Seen = BTreeMap<(usize, ItemId), (VersionVector, VersionVector)>;

/// The simulated world of one run.
#[derive(Debug)]
pub(super) struct World {
    /// The server.
    pub(super) server: Server,
    /// The devices.
    pub(super) devices: Vec<Device>,
    /// Whether each device has joined (a device that has not is a device enrolled later).
    joined: Vec<bool>,
    /// Whether each device is online.
    online: Vec<bool>,
    /// Whether each device left for good without being revoked (its uploaded ops stay in U).
    left: Vec<bool>,
    /// The revoked devices and their cut-offs.
    revoked: BTreeMap<usize, u64>,
    /// The items.
    pub(super) items: Vec<ItemId>,
    /// Every op written, by dot.
    ledger: BTreeMap<Dot, LedgerOp>,
    /// The scheduler's generator.
    pub(super) rng: Rng,
    /// Delivery faults.
    pub(super) faults: Faults,
    /// Values written so far, for fresh values.
    written: u64,
    /// Whether the server was ever restored.
    restored: bool,
    /// The VVs last seen, for monotonicity.
    seen: Seen,
    /// Whether the drain runs: Fetch responses then come as one page (see [`World::drain`]).
    draining: bool,
    /// The faulty device, if any.
    faulty: Option<usize>,
    /// Snapshots the order-independence replays absorbed (property 3's coverage).
    pub(super) replay_absorbed: u64,
    /// Items on which property 1 was excused because a lie was reported (faulty runs).
    pub(super) excused_items: u64,
    /// The steps run, with the server heads before each, for failure analysis.
    pub(super) trace: Vec<String>,
    /// Every property violation found, as a line of server-visible metadata.
    pub(super) violations: Vec<String>,
}

impl World {
    /// A world of `devices` devices (the first `joined` of them enrolled from the start) and
    /// `items` items, scheduled from `seed`.
    pub(super) fn new(
        devices: usize,
        joined: usize,
        items: usize,
        seed: u64,
        faults: Faults,
    ) -> Self {
        let mut rng = Rng::new(seed);
        let devs = (0..devices)
            .map(|d| {
                let skew = rng.next() % 50;
                Device::new(device_id(d), T0 + skew, seed)
            })
            .collect();
        Self {
            server: Server::new(),
            devices: devs,
            joined: (0..devices).map(|d| d < joined.max(1)).collect(),
            online: vec![true; devices],
            left: vec![false; devices],
            revoked: BTreeMap::new(),
            items: (0..items).map(item_id).collect(),
            ledger: BTreeMap::new(),
            rng,
            faults,
            written: 0,
            restored: false,
            seen: Seen::new(),
            draining: false,
            faulty: None,
            replay_absorbed: 0,
            excused_items: 0,
            trace: Vec::new(),
            violations: Vec::new(),
        }
    }

    /// Makes device `d` the faulty device of the run; `heal_lie` is the lie it tells in the
    /// fresh snapshots of its healing requests.
    pub(super) fn set_faulty(&mut self, d: usize, heal_lie: Option<Fault>) {
        if let Some(dev) = self.devices.get_mut(d) {
            dev.faulty = true;
            dev.heal_lie = heal_lie;
            self.faulty = Some(d);
        }
    }

    /// The faulty device, if any.
    pub(super) fn faulty(&self) -> Option<usize> {
        self.faulty
    }

    /// Whether device `d` can act at all: joined and not gone. A revoked device still can: it
    /// does not know, and the server refuses what it uploads past its cut-off.
    fn can_act(&self, d: usize) -> bool {
        self.joined.get(d).copied().unwrap_or(false) && !self.left.get(d).copied().unwrap_or(true)
    }

    /// Whether device `d` takes part in the properties: it can act and is not revoked.
    pub(super) fn active(&self, d: usize) -> bool {
        self.can_act(d) && !self.revoked.contains_key(&d)
    }

    /// Device `d` leaves for good, without a revocation (the "never returns" of ADR 0021 §8).
    pub(super) fn leave(&mut self, d: usize) {
        if let Some(l) = self.left.get_mut(d) {
            *l = true;
        }
    }

    /// Parks device `d` (`true`) or brings it back (`false`): a parked device is out of the
    /// world as a device that left is, through drains and checks, but it comes back with
    /// everything it held (a device offline for a long time; the `faulty` family parks one
    /// across the first drain so that it meets covers of ops whose bodies it merged).
    pub(super) fn park(&mut self, d: usize, parked: bool) {
        if let Some(l) = self.left.get_mut(d) {
            *l = parked;
        }
    }

    /// Whether device `d` can talk to the server.
    fn reachable(&self, d: usize) -> bool {
        self.active(d) && self.online.get(d).copied().unwrap_or(false)
    }

    /// Enrols device `d` (a device added later: it starts from an empty state and fetches).
    pub(super) fn join(&mut self, d: usize) {
        if let Some(j) = self.joined.get_mut(d) {
            *j = true;
        }
    }

    /// Runs one step, then the per-step checks.
    pub(super) fn step(&mut self, step: Step) {
        self.trace
            .push(format!("{step:?} heads {:?}", self.server.heads()));
        match step {
            Step::Write { d, i, k } => self.write_keys(d, i, &[k]),
            Step::WriteMany { d, i, mask } => {
                let keys: Vec<usize> = (0..KEYS.len())
                    .filter(|k| u32::try_from(*k).is_ok_and(|b| mask & (1 << b) != 0))
                    .collect();
                self.write_keys(d, i, &keys);
            }
            Step::Trash { d, i } => self.write(d, i, &Edit::Trash),
            Step::Restore { d, i } => self.write(d, i, &Edit::Restore),
            Step::Purge { d, i } => self.write(d, i, &Edit::Purge),
            Step::Snapshot { d, i } => self.snapshot(d, i, None),
            Step::Lie { d, i, fault } => self.snapshot(d, i, faults::ALL.get(fault).copied()),
            Step::Upload { d, lose } => self.upload(d, lose, false),
            Step::UploadEarly { d } => self.upload(d, false, true),
            Step::Fetch { d } => self.fetch(d),
            Step::Toggle { d } => {
                if let Some(o) = self.online.get_mut(d) {
                    *o = !*o;
                }
            }
            Step::Worker => self.server.worker(),
            Step::Backup => self.server.backup(),
            Step::RestoreServer => {
                if self.server.restore() {
                    self.restored = true;
                }
            }
            Step::Revoke { d } => self.revoke(d),
        }
        self.check_step(&format!("{step:?}"));
    }

    /// Device `d` writes a snapshot of item `i`, telling `lie` if it is the faulty device.
    fn snapshot(&mut self, d: usize, i: usize, lie: Option<Fault>) {
        if !self.can_act(d) {
            return;
        }
        let heads = self.server.heads();
        if let (Some(dev), Some(&item)) = (self.devices.get_mut(d), self.items.get(i)) {
            dev.snapshot_with(item, lie.map(|f| (f, &heads)));
        }
    }

    /// Device `d` writes a fresh value to each of `KEYS[k]` for `k` in `keys`, in one op.
    fn write_keys(&mut self, d: usize, i: usize, keys: &[usize]) {
        let mut writes = Vec::new();
        for &k in keys {
            self.written += 1;
            let key = KEYS.get(k).copied().unwrap_or("item.name");
            writes.push((key.to_owned(), value(key, self.written)));
        }
        if writes.is_empty() {
            return;
        }
        self.write(d, i, &Edit::Write(writes));
    }

    /// Device `d` writes `writes` to item `i` in one op, then the per-step checks (for the
    /// named scenarios that need many keys in one op, such as an oversize item).
    pub(super) fn write_fields(&mut self, d: usize, i: usize, writes: Vec<(String, Vec<u8>)>) {
        self.trace.push(format!("write_fields {d} {i}"));
        self.write(d, i, &Edit::Write(writes));
        self.check_step(&format!("write_fields {d} {i}"));
    }

    /// A write of `edit` on item `i` by device `d`, kept in the ledger.
    fn write(&mut self, d: usize, i: usize, edit: &Edit) {
        if !self.can_act(d) {
            return;
        }
        let (Some(dev), Some(&item)) = (self.devices.get_mut(d), self.items.get(i)) else {
            return;
        };
        dev.now_ms += 1;
        if let Some((header, body)) = dev.write(item, edit) {
            let dot = header.dot;
            match LedgerOp::new(header, body) {
                Some(op) => {
                    self.ledger.insert(dot, op);
                }
                None => self
                    .violations
                    .push(format!("ledger: {dot:?} does not parse")),
            }
        }
    }

    /// Device `d` uploads (healing first if the server is behind it); `early` as in
    /// [`Step::UploadEarly`].
    fn upload(&mut self, d: usize, lose: bool, early: bool) {
        if !self.can_act(d) || !self.online.get(d).copied().unwrap_or(false) {
            return;
        }
        let Some(dev) = self.devices.get_mut(d) else {
            return;
        };
        if dev.server_behind(&self.server) {
            dev.read_only = true;
            dev.heal(&mut self.server);
        }
        if early {
            dev.upload_snapshots(&mut self.server, true);
        }
        dev.upload_ops(&mut self.server, lose);
        dev.upload_snapshots(&mut self.server, false);
        dev.read_only = dev.server_behind(&self.server);
    }

    /// Device `d` fetches (healing first if the server is behind it), with the run's delivery
    /// faults applied to the response.
    fn fetch(&mut self, d: usize) {
        if !self.reachable(d) {
            return;
        }
        let Some(dev) = self.devices.get_mut(d) else {
            return;
        };
        if dev.server_behind(&self.server) {
            dev.read_only = true;
            dev.heal(&mut self.server);
        }
        let response = self.server.fetch(
            dev.id,
            &dev.log.cursor(),
            if self.draining && !self.faults.page_in_drain {
                0
            } else {
                self.faults.page_len
            },
        );
        let mut pages: Vec<Page> = Vec::new();
        for mut page in response.pages {
            if self.faults.duplicate
                && !page.ops.is_empty()
                && self.rng.chance(1, 3)
                && let Some(extra) = page.ops.get(self.rng.below(page.ops.len())).cloned()
            {
                page.ops.push(extra);
            }
            if self.faults.shuffle {
                for j in (1..page.ops.len()).rev() {
                    page.ops.swap(j, self.rng.below(j + 1));
                }
            }
            let again = self.faults.duplicate && self.rng.chance(1, 5);
            if again {
                pages.push(page.clone());
            }
            pages.push(page);
        }
        dev.fetch(&response.cutoffs, response.generation, &pages);
        dev.read_only = dev.server_behind(&self.server);
    }

    /// Revokes device `d`, if at least two other devices stay active.
    fn revoke(&mut self, d: usize) {
        let others = (0..self.devices.len())
            .filter(|&e| e != d && self.active(e))
            .count();
        if !self.active(d) || others < 2 {
            return;
        }
        let Some(dev) = self.devices.get(d) else {
            return;
        };
        let cutoff = self.server.revoke(dev.id);
        self.revoked.insert(d, cutoff);
    }

    /// The checks after every step (see the module docs).
    fn check_step(&mut self, after: &str) {
        for d in 0..self.devices.len() {
            if !self.active(d) {
                continue;
            }
            let Some(dev) = self.devices.get_mut(d) else {
                continue;
            };
            for error in dev.errors.drain(..) {
                self.violations
                    .push(format!("after {after}: device {d}: {error}"));
            }
            for &item in &self.items {
                let covered = dev
                    .items
                    .get(&item)
                    .map(|m| m.covered().clone())
                    .unwrap_or_default();
                let settled = dev.log.settled(item);
                if let Some((was_covered, was_settled)) = self.seen.get(&(d, item)) {
                    for (now, was, what) in [
                        (&covered, was_covered, "item VV"),
                        (&settled, was_settled, "settled VV"),
                    ] {
                        if matches!(now.compare(was), VvOrdering::Less | VvOrdering::Concurrent) {
                            self.violations.push(format!(
                                "property 4 (monotonicity): device {d}'s {what} of {item:?} went back after {after}"
                            ));
                        }
                    }
                }
                self.seen.insert((d, item), (covered, settled));
            }
        }
        self.server.check_stored();
        for found in self.server.violations.drain(..) {
            self.violations.push(format!("after {after}: {found}"));
        }
        if !self.server.integrity_errors.is_empty() || self.server.input_errors > 0 {
            self.violations.push(format!(
                "ADR 0021 §4 integrity after {after}: {:?}",
                self.server.integrity_errors
            ));
            self.server.integrity_errors.clear();
            self.server.input_errors = 0;
        }
    }

    /// A fingerprint of every party's state, for the drain's fixed point.
    fn fingerprint(&self) -> String {
        let mut out = format!("{:?}", self.server.fingerprint());
        for dev in &self.devices {
            let _ = write!(out, "|{:?}", dev.log.cursor());
            for merge in dev.items.values() {
                let _ = write!(out, "{:?}", merge.covered());
            }
            let _ = write!(out, "{}{}", dev.outbox_empty(), dev.read_only);
        }
        out
    }

    /// Brings every active device online and syncs everyone, running `worker` between rounds,
    /// until nothing changes (the network is quiet). Returns whether the fixed point was
    /// reached within the round cap.
    ///
    /// From here on Fetch responses come as one page. A paged response can put a tombstone
    /// cover in the page of a bodiless header it covers and its recorded purge in a later page;
    /// the merge then refuses the cover (`PurgeAboveCut`: the purge is above the page's cut),
    /// the chain stops at a gap, and the next Fetch from the same cursor with the same paging
    /// repeats it. That is reported as a finding, not hidden: during the history paging stays
    /// on, and only the drain, which must reach quiescence, fetches whole responses. Exactly
    /// that refusal (the kind `PurgeAboveCut`, on a page that is a strict prefix of its
    /// response) is counted apart ([`super::device::DeviceStats::paged_refused`]) and excuses
    /// the "no gap ever reported" half of property 7 for the run
    /// ([`World::gap_check_skipped`]); any other refusal stays a violation.
    pub(super) fn drain(&mut self) -> bool {
        self.draining = true;
        for d in 0..self.devices.len() {
            if self.active(d)
                && let Some(o) = self.online.get_mut(d)
            {
                *o = true;
            }
        }
        let mut last = String::new();
        for _ in 0..40 {
            for d in 0..self.devices.len() {
                self.step(Step::Fetch { d });
                self.step(Step::Upload { d, lose: false });
            }
            self.step(Step::Worker);
            for d in 0..self.devices.len() {
                self.step(Step::Fetch { d });
            }
            let now = self.fingerprint();
            if now == last {
                return true;
            }
            last = now;
        }
        false
    }

    /// Whether the run's "no device ever reported a gap against the honest server" check is
    /// skipped: a device met the paging finding ([`World::drain`]).
    pub(super) fn gap_check_skipped(&self) -> bool {
        self.devices.iter().any(|dev| dev.stats.paged_refused > 0)
    }

    /// The ops of U on `item` (see the module docs).
    fn universe(&self, item: ItemId) -> Vec<&LedgerOp> {
        self.ledger
            .values()
            .filter(|op| op.header.item_id == item)
            .filter(|op| {
                let dot = op.header.dot;
                !self.revoked.iter().any(|(&d, &cutoff)| {
                    self.devices
                        .get(d)
                        .is_some_and(|dev| dev.id == dot.device_id())
                        && dot.seq() > cutoff
                })
            })
            .collect()
    }

    /// Every snapshot of `item` the server retains or an active device holds, once each.
    fn snapshots_of(&self, item: ItemId, active: &[usize]) -> Vec<&SnapRecord> {
        let mut snapshots: Vec<&SnapRecord> = self
            .server
            .snapshot_records()
            .filter(|s| s.header.item_id == item)
            .collect();
        for &d in active {
            if let Some(dev) = self.devices.get(d) {
                snapshots.extend(
                    dev.held_snapshots()
                        .iter()
                        .filter(|s| s.header.item_id == item),
                );
            }
        }
        snapshots.sort_by_key(|s| s.header.snapshot_id.to_bytes());
        snapshots.dedup_by_key(|s| s.header.snapshot_id.to_bytes());
        snapshots
    }

    /// The checks at quiescence (see the module docs), with `replays` random replay orders
    /// per item for property 3.
    #[expect(
        clippy::too_many_lines,
        reason = "one list of the quiescent property checks, each a few lines"
    )]
    pub(super) fn check_quiescent(&mut self, replays: usize) {
        let mut rng = Rng::new(self.rng.next());
        let active: Vec<usize> = (0..self.devices.len())
            .filter(|&d| self.active(d))
            .collect();
        let mut violations = Vec::new();
        let mut replay_absorbed = 0;
        let mut excused_items = 0;
        for &item in &self.items {
            let universe = self.universe(item);
            let mut want_vv = VersionVector::new();
            for op in &universe {
                want_vv.add(op.header.dot);
            }
            let want_state = expected(&universe);
            // A lie on this item was reported by some device: property 1 is excused on it.
            let reported = active.iter().any(|&d| {
                self.devices
                    .get(d)
                    .is_some_and(|dev| dev.disagreement_items.contains(&item))
            });
            if reported {
                excused_items += 1;
            }
            let mut bytes: Option<Vec<u8>> = None;
            let mut converged = true;
            let mut p1 = Vec::new();
            for &d in &active {
                let Some(dev) = self.devices.get(d) else {
                    continue;
                };
                let (covered, state, canonical) = match dev.items.get(&item) {
                    Some(merge) => (
                        merge.covered().clone(),
                        held(merge),
                        merge
                            .canonical_state()
                            .ok()
                            .flatten()
                            .map(|b| b.expose_secret().to_vec())
                            .unwrap_or_default(),
                    ),
                    None => (VersionVector::new(), Ok(State::Absent), Vec::new()),
                };
                if covered != want_vv {
                    p1.push(format!(
                        "property 1 (convergence): device {d}'s item VV of {item:?} is {covered:?}, U is {want_vv:?}"
                    ));
                }
                match &state {
                    Ok(state) => {
                        if *state != want_state {
                            p1.push(format!(
                                "property 1 (convergence): device {d}'s state of {item:?} is not the state of U"
                            ));
                        }
                        let applied: Vec<&LedgerOp> = universe
                            .iter()
                            .copied()
                            .filter(|op| covered.covers(op.header.dot))
                            .collect();
                        let lost = silent_losses(&applied, state);
                        if !lost.is_empty() && !dev.disagreement_items.contains(&item) {
                            violations.push(format!(
                                "property 2 (no silent loss): device {d}, {item:?}: values of {lost:?}"
                            ));
                        }
                    }
                    Err(e) => violations.push(format!("device {d}, {item:?}: {e}")),
                }
                match &bytes {
                    None => bytes = Some(canonical),
                    Some(b) if *b != canonical => {
                        converged = false;
                        p1.push(format!(
                            "property 1 (convergence): device {d}'s canonical state of {item:?} differs"
                        ));
                    }
                    Some(_) => {}
                }
            }
            converged &= p1.is_empty();
            if !reported {
                violations.extend(p1);
            }
            let snapshots = self.snapshots_of(item, &active);
            let honest: Vec<&SnapRecord> =
                snapshots.iter().copied().filter(|s| !s.tainted).collect();
            for _ in 0..replays {
                let with: Vec<&SnapRecord> = honest
                    .iter()
                    .copied()
                    .filter(|_| rng.chance(1, 2))
                    .collect();
                match replay(item, &universe, &with, &mut rng, true) {
                    Ok(r) => {
                        replay_absorbed += r.absorbed;
                        let bytes_differ =
                            converged && bytes.as_ref().is_some_and(|b| *b != r.bytes);
                        if r.state != want_state || bytes_differ {
                            violations.push(format!(
                                "property 3 (order independence), {item:?}: the replayed state differs"
                            ));
                            break;
                        }
                    }
                    Err(e) => {
                        violations.push(format!("property 3 (order independence), {item:?}: {e}"));
                        break;
                    }
                }
            }
            // P3-faulty: with the lies too, the merge is a function of the set of records.
            if snapshots.iter().any(|s| s.tainted) {
                let first = replay(item, &universe, &snapshots, &mut rng, false);
                let second = replay(item, &universe, &snapshots, &mut rng, false);
                match (first, second) {
                    (Ok(a), Ok(b)) if a.bytes == b.bytes => {}
                    (Ok(_), Ok(_)) => violations.push(format!(
                        "P3-faulty, {item:?}: two orders of the same records reach different states"
                    )),
                    (Err(e), _) | (_, Err(e)) => {
                        violations.push(format!("P3-faulty, {item:?}: {e}"));
                    }
                }
            }
        }
        let skip_gaps = self.restored || self.gap_check_skipped();
        for &d in &active {
            let Some(dev) = self.devices.get(d) else {
                continue;
            };
            if !dev.last_complete.is_empty() {
                violations.push(format!(
                    "property 7 / ADR 0021 §8: device {d} reports missing data at quiescence: {:?}",
                    dev.last_complete
                ));
            }
            let waiting = dev.log.waiting();
            if !waiting.is_empty() {
                violations.push(format!("device {d} still waits for {waiting:?}"));
            }
            if !skip_gaps {
                let gaps: Vec<&Report> = dev
                    .reports
                    .iter()
                    .filter(|r| !matches!(r, Report::Duplicate { .. }))
                    .collect();
                if !gaps.is_empty() {
                    violations.push(format!(
                        "ADR 0021 §8: device {d} reported against the honest server: {gaps:?}"
                    ));
                }
            }
            if !dev.honest_disagreements.is_empty() || dev.stats.refused > 0 {
                violations.push(format!(
                    "device {d}: disagreements {:?} or {} refusals on untainted records",
                    dev.honest_disagreements, dev.stats.refused
                ));
            }
            if self.faulty.is_none() && dev.items.values().any(|m| m.unresolved().next().is_some())
            {
                violations.push(format!(
                    "device {d}: unresolved disagreements on honest records"
                ));
            }
            if !dev.held_past_cutoff.is_empty() {
                violations.push(format!(
                    "property 6 (revocation): device {d} held ops past a cut-off: {:?}",
                    dev.held_past_cutoff
                ));
            }
            for (&r, &cutoff) in &self.revoked {
                let Some(rid) = self.devices.get(r).map(|x| x.id) else {
                    continue;
                };
                let past = dev.log.head(rid) > cutoff
                    || dev.items.values().any(|m| m.covered().get(rid) > cutoff);
                if past {
                    violations.push(format!(
                        "property 6 (revocation): device {d} holds device {r}'s ops past its cut-off {cutoff}"
                    ));
                }
            }
            if dev.read_only {
                violations.push(format!("device {d} is still read-only at quiescence"));
            }
        }
        self.replay_absorbed += replay_absorbed;
        self.excused_items += excused_items;
        self.violations.extend(violations);
    }

    /// What `@lifecycle` shows for item `i` on device `d`.
    pub(super) fn lifecycle(&self, d: usize, i: usize) -> ItemLifecycle {
        match (self.devices.get(d), self.items.get(i)) {
            (Some(dev), Some(item)) => dev
                .items
                .get(item)
                .map_or(ItemLifecycle::Absent, crate::merge::ItemMerge::lifecycle),
            _ => ItemLifecycle::Absent,
        }
    }

    /// The number of devices.
    pub(super) fn len(&self) -> usize {
        self.devices.len()
    }

    /// Sets the server's withholding fault: responses to device `victim` leave out `dot`.
    pub(super) fn withhold(&mut self, victim: usize, dot: Option<Dot>) {
        self.server.withhold = match (self.devices.get(victim), dot) {
            (Some(dev), Some(dot)) => Some(Withhold {
                victim: dev.id,
                dot,
            }),
            _ => None,
        };
    }

    /// The id of device `d`.
    pub(super) fn id(&self, d: usize) -> Option<DeviceId> {
        self.devices.get(d).map(|dev| dev.id)
    }

    /// The header of the op at `dot` in the ledger.
    pub(super) fn header_of(&self, dot: Dot) -> Option<&crate::header::OpHeader> {
        self.ledger.get(&dot).map(|op| &op.header)
    }

    /// The item of the op at `dot` in the ledger.
    pub(super) fn item_of(&self, dot: Dot) -> Option<ItemId> {
        self.ledger.get(&dot).map(|op| op.header.item_id)
    }

    /// The state U defines for item `i` ([`super::oracle::expected`]).
    pub(super) fn expected_state(&self, i: usize) -> State {
        self.items
            .get(i)
            .map_or(State::Absent, |&item| expected(&self.universe(item)))
    }

    /// The ledger's dots of device `d` on item `i`, ascending.
    pub(super) fn dots_of(&self, d: usize, i: usize) -> Vec<Dot> {
        let (Some(id), Some(&item)) = (self.id(d), self.items.get(i)) else {
            return Vec::new();
        };
        self.ledger
            .values()
            .filter(|op| op.header.dot.device_id() == id && op.header.item_id == item)
            .map(|op| op.header.dot)
            .collect()
    }

    /// The first violation, with the run's coverage, for a failure message.
    pub(super) fn verdict(&self) -> Result<(), String> {
        match self.violations.first() {
            None => Ok(()),
            Some(first) => {
                let events: Vec<(usize, &String)> = self
                    .devices
                    .iter()
                    .enumerate()
                    .flat_map(|(d, dev)| dev.events.iter().rev().take(3).map(move |l| (d, l)))
                    .collect();
                Err(format!(
                    "{} violation(s); first: {first}; server stats {:?}; last steps {:?}; last device events {events:?}",
                    self.violations.len(),
                    self.server.stats,
                    self.trace.iter().rev().take(6).collect::<Vec<_>>()
                ))
            }
        }
    }
}
