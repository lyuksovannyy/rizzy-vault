// SPDX-License-Identifier: AGPL-3.0-only

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
//! - **6, "a revoked device cannot decrypt anything written after the rotation"**
//!   ([`World::check_rotations`]). Every revocation is one request with a rotation (CRYPTO.md
//!   §11.8 step 3). At the rotation the world records what the revoked device holds (its item
//!   key ids and vault key epochs) and every envelope that exists. Every envelope written
//!   after it that the server or an active device holds must be sealed under an item key the
//!   revoked device does not hold, created at the rotation's epoch or later (the CRYPTO.md
//!   §11.6 writer rule; also checked for rotations without a revocation, as the INV-19-style
//!   "old-epoch keys open no post-rotation object"), and must not open under any key of its
//!   item the revoked device holds; no wrap-set row may open under a vault key it holds. The
//!   key-id check runs on the server's envelopes after every step, the rest at quiescence.
//! - **ADR 0021 §9 "Stale epoch"**, after every step: every op the server stored outside a
//!   healing request has a `vault_key_epoch` at least the vault's when it was stored, unless
//!   its author is revoked and it is at or below the cut-off; and a re-issued op keeps its dot
//!   and everything of its header but a higher `vault_key_epoch` ([`World::take_reissues`]).
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
//! # Two or more faulty devices
//!
//! ADR 0021 accepts that "two or more colluding faulty devices exceed the bound" for M1. With
//! several faulty devices every rule above still holds on an item that at most one of them lied
//! about; on an item two or more of them lied about (ground truth: [`Device::lied_items`]),
//! properties 1 and 2 may fail silently, and the run counts those items
//! ([`World::beyond_bound`]) instead of failing. In such a run a device that refused a lie
//! may be left with only lies as the covers of a bodiless header: it reports the gap, and its
//! chain stops there on every item, detected and reported, so properties 1 and 2 and "no gap
//! reported", "no missing data" and "nothing waits" at quiescence are not required of it
//! ([`World::lie_gapped`]). Property 3 (strict, untainted),
//! P3-faulty, the server properties and every other check stay strict there too.
//!
//! # Rotations, epochs and kind-4 authors
//!
//! The world holds the newest signed account state's vault epoch ([`World::epoch`]) and offers
//! it to every device a rotation keeps: a device processes it at its next Fetch, or after a
//! stale-epoch answer ([`Device::offered`]); a revoked device gets no grant. A rotation
//! ([`World::rotate`]) is made by an active device: it uploads, fetches until its cursor is
//! every head, re-wraps every wrap-set row it can open under the next vault key, and sends the
//! vault half, with the revocation if there is one, which the server checks (ADR 0025 §3). A
//! rotation the server refuses changes nothing. After a restore a device whose epoch is above
//! the server's repairs the vault epoch first (ADR 0032 §3, [`Server::heal_epoch`]).
//!
//! A kind-4 device ([`World::set_kind4`]) has a certificate with an `expires_at_ms`: it writes
//! no op whose HLC is past it (rule (c)), and once the server's clock (the latest device
//! clock) passes it, the server refuses its uploads and new snapshots, and the device is gone;
//! its stored ops and retained snapshots stay.
//!
//! **U, the universe of ops,** is every op a device wrote, except a revoked device's ops past its
//! cut-off (which no honest server stores) and an expired kind-4 device's ops the server did
//! not hold at its expiry (which nobody can upload any more). Devices are never lost here, so
//! every other op of U survives with its author (the spike's LOSS condition cannot arise).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use rizzy_core::ids::{DeviceId, ItemId, SymmetricKeyId};

use super::crypto;
use super::device::{Device, Edit};
use super::faults::{self, Fault};
use super::oracle::{LedgerOp, Rng, State, expected, held, replay, silent_losses};
use super::server::{Page, Rotation, Server, SnapRecord, Withhold};
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
    /// Device `d` is revoked, in one request with a rotation ([`World::rotate`]).
    Revoke {
        /// The device.
        d: usize,
    },
    /// Device `d` rotates the keys without a revocation (CRYPTO.md §11.6: "the user asking
    /// for it").
    Rotate {
        /// The rotating device.
        d: usize,
    },
}

/// What the world records at a rotation, for property 6 ([`World::check_rotations`]).
#[derive(Clone, Debug)]
struct RotationRecord {
    /// The new vault epoch.
    epoch: u32,
    /// The revoked device, if the rotation came with a revocation.
    revoked: Option<usize>,
    /// The item keys the revoked device held at the rotation.
    keys: Vec<SymmetricKeyId>,
    /// The vault key epochs it held.
    vault_keys: BTreeSet<u32>,
    /// Every envelope that existed at the rotation, or earlier: what was not written after it
    /// ([`World::ever_envelopes`] as of that moment, not just the live set, so a body R1 drops
    /// and a later restore brings back still counts as pre-existing).
    before: BTreeSet<Vec<u8>>,
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
    /// Keep paging during [`World::drain`] too: the ADR 0050 tests set it, so that every
    /// Fetch until quiescence may split a tombstone cover from its recorded purge. The
    /// generated families page during the history only.
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
    /// The server's `vault_key_epoch` immediately after each successful restore (ADR 0032 §3):
    /// a floor a plain (non-healing) upload may legitimately sit at or above once the server
    /// has rolled back to it, even if a later-recorded rotation's epoch is above it (a lag
    /// repair, [`Server::heal_epoch`], can then re-raise the server past that rotation again).
    /// Used by [`World::check_rotations`]'s writer-rule exemption, alongside envelopes that
    /// came in through a healing request.
    restore_floors: Vec<u32>,
    /// Every envelope ever observed live, server or device-held, accumulated across the run
    /// (never shrinks). [`Server::worker`]'s R1 can drop an op's body from
    /// [`Server::envelopes`]'s view (it stays fully covered by a retained snapshot); a later
    /// restore to a backup taken before that drop (ADR 0021 §2) brings the body back. Without
    /// this accumulator, a [`RotationRecord::before`] snapshot taken while the body was absent
    /// would miss it, and the resurrected, honestly pre-rotation envelope would then look like
    /// a fresh post-rotation write to [`World::check_rotations`]'s writer-rule check. Updated
    /// wherever a body could first become unreachable ([`Server::worker`]) and at every
    /// [`World::rotate`], so every `before` snapshot is this set as of that moment, not just the
    /// live one.
    ever_envelopes: BTreeSet<Vec<u8>>,
    /// The VVs last seen, for monotonicity.
    seen: Seen,
    /// Whether the drain runs: Fetch responses then come as one page (see [`World::drain`]).
    draining: bool,
    /// The faulty devices.
    faulty: BTreeSet<usize>,
    /// The vault epoch of the newest signed account state.
    pub(super) epoch: u32,
    /// Every rotation the server stored.
    rotations: Vec<RotationRecord>,
    /// The kind-4 devices and their certificates' `expires_at_ms`.
    kind4: BTreeMap<usize, u64>,
    /// The expired kind-4 devices and the server's head for each at its expiry.
    expired: BTreeMap<usize, u64>,
    /// Snapshots the order-independence replays absorbed (property 3's coverage).
    pub(super) replay_absorbed: u64,
    /// Items on which property 1 was excused because a lie was reported (faulty runs).
    pub(super) excused_items: u64,
    /// Items two or more faulty devices lied about, whose properties 1 and 2 were not required
    /// (see the module docs), and how many of them did not converge.
    pub(super) beyond_bound: (u64, u64),
    /// Devices that refused a lie in a run beyond the faulty-device bound and reported the gap
    /// it left, so properties 1 and 2 were not required of them.
    pub(super) lie_gapped: u64,
    /// Envelopes written after a rotation that property 6 checked, and key attempts made on
    /// them.
    pub(super) p6_checked: (u64, u64),
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
            restore_floors: Vec::new(),
            ever_envelopes: BTreeSet::new(),
            seen: Seen::new(),
            draining: false,
            faulty: BTreeSet::new(),
            epoch: 0,
            rotations: Vec::new(),
            kind4: BTreeMap::new(),
            expired: BTreeMap::new(),
            replay_absorbed: 0,
            excused_items: 0,
            beyond_bound: (0, 0),
            p6_checked: (0, 0),
            lie_gapped: 0,
            trace: Vec::new(),
            violations: Vec::new(),
        }
    }

    /// Makes device `d` a faulty device of the run; `heal_lie` is the lie it tells in the
    /// fresh snapshots of its healing requests.
    pub(super) fn set_faulty(&mut self, d: usize, heal_lie: Option<Fault>) {
        if let Some(dev) = self.devices.get_mut(d) {
            dev.faulty = true;
            dev.heal_lie = heal_lie;
            self.faulty.insert(d);
        }
    }

    /// The faulty devices.
    pub(super) fn faulty_set(&self) -> &BTreeSet<usize> {
        &self.faulty
    }

    /// Makes device `d` a kind-4 (web vault) device whose certificate expires at
    /// `expires_at_ms` (CRYPTO.md §10.2); the server and the peers learn the certificate.
    pub(super) fn set_kind4(&mut self, d: usize, expires_at_ms: u64) {
        if let Some(dev) = self.devices.get_mut(d) {
            dev.expires_at_ms = expires_at_ms;
            self.server.certificates.insert(dev.id, expires_at_ms);
            self.kind4.insert(d, expires_at_ms);
        }
    }

    /// How many devices were revoked.
    pub(super) fn revocations(&self) -> u64 {
        self.revoked.len() as u64
    }

    /// How many kind-4 devices expired.
    pub(super) fn expirations(&self) -> u64 {
        self.expired.len() as u64
    }

    /// Whether device `d` is online.
    pub(super) fn is_online(&self, d: usize) -> bool {
        self.online.get(d).copied().unwrap_or(false)
    }

    /// Lets `ms` milliseconds pass on every device's wall clock (the server's clock is the
    /// latest of them), then runs the expiries that follows.
    pub(super) fn pass_time(&mut self, ms: u64) {
        for dev in &mut self.devices {
            dev.now_ms += ms;
        }
        self.expire_kind4();
        self.check_step("pass_time");
    }

    /// Whether the kind-4 device `d` has expired.
    pub(super) fn is_expired(&self, d: usize) -> bool {
        self.expired.contains_key(&d)
    }

    /// The kind-4 device, if any.
    pub(super) fn kind4_device(&self) -> Option<usize> {
        self.kind4.keys().next().copied()
    }

    /// Whether device `d` can act at all: joined, not gone and not expired. A revoked device
    /// still can: it does not know, and the server refuses what it uploads past its cut-off.
    fn can_act(&self, d: usize) -> bool {
        self.joined.get(d).copied().unwrap_or(false)
            && !self.left.get(d).copied().unwrap_or(true)
            && !self.expired.contains_key(&d)
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

    /// Enrols device `d` (a device added later: it starts from an empty state and fetches),
    /// with the current account state: the vault key of the current epoch only.
    pub(super) fn join(&mut self, d: usize) {
        if let Some(j) = self.joined.get_mut(d)
            && !*j
        {
            *j = true;
            if let Some(dev) = self.devices.get_mut(d) {
                dev.enrol(self.epoch);
            }
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
            Step::Worker => {
                // Capture every live envelope before R1 can drop a covered op's body
                // (see `ever_envelopes`'s doc).
                let live = self.envelopes();
                self.ever_envelopes.extend(live);
                self.server.worker();
            }
            Step::Backup => self.server.backup(),
            Step::RestoreServer => {
                if self.server.restore() {
                    self.restored = true;
                    self.restore_floors.push(self.server.epoch());
                }
            }
            Step::Revoke { d } => self.revoke(d),
            Step::Rotate { d } => {
                self.rotate(d, None);
            }
        }
        self.take_reissues();
        self.expire_kind4();
        self.check_step(&format!("{step:?}"));
    }

    /// Moves every device's re-issued ops into the ledger, after checking that each keeps its
    /// dot and everything of its header but a higher `vault_key_epoch` (ADR 0018 §3 "Re-issued
    /// ops"; ADR 0021 §9 "Stale epoch": "with the same `device_seq`").
    fn take_reissues(&mut self) {
        for d in 0..self.devices.len() {
            let Some(dev) = self.devices.get_mut(d) else {
                continue;
            };
            for (header, key) in core::mem::take(&mut dev.reissued) {
                let dot = header.dot;
                let Some(op) = self.ledger.get_mut(&dot) else {
                    self.violations
                        .push(format!("a re-issue of {dot:?}, which no device wrote"));
                    continue;
                };
                let mut expected = op.header.clone();
                expected.vault_key_epoch = header.vault_key_epoch;
                if expected != header || header.vault_key_epoch <= op.header.vault_key_epoch {
                    self.violations.push(format!(
                        "stale epoch: the re-issue of {dot:?} changed more than a higher epoch"
                    ));
                }
                op.header = header;
                op.key_id = key;
            }
        }
    }

    /// Expires every kind-4 device whose certificate's `expires_at_ms` the server's clock (the
    /// latest wall clock of a device) has passed: it tries a last upload, which the server
    /// refuses, then it is gone; the server's head for it bounds its ops in U.
    fn expire_kind4(&mut self) {
        let clock = self
            .devices
            .iter()
            .enumerate()
            .filter(|(d, _)| self.joined.get(*d).copied().unwrap_or(false))
            .map(|(_, dev)| dev.now_ms)
            .max()
            .unwrap_or(T0);
        let due: Vec<usize> = self
            .kind4
            .iter()
            .filter(|&(d, &at)| clock > at && !self.expired.contains_key(d))
            .map(|(&d, _)| d)
            .collect();
        for d in due {
            let Some(dev) = self.devices.get_mut(d) else {
                continue;
            };
            self.server.expired.insert(dev.id);
            if self.joined.get(d).copied().unwrap_or(false) {
                for &item in &self.items {
                    dev.snapshot(item);
                }
                dev.upload_ops(&mut self.server, false);
                dev.upload_snapshots(&mut self.server, true);
            }
            let head = self.server.heads().get(dev.id);
            self.expired.insert(d, head);
        }
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
        if let Some((header, body, key)) = dev.write(item, edit) {
            let dot = header.dot;
            match LedgerOp::new(header, body, key) {
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
        self.offer(d);
        let Some(dev) = self.devices.get_mut(d) else {
            return;
        };
        // Process the offered account state (CRYPTO.md §11.3 steps 3-4) before detecting a
        // rollback and healing (ADR 0032 §1), as `World::fetch` already does: otherwise this
        // device heals under its own stale epoch, sealing a fresh item key wrapped at an epoch
        // other devices skip past when they adopt straight to the newest one, which leaves that
        // wrap permanently unreadable (regression, family 9 seed 0x22a680c6b68bfc42).
        if let Some(epoch) = dev.offered {
            dev.adopt(epoch);
        }
        Self::heal_epoch(dev, &mut self.server);
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
        self.offer(d);
        let Some(dev) = self.devices.get_mut(d) else {
            return;
        };
        if let Some(epoch) = dev.offered {
            dev.adopt(epoch);
        }
        Self::heal_epoch(dev, &mut self.server);
        if dev.server_behind(&self.server) {
            dev.read_only = true;
            dev.heal(&mut self.server);
        }
        let mut response = self.server.fetch(
            dev.id,
            &dev.log.cursor(),
            if self.draining && !self.faults.page_in_drain {
                0
            } else {
                self.faults.page_len
            },
        );
        let mut pages: Vec<Page> = Vec::new();
        for mut page in core::mem::take(&mut response.pages) {
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
        dev.fetch(&response, &pages);
        dev.read_only = dev.server_behind(&self.server);
    }

    /// Offers device `d` the newest account state: its vault epoch, unless `d` is revoked (no
    /// grant).
    fn offer(&mut self, d: usize) {
        let offered = (!self.revoked.contains_key(&d)).then_some(self.epoch);
        if let Some(dev) = self.devices.get_mut(d) {
            dev.offered = offered;
        }
    }

    /// The ADR 0032 §3 lag repair: a device whose vault epoch is above the server's (a restore
    /// rolled the server back past a rotation) sends the self-grant's epoch and every wrap-set
    /// row it holds, re-wrapped at that epoch, before any record.
    fn heal_epoch(dev: &mut Device, server: &mut Server) {
        if dev.epoch <= server.epoch() {
            return;
        }
        if let Some(rows) = dev.epoch_rows() {
            let stored = server.heal_epoch(dev.epoch, &rows);
            dev.events
                .push(format!("epoch heal to {}: {stored}", dev.epoch));
        }
    }

    /// Revokes device `d` in one request with a rotation made by another active device (CRYPTO.md
    /// §11.8 steps 1–3), if at least two other devices stay active.
    fn revoke(&mut self, d: usize) {
        let others: Vec<usize> = (0..self.devices.len())
            .filter(|&e| e != d && self.active(e))
            .collect();
        if !self.active(d) || others.len() < 2 || self.kind4.contains_key(&d) {
            return;
        }
        if let Some(&rotator) = others.iter().find(|&&e| !self.kind4.contains_key(&e)) {
            self.rotate(rotator, Some(d));
        }
    }

    /// A rotation by device `r` (CRYPTO.md §11.6, ADR 0025 §2), revoking `revoke` in the same
    /// request if given: `r` uploads and fetches (online for it), and the rotation goes only if
    /// it is then not read-only and its cursor is every head; it re-wraps the wrap set under
    /// the next vault key, and the server checks and stores the rotation ([`Server::rotate`]).
    /// The world then offers the new epoch to every device but the revoked one, and records
    /// what property 6 needs. Returns whether the rotation was stored.
    fn rotate(&mut self, r: usize, revoke: Option<usize>) -> bool {
        let epoch = self.epoch.max(self.server.epoch()) + 1;
        if !self.active(r) || self.kind4.contains_key(&r) || epoch >= crypto::EPOCHS {
            return false;
        }
        if let Some(o) = self.online.get_mut(r) {
            *o = true;
        }
        self.upload(r, false, false);
        self.fetch(r);
        let rows = self.server.rows();
        let heads = self.server.heads();
        let revoked_id = revoke.and_then(|v| self.devices.get(v).map(|dev| dev.id));
        let Some(dev) = self.devices.get_mut(r) else {
            return false;
        };
        let cursor = dev.log.cursor();
        let devices: BTreeSet<DeviceId> = heads
            .entries()
            .chain(cursor.entries())
            .map(Dot::device_id)
            .collect();
        if dev.read_only || devices.iter().any(|&e| heads.get(e) != cursor.get(e)) {
            dev.events
                .push(format!("rotation not sent: cursor {cursor:?}"));
            return false;
        }
        let (rewrapped, dropped) = dev.rewrap(&rows, epoch);
        let rotation = Rotation {
            epoch,
            cursor,
            rewrapped,
            dropped,
            revoke: revoked_id,
        };
        let live = self.envelopes();
        self.ever_envelopes.extend(live);
        let before = self.ever_envelopes.clone();
        match self.server.rotate(&rotation) {
            Ok(cutoff) => {
                self.epoch = epoch;
                if let Some(dev) = self.devices.get_mut(r) {
                    dev.adopt(epoch);
                }
                let (keys, vault_keys) = revoke
                    .and_then(|v| self.devices.get(v))
                    .map(|dev| (dev.held_keys(), dev.vault_keys.clone()))
                    .unwrap_or_default();
                if let (Some(v), Some(cutoff)) = (revoke, cutoff) {
                    self.revoked.insert(v, cutoff);
                }
                self.rotations.push(RotationRecord {
                    epoch,
                    revoked: revoke,
                    keys,
                    vault_keys,
                    before,
                });
                true
            }
            Err(refusal) => {
                self.violations.push(format!(
                    "ADR 0025: the server refused a rotation its rotator built after a complete Fetch: {refusal:?}"
                ));
                false
            }
        }
    }

    /// Every envelope that exists: the server's and every device's (property 6's "before").
    fn envelopes(&self) -> BTreeSet<Vec<u8>> {
        let mut all = BTreeSet::new();
        let (ops, snaps) = self.server.envelopes();
        all.extend(ops.into_iter().map(|(_, e)| e.to_vec()));
        all.extend(snaps.into_iter().map(|s| s.data.clone()));
        for dev in &self.devices {
            let (ops, snaps) = dev.envelopes();
            all.extend(ops.into_iter().map(|(_, e)| e.to_vec()));
            all.extend(snaps.into_iter().map(|s| s.data.clone()));
        }
        all
    }

    /// Property 6 and the writer rule on every envelope written after each rotation that the
    /// server holds, and at quiescence (`all`) every active device too (see the module docs).
    /// With `all`, the envelopes are also opened under every key of their item the revoked
    /// device holds, and the wrap-set rows under every vault key it holds.
    fn check_rotations(&mut self, all: bool) {
        if self.rotations.is_empty() {
            return;
        }
        let mut ops: Vec<(&crate::header::OpHeader, &[u8])> = Vec::new();
        let mut snaps: Vec<&SnapRecord> = Vec::new();
        let (server_ops, server_snaps) = self.server.envelopes();
        ops.extend(server_ops);
        snaps.extend(server_snaps);
        if all {
            for (d, dev) in self.devices.iter().enumerate() {
                if self.active(d) {
                    let (o, s) = dev.envelopes();
                    ops.extend(o);
                    snaps.extend(s);
                }
            }
        }
        let rows = self.server.rows();
        // A device that missed a rotation may still write under its old key, two ways ADR 0032
        // keeps the record: (1) the ADR 0021 §9 "Healing request" path, exempt from the
        // stale-epoch check outright; (2) a restore that rolls the server back to or below a
        // floor epoch F makes a plain upload at F legitimate again, and a later lag repair
        // ([`Server::heal_epoch`]) can then re-raise the server past a rotation this run still
        // records above F. Excuses exactly those envelopes, never every rotation for the rest
        // of the run just because a restore happened once. Property 6 is never excused.
        let healed_envelopes = self.server.healed_envelopes().clone();
        let restore_floors = self.restore_floors.clone();
        let mut found = Vec::new();
        let (mut checked, mut attempts) = (0, 0);
        for rotation in &self.rotations {
            let revoked_holds = |key: &SymmetricKeyId| rotation.keys.contains(key);
            let mut check = |item: ItemId,
                             envelope: &[u8],
                             opens: &dyn Fn(&SymmetricKeyId) -> bool| {
                if rotation.before.contains(envelope) {
                    return;
                }
                checked += 1;
                let key = crypto::envelope_key(envelope);
                let created = key.as_ref().and_then(crypto::key_info).map(|(_, e)| e);
                let excused = healed_envelopes.contains(envelope)
                    || restore_floors.iter().any(|&floor| {
                        floor < rotation.epoch && created.is_some_and(|e| e >= floor)
                    });
                if !excused && created.is_none_or(|e| e < rotation.epoch) {
                    found.push(format!(
                        "writer rule: an envelope of {item:?} written after the rotation to epoch {} is sealed under an item key created at {created:?}",
                        rotation.epoch
                    ));
                }
                let Some(revoked) = rotation.revoked else {
                    return;
                };
                if key.as_ref().is_some_and(revoked_holds) {
                    found.push(format!(
                        "property 6: device {revoked}, revoked at epoch {}, holds the key of an envelope of {item:?} written after the rotation",
                        rotation.epoch
                    ));
                }
                if all {
                    for k in rotation
                        .keys
                        .iter()
                        .filter(|k| crypto::key_info(k).is_some_and(|(i, _)| i == item))
                    {
                        attempts += 1;
                        if opens(k) {
                            found.push(format!(
                                "property 6: device {revoked} decrypts an envelope of {item:?} written after its revocation"
                            ));
                        }
                    }
                }
            };
            for &(header, envelope) in &ops {
                check(header.item_id, envelope, &|k| {
                    crypto::op_opens_under(header, envelope, k)
                });
            }
            for s in &snaps {
                check(s.header.item_id, &s.data, &|k| {
                    crypto::snapshot_opens_under(&s.header, &s.data, k)
                });
            }
            if all && rotation.revoked.is_some() {
                for row in &rows {
                    for &v in &rotation.vault_keys {
                        attempts += 1;
                        if crypto::unwrap(v, row.item, &row.wrap.envelope).is_some() {
                            found.push(format!(
                                "property 6: a vault key of epoch {v} the revoked device holds opens a wrap-set row at epoch {}",
                                row.wrap.epoch
                            ));
                        }
                    }
                }
            }
        }
        self.p6_checked.0 += checked;
        self.p6_checked.1 += attempts;
        self.violations.extend(found);
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
        // ADR 0021 §9 "Stale epoch": no op below the vault's epoch stored outside a healing
        // request, but a revoked device's op at or below its cut-off.
        let cutoffs = self.server.cutoffs();
        let stale: Vec<String> = self
            .server
            .stored_epochs()
            .filter(|(header, at)| {
                header.vault_key_epoch < *at
                    && cutoffs
                        .get(&header.dot.device_id())
                        .is_none_or(|&c| header.dot.seq() > c)
            })
            .map(|(header, at)| {
                format!(
                    "stale epoch after {after}: {:?} at epoch {} stored at vault epoch {at}",
                    header.dot, header.vault_key_epoch
                )
            })
            .collect();
        self.violations.extend(stale);
        self.check_rotations(false);
    }

    /// A fingerprint of every party's state, for the drain's fixed point.
    fn fingerprint(&self) -> String {
        let mut out = format!("{:?}", self.server.fingerprint());
        for dev in &self.devices {
            let _ = write!(out, "|{:?}{}", dev.log.cursor(), dev.epoch);
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
    /// From here on Fetch responses come as one page, unless [`Faults::page_in_drain`]. A paged
    /// response can put a tombstone cover in the page of a bodiless header it covers and its
    /// recorded purge in a later page (of the same chain or another device's); the merge
    /// refuses the cover (`PurgeAboveCut`: the purge is above the page's cut), and the device
    /// holds it until a later page of the same response delivers the purge (ADR 0050 §2). A
    /// hold the response leaves unresolved, and every other refusal of an untainted cover, is a
    /// violation.
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

    /// The ops of U on `item` (see the module docs).
    fn universe(&self, item: ItemId) -> Vec<&LedgerOp> {
        self.ledger
            .values()
            .filter(|op| op.header.item_id == item)
            .filter(|op| {
                let dot = op.header.dot;
                !self
                    .revoked
                    .iter()
                    .chain(&self.expired)
                    .any(|(&d, &cutoff)| {
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
        let mut beyond_bound = (0, 0);
        // Items two or more faulty devices lied about: beyond the bound (module docs).
        let beyond_items: BTreeSet<ItemId> = self
            .items
            .iter()
            .copied()
            .filter(|item| {
                self.faulty
                    .iter()
                    .filter(|&&f| {
                        self.devices
                            .get(f)
                            .is_some_and(|dev| dev.lied_items.contains(item))
                    })
                    .count()
                    >= 2
            })
            .collect();
        // In such a run, the devices that refused a lie and reported the gap it left: their
        // chains stop there, on every item, detected and reported.
        let lie_gapped: BTreeSet<usize> = active
            .iter()
            .copied()
            .filter(|_| !beyond_items.is_empty())
            .filter(|&d| {
                self.devices.get(d).is_some_and(|dev| {
                    dev.stats.lie_refused > 0
                        && dev.reports.iter().any(|r| matches!(r, Report::Gap { .. }))
                })
            })
            .collect();
        self.lie_gapped += lie_gapped.len() as u64;
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
            let beyond = beyond_items.contains(&item);
            let mut bytes: Option<Vec<u8>> = None;
            let mut converged = true;
            let mut p1 = Vec::new();
            for &d in active.iter().filter(|d| !lie_gapped.contains(d)) {
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
                        if !lost.is_empty() && !dev.disagreement_items.contains(&item) && !beyond {
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
            if beyond {
                beyond_bound.0 += 1;
                beyond_bound.1 += u64::from(!converged);
            } else if !reported {
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
        let skip_gaps = self.restored;
        for &d in &active {
            let Some(dev) = self.devices.get(d) else {
                continue;
            };
            let gapped = lie_gapped.contains(&d);
            if !dev.last_complete.is_empty() && !gapped {
                violations.push(format!(
                    "property 7 / ADR 0021 §8: device {d} reports missing data at quiescence: {:?}",
                    dev.last_complete
                ));
            }
            let waiting = dev.log.waiting();
            if !waiting.is_empty() && !gapped {
                violations.push(format!("device {d} still waits for {waiting:?}"));
            }
            if !skip_gaps && !gapped {
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
            if self.faulty.is_empty() && dev.items.values().any(|m| m.unresolved().next().is_some())
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
        self.beyond_bound.0 += beyond_bound.0;
        self.beyond_bound.1 += beyond_bound.1;
        self.violations.extend(violations);
        self.check_rotations(true);
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
