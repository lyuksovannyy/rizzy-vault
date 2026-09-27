//! A simulated single-vault server that runs generated histories through the compaction
//! functions, and an independent brute-force checker of ADR 0021 §8's server properties.
//!
//! **The server** stores op headers with a body flag, snapshots with their covered and
//! clamped VVs and store sequences, revocation cut-offs and expired certificates, and calls
//! only the public functions of [`super`]: [`clamp`] and [`check_snapshot`] when it stores a
//! snapshot, [`check_healing_request`] for a healing request, [`plan_worker`] for `worker`
//! and [`select_covers`] for Fetch. It models headers only: no crypto, no bodies' content,
//! one vault, two items, four devices. It can also run ADR 0012 §7's superseded rule (keep the
//! two newest snapshots, delete what the older covers, serve the newest), so that the named
//! scenarios show the failure ADR 0021's Context describes before showing it gone.
//!
//! **The checker** is written from ADR 0021 §2–§4 and §8, not from the module: "covers" is
//! spelled out as `o.device_seq ≤ clamped(S)[o.device_id]` on the same item, and each rule
//! is transcribed as the ADR words it, R3 with its "re-tested after each drop" as a restart
//! from the oldest. After every step it checks properties 1–3 (3 on two fetches: from an
//! empty cursor and from a cursor behind the heads), and after every `worker` run
//! properties 4 and 5, in their two-author form (as the merge spike's `server.rs`
//! `check_two_author_props` checks them). It also checks each acceptance decision of §9
//! against its own transcription.
//!
//! **Histories** interleave writes by four devices on two items; snapshots that cover the
//! heads, lag behind them (concurrent snapshots, as after concurrent purges or late edits) or
//! claim dots above them up to `u64::MAX`; healing requests that store headers without bodies
//! behind a fresh snapshot, some refused; backups and restores (ADR 0011 "Backups"), a restore
//! loading the last backup's rows and setting the store counter above their maximum (§2
//! "Store sequence"), so that later healing requests re-publish headers the restore lost;
//! revocations and certificate expiries; and `worker` runs at any point, so `worker` is paused
//! and resumed. A second generator keeps histories linear, so that property 5 is checked in
//! every run. Snapshots that claim dots above the heads, uploaded or inside a healing request,
//! stand for §8's "snapshots that claim unheld dots, up to `u64::MAX`" and "a snapshot
//! uploaded before ops it covers": §9 refuses them (inside a healing request against the heads
//! after its headers, the merge spike's reading), except a revoked device's entry above its
//! cut-off, which is stored and which the clamp cuts. An item that no step snapshots stands
//! for an oversize item (§5), whose bodies all stay. The restore generation, byte-identical
//! re-uploads and the stale-epoch rules (§9) belong to the caller's store and are not modelled
//! here.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestRng, TestRunner};

use super::*;

/// Devices in a generated history.
const DEVICES: usize = 4;
/// Their id bytes: device i is `[IDS[i]; 16]`.
const IDS: [u8; DEVICES] = [0xa1, 0xb2, 0xc3, 0xd4];
/// Items in a generated history.
const ITEMS: u8 = 2;

/// Device `i` of a history.
fn device_id(i: usize) -> DeviceId {
    DeviceId::from_bytes([IDS[i]; 16])
}

/// ADR 0021 §2 "Covers", spelled out: `dot.seq ≤ v[dot.device_id]`, a missing entry being 0.
fn vv_covers(v: &VersionVector, dot: Dot) -> bool {
    dot.seq() <= v.get(dot.device_id())
}

/// Whether every entry of `low` is at most `high`'s, spelled out.
fn vv_le(low: &VersionVector, high: &VersionVector) -> bool {
    low.entries().all(|entry| vv_covers(high, entry))
}

/// Which compaction rule the simulated server runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    /// ADR 0021, through the module.
    Adr0021,
    /// ADR 0012 §7 as it stood before ADR 0021, transcribed here for the named scenarios.
    Adr0012,
}

/// An op header the server holds.
#[derive(Clone, Debug)]
struct StoredOp {
    /// The item its header names.
    item: u8,
    /// Whether the body is held.
    held: bool,
    /// Its position in the server's store order (shared with snapshots' store sequences).
    stored_at: u64,
    /// Whether a healing request stored it without its body.
    healed: bool,
}

/// A retained snapshot.
#[derive(Clone, Debug)]
struct StoredSnap {
    /// The item it snapshots.
    item: u8,
    /// Its store sequence, from the same counter as the ops' store order.
    store_seq: u64,
    /// The device that signed it.
    author: DeviceId,
    /// The covered VV its signed header claims.
    covered: VersionVector,
    /// The clamped VV computed when it was stored.
    clamped: VersionVector,
}

impl StoredSnap {
    /// The module's view of it.
    fn retained(&self) -> RetainedSnapshot {
        RetainedSnapshot {
            store_seq: self.store_seq,
            clamped: self.clamped.clone(),
            author: self.author,
        }
    }
}

/// One item's part of a Fetch response.
#[derive(Clone, Debug, Default)]
struct ItemResponse {
    /// The item's op headers after the cursor, ascending by dot, with their body flag.
    ops: Vec<(Dot, bool)>,
    /// The covers served, in the order served.
    covers: Vec<StoredSnap>,
    /// Bodiless headers the server found no cover for (an integrity error).
    uncovered: Vec<Dot>,
}

/// A Fetch response, per item.
type Response = BTreeMap<u8, ItemResponse>;

/// Why a healing request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HealRefusal {
    /// A header past its device's revocation cut-off.
    PastCutoff,
    /// The fresh snapshot was refused.
    Snapshot(SnapshotRefusal),
    /// A bodiless header without a cover.
    Uncovered(UncoveredHeader),
}

/// The simulated server of one vault.
#[derive(Clone, Debug)]
struct Server {
    /// The compaction rule it runs.
    rule: Rule,
    /// Every op header ever stored, keyed by dot: headers are kept for the life of the vault.
    ops: BTreeMap<Dot, StoredOp>,
    /// The retained snapshots.
    snaps: Vec<StoredSnap>,
    /// The store counter: each stored op or snapshot takes the next value.
    clock: u64,
    /// Revocation cut-offs (`last_accepted_device_seq`).
    cutoffs: BTreeMap<DeviceId, u64>,
    /// Devices whose certificate has expired.
    expired: BTreeSet<DeviceId>,
    /// Per item, the covered VV of the last snapshot stored.
    last_covered: BTreeMap<u8, VersionVector>,
    /// Items whose history is not linear: some stored snapshot's covered VV was not ≥ the one
    /// stored before it (ADR 0021 §3 "Linear histories").
    nonlinear: BTreeSet<u8>,
}

impl Server {
    /// An empty vault.
    fn new(rule: Rule) -> Self {
        Self {
            rule,
            ops: BTreeMap::new(),
            snaps: Vec::new(),
            clock: 0,
            cutoffs: BTreeMap::new(),
            expired: BTreeSet::new(),
            last_covered: BTreeMap::new(),
            nonlinear: BTreeSet::new(),
        }
    }

    /// Every head h(V, d), as a VV.
    fn heads(&self) -> VersionVector {
        self.ops.keys().copied().collect()
    }

    /// The next store position.
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// The certificate state of `author`.
    fn expiry(&self, author: DeviceId) -> CertificateExpiry {
        if self.expired.contains(&author) {
            CertificateExpiry::Expired
        } else {
            CertificateExpiry::Unexpired
        }
    }

    /// Whether the clamp cut the claim of the snapshot stored last: its clamped VV differs
    /// from its covered VV. Snapshots are appended as they are stored, so the last one is it.
    fn newest_clamped_below(&self) -> bool {
        self.snaps.last().is_some_and(|s| s.clamped != s.covered)
    }

    /// The item's retained snapshots, oldest first.
    fn item_snaps(&self, item: u8) -> Vec<&StoredSnap> {
        let mut snaps: Vec<&StoredSnap> = self.snaps.iter().filter(|s| s.item == item).collect();
        snaps.sort_by_key(|s| s.store_seq);
        snaps
    }

    /// Uploads one op of `device` on `item` with its body, next in its chain. `None` when the
    /// server accepts nothing more from the device: revoked, or its certificate expired.
    fn write(&mut self, device: DeviceId, item: u8) -> Option<Dot> {
        if self.cutoffs.contains_key(&device) || self.expired.contains(&device) {
            return None;
        }
        let dot = Dot::new(device, self.heads().get(device).checked_add(1)?)?;
        let stored_at = self.tick();
        self.ops.insert(
            dot,
            StoredOp {
                item,
                held: true,
                stored_at,
                healed: false,
            },
        );
        Some(dot)
    }

    /// Stores an accepted snapshot: clamped VV and store sequence (ADR 0021 §2).
    fn store_snapshot(&mut self, item: u8, author: DeviceId, covered: VersionVector) -> u64 {
        let clamped = clamp(&covered, &self.heads());
        if self
            .last_covered
            .get(&item)
            .is_some_and(|last| !vv_le(last, &covered))
        {
            self.nonlinear.insert(item);
        }
        self.last_covered.insert(item, covered.clone());
        let store_seq = self.tick();
        self.snaps.push(StoredSnap {
            item,
            store_seq,
            author,
            covered,
            clamped,
        });
        store_seq
    }

    /// Uploads a snapshot outside a healing request.
    fn upload_snapshot(
        &mut self,
        item: u8,
        author: DeviceId,
        covered: VersionVector,
    ) -> Result<u64, SnapshotRefusal> {
        let heads = self.heads();
        check_snapshot(
            author,
            &covered,
            VaultChains {
                heads: &heads,
                cutoffs: &self.cutoffs,
            },
            self.expiry(author),
        )?;
        Ok(self.store_snapshot(item, author, covered))
    }

    /// One healing request, atomic: `count` headers of `chain` above its head on `item`,
    /// stored without bodies, then the healer's fresh snapshot with the covered VV `fresh`
    /// makes from the heads after those headers.
    fn heal(
        &mut self,
        healer: DeviceId,
        chain: DeviceId,
        item: u8,
        count: u8,
        fresh: impl Fn(&VersionVector) -> VersionVector,
    ) -> Result<(), HealRefusal> {
        let before = self.clone();
        let result = self.heal_inner(healer, chain, item, count, fresh);
        if result.is_err() {
            *self = before;
        }
        result
    }

    /// [`Server::heal`] without the rollback.
    fn heal_inner(
        &mut self,
        healer: DeviceId,
        chain: DeviceId,
        item: u8,
        count: u8,
        fresh: impl Fn(&VersionVector) -> VersionVector,
    ) -> Result<(), HealRefusal> {
        let mut stored = Vec::new();
        for _ in 0..count {
            let seq = self.heads().get(chain) + 1;
            if self.cutoffs.get(&chain).is_some_and(|&cutoff| seq > cutoff) {
                return Err(HealRefusal::PastCutoff);
            }
            let dot = Dot::new(chain, seq).unwrap();
            let stored_at = self.tick();
            self.ops.insert(
                dot,
                StoredOp {
                    item,
                    held: false,
                    stored_at,
                    healed: true,
                },
            );
            stored.push(dot);
        }
        let heads = self.heads();
        let covered = fresh(&heads);
        check_snapshot(
            healer,
            &covered,
            VaultChains {
                heads: &heads,
                cutoffs: &self.cutoffs,
            },
            self.expiry(healer),
        )
        .map_err(HealRefusal::Snapshot)?;
        self.store_snapshot(item, healer, covered);
        let retained: Vec<RetainedSnapshot> = self
            .item_snaps(item)
            .into_iter()
            .map(StoredSnap::retained)
            .collect();
        check_healing_request(&retained, &stored).map_err(HealRefusal::Uncovered)
    }

    /// One `worker` run over every item. Returns the number of bodies deleted and snapshots
    /// dropped.
    fn worker(&mut self) -> (usize, usize) {
        let (mut deleted, mut dropped) = (0, 0);
        for item in 0..ITEMS {
            let (delete, drop_seqs, older_seqs) = self.plan(item);
            for dot in &delete {
                let op = self.ops.get_mut(dot).unwrap();
                assert!(
                    op.held && op.item == item,
                    "worker deletes a body it does not hold"
                );
                op.held = false;
            }
            assert!(
                drop_seqs.iter().all(|seq| older_seqs.contains(seq)),
                "worker drops a snapshot outside the older ones of the item"
            );
            deleted += delete.len();
            dropped += drop_seqs.len();
            self.snaps
                .retain(|s| s.item != item || !drop_seqs.contains(&s.store_seq));
        }
        (deleted, dropped)
    }

    /// What `worker` does to `item` under the server's rule: the bodies to delete, the
    /// snapshots to drop, and the store sequences of the item's snapshots outside the two
    /// newest.
    fn plan(&self, item: u8) -> (Vec<Dot>, Vec<u64>, Vec<u64>) {
        let snaps = self.item_snaps(item);
        let n = snaps.len();
        let older_seqs: Vec<u64> = snaps[..n.saturating_sub(2)]
            .iter()
            .map(|s| s.store_seq)
            .collect();
        match self.rule {
            Rule::Adr0021 => {
                let retained: Vec<RetainedSnapshot> = snaps.iter().map(|s| s.retained()).collect();
                let ops: Vec<OpDot> = self
                    .ops
                    .iter()
                    .filter(|(_, op)| op.item == item)
                    .map(|(&dot, op)| OpDot {
                        dot,
                        body: if op.held { Body::Held } else { Body::Absent },
                    })
                    .collect();
                let plan = plan_worker(&retained, &ops).unwrap();
                (plan.delete_bodies, plan.drop_snapshots, older_seqs)
            }
            Rule::Adr0012 => {
                // "The server keeps the two newest snapshots per item. It deletes only the
                // bodies of the ops covered by the older of the two."
                let delete = match n.checked_sub(2).map(|i| &snaps[i].covered) {
                    Some(older) => self
                        .ops
                        .iter()
                        .filter(|(dot, op)| op.item == item && op.held && vv_covers(older, **dot))
                        .map(|(&dot, _)| dot)
                        .collect(),
                    None => Vec::new(),
                };
                (delete, older_seqs.clone(), older_seqs)
            }
        }
    }

    /// A Fetch from `cursor`: every op header after it, and the covers of each item's
    /// bodiless headers.
    fn fetch(&self, cursor: &VersionVector) -> Response {
        let mut response = Response::new();
        for (&dot, op) in &self.ops {
            if !vv_covers(cursor, dot) {
                response
                    .entry(op.item)
                    .or_default()
                    .ops
                    .push((dot, op.held));
            }
        }
        for (&item, part) in &mut response {
            let bodiless: Vec<Dot> = part
                .ops
                .iter()
                .filter(|(_, held)| !held)
                .map(|&(dot, _)| dot)
                .collect();
            let snaps = self.item_snaps(item);
            match self.rule {
                Rule::Adr0021 => {
                    let retained: Vec<RetainedSnapshot> =
                        snaps.iter().map(|s| s.retained()).collect();
                    let selection = select_covers(&retained, &bodiless).unwrap();
                    part.covers = selection
                        .covers
                        .iter()
                        .map(|seq| (*snaps.iter().find(|s| s.store_seq == *seq).unwrap()).clone())
                        .collect();
                    part.uncovered = selection.uncovered;
                }
                Rule::Adr0012 => {
                    // "plus the newest snapshot of that item".
                    if !bodiless.is_empty() {
                        part.covers = snaps.last().map(|s| (*s).clone()).into_iter().collect();
                    }
                }
            }
        }
        response
    }
}

/// ADR 0021 §4 "Covers", transcribed: "the server takes that item's retained snapshots newest
/// first. It adds each one that covers a bodiless header of the item in the response that the
/// snapshots added so far cover by no author, or by one author other than its own."
pub(super) fn literal_covers(snapshots: &[RetainedSnapshot], bodiless: &[Dot]) -> Vec<u64> {
    let mut newest_first: Vec<&RetainedSnapshot> = snapshots.iter().collect();
    newest_first.sort_by_key(|s| core::cmp::Reverse(s.store_seq));
    let mut added: Vec<&RetainedSnapshot> = Vec::new();
    for snapshot in newest_first {
        let adds = bodiless.iter().any(|&header| {
            let authors: BTreeSet<DeviceId> = added
                .iter()
                .filter(|s| vv_covers(&s.clamped, header))
                .map(|s| s.author)
                .collect();
            vv_covers(&snapshot.clamped, header)
                && (authors.is_empty()
                    || (authors.len() == 1 && !authors.contains(&snapshot.author)))
        });
        if adds {
            added.push(snapshot);
        }
    }
    added.iter().map(|s| s.store_seq).collect()
}

/// The number of distinct authors among `snapshots` that cover `dot`.
fn authors_covering(snapshots: &[&RetainedSnapshot], dot: Dot) -> usize {
    distinct_authors(snapshots.iter().map(|s| (s.author, &s.clamped)), dot)
}

/// The number of distinct authors among `(author, clamped VV)` pairs whose VV covers `dot`.
fn distinct_authors<'a>(
    snapshots: impl Iterator<Item = (DeviceId, &'a VersionVector)>,
    dot: Dot,
) -> usize {
    snapshots
        .filter(|(_, clamped)| vv_covers(clamped, dot))
        .map(|(author, _)| author)
        .collect::<BTreeSet<DeviceId>>()
        .len()
}

/// ADR 0021 §3, transcribed. R1: "The server deletes an op's body when, and only when, the
/// older of the item's two newest retained snapshots covers the op and retained snapshots by
/// two different authors cover it. With fewer than two retained snapshots it deletes nothing."
/// R3: "The item's two newest snapshots are always retained. An older snapshot stays while
/// dropping it would lower the number of authors that cover some bodiless header to fewer than
/// two. Every other older snapshot is dropped, tested oldest first and re-tested after each
/// drop": after each drop, testing starts again from the oldest.
pub(super) fn literal_worker(snapshots: &[RetainedSnapshot], ops: &[OpDot]) -> WorkerPlan {
    let mut retained: Vec<&RetainedSnapshot> = snapshots.iter().collect();
    retained.sort_by_key(|s| s.store_seq);
    let mut held: BTreeMap<Dot, bool> = ops
        .iter()
        .map(|op| (op.dot, op.body == Body::Held))
        .collect();
    let mut delete_bodies = Vec::new();
    if let Some(older) = retained.len().checked_sub(2).map(|i| retained[i]) {
        for (&dot, body) in &mut held {
            if *body && vv_covers(&older.clamped, dot) && authors_covering(&retained, dot) >= 2 {
                *body = false;
                delete_bodies.push(dot);
            }
        }
    }
    let mut drop_snapshots = Vec::new();
    'restart: loop {
        for i in 0..retained.len().saturating_sub(2) {
            let without: Vec<&RetainedSnapshot> = retained
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, s)| *s)
                .collect();
            let stays = held.iter().filter(|(_, body)| !**body).any(|(&dot, _)| {
                let with = authors_covering(&retained, dot);
                let after = authors_covering(&without, dot);
                after < with && after < 2
            });
            if !stays {
                drop_snapshots.push(retained.remove(i).store_seq);
                continue 'restart;
            }
        }
        break;
    }
    WorkerPlan {
        delete_bodies,
        drop_snapshots,
    }
}

/// ADR 0021 §9 "Server acceptance" and "Revoked and kind-4 authors", transcribed: whether the
/// server stores the snapshot. `heads` are the heads when it is stored: for an upload the
/// current ones, inside a healing request those after the request's headers.
fn literal_accepts(
    server: &Server,
    author: DeviceId,
    covered: &VersionVector,
    heads: &VersionVector,
) -> bool {
    // "the server refuses new ones after the author's revocation or expiry"
    if server.cutoffs.contains_key(&author) || server.expired.contains(&author) {
        return false;
    }
    // "The server refuses any snapshot whose covered-VV entry for its author is above that
    // author's head."
    if covered.get(author) > heads.get(author) {
        return false;
    }
    // "Outside a request it refuses a snapshot whose covered VV exceeds its heads, counting a
    // revoked device's entry only up to its last_accepted_device_seq." §9 is silent on a
    // snapshot inside a request; the merge spike's `integrated` server refuses it the same way
    // against the heads after the request's headers ("a healing request stores the claimed
    // headers before its snapshots, so its snapshots pass").
    covered.entries().all(|entry| {
        let counted = server
            .cutoffs
            .get(&entry.device_id())
            .map_or(entry.seq(), |&cutoff| entry.seq().min(cutoff));
        counted <= heads.get(entry.device_id())
    })
}

/// Properties 1 and 2, after every step, whether or not `worker` has run.
fn check_stored(server: &Server) -> Result<(), TestCaseError> {
    for (&dot, op) in &server.ops {
        // 1. Every bodiless header has a retained cover.
        if !op.held {
            prop_assert!(
                server
                    .snaps
                    .iter()
                    .any(|s| s.item == op.item && vv_covers(&s.clamped, dot)),
                "property 1: bodiless header {:?} without a retained cover",
                dot
            );
        }
        // 2. No snapshot covers an op stored after it.
        for s in &server.snaps {
            prop_assert!(
                !(s.item == op.item && op.stored_at > s.store_seq && vv_covers(&s.clamped, dot)),
                "property 2: snapshot {} covers {:?}, stored after it",
                s.store_seq,
                dot
            );
        }
    }
    Ok(())
}

/// Property 3 on one response, after every step: every bodiless header comes with a snapshot
/// whose clamped and covered VVs both cover it. Also, in §4's two-author form, covers by as
/// many authors as the retained snapshots have, up to two; and exactly §4's selection.
fn check_response(server: &Server, response: &Response) -> Result<(), TestCaseError> {
    for (&item, part) in response {
        let bodiless: Vec<Dot> = part
            .ops
            .iter()
            .filter(|(_, held)| !held)
            .map(|&(dot, _)| dot)
            .collect();
        let retained: Vec<RetainedSnapshot> = server
            .snaps
            .iter()
            .filter(|s| s.item == item)
            .map(StoredSnap::retained)
            .collect();
        for &dot in &bodiless {
            prop_assert!(
                part.covers.iter().any(|c| c.item == item
                    && vv_covers(&c.clamped, dot)
                    && vv_covers(&c.covered, dot)),
                "property 3: bodiless header {:?} served without a cover",
                dot
            );
            let available = distinct_authors(retained.iter().map(|s| (s.author, &s.clamped)), dot);
            let in_response =
                distinct_authors(part.covers.iter().map(|c| (c.author, &c.clamped)), dot);
            prop_assert!(
                in_response >= available.min(2),
                "§4: {:?} served with covers by {} authors of {}",
                dot,
                in_response,
                available
            );
        }
        prop_assert!(part.uncovered.is_empty());
        let cover_seqs: Vec<u64> = part.covers.iter().map(|c| c.store_seq).collect();
        prop_assert_eq!(cover_seqs, literal_covers(&retained, &bodiless));
    }
    Ok(())
}

/// Properties 4 and 5, right after `worker` runs, in their two-author form.
fn check_after_worker(server: &Server) -> Result<(), TestCaseError> {
    for item in 0..ITEMS {
        let ordered: Vec<RetainedSnapshot> = server
            .item_snaps(item)
            .into_iter()
            .map(StoredSnap::retained)
            .collect();
        let refs: Vec<&RetainedSnapshot> = ordered.iter().collect();
        let n = refs.len();
        let ops: Vec<(Dot, &StoredOp)> = server
            .ops
            .iter()
            .filter(|(_, op)| op.item == item)
            .map(|(&dot, op)| (dot, op))
            .collect();
        // 4. R3 keeps every retained snapshot outside the two newest: dropping it would lower
        // the number of authors covering some bodiless header to fewer than two.
        for i in 0..n.saturating_sub(2) {
            let without: Vec<&RetainedSnapshot> = refs
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, s)| *s)
                .collect();
            let stays = ops.iter().any(|&(dot, op)| {
                let after = authors_covering(&without, dot);
                !op.held
                    && vv_covers(&refs[i].clamped, dot)
                    && after < 2
                    && after < authors_covering(&refs, dot)
            });
            prop_assert!(
                stays,
                "property 4: item {} keeps snapshot {}, which R3 drops",
                item,
                refs[i].store_seq
            );
        }
        // 5. In a linear history, the bodiless headers are those R1 deletes behind the older of
        // the two newest, and those a healing request stored without a body.
        if !server.nonlinear.contains(&item) {
            let older = n.checked_sub(2).map(|i| &refs[i].clamped);
            for &(dot, op) in &ops {
                let r1 =
                    older.is_some_and(|v| vv_covers(v, dot)) && authors_covering(&refs, dot) >= 2;
                prop_assert_eq!(
                    !op.held,
                    r1 || op.healed,
                    "property 5: item {}, header {:?}",
                    item,
                    dot
                );
            }
        }
    }
    Ok(())
}

/// The covered VV of a generated snapshot, from the heads.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// The heads: everything the server holds.
    Heads,
    /// The heads, each device's entry lowered by this much: a snapshot behind or concurrent.
    Behind([u8; DEVICES]),
    /// The heads, one device's entry raised by this much (saturating): a claim of unheld dots.
    Ahead {
        /// The device whose entry is raised.
        device: usize,
        /// By how much.
        by: u64,
    },
}

impl Shape {
    /// The covered VV this shape makes from `heads`.
    fn covered(self, heads: &VersionVector) -> VersionVector {
        let mut entries: BTreeMap<DeviceId, u64> = heads
            .entries()
            .map(|entry| (entry.device_id(), entry.seq()))
            .collect();
        match self {
            Self::Heads => {}
            Self::Behind(lag) => {
                for (i, &lag) in lag.iter().enumerate() {
                    if let Some(seq) = entries.get_mut(&device_id(i)) {
                        *seq = seq.saturating_sub(u64::from(lag));
                    }
                }
            }
            Self::Ahead { device, by } => {
                let seq = entries.entry(device_id(device)).or_insert(0);
                *seq = seq.saturating_add(by);
            }
        }
        entries
            .into_iter()
            .filter_map(|(device, seq)| Dot::new(device, seq))
            .collect()
    }
}

/// One step of a generated history.
#[derive(Clone, Debug)]
enum Step {
    /// A device uploads an op on an item.
    Write {
        /// The device.
        device: usize,
        /// The item.
        item: u8,
    },
    /// A device uploads a snapshot of an item.
    Snapshot {
        /// The author.
        author: usize,
        /// The item.
        item: u8,
        /// Its covered VV.
        shape: Shape,
    },
    /// A healing request: `count` headers of `chain` without bodies, behind the healer's fresh
    /// snapshot.
    Heal {
        /// The device that sends it and signs its snapshot.
        healer: usize,
        /// The device whose chain it re-publishes.
        chain: usize,
        /// The item.
        item: u8,
        /// How many headers.
        count: u8,
        /// The fresh snapshot's covered VV, from the heads after the headers.
        shape: Shape,
    },
    /// `worker` runs.
    Worker,
    /// A device is revoked at its current head.
    Revoke(usize),
    /// A device's certificate expires.
    Expire(usize),
    /// The operator takes a backup of the database.
    Backup,
    /// The operator restores the last backup, if any (ADR 0011 "Backups").
    Restore,
}

/// Coverage counters: evidence that generated histories exercise each rule.
#[derive(Clone, Copy, Debug, Default)]
struct Stats {
    /// Bodies R1 deleted.
    bodies_deleted: usize,
    /// Snapshots R3 dropped.
    snapshots_dropped: usize,
    /// Older snapshots R3 kept after a `worker` run.
    older_kept: usize,
    /// Responses with covers by two authors for one header.
    two_author_responses: usize,
    /// Uploads refused for claiming unheld dots.
    claims_refused: usize,
    /// Snapshots stored with a claim above the heads that the clamp cut: a revoked device's
    /// entry above its cut-off, the one claim §9 lets through.
    claims_clamped: usize,
    /// Snapshots refused by the author rules.
    author_refused: usize,
    /// Healing requests stored, and refused.
    heals_stored: usize,
    /// Healing requests refused.
    heals_refused: usize,
    /// `worker` runs in a linear history that deleted a body.
    linear_deletions: usize,
    /// Runs that ended with some item's history not linear.
    nonlinear_runs: usize,
    /// Restores that rolled the server back.
    restores: usize,
    /// Healing requests stored after a restore in the same run.
    heals_after_restore: usize,
}

impl Stats {
    /// Adds another run's counters.
    fn add(&mut self, other: Self) {
        self.nonlinear_runs += other.nonlinear_runs;
        self.restores += other.restores;
        self.heals_after_restore += other.heals_after_restore;
        self.bodies_deleted += other.bodies_deleted;
        self.snapshots_dropped += other.snapshots_dropped;
        self.older_kept += other.older_kept;
        self.two_author_responses += other.two_author_responses;
        self.claims_refused += other.claims_refused;
        self.claims_clamped += other.claims_clamped;
        self.author_refused += other.author_refused;
        self.heals_stored += other.heals_stored;
        self.heals_refused += other.heals_refused;
        self.linear_deletions += other.linear_deletions;
    }
}

/// Runs a history on a fresh ADR 0021 server, checking properties 1–3 after every step (on a
/// fetch from nothing and one from `lag` behind the heads), 4 and 5 after every `worker` run,
/// and at the end that one more run leaves nothing to do.
fn run_history(steps: &[Step], lag: [u8; DEVICES]) -> Result<Stats, TestCaseError> {
    let mut server = Server::new(Rule::Adr0021);
    let mut backup = None;
    let mut stats = Stats::default();
    for step in steps {
        apply_step(&mut server, &mut backup, step, &mut stats)?;
        check_stored(&server)?;
        let behind = Shape::Behind(lag).covered(&server.heads());
        for cursor in [VersionVector::new(), behind] {
            let response = server.fetch(&cursor);
            check_response(&server, &response)?;
            let two = response.values().any(|part| {
                part.ops.iter().any(|&(dot, held)| {
                    !held
                        && distinct_authors(part.covers.iter().map(|c| (c.author, &c.clamped)), dot)
                            >= 2
                })
            });
            stats.two_author_responses += usize::from(two);
        }
    }
    apply_step(&mut server, &mut backup, &Step::Worker, &mut stats)?;
    prop_assert_eq!(
        server.worker(),
        (0, 0),
        "a second worker run changed something"
    );
    stats.nonlinear_runs = usize::from(!server.nonlinear.is_empty());
    Ok(stats)
}

/// Applies one step, checking each acceptance decision against §9's transcription. `backup` is
/// the operator's last backup of the database.
fn apply_step(
    server: &mut Server,
    backup: &mut Option<Server>,
    step: &Step,
    stats: &mut Stats,
) -> Result<(), TestCaseError> {
    match *step {
        Step::Write { device, item } => {
            server.write(device_id(device), item);
        }
        Step::Snapshot {
            author,
            item,
            shape,
        } => {
            let heads = server.heads();
            let author = device_id(author);
            let covered = shape.covered(&heads);
            let expected = literal_accepts(server, author, &covered, &heads);
            let result = server.upload_snapshot(item, author, covered);
            prop_assert_eq!(result.is_ok(), expected, "§9 acceptance: {:?}", result);
            match result {
                Err(SnapshotRefusal::ClaimsUnheldDots { .. }) => stats.claims_refused += 1,
                Err(_) => stats.author_refused += 1,
                Ok(_) => stats.claims_clamped += usize::from(server.newest_clamped_below()),
            }
        }
        Step::Heal {
            healer,
            chain,
            item,
            count,
            shape,
        } => {
            let snapshot_check = RefCell::new(None);
            let observer = server.clone();
            let result = server.heal(device_id(healer), device_id(chain), item, count, |heads| {
                let covered = shape.covered(heads);
                *snapshot_check.borrow_mut() = Some(literal_accepts(
                    &observer,
                    device_id(healer),
                    &covered,
                    heads,
                ));
                covered
            });
            match result {
                Ok(()) => {
                    stats.heals_stored += 1;
                    stats.heals_after_restore += usize::from(stats.restores > 0);
                    stats.claims_clamped += usize::from(server.newest_clamped_below());
                    prop_assert_eq!(*snapshot_check.borrow(), Some(true));
                }
                Err(HealRefusal::Snapshot(_)) => {
                    stats.heals_refused += 1;
                    prop_assert_eq!(*snapshot_check.borrow(), Some(false));
                }
                Err(HealRefusal::Uncovered(UncoveredHeader { dot })) => {
                    stats.heals_refused += 1;
                    prop_assert_eq!(*snapshot_check.borrow(), Some(true));
                    // Refused only if the fresh snapshot, clamped after the request's headers,
                    // does not cover the header.
                    let chain = device_id(chain);
                    let mut heads = observer.heads();
                    heads.add(Dot::new(chain, heads.get(chain) + u64::from(count)).unwrap());
                    prop_assert!(!vv_covers(&clamp(&shape.covered(&heads), &heads), dot));
                    prop_assert_eq!(dot.device_id(), chain);
                }
                Err(HealRefusal::PastCutoff) => stats.heals_refused += 1,
            }
        }
        Step::Worker => {
            let (deleted, dropped) = server.worker();
            stats.bodies_deleted += deleted;
            stats.snapshots_dropped += dropped;
            for item in 0..ITEMS {
                stats.older_kept += server.item_snaps(item).len().saturating_sub(2);
            }
            if deleted > 0 && server.nonlinear.is_empty() {
                stats.linear_deletions += 1;
            }
            check_after_worker(server)?;
        }
        Step::Revoke(device) => {
            // Phase 2 is accepted only if H is still the head (ADR 0012 §6).
            let device = device_id(device);
            let head = server.heads().get(device);
            server.cutoffs.entry(device).or_insert(head);
        }
        Step::Expire(device) => {
            server.expired.insert(device_id(device));
        }
        Step::Backup => *backup = Some(server.clone()),
        Step::Restore => {
            if let Some(dump) = backup {
                // The dump's rows, stored values kept. Its store counter is the restored
                // maximum, so the next op or snapshot stored lands above it (§2 "Store
                // sequence"). A certificate's expiry follows the clock, not the database.
                let expired = core::mem::take(&mut server.expired);
                *server = dump.clone();
                server.expired = expired;
                stats.restores += 1;
            }
        }
    }
    Ok(())
}

/// A generated covered-VV shape.
fn shape() -> impl Strategy<Value = Shape> {
    prop_oneof![
        4 => Just(Shape::Heads),
        3 => prop::array::uniform4(0u8..=3).prop_map(Shape::Behind),
        1 => (0..DEVICES, prop_oneof![Just(1u64), Just(2), Just(u64::MAX)])
            .prop_map(|(device, by)| Shape::Ahead { device, by }),
    ]
}

/// A generated step of any kind.
fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        24 => (0..DEVICES, 0..ITEMS).prop_map(|(device, item)| Step::Write { device, item }),
        16 => (0..DEVICES, 0..ITEMS, shape())
            .prop_map(|(author, item, shape)| Step::Snapshot { author, item, shape }),
        4 => (0..DEVICES, 0..DEVICES, 0..ITEMS, 1u8..=3, shape()).prop_map(
            |(healer, chain, item, count, shape)| Step::Heal { healer, chain, item, count, shape }
        ),
        12 => Just(Step::Worker),
        1 => (0..DEVICES).prop_map(Step::Revoke),
        1 => (0..DEVICES).prop_map(Step::Expire),
        2 => Just(Step::Backup),
        2 => Just(Step::Restore),
    ]
}

/// A generated step that keeps every item's history linear: every snapshot covers the heads.
/// A restore keeps it linear too: the heads it restores are at least the covered VV of the last
/// snapshot it restores, so the next snapshot, which covers the heads, is at least that.
fn linear_step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => (0..DEVICES, 0..ITEMS).prop_map(|(device, item)| Step::Write { device, item }),
        4 => (0..DEVICES, 0..ITEMS)
            .prop_map(|(author, item)| Step::Snapshot { author, item, shape: Shape::Heads }),
        1 => (0..DEVICES, 0..DEVICES, 0..ITEMS, 1u8..=3).prop_map(|(healer, chain, item, count)| {
            Step::Heal { healer, chain, item, count, shape: Shape::Heads }
        }),
        3 => Just(Step::Worker),
        1 => Just(Step::Backup),
        1 => Just(Step::Restore),
    ]
}

/// A history of up to 40 steps and the lag of the second fetch's cursor.
fn history(step: impl Strategy<Value = Step>) -> impl Strategy<Value = (Vec<Step>, [u8; DEVICES])> {
    (
        prop::collection::vec(step, 1..=40),
        prop::array::uniform4(0u8..=4),
    )
}

/// The ADR 0012 §12 budget: 1,000 cases per property on every PR.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// ADR 0021 §8 server properties 1–5 in generated histories.
    #[test]
    fn server_properties_hold((steps, lag) in history(step())) {
        run_history(&steps, lag)?;
    }

    /// Property 5 in linear histories, where it applies at every `worker` run.
    #[test]
    fn linear_histories_compact_as_adr_0012((steps, lag) in history(linear_step())) {
        let stats = run_history(&steps, lag)?;
        prop_assert_eq!(stats.nonlinear_runs, 0, "the linear generator made a non-linear history");
    }
}

/// A fixed-seed run of both generators that counts what the rules did, so that a generator
/// that stopped exercising a rule fails instead of passing vacuously.
#[test]
fn generated_histories_exercise_every_rule() {
    let totals = RefCell::new(Stats::default());
    for strategy in [history(step()).boxed(), history(linear_step()).boxed()] {
        let config = ProptestConfig {
            cases: 300,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let mut runner = TestRunner::new_with_rng(
            config.clone(),
            TestRng::deterministic_rng(config.rng_algorithm),
        );
        runner
            .run(&strategy, |(steps, lag)| {
                totals.borrow_mut().add(run_history(&steps, lag)?);
                Ok(())
            })
            .unwrap();
    }
    let t = totals.into_inner();
    assert!(t.bodies_deleted > 0, "{t:?}");
    assert!(t.snapshots_dropped > 0, "{t:?}");
    assert!(t.older_kept > 0, "{t:?}");
    assert!(t.two_author_responses > 0, "{t:?}");
    assert!(t.claims_refused > 0 && t.claims_clamped > 0, "{t:?}");
    assert!(t.author_refused > 0, "{t:?}");
    assert!(t.heals_stored > 0 && t.heals_refused > 0, "{t:?}");
    assert!(t.linear_deletions > 0, "{t:?}");
    assert!(t.nonlinear_runs > 0, "{t:?}");
    assert!(t.restores > 0 && t.heals_after_restore > 0, "{t:?}");
}

/// A device's side of the chain check after compaction (ADR 0012 §7): its cursor, and the
/// covered VVs of the snapshots it received. A bodiless header counts only if a snapshot of
/// its item, received now or held, covers it; anything else is missing data, and nothing past
/// it on that chain is applied.
#[derive(Default)]
struct Device {
    /// The highest `device_seq` applied per device.
    cursor: VersionVector,
    /// The (item, covered VV) of every snapshot received.
    snapshots: Vec<(u8, VersionVector)>,
    /// Dots applied from a body.
    bodies: BTreeSet<Dot>,
}

impl Device {
    /// Fetches from the server and applies the response. Returns the headers reported missing.
    fn sync(&mut self, server: &Server) -> Vec<Dot> {
        let response = server.fetch(&self.cursor);
        for (&item, part) in &response {
            self.snapshots
                .extend(part.covers.iter().map(|c| (item, c.covered.clone())));
        }
        let mut chains: Vec<(Dot, u8, bool)> = response
            .iter()
            .flat_map(|(&item, part)| part.ops.iter().map(move |&(dot, held)| (dot, item, held)))
            .collect();
        chains.sort_by_key(|&(dot, _, _)| dot);
        let mut missing = Vec::new();
        let mut blocked = BTreeSet::new();
        for (dot, item, held) in chains {
            if blocked.contains(&dot.device_id()) {
                continue;
            }
            let covered = self
                .snapshots
                .iter()
                .any(|(i, covered)| *i == item && vv_covers(covered, dot));
            if held || covered {
                self.cursor.add(dot);
                if held {
                    self.bodies.insert(dot);
                }
            } else {
                missing.push(dot);
                blocked.insert(dot.device_id());
            }
        }
        missing
    }
}

/// The item of the named scenarios.
const X: u8 = 0;

/// The VV of `(device, seq)` entries, zero entries left out.
fn vv_of(entries: &[(DeviceId, u64)]) -> VersionVector {
    entries
        .iter()
        .filter_map(|&(device, seq)| Dot::new(device, seq))
        .collect()
}

/// After an upload in a named scenario: `worker` if `run_worker`, the server properties
/// (ADR 0021 only), then a sync by the persistent device and one by a fresh device from an
/// empty cursor, a device that was behind. Returns the headers either reported missing.
fn observe(server: &mut Server, run_worker: bool, persistent: &mut Device) -> Vec<Dot> {
    if run_worker {
        server.worker();
    }
    if server.rule == Rule::Adr0021 {
        if run_worker {
            check_after_worker(server).unwrap();
        }
        check_stored(server).unwrap();
        check_response(server, &server.fetch(&VersionVector::new())).unwrap();
    }
    let mut missing = persistent.sync(server);
    missing.extend(Device::default().sync(server));
    missing
}

/// ADR 0021 Context and §5, "Concurrent purges": A creates X, B edits it, both purge it
/// concurrently (`P_A` = A2, `P_B` = B2) and upload tombstone snapshots `T_A` and `T_B`, in the given
/// order. A persistent device C and a fresh device sync after each upload, `worker` running
/// after each upload or only at the end. Returns every header reported missing, and the server.
fn concurrent_purges(rule: Rule, tb_first: bool, worker_each: bool) -> (Vec<Dot>, Server) {
    let (a, b) = (device_id(0), device_id(1));
    let mut server = Server::new(rule);
    let mut c = Device::default();
    let mut missing = Vec::new();
    for device in [a, b, a, b] {
        server.write(device, X).unwrap();
        missing.extend(observe(&mut server, worker_each, &mut c));
    }
    let t_a = vv_of(&[(a, 2), (b, 1)]);
    let t_b = vv_of(&[(a, 1), (b, 2)]);
    let uploads = if tb_first {
        [(b, t_b), (a, t_a)]
    } else {
        [(a, t_a), (b, t_b)]
    };
    for (author, covered) in uploads {
        server.upload_snapshot(X, author, covered).unwrap();
        missing.extend(observe(&mut server, worker_each, &mut c));
    }
    if !worker_each {
        missing.extend(observe(&mut server, true, &mut c));
    }
    (missing, server)
}

#[test]
fn concurrent_purges_report_no_gap() {
    let (a, b) = (device_id(0), device_id(1));
    let (p_a, p_b) = (Dot::new(a, 2).unwrap(), Dot::new(b, 2).unwrap());
    for tb_first in [false, true] {
        // ADR 0012's rule: the older tombstone's purge body goes, and the newest snapshot
        // served does not cover it, so a device that was behind reports a gap.
        let (missing, _) = concurrent_purges(Rule::Adr0012, tb_first, true);
        assert_eq!(missing, [if tb_first { p_b } else { p_a }]);

        for worker_each in [true, false] {
            let (missing, mut server) = concurrent_purges(Rule::Adr0021, tb_first, worker_each);
            assert!(missing.is_empty(), "{missing:?}");
            // Each purge is covered by its own author only, so both keep their bodies.
            assert!(server.ops[&p_a].held && server.ops[&p_b].held);
            // A and B each absorb the other's tombstone and write a merged snapshot covering
            // both purges: the purge bodies go, and R3 drops T_A and T_B.
            let both = vv_of(&[(a, 2), (b, 2)]);
            let merged_a = server.upload_snapshot(X, a, both.clone()).unwrap();
            let merged_b = server.upload_snapshot(X, b, both).unwrap();
            let mut c = Device::default();
            assert!(observe(&mut server, true, &mut c).is_empty());
            assert!(!server.ops[&p_a].held && !server.ops[&p_b].held);
            let retained: Vec<u64> = server.snaps.iter().map(|s| s.store_seq).collect();
            assert_eq!(retained, [merged_a, merged_b]);
            let response = server.fetch(&VersionVector::new());
            assert_eq!(response[&X].covers.len(), 2);
        }
    }
}

/// What the late-edits scenario leaves: the headers reported missing by the devices syncing
/// along the way and by the new device N at the end, L's late edits, what N applied from a
/// body, and the server.
struct LateEdits {
    /// Headers reported missing by the syncs after each upload.
    along_the_way: Vec<Dot>,
    /// Headers N reported missing.
    new_device: Vec<Dot>,
    /// L's 33 late edits.
    edits: Vec<Dot>,
    /// The dots N applied from a body.
    new_device_bodies: BTreeSet<Dot>,
    /// The server at the end.
    server: Server,
}

/// ADR 0021 Context and §5, "Late edits from a device that never returns": A and B edit X
/// and snapshot it; A trashes and purges it (A4, A5) and uploads the tombstone `T_1`; laptop L,
/// offline since before the trash, uploads 33 late edits and a live snapshot `S_L` that misses
/// the purge; two tombstone snapshots that miss the edits follow, `T_2` by B and `T_3` by A. L
/// never returns, and a new device N syncs from nothing.
fn late_edits(rule: Rule, worker_each: bool) -> LateEdits {
    let (a, b, l) = (device_id(0), device_id(1), device_id(2));
    let mut server = Server::new(rule);
    let mut watcher = Device::default();
    let mut along_the_way = Vec::new();
    for device in [a, a, a, b, b] {
        server.write(device, X).unwrap();
    }
    for author in [a, b] {
        server
            .upload_snapshot(X, author, vv_of(&[(a, 3), (b, 2)]))
            .unwrap();
        along_the_way.extend(observe(&mut server, worker_each, &mut watcher));
    }
    server.write(a, X).unwrap();
    server.write(a, X).unwrap();
    server
        .upload_snapshot(X, a, vv_of(&[(a, 5), (b, 2)]))
        .unwrap();
    along_the_way.extend(observe(&mut server, worker_each, &mut watcher));
    let edits: Vec<Dot> = (0..33).map(|_| server.write(l, X).unwrap()).collect();
    server
        .upload_snapshot(X, l, vv_of(&[(a, 3), (b, 2), (l, 33)]))
        .unwrap();
    along_the_way.extend(observe(&mut server, worker_each, &mut watcher));
    for author in [b, a] {
        server
            .upload_snapshot(X, author, vv_of(&[(a, 5), (b, 2)]))
            .unwrap();
        along_the_way.extend(observe(&mut server, worker_each, &mut watcher));
    }
    server.worker();
    if rule == Rule::Adr0021 {
        check_after_worker(&server).unwrap();
        check_stored(&server).unwrap();
    }
    let mut n = Device::default();
    let new_device = n.sync(&server);
    LateEdits {
        along_the_way,
        new_device,
        edits,
        new_device_bodies: n.bodies,
        server,
    }
}

#[test]
fn late_edits_keep_a_server_copy_when_their_device_never_returns() {
    // ADR 0012's rule: S_L becomes the older of the two newest, the edits' bodies go behind
    // it, T_3 pushes it out, and N finds no copy of the edits: it reports L's chain missing
    // from its first edit.
    let old = late_edits(Rule::Adr0012, true);
    assert_eq!(old.new_device, old.edits.get(..1).unwrap());

    let (a, b, l) = (device_id(0), device_id(1), device_id(2));
    for worker_each in [true, false] {
        let LateEdits {
            along_the_way,
            new_device,
            edits,
            new_device_bodies,
            mut server,
        } = late_edits(Rule::Adr0021, worker_each);
        assert!(along_the_way.is_empty() && new_device.is_empty());
        // Only L's snapshot covers the edits, so they keep their bodies, and N gets them.
        assert!(edits.iter().all(|dot| server.ops[dot].held));
        assert!(edits.iter().all(|dot| new_device_bodies.contains(dot)));
        // B, then A, apply the edits and snapshot the item: two authors cover the edits, the
        // bodies go, and R3 keeps covers by both.
        let all = vv_of(&[(a, 5), (b, 2), (l, 33)]);
        server.upload_snapshot(X, b, all.clone()).unwrap();
        server.upload_snapshot(X, a, all).unwrap();
        let mut n = Device::default();
        assert!(observe(&mut server, true, &mut n).is_empty());
        assert!(edits.iter().all(|dot| !server.ops[dot].held));
        let response = server.fetch(&VersionVector::new());
        for &dot in &edits {
            let authors: BTreeSet<DeviceId> = response[&X]
                .covers
                .iter()
                .filter(|c| vv_covers(&c.clamped, dot))
                .map(|c| c.author)
                .collect();
            assert_eq!(authors, BTreeSet::from([a, b]));
        }
    }
}
