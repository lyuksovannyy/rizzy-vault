//! The Server-mode server: ADR 0012 §7 upload rules and ADR 0021 §2-§4 (clamped VV, store
//! sequence, R1/R3 retention and deletion, Fetch covers), with the server rules the spike answers
//! propose as knobs (healing requests, refusal of unheld claims, two-author covers, the revoked
//! author's rules, the restore generation). It never looks inside a body.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use crate::config::{ServerRule, UploadDedup};
use crate::replica::Snapshot;
use crate::types::{Body, Dev, Dot, Header, KeyId, Op, Seq, VV};

#[derive(Clone, Debug)]
pub struct StoredOp {
    pub h: Header,
    /// None once R1 deleted the body, or when a healing request stored the header alone; the
    /// signed header stays for the life of the vault.
    pub b: Option<Body>,
    pub clock: u64,
}

#[derive(Clone, Debug)]
pub struct StoredSnap {
    /// ADR 0021 §2 "Store sequence".
    pub store_seq: u64,
    pub snap: Snapshot,
    /// ADR 0021 §2 "Clamped VV": min(covered, head), computed once when stored.
    pub clamped: VV,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpRes {
    Stored,
    AlreadyStored,
    Stale,
    PrevSeq(Seq),
    Conflict,
    Refused(&'static str),
}

/// One record of a healing request (answer 2; ADR 0012 §7 "Healing a server rollback" step 4,
/// "Who may upload").
#[derive(Clone, Debug)]
pub enum HealRec {
    /// A signed op header with its two hashes and signature, and its body when the healer sends
    /// it. Without a body it is stored as a bodiless header (ADR 0021 §2), which the request's
    /// snapshots must cover.
    Op(Header, Option<Body>),
    /// A fresh snapshot, or a held snapshot re-published verbatim.
    Snap(Snapshot),
    /// An `ITEM_KEY_WRAP` the healer holds (healing step 3). A header sent without its body no
    /// longer carries the wrap its body carried, so the wrap goes as a wrap-set row.
    Wrap(KeyId),
}

/// A Fetch response (ADR 0012 §7 "Fetch" with ADR 0021 §4).
#[derive(Clone, Debug)]
pub struct Response {
    pub chains: BTreeMap<Dev, Vec<(Header, Option<Body>)>>,
    pub covers: Vec<Snapshot>,
    pub wraps: BTreeSet<KeyId>,
    /// The server's restore generation (answer 3's condition, `StaleSent::RepublishGen`).
    pub restore_gen: u64,
}

#[derive(Clone, Debug)]
pub struct Server {
    /// Keyed by (device_id, device_seq): per-device chain order (ADR 0012 §7).
    pub ops: BTreeMap<Dot, StoredOp>,
    pub snaps: Vec<StoredSnap>,
    pub clock: u64,
    /// Current vault_key_epoch (from the signed account-state).
    pub epoch: u32,
    pub state_seq: u64,
    /// The wrap set rows (CRYPTO.md §4.2), by key id.
    pub wraps: BTreeSet<KeyId>,
    pub suspended: BTreeSet<Dev>,
    pub revocations: BTreeMap<Dev, Seq>,
    /// Answer 3's condition (not in any ADR): a counter the server raises on every restore from a
    /// backup, above any value the restored database held (like ADR 0021 §2's store sequence).
    pub restore_gen: u64,
    /// ADR 0021 §3 "Linear histories" (the condition of §8 property 5): every stored snapshot's
    /// covered VV is >= that of the one stored before it. Tracked over every snapshot this
    /// database stored, dropped ones included; a restore takes the checkpoint's value, so the
    /// snapshots lost with the restored-away state do not count (which checks property 5 in more
    /// histories than counting them would).
    pub linear: bool,
    pub last_covered: Option<VV>,
    /// ADR 0021 §8 server-property violations and integrity errors (deduplicated).
    pub violations: Vec<String>,
    /// Coverage counters (evidence that the explored schedules exercise the rules).
    pub stats: Stats,
    // Rule knobs (from `Config`, set by `World::new`).
    pub rule: ServerRule,
    pub dedup: UploadDedup,
    /// Answer 2 (`SnapClaims::RefuseUnheld*`).
    pub refuse_unheld_claims: bool,
    /// The resolution of answers 2 and 5: a revoked device's claimed entry counts only up to its
    /// cut-off (false for `SnapClaims::RefuseUnheldStrict`).
    pub claims_cap_at_cutoff: bool,
    /// Answer 5 (`Config::snap_author_head`).
    pub author_head: bool,
    /// Answer 5 (`Config::stale_exempt_revoked`).
    pub stale_exempt_revoked: bool,
    /// Headers a healing request stored without a body (never deleted by R1): ADR 0021 §8
    /// property 5 names them apart from R1's deletions, and the two-author property counts them
    /// apart.
    pub stored_bodiless: BTreeSet<Dot>,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub bodies_deleted: u64,
    pub snapshots_dropped: u64,
    pub bodiless_served: u64,
    pub multi_cover_responses: u64,
    /// Healing requests stored / refused, bodiless headers they stored, ops stored with a body,
    /// held snapshots re-published verbatim, and records stored although below the current epoch.
    pub heal_requests: u64,
    pub heal_refused: u64,
    pub heal_bodiless: u64,
    pub heal_with_body: u64,
    pub heal_verbatim_snaps: u64,
    pub heal_stale_exempted: u64,
    /// Snapshots refused for claiming dots above the heads, and stored although they do.
    pub claims_refused: u64,
    pub unheld_claims_stored: u64,
    /// Snapshots refused by the author-head rule alone (answer 5, without `RefuseUnheld`).
    pub snaps_refused_author_head: u64,
    /// Bodiless headers of a revoked device served after its revocation, covers by a revoked
    /// author served, and revoked authors' stale ops accepted by the answer-5 exemption.
    pub revoked_bodiless_served: u64,
    pub revoked_author_covers_served: u64,
    pub revoked_stale_exempted: u64,
    /// ADR 0021 §8 properties 4 and 5 in their two-author form (`check_two_author_props`):
    /// retained snapshots outside the two newest checked against property 4; `worker` runs in a
    /// linear history checked against property 5, those where R1 deletes some body, and those
    /// where the older of the two newest covers a body that keeps it for want of a second author.
    pub p4_two_author_checked: u64,
    pub p5_two_author_checked: u64,
    pub p5_two_author_r1: u64,
    pub p5_two_author_one_author_kept: u64,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            ops: BTreeMap::new(),
            snaps: Vec::new(),
            clock: 0,
            epoch: 0,
            state_seq: 0,
            wraps: BTreeSet::new(),
            suspended: BTreeSet::new(),
            revocations: BTreeMap::new(),
            restore_gen: 0,
            linear: true,
            last_covered: None,
            violations: Vec::new(),
            stats: Stats::default(),
            rule: ServerRule::Adr0021,
            dedup: UploadDedup::First,
            refuse_unheld_claims: false,
            claims_cap_at_cutoff: true,
            author_head: false,
            stale_exempt_revoked: false,
            stored_bodiless: BTreeSet::new(),
        }
    }
}

/// Distinct authors among `snaps` whose clamped VV covers `dot` (ADR 0021 §2 "Covers").
fn cover_authors<'a>(snaps: impl Iterator<Item = &'a StoredSnap>, dot: Dot) -> BTreeSet<Dev> {
    snaps
        .filter(|s| s.clamped.covers(dot))
        .map(|s| s.snap.author)
        .collect()
}

impl Server {
    /// ADR 0021 §2 "Head" h(V, d).
    pub fn head(&self, d: Dev) -> Seq {
        self.ops
            .range(Dot::new(d, 0)..=Dot::new(d, u64::MAX))
            .next_back()
            .map(|(k, _)| k.seq)
            .unwrap_or(0)
    }

    fn violation(&mut self, s: String) {
        if !self.violations.contains(&s) {
            self.violations.push(s);
        }
    }

    /// ADR 0012 §7 "Upload" for an op record.
    pub fn upload_op(&mut self, op: &Op, uploader: Dev) -> UpRes {
        self.store_op(&op.h, Some(&op.b), uploader, true)
    }

    /// ADR 0012 §7 "Upload" checks for one signed op record, with or without its body.
    /// `check_stale`: the stale-epoch check. It never applies to a bodiless header (it carries no
    /// ciphertext), and a healing request skips it for a record re-published verbatim (answer 2).
    fn store_op(
        &mut self,
        h: &Header,
        body: Option<&Body>,
        uploader: Dev,
        check_stale: bool,
    ) -> UpRes {
        let d = h.dot.dev;
        // The certificate must be unrevoked, or revoked with device_seq <= last_accepted.
        if let Some(&cut) = self.revocations.get(&d)
            && h.dot.seq > cut
        {
            return UpRes::Refused("revoked author past cut-off");
        }
        // ADR 0012 §6 phase 1: the server rejects the suspended device's uploads, and keeps H the
        // head it holds from that device.
        if self.suspended.contains(&uploader) && !self.revocations.contains_key(&uploader) {
            return UpRes::Refused("uploader suspended");
        }
        if self.revocations.contains_key(&uploader) {
            return UpRes::Refused("uploader revoked");
        }
        if self.suspended.contains(&d)
            && h.dot.seq > self.head(d)
            && !self.revocations.contains_key(&d)
        {
            return UpRes::Refused("author suspended");
        }
        // AMBIGUOUS 11 (`UploadDedup::First`): a byte-identical re-upload of a stored record (a
        // lost response) is answered "already stored" before the vault_prev_seq and stale-epoch
        // checks; read literally (`None`) the vault_prev_seq check rejects it. A bodiless header
        // is the same record when its signed header (with both hashes) is the same.
        if self.dedup == UploadDedup::First
            && let Some(so) = self.ops.get(&h.dot)
        {
            let same = so.h == *h
                && match (&so.b, body) {
                    (Some(x), Some(y)) => x == y,
                    _ => true,
                };
            return if same {
                UpRes::AlreadyStored
            } else {
                UpRes::Conflict
            };
        }
        // "It rejects an op whose vault_prev_seq is not the last op it holds from that device".
        let head = self.head(d);
        if h.prev != head {
            return UpRes::PrevSeq(head);
        }
        // "rejects an op or snapshot whose vault_key_epoch is below the vault's current epoch".
        // Answer 5: not for a revoked author's op at or below its cut-off (checked above), which
        // only its revoked author could re-issue.
        let revoked_exempt = self.stale_exempt_revoked && self.revocations.contains_key(&d);
        if check_stale && body.is_some() && h.epoch < self.epoch {
            if !revoked_exempt {
                return UpRes::Stale;
            }
            self.stats.revoked_stale_exempted += 1;
        }
        self.clock += 1;
        if let Some(w) = body.and_then(|b| b.wrap) {
            self.wraps.insert(w);
        }
        self.ops.insert(
            h.dot,
            StoredOp {
                h: h.clone(),
                b: body.cloned(),
                clock: self.clock,
            },
        );
        UpRes::Stored
    }

    /// Answer 2: one healing request, applied atomically under the account lock. Headers go
    /// first, in chain order per device, then the snapshots, so that the clamped VVs (ADR 0021 §2)
    /// cover the re-published headers. Every header stored without a body must then have a
    /// retained cover (ADR 0021 owner rule 3 / server property 1), or the whole request is refused.
    /// Returns the index and answer of the first refused record, or the dots of ops stored with a
    /// body below the current epoch (for the KEY check).
    pub fn heal_request(
        &mut self,
        recs: &[HealRec],
        uploader: Dev,
        stale_exempt: bool,
    ) -> Result<Vec<Dot>, (usize, UpRes)> {
        let backup = self.clone();
        let mut bodiless: Vec<Dot> = Vec::new();
        let mut stale_bodies: Vec<Dot> = Vec::new();
        let (mut with_body, mut exempted) = (0u64, 0u64);
        let refuse = |me: &mut Server, i: usize, r: UpRes| {
            let stats = std::mem::take(&mut me.stats);
            *me = backup.clone();
            me.stats = stats;
            me.stats.heal_refused += 1;
            Err((i, r))
        };
        for (i, r) in recs.iter().enumerate() {
            let res = match r {
                HealRec::Op(h, b) => {
                    let stale = b.is_some() && h.epoch < self.epoch;
                    let res = self.store_op(h, b.as_ref(), uploader, !stale_exempt);
                    if res == UpRes::Stored {
                        if b.is_none() {
                            bodiless.push(h.dot);
                        } else {
                            with_body += 1;
                            exempted += stale as u64;
                            if stale {
                                stale_bodies.push(h.dot);
                            }
                        }
                    }
                    res
                }
                HealRec::Wrap(k) => {
                    self.wraps.insert(*k);
                    UpRes::Stored
                }
                HealRec::Snap(sn) => {
                    let stale = sn.epoch < self.epoch;
                    let res = self.store_snap(sn, uploader, !stale_exempt);
                    if res == UpRes::Stored {
                        exempted += stale as u64;
                    }
                    res
                }
            };
            match res {
                UpRes::Stored | UpRes::AlreadyStored => {}
                other => return refuse(self, i, other),
            }
        }
        let uncovered = bodiless
            .iter()
            .any(|dot| !self.snaps.iter().any(|s| s.clamped.covers(*dot)));
        if uncovered {
            return refuse(
                self,
                recs.len(),
                UpRes::Refused("a bodiless header without a cover in the request"),
            );
        }
        self.stats.heal_requests += 1;
        self.stats.heal_bodiless += bodiless.len() as u64;
        self.stats.heal_with_body += with_body;
        self.stats.heal_stale_exempted += exempted;
        self.stored_bodiless.extend(bodiless.iter().copied());
        Ok(stale_bodies)
    }

    /// ADR 0012 §7 "Upload" for a snapshot record, with ADR 0021 §2 clamped VV and store sequence.
    pub fn upload_snap(&mut self, s: &Snapshot, uploader: Dev) -> UpRes {
        self.store_snap(s, uploader, true)
    }

    fn store_snap(&mut self, s: &Snapshot, uploader: Dev, check_stale: bool) -> UpRes {
        if self.revocations.contains_key(&uploader) || self.suspended.contains(&uploader) {
            return UpRes::Refused("uploader suspended or revoked");
        }
        // AMBIGUOUS 14: ADR 0021 open question 5 (open), recommendation taken (answer 5 keeps it):
        // the server refuses new snapshots after revocation and keeps counting retained ones.
        if self.revocations.contains_key(&s.author) {
            return UpRes::Refused("author revoked");
        }
        // AMBIGUOUS 11: re-uploads are deduplicated by snapshot_id (literal `None`: stored again).
        if self.dedup == UploadDedup::First && self.snaps.iter().any(|x| x.snap.id == s.id) {
            return UpRes::AlreadyStored;
        }
        if check_stale && s.epoch < self.epoch {
            return UpRes::Stale;
        }
        // ADR 0021 §5: "Snapshots that claim dots the server does not hold ... are stored."
        // Answer 2 (`SnapClaims::RefuseUnheld`): refused instead; a healing request stores the
        // claimed headers before its snapshots, so its snapshots pass.
        // Resolution of answers 2 and 5 (README Results): a revoked device's entry counts only up
        // to its `last_accepted_device_seq`. The server never holds that device's ops past the
        // cut-off, so no healing request can make such a claim "held"; refusing it would block a
        // healer whose state holds such an op (a revocation signed on a restored server, the
        // ADR 0012 §6 path) and keep it read-only for good. The clamped VV cuts it either way.
        let claims_unheld = s.state.vv().0.iter().any(|(&d, &c)| {
            let c = match self.revocations.get(&d) {
                Some(&cut) if self.claims_cap_at_cutoff => c.min(cut),
                _ => c,
            };
            c > self.head(d)
        });
        if claims_unheld {
            if self.refuse_unheld_claims {
                self.stats.claims_refused += 1;
                return UpRes::Refused("snapshot claims dots the server does not hold");
            }
            // Answer 5: a snapshot may claim dots the server does not hold (ADR 0021 §5), but not
            // its own author's. Every retained snapshot then has covered[author] <= the author's
            // head when stored, which is <= H if the author is later revoked (ADR 0012 §6).
            if self.author_head && s.state.vv().get(s.author) > self.head(s.author) {
                self.stats.snaps_refused_author_head += 1;
                return UpRes::Refused(
                    "snapshot claims its author's dots the server does not hold",
                );
            }
            self.stats.unheld_claims_stored += 1;
        }
        let clamped = s.state.vv().meet(&self.heads_vv());
        self.clock += 1;
        if let Some(w) = s.wrap {
            self.wraps.insert(w);
        }
        if let Some(prev) = &self.last_covered
            && !prev.leq(s.state.vv())
        {
            self.linear = false;
        }
        self.last_covered = Some(s.state.vv().clone());
        self.snaps.push(StoredSnap {
            store_seq: self.clock,
            snap: s.clone(),
            clamped,
        });
        UpRes::Stored
    }

    /// Every device's head, as a VV.
    pub fn heads_vv(&self) -> VV {
        let mut v = VV::default();
        for d in self.ops.keys() {
            v.add(*d);
        }
        v
    }

    /// ADR 0021 §3, `worker`: R1 then R3, recomputed from the current state.
    pub fn compact(&mut self) {
        if self.rule == ServerRule::None {
            // The "without server compaction" case: nothing is deleted or dropped.
            self.check_props(true);
            return;
        }
        let two = self.rule == ServerRule::TwoAuthors;
        self.snaps.sort_by_key(|s| s.store_seq);
        let n = self.snaps.len();
        // R1: delete a body when, and only when, the older of the two newest retained snapshots
        // covers the op. Fewer than two: delete nothing.
        // Answer 4 (TwoAuthors): and retained snapshots by two different authors cover it.
        if n >= 2 {
            let older = self.snaps[n - 2].clamped.clone();
            let snaps = &self.snaps;
            for (dot, so) in self.ops.iter_mut() {
                if so.b.is_some()
                    && older.covers(*dot)
                    && (!two || cover_authors(snaps.iter(), *dot).len() >= 2)
                {
                    so.b = None;
                    self.stats.bodies_deleted += 1;
                }
            }
        }
        // R3: the two newest are always retained; an older one stays while it is the only
        // retained cover of some bodiless header (TwoAuthors: while dropping it would leave some
        // bodiless header covered by fewer than two authors); every other older one is dropped,
        // tested oldest first and re-tested after each drop.
        loop {
            let n = self.snaps.len();
            if n <= 2 {
                break;
            }
            let drop_idx = (0..n - 2).find(|&i| !self.needed(i));
            match drop_idx {
                Some(i) => {
                    self.snaps.remove(i);
                    self.stats.snapshots_dropped += 1;
                }
                None => break,
            }
        }
        self.check_props(true);
    }

    /// Is retained snapshot `i` still needed as a cover (R3, or its TwoAuthors variant)?
    fn needed(&self, i: usize) -> bool {
        let two = self.rule == ServerRule::TwoAuthors;
        self.ops.iter().any(|(dot, so)| {
            if so.b.is_some() || !self.snaps[i].clamped.covers(*dot) {
                return false;
            }
            let others = self
                .snaps
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, t)| t);
            if two {
                let with = cover_authors(self.snaps.iter(), *dot);
                let without = cover_authors(others, *dot);
                without.is_empty() || (without.len() < 2 && without.len() < with.len())
            } else {
                !others.into_iter().any(|t| t.clamped.covers(*dot))
            }
        })
    }

    /// ADR 0012 §7 "Fetch" with ADR 0021 §4 covers.
    pub fn fetch(&mut self, cursor: &VV, me: Dev) -> Response {
        let mut chains: BTreeMap<Dev, Vec<(Header, Option<Body>)>> = BTreeMap::new();
        let mut bodiless = Vec::new();
        for (dot, so) in &self.ops {
            // AMBIGUOUS 13: the cursor is "the highest device_seq it has per device"; a device has
            // every op it wrote, so its own chain is never served back to it.
            if dot.dev == me || dot.seq <= cursor.get(dot.dev) {
                continue;
            }
            chains
                .entry(dot.dev)
                .or_default()
                .push((so.h.clone(), so.b.clone()));
            if so.b.is_none() {
                bodiless.push(*dot);
            }
        }
        let mut order: Vec<&StoredSnap> = self.snaps.iter().collect();
        order.sort_by_key(|s| Reverse(s.store_seq));
        let mut uncovered = bodiless.clone();
        let mut covers: Vec<Snapshot> = Vec::new();
        if self.rule == ServerRule::TwoAuthors {
            // Answer 4: newest first, add each snapshot that covers a bodiless header of the
            // response not yet covered by two authors among the added ones.
            let mut authors: BTreeMap<Dot, BTreeSet<Dev>> = BTreeMap::new();
            for s in order {
                let adds = bodiless.iter().any(|d| {
                    s.clamped.covers(*d)
                        && authors
                            .get(d)
                            .is_none_or(|a| a.len() < 2 && !a.contains(&s.snap.author))
                });
                if adds {
                    covers.push(s.snap.clone());
                    for d in &bodiless {
                        if s.clamped.covers(*d) {
                            authors.entry(*d).or_default().insert(s.snap.author);
                        }
                    }
                }
            }
            uncovered.retain(|d| !authors.contains_key(d));
        } else {
            for s in order {
                if uncovered.is_empty() {
                    break;
                }
                if uncovered.iter().any(|d| s.clamped.covers(*d)) {
                    covers.push(s.snap.clone());
                    uncovered.retain(|d| !s.clamped.covers(*d));
                }
            }
        }
        if !uncovered.is_empty() {
            // ADR 0021 §4: "A bodiless header without a retained cover means a bug or a damaged
            // database"; server property 3.
            self.violation("SRV-3 response holds a bodiless header without a cover".to_string());
        }
        self.stats.bodiless_served += bodiless.len() as u64;
        self.stats.revoked_bodiless_served += bodiless
            .iter()
            .filter(|d| self.revocations.contains_key(&d.dev))
            .count() as u64;
        self.stats.revoked_author_covers_served += covers
            .iter()
            .filter(|c| self.revocations.contains_key(&c.author))
            .count() as u64;
        if covers.len() > 1 {
            self.stats.multi_cover_responses += 1;
        }
        Response {
            chains,
            covers,
            wraps: self.wraps.clone(),
            restore_gen: self.restore_gen,
        }
    }

    /// ADR 0021 §8 server properties 1, 2 and (after `worker`) 4 and 5, with 4 and 5 in their
    /// two-author form (`check_two_author_props`) and a two-author property 6 under
    /// `ServerRule::TwoAuthors`. Property 3 is checked in `fetch`.
    pub fn check_props(&mut self, after_worker: bool) {
        let mut found = Vec::new();
        for (dot, so) in &self.ops {
            if so.b.is_none() && !self.snaps.iter().any(|s| s.clamped.covers(*dot)) {
                found.push("SRV-1 bodiless header without a retained cover".to_string());
            }
            for s in &self.snaps {
                if so.clock > s.store_seq && s.clamped.covers(*dot) {
                    found.push("SRV-2 a snapshot covers an op stored after it".to_string());
                }
            }
        }
        if self.rule == ServerRule::TwoAuthors {
            for (dot, so) in &self.ops {
                if so.b.is_none() && cover_authors(self.snaps.iter(), *dot).len() < 2 {
                    // A header a healing request stored without its body has, in general, only
                    // the healer's fresh snapshot as cover (answers 2 and 4 interact here).
                    if self.stored_bodiless.contains(dot) {
                        found.push(
                            "SRV-6 (TwoAuthors) a header a healing request stored bodiless has covers by fewer than two authors"
                                .to_string(),
                        );
                    } else {
                        found.push(
                            "SRV-6 (TwoAuthors) bodiless header without covers by two authors"
                                .to_string(),
                        );
                    }
                }
            }
        }
        if after_worker && self.rule == ServerRule::None {
            if self.ops.values().any(|o| o.b.is_none()) && self.stored_bodiless.is_empty() {
                found.push("SRV-none a body was deleted without compaction".to_string());
            }
        } else if after_worker {
            let mut ordered: Vec<&StoredSnap> = self.snaps.iter().collect();
            ordered.sort_by_key(|s| s.store_seq);
            let n = ordered.len();
            // Property 5: "in a linear history, the state after worker runs is ADR 0012's: the two
            // newest retained, and the bodies the older covers deleted."
            if self.linear && self.rule == ServerRule::Adr0021 {
                if n > 2 {
                    found.push("SRV-5 linear history keeps more than two snapshots".to_string());
                }
                let older = (n >= 2).then(|| ordered[n - 2].clamped.clone());
                for (dot, so) in &self.ops {
                    let covered = older.as_ref().is_some_and(|v| v.covers(*dot));
                    // Answer 2: a header a healing request stored without its body was never
                    // deleted by R1; property 5 reads "the bodies the older covers deleted, and
                    // the headers re-published without a body still without one".
                    if !covered && so.b.is_none() && self.stored_bodiless.contains(dot) {
                        continue;
                    }
                    if covered != so.b.is_none() {
                        found.push(
                            "SRV-5 linear history: bodies deleted are not exactly those the older of the two newest covers"
                                .to_string(),
                        );
                    }
                }
            }
            if self.rule == ServerRule::Adr0021 {
                for i in 0..n.saturating_sub(2) {
                    let s = ordered[i];
                    let sole = self.ops.iter().any(|(dot, so)| {
                        so.b.is_none()
                            && s.clamped.covers(*dot)
                            && !ordered
                                .iter()
                                .enumerate()
                                .any(|(j, t)| j != i && t.clamped.covers(*dot))
                    });
                    if !sole {
                        found.push(
                            "SRV-4 an older retained snapshot is not a sole cover".to_string(),
                        );
                    }
                }
            } else {
                self.check_two_author_props(&mut found);
            }
        }
        for f in found {
            self.violation(f);
        }
    }

    /// ADR 0021 §8 properties 4 and 5 in their two-author form, after `worker` runs under
    /// `ServerRule::TwoAuthors`, with §3 R1 and R3 as revised by owner decision 1. Computed from
    /// the rule texts alone, never through `compact`, `needed` or `cover_authors`, so that a slip
    /// in the worker cannot hide itself. "Covers" is §2's: the snapshot's clamped VV covers the
    /// dot; an author is the device that signed the snapshot.
    ///
    /// - Property 4, "after `worker` runs, R3 keeps every retained snapshot outside the two
    ///   newest". R3: "An older snapshot stays while dropping it would lower the number of authors
    ///   that cover some bodiless header to fewer than two."
    /// - Property 5, "in a linear history, after `worker` runs, the bodiless headers are those R1
    ///   deletes behind the older of the two newest, and the headers a healing request stored
    ///   without a body". R1: "the older of the item's two newest retained snapshots covers the op
    ///   and retained snapshots by two different authors cover it. With fewer than two retained
    ///   snapshots it deletes nothing." "Linear" is `Server::linear` (§3 "Linear histories").
    fn check_two_author_props(&mut self, found: &mut Vec<String>) {
        let mut ordered: Vec<&StoredSnap> = self.snaps.iter().collect();
        ordered.sort_by_key(|s| s.store_seq);
        let n = ordered.len();
        // The number of distinct authors among the retained snapshots, the one at `skip` left
        // out, that cover `dot`.
        let authors = |dot: Dot, skip: Option<usize>| -> usize {
            ordered
                .iter()
                .enumerate()
                .filter(|(j, s)| Some(*j) != skip && s.clamped.covers(dot))
                .map(|(_, s)| s.snap.author)
                .collect::<BTreeSet<Dev>>()
                .len()
        };
        for (i, s) in ordered.iter().enumerate().take(n.saturating_sub(2)) {
            self.stats.p4_two_author_checked += 1;
            let stays = self.ops.iter().any(|(dot, so)| {
                if so.b.is_some() || !s.clamped.covers(*dot) {
                    return false;
                }
                let without = authors(*dot, Some(i));
                without < 2 && without < authors(*dot, None)
            });
            if !stays {
                found.push(
                    "SRV-4 (TwoAuthors) an older retained snapshot is one R3 drops".to_string(),
                );
            }
        }
        if !self.linear {
            return;
        }
        self.stats.p5_two_author_checked += 1;
        let older = n.checked_sub(2).map(|i| &ordered[i].clamped);
        let (mut r1_any, mut one_author_kept) = (false, false);
        for (dot, so) in &self.ops {
            let older_covers = older.is_some_and(|v| v.covers(*dot));
            let two = authors(*dot, None) >= 2;
            let r1 = older_covers && two;
            r1_any |= r1;
            one_author_kept |= older_covers && !two && so.b.is_some();
            let healed = self.stored_bodiless.contains(dot);
            if (r1 || healed) && so.b.is_some() {
                found.push(
                    "SRV-5 (TwoAuthors) linear history: an op R1 deletes, or a healing request stored bodiless, has a body"
                        .to_string(),
                );
            }
            if !r1 && !healed && so.b.is_none() {
                found.push(
                    "SRV-5 (TwoAuthors) linear history: a bodiless header R1 does not delete and no healing request stored"
                        .to_string(),
                );
            }
        }
        self.stats.p5_two_author_r1 += r1_any as u64;
        self.stats.p5_two_author_one_author_kept += one_author_kept as u64;
    }
}
