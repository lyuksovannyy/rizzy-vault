//! A client device: HLC, per-vault device seq, causal delivery, authoring, snapshots, absorption,
//! re-issue after a stale-epoch rejection, Fetch processing with the chain check, the ADR 0012 §6
//! recomputation, and the answers' client rules (evidence merge, merged snapshot, kept headers).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::absorb::{AbsorbCtx, AbsorbOutcome, join_items};
use crate::config::{
    Config, MergedSnap, PastCutoff, ReissueLocal, ReissueScope, RevokedSnap, StaleSent,
};
use crate::item::{Item, Shown, accounts_for, em_join, max_hlc, restrict, singleton};
use crate::rng::XorShift;
use crate::server::Response;
use crate::types::{
    Body, Dev, Dot, Entry, Header, Headers, Hlc, Key, KeyId, LIFECYCLE, Marker, Op, Seq, VV, Val,
    header_heads,
};

/// One served chain link: a signed op header and its body, if the server still holds it.
type Link = (Header, Option<Body>);

/// ADR 0012 §2 "Skew guard": 24 h.
pub const SKEW_MS: u64 = 24 * 3600 * 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Active,
    Revoked,
    /// Gone for good (a lost device); excluded from P1, its stored ops still count for P2.
    Lost,
}

/// Local, user-visible reports. They change no state bytes. P2 counts a value as not silent when
/// the device reported the data missing (Gap, Rejected, a pending op, a Dispute, a ClaimCut).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Notice {
    /// ADR 0012 §7 chain check / INV-27: missing data from `dev` at `seq`; nothing past it applied.
    Gap {
        dev: Dev,
        seq: Seq,
    },
    Rejected {
        dot: Dot,
        why: &'static str,
    },
    SnapRejected {
        why: &'static str,
    },
    SnapIgnored {
        why: &'static str,
    },
    /// The server refused one of this device's snapshots for what it claims (answer 2's unheld
    /// claims, answer 5's author head); the device dropped it.
    SnapRefused {
        why: &'static str,
    },
    ReadOnly,
    UploadBlocked {
        dot: Dot,
        why: &'static str,
    },
    UploadConflict {
        dot: Dot,
    },
    HealBlocked {
        dot: Dot,
        why: &'static str,
    },
    /// INV-25: the item VV went below the highest VV this device accepted.
    VvBackwards {
        old: VV,
        new: VV,
    },
    ClockAhead,
    /// ADR 0012 §6: the replica holds ops of a revoked device past its cut-off and could not
    /// recompute without them (item flagged).
    PastCutoff {
        dev: Dev,
        cut: Seq,
    },
    /// Answer 4 (evidence merge): a snapshot by `author` and this replica's other sources disagree
    /// about the value at `dot` (one of them omits or fabricates it). Reported, never decided.
    Dispute {
        dot: Dot,
        author: Dev,
    },
    /// Answer 4 (evidence merge): a snapshot by `author` claims `dev`'s seqs `from+1..=to`, for
    /// which this replica holds no verified op header; not taken, reported.
    ClaimCut {
        dev: Dev,
        from: Seq,
        to: Seq,
        author: Dev,
    },
}

/// A dishonest but verifying snapshot (ADR 0018 "Settled by the merge spike" item 4; ADR 0021
/// "Faulty-client snapshots: one that verifies but omits a value, or claims dots nobody holds").
/// Every kind is built to pass the ADR 0018 §5 parse rules (`Item::validate_snapshot`), as a
/// "verified but dishonest" snapshot must; the ones marked §5 produce a state ADR 0018 §5 lists
/// as accepted although "no honest merge produces" it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// Omission: drop the highest-ranked non-lifecycle current (or late) value; keep the VV.
    OmitValue,
    /// Omission: drop the highest-ranked history entry; keep the VV.
    OmitHist,
    /// Claim: raise the covered VV to the next dot of a device beyond what the author holds.
    ClaimNext(Dev),
    /// Claim with content: claim the next dot of a device and put a fabricated value at it on
    /// key `a`, superseding the current values of `a` (moved to history, as an honest write would).
    ClaimValue(Dev),
    /// §5 "one dot with different HLCs under different keys": copy the highest-ranked current
    /// non-lifecycle value to key `z` with HLC + 1.
    AltHlc,
    /// A fabricated write at an existing dot: copy the highest-ranked current non-lifecycle value to
    /// key `z` with the same HLC (nothing in the record or its header shows it).
    AltKey,
    /// §5 "several current values from one device_id in one register": put the highest-ranked
    /// history entry back into its register as a current value.
    Resurrect,
    /// §5 "a purge_dot that c covers": present a live item as a tombstone whose recorded purge is
    /// the highest-ranked current value's dot (a write, not a Purge), with c = covered VV.
    FakeTomb,
    /// A live snapshot of a purged item: `@lifecycle` = Active at `purge_dot`, the late values as
    /// registers (a live state that covers a Purge, which no honest merge produces).
    FakeLive,
    /// §5 "an item_key_id that names no key the reader holds".
    WrongKey,
    /// Widen the tombstone's c to the covered VV (drops every late value, rule 8; §5 "a purge_dot
    /// that c covers").
    WidenC,
    /// §5 "a late value whose dot is purge_dot" (a Purge writes nothing).
    LateAtPurge,
    /// `FakeTomb` built to pass every header check: c = the context of the write it presents as a
    /// purge, late values = the current values c does not cover, the write's own values omitted.
    FakeTombSmart,
    /// `WidenC` built to pass every header check: c joined with the context of a later write
    /// whose context covers a late value, so c looks like a purge the author applied.
    WidenCSmart,
}

pub const ALL_FAULTS: &[Fault] = &[
    Fault::FakeTombSmart,
    Fault::WidenCSmart,
    Fault::OmitValue,
    Fault::OmitHist,
    Fault::ClaimNext(0),
    Fault::ClaimValue(0),
    Fault::AltHlc,
    Fault::AltKey,
    Fault::Resurrect,
    Fault::FakeTomb,
    Fault::FakeLive,
    Fault::WrongKey,
    Fault::WidenC,
    Fault::LateAtPurge,
];

impl Fault {
    /// Fault class, for grouping results.
    pub fn class(self) -> &'static str {
        match self {
            Fault::OmitValue | Fault::OmitHist | Fault::WidenC => "omission",
            Fault::ClaimNext(_) | Fault::ClaimValue(_) => "claim",
            Fault::AltHlc | Fault::Resurrect | Fault::LateAtPurge => {
                "header-detectable fabrication"
            }
            Fault::FakeTomb | Fault::FakeLive => "body-detectable fabrication",
            Fault::AltKey | Fault::WrongKey | Fault::FakeTombSmart | Fault::WidenCSmart => {
                "undetectable fabrication"
            }
        }
    }
}

/// ADR 0012 §3 snapshot header + ADR 0018 §3 snapshot data. The covered VV is `state.vv()`.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub id: (Dev, u32),
    pub author: Dev,
    pub epoch: u32,
    pub key_id: KeyId,
    pub wrap: Option<KeyId>,
    pub state: Item,
    /// No fault changed it (checker bookkeeping, not part of the record).
    pub honest: bool,
    pub fault: Option<Fault>,
    /// Checker bookkeeping, not part of the record: the author had absorbed a faulty (or tainted)
    /// snapshot before writing this one, so an honest author may carry faulty content.
    pub tainted: bool,
}

impl Snapshot {
    pub fn name(&self) -> String {
        format!("S{}.{}", self.id.0, self.id.1)
    }
}

#[derive(Clone, Debug)]
pub enum Out {
    Op(Op),
    Snap(Snapshot),
}

/// A user action that writes an op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit {
    Write(Vec<(Key, Val)>),
    Trash,
    Restore,
    Purge,
}

#[derive(Clone, Debug)]
pub struct Replica {
    pub id: Dev,
    pub status: Status,
    /// Injected wall clock = skew + own action count (ms); per device so that local actions of
    /// different devices commute (the explorer relies on it).
    pub skew: u64,
    pub ticks: u64,
    pub hlc: Hlc,
    pub next_seq: Seq,
    pub item: Item,
    /// ADR 0012 §4 step 2: ops held until their causal context and vault_prev_seq are applied.
    pub pending: Vec<Op>,
    /// ADR 0012 §6: the item's ops since its newest snapshot.
    pub retained: Vec<Op>,
    /// ADR 0012 §6 "recomputes the item from its retained ops and snapshots": the state of the
    /// newest snapshot, so that `item` equals `base` plus the `retained` ops. Under answer 1
    /// (`MergedSnap::AfterConcurrent`), after a concurrent absorption it is the join of the
    /// previous newest snapshot and the absorbed one until the merged snapshot replaces both.
    pub base: Item,
    /// Answer 1: a concurrent absorption happened in the current Fetch; a merged snapshot is due.
    pub merge_due: bool,
    /// Checker bookkeeping: this replica absorbed a faulty or tainted snapshot.
    pub tainted: bool,
    /// Covered VVs of snapshots held (written or absorbed): "already held" in the chain check.
    pub held_snaps: Vec<VV>,
    /// Answer 2: the honest snapshot records this replica wrote or absorbed ("Clients store it as a
    /// snapshot envelope", ADR 0018 §3). A healing request re-publishes them verbatim for an item
    /// that cannot get a fresh snapshot.
    pub held_records: Vec<Snapshot>,
    /// Every signed op header this replica verified (chain check) or wrote, latest version. Answer
    /// 2 keeps them for the life of the vault, as the server does (ADR 0012 §7); answer 4's
    /// evidence merge reads their contexts and HLCs.
    pub headers: Headers,
    pub outbox: VecDeque<Out>,
    /// Every own op ever authored (latest version). Used for healing only if `keep_own_ops`.
    pub own_log: BTreeMap<Seq, Op>,
    /// ADR 0012 §7 "Fetch": the highest device_seq it has per device (headers received).
    pub cursor: VV,
    pub acked_self: Seq,
    /// Own ops uploaded at least once without an answer, with the server's restore generation at
    /// the earliest such upload (`StaleSent`).
    pub lost_uploads: BTreeMap<Seq, u64>,
    /// Answer 2: item-key wraps this device knows the server held: received in a Fetch response
    /// (the wrap set, or carried by an op or snapshot), or uploaded and acknowledged.
    pub wraps_seen: BTreeSet<KeyId>,
    /// Fresh keys whose carrying record was dropped or refused before another record under the
    /// key was queued: the next record under the key carries the wrap (CRYPTO.md §11.6).
    pub orphan_wraps: BTreeSet<KeyId>,
    /// This device's fresh item keys whose wrap an acknowledged *op* of this device carried
    /// (ADR 0012 §3 "Key wrap": the wrap is on "the first op under a new item key").
    pub wraps_stored: BTreeSet<KeyId>,
    /// This device's fresh item keys for which it has written the first op (which carries the
    /// wrap, whether or not a snapshot carried it before).
    pub wrap_op_authored: BTreeSet<KeyId>,
    pub known_epoch: u32,
    pub state_seq: u64,
    pub keys: BTreeSet<KeyId>,
    pub revocations: BTreeMap<Dev, Seq>,
    pub read_only: bool,
    pub notices: Vec<Notice>,
    pub snap_n: u32,
    pub key_n: u32,
    pub ops_since_snap: usize,
    pub last_heal_vv: Option<VV>,
    /// ADR 0012 §7 "Freshness" / INV-25: the highest VV accepted.
    pub max_vv: VV,
    // Answer 4 (evidence merge) body knowledge.
    /// Dots this replica merged from an op body that is not a Purge.
    pub writes_seen: BTreeSet<Dot>,
    /// Dots this replica merged from a Purge body, with the body envelope's key_id.
    pub purges_seen: BTreeMap<Dot, KeyId>,
    /// Dots whose op body this replica merged (deduplication under the evidence merge).
    pub merged: BTreeSet<Dot>,
    /// The writes (lifecycle marker included) of every non-Purge op body merged or received.
    pub body_writes: BTreeMap<Dot, Vec<(Key, Val)>>,
    // Coverage counters.
    pub absorbed_dominating: u64,
    pub absorbed_concurrent: u64,
    /// Absorptions rejected because they would move the item VV backwards (INV-25).
    pub absorb_rejected_inv25: u64,
    /// History entries dropped by deterministic pruning inside a state join.
    pub join_pruned: u64,
    /// Committed concurrent absorptions by (local, snapshot) kind: live<-live, live<-tomb,
    /// tomb<-live, tomb<-tomb.
    pub conc_cases: [u64; 4],
    /// Merged snapshots written (answer 1).
    pub merged_written: u64,
    /// Evidence absorptions refused (clamp or contradiction), and with a dispute (answer 4).
    pub em_refused: u64,
    pub em_disputes: u64,
    /// Revoked authors' snapshots accepted / rejected at absorption; ADR 0012 §6 recomputations;
    /// recomputations whose base plus retained ops did not reproduce the state (must stay 0).
    pub revoked_snaps_accepted: u64,
    pub revoked_snaps_rejected: u64,
    pub past_cutoff_recomputed: u64,
    pub recompute_base_mismatch: u64,
    /// Set on the scratch copy an absorption runs on: the INV-25 check runs once on the result,
    /// not on each intermediate step of a replay.
    pub trial: bool,
    pub rec: bool,
    pub events: Vec<String>,
}

impl Replica {
    pub fn new(id: Dev, skew: u64) -> Self {
        Replica {
            id,
            status: Status::Active,
            skew,
            ticks: 0,
            hlc: 0,
            next_seq: 1,
            item: Item::default(),
            pending: Vec::new(),
            retained: Vec::new(),
            base: Item::default(),
            merge_due: false,
            tainted: false,
            held_snaps: Vec::new(),
            held_records: Vec::new(),
            headers: Headers::new(),
            outbox: VecDeque::new(),
            own_log: BTreeMap::new(),
            cursor: VV::default(),
            acked_self: 0,
            lost_uploads: BTreeMap::new(),
            wraps_seen: BTreeSet::new(),
            orphan_wraps: BTreeSet::new(),
            wraps_stored: BTreeSet::new(),
            wrap_op_authored: BTreeSet::new(),
            known_epoch: 0,
            state_seq: 0,
            keys: BTreeSet::new(),
            revocations: BTreeMap::new(),
            read_only: false,
            notices: Vec::new(),
            snap_n: 0,
            key_n: 0,
            ops_since_snap: 0,
            last_heal_vv: None,
            max_vv: VV::default(),
            writes_seen: BTreeSet::new(),
            purges_seen: BTreeMap::new(),
            merged: BTreeSet::new(),
            body_writes: BTreeMap::new(),
            absorbed_dominating: 0,
            absorbed_concurrent: 0,
            absorb_rejected_inv25: 0,
            join_pruned: 0,
            conc_cases: [0; 4],
            merged_written: 0,
            em_refused: 0,
            em_disputes: 0,
            revoked_snaps_accepted: 0,
            revoked_snaps_rejected: 0,
            past_cutoff_recomputed: 0,
            recompute_base_mismatch: 0,
            trial: false,
            rec: false,
            events: Vec::new(),
        }
    }

    pub fn ev(&mut self, s: String) {
        if self.rec {
            self.events.push(format!("D{} {}", self.id, s));
        }
    }

    pub fn note(&mut self, n: Notice) {
        if !self.notices.contains(&n) {
            self.ev(format!("notice {n:?}"));
            self.notices.push(n);
        }
    }

    fn wall(&self) -> u64 {
        self.skew + self.ticks
    }

    /// ADR 0012 §2 HLC, local/send event.
    fn tick_local(&mut self) -> Hlc {
        let pt = self.wall() << 16;
        self.hlc = std::cmp::max(self.hlc + 1, pt);
        self.hlc
    }

    /// ADR 0012 §2 HLC, receive event, with the skew guard: an HLC more than 24 h ahead of the
    /// local wall clock is applied but not adopted.
    fn tick_recv(&mut self, m: Hlc) {
        let pt = self.wall();
        if (m >> 16) > pt + SKEW_MS {
            self.note(Notice::ClockAhead);
            return;
        }
        self.hlc = std::cmp::max(pt << 16, std::cmp::max(self.hlc, m) + 1);
    }

    /// The item's current key: the held key with the highest (created_epoch, id).
    /// AMBIGUOUS 10: CRYPTO.md §11.6 says "the item's current ITEM_KEY_WRAP" without saying which
    /// one is current when two devices each generated a fresh key after one rotation.
    pub fn current_key(&self) -> Option<KeyId> {
        self.keys.iter().max().copied()
    }

    /// CRYPTO.md §11.6 writer rule: if the current key's created epoch is below the current vault
    /// epoch (or there is no key yet: a create), generate a fresh item key and carry its wrap.
    /// A wrap whose carrying record was dropped rides on the next record under that key.
    /// Returns (key, wrap carried, fresh).
    pub fn writer_key(&mut self) -> (KeyId, Option<KeyId>, bool) {
        match self.current_key() {
            Some(k) if k.created_epoch() >= self.known_epoch => {
                let wrap = self.orphan_wraps.remove(&k).then_some(k);
                (k, wrap, false)
            }
            _ => {
                self.key_n += 1;
                let k = KeyId::new(self.known_epoch, self.id, self.key_n);
                self.keys.insert(k);
                (k, Some(k), true)
            }
        }
    }

    /// ADR 0012 §3 "Key wrap": "Present only on the first op under a new item key". A key this
    /// device generated for a snapshot (the writer rule applies to snapshots too) had its wrap on
    /// that snapshot; the first op under the key carries it as well, since a snapshot is not in the
    /// device's chain and a restore or R3 can drop it. (Fidelity fix from answer 3.)
    fn first_op_wrap(&mut self, key_id: KeyId, wrap: Option<KeyId>) -> Option<KeyId> {
        let mut wrap = wrap;
        if wrap.is_none()
            && ((key_id.0 >> 8) & 0xff) as u8 == self.id
            && !self.wrap_op_authored.contains(&key_id)
        {
            wrap = Some(key_id);
        }
        if wrap.is_some() {
            self.wrap_op_authored.insert(key_id);
        }
        wrap
    }

    /// Author one op (one save of one item, ADR 0012 §3) and apply it locally.
    pub fn author(
        &mut self,
        e: &Edit,
        cfg: &Config,
    ) -> Result<(Op, Option<Snapshot>), &'static str> {
        if self.read_only {
            return Err("read-only: server behind (ADR 0012 §7 healing)");
        }
        let shown = self.item.shown();
        match e {
            // MODEL (authoring policy, not an ADR reading): only device 0 creates; a Write on a
            // tombstone models an editor that was open when the purge arrived (ADR 0018 §3
            // "Applying" 3, "its context covers purge_dot"); Trash, Restore and Purge are offered
            // only for the shown lifecycle.
            Edit::Write(_) => {
                if shown == Shown::Absent && self.id != 0 {
                    return Err("item not present on this device");
                }
            }
            Edit::Trash => {
                if shown != Shown::Active {
                    return Err("Trash needs a shown-Active item");
                }
            }
            Edit::Restore => {
                if shown != Shown::Trashed {
                    return Err("Restore needs a shown-Trashed item");
                }
            }
            Edit::Purge => {
                // ADR 0012 §5: "A Purge op is allowed only on trashed items" binds the writer.
                if shown != Shown::Trashed {
                    return Err("Purge only on a shown-Trashed item (ADR 0012 §5)");
                }
                // ADR 0018 §11 "No purge over an unapplied record".
                if !self.pending.is_empty() {
                    return Err("no purge over an unapplied record (ADR 0018 §11)");
                }
            }
        }
        let hlc = self.tick_local();
        let seq = self.next_seq;
        self.next_seq += 1;
        let had_key = self.current_key().is_some();
        let (key_id, wrap, fresh) = self.writer_key();
        let wrap = self.first_op_wrap(key_id, wrap);
        let (marker, mut writes) = match e {
            Edit::Write(ws) => (Marker::Active, ws.clone()),
            Edit::Trash => (Marker::Trashed, Vec::new()),
            Edit::Restore => (Marker::Active, Vec::new()),
            Edit::Purge => (Marker::Purge, Vec::new()),
        };
        writes.sort_by(|a, b| a.0.cmp(b.0));
        writes.dedup_by(|a, b| a.0 == b.0);
        let op = Op {
            h: Header {
                dot: Dot::new(self.id, seq),
                // One vault: vault_prev_seq is the previous device_seq (ADR 0012 §2).
                prev: seq - 1,
                hlc,
                // ADR 0012 §2 "Causal context": the item VV the author had at write time.
                ctx: self.item.vv().clone(),
                epoch: self.known_epoch,
            },
            b: Body {
                key_id,
                wrap,
                marker,
                writes,
            },
        };
        self.headers.insert(op.dot(), op.h.clone());
        self.apply_now(&op, cfg);
        self.outbox.push_back(Out::Op(op.clone()));
        self.own_log.insert(seq, op.clone());
        self.ev(format!("authors {}", op.describe()));
        // ADR 0012 §7 triggers (as ADR 0018 §10 restates them): the first write under a fresh item
        // key (the writer rule), a purge, or more than 32 ops since the last snapshot.
        // AMBIGUOUS 9: "the first write under a fresh item key (the writer rule in CRYPTO.md
        // §11.6)" is read as the writer-rule case only (a key made fresh because of a rotation);
        // the create, also a first write under a fresh key, does not trigger a snapshot.
        // AMBIGUOUS 16: the triggers are evaluated when this device authors an op: "a purge" is the
        // device's own purge, and applying received ops or a received purge triggers nothing.
        let trigger = (fresh && had_key)
            || (marker == Marker::Purge && cfg.snapshot_on_purge)
            || self.ops_since_snap > cfg.snapshot_after_ops;
        let snap = if trigger {
            self.write_snapshot(None, cfg)
        } else {
            None
        };
        Ok((op, snap))
    }

    fn check_mono(&mut self) {
        let new = self.item.vv().clone();
        if !self.max_vv.leq(&new) {
            let old = self.max_vv.clone();
            self.note(Notice::VvBackwards {
                old,
                new: new.clone(),
            });
        }
        self.max_vv.join(&new);
    }

    fn apply_now(&mut self, op: &Op, cfg: &Config) -> bool {
        let applied = if cfg.evidence() {
            // Answer 4: the op merges as a one-op state through the evidence join. For honest
            // states this is ADR 0012 §4 steps 3-4 and ADR 0018 §3 "Applying" 1-3; an op whose dot
            // the VV covers only through a snapshot that lacked its value is merged, not skipped.
            let fresh = !self.item.vv().covers(op.dot());
            let (st, _) = em_join(
                &self.item,
                &singleton(op),
                &self.headers,
                &self.keys,
                cfg.n_hist,
            );
            self.item = st;
            fresh
        } else {
            self.item.apply(op, cfg.n_hist)
        };
        let first_body = self.merged.insert(op.dot());
        self.learn_body(op);
        // Under the evidence merge a covered body merged for the first time is kept too: the
        // newest snapshot that covers its dot may lack its value (ADR 0012 §6 recomputation).
        if !applied
            && first_body
            && cfg.evidence()
            && !self.retained.iter().any(|o| o.dot() == op.dot())
        {
            self.retained.push(op.clone());
        }
        if applied {
            self.retained.push(op.clone());
            self.ops_since_snap += 1;
            if op.dot().dev != self.id {
                self.tick_recv(op.h.hlc);
            }
            if !self.trial {
                self.check_mono();
            }
        }
        applied
    }

    /// ADR 0012 §4 steps 1-3 for a verified op.
    pub fn deliver(&mut self, op: Op, cfg: &Config) {
        // Step 1 / CRYPTO.md §11.8 step 4: a revoked device's op past the cut-off is rejected.
        if let Some(&cut) = self.revocations.get(&op.dot().dev)
            && op.dot().seq > cut
        {
            self.note(Notice::Rejected {
                dot: op.dot(),
                why: "revoked device past cut-off",
            });
            return;
        }
        // CRYPTO.md §11.6 reader rule: a delivered wrap names an item key the reader can use.
        if let Some(w) = op.b.wrap {
            self.keys.insert(w);
            self.wraps_seen.insert(w);
        }
        // Its signed header was verified before the body (ADR 0012 §3, §7).
        self.headers.entry(op.dot()).or_insert_with(|| op.h.clone());
        // Step 3. Answer 4 (evidence merge): a covered op still merges (a union: a no-op for an
        // honest state), unless this replica merged that very body already.
        let covered = self.item.vv().covers(op.dot());
        let merged_body = self.merged.contains(&op.dot());
        if (covered && (!cfg.evidence() || merged_body))
            || self.pending.iter().any(|p| p.dot() == op.dot())
        {
            return;
        }
        self.pending.push(op);
        self.drain_pending(cfg);
    }

    /// ADR 0012 §4 step 2 "Deliver causally": apply every held op whose causal context and
    /// vault_prev_seq have been applied (and whose item key is known, CRYPTO.md §11.6 reader rule).
    pub fn drain_pending(&mut self, cfg: &Config) {
        loop {
            self.pending.sort_by_key(|p| p.dot());
            let vv = self.item.vv();
            let pos = self.pending.iter().position(|p| {
                vv.covers(p.dot())
                    || (p.h.ctx.leq(vv)
                        && vv.get(p.dot().dev) >= p.h.prev
                        && self.keys.contains(&p.b.key_id))
            });
            let Some(i) = pos else { break };
            let op = self.pending.remove(i);
            if self.apply_now(&op, cfg) {
                self.ev(format!("applies {}", op.dot()));
            }
        }
    }

    /// "Already held" in the chain check: a snapshot this replica accepted (wrote, absorbed, or
    /// found dominated).
    fn hold(&mut self, vv: &VV) {
        if !self.held_snaps.contains(vv) {
            self.held_snaps.push(vv.clone());
        }
    }

    fn keep_record(&mut self, s: &Snapshot) {
        if s.honest && !self.held_records.iter().any(|x| x.id == s.id) {
            self.held_records.push(s.clone());
        }
    }

    /// Absorb one verified snapshot through the configured strategy. Returns true when the
    /// replica accepted it (absorbed, or dominated and so a no-op); only an accepted snapshot is
    /// "held" for the chain check (`process_response`).
    pub fn absorb(&mut self, s: &Snapshot, cfg: &Config) -> bool {
        // ADR 0018 §5 rules the merge relies on (coverage, late values vs c).
        if let Err(why) = s.state.validate_snapshot() {
            self.note(Notice::SnapRejected { why });
            return false;
        }
        // ADR 0012 §4 step 1 "Verify first", for a snapshot whose author is revoked (ADR 0021
        // open question 5; answer 5).
        if let Some(&cut) = self.revocations.get(&s.author) {
            let refuse = match cfg.revoked_snap {
                RevokedSnap::AcceptAll => None,
                // AMBIGUOUS 17 (literal): no device_seq, so the "device_seq <= last_accepted"
                // exception of ADR 0012 §4 step 1 cannot apply to a snapshot.
                RevokedSnap::Reject => Some("author revoked (ADR 0012 §4 step 1)"),
                // ADR 0021 open question 5, recommendation (answer 5).
                RevokedSnap::AcceptIfCovered => (s.state.vv().get(s.author) > cut)
                    .then_some("revoked author's snapshot claims its dots past the cut-off"),
            };
            if let Some(why) = refuse {
                self.revoked_snaps_rejected += 1;
                self.ev(format!("rejects {}: {why}", s.name()));
                self.note(Notice::SnapRejected { why });
                return false;
            }
            self.revoked_snaps_accepted += 1;
        }
        if let Some(w) = s.wrap {
            self.keys.insert(w);
            self.wraps_seen.insert(w);
        }
        // CRYPTO.md §11.6 reader rule: "The key_id in an op or snapshot envelope header must equal
        // the key id derived from an item key the reader unwrapped for that item." A snapshot
        // under a key the reader does not hold cannot be decrypted; it is not absorbed.
        if !self.keys.contains(&s.key_id) {
            self.note(Notice::SnapIgnored {
                why: "reader rule: snapshot under an unknown item key",
            });
            return false;
        }
        // AMBIGUOUS 25: no text covers a snapshot (by any author) that claims a revoked device's
        // dot past its cut-off; literally it is absorbed, and the replica then takes the ADR 0012
        // §6 path. (The evidence merge takes no dot without a verified header, and a replica never
        // verifies a header past a cut-off, so there it is cut and reported.)
        if cfg.evidence() {
            return self.absorb_evidence(s, cfg);
        }
        let svv = s.state.vv().clone();
        // AMBIGUOUS 2: a dominated snapshot is a no-op.
        if svv.leq(self.item.vv()) {
            self.ev(format!("absorbs {} vv={}: dominated, no-op", s.name(), svv));
            self.hold(&svv);
            self.keep_record(s);
            return true;
        }
        let local_vv = self.item.vv().clone();
        let concurrent = !local_vv.leq(&svv);
        if concurrent {
            self.absorbed_concurrent += 1;
        } else {
            self.absorbed_dominating += 1;
        }
        let out = cfg.strategy().absorb(AbsorbCtx {
            local: &self.item,
            retained: &self.retained,
            snap: &s.state,
            n_hist: cfg.n_hist,
        });
        let how = if concurrent {
            "concurrent"
        } else {
            "dominating"
        };
        // The outcome runs on a scratch copy; INV-25 decides whether it is committed.
        let mut t = self.clone();
        t.trial = true;
        match out {
            AbsorbOutcome::Ignore(why) => {
                self.ev(format!(
                    "absorbs {} vv={} ({how} with local {}): ignored",
                    s.name(),
                    svv,
                    local_vv
                ));
                self.note(Notice::SnapIgnored { why });
                return false;
            }
            AbsorbOutcome::Replace { state, replay } => {
                let rp: Vec<String> = replay.iter().map(|o| o.dot().to_string()).collect();
                t.ev(format!(
                    "absorbs {} vv={} ({how} with local {}): replace, replay retained [{}]",
                    s.name(),
                    svv,
                    local_vv,
                    rp.join(",")
                ));
                t.item = state;
                t.base = s.state.clone();
                t.retained.clear();
                for op in replay {
                    if !t.pending.iter().any(|p| p.dot() == op.dot()) {
                        t.pending.push(op);
                    }
                }
            }
            AbsorbOutcome::Merge { state, pruned } => {
                t.ev(format!(
                    "absorbs {} vv={} ({how} with local {}): join",
                    s.name(),
                    svv,
                    local_vv
                ));
                t.join_pruned += pruned as u64;
                t.item = state;
                // AMBIGUOUS 3 (literal, `MergedSnap::Never`): the absorbed snapshot becomes the
                // replica's "newest snapshot" and the retained ops it covers are dropped. After a
                // concurrent absorption that snapshot no longer rebuilds the state with the
                // retained ops (RECOMP side condition).
                // Answer 1 (`AfterConcurrent`): after a concurrent absorption the replica keeps its
                // previous newest snapshot and the absorbed one until the merged snapshot replaces
                // both (for good when none can be written, ADR 0018 §10); their join, with the ops
                // neither covers, rebuilds the item.
                let basis = if concurrent && cfg.merged_snapshot == MergedSnap::AfterConcurrent {
                    join_items(&t.base, &s.state, cfg.n_hist)
                } else {
                    s.state.clone()
                };
                let bvv = basis.vv().clone();
                t.base = basis;
                t.retained.retain(|o| !bvv.covers(o.dot()));
            }
        }
        t.drain_pending(cfg);
        // ADR 0012 §7 "Freshness" / INV-25: "A server response that moves any of these backwards
        // ... is rejected and reported, never applied." The check is on the resulting item VV
        // against the highest VV accepted, after any replay.
        if !self.max_vv.leq(t.item.vv()) {
            self.absorb_rejected_inv25 += 1;
            self.ev(format!(
                "rejects {} vv={}: absorbing it would move the item VV from {} to {} (INV-25)",
                s.name(),
                svv,
                self.max_vv,
                t.item.vv()
            ));
            self.note(Notice::SnapRejected {
                why: "INV-25: absorbing it would move the item VV backwards",
            });
            return false;
        }
        t.trial = false;
        let local_tomb = self.item.is_tomb();
        *self = t;
        self.hold(&svv);
        self.keep_record(s);
        self.tainted |= !s.honest || s.tainted;
        self.check_mono();
        self.after_absorb(concurrent, local_tomb, &s.state, cfg);
        true
    }

    /// Answer 1, after a committed absorption: count the concurrent case, schedule the merged
    /// snapshot, and apply the HLC receipt.
    fn after_absorb(&mut self, concurrent: bool, local_tomb: bool, taken: &Item, cfg: &Config) {
        if concurrent {
            let i = (local_tomb as usize) * 2 + (taken.is_tomb() as usize);
            self.conc_cases[i] += 1;
            if cfg.merged_snapshot == MergedSnap::AfterConcurrent {
                self.merge_due = true;
            }
        }
        // AMBIGUOUS 18: ADR 0012 §2 applies the HLC rules "on local events and on receipt" but does
        // not say whether absorbing a snapshot is a receipt. Literal: it is not.
        // Answer 1 (`hlc_on_absorb`): the receive rule for the highest HLC the snapshot carries
        // (values, history, late values, purge_hlc), under the skew guard.
        if cfg.hlc_on_absorb
            && let Some(m) = max_hlc(taken)
        {
            self.tick_recv(m);
        }
    }

    /// Record what a verified op body says: a Purge (with its key_id) or the writes of a save.
    pub fn learn_body(&mut self, op: &Op) {
        match op.b.marker {
            Marker::Purge => {
                self.purges_seen.insert(op.dot(), op.b.key_id);
            }
            _ => {
                self.writes_seen.insert(op.dot());
                self.body_writes
                    .insert(op.dot(), op.writes_with_lifecycle());
            }
        }
    }

    /// Answer 4: the evidence absorption. A snapshot is a signed claim by its author; the replica
    /// takes from it only what verified op headers vouch for, and a snapshot can add values but
    /// never remove one this replica holds.
    /// 1. Clamp (claims): the covered VV is cut to the verified op headers this replica holds (its
    ///    own chain included), and values above the cut, or whose HLC is not their header's, are
    ///    not taken (`item::restrict`). A tombstone whose purge is above the cut is refused.
    /// 2. Contradictions with what this replica merged from op bodies: a tombstone whose recorded
    ///    purge is a dot that wrote values, or a purge this replica applied under another
    ///    item_key_id; a live snapshot holding a value at a Purge's dot; a c that discards a value
    ///    no op the snapshot covers can have purged. Such a snapshot is refused and reported.
    /// 3. The evidence join (`item::em_join`); disagreements it cannot decide are reported
    ///    (`Notice::Dispute`), never silently decided by absence.
    fn absorb_evidence(&mut self, s: &Snapshot, cfg: &Config) -> bool {
        let mut heads = header_heads(&self.headers);
        if self.next_seq > 1 {
            heads.add(Dot::new(self.id, self.next_seq - 1));
        }
        let refuse = |r: &mut Replica, why: &'static str| {
            r.em_refused += 1;
            r.ev(format!("refuses {}: {why}", s.name()));
            r.note(Notice::SnapRejected { why });
            false
        };
        // A claim above the verified headers is not taken, and it is reported: after a server
        // restore it may be the only record of a real op (ADR 0021 open question 4), which a
        // replica must not lose silently.
        for (&d, &c) in &s.state.vv().0 {
            let h = heads.get(d);
            if c > h {
                self.note(Notice::ClaimCut {
                    dev: d,
                    from: h,
                    to: c,
                    author: s.author,
                });
            }
        }
        let Some(sr) = restrict(&s.state, &heads, &self.headers) else {
            return refuse(
                self,
                "tombstone rests on a purge above the verified op headers",
            );
        };
        // Contradictions are judged only against op bodies (signed op truth) this replica merged
        // or received in the same Fetch response, never against values it took from another
        // snapshot: a disagreement between two snapshots is undecidable and only reported.
        if item_values(&sr).iter().any(|(k, e)| {
            self.body_writes
                .get(&e.dot)
                .is_some_and(|ws| !ws.iter().any(|(wk, wv)| wk == k && *wv == e.val))
        }) {
            return refuse(self, "a value that the op body at its dot did not write");
        }
        match &sr {
            Item::Tomb(t) => {
                if self.writes_seen.contains(&t.purge.dot) {
                    return refuse(self, "tombstone records a write as its purge");
                }
                if self
                    .purges_seen
                    .get(&t.purge.dot)
                    .is_some_and(|k| *k != t.purge.key_id)
                {
                    return refuse(
                        self,
                        "tombstone records another item_key_id for a known purge",
                    );
                }
                // c is the join of the contexts of purges the author applied (ADR 0018 §3
                // "Context"): each entry must be reached by the context of some op the snapshot
                // covers that is not known to be a write.
                let mut bound = VV::default();
                for (d, h) in &self.headers {
                    if t.vv.covers(*d) && !self.writes_seen.contains(d) {
                        bound.join(&h.ctx);
                    }
                }
                if !t.c.leq(&bound) {
                    return refuse(
                        self,
                        "c is not the join of the contexts of purges it covers",
                    );
                }
            }
            Item::Live(_) => {
                if item_values(&sr)
                    .iter()
                    .any(|(_, e)| self.purges_seen.contains_key(&e.dot))
                {
                    return refuse(self, "live snapshot holds a value at a Purge's dot");
                }
                // A live state that covers a Purge: the join keeps the tombstone (a Purge is never
                // undone, ADR 0018 §3); reported as a dispute below.
            }
        }
        let local_vals = item_values(&self.item);
        // Report what the two sides do not account for (omission or fabrication on one side).
        let mut disputes: Vec<Dot> = Vec::new();
        for (k, v) in &local_vals {
            if sr.vv().covers(v.dot) && !accounts_for(&sr, k, v, &self.headers, cfg.n_hist) {
                disputes.push(v.dot);
            }
        }
        for (k, v) in item_values(&sr) {
            if self.item.vv().covers(v.dot)
                && !accounts_for(&self.item, k, &v, &self.headers, cfg.n_hist)
            {
                disputes.push(v.dot);
            }
        }
        // A c that discards a value the other side keeps must come from a purge the other side
        // has not applied: an op header covered by this side only, not known to be a write, whose
        // context covers the value. Otherwise one of the two lies about c.
        let c_of = |i: &Item| match i {
            Item::Tomb(t) => t.c.clone(),
            Item::Live(_) => VV::default(),
        };
        for (x, y) in [(&self.item, &sr), (&sr, &self.item)] {
            let (cx, cy) = (c_of(x), c_of(y));
            for (k, v) in item_values(y) {
                if k == LIFECYCLE || !cx.covers(v.dot) || cy.covers(v.dot) {
                    continue;
                }
                let explained = self.headers.iter().any(|(d, h)| {
                    x.vv().covers(*d)
                        && !y.vv().covers(*d)
                        && !self.writes_seen.contains(d)
                        && h.ctx.covers(v.dot)
                });
                if !explained {
                    disputes.push(v.dot);
                }
            }
        }
        match (&self.item, &sr) {
            (Item::Live(l), Item::Tomb(t)) | (Item::Tomb(t), Item::Live(l))
                if l.vv.covers(t.purge.dot) && !l.regs.is_empty() =>
            {
                disputes.push(t.purge.dot);
            }
            (Item::Tomb(a), Item::Tomb(b)) if a.purge.dot == b.purge.dot && a.purge != b.purge => {
                disputes.push(a.purge.dot);
            }
            _ => {}
        }
        disputes.sort();
        disputes.dedup();
        if !disputes.is_empty() {
            self.em_disputes += 1;
        }
        for d in disputes {
            self.note(Notice::Dispute {
                dot: d,
                author: s.author,
            });
        }
        let local_vv = self.item.vv().clone();
        let svv = sr.vv().clone();
        let concurrent = !svv.leq(&local_vv) && !local_vv.leq(&svv);
        if svv.leq(&local_vv) {
            // Dominated (after the clamp): nothing to take beyond a union that changes nothing on
            // an honest state; it still counts as held.
        } else if concurrent {
            self.absorbed_concurrent += 1;
        } else {
            self.absorbed_dominating += 1;
        }
        let local_tomb = self.item.is_tomb();
        let (st, pruned) = em_join(&self.item, &sr, &self.headers, &self.keys, cfg.n_hist);
        self.ev(format!(
            "absorbs {} vv={} (clamped {}) into local {}: evidence join",
            s.name(),
            s.state.vv(),
            svv,
            local_vv
        ));
        self.join_pruned += pruned as u64;
        self.item = st;
        // AMBIGUOUS 3 / answer 1, as in `absorb`: the newest-snapshot basis. Under the evidence
        // merge a snapshot is never a substitute for what it lacks (answer 4: absence is not
        // evidence), so the basis is always the join of the previous basis and the taken part
        // (a dominated snapshot can still add a value another snapshot omitted); on an honest
        // dominating snapshot that join is the snapshot itself.
        // The retained ops the new basis covers are folded into it before they are dropped, so a
        // snapshot that covers an op without its value never removes that op's only local copy.
        {
            let mut basis = em_join(&self.base, &sr, &self.headers, &self.keys, cfg.n_hist).0;
            let bvv = basis.vv().clone();
            for o in self.retained.iter().filter(|o| bvv.covers(o.dot())) {
                basis = em_join(&basis, &singleton(o), &self.headers, &self.keys, cfg.n_hist).0;
            }
            self.base = basis;
            self.retained.retain(|o| !bvv.covers(o.dot()));
        }
        self.hold(&svv);
        self.keep_record(s);
        self.tainted |= !s.honest || s.tainted;
        self.drain_pending(cfg);
        self.check_mono();
        self.after_absorb(concurrent, local_tomb, &sr, cfg);
        true
    }

    /// ADR 0012 §6 recomputation: the newest snapshot's state (`base`), then the retained ops in a
    /// causal order, by the configured op merge. It must equal the item (RECOMP side condition).
    pub fn recompute(&self, cfg: &Config) -> Item {
        let mut it = self.base.clone();
        let mut rest: Vec<&Op> = self
            .retained
            .iter()
            .filter(|o| cfg.evidence() || !it.vv().covers(o.dot()))
            .collect();
        loop {
            let vv = it.vv().clone();
            let pos = rest.iter().position(|o| {
                vv.covers(o.dot()) || (o.h.ctx.leq(&vv) && vv.get(o.dot().dev) >= o.h.prev)
            });
            let Some(i) = pos else { break };
            let o = rest.remove(i);
            if cfg.evidence() {
                it = em_join(&it, &singleton(o), &self.headers, &self.keys, cfg.n_hist).0;
            } else {
                it.apply(o, cfg.n_hist);
            }
        }
        it
    }

    /// Write a signed snapshot of the current state (ADR 0012 §7 "Snapshots and compaction").
    pub fn write_snapshot(&mut self, fault: Option<Fault>, cfg: &Config) -> Option<Snapshot> {
        if self.item.is_absent() {
            return None;
        }
        // ADR 0018 §10 "No snapshot": a client writes no snapshot of an oversize item, whatever
        // the trigger (the writer rule and healing step 4 included: ADR 0018 open question 12,
        // recommendation). Its ops stay retained.
        if cfg.max_values.is_some_and(|l| self.item.oversize(l)) {
            self.ev("writes no snapshot: item is oversize (ADR 0018 §10)".to_string());
            return None;
        }
        // Answer 4 (evidence merge): a replica that holds an unresolved dispute about the item
        // writes no snapshot of it, so an honest author never re-signs ("launders") a state that
        // may carry another snapshot's fabrication. Like an oversize item, its ops stay retained.
        if cfg.evidence()
            && self
                .notices
                .iter()
                .any(|n| matches!(n, Notice::Dispute { .. }))
        {
            self.ev("writes no snapshot: it holds an unresolved dispute".to_string());
            return None;
        }
        // CRYPTO.md §11.6 writer rule applies to snapshots too.
        let (key_id, wrap, _) = self.writer_key();
        let mut state = self.item.clone();
        if let Some(f) = fault {
            apply_fault(&mut state, f, self.id, key_id, &self.headers, cfg.n_hist);
            // "Verified but dishonest": the fault must not break an ADR 0018 §5 parse rule. (Under
            // the DVV join, an author that absorbed an omitting snapshot can already hold a state
            // that §5 rejects, rule 7; that is the join's finding, not this fault's.)
            if self.item.validate_snapshot().is_ok()
                && let Err(why) = state.validate_snapshot()
            {
                panic!("fault {f:?} built a snapshot that ADR 0018 §5 rejects: {why}");
            }
            if state == self.item {
                self.ev(format!("fault {f:?} does not apply to this state"));
            }
        }
        let honest = fault.is_none() || state == self.item;
        self.snap_n += 1;
        let s = Snapshot {
            id: (self.id, self.snap_n),
            author: self.id,
            epoch: self.known_epoch,
            key_id,
            wrap,
            state,
            honest,
            fault,
            tainted: self.tainted,
        };
        if fault.is_none() {
            let vv = s.state.vv().clone();
            // ADR 0012 §6: keep the item's ops since its newest snapshot.
            // AMBIGUOUS 3: "newest snapshot" = the last snapshot this device wrote or absorbed; its
            // own ops that it covers are dropped too (literal; `keep_own_ops` is the alternative).
            self.base = self.item.clone();
            self.retained.retain(|o| !vv.covers(o.dot()));
            self.hold(&vv);
            self.ops_since_snap = 0;
            self.held_records.push(s.clone());
        }
        let kind = match fault {
            None => "snapshot".to_string(),
            Some(f) => format!("FAULTY snapshot ({f:?})"),
        };
        self.ev(format!(
            "writes {kind} {} epoch={} vv={}: {}",
            s.name(),
            s.epoch,
            s.state.vv(),
            s.state.canon()
        ));
        self.outbox.push_back(Out::Snap(s.clone()));
        Some(s)
    }

    /// May the server already have stored, and served, this own op? Then it is never re-issued
    /// (`StaleSent`): a second signed version of one dot could reach replicas that hold the first
    /// (answers 2 and 3). `server_gen` is the restore generation the stale answer carries.
    pub fn must_republish(&self, seq: Seq, cfg: &Config, server_gen: u64) -> bool {
        let acked = seq <= self.acked_self;
        let lost = self.lost_uploads.get(&seq).copied();
        match cfg.stale_sent {
            StaleSent::Reissue => false,
            StaleSent::Republish => acked || lost.is_some(),
            StaleSent::RepublishGen => acked || lost.is_some_and(|g| g != server_gen),
        }
    }

    /// ADR 0012 §7 "Upload": after a stale-epoch rejection the client processes the new
    /// account-state, applies the writer rule and re-issues the edit with the same device_seq.
    /// AMBIGUOUS 7: the re-issued op keeps its HLC, causal context and data; only
    /// `vault_key_epoch`, `key_id` and the carried wrap change (answer 3 confirms it).
    /// AMBIGUOUS 8: a stale snapshot in the outbox is dropped; the writer rule's "full snapshot
    /// under the new key" replaces it.
    /// `rejected` is the op whose own upload was answered "stale epoch", or None when the rejected
    /// record was a snapshot (knob `reissue_scope`). Unless `force`, an op `must_republish` keeps
    /// its bytes. Returns (original, re-issued) pairs and the writer-rule snapshot.
    pub fn reissue_outbox(
        &mut self,
        cfg: &Config,
        server_gen: u64,
        rejected: Option<Dot>,
        force: bool,
    ) -> (Vec<(Op, Op)>, Option<Snapshot>) {
        let old: Vec<Out> = self.outbox.drain(..).collect();
        let mut pairs = Vec::new();
        let mut dropped_snap = false;
        // CRYPTO.md §11.6 writer rule: only a *fresh* item key obliges the writer to "write a full
        // snapshot under the new key".
        let mut fresh_key = false;
        let reissued: Vec<Dot> = old
            .iter()
            .filter_map(|o| {
                if let Out::Op(op) = o {
                    // Answer 3 (`OwnAnswer`): only the rejected op and the ops after it in the
                    // device's chain (the server cannot hold them: it stores a chain in order).
                    let in_scope = match cfg.reissue_scope {
                        ReissueScope::Outbox => true,
                        ReissueScope::OwnAnswer => rejected.is_some_and(|r| op.dot().seq >= r.seq),
                    };
                    let keep = !force && self.must_republish(op.dot().seq, cfg, server_gen);
                    (in_scope && op.h.epoch < self.known_epoch && !keep).then_some(op.dot())
                } else {
                    None
                }
            })
            .collect();
        // CRYPTO.md §11.6: the wrap of a fresh item key travels with the first record under it.
        // When that record is a dropped snapshot, the wrap moves to the next record under the key.
        let mut lost_wraps: Vec<KeyId> = Vec::new();
        let mut carried: BTreeSet<KeyId> = BTreeSet::new();
        for o in old {
            match o {
                Out::Op(op) if reissued.contains(&op.dot()) => {
                    let (key_id, wrap, fresh) = self.writer_key();
                    fresh_key |= fresh;
                    let wrap = self.first_op_wrap(key_id, wrap);
                    let mut n = op.clone();
                    n.h.epoch = self.known_epoch;
                    n.b.key_id = key_id;
                    n.b.wrap = wrap;
                    if n.b.wrap.is_none()
                        && lost_wraps.contains(&key_id)
                        && !carried.contains(&key_id)
                    {
                        n.b.wrap = Some(key_id);
                    }
                    if let Some(w) = n.b.wrap {
                        carried.insert(w);
                    }
                    if cfg.reissue_local == ReissueLocal::Patch {
                        self.patch_local(&n);
                    }
                    // The re-issued op is the op of record: the body this author knows (answer 4's
                    // checks) and the header it keeps (answer 2).
                    self.learn_body(&n);
                    self.headers.insert(n.dot(), n.h.clone());
                    self.own_log.insert(n.dot().seq, n.clone());
                    self.ev(format!("re-issues {} as {}", op.dot(), n.describe()));
                    self.outbox.push_back(Out::Op(n.clone()));
                    pairs.push((op, n));
                }
                Out::Op(mut op) => {
                    if op.b.wrap.is_none()
                        && lost_wraps.contains(&op.b.key_id)
                        && !carried.contains(&op.b.key_id)
                    {
                        op.b.wrap = Some(op.b.key_id);
                    }
                    if let Some(w) = op.b.wrap {
                        carried.insert(w);
                    }
                    self.outbox.push_back(Out::Op(op));
                }
                Out::Snap(s) if s.epoch < self.known_epoch => {
                    self.ev(format!("drops stale {}", s.name()));
                    lost_wraps.extend(s.wrap);
                    dropped_snap = true;
                }
                // Answer 3: an unsent snapshot that covers an op being re-issued embeds the
                // pre-re-issue op (a tombstone's item_key_id); drop it too.
                Out::Snap(s)
                    if cfg.drop_covering_snaps
                        && reissued.iter().any(|d| s.state.vv().covers(*d)) =>
                {
                    self.ev(format!("drops {} (covers a re-issued op)", s.name()));
                    lost_wraps.extend(s.wrap);
                    dropped_snap = true;
                }
                Out::Snap(mut s) => {
                    if s.wrap.is_none()
                        && lost_wraps.contains(&s.key_id)
                        && !carried.contains(&s.key_id)
                    {
                        s.wrap = Some(s.key_id);
                    }
                    if let Some(w) = s.wrap {
                        carried.insert(w);
                    }
                    self.outbox.push_back(Out::Snap(s));
                }
            }
        }
        // Answer 3 (`reissue_moves_wrap`; literal: the wrap stays where it was). ADR 0012 §3
        // "Key wrap": present on "the first op under a new item key". After a re-issue, the first
        // op under one of this device's fresh keys may be a re-issued op that took the key while a
        // later op carried the wrap; if that later op is itself re-issued under a newer key, the
        // wrap is never stored. So the first op under such a key carries the wrap, and later ops
        // in the re-issued range (never stored: the server stores a chain in order) drop it.
        if cfg.reissue_moves_wrap && !reissued.is_empty() {
            let me = self.id;
            let stored = self.wraps_stored.clone();
            let acked = self.acked_self;
            let lost: BTreeSet<Seq> = self.lost_uploads.keys().copied().collect();
            let own_unstored = |k: KeyId| ((k.0 >> 8) & 0xff) as u8 == me && !stored.contains(&k);
            let mut firsts: BTreeSet<KeyId> = BTreeSet::new();
            let mut moved: Vec<String> = Vec::new();
            for o in self.outbox.iter_mut() {
                if let Out::Op(op) = o {
                    let k = op.b.key_id;
                    if !own_unstored(k) {
                        continue;
                    }
                    if firsts.insert(k) {
                        if op.b.wrap.is_none() && reissued.contains(&op.dot()) {
                            op.b.wrap = Some(k);
                            moved.push(format!("moves the wrap of {k} to re-issued {}", op.dot()));
                        }
                    } else if (reissued.contains(&op.dot()) || op.dot().seq > acked)
                        && op.b.wrap.is_some()
                        && !lost.contains(&op.dot().seq)
                    {
                        op.b.wrap = None;
                    }
                }
            }
            for m in moved {
                self.ev(m);
            }
        }
        // The outbox now holds the exact bytes this device will upload: keep its own op log and
        // kept headers in step, so a re-publication is byte-identical to what the server stores.
        let outbox_ops: Vec<Op> = self
            .outbox
            .iter()
            .filter_map(|o| match o {
                Out::Op(op) => Some(op.clone()),
                Out::Snap(_) => None,
            })
            .collect();
        for op in outbox_ops {
            self.own_log.insert(op.dot().seq, op.clone());
            self.headers.insert(op.dot(), op.h.clone());
            if cfg.reissue_local == ReissueLocal::Patch {
                for r in self.retained.iter_mut() {
                    if r.dot() == op.dot() {
                        *r = op.clone();
                    }
                }
            }
        }
        for (_, n) in pairs.iter_mut() {
            if let Some(v) = self.own_log.get(&n.dot().seq) {
                *n = v.clone();
            }
        }
        // The writer rule's snapshot when a re-issued op took a fresh key; and a replacement for
        // a dropped snapshot (AMBIGUOUS 8 above). It is written after the author's state took the
        // re-issued ops.
        let mut snap = if fresh_key || dropped_snap {
            self.write_snapshot(None, cfg)
        } else {
            None
        };
        if let Some(s) = snap.as_mut()
            && s.wrap.is_none()
            && lost_wraps.contains(&s.key_id)
            && !carried.contains(&s.key_id)
        {
            s.wrap = Some(s.key_id);
            if let Some(Out::Snap(last)) = self.outbox.back_mut() {
                last.wrap = Some(s.key_id);
            }
        } else if snap.is_none() {
            // A dropped record's wrap with no record left to carry it.
            for k in lost_wraps {
                if !carried.contains(&k) {
                    self.orphan_wraps.insert(k);
                }
            }
        }
        (pairs, snap)
    }

    /// Put a dropped record's key wrap on the next outbox record under that key, or, if none is
    /// queued, on the next record written or uploaded under it.
    pub fn reattach_wrap(&mut self, k: KeyId) {
        for o in self.outbox.iter_mut() {
            match o {
                Out::Op(op) if op.b.key_id == k => {
                    op.b.wrap.get_or_insert(k);
                    return;
                }
                Out::Snap(s) if s.key_id == k => {
                    s.wrap.get_or_insert(k);
                    return;
                }
                _ => {}
            }
        }
        self.orphan_wraps.insert(k);
    }

    /// Answer 3 `ReissueLocal::Patch`: make the author's own state match the re-issued op. The
    /// only state byte that depends on the op's envelope is a tombstone's `item_key_id` when the
    /// op is the recorded purge (ADR 0018 §3 "Recorded purge"); the newest-snapshot basis too.
    fn patch_local(&mut self, n: &Op) {
        for o in self.retained.iter_mut() {
            if o.dot() == n.dot() {
                *o = n.clone();
            }
        }
        for it in [&mut self.item, &mut self.base] {
            if let Item::Tomb(t) = it
                && t.purge.dot == n.dot()
            {
                t.purge.key_id = n.b.key_id;
            }
        }
        if self.purges_seen.contains_key(&n.dot()) {
            self.purges_seen.insert(n.dot(), n.b.key_id);
        }
    }

    /// Answer 2: the full record of `dot` if this replica still holds its body (outbox, retained,
    /// causal buffer, or the own-op log when `keep_own_ops`), and only in the version whose header
    /// it holds.
    pub fn body_of(&self, dot: Dot, cfg: &Config) -> Option<Op> {
        let want = self.headers.get(&dot)?;
        let from_outbox = self.outbox.iter().find_map(|o| match o {
            Out::Op(op) if op.dot() == dot => Some(op),
            _ => None,
        });
        let own = (cfg.keep_own_ops && dot.dev == self.id)
            .then(|| self.own_log.get(&dot.seq))
            .flatten();
        from_outbox
            .into_iter()
            .chain(self.retained.iter().filter(|o| o.dot() == dot))
            .chain(self.pending.iter().filter(|o| o.dot() == dot))
            .chain(own)
            .find(|o| o.h == *want)
            .cloned()
    }

    /// Own ops this device still holds (for healing step 4, `HealOps::Own` / `AllRetained`).
    pub fn own_ops_held(&self, cfg: &Config) -> BTreeMap<Seq, Op> {
        let mut m = BTreeMap::new();
        if cfg.keep_own_ops {
            for (s, o) in &self.own_log {
                m.insert(*s, o.clone());
            }
        }
        for o in &self.retained {
            if o.dot().dev == self.id {
                let latest = self
                    .own_log
                    .get(&o.dot().seq)
                    .cloned()
                    .unwrap_or_else(|| o.clone());
                m.insert(o.dot().seq, latest);
            }
        }
        for out in &self.outbox {
            if let Out::Op(o) = out {
                m.insert(o.dot().seq, o.clone());
            }
        }
        m
    }

    /// A revocation of `t` with `last_accepted_device_seq` = `cut` became known (ADR 0012 §6,
    /// CRYPTO.md §11.8 step 4). Ops of `t` past the cut-off still in the causal buffer are
    /// rejected (ADR 0012 §4 step 1). Returns true when the item holds none of them afterwards.
    pub fn learn_revocation(&mut self, t: Dev, cut: Seq, cfg: &Config) -> bool {
        self.revocations.insert(t, cut);
        let past: Vec<Dot> = self
            .pending
            .iter()
            .filter(|o| o.dot().dev == t && o.dot().seq > cut)
            .map(|o| o.dot())
            .collect();
        for d in past {
            self.pending.retain(|o| o.dot() != d);
            self.note(Notice::Rejected {
                dot: d,
                why: "revoked device past cut-off",
            });
        }
        if self.item.vv().get(t) <= cut {
            return true;
        }
        match cfg.past_cutoff {
            PastCutoff::Flag => false,
            PastCutoff::Recompute => self.recompute_without(t, cut, cfg),
        }
    }

    /// ADR 0012 §6: "the replica removes the op and recomputes the item from its retained ops and
    /// snapshots. If it cannot, it flags the item for the user. Clients keep each item's ops since
    /// its newest snapshot, which makes the recomputation possible."
    /// AMBIGUOUS 19: "cannot" = the newest snapshot state (`base`) already contains an op of `t`
    /// past the cut-off. Ops whose causal context covers a removed op stay in the causal buffer
    /// (ADR 0012 §4 step 2), since that op is never applied.
    /// AMBIGUOUS 20: the persisted highest VV (INV-25) is reset to the recomputed state's VV;
    /// otherwise every later absorption would be refused as "backwards".
    pub fn recompute_without(&mut self, t: Dev, cut: Seq, cfg: &Config) -> bool {
        if self.base.vv().get(t) > cut {
            return false;
        }
        // Model self-check: base plus the retained ops reproduces the current state.
        if self.recompute(cfg).canon() != self.item.canon() {
            self.recompute_base_mismatch += 1;
        }
        let keep = |o: &Op| !(o.dot().dev == t && o.dot().seq > cut);
        let mut n = self.clone();
        n.trial = true;
        n.item = self.base.clone();
        n.retained.clear();
        n.pending.clear();
        n.merged.retain(|d| self.base.vv().covers(*d));
        for o in self.retained.iter().chain(self.pending.iter()) {
            if keep(o) && !n.pending.iter().any(|p| p.dot() == o.dot()) {
                n.pending.push(o.clone());
            }
        }
        n.drain_pending(cfg);
        n.trial = false;
        n.max_vv = n.item.vv().clone();
        n.past_cutoff_recomputed += 1;
        let stuck: Vec<String> = n.pending.iter().map(|o| o.dot().to_string()).collect();
        n.ev(format!(
            "recomputes the item without D{t}'s ops past {cut} (ADR 0012 §6): {}; left in the causal buffer [{}]",
            n.item.canon(),
            stuck.join(",")
        ));
        *self = n;
        true
    }

    /// Process a Fetch response: ADR 0012 §7 "Chain check after compaction", then absorb the
    /// covers, then deliver the bodies causally. Returns the merged snapshot written after a
    /// concurrent absorption, if any (answer 1).
    pub fn process_response(
        &mut self,
        resp: &Response,
        cfg: &Config,
        rng: Option<&mut XorShift>,
    ) -> Option<Snapshot> {
        self.keys.extend(resp.wraps.iter().copied());
        self.wraps_seen.extend(resp.wraps.iter().copied());
        // CRYPTO.md §11.6 reader rule: "An op under an unknown item key waits for its wrap". A
        // wrap can arrive without any new op (a later record carried it), so the ops waiting for
        // it are retried now.
        if !self.pending.is_empty() {
            self.drain_pending(cfg);
        }
        // Pass 1: the links of each chain up to the first break.
        let mut links: Vec<(Dev, Vec<Link>)> = Vec::new();
        let mut bodiless: Vec<Dot> = Vec::new();
        for (&dev, chain) in &resp.chains {
            if dev == self.id {
                continue;
            }
            let mut prev = self.cursor.get(dev);
            let mut ls = Vec::new();
            for (h, b) in chain {
                if h.dot.seq <= prev {
                    continue;
                }
                if let Some(&cut) = self.revocations.get(&dev)
                    && h.dot.seq > cut
                {
                    self.note(Notice::Rejected {
                        dot: h.dot,
                        why: "revoked device past cut-off",
                    });
                    break;
                }
                // Follow vault_prev_seq from the cursor: every link must be a received header.
                if h.prev != prev {
                    self.note(Notice::Gap { dev, seq: prev + 1 });
                    break;
                }
                if b.is_none() {
                    // "A header without a body counts only if a snapshot of that item, received
                    // now or already held, covers its dot." Pass 1 stops at a header that no
                    // served or held snapshot covers ("nothing past the gap is applied").
                    let ok = resp.covers.iter().any(|s| s.state.vv().covers(h.dot))
                        || self.held_snaps.iter().any(|v| v.covers(h.dot));
                    if !ok {
                        self.note(Notice::Gap {
                            dev,
                            seq: h.dot.seq,
                        });
                        break;
                    }
                    bodiless.push(h.dot);
                }
                // A verified signed header (answer 2 keeps it; answer 4's clamp reads it).
                self.headers.insert(h.dot, h.clone());
                ls.push((h.clone(), b.clone()));
                prev = h.dot.seq;
            }
            links.push((dev, ls));
        }
        // Answer 4 (evidence merge): the bodies of this response are verified op truth; their
        // kind (write or Purge, and a Purge's key_id) is known before any cover is absorbed, so the
        // contradiction checks see every body a cover could contradict.
        if cfg.evidence() {
            let bodies: Vec<Op> = links
                .iter()
                .flat_map(|(_, ls)| ls.iter())
                .filter_map(|(h, b)| {
                    b.as_ref().map(|b| Op {
                        h: h.clone(),
                        b: b.clone(),
                    })
                })
                .collect();
            for op in &bodies {
                self.learn_body(op);
            }
        }
        // AMBIGUOUS 12: covers are absorbed before the bodies are delivered, in the served order
        // (newest first, ADR 0021 §4), and only a cover of at least one bodiless header that
        // passed pass 1.
        for s in &resp.covers {
            if bodiless.iter().any(|d| s.state.vv().covers(*d)) {
                self.absorb(s, cfg);
            }
        }
        // Pass 2: a bodiless header counts only against a snapshot the replica accepted (absorbed,
        // dominated, or held from before). AMBIGUOUS 15: "received now" read as "received and
        // accepted": INV-27 "A gap is reported as missing data, never skipped".
        let mut bodies: Vec<Op> = Vec::new();
        for (dev, ls) in links {
            for (h, b) in ls {
                match b {
                    Some(b) => bodies.push(Op { h: h.clone(), b }),
                    None => {
                        if !self.held_snaps.iter().any(|v| v.covers(h.dot)) {
                            self.note(Notice::Gap {
                                dev,
                                seq: h.dot.seq,
                            });
                            break;
                        }
                    }
                }
                self.cursor.add(h.dot);
            }
        }
        if let Some(r) = rng {
            r.shuffle(&mut bodies);
            if !bodies.is_empty() && r.chance(30) {
                let i = r.below(bodies.len());
                let dup = bodies[i].clone();
                bodies.push(dup);
            }
        }
        for op in bodies {
            self.deliver(op, cfg);
        }
        // CRYPTO.md §11.6 reader rule: a wrap that arrived in this response's wrap set releases a
        // waiting op even when the response carries no new body for it.
        self.drain_pending(cfg);
        // Answer 5 (`chain_to_cutoff`): the revocation's last_accepted_device_seq is a signed bound
        // on the revoked device's chain; a chain that stops below it is missing data (INV-27).
        if cfg.chain_to_cutoff {
            let short: Vec<(Dev, Seq)> = self
                .revocations
                .iter()
                .filter(|&(&t, &cut)| t != self.id && self.cursor.get(t) < cut)
                .map(|(&t, _)| (t, self.cursor.get(t) + 1))
                .collect();
            for (dev, seq) in short {
                self.note(Notice::Gap { dev, seq });
            }
        }
        // AMBIGUOUS 21: no ADR trigger covers absorption; ADR 0021 "Settled by the merge spike"
        // asks "when a replica writes a merged snapshot". Literal: never.
        // Answer 1 (`MergedSnap::AfterConcurrent`): once the response's ops are delivered, a
        // replica that absorbed a concurrent snapshot writes a snapshot of the state it reached. It
        // is an ordinary snapshot: the writer rule and the ADR 0018 §10 oversize exception apply.
        if std::mem::take(&mut self.merge_due) {
            let s = self.write_snapshot(None, cfg);
            if s.is_some() {
                self.merged_written += 1;
                self.ev("writes the merged snapshot above (after a concurrent absorption)".into());
            }
            return s;
        }
        None
    }
}

/// Every value of a state with its key: current and history of a live item, late values of a
/// tombstone.
pub fn item_values(i: &Item) -> Vec<(Key, Entry)> {
    match i {
        Item::Live(l) => l
            .regs
            .iter()
            .chain(l.hist.iter())
            .flat_map(|(k, es)| es.iter().map(move |e| (*k, *e)))
            .collect(),
        Item::Tomb(t) => t
            .late
            .iter()
            .flat_map(|(k, es)| es.iter().map(move |e| (*k, *e)))
            .collect(),
    }
}

/// Build the dishonest state of a faulty snapshot. It still passes the ADR 0018 §5 checks
/// (asserted in `write_snapshot`).
pub fn apply_fault(
    state: &mut Item,
    f: Fault,
    author: Dev,
    key: KeyId,
    hdr: &Headers,
    n_hist: usize,
) {
    // The highest-ranked non-lifecycle current (live) or late (tombstone) value.
    let top = |regs: &crate::item::Regs| -> Option<(Key, Entry)> {
        let mut best: Option<(Key, Entry)> = None;
        for (k, es) in regs.iter() {
            if *k == LIFECYCLE {
                continue;
            }
            for e in es {
                if best.is_none_or(|(_, b)| e.rank() > b.rank()) {
                    best = Some((*k, *e));
                }
            }
        }
        best
    };
    match f {
        Fault::OmitValue => {
            let mut removed_key: Option<Key> = None;
            {
                let regs = match state {
                    Item::Live(l) => &mut l.regs,
                    Item::Tomb(t) => &mut t.late,
                };
                if let Some((k, e)) = top(regs)
                    && let Some(es) = regs.get_mut(k)
                {
                    es.retain(|x| x.dot != e.dot);
                    if es.is_empty() {
                        regs.remove(k);
                        removed_key = Some(k);
                    }
                }
            }
            if let (Some(k), Item::Live(l)) = (removed_key, state) {
                // ADR 0018 §5 rule 7: a history group needs its register; drop it too.
                l.hist.remove(k);
            }
        }
        Fault::OmitHist => {
            if let Item::Live(l) = state {
                let mut best: Option<(Key, Entry)> = None;
                for (k, es) in &l.hist {
                    for e in es {
                        if best.is_none_or(|(_, b)| e.rank() > b.rank()) {
                            best = Some((*k, *e));
                        }
                    }
                }
                if let Some((k, e)) = best
                    && let Some(es) = l.hist.get_mut(k)
                {
                    es.retain(|x| x.dot != e.dot);
                    if es.is_empty() {
                        l.hist.remove(k);
                    }
                }
            }
        }
        Fault::ClaimNext(d) => {
            let s = state.vv().get(d) + 1;
            state.vv_mut().add(Dot::new(d, s));
        }
        Fault::ClaimValue(d) => {
            let s = state.vv().get(d) + 1;
            let dot = Dot::new(d, s);
            let max_hlc = match &*state {
                Item::Live(l) => l.regs.values().chain(l.hist.values()).flatten(),
                Item::Tomb(t) => t.late.values().chain(t.late.values()).flatten(),
            }
            .map(|e| e.hlc)
            .max()
            .unwrap_or(0);
            let fake = Entry {
                dot,
                hlc: max_hlc + 1,
                val: 900 + d as u32,
            };
            state.vv_mut().add(dot);
            match state {
                Item::Live(l) => {
                    let old = l.regs.insert("a", vec![fake]).unwrap_or_default();
                    if !old.is_empty() {
                        let h = l.hist.entry("a").or_default();
                        h.extend(old);
                        crate::item::prune(h, n_hist);
                    }
                }
                Item::Tomb(t) => {
                    let r = t.late.entry("a").or_default();
                    r.push(fake);
                    r.sort_by_key(|e| e.dot);
                }
            }
        }
        Fault::AltHlc | Fault::AltKey => {
            let bump = if f == Fault::AltHlc { 1 } else { 0 };
            let regs = match state {
                Item::Live(l) => &mut l.regs,
                Item::Tomb(t) => &mut t.late,
            };
            if let Some((_, e)) = top(regs) {
                let z = regs.entry("z").or_default();
                if !z.iter().any(|x| x.dot == e.dot) {
                    z.push(Entry {
                        dot: e.dot,
                        hlc: e.hlc + bump,
                        val: e.val + 5000,
                    });
                    z.sort_by_key(|x| x.dot);
                }
            }
        }
        Fault::Resurrect => {
            if let Item::Live(l) = state {
                let mut best: Option<(Key, Entry)> = None;
                for (k, es) in &l.hist {
                    for e in es {
                        if best.is_none_or(|(_, b)| e.rank() > b.rank()) {
                            best = Some((*k, *e));
                        }
                    }
                }
                if let Some((k, e)) = best {
                    if let Some(es) = l.hist.get_mut(k) {
                        es.retain(|x| x.dot != e.dot);
                        if es.is_empty() {
                            l.hist.remove(k);
                        }
                    }
                    let r = l.regs.entry(k).or_default();
                    r.push(e);
                    r.sort_by_key(|x| x.dot);
                }
            }
        }
        Fault::FakeTomb => {
            if let Item::Live(l) = &*state {
                let mut best: Option<Entry> = None;
                for es in l.regs.values() {
                    for e in es {
                        if best.is_none_or(|b| e.rank() > b.rank()) {
                            best = Some(*e);
                        }
                    }
                }
                if let Some(b) = best {
                    let vv = l.vv.clone();
                    *state = Item::Tomb(crate::item::Tomb {
                        c: vv.clone(),
                        vv,
                        purge: crate::item::PurgeRec {
                            dot: b.dot,
                            hlc: b.hlc,
                            // The item key the author holds (its snapshot's envelope key).
                            key_id: key,
                        },
                        late: crate::item::Regs::new(),
                    });
                }
            }
        }
        Fault::FakeLive => {
            if let Item::Tomb(t) = &*state {
                let mut regs = t.late.clone();
                regs.insert(
                    LIFECYCLE,
                    vec![Entry {
                        dot: t.purge.dot,
                        hlc: t.purge.hlc,
                        val: crate::types::ACTIVE,
                    }],
                );
                *state = Item::Live(crate::item::Live {
                    vv: t.vv.clone(),
                    regs,
                    hist: crate::item::Regs::new(),
                });
            }
        }
        Fault::WrongKey => {
            if let Item::Tomb(t) = state {
                t.purge.key_id = KeyId::new(0x7fff, author, 0xfe);
            }
        }
        Fault::WidenC => {
            if let Item::Tomb(t) = state {
                t.c = t.vv.clone();
                t.late.clear();
            }
        }
        Fault::FakeTombSmart => {
            if let Item::Live(l) = &*state {
                let mut best: Option<Entry> = None;
                for es in l.regs.values() {
                    for e in es {
                        if best.is_none_or(|b| e.rank() > b.rank()) {
                            best = Some(*e);
                        }
                    }
                }
                if let Some(b) = best
                    && let Some(h) = hdr.get(&b.dot)
                {
                    let c = h.ctx.clone();
                    let mut late = crate::item::Regs::new();
                    for (k, es) in &l.regs {
                        if *k == LIFECYCLE {
                            continue;
                        }
                        let kept: Vec<Entry> = es
                            .iter()
                            .filter(|e| !c.covers(e.dot) && e.dot != b.dot)
                            .copied()
                            .collect();
                        if !kept.is_empty() {
                            late.insert(*k, kept);
                        }
                    }
                    *state = Item::Tomb(crate::item::Tomb {
                        vv: l.vv.clone(),
                        purge: crate::item::PurgeRec {
                            dot: b.dot,
                            hlc: b.hlc,
                            key_id: key,
                        },
                        c,
                        late,
                    });
                }
            }
        }
        Fault::WidenCSmart => {
            if let Item::Tomb(t) = state {
                let pick = hdr.iter().rev().find(|(d, h)| {
                    t.vv.covers(**d)
                        && **d != t.purge.dot
                        && t.late.values().flatten().any(|e| h.ctx.covers(e.dot))
                });
                if let Some((_, h)) = pick {
                    t.c.join(&h.ctx);
                    let c = t.c.clone();
                    crate::item::filter_covered(&mut t.late, &c);
                }
            }
        }
        Fault::LateAtPurge => {
            if let Item::Tomb(t) = state {
                let (dot, hlc) = (t.purge.dot, t.purge.hlc);
                if !t.c.covers(dot) {
                    let z = t.late.entry("z").or_default();
                    if !z.iter().any(|x| x.dot == dot) {
                        z.push(Entry { dot, hlc, val: 777 });
                        z.sort_by_key(|x| x.dot);
                    }
                }
            }
        }
    }
}
