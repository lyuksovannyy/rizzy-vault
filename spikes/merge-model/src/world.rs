//! The simulated system: devices, the server, the scenario actions and the quiescence drain.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::config::{Config, HealOps, RollbackCmp, SnapClaims};
use crate::replica::{Edit, Fault, Notice, Out, Replica, Snapshot, Status};
use crate::rng::XorShift;
use crate::server::{HealRec, Server, UpRes};
use crate::types::{Dev, Dot, Header, Key, Op, Seq, Val};

/// One scenario step. Device actors take device actions; the server actor takes server actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Act {
    // Local device actions (they touch only the device's own state).
    Write(Vec<(Key, Val)>),
    Trash,
    Restore,
    Purge,
    Snapshot,
    Faulty(Fault),
    // Communicating device actions.
    Upload,
    /// Upload only the snapshots in the outbox, before the ops they cover (ADR 0021 §8 "a
    /// snapshot uploaded before ops it covers"; ADR 0012 §7 fixes the order of ops only).
    UploadSnaps,
    /// Upload only the first outbox record and process its response (a stale-epoch rejection
    /// re-issues the outbox but uploads nothing more), so that a later `SyncLost` can lose the
    /// response to the re-issued version.
    UploadOnce,
    Fetch,
    Sync,
    /// Upload, but every response is lost (the device keeps its outbox).
    SyncLost,
    /// Standard rotation by this device (CRYPTO.md §11.6), with the ADR 0012 §6 cut-off.
    Rotate,
    /// Two-phase revocation of the named device by this device (ADR 0012 §6).
    Revoke(Dev),
    /// The device is gone for good.
    Lose,
    // Server actions (a server action in a device's program runs as the server; a scenario uses
    // it to fix the order of, say, a revocation and a restore).
    Worker,
    Checkpoint(u8),
    RestoreServer(u8),
}

impl Act {
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Act::Write(_) | Act::Trash | Act::Restore | Act::Purge | Act::Snapshot | Act::Faulty(_)
        )
    }

    pub fn is_server(&self) -> bool {
        matches!(
            self,
            Act::Worker | Act::Checkpoint(_) | Act::RestoreServer(_)
        )
    }

    pub fn describe(&self) -> String {
        match self {
            Act::Write(ws) => {
                let s: Vec<String> = ws.iter().map(|(k, v)| format!("{k}={v}")).collect();
                format!("Write{{{}}}", s.join(","))
            }
            Act::Faulty(f) => format!("FaultySnapshot({f:?})"),
            Act::Revoke(d) => format!("Revoke(D{d})"),
            Act::Checkpoint(i) => format!("Checkpoint({i})"),
            Act::RestoreServer(i) => format!("RestoreServer({i})"),
            other => format!("{other:?}"),
        }
    }
}

pub fn actor_name(actor: usize, n_dev: usize) -> String {
    if actor == n_dev {
        "S".to_string()
    } else {
        format!("D{actor}")
    }
}

#[derive(Clone, Debug)]
pub struct World {
    pub cfg: Config,
    pub devs: Vec<Replica>,
    pub server: Server,
    pub checkpoints: BTreeMap<u8, Server>,
    /// Latest version of every op ever authored.
    pub authored: BTreeMap<Dot, Op>,
    /// Pre-re-issue versions of re-issued ops.
    pub originals: BTreeMap<Dot, Op>,
    /// Dots the server stored at some point (P2 universe, see check.rs).
    pub ever_stored: BTreeSet<Dot>,
    /// The version of each op the server stored last (what receivers get; after a restore and a
    /// re-issue it can differ from the version stored before the restore).
    pub stored_version: BTreeMap<Dot, Op>,
    /// Dots stored in two different signed versions over time (FORK).
    pub second_versions: BTreeSet<Dot>,
    /// Ops stored with a body although their epoch was stale, through an exemption (answer 2's
    /// verbatim re-publication, answer 5's revoked author): `republished_stored` for dots stored
    /// before (the intended case), `stale_exposed` for dots never stored before (KEY: content under
    /// a pre-rotation item key that the writer rule would have re-encrypted, CRYPTO.md §11.6).
    pub republished_stored: u64,
    pub stale_exposed: BTreeSet<Dot>,
    /// Re-uploads answered "already stored", and conflicts at a stored dot (coverage).
    pub already_stored: u64,
    pub conflicts: u64,
    pub stored_snaps: BTreeSet<(Dev, u32)>,
    pub snaps: Vec<Snapshot>,
    /// Seeded delivery shuffles and duplicates (random explorer only).
    pub rng: Option<XorShift>,
    /// The quiescence drain stopped at its round cap instead of reaching a fixed point.
    pub drain_capped: bool,
    /// Server restores executed (coverage).
    pub restores: u64,
    /// A Fetch served a header a healing request stored without its body with covers written only
    /// by devices that had written a faulty snapshot (the conflict of answers 2 and 4).
    pub faulty_sole_cover_served: bool,
    pub rec: bool,
    pub events: Vec<String>,
}

impl World {
    pub fn new(cfg: Config, n_dev: usize, skew: &[u64]) -> Self {
        let devs = (0..n_dev)
            .map(|i| Replica::new(i as Dev, skew.get(i).copied().unwrap_or(0)))
            .collect();
        let server = Server {
            rule: cfg.server_rule,
            dedup: cfg.upload_dedup,
            refuse_unheld_claims: cfg.snap_claims != SnapClaims::Store,
            claims_cap_at_cutoff: cfg.snap_claims != SnapClaims::RefuseUnheldStrict,
            author_head: cfg.snap_author_head,
            stale_exempt_revoked: cfg.stale_exempt_revoked,
            ..Server::default()
        };
        World {
            cfg,
            devs,
            server,
            checkpoints: BTreeMap::new(),
            authored: BTreeMap::new(),
            originals: BTreeMap::new(),
            ever_stored: BTreeSet::new(),
            stored_version: BTreeMap::new(),
            second_versions: BTreeSet::new(),
            republished_stored: 0,
            stale_exposed: BTreeSet::new(),
            already_stored: 0,
            conflicts: 0,
            stored_snaps: BTreeSet::new(),
            snaps: Vec::new(),
            rng: None,
            drain_capped: false,
            restores: 0,
            faulty_sole_cover_served: false,
            rec: false,
            events: Vec::new(),
        }
    }

    pub fn set_rec(&mut self, on: bool) {
        self.rec = on;
        for d in &mut self.devs {
            d.rec = on;
        }
    }

    fn ev(&mut self, s: String) {
        if self.rec {
            self.events.push(s);
        }
    }

    fn collect_events(&mut self) {
        if self.rec {
            for d in &mut self.devs {
                self.events.append(&mut d.events);
            }
        }
    }

    pub fn exec(&mut self, actor: usize, act: &Act) {
        let n = self.devs.len();
        if actor < n && act.is_server() {
            self.exec(n, act);
            return;
        }
        if actor == n {
            match act {
                Act::Worker => {
                    self.server.compact();
                    let snaps: Vec<String> = self
                        .server
                        .snaps
                        .iter()
                        .map(|s| format!("{}#{} clamped={}", s.snap.name(), s.store_seq, s.clamped))
                        .collect();
                    let bodiless: Vec<String> = self
                        .server
                        .ops
                        .iter()
                        .filter(|(_, o)| o.b.is_none())
                        .map(|(d, _)| d.to_string())
                        .collect();
                    self.ev(format!(
                        "S worker: retained [{}], bodiless [{}]",
                        snaps.join(", "),
                        bodiless.join(",")
                    ));
                }
                Act::Checkpoint(i) => {
                    self.checkpoints.insert(*i, self.server.clone());
                    self.ev(format!("S checkpoint {i}"));
                }
                Act::RestoreServer(i) => {
                    if let Some(cp) = self.checkpoints.get(i) {
                        // ADR 0021 §2: a restore keeps the stored values and sets the counter above
                        // the restored maximum (the restored clock already is).
                        let mut restored = cp.clone();
                        restored.violations = std::mem::take(&mut self.server.violations);
                        restored.stats = std::mem::take(&mut self.server.stats);
                        // Answer 3's restore generation goes above any value the server held.
                        restored.restore_gen = self.server.restore_gen.max(cp.restore_gen) + 1;
                        self.server = restored;
                        self.restores += 1;
                        self.ev(format!("S restored from checkpoint {i}"));
                    }
                }
                _ => {}
            }
            self.server.check_props(false);
            return;
        }
        if self.devs[actor].status != Status::Active {
            return;
        }
        self.devs[actor].ticks += 1;
        let cfg = self.cfg.clone();
        match act {
            Act::Write(_) | Act::Trash | Act::Restore | Act::Purge => {
                let e = match act {
                    Act::Write(ws) => Edit::Write(ws.clone()),
                    Act::Trash => Edit::Trash,
                    Act::Restore => Edit::Restore,
                    _ => Edit::Purge,
                };
                match self.devs[actor].author(&e, &cfg) {
                    Ok((op, snap)) => {
                        self.authored.insert(op.dot(), op);
                        if let Some(s) = snap {
                            self.snaps.push(s);
                        }
                    }
                    Err(why) => {
                        let s = format!("D{actor} skips {}: {why}", act.describe());
                        self.ev(s);
                    }
                }
            }
            Act::Snapshot => {
                if let Some(s) = self.devs[actor].write_snapshot(None, &cfg) {
                    self.snaps.push(s);
                }
            }
            Act::Faulty(f) => {
                if let Some(s) = self.devs[actor].write_snapshot(Some(*f), &cfg) {
                    self.snaps.push(s);
                }
            }
            Act::Upload => self.upload(actor, false),
            Act::UploadOnce => self.upload_n(actor, false, Some(1)),
            Act::UploadSnaps => {
                // The snapshots go first; the ops stay queued, in order, behind them.
                let dev = &mut self.devs[actor];
                let (snaps, ops): (Vec<Out>, Vec<Out>) = dev
                    .outbox
                    .drain(..)
                    .partition(|o| matches!(o, Out::Snap(_)));
                let n_snaps = snaps.len();
                dev.outbox.extend(snaps);
                dev.outbox.extend(ops);
                self.upload_n(actor, false, Some(n_snaps));
            }
            Act::Fetch => self.fetch(actor),
            Act::Sync => {
                self.upload(actor, false);
                self.fetch(actor);
            }
            Act::SyncLost => self.upload(actor, true),
            Act::Rotate => {
                if !self.devs[actor].read_only {
                    // ADR 0012 §6 "The same cut-off applies to every rotation": the rotating device
                    // fetches, then the request carries its cursor.
                    self.fetch(actor);
                    if let Some(why) = self.rotation_refused(actor) {
                        self.ev(format!("D{actor} rotation refused: {why}"));
                        self.collect_events();
                        return;
                    }
                    self.server.epoch += 1;
                    self.server.state_seq += 1;
                    let (e, s) = (self.server.epoch, self.server.state_seq);
                    let d = &mut self.devs[actor];
                    d.known_epoch = e;
                    d.state_seq = s;
                    self.ev(format!("D{actor} rotates: vault epoch -> {e}"));
                }
            }
            Act::Revoke(t) => {
                let t = *t;
                // MODEL: a lost device is revoked like any other (the usual case for a stolen
                // device).
                if (t as usize) < n
                    && t as usize != actor
                    && matches!(self.devs[t as usize].status, Status::Active | Status::Lost)
                {
                    // MODEL: the revoker syncs first (unlock, fresh re-authentication; CRYPTO.md
                    // §11.8 step 0), so a device behind a restored server heals before it suspends
                    // anyone, and a read-only device starts no revocation.
                    self.fetch(actor);
                    if self.devs[actor].read_only {
                        self.ev(format!("D{actor} skips Revoke(D{t}): read-only"));
                        self.collect_events();
                        return;
                    }
                    // Phase 1: suspend; H = the highest device_seq the server holds from t.
                    self.server.suspended.insert(t);
                    let h = self.server.head(t);
                    // Phase 2: the revoker fetches up to H, then revocation + account-state +
                    // rotation in one request (H is still the head: t is suspended).
                    self.fetch(actor);
                    if let Some(why) = self.rotation_refused(actor) {
                        self.server.suspended.remove(&t);
                        self.ev(format!("D{actor} skips Revoke(D{t}): {why}"));
                        self.collect_events();
                        return;
                    }
                    self.server.revocations.insert(t, h);
                    self.server.epoch += 1;
                    self.server.state_seq += 1;
                    let (e, s) = (self.server.epoch, self.server.state_seq);
                    let d = &mut self.devs[actor];
                    d.known_epoch = e;
                    d.state_seq = s;
                    if !d.learn_revocation(t, h, &cfg) {
                        d.note(Notice::PastCutoff { dev: t, cut: h });
                    }
                    self.devs[t as usize].status = Status::Revoked;
                    self.ev(format!(
                        "D{actor} revokes D{t} with last_accepted_device_seq={h}; epoch -> {e}"
                    ));
                }
            }
            Act::Lose => {
                self.devs[actor].status = Status::Lost;
                self.ev(format!("D{actor} is lost"));
            }
            Act::Worker | Act::Checkpoint(_) | Act::RestoreServer(_) => {}
        }
        self.collect_events();
        self.server.check_props(false);
    }

    /// ADR 0012 §6: "under the account lock the server refuses the rotation while it holds any op
    /// ... in a rotated vault beyond that cursor" (the rotating device's fetch cursor; its own
    /// chain is not fetched, AMBIGUOUS 13). A read-only device writes no account-state
    /// (ADR 0012 §7 healing, CRYPTO.md §11.3). Snapshots beyond the cursor are ADR 0021 open
    /// question 6 and not checked.
    fn rotation_refused(&self, d: usize) -> Option<&'static str> {
        let dev = &self.devs[d];
        if dev.read_only {
            return Some("read-only");
        }
        let beyond = self
            .server
            .ops
            .keys()
            .any(|dot| dot.dev != dev.id && dot.seq > dev.cursor.get(dot.dev));
        beyond.then_some("the server holds ops beyond the rotating device's cursor (ADR 0012 §6)")
    }

    /// The version of `h.dot` whose signed header is `h` (the latest authored one, or the
    /// pre-re-issue original).
    fn version_of(&self, h: &Header) -> Option<Op> {
        self.authored
            .get(&h.dot)
            .filter(|o| o.h == *h)
            .or_else(|| self.originals.get(&h.dot).filter(|o| o.h == *h))
            .cloned()
    }

    /// Bookkeeping for a newly stored op: the version receivers get, a second signed version of
    /// one dot (FORK), and a stale-epoch body accepted through an exemption (KEY when never stored
    /// before).
    fn note_stored(&mut self, op: &Op, with_body: bool, epoch_then: u32) {
        let dot = op.dot();
        if with_body && op.h.epoch < epoch_then {
            if self.ever_stored.contains(&dot) {
                self.republished_stored += 1;
            } else {
                self.stale_exposed.insert(dot);
            }
        }
        if let Some(prev) = self.stored_version.get(&dot)
            && prev != op
        {
            self.second_versions.insert(dot);
        }
        self.stored_version.insert(dot, op.clone());
        self.ever_stored.insert(dot);
    }

    /// Upload the outbox in order (ADR 0012 §7 "A device uploads its ops in device_seq order").
    pub fn upload(&mut self, d: usize, lost: bool) {
        self.upload_n(d, lost, None);
    }

    /// `upload`, stopping after `limit` records (and right after a stale-epoch answer when
    /// limited).
    pub fn upload_n(&mut self, d: usize, lost: bool, limit: Option<usize>) {
        let cfg = self.cfg.clone();
        // A lost-response upload: the client sends its outbox and learns nothing back, so every op
        // in it may or may not have been stored. Recorded after the sends.
        let lost_attempt: Option<(u64, Vec<Seq>)> = lost.then(|| {
            let seqs = self.devs[d]
                .outbox
                .iter()
                .filter_map(|o| match o {
                    Out::Op(op) => Some(op.dot().seq),
                    Out::Snap(_) => None,
                })
                .collect();
            (self.server.restore_gen, seqs)
        });
        let mut idx = 0usize;
        for (sent, _guard) in (0..200).enumerate() {
            if limit.is_some_and(|l| sent >= l) {
                break;
            }
            // A fresh key's wrap that left with a dropped or refused record goes with the next
            // record uploaded under that key (CRYPTO.md §11.6).
            {
                let dev = &mut self.devs[d];
                let pos = if lost { idx } else { 0 };
                if let Some(o) = dev.outbox.get_mut(pos) {
                    let (key, wrap) = match o {
                        Out::Op(op) => (op.b.key_id, &mut op.b.wrap),
                        Out::Snap(s) => (s.key_id, &mut s.wrap),
                    };
                    if wrap.is_none() && dev.orphan_wraps.remove(&key) {
                        *wrap = Some(key);
                    }
                }
            }
            let item = if lost {
                self.devs[d].outbox.get(idx).cloned()
            } else {
                self.devs[d].outbox.front().cloned()
            };
            let Some(out) = item else { break };
            let id = self.devs[d].id;
            let epoch_then = self.server.epoch;
            let res = match &out {
                Out::Op(op) => self.server.upload_op(op, id),
                Out::Snap(s) => self.server.upload_snap(s, id),
            };
            let what = match &out {
                Out::Op(op) => format!("op {}", op.dot()),
                Out::Snap(s) => s.name(),
            };
            if self.rec {
                let lost_s = if lost { " (response lost)" } else { "" };
                self.events
                    .push(format!("D{d} uploads {what}: {res:?}{lost_s}"));
            }
            match res {
                UpRes::Stored | UpRes::AlreadyStored => {
                    match &out {
                        Out::Op(op) => {
                            if res == UpRes::Stored {
                                self.note_stored(op, true, epoch_then);
                            } else {
                                self.already_stored += 1;
                                self.ever_stored.insert(op.dot());
                            }
                        }
                        Out::Snap(s) => {
                            self.stored_snaps.insert(s.id);
                        }
                    }
                    if lost {
                        idx += 1;
                    } else {
                        self.devs[d].outbox.pop_front();
                        let dev = &mut self.devs[d];
                        match &out {
                            Out::Op(op) => {
                                dev.acked_self = dev.acked_self.max(op.dot().seq);
                                if let Some(k) = op.b.wrap {
                                    dev.wraps_stored.insert(k);
                                    dev.wraps_seen.insert(k);
                                }
                            }
                            Out::Snap(s) => {
                                if let Some(k) = s.wrap {
                                    dev.wraps_seen.insert(k);
                                }
                            }
                        }
                    }
                }
                UpRes::Stale => {
                    if lost {
                        // The response is lost: the client learns nothing; it retries later.
                        break;
                    }
                    // "The client then processes the new account-state, applies the writer rule
                    // and re-issues the edit with the same device_seq".
                    let (e, s) = (self.server.epoch, self.server.state_seq);
                    let rgen = self.server.restore_gen;
                    {
                        let dev = &mut self.devs[d];
                        dev.known_epoch = dev.known_epoch.max(e);
                        dev.state_seq = dev.state_seq.max(s);
                    }
                    let rejected = match &out {
                        Out::Op(op) => Some(op.dot()),
                        Out::Snap(_) => None,
                    };
                    let mut force = false;
                    // Answers 2 and 3 (`StaleSent`): an op the server may have stored and served
                    // is re-published like healing step 4, not re-issued.
                    if let Some(dot) = rejected
                        && self.devs[d].must_republish(dot.seq, &cfg, rgen)
                    {
                        self.ev(format!(
                            "D{d}: {what} may have been stored and served before: re-published, not re-issued"
                        ));
                        let before = self.devs[d].outbox.len();
                        self.heal_headers(d);
                        self.collect_events();
                        if self.devs[d].outbox.len() < before {
                            idx = 0;
                            if limit.is_some() {
                                break;
                            }
                            continue;
                        }
                        // No snapshot can cover it (an oversize item) or the request was refused:
                        // fall back to the re-issue.
                        force = true;
                    }
                    let dev = &mut self.devs[d];
                    let (pairs, snap) = dev.reissue_outbox(&cfg, rgen, rejected, force);
                    for (old, new) in pairs {
                        self.originals.entry(old.dot()).or_insert(old);
                        self.authored.insert(new.dot(), new);
                    }
                    // Ops the re-issue re-signed without re-issuing them (a wrap moved off them).
                    let outbox_ops: Vec<Op> = self.devs[d]
                        .outbox
                        .iter()
                        .filter_map(|o| match o {
                            Out::Op(op) => Some(op.clone()),
                            Out::Snap(_) => None,
                        })
                        .collect();
                    for op in outbox_ops {
                        self.authored.insert(op.dot(), op);
                    }
                    if let Some(s) = snap {
                        self.snaps.push(s);
                    }
                    self.collect_events();
                    idx = 0;
                    if limit.is_some() {
                        break;
                    }
                }
                UpRes::PrevSeq(_) => {
                    if let Out::Op(op) = &out {
                        self.devs[d].note(Notice::UploadBlocked {
                            dot: op.dot(),
                            why: "vault_prev_seq is not the server's head",
                        });
                    }
                    break;
                }
                UpRes::Conflict => {
                    // AMBIGUOUS 11: the ADRs define no answer for a different record at a stored
                    // dot; the client reports it and drops its own version from the outbox.
                    self.conflicts += 1;
                    if let Out::Op(op) = &out {
                        self.devs[d].note(Notice::UploadConflict { dot: op.dot() });
                    }
                    if lost {
                        idx += 1;
                    } else {
                        self.devs[d].outbox.pop_front();
                        // The dropped record may have carried a fresh key's wrap: move it on.
                        if let Out::Op(op) = &out
                            && let Some(k) = op.b.wrap
                        {
                            self.devs[d].reattach_wrap(k);
                        }
                    }
                }
                UpRes::Refused(why) => match &out {
                    Out::Op(op) => {
                        self.devs[d].note(Notice::UploadBlocked { dot: op.dot(), why });
                        break;
                    }
                    // A snapshot refused for what it claims (answer 2's unheld claims, answer 5's
                    // author head) is dropped: the client learns the answer and writes a new one on
                    // the next trigger. Other refusals (a suspended or revoked uploader) stop the
                    // upload.
                    Out::Snap(sn) if why.starts_with("snapshot claims") => {
                        self.devs[d].note(Notice::SnapRefused { why });
                        if lost {
                            idx += 1;
                        } else {
                            self.devs[d].outbox.pop_front();
                            if let Some(k) = sn.wrap {
                                self.devs[d].reattach_wrap(k);
                            }
                        }
                    }
                    Out::Snap(_) => break,
                },
            }
        }
        if let Some((rgen, seqs)) = lost_attempt {
            // Keep the earliest attempt's generation: a restore after *any* lost attempt means the
            // op may have been stored and served, then rolled back.
            let dev = &mut self.devs[d];
            for q in seqs {
                dev.lost_uploads.entry(q).or_insert(rgen);
            }
        }
        self.collect_events();
    }

    /// Is the server behind this device's accepted state (ADR 0012 §7 "Healing a server rollback")?
    pub fn server_behind(&self, d: usize) -> bool {
        let dev = &self.devs[d];
        if self.server.state_seq < dev.state_seq {
            return true;
        }
        let own_behind = self.server.head(dev.id) < dev.acked_self;
        // An op past a revocation cut-off the device knows is refused by every honest server and
        // replica (ADR 0012 §6), so it never makes the server "behind".
        let cap = |x: Dev, s: Seq| dev.revocations.get(&x).map_or(s, |&c| s.min(c));
        let item_vv = || {
            dev.item
                .vv()
                .0
                .iter()
                .any(|(&x, &s)| x != dev.id && self.server.head(x) < cap(x, s))
        };
        let cursor = || {
            dev.cursor
                .0
                .iter()
                .any(|(&x, &s)| x != dev.id && self.server.head(x) < cap(x, s))
        };
        let others = match self.cfg.rollback_cmp {
            RollbackCmp::ItemVv => item_vv(),
            RollbackCmp::Cursor => cursor(),
            // Answer 2: either.
            RollbackCmp::Both => item_vv() || cursor(),
        };
        // Answer 2 (`detect_wraps`): ADR 0012 §7 lists "item-key wraps from rotations" among what
        // a restore rolls back; no VV shows a lost wrap.
        let wraps = self.cfg.detect_wraps
            && dev
                .wraps_seen
                .iter()
                .any(|k| !self.server.wraps.contains(k));
        own_behind || others || wraps
    }

    /// ADR 0012 §7 "Fetch", with rollback detection and healing first.
    pub fn fetch(&mut self, d: usize) {
        let cfg = self.cfg.clone();
        {
            let (se, ss) = (self.server.epoch, self.server.state_seq);
            let revs = self.server.revocations.clone();
            let dev = &mut self.devs[d];
            // Process the served account-state unless it is older than the accepted one.
            if ss >= dev.state_seq {
                dev.known_epoch = dev.known_epoch.max(se);
                dev.state_seq = ss;
                for (t, h) in revs {
                    // ADR 0012 §6: "Only a misbehaving server can make a replica hold an op past
                    // the cut-off. If that happens, the replica removes the op and recomputes the
                    // item from its retained ops and snapshots. If it cannot, it flags the item
                    // for the user." `Config::past_cutoff` picks flag-only or the recomputation.
                    if !dev.learn_revocation(t, h, &cfg) {
                        dev.note(Notice::PastCutoff { dev: t, cut: h });
                    }
                }
            }
        }
        if self.server_behind(d) {
            if !self.devs[d].read_only {
                self.devs[d].read_only = true;
                self.devs[d].note(Notice::ReadOnly);
            }
            self.heal(d);
        }
        let cursor = self.devs[d].cursor.clone();
        let id = self.devs[d].id;
        let resp = self.server.fetch(&cursor, id);
        if !self.faulty_sole_cover_served {
            let faulty: BTreeSet<Dev> = self
                .snaps
                .iter()
                .filter(|s| !s.honest)
                .map(|s| s.author)
                .collect();
            let healed_bodiless = resp.chains.values().flatten().any(|(h, b)| {
                b.is_none()
                    && self.server.stored_bodiless.contains(&h.dot)
                    && resp
                        .covers
                        .iter()
                        .filter(|c| c.state.vv().covers(h.dot))
                        .all(|c| faulty.contains(&c.author))
            });
            if healed_bodiless && !faulty.is_empty() {
                self.faulty_sole_cover_served = true;
            }
        }
        if self.rec {
            let mut s = String::new();
            for chain in resp.chains.values() {
                for (h, b) in chain {
                    let _ = write!(
                        s,
                        "{}{} ",
                        h.dot,
                        if b.is_some() { "" } else { "(bodiless)" }
                    );
                }
            }
            let covers: Vec<String> = resp
                .covers
                .iter()
                .map(|c| format!("{} vv={}", c.name(), c.state.vv()))
                .collect();
            self.events.push(format!(
                "D{d} fetches from cursor {cursor}: [{}] covers [{}]",
                s.trim(),
                covers.join(", ")
            ));
        }
        let merged = {
            let World { devs, rng, .. } = self;
            devs[d].process_response(&resp, &cfg, rng.as_mut())
        };
        if let Some(s) = merged {
            self.snaps.push(s);
        }
        if self.devs[d].read_only && !self.server_behind(d) {
            self.devs[d].read_only = false;
            self.ev(format!("D{d} leaves read-only"));
        }
        self.collect_events();
    }

    /// ADR 0012 §7 "Healing a server rollback": a read-only device re-publishes its account-state
    /// and revocations (step 2), its key wraps (step 3), then its ops and a fresh signed snapshot
    /// of the affected item (step 4).
    fn heal(&mut self, d: usize) {
        let cfg = self.cfg.clone();
        let id = self.devs[d].id;
        {
            let dev = &self.devs[d];
            self.server.epoch = self.server.epoch.max(dev.known_epoch);
            self.server.state_seq = self.server.state_seq.max(dev.state_seq);
            for (&t, &h) in &dev.revocations {
                self.server.revocations.insert(t, h);
                self.server.suspended.insert(t);
            }
            self.server.wraps.extend(dev.keys.iter().copied());
        }
        if cfg.heal_ops == HealOps::Headers {
            self.heal_headers(d);
            self.collect_events();
            self.upload(d, false);
            return;
        }
        // Step 4: its own ops beyond the server's head go to the front of the outbox, in chain
        // order; `upload` applies the usual checks.
        // AMBIGUOUS 6: steps run in the ADR's order (the account-state first), and nothing exempts a
        // re-published op from the stale-epoch check, so an op written before a rotation that the
        // restore rolled back comes back "stale" and is re-issued under a new key.
        let head = self.server.head(id);
        let own = self.devs[d].own_ops_held(&cfg);
        let in_outbox: BTreeSet<Seq> = self.devs[d]
            .outbox
            .iter()
            .filter_map(|o| {
                if let Out::Op(op) = o {
                    Some(op.dot().seq)
                } else {
                    None
                }
            })
            .collect();
        let missing: Vec<Op> = own
            .range(head + 1..)
            .filter(|(s, _)| !in_outbox.contains(s))
            .map(|(_, o)| o.clone())
            .collect();
        if self.rec && !missing.is_empty() {
            let m: Vec<String> = missing.iter().map(|o| o.dot().to_string()).collect();
            self.events.push(format!(
                "D{d} heals: re-publishes own ops [{}]",
                m.join(",")
            ));
        }
        for op in missing.into_iter().rev() {
            self.devs[d].outbox.push_front(Out::Op(op));
        }
        if cfg.heal_ops == HealOps::AllRetained {
            let others: BTreeMap<Dot, Op> = self.devs[d]
                .retained
                .iter()
                .filter(|o| o.dot().dev != id)
                .map(|o| (o.dot(), o.clone()))
                .collect();
            let mut blocked: BTreeSet<Dev> = BTreeSet::new();
            for (dot, op) in others {
                if blocked.contains(&dot.dev) || dot.seq <= self.server.head(dot.dev) {
                    continue;
                }
                let epoch_then = self.server.epoch;
                match self.server.upload_op(&op, id) {
                    r @ (UpRes::Stored | UpRes::AlreadyStored) => {
                        if r == UpRes::Stored {
                            self.note_stored(&op, true, epoch_then);
                        }
                        self.ever_stored.insert(dot);
                        self.ev(format!("D{d} heals: re-publishes {dot}"));
                    }
                    r => {
                        blocked.insert(dot.dev);
                        let why = match r {
                            UpRes::Stale => "stale epoch (cannot re-issue another device's op)",
                            UpRes::PrevSeq(_) => "chain gap on the server",
                            _ => "refused",
                        };
                        self.devs[d].note(Notice::HealBlocked { dot, why });
                    }
                }
            }
        }
        let vv = self.devs[d].item.vv().clone();
        if self.devs[d].last_heal_vv.as_ref() != Some(&vv) {
            self.devs[d].last_heal_vv = Some(vv);
            if let Some(s) = self.devs[d].write_snapshot(None, &cfg) {
                self.snaps.push(s);
            }
        }
        self.collect_events();
        self.upload(d, false);
    }

    /// Answer 2, healing step 4 ("Its ops, and a fresh signed snapshot of each affected item",
    /// ADR 0012 §7) as one atomic healing request (`Server::heal_request`):
    /// - for each device, every signed op header the healer holds above the server's head, in
    ///   chain order (its own chain up to its last op; another device's up to its fetch cursor);
    /// - without its body when the fresh snapshot covers it (no ciphertext under a stale key is
    ///   re-sent, so the stale-epoch check has nothing to check and nothing is re-issued);
    /// - otherwise with its body, re-published verbatim, or without it when a held snapshot that
    ///   covers it goes in the request too (an oversize item, ADR 0018 §10 and open question 12);
    /// - an own op the server never acknowledged and no snapshot covers stays in the outbox and
    ///   takes the normal upload path (it may be a new edit: ADR 0012 §7 "Upload" re-issue);
    /// - then the held snapshots needed as covers, verbatim, and the fresh snapshot.
    ///
    /// On success the device drops from its outbox the own ops the request stored and the unsent
    /// snapshots the fresh one dominates. On refusal nothing is stored, the fresh snapshot is not
    /// kept, and the device stays read-only and retries at its next fetch.
    fn heal_headers(&mut self, d: usize) {
        let cfg = self.cfg.clone();
        let id = self.devs[d].id;
        if cfg.heal_bodies_first {
            self.heal_bodies(d);
        }
        let saved = self.devs[d].clone();
        // The fresh snapshot; `write_snapshot` refuses an oversize item (ADR 0018 §10) and, under
        // the evidence merge, an item with an unresolved dispute.
        let fresh = self.devs[d].write_snapshot(None, &cfg);
        if fresh.is_some() {
            // It goes in the healing request, not through the outbox.
            self.devs[d].outbox.pop_back();
        }
        let dev = &self.devs[d];
        let mut recs: Vec<HealRec> = Vec::new();
        let mut covers: Vec<Snapshot> = Vec::new();
        let mut blocked: Vec<(Dot, &'static str)> = Vec::new();
        // Own never-acknowledged ops left to the normal upload path (`heal_prefer_bodies`).
        let mut own_left: Option<Seq> = None;
        let chains: BTreeSet<Dev> = dev.headers.keys().map(|k| k.dev).collect();
        for x in chains {
            // Answer 2: capped at the device's known revocation cut-off (an op past it is refused
            // by every honest replica and server, ADR 0012 §6).
            let hi = if x == id {
                dev.next_seq - 1
            } else {
                dev.cursor.get(x)
            };
            let hi = dev.revocations.get(&x).map_or(hi, |&c| hi.min(c));
            for seq in self.server.head(x) + 1..=hi {
                let dot = Dot::new(x, seq);
                let Some(h) = dev.headers.get(&dot) else {
                    blocked.push((dot, "header not held"));
                    break;
                };
                let own_unacked = x == id && seq > dev.acked_self;
                // Resolution of answers 2 and 4 (`heal_prefer_bodies`): a header goes with its
                // body whenever the healer holds the body of a record the server stored before
                // (verbatim), and an own op never acknowledged goes the normal upload path unless
                // the server may have stored and served it (`must_republish`). A header then goes
                // without its body only when no body is left to send, so the healer's snapshot is
                // the only cover only where it is the only record left.
                if cfg.heal_prefer_bodies {
                    if !own_unacked {
                        if let Some(op) = dev.body_of(dot, &cfg) {
                            recs.push(HealRec::Op(h.clone(), Some(op.b)));
                            continue;
                        }
                    } else if !dev.must_republish(seq, &cfg, self.server.restore_gen) {
                        own_left = Some(seq);
                        break;
                    }
                }
                if fresh.as_ref().is_some_and(|f| f.state.vv().covers(dot)) {
                    recs.push(HealRec::Op(h.clone(), None));
                    continue;
                }
                if own_unacked {
                    // Possibly never stored: a new edit, left to the normal upload path.
                    break;
                }
                if let Some(op) = dev.body_of(dot, &cfg) {
                    recs.push(HealRec::Op(h.clone(), Some(op.b)));
                    continue;
                }
                if let Some(s) = dev
                    .held_records
                    .iter()
                    .rev()
                    .find(|s| s.state.vv().covers(dot))
                {
                    if !covers.iter().any(|c| c.id == s.id) {
                        covers.push(s.clone());
                    }
                    recs.push(HealRec::Op(h.clone(), None));
                    continue;
                }
                blocked.push((dot, "neither the body nor a covering snapshot is held"));
                break;
            }
        }
        for (dot, why) in blocked {
            self.devs[d].note(Notice::HealBlocked { dot, why });
        }
        let mut fresh = fresh;
        if cfg.heal_prefer_bodies
            && let Some(f) = fresh.take()
        {
            let needs_cover = recs.iter().any(|r| matches!(r, HealRec::Op(_, None)));
            if !needs_cover {
                // Nothing in the request needs a cover: the fresh snapshot takes the normal upload
                // path, after the own ops it covers (it would claim them unheld otherwise).
                self.snaps.push(f.clone());
                self.devs[d].outbox.push_back(Out::Snap(f));
            } else {
                // A bodiless header needs the fresh snapshot, which also covers the own ops left
                // to the normal path: those go without their bodies too (answer 2 as written).
                if let Some(from) = own_left {
                    let dev = &self.devs[d];
                    for seq in from..dev.next_seq {
                        if let Some(h) = dev.headers.get(&Dot::new(id, seq))
                            && f.state.vv().covers(h.dot)
                        {
                            recs.push(HealRec::Op(h.clone(), None));
                        }
                    }
                }
                fresh = Some(f);
            }
        }
        let n_verbatim = covers.len() as u64;
        // Healing step 3 inside the request: every item-key wrap the healer holds that the server
        // lacks (a bodiless header no longer carries the wrap its body carried).
        let wraps: Vec<HealRec> = self.devs[d]
            .keys
            .iter()
            .filter(|k| !self.server.wraps.contains(k))
            .map(|k| HealRec::Wrap(*k))
            .collect();
        if !recs.is_empty() || !covers.is_empty() || fresh.is_some() {
            recs.splice(0..0, wraps);
        }
        recs.extend(covers.iter().cloned().map(HealRec::Snap));
        if let Some(f) = &fresh {
            recs.push(HealRec::Snap(f.clone()));
        }
        if recs.is_empty() {
            return;
        }
        if self.rec {
            let names: Vec<String> = recs
                .iter()
                .map(|r| match r {
                    HealRec::Op(h, b) => {
                        format!("{}{}", h.dot, if b.is_none() { "(bodiless)" } else { "" })
                    }
                    HealRec::Snap(s) => format!("{} vv={}", s.name(), s.state.vv()),
                    HealRec::Wrap(k) => format!("wrap {k}"),
                })
                .collect();
            self.events
                .push(format!("D{d} heals: request [{}]", names.join(", ")));
        }
        let epoch_then = self.server.epoch;
        let held_before: BTreeSet<Dot> = recs
            .iter()
            .filter_map(|r| match r {
                HealRec::Op(h, _) if self.server.ops.contains_key(&h.dot) => Some(h.dot),
                _ => None,
            })
            .collect();
        match self.server.heal_request(&recs, id, cfg.heal_stale_exempt) {
            Ok(_) => {
                self.server.stats.heal_verbatim_snaps += n_verbatim;
                for r in &recs {
                    match r {
                        HealRec::Op(h, b) => {
                            if !held_before.contains(&h.dot) {
                                let v = match b {
                                    Some(b) => Some(Op {
                                        h: h.clone(),
                                        b: b.clone(),
                                    }),
                                    None => self.version_of(h),
                                };
                                match v {
                                    Some(op) => self.note_stored(&op, b.is_some(), epoch_then),
                                    None => {
                                        self.ever_stored.insert(h.dot);
                                    }
                                }
                            }
                        }
                        HealRec::Snap(s) => {
                            self.stored_snaps.insert(s.id);
                        }
                        HealRec::Wrap(k) => {
                            self.devs[d].wraps_seen.insert(*k);
                        }
                    }
                }
                let fvv = fresh.as_ref().map(|f| f.state.vv().clone());
                if let Some(f) = fresh {
                    self.snaps.push(f);
                }
                let head = self.server.head(id);
                let dev = &mut self.devs[d];
                dev.acked_self = dev.acked_self.max(head);
                dev.outbox.retain(|o| match o {
                    Out::Op(op) => op.dot().seq > head,
                    Out::Snap(s) => {
                        !(s.honest && fvv.as_ref().is_some_and(|v| s.state.vv().leq(v)))
                    }
                });
                self.ev(format!("D{d} heals: request stored"));
            }
            Err((i, res)) => {
                self.devs[d] = saved;
                let dot = match recs.get(i) {
                    Some(HealRec::Op(h, _)) => h.dot,
                    _ => Dot::new(id, 0),
                };
                let why = match res {
                    UpRes::Stale => "healing request refused: stale epoch",
                    UpRes::PrevSeq(_) => "healing request refused: chain gap on the server",
                    UpRes::Conflict => {
                        "healing request refused: a different record at a stored dot"
                    }
                    UpRes::Refused(w) => w,
                    _ => "healing request refused",
                };
                self.devs[d].note(Notice::HealBlocked { dot, why });
            }
        }
    }

    /// Answer 2 (H1b), first phase: per device chain, in chain order from the server's head, every
    /// op the healer holds with its body and that the server stored before (another device's op up
    /// to the fetch cursor, or an own op up to the highest acknowledged seq), re-published verbatim
    /// (ADR 0012 §7 "Who may upload"). A refusal stops that chain only; the atomic request
    /// (`heal_headers`) carries what remains.
    fn heal_bodies(&mut self, d: usize) {
        let cfg = self.cfg.clone();
        let id = self.devs[d].id;
        let chains: BTreeSet<Dev> = self.devs[d].headers.keys().map(|k| k.dev).collect();
        for x in chains {
            let hi = if x == id {
                self.devs[d].acked_self
            } else {
                self.devs[d].cursor.get(x)
            };
            let hi = self.devs[d].revocations.get(&x).map_or(hi, |&c| hi.min(c));
            for seq in self.server.head(x) + 1..=hi {
                let dot = Dot::new(x, seq);
                let Some(op) = self.devs[d].body_of(dot, &cfg) else {
                    break;
                };
                let epoch_then = self.server.epoch;
                let res = self.server.heal_request(
                    &[HealRec::Op(op.h.clone(), Some(op.b.clone()))],
                    id,
                    cfg.heal_stale_exempt,
                );
                match res {
                    Ok(_) => {
                        self.note_stored(&op, true, epoch_then);
                        self.ev(format!("D{d} heals: re-publishes {dot} with its body"));
                    }
                    Err((_, r)) => {
                        let why = match r {
                            UpRes::Refused(w) => w,
                            UpRes::Stale => "stale epoch",
                            _ => "refused",
                        };
                        self.devs[d].note(Notice::HealBlocked { dot, why });
                        break;
                    }
                }
            }
        }
    }

    /// Quiescence: every active device syncs and `worker` runs, until nothing changes.
    pub fn drain(&mut self) {
        self.drain_capped = true;
        for _ in 0..40 {
            let before = self.fingerprint();
            for d in 0..self.devs.len() {
                if self.devs[d].status == Status::Active {
                    self.upload(d, false);
                    self.fetch(d);
                }
            }
            self.server.compact();
            if self.fingerprint() == before {
                self.drain_capped = false;
                break;
            }
        }
    }

    pub fn fingerprint(&self) -> String {
        let mut s = String::new();
        for d in &self.devs {
            let _ = write!(
                s,
                "{}|{}|{}|{}|{}|{}|{};",
                d.item.canon(),
                d.outbox.len(),
                d.pending.len(),
                d.cursor,
                d.read_only,
                d.keys.len(),
                d.known_epoch
            );
        }
        let bodiless = self.server.ops.values().filter(|o| o.b.is_none()).count();
        let _ = write!(
            s,
            "{}|{}|{}|{}|{}",
            self.server.ops.len(),
            bodiless,
            self.server.snaps.len(),
            self.server.epoch,
            self.server.state_seq
        );
        s
    }
}
