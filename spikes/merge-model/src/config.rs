//! Model configuration: the knobs that pick one reading of an ambiguous ADR passage, or switch on
//! one of the spike's proposed rules. `literal` is the most literal reading everywhere; `README.md`
//! lists what each knob decides. `integrated` switches on every rule the five spike answers chose,
//! with their conflicts resolved (README "Results").

use crate::absorb::{AbsorbStrategy, DVV_JOIN, LITERAL_DOMINATE, LITERAL_REPLACE};

/// AMBIGUOUS 1: no ADR defines snapshot absorption (ADR 0018 "Settled by the merge spike" 1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AbsorbKind {
    LiteralReplace,
    LiteralDominate,
    DvvJoin,
    /// Answer 4 (faulty snapshots): the evidence merge (`item::em_join`) with the header clamp
    /// (`item::restrict`) and the contradiction checks of `Replica::absorb_evidence`. Ops merge by
    /// the same join, so an op whose dot a snapshot covered without its value is not skipped. On
    /// every honest state it equals the DVV join (answer 1) and ADR 0012 §4 step 3.
    Evidence,
}

/// When a replica writes a snapshot of the state it reached by absorbing (ADR 0021 "Settled by the
/// merge spike", first bullet: "when a replica writes a merged snapshot").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MergedSnap {
    /// AMBIGUOUS 21, literal: only the ADR 0012 §7 triggers and healing; the absorbed snapshot
    /// alone becomes the replica's "newest snapshot" (ADR 0012 §6, AMBIGUOUS 3).
    Never,
    /// Answer 1: after a Fetch in which the replica absorbed a snapshot whose covered VV was
    /// concurrent with its own, it writes a snapshot of the resulting state once the response's ops
    /// are applied (writer rule and oversize exception apply). Until then its "newest snapshot" is
    /// the pair of its previous newest snapshot and the absorbed one.
    AfterConcurrent,
}

/// What the author does to its own state when it re-issues an op after a stale-epoch rejection
/// (ADR 0012 §7 "Upload"; CRYPTO.md §11.6 writer rule).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReissueLocal {
    /// AMBIGUOUS 7, literal: the text says only "re-issues the edit with the same device_seq"; the
    /// author already applied the original op and changes nothing locally.
    Keep,
    /// Answer 3: the author holds the re-issued op in place of the original: its retained copy and,
    /// when the tombstone's recorded purge is that dot, `item_key_id`. No other state byte depends
    /// on the op's envelope (ADR 0018 §3-§4).
    Patch,
}

/// Which outbox ops a stale-epoch rejection re-issues (ADR 0012 §7: "re-issues the edit").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReissueScope {
    /// AMBIGUOUS 23, literal (the model's earlier reading): any stale-epoch rejection, of an op or
    /// of a snapshot, re-issues every outbox op written under an older epoch.
    Outbox,
    /// Answer 3: only the op the server rejected, with the later old-epoch ops of its chain. A
    /// stale answer to a snapshot only discards and rewrites that snapshot.
    OwnAnswer,
}

/// How the server answers an upload of a record it already stores (ADR 0012 §7 does not say).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UploadDedup {
    /// Literal: the checks in ADR 0012 §7's order and nothing else. A re-upload of a stored op
    /// fails the `vault_prev_seq` check; a re-uploaded snapshot is stored again.
    None,
    /// AMBIGUOUS 11 (the model's earlier reading, kept by every preset) and answer 3: a
    /// byte-identical re-upload is answered "already stored" before the `vault_prev_seq` and
    /// stale-epoch checks; a different record at a stored dot is a conflict and never replaces it.
    First,
}

/// What a device does when an upload of an own op that the server may already have stored once
/// comes back "stale epoch" (ADR 0012 §7 "Upload": "re-issues the edit ..., which the server never
/// stored"). Answers 2 and 3 disagree here; `integrated` takes the combination (README Results).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StaleSent {
    /// AMBIGUOUS 22, literal: re-issued like any stale op ("which the server never stored" does
    /// not cover an op stored before a restore, or one whose response was lost).
    Reissue,
    /// Answer 2 (restore healing, point 5): an op sent before without an answer is never
    /// re-issued; it is re-published like healing step 4 (its header without the body, covered by
    /// a fresh snapshot under the new key, in one healing request). Falls back to the re-issue
    /// when no snapshot can be written (oversize item).
    Republish,
    /// Combination of answers 2 and 3: only an op the server may have stored *and served* is
    /// re-published as in `Republish`: one it acknowledged, or one whose upload response was lost
    /// before the server's restore generation changed (answer 3's condition). Any other stale op is
    /// re-issued (answer 3), since "not stored" is then authoritative.
    RepublishGen,
}

/// Which VV "Healing a server rollback" and "Leaving read-only" compare (ADR 0012 §7; ADR 0021
/// "Settled by the merge spike").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RollbackCmp {
    /// AMBIGUOUS 5, literal ("a VV behind its own"): the device's item VV against the server's
    /// per-device heads. The device's own entry uses the highest seq the server acknowledged.
    ItemVv,
    /// The device's fetch cursor against heads.
    Cursor,
    /// Answer 2: either (under the rule an item VV never exceeds the cursor, so both agree).
    Both,
}

/// What a read-only device re-publishes in healing step 4 ("Its ops, and a fresh signed snapshot
/// of each affected item", ADR 0012 §7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HealOps {
    /// AMBIGUOUS 4, literal: "its ops" = the device's own ops.
    Own,
    /// The earlier candidate: own ops and every retained op of other devices.
    AllRetained,
    /// Answer 2: one atomic healing request holding, in chain order per device, every signed op
    /// header the device holds above the server's head, each without its body when the request's
    /// fresh snapshot covers it, then the fresh snapshot (`world.rs` `heal_headers`).
    Headers,
}

/// What the server does with a snapshot whose covered VV claims dots above its heads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SnapClaims {
    /// ADR 0021 §5, literal: stored; the clamped VV limits its cover.
    Store,
    /// Answer 2 with the resolution of its conflict with answer 5: refused outside a healing
    /// request that first stores the headers it claims; a revoked device's entry counts only up to
    /// its `last_accepted_device_seq` (the server never holds more of it).
    RefuseUnheld,
    /// Answer 2 as written: every entry above the head counts, a revoked device's too.
    RefuseUnheldStrict,
}

/// The server's compaction rule (ADR 0021 §3-§4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerRule {
    /// ADR 0021 as written.
    Adr0021,
    /// Answer 4: R1 also needs retained covers by two different authors; R3 keeps an older
    /// snapshot while dropping it would leave a bodiless header covered by fewer than two authors;
    /// Fetch serves covers by two authors for each bodiless header.
    TwoAuthors,
    /// No compaction (the "without server compaction" case).
    None,
}

/// How a client treats a verified snapshot whose author is revoked (ADR 0021 open question 5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevokedSnap {
    /// The model's earlier behaviour (not an ADR reading): the author's revocation is not checked.
    AcceptAll,
    /// AMBIGUOUS 17, literal: ADR 0012 §4 step 1's exception is for ops with a `device_seq`; a
    /// snapshot has none, so a revoked author's snapshot is rejected.
    Reject,
    /// Answer 5 (ADR 0021 open question 5, recommendation): accepted when its covered entry for
    /// its author is at most that device's `last_accepted_device_seq`.
    AcceptIfCovered,
}

/// ADR 0012 §6: "the replica removes the op and recomputes the item from its retained ops and
/// snapshots. If it cannot, it flags the item for the user."
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PastCutoff {
    /// The model's earlier behaviour: flag only (the recomputation not modelled).
    Flag,
    /// ADR 0012 §6 as written (answer 5 models it): remove and recompute from the newest snapshot
    /// state plus the retained ops; flag when the newest snapshot already contains such an op.
    Recompute,
}

/// Which fault kinds the random faulty flavors draw from (`--faults`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultFilter {
    All,
    /// Omission, claims, header- and body-detectable fabrication.
    Decidable,
    /// Only the "undetectable fabrication" class.
    Undetectable,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub name: String,
    /// ADR 0012 §5 history N (50 in the ADR; small here so pruning is exercised).
    pub n_hist: usize,
    // Absorption (answers 1 and 4).
    pub absorb: AbsorbKind,
    pub merged_snapshot: MergedSnap,
    /// Answer 1: absorbing a snapshot is an HLC receipt (ADR 0012 §2 "on receipt"): the clock
    /// receives the highest HLC the (taken part of the) snapshot carries, under the skew guard.
    /// False is the literal reading (a snapshot header has no HLC).
    pub hlc_on_absorb: bool,
    // Re-issue (answer 3).
    pub reissue_local: ReissueLocal,
    /// Answer 3: on re-issue, discard unsent snapshots that cover a re-issued op (they embed the
    /// original); the writer rule's snapshot replaces them.
    pub drop_covering_snaps: bool,
    pub reissue_scope: ReissueScope,
    /// AMBIGUOUS 24 (literal: false, the wrap stays where it was). Answer 3: after a re-issue, the
    /// first op under one of this device's fresh keys whose wrap the server does not hold carries
    /// the wrap, and later unsent ops under it drop it.
    pub reissue_moves_wrap: bool,
    pub upload_dedup: UploadDedup,
    pub stale_sent: StaleSent,
    // Restore healing (answer 2).
    pub rollback_cmp: RollbackCmp,
    pub heal_ops: HealOps,
    /// Answer 2 (H1b): before the atomic request, re-publish per device chain every op whose body
    /// the healer holds and which the server stored before, verbatim; a refusal stops that chain.
    pub heal_bodies_first: bool,
    /// Resolution of answers 2 and 4 (README Results): in the healing request a header goes with
    /// its body whenever the healer holds the body of a record the server stored before, and an
    /// own op never acknowledged takes the normal upload path unless it `must_republish`. False is
    /// answer 2 as written: without its body whenever the fresh snapshot covers it.
    pub heal_prefer_bodies: bool,
    /// Answer 2: a record re-published verbatim in a healing request, and a bodiless header, are
    /// exempt from the stale-epoch check.
    pub heal_stale_exempt: bool,
    pub snap_claims: SnapClaims,
    /// Answer 2: the server is also "behind" when it lacks an item-key wrap the device knows it
    /// held (received from it, or uploaded and acknowledged).
    pub detect_wraps: bool,
    /// AMBIGUOUS 3: ADR 0012 §6 "Clients keep each item's ops since its newest snapshot" (literal:
    /// false) versus keeping every own op so healing step 4 can re-upload "its ops" (true).
    pub keep_own_ops: bool,
    // Faulty snapshots (answer 4).
    pub server_rule: ServerRule,
    // Revocation (answer 5).
    pub revoked_snap: RevokedSnap,
    pub past_cutoff: PastCutoff,
    /// Answer 5: the server refuses a snapshot whose covered entry for its own author is above the
    /// author's head (implied by `SnapClaims::RefuseUnheld`).
    pub snap_author_head: bool,
    /// Answer 5: the stale-epoch check does not apply to an op of a revoked device with
    /// `device_seq <= last_accepted_device_seq`, whoever uploads it.
    pub stale_exempt_revoked: bool,
    /// Answer 5: after a complete Fetch, a device whose cursor for a revoked device is below that
    /// device's `last_accepted_device_seq` reports missing data from it (INV-27).
    pub chain_to_cutoff: bool,
    // Triggers and limits.
    /// ADR 0012 §7 / ADR 0018 §10 trigger: a snapshot after a purge.
    pub snapshot_on_purge: bool,
    /// ADR 0012 §7 trigger: more than 32 ops since the last snapshot.
    pub snapshot_after_ops: usize,
    /// ADR 0018 §10, scaled down: the most values a register, history group or late register may
    /// hold before the item is *oversize* (256 in the ADR). None = no limit (set per scenario).
    pub max_values: Option<usize>,
    /// Random explorer: which fault kinds the faulty flavors draw.
    pub faults: FaultFilter,
}

pub const PRESETS: &[&str] = &[
    "literal",
    "literal-dominate",
    "join",
    "candidate",
    "integrated",
];

impl Config {
    pub fn preset(name: &str, n_hist: usize) -> Option<Config> {
        let base = Config {
            name: "literal".into(),
            n_hist,
            absorb: AbsorbKind::LiteralReplace,
            merged_snapshot: MergedSnap::Never,
            hlc_on_absorb: false,
            reissue_local: ReissueLocal::Keep,
            drop_covering_snaps: false,
            reissue_scope: ReissueScope::Outbox,
            reissue_moves_wrap: false,
            upload_dedup: UploadDedup::First,
            stale_sent: StaleSent::Reissue,
            rollback_cmp: RollbackCmp::ItemVv,
            heal_ops: HealOps::Own,
            heal_bodies_first: false,
            heal_prefer_bodies: false,
            heal_stale_exempt: false,
            snap_claims: SnapClaims::Store,
            detect_wraps: false,
            keep_own_ops: false,
            server_rule: ServerRule::Adr0021,
            revoked_snap: RevokedSnap::AcceptAll,
            past_cutoff: PastCutoff::Flag,
            snap_author_head: false,
            stale_exempt_revoked: false,
            chain_to_cutoff: false,
            snapshot_on_purge: true,
            snapshot_after_ops: 32,
            max_values: None,
            faults: FaultFilter::All,
        };
        Some(match name {
            "literal" => base,
            "literal-dominate" => Config {
                name: name.into(),
                absorb: AbsorbKind::LiteralDominate,
                ..base
            },
            // Literal everywhere except absorption: isolates the join.
            "join" => Config {
                name: name.into(),
                absorb: AbsorbKind::DvvJoin,
                ..base
            },
            // The model's earlier candidate knobs (before the five answers).
            "candidate" => Config {
                name: name.into(),
                absorb: AbsorbKind::DvvJoin,
                reissue_local: ReissueLocal::Patch,
                drop_covering_snaps: true,
                rollback_cmp: RollbackCmp::Cursor,
                heal_ops: HealOps::AllRetained,
                keep_own_ops: true,
                ..base
            },
            // Every rule the five answers chose, conflicts resolved (README "Results").
            "integrated" => Config {
                name: name.into(),
                absorb: AbsorbKind::Evidence,
                merged_snapshot: MergedSnap::AfterConcurrent,
                hlc_on_absorb: true,
                reissue_local: ReissueLocal::Patch,
                drop_covering_snaps: true,
                reissue_scope: ReissueScope::OwnAnswer,
                reissue_moves_wrap: true,
                upload_dedup: UploadDedup::First,
                stale_sent: StaleSent::RepublishGen,
                rollback_cmp: RollbackCmp::Both,
                heal_ops: HealOps::Headers,
                heal_bodies_first: true,
                heal_prefer_bodies: true,
                heal_stale_exempt: true,
                snap_claims: SnapClaims::RefuseUnheld,
                detect_wraps: true,
                keep_own_ops: false,
                server_rule: ServerRule::TwoAuthors,
                revoked_snap: RevokedSnap::AcceptIfCovered,
                past_cutoff: PastCutoff::Recompute,
                snap_author_head: true,
                stale_exempt_revoked: true,
                chain_to_cutoff: true,
                ..base
            },
            _ => return None,
        })
    }

    /// Override one knob (`--set key=value`), to isolate one rule inside a preset. Returns false
    /// for an unknown key or value.
    pub fn set(&mut self, key: &str, val: &str) -> bool {
        let yes = match val {
            "yes" | "on" | "true" => Some(true),
            "no" | "off" | "false" => Some(false),
            _ => None,
        };
        match (key, val) {
            ("absorb", "replace") => self.absorb = AbsorbKind::LiteralReplace,
            ("absorb", "dominate") => self.absorb = AbsorbKind::LiteralDominate,
            ("absorb", "join") => self.absorb = AbsorbKind::DvvJoin,
            ("absorb", "evidence") => self.absorb = AbsorbKind::Evidence,
            ("merged", _) if yes.is_some() => {
                self.merged_snapshot = if yes == Some(true) {
                    MergedSnap::AfterConcurrent
                } else {
                    MergedSnap::Never
                }
            }
            ("hlc-absorb", _) if yes.is_some() => self.hlc_on_absorb = yes == Some(true),
            ("reissue", "keep") => self.reissue_local = ReissueLocal::Keep,
            ("reissue", "patch") => self.reissue_local = ReissueLocal::Patch,
            ("snapdrop", _) if yes.is_some() => self.drop_covering_snaps = yes == Some(true),
            ("scope", "outbox") => self.reissue_scope = ReissueScope::Outbox,
            ("scope", "own") => self.reissue_scope = ReissueScope::OwnAnswer,
            ("movewrap", _) if yes.is_some() => self.reissue_moves_wrap = yes == Some(true),
            ("dedup", "none") => self.upload_dedup = UploadDedup::None,
            ("dedup", "first") => self.upload_dedup = UploadDedup::First,
            ("stale-sent", "reissue") => self.stale_sent = StaleSent::Reissue,
            ("stale-sent", "republish") => self.stale_sent = StaleSent::Republish,
            ("stale-sent", "gen") => self.stale_sent = StaleSent::RepublishGen,
            ("cmp", "itemvv") => self.rollback_cmp = RollbackCmp::ItemVv,
            ("cmp", "cursor") => self.rollback_cmp = RollbackCmp::Cursor,
            ("cmp", "both") => self.rollback_cmp = RollbackCmp::Both,
            ("heal", "own") => self.heal_ops = HealOps::Own,
            ("heal", "retained") => self.heal_ops = HealOps::AllRetained,
            ("heal", "headers") => self.heal_ops = HealOps::Headers,
            ("bodies", _) if yes.is_some() => self.heal_bodies_first = yes == Some(true),
            ("bodyfirst", _) if yes.is_some() => self.heal_prefer_bodies = yes == Some(true),
            ("exempt", _) if yes.is_some() => self.heal_stale_exempt = yes == Some(true),
            ("claims", "store") => self.snap_claims = SnapClaims::Store,
            ("claims", "refuse") => self.snap_claims = SnapClaims::RefuseUnheld,
            ("claims", "refuse-strict") => self.snap_claims = SnapClaims::RefuseUnheldStrict,
            ("wraps", _) if yes.is_some() => self.detect_wraps = yes == Some(true),
            ("keepown", _) if yes.is_some() => self.keep_own_ops = yes == Some(true),
            ("server", "adr") => self.server_rule = ServerRule::Adr0021,
            ("server", "2a") => self.server_rule = ServerRule::TwoAuthors,
            ("server", "none") => self.server_rule = ServerRule::None,
            ("revoked-snap", "all") => self.revoked_snap = RevokedSnap::AcceptAll,
            ("revoked-snap", "reject") => self.revoked_snap = RevokedSnap::Reject,
            ("revoked-snap", "covered") => self.revoked_snap = RevokedSnap::AcceptIfCovered,
            ("past-cutoff", "flag") => self.past_cutoff = PastCutoff::Flag,
            ("past-cutoff", "recompute") => self.past_cutoff = PastCutoff::Recompute,
            ("author-head", _) if yes.is_some() => self.snap_author_head = yes == Some(true),
            ("exempt-revoked", _) if yes.is_some() => self.stale_exempt_revoked = yes == Some(true),
            ("chain-cutoff", _) if yes.is_some() => self.chain_to_cutoff = yes == Some(true),
            ("faults", "all") => self.faults = FaultFilter::All,
            ("faults", "decidable") => self.faults = FaultFilter::Decidable,
            ("faults", "undetectable") => self.faults = FaultFilter::Undetectable,
            _ => return false,
        }
        self.name = format!("{}+{key}={val}", self.name);
        true
    }

    pub fn strategy(&self) -> &'static dyn AbsorbStrategy {
        match self.absorb {
            AbsorbKind::LiteralReplace => &LITERAL_REPLACE,
            AbsorbKind::LiteralDominate => &LITERAL_DOMINATE,
            AbsorbKind::DvvJoin | AbsorbKind::Evidence => &DVV_JOIN,
        }
    }

    pub fn evidence(&self) -> bool {
        self.absorb == AbsorbKind::Evidence
    }
}
