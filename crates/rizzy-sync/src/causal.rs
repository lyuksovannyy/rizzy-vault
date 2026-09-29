//! The per-device chains of one vault, as a client sees them: causal delivery, deduplication
//! and gap detection, cursors and acknowledgements, and the revocation cut-off ([ADR 0012] §4
//! steps 1–2, §6, §7; [ADR 0021] §4, §9; CRYPTO.md §10.2 rule (c), §11.8 step 4; threat model
//! INV-27).
//!
//! # What this layer decides
//!
//! A [`VaultLog`] holds, for one vault and one device (the *own* device), every signed op
//! header it accepted or wrote, per authoring device in chain order, and the version vector of
//! what it has settled per item. It decides:
//!
//! - which served headers extend each device's chain, following `vault_prev_seq` from the
//!   cursor, and where a chain has a gap (ADR 0012 §7 "Chain check after compaction");
//! - which covers of a Fetch response the client absorbs, and the most the merge may take of
//!   each (ADR 0021 §4; ADR 0018 §3 "Snapshots are claims": a replica absorbs a snapshot only
//!   as the cover of a bodiless header, cut to the op headers it has verified);
//! - which verified op bodies are deliverable, and in what order (ADR 0012 §4 step 2), and
//!   which are duplicates (step 3 as replaced by ADR 0018 §3 "Covered ops");
//! - what is missing or held, after a complete Fetch (INV-27, ADR 0021 §9 "Revoked and kind-4
//!   authors");
//! - the own chain's upload bookkeeping: acknowledgements, "already stored", and which ops a
//!   stale-epoch answer re-issues or re-publishes ([`own`]; ADR 0021 §2 "Restore generation",
//!   §9 "Already stored", "Stale epoch");
//! - whether the server is behind this device ([`behind`]; ADR 0021 §9 "Server behind");
//! - the author checks of ADR 0012 §4 step 1 that read only a header and the author's signed
//!   statements ([`author`]; CRYPTO.md §10.2 rule (c), §11.8 step 4).
//!
//! It never sees decrypted data: its inputs are parsed headers ([`OpHeader`],
//! [`SnapshotHeader`]), dots, version vectors and HLCs, and a verdict per body that the client
//! reached through `rizzy-core`. Everything here is server-visible metadata (ADR 0012 §11 as
//! replaced by ADR 0022 §2), so the types derive `Debug`.
//!
//! # Output boundary
//!
//! The per-item merge (module `merge`: registers, history, tombstones and snapshot absorption,
//! ADR 0012 §4 steps 4–5, ADR 0018 §3) is another module. This layer hands the client a batch
//! of [`Delivery`] values, in the order the merge must apply them; the client looks up each
//! verified body by its dot and applies it. When the merge absorbs a cover, it takes at most
//! [`CoverPlan::cut_of`] of its covered VV, and the client reports what it took with
//! [`VaultLog::record_absorbed`], which records no more than that cut. The ADR 0012 §6
//! recomputation after a revocation, and the choice of what a merge takes from a snapshot within
//! the cut, are the merge's.
//!
//! # The client's cycle
//!
//! For each Fetch response of the vault, or each page of it (ADR 0021 §4: "Each page of a paged
//! response carries its own covers"):
//!
//! 1. **Verify** (the client, through `rizzy-core`; ADR 0012 §4 step 1): each served header's
//!    `op` signature under its author's certificate, [`check_op_author`], then the body, if
//!    served, against the signed hash, its decryption with the commitment check, and its
//!    record parse (ADR 0018 §5). The verdict is a [`BodyStatus`]. A header that fails
//!    verification is left out; the chain check then reports the gap it leaves. Each cover's
//!    `snapshot` signature under its author's certificate, and [`check_snapshot_author`] with
//!    the author's bound (for a revoked author [`VaultLog::cutoff`], for a kind-4 author the
//!    [`author`] module's bound; CRYPTO.md §11.8 step 4, ADR 0021 §9 "Revoked and kind-4
//!    authors"). A cover that fails is left out. [`VaultLog::plan_covers`] checks the cut-offs
//!    it knows again and refuses such a cover ([`CoverPlan::refused`]).
//! 2. **Plan** ([`VaultLog::plan_covers`]): the first pass of the chain check, with the
//!    response's covers counting; it names the covers to absorb and the cut.
//! 3. **Absorb** (the merge): each named cover, cut to [`CoverPlan::cut_of`];
//!    [`VaultLog::record_absorbed`] for each one the merge accepted.
//! 4. **Commit** ([`VaultLog::commit`]): the second pass, in which a bodiless header counts only
//!    against a snapshot the replica accepted; links are accepted, the cursor advances, and
//!    gaps, duplicates and rejections are reported.
//! 5. **Deliver** ([`VaultLog::take_deliveries`]): the ops to apply now, in order.
//!
//! Later, when a waiting body becomes verifiable (its item key's wrap arrives, CRYPTO.md §11.6
//! reader rule), [`VaultLog::body_verified`] or [`VaultLog::body_rejected`], then
//! [`VaultLog::take_deliveries`] again. After the last page of a Fetch:
//! [`VaultLog::complete_fetch_reports`] and [`VaultLog::waiting`]. The Fetch request carries
//! [`VaultLog::cursor`].
//!
//! # Terms
//!
//! - **Chain** of device d: d's op headers in this vault, linked by `vault_prev_seq` (ADR 0012
//!   §2). `device_seq` counts d's ops in every vault, so a chain's seqs are increasing but need
//!   not be consecutive; the link, not seq − 1, names the predecessor.
//! - **Link:** a header this log accepted into its chain. Links are accepted only in chain
//!   order from the head, so the accepted links of a chain are a prefix of it.
//! - **Head:** the `device_seq` of the chain's last link, 0 if none.
//! - **Cursor entry:** the head, unless a link's body was rejected after it was accepted and no
//!   snapshot covers it yet; then the link before that one, so that the next Fetch serves the
//!   rejected link again (reading 8). The cursor sent with a Fetch is every entry, the own
//!   device's included (ADR 0012 §7 "Fetch": "the highest `device_seq` it has per device").
//! - **Settled VV** of an item: the join of the dots of the ops delivered on it and the parts
//!   of absorbed snapshots the merge took ([`VaultLog::record_absorbed`]), each cut to the
//!   chains' links (reading 7). It is the item VV of ADR 0012 §2 as this layer knows it; the
//!   merge keeps its own and the two agree when the client reports every absorption.
//! - **Settled link:** delivered, or its dot is covered by its item's settled VV (its effect is
//!   in the item through a snapshot).
//! - **Frontier:** a chain's first unsettled link; every link before it is settled.
//!
//! # Rules
//!
//! **Chain check** ([`VaultLog::commit`], ADR 0012 §7 "Chain check after compaction", INV-27).
//! Per device, in `device_seq` order from the head:
//! - a header at or below the head is a duplicate if it equals the held link, otherwise an
//!   equivocation (two signed versions of one chain); neither is applied. The exception is a
//!   held link whose body was rejected and that no snapshot covers: served again, it takes the
//!   new verdict on its body, or counts behind a cover (reading 8);
//! - a header of a revoked device past its cut-off is rejected and ends the chain
//!   (ADR 0012 §4 step 1; CRYPTO.md §11.8 step 4);
//! - a header whose `vault_prev_seq` is not the head is a gap: "Every link must be a received
//!   header";
//! - a bodiless header counts only if a snapshot of that item covers its dot, else it is a gap;
//! - "nothing past the gap is applied": a chain's walk stops at its first gap, and the cursor
//!   stays before it, so the next Fetch asks again. A cover's part past a gap is never
//!   recorded (reading 7).
//!
//! **Causal delivery** ([`VaultLog::take_deliveries`], ADR 0012 §4 step 2). An op with a
//! verified body is delivered fresh when every earlier link of its chain is settled and its
//! item's settled VV covers its causal context; its dot then joins the settled VV. An op whose
//! dot the settled VV already covers (through an absorbed snapshot) is delivered at once,
//! marked [`Delivery::covered`], because "the op body still merges" (ADR 0018 §3 "Covered
//! ops", owner decision 14). A body already delivered is never delivered again: "a body already
//! merged changes nothing".
//!
//! **Revocation** ([`VaultLog::learn_revocation`]). Held links past the cut-off are rejected
//! and never delivered. An item whose settled VV already holds the device past its cut-off is
//! reported, not repaired: "Only a misbehaving server can make a replica hold an op past the
//! cut-off, and a revocation signed on a restored server whose head for the device is below ops
//! some replica applied counts as one: detected and reported, not converged" (ADR 0021 §9
//! "Restored-server revocation"). ADR 0012 §6's "the replica removes the op and recomputes the
//! item … If it cannot, it flags the item" stays binding and is the merge's. A cover whose
//! covered-VV entry for its revoked author is above the cut-off is refused (CRYPTO.md §11.8
//! step 4).
//!
//! # Readings
//!
//! Where the specs leave a choice, this layer takes the one the merge spike
//! (`spikes/merge-model`, `integrated` preset) implements, or says why not:
//!
//! 1. **"Hold the op until … its `vault_prev_seq` has been applied"** (ADR 0012 §4 step 2) is
//!    read transitively: every earlier link of the chain is settled, not only the one
//!    `vault_prev_seq` names. ADR 0018 §11 says a parked record makes "later ops of that device
//!    in that vault wait too", and INV-27 that "nothing from that device past the gap is
//!    applied". With one item, as in the spike (`replica.rs` `drain_pending`, which compares the
//!    item VV's entry for the author with `vault_prev_seq`), both readings agree; they differ
//!    only when a snapshot of one item covers a later link while an earlier link on another item
//!    waits.
//! 2. **"Applied"** includes "covered by an absorbed snapshot": the spike releases an op whose
//!    item VV covers its predecessors whether they came as ops or inside a snapshot, and a
//!    covered op at once (`vv.covers(p.dot()) || …`).
//! 3. **Covers to absorb** are those that cover a bodiless header that passed the first pass,
//!    in served order (spike AMBIGUOUS 12); the second pass counts a bodiless header only
//!    against a snapshot the replica accepted, "received now" read as "received and accepted"
//!    (AMBIGUOUS 15).
//! 4. **A body that fails verification** is rejected and reported (ADR 0012 §4 step 1), and its
//!    header, which verified, is then treated as a bodiless header: it counts only if a
//!    snapshot of its item covers it. No spec or spike text covers a served body that fails
//!    while its header verifies.
//! 5. **The own chain** is never taken from a response (spike AMBIGUOUS 13: "a device has every
//!    op it wrote"). A served own header above the own head is reported as
//!    [`Report::UnknownOwnOp`], a report no spec names.
//! 6. **Equivocation.** A served header at or below the head that differs from the held link,
//!    or names a seq the chain skipped, is reported ([`Report::Equivocation`]). The spike counts
//!    the same condition as a failure (its FORK check: "no dot was stored in two signed
//!    versions"), and no spec names a report for it. Only header fields are compared: the body
//!    and wrap hashes and the signature are the client's to compare.
//! 7. **The cut** of ADR 0018 §3 ("It cuts the covered VV to the op headers it has verified")
//!    is, per device, the chain's head or its last header that passed the first pass,
//!    whichever is higher ([`CoverPlan::cut`]): the spike's `absorb_evidence` cuts to the heads
//!    of `self.headers`, into which its pass 1 inserts only the headers before each chain's
//!    first gap. Headers past a gap verify too, but taking them would apply ops past the gap
//!    (INV-27). The first pass counts every served cover, so when the merge refuses a cover the
//!    second pass can stop below the cut, and a cover of another item it accepted may already
//!    hold that chain past the new head. The spike has the same order; the commit reports it
//!    ([`Report::SettledPastHead`], a report no spec names) rather than hiding it, and the chain
//!    resumes on the next Fetch.
//! 8. **A body rejected after it waited** ([`VaultLog::body_rejected`]) is treated like one
//!    rejected at commit (reading 4), whose chain stops before it so that the next Fetch asks
//!    again: the link is kept (ADR 0021 §9 "Headers kept"), but the cursor entry drops to the
//!    link before it, so the server serves it again, with a cover if it is compacted by then,
//!    and the later links of the chain wait until a cover or a verified body settles it. No
//!    spec text covers a body that fails after its wrap arrives.
//!
//! # Headers kept
//!
//! "Clients keep every signed op header they receive or write, with both hashes and the
//! signature, for the life of the vault" (ADR 0021 §9 "Headers kept"). The log keeps every
//! accepted link's parsed header ([`VaultLog::header`], [`VaultLog::chain`]) and never drops
//! one; the client persists the signed statements (header bytes, both hashes, signature) next
//! to it, and the snapshot records it wrote or absorbed. Headers are about 225 bytes plus 24
//! per causal-context entry (ADR 0012 §7).
//!
//! # Cost
//!
//! For L held links, D devices with a chain, and causal contexts of n entries:
//! [`VaultLog::commit`] costs O(R log R) for a response of R records, plus a lookup per record
//! in the log. [`VaultLog::take_deliveries`] repeats a round while the previous one delivered
//! something. A round checks each chain's frontier, O(D·(n + log L)), and the ready bodies of
//! only the items whose settled VV grew, through a per-item, per-device index by seq, so each
//! ready body is looked at when it is delivered and not before. A batch delivers at least one
//! op per round, so it costs O(L·D·(n + log L)) in all, linear in L for the bounded number of
//! devices of an account: a withheld wrap that holds one chain back does not make the others
//! quadratic. [`VaultLog::complete_fetch_reports`] costs O(L·D). The Fetch response's size is
//! bounded by the protocol, not here.
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

use core::fmt;
use core::ops::Bound;
use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::{DeviceId, ItemId, VaultId};

use crate::dot::Dot;
use crate::header::{OpHeader, SnapshotHeader};
use crate::hlc::Hlc;
use crate::vv::VersionVector;

pub mod author;
pub mod behind;
pub mod own;

pub use author::{AuthorRefusal, AuthorStatus, check_op_author, check_snapshot_author};
pub use behind::{Behind, ServerView};
pub use own::{OwnError, RestoreGeneration, StalePlan};

/// What the client knows about one served op's body after verifying it (ADR 0012 §4 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BodyStatus {
    /// Served and verified: its `SHA-256` matched the signed hash, it decrypted with the
    /// commitment check, and its `data` parsed (ADR 0018 §5). Ready to apply.
    Verified,
    /// Served, but not verifiable yet: its item key's wrap has not arrived (CRYPTO.md §11.6
    /// reader rule, "An op under an unknown item key waits for its wrap"), or its
    /// `item_schema_version` is unknown and the record is parked (ADR 0018 §11). It blocks its
    /// chain until the client calls [`VaultLog::body_verified`] or [`VaultLog::body_rejected`].
    Waiting,
    /// Served, and failed verification: rejected and reported, never applied in part
    /// (ADR 0012 §4 step 1). Its header counts like a bodiless one (reading 4 in the module
    /// docs).
    Rejected,
    /// Not served: a bodiless header, whose body the server deleted behind snapshots or never
    /// held (ADR 0021 §2).
    Bodiless,
}

/// One op record of a Fetch response: its verified, parsed header and the verdict on its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedOp {
    /// The header, parsed from a verified `op` statement ([`OpHeader::parse_statement`]).
    pub header: OpHeader,
    /// What the client knows about its body.
    pub body: BodyStatus,
}

/// The first pass of the chain check over one response ([`VaultLog::plan_covers`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverPlan {
    /// Indices into the served covers of the covers to absorb, in served order: those that
    /// cover a bodiless header of their item that passed the first pass.
    pub absorb: Vec<usize>,
    /// The new headers that passed the first pass, per device in chain order.
    pub links: Vec<Dot>,
    /// The cut (reading 7): per device, the chain's head or the last of its `links`, whichever
    /// is higher, the own device's head included. ADR 0018 §3 "Snapshots are claims": the merge
    /// "cuts the covered VV to the op headers it has verified", and a header past a chain's gap
    /// never counts as one, so the merge takes nothing of a cover above this cut
    /// ([`CoverPlan::cut_of`]); [`VaultLog::record_absorbed`] records nothing above it.
    pub cut: VersionVector,
    /// Indices into the served covers of the covers refused because their covered-VV entry for
    /// their own author is above that author's revocation cut-off, which this log knows
    /// (CRYPTO.md §11.8 step 4; ADR 0021 §9 "Revoked and kind-4 authors"). They count for no
    /// header and are not absorbed; the client reports them.
    pub refused: Vec<usize>,
}

impl CoverPlan {
    /// The most the merge may take of a cover with this covered VV: the covered VV cut to
    /// [`CoverPlan::cut`], entry by entry (ADR 0018 §3 "Snapshots are claims"; reading 7). The
    /// merge reports the part it cut, as the spike's `ClaimCut` does.
    #[must_use]
    pub fn cut_of(&self, covered: &VersionVector) -> VersionVector {
        let mut out = covered.clone();
        out.meet(&self.cut);
        out
    }
}

/// The outcome of committing one response ([`VaultLog::commit`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Commit {
    /// The headers accepted as links, per device in chain order.
    pub accepted: Vec<Dot>,
    /// What the client reports: gaps, duplicates, rejections.
    pub reports: Vec<Report>,
}

/// Something the client reports to the user or logs. Server-visible metadata only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Report {
    /// A header at or below its chain's head, equal to the held link: a duplicate, ignored.
    Duplicate {
        /// The header's dot.
        dot: Dot,
    },
    /// A header at or below its chain's head that differs from the held link, or names a seq
    /// the chain skipped: two signed versions of one chain (reading 6). Ignored.
    Equivocation {
        /// The header's dot.
        dot: Dot,
    },
    /// A header of the own device above the own head: an op signed by this device's key that
    /// this device never wrote (reading 5). Ignored.
    UnknownOwnOp {
        /// The header's dot.
        dot: Dot,
    },
    /// A header of another vault in this vault's response. Ignored.
    ForeignVault {
        /// The header's dot.
        dot: Dot,
    },
    /// An op of a revoked device past its `last_accepted_device_seq`: rejected (ADR 0012 §4
    /// step 1; CRYPTO.md §11.8 step 4), and its chain goes no further.
    PastCutoff {
        /// The op's dot.
        dot: Dot,
        /// The revocation's `last_accepted_device_seq`.
        last_accepted: u64,
    },
    /// A served body that failed verification: rejected, never applied in part (ADR 0012 §4
    /// step 1). Its header counts only if a snapshot covers it (reading 4).
    RejectedBody {
        /// The op's dot.
        dot: Dot,
    },
    /// Missing data (INV-27): `device`'s chain stops after `after`, and nothing past the gap
    /// is accepted or applied.
    Gap {
        /// The device whose chain has the gap.
        device: DeviceId,
        /// The chain's head at the gap: the last link accepted.
        after: u64,
        /// What is missing.
        cause: GapCause,
    },
    /// After a complete Fetch, a held op waits for a causal predecessor that cannot be settled
    /// from what arrived: "missing ops from device X" (ADR 0012 §4 step 2). The predecessor's
    /// header never arrived, or no op of that device on that item at or above it is held that
    /// can still be applied (it was rejected, it is past a revocation cut-off, or the context
    /// names a seq that is not an op of that item).
    MissingPredecessor {
        /// The op that waits.
        waiting: Dot,
        /// The entry of its causal context that no settled op covers, as a dot.
        missing: Dot,
    },
    /// After a complete Fetch, a served body is still not verifiable: its item key's wrap
    /// never arrived (missing data, CRYPTO.md §11.6 reader rule), or its record is parked for an
    /// unknown `item_schema_version` (ADR 0018 §11). The client, which reached the verdict, tells
    /// the two apart. The later links of its chain wait behind it (reading 1). A report no spec
    /// names.
    Unverifiable {
        /// The op's dot.
        dot: Dot,
    },
    /// After a commit, an item's settled VV holds `device`'s ops up to `settled`, above the
    /// chain's head (reading 7): a cover the plan counted was refused, the second pass stopped
    /// below the cut, and a cover of `item_id` that the merge accepted already took ops past the
    /// new gap. Reported, not undone; the chain resumes on the next Fetch. A report no spec
    /// names.
    SettledPastHead {
        /// The item.
        item_id: ItemId,
        /// The device whose chain is behind.
        device: DeviceId,
        /// The item's settled VV entry for the device.
        settled: u64,
        /// The chain's head.
        head: u64,
    },
}

/// Why a chain has a gap ([`Report::Gap`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GapCause {
    /// The next header received does not link: its `vault_prev_seq` is not the head (ADR 0012
    /// §7: "Every link must be a received header"). At least one header is missing.
    Unlinked {
        /// The first header past the gap.
        next: Dot,
        /// Its `vault_prev_seq`.
        vault_prev_seq: u64,
    },
    /// A bodiless header, or one whose body was rejected, that no snapshot of its item, served
    /// now or held, covers (ADR 0012 §7; ADR 0021 §4).
    Uncovered {
        /// The header's dot.
        dot: Dot,
    },
    /// After a complete Fetch, a revoked device's chain stops below its
    /// `last_accepted_device_seq` (ADR 0021 §9 "Revoked and kind-4 authors").
    BelowCutoff {
        /// The revocation's `last_accepted_device_seq`.
        last_accepted: u64,
    },
}

/// One op to apply ([`VaultLog::take_deliveries`]). The client looks up the verified body by
/// `dot` and hands it to the merge, in the order of the batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Delivery {
    /// The op's dot.
    pub dot: Dot,
    /// The item it saves.
    pub item_id: ItemId,
    /// The op's HLC, for the receive rule (ADR 0012 §2).
    pub hlc: Hlc,
    /// The item's settled VV already covered the dot, through an absorbed snapshot: the body
    /// still merges (ADR 0018 §3 "Covered ops"), and it did not wait for its predecessors.
    pub covered: bool,
}

/// A held op that is not deliverable yet ([`VaultLog::waiting`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Waiting {
    /// The op's dot.
    pub dot: Dot,
    /// The item it saves.
    pub item_id: ItemId,
    /// What it waits for.
    pub reason: WaitReason,
}

/// Why a held op is not deliverable ([`Waiting`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WaitReason {
    /// Its body is not verifiable yet ([`BodyStatus::Waiting`]).
    Body,
    /// Its body was rejected after it waited ([`VaultLog::body_rejected`]) and no snapshot
    /// covers it yet; the cursor sits before it, so the next Fetch serves it again (reading 8).
    Rejected,
    /// It was accepted bodiless and its cover no longer counts. Unreachable through this API,
    /// which accepts a bodiless header only behind a cover; kept so that a link never waits
    /// without a reason.
    Uncovered,
    /// An earlier link of its chain is not settled (reading 1).
    Chain {
        /// The chain's first unsettled link.
        first_unsettled: Dot,
    },
    /// Its causal context has an entry the item's settled VV does not cover.
    Context {
        /// The first such entry, by `device_id`, as a dot.
        missing: Dot,
    },
}

/// What learning a revocation changed ([`VaultLog::learn_revocation`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revocation {
    /// Accepted but undelivered links past the cut-off, ascending: rejected now, never
    /// delivered (CRYPTO.md §11.8 step 4).
    pub rejected: Vec<Dot>,
    /// Items whose settled VV holds the device past its cut-off, delivered or through an
    /// absorbed snapshot: a misbehaving server's doing, reported and not converged (ADR 0021 §9
    /// "Restored-server revocation"). The merge removes the op and recomputes the item, or
    /// flags it (ADR 0012 §6).
    pub held_past_cutoff: Vec<ItemId>,
}

/// Why [`VaultLog::body_verified`] or [`VaultLog::body_rejected`] refused a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BodyError {
    /// No accepted link has this dot.
    UnknownOp,
    /// The link's body is not waiting: it was verified, rejected, delivered, or never served.
    NotWaiting,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownOp => "no accepted op has this dot",
            Self::NotWaiting => "the op's body is not waiting",
        })
    }
}

impl core::error::Error for BodyError {}

/// The chains of one vault as one device sees them: accepted links, settled version vectors,
/// revocation cut-offs and the own chain's upload state. See the module docs.
#[derive(Clone, Debug)]
pub struct VaultLog {
    /// The vault.
    vault_id: VaultId,
    /// The device this log belongs to.
    own: DeviceId,
    /// Every chain with at least one link, the own chain included.
    chains: BTreeMap<DeviceId, Chain>,
    /// The settled VV of every item with a settled op or an absorbed snapshot.
    items: BTreeMap<ItemId, VersionVector>,
    /// The links whose body is verified and not yet delivered.
    ready: ReadyIndex,
    /// The items whose settled VV grew, or that gained a ready body, since the last pass that
    /// delivers covered bodies: only their ready bodies can have become covered.
    dirty: BTreeSet<ItemId>,
    /// The items that absorbed a cover since the last commit, which checks them (reading 7).
    absorbed: BTreeSet<ItemId>,
    /// The revocation cut-offs this device knows: `last_accepted_device_seq` per revoked
    /// device.
    cutoffs: BTreeMap<DeviceId, u64>,
    /// The own chain's acknowledgements and unanswered sends.
    uploads: own::Uploads,
}

/// Verified, undelivered bodies: per item, per authoring device, their `device_seq`s. A body is
/// covered when its seq is at most its item's settled VV entry for its device, so the covered
/// ones are a range of each set.
type ReadyIndex = BTreeMap<ItemId, BTreeMap<DeviceId, BTreeSet<u64>>>;

/// One device's accepted links in this vault.
#[derive(Clone, Debug, Default)]
struct Chain {
    /// Every accepted link, by `device_seq`: the kept headers.
    links: BTreeMap<u64, Link>,
    /// The `device_seq` of the last link, 0 if none.
    head: u64,
    /// No link below this `device_seq` is unsettled. Settledness only grows (settled VVs only
    /// grow, and a delivered link stays delivered), so the value stays a valid bound.
    frontier: u64,
}

/// One accepted header and the state of its body.
#[derive(Clone, Debug)]
struct Link {
    /// The header, kept for the life of the vault.
    header: OpHeader,
    /// Where its body stands.
    state: LinkState,
}

/// Where an accepted link's body stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkState {
    /// Verified, not yet delivered.
    Ready,
    /// Served but not yet verifiable.
    Waiting,
    /// Failed verification; never delivered. Accepted this way at commit only behind a cover
    /// (reading 4); reached from [`LinkState::Waiting`] through [`VaultLog::body_rejected`],
    /// it drops the cursor entry below the link until a cover settles it (reading 8).
    Rejected,
    /// Accepted without a body behind a cover; never delivered.
    Bodiless,
    /// Handed to the merge (or, on the own chain, written by this device).
    Delivered,
    /// Past its device's revocation cut-off and undelivered when the revocation was learned;
    /// never delivered.
    Revoked,
}

impl LinkState {
    /// The state of a newly accepted link with this body verdict.
    const fn from_body(body: BodyStatus) -> Self {
        match body {
            BodyStatus::Verified => Self::Ready,
            BodyStatus::Waiting => Self::Waiting,
            BodyStatus::Rejected => Self::Rejected,
            BodyStatus::Bodiless => Self::Bodiless,
        }
    }
}

/// Whether a header with this body verdict counts only behind a snapshot that covers it: a
/// bodiless header, or one whose body was rejected (reading 4).
const fn needs_cover(body: BodyStatus) -> bool {
    matches!(body, BodyStatus::Bodiless | BodyStatus::Rejected)
}

/// Whether the item's settled VV covers the header's dot.
fn covered(items: &BTreeMap<ItemId, VersionVector>, header: &OpHeader) -> bool {
    items
        .get(&header.item_id)
        .is_some_and(|vv| vv.covers(header.dot))
}

/// Whether a link is settled: delivered, or covered by its item's settled VV.
fn settled(items: &BTreeMap<ItemId, VersionVector>, link: &Link) -> bool {
    link.state == LinkState::Delivered || covered(items, &link.header)
}

/// The first entry of the header's causal context, by `device_id`, that its item's settled VV
/// does not cover; `None` when the settled VV covers the whole context (ADR 0012 §4 step 2).
fn missing_context(items: &BTreeMap<ItemId, VersionVector>, header: &OpHeader) -> Option<Dot> {
    let settled = items.get(&header.item_id);
    header
        .causal_context
        .entries()
        .find(|&entry| !settled.is_some_and(|vv| vv.covers(entry)))
}

/// Adds a verified, undelivered body to the ready index and marks its item dirty.
fn ready_insert(ready: &mut ReadyIndex, dirty: &mut BTreeSet<ItemId>, item_id: ItemId, dot: Dot) {
    ready
        .entry(item_id)
        .or_default()
        .entry(dot.device_id())
        .or_default()
        .insert(dot.seq());
    dirty.insert(item_id);
}

/// Removes a body from the ready index, dropping emptied sets.
fn ready_remove(ready: &mut ReadyIndex, item_id: ItemId, dot: Dot) {
    if let Some(per_device) = ready.get_mut(&item_id) {
        if let Some(seqs) = per_device.get_mut(&dot.device_id()) {
            seqs.remove(&dot.seq());
            if seqs.is_empty() {
                per_device.remove(&dot.device_id());
            }
        }
        if per_device.is_empty() {
            ready.remove(&item_id);
        }
    }
}

/// One device's served headers after one walk from its head: the prefix that extends the chain,
/// the held links served again, and what was reported on the way.
struct Walk<'a> {
    /// The headers that extend the chain, in chain order.
    accepted: Vec<&'a ServedOp>,
    /// Headers equal to a held link whose body was rejected and that no snapshot covers: served
    /// again for it (reading 8).
    reserved: Vec<&'a ServedOp>,
    /// Duplicates, equivocations, rejections and the gap that ended the walk, if any.
    reports: Vec<Report>,
}

impl VaultLog {
    /// An empty log of `vault_id` for the device `own`: no link, no settled op, cursor 0
    /// everywhere.
    #[must_use]
    pub fn new(vault_id: VaultId, own: DeviceId) -> Self {
        Self {
            vault_id,
            own,
            chains: BTreeMap::new(),
            items: BTreeMap::new(),
            ready: BTreeMap::new(),
            dirty: BTreeSet::new(),
            absorbed: BTreeSet::new(),
            cutoffs: BTreeMap::new(),
            uploads: own::Uploads::default(),
        }
    }

    /// The vault.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The device this log belongs to.
    #[must_use]
    pub const fn own_device(&self) -> DeviceId {
        self.own
    }

    /// The head of `device`'s chain: the `device_seq` of its last accepted link, 0 if none.
    #[must_use]
    pub fn head(&self, device: DeviceId) -> u64 {
        self.chains.get(&device).map_or(0, |c| c.head)
    }

    /// The Fetch cursor (ADR 0012 §7 "Fetch"): every chain's cursor entry, the own device's
    /// included, so the server serves nothing of the own chain back (reading 5). An entry is the
    /// chain's head, or, below a link whose body was rejected after it waited and that no
    /// snapshot covers, the `vault_prev_seq` of that link, so the server serves it again
    /// (reading 8).
    #[must_use]
    pub fn cursor(&self) -> VersionVector {
        self.chains
            .iter()
            .filter_map(|(&device, chain)| Dot::new(device, self.cursor_entry(chain)))
            .collect()
    }

    /// One chain's cursor entry (see [`VaultLog::cursor`]).
    fn cursor_entry(&self, chain: &Chain) -> u64 {
        chain
            .links
            .range(chain.frontier..)
            .map(|(_, l)| l)
            .find(|l| l.state == LinkState::Rejected && !covered(&self.items, &l.header))
            .map_or(chain.head, |l| l.header.vault_prev_seq)
    }

    /// Every chain's head, as a vector.
    fn heads(&self) -> VersionVector {
        self.chains
            .iter()
            .filter_map(|(&device, chain)| Dot::new(device, chain.head))
            .collect()
    }

    /// The kept header of the accepted link at `dot`, if any.
    #[must_use]
    pub fn header(&self, dot: Dot) -> Option<&OpHeader> {
        self.link(dot).map(|l| &l.header)
    }

    /// The accepted link at `dot`, if any.
    fn link(&self, dot: Dot) -> Option<&Link> {
        self.chains
            .get(&dot.device_id())
            .and_then(|c| c.links.get(&dot.seq()))
    }

    /// The kept headers of `device`'s chain, in chain order.
    pub fn chain(&self, device: DeviceId) -> impl Iterator<Item = &OpHeader> + '_ {
        self.chains
            .get(&device)
            .into_iter()
            .flat_map(|c| c.links.values().map(|l| &l.header))
    }

    /// The settled VV of `item_id`: the dots of the ops delivered on it, joined with what the
    /// merge took from absorbed snapshots. Empty for an item with nothing settled.
    #[must_use]
    pub fn settled(&self, item_id: ItemId) -> VersionVector {
        self.items.get(&item_id).cloned().unwrap_or_default()
    }

    /// The revocation cut-off of `device` this log knows: its `last_accepted_device_seq`.
    #[must_use]
    pub fn cutoff(&self, device: DeviceId) -> Option<u64> {
        self.cutoffs.get(&device).copied()
    }

    /// The first pass of the chain check over one response (ADR 0012 §7 "Chain check after
    /// compaction", ADR 0021 §4): the covers the client absorbs before [`VaultLog::commit`], and
    /// the cut the merge applies to them.
    ///
    /// `ops` are the response's op records; `covers` the verified headers of its covers, in
    /// served order (newest first, ADR 0021 §4). A cover of another vault counts for nothing; a
    /// cover whose covered-VV entry for its own author is above that author's known cut-off is
    /// refused ([`CoverPlan::refused`]; CRYPTO.md §11.8 step 4). In this pass a bodiless header
    /// counts if a counting cover of its item covers its dot, or its item's settled VV does.
    /// The covers to absorb are the counting covers that cover a bodiless header that passed
    /// this pass, or a rejected held link served again (readings 3 and 8); ADR 0018 §3 lets a
    /// replica absorb a snapshot in Server-mode sync "only as the cover of a bodiless header".
    /// The cut is each chain's head or last header that passed, whichever is higher (reading 7).
    /// Nothing changes; reports wait for [`VaultLog::commit`].
    #[must_use]
    pub fn plan_covers(&self, ops: &[ServedOp], covers: &[SnapshotHeader]) -> CoverPlan {
        let mut ignored = Vec::new();
        let groups = self.group(ops, &mut ignored);
        let in_vault = |c: &SnapshotHeader| c.vault_id == self.vault_id;
        let over_cutoff =
            |c: &SnapshotHeader| check_snapshot_author(c, self.cutoff(c.author)).is_err();
        let counts_cover = |c: &SnapshotHeader| in_vault(c) && !over_cutoff(c);
        let served_cover = |h: &OpHeader| {
            covers
                .iter()
                .any(|c| counts_cover(c) && c.item_id == h.item_id && c.covered.covers(h.dot))
        };
        let counts = |h: &OpHeader| covered(&self.items, h) || served_cover(h);
        let mut bodiless: Vec<&OpHeader> = Vec::new();
        let mut links = Vec::new();
        let mut cut = self.heads();
        for (&device, served) in &groups {
            let walk = self.walk(device, served, &counts);
            for op in walk.accepted {
                links.push(op.header.dot);
                cut.add(op.header.dot);
                if needs_cover(op.body) {
                    bodiless.push(&op.header);
                }
            }
            for op in walk.reserved {
                if needs_cover(op.body) && counts(&op.header) {
                    bodiless.push(&op.header);
                }
            }
        }
        let indices = |keep: &dyn Fn(&SnapshotHeader) -> bool| -> Vec<usize> {
            covers
                .iter()
                .enumerate()
                .filter(|&(_, c)| keep(c))
                .map(|(i, _)| i)
                .collect()
        };
        let absorb = indices(&|c| {
            counts_cover(c)
                && bodiless
                    .iter()
                    .any(|h| h.item_id == c.item_id && c.covered.covers(h.dot))
        });
        let refused = indices(&|c| in_vault(c) && over_cutoff(c));
        CoverPlan {
            absorb,
            links,
            cut,
            refused,
        }
    }

    /// Records that the merge absorbed a cover of `item_id` named by `plan` and took `taken` of
    /// its covered VV (ADR 0018 §3 "Snapshots are claims"). The log records `taken` cut to
    /// [`CoverPlan::cut`], never more (reading 7), joins it into the item's settled VV ("The
    /// covered VV becomes the entrywise maximum"), which settles the links it covers and
    /// releases their bodies as covered ops, and returns what it recorded. The merge takes at
    /// most [`CoverPlan::cut_of`], so the two agree.
    ///
    /// Call it for a cover of `plan.absorb` that the merge accepted, never for one it refused,
    /// and before [`VaultLog::commit`] of the same response: a bodiless header counts only
    /// against a snapshot the replica accepted (reading 3), and the commit checks what was
    /// recorded against the heads it reaches ([`Report::SettledPastHead`]).
    pub fn record_absorbed(
        &mut self,
        plan: &CoverPlan,
        item_id: ItemId,
        taken: &VersionVector,
    ) -> VersionVector {
        let recorded = plan.cut_of(taken);
        self.items.entry(item_id).or_default().join(&recorded);
        self.dirty.insert(item_id);
        self.absorbed.insert(item_id);
        recorded
    }

    /// The second pass of the chain check over one response, which accepts its links (ADR 0012
    /// §7 "Chain check after compaction", INV-27).
    ///
    /// Call it with the same `ops` as [`VaultLog::plan_covers`], after the absorptions. Per
    /// device, from the head, in `device_seq` order: duplicates and equivocations are reported
    /// and skipped; a revoked device's header past its cut-off, a header that does not link, and
    /// a bodiless header (or one with a rejected body) that its item's settled VV does not cover
    /// each end the chain's walk with a report; every header before that becomes a link, and the
    /// head moves to the last one. A held link whose body was rejected, served again, takes the
    /// new verdict on its body or counts behind a cover, and is reported as a gap again if
    /// neither settles it (reading 8). Headers of another vault, and of the own device, are
    /// reported and skipped (reading 5). Last, every item that absorbed a cover since the
    /// previous commit is checked against the heads reached ([`Report::SettledPastHead`],
    /// reading 7).
    ///
    /// Every rule is checked again, so a commit without a plan is safe: bodiless headers then
    /// count only against snapshots absorbed before.
    pub fn commit(&mut self, ops: &[ServedOp]) -> Commit {
        let mut reports = Vec::new();
        let groups = self.group(ops, &mut reports);
        let mut accepted = Vec::new();
        for (device, served) in groups {
            let walk = self.walk(device, &served, &|h| covered(&self.items, h));
            reports.extend(walk.reports);
            for op in walk.reserved {
                self.serve_again(op, &mut reports);
            }
            for op in walk.accepted {
                accepted.push(op.header.dot);
                self.accept_link(op.header.clone(), LinkState::from_body(op.body));
            }
        }
        self.check_absorbed(&mut reports);
        Commit { accepted, reports }
    }

    /// A held link whose body was rejected, served again (reading 8): a verified body makes it
    /// ready, a waiting one makes it wait; otherwise it stays rejected, settled only if a
    /// snapshot covers it, and is reported again if none does.
    fn serve_again(&mut self, op: &ServedOp, reports: &mut Vec<Report>) {
        let header = &op.header;
        let dot = header.dot;
        let is_covered = covered(&self.items, header);
        let Some(link) = self
            .chains
            .get_mut(&dot.device_id())
            .and_then(|c| c.links.get_mut(&dot.seq()))
        else {
            return;
        };
        // The same record may be served twice in one response; only the first counts.
        if link.state != LinkState::Rejected {
            return;
        }
        match op.body {
            BodyStatus::Verified => {
                link.state = LinkState::Ready;
                ready_insert(&mut self.ready, &mut self.dirty, header.item_id, dot);
            }
            BodyStatus::Waiting => link.state = LinkState::Waiting,
            BodyStatus::Rejected | BodyStatus::Bodiless => {
                if op.body == BodyStatus::Rejected {
                    reports.push(Report::RejectedBody { dot });
                }
                if !is_covered {
                    reports.push(Report::Gap {
                        device: dot.device_id(),
                        after: header.vault_prev_seq,
                        cause: GapCause::Uncovered { dot },
                    });
                }
            }
        }
    }

    /// Reports every item that absorbed a cover since the last commit and whose settled VV now
    /// holds a device above its chain's head (reading 7).
    fn check_absorbed(&mut self, reports: &mut Vec<Report>) {
        for item_id in core::mem::take(&mut self.absorbed) {
            let Some(vv) = self.items.get(&item_id) else {
                continue;
            };
            for entry in vv.entries() {
                let device = entry.device_id();
                let head = self.head(device);
                if entry.seq() > head {
                    reports.push(Report::SettledPastHead {
                        item_id,
                        device,
                        settled: entry.seq(),
                        head,
                    });
                }
            }
        }
    }

    /// A waiting body became verifiable and verified (its wrap arrived, CRYPTO.md §11.6): the
    /// link can be delivered.
    ///
    /// # Errors
    /// [`BodyError::UnknownOp`] if no link has `dot`; [`BodyError::NotWaiting`] if its body was
    /// not [`BodyStatus::Waiting`].
    pub fn body_verified(&mut self, dot: Dot) -> Result<(), BodyError> {
        let item_id = self.resolve_waiting(dot, LinkState::Ready)?;
        ready_insert(&mut self.ready, &mut self.dirty, item_id, dot);
        Ok(())
    }

    /// A waiting body failed verification: rejected and never delivered (ADR 0012 §4 step 1).
    /// As for a body rejected at commit (reading 4), nothing of the chain past it is applied
    /// until a snapshot covers the link: the cursor entry drops to the link before it, so the
    /// next Fetch serves it again, with a cover if the server compacted it, and a verified body
    /// served then is taken (reading 8). Until then [`VaultLog::waiting`] lists it as
    /// [`WaitReason::Rejected`] and [`VaultLog::complete_fetch_reports`] as a gap.
    ///
    /// # Errors
    /// As [`VaultLog::body_verified`].
    pub fn body_rejected(&mut self, dot: Dot) -> Result<(), BodyError> {
        self.resolve_waiting(dot, LinkState::Rejected).map(|_| ())
    }

    /// The ops to apply now, in order (ADR 0012 §4 step 2; ADR 0018 §3 "Covered ops").
    ///
    /// Repeats until nothing more is deliverable: first every verified body whose item's
    /// settled VV covers its dot, by item and then by dot, marked [`Delivery::covered`]; then,
    /// device by device, each chain's frontier while it has a verified body and its item's
    /// settled VV covers its causal context. A fresh delivery joins its dot into the settled VV.
    /// Each body is delivered at most once.
    pub fn take_deliveries(&mut self) -> Vec<Delivery> {
        let mut out = Vec::new();
        loop {
            let before = out.len();
            self.deliver_covered(&mut out);
            self.deliver_frontiers(&mut out);
            if out.len() == before {
                return out;
            }
        }
    }

    /// Every held op that is not deliverable, and why, per device in chain order.
    ///
    /// Call it after [`VaultLog::take_deliveries`]: a link that is deliverable is not listed.
    /// Links past a revocation cut-off are not listed; [`VaultLog::learn_revocation`] reported
    /// them.
    #[must_use]
    pub fn waiting(&self) -> Vec<Waiting> {
        let mut out = Vec::new();
        for chain in self.chains.values() {
            let mut first_unsettled: Option<Dot> = None;
            for link in chain.links.range(chain.frontier..).map(|(_, l)| l) {
                if settled(&self.items, link) || link.state == LinkState::Revoked {
                    continue;
                }
                let dot = link.header.dot;
                let reason = match (link.state, first_unsettled) {
                    (LinkState::Waiting, _) => Some(WaitReason::Body),
                    (LinkState::Rejected, _) => Some(WaitReason::Rejected),
                    (LinkState::Bodiless, _) => Some(WaitReason::Uncovered),
                    (_, Some(first)) => Some(WaitReason::Chain {
                        first_unsettled: first,
                    }),
                    (_, None) => missing_context(&self.items, &link.header)
                        .map(|missing| WaitReason::Context { missing }),
                };
                if let Some(reason) = reason {
                    out.push(Waiting {
                        dot,
                        item_id: link.header.item_id,
                        reason,
                    });
                }
                first_unsettled.get_or_insert(dot);
            }
        }
        out
    }

    /// Learns that `device` is revoked with `last_accepted_device_seq` = `last_accepted`
    /// (ADR 0012 §6; CRYPTO.md §11.8 step 4), from a verified `device-revocation`.
    ///
    /// From now on the chain check rejects the device's headers past the cut-off, and
    /// [`VaultLog::plan_covers`] refuses a cover whose entry for the device, as its author, is
    /// above it. Its accepted, undelivered links past the cut-off are rejected and never
    /// delivered. An item whose settled VV already holds the device past the cut-off is reported
    /// (ADR 0021 §9 "Restored-server revocation"); the merge's ADR 0012 §6 recomputation, or its
    /// flag, is the client's next step. A second revocation of the same device keeps the lower
    /// cut-off: two signed cut-offs for one device can only come from a misbehaving party, and
    /// the lower one accepts less.
    pub fn learn_revocation(&mut self, device: DeviceId, last_accepted: u64) -> Revocation {
        let cut = self
            .cutoffs
            .get(&device)
            .map_or(last_accepted, |&c| c.min(last_accepted));
        self.cutoffs.insert(device, cut);
        let mut rejected = Vec::new();
        let Self { chains, ready, .. } = self;
        if let Some(chain) = chains.get_mut(&device) {
            for link in chain
                .links
                .range_mut((Bound::Excluded(cut), Bound::Unbounded))
                .map(|(_, l)| l)
            {
                if link.state != LinkState::Delivered && link.state != LinkState::Revoked {
                    link.state = LinkState::Revoked;
                    ready_remove(ready, link.header.item_id, link.header.dot);
                    rejected.push(link.header.dot);
                }
            }
        }
        let held_past_cutoff = self
            .items
            .iter()
            .filter(|(_, vv)| vv.get(device) > cut)
            .map(|(&item_id, _)| item_id)
            .collect();
        Revocation {
            rejected,
            held_past_cutoff,
        }
    }

    /// What a complete Fetch leaves missing or held (INV-27), to call after its last page and
    /// [`VaultLog::take_deliveries`]. It depends on the state reached, not on the order in which
    /// ops, verdicts and revocations were learned.
    ///
    /// - For every revoked device other than the own one whose head is below its
    ///   `last_accepted_device_seq`, a [`GapCause::BelowCutoff`] gap: "After a complete Fetch,
    ///   a client whose cursor for a revoked device is below that device's
    ///   `last_accepted_device_seq` reports missing data" (ADR 0021 §9 "Revoked and kind-4
    ///   authors"; CRYPTO.md §11.8 step 4). That text is for one vault per account, as in M1:
    ///   `device_seq` counts ops in every vault, so with more vaults a chain may legitimately
    ///   end below the cut-off, and ADR 0021 leaves the per-vault bound to M9.
    /// - For every link whose body was rejected after it waited and that no snapshot covers, a
    ///   [`GapCause::Uncovered`] gap after its `vault_prev_seq` (reading 8).
    /// - For every link whose body is still not verifiable, [`Report::Unverifiable`].
    /// - For every held op whose causal context names a dot that cannot be settled from what
    ///   arrived, a [`Report::MissingPredecessor`] (ADR 0012 §4 step 2): the dot is above its
    ///   device's head, or no link of that device on that item at or above it has a body that
    ///   is verified or waiting (it was rejected, it is past a revocation cut-off, or the
    ///   context names a seq that is no op of that item).
    #[must_use]
    pub fn complete_fetch_reports(&self) -> Vec<Report> {
        let mut out = Vec::new();
        for (&device, &cut) in &self.cutoffs {
            let head = self.head(device);
            if device != self.own && head < cut {
                out.push(Report::Gap {
                    device,
                    after: head,
                    cause: GapCause::BelowCutoff { last_accepted: cut },
                });
            }
        }
        for w in self.waiting() {
            match w.reason {
                WaitReason::Body => out.push(Report::Unverifiable { dot: w.dot }),
                WaitReason::Rejected | WaitReason::Uncovered => out.push(Report::Gap {
                    device: w.dot.device_id(),
                    after: self.header(w.dot).map_or(0, |h| h.vault_prev_seq),
                    cause: GapCause::Uncovered { dot: w.dot },
                }),
                WaitReason::Context { missing } if !self.can_settle(w.item_id, missing) => {
                    out.push(Report::MissingPredecessor {
                        waiting: w.dot,
                        missing,
                    });
                }
                WaitReason::Context { .. } | WaitReason::Chain { .. } => {}
            }
        }
        out
    }

    /// Whether a causal-context entry `missing` of an op on `item_id` can still be settled from
    /// what a complete Fetch brought: it is at or below its device's head, and a link of that
    /// device on that item at or above it has a body that is verified or waiting. Above the
    /// head, its header never arrived.
    fn can_settle(&self, item_id: ItemId, missing: Dot) -> bool {
        let device = missing.device_id();
        if missing.seq() > self.head(device) {
            return false;
        }
        self.chains.get(&device).is_some_and(|chain| {
            chain.links.range(missing.seq()..).any(|(_, l)| {
                l.header.item_id == item_id
                    && matches!(l.state, LinkState::Ready | LinkState::Waiting)
            })
        })
    }

    /// Splits a response into chains to walk, per device, each sorted by `device_seq` (the
    /// server sends "per device and in chain order", ADR 0012 §7; sorting also covers a server
    /// that does not). Headers of another vault and of the own device are reported into
    /// `reports` and left out.
    fn group<'a>(
        &self,
        ops: &'a [ServedOp],
        reports: &mut Vec<Report>,
    ) -> BTreeMap<DeviceId, Vec<&'a ServedOp>> {
        let mut groups: BTreeMap<DeviceId, Vec<&'a ServedOp>> = BTreeMap::new();
        for op in ops {
            let dot = op.header.dot;
            if op.header.vault_id != self.vault_id {
                reports.push(Report::ForeignVault { dot });
            } else if dot.device_id() == self.own {
                reports.push(match self.header(dot) {
                    Some(held) if *held == op.header => Report::Duplicate { dot },
                    _ if dot.seq() <= self.head(self.own) => Report::Equivocation { dot },
                    _ => Report::UnknownOwnOp { dot },
                });
            } else {
                groups.entry(dot.device_id()).or_default().push(op);
            }
        }
        for served in groups.values_mut() {
            served.sort_by_key(|op| op.header.dot.seq());
        }
        groups
    }

    /// Walks one device's served headers, sorted by `device_seq`, from the chain's head: the
    /// chain check of ADR 0012 §7. `counts` says whether a snapshot covers a bodiless header
    /// (or one with a rejected body) in this pass. Nothing changes.
    fn walk<'a>(
        &self,
        device: DeviceId,
        served: &[&'a ServedOp],
        counts: &dyn Fn(&OpHeader) -> bool,
    ) -> Walk<'a> {
        let chain = self.chains.get(&device);
        let mut prev = chain.map_or(0, |c| c.head);
        let mut accepted: Vec<&'a ServedOp> = Vec::new();
        let mut reserved: Vec<&'a ServedOp> = Vec::new();
        let mut reports = Vec::new();
        let cut = self.cutoffs.get(&device).copied();
        for &op in served {
            let h = &op.header;
            let dot = h.dot;
            if dot.seq() <= prev {
                let held_link = chain.and_then(|c| c.links.get(&dot.seq()));
                if let Some(link) = held_link
                    && link.header == *h
                    && link.state == LinkState::Rejected
                    && !covered(&self.items, h)
                {
                    reserved.push(op);
                    continue;
                }
                let held = held_link.map(|l| &l.header).or_else(|| {
                    // The links accepted in this walk ascend by seq.
                    accepted
                        .binary_search_by_key(&dot.seq(), |a| a.header.dot.seq())
                        .ok()
                        .and_then(|i| accepted.get(i))
                        .map(|a| &a.header)
                });
                reports.push(if held == Some(h) {
                    Report::Duplicate { dot }
                } else {
                    Report::Equivocation { dot }
                });
                continue;
            }
            if let Some(last_accepted) = cut
                && dot.seq() > last_accepted
            {
                reports.push(Report::PastCutoff { dot, last_accepted });
                break;
            }
            if h.vault_prev_seq != prev {
                reports.push(Report::Gap {
                    device,
                    after: prev,
                    cause: GapCause::Unlinked {
                        next: dot,
                        vault_prev_seq: h.vault_prev_seq,
                    },
                });
                break;
            }
            if op.body == BodyStatus::Rejected {
                reports.push(Report::RejectedBody { dot });
            }
            if needs_cover(op.body) && !counts(h) {
                reports.push(Report::Gap {
                    device,
                    after: prev,
                    cause: GapCause::Uncovered { dot },
                });
                break;
            }
            accepted.push(op);
            prev = dot.seq();
        }
        Walk {
            accepted,
            reserved,
            reports,
        }
    }

    /// Accepts `header` as the next link of its chain, with its body in `state`.
    fn accept_link(&mut self, header: OpHeader, state: LinkState) {
        let dot = header.dot;
        if state == LinkState::Ready {
            ready_insert(&mut self.ready, &mut self.dirty, header.item_id, dot);
        }
        let chain = self.chains.entry(dot.device_id()).or_default();
        chain.links.insert(dot.seq(), Link { header, state });
        chain.head = dot.seq();
    }

    /// Moves a waiting link's body to `state`, and returns its item.
    fn resolve_waiting(&mut self, dot: Dot, state: LinkState) -> Result<ItemId, BodyError> {
        let link = self
            .chains
            .get_mut(&dot.device_id())
            .and_then(|c| c.links.get_mut(&dot.seq()))
            .ok_or(BodyError::UnknownOp)?;
        if link.state != LinkState::Waiting {
            return Err(BodyError::NotWaiting);
        }
        link.state = state;
        Ok(link.header.item_id)
    }

    /// Delivers, as covered ops, every verified body whose item's settled VV covers its dot,
    /// looking only at the dirty items: a body's coverage changes only when its item's settled
    /// VV grows, or when it becomes ready, and both mark the item dirty.
    fn deliver_covered(&mut self, out: &mut Vec<Delivery>) {
        let Self {
            chains,
            items,
            ready,
            dirty,
            ..
        } = self;
        for item_id in core::mem::take(dirty) {
            let (Some(vv), Some(per_device)) = (items.get(&item_id), ready.get_mut(&item_id))
            else {
                continue;
            };
            let mut due = Vec::new();
            for (&device, seqs) in per_device.iter_mut() {
                let covered_seqs: Vec<u64> = seqs.range(..=vv.get(device)).copied().collect();
                for seq in covered_seqs {
                    seqs.remove(&seq);
                    due.extend(Dot::new(device, seq));
                }
            }
            per_device.retain(|_, seqs| !seqs.is_empty());
            if per_device.is_empty() {
                ready.remove(&item_id);
            }
            for dot in due {
                if let Some(link) = chains
                    .get_mut(&dot.device_id())
                    .and_then(|c| c.links.get_mut(&dot.seq()))
                {
                    link.state = LinkState::Delivered;
                    out.push(Delivery {
                        dot,
                        item_id,
                        hlc: link.header.hlc,
                        covered: true,
                    });
                }
            }
        }
    }

    /// Advances every chain's frontier past its settled links, delivering each frontier link
    /// whose body is verified and whose causal context is settled.
    fn deliver_frontiers(&mut self, out: &mut Vec<Delivery>) {
        let Self {
            chains,
            items,
            ready,
            dirty,
            ..
        } = self;
        for chain in chains.values_mut() {
            loop {
                let next = chain
                    .links
                    .range(chain.frontier..)
                    .find(|(_, l)| !settled(items, l))
                    .map(|(&seq, _)| seq);
                let Some(seq) = next else {
                    chain.frontier = chain.head.saturating_add(1);
                    break;
                };
                chain.frontier = seq;
                let Some(link) = chain.links.get_mut(&seq) else {
                    break;
                };
                if link.state != LinkState::Ready || missing_context(items, &link.header).is_some()
                {
                    break;
                }
                link.state = LinkState::Delivered;
                let dot = link.header.dot;
                let item_id = link.header.item_id;
                ready_remove(ready, item_id, dot);
                items.entry(item_id).or_default().add(dot);
                dirty.insert(item_id);
                out.push(Delivery {
                    dot,
                    item_id,
                    hlc: link.header.hlc,
                    covered: false,
                });
            }
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures it built; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "the generated histories index fixtures they built; a panic there fails the test, which CLAUDE.md allows"
)]
mod proptests;
