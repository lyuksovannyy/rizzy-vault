//! The server's compaction rules ([ADR 0021] §2–§4, §7) and its pure snapshot-acceptance checks
//! (§9 "Server acceptance", "Revoked and kind-4 authors").
//!
//! ADR 0021 partly supersedes [ADR 0012] §7 "Snapshots and compaction" and "Fetch": the server
//! deletes an op body only behind covers by two different authors, keeps an older snapshot
//! while dropping it would lower the number of authors that cover some bodiless header to fewer
//! than two, and serves every bodiless header with covers by two authors where the retained
//! snapshots have them. The
//! server holds no key and reads no field, so every rule here runs on cleartext it already
//! stores: store sequences, clamped version vectors, snapshot authors, op dots and heads
//! (ADR 0012 §11, as replaced by ADR 0022 §2).
//!
//! # Contract
//!
//! Pure functions over **one item** of **one vault** (ADR 0021 §7): no I/O, no clock, no
//! randomness, and the module builds for `wasm32-unknown-unknown` with the rest of the crate.
//! The caller, the vault domain inside the account lock, reads the rows, calls a function and
//! writes the result; `rizzy-domain-vault` and `worker` own every transaction (ADR 0021 §3
//! "Where it runs", §7). The inputs are the server's own rows or values already parsed by
//! [`VersionVector::read`], so nothing here parses bytes; inconsistent rows (a store sequence or
//! a dot given twice) are refused with an [`InputError`], never a panic.
//!
//! # Terms (ADR 0021 §2)
//!
//! A missing VV entry counts as 0.
//!
//! - **Head** h(V, d): the `device_seq` of the last op of device d the server holds in vault V,
//!   0 if none. The caller passes every head as one [`VersionVector`] whose entry for d is
//!   h(V, d).
//! - **Clamped VV:** `clamped(S)[d] = min(covered(S)[d], h(V, d))`, computed once by [`clamp`] in
//!   the transaction that stores S and persisted in the canonical VV encoding
//!   ([`VersionVector::encode`]), never sent. Ops are stored in chain order, so the clamp is why
//!   a snapshot never covers an op stored after it, whatever its covered VV claims, up to
//!   `u64::MAX`.
//! - **Store sequence:** a per-vault `u64`, strictly increasing with each stored snapshot.
//!   "Newest" and "oldest" mean by store sequence. Unique within the vault, so the outputs name
//!   a snapshot by its [`RetainedSnapshot::store_seq`].
//! - **Covers:** a retained snapshot S covers op o of the same item when
//!   `o.device_seq ≤ clamped(S)[o.device_id]` ([`RetainedSnapshot::covers`]). Its **author** is
//!   the device that signed it.
//! - **Bodiless header** ([`Body::Absent`]): an op whose body R1 deleted, or which a healing
//!   request stored without it. Its signed header, both hashes and signature stay for the life
//!   of the vault (ADR 0012 §7); nothing here deletes a header.
//!
//! # Rules
//!
//! | Function | Rule | Output |
//! |---|---|---|
//! | [`clamp`] | §2 "Clamped VV" | the clamped VV to persist with a snapshot |
//! | [`plan_worker`] | §3 R1, then R3, as `worker` applies them in one transaction | [`WorkerPlan`]: bodies to delete, snapshots to drop |
//! | [`select_covers`] | §4 "Covers" (owner rule 2) | [`CoverSelection`]: covers for one response or page, and any bodiless header without a cover |
//! | [`check_snapshot`] | §9 "Server acceptance" (second sentence, applied inside a healing request too, as the merge spike reads it), "Revoked and kind-4 authors" | refuse or accept one snapshot before it is stored |
//! | [`check_healing_request`] | §9 "Server acceptance" (first sentence) | refuse or accept a healing request's bodiless headers |
//!
//! - **R1, delete** (owner rule 1, owner decision 1): an op's body is deleted when, and only
//!   when, the older of the item's two newest retained snapshots covers the op and retained
//!   snapshots by two different authors cover it. With fewer than two retained snapshots
//!   nothing is deleted. Only the body goes.
//! - **R3, retain** (owner rule 3, owner decision 1): the two newest snapshots always stay. An
//!   older one stays while dropping it would lower the number of authors that cover some
//!   bodiless header to fewer than two; every other older one is dropped, tested oldest first
//!   and re-tested after each drop. R3 sees the bodies R1 deletes in the same run as bodiless.
//! - **Covers** (owner rule 2, owner decision 1): the item's retained snapshots, newest first;
//!   each one is added that covers a bodiless header of the response that the snapshots added
//!   so far cover by no author, or by one author other than its own. A bodiless header left
//!   without a cover is a bug or a damaged database: the caller serves the header alone and
//!   logs an integrity error naming the vault, item and dot, never content (§4).
//!
//! Nothing else deletes a body or drops a snapshot (§3 "Nothing else").
//!
//! # R3 in one pass
//!
//! [`plan_worker`] tests each older snapshot once, oldest first, against the retained set left
//! by the drops before it. That is the rule's "tested oldest first and re-tested after each
//! drop": whether a snapshot is needed can only turn from false to true as others are dropped,
//! never back. A snapshot S of author a is needed when some bodiless header it covers has
//! covers by at most two authors among which S is a's only one; dropping another snapshot
//! never adds an author or a second cover by a, so S stays needed. Every snapshot the full
//! re-test would examine again before the next drop was already found needed, and still is.
//! The unit tests check the single pass against the literal restart-from-the-oldest loop.
//!
//! # Where the other §9 rules live
//!
//! The caller applies the checks that need its rows or its clock: "Already stored"
//! (byte-identical records and `snapshot_id`s), the `vault_prev_seq` chain check, the stale-epoch
//! check and its exemptions, the certificate and signature checks, and the certificate expiry
//! it reports as [`CertificateExpiry`]. The rotation cut-off (§9 "Rotation cut-off") and the
//! clients' side of "Revoked and kind-4 authors" are not in this module.
//!
//! # Cost
//!
//! With S retained snapshots and B ops of the item, [`plan_worker`] costs O(S·B) VV lookups and
//! [`select_covers`] O(S·B') for the B' bodiless headers of one response; R3 holds one count
//! per bodiless header and covering author. Bodiless headers accumulate for the life of the
//! vault, and no per-item cap on retained snapshots exists in M1 (owner decision 2): the
//! account storage quota bounds both ([THREAT_MODEL] A15, §7.6).
//!
//! # Why the rules hold (ADR 0021 §3)
//!
//! R1 deletes only behind a retained cover, R3 never leaves a bodiless header without one, and
//! §4 serves one, so owner rules 1–3 hold and a client's chain check (ADR 0012 §7, INV-27)
//! never meets a bodiless header without a cover from an honest server. Covers by two authors
//! mean one faulty device never holds the only server copy of a deleted body; a header a
//! healing request stored without its body can have the healer's cover alone (owner decision
//! 8). Compaction discards only ops covered by snapshots clients produced and signed (INV-26).
//!
//! # Tests
//!
//! The unit tests pin each rule and each refusal, and check [`plan_worker`] and
//! [`select_covers`] against literal transcriptions of R1, R3 and §4. A simulated single-vault
//! server (`sim`, test-only) runs generated histories through these functions: writes,
//! snapshots from several devices in generated interleavings (concurrent purges and late
//! edits included), claims up to `u64::MAX`, healing requests, backups and restores,
//! revocations and expiries, `worker` paused and resumed, and fetches from cursors behind the
//! heads after every step. An independent brute-force checker, written from ADR 0021 §2–§4 and
//! not from this module, checks §8 server properties 1–3 after every step and 4–5 after every
//! `worker` run, 4 and 5 in their two-author form. The named scenarios of §8 (concurrent
//! purges `T_A` and `T_B` in both orders; `S_L` with 33 late edits) run there too, each first
//! under ADR 0012's superseded rule to show the failure ADR 0021's Context describes. The
//! fuzz target `sync_compaction` runs every function on arbitrary rows and claims.
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md
//! [THREAT_MODEL]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/THREAT_MODEL.md

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::DeviceId;

use crate::dot::Dot;
use crate::vv::VersionVector;

/// One retained snapshot of the item, as the rules see it (ADR 0021 §2, §7 input).
///
/// Only cleartext the server stores: never the envelope, and never the covered VV, which the
/// rules do not use once the clamped VV is computed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RetainedSnapshot {
    /// The store sequence the server assigned when it stored the snapshot, under the account
    /// lock. Unique within the vault; the outputs name the snapshot by it.
    pub store_seq: u64,
    /// The clamped VV persisted with the snapshot ([`clamp`] at store time).
    pub clamped: VersionVector,
    /// The device that signed the snapshot.
    pub author: DeviceId,
}

impl RetainedSnapshot {
    /// Whether this snapshot covers the op with `dot` (ADR 0021 §2 "Covers"):
    /// `dot.seq ≤ clamped[dot.device_id]`.
    ///
    /// The op must name the snapshot's vault and item; the functions of this module take one
    /// item's records, so the caller ensures it.
    #[must_use]
    pub fn covers(&self, dot: Dot) -> bool {
        self.clamped.covers(dot)
    }
}

/// Whether the server holds an op's body (ADR 0021 §7, "each with a body flag").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Body {
    /// The server holds the body.
    Held,
    /// A bodiless header: R1 deleted the body, or a healing request stored the header without
    /// it (ADR 0021 §2).
    Absent,
}

/// One op of the item: its dot and whether its body is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpDot {
    /// The op's `(device_id, device_seq)`.
    pub dot: Dot,
    /// Whether the server holds its body.
    pub body: Body,
}

/// What one `worker` run does to one item: R1's deletions, then R3's drops (ADR 0021 §3).
///
/// The caller applies both in one transaction under the account lock, recomputed from the
/// current rows (§3 "Where it runs").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerPlan {
    /// The ops whose bodies R1 deletes, ascending by dot. Their signed headers stay.
    pub delete_bodies: Vec<Dot>,
    /// The store sequences of the snapshots R3 drops, oldest first.
    pub drop_snapshots: Vec<u64>,
}

impl WorkerPlan {
    /// Whether the run changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.delete_bodies.is_empty() && self.drop_snapshots.is_empty()
    }
}

/// The covers of one item for one Fetch response, or one page of it (ADR 0021 §4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverSelection {
    /// The store sequences of the snapshots to serve as covers, newest first. Each goes as its
    /// full record: header, envelope, signature and, if held, its wrap.
    pub covers: Vec<u64>,
    /// The bodiless headers of the response that no retained snapshot covers, ascending: a bug
    /// or a damaged database (§4). The caller serves each header alone and logs an integrity
    /// error naming the vault, item and dot, never content. Empty on an honest server
    /// (§8 property 1).
    pub uncovered: Vec<Dot>,
}

/// The input rows are inconsistent: the caller read them wrongly or the database is damaged.
///
/// Carries only server-visible metadata (a store sequence or a dot), never content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InputError {
    /// Two retained snapshots have the same store sequence, so "newest" is undefined.
    DuplicateStoreSeq(u64),
    /// The same dot appears twice among the item's ops.
    DuplicateOp(Dot),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateStoreSeq(seq) => {
                write!(f, "two retained snapshots with store sequence {seq}")
            }
            Self::DuplicateOp(_) => f.write_str("the same op dot given twice"),
        }
    }
}

impl core::error::Error for InputError {}

/// Whether the snapshot's author holds an expired certificate at the server's clock
/// (CRYPTO.md §10.2 `expires_at_ms`; ADR 0021 §9 "Revoked and kind-4 authors").
///
/// Kind-4 certificates always carry an expiry, and a durable one may. The server reads its
/// clock and the certificate; this module has neither. Revocation is read from
/// [`VaultChains::cutoffs`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertificateExpiry {
    /// No expiry, or not yet past it.
    Unexpired,
    /// Past `expires_at_ms`: the server refuses new snapshots from it.
    Expired,
}

/// The server's view of the vault's chains at the moment it stores a snapshot, under the
/// account lock (ADR 0021 §2, §9).
#[derive(Clone, Copy, Debug)]
pub struct VaultChains<'a> {
    /// Every head h(V, d) as one vector: entry d is the `device_seq` of the last op of d the
    /// server holds in the vault, 0 if none. For a normal upload, the vault's current heads;
    /// for a snapshot inside a healing request, the heads after the request's headers, the
    /// same heads its clamp uses (§2).
    pub heads: &'a VersionVector,
    /// The revocation cut-off of every revoked device: its signed `last_accepted_device_seq`
    /// (ADR 0012 §6). A device is revoked exactly when it has an entry here.
    pub cutoffs: &'a BTreeMap<DeviceId, u64>,
}

/// Why the server refuses a snapshot (ADR 0021 §9). Carries only server-visible metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SnapshotRefusal {
    /// The author is revoked: "the server refuses new ones after the author's revocation".
    AuthorRevoked,
    /// The author's certificate has expired: "refuses new ones after the author's … expiry".
    AuthorExpired,
    /// The covered-VV entry for its own author is above that author's head.
    AuthorEntryAboveHead,
    /// The covered VV exceeds the heads for this device, a revoked device's entry counted only
    /// up to its `last_accepted_device_seq`. Inside a healing request the heads are those after
    /// the request's headers (see [`check_snapshot`]).
    ClaimsUnheldDots {
        /// The first device, by `device_id`, whose entry exceeds its head.
        device_id: DeviceId,
    },
}

impl fmt::Display for SnapshotRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuthorRevoked => "snapshot author is revoked",
            Self::AuthorExpired => "snapshot author's certificate has expired",
            Self::AuthorEntryAboveHead => {
                "snapshot claims its author's dots the server does not hold"
            }
            Self::ClaimsUnheldDots { .. } => "snapshot claims dots the server does not hold",
        })
    }
}

impl core::error::Error for SnapshotRefusal {}

/// A healing request stores a bodiless header of the item that none of the item's snapshots
/// covers, so the server refuses the whole request (ADR 0021 §9 "Server acceptance").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UncoveredHeader {
    /// The lowest such header's dot.
    pub dot: Dot,
}

impl fmt::Display for UncoveredHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a healing request stores a bodiless header without a cover")
    }
}

impl core::error::Error for UncoveredHeader {}

/// The clamped VV of a snapshot (ADR 0021 §2): `min(covered[d], h(V, d))` for every device,
/// zero entries left out.
///
/// The caller computes it once, in the transaction that stores the snapshot, under the account
/// lock, from the heads at that moment (inside a healing request, after the request's headers),
/// and persists it with the snapshot in the canonical VV encoding. It is never sent. It is at
/// most the covered VV, so a cover by it also counts in the client's chain check
/// (ADR 0012 §7).
#[must_use]
pub fn clamp(covered: &VersionVector, heads: &VersionVector) -> VersionVector {
    let mut clamped = covered.clone();
    clamped.meet(heads);
    clamped
}

/// R1 then R3 for one item (ADR 0021 §3): the bodies `worker` deletes and the snapshots it
/// drops, recomputed from the item's current retained snapshots and ops.
///
/// `snapshots` are the item's retained snapshots in any order; `ops` are all of the item's
/// stored ops, bodiless headers included, in any order. R1 runs first and R3 over its result,
/// counting the bodies R1 deletes in this run as bodiless, as the merge spike's `worker` does
/// (§3 does not say whether R3 sees R1's deletions of the same run). Running the plan's result
/// through `plan_worker` again yields an empty plan.
///
/// # Errors
/// [`InputError::DuplicateStoreSeq`] if two snapshots share a store sequence, and
/// [`InputError::DuplicateOp`] if a dot appears twice in `ops`.
pub fn plan_worker(
    snapshots: &[RetainedSnapshot],
    ops: &[OpDot],
) -> Result<WorkerPlan, InputError> {
    let ordered = by_store_seq(snapshots)?;
    let ops = index_ops(ops)?;
    let delete_bodies = r1_deletions(&ordered, &ops);
    let mut bodiless: BTreeSet<Dot> = ops
        .iter()
        .filter(|&(_, &body)| body == Body::Absent)
        .map(|(&dot, _)| dot)
        .collect();
    bodiless.extend(delete_bodies.iter().copied());
    let drop_snapshots = r3_drops(&ordered, &bodiless);
    Ok(WorkerPlan {
        delete_bodies,
        drop_snapshots,
    })
}

/// The covers of one item for one Fetch response or page (ADR 0021 §4, owner rule 2).
///
/// `snapshots` are the item's retained snapshots, read in the same read transaction as the
/// response's headers and bodies (§4 "One consistent read"); `bodiless` are the item's bodiless
/// headers in this response or page, each page carrying its own covers. Duplicates in
/// `bodiless` count once.
///
/// Newest first, a snapshot is added when it covers a bodiless header that the snapshots added
/// so far cover by no author, or by one author other than its own. So every header gets covers
/// by two authors when the retained snapshots have them, and one otherwise.
///
/// # Errors
/// [`InputError::DuplicateStoreSeq`] if two snapshots share a store sequence.
pub fn select_covers(
    snapshots: &[RetainedSnapshot],
    bodiless: &[Dot],
) -> Result<CoverSelection, InputError> {
    let ordered = by_store_seq(snapshots)?;
    let headers: BTreeSet<Dot> = bodiless.iter().copied().collect();
    // The authors of the covers added so far, per header they cover.
    let mut authors: BTreeMap<Dot, BTreeSet<DeviceId>> = BTreeMap::new();
    let mut covers = Vec::new();
    for snapshot in ordered.iter().rev() {
        let adds = headers.iter().any(|&dot| {
            snapshot.covers(dot)
                && authors
                    .get(&dot)
                    .is_none_or(|by| by.len() == 1 && !by.contains(&snapshot.author))
        });
        if adds {
            covers.push(snapshot.store_seq);
            for &dot in headers.iter().filter(|&&dot| snapshot.covers(dot)) {
                authors.entry(dot).or_default().insert(snapshot.author);
            }
        }
    }
    let uncovered = headers
        .into_iter()
        .filter(|dot| !authors.contains_key(dot))
        .collect();
    Ok(CoverSelection { covers, uncovered })
}

/// Whether the server accepts a snapshot, before storing it (ADR 0021 §9 "Server acceptance",
/// "Revoked and kind-4 authors").
///
/// `author` and `covered` come from the snapshot's verified header; `chains` holds the heads at
/// this point of the transaction and the revocation cut-offs. For a normal upload the heads are
/// the vault's current ones; for a snapshot inside a healing request, the heads after the
/// request's headers, the same heads its clamp uses (§2). The checks, in order:
///
/// 1. the server refuses new snapshots after the author's revocation or expiry (retained ones
///    keep counting as covers);
/// 2. it refuses any snapshot whose covered-VV entry for its author is above that author's
///    head;
/// 3. it refuses a snapshot whose covered VV exceeds its heads, counting a revoked device's
///    entry only up to its `last_accepted_device_seq`.
///
/// **Inside a healing request.** §9 states check 3 for a snapshot "outside a request" and says
/// nothing of one inside a request. This function applies it inside a healing request too,
/// against the heads after the request's headers, as the merge spike's `integrated` server does
/// (`SnapClaims::RefuseUnheld`: "a healing request stores the claimed headers before its
/// snapshots, so its snapshots pass"); ADR 0021 "Settled by the merge spike" rests on that
/// preset. The other reading, which skips check 3 inside a request, would let any device that
/// passes checks 1 and 2 store a snapshot claiming other devices' dots nobody holds, up to
/// `u64::MAX`, by sending a healing request with no headers, and would serve those claims to
/// clients as covers: the claims owner decision 4 refuses. The clamp would still keep such a
/// snapshot from covering an op stored after it, but the spike never validated that reading.
/// The revoked device's cap is what keeps a healer whose state holds a revoked device's op past
/// its cut-off from being refused for good (the ADR 0012 §6 path of §9 "Restored-server
/// revocation").
///
/// All three checks apply to a held snapshot re-published verbatim in a healing request as to a
/// fresh one, as the merge spike's server applies them. Which records are new, as opposed to
/// "already stored", is the caller's check (§9 "Already stored").
///
/// # Errors
/// The first failing check, as a [`SnapshotRefusal`].
pub fn check_snapshot(
    author: DeviceId,
    covered: &VersionVector,
    chains: VaultChains<'_>,
    expiry: CertificateExpiry,
) -> Result<(), SnapshotRefusal> {
    if chains.cutoffs.contains_key(&author) {
        return Err(SnapshotRefusal::AuthorRevoked);
    }
    if expiry == CertificateExpiry::Expired {
        return Err(SnapshotRefusal::AuthorExpired);
    }
    if covered.get(author) > chains.heads.get(author) {
        return Err(SnapshotRefusal::AuthorEntryAboveHead);
    }
    for entry in covered.entries() {
        let device_id = entry.device_id();
        let counted = chains
            .cutoffs
            .get(&device_id)
            .map_or(entry.seq(), |&cutoff| entry.seq().min(cutoff));
        if counted > chains.heads.get(device_id) {
            return Err(SnapshotRefusal::ClaimsUnheldDots { device_id });
        }
    }
    Ok(())
}

/// Whether a healing request's bodiless headers of one item all have a cover (ADR 0021 §9
/// "Server acceptance": "The server stores a bodiless header only inside a healing request
/// whose snapshots cover it, clamped after the request's headers, else it refuses the whole
/// request").
///
/// `snapshots` are the item's retained snapshots once the request's snapshots are stored, the
/// request's own clamped after the request's headers (§2); `stored_bodiless` are the item's
/// headers the request stores without a body. A snapshot stored before the request is clamped
/// below every header the request stores, which lies above the head of its chain, so only the
/// request's own snapshots can cover them: passing all retained snapshots, as the merge spike's
/// server does, gives the same answer as passing the request's alone.
///
/// # Errors
/// [`UncoveredHeader`] naming the lowest header no snapshot covers; the caller then refuses
/// the whole request and rolls its transaction back.
pub fn check_healing_request(
    snapshots: &[RetainedSnapshot],
    stored_bodiless: &[Dot],
) -> Result<(), UncoveredHeader> {
    let uncovered = stored_bodiless
        .iter()
        .copied()
        .filter(|&dot| !snapshots.iter().any(|s| s.covers(dot)))
        .min();
    match uncovered {
        Some(dot) => Err(UncoveredHeader { dot }),
        None => Ok(()),
    }
}

/// The snapshots sorted by store sequence, oldest first.
///
/// # Errors
/// [`InputError::DuplicateStoreSeq`] if two share a store sequence.
fn by_store_seq(snapshots: &[RetainedSnapshot]) -> Result<Vec<&RetainedSnapshot>, InputError> {
    let mut ordered: Vec<&RetainedSnapshot> = snapshots.iter().collect();
    ordered.sort_by_key(|s| s.store_seq);
    for pair in ordered.windows(2) {
        if let [a, b] = pair
            && a.store_seq == b.store_seq
        {
            return Err(InputError::DuplicateStoreSeq(a.store_seq));
        }
    }
    Ok(ordered)
}

/// The ops keyed by dot.
///
/// # Errors
/// [`InputError::DuplicateOp`] if a dot appears twice.
fn index_ops(ops: &[OpDot]) -> Result<BTreeMap<Dot, Body>, InputError> {
    let mut indexed = BTreeMap::new();
    for op in ops {
        if indexed.insert(op.dot, op.body).is_some() {
            return Err(InputError::DuplicateOp(op.dot));
        }
    }
    Ok(indexed)
}

/// The distinct authors of the retained snapshots that cover `dot`.
fn cover_authors(ordered: &[&RetainedSnapshot], dot: Dot) -> BTreeSet<DeviceId> {
    ordered
        .iter()
        .filter(|s| s.covers(dot))
        .map(|s| s.author)
        .collect()
}

/// R1 (ADR 0021 §3): the held bodies that the older of the two newest snapshots covers and
/// that snapshots by two different authors cover. Nothing with fewer than two snapshots.
fn r1_deletions(ordered: &[&RetainedSnapshot], ops: &BTreeMap<Dot, Body>) -> Vec<Dot> {
    // `ordered` is oldest first, so the older of the two newest is the second from the end.
    let Some(older) = ordered.iter().rev().nth(1) else {
        return Vec::new();
    };
    ops.iter()
        .filter(|&(&dot, &body)| {
            body == Body::Held && older.covers(dot) && cover_authors(ordered, dot).len() >= 2
        })
        .map(|(&dot, _)| dot)
        .collect()
}

/// R3 (ADR 0021 §3): the store sequences of the older snapshots to drop, oldest first, given
/// every bodiless header of the item after R1. See the module docs, "R3 in one pass", for why
/// one pass equals the rule's re-test after each drop.
fn r3_drops(ordered: &[&RetainedSnapshot], bodiless: &BTreeSet<Dot>) -> Vec<u64> {
    let Some((older, _two_newest)) = ordered
        .len()
        .checked_sub(2)
        .and_then(|n| ordered.split_at_checked(n))
    else {
        return Vec::new();
    };
    // Per bodiless header that some retained snapshot covers: the number of covering retained
    // snapshots per author.
    let mut covers: BTreeMap<Dot, BTreeMap<DeviceId, usize>> = BTreeMap::new();
    for &dot in bodiless {
        for snapshot in ordered.iter().filter(|s| s.covers(dot)) {
            let count = covers
                .entry(dot)
                .or_default()
                .entry(snapshot.author)
                .or_insert(0);
            *count = count.saturating_add(1);
        }
    }
    let mut dropped = Vec::new();
    for snapshot in older {
        let needed = covers.iter().any(|(&dot, by_author)| {
            snapshot.covers(dot) && lowers_below_two(by_author, snapshot.author)
        });
        if needed {
            continue;
        }
        dropped.push(snapshot.store_seq);
        for (_, by_author) in covers.iter_mut().filter(|(dot, _)| snapshot.covers(**dot)) {
            if let Some(count) = by_author.get_mut(&snapshot.author) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    by_author.remove(&snapshot.author);
                }
            }
        }
    }
    dropped
}

/// Whether dropping one covering snapshot by `author` would lower the number of distinct
/// authors that cover a header, counted in `by_author`, to fewer than two (R3).
fn lowers_below_two(by_author: &BTreeMap<DeviceId, usize>, author: DeviceId) -> bool {
    let with = by_author.len();
    let without = if by_author.get(&author) == Some(&1) {
        with.saturating_sub(1)
    } else {
        with
    };
    without < 2 && without < with
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
    reason = "the simulated server indexes fixtures it built; a panic there fails the test, which CLAUDE.md allows"
)]
mod sim;
