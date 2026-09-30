//! Server-mode sync: upload, Fetch and the healing request (ADR 0012 §7 as ADR 0021 §1, §2, §4
//! and §9 supersede it in part; ADR 0022: Server mode only).
//!
//! | Step | Request | Response |
//! |---|---|---|
//! | Upload, in `device_seq` order | [`UploadRequest`] | [`UploadResponse`] |
//! | Fetch from a cursor, paged | [`FetchRequest`] | [`FetchResponse`] |
//! | Restore healing, one atomic request per vault (ADR 0021 §9 "Healing request") | [`HealingRequest`] | [`HealingResponse`] |
//!
//! **Records.** An op or snapshot travels as its signed statement plus the envelopes the
//! statement signs by hash (CRYPTO.md §10.2): the body and, when present, the `ITEM_KEY_WRAP`.
//! The server parses the canonical header from the statement with `rizzy-sync`, verifies the
//! signature with `rizzy-core`, and checks each carried envelope against its signed hash; a
//! receiver does the same before anything else (ADR 0012 §3). An op whose body the server
//! deleted, or which a healing request stored without it, travels without `body`: a
//! bodiless header (ADR 0021 §2). A snapshot always carries its envelope.
//!
//! **The restore generation** (ADR 0021 §2): "Every upload answer and Fetch response carries
//! it." The healing answer carries it too, as the answer to an upload.
//!
//! **Heads** (ADR 0021 §2): the Fetch response carries the server's head h(V, d) per device, so
//! the client can evaluate "Server behind" (§9; `rizzy-sync` `causal::ServerView`), which needs
//! heads even where the page serves no header.
//!
//! The endpoint paths and methods are ADR 0028 item 1's ([`crate::http::paths`]). **Not fixed
//! by an ADR:** how a
//! paged Fetch continues. This crate reads "a paged response" (ADR 0021 §4) conservatively: the
//! client sends its advanced cursor again until a response says `complete`.

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::error::ErrorCode;
use crate::limits::{MAX_ITEM_KEY_WRAPS, MAX_RECORDS, MAX_VV_ENTRIES, RESTORE_GENERATION_LEN};
use crate::objects::{Envelope, ItemKeyWrap, KeyEnvelope, OpStatement, SnapshotStatement};
use crate::wire::{Fixed, Id, List, WireError};

/// A server database's restore generation (ADR 0021 §2): 128 random bits, redrawn by each
/// `rizzy-vault restore`. Server-visible metadata, not a secret.
pub type RestoreGeneration = Fixed<RESTORE_GENERATION_LEN>;

/// One entry of a [`SeqVector`]: a device and a `device_seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeqEntry {
    /// The device.
    pub device_id: Id,
    /// A `device_seq`, at least 1.
    pub seq: u64,
}

/// A per-device sequence vector in canonical form, as ADR 0012 §3 requires of every version
/// vector: entries strictly ascending by `device_id` bytewise (so no duplicates), every `seq`
/// at least 1 (a missing entry means 0), at most `u16::MAX` entries. Used for a Fetch cursor
/// ("the highest `device_seq` it has per device", ADR 0012 §7) and for the server's heads.
///
/// Deserialising rejects any other form, so each vector has one JSON form.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SeqVector(List<SeqEntry, MAX_VV_ENTRIES>);

impl SeqVector {
    /// Checks and wraps `entries`.
    ///
    /// # Errors
    /// [`WireError::TooMany`] above `u16::MAX` entries; [`WireError::NotCanonical`] for a zero
    /// `seq` or entries not strictly ascending by `device_id`.
    pub fn new(entries: Vec<SeqEntry>) -> Result<Self, WireError> {
        Self::checked(List::new(entries)?)
    }

    /// The canonical-form check.
    fn checked(entries: List<SeqEntry, MAX_VV_ENTRIES>) -> Result<Self, WireError> {
        let slice = entries.as_slice();
        let ascending = slice
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.device_id < b.device_id));
        if ascending && slice.iter().all(|e| e.seq >= 1) {
            Ok(Self(entries))
        } else {
            Err(WireError::NotCanonical)
        }
    }

    /// The entries, ascending by `device_id`.
    #[must_use]
    pub fn entries(&self) -> &[SeqEntry] {
        self.0.as_slice()
    }

    /// The `seq` for `device_id`, 0 if absent.
    #[must_use]
    pub fn get(&self, device_id: &Id) -> u64 {
        self.entries()
            .binary_search_by(|e| e.device_id.cmp(device_id))
            .ok()
            .and_then(|i| self.entries().get(i))
            .map_or(0, |e| e.seq)
    }
}

impl<'de> Deserialize<'de> for SeqVector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = List::<SeqEntry, MAX_VV_ENTRIES>::deserialize(deserializer)?;
        Self::checked(entries).map_err(de::Error::custom)
    }
}

/// An `ITEM_KEY_WRAP` carried with an op or snapshot (ADR 0012 §3 "Key wrap"), with the one
/// locator field its record's header does not already name: the item key's id (CRYPTO.md
/// §4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordKeyWrap {
    /// The wrapped item key's key id.
    pub item_key_id: Id,
    /// The envelope.
    pub envelope: KeyEnvelope,
}

/// An op record (ADR 0012 §3): the signed `op` statement, the body unless it is a bodiless
/// header, and the key wrap when the op carries one and the server still serves it (CRYPTO.md
/// §4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpRecord {
    /// The `op` statement.
    pub statement: OpStatement,
    /// The `ITEM_OP` envelope; absent for a bodiless header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Envelope>,
    /// The `ITEM_KEY_WRAP` carried with the op.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_wrap: Option<RecordKeyWrap>,
}

/// A snapshot record (ADR 0012 §3; ADR 0021 §4 "Each comes as its full record: header, envelope,
/// signature and, if held, its wrap").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    /// The `snapshot` statement.
    pub statement: SnapshotStatement,
    /// The `ITEM_SNAPSHOT` envelope.
    pub envelope: Envelope,
    /// The `ITEM_KEY_WRAP` carried with the snapshot, if held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_wrap: Option<RecordKeyWrap>,
}

/// One record of an upload or healing request, in the order the server must store it: a
/// device's ops in chain order, a snapshot after the ops it covers (ADR 0012 §7 "Upload";
/// ADR 0021 §2, §9 "Server acceptance").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Record {
    /// An op.
    Op(OpRecord),
    /// A snapshot.
    Snapshot(SnapshotRecord),
}

/// An upload (ADR 0012 §7 "Upload"; ADR 0021 §9): records of one vault, in order. The server
/// stores each under the account lock and answers each (ADR 0021 §9 "Already stored",
/// "Stale epoch", "Revoked and kind-4 authors").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    /// The vault.
    pub vault_id: Id,
    /// The records, in storing order.
    pub records: List<Record, MAX_RECORDS>,
}

/// The server's answer to one uploaded record.
///
/// This crate's reading of a batch: the server answers every record, in request order, and
/// after the first `rejected` record it stores nothing further from that request and answers
/// the rest `not_processed`, because a later op of the same chain cannot pass the
/// `vault_prev_seq` check without the earlier one (ADR 0012 §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum UploadResult {
    /// Stored now.
    Stored,
    /// Byte-identical to the record stored at that dot or `snapshot_id`; nothing stored, and
    /// the client treats it as an acknowledgement (ADR 0021 §9 "Already stored").
    AlreadyStored,
    /// Refused, with the reason: [`ErrorCode::StaleEpoch`], [`ErrorCode::RecordConflict`],
    /// [`ErrorCode::PrevSeqMismatch`], or [`ErrorCode::InvalidRequest`] for a record that fails
    /// parsing, signature or author checks.
    Rejected {
        /// The reason.
        error: ErrorCode,
    },
    /// Not looked at, because an earlier record of the request was rejected.
    NotProcessed,
}

/// The answer to an [`UploadRequest`].
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadResponse {
    /// The server database's restore generation (ADR 0021 §2).
    pub restore_generation: RestoreGeneration,
    /// One result per request record, in request order.
    pub results: List<UploadResult, MAX_RECORDS>,
}

/// A Fetch (ADR 0012 §7 "Fetch"): the device's cursor for one vault, and the newest
/// `vault_key_epoch` of the wrap-set rows it already fetched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    /// The vault.
    pub vault_id: Id,
    /// The highest `device_seq` the device has, per device.
    pub cursor: SeqVector,
    /// The `vault_key_epoch` of the wrap-set rows last fetched; absent on a first fetch, which
    /// receives every row (ADR 0012 §7; CRYPTO.md §4.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wraps_after_epoch: Option<u32>,
}

/// A Fetch response page (ADR 0012 §7 "Fetch" as ADR 0021 §4 amends it), from one consistent
/// read.
///
/// A response type: unknown fields are ignored. The client verifies every header and envelope
/// and runs its chain check (ADR 0012 §7 "Chain check after compaction"); nothing here is
/// trusted because the server sent it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchResponse {
    /// The server database's restore generation (ADR 0021 §2).
    pub restore_generation: RestoreGeneration,
    /// The server's head h(V, d) for every device with ops in the vault (ADR 0021 §2).
    pub heads: SeqVector,
    /// Every op header after the cursor, per device in chain order, with its body when held.
    pub ops: List<OpRecord, MAX_RECORDS>,
    /// The covers of this page's bodiless headers (ADR 0021 §4).
    pub covers: List<SnapshotRecord, MAX_RECORDS>,
    /// Wrap-set rows newer than the request's `wraps_after_epoch`.
    pub item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>,
    /// `true` when nothing after this page remains: a complete Fetch (ADR 0021 §9 "Revoked and
    /// kind-4 authors"). `false`: fetch again from the advanced cursor.
    pub complete: bool,
}

/// Restore healing for one vault (ADR 0021 §9 "Healing request", replacing ADR 0012 §7
/// "Healing a server rollback" step 4): "every item-key wrap the server lacks, then per chain
/// from h + 1 up to the device's cursor … every header the device holds, with its body if it
/// holds the body of a record the server stored before, else without it behind the request's
/// fresh snapshot or a held snapshot sent verbatim". Atomic under the account lock: the server
/// stores all of it or refuses all of it (§9 "Server acceptance").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealingRequest {
    /// The vault.
    pub vault_id: Id,
    /// The item-key wraps the server lacks.
    pub item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>,
    /// Headers (with or without bodies) and snapshots, in storing order.
    pub records: List<Record, MAX_RECORDS>,
}

/// The answer to an accepted [`HealingRequest`]; a refused one gets an
/// [`ErrorResponse`](crate::error::ErrorResponse).
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealingResponse {
    /// The server database's restore generation (ADR 0021 §2).
    pub restore_generation: RestoreGeneration,
}
