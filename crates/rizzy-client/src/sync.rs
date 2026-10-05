//! The sync driver of one vault on one device (ADR 0012 §4, §7; ADR 0018 §3, §10; ADR 0021
//! §2, §4, §9; CRYPTO.md §8.4, §10.2, §11.6 reader and writer rules).
//!
//! [`VaultSync`] owns the vault's [`VaultLog`] (the per-device chains, `rizzy_sync::causal`),
//! one [`ItemMerge`] per item (`rizzy_sync::merge`), the item keys it could open, the decrypted
//! op data it still needs, and the own records waiting for upload. The host drives it:
//!
//! ```text
//! fetch_request ──FetchRequest──► host ──FetchResponse──► apply_fetch(authors, …)
//! (edits: crate::items) ──► upload_request ──UploadRequest──► host ──UploadResponse──►
//!   apply_upload_response
//! ```
//!
//! # Fetch: verify first (ADR 0012 §4 step 1)
//!
//! For every served op record, in this order, and before anything is trusted:
//! 1. The signer's certificate by the key id in the signature container ([`Authors`]); an
//!    unknown signer drops the record, and the chain check reports the gap it leaves.
//! 2. `verify_strict` of the `op` statement under that key; the header parsed strictly; it
//!    names the certificate's device and this vault; the author checks (revocation cut-off,
//!    certificate expiry against the header's HLC).
//! 3. A carried `ITEM_KEY_WRAP` only if it matches the signed wrap hash; it opens under the
//!    vault key with the context rebuilt from the header, and the item key joins the item's
//!    wrap set under its derived id (the locator is never trusted, CRYPTO.md §4.2).
//! 4. A served body only if it matches the signed body hash, then decrypted under the item key
//!    whose derived id the envelope header names (with the commitment check), then parsed by
//!    the record layer. A body under an unknown item key waits for its wrap (§11.6 reader
//!    rule); a body of an unknown `item_schema_version` is parked (ADR 0018 §11); any other
//!    failure rejects the body.
//!
//! Covers (snapshot records) are verified the same way, with the snapshot author bound of
//! CRYPTO.md §10.2 rule (c) and §11.8 step 4. Then the `causal` cycle: plan, absorb, commit,
//! deliver.
//!
//! # Upload
//!
//! Own ops go up in chain order, then the own snapshots whose own entry is acknowledged (the
//! server refuses a snapshot claiming its author's unstored dots, ADR 0021 §9). "Already
//! stored" is an acknowledgement. The restore generation of every answer goes to the log, so
//! an op the server may have stored and served is never re-issued.
//!
//! # Key rotation (ADR 0025)
//!
//! The driver keeps the wrap-set rows of the last Fetch as served and knows whether it is
//! synced (a complete Fetch after its last write or upload). [`crate::rotation`] builds each
//! vault's half of a rotation from them: this device's exact cursor, every row it can open
//! re-wrapped under the new vault key, the rest dropped. After the commit, and after a rotation
//! elsewhere, [`VaultSync::adopt_vault_key`] moves the driver to the new epoch; a second key
//! at an epoch it already saw is a fork alarm and makes the vault read-only.
//!
//! # Read-only
//!
//! The vault is read-only while the host says so ([`VaultSync::set_read_only`]: a rollback, a
//! fork or an unconfirmed identity change of the account) or while the server is behind this
//! device ([`VaultLog::server_behind`], checked on every Fetch). No op is written then.
//!
//! # Restore healing and stale answers (ADR 0021 §9)
//!
//! While the server is behind, the host sends the healing request of the `heal` module
//! ([`VaultSync::healing_request`]) and Fetches again; the vault leaves read-only once no
//! condition of "Server behind" holds. The conditions are evaluated on every Fetch: a head
//! below this device's cursor, item-VV entry or acknowledged own `device_seq`, and a wrap the
//! server lacks that this device got from it or had acknowledged ([`VaultSync`]
//! `known_wraps`, compared with the served wrap-set rows by item and derived item-key id).
//!
//! A stale-epoch answer to an own op written at the old epoch before this device learned of a
//! rotation (ADR 0025 §4) is re-issued: once the host adopts the new vault key
//! ([`VaultSync::adopt_vault_key`]; until then [`ClientError::VaultKeyRotated`]), the next
//! upload re-issues it and the later old-epoch ops of the chain with the same `device_seq`
//! under the writer rule's item key (a fresh one when every held key is stale, CRYPTO.md
//! §11.6), and a stale snapshot is rewritten. An own op of that plan that the server may have
//! stored and served before a restore is never re-issued: [`VaultSync::upload_request`]
//! answers [`ClientError::HealingRequired`] until a healing request re-published it.
//!
//! # Not in this build (reported)
//!
//! - The server's `state_seq` in "Server behind": the account-state checks of
//!   [`crate::unlock`] cover a lower `state_seq`, so the vault check passes 0 for both.
//!
//! # Device sequence numbers
//!
//! `device_seq` counts a device's ops in every vault, so the counter lives with the device
//! (`rizzy_sync::causal::own`). M1 has one vault per account; the host passes the next
//! `device_seq` when it builds the driver, and reads it back with
//! [`VaultSync::next_device_seq`].

mod heal;

pub use heal::HealingOutcome;

use std::collections::{BTreeMap, BTreeSet};

use core::fmt;

use rizzy_core::envelope::parse::{EnvelopeRef, parse as parse_envelope};
use rizzy_core::envelope::purpose::ItemKeyWrapCtx;
use rizzy_core::envelope::{open, seal};
use rizzy_core::ids::{DeviceId, ItemId, PublicKeyId, SnapshotId, SymmetricKeyId, VaultId};
use rizzy_core::item::SchemaVersion;
use rizzy_core::keys::{ItemKey, VaultKey};
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret::SecretBytes;
use rizzy_core::sign::{
    CONTAINER_LEN, DeviceKind, DeviceVerifyingKey, OpStatement, SignatureContainer,
    SnapshotStatement,
};
use rizzy_proto::error::ErrorCode;
use rizzy_proto::limits::MAX_RECORDS;
use rizzy_proto::objects::ItemKeyWrap;
use rizzy_proto::vault::{
    FetchRequest, FetchResponse, OpRecord, Record, RecordKeyWrap, SeqEntry, SeqVector,
    SnapshotRecord, UploadRequest, UploadResponse, UploadResult,
};
use rizzy_proto::wire::List;
use rizzy_sync::causal::{
    AuthorStatus, BodyStatus, Report, RestoreGeneration, ServedOp, ServerView, VaultLog,
    check_op_author, check_snapshot_author,
};
use rizzy_sync::dot::Dot;
use rizzy_sync::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use rizzy_sync::hlc::Hlc;
use rizzy_sync::merge::{AbsorbOutcome, ItemMerge, OpInput, SnapshotInput};
use rizzy_sync::record::{parse_op, parse_snapshot};
use rizzy_sync::vv::VersionVector;

use crate::account::{CertifiedDevice, RevokedDevice, VerifiedAccount};
use crate::device::UnlockedDevice;
use crate::error::{ClientError, internal};
use crate::store::floors::{id16, u64_be};
use crate::store::rows::{Changeset, OpRow, SnapshotRow, WrapRow, Write, meta, own};
use crate::wire::{bytes, id};

/// One author of the account: its certificate's key and status (ADR 0012 §4 step 1).
#[derive(Clone, Debug)]
pub(crate) struct Author {
    /// The key id the signature container names.
    pub(crate) key_id: PublicKeyId,
    /// The certificate's device key.
    pub(crate) verifying_key: DeviceVerifyingKey,
    /// Revocation cut-off and expiry.
    pub(crate) status: AuthorStatus,
    /// The certificate's kind.
    pub(crate) kind: DeviceKind,
}

/// The verified certificates and revocations of the account, indexed for op verification.
/// Built only from statements that verified under the identity key ([`crate::account`]).
#[derive(Clone, Debug, Default)]
pub struct Authors {
    /// Every author.
    pub(crate) entries: Vec<Author>,
}

impl Authors {
    /// The authors of a verified account answer.
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] if a revocation names a device twice.
    pub fn from_account(account: &VerifiedAccount) -> Result<Self, ClientError> {
        Self::from_statements(account.certificates(), account.revocations())
    }

    /// The authors of verified certificates and revocations.
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] if two revocations name one device.
    pub fn from_statements(
        certificates: &[CertifiedDevice],
        revocations: &[RevokedDevice],
    ) -> Result<Self, ClientError> {
        let mut entries = Vec::with_capacity(certificates.len());
        for c in certificates {
            let cert = &c.certificate;
            let mut matching = revocations
                .iter()
                .filter(|r| r.revocation.device_id == cert.device_id);
            let revocation = matching.next().map(|r| r.revocation.statement());
            if matching.next().is_some() {
                return Err(ClientError::InvalidServerResponse);
            }
            let status = AuthorStatus::from_statements(cert.statement(), revocation)
                .map_err(|_| ClientError::InvalidServerResponse)?;
            entries.push(Author {
                key_id: cert.device_ed25519.key_id(),
                verifying_key: cert.device_ed25519,
                status,
                kind: cert.device_kind,
            });
        }
        Ok(Self { entries })
    }

    /// The author whose key signed `wire`: the key id in the statement's last 82 bytes.
    pub(crate) fn signer(&self, wire: &[u8]) -> Option<&Author> {
        let tail = wire
            .len()
            .checked_sub(CONTAINER_LEN)
            .and_then(|at| wire.get(at..))?;
        let container = SignatureContainer::from_bytes(tail).ok()?;
        self.entries
            .iter()
            .find(|a| a.key_id == *container.signer_key_id())
    }
}

/// An own op record, kept until acknowledged, and its decrypted data's key id.
#[derive(Clone)]
struct OwnRecord {
    /// The record as uploaded.
    record: OpRecord,
}

/// An own snapshot waiting for upload.
#[derive(Clone)]
struct OwnSnapshot {
    /// Its header.
    header: SnapshotHeader,
    /// The record as uploaded.
    record: SnapshotRecord,
}

/// What an upload request carried, in order, to match the answer's results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InFlight {
    /// An own op, by `device_seq`.
    Op(u64),
    /// An own snapshot, by its id.
    Snapshot(SnapshotId),
}

/// A body that waits for its item key's wrap.
struct WaitingBody {
    /// The op's header.
    header: OpHeader,
    /// The `ITEM_OP` envelope.
    envelope: Vec<u8>,
}

/// What a Fetch did, as server-visible metadata only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchOutcome {
    /// The ops applied.
    pub applied: usize,
    /// Covers absorbed.
    pub absorbed: usize,
    /// Covers the merge refused ("Snapshots are claims").
    pub refused_covers: usize,
    /// Records dropped before the chain check: unknown signer, bad signature, foreign vault,
    /// author checks.
    pub dropped: usize,
    /// The chain check's reports, and after a complete Fetch the missing-data reports.
    pub reports: Vec<Report>,
    /// Whether the server is behind this device (the vault is read-only).
    pub server_behind: bool,
    /// Whether the server holds more of this device's own history than this device does
    /// ([ADR 0026] §4 step 7): an own head above the highest own `device_seq` held, or a served
    /// own record this device does not hold or holds with other bytes. The device state is an
    /// older copy; the host raises the alarm and goes read-only
    /// ([`ClientError::DeviceStateOutdated`]). The server's head is unsigned, so it only raises
    /// the alarm: it never moves `next_device_seq`.
    ///
    /// [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
    pub own_history_ahead: bool,
}

/// What an upload answer did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadOutcome {
    /// Own ops acknowledged.
    pub acknowledged: usize,
    /// Own snapshots stored.
    pub snapshots_stored: usize,
    /// Own snapshots the server refused and this client discarded.
    pub snapshots_discarded: usize,
    /// Answers that refused an own op, by error code.
    pub rejected: Vec<ErrorCode>,
    /// Whether the server refused an own op as a conflict at its dot (`record_conflict`): it
    /// holds another record there, so this device state is an older copy (ADR 0026 §4 step 7;
    /// [`FetchOutcome::own_history_ahead`]). No new bytes are signed for that dot.
    pub own_conflict: bool,
}

/// The persisted rows of one vault, as [`crate::store::load`] hands them to
/// [`VaultSync::restore`] after it checked their lengths (ADR 0026 §3, §4 step 5).
pub(crate) struct VaultImage<'a> {
    /// The stored `next_device_seq`.
    pub(crate) next_device_seq: u64,
    /// The stored HLC.
    pub(crate) hlc: u64,
    /// The restore generation of the last response, if any.
    pub(crate) generation: Option<RestoreGeneration>,
    /// The wrap-set rows.
    pub(crate) wraps: Vec<ItemKeyWrap>,
    /// The op rows of this vault.
    pub(crate) ops: Vec<&'a OpRow>,
    /// The snapshot rows of this vault.
    pub(crate) snapshots: Vec<&'a SnapshotRow>,
}

/// What [`VaultSync::settle`] accepted, for the cache journal.
#[derive(Default)]
struct Settled {
    /// The dots the commit accepted as new links.
    accepted: Vec<Dot>,
    /// The indexes, into the verified covers, of the covers the merge absorbed.
    absorbed: Vec<usize>,
}

/// What the journal last wrote of the values that live in `cache_meta` and `vaults`, so that a
/// value is written again only when it moved.
#[derive(Clone, Copy, Default)]
struct Journaled {
    /// `next_device_seq`.
    next_seq: u64,
    /// The HLC.
    hlc: u64,
    /// The restore generation.
    generation: Option<RestoreGeneration>,
}

/// The sync state of one vault (see the module docs). Holds decrypted item data and keys;
/// not `Clone`, `Debug` shows server-visible metadata only.
pub struct VaultSync {
    /// The vault.
    vault_id: VaultId,
    /// This device.
    device_id: DeviceId,
    /// The vault key.
    vault_key: VaultKey,
    /// The per-device chains.
    log: VaultLog,
    /// One merge per item.
    items: BTreeMap<ItemId, ItemMerge>,
    /// The item keys this device could open, per item.
    item_keys: BTreeMap<ItemId, Vec<ItemKey>>,
    /// Items whose merge asked for a snapshot; written at the next upload.
    pending_snapshots: BTreeSet<ItemId>,
    /// Verified op data still needed, with the key id of its envelope.
    bodies: BTreeMap<Dot, (SymmetricKeyId, SecretBytes)>,
    /// Bodies waiting for their item key.
    waiting_bodies: BTreeMap<Dot, WaitingBody>,
    /// Own op records not acknowledged yet.
    own_records: BTreeMap<u64, OwnRecord>,
    /// Own snapshots not uploaded yet.
    outbox: Vec<OwnSnapshot>,
    /// What the last upload request carried.
    in_flight: Vec<InFlight>,
    /// The HLC.
    clock: Hlc,
    /// The next own `device_seq`.
    next_seq: u64,
    /// Read-only by the host's decision.
    host_read_only: bool,
    /// Read-only because the server is behind.
    server_behind: bool,
    /// The last restore generation seen.
    generation: Option<RestoreGeneration>,
    /// The wrap-set rows of the last Fetch page (each page carries the whole set), as served:
    /// what a rotation re-wraps or drops (ADR 0025 §2 step 3).
    wrap_rows: Vec<ItemKeyWrap>,
    /// Whether the last Fetch page was complete, the server was not behind, and nothing was
    /// written or uploaded since: the cursor is what a rotation sends (ADR 0025 §2 step 1).
    synced: bool,
    /// Every `vault_key_epoch` this device held a vault key of, with that key's id: a second key
    /// at a seen epoch is a fork (ADR 0025 §4).
    seen_keys: BTreeMap<u32, SymmetricKeyId>,
    /// The lowest own `device_seq` the server answered `stale_epoch` and this device has not
    /// re-issued yet (ADR 0021 §9 "Stale epoch"; ADR 0025 §4). The next
    /// [`VaultSync::upload_request`] re-issues it and the later old-epoch ops of the chain.
    stale_from: Option<u64>,
    /// The cache writes of the steps since the last [`VaultSync::take_writes`], for a host that
    /// persists the vault (ADR 0026 §4); `None` for one that does not (the web vault).
    journal: Option<Vec<Write>>,
    /// What the journal last wrote of the counters and the restore generation.
    journaled: Journaled,
    /// Per own op the server answered without storing it: the restore generation of that
    /// answer. A re-issue names it, so the cache replaces only a row whose `sent_generation`
    /// is that generation (ADR 0026 §4 step 6). In memory only: "a `stale_epoch` answer changes
    /// no row".
    answered: BTreeMap<u64, RestoreGeneration>,
    /// Every op record this device holds that the server stored: each accepted served op and
    /// each acknowledged own op, verbatim (signed statement, the body while it is kept, the
    /// carried wrap with its derived locator). What a healing request re-publishes (ADR 0021
    /// §9 "Headers kept", "Healing request"); the body goes when [`VaultSync::prune_bodies`]
    /// drops it.
    held_ops: BTreeMap<Dot, OpRecord>,
    /// Every snapshot record this device holds as a cover: the covers it absorbed and its own
    /// snapshots the server acknowledged (ADR 0021 §9 "Headers kept": "every snapshot record
    /// they wrote or absorbed"). A healing request sends them verbatim as the covers of the
    /// headers it sends without a body.
    held_covers: Vec<(SnapshotHeader, SnapshotRecord)>,
    /// The server's heads h(V, d) in the last Fetch page, for the healing request's ranges.
    server_heads: Option<VersionVector>,
    /// The item-key wraps of this vault at the held vault key's epoch that this device got
    /// from the server (wrap-set rows, wraps carried by served records) or had acknowledged
    /// (wraps carried by own acknowledged ops), by item and derived item-key id (ADR 0021 §9
    /// "Server behind": "the server lacks an item-key wrap the device got from it or had
    /// acknowledged").
    known_wraps: BTreeMap<(ItemId, [u8; 16]), ItemKeyWrap>,
    /// The (item, item-key id) pairs of the wrap-set rows of the last Fetch page that opened
    /// at the held epoch.
    served_wraps: BTreeSet<(ItemId, [u8; 16])>,
    /// The vault-key epoch at which [`VaultSync::known_wraps`] holds the whole wrap set: the
    /// held epoch after a complete Fetch at it, or after a load (the cache writes the wrap set
    /// of an epoch in the transaction that adopts its key, ADR 0026 §4 step 3); `None` after a
    /// new key was adopted and before the next complete Fetch. Healing step 3b needs it (ADR
    /// 0032 §3 "Client precondition").
    wraps_complete_at: Option<u32>,
    /// The own `device_seq`s of the healing request in flight, for its answer.
    healing: Option<heal::HealInFlight>,
}

impl fmt::Debug for VaultSync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSync")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .field("items", &self.items.len())
            .field("read_only", &self.is_read_only())
            .finish_non_exhaustive()
    }
}

/// The cache rows of the served wrap-set rows at `epoch`, the epoch of the held vault key: the
/// only rows a [`Write::Wraps`] stores (a row at another epoch opens under no key this device
/// holds).
pub(crate) fn wrap_rows(vault_id: VaultId, epoch: u32, served: &[ItemKeyWrap]) -> Vec<WrapRow> {
    served
        .iter()
        .filter(|w| w.vault_key_epoch == epoch)
        .map(|w| WrapRow {
            vault_id: vault_id.to_bytes().to_vec(),
            item_id: w.item_id.to_bytes().to_vec(),
            item_key_id: w.item_key_id.to_bytes().to_vec(),
            vault_key_epoch: i64::from(w.vault_key_epoch),
            envelope: w.envelope.as_slice().to_vec(),
        })
        .collect()
}

/// Converts the server's heads to a version vector.
fn heads_vv(heads: &SeqVector) -> VersionVector {
    let mut vv = VersionVector::new();
    for e in heads.entries() {
        if let Some(dot) = Dot::new(DeviceId::from_bytes(e.device_id.to_bytes()), e.seq) {
            vv.add(dot);
        }
    }
    vv
}

impl VaultSync {
    /// The driver of `vault_id` with its vault key, for this device, whose next `device_seq`
    /// is `next_device_seq` (1 for a new device).
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if the vault key is another vault's or `next_device_seq`
    /// is 0.
    pub fn new(
        vault_key: VaultKey,
        unlocked: &UnlockedDevice,
        next_device_seq: u64,
    ) -> Result<Self, ClientError> {
        if next_device_seq == 0 {
            return Err(ClientError::InvalidInput);
        }
        let vault_id = vault_key.vault_id();
        let mut seen_keys = BTreeMap::new();
        seen_keys.insert(vault_key.epoch(), vault_key.key_id().map_err(internal)?);
        Ok(Self {
            vault_id,
            device_id: unlocked.device_id,
            vault_key,
            log: VaultLog::new(vault_id, unlocked.device_id),
            items: BTreeMap::new(),
            item_keys: BTreeMap::new(),
            pending_snapshots: BTreeSet::new(),
            bodies: BTreeMap::new(),
            waiting_bodies: BTreeMap::new(),
            own_records: BTreeMap::new(),
            outbox: Vec::new(),
            in_flight: Vec::new(),
            clock: Hlc::ZERO,
            next_seq: next_device_seq,
            host_read_only: false,
            server_behind: false,
            generation: None,
            wrap_rows: Vec::new(),
            synced: false,
            seen_keys,
            stale_from: None,
            journal: None,
            journaled: Journaled::default(),
            answered: BTreeMap::new(),
            held_ops: BTreeMap::new(),
            held_covers: Vec::new(),
            server_heads: None,
            known_wraps: BTreeMap::new(),
            served_wraps: BTreeSet::new(),
            wraps_complete_at: None,
            healing: None,
        })
    }

    /// Turns the cache journal on (ADR 0026 §4): from now on every step records the rows it
    /// adds or changes, and the host takes them with [`VaultSync::take_writes`] and commits
    /// them in one transaction before it releases the next request. A host that persists the
    /// vault calls this once, on the driver of a new signup or enrolment;
    /// [`crate::store::load::load`] returns drivers with the journal already on.
    pub fn persist(&mut self) {
        if self.journal.is_none() {
            self.journal = Some(Vec::new());
        }
    }

    /// The cache writes of the steps since the last call, with the counters and the restore
    /// generation if they moved (ADR 0026 §4 steps 1–2 and 6). Empty when the journal is off
    /// or nothing changed.
    pub fn take_writes(&mut self) -> Changeset {
        let Some(journal) = self.journal.as_mut() else {
            return Changeset::new();
        };
        let mut writes = core::mem::take(journal);
        if self.journaled.next_seq != self.next_seq {
            writes.push(Write::Meta {
                key: meta::NEXT_DEVICE_SEQ,
                value: self.next_seq.to_be_bytes().to_vec(),
            });
            self.journaled.next_seq = self.next_seq;
        }
        let hlc = self.clock.to_u64();
        if self.journaled.hlc != hlc {
            writes.push(Write::Meta {
                key: meta::HLC,
                value: hlc.to_be_bytes().to_vec(),
            });
            self.journaled.hlc = hlc;
        }
        if let Some(generation) = self.generation
            && self.journaled.generation != Some(generation)
        {
            writes.push(Write::VaultGeneration {
                vault_id: self.vault_id.to_bytes(),
                generation: generation.to_bytes(),
            });
            self.journaled.generation = Some(generation);
        }
        // The counters come first: an own op row is admitted only with a counter above it.
        writes.sort_by_key(|w| !matches!(w, Write::Meta { .. }));
        writes.into_iter().collect()
    }

    /// Records one cache write, if the journal is on.
    fn record(&mut self, write: impl FnOnce() -> Write) {
        if let Some(journal) = self.journal.as_mut() {
            journal.push(write());
        }
    }

    /// The `ops` row of `record` with `header` (ADR 0026 §3). `body` and `wrap` say whether the
    /// served body and carried wrap matched the signed hashes; one that did not is not kept.
    fn op_row(
        &self,
        header: &OpHeader,
        record: &OpRecord,
        body: bool,
        wrap: bool,
        own: i64,
    ) -> OpRow {
        OpRow {
            vault_id: self.vault_id.to_bytes().to_vec(),
            device_id: header.dot.device_id().to_bytes().to_vec(),
            device_seq: header.dot.seq().to_be_bytes().to_vec(),
            item_id: header.item_id.to_bytes().to_vec(),
            statement: record.statement.as_slice().to_vec(),
            body: record
                .body
                .as_ref()
                .filter(|_| body)
                .map(|b| b.as_slice().to_vec()),
            key_wrap: record
                .key_wrap
                .as_ref()
                .filter(|_| wrap)
                .map(|w| w.envelope.as_slice().to_vec()),
            own,
            sent_generation: None,
        }
    }

    /// The `snapshots` row of `record` with `header`.
    fn snapshot_row(
        &self,
        header: &SnapshotHeader,
        record: &SnapshotRecord,
        wrap: bool,
        own: i64,
    ) -> SnapshotRow {
        SnapshotRow {
            vault_id: self.vault_id.to_bytes().to_vec(),
            snapshot_id: header.snapshot_id.to_bytes().to_vec(),
            item_id: header.item_id.to_bytes().to_vec(),
            statement: record.statement.as_slice().to_vec(),
            envelope: record.envelope.as_slice().to_vec(),
            key_wrap: record
                .key_wrap
                .as_ref()
                .filter(|_| wrap)
                .map(|w| w.envelope.as_slice().to_vec()),
            own,
            sent_generation: None,
        }
    }

    /// The vault.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The next own `device_seq`, for the host to keep with the device.
    #[must_use]
    pub const fn next_device_seq(&self) -> u64 {
        self.next_seq
    }

    /// Whether writes are refused (see the module docs).
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.host_read_only || self.server_behind
    }

    /// Sets or clears the host's read-only decision: a rollback, a fork or an unconfirmed
    /// identity change of the account (CRYPTO.md §11.3 step 2.5).
    pub fn set_read_only(&mut self, read_only: bool) {
        self.host_read_only = read_only;
    }

    /// The Fetch request: the cursor, every chain's head (ADR 0012 §7 "Fetch").
    ///
    /// # Errors
    /// [`ClientError::Internal`] if the cursor exceeds the wire bound.
    pub fn fetch_request(&self) -> Result<FetchRequest, ClientError> {
        Ok(FetchRequest {
            vault_id: id(self.vault_id.to_bytes()),
            cursor: self.cursor()?,
            wraps_after_epoch: None,
        })
    }

    /// The cursor: the highest `device_seq` this device has, per device (ADR 0012 §7).
    fn cursor(&self) -> Result<SeqVector, ClientError> {
        let entries = self
            .log
            .cursor()
            .entries()
            .map(|d| SeqEntry {
                device_id: id(d.device_id().to_bytes()),
                seq: d.seq(),
            })
            .collect();
        SeqVector::new(entries).map_err(|_| ClientError::Internal)
    }

    /// The merge of `item`, created with every item key of its wrap set.
    fn merge_mut<'a>(
        items: &'a mut BTreeMap<ItemId, ItemMerge>,
        item_keys: &BTreeMap<ItemId, Vec<ItemKey>>,
        item: ItemId,
    ) -> &'a mut ItemMerge {
        items.entry(item).or_insert_with(|| {
            let mut merge = ItemMerge::new(item);
            for key in item_keys.get(&item).into_iter().flatten() {
                if let Ok(id) = key.key_id() {
                    merge.add_item_key(id);
                }
            }
            merge
        })
    }

    /// Adds an item key to the item's wrap set, once per key id.
    fn add_item_key(&mut self, item: ItemId, key: ItemKey) {
        let Ok(key_id) = key.key_id() else {
            return;
        };
        let keys = self.item_keys.entry(item).or_default();
        if keys.iter().any(|k| k.matches_key_id(&key_id)) {
            return;
        }
        keys.push(key);
        if let Some(merge) = self.items.get_mut(&item) {
            merge.add_item_key(key_id);
        }
    }

    /// Opens an `ITEM_KEY_WRAP` of `item` wrapped at `vault_key_epoch` and adds the key.
    /// A wrap under another epoch than the held vault key's is ignored: after a rotation every
    /// row is re-wrapped at the new epoch (ADR 0025 §3), and this device adopts that key first
    /// ([`VaultSync::adopt_vault_key`]).
    /// Returns the derived id of the item key it opened to, if it opened.
    fn learn_wrap(
        &mut self,
        item: ItemId,
        vault_key_epoch: u32,
        envelope: &[u8],
    ) -> Option<SymmetricKeyId> {
        if vault_key_epoch != self.vault_key.epoch() {
            return None;
        }
        let ctx = ItemKeyWrapCtx {
            vault_id: self.vault_id,
            item_id: item,
            vault_key_epoch,
        };
        let key = self.vault_key.unwrap_item_key(&ctx, envelope).ok()?;
        let key_id = key.key_id().ok()?;
        self.add_item_key(item, key);
        Some(key_id)
    }

    /// [`VaultSync::learn_wrap`], and the wrap joins the wraps this device knows the server
    /// held ([`VaultSync::known_wraps`]): a wrap-set row the server served, or a wrap carried
    /// by a record the server stored. Returns the derived item-key id.
    fn remember_wrap(
        &mut self,
        item: ItemId,
        vault_key_epoch: u32,
        envelope: &[u8],
    ) -> Option<SymmetricKeyId> {
        let key_id = self.learn_wrap(item, vault_key_epoch, envelope)?;
        if let Ok(envelope) = rizzy_proto::wire::Bytes::from_slice(envelope) {
            self.known_wraps
                .entry((item, *key_id.as_bytes()))
                .or_insert_with(|| ItemKeyWrap {
                    item_id: id(item.to_bytes()),
                    item_key_id: id(*key_id.as_bytes()),
                    vault_key_epoch,
                    envelope,
                });
        }
        Some(key_id)
    }

    /// The carried wrap of a held record, as a healing request re-publishes it: at the held
    /// epoch with the locator set to the derived id of the item key it opens to (and the wrap
    /// remembered), or dropped if it does not open; below the held epoch as it came, since the
    /// server keeps such a wrap with the record and fills no row with it (ADR 0025 open
    /// question 4). `None` for a wrap that did not match the signed hash.
    fn held_wrap(
        &mut self,
        item: ItemId,
        vault_key_epoch: u32,
        carried: Option<&RecordKeyWrap>,
        matched: bool,
    ) -> Option<RecordKeyWrap> {
        let carried = carried.filter(|_| matched)?;
        if vault_key_epoch != self.vault_key.epoch() {
            return Some(carried.clone());
        }
        let key_id = self.remember_wrap(item, vault_key_epoch, carried.envelope.as_slice())?;
        Some(RecordKeyWrap {
            item_key_id: id(*key_id.as_bytes()),
            envelope: carried.envelope.clone(),
        })
    }

    /// Keeps `record` as a held op record (the server stored it). `body` and `wrap` say whether
    /// the body and the wrap matched the signed hashes; one that did not is not kept.
    fn hold_op(&mut self, header: &OpHeader, record: &OpRecord, body: bool, wrap: bool) {
        let key_wrap = self.held_wrap(
            header.item_id,
            header.vault_key_epoch,
            record.key_wrap.as_ref(),
            wrap,
        );
        let held = OpRecord {
            statement: record.statement.clone(),
            body: record.body.clone().filter(|_| body),
            key_wrap,
        };
        self.held_ops.insert(header.dot, held);
    }

    /// Keeps a snapshot record as a held cover (absorbed, or own and acknowledged), once.
    /// `wrap` says whether its carried wrap matched the signed hash.
    fn hold_cover(&mut self, header: &SnapshotHeader, record: &SnapshotRecord, wrap: bool) {
        if self
            .held_covers
            .iter()
            .any(|(h, _)| h.snapshot_id == header.snapshot_id)
        {
            return;
        }
        let key_wrap = self.held_wrap(
            header.item_id,
            header.vault_key_epoch,
            record.key_wrap.as_ref(),
            wrap,
        );
        let held = SnapshotRecord {
            statement: record.statement.clone(),
            envelope: record.envelope.clone(),
            key_wrap,
        };
        self.held_covers.push((header.clone(), held));
    }

    /// Decrypts an `ITEM_OP` envelope under the item key its header names, if held. `Ok(None)`
    /// when the key is unknown (the body waits); `Err` when it fails.
    fn open_op(
        &self,
        header: &OpHeader,
        envelope: &[u8],
    ) -> Result<Option<(SymmetricKeyId, SecretBytes)>, ()> {
        let Ok(EnvelopeRef::Symmetric(parsed)) = parse_envelope(envelope) else {
            return Err(());
        };
        let key_id = SymmetricKeyId::from_bytes(*parsed.key_id());
        let Some(key) = self
            .item_keys
            .get(&header.item_id)
            .and_then(|keys| keys.iter().find(|k| k.matches_key_id(&key_id)))
        else {
            return Ok(None);
        };
        let ctx = header.envelope_context().map_err(|_| ())?;
        let plaintext = open(key.key(), &ctx, envelope).map_err(|_| ())?;
        parse_op(plaintext.expose_secret()).map_err(|_| ())?;
        Ok(Some((key_id, plaintext)))
    }

    /// Decrypts an `ITEM_SNAPSHOT` envelope; `None` for an unknown key or any failure.
    fn open_snapshot(&self, header: &SnapshotHeader, envelope: &[u8]) -> Option<SecretBytes> {
        let Ok(EnvelopeRef::Symmetric(parsed)) = parse_envelope(envelope) else {
            return None;
        };
        let key_id = SymmetricKeyId::from_bytes(*parsed.key_id());
        let key = self
            .item_keys
            .get(&header.item_id)?
            .iter()
            .find(|k| k.matches_key_id(&key_id))?;
        let ctx = header.envelope_context().ok()?;
        let plaintext = open(key.key(), &ctx, envelope).ok()?;
        parse_snapshot(&header.covered, plaintext.expose_secret()).ok()?;
        Some(plaintext)
    }

    /// Verifies one served op record (module docs, steps 1–4). `None` drops it. The flag says
    /// whether the record carries a wrap that matches the signed wrap hash.
    fn verify_op(&mut self, authors: &Authors, record: &OpRecord) -> Option<(ServedOp, bool)> {
        let wire = record.statement.as_slice();
        let author = authors.signer(wire)?;
        let verified = OpStatement::verify(wire, &author.verifying_key).ok()?;
        let header = OpHeader::parse_statement(&verified).ok()?;
        if header.dot.device_id() != author.status.device || header.vault_id != self.vault_id {
            return None;
        }
        check_op_author(&header, author.status).ok()?;
        let body = self.verify_body(&verified, &header, record);
        let wrap = record
            .key_wrap
            .as_ref()
            .is_some_and(|w| verified.matches_wrap(w.envelope.as_slice()));
        Some((ServedOp { header, body }, wrap))
    }

    /// Steps 3 and 4 of the module docs for a record whose statement verified: learns a carried
    /// wrap that matches the signed hash, then gives the verdict on the body.
    fn verify_body(
        &mut self,
        verified: &OpStatement,
        header: &OpHeader,
        record: &OpRecord,
    ) -> BodyStatus {
        if let Some(wrap) = &record.key_wrap
            && verified.matches_wrap(wrap.envelope.as_slice())
        {
            self.learn_wrap(
                header.item_id,
                header.vault_key_epoch,
                wrap.envelope.as_slice(),
            );
        }
        match &record.body {
            None => BodyStatus::Bodiless,
            Some(b) if !verified.matches_envelope(b.as_slice()) => BodyStatus::Rejected,
            // A record of an unknown `item_schema_version` is parked (ADR 0018 §11).
            Some(_)
                if SchemaVersion::classify(header.item_schema_version.get())
                    != SchemaVersion::Supported =>
            {
                BodyStatus::Waiting
            }
            Some(b) => match self.open_op(header, b.as_slice()) {
                Ok(Some(opened)) => {
                    self.bodies.insert(header.dot, opened);
                    BodyStatus::Verified
                }
                Ok(None) => {
                    self.waiting_bodies.insert(
                        header.dot,
                        WaitingBody {
                            header: header.clone(),
                            envelope: b.as_slice().to_vec(),
                        },
                    );
                    BodyStatus::Waiting
                }
                Err(()) => BodyStatus::Rejected,
            },
        }
    }

    /// Verifies one served cover. `None` drops it. The flag says whether the record carries a
    /// wrap that matches the signed wrap hash.
    fn verify_cover(
        &mut self,
        authors: &Authors,
        record: &SnapshotRecord,
        served: &[ServedOp],
    ) -> Option<(SnapshotHeader, SecretBytes, bool)> {
        let wire = record.statement.as_slice();
        let author = authors.signer(wire)?;
        let verified = SnapshotStatement::verify(wire, &author.verifying_key).ok()?;
        let header = SnapshotHeader::parse_statement(&verified).ok()?;
        if header.author != author.status.device || header.vault_id != self.vault_id {
            return None;
        }
        // CRYPTO.md §10.2 rule (c), §11.8 step 4. For a kind-4 author the bound is the highest
        // `device_seq` of its ops this client verified, this response included (the reading
        // `rizzy_sync::causal::author` suggests).
        let bound = author.status.last_accepted.or_else(|| {
            (author.kind == DeviceKind::WebEphemeral).then(|| {
                served
                    .iter()
                    .filter(|s| s.header.dot.device_id() == header.author)
                    .map(|s| s.header.dot.seq())
                    .chain([self.log.head(header.author)])
                    .max()
                    .unwrap_or(0)
            })
        });
        check_snapshot_author(&header, bound).ok()?;
        let wrap = record
            .key_wrap
            .as_ref()
            .is_some_and(|w| verified.matches_wrap(w.envelope.as_slice()));
        if let Some(carried) = record.key_wrap.as_ref().filter(|_| wrap) {
            self.learn_wrap(
                header.item_id,
                header.vault_key_epoch,
                carried.envelope.as_slice(),
            );
        }
        if !verified.matches_envelope(record.envelope.as_slice())
            || header.item_schema_version != ItemSchemaVersion::V1
        {
            return None;
        }
        let plaintext = self.open_snapshot(&header, record.envelope.as_slice())?;
        Some((header, plaintext, wrap))
    }

    /// Processes one Fetch response page (see the module docs). `now_ms` is the host's wall
    /// clock, for the HLC receive rule.
    ///
    /// `FetchResponse` carries no vault id: the vault is the one the request named, and each
    /// record's signed header is checked against this vault (a record of another vault is
    /// dropped and counted in [`FetchOutcome::dropped`], not an error).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] if the item merge refuses a verified, chain-checked
    /// op header ([`ItemMerge::record_header`]: another header held for the same dot, or an
    /// unsupported schema version), in the plan step or after the commit.
    ///
    /// The error is **not** atomic: by then the response's restore generation has been
    /// observed, its item-key wraps learned and verified bodies kept; for an error after the
    /// commit, covers have also been absorbed and the page committed to the log. The host
    /// treats the error as a server fault and does not assume the response left no trace;
    /// everything applied before the error came from records that verified.
    pub fn apply_fetch(
        &mut self,
        authors: &Authors,
        response: &FetchResponse,
        now_ms: u64,
    ) -> Result<FetchOutcome, ClientError> {
        let generation = RestoreGeneration::from_bytes(response.restore_generation.to_bytes());
        self.log.observe_generation(generation);
        self.generation = Some(generation);
        let mut outcome = FetchOutcome::default();
        self.learn_revocations(authors);
        // The current wrap set, kept as served for a rotation (every page carries all of it).
        let mut served_wraps = BTreeSet::new();
        for wrap in response.item_key_wraps.as_slice() {
            let item = ItemId::from_bytes(wrap.item_id.to_bytes());
            if let Some(key_id) =
                self.remember_wrap(item, wrap.vault_key_epoch, wrap.envelope.as_slice())
            {
                served_wraps.insert((item, *key_id.as_bytes()));
            }
        }
        self.served_wraps = served_wraps;
        if self.wrap_rows.as_slice() != response.item_key_wraps.as_slice() {
            let vault_id = self.vault_id.to_bytes();
            let epoch = self.vault_key.epoch();
            let rows = wrap_rows(self.vault_id, epoch, response.item_key_wraps.as_slice());
            self.record(|| Write::Wraps {
                vault_id,
                epoch,
                wraps: rows,
            });
        }
        self.wrap_rows = response.item_key_wraps.as_slice().to_vec();
        // 1. Verify.
        let mut served = Vec::with_capacity(response.ops.as_slice().len());
        // Per verified op: its record, and whether its carried wrap matched the signed hash.
        let mut op_records = Vec::with_capacity(response.ops.as_slice().len());
        for record in response.ops.as_slice() {
            match self.verify_op(authors, record) {
                Some((op, wrap)) => {
                    served.push(op);
                    op_records.push((record, wrap));
                }
                None => outcome.dropped += 1,
            }
        }
        let mut covers = Vec::new();
        let mut cover_records = Vec::new();
        for record in response.covers.as_slice() {
            match self.verify_cover(authors, record, &served) {
                Some((header, plaintext, wrap)) => {
                    covers.push((header, plaintext));
                    cover_records.push((record, wrap));
                }
                None => outcome.dropped += 1,
            }
        }
        let settled = self.settle(&mut served, &covers, now_ms, &mut outcome)?;
        // The rows of what was accepted (ADR 0026 §4 step 2): every accepted op statement with
        // the body and wrap that matched its signed hashes, every absorbed snapshot record.
        // The same records are held in memory for a healing request (ADR 0021 §9).
        for (op, (record, wrap)) in served.iter().zip(&op_records) {
            if settled.accepted.contains(&op.header.dot) {
                let body = matches!(op.body, BodyStatus::Verified | BodyStatus::Waiting);
                self.hold_op(&op.header, record, body, *wrap);
                if self.journal.is_some() {
                    let row = self.op_row(&op.header, record, body, *wrap, own::SERVED);
                    self.record(|| Write::PutOp(row));
                }
            }
        }
        for index in &settled.absorbed {
            if let (Some((header, _)), Some((record, wrap))) =
                (covers.get(*index), cover_records.get(*index))
            {
                self.hold_cover(header, record, *wrap);
                if self.journal.is_some() {
                    let row = self.snapshot_row(header, record, *wrap, own::SERVED);
                    self.record(|| Write::PutSnapshot(row));
                }
            }
        }
        if response.complete {
            outcome.reports.extend(self.log.complete_fetch_reports());
        }
        // Server behind (ADR 0021 §9).
        let heads = heads_vv(&response.heads);
        let behind = self.log.server_behind(
            0,
            ServerView {
                state_seq: 0,
                heads: &heads,
                lacks_wrap: self.lacks_wrap(),
            },
        );
        self.server_behind = !behind.is_empty();
        outcome.server_behind = self.server_behind;
        // An older copy of the device state (ADR 0026 §4 step 7): the server's own head is
        // above every own dot held, or it served an own record this device does not hold, or
        // holds with other bytes.
        let own_device = self.device_id;
        outcome.own_history_ahead = heads.get(own_device) > self.log.head(own_device)
            || outcome.reports.iter().any(|r| match r {
                Report::UnknownOwnOp { .. } => true,
                Report::Equivocation { dot, .. } => dot.device_id() == own_device,
                _ => false,
            });
        self.synced = response.complete && !self.server_behind && !outcome.own_history_ahead;
        if response.complete {
            self.wraps_complete_at = Some(self.vault_key.epoch());
        }
        self.server_heads = Some(heads);
        self.prune_bodies();
        Ok(outcome)
    }

    /// Whether the server lacks an item-key wrap this device got from it or had acknowledged
    /// (ADR 0021 §9 "Server behind"): a wrap of [`VaultSync::known_wraps`] at the held epoch
    /// whose row the last Fetch page did not serve. Compared by item and derived item-key id;
    /// a served row whose locator lies counts as missing, the conservative side.
    ///
    /// A served row above the held epoch means a rotation this device has not adopted yet
    /// (ADR 0025 §3: the rotation re-wraps the whole set at the new epoch): the set at the held
    /// epoch is gone by design, and the account answer, not this check, moves the device on
    /// ([`VaultSync::adopt_vault_key`]). Nothing is compared then.
    fn lacks_wrap(&self) -> bool {
        let epoch = self.vault_key.epoch();
        let rotated = self.wrap_rows.iter().any(|w| w.vault_key_epoch > epoch);
        !rotated
            && self
                .known_wraps
                .keys()
                .any(|known| !self.served_wraps.contains(known))
    }

    /// Teaches the log the revocation cut-offs of `authors` it does not know yet.
    fn learn_revocations(&mut self, authors: &Authors) {
        for author in &authors.entries {
            if let Some(cutoff) = author.status.last_accepted
                && self.log.cutoff(author.status.device).is_none()
            {
                self.log.learn_revocation(author.status.device, cutoff);
            }
        }
    }

    /// Steps 2–5 of the causal cycle for verified ops and covers: plan, absorb, commit,
    /// deliver. Shared by [`VaultSync::apply_fetch`] and [`VaultSync::restore`], so a cache
    /// load runs the same code as a Fetch (ADR 0026 §4 step 5).
    ///
    /// # Errors
    /// As [`VaultSync::apply_fetch`].
    fn settle(
        &mut self,
        served: &mut [ServedOp],
        covers: &[(SnapshotHeader, SecretBytes)],
        now_ms: u64,
        outcome: &mut FetchOutcome,
    ) -> Result<Settled, ClientError> {
        let mut settled = Settled::default();
        // Bodies that waited and whose key arrived now.
        self.retry_waiting(served);
        let served: &[ServedOp] = served;
        // 2. Plan.
        let cover_headers: Vec<SnapshotHeader> = covers.iter().map(|(h, _)| h.clone()).collect();
        let plan = self.log.plan_covers(served, &cover_headers);
        for dot in &plan.links {
            if let Some(op) = served.iter().find(|s| s.header.dot == *dot) {
                Self::merge_mut(&mut self.items, &self.item_keys, op.header.item_id)
                    .record_header(&op.header)
                    .map_err(|_| ClientError::InvalidServerResponse)?;
            }
        }
        // 3. Absorb.
        let mut touched = BTreeSet::new();
        for &i in &plan.absorb {
            let Some((header, plaintext)) = covers.get(i) else {
                continue;
            };
            let Ok(data) = parse_snapshot(&header.covered, plaintext.expose_secret()) else {
                continue;
            };
            let item = header.item_id;
            let page_bodies: Vec<(&OpHeader, SymmetricKeyId, &SecretBytes)> = served
                .iter()
                .filter(|s| s.header.item_id == item && s.body == BodyStatus::Verified)
                .filter_map(|s| {
                    let (key_id, body) = self.bodies.get(&s.header.dot)?;
                    Some((&s.header, *key_id, body))
                })
                .collect();
            let parsed: Vec<(&OpHeader, SymmetricKeyId, rizzy_sync::record::OpData<'_>)> =
                page_bodies
                    .iter()
                    .filter_map(|(h, k, b)| Some((*h, *k, parse_op(b.expose_secret()).ok()?)))
                    .collect();
            let with: Vec<OpInput<'_>> = parsed
                .iter()
                .map(|(h, k, d)| OpInput {
                    header: h,
                    key_id: *k,
                    data: d,
                })
                .collect();
            let merge = Self::merge_mut(&mut self.items, &self.item_keys, item);
            match merge.absorb_snapshot(
                SnapshotInput {
                    header,
                    data: &data,
                },
                &with,
            ) {
                Ok(absorption) => match absorption.outcome {
                    AbsorbOutcome::Absorbed(absorbed) => {
                        let taken = merge.covered().clone();
                        self.log.record_absorbed(&plan, item, &taken);
                        if let Some(hlc) = absorbed.receive_hlc
                            && let Ok(receipt) = self.clock.receive(hlc, now_ms)
                        {
                            self.clock = receipt.clock;
                        }
                        touched.insert(item);
                        outcome.absorbed += 1;
                        settled.absorbed.push(i);
                    }
                    AbsorbOutcome::Refused(_) => outcome.refused_covers += 1,
                },
                Err(_) => outcome.refused_covers += 1,
            }
        }
        // 4. Commit.
        let commit = self.log.commit(served);
        outcome.reports.extend(commit.reports);
        for dot in &commit.accepted {
            if let Some(header) = self.log.header(*dot).cloned() {
                Self::merge_mut(&mut self.items, &self.item_keys, header.item_id)
                    .record_header(&header)
                    .map_err(|_| ClientError::InvalidServerResponse)?;
            }
        }
        settled.accepted = commit.accepted;
        // 5. Deliver.
        outcome.applied += self.deliver(now_ms, &mut touched);
        for item in touched {
            let due = self.items.get_mut(&item).and_then(ItemMerge::end_fetch);
            if due.is_some() {
                self.pending_snapshots.insert(item);
            }
        }
        Ok(settled)
    }

    /// Re-tries the bodies that waited for their item key. A body served in the page being
    /// processed takes its new verdict in `served` (the commit then sees it); one the log
    /// already holds as waiting gets it through [`VaultLog::body_verified`] or
    /// [`VaultLog::body_rejected`].
    fn retry_waiting(&mut self, served: &mut [ServedOp]) {
        let dots: Vec<Dot> = self.waiting_bodies.keys().copied().collect();
        for dot in dots {
            let Some(waiting) = self.waiting_bodies.get(&dot) else {
                continue;
            };
            let verdict = match self.open_op(&waiting.header, &waiting.envelope) {
                Ok(None) => continue,
                Ok(Some(opened)) => {
                    self.bodies.insert(dot, opened);
                    BodyStatus::Verified
                }
                Err(()) => BodyStatus::Rejected,
            };
            self.waiting_bodies.remove(&dot);
            if let Some(op) = served
                .iter_mut()
                .find(|s| s.header.dot == dot && s.body == BodyStatus::Waiting)
            {
                op.body = verdict;
            } else if verdict == BodyStatus::Verified {
                // An error means the log holds no such waiting link; nothing to release.
                let _ = self.log.body_verified(dot);
            } else {
                let _ = self.log.body_rejected(dot);
            }
        }
    }

    /// Applies every op the causal layer releases, in its order. Returns how many applied.
    fn deliver(&mut self, now_ms: u64, touched: &mut BTreeSet<ItemId>) -> usize {
        let mut applied = 0;
        for delivery in self.log.take_deliveries() {
            let (Some(header), Some((key_id, body))) = (
                self.log.header(delivery.dot),
                self.bodies.get(&delivery.dot),
            ) else {
                continue;
            };
            let Ok(data) = parse_op(body.expose_secret()) else {
                continue;
            };
            let merge = Self::merge_mut(&mut self.items, &self.item_keys, delivery.item_id);
            if let Ok(result) = merge.apply_op(OpInput {
                header,
                key_id: *key_id,
                data: &data,
            }) {
                applied += 1;
                touched.insert(delivery.item_id);
                if let Some(hlc) = result.receive_hlc
                    && let Ok(receipt) = self.clock.receive(hlc, now_ms)
                {
                    self.clock = receipt.clock;
                }
            }
        }
        applied
    }

    /// Drops the op data the device no longer needs: it keeps each item's retained ops, the
    /// waiting ones and its own unacknowledged ops (ADR 0018 §10 "Newest snapshot").
    ///
    /// # The cache (ADR 0026 §1, §4 step 2)
    ///
    /// The cache keeps "op bodies since each item's newest snapshot", and a Fetch or upload
    /// step persists the "pruning of bodies ADR 0018 §10 no longer needs". This build prunes
    /// the most conservative subset of that, the body ([`Write::PruneOpBody`]; the signed
    /// statement stays for the life of the vault, ADR 0021 §9 "Headers kept") of an op that:
    /// - is another device's: an own op goes back into the own chain at load through its body
    ///   (`restore`), so own rows keep theirs;
    /// - is not among the retained, waiting or unacknowledged ops above;
    /// - is covered by a snapshot of its item that **this device wrote and the server
    ///   acknowledged**. Such a snapshot is this device's own merged state, so the load
    ///   rebuilds the item from it exactly; an absorbed cover is another author's claim
    ///   (ADR 0018 §3 "Snapshots are claims"), which the in-memory merge folds the op into
    ///   before dropping it but a load from the snapshot alone could not, so it never lets a
    ///   body go. The snapshot row is `own = 2`, which the load reads as a cover.
    fn prune_bodies(&mut self) {
        let mut keep: BTreeSet<Dot> = self
            .items
            .values()
            .flat_map(ItemMerge::retained_ops)
            .collect();
        keep.extend(self.log.waiting().iter().map(|w| w.dot));
        keep.extend(self.log.unacknowledged().map(|h| h.dot));
        self.bodies.retain(|dot, _| keep.contains(dot));
        let own_device = self.device_id;
        let prunable: Vec<Dot> = self
            .held_ops
            .iter()
            .filter(|(dot, record)| {
                record.body.is_some() && dot.device_id() != own_device && !keep.contains(dot)
            })
            .filter(|(dot, _)| {
                self.log.header(**dot).is_some_and(|header| {
                    self.held_covers.iter().any(|(cover, _)| {
                        cover.author == own_device
                            && cover.item_id == header.item_id
                            && cover.covered.covers(**dot)
                    })
                })
            })
            .map(|(dot, _)| *dot)
            .collect();
        let vault_id = self.vault_id.to_bytes();
        for dot in prunable {
            if let Some(record) = self.held_ops.get_mut(&dot) {
                record.body = None;
            }
            self.record(|| Write::PruneOpBody {
                vault_id,
                device_id: dot.device_id().to_bytes(),
                device_seq: dot.seq(),
            });
        }
    }
}

/// Why an own op is written: the op's lifecycle marker and its field writes (ADR 0018 §3).
pub(crate) struct OwnChange<'a> {
    /// The lifecycle marker.
    pub(crate) lifecycle: rizzy_sync::record::Lifecycle,
    /// The field writes, as final key and encoded value bytes; any order, no duplicate key.
    pub(crate) writes: &'a [(&'a str, &'a [u8])],
}

impl VaultSync {
    /// Whether the client holds an unapplied record of `item` (ADR 0018 §11: no purge then).
    fn holds_unapplied(&self, item: ItemId) -> bool {
        self.log.waiting().iter().any(|w| w.item_id == item)
    }

    /// The newest item key of `item` usable for a write (CRYPTO.md §11.6 writer rule).
    /// `Ok(None)` when none is held or every held key is stale: the writer then generates a
    /// fresh item key at the current `vault_key_epoch`, carries its wrap with the op, and the
    /// merge makes a full snapshot due ([`OwnWrite::fresh_item_key`](rizzy_sync::merge::OwnWrite)).
    fn writer_key(&self, item: ItemId) -> Option<&ItemKey> {
        self.item_keys.get(&item).and_then(|keys| {
            keys.iter()
                .rev()
                .find(|k| !k.is_stale(self.vault_key.epoch()))
        })
    }

    /// Writes one own op on `item` (ADR 0012 §2–§4, ADR 0018 §3; CRYPTO.md §8.4, §10.2):
    /// encodes the data, seals it under the item key (a fresh one, carried as a signed wrap, if
    /// the item has none), signs the statement with the device key, applies it to the merge
    /// with the writer rules, and keeps the record for upload. The schema checks are the
    /// caller's ([`crate::items`]).
    ///
    /// # Errors
    /// [`ClientError::ReadOnly`]; [`ClientError::InvalidInput`] if `unlocked` is another
    /// device's; [`ClientError::InvalidEdit`] for a key the record layer refuses, a duplicate
    /// key, data the record layer cannot encode, or a purge the writer rules forbid;
    /// [`ClientError::Internal`].
    #[expect(
        clippy::too_many_lines,
        reason = "one own op built in the order of ADR 0012 §3 and CRYPTO.md §10.2"
    )]
    pub(crate) fn write_op<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
        change: &OwnChange<'_>,
        now_ms: u64,
    ) -> Result<Dot, ClientError> {
        use rizzy_core::envelope::purpose::ItemKeyWrapCtx as WrapCtx;
        use rizzy_core::item::ITEM_SCHEMA_VERSION;
        use rizzy_sync::merge::{MergeError, OwnWrite};
        use rizzy_sync::record::{FieldKey, OpData, Value, Write, encode_op};

        if self.is_read_only() {
            return Err(ClientError::ReadOnly);
        }
        if unlocked.device_id != self.device_id {
            return Err(ClientError::InvalidInput);
        }
        // The data, strictly ascending by key.
        let mut sorted: Vec<&(&str, &[u8])> = change.writes.iter().collect();
        sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if sorted.windows(2).any(|w| matches!(w, [a, b] if a.0 == b.0)) {
            return Err(ClientError::InvalidEdit);
        }
        let mut writes = Vec::with_capacity(sorted.len());
        for (key, value) in sorted {
            let key = FieldKey::new(key).map_err(|_| ClientError::InvalidEdit)?;
            writes.push(Write::new(key, Value::new(value)));
        }
        let plaintext = encode_op(&OpData::new(change.lifecycle, writes))
            .map_err(|_| ClientError::InvalidEdit)?;
        // The item key: the writer rule's, or a fresh one with its wrap.
        let fresh = match self.writer_key(item) {
            Some(_) => None,
            None => Some(ItemKey::generate(rng, self.vault_key.epoch())),
        };
        let hlc = self.clock.tick(now_ms).map_err(|_| ClientError::Internal)?;
        let dot = Dot::new(self.device_id, self.next_seq).ok_or(ClientError::Internal)?;
        let schema = ItemSchemaVersion::new(ITEM_SCHEMA_VERSION).ok_or(ClientError::Internal)?;
        let causal_context = Self::merge_mut(&mut self.items, &self.item_keys, item)
            .covered()
            .clone();
        let header = OpHeader {
            vault_id: self.vault_id,
            item_id: item,
            op_id: rizzy_core::ids::OpId::generate(rng),
            dot,
            vault_prev_seq: self.log.own_vault_prev_seq(),
            hlc,
            item_schema_version: schema,
            vault_key_epoch: self.vault_key.epoch(),
            causal_context,
        };
        let canonical = header.to_vec().map_err(|_| ClientError::InvalidEdit)?;
        let ctx = header
            .envelope_context()
            .map_err(|_| ClientError::InvalidEdit)?;
        let (key_id, envelope, wrap) = {
            let key = match &fresh {
                Some(k) => k,
                None => self.writer_key(item).ok_or(ClientError::Internal)?,
            };
            let key_id = key.key_id().map_err(internal)?;
            let envelope = seal(rng, key.key(), &ctx, plaintext.expose_secret())
                .map_err(|_| ClientError::InvalidEdit)?;
            let wrap = match &fresh {
                Some(k) => Some(
                    self.vault_key
                        .wrap_item_key(
                            rng,
                            &WrapCtx {
                                vault_id: self.vault_id,
                                item_id: item,
                                vault_key_epoch: self.vault_key.epoch(),
                            },
                            k,
                        )
                        .map_err(internal)?,
                ),
                None => None,
            };
            (key_id, envelope, wrap)
        };
        let statement =
            OpStatement::new(&canonical, &envelope, wrap.as_deref()).map_err(internal)?;
        let wire = statement
            .sign(unlocked.device_keys.signing_key())
            .map_err(internal)?;
        let data = parse_op(plaintext.expose_secret()).map_err(|_| ClientError::InvalidEdit)?;
        let holds_unapplied = self.holds_unapplied(item);
        let merge = Self::merge_mut(&mut self.items, &self.item_keys, item);
        if fresh.is_some() {
            merge.add_item_key(key_id);
        }
        let applied = merge
            .apply_own_op(
                OpInput {
                    header: &header,
                    key_id,
                    data: &data,
                },
                OwnWrite {
                    fresh_item_key: fresh.is_some(),
                    holds_unapplied_record: holds_unapplied,
                },
            )
            .map_err(|e| match e {
                MergeError::WriterRule => ClientError::InvalidEdit,
                _ => ClientError::Internal,
            })?;
        drop(data);
        self.log
            .record_own_op(header)
            .map_err(|_| ClientError::Internal)?;
        let record = OpRecord {
            statement: bytes(wire)?,
            body: Some(bytes(envelope)?),
            key_wrap: match wrap {
                Some(w) => Some(RecordKeyWrap {
                    item_key_id: id(*key_id.as_bytes()),
                    envelope: bytes(w)?,
                }),
                None => None,
            },
        };
        // ADR 0026 §4 step 1: the own op row (`own = 1`) and the advanced counter land in one
        // transaction ([`VaultSync::take_writes`] adds the counter).
        let row = self.own_op_row(dot, item, &record);
        self.record(|| crate::store::rows::Write::PutOp(row));
        self.own_records.insert(dot.seq(), OwnRecord { record });
        self.bodies.insert(dot, (key_id, plaintext));
        if let Some(key) = fresh {
            self.add_item_key(item, key);
        }
        if applied.snapshot_due.is_some() {
            self.pending_snapshots.insert(item);
        }
        self.clock = hlc;
        self.next_seq = self.next_seq.checked_add(1).ok_or(ClientError::Internal)?;
        self.synced = false;
        Ok(dot)
    }

    /// The `ops` row of an own, unsent record at `dot` on `item`.
    fn own_op_row(&self, dot: Dot, item: ItemId, record: &OpRecord) -> OpRow {
        OpRow {
            vault_id: self.vault_id.to_bytes().to_vec(),
            device_id: dot.device_id().to_bytes().to_vec(),
            device_seq: dot.seq().to_be_bytes().to_vec(),
            item_id: item.to_bytes().to_vec(),
            statement: record.statement.as_slice().to_vec(),
            body: record.body.as_ref().map(|b| b.as_slice().to_vec()),
            key_wrap: record
                .key_wrap
                .as_ref()
                .map(|w| w.envelope.as_slice().to_vec()),
            own: own::UNSENT,
            sent_generation: None,
        }
    }

    /// Writes an own snapshot of `item` into the outbox, if the merge can write one (ADR 0018
    /// §3, §10). Skipped, not an error, when there is nothing to write.
    fn write_snapshot<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        item: ItemId,
    ) -> Result<(), ClientError> {
        if self.writer_key(item).is_none() {
            return Ok(());
        }
        let Some(merge) = self.items.get_mut(&item) else {
            return Ok(());
        };
        let Ok(written) = merge.write_snapshot() else {
            return Ok(());
        };
        let header = SnapshotHeader {
            vault_id: self.vault_id,
            item_id: item,
            snapshot_id: SnapshotId::generate(rng),
            author: self.device_id,
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: self.vault_key.epoch(),
            covered: written.covered,
        };
        let canonical = header.to_vec().map_err(internal)?;
        let ctx = header.envelope_context().map_err(internal)?;
        let key = self.writer_key(item).ok_or(ClientError::Internal)?;
        let envelope =
            seal(rng, key.key(), &ctx, written.data.expose_secret()).map_err(internal)?;
        let statement = SnapshotStatement::new(&canonical, &envelope, None).map_err(internal)?;
        let wire = statement
            .sign(unlocked.device_keys.signing_key())
            .map_err(internal)?;
        let record = SnapshotRecord {
            statement: bytes(wire)?,
            envelope: bytes(envelope)?,
            key_wrap: None,
        };
        let row = self.snapshot_row(&header, &record, false, own::UNSENT);
        self.record(|| Write::PutSnapshot(row));
        self.outbox.push(OwnSnapshot { header, record });
        Ok(())
    }

    /// Re-issues the own ops a `stale_epoch` answer calls for (ADR 0021 §9 "Stale epoch";
    /// ADR 0025 §4: "the writer creates a fresh item key and re-issues the op with the same
    /// `device_seq`"; ADR 0018 §3 "Re-issued ops", owner decision 15). Nothing to do without a
    /// pending stale answer.
    ///
    /// [`VaultLog::stale_plan`] picks the answered op and every later own op below the current
    /// `vault_key_epoch`. Each one keeps its header but for `vault_key_epoch`, which becomes the
    /// current one, and its op data (the decrypted body this device keeps for unacknowledged
    /// ops); the data is sealed again under the CRYPTO.md §11.6 writer rule's item key (a fresh
    /// one at the current epoch, carried as a signed wrap, when every held key of the item is
    /// stale), signed again, and replaces the record in the log, the merge and the upload queue.
    /// Unsent snapshots of the item that cover the op are discarded, and the snapshot the merge
    /// asks for is due.
    ///
    /// Every refusal below is decided before the first op is replaced; only a failure valid
    /// state cannot cause ([`ClientError::Internal`]) can stop it half-way.
    ///
    /// # Errors
    /// [`ClientError::VaultKeyRotated`] while this device still writes at the answered op's
    /// epoch: it must adopt the new vault key first. [`ClientError::HealingRequired`] when the
    /// plan names an op the server may have stored and served (a restore came between): such an
    /// op is never re-issued but re-published by [`VaultSync::healing_request`] first; until
    /// that request is acknowledged, or a Fetch shows the server's own head at or above the
    /// op (it is stored, and goes up verbatim to be answered "already stored"), nothing is
    /// re-issued or sent from the chain. [`ClientError::Internal`].
    fn reissue_stale<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
    ) -> Result<(), ClientError> {
        use rizzy_sync::causal::OwnError;
        use rizzy_sync::merge::Reissue;

        let Some(rejected) = self.stale_from else {
            return Ok(());
        };
        let current = self.vault_key.epoch();
        let plan = match self.log.stale_plan(rejected, current) {
            Ok(plan) => plan,
            Err(OwnError::NotStale) => return Err(ClientError::VaultKeyRotated),
            Err(_) => return Err(ClientError::Internal),
        };
        // An op the server may have stored and served is re-published in a healing request
        // first ([`VaultSync::healing_request`]); once that request is acknowledged it is no
        // longer in the way. One at or below the server's own head is stored: it goes up
        // verbatim by the normal upload path, answered "already stored"
        // ([`VaultSync::awaits_republish`]).
        if plan.republish.iter().any(|dot| self.awaits_republish(*dot)) {
            return Err(ClientError::HealingRequired);
        }
        let headers: Vec<OpHeader> = self
            .log
            .unacknowledged()
            .filter(|h| plan.reissue.contains(&h.dot))
            .cloned()
            .collect();
        if headers.len() != plan.reissue.len() {
            return Err(ClientError::Internal);
        }
        for old in headers {
            let dot = old.dot;
            let item = old.item_id;
            let header = OpHeader {
                vault_key_epoch: current,
                ..old
            };
            let fresh = match self.writer_key(item) {
                Some(_) => None,
                None => Some(ItemKey::generate(rng, current)),
            };
            let (key_id, record) = self.reissued_record(rng, unlocked, &header, fresh.as_ref())?;
            self.log
                .reissue_own_op(header.clone())
                .map_err(|_| ClientError::Internal)?;
            let fresh_item_key = fresh.is_some();
            if let Some(key) = fresh {
                self.add_item_key(item, key);
            }
            let before = self.outbox.len();
            let own = self.device_id;
            // ADR 0026 §4 step 6: the re-issued row and the unsent own snapshots ADR 0018 §3
            // discards change in the transaction committed before the new bytes are sent.
            let vault_id = self.vault_id.to_bytes();
            let discarded: Vec<SnapshotId> = self
                .outbox
                .iter()
                .filter(|s| s.header.item_id == item && s.header.covered.get(own) >= dot.seq())
                .map(|s| s.header.snapshot_id)
                .collect();
            for snapshot_id in discarded {
                self.record(|| Write::DeleteSnapshot {
                    vault_id,
                    snapshot_id: snapshot_id.to_bytes(),
                });
            }
            let row = self.own_op_row(dot, item, &record);
            let stale_generation = self
                .answered
                .remove(&dot.seq())
                .map(RestoreGeneration::to_bytes);
            self.record(|| Write::ReissueOp {
                row,
                stale_generation,
            });
            self.outbox
                .retain(|s| s.header.item_id != item || s.header.covered.get(own) < dot.seq());
            let trigger = self
                .items
                .get_mut(&item)
                .ok_or(ClientError::Internal)?
                .reissue_own_op(
                    &header,
                    key_id,
                    Reissue {
                        fresh_item_key,
                        discarded_unsent_snapshot: self.outbox.len() != before,
                    },
                )
                .map_err(internal)?;
            if trigger.is_some() {
                self.pending_snapshots.insert(item);
            }
            self.own_records.insert(dot.seq(), OwnRecord { record });
            if let Some(body) = self.bodies.get_mut(&dot) {
                body.0 = key_id;
            }
        }
        self.stale_from = None;
        self.synced = false;
        Ok(())
    }

    /// The record of a re-issued own op ([`VaultSync::reissue_stale`]): the kept op data of
    /// `header`'s dot sealed under `fresh` or else the writer rule's item key, `fresh`'s wrap
    /// under the current vault key when there is one, and the statement signed again. Returns
    /// the item key's id with the record.
    fn reissued_record<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
        header: &OpHeader,
        fresh: Option<&ItemKey>,
    ) -> Result<(SymmetricKeyId, OpRecord), ClientError> {
        let item = header.item_id;
        let key = match fresh {
            Some(k) => k,
            None => self.writer_key(item).ok_or(ClientError::Internal)?,
        };
        let key_id = key.key_id().map_err(internal)?;
        let (_, plaintext) = self.bodies.get(&header.dot).ok_or(ClientError::Internal)?;
        let ctx = header.envelope_context().map_err(internal)?;
        let envelope = seal(rng, key.key(), &ctx, plaintext.expose_secret()).map_err(internal)?;
        let wrap = match fresh {
            Some(k) => Some(
                self.vault_key
                    .wrap_item_key(
                        rng,
                        &ItemKeyWrapCtx {
                            vault_id: self.vault_id,
                            item_id: item,
                            vault_key_epoch: header.vault_key_epoch,
                        },
                        k,
                    )
                    .map_err(internal)?,
            ),
            None => None,
        };
        let canonical = header.to_vec().map_err(internal)?;
        let statement =
            OpStatement::new(&canonical, &envelope, wrap.as_deref()).map_err(internal)?;
        let wire = statement
            .sign(unlocked.device_keys.signing_key())
            .map_err(internal)?;
        let record = OpRecord {
            statement: bytes(wire)?,
            body: Some(bytes(envelope)?),
            key_wrap: match wrap {
                Some(w) => Some(RecordKeyWrap {
                    item_key_id: id(*key_id.as_bytes()),
                    envelope: bytes(w)?,
                }),
                None => None,
            },
        };
        Ok((key_id, record))
    }

    /// The highest own `device_seq` the server acknowledged in this vault.
    const fn acked(&self) -> u64 {
        self.log.acknowledged()
    }

    /// Moves the own records the server acknowledged (every own link up to the highest
    /// acknowledged `device_seq`) from the upload queue to the held records: the server stored
    /// them, so a healing request re-publishes them (ADR 0021 §9).
    fn hold_acknowledged(&mut self) {
        let acked = self.acked();
        let done: Vec<u64> = self.own_records.range(..=acked).map(|(s, _)| *s).collect();
        for seq in done {
            let Some(own) = self.own_records.remove(&seq) else {
                continue;
            };
            let header =
                Dot::new(self.device_id, seq).and_then(|dot| self.log.header(dot).cloned());
            if let Some(header) = header {
                // This device built the record: its body and wrap are the ones it signed.
                self.hold_op(&header, &own.record, true, true);
            }
        }
    }

    /// The next upload (ADR 0012 §7 "Upload"): every own op not acknowledged, in chain order,
    /// then the own snapshots whose own entry is acknowledged; `None` when there is nothing to
    /// send or the vault is read-only. Own ops the server answered `stale_epoch` are re-issued
    /// first (module docs, "Restore healing and stale answers"; ADR 0025 §4), then due snapshots are written.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if `unlocked` is another device's;
    /// [`ClientError::FetchRequired`] before the first Fetch or upload answer;
    /// [`ClientError::VaultKeyRotated`] after a `stale_epoch` answer until the new vault key is
    /// adopted; [`ClientError::HealingRequired`] when that answer names an op the server may have
    /// stored and served before a restore, until [`VaultSync::healing_request`] re-published it;
    /// [`ClientError::Internal`].
    pub fn upload_request<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
    ) -> Result<Option<UploadRequest>, ClientError> {
        if unlocked.device_id != self.device_id {
            return Err(ClientError::InvalidInput);
        }
        if self.is_read_only() {
            return Ok(None);
        }
        if self.generation.is_none() {
            return Err(ClientError::FetchRequired);
        }
        self.reissue_stale(rng, unlocked)?;
        for item in core::mem::take(&mut self.pending_snapshots) {
            self.write_snapshot(rng, unlocked, item)?;
        }
        let mut records = Vec::new();
        let mut in_flight = Vec::new();
        let seqs: Vec<u64> = self.log.unacknowledged().map(|h| h.dot.seq()).collect();
        for seq in seqs {
            if records.len() >= MAX_RECORDS {
                break;
            }
            let own = self.own_records.get(&seq).ok_or(ClientError::Internal)?;
            records.push(Record::Op(own.record.clone()));
            in_flight.push(InFlight::Op(seq));
            self.log
                .record_sent(seq)
                .map_err(|_| ClientError::Internal)?;
        }
        let acked = self.acked();
        for snap in &self.outbox {
            if records.len() >= MAX_RECORDS {
                break;
            }
            if snap.header.covered.get(self.device_id) <= acked {
                records.push(Record::Snapshot(snap.record.clone()));
                in_flight.push(InFlight::Snapshot(snap.header.snapshot_id));
            }
        }
        if records.is_empty() {
            return Ok(None);
        }
        self.journal_sent(&in_flight);
        self.in_flight = in_flight;
        self.synced = false;
        Ok(Some(UploadRequest {
            vault_id: id(self.vault_id.to_bytes()),
            records: List::new(records).map_err(|_| ClientError::Internal)?,
        }))
    }

    /// Applies the answer to the last [`VaultSync::upload_request`] (ADR 0021 §2, §9).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] if the answer has another number of results than
    /// the request had records; [`ClientError::Internal`].
    pub fn apply_upload_response(
        &mut self,
        response: &UploadResponse,
    ) -> Result<UploadOutcome, ClientError> {
        let in_flight = core::mem::take(&mut self.in_flight);
        self.synced = false;
        let results = response.results.as_slice();
        if results.len() != in_flight.len() {
            return Err(ClientError::InvalidServerResponse);
        }
        let generation = RestoreGeneration::from_bytes(response.restore_generation.to_bytes());
        self.log.observe_generation(generation);
        self.generation = Some(generation);
        let mut outcome = UploadOutcome::default();
        let vault_id = self.vault_id.to_bytes();
        let device_id = self.device_id.to_bytes();
        for (sent, result) in in_flight.iter().zip(results) {
            match (*sent, *result) {
                (InFlight::Op(seq), UploadResult::Stored | UploadResult::AlreadyStored) => {
                    self.log
                        .acknowledge(seq)
                        .map_err(|_| ClientError::Internal)?;
                    self.answered.remove(&seq);
                    self.hold_acknowledged();
                    // "Already stored" moves a row to `own = 2` (ADR 0026 §4 step 6).
                    self.record(|| Write::OpOwn {
                        vault_id,
                        device_id,
                        device_seq: seq,
                        own: own::ACKNOWLEDGED,
                        sent_generation: None,
                    });
                    outcome.acknowledged += 1;
                }
                (InFlight::Op(seq), UploadResult::Rejected { error }) => {
                    self.log
                        .record_answered(seq, generation)
                        .map_err(|_| ClientError::Internal)?;
                    self.answered.insert(seq, generation);
                    if error == ErrorCode::StaleEpoch {
                        self.stale_from = Some(self.stale_from.map_or(seq, |s| s.min(seq)));
                    }
                    // A conflict answer at an own dot changes no row, and no new bytes are
                    // signed for that dot (ADR 0026 §4 step 6): the host raises the alarm.
                    if error == ErrorCode::RecordConflict {
                        outcome.own_conflict = true;
                    }
                    outcome.rejected.push(error);
                }
                (InFlight::Op(seq), _) => {
                    self.log
                        .record_answered(seq, generation)
                        .map_err(|_| ClientError::Internal)?;
                    self.answered.insert(seq, generation);
                }
                (InFlight::Snapshot(sid), UploadResult::Stored | UploadResult::AlreadyStored) => {
                    if let Some(stored) = self
                        .outbox
                        .iter()
                        .find(|s| s.header.snapshot_id == sid)
                        .cloned()
                    {
                        // An own snapshot carries no wrap (`write_snapshot`).
                        self.hold_cover(&stored.header, &stored.record, false);
                    }
                    self.outbox.retain(|s| s.header.snapshot_id != sid);
                    self.record(|| Write::SnapshotOwn {
                        vault_id,
                        snapshot_id: sid.to_bytes(),
                        own: own::ACKNOWLEDGED,
                        sent_generation: None,
                    });
                    outcome.snapshots_stored += 1;
                }
                (InFlight::Snapshot(sid), UploadResult::Rejected { error }) => {
                    // "A refusal only discards" the snapshot; "A stale answer to a snapshot
                    // only discards and rewrites it" (ADR 0021 §9): the rewrite is due at the
                    // next upload, under the writer rule's key at the current epoch.
                    if error == ErrorCode::StaleEpoch
                        && let Some(stale) =
                            self.outbox.iter().find(|s| s.header.snapshot_id == sid)
                    {
                        self.pending_snapshots.insert(stale.header.item_id);
                    }
                    self.outbox.retain(|s| s.header.snapshot_id != sid);
                    self.record(|| Write::DeleteSnapshot {
                        vault_id,
                        snapshot_id: sid.to_bytes(),
                    });
                    outcome.snapshots_discarded += 1;
                }
                (InFlight::Snapshot(_), _) => {}
            }
        }
        self.prune_bodies();
        Ok(outcome)
    }

    /// The items this vault holds, in id order.
    #[must_use]
    pub fn item_ids(&self) -> Vec<ItemId> {
        self.items.keys().copied().collect()
    }

    /// The merge of `item`, if any op reached it.
    pub(crate) fn merge(&self, item: ItemId) -> Option<&ItemMerge> {
        self.items.get(&item)
    }

    /// Every item's merge, ascending by item id (the order of an export payload, ADR 0027 §1).
    pub(crate) fn merges(&self) -> impl Iterator<Item = (ItemId, &ItemMerge)> + '_ {
        self.items.iter().map(|(id, merge)| (*id, merge))
    }

    /// Whether `unlocked` may write an own op now: the checks [`VaultSync::write_op`] makes
    /// first, for a caller that writes several ops and must refuse before the first.
    ///
    /// # Errors
    /// [`ClientError::ReadOnly`]; [`ClientError::InvalidInput`] if `unlocked` is another
    /// device's.
    pub(crate) fn check_writable(&self, unlocked: &UnlockedDevice) -> Result<(), ClientError> {
        if self.is_read_only() {
            return Err(ClientError::ReadOnly);
        }
        if unlocked.device_id != self.device_id {
            return Err(ClientError::InvalidInput);
        }
        Ok(())
    }

    /// The `vault_key_epoch` of the vault key this driver writes under.
    #[must_use]
    pub const fn vault_key_epoch(&self) -> u32 {
        self.vault_key.epoch()
    }

    /// The epoch of a rotation's new vault key (ADR 0025 §3 check 2): above every epoch this
    /// device saw for the vault (its keys and the served wrap-set rows), so an epoch the server
    /// may have rolled back is never reused.
    pub(crate) fn next_vault_epoch(&self) -> Result<u32, ClientError> {
        let seen = self
            .wrap_rows
            .iter()
            .map(|w| w.vault_key_epoch)
            .chain(self.seen_keys.keys().copied())
            .fold(self.vault_key.epoch(), u32::max);
        seen.checked_add(1).ok_or(ClientError::Internal)
    }

    /// The highest `device_seq` this device holds from `device` in this vault.
    pub(crate) fn cursor_of(&self, device: DeviceId) -> u64 {
        self.log.cursor().get(device)
    }

    /// The vault half of a rotation for this vault (ADR 0025 §2 steps 1–3; CRYPTO.md §11.6
    /// step 3): the new self-grant, this device's cursor, every served wrap-set row it can open
    /// re-wrapped under `new_vault_key`, the rest dropped.
    ///
    /// # Errors
    /// [`ClientError::SyncRequired`] unless every own op and snapshot is uploaded and a complete
    /// Fetch ran after that; [`ClientError::ReadOnly`] while the vault is read-only (a server
    /// behind this device heals first, ADR 0025 §2 step 2); [`ClientError::InvalidInput`] for
    /// a key of another vault or not above every epoch seen; [`ClientError::Internal`].
    pub(crate) fn rotation_half<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        account_id: rizzy_core::ids::AccountId,
        new_account_key: &rizzy_core::keys::AccountKey,
        new_vault_key: &VaultKey,
    ) -> Result<crate::rotation::VaultHalf, ClientError> {
        if self.is_read_only() {
            return Err(ClientError::ReadOnly);
        }
        let queued = self.log.unacknowledged().next().is_some()
            || !self.outbox.is_empty()
            || !self.pending_snapshots.is_empty();
        if queued || !self.synced {
            return Err(ClientError::SyncRequired);
        }
        if new_vault_key.vault_id() != self.vault_id
            || new_vault_key.epoch() < self.next_vault_epoch()?
        {
            return Err(ClientError::InvalidInput);
        }
        crate::rotation::build_vault_half(
            rng,
            account_id,
            &[&self.vault_key],
            &self.wrap_rows,
            self.cursor()?,
            new_account_key,
            new_vault_key,
        )
    }

    /// Adopts a vault key of this vault that opened under the verified account key: after this
    /// device's own rotation committed, or after a rotation elsewhere (CRYPTO.md §11.3 step 4.4,
    /// §11.6 "Current vault epoch"). A key at a higher epoch becomes the one writes use; the
    /// item keys learned so far stay (old ops still open), and are stale for writing.
    ///
    /// ADR 0025 §4: a key at an epoch this device already saw with another key id is a fork;
    /// the vault goes read-only and nothing is adopted.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for another vault's key; [`ClientError::Fork`] for a second
    /// key at a seen epoch; [`ClientError::Rollback`] for a key below the current epoch;
    /// [`ClientError::Internal`].
    pub fn adopt_vault_key(&mut self, key: VaultKey) -> Result<(), ClientError> {
        if key.vault_id() != self.vault_id {
            return Err(ClientError::InvalidInput);
        }
        let key_id = key.key_id().map_err(internal)?;
        if let Some(seen) = self.seen_keys.get(&key.epoch()) {
            if *seen != key_id {
                self.host_read_only = true;
                return Err(ClientError::Fork);
            }
            return if key.epoch() == self.vault_key.epoch() {
                Ok(())
            } else {
                Err(ClientError::Rollback)
            };
        }
        if key.epoch() < self.vault_key.epoch() {
            return Err(ClientError::Rollback);
        }
        self.seen_keys.insert(key.epoch(), key_id);
        self.vault_key = key;
        self.wrap_rows.clear();
        // The wraps this device knows the server held were at the old epoch; the rows at the
        // new one come with the next Fetch.
        self.known_wraps.clear();
        self.served_wraps.clear();
        self.wraps_complete_at = None;
        self.synced = false;
        Ok(())
    }

    /// Test access: the ids and creation epochs of the item keys held for `item`, oldest first.
    #[cfg(test)]
    pub(crate) fn item_key_ids(&self, item: ItemId) -> Vec<(SymmetricKeyId, u32)> {
        self.item_keys
            .get(&item)
            .into_iter()
            .flatten()
            .filter_map(|k| Some((k.key_id().ok()?, k.created_vault_key_epoch())))
            .collect()
    }

    /// Test access: whether the log counts the own op `seq` as possibly stored and served
    /// ([`VaultLog::may_have_been_served`]), the verdict the restore generations decide.
    #[cfg(test)]
    pub(crate) fn may_have_been_served(&self, seq: u64) -> bool {
        self.log.may_have_been_served(seq)
    }
}

/// A 16-byte restore-generation column.
fn generation_column(column: Option<&Vec<u8>>) -> Result<Option<RestoreGeneration>, ClientError> {
    column
        .map(|g| id16(g).map(RestoreGeneration::from_bytes))
        .transpose()
}

/// The wire record of an `ops` row. Each blob is checked against its `rizzy-proto` limit before
/// it is parsed (ADR 0026 §3). The wrap's locator is a placeholder: it is never trusted
/// (CRYPTO.md §4.2), and [`VaultSync::restore`] sets the derived id on the records it sends.
fn op_record(row: &OpRow) -> Result<OpRecord, ClientError> {
    let corrupt = |_| ClientError::CacheCorrupt;
    Ok(OpRecord {
        statement: rizzy_proto::wire::Bytes::from_slice(&row.statement).map_err(corrupt)?,
        body: row
            .body
            .as_deref()
            .map(rizzy_proto::wire::Bytes::from_slice)
            .transpose()
            .map_err(corrupt)?,
        key_wrap: row
            .key_wrap
            .as_deref()
            .map(|w| {
                Ok(RecordKeyWrap {
                    item_key_id: id([0; 16]),
                    envelope: rizzy_proto::wire::Bytes::from_slice(w)?,
                })
            })
            .transpose()
            .map_err(|_: rizzy_proto::wire::WireError| ClientError::CacheCorrupt)?,
    })
}

/// The wire record of a `snapshots` row, as [`op_record`].
fn snapshot_record(row: &SnapshotRow) -> Result<SnapshotRecord, ClientError> {
    let corrupt = |_| ClientError::CacheCorrupt;
    Ok(SnapshotRecord {
        statement: rizzy_proto::wire::Bytes::from_slice(&row.statement).map_err(corrupt)?,
        envelope: rizzy_proto::wire::Bytes::from_slice(&row.envelope).map_err(corrupt)?,
        key_wrap: row
            .key_wrap
            .as_deref()
            .map(|w| {
                Ok(RecordKeyWrap {
                    item_key_id: id([0; 16]),
                    envelope: rizzy_proto::wire::Bytes::from_slice(w)?,
                })
            })
            .transpose()
            .map_err(|_: rizzy_proto::wire::WireError| ClientError::CacheCorrupt)?,
    })
}

/// An own op row whose statement verified under this device's key and whose columns agree
/// with it.
struct OwnRow<'a> {
    /// The parsed header.
    header: OpHeader,
    /// The verified statement.
    statement: rizzy_core::sign::Verified<OpStatement>,
    /// The record, as it goes back to the server.
    record: OpRecord,
    /// The row.
    row: &'a OpRow,
}

impl VaultSync {
    /// Rebuilds the driver of a vault from its persisted rows ([ADR 0026] §4 step 5: "verify
    /// … every record through the same code as a Fetch … and rebuild the logs and merges").
    ///
    /// - **Served rows** (`own = 0`) go through the checks of a Fetch ([`VaultSync::apply_fetch`]
    ///   steps 1–4) and then the same plan, absorb, commit and deliver. A statement that fails
    ///   under its signer's key, or a column that disagrees with the parsed statement, fails the
    ///   load (§5 (d)). A row whose signer is no longer among the verified certificates, or
    ///   whose author checks now refuse it (a revocation learned since), is left out exactly as
    ///   a Fetch would drop it; the chain check then stops that chain there.
    /// - **Own rows** (`own` 1, 2, 3) are never taken from a response (`rizzy_sync::causal`
    ///   reading 5), so they are put back one by one in `device_seq` order: statement under this
    ///   device's key, columns, the own chain's link and causal context
    ///   ([`VaultLog::record_own_op`]), the body through the reader's path of the merge. A row
    ///   that breaks one of these fails the load (§4 step 7, §5 (d)). Acknowledged rows are
    ///   acknowledged in the log, sent rows keep the restore generation of their first send,
    ///   and the records of `own` 1 and 3 go back to the upload queue byte for byte.
    /// - **A body, snapshot envelope or wrap that fails** under a statement that verified is
    ///   handled as the same bytes from a server are: missing data, the load stands (§5 (e)).
    /// - The stored `next_device_seq` must be above every own `device_seq` held (§4 step 7); the
    ///   server's unsigned head never moves it.
    ///
    /// # Known limit
    ///
    /// An own op whose causal context names an op this device can no longer open (its item
    /// key's wrap is gone from the wrap set at the held epoch, which only a rotation that
    /// dropped the row causes, ADR 0025 §2 step 3) cannot be put back into the own chain: the
    /// load fails, and the recourse is removal and a new enrolment (§5).
    ///
    /// # Errors
    /// [`ClientError::CacheCorrupt`].
    ///
    /// [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
    #[expect(
        clippy::too_many_lines,
        reason = "the load of one vault in its order: own headers, served rows, own chain, outbox"
    )]
    pub(crate) fn restore(
        vault_key: VaultKey,
        unlocked: &UnlockedDevice,
        authors: &Authors,
        image: &VaultImage<'_>,
        now_ms: u64,
    ) -> Result<Self, ClientError> {
        let corrupt = ClientError::CacheCorrupt;
        let mut vault =
            Self::new(vault_key, unlocked, image.next_device_seq).map_err(|_| corrupt)?;
        vault.clock = Hlc::from_u64(image.hlc);
        vault.learn_revocations(authors);
        for wrap in &image.wraps {
            let item = ItemId::from_bytes(wrap.item_id.to_bytes());
            // A row on disk was served at the held epoch: the server held it.
            vault.remember_wrap(item, wrap.vault_key_epoch, wrap.envelope.as_slice());
        }
        vault.wrap_rows.clone_from(&image.wraps);
        vault.wraps_complete_at = Some(vault.vault_key.epoch());
        // The item keys that records carry, before any envelope is opened: a cover may be
        // sealed under an item key whose wrap only an own op carries (a fresh key of the
        // writer rule), and the own ops are put back after the covers are absorbed. A wrap
        // opens only under the held vault key with the context it was sealed for (vault, item,
        // epoch), so trying it at the held epoch with the row's item is safe: a wrong column
        // or another epoch does not open, and nothing else is taken from the row here.
        let epoch = vault.vault_key.epoch();
        for (item, wrap) in image
            .ops
            .iter()
            .filter_map(|r| Some((&r.item_id, r.key_wrap.as_ref()?)))
            .chain(
                image
                    .snapshots
                    .iter()
                    .filter_map(|r| Some((&r.item_id, r.key_wrap.as_ref()?))),
            )
        {
            if let Ok(item) = id16(item) {
                vault.learn_wrap(ItemId::from_bytes(item), epoch, wrap);
            }
        }
        let own_device = unlocked.device_id;
        let own_key = *unlocked.device_keys.signing_key().verifying_key();

        // Split the rows. `own` and the author must agree: an own row is this device's, a
        // served row is never this device's (the own chain is never taken from a response).
        let mut foreign: Vec<(DeviceId, u64, &OpRow)> = Vec::new();
        let mut own_rows: Vec<(u64, &OpRow)> = Vec::new();
        for row in &image.ops {
            let device = DeviceId::from_bytes(id16(&row.device_id)?);
            let seq = u64_be(&row.device_seq)?;
            let sent = generation_column(row.sent_generation.as_ref())?;
            let own_row = match row.own {
                own::SERVED => false,
                own::UNSENT | own::ACKNOWLEDGED | own::SENT => true,
                _ => return Err(corrupt),
            };
            // `sent_generation` is set exactly on rows that were sent (`own` 3, and 2 after it).
            let generation_ok = match row.own {
                own::SERVED | own::UNSENT => sent.is_none(),
                own::SENT => sent.is_some(),
                _ => true,
            };
            // A row was sent only after a response gave this device a restore generation.
            let sent_without_response = image.generation.is_none() && sent.is_some();
            if own_row != (device == own_device)
                || !generation_ok
                || sent_without_response
                || seq == 0
            {
                return Err(corrupt);
            }
            if own_row {
                if seq >= image.next_device_seq {
                    return Err(corrupt);
                }
                own_rows.push((seq, row));
            } else {
                foreign.push((device, seq, row));
            }
        }
        foreign.sort_by_key(|(device, seq, _)| (*device, *seq));
        own_rows.sort_by_key(|(seq, _)| *seq);

        // The own headers first, into the merges only: a snapshot is cut to the op headers the
        // merge has verified (ADR 0018 §3), and this device verified its own.
        let mut own_ops: Vec<OwnRow<'_>> = Vec::with_capacity(own_rows.len());
        for (seq, row) in own_rows {
            let record = op_record(row)?;
            let statement =
                OpStatement::verify(record.statement.as_slice(), &own_key).map_err(|_| corrupt)?;
            let header = OpHeader::parse_statement(&statement).map_err(|_| corrupt)?;
            if Dot::new(own_device, seq) != Some(header.dot)
                || header.vault_id != vault.vault_id
                || header.item_id.to_bytes().as_slice() != row.item_id.as_slice()
            {
                return Err(corrupt);
            }
            Self::merge_mut(&mut vault.items, &vault.item_keys, header.item_id)
                .record_header(&header)
                .map_err(|_| corrupt)?;
            own_ops.push(OwnRow {
                header,
                statement,
                record,
                row,
            });
        }

        // The served rows, as a Fetch verifies them.
        let mut served = Vec::with_capacity(foreign.len());
        let mut served_records = Vec::with_capacity(foreign.len());
        for (device, seq, row) in foreign {
            let record = op_record(row)?;
            let wire = record.statement.as_slice();
            let Some(author) = authors.signer(wire) else {
                continue;
            };
            let statement =
                OpStatement::verify(wire, &author.verifying_key).map_err(|_| corrupt)?;
            let header = OpHeader::parse_statement(&statement).map_err(|_| corrupt)?;
            if Dot::new(device, seq) != Some(header.dot)
                || header.dot.device_id() != author.status.device
                || header.vault_id != vault.vault_id
                || header.item_id.to_bytes().as_slice() != row.item_id.as_slice()
            {
                return Err(corrupt);
            }
            if check_op_author(&header, author.status).is_err() {
                continue;
            }
            let body = vault.verify_body(&statement, &header, &record);
            let wrap = record
                .key_wrap
                .as_ref()
                .is_some_and(|w| statement.matches_wrap(w.envelope.as_slice()));
            served_records.push((record, wrap));
            served.push(ServedOp { header, body });
        }
        let mut covers = Vec::new();
        let mut cover_records = Vec::new();
        let mut outbox = Vec::new();
        for row in &image.snapshots {
            let record = snapshot_record(row)?;
            let wire = record.statement.as_slice();
            let snapshot_id = SnapshotId::from_bytes(id16(&row.snapshot_id)?);
            let sent = generation_column(row.sent_generation.as_ref())?;
            let columns = |header: &SnapshotHeader| {
                header.snapshot_id == snapshot_id
                    && header.vault_id == vault.vault_id
                    && header.item_id.to_bytes().as_slice() == row.item_id.as_slice()
            };
            match row.own {
                own::SERVED | own::ACKNOWLEDGED => {
                    if row.own == own::SERVED && sent.is_some() {
                        return Err(corrupt);
                    }
                    let Some(author) = authors.signer(wire) else {
                        continue;
                    };
                    let statement = SnapshotStatement::verify(wire, &author.verifying_key)
                        .map_err(|_| corrupt)?;
                    let header =
                        SnapshotHeader::parse_statement(&statement).map_err(|_| corrupt)?;
                    if !columns(&header)
                        || (row.own == own::ACKNOWLEDGED) != (header.author == own_device)
                    {
                        return Err(corrupt);
                    }
                    // The author checks, the envelope and its key as a Fetch applies them; a
                    // cover that fails them is left out (§5 (e)).
                    if let Some((header, plaintext, wrap)) =
                        vault.verify_cover(authors, &record, &served)
                    {
                        cover_records.push((header.clone(), record, wrap));
                        covers.push((header, plaintext));
                    }
                }
                own::UNSENT | own::SENT => {
                    if (row.own == own::SENT) != sent.is_some() {
                        return Err(corrupt);
                    }
                    let statement =
                        SnapshotStatement::verify(wire, &own_key).map_err(|_| corrupt)?;
                    let header =
                        SnapshotHeader::parse_statement(&statement).map_err(|_| corrupt)?;
                    if !columns(&header) || header.author != own_device {
                        return Err(corrupt);
                    }
                    outbox.push(OwnSnapshot { header, record });
                }
                _ => return Err(corrupt),
            }
        }
        let mut outcome = FetchOutcome::default();
        let settled = vault
            .settle(&mut served, &covers, now_ms, &mut outcome)
            .map_err(|_| corrupt)?;
        // The records held for a healing request, as a Fetch holds them.
        for (op, (record, wrap)) in served.iter().zip(&served_records) {
            if settled.accepted.contains(&op.header.dot) {
                let body = matches!(op.body, BodyStatus::Verified | BodyStatus::Waiting);
                vault.hold_op(&op.header, record, body, *wrap);
            }
        }
        for (header, record, wrap) in &cover_records {
            vault.hold_cover(header, record, *wrap);
        }

        // The own chain, in order; after each link the ops that waited for it are delivered.
        let mut acknowledged = true;
        for own_op in own_ops {
            let seq = own_op.header.dot.seq();
            match own_op.row.own {
                own::ACKNOWLEDGED if acknowledged => {}
                // The server stores a chain only in order: an acknowledged row after an
                // unacknowledged one is no state this device wrote.
                own::ACKNOWLEDGED => return Err(corrupt),
                _ => acknowledged = false,
            }
            let sent = generation_column(own_op.row.sent_generation.as_ref())?;
            vault.restore_own_op(&own_op.header, &own_op.statement, own_op.record, now_ms)?;
            match own_op.row.own {
                own::ACKNOWLEDGED => {
                    vault.log.acknowledge(seq).map_err(|_| corrupt)?;
                    vault.hold_acknowledged();
                }
                own::SENT => {
                    // "Each with the restore generation of its first send" (ADR 0021 §2).
                    vault.log.observe_generation(sent.ok_or(corrupt)?);
                    vault.log.record_sent(seq).map_err(|_| corrupt)?;
                }
                _ => {}
            }
        }
        vault.outbox = outbox;
        if let Some(generation) = image.generation {
            vault.log.observe_generation(generation);
            vault.generation = Some(generation);
        }
        // Neither counter goes backwards (§4 "What never goes backwards").
        if vault.clock.to_u64() < image.hlc {
            vault.clock = Hlc::from_u64(image.hlc);
        }
        vault.next_seq = image.next_device_seq;
        vault.synced = false;
        vault.journal = Some(Vec::new());
        vault.journaled = Journaled {
            next_seq: image.next_device_seq,
            hlc: image.hlc,
            generation: image.generation,
        };
        // After the journal is on: a body this load no longer needs is pruned on disk too.
        vault.prune_bodies();
        Ok(vault)
    }

    /// Puts one own op back into the own chain (see [`VaultSync::restore`]).
    fn restore_own_op(
        &mut self,
        header: &OpHeader,
        statement: &OpStatement,
        mut record: OpRecord,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        let dot = header.dot;
        let item = header.item_id;
        let verdict = self.verify_body(statement, header, &record);
        self.log
            .record_own_op(header.clone())
            .map_err(|_| ClientError::CacheCorrupt)?;
        // The log settled the dot: the body does not wait in the causal layer.
        self.waiting_bodies.remove(&dot);
        if verdict == BodyStatus::Verified
            && let Some((key_id, body)) = self.bodies.get(&dot)
            && let Ok(data) = parse_op(body.expose_secret())
        {
            let merge = Self::merge_mut(&mut self.items, &self.item_keys, item);
            // An error leaves the item as a reader sees it with this op's data missing.
            let _ = merge.apply_op(OpInput {
                header,
                key_id: *key_id,
                data: &data,
            });
        }
        // The locator of a carried wrap is derived, never stored: the record goes back to the
        // server with the id of the item key the wrap opens to.
        if let Some(wrap) = record.key_wrap.as_mut() {
            let ctx = ItemKeyWrapCtx {
                vault_id: self.vault_id,
                item_id: item,
                vault_key_epoch: header.vault_key_epoch,
            };
            if let Ok(key_id) = self
                .vault_key
                .unwrap_item_key(&ctx, wrap.envelope.as_slice())
                .map_err(|_| ())
                .and_then(|key| key.key_id().map_err(|_| ()))
            {
                wrap.item_key_id = id(*key_id.as_bytes());
            }
        }
        self.own_records.insert(dot.seq(), OwnRecord { record });
        let mut touched = BTreeSet::new();
        self.deliver(now_ms, &mut touched);
        Ok(())
    }

    /// The upload of what this device wrote and the server never acknowledged, byte for byte as
    /// it was stored: the own ops in chain order, then the own snapshots (ADR 0026 §5 and the
    /// owner's decision on open question 6: "upload the `own` 1 and 3 rows byte-identically
    /// before deleting (no new dot is signed)"). Unlike [`VaultSync::upload_request`] it
    /// re-issues nothing and writes no new snapshot. `None` when nothing is queued.
    ///
    /// # Errors
    /// [`ClientError::FetchRequired`] before the first Fetch or upload answer;
    /// [`ClientError::Internal`].
    pub fn unsent_upload_request(&mut self) -> Result<Option<UploadRequest>, ClientError> {
        if self.generation.is_none() {
            return Err(ClientError::FetchRequired);
        }
        let mut records = Vec::new();
        let mut in_flight = Vec::new();
        let seqs: Vec<u64> = self.log.unacknowledged().map(|h| h.dot.seq()).collect();
        for seq in seqs {
            if records.len() >= MAX_RECORDS {
                break;
            }
            let own = self.own_records.get(&seq).ok_or(ClientError::Internal)?;
            records.push(Record::Op(own.record.clone()));
            in_flight.push(InFlight::Op(seq));
            self.log
                .record_sent(seq)
                .map_err(|_| ClientError::Internal)?;
        }
        let acked = self.acked();
        for snap in &self.outbox {
            if records.len() < MAX_RECORDS && snap.header.covered.get(self.device_id) <= acked {
                records.push(Record::Snapshot(snap.record.clone()));
                in_flight.push(InFlight::Snapshot(snap.header.snapshot_id));
            }
        }
        if records.is_empty() {
            return Ok(None);
        }
        self.journal_sent(&in_flight);
        self.in_flight = in_flight;
        self.synced = false;
        Ok(Some(UploadRequest {
            vault_id: id(self.vault_id.to_bytes()),
            records: List::new(records).map_err(|_| ClientError::Internal)?,
        }))
    }

    /// ADR 0026 §4 step 1: each own row an upload carries moves to `own = 3` with the restore
    /// generation of the last response, in the transaction the host commits before it sends
    /// the request. A resend keeps the first value (the cache stores it only once).
    fn journal_sent(&mut self, in_flight: &[InFlight]) {
        let Some(generation) = self.generation.map(RestoreGeneration::to_bytes) else {
            return;
        };
        let vault_id = self.vault_id.to_bytes();
        let device_id = self.device_id.to_bytes();
        for sent in in_flight {
            let write = match *sent {
                InFlight::Op(seq) => Write::OpOwn {
                    vault_id,
                    device_id,
                    device_seq: seq,
                    own: own::SENT,
                    sent_generation: Some(generation),
                },
                InFlight::Snapshot(sid) => Write::SnapshotOwn {
                    vault_id,
                    snapshot_id: sid.to_bytes(),
                    own: own::SENT,
                    sent_generation: Some(generation),
                },
            };
            self.record(|| write);
        }
    }

    /// How many own ops and own snapshots the server has not acknowledged: what removal of
    /// this device would lose (ADR 0026 §5).
    #[must_use]
    pub fn unacknowledged(&self) -> (usize, usize) {
        (self.log.unacknowledged().count(), self.outbox.len())
    }
}
