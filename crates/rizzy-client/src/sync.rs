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
//! # Not in this build (reported)
//!
//! - The healing request of ADR 0021 §9 "Healing request" while the server is behind: the
//!   driver detects the condition and stays read-only, but builds no healing request.
//! - A stale-epoch answer to an own op the server may have stored and served before a restore
//!   (ADR 0021 §9 "Stale epoch": re-published in a healing request, never re-issued) stops the
//!   chain's upload with [`ClientError::HealingRequired`]. A stale-epoch answer to any other own
//!   op (written at the old epoch before this device learned of a rotation, ADR 0025 §4) is
//!   handled: once the host adopts the new vault key ([`VaultSync::adopt_vault_key`]; until
//!   then [`ClientError::VaultKeyRotated`]), the next upload re-issues it and the later
//!   old-epoch ops of the chain with the same `device_seq` under the writer rule's item key
//!   (a fresh one when every held key is stale, CRYPTO.md §11.6), and a stale snapshot is
//!   rewritten.
//! - The `lacks_wrap` condition of "Server behind": wrap acknowledgements are not tracked, so
//!   it is passed as false.
//! - The server's `state_seq` in "Server behind": the account-state checks of
//!   [`crate::unlock`] cover a lower `state_seq`, so the vault check passes 0 for both.
//!
//! # Device sequence numbers
//!
//! `device_seq` counts a device's ops in every vault, so the counter lives with the device
//! (`rizzy_sync::causal::own`). M1 has one vault per account; the host passes the next
//! `device_seq` when it builds the driver, and reads it back with
//! [`VaultSync::next_device_seq`].

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
        })
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
    fn learn_wrap(&mut self, item: ItemId, vault_key_epoch: u32, envelope: &[u8]) {
        if vault_key_epoch != self.vault_key.epoch() {
            return;
        }
        let ctx = ItemKeyWrapCtx {
            vault_id: self.vault_id,
            item_id: item,
            vault_key_epoch,
        };
        if let Ok(key) = self.vault_key.unwrap_item_key(&ctx, envelope) {
            self.add_item_key(item, key);
        }
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

    /// Verifies one served op record (module docs, steps 1–4). `None` drops it.
    fn verify_op(&mut self, authors: &Authors, record: &OpRecord) -> Option<ServedOp> {
        let wire = record.statement.as_slice();
        let author = authors.signer(wire)?;
        let verified = OpStatement::verify(wire, &author.verifying_key).ok()?;
        let header = OpHeader::parse_statement(&verified).ok()?;
        if header.dot.device_id() != author.status.device || header.vault_id != self.vault_id {
            return None;
        }
        check_op_author(&header, author.status).ok()?;
        if let Some(wrap) = &record.key_wrap
            && verified.matches_wrap(wrap.envelope.as_slice())
        {
            self.learn_wrap(
                header.item_id,
                header.vault_key_epoch,
                wrap.envelope.as_slice(),
            );
        }
        let body = match &record.body {
            None => BodyStatus::Bodiless,
            Some(b) if !verified.matches_envelope(b.as_slice()) => BodyStatus::Rejected,
            // A record of an unknown `item_schema_version` is parked (ADR 0018 §11).
            Some(_)
                if SchemaVersion::classify(header.item_schema_version.get())
                    != SchemaVersion::Supported =>
            {
                BodyStatus::Waiting
            }
            Some(b) => match self.open_op(&header, b.as_slice()) {
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
        };
        Some(ServedOp { header, body })
    }

    /// Verifies one served cover. `None` drops it.
    fn verify_cover(
        &mut self,
        authors: &Authors,
        record: &SnapshotRecord,
        served: &[ServedOp],
    ) -> Option<(SnapshotHeader, SecretBytes)> {
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
        if let Some(wrap) = &record.key_wrap
            && verified.matches_wrap(wrap.envelope.as_slice())
        {
            self.learn_wrap(
                header.item_id,
                header.vault_key_epoch,
                wrap.envelope.as_slice(),
            );
        }
        if !verified.matches_envelope(record.envelope.as_slice())
            || header.item_schema_version != ItemSchemaVersion::V1
        {
            return None;
        }
        let plaintext = self.open_snapshot(&header, record.envelope.as_slice())?;
        Some((header, plaintext))
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
    #[expect(
        clippy::too_many_lines,
        reason = "the five steps of the causal cycle, kept together in their order"
    )]
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
        // Revocations the log does not know yet.
        for author in &authors.entries {
            if let Some(cutoff) = author.status.last_accepted
                && self.log.cutoff(author.status.device).is_none()
            {
                self.log.learn_revocation(author.status.device, cutoff);
            }
        }
        // The current wrap set, kept as served for a rotation (every page carries all of it).
        for wrap in response.item_key_wraps.as_slice() {
            let item = ItemId::from_bytes(wrap.item_id.to_bytes());
            self.learn_wrap(item, wrap.vault_key_epoch, wrap.envelope.as_slice());
        }
        self.wrap_rows = response.item_key_wraps.as_slice().to_vec();
        // 1. Verify.
        let mut served = Vec::with_capacity(response.ops.as_slice().len());
        for record in response.ops.as_slice() {
            match self.verify_op(authors, record) {
                Some(op) => served.push(op),
                None => outcome.dropped += 1,
            }
        }
        let mut covers = Vec::new();
        for record in response.covers.as_slice() {
            match self.verify_cover(authors, record, &served) {
                Some(cover) => covers.push(cover),
                None => outcome.dropped += 1,
            }
        }
        // Bodies that waited and whose key arrived now.
        self.retry_waiting(&mut served);
        // 2. Plan.
        let cover_headers: Vec<SnapshotHeader> = covers.iter().map(|(h, _)| h.clone()).collect();
        let plan = self.log.plan_covers(&served, &cover_headers);
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
                    }
                    AbsorbOutcome::Refused(_) => outcome.refused_covers += 1,
                },
                Err(_) => outcome.refused_covers += 1,
            }
        }
        // 4. Commit.
        let commit = self.log.commit(&served);
        outcome.reports.extend(commit.reports);
        for dot in commit.accepted {
            if let Some(header) = self.log.header(dot).cloned() {
                Self::merge_mut(&mut self.items, &self.item_keys, header.item_id)
                    .record_header(&header)
                    .map_err(|_| ClientError::InvalidServerResponse)?;
            }
        }
        // 5. Deliver.
        outcome.applied += self.deliver(now_ms, &mut touched);
        for item in touched {
            let due = self.items.get_mut(&item).and_then(ItemMerge::end_fetch);
            if due.is_some() {
                self.pending_snapshots.insert(item);
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
                lacks_wrap: false,
            },
        );
        self.server_behind = !behind.is_empty();
        outcome.server_behind = self.server_behind;
        self.synced = response.complete && !self.server_behind;
        self.prune_bodies();
        Ok(outcome)
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
    fn prune_bodies(&mut self) {
        let mut keep: BTreeSet<Dot> = self
            .items
            .values()
            .flat_map(ItemMerge::retained_ops)
            .collect();
        keep.extend(self.log.waiting().iter().map(|w| w.dot));
        keep.extend(self.log.unacknowledged().map(|h| h.dot));
        self.bodies.retain(|dot, _| keep.contains(dot));
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
        self.outbox.push(OwnSnapshot {
            header,
            record: SnapshotRecord {
                statement: bytes(wire)?,
                envelope: bytes(envelope)?,
                key_wrap: None,
            },
        });
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
    /// op is never re-issued, and the healing request that re-publishes it is not in this build;
    /// nothing is re-issued or sent from the chain then. [`ClientError::Internal`].
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
        if !plan.republish.is_empty() {
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

    /// The next upload (ADR 0012 §7 "Upload"): every own op not acknowledged, in chain order,
    /// then the own snapshots whose own entry is acknowledged; `None` when there is nothing to
    /// send or the vault is read-only. Own ops the server answered `stale_epoch` are re-issued
    /// first (module docs, "Not in this build"; ADR 0025 §4), then due snapshots are written.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if `unlocked` is another device's;
    /// [`ClientError::FetchRequired`] before the first Fetch or upload answer;
    /// [`ClientError::VaultKeyRotated`] after a `stale_epoch` answer until the new vault key is
    /// adopted; [`ClientError::HealingRequired`] when that answer names an op the server may have
    /// stored and served before a restore; [`ClientError::Internal`].
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
        for (sent, result) in in_flight.iter().zip(results) {
            match (*sent, *result) {
                (InFlight::Op(seq), UploadResult::Stored | UploadResult::AlreadyStored) => {
                    self.log
                        .acknowledge(seq)
                        .map_err(|_| ClientError::Internal)?;
                    outcome.acknowledged += 1;
                }
                (InFlight::Op(seq), UploadResult::Rejected { error }) => {
                    self.log
                        .record_answered(seq, generation)
                        .map_err(|_| ClientError::Internal)?;
                    if error == ErrorCode::StaleEpoch {
                        self.stale_from = Some(self.stale_from.map_or(seq, |s| s.min(seq)));
                    }
                    outcome.rejected.push(error);
                }
                (InFlight::Op(seq), _) => {
                    self.log
                        .record_answered(seq, generation)
                        .map_err(|_| ClientError::Internal)?;
                }
                (InFlight::Snapshot(sid), UploadResult::Stored | UploadResult::AlreadyStored) => {
                    self.outbox.retain(|s| s.header.snapshot_id != sid);
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
