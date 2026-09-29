//! The own chain: writing, uploading and acknowledging this device's ops in one vault
//! ([ADR 0012] §7 "Upload" as partly superseded by [ADR 0021] §9; ADR 0021 §2 "Restore
//! generation"; [ADR 0018] §3 "Re-issued ops").
//!
//! # Writing
//!
//! An own op's `vault_prev_seq` is the own chain's head ([`VaultLog::own_vault_prev_seq`]),
//! and its causal context is the item VV the device had (ADR 0012 §2). `device_seq` counts the
//! device's ops in every vault, so the counter lives with the device, not with one vault's log.
//! [`VaultLog::record_own_op`] checks the link and that the context names only settled dots,
//! then keeps the header (ADR 0021 §9 "Headers kept") and settles the dot: the author applies
//! its own op when it writes it.
//!
//! # Uploading and acknowledgements
//!
//! A device uploads its ops in `device_seq` order ([`VaultLog::unacknowledged`]), and the server
//! stores a chain only in order, so an acknowledgement of seq s acknowledges every own link up
//! to s ([`VaultLog::acknowledge`]). "An upload byte-identical to the record the server stores
//! at that (`vault_id`, `device_id`, `device_seq`) … is answered 'already stored' …; the client
//! treats it as an acknowledgement" (ADR 0021 §9 "Already stored"): the same call.
//!
//! # The restore generation
//!
//! Every upload answer and Fetch response carries the server database's restore generation,
//! a random 128-bit value drawn when the database is created and again by
//! `rizzy-vault restore` (ADR 0021 §2). "A client keeps, with each own op it sent without an
//! answer, the value of its last response before the first send": the client passes each
//! answer's value to [`VaultLog::observe_generation`], and [`VaultLog::record_sent`] stores
//! the last one with an op on its first send without an answer. An answer to a send ends
//! "sent without an answer": an acknowledgement ([`VaultLog::acknowledge`]) clears the entry,
//! and so does any other answer ([`VaultLog::record_answered`]: a refusal, a stale-epoch
//! rejection) whose generation is the entry's, because the server answered before any restore
//! and did not store the op. An answer under another generation keeps the entry: a restore
//! came between the first send and the answer, so the op may have been stored, served and lost.
//! A later send records a fresh entry. A re-issue, which replaces the op, clears it too.
//!
//! An own op **may have been stored and served** ([`VaultLog::may_have_been_served`]) when it
//! was acknowledged, or when it was sent without an answer and the restore generation changed
//! since: the server may have stored it, served it to other devices, and lost it in a restore.
//!
//! # A stale-epoch answer
//!
//! ADR 0021 §9 "Stale epoch": the client "re-issues, with the same `device_seq`, only an op the
//! server rejected itself as stale, with the later old-epoch ops of its chain, and never one
//! the server may have stored and served … It re-publishes such an op in a healing request. A
//! stale answer to a snapshot only discards and rewrites it." [`VaultLog::stale_plan`] splits
//! the rejected op and the later own ops whose `vault_key_epoch` is below the current epoch into
//! ops to re-issue and ops to re-publish; a stale answer to a snapshot changes nothing here.
//! Re-issuing two signed versions of one dot, when the first may have reached other devices,
//! would fork the chain; re-publishing an op the server never stored would let an old-epoch body
//! past the stale-epoch check, which exempts re-published records (the spike's KEY check). The
//! restore generation tells the two apart.
//!
//! A re-issued op "keeps `device_seq`, `vault_prev_seq`, `hlc`, the causal context and the op
//! data; only `vault_key_epoch`, the item key the CRYPTO.md §11.6 writer rule picks (so the
//! envelope's `key_id`), the carried wrap and the signature change" (ADR 0018 §3, owner
//! decision 15). Of the header's fields only `vault_key_epoch` may therefore differ, and
//! [`VaultLog::reissue_own_op`] checks it, then holds the new header in place of the original.
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0018]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0018-item-record-encoding.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

use core::fmt;
use std::collections::BTreeMap;

use crate::dot::Dot;
use crate::header::OpHeader;

use super::{LinkState, VaultLog, missing_context};

/// A server database's restore generation (ADR 0021 §2): one random 128-bit value per server
/// database, drawn at creation and again by `rizzy-vault restore`. Every upload answer and
/// Fetch response carries it. Server-visible metadata, never a secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RestoreGeneration([u8; RestoreGeneration::LEN]);

impl RestoreGeneration {
    /// Length in bytes: 128 bits.
    pub const LEN: usize = 16;

    /// The generation with these bytes, as an answer carries them.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The generation's bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }
}

impl fmt::Debug for RestoreGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RestoreGeneration(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

/// The own chain's upload state in one vault.
#[derive(Clone, Debug, Default)]
pub(super) struct Uploads {
    /// The highest own `device_seq` the server acknowledged in this vault (stored, or already
    /// stored), 0 if none. Every own link up to it is acknowledged.
    acked: u64,
    /// The own ops sent without an answer, above `acked`, each with the restore generation of
    /// the last response before its first send.
    unanswered: BTreeMap<u64, RestoreGeneration>,
    /// The restore generation of the last answer or Fetch response.
    last_generation: Option<RestoreGeneration>,
}

/// Which own ops a stale-epoch answer re-issues and which it re-publishes
/// ([`VaultLog::stale_plan`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StalePlan {
    /// The ops to re-issue with the same `device_seq` under the current epoch, ascending: the
    /// server never stored or served them. Each goes back through
    /// [`VaultLog::reissue_own_op`] and the normal upload path.
    pub reissue: Vec<Dot>,
    /// The ops the server may have stored and served, ascending: re-published verbatim in a
    /// healing request (ADR 0012 §7), never re-issued.
    pub republish: Vec<Dot>,
}

/// Why an own-chain call was refused. Server-visible metadata only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OwnError {
    /// The header names another vault.
    WrongVault,
    /// The header names another device.
    NotOwnDevice,
    /// The header does not extend the own chain: its `vault_prev_seq` is not the head, or its
    /// `device_seq` is not above it.
    BrokenChain {
        /// The own chain's head.
        head: u64,
    },
    /// The causal context names a dot that the item's settled VV does not cover: the author
    /// cannot have applied it, so no receiver could deliver the op.
    ContextNotSettled,
    /// No own link has this `device_seq`.
    UnknownOp,
    /// The op was acknowledged: the server stored it, and may have served it. Never re-issued.
    Acknowledged,
    /// The op was sent without an answer before the restore generation changed: the server may
    /// have stored and served it. Never re-issued.
    MayHaveBeenServed,
    /// The new header differs from the held one in more than a higher `vault_key_epoch`
    /// (ADR 0018 §3 "Re-issued ops").
    NotAReissue,
    /// No answer or Fetch response has been observed yet, so the restore generation of the
    /// last response before the send is unknown. Fetch first.
    NoGeneration,
    /// The rejected op's `vault_key_epoch` is not below the current epoch.
    NotStale,
}

impl fmt::Display for OwnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongVault => f.write_str("the op names another vault"),
            Self::NotOwnDevice => f.write_str("the op names another device"),
            Self::BrokenChain { head } => {
                write!(f, "the op does not extend the own chain at head {head}")
            }
            Self::ContextNotSettled => f.write_str("the causal context names an unsettled dot"),
            Self::UnknownOp => f.write_str("no own op has this sequence number"),
            Self::Acknowledged => f.write_str("the op was acknowledged"),
            Self::MayHaveBeenServed => f.write_str("the op may have been stored and served"),
            Self::NotAReissue => f.write_str("the header is not a re-issue of the held op"),
            Self::NoGeneration => f.write_str("no restore generation observed yet"),
            Self::NotStale => f.write_str("the op's epoch is not below the current epoch"),
        }
    }
}

impl core::error::Error for OwnError {}

impl VaultLog {
    /// The `vault_prev_seq` of the next own op: the own chain's head, 0 before the first
    /// (ADR 0012 §2).
    #[must_use]
    pub fn own_vault_prev_seq(&self) -> u64 {
        self.head(self.own)
    }

    /// Records an op this device wrote: the next link of the own chain, settled at once.
    ///
    /// # Errors
    /// [`OwnError::WrongVault`], [`OwnError::NotOwnDevice`]; [`OwnError::BrokenChain`] unless
    /// `vault_prev_seq` is the own head and `device_seq` is above it;
    /// [`OwnError::ContextNotSettled`] if the causal context names a dot the item's settled VV
    /// does not cover. Nothing changes on error.
    pub fn record_own_op(&mut self, header: OpHeader) -> Result<(), OwnError> {
        self.check_own(&header)?;
        let head = self.own_vault_prev_seq();
        if header.vault_prev_seq != head || header.dot.seq() <= head {
            return Err(OwnError::BrokenChain { head });
        }
        if missing_context(&self.items, &header).is_some() {
            return Err(OwnError::ContextNotSettled);
        }
        let dot = header.dot;
        self.items.entry(header.item_id).or_default().add(dot);
        self.accept_link(header, LinkState::Delivered);
        Ok(())
    }

    /// The highest own `device_seq` the server acknowledged in this vault, 0 if none.
    #[must_use]
    pub const fn acknowledged(&self) -> u64 {
        self.uploads.acked
    }

    /// The own ops not yet acknowledged, in `device_seq` order: the upload queue (ADR 0012 §7
    /// "A device uploads its ops in `device_seq` order").
    pub fn unacknowledged(&self) -> impl Iterator<Item = &OpHeader> + '_ {
        let acked = self.uploads.acked;
        self.chain(self.own).filter(move |h| h.dot.seq() > acked)
    }

    /// Notes the restore generation an upload answer or a Fetch response carried (ADR 0021 §2).
    /// Call it for every answer, before acting on it.
    pub fn observe_generation(&mut self, generation: RestoreGeneration) {
        self.uploads.last_generation = Some(generation);
    }

    /// Notes that the own op with `device_seq` = `seq` is being sent. On its first send without
    /// an answer the log keeps the restore generation of the last response; later sends keep
    /// that first value. An acknowledged op needs no entry.
    ///
    /// # Errors
    /// [`OwnError::UnknownOp`] if no own link has `seq`; [`OwnError::NoGeneration`] if no answer
    /// or response has been observed.
    pub fn record_sent(&mut self, seq: u64) -> Result<(), OwnError> {
        if self.own_link(seq).is_none() {
            return Err(OwnError::UnknownOp);
        }
        if seq <= self.uploads.acked {
            return Ok(());
        }
        let generation = self.uploads.last_generation.ok_or(OwnError::NoGeneration)?;
        self.uploads.unanswered.entry(seq).or_insert(generation);
        Ok(())
    }

    /// The server stored the own op with `device_seq` = `seq`, or answered "already stored"
    /// (ADR 0021 §9): it and every own link before it are acknowledged, since the server stores
    /// a chain only in order.
    ///
    /// # Errors
    /// [`OwnError::UnknownOp`] if no own link has `seq`.
    pub fn acknowledge(&mut self, seq: u64) -> Result<(), OwnError> {
        if self.own_link(seq).is_none() {
            return Err(OwnError::UnknownOp);
        }
        let uploads = &mut self.uploads;
        uploads.acked = uploads.acked.max(seq);
        let acked = uploads.acked;
        uploads.unanswered.retain(|&s, _| s > acked);
        Ok(())
    }

    /// The server answered a send of the own op with `device_seq` = `seq` without storing it (a
    /// refusal such as a stale-epoch rejection or a `vault_prev_seq` mismatch), and the answer
    /// carried `generation`. If the op's entry was kept under the same generation, the server
    /// answered before any restore, so the op was never stored and the entry is cleared: the op
    /// is no longer "sent without an answer" (ADR 0021 §2, §9 "Stale epoch"). Under another
    /// generation the entry stays: a restore came between the first send and this answer, and
    /// the op may have been stored and served before it. Call it on every such answer, when it
    /// arrives, before [`VaultLog::stale_plan`]; call [`VaultLog::observe_generation`] with the
    /// same value too.
    ///
    /// # Errors
    /// [`OwnError::UnknownOp`] if no own link has `seq`.
    pub fn record_answered(
        &mut self,
        seq: u64,
        generation: RestoreGeneration,
    ) -> Result<(), OwnError> {
        if self.own_link(seq).is_none() {
            return Err(OwnError::UnknownOp);
        }
        if self.uploads.unanswered.get(&seq) == Some(&generation) {
            self.uploads.unanswered.remove(&seq);
        }
        Ok(())
    }

    /// Whether the server may have stored, and served, the own op with `device_seq` = `seq`:
    /// it was acknowledged, or it was sent without an answer and the last observed restore
    /// generation differs from the one before its first send (ADR 0021 §9 "Stale epoch").
    #[must_use]
    pub fn may_have_been_served(&self, seq: u64) -> bool {
        seq <= self.uploads.acked
            || self
                .uploads
                .unanswered
                .get(&seq)
                .is_some_and(|&g| Some(g) != self.uploads.last_generation)
    }

    /// What a stale-epoch answer to the own op `rejected` re-issues and re-publishes
    /// (ADR 0021 §9 "Stale epoch"): the rejected op and every later own op whose
    /// `vault_key_epoch` is below `current_epoch`, the vault epoch of the new `account-state`
    /// the client processed first (CRYPTO.md §11.3 steps 3–4). Each one the server may have
    /// stored and served is re-published; the others are re-issued. Call
    /// [`VaultLog::record_answered`] for the stale answer when it arrives, so that a restore
    /// observed after it (a later Fetch) does not make the rejected op "maybe served".
    ///
    /// # Errors
    /// [`OwnError::UnknownOp`] if no own link has `rejected`; [`OwnError::NotStale`] if its
    /// `vault_key_epoch` is not below `current_epoch`.
    pub fn stale_plan(&self, rejected: u64, current_epoch: u32) -> Result<StalePlan, OwnError> {
        let link = self.own_link(rejected).ok_or(OwnError::UnknownOp)?;
        if link.vault_key_epoch >= current_epoch {
            return Err(OwnError::NotStale);
        }
        let mut plan = StalePlan::default();
        for h in self
            .chain(self.own)
            .filter(|h| h.dot.seq() >= rejected && h.vault_key_epoch < current_epoch)
        {
            if self.may_have_been_served(h.dot.seq()) {
                plan.republish.push(h.dot);
            } else {
                plan.reissue.push(h.dot);
            }
        }
        Ok(plan)
    }

    /// Holds a re-issued own op in place of the original (ADR 0018 §3 "Re-issued ops", owner
    /// decision 15): the same header but for a higher `vault_key_epoch`. The re-issued op has
    /// not been sent, so any unanswered send of the original is forgotten.
    ///
    /// # Errors
    /// [`OwnError::WrongVault`], [`OwnError::NotOwnDevice`], [`OwnError::UnknownOp`];
    /// [`OwnError::Acknowledged`] or [`OwnError::MayHaveBeenServed`] if the server may have
    /// stored and served the original; [`OwnError::NotAReissue`] if another field differs or
    /// the epoch is not higher. Nothing changes on error.
    pub fn reissue_own_op(&mut self, header: OpHeader) -> Result<(), OwnError> {
        self.check_own(&header)?;
        let seq = header.dot.seq();
        let original = self.own_link(seq).ok_or(OwnError::UnknownOp)?;
        if seq <= self.uploads.acked {
            return Err(OwnError::Acknowledged);
        }
        if self.may_have_been_served(seq) {
            return Err(OwnError::MayHaveBeenServed);
        }
        let mut expected = original.clone();
        expected.vault_key_epoch = header.vault_key_epoch;
        if expected != header || header.vault_key_epoch <= original.vault_key_epoch {
            return Err(OwnError::NotAReissue);
        }
        if let Some(link) = self
            .chains
            .get_mut(&self.own)
            .and_then(|c| c.links.get_mut(&seq))
        {
            link.header = header;
        }
        self.uploads.unanswered.remove(&seq);
        Ok(())
    }

    /// The held header of the own link with `device_seq` = `seq`.
    fn own_link(&self, seq: u64) -> Option<&OpHeader> {
        Dot::new(self.own, seq).and_then(|dot| self.header(dot))
    }

    /// Refuses a header of another vault or device.
    fn check_own(&self, header: &OpHeader) -> Result<(), OwnError> {
        if header.vault_id != self.vault_id {
            Err(OwnError::WrongVault)
        } else if header.dot.device_id() != self.own {
            Err(OwnError::NotOwnDevice)
        } else {
            Ok(())
        }
    }
}
