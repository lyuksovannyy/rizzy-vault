//! Restore healing of one vault: the client's half of ADR 0021 §9 "Server behind", "Healing
//! request" and "Stale epoch" (which replace ADR 0012 §7 "Healing a server rollback" step 4,
//! its read-only condition and "Leaving read-only"), with the persistence steps of ADR 0026
//! §4.
//!
//! # When
//!
//! [`VaultSync::needs_healing`] holds while the last Fetch found the server behind this device
//! (the vault is read-only, [`VaultSync::is_read_only`]), or while a `stale_epoch` answer named
//! an own op the server may have stored and served before a restore, which "is re-published in
//! a healing request" and never re-issued ([`ClientError::HealingRequired`] from
//! [`VaultSync::upload_request`]). The host then Fetches (the healing ranges start at the
//! server's heads of the last Fetch), sends [`VaultSync::healing_request`] to `vault/heal`,
//! passes the answer to [`VaultSync::apply_healing_response`] (or calls
//! [`VaultSync::healing_refused`]), and Fetches again: "the device leaves read-only once none
//! [of the conditions] holds". Then the normal upload path runs.
//!
//! # What the request holds
//!
//! "Every item-key wrap the server lacks, then per chain from h + 1 up to the device's cursor,
//! capped at a known cut-off, every header the device holds, with its body if it holds the
//! body of a record the server stored before, else without it behind the request's fresh
//! snapshot or a held snapshot sent verbatim. An own op never acknowledged takes the normal
//! upload path unless the server may have stored and served it."
//!
//! - **Wraps:** the wraps this device knows the server held at the held vault-key epoch (served
//!   wrap-set rows, wraps carried by served or acknowledged records) whose row the last Fetch
//!   did not serve. The wrap a re-published record carries fills its row as well.
//! - **Another device's chain:** each held link above the server's head, up to this device's
//!   cursor for it and its known revocation cut-off, verbatim: every record held came from the
//!   server, so the server stored it before. A link whose body this device does not hold (the
//!   server served it bodiless, or this device pruned it) goes without the body, behind a held
//!   snapshot that covers it, sent verbatim.
//! - **The own chain:** each own link above the server's head that the server acknowledged or
//!   may have stored and served (sent without an answer before the restore generation
//!   changed), verbatim with its body; the walk stops at the first own op that is neither,
//!   which goes up afterwards by the normal upload path (its `vault_prev_seq` is then the
//!   server's head again). An own op at or below the server's head is stored and outside
//!   the request's range; if never acknowledged, it goes up verbatim by the normal upload
//!   path and is answered "already stored" ([`VaultSync::awaits_republish`]).
//! - **Covers last**, after every header: the server clamps a request's snapshots "after the
//!   request's headers".
//!
//! # Readings (reported)
//!
//! - **No fresh snapshot.** The ADR allows "the request's fresh snapshot or a held snapshot
//!   sent verbatim". This build sends held snapshots only. Every bodiless header this device
//!   holds was accepted behind a cover it absorbed (ADR 0012 §7 chain check), or was pruned
//!   behind an own acknowledged snapshot ([`VaultSync`] `prune_bodies`), and both are held, so
//!   a held cover always exists; a fresh snapshot would also cover the own ops left to the
//!   normal upload path, which the server refuses as claims of unheld dots (ADR 0021 §9
//!   "Server acceptance"). Oversize items need no special case: they get no fresh snapshot
//!   either way (ADR 0018 owner decision 12).
//! - **One request.** "Step 4 is one request per vault." A request beyond the wire limits
//!   ([`MAX_RECORDS`], [`MAX_ITEM_KEY_WRAPS`]) is not split: [`ClientError::CannotHeal`].
//!   So is a range with a header this device does not hold, or holds with neither its body nor
//!   a held cover, and a server behind on a device for which this device holds nothing to send
//!   (an absorbed snapshot's claim above the server's head): the vault stays read-only and the
//!   host reports it.
//! - **Not under an alarm.** While the host holds the vault read-only (a rollback, a fork, an
//!   unconfirmed identity change, an outdated device state) no healing request is built: the
//!   device state itself may be the older copy (ADR 0026 §4 step 7).
//! - **Step 3b** (ADR 0032 §2): the vault's self-grant and its wrap set at that grant's epoch, in
//!   a request without records ([`VaultSync::self_grant_healing_request`]), sent before this
//!   module's request so that no record waits on the epoch.
//! - **Account healing** (ADR 0012 §7 steps 1–3: the bundle chain, the `account-state`, grants
//!   and self-grants) is not here but in [`crate::healing`]: a server whose `account-state` is
//!   behind is reported by the unlock checks of [`crate::unlock`] as a rollback, the host
//!   re-publishes what that module builds, and the vault is healed after the account answer
//!   verifies again.
//!
//! # Persistence (ADR 0026 §4)
//!
//! Building the request writes nothing: every record it carries is already a row. The answer
//! moves every own row up to the highest re-published one to `own = 2` ("already stored" and
//! stored alike are an acknowledgement, §4 step 6), the rows at or below the server's head that
//! the request skipped included, and stores the answer's restore generation, in the changeset
//! [`VaultSync::take_writes`] returns next. A refusal changes no row.

use rizzy_proto::limits::{MAX_ITEM_KEY_WRAPS, MAX_RECORDS};
use rizzy_proto::objects::{ItemKeyWrap, VaultSelfGrant};
use rizzy_proto::vault::{HealingRequest, HealingResponse, OpRecord, Record};
use rizzy_proto::wire::List;
use rizzy_sync::causal::RestoreGeneration;
use rizzy_sync::dot::Dot;

use super::VaultSync;
use crate::error::ClientError;
use crate::store::rows::{Write, own};
use crate::wire::id;

/// What an accepted healing request did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HealingOutcome {
    /// Op records the request carried (own and other devices').
    pub ops: usize,
    /// Of them, own ops: acknowledged now.
    pub own_acknowledged: usize,
    /// Held snapshots sent verbatim as covers.
    pub covers: usize,
    /// Item-key wraps sent.
    pub wraps: usize,
}

/// The request in flight, for its answer.
#[derive(Clone, Debug, Default)]
pub(super) struct HealInFlight {
    /// The own `device_seq`s the request re-published, ascending.
    own: Vec<u64>,
    /// What the request carried.
    outcome: HealingOutcome,
}

impl VaultSync {
    /// Whether this vault needs a healing request (module docs, "When").
    #[must_use]
    pub fn needs_healing(&self) -> bool {
        self.server_behind || !self.stale_republish().is_empty()
    }

    /// The own ops a pending `stale_epoch` answer re-publishes (ADR 0021 §9 "Stale epoch"):
    /// those of [`rizzy_sync::causal::VaultLog::stale_plan`] that the server may have stored and
    /// served and that it has not acknowledged since ([`VaultSync::awaits_republish`]). Empty
    /// without a pending answer, or while the new vault key is not adopted yet.
    pub(super) fn stale_republish(&self) -> Vec<Dot> {
        let Some(rejected) = self.stale_from else {
            return Vec::new();
        };
        self.log
            .stale_plan(rejected, self.vault_key.epoch())
            .map(|plan| {
                plan.republish
                    .into_iter()
                    .filter(|dot| self.awaits_republish(*dot))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether the own op at `dot`, one a stale answer's plan re-publishes, still waits for a
    /// healing request: it is not acknowledged, and it is above the server's own head of the
    /// last Fetch.
    ///
    /// An own op at or below that head is stored: the server stores a chain only in order, and
    /// only this device signs its dots. A healing request's ranges start at h + 1 (ADR 0021 §9
    /// "Healing request"), so it cannot carry such an op; the normal upload path re-sends it
    /// verbatim instead, which the server answers "already stored" before the stale-epoch
    /// check, and that answer acknowledges it ("Already stored"). This is how an op gets
    /// acknowledged whose healing answer was lost, or which another device's healing request
    /// re-published first. Were the server's record at that dot another one (an older copy of
    /// this device's state), the upload is refused as a conflict and the host raises the alarm
    /// (ADR 0026 §4 step 6); no op is re-issued at a stored dot either way.
    pub(super) fn awaits_republish(&self, dot: Dot) -> bool {
        let server_head = self
            .server_heads
            .as_ref()
            .map_or(0, |heads| heads.get(self.device_id));
        dot.seq() > self.acked() && dot.seq() > server_head
    }

    /// The healing request of this vault (module docs), or `None` when it needs none.
    ///
    /// # Errors
    /// [`ClientError::ReadOnly`] while the host holds the vault read-only (an alarm);
    /// [`ClientError::FetchRequired`] before the first Fetch; [`ClientError::CannotHeal`] when
    /// no complete request can be built (module docs, "Readings"); [`ClientError::Internal`].
    pub fn healing_request(&mut self) -> Result<Option<HealingRequest>, ClientError> {
        if self.host_read_only {
            return Err(ClientError::ReadOnly);
        }
        let (Some(heads), Some(_)) = (self.server_heads.as_ref(), self.generation) else {
            return Err(ClientError::FetchRequired);
        };
        if !self.needs_healing() {
            return Ok(None);
        }
        let own_device = self.device_id;
        let cursor = self.log.cursor();
        let mut devices: Vec<_> = cursor.entries().map(Dot::device_id).collect();
        if !devices.contains(&own_device) {
            devices.push(own_device);
        }
        devices.sort_unstable();
        let mut range = HealRange::default();
        for device in devices {
            let server_head = heads.get(device);
            if device == own_device {
                self.own_range(server_head, &mut range)?;
            } else {
                let top = self
                    .log
                    .cutoff(device)
                    .map_or(cursor.get(device), |cut| cursor.get(device).min(cut));
                self.other_range(device, server_head, top, &mut range)?;
            }
        }
        let HealRange {
            ops,
            covers: cover_ids,
            own: own_seqs,
        } = range;
        let wraps: Vec<ItemKeyWrap> = self
            .known_wraps
            .iter()
            .filter(|(key, _)| !self.served_wraps.contains(key))
            .map(|(_, wrap)| wrap.clone())
            .collect();
        let mut records: Vec<Record> = ops.into_iter().cloned().map(Record::Op).collect();
        let op_count = records.len();
        for index in &cover_ids {
            let (_, record) = self.held_covers.get(*index).ok_or(ClientError::Internal)?;
            records.push(Record::Snapshot(record.clone()));
        }
        if records.is_empty() && wraps.is_empty() {
            // Behind, with nothing this device can send back.
            return if self.server_behind {
                Err(ClientError::CannotHeal)
            } else {
                Ok(None)
            };
        }
        if records.len() > MAX_RECORDS || wraps.len() > MAX_ITEM_KEY_WRAPS {
            return Err(ClientError::CannotHeal);
        }
        let outcome = HealingOutcome {
            ops: op_count,
            own_acknowledged: own_seqs.len(),
            covers: cover_ids.len(),
            wraps: wraps.len(),
        };
        let request = HealingRequest {
            vault_id: id(self.vault_id.to_bytes()),
            item_key_wraps: List::new(wraps).map_err(|_| ClientError::CannotHeal)?,
            records: List::new(records).map_err(|_| ClientError::CannotHeal)?,
            self_grant: None,
        };
        self.healing = Some(HealInFlight {
            own: own_seqs,
            outcome,
        });
        self.synced = false;
        Ok(Some(request))
    }

    /// Applies the server's acceptance of the last [`VaultSync::healing_request`]: the
    /// re-published own ops, and every own op before them, are acknowledged (and their rows
    /// move to `own = 2`, ADR 0026 §4 step 6), and the answer's restore generation is noted.
    /// The vault stays read-only until the next Fetch shows the server's heads again
    /// ("Leaving read-only").
    ///
    /// # Errors
    /// [`ClientError::Internal`] without a request in flight.
    pub fn apply_healing_response(
        &mut self,
        response: &HealingResponse,
    ) -> Result<HealingOutcome, ClientError> {
        let in_flight = self.healing.take().ok_or(ClientError::Internal)?;
        let generation = RestoreGeneration::from_bytes(response.restore_generation.to_bytes());
        self.log.observe_generation(generation);
        self.generation = Some(generation);
        if let Some(&top) = in_flight.own.last() {
            // The server stores a chain only in order, so the answer acknowledges every own
            // link up to `top` ([`rizzy_sync::causal::VaultLog::acknowledge`]), the ones at or
            // below the server's head that the request skipped (they were stored already)
            // included. Every one of them moves to `own = 2` (ADR 0026 §4 step 6), so the rows
            // on disk agree with the log: an acknowledged row never follows an unacknowledged
            // one.
            let before = self.acked();
            let acknowledged: Vec<u64> = self
                .log
                .chain(self.device_id)
                .map(|header| header.dot.seq())
                .filter(|&seq| seq > before && seq <= top)
                .collect();
            self.log
                .acknowledge(top)
                .map_err(|_| ClientError::Internal)?;
            let vault_id = self.vault_id.to_bytes();
            let device_id = self.device_id.to_bytes();
            for seq in acknowledged {
                self.answered.remove(&seq);
                self.record(|| Write::OpOwn {
                    vault_id,
                    device_id,
                    device_seq: seq,
                    own: own::ACKNOWLEDGED,
                    sent_generation: None,
                });
            }
            self.hold_acknowledged();
        }
        self.synced = false;
        self.prune_bodies();
        Ok(in_flight.outcome)
    }

    /// Healing step 3b of [ADR 0032] §2 for this vault: `grant`, the vault's self-grant under
    /// the pinned state's account key (from [`crate::healing::AccountHealing::self_grants`]),
    /// and in `item_key_wraps` every wrap-set row this device holds at that grant's
    /// `vault_key_epoch`, without records. The server repairs its self-grant with it while the
    /// stored one lags the signed state (ADR 0032 §3), and takes a repeat as success. Building
    /// it changes nothing here; the host sends it before step 4 and fetches afterwards (the next
    /// Fetch shows the healed wrap set and restore generation), so no answer needs applying.
    ///
    /// **Client precondition** (§3): only for a vault whose last complete Fetch was at the current
    /// `vault_key_epoch`, that is, while this device holds the whole wrap set at the held epoch
    /// (after a load from the cache, or a complete Fetch since the key was adopted). A row the
    /// server lacks afterwards is re-published with step 4's request.
    ///
    /// [ADR 0032]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0032-healing-rotation-after-backup.md
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for another vault's grant or a grant at another epoch than
    /// the held vault key's;
    /// [`ClientError::CannotHeal`] when the precondition does not hold or the wraps exceed the
    /// wire limit.
    pub fn self_grant_healing_request(
        &self,
        grant: &VaultSelfGrant,
    ) -> Result<HealingRequest, ClientError> {
        let epoch = self.vault_key.epoch();
        if grant.vault_id.to_bytes() != self.vault_id.to_bytes() || grant.vault_key_epoch != epoch {
            return Err(ClientError::InvalidInput);
        }
        if self.wraps_complete_at != Some(epoch) {
            return Err(ClientError::CannotHeal);
        }
        let wraps: Vec<ItemKeyWrap> = self
            .known_wraps
            .values()
            .filter(|w| w.vault_key_epoch == epoch)
            .cloned()
            .collect();
        if wraps.len() > MAX_ITEM_KEY_WRAPS {
            return Err(ClientError::CannotHeal);
        }
        Ok(HealingRequest {
            vault_id: id(self.vault_id.to_bytes()),
            item_key_wraps: List::new(wraps).map_err(|_| ClientError::CannotHeal)?,
            records: List::empty(),
            self_grant: Some(grant.clone()),
        })
    }

    /// The server refused the last [`VaultSync::healing_request`] (ADR 0021 §9: "else it
    /// refuses the whole request"): nothing was stored and no row changes. The vault stays
    /// read-only; the host reports the refusal.
    pub fn healing_refused(&mut self) {
        self.healing = None;
    }
}

/// The ranges of a healing request, collected chain by chain.
#[derive(Default)]
struct HealRange<'a> {
    /// The op records, in storing order.
    ops: Vec<&'a OpRecord>,
    /// Indexes into the held covers of the covers the request sends, in first-use order.
    covers: Vec<usize>,
    /// The own `device_seq`s re-published, ascending.
    own: Vec<u64>,
}

impl VaultSync {
    /// The own chain's part of a healing request (module docs): each own link above the
    /// server's head `server_head` that the server acknowledged or may have stored and served,
    /// up to the first that is neither.
    fn own_range<'a>(
        &'a self,
        server_head: u64,
        range: &mut HealRange<'a>,
    ) -> Result<(), ClientError> {
        for header in self.log.chain(self.device_id) {
            let seq = header.dot.seq();
            if seq <= server_head {
                continue;
            }
            let record = if seq <= self.acked() {
                self.held_ops
                    .get(&header.dot)
                    .or_else(|| self.own_records.get(&seq).map(|o| &o.record))
            } else if self.log.may_have_been_served(seq) {
                self.own_records.get(&seq).map(|o| &o.record)
            } else {
                // Never stored: the normal upload path, after the request.
                break;
            };
            let record = record.ok_or(ClientError::CannotHeal)?;
            if record.body.is_none() {
                return Err(ClientError::CannotHeal);
            }
            range.ops.push(record);
            range.own.push(seq);
        }
        Ok(())
    }

    /// Another device's part of a healing request (module docs): each held link of `device`
    /// above `server_head` and up to `top`, with its body, or without it behind the newest held
    /// snapshot of its item that covers it.
    fn other_range<'a>(
        &'a self,
        device: rizzy_core::ids::DeviceId,
        server_head: u64,
        top: u64,
        range: &mut HealRange<'a>,
    ) -> Result<(), ClientError> {
        for header in self.log.chain(device) {
            let seq = header.dot.seq();
            if seq <= server_head || seq > top {
                continue;
            }
            let record = self
                .held_ops
                .get(&header.dot)
                .ok_or(ClientError::CannotHeal)?;
            if record.body.is_none() {
                let cover = self
                    .held_covers
                    .iter()
                    .rposition(|(s, _)| s.item_id == header.item_id && s.covered.covers(header.dot))
                    .ok_or(ClientError::CannotHeal)?;
                if !range.covers.contains(&cover) {
                    range.covers.push(cover);
                }
            }
            range.ops.push(record);
        }
        Ok(())
    }
}
