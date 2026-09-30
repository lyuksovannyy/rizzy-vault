//! What never goes backwards ([ADR 0026] §4, "What never goes backwards"; threat model INV-25,
//! INV-27): the check every [`Changeset`] passes before the host writes it.
//!
//! "The `store` module refuses a changeset that breaks one of these as an internal error and
//! writes nothing." [`Floors`] is a small index of what the file holds (no envelope, no key);
//! [`Floors::admit`] checks a changeset against it, all or nothing, and only then moves the
//! index. The host writes the changeset after `admit` accepted it, in one transaction.
//!
//! # The rules
//!
//! No changeset may:
//! - replace the `account-state` row by a state with a lower `state_seq` or `settings_seq`, or
//!   by other bytes at the same `state_seq` (the flows write alarm 1 or 2 instead);
//! - replace a held bundle or `ACCOUNT_SETTINGS` row by other bytes, or delete a bundle,
//!   settings or `E_id` row, so the newest `bundle_seq` and `identity_epoch` held never go
//!   down (an `E_id` row is replaced when a rotation re-wraps the identity keys under a new
//!   account key at the same `identity_epoch`); only certificate and revocation rows may be
//!   deleted;
//! - delete an `ops` row, or replace its statement, except by a re-issue of a row that is
//!   `own = 1`, or `own = 3` with `sent_generation` equal to the stale answer's restore
//!   generation (§4 step 6);
//! - lower `next_device_seq` or the stored HLC, leave `next_device_seq` at or below an own
//!   `device_seq` held, or insert an own op below the `next_device_seq` stored before (a
//!   reused dot);
//! - replace a `self_grant` by one of a lower `vault_key_epoch`, or of another vault key id at
//!   the same epoch (the fork alarm of ADR 0025 §4);
//! - move `own` other than 1 → 3 → 2, or rewrite a set `sent_generation` (§4 step 6
//!   excepted);
//! - delete a snapshot row that is served or acknowledged;
//! - delete an alarm, except the unconfirmed-identity-change alarm when the user confirmed the
//!   new fingerprint (the one flow of this build that resolves an alarm); removal of the
//!   device removes the file;
//! - change `format`, `server_origin`, `account_id` or `device_id` once set, or write a
//!   device-state record that does not parse or names another account or device.
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use std::collections::BTreeMap;

use rizzy_proto::limits::MAX_UPLOAD_BODY_LEN;

use crate::error::ClientError;
use crate::store::record::DeviceRecord;
use crate::store::rows::{
    Alarm, CACHE_FORMAT, CacheRows, Changeset, OpRow, SnapshotRow, Write, kind, meta, own,
};

/// A 16-byte id.
type Id16 = [u8; 16];

/// A row's id column as 16 bytes.
///
/// # Errors
/// [`ClientError::CacheCorrupt`] for any other length.
pub(crate) fn id16(bytes: &[u8]) -> Result<Id16, ClientError> {
    bytes.try_into().map_err(|_| ClientError::CacheCorrupt)
}

/// A row's `u64` column from its 8-byte big-endian blob.
///
/// # Errors
/// [`ClientError::CacheCorrupt`] for any other length.
pub(crate) fn u64_be(bytes: &[u8]) -> Result<u64, ClientError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| ClientError::CacheCorrupt)?,
    ))
}

/// What the index keeps of an `ops` row.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OpFloor {
    /// The statement, to refuse another one at the same dot.
    statement: Vec<u8>,
    /// The `own` column.
    own: i64,
    /// The `sent_generation` column.
    sent_generation: Option<Id16>,
}

/// What the index keeps of a `snapshots` row.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotFloor {
    /// The statement.
    statement: Vec<u8>,
    /// The `own` column.
    own: i64,
}

/// The `account-state` row.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StateFloor {
    /// Its `state_seq`.
    state_seq: u64,
    /// Its `settings_seq`.
    settings_seq: u64,
    /// Its wire form.
    wire: Vec<u8>,
}

/// The index of what a cache file holds, for the checks of the module docs. Server-visible
/// metadata and signed statements only; `Debug` shows counts.
#[derive(Clone, Default)]
pub struct Floors {
    /// The set-once meta rows (`format`, `server_origin`, `account_id`, `device_id`).
    fixed: BTreeMap<&'static str, Vec<u8>>,
    /// `next_device_seq`, 0 before the first write of it.
    next_device_seq: u64,
    /// The stored HLC.
    hlc: u64,
    /// The `account-state` row.
    state: Option<StateFloor>,
    /// The rows of kinds 1, 3 and 6 (never replaced by other bytes), and the alarm keys.
    objects: BTreeMap<(i64, Vec<u8>), Vec<u8>>,
    /// Per vault: the self-grant's `vault_key_epoch` and the id of the vault key it holds.
    vaults: BTreeMap<Id16, (u32, Id16)>,
    /// The `ops` rows.
    ops: BTreeMap<(Id16, Id16, u64), OpFloor>,
    /// The `snapshots` rows.
    snapshots: BTreeMap<(Id16, Id16), SnapshotFloor>,
}

impl core::fmt::Debug for Floors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Floors")
            .field("next_device_seq", &self.next_device_seq)
            .field("ops", &self.ops.len())
            .field("snapshots", &self.snapshots.len())
            .finish_non_exhaustive()
    }
}

/// The fixed meta key equal to `key`, if it is one of the set-once keys.
fn fixed_key(key: &str) -> Option<&'static str> {
    [
        meta::FORMAT,
        meta::SERVER_ORIGIN,
        meta::ACCOUNT_ID,
        meta::DEVICE_ID,
    ]
    .into_iter()
    .find(|k| *k == key)
}

/// Whether `kind` is one whose rows are never replaced by other bytes.
const fn immutable_kind(kind: i64) -> bool {
    matches!(kind, kind::BUNDLE | kind::SETTINGS | kind::ALARM)
}

/// The key of an op row.
fn op_key(row: &OpRow) -> Result<(Id16, Id16, u64), ClientError> {
    Ok((
        id16(&row.vault_id)?,
        id16(&row.device_id)?,
        u64_be(&row.device_seq)?,
    ))
}

/// The key of a snapshot row.
fn snapshot_key(row: &SnapshotRow) -> Result<(Id16, Id16), ClientError> {
    Ok((id16(&row.vault_id)?, id16(&row.snapshot_id)?))
}

/// An optional generation column as 16 bytes.
fn generation(column: Option<&Vec<u8>>) -> Result<Option<Id16>, ClientError> {
    column.map(|g| id16(g)).transpose()
}

impl Floors {
    /// The floors of an empty cache: the first changeset of a signup or an enrolment is
    /// admitted against it.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The floors of the rows a load verified. `state` is the verified `account-state`'s
    /// `state_seq` and `settings_seq`; `vault_keys` names, per vault, the id of the vault key
    /// its self-grant opened to.
    ///
    /// # Errors
    /// [`ClientError::CacheCorrupt`] for a row whose key columns have the wrong length, a
    /// missing or malformed counter, or a vault without its key id.
    pub(crate) fn of_rows(
        rows: &CacheRows,
        state: (u64, u64),
        vault_keys: &[(Id16, Id16)],
    ) -> Result<Self, ClientError> {
        let bad = ClientError::CacheCorrupt;
        let mut floors = Self::empty();
        for (key, value) in &rows.meta {
            if let Some(fixed) = fixed_key(key) {
                floors.fixed.insert(fixed, value.clone());
            }
        }
        floors.next_device_seq = u64_be(rows.meta.get(meta::NEXT_DEVICE_SEQ).ok_or(bad)?)?;
        floors.hlc = u64_be(rows.meta.get(meta::HLC).ok_or(bad)?)?;
        for object in &rows.objects {
            if object.kind == kind::ACCOUNT_STATE {
                floors.state = Some(StateFloor {
                    state_seq: state.0,
                    settings_seq: state.1,
                    wire: object.bytes.clone(),
                });
            } else if immutable_kind(object.kind) {
                floors
                    .objects
                    .insert((object.kind, object.key.clone()), object.bytes.clone());
            }
        }
        for vault in &rows.vaults {
            let vault_id = id16(&vault.vault_id)?;
            let key_id = vault_keys
                .iter()
                .find(|(id, _)| *id == vault_id)
                .map(|(_, key)| *key)
                .ok_or(bad)?;
            floors
                .vaults
                .insert(vault_id, (vault.self_grant.vault_key_epoch, key_id));
        }
        for op in &rows.ops {
            floors.ops.insert(
                op_key(op)?,
                OpFloor {
                    statement: op.statement.clone(),
                    own: op.own,
                    sent_generation: generation(op.sent_generation.as_ref())?,
                },
            );
        }
        for snapshot in &rows.snapshots {
            floors.snapshots.insert(
                snapshot_key(snapshot)?,
                SnapshotFloor {
                    statement: snapshot.statement.clone(),
                    own: snapshot.own,
                },
            );
        }
        Ok(floors)
    }

    /// The stored `next_device_seq` (0 before the first write).
    #[must_use]
    pub const fn next_device_seq(&self) -> u64 {
        self.next_device_seq
    }

    /// Checks `changeset` against the rules of the module docs and, if every write passes,
    /// moves the index to the state after it. On an error the index is unchanged and the host
    /// writes nothing.
    ///
    /// # Errors
    /// [`ClientError::Internal`] for a changeset that breaks a rule.
    pub fn admit(&mut self, changeset: &Changeset) -> Result<(), ClientError> {
        let mut next = Pending {
            base: self,
            fixed: BTreeMap::new(),
            next_device_seq: self.next_device_seq,
            hlc: self.hlc,
            state: None,
            objects: BTreeMap::new(),
            vaults: BTreeMap::new(),
            ops: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            record: None,
        };
        for write in changeset.writes() {
            next.check(write).map_err(|_| ClientError::Internal)?;
        }
        next.finish().map_err(|_| ClientError::Internal)?;
        let Pending {
            fixed,
            next_device_seq,
            hlc,
            state,
            objects,
            vaults,
            ops,
            snapshots,
            ..
        } = next;
        self.fixed.extend(fixed);
        self.next_device_seq = next_device_seq;
        self.hlc = hlc;
        if let Some(state) = state {
            self.state = Some(state);
        }
        self.objects.extend(objects);
        self.vaults.extend(vaults);
        self.ops.extend(ops);
        for (key, value) in snapshots {
            match value {
                Some(floor) => {
                    self.snapshots.insert(key, floor);
                }
                None => {
                    self.snapshots.remove(&key);
                }
            }
        }
        Ok(())
    }
}

/// A broken rule. No detail: the caller reports [`ClientError::Internal`].
struct Refused;

/// The state a changeset leads to, kept apart from the index until every write passed.
struct Pending<'a> {
    /// The index before the changeset.
    base: &'a Floors,
    /// Set-once meta rows written here.
    fixed: BTreeMap<&'static str, Vec<u8>>,
    /// `next_device_seq` after the writes so far.
    next_device_seq: u64,
    /// The HLC after the writes so far.
    hlc: u64,
    /// The `account-state` written here.
    state: Option<StateFloor>,
    /// Immutable-kind rows written here.
    objects: BTreeMap<(i64, Vec<u8>), Vec<u8>>,
    /// Vault grants written here.
    vaults: BTreeMap<Id16, (u32, Id16)>,
    /// Op rows written or changed here.
    ops: BTreeMap<(Id16, Id16, u64), OpFloor>,
    /// Snapshot rows written or changed (`Some`) or deleted (`None`) here.
    snapshots: BTreeMap<(Id16, Id16), Option<SnapshotFloor>>,
    /// The ids of a device-state record written here.
    record: Option<(Id16, Id16)>,
}

impl Pending<'_> {
    /// The value of a set-once meta row after the writes so far.
    fn fixed(&self, key: &str) -> Option<&Vec<u8>> {
        self.fixed.get(key).or_else(|| self.base.fixed.get(key))
    }

    /// The op row at `key` after the writes so far.
    fn op(&self, key: &(Id16, Id16, u64)) -> Option<&OpFloor> {
        self.ops.get(key).or_else(|| self.base.ops.get(key))
    }

    /// The snapshot row at `key` after the writes so far.
    fn snapshot(&self, key: &(Id16, Id16)) -> Option<&SnapshotFloor> {
        match self.snapshots.get(key) {
            Some(changed) => changed.as_ref(),
            None => self.base.snapshots.get(key),
        }
    }

    /// Whether the vault exists after the writes so far.
    fn vault(&self, vault_id: &Id16) -> Option<&(u32, Id16)> {
        self.vaults
            .get(vault_id)
            .or_else(|| self.base.vaults.get(vault_id))
    }

    /// Checks one write and records its effect.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per write kind, each the rule of the module docs for that kind"
    )]
    fn check(&mut self, write: &Write) -> Result<(), Refused> {
        let corrupt = |_: ClientError| Refused;
        match write {
            Write::Meta { key, value } => self.meta(key, value),
            Write::DeviceState(bytes) => {
                let record = DeviceRecord::parse(bytes).map_err(corrupt)?;
                self.record = Some((
                    record.account_id().to_bytes(),
                    record.device_id().to_bytes(),
                ));
                Ok(())
            }
            Write::PendingCommit(request) => {
                if request
                    .as_ref()
                    .is_some_and(|r| r.is_empty() || r.len() > MAX_UPLOAD_BODY_LEN)
                {
                    return Err(Refused);
                }
                Ok(())
            }
            Write::AccountState {
                wire,
                state_seq,
                settings_seq,
            } => {
                let held = self.state.as_ref().or(self.base.state.as_ref());
                if let Some(held) = held {
                    let rollback = *state_seq < held.state_seq || *settings_seq < held.settings_seq;
                    let fork = *state_seq == held.state_seq && *wire != held.wire;
                    if rollback || fork {
                        return Err(Refused);
                    }
                }
                self.state = Some(StateFloor {
                    state_seq: *state_seq,
                    settings_seq: *settings_seq,
                    wire: wire.clone(),
                });
                Ok(())
            }
            Write::PutObject(row) => {
                let key_len = match row.kind {
                    kind::BUNDLE | kind::SETTINGS => 8,
                    kind::IDENTITY_KEYS => 4,
                    kind::ALARM => 1,
                    _ => return Err(Refused),
                };
                if row.key.len() != key_len || (row.bytes.is_empty() && row.kind != kind::ALARM) {
                    return Err(Refused);
                }
                if immutable_kind(row.kind) {
                    let key = (row.kind, row.key.clone());
                    let held = self
                        .objects
                        .get(&key)
                        .or_else(|| self.base.objects.get(&key));
                    // An alarm row may gain evidence; a bundle or settings row never changes.
                    if row.kind != kind::ALARM && held.is_some_and(|h| *h != row.bytes) {
                        return Err(Refused);
                    }
                    self.objects.insert(key, row.bytes.clone());
                }
                Ok(())
            }
            Write::ClearAlarm(alarm) => {
                // Only the alarm a flow of this build resolves; the others stay for good.
                if *alarm == Alarm::UnconfirmedIdentityChange {
                    Ok(())
                } else {
                    Err(Refused)
                }
            }
            Write::DeviceSet {
                certificates,
                revocations,
            } => {
                // The rows are the signed set, whatever it is; only empty statements are
                // refused here. The set's hash is checked by the flow that verified it.
                if certificates
                    .iter()
                    .chain(revocations)
                    .any(|(_, wire)| wire.is_empty())
                {
                    return Err(Refused);
                }
                Ok(())
            }
            Write::VaultGrant {
                grant,
                vault_key_id,
            } => {
                let vault_id = grant.vault_id.to_bytes();
                if let Some((epoch, key_id)) = self.vault(&vault_id) {
                    let lower = grant.vault_key_epoch < *epoch;
                    let fork = grant.vault_key_epoch == *epoch && key_id != vault_key_id;
                    if lower || fork {
                        return Err(Refused);
                    }
                }
                self.vaults
                    .insert(vault_id, (grant.vault_key_epoch, *vault_key_id));
                Ok(())
            }
            Write::VaultGeneration { vault_id, .. } => {
                self.vault(vault_id).map(|_| ()).ok_or(Refused)
            }
            Write::Wraps {
                vault_id,
                epoch,
                wraps,
            } => {
                // The rows are of this vault, at the epoch of the vault key the grant on disk
                // holds after this changeset.
                let held = self.vault(vault_id).ok_or(Refused)?.0;
                if held != *epoch
                    || wraps
                        .iter()
                        .any(|w| w.vault_id != *vault_id || w.vault_key_epoch != i64::from(*epoch))
                {
                    return Err(Refused);
                }
                Ok(())
            }
            Write::PutOp(row) => self.put_op(row),
            Write::ReissueOp {
                row,
                stale_generation,
            } => {
                let key = op_key(row).map_err(corrupt)?;
                let held = self.op(&key).ok_or(Refused)?;
                let unsent = held.own == own::UNSENT;
                let answered_stale = held.own == own::SENT
                    && stale_generation.is_some()
                    && held.sent_generation == *stale_generation;
                if !(unsent || answered_stale) || row.own != own::UNSENT {
                    return Err(Refused);
                }
                self.ops.insert(
                    key,
                    OpFloor {
                        statement: row.statement.clone(),
                        own: own::UNSENT,
                        sent_generation: None,
                    },
                );
                Ok(())
            }
            Write::OpOwn {
                vault_id,
                device_id,
                device_seq,
                own,
                sent_generation,
            } => {
                let key = (*vault_id, *device_id, *device_seq);
                let mut held = self.op(&key).ok_or(Refused)?.clone();
                advance_own(held.own, *own, sent_generation.is_some())?;
                held.own = *own;
                if held.sent_generation.is_none() {
                    held.sent_generation = *sent_generation;
                }
                self.ops.insert(key, held);
                Ok(())
            }
            Write::PutSnapshot(row) => {
                let key = snapshot_key(row).map_err(corrupt)?;
                match self.snapshot(&key) {
                    Some(held) if held.statement != row.statement => Err(Refused),
                    Some(_) => Ok(()),
                    None => {
                        if !matches!(row.own, own::SERVED | own::UNSENT)
                            || row.sent_generation.is_some()
                            || self.vault(&key.0).is_none()
                        {
                            return Err(Refused);
                        }
                        self.snapshots.insert(
                            key,
                            Some(SnapshotFloor {
                                statement: row.statement.clone(),
                                own: row.own,
                            }),
                        );
                        Ok(())
                    }
                }
            }
            Write::SnapshotOwn {
                vault_id,
                snapshot_id,
                own,
                sent_generation,
            } => {
                let key = (*vault_id, *snapshot_id);
                let mut held = self.snapshot(&key).ok_or(Refused)?.clone();
                advance_own(held.own, *own, sent_generation.is_some())?;
                held.own = *own;
                self.snapshots.insert(key, Some(held));
                Ok(())
            }
            Write::DeleteSnapshot {
                vault_id,
                snapshot_id,
            } => {
                let key = (*vault_id, *snapshot_id);
                match self.snapshot(&key) {
                    Some(held) if matches!(held.own, own::UNSENT | own::SENT) => {
                        self.snapshots.insert(key, None);
                        Ok(())
                    }
                    Some(_) => Err(Refused),
                    // Already gone: deleting nothing breaks no rule.
                    None => Ok(()),
                }
            }
        }
    }

    /// [`Write::Meta`].
    fn meta(&mut self, key: &'static str, value: &[u8]) -> Result<(), Refused> {
        if let Some(fixed) = fixed_key(key) {
            let valid = match fixed {
                meta::FORMAT => value == CACHE_FORMAT.to_be_bytes().as_slice(),
                meta::SERVER_ORIGIN => !value.is_empty(),
                _ => value.len() == 16,
            };
            if !valid
                || self
                    .fixed(fixed)
                    .is_some_and(|held| held.as_slice() != value)
            {
                return Err(Refused);
            }
            self.fixed.insert(fixed, value.to_vec());
            return Ok(());
        }
        let number = u64_be(value).map_err(|_| Refused)?;
        match key {
            meta::NEXT_DEVICE_SEQ => {
                if number == 0 || number < self.next_device_seq {
                    return Err(Refused);
                }
                self.next_device_seq = number;
            }
            meta::HLC => {
                if number < self.hlc {
                    return Err(Refused);
                }
                self.hlc = number;
            }
            _ => return Err(Refused),
        }
        Ok(())
    }

    /// [`Write::PutOp`].
    fn put_op(&mut self, row: &OpRow) -> Result<(), Refused> {
        let key = op_key(row).map_err(|_| Refused)?;
        if let Some(held) = self.op(&key) {
            // The same record again: only a missing body or wrap is filled.
            return if held.statement == row.statement {
                Ok(())
            } else {
                Err(Refused)
            };
        }
        if self.vault(&key.0).is_none() || row.sent_generation.is_some() {
            return Err(Refused);
        }
        let own_device = self
            .fixed(meta::DEVICE_ID)
            .is_some_and(|id| id.as_slice() == key.1.as_slice());
        match row.own {
            own::SERVED if !own_device => {}
            // A new own op takes a dot this file never used: at or above the counter stored
            // before this changeset. `finish` checks that the counter then moved past it.
            own::UNSENT if own_device && key.2 >= self.base.next_device_seq.max(1) => {}
            _ => return Err(Refused),
        }
        self.ops.insert(
            key,
            OpFloor {
                statement: row.statement.clone(),
                own: row.own,
                sent_generation: None,
            },
        );
        Ok(())
    }

    /// The checks that need the whole changeset: the counter is above every own dot written
    /// here, and a device-state record names the cache's account and device.
    fn finish(&self) -> Result<(), Refused> {
        let own_written = self
            .ops
            .iter()
            .filter(|(_, floor)| floor.own != own::SERVED)
            .map(|((_, _, seq), _)| *seq)
            .max();
        if own_written.is_some_and(|seq| seq >= self.next_device_seq) {
            return Err(Refused);
        }
        if let Some((account_id, device_id)) = &self.record {
            let matches = |key: &str, id: &Id16| {
                self.fixed(key)
                    .is_some_and(|held| held.as_slice() == id.as_slice())
            };
            if !matches(meta::ACCOUNT_ID, account_id) || !matches(meta::DEVICE_ID, device_id) {
                return Err(Refused);
            }
        }
        Ok(())
    }
}

/// The `own` column moves only 1 → 3 → 2; a resend leaves 3 at 3. A move to 3 carries the
/// restore generation of the last response.
const fn advance_own(from: i64, to: i64, has_generation: bool) -> Result<(), Refused> {
    match (from, to) {
        (own::UNSENT | own::SENT, own::SENT) if has_generation => Ok(()),
        (own::SENT | own::ACKNOWLEDGED, own::ACKNOWLEDGED) => Ok(()),
        _ => Err(Refused),
    }
}
