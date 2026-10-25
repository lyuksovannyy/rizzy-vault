// SPDX-License-Identifier: AGPL-3.0-only

//! The durable device's alarms ([ADR 0026] §3 kind 7, §4 step 4, §5; the replacement text of
//! [ADR 0095] §A, §C and §D, as `rizzy-client` and `rv` implement it): what the extension
//! persists so that "a restart never lifts read-only mode", and the removal rules.
//!
//! # The split (written before this module's code, as CLAUDE.md requires)
//!
//! Every decision about the rows is already [`rizzy_client::store`]'s: the row an alarm is
//! ([`store::alarm_write`]), the one write that clears one ([`Write::ClearAlarm`], refused by the
//! floors for every alarm but a resolved rollback and a confirmed identity change), and the
//! load that refuses an alarm key this build does not know and makes every vault read-only
//! while an alarm is held ([`store::load::Loaded::alarms`]). This module only does what `rv`'s
//! `Device::raise`/`Device::alarms` and `commands.rs`'s `refuse_under_alarm` do for a native
//! host: it keeps the held set and the writes not yet drained, and names the alarm that
//! refuses a sync or a removal. No new row, key or format: an alarm is an `account_objects`
//! row of kind 7 in the extension's store exactly as in `rv`'s `SQLite` file (`crate::store`'s
//! codec already carries every kind from 1 to 7).
//!
//! | Alarm | Raised here when | Cleared | Sync | Removal |
//! |---|---|---|---|---|
//! | 1 rollback | the account answer or a vault key is older than the pin | in the changeset that adopts a verified answer (ADR 0021 §9 "Server behind") | runs (it may resolve it) | refused |
//! | 2 fork | two account states or vault keys at one sequence | never | refused | refused |
//! | 3 unconfirmed identity change | never: the extension has no confirmation flow (the sync ends with `identity_change_unconfirmed` and writes nothing) | only by `rv`'s confirmation | runs | refused |
//! | 4 device state outdated | a Fetch shows more own history, or an upload a conflict at an own dot (ADR 0095 §C) | never | refused | allowed: its only resolution |
//!
//! The key-less check ([`removal_refusal`]) reads the alarm keys of a cache that does not
//! unlock, as `rv`'s `Db::alarm_keys` does: the rows are cleartext (§3), so a cache that does
//! not unlock is refused removal by the same rule, and an alarm key this build does not know
//! is refused too (it may be an alarm of a newer build; deleting evidence is not undone).
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
//! [ADR 0095]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0095-owner-answers-0023-0028-recorded.md

use std::collections::BTreeSet;

use core::fmt;

use rizzy_client::ClientError;
use rizzy_client::store::rows::{Alarm, Changeset, Write, kind};
use rizzy_client::store::{self};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::store::KvRow;

/// The code an alarm key this build does not know is named by.
pub const ALARM_UNKNOWN: &str = "alarm_unknown";

/// The error an alarm stands for; its code names the alarm to the host.
#[must_use]
pub(crate) const fn error_of(alarm: Alarm) -> ClientError {
    match alarm {
        Alarm::Rollback => ClientError::Rollback,
        Alarm::Fork => ClientError::Fork,
        Alarm::UnconfirmedIdentityChange => ClientError::IdentityChangeUnconfirmed,
        Alarm::DeviceStateOutdated => ClientError::DeviceStateOutdated,
    }
}

/// The alarm a vault-key refusal raises (ADR 0025 §4, as `rv`'s `device/vaults.rs`): a second
/// vault key at a seen epoch is a fork, one below the held epoch a rollback.
#[must_use]
pub(crate) fn of_vault_key_error(code: &str) -> Option<Alarm> {
    if code == ClientError::Fork.code() {
        Some(Alarm::Fork)
    } else if code == ClientError::Rollback.code() {
        Some(Alarm::Rollback)
    } else {
        None
    }
}

/// The alarms a durable device holds, and the writes of those raised or cleared since the last
/// drain (module docs).
#[derive(Default)]
pub(crate) struct Alarms {
    /// The alarms held: the loaded rows, then every one raised.
    held: BTreeSet<Alarm>,
    /// The writes not yet drained to the host.
    writes: Changeset,
}

impl fmt::Debug for Alarms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Alarms")
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl Alarms {
    /// The alarms a cache loaded with ([`store::load::Loaded::alarms`]).
    pub(crate) const fn loaded(held: BTreeSet<Alarm>) -> Self {
        Self {
            held,
            writes: Changeset::new(),
        }
    }

    /// Raises `alarm` with the conflicting signed statements as evidence (ADR 0026 §4 step 4):
    /// its row goes out with the next drain, which also carries the answer that raised it.
    ///
    /// # Errors
    /// As [`store::alarm_write`].
    pub(crate) fn raise(&mut self, alarm: Alarm, evidence: &[&[u8]]) -> Result<(), ClientError> {
        self.writes.push(store::alarm_write(alarm, evidence)?);
        self.held.insert(alarm);
        Ok(())
    }

    /// Clears a held rollback alarm (ADR 0021 §9 "Server behind", as `rv`'s `Device::adopt`):
    /// called only when a verified account answer is adopted, so the drain that carries the
    /// clear also carries that answer's `account-state`, which the floors require. Whether one
    /// was held.
    pub(crate) fn resolve_rollback(&mut self) -> bool {
        let held = self.held.remove(&Alarm::Rollback);
        if held {
            self.writes.push(Write::ClearAlarm(Alarm::Rollback));
        }
        held
    }

    /// Whether any alarm is held.
    pub(crate) fn is_raised(&self) -> bool {
        !self.held.is_empty()
    }

    /// The alarm that refuses a sync, as `rv`'s `Device::online`: a fork and an outdated
    /// device state end the online life of this cache. A rollback does not (the next account
    /// answer may resolve it), nor does an unconfirmed identity change (the answer is checked
    /// again).
    pub(crate) fn sync_refusal(&self) -> Option<Alarm> {
        self.held
            .iter()
            .copied()
            .find(|a| matches!(a, Alarm::Fork | Alarm::DeviceStateOutdated))
    }

    /// The alarm that refuses removal of this device (ADR 0095 §D): every alarm but 4.
    pub(crate) fn removal_refusal(&self) -> Option<Alarm> {
        self.held
            .iter()
            .copied()
            .find(|a| *a != Alarm::DeviceStateOutdated)
    }

    /// The codes of the held alarms, ascending by key.
    pub(crate) fn codes(&self) -> Vec<String> {
        self.held
            .iter()
            .map(|a| error_of(*a).code().to_owned())
            .collect()
    }

    /// The writes since the last call.
    pub(crate) fn take_writes(&mut self) -> Changeset {
        core::mem::take(&mut self.writes)
    }
}

/// The alarm that refuses removal of the device whose cache holds `rows`, read without any
/// key (module docs; ADR 0095 §D): the code of alarm 1, 2 or 3, or [`ALARM_UNKNOWN`] for an
/// alarm key this build does not know; `undefined` when removal may go on (no alarm, or only
/// alarm 4). Only the `account_objects` rows are read, and nothing else of them is parsed.
#[wasm_bindgen(js_name = removalRefusal)]
#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "wasm-bindgen hands this exported call ownership of the JS array as Vec<KvRow>, never a slice"
)]
pub fn removal_refusal(rows: Vec<KvRow>) -> Option<String> {
    removal_refusal_of(&rows).map(str::to_owned)
}

/// [`removal_refusal`] over a slice: a known alarm is named before an unknown key, the lowest
/// known key first.
pub(crate) fn removal_refusal_of(rows: &[KvRow]) -> Option<&'static str> {
    let mut known: BTreeSet<Alarm> = BTreeSet::new();
    let mut unknown = false;
    for row in rows.iter().filter(|r| r.store() == "account_objects") {
        let row_key = row.key();
        let Some(key) = alarm_key_of(&row_key) else {
            continue;
        };
        match key {
            [byte] => match Alarm::from_u8(*byte) {
                Some(Alarm::DeviceStateOutdated) => {}
                Some(alarm) => {
                    known.insert(alarm);
                }
                None => unknown = true,
            },
            _ => unknown = true,
        }
    }
    match known.first() {
        Some(alarm) => Some(error_of(*alarm).code()),
        None => unknown.then_some(ALARM_UNKNOWN),
    }
}

/// The alarm key of an `account_objects` row key in [`crate::store`]'s codec (`u64` kind,
/// then the key column), or `None` for a row of another kind; as `rv`'s `Db::alarm_keys`
/// selects `kind = 7`.
fn alarm_key_of(row_key: &[u8]) -> Option<&[u8]> {
    let (prefix, rest) = row_key.split_first_chunk::<8>()?;
    (i64::from_be_bytes(*prefix) == kind::ALARM).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alarm_row(key: &[u8]) -> KvRow {
        let mut k = 7u64.to_be_bytes().to_vec();
        k.extend_from_slice(key);
        KvRow::new("account_objects", k, Vec::new())
    }

    #[test]
    fn removal_is_refused_under_alarms_1_to_3_and_allowed_under_4() {
        assert_eq!(removal_refusal_of(&[]), None);
        assert_eq!(removal_refusal_of(&[alarm_row(&[4])]), None);
        assert_eq!(removal_refusal_of(&[alarm_row(&[1])]), Some("rollback"));
        assert_eq!(removal_refusal_of(&[alarm_row(&[2])]), Some("fork"));
        assert_eq!(
            removal_refusal_of(&[alarm_row(&[4]), alarm_row(&[3])]),
            Some("identity_change_unconfirmed")
        );
    }

    #[test]
    fn an_unknown_alarm_key_refuses_removal_but_a_known_alarm_is_named_first() {
        for key in [&[5u8][..], &[0], &[], &[4, 4]] {
            assert_eq!(removal_refusal_of(&[alarm_row(key)]), Some(ALARM_UNKNOWN));
        }
        assert_eq!(
            removal_refusal_of(&[alarm_row(&[9]), alarm_row(&[2]), alarm_row(&[1])]),
            Some("rollback")
        );
    }

    #[test]
    fn rows_that_are_not_alarms_are_not_read_as_alarms() {
        let mut bundle = 1u64.to_be_bytes().to_vec();
        bundle.extend_from_slice(&[1]);
        let rows = [
            KvRow::new("account_objects", bundle, vec![1]),
            KvRow::new("account_objects", vec![0, 0, 7], Vec::new()),
            KvRow::new("ops", alarm_row(&[1]).key(), Vec::new()),
        ];
        assert_eq!(removal_refusal_of(&rows), None);
    }

    #[test]
    fn the_held_set_names_the_refusals_as_rv_does() {
        let mut alarms = Alarms::default();
        assert!(!alarms.is_raised());
        assert_eq!(alarms.sync_refusal(), None);
        alarms.raise(Alarm::DeviceStateOutdated, &[]).unwrap();
        assert_eq!(alarms.sync_refusal(), Some(Alarm::DeviceStateOutdated));
        assert_eq!(alarms.removal_refusal(), None);
        alarms.raise(Alarm::Rollback, &[b"a", b"b"]).unwrap();
        assert_eq!(alarms.removal_refusal(), Some(Alarm::Rollback));
        assert_eq!(
            alarms.codes(),
            vec!["rollback".to_owned(), "device_state_outdated".to_owned()]
        );
        assert_eq!(alarms.take_writes().writes().len(), 2);
        assert!(alarms.resolve_rollback());
        assert!(!alarms.resolve_rollback());
        let writes = alarms.take_writes();
        assert!(matches!(
            writes.writes(),
            [Write::ClearAlarm(Alarm::Rollback)]
        ));
        assert!(alarms.is_raised(), "alarm 4 is never cleared");
    }

    #[test]
    fn a_vault_key_refusal_names_its_alarm() {
        assert_eq!(of_vault_key_error("fork"), Some(Alarm::Fork));
        assert_eq!(of_vault_key_error("rollback"), Some(Alarm::Rollback));
        assert_eq!(of_vault_key_error("invalid_server_response"), None);
    }
}
