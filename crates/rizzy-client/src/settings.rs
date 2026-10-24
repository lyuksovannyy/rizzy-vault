// SPDX-License-Identifier: AGPL-3.0-only

//! The `ACCOUNT_SETTINGS` plaintext ([ADR 0042]): its outer versioned, tagged record (§2),
//! reading it (§6) and changing it by whole-record replace under the existing `account-state`
//! compare-and-swap (§5). The matching section inside it (tag `0x0001`, §3–§4) is
//! `rizzy-match`'s [`MatchingSettings`] (ADR 0042 §1: "Matching payload: `rizzy-match`").
//!
//! # Layout (ADR 0042 §2)
//!
//! ```text
//! account_settings_plaintext
//!   u16 format_version = 1
//!   u16 n ‖ n × entry            n ≤ 256 (MAX_SETTINGS_ENTRIES), sorted by tag, no duplicate tag
//! entry
//!   u16 tag
//!   bytes(value)                 u32(len) ‖ value; len ≤ MAX_SETTINGS_ENTRY_LEN (1 MiB)
//! ```
//!
//! - **Tags.** `0x0000` is invalid; `0x0001` is the matching section; `0x0004` is the identity
//!   generator's defaults ([`crate::identity_gen::IdentityDefaults`], ADR 0079 Open question 7;
//!   `0x0002` and `0x0003` are reserved by the Proposed ADR 0081); every other tag up to
//!   `0xFFFE` is unassigned; `0xFFFF` is reserved and never assigned, so no valid record holds it and it is
//!   rejected like `0x0000`.
//! - **Absent object or absent tag.** While `settings_seq = 0` there is no envelope, and a record
//!   without tag `0x0001` has the default matching settings (ADR 0037 §6: *Base domain*, nothing
//!   disabled, no user groups).
//! - **Unknown tags** are kept verbatim and written back unchanged on the next whole-record write;
//!   they never fail parsing (ADR 0042 §2 "Forward compatibility").
//! - **Rejected outright**, with the severity of a failed decryption
//!   ([`ClientError::InvalidServerResponse`]): wrong or truncated lengths, trailing bytes, tags out
//!   of order or repeated, tag `0x0000`/`0xFFFF`, an entry over the bounds, or any violation
//!   inside the matching section. `format_version ≠ 1` is parked instead:
//!   [`ClientError::SettingsUpdateRequired`]. Either way no settings write is built until it is
//!   resolved (ADR 0042 §2: "a reject blocks further settings writes"), and the matching calls of
//!   this crate answer the same error rather than guess at settings they cannot read: falling back
//!   to the defaults could re-enable a global group the account disabled, or widen an account
//!   default narrower than *Base domain* (INV-38).
//!
//! # Writing (ADR 0042 §5)
//!
//! [`change_settings`] decrypts and parses the current record (or starts from the absent one at
//! `settings_seq = 0`), applies one [`SettingsEdit`] to the matching section, re-encodes the
//! **whole** record with every unknown tag carried forward, seals it under the current account key
//! at `settings_seq + 1` (`AccountSettingsCtx` unchanged), and signs a new `account-state` at
//! `state_seq + 1` with `settings_hash = SHA-256(new envelope)`. The host sends
//! [`PendingSettingsChange::commit_request`] to `account/commit`; on 204 it calls
//! [`PendingSettingsChange::finalize`]. On `state_conflict` it re-fetches the account and calls
//! [`PendingSettingsChange::on_state_conflict`]: the existing `CasRetry` decides (CRYPTO.md
//! §10.2) — `Rollback` and `Fork` stop the change; `Reapply` (only `state_seq` and
//! `device_set_hash` moved) rebuilds on the new state; `Restart` (anything else moved, a newer
//! `settings_seq` included) redoes the same edit on the winner's full record. Rollback protection is
//! the existing `matches_settings`/INV-25 check; nothing new.
//!
//! The server accepts a settings-only commit over a durable device's session or a fresh OPAQUE
//! session (CRYPTO.md §11 "Replacing credentials"; `rizzy-domain-auth`'s `commit_change`).
//!
//! [ADR 0042]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0042-account-settings-matching-layout.md

use core::fmt;

use rizzy_core::encoding::{Reader, put_bytes, put_u16};
use rizzy_core::envelope::purpose::AccountSettingsCtx;
use rizzy_core::envelope::{open, seal};
use rizzy_core::keys::settings_hash;
use rizzy_core::rng::CryptoRng;
use rizzy_core::sign::{AccountState, CasRetry};
use rizzy_match::error::MatchingSettingsError;
use rizzy_match::{EquivalenceGroup, GroupId, MatchMode, MatchingSettings, user_group};
use rizzy_proto::change::CommitChangeRequest;
use rizzy_proto::objects::AccountSettings;
use rizzy_proto::wire::List;
use zeroize::Zeroizing;

use crate::account::{AccountPin, VerifiedAccount};
use crate::device::UnlockedDevice;
use crate::error::{ClientError, internal};
use crate::identity_gen::{IdentityDefaults, TAG_IDENTITY_DEFAULTS};
use crate::wire::bytes;

/// The only `format_version` this build reads and writes (ADR 0042 §2).
pub const FORMAT_VERSION: u16 = 1;
/// The most entries a record may hold (ADR 0042 §2, §4; owner answer 2 at acceptance).
pub const MAX_SETTINGS_ENTRIES: u16 = 256;
/// The longest one entry's value may be (ADR 0042 §4): 1 MiB.
pub const MAX_SETTINGS_ENTRY_LEN: usize = 1_048_576;
/// The tag of the matching section (ADR 0042 §2 "Tag registry", §3).
pub const TAG_MATCHING: u16 = 0x0001;
/// Tag `0x0000`: invalid (ADR 0042 §2).
const TAG_INVALID: u16 = 0x0000;
/// Tag `0xFFFF`: reserved, never assigned (ADR 0042 §2).
const TAG_RESERVED: u16 = 0xFFFF;

/// A decoded `ACCOUNT_SETTINGS` plaintext (module docs).
///
/// Decrypted account data: `Debug` shows counts only, and the bytes of unknown entries are wiped
/// on drop.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct AccountSettingsRecord {
    /// The matching section; the default when the tag is absent.
    matching: MatchingSettings,
    /// Whether tag `0x0001` is present (so a record that holds the default section explicitly
    /// re-encodes to the same bytes as it decoded from).
    matching_present: bool,
    /// The identity generator's defaults, tag `0x0004` (ADR 0079 Open question 7); absent until
    /// first set.
    identity_defaults: Option<IdentityDefaults>,
    /// Every unrecognised entry, sorted by tag, value verbatim.
    unknown: Vec<(u16, Zeroizing<Vec<u8>>)>,
}

impl fmt::Debug for AccountSettingsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountSettingsRecord")
            .field("matching", &self.matching)
            .field("matching_present", &self.matching_present)
            .field("identity_defaults", &self.identity_defaults.is_some())
            .field("unknown_entries", &self.unknown.len())
            .finish()
    }
}

impl AccountSettingsRecord {
    /// The matching section (the default when the record has no tag `0x0001`).
    #[must_use]
    pub const fn matching(&self) -> &MatchingSettings {
        &self.matching
    }

    /// The identity generator's defaults (tag `0x0004`), if set (ADR 0079 Open question 7).
    #[must_use]
    pub const fn identity_defaults(&self) -> Option<&IdentityDefaults> {
        self.identity_defaults.as_ref()
    }

    /// The tags of the entries this build does not know, in order.
    pub fn unknown_tags(&self) -> impl Iterator<Item = u16> + '_ {
        self.unknown.iter().map(|(tag, _)| *tag)
    }

    /// Decodes a plaintext (module docs).
    ///
    /// # Errors
    /// [`ClientError::SettingsUpdateRequired`] for a `format_version` other than 1;
    /// [`ClientError::InvalidServerResponse`] for every other violation.
    pub fn decode(plaintext: &[u8]) -> Result<Self, ClientError> {
        let bad = |_| ClientError::InvalidServerResponse;
        let mut r = Reader::new(plaintext);
        if r.u16().map_err(bad)? != FORMAT_VERSION {
            return Err(ClientError::SettingsUpdateRequired);
        }
        let n = r.u16().map_err(bad)?;
        if n > MAX_SETTINGS_ENTRIES {
            return Err(ClientError::InvalidServerResponse);
        }
        let mut record = Self::default();
        let mut previous: Option<u16> = None;
        for _ in 0..n {
            let tag = r.u16().map_err(bad)?;
            let value = r.bytes_max(MAX_SETTINGS_ENTRY_LEN).map_err(bad)?;
            if tag == TAG_INVALID || tag == TAG_RESERVED || previous.is_some_and(|p| tag <= p) {
                return Err(ClientError::InvalidServerResponse);
            }
            previous = Some(tag);
            if tag == TAG_MATCHING {
                record.matching = MatchingSettings::decode(value)
                    .map_err(|_| ClientError::InvalidServerResponse)?;
                record.matching_present = true;
            } else if tag == TAG_IDENTITY_DEFAULTS {
                record.identity_defaults = Some(
                    IdentityDefaults::decode(value).ok_or(ClientError::InvalidServerResponse)?,
                );
            } else {
                record.unknown.push((tag, Zeroizing::new(value.to_vec())));
            }
        }
        r.finish().map_err(bad)?;
        Ok(record)
    }

    /// Encodes the whole record: the matching section if present, and every unknown entry
    /// verbatim, sorted by tag.
    ///
    /// # Errors
    /// [`ClientError::SettingsLimitReached`] if an entry would exceed
    /// [`MAX_SETTINGS_ENTRY_LEN`] or the record [`MAX_SETTINGS_ENTRIES`].
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        let matching = if self.matching_present {
            Some(Zeroizing::new(self.matching.encode().map_err(internal)?))
        } else {
            None
        };
        let mut entries: Vec<(u16, &[u8])> = self
            .unknown
            .iter()
            .map(|(tag, value)| (*tag, value.as_slice()))
            .collect();
        if let Some(m) = &matching {
            entries.push((TAG_MATCHING, m.as_slice()));
        }
        let identity = match &self.identity_defaults {
            Some(d) => Some(Zeroizing::new(d.encode().map_err(internal)?)),
            None => None,
        };
        if let Some(i) = &identity {
            entries.push((TAG_IDENTITY_DEFAULTS, i.as_slice()));
        }
        entries.sort_by_key(|(tag, _)| *tag);
        let n = u16::try_from(entries.len()).map_err(|_| ClientError::SettingsLimitReached)?;
        if n > MAX_SETTINGS_ENTRIES {
            return Err(ClientError::SettingsLimitReached);
        }
        let mut out = Zeroizing::new(Vec::new());
        put_u16(&mut out, FORMAT_VERSION);
        put_u16(&mut out, n);
        for (tag, value) in entries {
            if value.len() > MAX_SETTINGS_ENTRY_LEN {
                return Err(ClientError::SettingsLimitReached);
            }
            put_u16(&mut out, tag);
            put_bytes(&mut out, value).map_err(|_| ClientError::SettingsLimitReached)?;
        }
        Ok(out)
    }

    /// Applies one resolved edit: to the matching section, or the identity defaults.
    fn apply(&mut self, edit: &Edit) -> Result<(), ClientError> {
        if let Edit::IdentityDefaults(d) = edit {
            self.identity_defaults = Some(d.clone());
            return Ok(());
        }
        let m = &mut self.matching;
        match edit {
            Edit::Default(mode) => m.set_match_default(*mode).map_err(edit_error)?,
            Edit::Add(group) => m.add_user_group(group.clone()).map_err(edit_error)?,
            Edit::Remove(id) => {
                if !m.remove_user_group(*id) {
                    return Err(ClientError::InvalidInput);
                }
            }
            Edit::Disable(id) => {
                if m.disabled_global().contains(id) {
                    return Err(ClientError::InvalidInput);
                }
                m.disable_global(*id).map_err(edit_error)?;
            }
            Edit::Enable(id) => {
                if !m.enable_global(*id) {
                    return Err(ClientError::InvalidInput);
                }
            }
            Edit::IdentityDefaults(_) => return Ok(()),
        }
        self.matching_present = true;
        Ok(())
    }
}

/// The client error of a refused matching-settings edit (no domain or id in it).
const fn edit_error(e: MatchingSettingsError) -> ClientError {
    match e {
        MatchingSettingsError::NotRegistrableDomain => ClientError::EquivalenceDomainRejected,
        MatchingSettingsError::TooManyUserGroups | MatchingSettingsError::TooManyDisabledGroups => {
            ClientError::SettingsLimitReached
        }
        _ => ClientError::InvalidInput,
    }
}

/// Reads the account's settings from a verified account (ADR 0042 §6): the absent record while
/// `settings_seq = 0`, otherwise the envelope the signed state's `settings_hash` matched,
/// opened under the account key and decoded.
///
/// # Errors
/// [`ClientError::InvalidInput`] for another account's `unlocked`;
/// [`ClientError::AccountKeyRotated`] if `unlocked` holds an older account key than the state
/// names; [`ClientError::InvalidServerResponse`] if the envelope is missing or does not open, or
/// the record is rejected; [`ClientError::SettingsUpdateRequired`].
pub fn account_settings(
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
) -> Result<AccountSettingsRecord, ClientError> {
    if unlocked.account_id != account.account_id {
        return Err(ClientError::InvalidInput);
    }
    let state = &account.pin.state;
    if state.settings_seq == 0 {
        return Ok(AccountSettingsRecord::default());
    }
    if !state.matches_account_key(&unlocked.account_key) {
        return Err(ClientError::AccountKeyRotated);
    }
    let held = account
        .pin
        .settings
        .as_ref()
        .filter(|s| s.settings_seq == state.settings_seq)
        .ok_or(ClientError::InvalidServerResponse)?;
    let plaintext = open(
        unlocked.account_key.key(),
        &AccountSettingsCtx {
            account_id: account.account_id,
            settings_seq: state.settings_seq,
        },
        held.envelope.as_slice(),
    )
    .map_err(|_| ClientError::InvalidServerResponse)?;
    AccountSettingsRecord::decode(plaintext.expose_secret())
}

/// The parsed settings of the last state read, so a host decrypts and parses them once per
/// `ACCOUNT_SETTINGS` object, not once per match decision (ADR 0042 §6: "decrypts and parses
/// per §2 once"). Keyed on the state's `settings_seq` and `settings_hash`, so any newer verified
/// state with other settings is read again.
#[derive(Default)]
pub struct SettingsCache {
    /// `(settings_seq, settings_hash, result)` of the last read.
    held: Option<(u64, [u8; 32], Result<AccountSettingsRecord, ClientError>)>,
}

impl fmt::Debug for SettingsCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SettingsCache")
            .field("settings_seq", &self.held.as_ref().map(|(seq, _, _)| *seq))
            .finish_non_exhaustive()
    }
}

impl SettingsCache {
    /// The settings of `account`, read through [`account_settings`] unless the last read was of
    /// the same object.
    ///
    /// # Errors
    /// As [`account_settings`]; a failed read is kept too, so it is not retried for the same
    /// object.
    pub fn get(
        &mut self,
        account: &VerifiedAccount,
        unlocked: &UnlockedDevice,
    ) -> Result<&AccountSettingsRecord, ClientError> {
        let state = &account.pin.state;
        let key = (state.settings_seq, state.settings_hash);
        let fresh = !matches!(&self.held, Some((seq, hash, _)) if (*seq, *hash) == key);
        if fresh {
            let read = account_settings(account, unlocked);
            // An `AccountKeyRotated` answer depends on `unlocked`, not on the object: not kept.
            if read == Err(ClientError::AccountKeyRotated) {
                return Err(ClientError::AccountKeyRotated);
            }
            self.held = Some((key.0, key.1, read));
        }
        match &self.held {
            Some((_, _, Ok(record))) => Ok(record),
            Some((_, _, Err(e))) => Err(*e),
            None => Err(ClientError::Internal),
        }
    }

    /// Forgets the held read (after this client committed new settings, say).
    pub fn clear(&mut self) {
        self.held = None;
    }
}

/// One change to the account's matching settings (ADR 0037 §6–§7; ADR 0042 §3–§5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsEdit {
    /// Sets the account-level match default (`0x0001`–`0x0006`).
    SetMatchDefault(MatchMode),
    /// Adds a user-defined group of these typed domains, under a new random `group_id`.
    AddUserGroup(Vec<String>),
    /// Removes the user-defined group with this id.
    RemoveUserGroup(GroupId),
    /// Disables the global group with this id.
    DisableGlobalGroup(GroupId),
    /// Enables the global group with this id again.
    EnableGlobalGroup(GroupId),
    /// Sets the identity generator's defaults, tag `0x0004` (ADR 0079 Open question 7).
    SetIdentityDefaults(IdentityDefaults),
}

/// A [`SettingsEdit`] with its random parts drawn, so a restart redoes exactly the same edit.
#[derive(Clone, PartialEq, Eq)]
enum Edit {
    /// Set the match default.
    Default(MatchMode),
    /// Add this user group.
    Add(EquivalenceGroup),
    /// Remove the user group.
    Remove(GroupId),
    /// Disable the global group.
    Disable(GroupId),
    /// Enable the global group.
    Enable(GroupId),
    /// Set the identity generator's defaults.
    IdentityDefaults(IdentityDefaults),
}

impl fmt::Debug for Edit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The kind only: a group's domains are the user's private data.
        f.write_str(match self {
            Self::Default(_) => "Edit::Default",
            Self::Add(_) => "Edit::Add",
            Self::Remove(_) => "Edit::Remove",
            Self::Disable(_) => "Edit::Disable",
            Self::Enable(_) => "Edit::Enable",
            Self::IdentityDefaults(_) => "Edit::IdentityDefaults",
        })
    }
}

impl Edit {
    /// Resolves `edit`, drawing a new group's id from `rng` and checking its domains
    /// (ADR 0042 §4).
    fn resolve<R: CryptoRng + ?Sized>(
        rng: &mut R,
        edit: SettingsEdit,
    ) -> Result<Self, ClientError> {
        Ok(match edit {
            SettingsEdit::SetMatchDefault(mode) => Self::Default(mode),
            SettingsEdit::AddUserGroup(domains) => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                Self::Add(user_group(GroupId::from_bytes(id), domains).map_err(edit_error)?)
            }
            SettingsEdit::RemoveUserGroup(id) => Self::Remove(id),
            SettingsEdit::DisableGlobalGroup(id) => Self::Disable(id),
            SettingsEdit::EnableGlobalGroup(id) => Self::Enable(id),
            SettingsEdit::SetIdentityDefaults(d) => Self::IdentityDefaults(d),
        })
    }
}

/// A settings change waiting for its `account/commit` (module docs, "Writing"). `Debug` shows
/// the sequence numbers only.
pub struct PendingSettingsChange {
    /// The edit, resolved.
    edit: Edit,
    /// The state the change was built on.
    base: AccountState,
    /// The commit.
    request: CommitChangeRequest,
    /// The pin after the commit.
    pin: AccountPin,
    /// The record the commit carries.
    record: AccountSettingsRecord,
}

impl fmt::Debug for PendingSettingsChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSettingsChange")
            .field("state_seq", &self.pin.state.state_seq)
            .field("settings_seq", &self.pin.state.settings_seq)
            .finish_non_exhaustive()
    }
}

/// Builds a settings change (module docs, "Writing"): reads the current record of `account`,
/// applies `edit`, and builds the commit.
///
/// # Errors
/// As [`account_settings`] (a rejected or parked record blocks every write);
/// [`ClientError::InvalidInput`] for an edit that changes nothing (removing a group that is not
/// there, disabling a disabled group, enabling an enabled one), a typed domain that does not
/// normalise, or a group of fewer than 2 or more than 64 domains;
/// [`ClientError::EquivalenceDomainRejected`] for a public suffix or a subdomain;
/// [`ClientError::SettingsLimitReached`]; [`ClientError::Internal`].
pub fn change_settings<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
    edit: SettingsEdit,
) -> Result<PendingSettingsChange, ClientError> {
    let edit = Edit::resolve(rng, edit)?;
    build(rng, account, unlocked, edit)
}

/// Reads, applies and seals (module docs).
fn build<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
    edit: Edit,
) -> Result<PendingSettingsChange, ClientError> {
    let mut record = account_settings(account, unlocked)?;
    record.apply(&edit)?;
    let plaintext = record.encode()?;
    let (request, pin) = seal_commit(rng, account, unlocked, &plaintext)?;
    Ok(PendingSettingsChange {
        edit,
        base: account.pin.state.clone(),
        request,
        pin,
        record,
    })
}

/// Seals `plaintext` as the next `ACCOUNT_SETTINGS` of `account` and signs the state that
/// commits to it (module docs, "Writing"): the commit and the pin after it.
pub(crate) fn seal_commit<R: CryptoRng + ?Sized>(
    rng: &mut R,
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
    plaintext: &[u8],
) -> Result<(CommitChangeRequest, AccountPin), ClientError> {
    let base = &account.pin.state;
    if unlocked.account_id != account.account_id {
        return Err(ClientError::InvalidInput);
    }
    if !base.matches_account_key(&unlocked.account_key) {
        return Err(ClientError::AccountKeyRotated);
    }
    let settings_seq = base
        .settings_seq
        .checked_add(1)
        .ok_or(ClientError::Internal)?;
    let envelope = seal(
        rng,
        unlocked.account_key.key(),
        &AccountSettingsCtx {
            account_id: account.account_id,
            settings_seq,
        },
        plaintext,
    )
    .map_err(internal)?;
    let mut next = base.clone();
    next.state_seq = base.state_seq.checked_add(1).ok_or(ClientError::Internal)?;
    next.settings_seq = settings_seq;
    next.settings_hash =
        settings_hash(settings_seq, Some(&envelope)).ok_or(ClientError::Internal)?;
    let state_wire = next
        .sign(account.identity.signing_key())
        .map_err(internal)?;
    let settings = AccountSettings {
        settings_seq,
        envelope: bytes(envelope)?,
    };
    let request = CommitChangeRequest {
        account_state: bytes(state_wire.clone())?,
        registration_upload: None,
        setup_id: None,
        account_key_server_wrap: None,
        recovery: None,
        account_settings: Some(settings.clone()),
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        bundle: None,
        identity_secret_keys: None,
        retired_secret_keys: List::empty(),
        device_grants: List::empty(),
        recovery_rewrap: None,
        vault_rotation: None,
        vault_create: None,
        vault_delete: None,
    };
    let pin = AccountPin {
        bundle: account.pin.bundle.clone(),
        state: next,
        state_wire,
        settings: Some(settings),
    };
    Ok((request, pin))
}

impl PendingSettingsChange {
    /// The `account/commit` request.
    #[must_use]
    pub const fn commit_request(&self) -> &CommitChangeRequest {
        &self.request
    }

    /// The record this change writes.
    #[must_use]
    pub const fn record(&self) -> &AccountSettingsRecord {
        &self.record
    }

    /// After the server acknowledged the commit: `account` takes the new state and settings as
    /// its pin, so the next match decision and the next refresh use them.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if `account` moved since the change was built (another
    /// state is pinned now): the host refreshes instead.
    pub fn finalize(self, account: &mut VerifiedAccount) -> Result<(), ClientError> {
        if account.pin.state != self.base {
            return Err(ClientError::InvalidInput);
        }
        account.settings.clone_from(&self.pin.settings);
        account.pin = self.pin;
        Ok(())
    }

    /// After `state_conflict` and a re-fetch whose verified result is `current` (module docs,
    /// "Writing"): the change rebuilt on the current state, with the same edit.
    ///
    /// # Errors
    /// [`ClientError::Rollback`] or [`ClientError::Fork`] as `CasRetry` decides; as
    /// [`change_settings`] for the rebuilt change (the edit may no longer apply to the winner's
    /// record, for example a group another device removed: [`ClientError::InvalidInput`]).
    pub fn on_state_conflict<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        current: &VerifiedAccount,
        unlocked: &UnlockedDevice,
    ) -> Result<Self, ClientError> {
        match self.base.cas_retry(&current.pin.state) {
            CasRetry::Rollback => Err(ClientError::Rollback),
            CasRetry::Fork => Err(ClientError::Fork),
            CasRetry::Reapply | CasRetry::Restart => build(rng, current, unlocked, self.edit),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index the fixtures they built and the bytes they mutate"
)]
mod tests;
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "vector tests index hex they parse and the JSON file they read"
)]
mod vectors;
