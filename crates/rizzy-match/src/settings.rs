// SPDX-License-Identifier: AGPL-3.0-only

//! The account's matching settings: tag `0x0001` of the `ACCOUNT_SETTINGS` plaintext
//! ([ADR 0042] §3): the account-level match default ([ADR 0037] §6), the global equivalence
//! groups the account disabled, and its own user-defined groups ([ADR 0038] §5).
//!
//! **Layout** (ADR 0042 §3; every integer big-endian, `str` is `u32(len) ‖ UTF-8`, CRYPTO.md §2):
//!
//! ```text
//! matching_settings
//!   u16 match_default             ADR 0037 §4 enum, 0x0001..=0x0006 only
//!   u16 d ‖ d × group_id (16 B)   disabled global ids, sorted, no duplicates, d ≤ 1,024
//!   u16 u ‖ u × user_group        sorted by group_id, no duplicate group_id, u ≤ 64
//! user_group                      ADR 0038 §1 "group", minus the signature (ADR 0038 §5)
//!   16  group_id                  random, client-assigned at creation, stable
//!   u16 m ‖ m × str(domain)       2 ≤ m ≤ 64, A-label, sorted, no duplicates
//!   u8  flag_third_party_hostable always 0x00 for a user group
//! ```
//!
//! A `user_group` is read and written by [`EquivalenceGroup`]'s own codec, the one the signed
//! global list uses (ADR 0042 §3: "no second codec for the same shape"); this module adds only
//! the two structural checks ADR 0042 §4 puts on top of it for a *user* group: every domain is
//! its own registrable domain under the compiled-in Public Suffix List ([`crate::suffix`]), so a
//! bare public suffix (`co.uk`, `github.io`) or a subdomain is refused, and
//! `flag_third_party_hostable` is `0x00` (that flag records a *reviewed* exception, ADR 0038 §4
//! point 3, which no user group has).
//!
//! The decoder is strict, like every decoder of the format family: one accepted encoding per
//! value, so `encode(decode(x)) == x` for every `x` that decodes (ADR 0018 §12's property,
//! applied here by ADR 0042 §8). Every count is checked against its bound before anything is
//! allocated for it, so hostile bytes cannot make the parser reserve unbounded memory.
//!
//! **Not secret, but private.** The user's own groups name sites the user has logins on, so
//! [`MatchingSettings`]'s `Debug` shows counts only, never a domain or a group id.
//!
//! [ADR 0037]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0037-url-matching-and-autofill-rules.md
//! [ADR 0038]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0038-equivalent-domain-list.md
//! [ADR 0042]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0042-account-settings-matching-layout.md

use core::fmt;
use std::collections::BTreeSet;

use rizzy_core::encoding::{Reader, put_u16};
use rizzy_core::error::EncodeError;

use crate::equivalence::{EquivalenceGroup, EquivalenceView, GroupId};
use crate::error::{
    MAX_DISABLED_GROUPS, MAX_GROUP_DOMAINS, MAX_USER_GROUPS, MatchingSettingsError,
};
use crate::modes::MatchMode;
use crate::normalize::normalize_domain;
use crate::suffix::registrable_domain;

/// The matching section of the account settings (module docs). Build one with
/// [`MatchingSettings::default`] (the ADR 0037 §6 default: *Base domain*, nothing disabled, no
/// user groups) and the editing methods, or with [`MatchingSettings::decode`].
///
/// Every value of this type satisfies ADR 0042 §3–§4: the match default is `0x0001..=0x0006`,
/// at most [`MAX_DISABLED_GROUPS`] disabled ids and [`MAX_USER_GROUPS`] user groups, each user
/// group passed [`user_group`]'s checks, no two user groups share an id.
#[derive(Clone, PartialEq, Eq)]
pub struct MatchingSettings {
    /// The mode a URI with `uri/<id>/match = 0x0000` falls back to (ADR 0037 §6). Never
    /// [`MatchMode::AccountDefault`].
    match_default: MatchMode,
    /// The global group ids the account disabled (ADR 0037 §6, ADR 0038 §5).
    disabled_global: BTreeSet<GroupId>,
    /// The account's own groups, sorted by id, no duplicate id.
    user_groups: Vec<EquivalenceGroup>,
}

impl Default for MatchingSettings {
    /// The settings of an account that never wrote any (ADR 0042 §3 "Absent tag"): *Base
    /// domain*, no disabled groups, no user groups.
    fn default() -> Self {
        Self {
            match_default: MatchMode::BaseDomain,
            disabled_global: BTreeSet::new(),
            user_groups: Vec::new(),
        }
    }
}

impl fmt::Debug for MatchingSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatchingSettings")
            .field("match_default", &self.match_default)
            .field("disabled_global", &self.disabled_global.len())
            .field("user_groups", &self.user_groups.len())
            .finish()
    }
}

/// Builds a user-defined group from typed domains (ADR 0042 §4), with the checks a user group
/// needs on top of [`EquivalenceGroup::new`]:
///
/// 1. every domain goes through [`normalize_domain`] first, the path the global list's own
///    tooling uses, so a user group and a page's registrable domain compute identically;
/// 2. every normalised domain must equal its own registrable domain under the compiled-in
///    Public Suffix List: a bare public suffix (`co.uk`, `github.io`) and a subdomain
///    (`www.example.com`) are refused;
/// 3. `flag_third_party_hostable` is always `false`.
///
/// # Errors
/// [`MatchingSettingsError::InvalidDomain`] if a domain does not normalise;
/// [`MatchingSettingsError::NotRegistrableDomain`] for rule 2;
/// [`MatchingSettingsError::InvalidGroup`] for fewer than two or more than
/// [`MAX_GROUP_DOMAINS`] domains, or two that normalise to the same value.
pub fn user_group(
    id: GroupId,
    domains: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<EquivalenceGroup, MatchingSettingsError> {
    let mut normalized = Vec::new();
    for domain in domains {
        if normalized.len() >= usize::from(MAX_GROUP_DOMAINS) {
            return Err(MatchingSettingsError::InvalidGroup);
        }
        let domain =
            normalize_domain(domain.as_ref()).map_err(|_| MatchingSettingsError::InvalidDomain)?;
        if !is_own_registrable_domain(&domain) {
            return Err(MatchingSettingsError::NotRegistrableDomain);
        }
        normalized.push(domain);
    }
    EquivalenceGroup::new(id, normalized, false).map_err(|_| MatchingSettingsError::InvalidGroup)
}

/// Whether `domain` (already normalised) is its own registrable domain (module docs).
fn is_own_registrable_domain(domain: &str) -> bool {
    registrable_domain(domain).as_deref() == Some(domain)
}

/// Whether `group` may be stored as a user group (ADR 0042 §4): rule 2 and 3 of [`user_group`].
/// [`EquivalenceGroup::new`] and [`EquivalenceGroup::decode`] already guarantee the rest.
fn is_valid_user_group(group: &EquivalenceGroup) -> bool {
    !group.third_party_hostable()
        && group
            .domains()
            .iter()
            .all(|domain| is_own_registrable_domain(domain))
}

impl MatchingSettings {
    /// The account-level match default (ADR 0037 §6); never [`MatchMode::AccountDefault`].
    #[must_use]
    pub const fn match_default(&self) -> MatchMode {
        self.match_default
    }

    /// The disabled global group ids.
    #[must_use]
    pub const fn disabled_global(&self) -> &BTreeSet<GroupId> {
        &self.disabled_global
    }

    /// The user-defined groups, sorted by id.
    #[must_use]
    pub fn user_groups(&self) -> &[EquivalenceGroup] {
        &self.user_groups
    }

    /// The merged view a match decision uses (ADR 0038 §5; ADR 0037 §7): `global` minus the
    /// disabled ids, plus the user groups (ADR 0042 §3: "`EquivalenceView::new(global,
    /// &disabled_set, &user_groups)` straight from the parsed tag").
    #[must_use]
    pub fn view<'a>(&'a self, global: &'a [EquivalenceGroup]) -> EquivalenceView<'a> {
        EquivalenceView::new(global, &self.disabled_global, &self.user_groups)
    }

    /// Sets the account-level match default.
    ///
    /// # Errors
    /// [`MatchingSettingsError::InvalidMatchDefault`] for [`MatchMode::AccountDefault`]
    /// (`0x0000` cannot be its own fallback; ADR 0042 §3).
    pub fn set_match_default(&mut self, mode: MatchMode) -> Result<(), MatchingSettingsError> {
        if mode == MatchMode::AccountDefault {
            return Err(MatchingSettingsError::InvalidMatchDefault);
        }
        self.match_default = mode;
        Ok(())
    }

    /// Disables the global group `id`. Disabling an id already disabled changes nothing.
    ///
    /// # Errors
    /// [`MatchingSettingsError::TooManyDisabledGroups`] past [`MAX_DISABLED_GROUPS`].
    pub fn disable_global(&mut self, id: GroupId) -> Result<(), MatchingSettingsError> {
        if !self.disabled_global.contains(&id)
            && self.disabled_global.len() >= usize::from(MAX_DISABLED_GROUPS)
        {
            return Err(MatchingSettingsError::TooManyDisabledGroups);
        }
        self.disabled_global.insert(id);
        Ok(())
    }

    /// Enables the global group `id` again. Returns whether it was disabled.
    pub fn enable_global(&mut self, id: GroupId) -> bool {
        self.disabled_global.remove(&id)
    }

    /// Adds a user group built by [`user_group`].
    ///
    /// # Errors
    /// [`MatchingSettingsError::NotRegistrableDomain`] for a group that breaks rule 2 or 3 of
    /// [`user_group`] (one built some other way); [`MatchingSettingsError::DuplicateGroup`]
    /// if a user group with its id exists; [`MatchingSettingsError::TooManyUserGroups`] past
    /// [`MAX_USER_GROUPS`].
    pub fn add_user_group(&mut self, group: EquivalenceGroup) -> Result<(), MatchingSettingsError> {
        if !is_valid_user_group(&group) {
            return Err(MatchingSettingsError::NotRegistrableDomain);
        }
        let Err(at) = self
            .user_groups
            .binary_search_by_key(&group.id(), EquivalenceGroup::id)
        else {
            return Err(MatchingSettingsError::DuplicateGroup);
        };
        if self.user_groups.len() >= usize::from(MAX_USER_GROUPS) {
            return Err(MatchingSettingsError::TooManyUserGroups);
        }
        self.user_groups.insert(at, group);
        Ok(())
    }

    /// Removes the user group `id`. Returns whether there was one.
    pub fn remove_user_group(&mut self, id: GroupId) -> bool {
        let before = self.user_groups.len();
        self.user_groups.retain(|g| g.id() != id);
        self.user_groups.len() != before
    }

    /// Encodes the section (module docs).
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if a count does not fit its `u16` (unreachable: every count is
    /// bounded far below it by construction) or a domain exceeds `u32::MAX` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        put_u16(&mut out, self.match_default.to_wire());
        put_u16(&mut out, count(self.disabled_global.len())?);
        for id in &self.disabled_global {
            out.extend_from_slice(id.as_bytes());
        }
        put_u16(&mut out, count(self.user_groups.len())?);
        for group in &self.user_groups {
            group.encode(&mut out)?;
        }
        Ok(out)
    }

    /// Decodes the section, strictly (module docs; ADR 0042 §2 "Rejected outright", §3).
    ///
    /// # Errors
    /// [`MatchingSettingsError::Malformed`] for anything but exactly one canonical encoding:
    /// truncated or trailing bytes, a match default outside `0x0001..=0x0006`, a count above
    /// its bound, ids out of order or repeated, or a user group that breaks any rule of
    /// [`user_group`] or [`EquivalenceGroup`]'s codec (a one-domain group, a public suffix,
    /// `flag = 1`, a domain not in canonical form).
    pub fn decode(bytes: &[u8]) -> Result<Self, MatchingSettingsError> {
        let malformed = |_| MatchingSettingsError::Malformed;
        let mut r = Reader::new(bytes);
        let match_default = match MatchMode::from_wire(r.u16().map_err(malformed)?) {
            Some(MatchMode::AccountDefault) | None => {
                return Err(MatchingSettingsError::Malformed);
            }
            Some(mode) => mode,
        };
        let d = r.u16().map_err(malformed)?;
        if d > MAX_DISABLED_GROUPS {
            return Err(MatchingSettingsError::Malformed);
        }
        let mut disabled_global = BTreeSet::new();
        let mut previous: Option<GroupId> = None;
        for _ in 0..d {
            let id = GroupId::from_bytes(*r.array::<16>().map_err(malformed)?);
            if previous.is_some_and(|p| id <= p) {
                return Err(MatchingSettingsError::Malformed);
            }
            previous = Some(id);
            disabled_global.insert(id);
        }
        let u = r.u16().map_err(malformed)?;
        if u > MAX_USER_GROUPS {
            return Err(MatchingSettingsError::Malformed);
        }
        let mut user_groups: Vec<EquivalenceGroup> = Vec::with_capacity(usize::from(u));
        for _ in 0..u {
            let group =
                EquivalenceGroup::decode(&mut r).map_err(|_| MatchingSettingsError::Malformed)?;
            if !is_valid_user_group(&group)
                || user_groups.last().is_some_and(|p| group.id() <= p.id())
            {
                return Err(MatchingSettingsError::Malformed);
            }
            user_groups.push(group);
        }
        r.finish().map_err(malformed)?;
        Ok(Self {
            match_default,
            disabled_global,
            user_groups,
        })
    }
}

/// A count as its `u16` prefix.
fn count(len: usize) -> Result<u16, EncodeError> {
    u16::try_from(len).map_err(|_| EncodeError::TooLong)
}

#[cfg(test)]
mod tests;
