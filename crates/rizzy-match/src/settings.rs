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
//! point 3, which no user group has). The codec itself already enforces ADR 0044's member rules
//! for every group, global or user (no IP literal; each member its own registrable domain), so
//! the first check adds, for a user group, only the refusal of a dotless name
//! ([`crate::equivalence::is_valid_member`] accepts one as its own registrable domain; the PSL
//! does not).
//!
//! **Structural rules and content rules** (ADR 0097 §4.2, which replaces ADR 0042 §4 in part).
//! [`MatchingSettings::decode`] rejects the section only for a *structural* fault, none of which
//! consults compiled-in data: truncated or trailing bytes, a match default outside
//! `0x0001..=0x0006`, `d > 1,024` or `u > 64`, ids out of order, `m` outside `2..=64`, a
//! domain that is not UTF-8, empty or over 253 bytes, domains of a group not strictly ascending
//! bytewise, a flag byte other than `0x00`/`0x01`. The *content* rules a writer checks (canonical
//! form, no IP literal, each domain its own registrable domain under this build's PSL, a dot in
//! every domain — Option B of ADR 0097 §5 — and flag `0x00`) never reject the record: a stored
//! group that fails one is *inert* ([`InertGroup`]). It is kept as its exact wire bytes, counts
//! towards `u`, is written back byte for byte, is left out of the [`EquivalenceView`], and is
//! listed with its reasons by [`MatchingSettings::inert_groups`]. Inertness is recomputed on
//! every read, so a later PSL snapshot can make the group active again with no write. A PSL
//! update therefore never makes the section unreadable.
//!
//! The decoder is strict, like every decoder of the format family: one accepted encoding per
//! value, so `encode(decode(x)) == x` for every `x` that decodes, inert groups included (ADR
//! 0018 §12's property, applied here by ADR 0042 §8). Every count is checked against its bound before anything is
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

use rizzy_core::encoding::{Reader, put_str, put_u8, put_u16};
use rizzy_core::error::EncodeError;

use crate::equivalence::{
    EquivalenceGroup, EquivalenceView, GroupId, MemberRuleViolation, is_valid_member,
    member_rule_violation,
};
use crate::error::{
    MAX_DISABLED_GROUPS, MAX_GROUP_DOMAINS, MAX_HOST_LEN, MAX_USER_GROUPS, MatchingSettingsError,
};
use crate::modes::MatchMode;
use crate::normalize::normalize_domain;

/// The matching section of the account settings (module docs). Build one with
/// [`MatchingSettings::default`] (the ADR 0037 §6 default: *Base domain*, nothing disabled, no
/// user groups) and the editing methods, or with [`MatchingSettings::decode`].
///
/// Every value of this type satisfies ADR 0042 §3–§4: the match default is `0x0001..=0x0006`,
/// at most [`MAX_DISABLED_GROUPS`] disabled ids and [`MAX_USER_GROUPS`] user groups, each user
/// group passed [`user_group`]'s checks or is [`InertGroup`], no two user groups share an id.
#[derive(Clone, PartialEq, Eq)]
pub struct MatchingSettings {
    /// The mode a URI with `uri/<id>/match = 0x0000` falls back to (ADR 0037 §6). Never
    /// [`MatchMode::AccountDefault`].
    match_default: MatchMode,
    /// The global group ids the account disabled (ADR 0037 §6, ADR 0038 §5).
    disabled_global: BTreeSet<GroupId>,
    /// The account's own active groups, sorted by id, no duplicate id.
    user_groups: Vec<EquivalenceGroup>,
    /// The account's stored groups that fail a content rule (ADR 0097 §4.2), sorted by id. No
    /// id appears in both lists.
    inert_groups: Vec<InertGroup>,
}

/// Which content rule a stored user group fails (ADR 0097 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InertReasonKind {
    /// A domain is not in canonical form (`normalize_domain(d) != d`).
    NotCanonical,
    /// A domain is an IP literal.
    IpLiteral,
    /// A domain is not its own registrable domain under this build's PSL (a public suffix or a
    /// subdomain). The UI reads: "`<domain>` is not a registrable domain for this version of
    /// rizzy-vault".
    NotRegistrable,
    /// A domain has no dot (ADR 0097 §5, Option B).
    Dotless,
    /// The group's `flag_third_party_hostable` is `0x01`.
    ThirdPartyFlag,
}

/// One reason a stored user group is inert: the rule, and the failing domain (`None` for
/// [`InertReasonKind::ThirdPartyFlag`]). `Debug` shows the kind only, never the domain.
#[derive(Clone, PartialEq, Eq)]
pub struct InertReason {
    kind: InertReasonKind,
    domain: Option<String>,
}

impl InertReason {
    /// The content rule that failed.
    #[must_use]
    pub const fn kind(&self) -> InertReasonKind {
        self.kind
    }

    /// The failing domain, exactly as stored; `None` for the group's flag.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

impl fmt::Debug for InertReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InertReason")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// A stored user group that passed the structural rules but fails a content rule (ADR 0097
/// §4.2). It never widens a match; it is written back byte for byte; the user can only delete
/// it ([`MatchingSettings::remove_user_group`]). `Debug` shows counts only.
#[derive(Clone, PartialEq, Eq)]
pub struct InertGroup {
    id: GroupId,
    /// The domains exactly as stored, strictly ascending bytewise.
    domains: Vec<String>,
    /// The flag byte as stored, `0x00` or `0x01`.
    flag: u8,
    reasons: Vec<InertReason>,
}

impl InertGroup {
    /// The group's id.
    #[must_use]
    pub const fn id(&self) -> GroupId {
        self.id
    }

    /// The domains exactly as stored.
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Every content rule it fails: one per failing domain, plus the flag.
    #[must_use]
    pub fn reasons(&self) -> &[InertReason] {
        &self.reasons
    }

    /// Writes the stored bytes back: `group_id ‖ u16 m ‖ m × str ‖ flag`. The structural
    /// codec has one encoding per value, so this is byte for byte what was read.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.extend_from_slice(self.id.as_bytes());
        put_u16(out, count(self.domains.len())?);
        for domain in &self.domains {
            put_str(out, domain)?;
        }
        put_u8(out, self.flag);
        Ok(())
    }
}

impl fmt::Debug for InertGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InertGroup")
            .field("domains", &self.domains.len())
            .field("reasons", &self.reasons)
            .finish_non_exhaustive()
    }
}

/// The content rules of ADR 0097 §4.2 for one structurally valid stored group: the first rule
/// each domain fails, then the flag. Empty when the group may be active.
fn content_violations(domains: &[String], flag: u8) -> Vec<InertReason> {
    let mut out = Vec::new();
    for domain in domains {
        let kind = if normalize_domain(domain).as_deref() != Ok(domain.as_str()) {
            Some(InertReasonKind::NotCanonical)
        } else if member_rule_violation(domain) == Some(MemberRuleViolation::NotADomain) {
            Some(InertReasonKind::IpLiteral)
        } else if !domain.contains('.') {
            Some(InertReasonKind::Dotless)
        } else if !is_own_registrable_domain(domain) {
            Some(InertReasonKind::NotRegistrable)
        } else {
            None
        };
        if let Some(kind) = kind {
            out.push(InertReason {
                kind,
                domain: Some(domain.clone()),
            });
        }
    }
    if flag != 0 {
        out.push(InertReason {
            kind: InertReasonKind::ThirdPartyFlag,
            domain: None,
        });
    }
    out
}

/// Reads one stored user group under the structural rules only (ADR 0097 §4.2): id, `m` in
/// `2..=64`, each domain UTF-8, non-empty, at most [`MAX_HOST_LEN`] bytes and strictly above
/// the previous one bytewise, and a flag of `0x00` or `0x01`. Consults no compiled-in data.
fn decode_stored_group(
    r: &mut Reader<'_>,
) -> Result<(GroupId, Vec<String>, u8), MatchingSettingsError> {
    let malformed = |_| MatchingSettingsError::Malformed;
    let id = GroupId::from_bytes(*r.array::<16>().map_err(malformed)?);
    let m = r.u16().map_err(malformed)?;
    if !(2..=MAX_GROUP_DOMAINS).contains(&m) {
        return Err(MatchingSettingsError::Malformed);
    }
    let mut domains: Vec<String> = Vec::with_capacity(usize::from(m));
    for _ in 0..m {
        let domain = r.str().map_err(malformed)?;
        if domain.is_empty()
            || domain.len() > MAX_HOST_LEN
            || domains
                .last()
                .is_some_and(|previous| domain.as_bytes() <= previous.as_bytes())
        {
            return Err(MatchingSettingsError::Malformed);
        }
        domains.push(domain.to_owned());
    }
    let flag = r.u8().map_err(malformed)?;
    if flag > 1 {
        return Err(MatchingSettingsError::Malformed);
    }
    Ok((id, domains, flag))
}

impl Default for MatchingSettings {
    /// The settings of an account that never wrote any (ADR 0042 §3 "Absent tag"): *Base
    /// domain*, no disabled groups, no user groups.
    fn default() -> Self {
        Self {
            match_default: MatchMode::BaseDomain,
            disabled_global: BTreeSet::new(),
            user_groups: Vec::new(),
            inert_groups: Vec::new(),
        }
    }
}

impl fmt::Debug for MatchingSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatchingSettings")
            .field("match_default", &self.match_default)
            .field("disabled_global", &self.disabled_global.len())
            .field("user_groups", &self.user_groups.len())
            .field("inert_groups", &self.inert_groups.len())
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
///    (`www.example.com`) are refused, and so is a dotless single-label name such as `nas`
///    (ADR 0097 §5, Option B: refused in user groups, still accepted in the signed global list);
/// 3. `flag_third_party_hostable` is always `false`.
///
/// These are write-time checks. A *stored* group that breaks one is never a reject when read:
/// it is an [`InertGroup`] (ADR 0097 §4.2).
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

/// Whether `domain` (already normalised) is its own registrable domain under the compiled-in
/// PSL (module docs; ADR 0042 §4).
///
/// The member rules every group obeys live in one place, [`is_valid_member`] (ADR 0044: no IP
/// literal; the domain equals its own registrable domain, with a dotless name counting as its own),
/// which [`EquivalenceGroup::new`] and [`EquivalenceGroup::decode`] enforce for every caller.
/// This check is only what ADR 0042 §4 asks of a *user* group on top of that: the domain must be
/// its own *PSL* registrable domain, which a dotless name never is (under the PSL's default `*`
/// rule a single label is itself a suffix, `com` or an unlisted `nas` alike), so a user group
/// also refuses one. The check runs here, before [`EquivalenceGroup::new`], only so the caller
/// gets [`MatchingSettingsError::NotRegistrableDomain`] rather than the generic
/// [`MatchingSettingsError::InvalidGroup`].
fn is_own_registrable_domain(domain: &str) -> bool {
    is_valid_member(domain) && domain.contains('.')
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

    /// The stored user groups that are inert under this build (ADR 0097 §4.2), sorted by id,
    /// each with its reasons. Never part of [`Self::view`].
    #[must_use]
    pub fn inert_groups(&self) -> &[InertGroup] {
        &self.inert_groups
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
        if self.inert_groups.iter().any(|inert| inert.id == group.id()) {
            return Err(MatchingSettingsError::DuplicateGroup);
        }
        // Inert groups count towards `u` (ADR 0097 §4.2).
        if self.user_groups.len() + self.inert_groups.len() >= usize::from(MAX_USER_GROUPS) {
            return Err(MatchingSettingsError::TooManyUserGroups);
        }
        self.user_groups.insert(at, group);
        Ok(())
    }

    /// Removes the user group `id`, active or inert (ADR 0097 §4.2: Delete is the one edit
    /// offered for an inert group). Returns whether there was one.
    pub fn remove_user_group(&mut self, id: GroupId) -> bool {
        let before = self.user_groups.len() + self.inert_groups.len();
        self.user_groups.retain(|g| g.id() != id);
        self.inert_groups.retain(|g| g.id != id);
        self.user_groups.len() + self.inert_groups.len() != before
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
        put_u16(
            &mut out,
            count(self.user_groups.len() + self.inert_groups.len())?,
        );
        // Active and inert groups together, in one ascending `group_id` order.
        let mut active = self.user_groups.iter().peekable();
        let mut inert = self.inert_groups.iter().peekable();
        loop {
            let take_active = match (active.peek(), inert.peek()) {
                (Some(a), Some(i)) => a.id() < i.id,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            if take_active {
                if let Some(group) = active.next() {
                    group.encode(&mut out)?;
                }
            } else if let Some(group) = inert.next() {
                group.encode(&mut out)?;
            }
        }
        Ok(out)
    }

    /// Decodes the section, strictly (module docs; ADR 0042 §2 "Rejected outright", §3).
    ///
    /// # Errors
    /// [`MatchingSettingsError::Malformed`] for a structural fault only (module docs; ADR 0097
    /// §4.2): truncated or trailing bytes, a match default outside `0x0001..=0x0006`, a count
    /// above its bound, ids out of order or repeated, `m` outside `2..=64`, a domain that is not
    /// UTF-8, empty or over 253 bytes, domains not strictly ascending, a flag above `0x01`. A
    /// group that only fails a content rule (a public suffix, a subdomain, a dotless name, an
    /// IP literal, a non-canonical domain, `flag = 1`) is kept as an [`InertGroup`].
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
        let mut inert_groups: Vec<InertGroup> = Vec::new();
        let mut previous: Option<GroupId> = None;
        for _ in 0..u {
            let (id, domains, flag) = decode_stored_group(&mut r)?;
            if previous.is_some_and(|p| id <= p) {
                return Err(MatchingSettingsError::Malformed);
            }
            previous = Some(id);
            let mut reasons = content_violations(&domains, flag);
            if reasons.is_empty() {
                // Every content rule holds, so the shared codec's constructor accepts it with
                // the same canonical, sorted domains: re-encoding gives the stored bytes.
                match EquivalenceGroup::new(id, &domains, false) {
                    Ok(group) if is_valid_user_group(&group) => {
                        user_groups.push(group);
                        continue;
                    }
                    _ => reasons.push(InertReason {
                        kind: InertReasonKind::NotRegistrable,
                        domain: None,
                    }),
                }
            }
            inert_groups.push(InertGroup {
                id,
                domains,
                flag,
                reasons,
            });
        }
        r.finish().map_err(malformed)?;
        Ok(Self {
            match_default,
            disabled_global,
            user_groups,
            inert_groups,
        })
    }
}

/// A count as its `u16` prefix.
fn count(len: usize) -> Result<u16, EncodeError> {
    u16::try_from(len).map_err(|_| EncodeError::TooLong)
}

#[cfg(test)]
mod tests;
