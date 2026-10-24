// SPDX-License-Identifier: AGPL-3.0-only

//! The signed global equivalence list (ADR 0038 §1–§3) and the merged equivalence view
//! (ADR 0038 §5; ADR 0037 §6–§7).
//!
//! **Wire layout** (ADR 0038 §1; CRYPTO.md §10.2 row "equivalence-list"):
//!
//! ```text
//! wire = ctx ‖ ed25519_signature (64 B)
//! ctx  = u16 format_version (= 1)
//!      ‖ u32 list_version                  strictly increasing across every published list
//!      ‖ u64 published_at_ms               informational only
//!      ‖ u16 n ‖ n × group                 sorted by group_id, no duplicate group_id
//! group = 16  group_id                     random, assigned once, never reused
//!       ‖ u16 m ‖ m × str(domain)          2 ≤ m, A-label, sorted bytewise, no duplicates;
//!                                          each its own registrable domain, never an IP
//!                                          literal (ADR 0044; [`is_valid_member`])
//!       ‖ u8  flag_third_party_hostable    0 normally; 1 only for a PSL-split suffix
//! ```
//!
//! `ctx` is exactly the bytes [`rizzy_core::sign::verify_detached`] hashes as
//! `LABEL("sig/equivalence-list") ‖ 0x00 ‖ ctx`: CRYPTO.md §10.2 says "`statement_version` is
//! the list's `format_version` (1)", so `format_version` fills the role every other statement's
//! `u16(statement_version)` fills, and the rest of `ctx` is this statement's body. The result is
//! the same signed bytes ADR 0038 §1 spells out ("`LABEL ‖ 0x00 ‖` everything above"); only the
//! bookkeeping of which two bytes are "version" and which are "body" differs between the two
//! documents, never the bytes actually signed.
//!
//! There is no [`rizzy_core::sign::SignatureContainer`] here (ADR 0038 §1 says
//! `ed25519_signature (64 B)`, not an 82-byte container): the public key is pinned in this
//! crate's source, not looked up by id, so no container framing is needed.

use std::collections::BTreeSet;

use rizzy_core::encoding::Reader;
use rizzy_core::labels;

use crate::error::{
    EquivalenceListError, MAX_GROUP_DOMAINS, MAX_GROUPS, MAX_HOST_LEN, MAX_LIST_LEN,
};
use crate::normalize::normalize_domain;
use crate::suffix;

/// `format_version` of every equivalence list this build accepts (ADR 0038 §1).
pub const FORMAT_VERSION: u16 = 1;

/// Length of the detached Ed25519 signature appended to the list bytes (ADR 0038 §1).
const SIGNATURE_LEN: usize = 64;

/// A group's random, stable identifier (ADR 0038 §1: "random, assigned once, never reused or
/// reassigned"), 16 bytes, unrelated to the domains it names so renaming or correcting a
/// domain's spelling never changes a group's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId([u8; 16]);

impl GroupId {
    /// Wraps a 16-byte identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16-byte encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Whether an already-normalised domain may be a member of an [`EquivalenceGroup`]
/// ([ADR 0044], which replaces ADR 0038 §1's `group` member clause).
///
/// 1. **No IP literal.** The `url` crate's WHATWG host parser, the same classification
///    [`crate::normalize::NormalizedUrl::parse`] relies on, must classify the string as a
///    domain. This refuses dotted IPv4 and also the dotless, octal and hex notations
///    (`2130706433`, `0x7f.1`) a dotted-quad check would miss, and it runs *before* rule 2 so
///    a dotless decimal IPv4 never reaches rule 2's dotless fallback. An IPv6 literal never gets
///    here at all: [`normalize_domain`] already denies `:`, `[` and `]`. A string the host
///    parser refuses outright (for example `foo.123`, which "ends in a number" but is no valid
///    IPv4 address) is refused too: no page URL can ever have that host, so the member could
///    never match anything, and refusing it is the "only ever refuse more" side.
/// 2. **Registrable domain, exactly.** The domain must equal its own registrable domain as
///    `NormalizedUrl::parse` computes one: [`suffix::registrable_domain`] (eTLD+1 under the
///    compiled-in PSL snapshot), or the host itself when it has no dot. A bare multi-label
///    suffix (`co.uk`) and a subdomain (`mail.example.com`) are refused; a dotless intranet
///    name (`nas`) is accepted, since the gate compares it as its own registrable domain.
///
/// [ADR 0044]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0044-equivalence-group-member-rules.md
#[must_use]
pub fn is_valid_member(domain: &str) -> bool {
    if !matches!(url::Host::parse(domain), Ok(url::Host::Domain(_))) {
        return false;
    }
    let registrable = suffix::registrable_domain(domain)
        .or_else(|| (!domain.contains('.')).then(|| domain.to_owned()));
    registrable.as_deref() == Some(domain)
}

/// One equivalence group: two or more registrable domains that are the same login, with the
/// PSL-split exception flag (ADR 0038 §1, §4 point 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivalenceGroup {
    /// The group's stable identifier.
    id: GroupId,
    /// The member domains, A-label form, sorted bytewise, no duplicates, 2..=64 entries
    /// ([`MAX_GROUP_DOMAINS`]).
    domains: Vec<String>,
    /// `true` only for a domain the PSL already splits by registrant (ADR 0037 §3; ADR 0038
    /// §1), recorded so review can see the exception was intentional.
    third_party_hostable: bool,
}

impl EquivalenceGroup {
    /// Builds a group from its id and member domains, normalising, sorting and validating them.
    ///
    /// Each domain is run through [`normalize_domain`], so callers may pass domains in mixed
    /// case or with a trailing dot; the stored form is always the canonical A-label.
    ///
    /// # Errors
    /// [`EquivalenceListError::Malformed`] if a domain does not normalise, breaks a member rule
    /// of [ADR 0044] (an IP literal, or a string that is not its own registrable domain: a bare
    /// public suffix such as `co.uk` or a subdomain such as `mail.example.com`; see
    /// [`is_valid_member`]), there are fewer than two domains or more than
    /// [`MAX_GROUP_DOMAINS`], or two domains normalise to the same value.
    ///
    /// [ADR 0044]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0044-equivalence-group-member-rules.md
    pub fn new(
        id: GroupId,
        domains: impl IntoIterator<Item = impl AsRef<str>>,
        third_party_hostable: bool,
    ) -> Result<Self, EquivalenceListError> {
        let mut normalized: Vec<String> = domains
            .into_iter()
            .map(|d| normalize_domain(d.as_ref()).map_err(|_| EquivalenceListError::Malformed))
            .collect::<Result<_, _>>()?;
        if !normalized.iter().all(|d| is_valid_member(d)) {
            return Err(EquivalenceListError::Malformed);
        }
        let supplied_len = normalized.len();
        normalized.sort();
        normalized.dedup();
        // A duplicate after normalisation is an error, not a silent drop: the doc comment above
        // promises `Malformed` for it, and a reviewer of a group's source list expects every
        // domain they listed to end up in the signed list, not fewer members than they typed.
        if normalized.len() != supplied_len {
            return Err(EquivalenceListError::Malformed);
        }
        if normalized.len() < 2 || normalized.len() > usize::from(MAX_GROUP_DOMAINS) {
            return Err(EquivalenceListError::Malformed);
        }
        Ok(Self {
            id,
            domains: normalized,
            third_party_hostable,
        })
    }

    /// The group's id.
    #[must_use]
    pub const fn id(&self) -> GroupId {
        self.id
    }

    /// The member domains, A-label form, sorted bytewise.
    #[must_use]
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    /// Whether this group is the PSL-split exception (ADR 0038 §1, §4 point 3).
    #[must_use]
    pub const fn third_party_hostable(&self) -> bool {
        self.third_party_hostable
    }

    /// Whether `domain` (an already-normalised A-label registrable domain) is a member.
    #[must_use]
    pub fn contains(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| d == domain)
    }

    /// Encodes `16 group_id ‖ u16 m ‖ m × str(domain) ‖ u8 flag` (ADR 0038 §1).
    ///
    /// # Errors
    /// [`rizzy_core::error::EncodeError::TooLong`] if a domain somehow exceeds `u32::MAX`
    /// bytes; unreachable in practice, since every domain here already passed
    /// [`EquivalenceGroup::new`] or [`EquivalenceGroup::decode`], both bounded by
    /// [`MAX_HOST_LEN`], but still propagated rather than assumed.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), rizzy_core::error::EncodeError> {
        out.extend_from_slice(self.id.as_bytes());
        rizzy_core::encoding::put_u16(out, u16::try_from(self.domains.len()).unwrap_or(0));
        for domain in &self.domains {
            rizzy_core::encoding::put_str(out, domain)?;
        }
        rizzy_core::encoding::put_u8(out, u8::from(self.third_party_hostable));
        Ok(())
    }

    /// Decodes one `group` record; `r` must be positioned at its first byte.
    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, EquivalenceListError> {
        let id = GroupId(
            *r.array::<16>()
                .map_err(|_| EquivalenceListError::Malformed)?,
        );
        let m = r.u16().map_err(|_| EquivalenceListError::Malformed)?;
        if !(2..=MAX_GROUP_DOMAINS).contains(&m) {
            return Err(EquivalenceListError::Malformed);
        }
        let mut domains = Vec::with_capacity(usize::from(m));
        let mut previous: Option<String> = None;
        for _ in 0..m {
            let domain = r.str().map_err(|_| EquivalenceListError::Malformed)?;
            if domain.len() > MAX_HOST_LEN {
                return Err(EquivalenceListError::Malformed);
            }
            // Canonical form only: a wire-encoded domain that does not already normalise to
            // itself is rejected rather than silently re-normalised, so there is exactly one
            // accepted encoding per domain (mirrors `rizzy-core`'s "decoders are strict"
            // rule).
            if normalize_domain(domain).as_deref() != Ok(domain) {
                return Err(EquivalenceListError::Malformed);
            }
            // ADR 0044: the same member rules `new` applies, so a hand-built wire group cannot
            // smuggle in a member `new` would refuse.
            if !is_valid_member(domain) {
                return Err(EquivalenceListError::Malformed);
            }
            if let Some(prev) = &previous
                && domain <= prev.as_str()
            {
                return Err(EquivalenceListError::Malformed);
            }
            previous = Some(domain.to_owned());
            domains.push(domain.to_owned());
        }
        let flag = r.u8().map_err(|_| EquivalenceListError::Malformed)?;
        let third_party_hostable = match flag {
            0 => false,
            1 => true,
            _ => return Err(EquivalenceListError::Malformed),
        };
        Ok(Self {
            id,
            domains,
            third_party_hostable,
        })
    }
}

/// A parsed, **not yet signature-checked**, equivalence list body. Build one with
/// [`EquivalenceList::new`] (for the xtask signing tool) or get one back from
/// [`EquivalenceList::verify`] (for a client, which never trusts an unverified value — this
/// type is `pub(crate)`-constructible outside `verify` only through `new`, which is for the
/// signing tool's own round trip, never shipped as "verified" to a match decision).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivalenceList {
    /// Always [`FORMAT_VERSION`] once parsed; checked, not stored redundantly in spirit, but
    /// kept so `encode` can round-trip a value built with a future format without guessing.
    format_version: u16,
    /// Strictly increasing across every published list (ADR 0038 §2; INV-39).
    list_version: u32,
    /// Informational only (ADR 0038 §1).
    published_at_ms: u64,
    /// Sorted by `group_id`, no duplicates.
    groups: Vec<EquivalenceGroup>,
}

impl EquivalenceList {
    /// Builds a list from its fields, sorting the groups by id and validating there are no
    /// duplicate ids and no more than [`crate::error::MAX_GROUPS`] of them. For the xtask
    /// signing tool: a client only ever receives a list through [`EquivalenceList::verify`].
    ///
    /// # Errors
    /// [`EquivalenceListError::Malformed`] for too many groups or a duplicate `group_id`.
    pub fn new(
        list_version: u32,
        published_at_ms: u64,
        mut groups: Vec<EquivalenceGroup>,
    ) -> Result<Self, EquivalenceListError> {
        if groups.len() > usize::from(MAX_GROUPS) {
            return Err(EquivalenceListError::Malformed);
        }
        groups.sort_by_key(EquivalenceGroup::id);
        for pair in groups.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(EquivalenceListError::Malformed);
            }
        }
        Ok(Self {
            format_version: FORMAT_VERSION,
            list_version,
            published_at_ms,
            groups,
        })
    }

    /// The list's version (ADR 0038 §2).
    #[must_use]
    pub const fn list_version(&self) -> u32 {
        self.list_version
    }

    /// When the list was published (informational only).
    #[must_use]
    pub const fn published_at_ms(&self) -> u64 {
        self.published_at_ms
    }

    /// The groups, sorted by id.
    #[must_use]
    pub fn groups(&self) -> &[EquivalenceGroup] {
        &self.groups
    }

    /// Encodes `ctx` (the bytes that are signed, and that precede the signature on the wire):
    /// `u16 format_version ‖ u32 list_version ‖ u64 published_at_ms ‖ u16 n ‖ n × group`.
    ///
    /// # Errors
    /// [`rizzy_core::error::EncodeError::TooLong`]; see `EquivalenceGroup::encode`'s doc
    /// (unreachable in practice, propagated rather than assumed).
    pub fn encode_ctx(&self) -> Result<Vec<u8>, rizzy_core::error::EncodeError> {
        let mut out = Vec::new();
        rizzy_core::encoding::put_u16(&mut out, self.format_version);
        rizzy_core::encoding::put_u32(&mut out, self.list_version);
        rizzy_core::encoding::put_u64(&mut out, self.published_at_ms);
        rizzy_core::encoding::put_u16(&mut out, u16::try_from(self.groups.len()).unwrap_or(0));
        for group in &self.groups {
            group.encode(&mut out)?;
        }
        Ok(out)
    }

    /// Appends a detached signature to [`EquivalenceList::encode_ctx`]'s output, producing the
    /// full wire form the signing tool writes to the compiled-in data file.
    ///
    /// # Errors
    /// As [`EquivalenceList::encode_ctx`].
    pub fn encode_signed(
        &self,
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<Vec<u8>, rizzy_core::error::EncodeError> {
        let mut out = self.encode_ctx()?;
        out.extend_from_slice(signature);
        Ok(out)
    }

    /// Parses and decodes `ctx` (the signed bytes, without the trailing signature). Pure,
    /// bounded, non-panicking: every length field is checked against the bytes actually
    /// present before anything is read (fuzz target `equivalence_list`).
    ///
    /// # Errors
    /// [`EquivalenceListError::UnsupportedVersion`] if `format_version` is not
    /// [`FORMAT_VERSION`]; [`EquivalenceListError::Malformed`] for any other structural
    /// violation (truncation, trailing bytes, too many groups, an unsorted or duplicate
    /// `group_id`, a malformed group).
    fn decode_ctx(ctx: &[u8]) -> Result<Self, EquivalenceListError> {
        let mut r = Reader::new(ctx);
        let format_version = r.u16().map_err(|_| EquivalenceListError::Malformed)?;
        if format_version != FORMAT_VERSION {
            return Err(EquivalenceListError::UnsupportedVersion);
        }
        let list_version = r.u32().map_err(|_| EquivalenceListError::Malformed)?;
        let published_at_ms = r.u64().map_err(|_| EquivalenceListError::Malformed)?;
        let n = r.u16().map_err(|_| EquivalenceListError::Malformed)?;
        if n > MAX_GROUPS {
            return Err(EquivalenceListError::Malformed);
        }
        let mut groups = Vec::with_capacity(usize::from(n));
        let mut previous: Option<GroupId> = None;
        for _ in 0..n {
            let group = EquivalenceGroup::decode(&mut r)?;
            if let Some(prev) = previous
                && group.id <= prev
            {
                return Err(EquivalenceListError::Malformed);
            }
            previous = Some(group.id);
            groups.push(group);
        }
        r.finish().map_err(|_| EquivalenceListError::Malformed)?;
        Ok(Self {
            format_version,
            list_version,
            published_at_ms,
            groups,
        })
    }

    /// Parses, structurally validates, signature-checks and freshness-checks a wire-form
    /// equivalence list (ADR 0038 §1–§2; INV-39).
    ///
    /// Order, deliberately: the bytes are parsed and structurally validated *before* the
    /// signature is checked (an attacker's malformed bytes are rejected without ever reaching
    /// `verify_strict`, the same order `rizzy-core`'s own statement verifiers use), and the
    /// `list_version` freshness check runs only *after* the signature verifies — an
    /// unauthenticated `list_version` is never trusted to decide anything, including whether
    /// to reject the list as stale.
    ///
    /// `highest_accepted_version` is the caller's highest `list_version` ever accepted
    /// (persisted by the caller: `rizzy-match` is a no-I/O crate and keeps no state itself,
    /// ADR 0016 R1).
    ///
    /// # Errors
    /// [`EquivalenceListError::TooLong`] if `wire` exceeds [`MAX_LIST_LEN`];
    /// [`EquivalenceListError::BadSignatureLength`] if `wire` is shorter than the 64-byte
    /// signature; the structural errors of `EquivalenceList::decode_ctx`
    /// ([`EquivalenceListError::UnsupportedVersion`], [`EquivalenceListError::Malformed`]);
    /// [`EquivalenceListError::BadSignature`] if the signature does not verify;
    /// [`EquivalenceListError::NotNewer`] if `list_version` is lower than
    /// `highest_accepted_version` (INV-39; ADR 0038 §2 as amended by ADR 0080 §6: "reject a
    /// list with a lower version"), or is the reserved value `0`, whatever the floor (ADR 0080
    /// §6: version 0 is never published, because floor 0 means "nothing accepted yet").
    ///
    /// A list whose version **equals** `highest_accepted_version` is accepted (ADR 0080 §6): it
    /// is the same list re-verified, typically the compiled-in list at the next start. Raising
    /// the persisted floor is the caller's job and happens only for a strictly newer list (ADR
    /// 0051 §3–§4), so an equal version never writes anything.
    pub fn verify(
        wire: &[u8],
        public_key: &[u8; 32],
        highest_accepted_version: u32,
    ) -> Result<Self, EquivalenceListError> {
        if wire.len() > MAX_LIST_LEN {
            return Err(EquivalenceListError::TooLong);
        }
        if wire.len() < SIGNATURE_LEN {
            return Err(EquivalenceListError::BadSignatureLength);
        }
        let (ctx, signature_bytes) = wire.split_at(wire.len() - SIGNATURE_LEN);
        let list = Self::decode_ctx(ctx)?;
        let signature: [u8; SIGNATURE_LEN] = signature_bytes
            .try_into()
            .map_err(|_| EquivalenceListError::BadSignatureLength)?;
        rizzy_core::sign::verify_detached(
            labels::SIG_EQUIVALENCE_LIST,
            ctx,
            public_key,
            &signature,
        )
        .map_err(|_| EquivalenceListError::BadSignature)?;
        if list.list_version == 0 || list.list_version < highest_accepted_version {
            return Err(EquivalenceListError::NotNewer);
        }
        Ok(list)
    }
}

/// The merged equivalence view a match decision uses (ADR 0038 §5; ADR 0037 §7): every global
/// group not disabled by the account, plus every user-defined group, with no further widening
/// between them.
///
/// Holds borrowed slices: `rizzy-match` is a no-I/O crate and never owns account settings or
/// the compiled-in list's lifetime itself (ADR 0016 R1); the caller (`rizzy-client`) owns both
/// and builds a view for the duration of one match decision.
#[derive(Clone, Copy, Debug)]
pub struct EquivalenceView<'a> {
    /// The compiled-in global list's groups, or an empty slice when no signed list is compiled
    /// in yet (see the crate root's `COMPILED_GLOBAL_LIST`): equivalence matching then runs
    /// from `user_defined` only, never from an unsigned source.
    global: &'a [EquivalenceGroup],
    /// Global group ids the account has disabled (ADR 0037 §6; ADR 0038 §5).
    disabled_global: &'a BTreeSet<GroupId>,
    /// The account's own groups (ADR 0037 §7; ADR 0038 §5): never community-reviewed, the
    /// account owner's own risk.
    user_defined: &'a [EquivalenceGroup],
}

impl<'a> EquivalenceView<'a> {
    /// Builds a view over the caller's global list, disabled-group set and user-defined
    /// groups. Borrows all three; build a fresh view per match decision if any of them change.
    #[must_use]
    pub const fn new(
        global: &'a [EquivalenceGroup],
        disabled_global: &'a BTreeSet<GroupId>,
        user_defined: &'a [EquivalenceGroup],
    ) -> Self {
        Self {
            global,
            disabled_global,
            user_defined,
        }
    }

    /// An empty view: no global list compiled in, no disabled groups, no user-defined groups.
    /// Every [`EquivalenceView::same_group`] call then returns `None`, so matching falls back
    /// to plain registrable-domain equality — never to an unsigned or absent source.
    #[must_use]
    pub fn empty() -> Self {
        static EMPTY_GROUPS: [EquivalenceGroup; 0] = [];
        static EMPTY_DISABLED: BTreeSet<GroupId> = BTreeSet::new();
        Self {
            global: &EMPTY_GROUPS,
            disabled_global: &EMPTY_DISABLED,
            user_defined: &EMPTY_GROUPS,
        }
    }

    /// The group id both `a` and `b` (already-normalised registrable domains) are members of,
    /// among the active groups, or `None` if no active group names both.
    ///
    /// A disabled global group cannot match through this view even if a user-defined group
    /// happens to name the same two domains under a different id — that is a separate,
    /// explicit user choice (ADR 0038 §5), visible as the user's own data, never a silent
    /// re-enabling of the disabled group.
    #[must_use]
    pub fn same_group(&self, a: &str, b: &str) -> Option<GroupId> {
        self.active_groups()
            .find(|group| group.contains(a) && group.contains(b))
            .map(EquivalenceGroup::id)
    }

    /// The active groups: global groups not in `disabled_global`, then every user-defined
    /// group.
    fn active_groups(&self) -> impl Iterator<Item = &EquivalenceGroup> {
        self.global
            .iter()
            .filter(|group| !self.disabled_global.contains(&group.id))
            .chain(self.user_defined.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid(byte: u8) -> GroupId {
        GroupId::from_bytes([byte; 16])
    }

    fn group(id: u8, domains: &[&str]) -> EquivalenceGroup {
        EquivalenceGroup::new(gid(id), domains.iter().copied(), false).unwrap()
    }

    #[test]
    fn group_rejects_a_dot_only_member() {
        // Regression: before `normalize_domain` stripped every trailing dot instead of just
        // one, `normalize_domain("..")` returned `Ok(".")` — a degenerate, non-registrable
        // "domain" that `new` happily stored as a group member (no round-trip check here),
        // while `decode`'s stricter round-trip check (line below this block) would reject
        // that same stored member as `Malformed` on every future load. `new` and `decode`
        // must agree: a dot-only input is never a valid member, at either entry point.
        assert_eq!(
            EquivalenceGroup::new(gid(1), ["..", "example.com"], false).unwrap_err(),
            EquivalenceListError::Malformed
        );
    }

    #[test]
    fn group_member_normalised_from_an_idna_separator_round_trips_through_encode_and_decode() {
        // Regression: `normalize_domain` used to leave the dots idna's own domain-to-ASCII
        // processing produces from U+3002/U+FF0E/U+FF61 in its output (it only trimmed ASCII
        // dots from the *input*), so `new` would normalise "a\u{3002}\u{3002}" to "a.." and
        // store that as a member — a value `decode`'s own round-trip check,
        // `normalize_domain(domain) == domain`, then rejects, because re-normalising "a.."
        // hits the ASCII-only path and returns "a" instead. `new` and `decode` must agree:
        // whatever `new` accepts and stores must also survive `decode`'s self-check, for
        // every raw spelling, not only ASCII ones.
        let built = EquivalenceGroup::new(gid(1), ["a\u{3002}\u{3002}", "example.com"], false)
            .expect("the ideographic-full-stop spelling normalises to a valid member");
        assert!(built.domains().contains(&"a".to_owned()));
        let mut out = Vec::new();
        built.encode(&mut out).unwrap();
        let mut reader = Reader::new(&out);
        let decoded = EquivalenceGroup::decode(&mut reader).expect(
            "a member `new` just normalised and stored must not be rejected by decode's own \
             round-trip check",
        );
        assert_eq!(built, decoded);
    }

    #[test]
    fn group_rejects_fewer_than_two_domains() {
        assert_eq!(
            EquivalenceGroup::new(gid(1), ["only.example"], false).unwrap_err(),
            EquivalenceListError::Malformed
        );
    }

    #[test]
    fn group_rejects_two_domains_that_normalise_to_the_same_value() {
        // "Example.com." and "example.com" normalise to the same A-label, collapsing to a
        // single member, below the two-domain minimum.
        let g = EquivalenceGroup::new(gid(1), ["Example.com.", "example.com"], false);
        assert_eq!(g.unwrap_err(), EquivalenceListError::Malformed);
    }

    #[test]
    fn group_rejects_a_collision_even_with_enough_members_left_after_dedup() {
        // Regression: three domains where exactly one pair normalises to the same value used
        // to silently dedup down to two members and return `Ok`, even though the doc comment on
        // `new` promises `Malformed` for "two domains normalise to the same value". With three
        // distinct members remaining after the collision, the old `< 2` check never caught it.
        let g = EquivalenceGroup::new(
            gid(1),
            [
                "Example.com.",
                "example.com",
                "other.example",
                "third.example",
            ],
            false,
        );
        assert_eq!(g.unwrap_err(), EquivalenceListError::Malformed);
    }

    #[test]
    fn list_round_trips_through_encode_and_decode() {
        let list = EquivalenceList::new(
            1,
            1_700_000_000_000,
            vec![
                group(1, &["youtube.com", "youtu.be", "youtube-nocookie.com"]),
                group(2, &["apple.com", "icloud.com"]),
            ],
        )
        .unwrap();
        let ctx = list.encode_ctx().unwrap();
        let decoded = EquivalenceList::decode_ctx(&ctx).unwrap();
        assert_eq!(list, decoded);
    }

    #[test]
    fn list_rejects_unsorted_or_duplicate_group_ids() {
        assert_eq!(
            EquivalenceList::new(
                1,
                0,
                vec![
                    group(5, &["a.example", "b.example"]),
                    group(5, &["c.example", "d.example"]),
                ],
            )
            .unwrap_err(),
            EquivalenceListError::Malformed
        );
    }

    /// Independent known answer (Python `cryptography` 50.0.2's `Ed25519PrivateKey`, not this
    /// code): seed `0x55` repeated 32 times, one group (`apple.com`, `icloud.com`),
    /// `list_version = 1`, `published_at_ms = 1_700_000_000_000`.
    #[test]
    fn verify_known_answer_with_a_test_key() {
        let public_key: [u8; 32] =
            *hex("c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242")
                .first_chunk()
                .unwrap();
        let wire = hex(
            "0001000000010000018bcfe568000001010101010101010101010101010101\
             01000200000009 6170706c652e636f6d 0000000a 69636c6f75642e636f6d \
             00 3c1ba71349483563cbf92065d233029763443542d04721d6e1aa226a1722\
             ad3769496a230c9493d86df64e49c9d72ad9721588bf9f1d5e5c7424dc46c78\
             f500f",
        );
        let list = EquivalenceList::verify(&wire, &public_key, 0).unwrap();
        assert_eq!(list.list_version(), 1);
        assert_eq!(list.published_at_ms(), 1_700_000_000_000);
        assert_eq!(list.groups().len(), 1);
        assert_eq!(list.groups()[0].domains(), ["apple.com", "icloud.com"]);

        // ADR 0080 §6: floor = version is the same list re-verified (accepted), floor =
        // version + 1 is a downgrade (rejected), floor = version − 1 is a newer list (accepted).
        assert_eq!(
            EquivalenceList::verify(&wire, &public_key, 1).unwrap(),
            list
        );
        assert_eq!(
            EquivalenceList::verify(&wire, &public_key, 2).unwrap_err(),
            EquivalenceListError::NotNewer
        );
        assert_eq!(
            EquivalenceList::verify(&wire, &public_key, 0).unwrap(),
            list
        );
        assert_eq!(
            EquivalenceList::verify(&wire, &public_key, u32::MAX).unwrap_err(),
            EquivalenceListError::NotNewer
        );
        // A tampered byte fails signature verification.
        let mut tampered = wire.clone();
        let last_index = tampered.len() - 1;
        tampered[last_index] ^= 0x01;
        assert_eq!(
            EquivalenceList::verify(&tampered, &public_key, 0).unwrap_err(),
            EquivalenceListError::BadSignature
        );
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => u8::MAX,
            })
            .collect();
        digits.chunks(2).map(|p| p[0] << 4 | p[1]).collect()
    }

    #[test]
    fn view_merges_global_minus_disabled_plus_user_defined() {
        let global = vec![
            group(1, &["youtube.com", "youtu.be"]),
            group(2, &["disabled-a.example", "disabled-b.example"]),
        ];
        let user = vec![group(3, &["mine-a.example", "mine-b.example"])];
        let mut disabled = BTreeSet::new();
        disabled.insert(gid(2));

        let view = EquivalenceView::new(&global, &disabled, &user);
        assert_eq!(view.same_group("youtube.com", "youtu.be"), Some(gid(1)));
        assert_eq!(
            view.same_group("disabled-a.example", "disabled-b.example"),
            None
        );
        assert_eq!(
            view.same_group("mine-a.example", "mine-b.example"),
            Some(gid(3))
        );
        assert_eq!(view.same_group("youtube.com", "mine-a.example"), None);
    }

    #[test]
    fn empty_view_never_matches() {
        let view = EquivalenceView::empty();
        assert_eq!(view.same_group("youtube.com", "youtu.be"), None);
    }

    // --- ADR 0044: member rules ---------------------------------------------------------------

    /// Hostile members every group refuses (ADR 0044 "Tests required"): IPv4 in dotted and in the
    /// dotless/octal/hex notations the WHATWG host parser also reads as IPv4, IPv6 literals, a
    /// bare public suffix (ICANN and private section) and subdomains.
    const HOSTILE_MEMBERS: &[&str] = &[
        "192.168.1.1",
        "10.0.1.1",
        "127.0.0.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "0x7f.1",
        "192.168.1.1.",
        "::1",
        "[::1]",
        "2001:db8::1",
        "[2001:db8::1]",
        "::ffff:192.168.1.1",
        "co.uk",
        "github.io",
        "mail.example.com",
        "www.example.com",
        "a.b.example.co.uk",
        "foo.github.io.example",
        "foo.123",
        "www.xn--bcher-kva.example",
        "www.bücher.example",
    ];

    #[test]
    fn group_rejects_ip_literals_suffixes_and_subdomains() {
        for bad in HOSTILE_MEMBERS {
            assert_eq!(
                EquivalenceGroup::new(gid(1), [*bad, "example.org"], false),
                Err(EquivalenceListError::Malformed),
                "{bad:?} must not be a group member"
            );
        }
    }

    #[test]
    fn dotless_decimal_ipv4_is_refused_before_the_dotless_fallback() {
        // Rule 1 must run first: rule 2's dotless fallback would otherwise accept this string
        // as its own registrable domain, exactly like `nas`.
        assert!(!"2130706433".contains('.'));
        assert!(!is_valid_member("2130706433"));
        assert!(is_valid_member("nas"));
    }

    #[test]
    fn group_accepts_registrable_domains_and_dotless_names() {
        for good in [
            "example.com",
            "example.co.uk",
            "foo.github.io",
            "xn--bcher-kva.example",
            "nas",
            "localhost",
        ] {
            let built = EquivalenceGroup::new(gid(1), [good, "example.org"], false);
            assert!(built.is_ok(), "{good:?} must be accepted");
        }
        // An IDNA U-label normalises to its A-label first, and that A-label is checked.
        let idn = EquivalenceGroup::new(gid(1), ["BÜCHER.example", "example.org"], false).unwrap();
        assert_eq!(idn.domains(), ["example.org", "xn--bcher-kva.example"]);
    }

    /// A wire group (bypassing `new`) with the given, already sorted, members.
    fn wire_group(domains: &[&str]) -> Vec<u8> {
        let mut out = vec![0x42; 16];
        rizzy_core::encoding::put_u16(&mut out, u16::try_from(domains.len()).unwrap());
        for domain in domains {
            rizzy_core::encoding::put_str(&mut out, domain).unwrap();
        }
        rizzy_core::encoding::put_u8(&mut out, 0);
        out
    }

    #[test]
    fn decode_rejects_a_hand_built_group_with_a_bad_member() {
        // Control: the same shape with valid members decodes.
        let ok = wire_group(&["example.com", "nas"]);
        assert!(EquivalenceGroup::decode(&mut Reader::new(&ok)).is_ok());
        for bad in HOSTILE_MEMBERS {
            // Only members already in canonical form can reach the new rule (the decoder
            // rejects a non-canonical spelling first); both orders keep the pair sorted.
            let mut members = [*bad, "zz.example"];
            members.sort_unstable();
            let wire = wire_group(&members);
            assert_eq!(
                EquivalenceGroup::decode(&mut Reader::new(&wire)),
                Err(EquivalenceListError::Malformed),
                "{bad:?} must not decode as a group member"
            );
        }
    }

    #[test]
    fn a_signed_list_with_a_bad_member_is_malformed_not_skipped() {
        // ADR 0044 "A PSL bump ...": reject the whole list, never skip the group. A valid group
        // next to a bad one still makes the whole ctx `Malformed`.
        let mut ctx = Vec::new();
        rizzy_core::encoding::put_u16(&mut ctx, FORMAT_VERSION);
        ctx.extend_from_slice(&1u32.to_be_bytes());
        ctx.extend_from_slice(&0u64.to_be_bytes());
        rizzy_core::encoding::put_u16(&mut ctx, 2);
        let mut good = vec![0x01; 16];
        rizzy_core::encoding::put_u16(&mut good, 2);
        rizzy_core::encoding::put_str(&mut good, "apple.com").unwrap();
        rizzy_core::encoding::put_str(&mut good, "icloud.com").unwrap();
        rizzy_core::encoding::put_u8(&mut good, 0);
        ctx.extend_from_slice(&good);
        ctx.extend_from_slice(&wire_group(&["co.uk", "example.com"]));
        assert_eq!(
            EquivalenceList::decode_ctx(&ctx).unwrap_err(),
            EquivalenceListError::Malformed
        );
    }

    /// Signs `ctx` with a test seed the way `cargo xtask equivalence-list` does.
    fn sign_test_list(list: &EquivalenceList, seed: &[u8; 32]) -> Vec<u8> {
        let mut wire = list.encode_ctx().unwrap();
        let signature =
            rizzy_core::sign::sign_detached(labels::SIG_EQUIVALENCE_LIST, &wire, seed).unwrap();
        wire.extend_from_slice(&signature);
        wire
    }

    fn test_public_key(seed: &[u8; 32]) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes()
    }

    /// ADR 0080 §6: `list_version` 0 is reserved and never published, so a correctly signed
    /// version-0 list is `NotNewer` at floor 0 (where `>=` alone would accept it) and above.
    #[test]
    fn verify_rejects_a_version_zero_list_at_every_floor() {
        let seed = [0x24; 32];
        let list =
            EquivalenceList::new(0, 0, vec![group(1, &["apple.com", "icloud.com"])]).unwrap();
        let wire = sign_test_list(&list, &seed);
        for floor in [0, 1, u32::MAX] {
            assert_eq!(
                EquivalenceList::verify(&wire, &test_public_key(&seed), floor).unwrap_err(),
                EquivalenceListError::NotNewer,
                "floor {floor}"
            );
        }
    }

    proptest::proptest! {
        /// ADR 0080 §8: a correctly signed list is accepted exactly when
        /// `list_version >= floor && list_version >= 1`, and is otherwise `NotNewer`.
        #[test]
        fn verify_accepts_exactly_versions_at_or_above_the_floor_and_never_zero(
            list_version in proptest::prop_oneof![
                proptest::strategy::Just(0u32),
                proptest::strategy::Just(1u32),
                proptest::strategy::Just(u32::MAX),
                0u32..8,
                proptest::prelude::any::<u32>(),
            ],
            floor in proptest::prop_oneof![
                proptest::strategy::Just(0u32),
                proptest::strategy::Just(u32::MAX),
                0u32..8,
                proptest::prelude::any::<u32>(),
            ],
        ) {
            let seed = [0x31; 32];
            let list = EquivalenceList::new(
                list_version,
                1_700_000_000_000,
                vec![group(1, &["apple.com", "icloud.com"])],
            )
            .unwrap();
            let wire = sign_test_list(&list, &seed);
            let result = EquivalenceList::verify(&wire, &test_public_key(&seed), floor);
            if list_version >= floor && list_version >= 1 {
                proptest::prop_assert_eq!(result, Ok(list));
            } else {
                proptest::prop_assert_eq!(result, Err(EquivalenceListError::NotNewer));
            }
        }

        #[test]
        fn verify_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let key = [0x11u8; 32];
            let _ = EquivalenceList::verify(&bytes, &key, 0);
        }

        /// Every IPv4 address, in dotted-quad, decimal, hex and dotted-octal notation, is refused.
        #[test]
        fn no_ipv4_notation_is_a_member(addr in proptest::prelude::any::<u32>()) {
            let [a, b, c, d] = addr.to_be_bytes();
            for spelling in [
                format!("{a}.{b}.{c}.{d}"),
                format!("{addr}"),
                format!("0x{addr:x}"),
                format!("0{a:o}.0{b:o}.0{c:o}.0{d:o}"),
            ] {
                proptest::prop_assert!(!is_valid_member(&spelling), "{spelling}");
                proptest::prop_assert!(
                    EquivalenceGroup::new(gid(1), [spelling.as_str(), "example.org"], false).is_err()
                );
            }
        }

        /// Every IPv6 address, bracketed or not, is refused.
        #[test]
        fn no_ipv6_literal_is_a_member(segments in proptest::prelude::any::<[u16; 8]>()) {
            let addr = core::net::Ipv6Addr::from(segments);
            for spelling in [format!("{addr}"), format!("[{addr}]")] {
                proptest::prop_assert!(
                    EquivalenceGroup::new(gid(1), [spelling.as_str(), "example.org"], false).is_err(),
                    "{spelling}"
                );
            }
        }

        /// Whatever `new` accepts is exactly the registrable domain `NormalizedUrl::parse`
        /// computes for a page at that host, and never an IP literal: the member can match a page.
        #[test]
        fn every_accepted_member_is_a_pages_own_registrable_domain(
            labels in proptest::collection::vec("[a-z0-9\\-]{1,8}", 1..4),
            tld in proptest::sample::select(vec!["com", "co.uk", "github.io", "example", "xn--p1ai", "jp", "123"]),
        ) {
            let candidate = format!("{}.{tld}", labels.join("."));
            if let Ok(group) = EquivalenceGroup::new(gid(1), [candidate.as_str(), "example.org"], false) {
                for member in group.domains() {
                    proptest::prop_assert!(member.parse::<core::net::IpAddr>().is_err());
                    let page = crate::normalize::NormalizedUrl::parse(&format!("https://{member}/"));
                    let page = page.map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{member}: {e:?}")))?;
                    proptest::prop_assert_eq!(page.registrable_domain(), Some(member.as_str()));
                }
            }
        }
    }
}
