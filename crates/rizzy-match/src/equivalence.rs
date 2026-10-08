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
//!       ‖ u16 m ‖ m × str(domain)          2 ≤ m, A-label, sorted bytewise, no duplicates
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
    /// [`EquivalenceListError::Malformed`] if a domain does not normalise, there are fewer than
    /// two domains or more than [`MAX_GROUP_DOMAINS`], or two domains normalise to the same
    /// value.
    pub fn new(
        id: GroupId,
        domains: impl IntoIterator<Item = impl AsRef<str>>,
        third_party_hostable: bool,
    ) -> Result<Self, EquivalenceListError> {
        let mut normalized: Vec<String> = domains
            .into_iter()
            .map(|d| normalize_domain(d.as_ref()).map_err(|_| EquivalenceListError::Malformed))
            .collect::<Result<_, _>>()?;
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
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), rizzy_core::error::EncodeError> {
        out.extend_from_slice(self.id.as_bytes());
        rizzy_core::encoding::put_u16(out, u16::try_from(self.domains.len()).unwrap_or(0));
        for domain in &self.domains {
            rizzy_core::encoding::put_str(out, domain)?;
        }
        rizzy_core::encoding::put_u8(out, u8::from(self.third_party_hostable));
        Ok(())
    }

    /// Decodes one `group` record; `r` must be positioned at its first byte.
    fn decode(r: &mut Reader<'_>) -> Result<Self, EquivalenceListError> {
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
    /// [`EquivalenceListError::NotNewer`] if `list_version` is not strictly greater than
    /// `highest_accepted_version` (INV-39: "reject a list with an equal or lower version").
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
        if list.list_version <= highest_accepted_version {
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

        // The same version is not newer than itself (INV-39): rejected.
        assert_eq!(
            EquivalenceList::verify(&wire, &public_key, 1).unwrap_err(),
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

    proptest::proptest! {
        #[test]
        fn verify_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let key = [0x11u8; 32];
            let _ = EquivalenceList::verify(&bytes, &key, 0);
        }
    }
}
