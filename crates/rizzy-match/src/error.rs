// SPDX-License-Identifier: AGPL-3.0-only

//! Error types for URL normalisation and the equivalence list (ADR 0037, ADR 0038).
//!
//! None of these carry secrets: a URL and an equivalence list are both public data (ADR 0037
//! §1, §3). `Debug` and `Display` are safe to log.

use core::fmt;

/// `rizzy-match` never parses a URL longer than this before even calling the `url` crate
/// (ADR 0037 §2: untrusted input is size-limited, CLAUDE.md "Code rules"). 4096 bytes is well
/// above every browser's practical URL length and the longest path a login page's own form
/// `action` is likely to use, while bounding the cost of IDNA and percent-decoding on a
/// maliciously long string.
pub const MAX_URL_LEN: usize = 4096;

/// The longest a single DNS label or a full host may be after normalisation (RFC 1035 §3.1:
/// 253 octets total, 63 per label). `rizzy-match` checks the whole-host bound itself; the `url`
/// and `idna` crates already enforce the per-label bound during IDNA processing.
pub const MAX_HOST_LEN: usize = 253;

/// Why a URL did not normalise (ADR 0037 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NormalizeError {
    /// The raw input exceeded [`MAX_URL_LEN`], checked before parsing.
    TooLong,
    /// The `url` crate rejected the input: not an absolute URL, or a malformed component.
    Parse,
    /// The scheme is not `http` or `https` (ADR 0037 §2 point 2; INV-42): never matched, never
    /// filled, so normalisation refuses it rather than returning a value no mode can ever use.
    UnsupportedScheme,
    /// The host, after IDNA processing, exceeds [`MAX_HOST_LEN`].
    HostTooLong,
    /// A `http(s)` URL with no host. The `url` crate rejects this during parsing for the
    /// special schemes, so this variant exists for completeness rather than reachability.
    NoHost,
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("url exceeds the maximum length"),
            Self::Parse => f.write_str("url did not parse"),
            Self::UnsupportedScheme => f.write_str("scheme is not http or https"),
            Self::HostTooLong => f.write_str("host exceeds the maximum length"),
            Self::NoHost => f.write_str("url has no host"),
        }
    }
}

impl core::error::Error for NormalizeError {}

/// Why a bare domain string (an equivalence-group entry, not a full URL) did not normalise
/// (ADR 0038 §1: group domains are "each in normalized A-label form (ADR 0037 §2)").
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainError {
    /// Exceeds [`MAX_HOST_LEN`].
    TooLong,
    /// `idna`'s domain-to-ASCII algorithm rejected it (invalid code points, a bidi violation, a
    /// label that does not round-trip through punycode).
    Invalid,
    /// Empty after normalisation.
    Empty,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("domain exceeds the maximum length"),
            Self::Invalid => f.write_str("domain is not valid under IDNA"),
            Self::Empty => f.write_str("domain is empty"),
        }
    }
}

impl core::error::Error for DomainError {}

/// The equivalence list's own size bounds (ADR 0038 §1), checked before allocation so a
/// corrupted or hostile blob cannot make the parser reserve unbounded memory.
pub const MAX_LIST_LEN: usize = 1 << 20;
/// The most groups a list may carry.
pub const MAX_GROUPS: u16 = 4096;
/// The most domains a single group may carry.
pub const MAX_GROUP_DOMAINS: u16 = 64;

/// Why a signed equivalence list was rejected (ADR 0038 §1–§2; INV-39).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EquivalenceListError {
    /// Exceeds [`MAX_LIST_LEN`], checked before any field is read.
    TooLong,
    /// The canonical layout is truncated, has trailing bytes, or a field is out of its allowed
    /// range (too many groups, too many domains in a group, an empty group, a duplicate
    /// `group_id`, domains not sorted bytewise, a domain that is not a valid A-label, or
    /// duplicate domains within a group).
    Malformed,
    /// `format_version` is not `1`.
    UnsupportedVersion,
    /// The trailing bytes are not exactly a 64-byte signature.
    BadSignatureLength,
    /// The signature did not verify against the given public key ([`rizzy_core::error::VerifyError`]
    /// via [`rizzy_core::sign::verify_detached`]).
    BadSignature,
    /// `list_version` is not strictly greater than the caller's highest accepted version
    /// (INV-39: "reject a list with an equal or lower version").
    NotNewer,
}

impl fmt::Display for EquivalenceListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("equivalence list exceeds the maximum length"),
            Self::Malformed => f.write_str("equivalence list is malformed"),
            Self::UnsupportedVersion => f.write_str("equivalence list format_version is not 1"),
            Self::BadSignatureLength => f.write_str("equivalence list signature is not 64 bytes"),
            Self::BadSignature => f.write_str("equivalence list signature did not verify"),
            Self::NotNewer => {
                f.write_str("equivalence list is not newer than the accepted version")
            }
        }
    }
}

impl core::error::Error for EquivalenceListError {}

/// The most user-defined groups an account's matching settings may hold (ADR 0042 §3–§4,
/// `MAX_USER_GROUPS`; owner answer 2 at acceptance).
pub const MAX_USER_GROUPS: u16 = 64;
/// The most global group ids an account may disable (ADR 0042 §3–§4, `MAX_DISABLED_GROUPS`;
/// owner answer 2 at acceptance). Independent of the list's own [`MAX_GROUPS`] on purpose:
/// "disable every global group" must not consume the whole settings entry (ADR 0042 §3).
pub const MAX_DISABLED_GROUPS: u16 = 1024;

/// Why the account's matching settings (ADR 0042 §3) did not decode, or an edit of them was
/// refused (ADR 0042 §4). None of these carry a domain or a group id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MatchingSettingsError {
    /// The encoded section is not exactly one canonical encoding (truncated or trailing bytes,
    /// a value out of range, a count above its bound, ids out of order or repeated, a user group
    /// that breaks a rule). The whole record is rejected (ADR 0042 §2).
    Malformed,
    /// A typed domain does not normalise (ADR 0037 §2).
    InvalidDomain,
    /// A typed domain is not its own registrable domain: a bare public suffix (`co.uk`,
    /// `github.io`) or a subdomain (`www.example.com`) (ADR 0042 §4). Or a group built
    /// elsewhere carries `flag_third_party_hostable = 1`.
    NotRegistrableDomain,
    /// Fewer than two domains, more than [`MAX_GROUP_DOMAINS`], or two that normalise to the
    /// same value.
    InvalidGroup,
    /// A user group with the same `group_id` already exists.
    DuplicateGroup,
    /// More than [`MAX_USER_GROUPS`] user groups.
    TooManyUserGroups,
    /// More than [`MAX_DISABLED_GROUPS`] disabled global groups.
    TooManyDisabledGroups,
    /// `0x0000` (account default) given as the account default itself.
    InvalidMatchDefault,
}

impl fmt::Display for MatchingSettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "matching settings are malformed",
            Self::InvalidDomain => "domain does not normalise",
            Self::NotRegistrableDomain => "domain is not a registrable domain",
            Self::InvalidGroup => "a group needs 2 to 64 distinct domains",
            Self::DuplicateGroup => "a user group with this id exists",
            Self::TooManyUserGroups => "too many user groups",
            Self::TooManyDisabledGroups => "too many disabled groups",
            Self::InvalidMatchDefault => "the account default cannot be account default",
        })
    }
}

impl core::error::Error for MatchingSettingsError {}
