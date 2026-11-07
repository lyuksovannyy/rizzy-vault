// SPDX-License-Identifier: AGPL-3.0-only

//! `GET /api/meta` and the `Rizzy-Client` request header (ADR 0002 point 3; [ADR 0028] item 14).
//!
//! `/api/meta` is the one unversioned endpoint. ADR 0002 point 3 lists what it returns; ADR
//! 0022 removes the second item ("the sync modes the admin allows"), so [`MetaResponse`]
//! carries:
//! - the server version and the API versions it serves;
//! - the minimum client version per platform;
//! - the URL of the running server's source code ([ADR 0106], AGPL §13): [`SourceUrl`].
//!
//! [ADR 0028] item 14 fixes the rest: the JSON field names of [`MetaResponse`], the eight
//! platform names ([`PLATFORMS`]), and the version rule of the `Rizzy-Client` check: versions
//! compare by `SemVer` 2.0.0 precedence ([`semver_precedence`]), and a version that is not `SemVer`
//! counts as below any minimum ([`client_too_old`]). The meta answer is unauthenticated and
//! public on purpose: it holds no secret and nothing about any account. A malicious server can
//! lie in it; it never selects an algorithm or parameter (ADR 0002 point 4), only whether the
//! client shows "update required".
//!
//! **The header is compatibility signalling, not a security boundary**: it is unauthenticated
//! and chosen by the client, so nothing is granted or withheld for security on its strength. A
//! client that lies only loses the early `client_too_old` answer. Clients always send it; the
//! server serves a request without it, or with a malformed one, normally until v1.0.
//!
//! [ADR 0106] adds `source_url` and fixes its grammar ([`SourceUrl::parse`]): `https://` only,
//! at most [`SourceUrl::MAX_LEN`] bytes of printable ASCII, a plain `host[:port]` authority. The
//! server always sends it; a client reads it leniently: an absent, non-string or invalid value
//! is `None` and the rest of the answer is used normally, so a bad source link never blocks a
//! login.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md

use core::cmp::Ordering;
use core::fmt;

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::limits::{ApiVersionRule, MAX_META_ENTRIES, PlatformRule, VersionRule};
use crate::wire::{List, Text, WireError};

/// A server or client version string ([`VersionRule`]).
pub type Version = Text<VersionRule>;
/// A client platform name ([`PlatformRule`]).
pub type Platform = Text<PlatformRule>;
/// An API version name such as `v1` ([`ApiVersionRule`]).
pub type ApiVersion = Text<ApiVersionRule>;

/// The API version this crate describes: every path under [`API_V1_PREFIX`].
pub const API_V1: &str = "v1";

/// The path prefix of every versioned endpoint (ADR 0002 point 3).
pub const API_V1_PREFIX: &str = "/api/v1/";

/// The one unversioned endpoint (ADR 0002 point 3).
pub const META_PATH: &str = "/api/meta";

/// The request header that identifies a client (ADR 0002 point 3).
pub const CLIENT_HEADER: &str = "Rizzy-Client";

/// The platforms a `Rizzy-Client` header may name ([ADR 0028] item 14). A header naming any
/// other platform is malformed.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const PLATFORMS: [&str; 8] = [
    "web",
    "cli",
    "extension",
    "macos",
    "windows",
    "linux",
    "ios",
    "android",
];

/// A version split by the `SemVer` 2.0.0 grammar: the three numeric identifiers of the version
/// core and the pre-release, if any. Build metadata is checked and dropped: it takes no part in
/// precedence.
struct SemVer<'a> {
    /// `major`, `minor`, `patch`: digits without a leading zero.
    core: [&'a str; 3],
    /// The pre-release identifiers, dot-separated, without the leading `-`.
    pre: Option<&'a str>,
}

/// Whether `id` is a `SemVer` numeric identifier: `0`, or digits without a leading zero.
fn is_numeric_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_digit())
        && (id.len() == 1 || !id.starts_with('0'))
}

/// Whether `id` is made of `SemVer` identifier characters, `[0-9A-Za-z-]`, and is not empty.
fn is_identifier(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Whether `id` is a `SemVer` pre-release identifier: an identifier that, when it is all digits,
/// has no leading zero.
fn is_pre_release_identifier(id: &str) -> bool {
    is_identifier(id) && (!id.bytes().all(|b| b.is_ascii_digit()) || is_numeric_identifier(id))
}

impl<'a> SemVer<'a> {
    /// Parses `text` by the `SemVer` 2.0.0 grammar; `None` when it does not match.
    fn parse(text: &'a str) -> Option<Self> {
        let (rest, build) = match text.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (text, None),
        };
        if build.is_some_and(|b| !b.split('.').all(is_identifier)) {
            return None;
        }
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        if pre.is_some_and(|p| !p.split('.').all(is_pre_release_identifier)) {
            return None;
        }
        let mut parts = core.split('.');
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        [major, minor, patch]
            .iter()
            .all(|id| is_numeric_identifier(id))
            .then_some(Self {
                core: [major, minor, patch],
                pre,
            })
    }

    /// `SemVer` 2.0.0 §11 precedence.
    fn precedence(&self, other: &Self) -> Ordering {
        for (a, b) in self.core.iter().zip(other.core.iter()) {
            let ord = cmp_numeric(a, b);
            if ord != Ordering::Equal {
                return ord;
            }
        }
        match (self.pre, other.pre) {
            (None, None) => Ordering::Equal,
            // A pre-release version has lower precedence than the normal version.
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => cmp_pre_release(a, b),
        }
    }
}

/// Compares two numeric identifiers as numbers. Neither has a leading zero, so the longer one
/// is the larger and equal lengths compare digit by digit: no integer is parsed, so none
/// overflows.
fn cmp_numeric(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compares two pre-releases identifier by identifier (`SemVer` 2.0.0 §11.4): numeric ones as
/// numbers, the others in ASCII order, a numeric one below any other, and, when every shared
/// identifier is equal, the shorter list below the longer.
fn cmp_pre_release(a: &str, b: &str) -> Ordering {
    let mut left = a.split('.');
    let mut right = b.split('.');
    loop {
        let ord = match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => match (is_numeric_identifier(x), is_numeric_identifier(y)) {
                (true, true) => cmp_numeric(x, y),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => x.cmp(y),
            },
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
}

/// Compares two version strings by `SemVer` 2.0.0 precedence ([ADR 0028] item 14): the version
/// core numerically, a pre-release below its normal version, build metadata ignored.
///
/// `None` when either is not a `SemVer` 2.0.0 version; such a version has no place in the order.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
#[must_use]
pub fn semver_precedence(a: &str, b: &str) -> Option<Ordering> {
    Some(SemVer::parse(a)?.precedence(&SemVer::parse(b)?))
}

/// Whether the server answers `client_too_old` to `client` under `minimums` ([ADR 0028] item
/// 14): the client's platform has a minimum above the client's version.
///
/// A client version that is not `SemVer` counts as below any minimum. A minimum that is not
/// `SemVer` has no place in the order either, so no version is known to reach it and the client
/// is refused (the conservative reading; a server's own list never holds one). A platform
/// without a minimum is never refused.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
#[must_use]
pub fn client_too_old(client: &ClientHeader, minimums: &[MinClientVersion]) -> bool {
    minimums
        .iter()
        .filter(|m| m.platform == client.platform)
        .any(|m| {
            semver_precedence(client.version.as_str(), m.version.as_str())
                .is_none_or(|ord| ord == Ordering::Less)
        })
}

/// The minimum client version for one platform (ADR 0002 point 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinClientVersion {
    /// The platform.
    pub platform: Platform,
    /// The lowest version the server serves on that platform.
    pub version: Version,
}

/// The body of `GET /api/meta` (ADR 0002 point 3, as ADR 0022 amends it).
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaResponse {
    /// The server's version.
    pub server_version: Version,
    /// The API versions the server serves, such as `["v1"]`.
    pub api_versions: List<ApiVersion, MAX_META_ENTRIES>,
    /// The minimum client version per platform. A platform not listed has no minimum.
    pub min_client_versions: List<MinClientVersion, MAX_META_ENTRIES>,
    /// Where users get the source of the running server and web vault ([ADR 0106] §3). The
    /// server always sends it. Read leniently: absent, not a string or not a valid
    /// [`SourceUrl`] is `None`, never an error; `None` is not serialised.
    ///
    /// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
    #[serde(
        default,
        deserialize_with = "lenient_source_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_url: Option<SourceUrl>,
}

/// Why a [`SourceUrl`] was refused: the rule of [ADR 0106] §1 it breaks. Names the rule only,
/// never the input.
///
/// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceUrlError {
    /// Rule 1: shorter than 9 or longer than [`SourceUrl::MAX_LEN`] bytes.
    Length,
    /// Rule 2: a byte outside printable ASCII `0x21`–`0x7E`.
    Character,
    /// Rule 3: it does not begin with exactly `https://`.
    Scheme,
    /// Rule 4: the authority is not `host` or `host:port`.
    Authority,
    /// Rule 5: the path, query or fragment has a character outside RFC 3986's sets, or a `%`
    /// not followed by two hex digits.
    Path,
}

impl fmt::Display for SourceUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "source URL is not 9 to 2048 bytes",
            Self::Character => "source URL has a byte outside printable ASCII",
            Self::Scheme => "source URL does not begin with https://",
            Self::Authority => "source URL authority is not host or host:port",
            Self::Path => "source URL path, query or fragment has an invalid character",
        })
    }
}

impl std::error::Error for SourceUrlError {}

/// The URL of the running server's source code ([ADR 0106] §1; AGPL §13): the
/// `RIZZY_SOURCE_URL` setting or the build's upstream source, sent as `/api/meta`'s
/// `source_url`.
///
/// Only [`SourceUrl::parse`] makes one, so every value satisfies the grammar. It is kept byte
/// for byte as given: no normalisation. It is public, not a secret.
///
/// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceUrl(String);

impl SourceUrl {
    /// The longest value, in bytes ([ADR 0106] §1 rule 1).
    ///
    /// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
    pub const MAX_LEN: usize = 2048;
    /// The shortest value: `https://` and a one-byte host.
    pub const MIN_LEN: usize = 9;
    /// The one scheme accepted, exactly as written.
    const SCHEME: &'static str = "https://";

    /// Parses a source URL by [ADR 0106] §1's rules 1 to 5, checking the length before
    /// anything else is scanned.
    ///
    /// # Errors
    /// The first rule the value breaks.
    ///
    /// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
    pub fn parse(value: &str) -> Result<Self, SourceUrlError> {
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&value.len()) {
            return Err(SourceUrlError::Length);
        }
        if !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(SourceUrlError::Character);
        }
        let rest = value
            .strip_prefix(Self::SCHEME)
            .ok_or(SourceUrlError::Scheme)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest
            .split_at_checked(end)
            .ok_or(SourceUrlError::Authority)?;
        if !is_authority(authority) {
            return Err(SourceUrlError::Authority);
        }
        if !is_path_query_fragment(tail.as_bytes()) {
            return Err(SourceUrlError::Path);
        }
        Ok(Self(value.to_owned()))
    }

    /// The URL, exactly as configured.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this URL can be the base the build's default is derived from ([ADR 0106] §2,
    /// the `repository` row): no query, no fragment, and no trailing `/`.
    ///
    /// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
    #[must_use]
    pub fn is_base(&self) -> bool {
        !self.0.contains(['?', '#']) && !self.0.ends_with('/')
    }
}

/// Rule 4: `host` or `host:port`. `host` is 1 to 253 bytes of `[A-Za-z0-9.-]`, neither
/// starting nor ending with `.` or `-`; `port` is 1 to 5 digits with a value of 1 to 65535.
/// So userinfo (`@`) and bracketed IP literals are refused.
fn is_authority(authority: &str) -> bool {
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host_ok = (1..=253).contains(&host.len())
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    let port_ok = port.is_none_or(|port| {
        (1..=5).contains(&port.len())
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u32>().is_ok_and(|n| (1..=65_535).contains(&n))
    });
    host_ok && port_ok
}

/// Rule 5: RFC 3986's unreserved and reserved characters and `%`, each `%` followed by two
/// hex digits.
fn is_path_query_fragment(tail: &[u8]) -> bool {
    let mut bytes = tail.iter();
    while let Some(&b) = bytes.next() {
        let ok = match b {
            b'%' => {
                bytes.next().is_some_and(u8::is_ascii_hexdigit)
                    && bytes.next().is_some_and(u8::is_ascii_hexdigit)
            }
            _ => b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=".contains(&b),
        };
        if !ok {
            return false;
        }
    }
    true
}

impl fmt::Display for SourceUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for SourceUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SourceUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`SourceUrl`]: strict.
        struct V;
        impl Visitor<'_> for V {
            type Value = SourceUrl;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an https:// source URL of at most 2048 bytes")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                SourceUrl::parse(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// `MetaResponse::source_url`'s lenient reader ([ADR 0106] §3): any JSON value is accepted;
/// only a string that [`SourceUrl::parse`] accepts is `Some`. Arrays and objects are skipped
/// element by element without being kept.
///
/// [ADR 0106]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0106-agpl-source-url.md
fn lenient_source_url<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SourceUrl>, D::Error> {
    /// Visitor for any JSON value.
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Option<SourceUrl>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(SourceUrl::parse(v).ok())
        }
        fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(None)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(None)
        }
    }
    deserializer.deserialize_any(V)
}

/// The value of the `Rizzy-Client: <platform>/<version>` header (ADR 0002 point 3).
///
/// [`ClientHeader::parse`] is strict and bounded: one `/`, a [`Platform`] before it and a
/// [`Version`] after it, nothing else; the whole value is at most
/// [`ClientHeader::MAX_LEN`] bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientHeader {
    /// The client platform.
    pub platform: Platform,
    /// The client version.
    pub version: Version,
}

impl ClientHeader {
    /// The longest header value: platform, `/`, version.
    pub const MAX_LEN: usize = <PlatformRule as crate::wire::TextRule>::MAX
        + 1
        + <VersionRule as crate::wire::TextRule>::MAX;

    /// Parses a header value.
    ///
    /// # Errors
    /// [`WireError::TooLong`] for a value over [`ClientHeader::MAX_LEN`] bytes (checked first),
    /// [`WireError::InvalidCharacter`] without exactly one `/`, and the [`Text`] errors of
    /// either part.
    pub fn parse(value: &str) -> Result<Self, WireError> {
        if value.len() > Self::MAX_LEN {
            return Err(WireError::TooLong { max: Self::MAX_LEN });
        }
        let (platform, version) = value.split_once('/').ok_or(WireError::InvalidCharacter)?;
        Ok(Self {
            platform: Platform::from_str(platform)?,
            version: Version::from_str(version)?,
        })
    }

    /// Whether the platform is one of [`PLATFORMS`] ([ADR 0028] item 14). A header naming
    /// another platform is malformed; [`ClientHeader::parse`] still reads it, so that the
    /// caller decides (the server serves a malformed header normally until v1.0).
    ///
    /// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
    #[must_use]
    pub fn has_known_platform(&self) -> bool {
        PLATFORMS.contains(&self.platform.as_str())
    }
}

impl fmt::Display for ClientHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.platform.as_str(), self.version.as_str())
    }
}

impl fmt::Debug for ClientHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientHeader({self})")
    }
}

#[cfg(test)]
mod tests {
    //! The meta answer's known-answer JSON and the `Rizzy-Client` header parser.

    use super::*;

    #[test]
    fn meta_known_answer_json() {
        let meta = MetaResponse {
            server_version: Version::from_str("0.1.0").unwrap(),
            api_versions: List::new(vec![ApiVersion::from_str("v1").unwrap()]).unwrap(),
            min_client_versions: List::new(vec![MinClientVersion {
                platform: Platform::from_str("cli").unwrap(),
                version: Version::from_str("0.1.0").unwrap(),
            }])
            .unwrap(),
            source_url: None,
        };
        let json = r#"{"server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[{"platform":"cli","version":"0.1.0"}]}"#;
        assert_eq!(serde_json::to_string(&meta).unwrap(), json);
        assert_eq!(serde_json::from_str::<MetaResponse>(json).unwrap(), meta);
        // A response: a newer server's extra field is ignored.
        let newer =
            r#"{"server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[],"x":true}"#;
        assert!(serde_json::from_str::<MetaResponse>(newer).is_ok());
    }

    /// ADR 0106 implementation step 1: the valid and invalid vectors of §1.
    #[test]
    fn source_url_grammar() {
        let exact = format!(
            "https://example.com/{}",
            "a".repeat(SourceUrl::MAX_LEN - 20)
        );
        assert_eq!(exact.len(), SourceUrl::MAX_LEN);
        let long_host = format!("https://{}", "h".repeat(253));
        for good in [
            "https://github.com/lyuksovannyy/rizzy-vault/tree/0123456789abcdef0123456789abcdef01234567",
            "https://github.com/lyuksovannyy/rizzy-vault/releases/tag/v1.0.0",
            "https://example.com:8443/src",
            "https://example.com/src?ref=v1#top",
            "https://example.com/a%2Fb",
            "https://h",
            "https://example.com",
            "https://192.0.2.1/src",
            "https://example.com/p:a@b[c]!$&'()*+,;=-._~",
            "https://xn--bcher-kva.example/src",
            "https://example.com:00443",
            exact.as_str(),
            long_host.as_str(),
        ] {
            let url = SourceUrl::parse(good).unwrap_or_else(|e| panic!("{good}: {e}"));
            // No normalisation: byte for byte.
            assert_eq!(url.as_str(), good);
            assert_eq!(url.to_string(), good);
        }
        let too_long = format!("{exact}a");
        let host_too_long = format!("https://{}", "h".repeat(254));
        for (bad, why) in [
            ("", SourceUrlError::Length),
            ("https://", SourceUrlError::Length),
            (too_long.as_str(), SourceUrlError::Length),
            ("http://example.com", SourceUrlError::Scheme),
            ("HTTPS://example.com", SourceUrlError::Scheme),
            ("//example.com/src", SourceUrlError::Scheme),
            ("ftp://example.com", SourceUrlError::Scheme),
            ("https://example.com/a b", SourceUrlError::Character),
            ("https://example.com/a\tb", SourceUrlError::Character),
            ("https://example.com/\u{e9}", SourceUrlError::Character),
            ("https://user@example.com", SourceUrlError::Authority),
            ("https://user:pw@example.com", SourceUrlError::Authority),
            ("https://[::1]/src", SourceUrlError::Authority),
            ("https://example.com:0", SourceUrlError::Authority),
            ("https://example.com:65536", SourceUrlError::Authority),
            ("https://example.com:123456", SourceUrlError::Authority),
            ("https://example.com:", SourceUrlError::Authority),
            ("https://example.com:80:80", SourceUrlError::Authority),
            ("https://-host", SourceUrlError::Authority),
            ("https://host.", SourceUrlError::Authority),
            ("https://.host", SourceUrlError::Authority),
            ("https://host-", SourceUrlError::Authority),
            ("https:///src", SourceUrlError::Authority),
            ("https://ho_st", SourceUrlError::Authority),
            (host_too_long.as_str(), SourceUrlError::Authority),
            ("https://example.com/%zz", SourceUrlError::Path),
            ("https://example.com/%4", SourceUrlError::Path),
            ("https://example.com/\"", SourceUrlError::Path),
            ("https://example.com/<", SourceUrlError::Path),
            ("https://example.com/\\", SourceUrlError::Path),
            ("https://example.com/{x}", SourceUrlError::Path),
            ("https://example.com/a|b", SourceUrlError::Path),
        ] {
            assert_eq!(SourceUrl::parse(bad), Err(why), "{bad:?}");
        }
        // Eight and 2049 bytes, named by length.
        assert_eq!("https://".len(), 8);
        assert_eq!(too_long.len(), 2049);
    }

    #[test]
    fn source_url_base() {
        let base = |s| SourceUrl::parse(s).unwrap().is_base();
        assert!(base("https://github.com/lyuksovannyy/rizzy-vault"));
        assert!(!base("https://github.com/lyuksovannyy/rizzy-vault/"));
        assert!(!base("https://example.com/src?x"));
        assert!(!base("https://example.com/src#x"));
    }

    /// ADR 0106 §3: `source_url` round trips when valid and reads as `None` when absent, not a
    /// string or invalid, with the other members intact.
    #[test]
    fn meta_source_url_is_read_leniently() {
        let head = r#""server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[]"#;
        let with = format!(r#"{{{head},"source_url":"https://example.com/src"}}"#);
        let meta: MetaResponse = serde_json::from_str(&with).unwrap();
        assert_eq!(
            meta.source_url.as_ref().map(SourceUrl::as_str),
            Some("https://example.com/src")
        );
        assert_eq!(serde_json::to_string(&meta).unwrap(), with);
        let over = format!("https://example.com/{}", "a".repeat(SourceUrl::MAX_LEN));
        for member in [
            String::new(),
            r#","source_url":5"#.to_owned(),
            r#","source_url":null"#.to_owned(),
            r#","source_url":true"#.to_owned(),
            r#","source_url":["https://example.com/src"]"#.to_owned(),
            r#","source_url":{"a":[1,{"b":null}]}"#.to_owned(),
            r#","source_url":"http://example.com/src""#.to_owned(),
            r#","source_url":"""#.to_owned(),
            format!(r#","source_url":"{over}""#),
        ] {
            let json = format!(r#"{{{head}{member},"x":1}}"#);
            let meta: MetaResponse =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{json}: {e}"));
            assert_eq!(meta.source_url, None, "{json}");
            assert_eq!(meta.server_version.as_str(), "0.1.0");
            assert_eq!(meta.api_versions.len(), 1);
            // `None` is not serialised.
            assert_eq!(serde_json::to_string(&meta).unwrap(), format!("{{{head}}}"));
        }
        // A broken document is still an error.
        assert!(
            serde_json::from_str::<MetaResponse>(&format!(r#"{{{head},"source_url":[}}"#)).is_err()
        );
        // The type on its own is strict.
        assert!(serde_json::from_str::<SourceUrl>(r#""http://example.com""#).is_err());
        assert!(serde_json::from_str::<SourceUrl>("5").is_err());
    }

    #[test]
    fn semver_grammar() {
        for good in [
            "0.0.0",
            "1.2.3",
            "10.20.30",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-0.3.7",
            "1.0.0-x.7.z.92",
            "1.0.0-x-y-z.--",
            "1.0.0+20130313144700",
            "1.0.0-beta+exp.sha.5114f85",
            "1.0.0+21AF26D3----117B344092BD",
            "1.0.0+001",
            "99999999999999999999999.999999999999999999.99999999999999999",
        ] {
            assert_eq!(
                semver_precedence(good, good),
                Some(Ordering::Equal),
                "{good}"
            );
        }
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3-a..b",
            "1.2.3+",
            "1.2.3+a..b",
            "1.2.3+a+b",
            "v1.2.3",
            "1.2.x",
            "1.2.3 ",
            "1..3",
            "-1.2.3",
        ] {
            assert_eq!(semver_precedence(bad, "1.0.0"), None, "{bad:?}");
            assert_eq!(semver_precedence("1.0.0", bad), None, "{bad:?}");
        }
    }

    #[test]
    fn semver_precedence_follows_the_specification() {
        // SemVer 2.0.0 §11.4's own chain, and §11.2's.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "2.0.0",
            "2.1.0",
            "2.1.1",
            "2.10.0",
            "10.0.0",
            "100000000000000000000.0.0",
        ];
        for (i, a) in chain.iter().enumerate() {
            for (j, b) in chain.iter().enumerate() {
                assert_eq!(semver_precedence(a, b), Some(i.cmp(&j)), "{a} vs {b}");
            }
        }
        // Build metadata takes no part.
        assert_eq!(
            semver_precedence("1.0.0+a", "1.0.0+b"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            semver_precedence("1.0.0-rc.1+x", "1.0.0"),
            Some(Ordering::Less)
        );
    }

    #[test]
    fn client_too_old_rule() {
        let min = |platform: &str, version: &str| MinClientVersion {
            platform: Platform::from_str(platform).unwrap(),
            version: Version::from_str(version).unwrap(),
        };
        let minimums = [min("cli", "0.3.0"), min("ios", "1.2.0")];
        let old = |value: &str| client_too_old(&ClientHeader::parse(value).unwrap(), &minimums);
        assert!(!old("cli/0.3.0"));
        assert!(!old("cli/0.10.0"));
        assert!(!old("cli/1.0.0-rc.1"));
        assert!(old("cli/0.2.9"));
        // A pre-release of the minimum is below it.
        assert!(old("cli/0.3.0-rc.1"));
        // Not SemVer: below any minimum.
        assert!(old("cli/0.3"));
        assert!(old("cli/nightly"));
        // A platform without a minimum is never refused, whatever its version.
        assert!(!old("web/0.0.1"));
        assert!(!old("web/nightly"));
        // Each platform has its own minimum.
        assert!(old("ios/1.1.9"));
        assert!(!old("ios/1.2.0"));
        // No list: nobody is refused.
        assert!(!client_too_old(
            &ClientHeader::parse("cli/0.0.1").unwrap(),
            &[]
        ));
        // A minimum that is not SemVer is never reached.
        assert!(client_too_old(
            &ClientHeader::parse("cli/9.9.9").unwrap(),
            &[min("cli", "soon")]
        ));
    }

    #[test]
    fn known_platforms() {
        for platform in PLATFORMS {
            let header = ClientHeader::parse(&format!("{platform}/1.0.0")).unwrap();
            assert!(header.has_known_platform(), "{platform}");
        }
        assert!(
            !ClientHeader::parse("freebsd/1.0.0")
                .unwrap()
                .has_known_platform()
        );
    }

    #[test]
    fn client_header() {
        let h = ClientHeader::parse("cli/0.1.0-rc.1").unwrap();
        assert_eq!(h.platform.as_str(), "cli");
        assert_eq!(h.version.as_str(), "0.1.0-rc.1");
        assert_eq!(h.to_string(), "cli/0.1.0-rc.1");
        for bad in [
            "",
            "cli",
            "/0.1",
            "cli/",
            "CLI/0.1",
            "cli/0.1/2",
            "cli/0 1",
            "cli\u{e9}/0.1",
        ] {
            assert!(ClientHeader::parse(bad).is_err(), "{bad:?}");
        }
        let long = format!("cli/{}", "1".repeat(ClientHeader::MAX_LEN));
        assert_eq!(
            ClientHeader::parse(&long),
            Err(WireError::TooLong {
                max: ClientHeader::MAX_LEN
            })
        );
    }
}
