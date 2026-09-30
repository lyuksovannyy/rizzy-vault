//! `GET /api/meta` and the `Rizzy-Client` request header (ADR 0002 point 3; [ADR 0028] item 14).
//!
//! `/api/meta` is the one unversioned endpoint. ADR 0002 point 3 lists what it returns; ADR
//! 0022 removes the second item ("the sync modes the admin allows"), so [`MetaResponse`]
//! carries:
//! - the server version and the API versions it serves;
//! - the minimum client version per platform.
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
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use core::cmp::Ordering;
use core::fmt;

use serde::{Deserialize, Serialize};

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
        };
        let json = r#"{"server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[{"platform":"cli","version":"0.1.0"}]}"#;
        assert_eq!(serde_json::to_string(&meta).unwrap(), json);
        assert_eq!(serde_json::from_str::<MetaResponse>(json).unwrap(), meta);
        // A response: a newer server's extra field is ignored.
        let newer =
            r#"{"server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[],"x":true}"#;
        assert!(serde_json::from_str::<MetaResponse>(newer).is_ok());
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
