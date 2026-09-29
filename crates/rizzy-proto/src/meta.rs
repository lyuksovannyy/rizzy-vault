//! `GET /api/meta` and the `Rizzy-Client` request header (ADR 0002 point 3).
//!
//! `/api/meta` is the one unversioned endpoint. ADR 0002 point 3 lists what it returns; ADR
//! 0022 removes the second item ("the sync modes the admin allows"), so [`MetaResponse`]
//! carries:
//! - the server version and the API versions it serves;
//! - the minimum client version per platform.
//!
//! The field names, the platform names and the version grammar are not fixed by any ADR; they
//! are this crate's pre-v1.0 choice (ADR 0002 point 5). The meta answer is unauthenticated
//! and a malicious server can lie in it; it never selects an algorithm or parameter (ADR 0002
//! point 4), only whether the client shows "update required".

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
