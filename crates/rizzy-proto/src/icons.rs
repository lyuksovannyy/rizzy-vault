// SPDX-License-Identifier: AGPL-3.0-only

//! The favicon fetch of the `icons` role ([ADR 0052] point 6).
//!
//! | Endpoint | Request | Response | Caller |
//! |---|---|---|---|
//! | `icons/fetch` | [`IconFetchRequest`] | [`IconFetchResponse`] | anyone: no session, no bearer token |
//!
//! - **What the client sends:** a hostname and nothing else ([`IconHost`]): no scheme, no
//!   port, no path (the role chooses them, ADR 0052 point 2), and no account, session or item
//!   identifier (point 5). Unknown fields are refused, so none can ride along.
//! - **What the server returns:** one PNG of at most 128×128 pixels, re-encoded by the role
//!   from whatever image it fetched (ADR 0052 point 4): `content_type` is always
//!   [`ICON_CONTENT_TYPE`], `data` the PNG bytes as base64url, at most [`MAX_ICON_PNG_LEN`]
//!   bytes. The client checks both again ([`IconFetchResponse::check`]): the threat model
//!   trusts neither the upstream nor the server.
//! - **Errors** are ADR 0028 item 3's uniform codes: `invalid_request` for a malformed host,
//!   `not_found` when no icon could be fetched or decoded, `rate_limited`, `internal`.
//! - **Served by the `icons` role only**, on its own listener, never by `api` (ADR 0052
//!   point 1; ADR 0010 §1–§2). Not in [`crate::http::paths::ALL`].
//!
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md

use core::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::limits::MAX_ICON_PNG_LEN;
use crate::wire::{Bytes, WireError};

/// The longest hostname, in bytes (RFC 1123; ADR 0052 point 5).
pub const MAX_HOST_LEN: usize = 253;

/// The longest label of a hostname, in bytes (RFC 1123; ADR 0052 point 5).
pub const MAX_LABEL_LEN: usize = 63;

/// The only content type an icon is served as (ADR 0052 point 4, owner answer 1).
pub const ICON_CONTENT_TYPE: &str = "image/png";

/// The eight bytes every PNG starts with (PNG specification §5.2).
pub const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// Whether `host` is a hostname of the form ADR 0052 point 5 accepts: RFC 1123 syntax in
/// lowercase ASCII. 1 to 253 bytes; labels of 1 to 63 bytes from `[a-z0-9-]`, never starting
/// or ending with `-`; no empty label, so no leading, trailing or doubled dot. That rules out
/// `/`, `..`, `:`, `@`, `%`, whitespace, uppercase and every non-ASCII byte, so the
/// value is safe as a cache file name and as an HTTP `Host` header.
#[must_use]
pub fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return false;
    }
    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= MAX_LABEL_LEN
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && bytes.first() != Some(&b'-')
            && bytes.last() != Some(&b'-')
    })
}

/// A hostname that passed [`is_valid_host`]. `Debug` prints its length only: which sites a
/// user has accounts on is exactly what the role must not log (INV-51; threat model §7.11 "I").
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct IconHost(String);

impl IconHost {
    /// Checks and copies a hostname.
    ///
    /// # Errors
    /// [`WireError::Empty`], [`WireError::TooLong`], or [`WireError::InvalidCharacter`]
    /// for anything else [`is_valid_host`] refuses.
    pub fn parse(text: &str) -> Result<Self, WireError> {
        if text.is_empty() {
            Err(WireError::Empty)
        } else if text.len() > MAX_HOST_LEN {
            Err(WireError::TooLong { max: MAX_HOST_LEN })
        } else if is_valid_host(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(WireError::InvalidCharacter)
        }
    }

    /// The hostname.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IconHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IconHost({} bytes)", self.0.len())
    }
}

impl Serialize for IconHost {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IconHost {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`IconHost`].
        struct V;
        impl Visitor<'_> for V {
            type Value = IconHost;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a lowercase ASCII hostname")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                IconHost::parse(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// Body of `icons/fetch`: the hostname, and nothing else (ADR 0052 points 5–6). Unknown
/// fields are refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IconFetchRequest {
    /// The site whose icon is wanted.
    pub host: IconHost,
}

/// The PNG bytes of an icon: at most [`MAX_ICON_PNG_LEN`].
pub type IconData = Bytes<MAX_ICON_PNG_LEN>;

/// Answer of `icons/fetch`. A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IconFetchResponse {
    /// Always [`ICON_CONTENT_TYPE`].
    pub content_type: String,
    /// The re-encoded PNG.
    pub data: IconData,
}

/// Why an [`IconFetchResponse`] was refused by [`IconFetchResponse::check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IconError {
    /// `content_type` is not [`ICON_CONTENT_TYPE`].
    ContentType,
    /// `data` does not start with [`PNG_SIGNATURE`].
    NotPng,
}

impl fmt::Display for IconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ContentType => "the icon is not served as image/png",
            Self::NotPng => "the icon is not a PNG",
        })
    }
}

impl std::error::Error for IconError {}

impl IconFetchResponse {
    /// An answer for `png`, with the one content type.
    #[must_use]
    pub fn png(data: IconData) -> Self {
        Self {
            content_type: ICON_CONTENT_TYPE.to_owned(),
            data,
        }
    }

    /// The client's check of an answer: the content type is exactly [`ICON_CONTENT_TYPE`]
    /// and the bytes start with the PNG signature (their length was bounded when they were
    /// parsed). The pixels are decoded by the client's own image decoder, never trusted to be
    /// well formed.
    ///
    /// # Errors
    /// [`IconError`].
    pub fn check(&self) -> Result<(), IconError> {
        if self.content_type != ICON_CONTENT_TYPE {
            return Err(IconError::ContentType);
        }
        if !self.data.as_slice().starts_with(&PNG_SIGNATURE) {
            return Err(IconError::NotPng);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Hostname syntax (ADR 0052 point 5), the strict request, and the client's check.

    use super::*;

    #[test]
    fn accepts_rfc_1123_lowercase_hosts() {
        for host in [
            "example.com",
            "a",
            "xn--bcher-kva.example",
            "1.2.3.4",
            "a-b.c-d.e",
            "0leading-digit.example",
        ] {
            assert!(is_valid_host(host), "{host}");
            assert_eq!(IconHost::parse(host).unwrap().as_str(), host);
        }
        let label = "a".repeat(MAX_LABEL_LEN);
        let long = [
            label.as_str(),
            label.as_str(),
            label.as_str(),
            &"a".repeat(61),
        ]
        .join(".");
        assert_eq!(long.len(), MAX_HOST_LEN);
        assert!(is_valid_host(&long));
    }

    #[test]
    fn refuses_everything_else() {
        let label = "a".repeat(MAX_LABEL_LEN + 1);
        let too_long = format!("{}.com", "a.".repeat(126));
        assert!(too_long.len() > MAX_HOST_LEN);
        for host in [
            "",
            ".",
            ".example.com",
            "example.com.",
            "a..b",
            "-a.com",
            "a-.com",
            "Example.com",
            "exa mple.com",
            "example.com/x",
            "../etc",
            "..",
            "example.com:443",
            "user@example.com",
            "[::1]",
            "exa%2fmple.com",
            "b\u{fc}cher.de",
            "a_b.com",
            "a\nb",
            label.as_str(),
            too_long.as_str(),
        ] {
            assert!(!is_valid_host(host), "{host:?}");
            assert!(IconHost::parse(host).is_err(), "{host:?}");
        }
        assert_eq!(IconHost::parse(""), Err(WireError::Empty));
        assert_eq!(
            IconHost::parse(&too_long),
            Err(WireError::TooLong { max: MAX_HOST_LEN })
        );
    }

    #[test]
    fn debug_hides_the_host() {
        let host = IconHost::parse("secret-bank.example").unwrap();
        let printed = format!("{host:?} {:?}", IconFetchRequest { host: host.clone() });
        assert!(!printed.contains("secret-bank"), "{printed}");
    }

    #[test]
    fn request_is_exactly_the_host() {
        let request: IconFetchRequest = serde_json::from_str(r#"{"host":"example.com"}"#).unwrap();
        assert_eq!(request.host.as_str(), "example.com");
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"host":"example.com"}"#
        );
        for body in [
            r#"{"host":"example.com","account":"x"}"#,
            r#"{"host":"https://example.com"}"#,
            r#"{"host":"EXAMPLE.com"}"#,
            r#"{"host":""}"#,
            "{}",
            r#"{"host":5}"#,
        ] {
            assert!(
                serde_json::from_str::<IconFetchRequest>(body).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn response_round_trip_and_check() {
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend_from_slice(b"rest");
        let response = IconFetchResponse::png(IconData::new(png).unwrap());
        let json = serde_json::to_string(&response).unwrap();
        assert!(
            json.starts_with(r#"{"content_type":"image/png","data":""#),
            "{json}"
        );
        let back: IconFetchResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, response);
        assert_eq!(back.check(), Ok(()));

        let svg: IconFetchResponse =
            serde_json::from_str(r#"{"content_type":"image/svg+xml","data":"iVBORw0KGgo"}"#)
                .unwrap();
        assert_eq!(svg.check(), Err(IconError::ContentType));
        let gif: IconFetchResponse =
            serde_json::from_str(r#"{"content_type":"image/png","data":"R0lGODlh"}"#).unwrap();
        assert_eq!(gif.check(), Err(IconError::NotPng));
        let big = "A".repeat((MAX_ICON_PNG_LEN + 3) / 3 * 4 + 8);
        let json = format!(r#"{{"content_type":"image/png","data":"{big}"}}"#);
        assert!(serde_json::from_str::<IconFetchResponse>(&json).is_err());
        // Unknown fields in the answer are ignored (ADR 0002 point 3).
        let extra: IconFetchResponse =
            serde_json::from_str(r#"{"content_type":"image/png","data":"iVBORw0KGgo","later":1}"#)
                .unwrap();
        assert_eq!(extra.check(), Ok(()));
    }
}
