// SPDX-License-Identifier: AGPL-3.0-only

//! The breach check of the `icons` role ([ADR 0053]; CRYPTO.md §11.16).
//!
//! | Endpoint | Request | Response | Caller |
//! |---|---|---|---|
//! | `icons/breach-range` | [`BreachRangeRequest`] | [`BreachRangeResponse`] | anyone: no session, no bearer token |
//!
//! - **What the client sends** (ADR 0053 item 1, INV-77): the first 5 characters of the
//!   uppercase hex SHA-1 digest of `UTF-8(NFC(password))` ([`HashPrefix`]), and nothing
//!   else: no account identity, no session token, no item id. The digest itself is
//!   `rizzy-core`'s (`breach`).
//! - **What the server returns:** the upstream range response, relayed unmodified as one JSON
//!   string ([`RangeBody`]): CRLF-separated `SUFFIX:COUNT` lines, each suffix the remaining 35
//!   uppercase hex characters of a digest with that prefix, each count a decimal number of
//!   sightings. Padded entries (count `0`) are fake and mean "not seen". The server checks
//!   the format before it caches or relays a body ([`parse_range`]), and the client checks it
//!   again when it parses the response, since the threat model trusts neither the upstream
//!   nor the server.
//! - **The endpoint is served by the `icons` role only** (ADR 0053 item 1, ADR 0010 §1–§2), on
//!   its own listener, never by `api`. It answers `404 not_found` when breach checking is off
//!   (ADR 0053 item 5) and `429 rate_limited` past the per-source limit (item 8).
//! - **Nothing here is logged.** [`HashPrefix`] and [`RangeBody`] print no content from
//!   `Debug`, and [`RangeError`] carries no input.
//!
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

use core::fmt;

use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::limits::{MAX_BREACH_RANGE_ENTRIES, MAX_BREACH_RANGE_LEN};
use crate::wire::WireError;

/// Characters of a [`HashPrefix`] (20 bits of the digest; ADR 0053 item 1).
pub const PREFIX_LEN: usize = 5;

/// Characters of the suffix of each range entry (the 35 hex characters after the prefix).
pub const SUFFIX_LEN: usize = 35;

/// The longest count a range line may carry, in decimal digits (`u64::MAX` has 20).
pub const MAX_COUNT_DIGITS: usize = 20;

/// Whether `b` is an uppercase hex digit (`0`–`9`, `A`–`F`), the only case ADR 0053
/// item 1 admits.
const fn is_upper_hex(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'A'..=b'F')
}

/// The 5 uppercase hex characters a client sends. `Debug` prints no content: the prefix is
/// never logged (INV-77).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HashPrefix([u8; PREFIX_LEN]);

impl HashPrefix {
    /// Checks and wraps 5 bytes.
    ///
    /// # Errors
    /// [`WireError::InvalidCharacter`] unless every byte is an uppercase hex digit.
    pub fn from_bytes(bytes: [u8; PREFIX_LEN]) -> Result<Self, WireError> {
        if bytes.iter().all(|b| is_upper_hex(*b)) {
            Ok(Self(bytes))
        } else {
            Err(WireError::InvalidCharacter)
        }
    }

    /// Checks and copies a prefix written as text.
    ///
    /// # Errors
    /// [`WireError::WrongLength`] unless `text` is 5 bytes, [`WireError::InvalidCharacter`]
    /// unless each is an uppercase hex digit.
    pub fn parse(text: &str) -> Result<Self, WireError> {
        let bytes: [u8; PREFIX_LEN] =
            text.as_bytes()
                .try_into()
                .map_err(|_| WireError::WrongLength {
                    expected: PREFIX_LEN,
                })?;
        Self::from_bytes(bytes)
    }

    /// The prefix as text: 5 ASCII characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Every byte is an ASCII hex digit (checked on construction), so this never fails.
        core::str::from_utf8(&self.0).unwrap_or("")
    }

    /// The prefix as bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PREFIX_LEN] {
        &self.0
    }
}

impl fmt::Debug for HashPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashPrefix([REDACTED])")
    }
}

impl Serialize for HashPrefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HashPrefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`HashPrefix`].
        struct V;
        impl Visitor<'_> for V {
            type Value = HashPrefix;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("5 uppercase hex characters")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                HashPrefix::parse(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// Body of `icons/breach-range`: the prefix, and nothing else (INV-77). Unknown fields are
/// refused, so a client cannot add an identifier the server would then see.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreachRangeRequest {
    /// The first 5 uppercase hex characters of the candidate's digest.
    pub prefix: HashPrefix,
}

/// Answer of `icons/breach-range`. A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachRangeResponse {
    /// The upstream range response for the prefix, unmodified.
    pub range: RangeBody,
}

/// An upstream range response that passed [`parse_range`]: at most [`MAX_BREACH_RANGE_LEN`]
/// bytes and [`MAX_BREACH_RANGE_ENTRIES`] entries. `Debug` prints its length only.
#[derive(Clone, PartialEq, Eq)]
pub struct RangeBody(String);

impl RangeBody {
    /// Checks and wraps a range response.
    ///
    /// # Errors
    /// The [`RangeError`] of [`parse_range`].
    pub fn new(text: String) -> Result<Self, RangeError> {
        parse_range(&text)?;
        Ok(Self(text))
    }

    /// Checks and wraps a range response given as bytes (the upstream's body).
    ///
    /// # Errors
    /// [`RangeError::TooLong`] past the limit (checked before any copy), [`RangeError::Malformed`]
    /// for bytes that are not the range format (which is ASCII).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RangeError> {
        if bytes.len() > MAX_BREACH_RANGE_LEN {
            return Err(RangeError::TooLong);
        }
        let text = core::str::from_utf8(bytes).map_err(|_| RangeError::Malformed)?;
        Self::new(text.to_owned())
    }

    /// The text, as relayed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The entries. Never fails: the text was checked on construction.
    #[must_use]
    pub fn entries(&self) -> Vec<RangeEntry<'_>> {
        parse_range(&self.0).unwrap_or_default()
    }
}

impl fmt::Debug for RangeBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RangeBody")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Serialize for RangeBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RangeBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Visitor for [`RangeBody`].
        struct V;
        impl Visitor<'_> for V {
            type Value = RangeBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "a range response of at most {MAX_BREACH_RANGE_LEN} bytes"
                )
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                // The length is checked before the copy.
                if v.len() > MAX_BREACH_RANGE_LEN {
                    return Err(E::custom(RangeError::TooLong));
                }
                RangeBody::new(v.to_owned()).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(V)
    }
}

/// One line of a range response.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RangeEntry<'a> {
    /// The 35 uppercase hex characters after the prefix.
    pub suffix: &'a [u8],
    /// How often the upstream saw the password; `0` for a padded (fake) entry.
    pub count: u64,
}

impl fmt::Debug for RangeEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RangeEntry").finish_non_exhaustive()
    }
}

/// Why a range response was refused. Carries no input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RangeError {
    /// Longer than [`MAX_BREACH_RANGE_LEN`] bytes.
    TooLong,
    /// More than [`MAX_BREACH_RANGE_ENTRIES`] entries.
    TooManyEntries,
    /// A line is not `SUFFIX:COUNT` (35 uppercase hex characters, a colon, 1 to 20 decimal
    /// digits whose value fits a `u64`), or the lines are not separated by CRLF.
    Malformed,
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "range response longer than {MAX_BREACH_RANGE_LEN} bytes"),
            Self::TooManyEntries => write!(
                f,
                "range response with more than {MAX_BREACH_RANGE_ENTRIES} entries"
            ),
            Self::Malformed => f.write_str("malformed range response"),
        }
    }
}

impl std::error::Error for RangeError {}

/// Parses an upstream range response, without panicking on any input.
///
/// The format (Have I Been Pwned's range API, read 2026-10-22): lines separated by CRLF, each
/// `SUFFIX:COUNT`. Accepted: an empty body (no entries), and one CRLF after the last line.
/// Refused: anything longer than [`MAX_BREACH_RANGE_LEN`] bytes or with more than
/// [`MAX_BREACH_RANGE_ENTRIES`] lines, an empty line, a bare CR or LF, lowercase hex, a
/// suffix of another length, a missing or repeated colon, a count that is empty, signed,
/// longer than 20 digits or above `u64::MAX`.
///
/// # Errors
/// [`RangeError`].
pub fn parse_range(body: &str) -> Result<Vec<RangeEntry<'_>>, RangeError> {
    if body.len() > MAX_BREACH_RANGE_LEN {
        return Err(RangeError::TooLong);
    }
    let mut entries = Vec::new();
    if body.is_empty() {
        return Ok(entries);
    }
    let body = body.strip_suffix("\r\n").unwrap_or(body);
    for line in body.split("\r\n") {
        if entries.len() >= MAX_BREACH_RANGE_ENTRIES {
            return Err(RangeError::TooManyEntries);
        }
        entries.push(parse_line(line)?);
    }
    Ok(entries)
}

/// One `SUFFIX:COUNT` line.
fn parse_line(line: &str) -> Result<RangeEntry<'_>, RangeError> {
    let (suffix, count) = line.split_once(':').ok_or(RangeError::Malformed)?;
    let suffix = suffix.as_bytes();
    if suffix.len() != SUFFIX_LEN || !suffix.iter().all(|b| is_upper_hex(*b)) {
        return Err(RangeError::Malformed);
    }
    if count.is_empty()
        || count.len() > MAX_COUNT_DIGITS
        || !count.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(RangeError::Malformed);
    }
    let count = count.parse::<u64>().map_err(|_| RangeError::Malformed)?;
    Ok(RangeEntry { suffix, count })
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! The request and response shapes, and the range parser on accepted and refused inputs.

    use super::*;

    const HIT: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn request_known_answer_and_strictness() {
        let request = BreachRangeRequest {
            prefix: HashPrefix::parse("5BAA6").unwrap(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"prefix":"5BAA6"}"#);
        assert_eq!(
            serde_json::from_str::<BreachRangeRequest>(&json).unwrap(),
            request
        );
        for bad in [
            r#"{"prefix":"5baa6"}"#,
            r#"{"prefix":"5BAA"}"#,
            r#"{"prefix":"5BAA61"}"#,
            r#"{"prefix":"5BAG6"}"#,
            r#"{"prefix":""}"#,
            r#"{"prefix":5}"#,
            "{}",
            // No identity rides along (INV-77).
            r#"{"prefix":"5BAA6","item_id":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
            r#"{"prefix":"5BAA6","account":"x"}"#,
        ] {
            assert!(
                serde_json::from_str::<BreachRangeRequest>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn prefix_debug_is_redacted() {
        let prefix = HashPrefix::parse("5BAA6").unwrap();
        assert!(!format!("{prefix:?}").contains("5BAA6"));
        let request = BreachRangeRequest { prefix };
        assert!(!format!("{request:?}").contains("5BAA6"));
        assert_eq!(prefix.as_str(), "5BAA6");
    }

    #[test]
    fn response_round_trip_tolerates_unknown_fields() {
        let body = format!("{HIT}:3\r\n");
        let json = format!(r#"{{"range":"{HIT}:3\r\n","future":1}}"#);
        let response: BreachRangeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response.range.as_str(), body);
        assert!(!format!("{response:?}").contains(HIT));
        let entries = response.range.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].suffix, HIT.as_bytes());
        assert_eq!(entries[0].count, 3);
        // A malformed body fails the whole response.
        assert!(serde_json::from_str::<BreachRangeResponse>(r#"{"range":"nope"}"#).is_err());
    }

    #[test]
    fn parser_accepts_the_upstream_format() {
        assert_eq!(parse_range("").unwrap(), vec![]);
        let one = format!("{HIT}:0");
        assert_eq!(parse_range(&one).unwrap()[0].count, 0);
        let two = format!("{HIT}:18446744073709551615\r\n{HIT}:1\r\n");
        let entries = parse_range(&two).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].count, u64::MAX);
        // Leading zeros in a count are digits too (the upstream does not send them, but they
        // name the same number).
        assert_eq!(parse_range(&format!("{HIT}:007")).unwrap()[0].count, 7);
    }

    #[test]
    fn parser_refuses_everything_else() {
        let lower = HIT.to_lowercase();
        let short = &HIT[..34];
        let long = format!("{HIT}0");
        for bad in [
            format!("{lower}:1"),
            format!("{short}:1"),
            format!("{long}:1"),
            format!("{HIT}:"),
            HIT.to_owned(),
            format!("{HIT}:1:2"),
            format!("{HIT}:-1"),
            format!("{HIT}:+1"),
            format!("{HIT}: 1"),
            format!("{HIT}:18446744073709551616"),
            format!("{HIT}:000000000000000000001"),
            format!("{HIT}:1\n{HIT}:2"),
            format!("{HIT}:1\r{HIT}:2"),
            format!("{HIT}:1\r\n\r\n{HIT}:2"),
            format!("{HIT}:1\r\n\r\n"),
            "\r\n".to_owned(),
            format!(" {HIT}:1"),
            format!("{HIT}:1 "),
        ] {
            assert_eq!(parse_range(&bad), Err(RangeError::Malformed), "{bad:?}");
        }
    }

    #[test]
    fn parser_limits() {
        let line = format!("{HIT}:1\r\n");
        let full = line.repeat(MAX_BREACH_RANGE_ENTRIES);
        assert_eq!(parse_range(&full).unwrap().len(), MAX_BREACH_RANGE_ENTRIES);
        let over = line.repeat(MAX_BREACH_RANGE_ENTRIES + 1);
        assert!(matches!(
            parse_range(&over),
            Err(RangeError::TooManyEntries | RangeError::TooLong)
        ));
        let huge = "A".repeat(MAX_BREACH_RANGE_LEN + 1);
        assert_eq!(parse_range(&huge), Err(RangeError::TooLong));
        assert_eq!(
            RangeBody::from_bytes(huge.as_bytes()),
            Err(RangeError::TooLong)
        );
        assert_eq!(
            RangeBody::from_bytes(&[0xff, 0xfe]),
            Err(RangeError::Malformed)
        );
        // Errors quote nothing.
        for e in [
            RangeError::TooLong,
            RangeError::TooManyEntries,
            RangeError::Malformed,
        ] {
            assert!(!e.to_string().contains(HIT));
        }
    }
}
