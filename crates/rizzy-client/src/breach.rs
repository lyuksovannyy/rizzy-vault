// SPDX-License-Identifier: AGPL-3.0-only

//! The breach check, the client half (CRYPTO.md §11.16; [ADR 0053] item 1;
//! `rizzy_proto::breach`).
//!
//! ```text
//! BreachCheck::start(password) ──BreachRangeRequest { prefix }──► host ──► icons/breach-range
//!                                   (no session, no Authorization header, nothing else)
//! host ──BreachRangeResponse { range }──► BreachCheck::finish ──► BreachVerdict
//! ```
//!
//! - **Only the prefix leaves the device.** [`BreachCheck::start`] computes the digest of
//!   `UTF-8(NFC(password))` (`rizzy_core::breach`), keeps it in a wiped buffer, and puts its
//!   first 5 uppercase hex characters, and nothing else, into the request (INV-77). The host
//!   sends it without a bearer token or any other identifier: it is not a session request.
//! - **The answer is untrusted.** The range was bounded and its line format checked by
//!   `rizzy-proto` when the host deserialised the response ([`BreachRangeResponse`]).
//!   [`BreachCheck::finish`] compares every suffix with the digest's own suffix in constant
//!   time, with no early exit, and returns the matching count; a padded entry (count `0`) is
//!   "not found".
//! - **What a verdict means.** "Found" is the upstream's word that the password appeared in a
//!   breach corpus, relayed by a server the threat model does not trust: a malicious server
//!   can hide a breach or invent one. It is advice for the user, never a security decision.
//!
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

use core::fmt;

use rizzy_core::breach::BreachDigest;
use rizzy_proto::breach::{BreachRangeRequest, BreachRangeResponse, HashPrefix};

use crate::error::ClientError;

/// A started breach check: the candidate's digest, wiped on drop. `Debug` prints nothing of
/// it.
pub struct BreachCheck {
    /// The digest; only its prefix is sent.
    digest: BreachDigest,
    /// The digest's prefix, checked.
    prefix: HashPrefix,
}

impl fmt::Debug for BreachCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BreachCheck").finish_non_exhaustive()
    }
}

/// The outcome of a breach check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreachVerdict {
    /// No entry of the range matched (or only a padded one).
    NotFound,
    /// An entry matched: the upstream saw the password this many times.
    Found {
        /// Sightings, at least 1.
        count: u64,
    },
}

impl BreachCheck {
    /// Computes the digest of `password` and the request for its range.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for an empty password (nothing to check) or one whose NFC
    /// form overflows memory.
    pub fn start(password: &str) -> Result<(Self, BreachRangeRequest), ClientError> {
        if password.is_empty() {
            return Err(ClientError::InvalidInput);
        }
        let digest = BreachDigest::of_password(password).map_err(|_| ClientError::InvalidInput)?;
        let prefix =
            HashPrefix::from_bytes(digest.prefix()).map_err(|_| ClientError::InvalidInput)?;
        Ok((Self { digest, prefix }, BreachRangeRequest { prefix }))
    }

    /// The prefix this check sends, for a host that groups checks to send one request per
    /// prefix. Public by design: it is exactly what goes on the wire.
    #[must_use]
    pub const fn prefix(&self) -> HashPrefix {
        self.prefix
    }

    /// Reads the answer: scans every entry of the range with the constant-time suffix
    /// comparison and returns the verdict. Consumes the check, so the digest is wiped.
    #[must_use]
    pub fn finish(self, response: &BreachRangeResponse) -> BreachVerdict {
        let entries = response.range.entries();
        let count = self
            .digest
            .count_in(entries.iter().map(|e| (e.suffix, e.count)));
        if count == 0 {
            BreachVerdict::NotFound
        } else {
            BreachVerdict::Found { count }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The request carries the prefix only; the verdict reads the range.

    use rizzy_proto::breach::RangeBody;

    use super::*;

    fn response(range: &str) -> BreachRangeResponse {
        BreachRangeResponse {
            range: RangeBody::new(range.to_owned()).unwrap(),
        }
    }

    #[test]
    fn the_request_is_the_prefix_and_nothing_else() {
        let (check, request) = BreachCheck::start("password").unwrap();
        assert_eq!(request.prefix.as_str(), "5BAA6");
        assert_eq!(check.prefix(), request.prefix);
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"prefix":"5BAA6"}"#);
        // Neither the password nor any part of the suffix is in the body or in Debug output.
        for text in [json, format!("{check:?}"), format!("{request:?}")] {
            assert!(!text.contains("password"));
            assert!(!text.contains("1E4C9B93F3F0682250B6CF8331B7EE68FD8"));
            assert!(!text.contains("1E4C9"));
        }
    }

    #[test]
    fn verdicts() {
        let hit = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let other = "0018A45C4D1DEF81644B54AB7F969B88D65";
        let found = |range: &str| {
            let (check, _) = BreachCheck::start("password").unwrap();
            check.finish(&response(range))
        };
        assert_eq!(
            found(&format!("{other}:1\r\n{hit}:52256179")),
            BreachVerdict::Found { count: 52_256_179 }
        );
        assert_eq!(found(&format!("{other}:1")), BreachVerdict::NotFound);
        assert_eq!(found(""), BreachVerdict::NotFound);
        // A padded entry is not a breach.
        assert_eq!(found(&format!("{hit}:0")), BreachVerdict::NotFound);
    }

    #[test]
    fn nfc_forms_check_alike() {
        let (a, ra) = BreachCheck::start("caf\u{e9}").unwrap();
        let (b, rb) = BreachCheck::start("cafe\u{301}").unwrap();
        assert_eq!(ra, rb);
        assert_eq!(a.prefix(), b.prefix());
    }

    #[test]
    fn an_empty_password_is_not_checked() {
        assert_eq!(
            BreachCheck::start("").map(|_| ()),
            Err(ClientError::InvalidInput)
        );
    }
}
