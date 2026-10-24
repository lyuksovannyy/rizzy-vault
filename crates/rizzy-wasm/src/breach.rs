// SPDX-License-Identifier: AGPL-3.0-only

//! The breach check across the boundary (CRYPTO.md §11.16; ADR 0053; `rizzy_client::breach`).
//!
//! ```text
//! BreachCheck.forPassword(bytes) | session.breachCheckItem(id)
//!   → check.request()          POST /api/v1/icons/breach-range {"prefix":"XXXXX"}
//!                               no Authorization header, no other field (INV-77)
//!   → check.finish(status, body) → BreachVerdict { found, count }
//! ```
//!
//! - **The password never crosses back.** A password the user typed or generated comes in as
//!   UTF-8 bytes that are wiped ([`crate::secret`]); an item's password is read inside the
//!   core ([`crate::Session::breach_check_item`]) and never crosses at all. Only the 5-character
//!   prefix goes out, in the request body, and through [`BreachCheck::prefix`] so the host can
//!   reuse one answer for checks that share a prefix.
//! - **The request is not a session request.** It carries no bearer token: the `icons` role
//!   would not read one, and INV-77 wants no identity sent.
//! - **Answers** follow [ADR 0028] items 2–3: `200` with the range, parsed and bounded by
//!   `rizzy-proto`; anything else is the server's code (`server_not_found` when the breach check
//!   is off, `server_rate_limited` past the limit, `server_internal` when the upstream failed).
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use core::fmt;

use rizzy_client::breach::{BreachCheck as ClientCheck, BreachVerdict as ClientVerdict};
use rizzy_client::rizzy_proto::breach::{BreachRangeRequest, BreachRangeResponse};
use rizzy_client::rizzy_proto::http::paths::ICONS_BREACH_RANGE;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::{CoreError, CoreResult, WRONG_STATE};
use crate::http::{HttpRequest, json};
use crate::secret::take_secret;

/// One breach check: the candidate's digest inside the core, wiped when freed or finished.
#[wasm_bindgen]
pub struct BreachCheck {
    /// The client check; `None` once finished.
    check: Option<ClientCheck>,
    /// The request body: the prefix only.
    request: BreachRangeRequest,
}

impl fmt::Debug for BreachCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BreachCheck")
            .field("finished", &self.check.is_none())
            .finish_non_exhaustive()
    }
}

impl BreachCheck {
    /// A check of `password`.
    pub(crate) fn of(password: &str) -> CoreResult<Self> {
        let (check, request) = ClientCheck::start(password)?;
        Ok(Self {
            check: Some(check),
            request,
        })
    }
}

#[wasm_bindgen]
impl BreachCheck {
    /// A check of a password the user typed or generated, passed as UTF-8 bytes; the array
    /// holds zeroes when this returns.
    ///
    /// # Errors
    /// `invalid_input` for bytes that are not UTF-8 or an empty password.
    #[wasm_bindgen(js_name = forPassword)]
    pub fn for_password(password: &mut [u8]) -> Result<BreachCheck, CoreError> {
        let password = take_secret(password)?;
        Self::of(&password)
    }

    /// The 5 uppercase hex characters the request carries (and nothing more of the digest).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn prefix(&self) -> String {
        self.request.prefix.as_str().to_owned()
    }

    /// The request: `POST /api/v1/icons/breach-range`, the prefix as its only field, no
    /// `Authorization`.
    ///
    /// # Errors
    /// `internal` if the body cannot be serialised (never).
    pub fn request(&self) -> Result<HttpRequest, CoreError> {
        HttpRequest::post(ICONS_BREACH_RANGE, &self.request, None)
    }

    /// Reads the answer and wipes the digest. A second call is `wrong_state`.
    ///
    /// # Errors
    /// The server's code for a non-`200` answer; `invalid_server_response` for a body that is
    /// not a range; `wrong_state` after a first call.
    pub fn finish(&mut self, status: u16, body: &[u8]) -> Result<BreachVerdict, CoreError> {
        let check = self
            .check
            .take()
            .ok_or_else(|| CoreError::new(WRONG_STATE))?;
        let response: BreachRangeResponse = json(status, body)?;
        Ok(match check.finish(&response) {
            ClientVerdict::NotFound => BreachVerdict { count: 0 },
            ClientVerdict::Found { count } => BreachVerdict { count },
        })
    }
}

/// The outcome of a [`BreachCheck`]: advice from the upstream, relayed by a server the threat
/// model does not trust (`rizzy_client::breach` module docs).
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreachVerdict {
    /// Sightings; `0` when not found.
    count: u64,
}

#[wasm_bindgen]
impl BreachVerdict {
    /// Whether the password appeared in the upstream's breach corpus.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn found(&self) -> bool {
        self.count > 0
    }

    /// How often it appeared, saturated at `u32::MAX`; `0` when not found.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn count(&self) -> u32 {
        u32::try_from(self.count).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests {
    //! The request carries the prefix only, the bytes are wiped, the verdicts and refusals.

    use super::*;

    const HIT: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    fn check(password: &str) -> BreachCheck {
        let mut bytes = password.as_bytes().to_vec();
        let check = BreachCheck::for_password(&mut bytes).unwrap();
        assert!(bytes.iter().all(|b| *b == 0), "the array is wiped");
        check
    }

    #[test]
    fn the_request_is_the_prefix_without_a_session() {
        let check = check("password");
        assert_eq!(check.prefix(), "5BAA6");
        let request = check.request().unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.path(), "/api/v1/icons/breach-range");
        assert!(request.authorization().is_none());
        assert_eq!(request.body().unwrap(), br#"{"prefix":"5BAA6"}"#.to_vec());
        assert!(!format!("{check:?}").contains("5BAA6"));
    }

    #[test]
    fn verdicts_and_refusals() {
        let found = format!(r#"{{"range":"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{HIT}:42"}}"#);
        let mut c = check("password");
        let verdict = c.finish(200, found.as_bytes()).unwrap();
        assert!(verdict.found());
        assert_eq!(verdict.count(), 42);
        assert_eq!(
            c.finish(200, found.as_bytes()).unwrap_err().as_str(),
            "wrong_state"
        );

        let mut c = check("password");
        let verdict = c.finish(200, br#"{"range":""}"#).unwrap();
        assert!(!verdict.found());
        assert_eq!(verdict.count(), 0);

        for (status, body, code) in [
            (404, &br#"{"error":"not_found"}"#[..], "server_not_found"),
            (429, br#"{"error":"rate_limited"}"#, "server_rate_limited"),
            (500, br#"{"error":"internal"}"#, "server_internal"),
            (200, br#"{"range":"<html>"}"#, "invalid_server_response"),
            (200, b"not json", "invalid_server_response"),
        ] {
            let mut c = check("password");
            assert_eq!(c.finish(status, body).unwrap_err().as_str(), code);
        }
        let mut empty = Vec::new();
        assert_eq!(
            BreachCheck::for_password(&mut empty).unwrap_err().as_str(),
            "invalid_input"
        );
        let mut not_utf8 = vec![0xff, 0xfe];
        assert_eq!(
            BreachCheck::for_password(&mut not_utf8)
                .unwrap_err()
                .as_str(),
            "invalid_input"
        );
    }
}
