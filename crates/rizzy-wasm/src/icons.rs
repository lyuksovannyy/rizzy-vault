// SPDX-License-Identifier: AGPL-3.0-only

//! Item icons across the boundary ([ADR 0052] point 6; `rizzy_client::icons`).
//!
//! ```text
//! IconFetch.forHost(summary.websiteHost)
//!   -> fetch.request()        POST /api/v1/icons/fetch {"host":"<A-label hostname>"}
//!                             no Authorization header, no other field
//!   -> fetch.finish(status, body) -> PNG bytes (Uint8Array)
//! ```
//!
//! - **The request is not a session request.** It carries the normalised hostname only and no
//!   bearer token; the `icons` role would not read one and must not learn who asks.
//! - **The answer** follows [ADR 0028] items 2–3: `200` with an `image/png` whose bytes start
//!   with the PNG signature, at most `MAX_ICON_PNG_LEN` bytes; anything else is the server's
//!   code (`server_not_found` when there is no icon or no `icons` role, `server_rate_limited`
//!   past the limit). The host hands the bytes to its image decoder as an image only (the web
//!   vault: a `blob:` URL in an `<img>`), never as markup.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md

use core::fmt;

use rizzy_client::icons::{icon_finish, icon_request};
use rizzy_client::rizzy_proto::http::paths::ICONS_FETCH;
use rizzy_client::rizzy_proto::icons::{IconFetchRequest, IconFetchResponse};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::{CoreError, CoreResult};
use crate::http::{HttpRequest, json};

/// One icon fetch for one hostname. `Debug` prints no host.
#[wasm_bindgen]
pub struct IconFetch {
    /// The checked request.
    request: IconFetchRequest,
}

impl fmt::Debug for IconFetch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IconFetch").finish_non_exhaustive()
    }
}

impl IconFetch {
    /// A fetch for `website_host`.
    pub(crate) fn of(website_host: &str) -> CoreResult<Self> {
        Ok(Self {
            request: icon_request(website_host)?,
        })
    }
}

#[wasm_bindgen]
impl IconFetch {
    /// A fetch for the host of an item's website (`ItemSummary.websiteHost`), normalised to
    /// its lowercase A-label form.
    ///
    /// # Errors
    /// `invalid_input` for a host that is not a usable hostname (an IP literal in brackets,
    /// empty, too long): nothing is to be sent for it.
    #[wasm_bindgen(js_name = forHost)]
    pub fn for_host(website_host: &str) -> Result<IconFetch, CoreError> {
        Self::of(website_host)
    }

    /// The normalised hostname the request carries, for the host's in-memory cache key.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn host(&self) -> String {
        self.request.host.as_str().to_owned()
    }

    /// The request: `POST /api/v1/icons/fetch`, the hostname as its only field, no
    /// `Authorization`.
    ///
    /// # Errors
    /// `internal` if the body cannot be serialised (never).
    pub fn request(&self) -> Result<HttpRequest, CoreError> {
        HttpRequest::post(ICONS_FETCH, &self.request, None)
    }

    /// Reads the answer: the PNG bytes.
    ///
    /// # Errors
    /// The server's code for a non-`200` answer; `invalid_server_response` for a body that
    /// is not an `image/png` PNG within the size limit.
    pub fn finish(&self, status: u16, body: &[u8]) -> Result<Vec<u8>, CoreError> {
        let response: IconFetchResponse = json(status, body)?;
        Ok(icon_finish(response)?)
    }
}

#[cfg(test)]
mod tests {
    //! The request carries the hostname only; answers and refusals.

    use super::*;

    #[test]
    fn the_request_is_the_host_without_a_session() {
        let fetch = IconFetch::for_host("Secret-Bank.Example.").unwrap();
        assert_eq!(fetch.host(), "secret-bank.example");
        let request = fetch.request().unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.path(), "/api/v1/icons/fetch");
        assert!(request.authorization().is_none());
        assert_eq!(
            request.body().unwrap(),
            br#"{"host":"secret-bank.example"}"#.to_vec()
        );
        assert!(!format!("{fetch:?}").contains("secret"));
        assert_eq!(
            IconFetch::for_host("[::1]").unwrap_err().as_str(),
            "invalid_input"
        );
    }

    #[test]
    fn answers_and_refusals() {
        let fetch = IconFetch::for_host("example.com").unwrap();
        let png = fetch
            .finish(
                200,
                br#"{"content_type":"image/png","data":"iVBORw0KGgoAAA"}"#,
            )
            .unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        for (status, body, code) in [
            (404, &br#"{"error":"not_found"}"#[..], "server_not_found"),
            (429, br#"{"error":"rate_limited"}"#, "server_rate_limited"),
            (500, br#"{"error":"internal"}"#, "server_internal"),
            (
                200,
                br#"{"content_type":"image/svg+xml","data":"iVBORw0KGgoAAA"}"#,
                "invalid_server_response",
            ),
            (
                200,
                br#"{"content_type":"image/png","data":"PHN2Zy8-"}"#,
                "invalid_server_response",
            ),
            (200, b"not json", "invalid_server_response"),
        ] {
            assert_eq!(fetch.finish(status, body).unwrap_err().as_str(), code);
        }
    }
}
