// SPDX-License-Identifier: AGPL-3.0-only

//! Item icons across the boundary ([ADR 0052] point 6; `rizzy_client::icons`), only under this
//! session's permit ([ADR 0099] §2–§4).
//!
//! ```text
//! session.websiteIcons()          the account's setting (ACCOUNT_SETTINGS tag 0x0005)
//! session.iconProbeRequest()      POST /api/v1/icons/fetch {"host":""}   (setting on, once)
//! session.iconProbeFinish(s, b)   "available" | "rate_limited" | "unavailable"
//! session.iconFetch(websiteHost)  -> fetch.request()  POST /api/v1/icons/fetch {"host":"<A-label>"}
//!                                 -> fetch.finish(status, body) -> PNG bytes (Uint8Array)
//! ```
//!
//! - **No permit, no request.** The `Session` holds the `IconPermit` the probe earned; it drops
//!   it on lock (with the session), when a settings read says off, and when this client turns
//!   the setting off. `iconFetch` and `iconProbeRequest` refuse with `icons_off` while the
//!   setting reads off; `iconFetch` refuses with `icons_off` too until the probe found the role.
//!   There is no other way to build an icon request: [`IconFetch::host_name`] only normalises.
//! - **The request is not a session request.** It carries the normalised hostname only and no
//!   bearer token; the `icons` role would not read one and must not learn who asks.
//! - **The answer** follows [ADR 0028] items 2–3: `200` with an `image/png` whose bytes start
//!   with the PNG signature, at most `MAX_ICON_PNG_LEN` bytes; anything else is the server's
//!   code (`server_not_found` when there is no icon, `server_rate_limited` past the limit). The
//!   host hands the bytes to its image decoder as an image only (the web vault: a `blob:` URL
//!   in an `<img>`), never as markup.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md
//! [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md

use core::fmt;

use rizzy_client::icons::{
    ICON_PROBE_MAX_ATTEMPTS, IconPermit, IconProbeOutcome, IconsSetting, icon_finish, icon_host,
    icon_probe_finish, icon_probe_request, icon_request,
};
use rizzy_client::rizzy_proto::http::paths::ICONS_FETCH;
use rizzy_client::rizzy_proto::icons::{IconFetchRequest, IconFetchResponse};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::error::{CoreError, CoreResult, ICONS_OFF, WRONG_STATE};
use crate::http::{HttpRequest, json, server_code};

/// One icon fetch for one hostname, built under the session's permit. `Debug` prints no host.
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

#[wasm_bindgen]
impl IconFetch {
    /// The hostname an icon request for `website_host` would carry (lowercase A-labels), or
    /// `undefined` when nothing would be sent for it. Builds no request.
    #[wasm_bindgen(js_name = hostName)]
    #[must_use]
    pub fn host_name(website_host: &str) -> Option<String> {
        icon_host(website_host).ok().map(|h| h.as_str().to_owned())
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

/// Where this session stands on icons (module docs): dropped with the session at lock.
#[derive(Debug, Default)]
pub(crate) enum IconsState {
    /// No probe sent since unlock or since the setting last read off.
    #[default]
    NotProbed,
    /// This many probes sent, the last one not yet answered or answered `rate_limited`.
    Probing(u8),
    /// The probe found the role: hosts may be sent.
    Available(IconPermit),
    /// The probe did not find the role: nothing more is sent this session.
    Unavailable,
}

impl IconsState {
    /// What the host shows: `off`, `unknown` (not probed yet), `available` or `unavailable`.
    pub(crate) fn status(&mut self, setting: IconsSetting) -> &'static str {
        if !setting.is_on() {
            *self = Self::NotProbed;
            return "off";
        }
        match self {
            Self::NotProbed | Self::Probing(_) => "unknown",
            Self::Available(_) => "available",
            Self::Unavailable => "unavailable",
        }
    }

    /// The probe request, or `icons_off` while the setting reads off (then nothing is sent);
    /// `wrong_state` once the outcome is known or every attempt was sent.
    pub(crate) fn probe_request(&mut self, setting: IconsSetting) -> CoreResult<HttpRequest> {
        let Some(body) = icon_probe_request(setting) else {
            *self = Self::NotProbed;
            return Err(CoreError::new(ICONS_OFF));
        };
        let sent = match self {
            Self::NotProbed => 0,
            Self::Probing(n) if *n < ICON_PROBE_MAX_ATTEMPTS => *n,
            _ => return Err(CoreError::new(WRONG_STATE)),
        };
        *self = Self::Probing(sent.saturating_add(1));
        Ok(HttpRequest::post_bytes(ICONS_FETCH, body))
    }

    /// Reads a probe answer; a `rate_limited` answer after the last attempt reads unavailable.
    pub(crate) fn probe_finish(
        &mut self,
        setting: IconsSetting,
        status: u16,
        body: &[u8],
    ) -> CoreResult<&'static str> {
        let Self::Probing(sent) = *self else {
            return Err(CoreError::new(WRONG_STATE));
        };
        if !setting.is_on() {
            *self = Self::NotProbed;
            return Err(CoreError::new(ICONS_OFF));
        }
        Ok(
            match icon_probe_finish(status, server_code(status, body), setting) {
                IconProbeOutcome::Available(permit) => {
                    *self = Self::Available(permit);
                    "available"
                }
                IconProbeOutcome::RateLimited if sent < ICON_PROBE_MAX_ATTEMPTS => "rate_limited",
                IconProbeOutcome::RateLimited | IconProbeOutcome::Unavailable => {
                    *self = Self::Unavailable;
                    "unavailable"
                }
            },
        )
    }

    /// An icon fetch under the permit, or `icons_off` without one (setting off, or the role not
    /// found yet); `invalid_input` for a host that is not a usable hostname.
    pub(crate) fn fetch(
        &mut self,
        setting: IconsSetting,
        website_host: &str,
    ) -> CoreResult<IconFetch> {
        if !setting.is_on() {
            *self = Self::NotProbed;
            return Err(CoreError::new(ICONS_OFF));
        }
        let Self::Available(permit) = self else {
            return Err(CoreError::new(ICONS_OFF));
        };
        Ok(IconFetch {
            request: icon_request(permit, website_host)?,
        })
    }

    /// The setting was turned off here: the permit and any probe go.
    pub(crate) fn turn_off(&mut self) {
        *self = Self::NotProbed;
    }
}

#[cfg(test)]
mod tests {
    //! The permit's life in a session; the request carries the hostname only; answers.

    use rizzy_client::settings::AccountSettingsRecord;

    use super::*;

    const INVALID: &[u8] = br#"{"error":"invalid_request"}"#;
    const LIMITED: &[u8] = br#"{"error":"rate_limited"}"#;

    fn on() -> IconsSetting {
        AccountSettingsRecord::default().website_icons()
    }

    fn off() -> IconsSetting {
        IconsSetting::from_read(Err(rizzy_client::ClientError::InvalidServerResponse))
    }

    fn available() -> IconsState {
        let mut state = IconsState::default();
        state.probe_request(on()).unwrap();
        assert_eq!(state.probe_finish(on(), 400, INVALID).unwrap(), "available");
        state
    }

    #[test]
    fn nothing_is_sent_while_off_not_even_the_probe() {
        let mut state = IconsState::default();
        assert_eq!(state.status(off()), "off");
        assert_eq!(
            state.probe_request(off()).unwrap_err().as_str(),
            "icons_off"
        );
        assert_eq!(
            state.fetch(off(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
        // On, but not probed yet: no host either.
        assert_eq!(state.status(on()), "unknown");
        assert_eq!(
            state.fetch(on(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
    }

    #[test]
    fn the_probe_is_the_empty_host_without_a_session() {
        let mut state = IconsState::default();
        let request = state.probe_request(on()).unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.path(), "/api/v1/icons/fetch");
        assert!(request.authorization().is_none());
        assert_eq!(request.body().unwrap(), br#"{"host":""}"#.to_vec());
        // One probe in flight: no second, no host.
        assert_eq!(
            state.fetch(on(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
    }

    #[test]
    fn a_role_that_is_off_keeps_every_host() {
        let mut state = IconsState::default();
        state.probe_request(on()).unwrap();
        let not_found = br#"{"error":"not_found"}"#;
        assert_eq!(
            state.probe_finish(on(), 404, not_found).unwrap(),
            "unavailable"
        );
        assert_eq!(state.status(on()), "unavailable");
        assert_eq!(
            state.fetch(on(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
        // The outcome holds: no second probe this session.
        assert_eq!(
            state.probe_request(on()).unwrap_err().as_str(),
            "wrong_state"
        );
    }

    #[test]
    fn rate_limited_probes_stop_after_three_attempts() {
        let mut state = IconsState::default();
        for _ in 0..2 {
            state.probe_request(on()).unwrap();
            assert_eq!(
                state.probe_finish(on(), 429, LIMITED).unwrap(),
                "rate_limited"
            );
        }
        state.probe_request(on()).unwrap();
        assert_eq!(
            state.probe_finish(on(), 429, LIMITED).unwrap(),
            "unavailable"
        );
        assert_eq!(
            state.probe_request(on()).unwrap_err().as_str(),
            "wrong_state"
        );
    }

    #[test]
    fn turning_off_drops_the_permit_and_on_again_probes_again() {
        let mut state = available();
        assert_eq!(state.status(on()), "available");
        state.fetch(on(), "example.com").unwrap();
        // A settings read that says off drops the permit at once.
        assert_eq!(
            state.fetch(off(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
        assert_eq!(
            state.fetch(on(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
        let mut state = available();
        state.turn_off();
        assert_eq!(
            state.fetch(on(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
        // Back on: one more probe before any host.
        state.probe_request(on()).unwrap();
        assert_eq!(state.probe_finish(on(), 400, INVALID).unwrap(), "available");
        // An answer that arrives after the setting went off makes no permit.
        let mut state = IconsState::default();
        state.probe_request(on()).unwrap();
        assert_eq!(
            state
                .probe_finish(off(), 400, INVALID)
                .unwrap_err()
                .as_str(),
            "icons_off"
        );
        assert_eq!(
            state.fetch(on(), "example.com").unwrap_err().as_str(),
            "icons_off"
        );
    }

    #[test]
    fn the_request_is_the_host_without_a_session() {
        let mut state = available();
        let fetch = state.fetch(on(), "Secret-Bank.Example.").unwrap();
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
            state.fetch(on(), "[::1]").unwrap_err().as_str(),
            "invalid_input"
        );
        assert_eq!(
            IconFetch::host_name("WWW.Example.COM.").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(IconFetch::host_name("[::1]"), None);
    }

    #[test]
    fn answers_and_refusals() {
        let fetch = available().fetch(on(), "example.com").unwrap();
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
