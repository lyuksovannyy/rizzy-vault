// SPDX-License-Identifier: AGPL-3.0-only

//! Item icons, the client half ([ADR 0052] point 6; `rizzy_proto::icons`), and the rule that
//! keeps every host on the device unless the account's website-icons setting reads on and this
//! session's probe found the `icons` role ([ADR 0099] §2–§4).
//!
//! ```text
//! verified settings record ──▶ IconsSetting (tag 0x0005; absent = on; unreadable = off)
//! setting on ──▶ icon_probe_request ── {"host":""} ──▶ icons/fetch     (once per session)
//! status, body ──▶ icon_probe_finish ──▶ Available(IconPermit) | RateLimited | Unavailable
//! ```
//!
//! - **No permit, no request.** [`IconPermit`] has a private constructor; only
//!   [`icon_probe_finish`] makes one, for a `400 invalid_request` answer (the role is there and
//!   refused the empty host) while the setting reads on. [`icon_request`] needs a permit. While
//!   the setting reads off, or before the settings record is loaded and verified (the caller has
//!   no [`IconsSetting`] to pass), [`icon_probe_request`] gives no probe either.
//! - **The probe** is `POST /api/v1/icons/fetch` with the 11-byte body `{"host":""}`, the same
//!   headers as an icon fetch. `404 not_found` (no role), any other code, a `2xx`, a `5xx` or a
//!   transport failure read **unavailable**; `429 rate_limited` waits ([`ICON_PROBE_PAUSE_SECS`]
//!   or `Retry-After`) and tries again, at most [`ICON_PROBE_MAX_ATTEMPTS`] in all.
//!
//! ```text
//! icon_request(website host) ── IconFetchRequest { host } ──▶ host ──▶ icons/fetch
//!                                (no session, no Authorization header, nothing else)
//! host ── status, body ──▶ icon_finish ──▶ PNG bytes for the host's own image decoder
//! ```
//!
//! - **Only a hostname leaves the device.** [`icon_request`] takes the host of an item's
//!   website (already split from its URL, never the URL itself) and normalises it: IDNA
//!   A-labels, lowercase, no trailing dot (`rizzy_match::normalize::normalize_domain`). A host
//!   that does not normalise to RFC 1123 syntax (an IP literal in brackets, an empty or
//!   oversized value) is refused, so nothing is sent for it. The request carries no account,
//!   session or item identifier and is sent without a bearer token.
//! - **The answer is untrusted** ([`icon_finish`]): its length was bounded when it was parsed;
//!   the content type must be `image/png` and the bytes must start with the PNG signature. The
//!   pixels are left to the host's decoder: the web vault and the extension hand the bytes to
//!   the browser as a `blob:` image, never as markup and never as a `data:` URL; a native
//!   client decodes them in safe Rust ([ADR 0019] §5.1).
//!
//! [ADR 0019]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0019-native-clients.md
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md
//! [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md

use rizzy_match::normalize::normalize_domain;
use rizzy_proto::error::ErrorCode;
use rizzy_proto::icons::{IconFetchRequest, IconFetchResponse, IconHost};

use crate::error::ClientError;
use crate::settings::AccountSettingsRecord;

/// The account's website-icons setting ([ADR 0099] §1), as read from its `ACCOUNT_SETTINGS`
/// record: tag `0x0005` = `0x01` or an absent tag (or an absent record) reads on, `0x00` reads
/// off. Made only from a decoded record ([`AccountSettingsRecord::website_icons`]) or from a
/// read that failed ([`IconsSetting::from_read`], which reads off).
///
/// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IconsSetting {
    /// Whether the setting reads on.
    on: bool,
}

impl IconsSetting {
    /// The setting with the value `on` (for the record's accessor).
    pub(crate) const fn of(on: bool) -> Self {
        Self { on }
    }

    /// The setting of a settings read ([`crate::settings::SettingsCache::get`] or
    /// [`crate::settings::account_settings`]): the record's value, or **off** when the record was
    /// rejected or parked (`settings_update_required`), or its tag `0x0005` could not be read. The
    /// client never falls back to the default, which is the wider one, when the record it cannot
    /// read may hold an explicit `0x00` ([ADR 0099] §1 "Reading").
    ///
    /// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
    #[must_use]
    pub fn from_read(read: Result<&AccountSettingsRecord, ClientError>) -> Self {
        read.map_or(Self::of(false), AccountSettingsRecord::website_icons)
    }

    /// Whether the setting reads on.
    #[must_use]
    pub const fn is_on(self) -> bool {
        self.on
    }
}

/// The probe's body, exactly these 11 bytes ([ADR 0099] §3).
///
/// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
pub const ICON_PROBE_BODY: &[u8; 11] = br#"{"host":""}"#;
/// The most probe requests one session sends, the first one included ([ADR 0099] §3).
///
/// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
pub const ICON_PROBE_MAX_ATTEMPTS: u8 = 3;
/// The pause after a `429` probe answer without a `Retry-After` value, in seconds.
pub const ICON_PROBE_PAUSE_SECS: u32 = 4;

/// Leave to send host names to `icons/fetch` in this session ([ADR 0099] §4): the setting read
/// on and the probe found the role. No public constructor: only [`icon_probe_finish`] makes
/// one. Not `Clone`: a host holds the one it got and drops it on lock or when the setting reads
/// off.
///
/// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
#[derive(Debug, PartialEq, Eq)]
pub struct IconPermit {
    /// Keeps the constructor private.
    _sealed: (),
}

/// What one probe answer means ([ADR 0099] §3 "Outcome").
///
/// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
#[derive(Debug, PartialEq, Eq)]
pub enum IconProbeOutcome {
    /// `400 invalid_request`: the role is there; hosts may be sent this session.
    Available(IconPermit),
    /// `429 rate_limited`: wait (`Retry-After`, or [`ICON_PROBE_PAUSE_SECS`]) and probe again,
    /// if fewer than [`ICON_PROBE_MAX_ATTEMPTS`] probes were sent; otherwise unavailable.
    RateLimited,
    /// Anything else: no host is sent this session.
    Unavailable,
}

/// The probe's body, or `None` while the setting reads off: then nothing is sent at all, not
/// even the probe ([ADR 0099] §2). A caller that has not loaded and verified the account's
/// settings record has no [`IconsSetting`] to pass, so it cannot probe either.
///
/// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
#[must_use]
pub const fn icon_probe_request(setting: IconsSetting) -> Option<&'static [u8; 11]> {
    if setting.is_on() {
        Some(ICON_PROBE_BODY)
    } else {
        None
    }
}

/// Reads the probe's answer ([ADR 0099] §3), and makes the [`IconPermit`] for an "available"
/// answer while `setting` reads on. `error` is the answer's `/api/v1` error code as the host's
/// transport parsed it (`None` for a body that is not an error answer, or for a transport
/// failure). A `400` whose code is not `invalid_request`, a `429` that is not `rate_limited`
/// and every other status read unavailable.
///
/// [ADR 0099]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0099-website-icons-opt-in.md
#[must_use]
pub const fn icon_probe_finish(
    status: u16,
    error: Option<ErrorCode>,
    setting: IconsSetting,
) -> IconProbeOutcome {
    if !setting.is_on() {
        return IconProbeOutcome::Unavailable;
    }
    match (status, error) {
        (400, Some(ErrorCode::InvalidRequest)) => {
            IconProbeOutcome::Available(IconPermit { _sealed: () })
        }
        (429, Some(ErrorCode::RateLimited)) => IconProbeOutcome::RateLimited,
        _ => IconProbeOutcome::Unavailable,
    }
}

/// The request for the icon of `website_host` (module docs), under this session's permit.
///
/// # Errors
/// [`ClientError::InvalidInput`] for a host that does not normalise to RFC 1123 syntax.
pub fn icon_request(
    _permit: &IconPermit,
    website_host: &str,
) -> Result<IconFetchRequest, ClientError> {
    Ok(IconFetchRequest {
        host: icon_host(website_host)?,
    })
}

/// The normalised host an icon request for `website_host` would carry (lowercase A-labels),
/// for a host's in-memory cache key. Builds no request.
///
/// # Errors
/// [`ClientError::InvalidInput`] for a host that does not normalise to RFC 1123 syntax.
pub fn icon_host(website_host: &str) -> Result<IconHost, ClientError> {
    let trimmed = website_host.trim();
    if trimmed.starts_with('[') {
        return Err(ClientError::InvalidInput);
    }
    let normalized = normalize_domain(trimmed).map_err(|_| ClientError::InvalidInput)?;
    IconHost::parse(&normalized).map_err(|_| ClientError::InvalidInput)
}

/// Checks an `icons/fetch` answer and returns its PNG bytes (module docs).
///
/// # Errors
/// [`ClientError::InvalidServerResponse`] for a content type other than `image/png` or bytes
/// that are not a PNG.
pub fn icon_finish(response: IconFetchResponse) -> Result<Vec<u8>, ClientError> {
    response
        .check()
        .map_err(|_| ClientError::InvalidServerResponse)?;
    Ok(response.data.into_vec())
}

#[cfg(test)]
mod tests {
    //! The permit and the probe, host normalisation and the answer check.

    use rizzy_proto::icons::{IconData, PNG_SIGNATURE};

    use super::*;

    const ON: IconsSetting = IconsSetting::of(true);
    const OFF: IconsSetting = IconsSetting::of(false);

    /// A permit, made the only way there is: an "available" probe answer while on.
    fn permit() -> IconPermit {
        match icon_probe_finish(400, Some(ErrorCode::InvalidRequest), ON) {
            IconProbeOutcome::Available(p) => p,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_probe_is_the_eleven_byte_empty_host_and_only_while_on() {
        assert_eq!(icon_probe_request(ON), Some(br#"{"host":""}"#));
        assert_eq!(ICON_PROBE_BODY.len(), 11);
        assert_eq!(icon_probe_request(OFF), None);
        // The empty host is the one the role refuses with invalid_request: no real host.
        assert!(icon_host("").is_err());
    }

    #[test]
    fn only_a_400_invalid_request_while_on_makes_a_permit() {
        let invalid = Some(ErrorCode::InvalidRequest);
        assert!(matches!(
            icon_probe_finish(400, invalid, ON),
            IconProbeOutcome::Available(_)
        ));
        // Off: no permit, whatever the server says.
        assert_eq!(
            icon_probe_finish(400, invalid, OFF),
            IconProbeOutcome::Unavailable
        );
        assert_eq!(
            icon_probe_finish(429, Some(ErrorCode::RateLimited), ON),
            IconProbeOutcome::RateLimited
        );
        for (status, error) in [
            (404, Some(ErrorCode::NotFound)),
            (400, Some(ErrorCode::PayloadTooLarge)),
            (400, None),
            (429, None),
            (200, invalid),
            (204, None),
            (500, Some(ErrorCode::Internal)),
            (502, None),
            (0, None),
        ] {
            assert_eq!(
                icon_probe_finish(status, error, ON),
                IconProbeOutcome::Unavailable,
                "{status}"
            );
        }
    }

    #[test]
    fn a_settings_record_gives_the_setting_and_an_unreadable_one_reads_off() {
        use crate::settings::AccountSettingsRecord;
        assert!(AccountSettingsRecord::default().website_icons().is_on());
        assert!(!IconsSetting::from_read(Err(ClientError::InvalidServerResponse)).is_on());
        assert!(!IconsSetting::from_read(Err(ClientError::SettingsUpdateRequired)).is_on());
        assert!(!IconsSetting::from_read(Err(ClientError::AccountKeyRotated)).is_on());
    }

    #[test]
    fn hosts_are_normalised_to_a_labels() {
        for (input, want) in [
            ("example.com", "example.com"),
            ("WWW.Example.COM", "www.example.com"),
            ("example.com.", "example.com"),
            ("  example.com ", "example.com"),
            ("b\u{fc}cher.de", "xn--bcher-kva.de"),
            ("1.2.3.4", "1.2.3.4"),
        ] {
            let request = icon_request(&permit(), input).unwrap();
            assert_eq!(request.host.as_str(), want, "{input}");
            assert_eq!(
                serde_json::to_string(&request).unwrap(),
                format!(r#"{{"host":"{want}"}}"#)
            );
        }
    }

    #[test]
    fn unusable_hosts_send_nothing() {
        for input in [
            "",
            " ",
            "[::1]",
            "exa mple.com",
            "a/b",
            "user@example.com",
            "a_b.com",
        ] {
            assert_eq!(
                icon_request(&permit(), input).map(|_| ()),
                Err(ClientError::InvalidInput),
                "{input:?}"
            );
        }
        let long = format!("{}.com", "a.".repeat(130));
        assert!(icon_request(&permit(), &long).is_err());
    }

    #[test]
    fn answers_are_checked() {
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend_from_slice(b"...");
        let good = IconFetchResponse::png(IconData::new(png.clone()).unwrap());
        assert_eq!(icon_finish(good).unwrap(), png);
        let wrong_type = IconFetchResponse {
            content_type: "image/svg+xml".to_owned(),
            data: IconData::new(png).unwrap(),
        };
        assert_eq!(
            icon_finish(wrong_type),
            Err(ClientError::InvalidServerResponse)
        );
        let not_png = IconFetchResponse::png(IconData::new(b"<svg/>".to_vec()).unwrap());
        assert_eq!(
            icon_finish(not_png),
            Err(ClientError::InvalidServerResponse)
        );
    }
}
