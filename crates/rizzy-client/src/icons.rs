// SPDX-License-Identifier: AGPL-3.0-only

//! Item icons, the client half ([ADR 0052] point 6; `rizzy_proto::icons`).
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

use rizzy_match::normalize::normalize_domain;
use rizzy_proto::icons::{IconFetchRequest, IconFetchResponse, IconHost};

use crate::error::ClientError;

/// The request for the icon of `website_host` (module docs).
///
/// # Errors
/// [`ClientError::InvalidInput`] for a host that does not normalise to RFC 1123 syntax.
pub fn icon_request(website_host: &str) -> Result<IconFetchRequest, ClientError> {
    let trimmed = website_host.trim();
    if trimmed.starts_with('[') {
        return Err(ClientError::InvalidInput);
    }
    let normalized = normalize_domain(trimmed).map_err(|_| ClientError::InvalidInput)?;
    let host = IconHost::parse(&normalized).map_err(|_| ClientError::InvalidInput)?;
    Ok(IconFetchRequest { host })
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
    //! Host normalisation and the answer check.

    use rizzy_proto::icons::{IconData, PNG_SIGNATURE};

    use super::*;

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
            let request = icon_request(input).unwrap();
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
                icon_request(input).map(|_| ()),
                Err(ClientError::InvalidInput),
                "{input:?}"
            );
        }
        let long = format!("{}.com", "a.".repeat(130));
        assert!(icon_request(&long).is_err());
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
