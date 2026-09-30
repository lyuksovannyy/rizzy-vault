//! The HTTP conventions of `/api/v1` that the server and every client share ([ADR 0028] items
//! 1, 4 and 5): the endpoint paths, the bearer-token header and the two request-signing
//! headers.
//!
//! This module holds constants only. [ADR 0028] is the owner of what they mean; the server's
//! parsers (`rizzy-server`, `http::headers`) and the clients' request builders both read them
//! from here, so the two sides cannot drift apart. The body limits of item 7 are in
//! [`crate::limits`]; `GET /api/meta` and the `Rizzy-Client` header of item 14 are in
//! [`crate::meta`].
//!
//! # Paths and methods (item 1)
//!
//! The 27 endpoints of [`paths`], all under [`crate::meta::API_V1_PREFIX`]. Every one is `POST`
//! except [`paths::DEVICES_GRANTS`], which is `GET` (and `HEAD`); `GET /api/meta` is the one
//! unversioned endpoint. A request body never goes in a URL, and `v1` defines no query
//! parameter, so a client sends no query.
//!
//! # Bearer token (item 4)
//!
//! `Authorization: Bearer <token>`, the token as the [`BEARER_TOKEN_CHARS`] base64url characters
//! of its 32 bytes. The scheme name is matched case-insensitively; nothing else is accepted,
//! and the token never travels in a query parameter or a cookie (threat model INV-52).
//!
//! # Request signing (item 5)
//!
//! A request over a device-authenticated session carries both headers, any other request
//! neither:
//! - [`REQUEST_COUNTER_HEADER`]: the `u64` `request_counter` in decimal, 1 to
//!   [`MAX_REQUEST_COUNTER_DIGITS`] digits, no sign, no leading zero (`0` alone is valid);
//! - [`REQUEST_SIGNATURE_HEADER`]: the 82-byte `device-request` signature container as
//!   [`REQUEST_SIGNATURE_CHARS`] base64url characters.
//!
//! **The signed bytes.** `method` is the request method as sent, in upper case.
//! `path_and_query` is the raw bytes of the origin-form request-target on the request line: the
//! path and, when a `?` is present, the `?` and everything after it. Neither side parses,
//! decodes, normalises or re-encodes them before signing or verifying. Clients send origin-form
//! only, and never a fragment: a `#` is no part of a request-target, and the server's HTTP
//! library drops it and what follows before verification, so a signature over a target with a
//! fragment fails. CRYPTO.md §5.10 and the `device-request` row of §10.2 own the signed message and the
//! counter rule.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use crate::limits::SIGNATURE_CONTAINER_LEN;
use crate::wire::{SessionToken, b64url_len};

/// The authentication scheme of the `Authorization` header ([ADR 0028] item 4), matched
/// case-insensitively by the server.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const BEARER_SCHEME: &str = "Bearer";

/// The length of a bearer token in the `Authorization` header: 43 base64url characters for its
/// 32 bytes ([ADR 0028] item 4; CRYPTO.md §5.10, §9.6).
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const BEARER_TOKEN_CHARS: usize = b64url_len(SessionToken::LEN);

/// The request header of the `request_counter` ([ADR 0028] item 5).
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const REQUEST_COUNTER_HEADER: &str = "Rizzy-Request-Counter";

/// The request header of the `device-request` signature container ([ADR 0028] item 5).
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub const REQUEST_SIGNATURE_HEADER: &str = "Rizzy-Request-Signature";

/// The most decimal digits of a `request_counter` header value: `u64::MAX` has 20.
pub const MAX_REQUEST_COUNTER_DIGITS: usize = 20;

/// The length of the signature header's value: 110 base64url characters for the 82-byte
/// container (CRYPTO.md §9.3, §9.6).
pub const REQUEST_SIGNATURE_CHARS: usize = b64url_len(SIGNATURE_CONTAINER_LEN);

pub mod paths {
    //! The path of every `/api/v1` endpoint ([ADR 0028] item 1), grouped by resource, verb
    //! last. The server's router matches them byte for byte: a trailing slash, `//`, a dot
    //! segment or a percent-encoded octet is `404 not_found`.
    //!
    //! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

    /// Signup, OPAQUE registration start.
    pub const REGISTER_START: &str = "/api/v1/register/start";
    /// Signup commit.
    pub const REGISTER_FINISH: &str = "/api/v1/register/finish";
    /// Login, KE1 → KE2.
    pub const LOGIN_START: &str = "/api/v1/login/start";
    /// Login, KE3 → session.
    pub const LOGIN_FINISH: &str = "/api/v1/login/finish";
    /// Device authentication, the challenge.
    pub const DEVICE_AUTH_START: &str = "/api/v1/device-auth/start";
    /// Device authentication, the signature.
    pub const DEVICE_AUTH_FINISH: &str = "/api/v1/device-auth/finish";
    /// The unlock's account view.
    pub const ACCOUNT_STATE: &str = "/api/v1/account/state";
    /// OPAQUE re-registration start.
    pub const ACCOUNT_REREGISTER_START: &str = "/api/v1/account/reregister/start";
    /// The atomic commit of a credential, settings, device or key-rotation change.
    pub const ACCOUNT_COMMIT: &str = "/api/v1/account/commit";
    /// Enrolment of a durable device.
    pub const DEVICES_ENROL: &str = "/api/v1/devices/enrol";
    /// The web vault's kind-4 certificate.
    pub const DEVICES_WEB_CERTIFICATE: &str = "/api/v1/devices/web-certificate";
    /// Pending device grants. The one `GET` (and `HEAD`) endpoint of `v1`.
    pub const DEVICES_GRANTS: &str = "/api/v1/devices/grants";
    /// Grant acknowledgement.
    pub const DEVICES_GRANTS_ACK: &str = "/api/v1/devices/grants/ack";
    /// Revocation phase 1: suspension.
    pub const DEVICES_SUSPEND: &str = "/api/v1/devices/suspend";
    /// Lifting a suspension.
    pub const DEVICES_UNSUSPEND: &str = "/api/v1/devices/unsuspend";
    /// Healing step 1: the bundles.
    pub const HEALING_BUNDLES: &str = "/api/v1/healing/bundles";
    /// Healing step 2: the account state.
    pub const HEALING_ACCOUNT_STATE: &str = "/api/v1/healing/account-state";
    /// Healing step 3: the grants.
    pub const HEALING_GRANTS: &str = "/api/v1/healing/grants";
    /// Recovery start.
    pub const RECOVERY_START: &str = "/api/v1/recovery/start";
    /// Recovery cancel, by a device.
    pub const RECOVERY_CANCEL: &str = "/api/v1/recovery/cancel";
    /// Recovery complete.
    pub const RECOVERY_COMPLETE: &str = "/api/v1/recovery/complete";
    /// TOTP enrolment start.
    pub const TOTP_ENROL_START: &str = "/api/v1/totp/enrol/start";
    /// TOTP enrolment confirmation.
    pub const TOTP_ENROL_CONFIRM: &str = "/api/v1/totp/enrol/confirm";
    /// TOTP removal.
    pub const TOTP_DISABLE: &str = "/api/v1/totp/disable";
    /// Vault upload.
    pub const VAULT_UPLOAD: &str = "/api/v1/vault/upload";
    /// Vault Fetch.
    pub const VAULT_FETCH: &str = "/api/v1/vault/fetch";
    /// Vault restore healing.
    pub const VAULT_HEAL: &str = "/api/v1/vault/heal";

    /// Every `/api/v1` path, in the order above.
    pub const ALL: [&str; 27] = [
        REGISTER_START,
        REGISTER_FINISH,
        LOGIN_START,
        LOGIN_FINISH,
        DEVICE_AUTH_START,
        DEVICE_AUTH_FINISH,
        ACCOUNT_STATE,
        ACCOUNT_REREGISTER_START,
        ACCOUNT_COMMIT,
        DEVICES_ENROL,
        DEVICES_WEB_CERTIFICATE,
        DEVICES_GRANTS,
        DEVICES_GRANTS_ACK,
        DEVICES_SUSPEND,
        DEVICES_UNSUSPEND,
        HEALING_BUNDLES,
        HEALING_ACCOUNT_STATE,
        HEALING_GRANTS,
        RECOVERY_START,
        RECOVERY_CANCEL,
        RECOVERY_COMPLETE,
        TOTP_ENROL_START,
        TOTP_ENROL_CONFIRM,
        TOTP_DISABLE,
        VAULT_UPLOAD,
        VAULT_FETCH,
        VAULT_HEAL,
    ];
}

#[cfg(test)]
mod tests {
    //! The constants against ADR 0028's numbers and path rules.

    use super::*;
    use crate::meta::API_V1_PREFIX;

    #[test]
    fn header_forms() {
        assert_eq!(BEARER_TOKEN_CHARS, 43);
        assert_eq!(REQUEST_SIGNATURE_CHARS, 110);
        assert_eq!(u64::MAX.to_string().len(), MAX_REQUEST_COUNTER_DIGITS);
        for name in [REQUEST_COUNTER_HEADER, REQUEST_SIGNATURE_HEADER] {
            assert!(name.starts_with("Rizzy-"), "{name}");
        }
    }

    #[test]
    fn paths_are_unique_literal_and_under_the_prefix() {
        let mut sorted = paths::ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 27);
        for path in paths::ALL {
            assert!(path.starts_with(API_V1_PREFIX), "{path}");
            // Nothing a proxy or a URL library would rewrite, and no query.
            assert!(!path.ends_with('/') && !path.contains("//"), "{path}");
            assert!(
                path.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'/'
                    || b == b'-'),
                "{path}"
            );
        }
    }
}
