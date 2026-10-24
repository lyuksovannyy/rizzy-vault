// SPDX-License-Identifier: AGPL-3.0-only

//! `WebAuthn` security keys as a server-side second factor ([ADR 0058] as amended by [ADR 0077];
//! CRYPTO.md §11.17).
//!
//! | Flow step | Endpoint | Request | Response | Caller |
//! |---|---|---|---|---|
//! | Enrolment start | `webauthn/enrol/start` | – | [`WebauthnEnrolStartResponse`] | fresh OPAQUE |
//! | Enrolment confirmation | `webauthn/enrol/confirm` | [`WebauthnEnrolConfirmRequest`] | empty success | fresh OPAQUE |
//! | List | `webauthn/list` | – | [`WebauthnListResponse`] | OPAQUE or device |
//! | Removal | `webauthn/remove` | [`WebauthnRemoveRequest`] | empty success | fresh OPAQUE |
//! | Login challenge | `webauthn/login/challenge` | [`WebauthnLoginChallengeRequest`] | [`WebauthnLoginChallengeResponse`] | none (after `login/finish`) |
//! | Login finish | `webauthn/login/finish` | [`WebauthnLoginFinishRequest`] | [`LoginFinishResponse`](crate::auth::LoginFinishResponse) | none |
//!
//! - **Second factor after OPAQUE.** `login/finish` answers `second_factor_required` only after
//!   KE3 verified (CRYPTO.md §5.9). When the account holds a security key, the server has then
//!   kept a 60 s, single-use second-factor-pending row whose `pending_id` is the login's own
//!   `login_id` (ADR 0058 point 3), so no new field is needed in the error body (ADR 0028
//!   item 3). `webauthn/login/challenge` answers `not_found` when there is no such row: the
//!   account has no security key (TOTP only), or the row expired or was used.
//! - **The browser's JSON, as text.** `options` is the creation or request options as
//!   `webauthn-rs` serialises them (`{"publicKey": {...}}`, binary values as base64url), and
//!   `credential` is the browser's `PublicKeyCredential` in the same JSON form (`toJSON()`).
//!   Both travel as JSON *text* in a [`WebauthnJson`] string (at most 64 KiB of printable
//!   ASCII): this crate holds no JSON parser of its own (ADR 0016 §3), and does not look inside
//!   them. `rizzy-domain-auth` parses them with `webauthn-rs`.
//! - **The ceremony state never travels** (ADR 0077 §2 rule 3): no type here carries it.
//!
//! [ADR 0058]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0058-webauthn-2fa-second-factor.md
//! [ADR 0077]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0077-webauthn-rs-integration-fixes.md

use core::fmt;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

use crate::limits::{
    MAX_WEBAUTHN_CREDENTIAL_ID_LEN, MAX_WEBAUTHN_CREDENTIALS, MAX_WEBAUTHN_LABEL_LEN,
    WebauthnJsonRule,
};
use crate::wire::{Bytes, Id, List, Text, WireError};

/// `WebAuthn` options or credential JSON, as text (module docs).
pub type WebauthnJson = Text<WebauthnJsonRule>;

/// A `WebAuthn` credential id (1 to 1023 bytes, base64url).
pub type WebauthnCredentialId = Bytes<MAX_WEBAUTHN_CREDENTIAL_ID_LEN>;

/// A security key's label: 1 to [`MAX_WEBAUTHN_LABEL_LEN`] bytes of UTF-8, no control
/// characters, no leading or trailing white space. Personal metadata (threat model §3.4), so
/// `Debug` prints the length only.
#[derive(Clone, PartialEq, Eq)]
pub struct WebauthnLabel(String);

impl WebauthnLabel {
    /// Checks and wraps `text`.
    ///
    /// # Errors
    /// [`WireError::Empty`], [`WireError::TooLong`] or [`WireError::InvalidCharacter`].
    pub fn new(text: String) -> Result<Self, WireError> {
        if text.is_empty() {
            Err(WireError::Empty)
        } else if text.len() > MAX_WEBAUTHN_LABEL_LEN {
            Err(WireError::TooLong {
                max: MAX_WEBAUTHN_LABEL_LEN,
            })
        } else if text.chars().any(char::is_control) || text.trim() != text {
            Err(WireError::InvalidCharacter)
        } else {
            Ok(Self(text))
        }
    }

    /// The label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WebauthnLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebauthnLabel({} bytes)", self.0.len())
    }
}

impl Serialize for WebauthnLabel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for WebauthnLabel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(de::Error::custom)
    }
}

/// The answer to `webauthn/enrol/start`: the enrolment to confirm, and the creation options
/// for `navigator.credentials.create`.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnEnrolStartResponse {
    /// Names the enrolment in the confirmation; valid for 60 s, once.
    pub enrolment_id: Id,
    /// `webauthn-rs`'s creation challenge response (`{"publicKey": {...}}`).
    pub options: WebauthnJson,
}

/// `webauthn/enrol/confirm`: the authenticator's attestation response for enrolment
/// `enrolment_id`, and the user's label for the key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnEnrolConfirmRequest {
    /// From [`WebauthnEnrolStartResponse`].
    pub enrolment_id: Id,
    /// The user's name for the key.
    pub label: WebauthnLabel,
    /// The browser's `PublicKeyCredential` from `create()`, as JSON.
    pub credential: WebauthnJson,
}

/// One enrolled security key, as the account's owner sees it.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebauthnCredentialView {
    /// The credential id, which names the key in [`WebauthnRemoveRequest`].
    pub credential_id: WebauthnCredentialId,
    /// The user's label.
    pub label: WebauthnLabel,
    /// When the key was enrolled, in Unix milliseconds.
    pub created_ms: u64,
}

/// The answer to `webauthn/list`: the account's security keys, oldest first.
///
/// A response type: unknown fields are ignored. More than [`MAX_WEBAUTHN_CREDENTIALS`] is a parse
/// error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebauthnListResponse {
    /// At most [`MAX_WEBAUTHN_CREDENTIALS`] keys.
    pub credentials: List<WebauthnCredentialView, MAX_WEBAUTHN_CREDENTIALS>,
}

/// `webauthn/remove`: removes one security key of the caller's account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnRemoveRequest {
    /// From [`WebauthnCredentialView`].
    pub credential_id: WebauthnCredentialId,
}

/// `webauthn/login/challenge`: a fresh assertion challenge for the login demoted to
/// second-factor-pending row `pending_id` (module docs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnLoginChallengeRequest {
    /// The `login_id` of the `login/finish` that answered `second_factor_required`.
    pub pending_id: Id,
}

/// The answer to `webauthn/login/challenge`.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebauthnLoginChallengeResponse {
    /// `webauthn-rs`'s request challenge response (`{"publicKey": {...}}`) for
    /// `navigator.credentials.get`, with the account's keys as `allowCredentials`.
    pub options: WebauthnJson,
    /// Whether the account also holds a confirmed TOTP enrolment, so a client may offer a code
    /// instead (a code restarts the OPAQUE login with it).
    #[serde(default)]
    pub totp: bool,
}

/// `webauthn/login/finish`: the assertion for pending row `pending_id`. Answers a
/// [`LoginFinishResponse`](crate::auth::LoginFinishResponse) on success.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnLoginFinishRequest {
    /// As in [`WebauthnLoginChallengeRequest`].
    pub pending_id: Id,
    /// The browser's `PublicKeyCredential` from `get()`, as JSON.
    pub credential: WebauthnJson,
}

#[cfg(test)]
mod tests {
    //! Known-answer JSON, strict requests and the label rule.
    use super::*;

    #[test]
    fn known_answer_json() {
        let id = Id::from_bytes([7; 16]);
        let confirm = WebauthnEnrolConfirmRequest {
            enrolment_id: id,
            label: WebauthnLabel::new("YubiKey 5C".to_owned()).unwrap(),
            credential: WebauthnJson::new(r#"{"id":"AQ"}"#.to_owned()).unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&confirm).unwrap(),
            r#"{"enrolment_id":"BwcHBwcHBwcHBwcHBwcHBw","label":"YubiKey 5C","credential":"{\"id\":\"AQ\"}"}"#
        );
        let remove = WebauthnRemoveRequest {
            credential_id: WebauthnCredentialId::new(vec![1, 2, 3]).unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&remove).unwrap(),
            r#"{"credential_id":"AQID"}"#
        );
        let challenge: WebauthnLoginChallengeResponse =
            serde_json::from_str(r#"{"options":"{}","extra":1}"#).unwrap();
        assert!(!challenge.totp, "totp defaults to false");
        let list: WebauthnListResponse = serde_json::from_str(
            r#"{"credentials":[{"credential_id":"AQID","label":"Key","created_ms":5}]}"#,
        )
        .unwrap();
        assert_eq!(list.credentials.as_slice().first().unwrap().created_ms, 5);
    }

    #[test]
    fn requests_are_strict() {
        for bad in [
            r#"{"pending_id":"BwcHBwcHBwcHBwcHBwcHBw","credential":"{}","x":1}"#,
            r#"{"pending_id":"BwcHBwcHBwcHBwcHBwcHBw","credential":""}"#,
            r#"{"pending_id":"BwcHBwcHBwcHBwcHBwcHBw","credential":"{\u00e9}"}"#,
            r#"{"pending_id":"short","credential":"{}"}"#,
        ] {
            assert!(
                serde_json::from_str::<WebauthnLoginFinishRequest>(bad).is_err(),
                "{bad}"
            );
        }
        let long = "a".repeat(64 * 1024 + 1);
        let body = format!(r#"{{"pending_id":"BwcHBwcHBwcHBwcHBwcHBw","credential":"{long}"}}"#);
        assert!(serde_json::from_str::<WebauthnLoginFinishRequest>(&body).is_err());
        let too_many = format!(
            r#"{{"credentials":[{}]}}"#,
            vec![r#"{"credential_id":"AQ","label":"k","created_ms":1}"#; 33].join(",")
        );
        assert!(serde_json::from_str::<WebauthnListResponse>(&too_many).is_err());
    }

    #[test]
    fn labels() {
        assert!(WebauthnLabel::new("Clé de sécurité".to_owned()).is_ok());
        assert_eq!(WebauthnLabel::new(String::new()), Err(WireError::Empty));
        assert_eq!(
            WebauthnLabel::new("x".repeat(65)),
            Err(WireError::TooLong { max: 64 })
        );
        for bad in [" lead", "trail ", "tab\there", "nl\n"] {
            assert_eq!(
                WebauthnLabel::new(bad.to_owned()),
                Err(WireError::InvalidCharacter),
                "{bad:?}"
            );
        }
        let label = WebauthnLabel::new("Private name".to_owned()).unwrap();
        assert_eq!(format!("{label:?}"), "WebauthnLabel(12 bytes)");
    }
}
