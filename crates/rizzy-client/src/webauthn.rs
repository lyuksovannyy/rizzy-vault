// SPDX-License-Identifier: AGPL-3.0-only

//! `WebAuthn` security keys as a server-side second factor, the client half (ADR 0058 as
//! amended by ADR 0077; CRYPTO.md §11.17; `rizzy_proto::webauthn`).
//!
//! ```text
//! enrolment (fresh OPAQUE session):
//!   webauthn/enrol/start ──options──► host: navigator.credentials.create(options)
//!   ──credential JSON──► enrol_confirm_request(enrolment_id, label, json) ──► webauthn/enrol/confirm
//! login, after login/finish answered second_factor_required:
//!   login_challenge_request(login_id) ──► webauthn/login/challenge
//!     200 ─► SecondFactor::SecurityKey { options, totp } ─► navigator.credentials.get(options)
//!            ──► login_finish_request(login_id, json) ──► webauthn/login/finish ─► LoginFinishResponse
//!     404 ─► SecondFactor::Totp (restart the OPAQUE login with a code, as before)
//! ```
//!
//! The ceremony itself runs in the browser (`navigator.credentials`, on the web vault's own
//! origin) and on the server (`webauthn-rs`); this module only builds and reads the wire types,
//! checking their bounds before anything is sent. A client without `WebAuthn` for the server's
//! RP ID (rv, the browser extension's own pages) uses [`SecondFactor::from_challenge`] to tell
//! the user that the account needs a security key it cannot use, instead of asking for a code
//! that does not exist. 2FA gates server access only: nothing here touches a key (§5.10).

use rizzy_proto::error::ErrorCode;
use rizzy_proto::webauthn::{
    WebauthnCredentialId, WebauthnEnrolConfirmRequest, WebauthnJson, WebauthnLabel,
    WebauthnLoginChallengeRequest, WebauthnLoginChallengeResponse, WebauthnLoginFinishRequest,
    WebauthnRemoveRequest,
};
use rizzy_proto::wire::Id;

use crate::error::ClientError;

/// The second factor a login can finish with, read from the answer to
/// `webauthn/login/challenge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondFactor {
    /// No security key (the server answered `not_found`): a TOTP code, which restarts the OPAQUE
    /// login.
    Totp,
    /// A security key: `options` for `navigator.credentials.get`, and whether a TOTP code would
    /// also do.
    SecurityKey {
        /// The request options JSON, as the server sent it.
        options: String,
        /// Whether the account also has a confirmed TOTP enrolment.
        totp: bool,
    },
}

impl SecondFactor {
    /// Reads the challenge answer: the parsed body of a 200, or the error code of anything else.
    ///
    /// # Errors
    /// The server's error code, for one other than `not_found`.
    pub fn from_challenge(
        answer: Result<WebauthnLoginChallengeResponse, ErrorCode>,
    ) -> Result<Self, ErrorCode> {
        match answer {
            Ok(response) => Ok(Self::SecurityKey {
                options: response.options.as_str().to_owned(),
                totp: response.totp,
            }),
            Err(ErrorCode::NotFound) => Ok(Self::Totp),
            Err(code) => Err(code),
        }
    }
}

/// The body of `webauthn/login/challenge` for the login `login_id` (its pending id).
#[must_use]
pub const fn login_challenge_request(login_id: Id) -> WebauthnLoginChallengeRequest {
    WebauthnLoginChallengeRequest {
        pending_id: login_id,
    }
}

/// Wraps browser JSON, checked against the wire bounds.
fn json(text: &str) -> Result<WebauthnJson, ClientError> {
    WebauthnJson::new(text.to_owned()).map_err(|_| ClientError::InvalidInput)
}

/// The body of `webauthn/login/finish`: the browser's assertion JSON for the login `login_id`.
///
/// # Errors
/// [`ClientError::InvalidInput`] for JSON outside the wire bounds (64 KiB of printable ASCII).
pub fn login_finish_request(
    login_id: Id,
    credential_json: &str,
) -> Result<WebauthnLoginFinishRequest, ClientError> {
    Ok(WebauthnLoginFinishRequest {
        pending_id: login_id,
        credential: json(credential_json)?,
    })
}

/// The body of `webauthn/enrol/confirm`: the browser's attestation JSON for `enrolment_id`,
/// and the user's label, trimmed.
///
/// # Errors
/// [`ClientError::InvalidInput`] for an empty or over-long label (64 bytes), or JSON outside the
/// wire bounds.
pub fn enrol_confirm_request(
    enrolment_id: Id,
    label: &str,
    credential_json: &str,
) -> Result<WebauthnEnrolConfirmRequest, ClientError> {
    Ok(WebauthnEnrolConfirmRequest {
        enrolment_id,
        label: WebauthnLabel::new(label.trim().to_owned())
            .map_err(|_| ClientError::InvalidInput)?,
        credential: json(credential_json)?,
    })
}

/// The body of `webauthn/remove` for the key `credential_id`.
///
/// # Errors
/// [`ClientError::InvalidInput`] for an empty id or one above 1023 bytes.
pub fn remove_request(credential_id: &[u8]) -> Result<WebauthnRemoveRequest, ClientError> {
    Ok(WebauthnRemoveRequest {
        credential_id: WebauthnCredentialId::new(credential_id.to_vec())
            .map_err(|_| ClientError::InvalidInput)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_factor_from_the_challenge_answer() {
        let answer: WebauthnLoginChallengeResponse =
            serde_json::from_str(r#"{"options":"{\"publicKey\":{}}","totp":true}"#).unwrap();
        assert_eq!(
            SecondFactor::from_challenge(Ok(answer)).unwrap(),
            SecondFactor::SecurityKey {
                options: r#"{"publicKey":{}}"#.to_owned(),
                totp: true
            }
        );
        assert_eq!(
            SecondFactor::from_challenge(Err(ErrorCode::NotFound)).unwrap(),
            SecondFactor::Totp
        );
        assert_eq!(
            SecondFactor::from_challenge(Err(ErrorCode::RateLimited)),
            Err(ErrorCode::RateLimited)
        );
    }

    #[test]
    fn requests_check_their_bounds() {
        let id = Id::from_bytes([1; 16]);
        let ok = enrol_confirm_request(id, "  Desk key ", "{}").unwrap();
        assert_eq!(ok.label.as_str(), "Desk key");
        assert!(enrol_confirm_request(id, "   ", "{}").is_err());
        assert!(enrol_confirm_request(id, &"k".repeat(65), "{}").is_err());
        assert!(login_finish_request(id, "").is_err());
        assert!(login_finish_request(id, "{\"é\":1}").is_err());
        assert!(remove_request(&[]).is_err());
        assert!(remove_request(&[0; 1024]).is_err());
        assert_eq!(
            remove_request(&[7; 16]).unwrap().credential_id.as_slice(),
            &[7; 16]
        );
    }
}
