//! Server-side 2FA with TOTP, the client half (CRYPTO.md §5.10 "Server-side 2FA", §11.15;
//! `rizzy_proto::totp`).
//!
//! ```text
//! (fresh OPAQUE session: a re-authentication)
//! host: totp/enrol/start ──TotpEnrolStartResponse──► TotpEnrolment::from_response
//!   ──► render otpauth_uri / secret_base32 for the authenticator app
//!   ──► confirm_request(code) ──TotpEnrolConfirmRequest──► host (totp/enrol/confirm)
//! disable_request(code) ──TotpDisableRequest──► host (totp/disable)
//! ```
//!
//! At login the code travels in `LoginFinishRequest::totp` ([`crate::login`]); the host asks
//! for it when the server answers `second_factor_required`.
//!
//! The server issues the secret and returns it once (§11.15: "generated at 20 bytes"). This
//! module renders it for the user's authenticator as an `otpauth://totp/` URI with the
//! server's parameters ([`TotpParams::DEFAULT`]: SHA-1, 6 digits, 30 s, the ones the server
//! verifies with) and as RFC 4648 Base32 for manual entry, and checks a typed code's shape
//! before anything is sent. The secret is held in wiped buffers and is never stored by the
//! client. 2FA gates server access only: nothing here touches a key (§5.10).

use core::fmt;

use rizzy_core::normalize::{LoginName, ServerOrigin};
use rizzy_core::totp::{MIN_SERVER_SECRET_LEN, OtpAuthUri, TotpParams, TotpSecret};
use rizzy_proto::auth::TotpCode;
use rizzy_proto::totp::{TotpDisableRequest, TotpEnrolConfirmRequest, TotpEnrolStartResponse};
use zeroize::Zeroizing;

use crate::error::ClientError;

/// The issuer an authenticator app shows for the enrolment.
pub const TOTP_ISSUER: &str = "rizzy-vault";

/// A started enrolment: the server's secret, shown to the user once. `Debug` shows the
/// sequence number only; the secret is wiped on drop.
pub struct TotpEnrolment {
    /// The enrolment's `totp_credential_seq`.
    totp_credential_seq: u32,
    /// The otpauth URI, which holds the secret.
    uri: OtpAuthUri,
}

impl fmt::Debug for TotpEnrolment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpEnrolment")
            .field("totp_credential_seq", &self.totp_credential_seq)
            .finish_non_exhaustive()
    }
}

impl TotpEnrolment {
    /// Reads the server's answer to `totp/enrol/start`. `server_origin` and `login_name` name
    /// the account in the authenticator (label `rizzy-vault:<login name>@<host>`).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] for a secret shorter than the server floor
    /// (§11.15: 16 bytes; the wire type fixes 20); [`ClientError::InvalidInput`] for an origin
    /// or login name that does not normalise.
    pub fn from_response(
        response: &TotpEnrolStartResponse,
        server_origin: &str,
        login_name: &str,
    ) -> Result<Self, ClientError> {
        let origin = ServerOrigin::parse(server_origin).map_err(|_| ClientError::InvalidInput)?;
        let name = LoginName::parse(login_name).map_err(|_| ClientError::InvalidInput)?;
        let bytes = response.secret.expose_secret();
        if bytes.len() < MIN_SERVER_SECRET_LEN {
            return Err(ClientError::InvalidServerResponse);
        }
        let secret =
            TotpSecret::from_slice(bytes).map_err(|_| ClientError::InvalidServerResponse)?;
        let host = origin
            .as_str()
            .split_once("://")
            .map_or(origin.as_str(), |(_, rest)| rest);
        let label = Zeroizing::new(format!("{TOTP_ISSUER}:{}@{host}", name.as_str()));
        let uri = OtpAuthUri::new_totp(
            label,
            Some(Zeroizing::new(TOTP_ISSUER.to_owned())),
            TotpParams::DEFAULT,
            secret,
        )
        .map_err(|_| ClientError::InvalidInput)?;
        Ok(Self {
            totp_credential_seq: response.totp_credential_seq,
            uri,
        })
    }

    /// The `otpauth://totp/` URI for the authenticator (a QR code, or a paste). A secret:
    /// render it, never log it.
    #[must_use]
    pub fn otpauth_uri(&self) -> Zeroizing<String> {
        self.uri.to_uri()
    }

    /// The secret as canonical RFC 4648 Base32 (§11.15), for manual entry. A secret.
    #[must_use]
    pub fn secret_base32(&self) -> Zeroizing<String> {
        self.uri.secret().to_base32()
    }

    /// The confirmation with the current code from the user's authenticator.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a code that is not 6–8 ASCII digits.
    pub fn confirm_request(&self, code: &str) -> Result<TotpEnrolConfirmRequest, ClientError> {
        Ok(TotpEnrolConfirmRequest {
            totp_credential_seq: self.totp_credential_seq,
            code: totp_code(code)?,
        })
    }
}

/// The removal of 2FA with a current code.
///
/// # Errors
/// [`ClientError::InvalidInput`] for a code that is not 6–8 ASCII digits.
pub fn disable_request(code: &str) -> Result<TotpDisableRequest, ClientError> {
    Ok(TotpDisableRequest {
        code: totp_code(code)?,
    })
}

/// A typed code, with surrounding whitespace and inner spaces removed (authenticators show
/// `123 456`).
fn totp_code(code: &str) -> Result<TotpCode, ClientError> {
    let compact = Zeroizing::new(code.trim().replace(' ', ""));
    // §11.15 allows 6–8 digits; the wire type checks the digits and the upper bound.
    if compact.len() < 6 {
        return Err(ClientError::InvalidInput);
    }
    TotpCode::new(&compact).map_err(|_| ClientError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use rizzy_proto::wire::SecretFixed;

    use super::*;

    /// An enrolment answer with the secret `0x00 0x01 … 0x13`.
    fn answer() -> TotpEnrolStartResponse {
        let bytes: Vec<u8> = (0u8..20).collect();
        TotpEnrolStartResponse {
            totp_credential_seq: 3,
            secret: SecretFixed::from_slice(&bytes).unwrap(),
        }
    }

    #[test]
    fn enrolment_renders_the_server_secret_with_the_server_parameters() {
        let enrolment =
            TotpEnrolment::from_response(&answer(), "https://vault.example.org", "Alice").unwrap();
        let uri = enrolment.otpauth_uri();
        // The URI parses back to the same secret and the parameters the server verifies with.
        let parsed = OtpAuthUri::parse(&uri).unwrap();
        assert_eq!(
            parsed.secret().expose_secret(),
            &(0u8..20).collect::<Vec<_>>()[..]
        );
        assert_eq!(parsed.totp_params(), Some(TotpParams::DEFAULT));
        assert_eq!(parsed.issuer(), Some(TOTP_ISSUER));
        assert_eq!(parsed.label(), "rizzy-vault:alice@vault.example.org");
        assert_eq!(
            enrolment.secret_base32().as_str(),
            "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQT"
        );
        let confirm = enrolment.confirm_request(" 123 456 ").unwrap();
        assert_eq!(confirm.totp_credential_seq, 3);
        assert_eq!(confirm.code.expose_secret(), "123456");
        // Debug never shows the secret.
        assert!(!format!("{enrolment:?}").contains("AAAQ"));
    }

    #[test]
    fn codes_are_checked_before_anything_is_sent() {
        let enrolment =
            TotpEnrolment::from_response(&answer(), "https://vault.example.org", "alice").unwrap();
        for bad in ["", "12345", "12a456", "123456789", "١٢٣٤٥٦"] {
            assert_eq!(
                enrolment.confirm_request(bad).unwrap_err(),
                ClientError::InvalidInput,
                "{bad}"
            );
            assert_eq!(disable_request(bad).unwrap_err(), ClientError::InvalidInput);
        }
        assert!(disable_request("00000000").is_ok());
        assert_eq!(
            TotpEnrolment::from_response(&answer(), "not an origin", "alice").unwrap_err(),
            ClientError::InvalidInput
        );
    }
}
