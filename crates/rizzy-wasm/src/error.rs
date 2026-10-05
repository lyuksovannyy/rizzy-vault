//! The one error type that crosses the boundary (ADR 0013 §3 rule 4: "Errors are typed and
//! carry no secrets. They cross as enums with stable codes").
//!
//! [`CoreError`] holds a stable code and nothing else: no message, no input echo, no key
//! bytes, plaintext or password (threat model INV-21). JavaScript receives it as the thrown
//! value of a failed call, an instance of the exported `CoreError` class with a `code`
//! getter; `packages/core` turns it into a TypeScript error with the same code.
//!
//! # Codes
//!
//! | Source | Code |
//! |---|---|
//! | `rizzy-client` | [`ClientError::code`] as it stands (`wrong_password_or_secret_key`, `read_only`, …) |
//! | The server's `{"error":"<code>"}` (ADR 0028 item 3) | `server_` and the code (`server_rate_limited`, `server_state_conflict`, …); a code this build does not know is `server_unknown` |
//! | This crate | the constants below |
//!
//! Codes never change meaning; new ones are only added.

use rizzy_client::ClientError;
use rizzy_client::rizzy_proto::error::ErrorCode;
use wasm_bindgen::prelude::wasm_bindgen;

/// A call came in an order the flow does not allow: a response with no request outstanding, a
/// second factor when none was asked for, a result before the flow finished.
pub const WRONG_STATE: &str = "wrong_state";
/// The session was locked ([`crate::Session::lock`]); log in again.
pub const LOCKED: &str = "locked";
/// A response body larger than anything `/api/v1` sizes (ADR 0028 item 7).
pub const RESPONSE_TOO_LARGE: &str = "response_too_large";
/// An export needs a re-authentication less than [`crate::session::REAUTH_WINDOW_MS`]
/// old (owner decision 2026-10-05; ADR 0013 §3 rule 2: "an explicit plaintext export, after
/// re-authentication"). The same code as `rizzy-client`'s `ClientError::ReauthRequired`.
pub const REAUTH_REQUIRED: &str = "reauth_required";
/// The Emergency Kit was already handed out once (ADR 0013 §3 rule 2: "go out once").
pub const ALREADY_SHOWN: &str = "already_shown";
/// An import or export format name this build does not know.
pub const UNKNOWN_FORMAT: &str = "unknown_format";
/// An import file the importer refused as a whole (`rizzy-import`'s `ImportError`; which part
/// failed is not said, INV-48).
pub const IMPORT_FAILED: &str = "import_failed";
/// The vault key was rotated by another device during this session (ADR 0025 §4). The web
/// vault keeps no account-state follow-up in this build: it logs in again, which reads the new
/// key. Edits not yet uploaded are lost with the old session.
pub const VAULT_KEY_ROTATED: &str = "vault_key_rotated";

/// A failed call: a stable code, nothing else (module docs).
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreError {
    /// The stable code.
    code: &'static str,
}

#[wasm_bindgen]
impl CoreError {
    /// The stable code (module docs, "Codes").
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn code(&self) -> String {
        self.code.to_owned()
    }
}

impl CoreError {
    /// The error with `code`.
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }

    /// The code, without an allocation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.code
    }

    /// A refusal by the server, by its `/api/v1` code (ADR 0028 item 3).
    #[must_use]
    pub const fn server(code: ErrorCode) -> Self {
        Self::new(match code {
            ErrorCode::ClientTooOld => "server_client_too_old",
            ErrorCode::ApiVersionGone => "server_api_version_gone",
            ErrorCode::InvalidRequest => "server_invalid_request",
            ErrorCode::PayloadTooLarge => "server_payload_too_large",
            ErrorCode::Unauthorized => "server_unauthorized",
            ErrorCode::SecondFactorRequired => "server_second_factor_required",
            ErrorCode::FreshSessionRequired => "server_fresh_session_required",
            ErrorCode::RateLimited => "server_rate_limited",
            ErrorCode::NotFound => "server_not_found",
            ErrorCode::StateConflict => "server_state_conflict",
            ErrorCode::StaleEpoch => "server_stale_epoch",
            ErrorCode::RecordConflict => "server_record_conflict",
            ErrorCode::PrevSeqMismatch => "server_prev_seq_mismatch",
            ErrorCode::SetupRetired => "server_setup_retired",
            ErrorCode::CredentialsStale => "server_credentials_stale",
            ErrorCode::Internal => "server_internal",
            _ => "server_unknown",
        })
    }
}

impl From<ClientError> for CoreError {
    fn from(e: ClientError) -> Self {
        Self::new(e.code())
    }
}

impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code)
    }
}

impl core::error::Error for CoreError {}

/// The result of every fallible call.
pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_strings() {
        assert_eq!(
            CoreError::from(ClientError::WrongPasswordOrSecretKey).as_str(),
            "wrong_password_or_secret_key"
        );
        assert_eq!(
            CoreError::server(ErrorCode::RateLimited).as_str(),
            "server_rate_limited"
        );
        assert_eq!(
            CoreError::server(ErrorCode::Unknown).as_str(),
            "server_unknown"
        );
        assert_eq!(
            CoreError::server(ErrorCode::SetupRetired).as_str(),
            "server_setup_retired"
        );
        assert_eq!(
            CoreError::server(ErrorCode::CredentialsStale).as_str(),
            "server_credentials_stale"
        );
        assert_eq!(
            CoreError::from(ClientError::SetupRetired).as_str(),
            "setup_retired"
        );
        assert_eq!(CoreError::new(LOCKED).code(), "locked");
        assert_eq!(CoreError::new(LOCKED).to_string(), "locked");
    }
}
