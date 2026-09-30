//! The error response body (ADR 0002 point 3: "a machine-readable error code").
//!
//! Every error answer of `/api/v1` and `/api/meta` is one [`ErrorResponse`]: a JSON object with
//! one field, `error`, holding an [`ErrorCode`] in `snake_case`. No free-text message, no
//! input echo, no internals: the `api` role's errors are uniform (threat model §7.6 "I") and
//! logs and answers never carry secrets (INV-48).
//!
//! **Which codes the ADRs name, and which are this crate's.**
//! - Named by a spec: `client_too_old` (ADR 0002 point 3), `api_version_gone` (the
//!   machine-readable code of ADR 0002 point 3's `410 Gone`; the spec names the status, not the
//!   string), `stale_epoch` (ADR 0012 §7 "Upload", ADR 0021 §9), `record_conflict` ("a
//!   different record at a stored dot is refused as a conflict", ADR 0021 §9 "Already
//!   stored"), `prev_seq_mismatch` (ADR 0021 §9 "Already stored", last sentence),
//!   `state_conflict` (the lost compare-and-swap on `state_seq`, CRYPTO.md §10.2),
//!   `fresh_session_required` (CRYPTO.md §11 "Replacing credentials": a fresh OPAQUE session of
//!   at most 5 minutes).
//! - Generic, this crate's: `invalid_request`, `payload_too_large`, `unauthorized`,
//!   `second_factor_required`, `rate_limited`, `not_found`, `internal`.
//!
//! ADR 0028 item 3 freezes the whole set for `v1`, with the HTTP status of each code:
//! `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401;
//! `fresh_session_required` 403; `not_found` 404; `state_conflict`, `stale_epoch`,
//! `record_conflict` and `prev_seq_mismatch` 409; `api_version_gone` 410; `payload_too_large`
//! 413; `rate_limited` 429, with `Retry-After` in whole seconds; `internal` 500. A method a
//! route does not serve is `405` with `invalid_request`. **Clients branch on the code, never on
//! the status.**
//!
//! **Forward compatibility.** A client that reads a code it does not know gets
//! [`ErrorCode::Unknown`] instead of a parse failure: a new code is a new response value, which
//! ADR 0002 point 3 counts as additive. `Unknown` is never sent.

use serde::{Deserialize, Serialize};

/// A machine-readable error code (ADR 0002 point 3). See the module documentation for which
/// codes a spec names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The `Rizzy-Client` version is below the server's minimum for that platform (ADR 0002
    /// point 3). The client shows "update required" and never falls back (point 5).
    ClientTooOld,
    /// The API version in the path has been removed; sent with `410 Gone` (ADR 0002 point 3).
    ApiVersionGone,
    /// The body is not valid for this endpoint: malformed JSON, an unknown field, a missing
    /// field, a value outside its limit or character set. Never says which, never quotes the
    /// input.
    InvalidRequest,
    /// The body exceeds the server's size limit (threat model §7.6 "D").
    PayloadTooLarge,
    /// Authentication failed or is missing: a wrong password or Secret Key, an unknown account,
    /// a bad or expired token, challenge or request signature. One code for all of them, so no
    /// answer tells an unknown account from a wrong password (CRYPTO.md §5.9).
    Unauthorized,
    /// The account has server-side 2FA and the login carried no valid code (CRYPTO.md §5.10,
    /// §11.2 step 5). Sent only after KE3 has verified (§5.9).
    SecondFactorRequired,
    /// The request needs a fresh OPAQUE session of at most 5 minutes (CRYPTO.md §11
    /// "Replacing credentials", §11.5 step 1).
    FreshSessionRequired,
    /// Rate limit or backoff (CRYPTO.md §5.9, threat model A15). Never a hard lockout.
    RateLimited,
    /// The resource does not exist, or the session may not see it; the two are not told apart
    /// (threat model §7.6 "I").
    NotFound,
    /// The compare-and-swap on `state_seq` failed: another change was committed first. The
    /// client re-fetches and follows CRYPTO.md §10.2's rules for the loser.
    StateConflict,
    /// An op or snapshot names a `vault_key_epoch` below the vault's current one (ADR 0012 §7
    /// "Upload", as ADR 0021 §9 "Stale epoch" restates it).
    StaleEpoch,
    /// A record differs from the one stored at the same dot or `snapshot_id` (ADR 0021 §9
    /// "Already stored").
    RecordConflict,
    /// An op whose `vault_prev_seq` is not the last op the server holds from that device in
    /// that vault (ADR 0021 §9 "Already stored").
    PrevSeqMismatch,
    /// The server failed. No detail.
    Internal,
    /// A code this build does not know; only ever produced by parsing a newer server's answer.
    #[serde(other)]
    Unknown,
}

/// The body of every error answer (ADR 0002 point 3).
///
/// A response type: unknown fields are ignored, so a later server may add fields (ADR 0002
/// point 3, additive changes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The machine-readable code.
    pub error: ErrorCode,
}

impl ErrorResponse {
    /// The answer carrying `error`.
    #[must_use]
    pub const fn new(error: ErrorCode) -> Self {
        Self { error }
    }
}

#[cfg(test)]
mod tests {
    //! The error body's known-answer JSON and its tolerance of new codes and fields.

    use super::*;

    #[test]
    fn known_answer_json() {
        let body = ErrorResponse::new(ErrorCode::ClientTooOld);
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"error":"client_too_old"}"#
        );
        assert_eq!(
            serde_json::to_string(&ErrorResponse::new(ErrorCode::StaleEpoch)).unwrap(),
            r#"{"error":"stale_epoch"}"#
        );
    }

    #[test]
    fn new_codes_and_fields_are_tolerated() {
        let parsed: ErrorResponse =
            serde_json::from_str(r#"{"error":"from_the_future","detail":1}"#).unwrap();
        assert_eq!(parsed.error, ErrorCode::Unknown);
        for code in [
            ErrorCode::ApiVersionGone,
            ErrorCode::InvalidRequest,
            ErrorCode::StateConflict,
            ErrorCode::RecordConflict,
            ErrorCode::PrevSeqMismatch,
        ] {
            let json = serde_json::to_string(&ErrorResponse::new(code)).unwrap();
            assert_eq!(
                serde_json::from_str::<ErrorResponse>(&json).unwrap().error,
                code
            );
        }
    }
}
