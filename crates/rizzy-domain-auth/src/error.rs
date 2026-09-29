//! The error type of `rizzy-domain-auth`.
//!
//! **What an error may say.** A variant names a kind of failure, never a value: no login
//! name, token, key, OPAQUE message, statement or envelope, and no bound SQL value (threat
//! model INV-48). [`AuthError::code`] maps each variant onto the one machine-readable code the
//! API answers with ([`ErrorCode`], ADR 0002 point 3). Several variants deliberately share
//! [`ErrorCode::Unauthorized`], so no answer tells an unknown account from a wrong password, a
//! wrong recovery code, an expired challenge or a bad signature (CRYPTO.md §5.9).
//!
//! **Logging.** `Display` gives a fixed sentence per variant. [`AuthError::Storage`] wraps a
//! [`rizzy_storage::Error`], whose own `Debug` and `Display` leave out bound values and driver
//! detail fields; log it with `Display`, as that crate's docs require.

use core::fmt;

use rizzy_proto::error::ErrorCode;

/// Everything that can go wrong in the auth domain.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthError {
    /// The request is malformed or violates a rule of the flow: a statement that does not
    /// parse or verify, a locator that disagrees with the signed state, an epoch or sequence
    /// number that does not follow. Never says which.
    InvalidRequest,
    /// Authentication failed or is missing: a wrong password or Secret Key, an unknown account,
    /// a wrong recovery code, a bad, expired or used token, challenge or request signature, a
    /// revoked or suspended device. One variant for all of them (CRYPTO.md §5.9).
    Unauthorized,
    /// The OPAQUE login verified, but the account has server-side 2FA and the login carried no
    /// valid code (CRYPTO.md §5.10, §11.15). Only ever returned after KE3 verified (§5.9).
    SecondFactorRequired,
    /// The operation needs a fresh OPAQUE session of at most 5 minutes, or the recovery-only
    /// session (CRYPTO.md §11 "Replacing credentials", §11.5 step 1).
    FreshSessionRequired,
    /// Rate limit or backoff (ADR 0010 §5, CRYPTO.md §5.9, INV-7). Never a hard lockout.
    RateLimited,
    /// The resource does not exist, or this session may not see it (threat model §7.6 "I").
    NotFound,
    /// The compare-and-swap on `state_seq` failed, or the offered state is older than the one
    /// held (CRYPTO.md §10.2). The client re-fetches and follows the loser's rules.
    StateConflict,
    /// A verified `account-state` with the `state_seq` the server holds but a different body:
    /// a fork of the signed state (CRYPTO.md §10.2 "Forks of the signed state"). It is refused
    /// and never adopted. Answered like [`AuthError::StateConflict`]; the client's own
    /// comparison (`AccountState::cas_retry`) reports the fork to the user.
    StateFork,
    /// The name or id is taken, or a repeat of a commit is not byte-identical to the one
    /// applied. Signup is invite-only or rate-limited because this is an enumeration oracle
    /// (CRYPTO.md §5.9).
    Conflict,
    /// Signup is closed on this server, or the invite was refused (CRYPTO.md §5.9).
    SignupRefused,
    /// A pending recovery exists but its waiting period has not ended (CRYPTO.md §11.9 step 3,
    /// ADR 0008 decision 5).
    RecoveryWaiting,
    /// The storage layer failed. Carries no bound value.
    Storage(rizzy_storage::Error),
    /// The server is misconfigured or its stored state is inconsistent: a data key the secrets
    /// file lacks, a stored statement that no longer verifies. The `&'static str` says what,
    /// never with a value.
    Internal(&'static str),
}

impl AuthError {
    /// The API error code for this error (ADR 0002 point 3; `rizzy-proto`'s [`ErrorCode`]).
    ///
    /// `StateFork` answers `state_conflict`, `Conflict` and `SignupRefused` answer
    /// `invalid_request` and `unauthorized` (no Accepted ADR names a code for them), and
    /// `RecoveryWaiting` answers `rate_limited`: the client retries after the waiting period.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidRequest | Self::Conflict => ErrorCode::InvalidRequest,
            Self::Unauthorized | Self::SignupRefused => ErrorCode::Unauthorized,
            Self::SecondFactorRequired => ErrorCode::SecondFactorRequired,
            Self::FreshSessionRequired => ErrorCode::FreshSessionRequired,
            Self::RateLimited | Self::RecoveryWaiting => ErrorCode::RateLimited,
            Self::NotFound => ErrorCode::NotFound,
            Self::StateConflict | Self::StateFork => ErrorCode::StateConflict,
            Self::Storage(_) | Self::Internal(_) => ErrorCode::Internal,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("invalid request"),
            Self::Unauthorized => f.write_str("unauthorized"),
            Self::SecondFactorRequired => f.write_str("second factor required"),
            Self::FreshSessionRequired => f.write_str("fresh session required"),
            Self::RateLimited => f.write_str("rate limited"),
            Self::NotFound => f.write_str("not found"),
            Self::StateConflict => f.write_str("account-state compare-and-swap failed"),
            Self::StateFork => f.write_str("account-state fork refused"),
            Self::Conflict => f.write_str("conflict with stored data"),
            Self::SignupRefused => f.write_str("signup refused"),
            Self::RecoveryWaiting => f.write_str("recovery waiting period not over"),
            Self::Storage(e) => write!(f, "storage: {e}"),
            Self::Internal(what) => write!(f, "internal: {what}"),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rizzy_storage::Error> for AuthError {
    fn from(e: rizzy_storage::Error) -> Self {
        Self::Storage(e)
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        Self::Storage(rizzy_storage::Error::from(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_relevant_failures_share_one_code() {
        for e in [AuthError::Unauthorized, AuthError::SignupRefused] {
            assert_eq!(e.code(), ErrorCode::Unauthorized);
        }
        assert_eq!(AuthError::StateFork.code(), ErrorCode::StateConflict);
        assert_eq!(AuthError::Internal("x").code(), ErrorCode::Internal);
    }
}
