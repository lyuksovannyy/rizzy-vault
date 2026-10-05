//! The one error type of `rv`.
//!
//! Every variant is a kind with, at most, a path the user typed, a server error code or an OS
//! error kind: never a byte of a key, a password, a token, a plaintext or a server answer
//! (CLAUDE.md "Never log secrets"; threat model INV-48, INV-56). `Display` is what the user
//! reads on stderr; [`CliError::exit_code`] is the process exit code (0 success, 1 a failure, 2
//! a usage error, as `rizzy-vault`).

use std::fmt;
use std::io;

use rizzy_client::ClientError;
use rizzy_client::rizzy_import::ImportError;
use rizzy_client::rizzy_proto::error::ErrorCode;
use rizzy_client::store::rows::Alarm;

/// Why a command failed. See the module docs.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// The command line is not one `rv` knows. The usage text follows on stderr.
    Usage(String),
    /// A flow of the client core refused (`rizzy-client`'s typed error; no secret in it).
    Client(ClientError),
    /// The server answered an error code (ADR 0028 item 3) where the flow needed success.
    Server(ErrorCode),
    /// The server answered `rate_limited`; `Retry-After` in whole seconds, if it sent one (ADR
    /// 0028, owner decision on open question 1).
    RateLimited(Option<u64>),
    /// The server answered something that is no `/api/v1` answer: a status without the error
    /// body, a body that does not parse, or one above the client's cap.
    BadAnswer,
    /// The connection failed, or no answer arrived in time. The outcome of the request is
    /// unknown (ADR 0028 "Retry after an unknown outcome").
    Network,
    /// The origin is `http://` and not a loopback address: tokens and signed requests would
    /// travel in clear. Only `https://` origins, and `http://` to `localhost` or a loopback
    /// address, are dialled.
    InsecureOrigin,
    /// The TLS handshake with an `https://` origin failed (ADR 0030 Decision 6): the origin
    /// and a fixed kind, never data from the peer. Nothing was sent: the request was not
    /// applied.
    Tls {
        /// The canonical origin dialled.
        origin: String,
        /// What failed.
        failure: TlsFailure,
    },
    /// A file or directory operation failed; the kind says how, the text names what.
    Io(&'static str, io::ErrorKind),
    /// Something already exists at the output path. `rv` never overwrites (ADR 0027 §5).
    FileExists,
    /// The cache is in use by another `rv` (ADR 0026 §3).
    InUse,
    /// The `SQLite` cache could not be read or written.
    Database,
    /// No device is enrolled in the data directory (or none matches `--account`).
    NotEnrolled,
    /// Several accounts are enrolled in the data directory: `--account` must name one.
    SeveralAccounts,
    /// A device is already enrolled for this account in the data directory.
    AlreadyEnrolled,
    /// A secret was asked for, but standard input is a terminal whose echo cannot be turned
    /// off; or a phrase that must be typed at a terminal was asked for without one.
    NoTerminal,
    /// Standard input ended before an answer was read.
    InputEnded,
    /// The device is read-only because an alarm is raised (ADR 0026 §4 step 4).
    Alarm(Alarm),
    /// An import file could not be read as the named format.
    Import(ImportError),
    /// The answer to a prompt was not acceptable (a mismatched confirmation, an empty value).
    BadInput(&'static str),
}

/// The fixed kind of a TLS handshake failure (ADR 0030 Decision 6), from the rustls error's
/// kind alone (`crate::tls::failure_of`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsFailure {
    /// The certificate chain does not lead to a trusted root: the public roots, or the private
    /// CA file when one is given.
    UnknownIssuer,
    /// The certificate has expired.
    Expired,
    /// The certificate is not valid yet.
    NotValidYet,
    /// The certificate does not name the origin's host or IP address.
    WrongName,
    /// The certificate was refused for another reason (a CA certificate used as the server's
    /// own, a bad signature, an unsupported algorithm, revocation data).
    BadCertificate,
    /// The server offers no TLS 1.3, or nothing this client offers.
    Incompatible,
    /// The handshake failed otherwise.
    Handshake,
    /// rustls refused this client's configuration.
    Configuration,
}

impl TlsFailure {
    /// What the user reads.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::UnknownIssuer => {
                "the server's certificate is not issued by a trusted CA (a private CA is \
                 trusted with --ca-file or RIZZY_CLI_CA_FILE)"
            }
            Self::Expired => "the server's certificate has expired",
            Self::NotValidYet => "the server's certificate is not valid yet (check the clock)",
            Self::WrongName => "the server's certificate is for another name",
            Self::BadCertificate => {
                "the server's certificate was refused (a self-signed or CA certificate cannot \
                 be the server's own)"
            }
            Self::Incompatible => "the server does not offer TLS 1.3",
            Self::Handshake => "the TLS handshake failed",
            Self::Configuration => "the TLS client could not be configured",
        }
    }
}

impl CliError {
    /// The process exit code.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            _ => 1,
        }
    }

    /// Whether this error, as the answer to a commit (`account/commit`, `register/finish`,
    /// `devices/enrol`), proves that the server did **not** apply it.
    ///
    /// Only a parsed `/api/v1` error body with a code the server sends when it refuses a
    /// request does (ADR 0028 item 3). Everything else leaves the outcome unknown, and the
    /// state saved for the commit must stay for the restart rule of CRYPTO.md §11 "Secrets
    /// before commit" ("the client fetches `account-state`: if the server holds the new state
    /// it finalises, otherwise it resends the same request"):
    /// - [`CliError::Network`]: no answer arrived;
    /// - [`CliError::BadAnswer`]: a proxy's `502`/`504` page, a truncated or oversized body,
    ///   a success of the wrong shape, none of which says what the server behind did;
    /// - `internal` and an unknown code: the server failed, or said something this build
    ///   cannot read, possibly after the transaction committed;
    /// - [`CliError::RateLimited`]: not applied, but the same bytes are good later, so the
    ///   saved state is kept and sent again rather than thrown away.
    #[must_use]
    pub const fn refuses_commit(&self) -> bool {
        matches!(
            self,
            Self::Server(
                ErrorCode::InvalidRequest
                    | ErrorCode::Unauthorized
                    | ErrorCode::SecondFactorRequired
                    | ErrorCode::FreshSessionRequired
                    | ErrorCode::StateConflict
                    | ErrorCode::StaleEpoch
                    | ErrorCode::RecordConflict
                    | ErrorCode::PrevSeqMismatch
                    | ErrorCode::PayloadTooLarge
                    | ErrorCode::NotFound
                    | ErrorCode::ClientTooOld
                    | ErrorCode::ApiVersionGone
            )
        )
    }

    /// Whether this error, as the answer to a commit, leaves unknown whether the server
    /// applied it: neither a refusal ([`CliError::refuses_commit`]) nor a rate limit (not
    /// applied, to be sent again later).
    #[must_use]
    pub const fn outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::Network
                | Self::BadAnswer
                | Self::Server(ErrorCode::Internal | ErrorCode::Unknown)
        )
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(what) => write!(f, "{what}"),
            Self::Client(e) => write!(f, "{e} ({})", e.code()),
            Self::Server(code) => write!(f, "the server refused: {}", code_name(*code)),
            Self::RateLimited(Some(seconds)) => write!(
                f,
                "the server is rate-limiting this; try again in {seconds} seconds"
            ),
            Self::RateLimited(None) => f.write_str("the server is rate-limiting this; try later"),
            Self::BadAnswer => f.write_str("the server's answer is not a rizzy-vault API answer"),
            Self::Network => f.write_str(
                "the connection failed; whether the request was applied is unknown, so run `rv sync` before repeating it",
            ),
            Self::InsecureOrigin => f.write_str(
                "refusing an http:// server that is not localhost or a loopback address; use https://",
            ),
            Self::Tls { origin, failure } => write!(
                f,
                "TLS with {origin} failed: {}; nothing was sent",
                failure.text()
            ),
            Self::Io(what, kind) => write!(f, "{what}: {kind}"),
            Self::FileExists => {
                f.write_str("file exists; name another path or remove it (rv never overwrites)")
            }
            Self::InUse => f.write_str("the local data is in use by another rv"),
            Self::Database => f.write_str("the local data could not be read or written"),
            Self::NotEnrolled => f.write_str(
                "no device is enrolled here; run `rv signup` or `rv login` (or pass --account)",
            ),
            Self::SeveralAccounts => {
                f.write_str("several accounts are enrolled here; pass --account <id>")
            }
            Self::AlreadyEnrolled => {
                f.write_str("a device of this account is already enrolled here")
            }
            Self::NoTerminal => f.write_str(
                "cannot read this from the terminal (echo cannot be turned off, or no terminal); \
                 secrets can be piped on standard input, one per line",
            ),
            Self::InputEnded => f.write_str("standard input ended before an answer was read"),
            Self::Alarm(alarm) => write!(f, "this device is read-only: {}", alarm_text(*alarm)),
            Self::Import(e) => write!(f, "the file could not be imported: {e}"),
            Self::BadInput(what) => f.write_str(what),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ClientError> for CliError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

/// What an alarm means, in the words of CRYPTO.md §11.3 step 2.5 and ADR 0026 §4 step 7.
#[must_use]
pub const fn alarm_text(alarm: Alarm) -> &'static str {
    match alarm {
        Alarm::Rollback => "possible rollback by the server",
        Alarm::Fork => "the server has shown two versions of this account",
        Alarm::UnconfirmedIdentityChange => {
            "the account's identity key changed and was not confirmed on this device"
        }
        Alarm::DeviceStateOutdated => {
            "the local data is older than this device's own history (a restored image or a \
             copied profile); remove this device with `rv device forget` and log in again"
        }
    }
}

/// The wire name of a server error code (ADR 0028 item 3), for messages.
fn code_name(code: ErrorCode) -> String {
    serde_json::to_string(&code)
        .map_or_else(|_| "unknown".to_owned(), |s| s.trim_matches('"').to_owned())
}

/// Maps an I/O error to [`CliError::Io`], keeping its kind only.
pub(crate) fn io_error(what: &'static str) -> impl FnOnce(io::Error) -> CliError {
    move |e| CliError::Io(what, e.kind())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which answers to a commit prove a refusal, which leave the outcome unknown, and that
    /// no answer is both (CRYPTO.md §11 "Secrets before commit"; ADR 0028 item 3).
    #[test]
    fn only_an_api_refusal_proves_a_commit_was_not_applied() {
        for refusal in [
            ErrorCode::InvalidRequest,
            ErrorCode::Unauthorized,
            ErrorCode::FreshSessionRequired,
            ErrorCode::StateConflict,
            ErrorCode::PayloadTooLarge,
            ErrorCode::ClientTooOld,
        ] {
            let e = CliError::Server(refusal);
            assert!(e.refuses_commit() && !e.outcome_unknown(), "{refusal:?}");
        }
        for unknown in [
            CliError::Network,
            CliError::BadAnswer,
            CliError::Server(ErrorCode::Internal),
            CliError::Server(ErrorCode::Unknown),
        ] {
            assert!(
                !unknown.refuses_commit() && unknown.outcome_unknown(),
                "{unknown:?}"
            );
        }
        // Not applied, but the same bytes are good later: kept, and not "unknown".
        let limited = CliError::RateLimited(Some(3));
        assert!(!limited.refuses_commit() && !limited.outcome_unknown());
        // A failed handshake sent nothing: not applied, but no API refusal either, so what
        // was saved for the commit is kept (ADR 0030 Decision 6).
        let tls = CliError::Tls {
            origin: "https://vault.example.com".to_owned(),
            failure: TlsFailure::UnknownIssuer,
        };
        assert!(!tls.refuses_commit() && !tls.outcome_unknown());
        assert!(tls.to_string().contains("https://vault.example.com"));
    }
}
