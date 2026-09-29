//! The errors of the vault domain.
//!
//! **What an error may say** (threat model INV-48). A message names a rule, a table or column,
//! or a kind of failure; never a bound value, an envelope, a statement, a header byte or any key.
//! Ids are server-visible routing metadata, but errors carry none either: the one report that
//! names ids is [`IntegrityError`](crate::fetch::IntegrityError), which ADR 0021 §4 asks for.
//!
//! Every error maps to one [`ErrorCode`] with [`VaultError::code`], so `rizzy-server` answers
//! with the uniform error body of `rizzy-proto` (ADR 0002 point 3; threat model §7.6 "I").

use core::fmt;

use rizzy_proto::error::ErrorCode;

use crate::authors::DirectoryError;

/// A request the vault domain could not serve at all. Refusals of single upload records are not
/// errors: they are [`UploadResult::Rejected`](rizzy_proto::vault::UploadResult) answers.
#[derive(Debug)]
#[non_exhaustive]
pub enum VaultError {
    /// The vault does not exist, or it belongs to another account. The two are not told apart
    /// (threat model §7.6 "I").
    NotFound,
    /// The request breaks a rule of the call it was made to (see that call's docs); answered
    /// `invalid_request`.
    Invalid,
    /// The database failed, or a stored integer is out of range.
    Storage(rizzy_storage::Error),
    /// The `auth` domain could not supply the account's device certificates (ADR 0016 R4).
    Directory(DirectoryError),
    /// The database has no restore generation: `rizzy-server` did not call
    /// `rizzy_storage::meta::ensure_restore_generation` at startup (ADR 0021 §2).
    NoRestoreGeneration,
    /// A stored row does not have the shape this domain wrote: a damaged database or a bug.
    Corrupt {
        /// Which table and column, or which rule.
        what: &'static str,
    },
    /// The wrap-set rows a Fetch must return do not fit one response
    /// ([`MAX_ITEM_KEY_WRAPS`](rizzy_proto::limits::MAX_ITEM_KEY_WRAPS)). `rizzy-proto` has no
    /// way to page them (see the crate docs, "Open wire details"), so the Fetch fails rather
    /// than returning a truncated wrap set.
    WrapSetTooLarge,
}

impl VaultError {
    /// The machine-readable code `rizzy-server` answers with.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::NotFound => ErrorCode::NotFound,
            Self::Invalid => ErrorCode::InvalidRequest,
            Self::Storage(_)
            | Self::Directory(_)
            | Self::NoRestoreGeneration
            | Self::Corrupt { .. }
            | Self::WrapSetTooLarge => ErrorCode::Internal,
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("vault not found"),
            Self::Invalid => f.write_str("request refused by a vault rule"),
            Self::Storage(e) => write!(f, "storage: {e}"),
            Self::Directory(e) => write!(f, "device directory: {e}"),
            Self::NoRestoreGeneration => f.write_str("the database has no restore generation"),
            Self::Corrupt { what } => write!(f, "stored row malformed: {what}"),
            Self::WrapSetTooLarge => f.write_str("the wrap set does not fit one Fetch response"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Directory(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rizzy_storage::Error> for VaultError {
    fn from(e: rizzy_storage::Error) -> Self {
        Self::Storage(e)
    }
}

impl From<sqlx::Error> for VaultError {
    fn from(e: sqlx::Error) -> Self {
        Self::Storage(e.into())
    }
}

impl From<DirectoryError> for VaultError {
    fn from(e: DirectoryError) -> Self {
        Self::Directory(e)
    }
}

/// Why a healing request was not stored (ADR 0021 §9 "Healing request", "Server acceptance").
/// The request is atomic: either every part of it is stored, or nothing is.
#[derive(Debug)]
#[non_exhaustive]
pub enum HealingError {
    /// The server refused the whole request, for the reason the code names:
    /// [`ErrorCode::InvalidRequest`] (a record failed verification or an author rule, a
    /// bodiless header is left without a cover, a snapshot claims unheld dots),
    /// [`ErrorCode::RecordConflict`] (a different record at a stored dot or `snapshot_id`) or
    /// [`ErrorCode::PrevSeqMismatch`] (a header does not extend its chain). Nothing was stored.
    Refused(ErrorCode),
    /// The request could not be served at all; nothing was stored.
    Failed(VaultError),
}

impl HealingError {
    /// The machine-readable code `rizzy-server` answers with.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Refused(code) => *code,
            Self::Failed(e) => e.code(),
        }
    }
}

impl fmt::Display for HealingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(_) => f.write_str("healing request refused"),
            Self::Failed(e) => write!(f, "healing request failed: {e}"),
        }
    }
}

impl std::error::Error for HealingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(_) => None,
            Self::Failed(e) => Some(e),
        }
    }
}

impl From<VaultError> for HealingError {
    fn from(e: VaultError) -> Self {
        Self::Failed(e)
    }
}

impl From<rizzy_storage::Error> for HealingError {
    fn from(e: rizzy_storage::Error) -> Self {
        Self::Failed(e.into())
    }
}

impl From<sqlx::Error> for HealingError {
    fn from(e: sqlx::Error) -> Self {
        Self::Failed(e.into())
    }
}

impl From<DirectoryError> for HealingError {
    fn from(e: DirectoryError) -> Self {
        Self::Failed(e.into())
    }
}
