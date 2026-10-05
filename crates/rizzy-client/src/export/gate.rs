//! The gates in front of every export (owner decision 2026-10-05): a fresh re-authentication
//! before any export, encrypted or plaintext, and a 10-second hold after the plaintext
//! warning.
//!
//! # What the owner decided, and where it comes from
//!
//! | Gate | Applies to | Source |
//! |---|---|---|
//! | Re-authentication with the current master password (and the Secret Key, as a login needs it): an OPAQUE login of the same account, accepted for [`REAUTH_WINDOW_MS`] and spent by one export | every export | owner decision 2026-10-05; for plaintext also [ADR 0013] §3 rule 2 ("an explicit plaintext export, after re-authentication") |
//! | The warning, then the typed `EXPORT PLAINTEXT` ([`PlaintextExportAck`](super::plaintext::PlaintextExportAck)) | plaintext | [ADR 0027] §5 (Accepted) |
//! | A hold of [`PLAINTEXT_EXPORT_HOLD_MS`] after the warning is shown, before the export may proceed | plaintext | owner decision 2026-10-05 |
//!
//! The re-authentication for an encrypted export and the 10-second hold are additions to ADR
//! 0027 that an amendment or note to it should record (reported; this module does not edit
//! the ADR).
//!
//! # How a host uses it
//!
//! 1. It runs the OPAQUE login itself (it owns the transport) and, once the login verified,
//!    calls [`ExportGate::accept_reauth`] with the account the login verified and the account
//!    of the session. Another account is refused as a wrong password.
//! 2. For a plaintext export it shows the warning and calls
//!    [`ExportGate::plaintext_warning_shown`]; each call restarts the hold (a dialog shown
//!    again starts its countdown again).
//! 3. It asks for [`ExportGate::authorize_encrypted`] or [`ExportGate::authorize_plaintext`]
//!    right before the export. Success spends the re-authentication (and the hold): one
//!    re-authentication allows one export. A refusal spends nothing.
//! 4. The token goes into [`VaultSync::export_encrypted`](crate::sync::VaultSync::export_encrypted),
//!    [`VaultSync::export_plaintext_json`](crate::sync::VaultSync::export_plaintext_json) or
//!    [`VaultSync::export_plaintext_csv`](crate::sync::VaultSync::export_plaintext_csv), which
//!    take no export without one. The tokens have no public constructor.
//!
//! # Clocks
//!
//! The host's clock decides (this crate reads none). A clock that goes backwards counts as no
//! time passed: the re-authentication is no longer fresh and the hold starts over, never the
//! other way. A host that lies to itself only weakens its own check (ADR 0013 §4, "Honest
//! limit"); `rv` measures its hold with a monotonic clock and holds the terminal for the whole
//! time.
//!
//! [ADR 0013]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0013-shared-client-core.md
//! [ADR 0027]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0027-export-payload.md

use rizzy_core::ids::AccountId;
use rizzy_core::kdf::check_new_password;

use crate::error::ClientError;

/// How long an accepted re-authentication allows one export: 5 minutes, the freshness window
/// CRYPTO.md §11 "Replacing credentials" gives the server's fresh session.
pub const REAUTH_WINDOW_MS: u64 = 5 * 60 * 1000;

/// How long a host holds the user after showing the plaintext-export warning before the
/// export may proceed: 10 seconds (owner decision 2026-10-05).
pub const PLAINTEXT_EXPORT_HOLD_MS: u64 = 10_000;

/// The checks CRYPTO.md §2 "New passwords" runs on a newly chosen export password: not empty,
/// no unassigned code point. A host runs it before it spends a re-authentication, so a
/// refused password does not cost the user another login; the export runs it again.
///
/// # Errors
/// [`ClientError::InvalidInput`].
pub fn check_export_password(password: &str) -> Result<(), ClientError> {
    if password.is_empty() {
        return Err(ClientError::InvalidInput);
    }
    check_new_password(password).map_err(|_| ClientError::InvalidInput)
}

/// Permission for one encrypted export (module docs). Only [`ExportGate::authorize_encrypted`]
/// makes one; the export consumes it.
#[derive(Debug)]
pub struct EncryptedExportAuth(());

/// Permission for one plaintext export (module docs). Only [`ExportGate::authorize_plaintext`]
/// makes one; the export consumes it, with the typed acknowledgement.
#[derive(Debug)]
pub struct PlaintextExportAuth(());

impl EncryptedExportAuth {
    /// Takes the token apart, for the export that consumes it.
    pub(crate) const fn spend(self) {
        let Self(()) = self;
    }
}

impl PlaintextExportAuth {
    /// Takes the token apart, for the export that consumes it.
    pub(crate) const fn spend(self) {
        let Self(()) = self;
    }
}

/// The state of the export gates of one session (module docs). Holds two times and nothing
/// secret.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExportGate {
    /// When the last accepted re-authentication happened, while it is unspent.
    reauth_at_ms: Option<u64>,
    /// When the plaintext warning was last shown, while unspent.
    warning_at_ms: Option<u64>,
}

impl ExportGate {
    /// A gate with nothing accepted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reauth_at_ms: None,
            warning_at_ms: None,
        }
    }

    /// Accepts a verified re-authentication: `reauthenticated` is the account the OPAQUE
    /// login verified, `expected` the session's.
    ///
    /// # Errors
    /// [`ClientError::WrongPasswordOrSecretKey`] when they differ (credentials of another
    /// account); nothing is accepted.
    pub fn accept_reauth(
        &mut self,
        reauthenticated: AccountId,
        expected: AccountId,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        if reauthenticated != expected {
            return Err(ClientError::WrongPasswordOrSecretKey);
        }
        self.reauth_at_ms = Some(now_ms);
        Ok(())
    }

    /// Whether an unspent re-authentication is fresh at `now_ms`.
    #[must_use]
    pub fn reauth_fresh(&self, now_ms: u64) -> bool {
        self.reauth_at_ms
            .is_some_and(|at| now_ms >= at && now_ms - at <= REAUTH_WINDOW_MS)
    }

    /// Records that the plaintext warning is shown at `now_ms`: the hold starts, or starts
    /// over.
    pub const fn plaintext_warning_shown(&mut self, now_ms: u64) {
        self.warning_at_ms = Some(now_ms);
    }

    /// How much of the hold is left at `now_ms`: [`PLAINTEXT_EXPORT_HOLD_MS`] when the warning
    /// was not shown (or the clock went back), 0 once the hold is over.
    #[must_use]
    pub fn plaintext_hold_remaining_ms(&self, now_ms: u64) -> u64 {
        match self.warning_at_ms {
            Some(at) if now_ms >= at => PLAINTEXT_EXPORT_HOLD_MS.saturating_sub(now_ms - at),
            _ => PLAINTEXT_EXPORT_HOLD_MS,
        }
    }

    /// Forgets everything accepted (a lock, a closed dialog).
    pub const fn clear(&mut self) {
        self.reauth_at_ms = None;
        self.warning_at_ms = None;
    }

    /// Permission for one encrypted export; spends the re-authentication.
    ///
    /// # Errors
    /// [`ClientError::ReauthRequired`] without a fresh re-authentication; nothing is spent.
    pub fn authorize_encrypted(&mut self, now_ms: u64) -> Result<EncryptedExportAuth, ClientError> {
        if !self.reauth_fresh(now_ms) {
            return Err(ClientError::ReauthRequired);
        }
        self.clear();
        Ok(EncryptedExportAuth(()))
    }

    /// Permission for one plaintext export; spends the re-authentication and the hold.
    ///
    /// # Errors
    /// [`ClientError::ReauthRequired`] without a fresh re-authentication;
    /// [`ClientError::PlaintextExportHold`] while the hold runs (or the warning was not
    /// shown). Nothing is spent.
    pub fn authorize_plaintext(&mut self, now_ms: u64) -> Result<PlaintextExportAuth, ClientError> {
        if !self.reauth_fresh(now_ms) {
            return Err(ClientError::ReauthRequired);
        }
        if self.plaintext_hold_remaining_ms(now_ms) > 0 {
            return Err(ClientError::PlaintextExportHold);
        }
        self.clear();
        Ok(PlaintextExportAuth(()))
    }
}

/// A gate already passed, for the crate's own tests.
#[cfg(test)]
pub(crate) fn test_auth() -> (EncryptedExportAuth, PlaintextExportAuth) {
    (EncryptedExportAuth(()), PlaintextExportAuth(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: AccountId = AccountId::from_bytes([1; 16]);
    const B: AccountId = AccountId::from_bytes([2; 16]);
    const T: u64 = 1_790_000_000_000;

    #[test]
    fn nothing_is_allowed_without_a_reauthentication() {
        let mut gate = ExportGate::new();
        assert_eq!(
            gate.authorize_encrypted(T).unwrap_err(),
            ClientError::ReauthRequired
        );
        gate.plaintext_warning_shown(T);
        assert_eq!(
            gate.authorize_plaintext(T + PLAINTEXT_EXPORT_HOLD_MS)
                .unwrap_err(),
            ClientError::ReauthRequired
        );
    }

    #[test]
    fn another_account_is_a_wrong_password() {
        let mut gate = ExportGate::new();
        assert_eq!(
            gate.accept_reauth(B, A, T).unwrap_err(),
            ClientError::WrongPasswordOrSecretKey
        );
        assert!(!gate.reauth_fresh(T));
    }

    #[test]
    fn one_reauthentication_allows_one_export_within_the_window() {
        let mut gate = ExportGate::new();
        gate.accept_reauth(A, A, T).unwrap();
        assert!(gate.reauth_fresh(T + REAUTH_WINDOW_MS));
        gate.authorize_encrypted(T + REAUTH_WINDOW_MS).unwrap();
        assert_eq!(
            gate.authorize_encrypted(T + 1).unwrap_err(),
            ClientError::ReauthRequired
        );
        gate.accept_reauth(A, A, T).unwrap();
        assert_eq!(
            gate.authorize_encrypted(T + REAUTH_WINDOW_MS + 1)
                .unwrap_err(),
            ClientError::ReauthRequired
        );
        // A clock that went back is not fresh either.
        gate.accept_reauth(A, A, T).unwrap();
        assert_eq!(
            gate.authorize_encrypted(T - 1).unwrap_err(),
            ClientError::ReauthRequired
        );
    }

    #[test]
    fn the_plaintext_hold_is_ten_seconds_after_the_warning() {
        assert_eq!(PLAINTEXT_EXPORT_HOLD_MS, 10_000);
        let mut gate = ExportGate::new();
        gate.accept_reauth(A, A, T).unwrap();
        // Not shown: the whole hold is left.
        assert_eq!(gate.plaintext_hold_remaining_ms(T + 60_000), 10_000);
        assert_eq!(
            gate.authorize_plaintext(T + 60_000).unwrap_err(),
            ClientError::PlaintextExportHold
        );
        gate.plaintext_warning_shown(T);
        assert_eq!(gate.plaintext_hold_remaining_ms(T + 9_999), 1);
        assert_eq!(
            gate.authorize_plaintext(T + 9_999).unwrap_err(),
            ClientError::PlaintextExportHold
        );
        // Shown again: the hold starts over.
        gate.plaintext_warning_shown(T + 5_000);
        assert_eq!(
            gate.authorize_plaintext(T + 10_000).unwrap_err(),
            ClientError::PlaintextExportHold
        );
        assert_eq!(gate.plaintext_hold_remaining_ms(T + 15_000), 0);
        // A refusal spent nothing.
        gate.authorize_plaintext(T + 15_000).unwrap();
        assert_eq!(
            gate.authorize_plaintext(T + 15_000).unwrap_err(),
            ClientError::ReauthRequired
        );
        // Spent: the next plaintext export needs the warning again.
        gate.accept_reauth(A, A, T + 16_000).unwrap();
        assert_eq!(
            gate.authorize_plaintext(T + 40_000).unwrap_err(),
            ClientError::PlaintextExportHold
        );
        // A clock that went back starts the hold over.
        gate.plaintext_warning_shown(T + 20_000);
        assert_eq!(gate.plaintext_hold_remaining_ms(T + 19_000), 10_000);
    }

    #[test]
    fn export_passwords_get_the_new_password_checks() {
        assert_eq!(check_export_password(""), Err(ClientError::InvalidInput));
        assert_eq!(
            check_export_password("a\u{0378}b"),
            Err(ClientError::InvalidInput)
        );
        assert_eq!(check_export_password("file password"), Ok(()));
    }
}
