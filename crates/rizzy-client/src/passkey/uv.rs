// SPDX-License-Identifier: AGPL-3.0-only

//! `UV` under the lock settings ([ADR 0110] §5 point 2, §6, §7 point 4; INV-123).
//!
//! The extension signs a ceremony with `UV=1` only when one of two things holds, decided at
//! signing time by [`decide_uv`] and nowhere else (§6 point 5):
//!
//! - the policy is **bounding**: the session was unlocked with the master password and its lock
//!   settings bound the unlocked time ([`LockSettings::is_bounding`], §6 point 1); or
//! - the session's `verified_at` is **fresh**: a master-password verification succeeded no more
//!   than [`UV_FRESH_MS`] before `now`, by the host clock ([`is_fresh`], §6 points 2 and 4).
//!
//! Otherwise a [`UvRequirement::Required`] request is not signed at all
//! ([`UvDecision::UvRequired`], which the host answers with the re-verification of §7), and a
//! Preferred or Discouraged one is signed with `UV=0`. A Required request is never answered
//! with `UV=0`.
//!
//! [`UvState`] is the part of an unlocked session this rule reads: how the session was unlocked
//! and its `verified_at`. It lives in memory only, inside the session object of the long-lived
//! context (§6 point 4); nothing here writes it anywhere, and dropping the session drops it.
//! [`reverify`] is §7 point 4.3's primitive: the local unlock run once more, its keys dropped.
//!
//! No I/O and no clock: `now_ms` always comes from the caller.
//!
//! [ADR 0110]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0110-passkey-user-verification.md

use crate::device::DeviceState;
use crate::error::ClientError;
use crate::lock_settings::{LockSettings, UnlockedBy};

/// How long a master-password verification counts as user verification when the policy is not
/// bounding (ADR 0110 §6 point 2): 5 minutes, ADR 0034's `REAUTH_WINDOW_MS`.
pub const UV_FRESH_MS: u64 = 300_000;

/// The relying party's `userVerification` requirement, as the background maps the relayed
/// string (ADR 0110 §5 point 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UvRequirement {
    /// `"required"`: verified or not signed.
    Required,
    /// `"preferred"`, absent, or any other value: the `WebAuthn` default.
    Preferred,
    /// `"discouraged"`.
    Discouraged,
}

impl UvRequirement {
    /// Maps the page's relayed value: exactly `"required"` and `"discouraged"` are recognised;
    /// anything else, `"REQUIRED"` and an absent value included, is
    /// [`UvRequirement::Preferred`] (§5 point 2). The value is page-supplied, and that is
    /// acceptable: a page can only lower its own ceremony's requirement (§5 point 3).
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("required") => Self::Required,
            Some("discouraged") => Self::Discouraged,
            _ => Self::Preferred,
        }
    }

    /// The canonical name: `"required"`, `"preferred"` or `"discouraged"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Preferred => "preferred",
            Self::Discouraged => "discouraged",
        }
    }
}

/// The `UV` flag of one ceremony's `authenticatorData`. Callers get it from
/// [`UvDecision::user_verified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerified {
    /// `UV=1`.
    Yes,
    /// `UV=0`.
    No,
}

/// The result of [`decide_uv`] (ADR 0110 §6's table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UvDecision {
    /// Sign, with `UV` set exactly when `uv` is true.
    Sign {
        /// The `UV` flag.
        uv: bool,
    },
    /// Do not sign: a Required request, the policy not bounding and `verified_at` not fresh.
    /// The host starts the re-verification of §7.
    UvRequired,
}

impl UvDecision {
    /// The flag to sign with.
    ///
    /// # Errors
    /// [`ClientError::UvRequired`] for [`UvDecision::UvRequired`]: nothing is to be signed.
    pub const fn user_verified(self) -> Result<UserVerified, ClientError> {
        match self {
            Self::Sign { uv: true } => Ok(UserVerified::Yes),
            Self::Sign { uv: false } => Ok(UserVerified::No),
            Self::UvRequired => Err(ClientError::UvRequired),
        }
    }
}

/// Whether `verified_at` is fresh at `now_ms` (ADR 0110 §6 point 4): `Some(t)` with
/// `0 ≤ now_ms − t ≤ UV_FRESH_MS`. A clock that went back (`now_ms < t`) is not fresh (ADR 0034
/// point 2), nor is `None`.
#[must_use]
pub const fn is_fresh(verified_at: Option<u64>, now_ms: u64) -> bool {
    match verified_at {
        Some(t) => match now_ms.checked_sub(t) {
            Some(elapsed) => elapsed <= UV_FRESH_MS,
            None => false,
        },
        None => false,
    }
}

/// ADR 0110 §6's rule, the one function every ceremony goes through at signing time.
/// `bounding` is [`LockSettings::is_bounding`] of the current settings and the session's
/// [`UnlockedBy`] ([`UvState::decide`] computes it).
///
/// | `bounding` | requirement | fresh | result |
/// |---|---|---|---|
/// | yes | any | – | `Sign { uv: true }` |
/// | no | Required | yes / no | `Sign { uv: true }` / `UvRequired` |
/// | no | Preferred, Discouraged | yes / no | `Sign { uv: true }` / `Sign { uv: false }` |
#[must_use]
pub const fn decide_uv(
    requirement: UvRequirement,
    bounding: bool,
    verified_at: Option<u64>,
    now_ms: u64,
) -> UvDecision {
    if bounding || is_fresh(verified_at, now_ms) {
        return UvDecision::Sign { uv: true };
    }
    match requirement {
        UvRequirement::Required => UvDecision::UvRequired,
        UvRequirement::Preferred | UvRequirement::Discouraged => UvDecision::Sign { uv: false },
    }
}

/// What one unlocked session holds for [`decide_uv`] (ADR 0110 §6 point 4): how it was unlocked
/// and `verified_at`, in milliseconds since the Unix epoch by the host clock. In memory only;
/// never persisted. `Debug` shows both: neither is a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UvState {
    /// The last unlock of the session.
    unlocked_by: UnlockedBy,
    /// The last successful master-password verification of the session.
    verified_at: Option<u64>,
}

impl UvState {
    /// A session just unlocked with the master password at `now_ms`: the local unlock
    /// ([`DeviceState::unlock`]) or the master-password OPAQUE login at enrolment. `verified_at`
    /// is `now_ms`.
    #[must_use]
    pub const fn master_password(now_ms: u64) -> Self {
        Self {
            unlocked_by: UnlockedBy::MasterPassword,
            verified_at: Some(now_ms),
        }
    }

    /// A session unlocked any other way (a keystore-gated unlock, the device key, a
    /// recovery-code flow): never bounding, and not verified until a [`reverify`] succeeds.
    #[must_use]
    pub const fn other() -> Self {
        Self {
            unlocked_by: UnlockedBy::Other,
            verified_at: None,
        }
    }

    /// A session unlocked with the master password whose host keeps no `verified_at` (the web
    /// vault: §6 point 4 holds `verified_at` in the extension's long-lived context only). It can
    /// be bounding; it is never fresh.
    #[must_use]
    pub const fn master_password_unverified() -> Self {
        Self {
            unlocked_by: UnlockedBy::MasterPassword,
            verified_at: None,
        }
    }

    /// How the session was unlocked.
    #[must_use]
    pub const fn unlocked_by(&self) -> UnlockedBy {
        self.unlocked_by
    }

    /// The last successful master-password verification, if any.
    #[must_use]
    pub const fn verified_at(&self) -> Option<u64> {
        self.verified_at
    }

    /// [`decide_uv`] for this session under `settings` at `now_ms`.
    #[must_use]
    pub const fn decide(
        &self,
        requirement: UvRequirement,
        settings: &LockSettings,
        now_ms: u64,
    ) -> UvDecision {
        decide_uv(
            requirement,
            settings.is_bounding(self.unlocked_by),
            self.verified_at,
            now_ms,
        )
    }
}

/// The re-verification of ADR 0110 §7 point 4.3: runs the local unlock primitive
/// ([`DeviceState::unlock`], CRYPTO.md §11.3's offline part, the one the session's own unlock
/// ran) against `device`, the device state the session was unlocked from, and drops the keys
/// it opens at once (they zeroize on drop). Nothing of the running session is compared or
/// replaced; only `state`'s `verified_at` becomes `now_ms`, on success. How the session was
/// unlocked does not change, so a session unlocked another way does not become bounding.
///
/// # Errors
/// [`ClientError::WrongPasswordOrSecretKey`] for a wrong password, and whatever else
/// [`DeviceState::unlock`] returns; `state` is unchanged then.
pub fn reverify(
    state: &mut UvState,
    device: &DeviceState,
    password: &str,
    now_ms: u64,
) -> Result<(), ClientError> {
    drop(device.unlock(password)?);
    state.verified_at = Some(now_ms);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        UV_FRESH_MS, UserVerified, UvDecision, UvRequirement, UvState, decide_uv, is_fresh,
    };
    use crate::error::ClientError;
    use crate::lock_settings::{IDLE_MINUTES, LockSettings, UnlockedBy};

    const T: u64 = 1_800_000_000_000;

    fn settings(auto_lock: bool, idle_minutes: u16) -> LockSettings {
        LockSettings::new(auto_lock, idle_minutes, true).unwrap()
    }

    #[test]
    fn the_requirement_parser_recognises_two_exact_values_and_defaults_to_preferred() {
        let cases = [
            (Some("required"), UvRequirement::Required),
            (Some("discouraged"), UvRequirement::Discouraged),
            (Some("preferred"), UvRequirement::Preferred),
            (None, UvRequirement::Preferred),
            (Some(""), UvRequirement::Preferred),
            (Some("REQUIRED"), UvRequirement::Preferred),
            (Some("Required"), UvRequirement::Preferred),
            (Some(" required"), UvRequirement::Preferred),
            (Some("required "), UvRequirement::Preferred),
            (Some("DISCOURAGED"), UvRequirement::Preferred),
            (Some("whatever"), UvRequirement::Preferred),
        ];
        for (value, expected) in cases {
            assert_eq!(UvRequirement::parse(value), expected, "{value:?}");
        }
        for requirement in [
            UvRequirement::Required,
            UvRequirement::Preferred,
            UvRequirement::Discouraged,
        ] {
            assert_eq!(
                UvRequirement::parse(Some(requirement.as_str())),
                requirement
            );
        }
    }

    #[test]
    fn freshness_holds_from_t_to_t_plus_uv_fresh_ms_and_a_clock_back_is_stale() {
        assert_eq!(UV_FRESH_MS, 300_000);
        assert!(is_fresh(Some(T), T));
        assert!(is_fresh(Some(T), T + 1));
        assert!(is_fresh(Some(T), T + UV_FRESH_MS));
        assert!(!is_fresh(Some(T), T + UV_FRESH_MS + 1));
        assert!(!is_fresh(Some(T), T - 1));
        assert!(!is_fresh(Some(T), 0));
        assert!(!is_fresh(None, T));
        assert!(!is_fresh(Some(u64::MAX), 0));
        assert!(is_fresh(Some(u64::MAX), u64::MAX));
    }

    /// ADR 0110 §6's table, row by row. Fresh is `verified_at = T` at `T` and at
    /// `T + UV_FRESH_MS`; not fresh is `None`, `T + UV_FRESH_MS + 1` and a clock back to `T - 1`.
    #[test]
    fn the_decision_follows_adr_0110_section_6s_table() {
        use UvRequirement::{Discouraged, Preferred, Required};
        let sign = |uv| UvDecision::Sign { uv };
        let fresh = [(Some(T), T), (Some(T), T + UV_FRESH_MS)];
        let stale = [(None, T), (Some(T), T + UV_FRESH_MS + 1), (Some(T), T - 1)];
        // (bounding, requirement, fresh?, expected)
        let table = [
            (true, Required, true, sign(true)),
            (true, Required, false, sign(true)),
            (true, Preferred, true, sign(true)),
            (true, Preferred, false, sign(true)),
            (true, Discouraged, true, sign(true)),
            (true, Discouraged, false, sign(true)),
            (false, Required, true, sign(true)),
            (false, Required, false, UvDecision::UvRequired),
            (false, Preferred, true, sign(true)),
            (false, Preferred, false, sign(false)),
            (false, Discouraged, true, sign(true)),
            (false, Discouraged, false, sign(false)),
        ];
        for (bounding, requirement, is_fresh_row, expected) in table {
            let cases: &[(Option<u64>, u64)] = if is_fresh_row { &fresh } else { &stale };
            for &(verified_at, now) in cases {
                assert_eq!(
                    decide_uv(requirement, bounding, verified_at, now),
                    expected,
                    "{bounding} {requirement:?} {verified_at:?} {now}"
                );
            }
        }
    }

    #[test]
    fn required_is_never_signed_without_uv() {
        for bounding in [true, false] {
            for verified_at in [None, Some(0), Some(T), Some(u64::MAX)] {
                for now in [0, T - 1, T, T + UV_FRESH_MS, T + UV_FRESH_MS + 1, u64::MAX] {
                    let decision = decide_uv(UvRequirement::Required, bounding, verified_at, now);
                    assert_ne!(decision, UvDecision::Sign { uv: false });
                }
            }
        }
    }

    #[test]
    fn uv_required_reaches_the_caller_as_the_uv_required_error() {
        assert_eq!(
            UvDecision::UvRequired.user_verified(),
            Err(ClientError::UvRequired)
        );
        assert_eq!(ClientError::UvRequired.code(), "uv_required");
        assert_eq!(
            UvDecision::Sign { uv: true }.user_verified(),
            Ok(UserVerified::Yes)
        );
        assert_eq!(
            UvDecision::Sign { uv: false }.user_verified(),
            Ok(UserVerified::No)
        );
    }

    /// §6 point 1: bounding at 1, 2 and 5 minutes, not at 10, 15, 30, 60 or 240, and never with
    /// locking off; only for a master-password unlock.
    #[test]
    fn a_master_password_session_is_bounding_at_1_2_and_5_minutes_only() {
        let unverified = UvState::master_password_unverified();
        for minutes in IDLE_MINUTES {
            let on = settings(true, minutes);
            let bounding = matches!(minutes, 1 | 2 | 5);
            assert_eq!(
                on.is_bounding(UnlockedBy::MasterPassword),
                bounding,
                "{minutes}"
            );
            let expected = if bounding {
                UvDecision::Sign { uv: true }
            } else {
                UvDecision::UvRequired
            };
            assert_eq!(unverified.decide(UvRequirement::Required, &on, T), expected);
            let off = settings(false, minutes);
            assert!(!off.is_bounding(UnlockedBy::MasterPassword));
            assert_eq!(
                unverified.decide(UvRequirement::Required, &off, T),
                UvDecision::UvRequired
            );
        }
        for minutes in [10, 15, 30, 60, 240] {
            assert!(!settings(true, minutes).is_bounding(UnlockedBy::MasterPassword));
        }
        assert!(LockSettings::DEFAULT.is_bounding(UnlockedBy::MasterPassword));
    }

    /// A keystore-unlocked (or any other non-password) session is never bounding, whatever the
    /// settings, and starts with no `verified_at`.
    #[test]
    fn a_keystore_unlocked_session_is_never_bounding_and_never_fresh() {
        let state = UvState::other();
        assert_eq!(state.unlocked_by(), UnlockedBy::Other);
        assert_eq!(state.verified_at(), None);
        for minutes in IDLE_MINUTES {
            for auto_lock in [true, false] {
                let s = settings(auto_lock, minutes);
                assert!(!s.is_bounding(UnlockedBy::Other));
                assert_eq!(
                    state.decide(UvRequirement::Required, &s, T),
                    UvDecision::UvRequired
                );
                assert_eq!(
                    state.decide(UvRequirement::Preferred, &s, T),
                    UvDecision::Sign { uv: false }
                );
            }
        }
    }

    #[test]
    fn a_master_password_unlock_is_fresh_for_uv_fresh_ms() {
        let state = UvState::master_password(T);
        assert_eq!(state.unlocked_by(), UnlockedBy::MasterPassword);
        assert_eq!(state.verified_at(), Some(T));
        let loose = settings(true, 60);
        let required = UvRequirement::Required;
        assert_eq!(
            state.decide(required, &loose, T + UV_FRESH_MS),
            UvDecision::Sign { uv: true }
        );
        assert_eq!(
            state.decide(required, &loose, T + UV_FRESH_MS + 1),
            UvDecision::UvRequired
        );
        assert_eq!(
            state.decide(required, &loose, T - 1),
            UvDecision::UvRequired
        );
    }

    /// §6 point 6: turning locking off or raising the idle time never yields more `UV` than the
    /// stronger settings did, for every requirement, kind of session, `verified_at` and `now`.
    /// "More" orders `UvRequired` < `UV=0` < `UV=1`.
    #[test]
    fn weakening_the_lock_settings_never_yields_more_uv() {
        const fn rank(decision: UvDecision) -> u8 {
            match decision {
                UvDecision::UvRequired => 0,
                UvDecision::Sign { uv: false } => 1,
                UvDecision::Sign { uv: true } => 2,
            }
        }
        /// Whether `weak` is at most as strong as `strong`: locking off is weaker than on, and a
        /// longer idle time weaker than a shorter one.
        fn weaker_or_equal(weak: LockSettings, strong: LockSettings) -> bool {
            !weak.auto_lock()
                || (strong.auto_lock() && weak.idle_minutes() >= strong.idle_minutes())
        }
        let mut all = Vec::new();
        for minutes in IDLE_MINUTES {
            for auto_lock in [true, false] {
                all.push(settings(auto_lock, minutes));
            }
        }
        let mut verified_other = UvState::other();
        verified_other.verified_at = Some(T);
        let states = [
            UvState::master_password(T),
            UvState::master_password_unverified(),
            UvState::other(),
            verified_other,
        ];
        let requirements = [
            UvRequirement::Required,
            UvRequirement::Preferred,
            UvRequirement::Discouraged,
        ];
        let mut compared = 0_u32;
        for &strong in &all {
            for &weak in all.iter().filter(|&&w| weaker_or_equal(w, strong)) {
                for state in states {
                    for requirement in requirements {
                        for now in [T - 1, T, T + UV_FRESH_MS, T + UV_FRESH_MS + 1] {
                            let before = rank(state.decide(requirement, &strong, now));
                            let after = rank(state.decide(requirement, &weak, now));
                            assert!(
                                after <= before,
                                "{strong:?} -> {weak:?}, {state:?}, {requirement:?}, {now}"
                            );
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert!(compared > 0);
    }
}
