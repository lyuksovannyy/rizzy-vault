//! The auth domain's configuration: the canonical origin, the signup policy, session
//! lifetimes, the recovery waiting period and the rate limits.
//!
//! Values the specs fix are constants here ([`LOGIN_STATE_TTL_MS`], [`CHALLENGE_TTL_MS`],
//! [`FRESH_SESSION_MS`], [`RECOVERY_SESSION_TTL_MS`], [`REQUEST_WINDOW`]). Values the specs
//! leave to the operator carry a default and a documented bound. Values no Accepted ADR fixes
//! at all (the session lifetimes, the rate-limit numbers) carry a conservative default, and the
//! crate docs list them as open.

use core::fmt;

use rizzy_core::normalize::{LoginName, ServerOrigin};

/// How long a sealed OPAQUE login state lives (CRYPTO.md §5.10: 60 s TTL).
pub const LOGIN_STATE_TTL_MS: u64 = rizzy_core::server_seal::LOGIN_STATE_TTL_MS;

/// How long a device-authentication challenge lives (CRYPTO.md §5.10: 60 s TTL).
pub const CHALLENGE_TTL_MS: u64 = 60_000;

/// How long an OPAQUE session counts as fresh for credential replacement, enrolment and the
/// other operations that need a re-authentication (CRYPTO.md §11 "Replacing credentials":
/// "a fresh OPAQUE session (≤ 5 min)"; §11.5 step 1).
pub const FRESH_SESSION_MS: u64 = 5 * 60_000;

/// The lifetime of the recovery-only session (CRYPTO.md §11.9 step 3: "a 10-minute TTL").
pub const RECOVERY_SESSION_TTL_MS: u64 = 10 * 60_000;

/// The request-counter window of a device-authenticated session (CRYPTO.md §5.10: "accepts
/// each `request_counter` at most once per session, within a sliding window of 64").
pub const REQUEST_WINDOW: u64 = 64;

/// The default, and the highest allowed value, of [`AuthConfig::max_web_certificates`]: the
/// most kind-4 (web vault) certificates one account holds at a time (CRYPTO.md §11.4).
///
/// Every web login stores one, and they never join the device set, so nothing else bounds
/// them; but every account view serves them and a full rotation re-issues them, both within
/// `rizzy_proto::limits::MAX_DEVICE_STATEMENTS` (4096) together with the durable ones. Expired
/// ones that authored nothing are deleted when a new one is uploaded; past this many that
/// remain, the upload is refused with [`crate::AuthError::RateLimited`] (the web vault stays
/// usable for reading; logins, recovery and rotations are never blocked). No Accepted ADR
/// fixes the number; a quarter of the wire limit leaves the rest to durable devices.
pub const MAX_WEB_CERTIFICATES: usize = 1024;

/// The default recovery waiting period (ADR 0008 decision 5, CRYPTO.md §11.9 step 2: 72 h).
pub const DEFAULT_RECOVERY_WAIT_MS: u64 = 72 * 3_600_000;

/// The longest recovery waiting period an admin may configure (ADR 0008 decision 5: "from 0
/// to 30 days").
pub const MAX_RECOVERY_WAIT_MS: u64 = 30 * 24 * 3_600_000;

/// The default admin-set limit of a reconciliation epoch (ADR 0012 §7 "End of the
/// reconciliation epoch": "an admin-set limit (default 30 days)").
pub const DEFAULT_RECONCILIATION_LIMIT_MS: u64 = 30 * 24 * 3_600_000;

/// Decides whether an invite token admits a signup under a login name (CRYPTO.md §5.9: "an
/// admin-issued invite token, bound to a login name").
///
/// The schema has no invite table and no Accepted ADR fixes the token format or who issues it
/// (the admin API is M3), so the check is the server's to wire in. It must bind the token to
/// the name, compare in constant time, and never log the token.
pub trait InviteVerifier: Send + Sync {
    /// Whether `token` admits a signup under `login_name`.
    fn admits(&self, token: &str, login_name: &LoginName) -> bool;
}

/// Who may sign up (CRYPTO.md §5.9: "The M1 default is invite-only signup … Open signup is
/// opt-in, rate-limited per IP").
pub enum SignupPolicy {
    /// Nobody: every registration is refused. The default until an invite verifier is wired.
    Closed,
    /// Invite-only: a registration needs a token the verifier admits for the login name.
    Invite(Box<dyn InviteVerifier>),
    /// Open signup, rate-limited per source, per (name, source) and per name
    /// ([`RateLimits::signup_per_source`], [`RateLimits::signup_per_name_source`],
    /// [`RateLimits::signup_per_name`]).
    Open,
}

impl fmt::Debug for SignupPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "SignupPolicy::Closed",
            Self::Invite(_) => "SignupPolicy::Invite",
            Self::Open => "SignupPolicy::Open",
        })
    }
}

/// One rate-limit rule: at most `max_attempts` counted attempts per `window_ms`, then
/// exponential backoff starting at `backoff_base_ms` and capped at `backoff_max_ms`. The cap
/// keeps it a delay, never a hard lockout (INV-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateRule {
    /// Attempts allowed per window before backoff starts.
    pub max_attempts: u32,
    /// The counting window.
    pub window_ms: u64,
    /// The first backoff delay.
    pub backoff_base_ms: u64,
    /// The longest backoff delay.
    pub backoff_max_ms: u64,
}

/// The rate limits of ADR 0010 §5 and INV-7.
///
/// No Accepted ADR fixes the numbers; the defaults are conservative for a personal server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimits {
    /// Unauthenticated login attempts per (login name, source): exponential backoff (INV-7).
    pub login_per_name_source: RateRule,
    /// Unauthenticated login attempts per login name from every source: the per-account cap
    /// (INV-7).
    pub login_per_name: RateRule,
    /// OPAQUE re-authentication from a device-authenticated session of the same account: its
    /// own bucket, which unauthenticated attempts cannot exhaust (INV-7).
    pub reauth_per_device: RateRule,
    /// Registration attempts per source (CRYPTO.md §5.9: "rate-limited per IP").
    pub signup_per_source: RateRule,
    /// Registration attempts per (login name, source): exponential backoff (INV-7 names
    /// registration too; the "name taken" answer is an enumeration oracle, §5.9).
    pub signup_per_name_source: RateRule,
    /// Registration attempts per login name from every source: the per-name cap (INV-7).
    pub signup_per_name: RateRule,
    /// Recovery attempts per (login name, source), and per login name (CRYPTO.md §11.9 step 2:
    /// "The server rate-limits").
    pub recovery_per_name_source: RateRule,
    /// Recovery attempts per login name from every source.
    pub recovery_per_name: RateRule,
    /// TOTP code checks per account (login, enrolment, removal; CRYPTO.md §11.15 leaves the
    /// rate limiting to the caller). Only a client that verified KE3 or holds a fresh OPAQUE
    /// session reaches a check, so this bounds guessing by someone who knows the password.
    pub totp_per_account: RateRule,
}

impl Default for RateLimits {
    fn default() -> Self {
        let backoff = |max_attempts, window_ms| RateRule {
            max_attempts,
            window_ms,
            backoff_base_ms: 1_000,
            backoff_max_ms: 15 * 60_000,
        };
        Self {
            login_per_name_source: backoff(5, 15 * 60_000),
            login_per_name: backoff(100, 60 * 60_000),
            reauth_per_device: backoff(10, 15 * 60_000),
            signup_per_source: backoff(5, 60 * 60_000),
            signup_per_name_source: backoff(5, 60 * 60_000),
            signup_per_name: backoff(20, 60 * 60_000),
            recovery_per_name_source: backoff(5, 60 * 60_000),
            recovery_per_name: backoff(20, 60 * 60_000),
            totp_per_account: backoff(10, 15 * 60_000),
        }
    }
}

/// Why an [`AuthConfig`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The recovery waiting period is above [`MAX_RECOVERY_WAIT_MS`] (ADR 0008 decision 5).
    RecoveryWaitTooLong,
    /// A session lifetime is zero.
    ZeroSessionLifetime,
    /// The kind-4 certificate limit is zero or above [`MAX_WEB_CERTIFICATES`].
    WebCertificateLimit,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RecoveryWaitTooLong => "recovery waiting period above 30 days",
            Self::ZeroSessionLifetime => "session lifetime of zero",
            Self::WebCertificateLimit => "web certificate limit of zero or above 1024",
        })
    }
}

impl std::error::Error for ConfigError {}

/// The auth domain's configuration. Build it with [`AuthConfig::new`] and adjust the public
/// fields, then check it with [`AuthConfig::validate`] (the service does so on construction).
#[derive(Debug)]
pub struct AuthConfig {
    /// The server's configured canonical origin (CRYPTO.md §2 `server_origin`): bound into the
    /// OPAQUE Context and every `device-auth` and `device-request` message the server rebuilds.
    pub server_origin: ServerOrigin,
    /// Who may sign up.
    pub signup: SignupPolicy,
    /// The recovery waiting period, 0 to [`MAX_RECOVERY_WAIT_MS`] (ADR 0008 decision 5).
    pub recovery_wait_ms: u64,
    /// Lifetime of an OPAQUE session (bearer token; the web vault's session, §11.4). Not fixed
    /// by any Accepted ADR ("short-lived bearer tokens", CRYPTO.md §5.10); default 1 h.
    pub opaque_session_ttl_ms: u64,
    /// Lifetime of a device-authenticated session. Not fixed by any Accepted ADR; default 1 h.
    /// A device re-authenticates with its key, which costs no Argon2id.
    pub device_session_ttl_ms: u64,
    /// The admin-set limit of a reconciliation epoch (ADR 0012 §7), default 30 days.
    pub reconciliation_limit_ms: u64,
    /// The most kind-4 certificates one account holds at a time, 1 to
    /// [`MAX_WEB_CERTIFICATES`] (the default).
    pub max_web_certificates: usize,
    /// The rate limits.
    pub rate_limits: RateLimits,
}

impl AuthConfig {
    /// A configuration for `server_origin` with signup closed and every other value at its
    /// default.
    #[must_use]
    pub fn new(server_origin: ServerOrigin) -> Self {
        Self {
            server_origin,
            signup: SignupPolicy::Closed,
            recovery_wait_ms: DEFAULT_RECOVERY_WAIT_MS,
            opaque_session_ttl_ms: 3_600_000,
            device_session_ttl_ms: 3_600_000,
            reconciliation_limit_ms: DEFAULT_RECONCILIATION_LIMIT_MS,
            max_web_certificates: MAX_WEB_CERTIFICATES,
            rate_limits: RateLimits::default(),
        }
    }

    /// Checks the bounds the specs set.
    ///
    /// # Errors
    /// [`ConfigError`].
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if self.recovery_wait_ms > MAX_RECOVERY_WAIT_MS {
            return Err(ConfigError::RecoveryWaitTooLong);
        }
        if self.opaque_session_ttl_ms == 0 || self.device_session_ttl_ms == 0 {
            return Err(ConfigError::ZeroSessionLifetime);
        }
        if self.max_web_certificates == 0 || self.max_web_certificates > MAX_WEB_CERTIFICATES {
            return Err(ConfigError::WebCertificateLimit);
        }
        Ok(())
    }
}
