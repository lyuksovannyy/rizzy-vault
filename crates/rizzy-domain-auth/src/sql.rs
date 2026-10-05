//! The auth domain's SQL: every query text, and the helpers that run them on either engine.
//!
//! **Bound parameters only** (ADR 0011 point 2, INV-53). Every query is a `&'static str` read
//! from a `.sql` file under `queries/` with `include_str!`; sqlx 0.9's `SqlSafeStr` refuses
//! anything else, and this crate's `clippy.toml` bans the escape hatches. The files use
//! `$1, $2, …` on both engines and only syntax both engines accept (`ON CONFLICT … DO UPDATE`,
//! `DELETE … RETURNING`).
//!
//! **Own tables only** (ADR 0011 point 5, ADR 0016 R4): every query here touches `auth_`
//! tables. The reconciliation epoch (`storage_reconciliation`) is read and ended through
//! `rizzy_storage::meta`; the vault's tables through [`crate::ports::VaultPort`].
//!
//! The macros expand one body into both arms of [`rizzy_storage::on_engine!`], so the two
//! engines always run the same text with the same binds.

/// Defines one `const` per query file.
macro_rules! queries {
    ($( $(#[$doc:meta])* $name:ident = $file:literal; )+) => {$(
        $(#[$doc])*
        pub(crate) const $name: &str = include_str!(concat!("../queries/", $file, ".sql"));
    )+};
}

queries! {
    /// Reserves a login name for a new account id.
    ACCOUNT_INSERT = "account_insert";
    /// The account id of a normalised login name.
    ACCOUNT_BY_NAME = "account_by_name";
    /// The login name of an account.
    ACCOUNT_BY_ID = "account_by_id";
    /// A stored OPAQUE setup's AKE public-key hash and retirement time.
    SETUP_GET = "setup_get";
    /// Records an OPAQUE setup's AKE public-key hash.
    SETUP_INSERT = "setup_insert";
    /// Every recorded OPAQUE setup with its recording and retirement times.
    SETUPS_ALL = "setups_all";
    /// When one OPAQUE setup was retired, if it was.
    SETUP_RETIRED_AT = "setup_retired_at";
    /// Retires one OPAQUE setup, keeping an earlier retirement time.
    SETUP_RETIRE = "setup_retire";
    /// How many OPAQUE records name each `setup_id`.
    CREDENTIAL_SETUP_COUNTS = "credential_setup_counts";
    /// Deletes every sealed login state.
    LOGIN_STATES_DELETE_ALL = "login_states_delete_all";
    /// The OPAQUE record, `kdf_id`, `password_epoch`, `E_srv` and `account_key_epoch` of an
    /// account.
    CREDENTIAL_GET = "credential_get";
    /// Stores or replaces the OPAQUE record and `E_srv`.
    CREDENTIAL_UPSERT = "credential_upsert";
    /// Every `setup_id` a record names.
    CREDENTIAL_SETUP_IDS = "credential_setup_ids";
    /// The accounts with a credential or recovery row whose `account_key_epoch` is missing.
    CREDENTIAL_EPOCHS_MISSING = "credential_epochs_missing";
    /// Fills a missing `account_key_epoch` of a credential row.
    CREDENTIAL_EPOCH_FILL = "credential_epoch_fill";
    /// Fills a missing `account_key_epoch` of a recovery row.
    RECOVERY_EPOCH_FILL = "recovery_epoch_fill";
    /// `E_id` of an account.
    IDENTITY_GET = "identity_get";
    /// Stores or replaces `E_id`.
    IDENTITY_UPSERT = "identity_upsert";
    /// `E_rec` and `H_rec` of an account.
    RECOVERY_GET = "recovery_get";
    /// Stores or replaces `E_rec` and `H_rec`.
    RECOVERY_UPSERT = "recovery_upsert";
    /// Removes `E_rec` and `H_rec`.
    RECOVERY_DELETE = "recovery_delete";
    /// The bundle chain, oldest first.
    BUNDLES_ALL = "bundles_all";
    /// Appends a bundle.
    BUNDLE_INSERT = "bundle_insert";
    /// The current `account-state`.
    STATE_GET = "state_get";
    /// Stores the first `account-state`.
    STATE_INSERT = "state_insert";
    /// Compare-and-swap of the `account-state`.
    STATE_CAS = "state_cas";
    /// The current `ACCOUNT_SETTINGS`.
    SETTINGS_GET = "settings_get";
    /// Every device certificate of an account.
    CERTS_ALL = "certs_all";
    /// Stores or replaces a device certificate.
    CERT_UPSERT = "cert_upsert";
    /// Suspends a device.
    CERT_SUSPEND = "cert_suspend";
    /// Every device revocation of an account.
    REVOCATIONS_ALL = "revocations_all";
    /// Stores or replaces a device revocation.
    REVOCATION_UPSERT = "revocation_upsert";
    /// The pending device grants of a device.
    GRANTS_FOR_DEVICE = "grants_for_device";
    /// Stores or replaces a device grant.
    GRANT_UPSERT = "grant_upsert";
    /// Deletes acknowledged device grants.
    GRANTS_ACK = "grants_ack";
    /// Stores a session.
    SESSION_INSERT = "session_insert";
    /// A session by token hash.
    SESSION_GET = "session_get";
    /// Records a session's request-counter window.
    SESSION_WINDOW_UPDATE = "session_window_update";
    /// Ends every session of an account.
    SESSIONS_DELETE_ACCOUNT = "sessions_delete_account";
    /// Ends every session of a device.
    SESSIONS_DELETE_DEVICE = "sessions_delete_device";
    /// Ends every session of one kind of an account.
    SESSIONS_DELETE_KIND = "sessions_delete_kind";
    /// Deletes expired sessions.
    SESSIONS_DELETE_EXPIRED = "sessions_delete_expired";
    /// The TOTP credentials of an account.
    TOTP_LIST = "totp_list";
    /// Stores a sealed TOTP credential.
    TOTP_INSERT = "totp_insert";
    /// Records a TOTP credential's last accepted step.
    TOTP_SET_STEP = "totp_set_step";
    /// Deletes every TOTP credential but one.
    TOTP_DELETE_EXCEPT = "totp_delete_except";
    /// Deletes every TOTP credential.
    TOTP_DELETE_ALL = "totp_delete_all";
    /// Every `data_key_id` a TOTP row names.
    TOTP_DATA_KEY_IDS = "totp_data_key_ids";
    /// Stores a sealed login state.
    LOGIN_STATE_INSERT = "login_state_insert";
    /// Reads and deletes a login state.
    LOGIN_STATE_TAKE = "login_state_take";
    /// Deletes expired login states.
    LOGIN_STATES_DELETE_EXPIRED = "login_states_delete_expired";
    /// Every `data_key_id` a login state names.
    LOGIN_STATE_DATA_KEY_IDS = "login_state_data_key_ids";
    /// Stores a device-auth challenge.
    CHALLENGE_INSERT = "challenge_insert";
    /// Reads and deletes a device-auth challenge.
    CHALLENGE_TAKE = "challenge_take";
    /// Deletes expired challenges.
    CHALLENGES_DELETE_EXPIRED = "challenges_delete_expired";
    /// A rate-limit bucket's counters.
    RATE_GET = "rate_get";
    /// Stores a rate-limit bucket's counters.
    RATE_UPSERT = "rate_upsert";
    /// Clears a rate-limit bucket.
    RATE_DELETE = "rate_delete";
    /// Deletes expired rate-limit buckets.
    RATE_DELETE_EXPIRED = "rate_delete_expired";
    /// A pending recovery.
    PENDING_RECOVERY_GET = "pending_recovery_get";
    /// Opens a pending recovery.
    PENDING_RECOVERY_INSERT = "pending_recovery_insert";
    /// Cancels or closes a pending recovery.
    PENDING_RECOVERY_DELETE = "pending_recovery_delete";
    /// Lifts a device's suspension.
    CERT_UNSUSPEND = "cert_unsuspend";
    /// Adopts a newer `account-state` during the reconciliation epoch.
    STATE_REPLACE = "state_replace";
    /// Stores or replaces `ACCOUNT_SETTINGS`.
    SETTINGS_UPSERT = "settings_upsert";
    /// Stores or replaces a `RETIRED_SECRET_KEY` envelope.
    RETIRED_KEY_UPSERT = "retired_key_upsert";
    /// Ends every session of one kind of an account but one.
    SESSIONS_DELETE_KIND_EXCEPT = "sessions_delete_kind_except";
    /// Deletes the unconfirmed TOTP enrolments.
    TOTP_DELETE_PENDING = "totp_delete_pending";
    /// The credential identifier of a login state, without taking it.
    LOGIN_STATE_PEEK = "login_state_peek";
    /// Deletes one login state (after a rolled-back finish).
    LOGIN_STATE_DELETE = "login_state_delete";
    /// Deletes every login state of a credential identifier (its record was replaced).
    LOGIN_STATES_DELETE_CREDENTIAL = "login_states_delete_credential";
    /// Deletes one device-auth challenge (after a rolled-back finish).
    CHALLENGE_DELETE = "challenge_delete";
    /// Deletes one device certificate (an expired kind-4 one that authored nothing).
    CERT_DELETE = "cert_delete";
    /// When the current `account-state` was stored.
    STATE_UPDATED_AT = "state_updated_at";
    /// A page of accounts holding a TOTP row sealed under another data key than the current.
    TOTP_STALE_ACCOUNTS = "totp_stale_accounts";
    /// Replaces a TOTP row's sealed secret and data key id.
    TOTP_RESEAL = "totp_reseal";
}

/// Runs a statement on a [`rizzy_storage::Conn`] and returns the number of rows it changed:
/// `exec!(conn, QUERY, bind1, bind2, …)`.
macro_rules! exec {
    ($conn:expr, $q:expr $(, $b:expr)* $(,)?) => {
        rizzy_storage::on_engine!($conn, |c| sqlx::query($q)
            $(.bind($b))*
            .execute(&mut *c)
            .await
            .map(|r| r.rows_affected()))
    };
}

/// Runs a query and returns at most one row as the tuple type `$t`:
/// `fetch_opt!(conn, (Vec<u8>, i64), QUERY, bind1, …)`.
macro_rules! fetch_opt {
    ($conn:expr, $t:ty, $q:expr $(, $b:expr)* $(,)?) => {
        rizzy_storage::on_engine!($conn, |c| sqlx::query_as::<_, $t>($q)
            $(.bind($b))*
            .fetch_optional(&mut *c)
            .await)
    };
}

/// Runs a query and returns every row as the tuple type `$t`.
macro_rules! fetch_all {
    ($conn:expr, $t:ty, $q:expr $(, $b:expr)* $(,)?) => {
        rizzy_storage::on_engine!($conn, |c| sqlx::query_as::<_, $t>($q)
            $(.bind($b))*
            .fetch_all(&mut *c)
            .await)
    };
}

pub(crate) use {exec, fetch_all, fetch_opt};

use crate::error::AuthError;

/// A `u64` (a time, a sequence number, a step) as an SQL integer, refusing values above
/// `i64::MAX`, which only a forged value reaches ([`rizzy_storage::convert`]).
pub(crate) fn u64_sql(value: u64, what: &'static str) -> Result<i64, AuthError> {
    Ok(rizzy_storage::convert::u64_to_sql(value, what)?)
}

/// An SQL integer read back as a `u64`.
pub(crate) fn sql_u64(value: i64, what: &'static str) -> Result<u64, AuthError> {
    Ok(rizzy_storage::convert::sql_to_u64(value, what)?)
}

/// An SQL integer read back as a `u32` (an epoch, an id).
pub(crate) fn sql_u32(value: i64, what: &'static str) -> Result<u32, AuthError> {
    Ok(rizzy_storage::convert::sql_to_u32(value, what)?)
}

/// A stored 16-byte id.
pub(crate) fn id16(bytes: &[u8], what: &'static str) -> Result<[u8; 16], AuthError> {
    <[u8; 16]>::try_from(bytes).map_err(|_| AuthError::Internal(what))
}

/// A stored 32-byte hash.
pub(crate) fn hash32(bytes: &[u8], what: &'static str) -> Result<[u8; 32], AuthError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| AuthError::Internal(what))
}
