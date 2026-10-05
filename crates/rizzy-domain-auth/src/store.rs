//! Row-level reads and writes of the auth tables that several flows share: accounts,
//! credentials, `E_id`, recovery rows, statements, and the compare-and-swap on the signed
//! `account-state`.
//!
//! Every function runs on the caller's transaction; the flows take the account lock first
//! (ADR 0011 "Transactions and concurrency"). Nothing here verifies a signature: the flows
//! verify with `rizzy-core` before they call a writer, and [`crate::trust`] re-verifies on
//! every read that matters.

use core::cmp::Ordering;

use rizzy_core::ids::AccountId;
use rizzy_core::sign::{AccountState, DeviceCertificate, DeviceRevocation, Verified};
use rizzy_storage::Conn;

use crate::error::AuthError;
use crate::sql::{self, exec, fetch_opt};
use crate::trust::reborrow;

/// An account's stored OPAQUE credential row (CRYPTO.md §11.1 step 8).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    /// The `setup_id` of the `server_setup` the record was registered under (§5.8).
    pub(crate) setup_id: u32,
    /// The OPAQUE registration record.
    pub(crate) record: Vec<u8>,
    /// The `kdf_id` stored with the record, from the signed state of its commit.
    pub(crate) kdf_id: u16,
    /// The `password_epoch` stored with the record (INV-59 compares it).
    pub(crate) password_epoch: u32,
    /// `E_srv`.
    pub(crate) e_srv: Vec<u8>,
    /// The `account_key_epoch` of the signed state of the commit that wrote the row (ADR 0032
    /// §4); `None` for a row migration 0005 found and the startup fill has not reached yet,
    /// which lags (fail closed).
    pub(crate) account_key_epoch: Option<u32>,
}

impl Credential {
    /// Whether the record lags `state`: its (`password_epoch`, `kdf_id`, `account_key_epoch`) is
    /// not the state's (ADR 0032 §4 "Record lag"). Possible only after a restore to before a
    /// credential change or a key rotation, since every flow that moves them writes the record
    /// in the transaction of the state.
    pub(crate) fn lags(&self, state: &AccountState) -> bool {
        self.password_epoch != state.password_epoch
            || self.kdf_id != state.kdf_id.get()
            || self.account_key_epoch != Some(state.account_key_epoch)
    }
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credential")
            .field("setup_id", &self.setup_id)
            .field("kdf_id", &self.kdf_id)
            .field("password_epoch", &self.password_epoch)
            .field("account_key_epoch", &self.account_key_epoch)
            .finish_non_exhaustive()
    }
}

/// An account's stored recovery row (CRYPTO.md §11.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryRow {
    /// The `recovery_epoch` stored beside `H_rec` (INV-59 compares it).
    pub(crate) recovery_epoch: u32,
    /// `E_rec`.
    pub(crate) e_rec: Vec<u8>,
    /// `H_rec = SHA-256(recovery_auth_token)`.
    pub(crate) h_rec: [u8; 32],
    /// The `account_key_epoch` of the signed state of the commit that wrote the row (ADR 0032
    /// §4); `None` as for [`Credential::account_key_epoch`].
    pub(crate) account_key_epoch: Option<u32>,
}

impl RecoveryRow {
    /// Whether the row lags `state`: its `recovery_epoch` or its `account_key_epoch` is not the
    /// state's (ADR 0032 §4 "Step 6"). `H_rec` and `E_rec` are one credential, so either
    /// makes the whole row lag.
    pub(crate) fn lags(&self, state: &AccountState) -> bool {
        self.recovery_epoch != state.recovery_epoch
            || self.account_key_epoch != Some(state.account_key_epoch)
    }
}

/// The account id of a normalised login name.
pub(crate) async fn account_by_name(
    conn: Conn<'_>,
    login_name: &str,
) -> Result<Option<AccountId>, AuthError> {
    let row: Option<(Vec<u8>,)> = fetch_opt!(conn, (Vec<u8>,), sql::ACCOUNT_BY_NAME, login_name)?;
    row.map(|(id,)| sql::id16(&id, "auth_accounts.id").map(AccountId::from_bytes))
        .transpose()
}

/// The login name of an account, if the account row exists.
pub(crate) async fn account_name(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Option<String>, AuthError> {
    let row: Option<(String,)> = fetch_opt!(
        conn,
        (String,),
        sql::ACCOUNT_BY_ID,
        &account_id.as_bytes()[..]
    )?;
    Ok(row.map(|(name,)| name))
}

/// The OPAQUE credential of `credential_identifier` (an account id, or a fake id that finds
/// nothing).
pub(crate) async fn credential(
    conn: Conn<'_>,
    credential_identifier: &[u8; 16],
) -> Result<Option<Credential>, AuthError> {
    type Row = (i64, Vec<u8>, i64, i64, Vec<u8>, Option<i64>);
    let row: Option<Row> = fetch_opt!(conn, Row, sql::CREDENTIAL_GET, &credential_identifier[..])?;
    row.map(
        |(setup_id, record, kdf_id, password_epoch, e_srv, account_key_epoch)| {
            Ok(Credential {
                setup_id: sql::sql_u32(setup_id, "setup_id")?,
                record,
                kdf_id: u16::try_from(kdf_id).map_err(|_| AuthError::Internal("kdf_id"))?,
                password_epoch: sql::sql_u32(password_epoch, "password_epoch")?,
                e_srv,
                account_key_epoch: account_key_epoch
                    .map(|e| sql::sql_u32(e, "account_key_epoch"))
                    .transpose()?,
            })
        },
    )
    .transpose()
}

/// Stores or replaces the credential of `account_id`, and deletes every pending login state
/// started for it (the caller holds the account lock).
///
/// A login state seals the `ServerLogin` of the record current at login start; its KE3 still
/// verifies against that record after the record was replaced. So a login started before a
/// password or Secret Key change (CRYPTO.md §11.5 step 5), a recovery (§11.9 step 6) or a
/// restore-driven re-registration must not finish after it (INV-59). Login start reads the
/// record and stores the state, and login finish takes the state and reads the record, each
/// under the same account lock, so no state of the old record survives this call.
pub(crate) async fn put_credential(
    mut conn: Conn<'_>,
    account_id: AccountId,
    credential: &Credential,
    now_ms: u64,
) -> Result<(), AuthError> {
    exec!(
        reborrow(&mut conn),
        sql::LOGIN_STATES_DELETE_CREDENTIAL,
        &account_id.as_bytes()[..],
    )?;
    exec!(
        conn,
        sql::CREDENTIAL_UPSERT,
        &account_id.as_bytes()[..],
        i64::from(credential.setup_id),
        &credential.record[..],
        i64::from(credential.kdf_id),
        i64::from(credential.password_epoch),
        &credential.e_srv[..],
        sql::u64_sql(now_ms, "updated_at_ms")?,
        credential.account_key_epoch.map(i64::from),
    )?;
    Ok(())
}

/// `E_id` of `account_id` with its `identity_epoch`.
pub(crate) async fn identity(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Option<(u32, Vec<u8>)>, AuthError> {
    let row: Option<(i64, Vec<u8>)> = fetch_opt!(
        conn,
        (i64, Vec<u8>),
        sql::IDENTITY_GET,
        &account_id.as_bytes()[..]
    )?;
    row.map(|(epoch, e_id)| Ok((sql::sql_u32(epoch, "identity_epoch")?, e_id)))
        .transpose()
}

/// Stores or replaces `E_id`.
pub(crate) async fn put_identity(
    conn: Conn<'_>,
    account_id: AccountId,
    identity_epoch: u32,
    e_id: &[u8],
    now_ms: u64,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::IDENTITY_UPSERT,
        &account_id.as_bytes()[..],
        i64::from(identity_epoch),
        e_id,
        sql::u64_sql(now_ms, "updated_at_ms")?,
    )?;
    Ok(())
}

/// The recovery row of `account_id`.
pub(crate) async fn recovery(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Option<RecoveryRow>, AuthError> {
    type Row = (i64, Vec<u8>, Vec<u8>, Option<i64>);
    let row: Option<Row> = fetch_opt!(conn, Row, sql::RECOVERY_GET, &account_id.as_bytes()[..])?;
    row.map(|(epoch, e_rec, h_rec, account_key_epoch)| {
        Ok(RecoveryRow {
            recovery_epoch: sql::sql_u32(epoch, "recovery_epoch")?,
            e_rec,
            h_rec: sql::hash32(&h_rec, "h_rec")?,
            account_key_epoch: account_key_epoch
                .map(|e| sql::sql_u32(e, "account_key_epoch"))
                .transpose()?,
        })
    })
    .transpose()
}

/// Stores or replaces the recovery row.
pub(crate) async fn put_recovery(
    conn: Conn<'_>,
    account_id: AccountId,
    row: &RecoveryRow,
    now_ms: u64,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::RECOVERY_UPSERT,
        &account_id.as_bytes()[..],
        i64::from(row.recovery_epoch),
        &row.e_rec[..],
        &row.h_rec[..],
        sql::u64_sql(now_ms, "updated_at_ms")?,
        row.account_key_epoch.map(i64::from),
    )?;
    Ok(())
}

/// The current `ACCOUNT_SETTINGS` of `account_id`.
pub(crate) async fn settings(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Option<(u64, Vec<u8>)>, AuthError> {
    let row: Option<(i64, Vec<u8>)> = fetch_opt!(
        conn,
        (i64, Vec<u8>),
        sql::SETTINGS_GET,
        &account_id.as_bytes()[..]
    )?;
    row.map(|(seq, envelope)| Ok((sql::sql_u64(seq, "settings_seq")?, envelope)))
        .transpose()
}

/// Stores a verified bundle at the end of the chain.
pub(crate) async fn put_bundle(
    conn: Conn<'_>,
    account_id: AccountId,
    bundle_seq: u64,
    wire: &[u8],
    now_ms: u64,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::BUNDLE_INSERT,
        &account_id.as_bytes()[..],
        sql::u64_sql(bundle_seq, "bundle_seq")?,
        wire,
        sql::u64_sql(now_ms, "stored_at_ms")?,
    )?;
    Ok(())
}

/// Stores or replaces a verified certificate, with its cleartext fields copied out.
pub(crate) async fn put_cert(
    conn: Conn<'_>,
    cert: &Verified<DeviceCertificate>,
    wire: &[u8],
    now_ms: u64,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::CERT_UPSERT,
        &cert.account_id.as_bytes()[..],
        &cert.device_id.as_bytes()[..],
        i64::from(cert.identity_epoch),
        i64::from(cert.device_kind.to_u8()),
        sql::u64_sql(cert.expires_at_ms, "expires_at_ms")?,
        wire,
        sql::u64_sql(now_ms, "stored_at_ms")?,
    )?;
    Ok(())
}

/// Stores or replaces a verified revocation.
pub(crate) async fn put_revocation(
    conn: Conn<'_>,
    revocation: &Verified<DeviceRevocation>,
    wire: &[u8],
    now_ms: u64,
) -> Result<(), AuthError> {
    exec!(
        conn,
        sql::REVOCATION_UPSERT,
        &revocation.account_id.as_bytes()[..],
        &revocation.device_id.as_bytes()[..],
        sql::u64_sql(
            revocation.last_accepted_device_seq,
            "last_accepted_device_seq"
        )?,
        wire,
        sql::u64_sql(now_ms, "stored_at_ms")?,
    )?;
    Ok(())
}

/// How an offered `account-state` relates to the one the server holds (CRYPTO.md §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Offered {
    /// Byte-identical to the held state: a repeat of an applied commit (§11 "Secrets before
    /// commit": "The server treats a repeat of an already-applied commit (byte-identical new
    /// state) as success").
    Repeat,
    /// `state_seq + 1`: a candidate for the compare-and-swap.
    Next,
}

/// Places an offered, verified state against the held one: a byte-identical repeat, the next
/// state, or a refusal. The same `state_seq` with another body is two versions at one
/// position; it is refused as [`AuthError::StateFork`] and never adopted (§10.2 "Forks of the
/// signed state": a compare-and-swap loser's state must never be served). A lower or a
/// skipped-ahead `state_seq` is [`AuthError::StateConflict`].
pub(crate) fn place_offered(
    held: &AccountState,
    held_wire: &[u8],
    offered: &AccountState,
    offered_wire: &[u8],
) -> Result<Offered, AuthError> {
    match offered.state_seq.cmp(&held.state_seq) {
        Ordering::Equal if offered_wire == held_wire => Ok(Offered::Repeat),
        Ordering::Equal => Err(AuthError::StateFork),
        Ordering::Greater if held.state_seq.checked_add(1) == Some(offered.state_seq) => {
            Ok(Offered::Next)
        }
        Ordering::Less | Ordering::Greater => Err(AuthError::StateConflict),
    }
}

/// When the current `account-state` of `account_id` was stored, in ms since the Unix epoch.
///
/// # Errors
/// [`AuthError::NotFound`] for an account without a state; storage errors.
pub(crate) async fn state_updated_at(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<u64, AuthError> {
    let row: Option<(i64,)> = fetch_opt!(
        conn,
        (i64,),
        sql::STATE_UPDATED_AT,
        &account_id.as_bytes()[..]
    )?;
    let (updated_at_ms,) = row.ok_or(AuthError::NotFound)?;
    sql::sql_u64(updated_at_ms, "updated_at_ms")
}

/// The compare-and-swap on `state_seq` (CRYPTO.md §10.2): replaces the state of `account_id`
/// only if the stored `state_seq` is still `expected_seq`. The caller holds the account lock,
/// so this is the last line of defence, not the concurrency control.
pub(crate) async fn cas_state(
    conn: Conn<'_>,
    account_id: AccountId,
    expected_seq: u64,
    new: &AccountState,
    wire: &[u8],
    now_ms: u64,
) -> Result<(), AuthError> {
    let changed = exec!(
        conn,
        sql::STATE_CAS,
        &account_id.as_bytes()[..],
        sql::u64_sql(new.state_seq, "state_seq")?,
        wire,
        sql::u64_sql(now_ms, "updated_at_ms")?,
        sql::u64_sql(expected_seq, "state_seq")?,
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(AuthError::StateConflict)
    }
}
