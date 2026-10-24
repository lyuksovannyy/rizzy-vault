// SPDX-License-Identifier: AGPL-3.0-only

//! `WebAuthn` security keys as a server-side second factor ([ADR 0058] as amended by [ADR 0077];
//! CRYPTO.md §11.17; INV-83, INV-84).
//!
//! rizzy-vault is the relying party. The ceremonies run through `webauthn-rs` ([ADR 0059]),
//! confined to this crate: `rizzy-server` never names it, and this module keeps every
//! `webauthn-rs` type out of the crate's public items.
//!
//! - **RP ID and origin (INV-84).** `rp_id` is the host of the configured canonical origin and the
//!   only allowed origin is that origin itself, with no subdomains and no other port. A server
//!   whose origin host is an IP address cannot be a `WebAuthn` relying party: browsers refuse an IP
//!   as `rp.id` and `webauthn-rs` refuses to build. There every endpoint answers
//!   [`AuthError::NotFound`], and no account can hold a key.
//! - **Enrolment** (point 2) needs a fresh OPAQUE session, like TOTP's. The creation options ask
//!   for attestation `"none"` with no CA list; whatever statement arrives is checked by the crate
//!   on its own terms and kept, parsed, inside the stored `SecurityKey` (ADR 0077 §5). Only ES256
//!   is stored (§6): a key that chose RS256 is refused with [`AuthError::KeyAlgorithm`].
//! - **Ceremony state** (§2): the facade's `SecurityKeyRegistration`/`SecurityKeyAuthentication`
//!   as JSON in `auth_webauthn_challenges`, unsealed, with `state_format` 1. It is read and
//!   deleted once, in the transaction of the verification and under the account lock, whether the
//!   verification succeeds or not; refused after 60 s (checked here, not only by `worker`),
//!   above 64 KiB or with an unknown format; and never part of a response, a log line or an error.
//! - **Login** (point 3): a login whose KE3 verified, on an account with a key and without a
//!   matching TOTP code, is demoted to a 60 s second-factor-pending row named by its `login_id`.
//!   [`AuthService::webauthn_login_challenge`] issues the assertion options for it (a new
//!   challenge replaces the previous one); [`AuthService::webauthn_login_finish`] takes the
//!   pending row and the state once, verifies the assertion and issues the session.
//! - **Credentials and counters** (§2 rule 4, §4, INV-83): the asserted credential must be one of
//!   the account's current rows, re-read under the lock, and the counter is decided against the
//!   row's `sign_count`, never the copy inside the state. A refused counter, by the crate or by
//!   INV-83, is [`AuthError::PossibleClone`]: `rizzy-server` records it as a security event; the
//!   credential stays enrolled (ADR 0058 owner answer 4).
//! - **User verification** (§7): the facade's security-key policy. UP always; UV preferred, and
//!   required at assertion exactly when the key performed UV at enrolment.
//! - **2FA gates server access only.** It never enters key derivation, and recovery does not
//!   require it (ADR 0008 owner decision 2), as for TOTP.
//!
//! [ADR 0058]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0058-webauthn-2fa-second-factor.md
//! [ADR 0059]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0059-webauthn-rs-crate-approval.md
//! [ADR 0077]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0077-webauthn-rs-integration-fixes.md

use std::time::Duration;

use rizzy_core::ids::AccountId;
use rizzy_core::normalize::ServerOrigin;
use rizzy_core::rng::CryptoRng;
use rizzy_proto::auth::LoginFinishResponse;
use rizzy_proto::limits::MAX_WEBAUTHN_CREDENTIALS;
use rizzy_proto::webauthn::{
    WebauthnCredentialId, WebauthnCredentialView, WebauthnEnrolConfirmRequest,
    WebauthnEnrolStartResponse, WebauthnJson, WebauthnLabel, WebauthnListResponse,
    WebauthnLoginChallengeRequest, WebauthnLoginChallengeResponse, WebauthnLoginFinishRequest,
    WebauthnRemoveRequest,
};
use rizzy_proto::wire::{Id, List};
use rizzy_storage::{Conn, WriteTx, lock_account};
use serde::Serialize;
use serde::de::DeserializeOwned;
use webauthn_rs::prelude::{
    COSEAlgorithm, CredentialID, PublicKeyCredential, RegisterPublicKeyCredential, SecurityKey,
    SecurityKeyAuthentication, SecurityKeyRegistration, Url, Uuid, WebauthnError,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::ratelimit::{self, BucketKind, bucket};
use crate::session::{self, Session, SessionKind};
use crate::sql::{self, exec, fetch_all, fetch_opt};
use crate::store;
use crate::trust::AccountTrust;
use crate::{AuthService, over_limit, totp};

/// The ceremony TTL (ADR 0077 §2 rule 2) and the pending row's (ADR 0058 point 3): 60 s.
pub(crate) const CEREMONY_TTL_MS: u64 = 60_000;

/// `state_format` of a stored ceremony state: `webauthn-rs` 0.5.x JSON (ADR 0077 §2).
pub(crate) const STATE_FORMAT: u16 = 1;

/// `security_key_format` of a stored credential: `webauthn-rs` 0.5.x JSON (ADR 0077 §4).
pub(crate) const SECURITY_KEY_FORMAT: u16 = 1;

/// The largest stored ceremony state or `SecurityKey` read back (ADR 0077 §2: 64 KiB).
pub(crate) const MAX_STORED_JSON_LEN: usize = 64 * 1024;

/// `alg` of an ES256 credential: ADR 0039 §1's value, the only one stored (ADR 0077 §6).
const ALG_ES256: i64 = 1;

/// `purpose` of an enrolment's ceremony state.
const PURPOSE_ENROL: i64 = 1;
/// `purpose` of a login's ceremony state.
const PURPOSE_LOGIN: i64 = 2;

/// The relying party for `origin`, or `None` when its host cannot be an RP ID (module docs).
pub(crate) fn relying_party(origin: &ServerOrigin) -> Option<Webauthn> {
    let url = Url::parse(origin.as_str()).ok()?;
    let host = url.domain()?.to_owned();
    WebauthnBuilder::new(&host, &url)
        .ok()?
        .timeout(Duration::from_millis(CEREMONY_TTL_MS))
        .build()
        .ok()
}

/// One stored credential row.
pub(crate) struct StoredKey {
    /// The credential id.
    pub(crate) credential_id: Vec<u8>,
    /// The `SecurityKey` JSON.
    pub(crate) security_key: String,
    /// Its shape (1 = `webauthn-rs` 0.5.x).
    pub(crate) security_key_format: u16,
    /// The counter of record (INV-83).
    pub(crate) sign_count: u32,
    /// The user's label.
    pub(crate) label: String,
    /// When it was enrolled.
    pub(crate) created_ms: u64,
}

impl StoredKey {
    /// The `SecurityKey`, refused when its format is unknown or it is oversized (bounded input,
    /// fail closed).
    fn decode(&self) -> Result<SecurityKey, AuthError> {
        decode_security_key(self.security_key_format, &self.security_key)
            .ok_or(AuthError::Internal("a stored security key does not decode"))
    }
}

/// Decodes a stored `SecurityKey` (ADR 0077 §4): `None` for an unknown format, more than 64 KiB
/// or JSON that is not a `webauthn-rs` 0.5.x `SecurityKey`. The fuzz target `webauthn_stored`
/// drives it.
#[must_use]
pub(crate) fn decode_security_key(format: u16, json: &str) -> Option<SecurityKey> {
    decode_json(format, SECURITY_KEY_FORMAT, json)
}

/// Decodes stored ceremony state of type `T` (ADR 0077 §2), with the same bounds.
fn decode_json<T: DeserializeOwned>(format: u16, known: u16, json: &str) -> Option<T> {
    if format != known || json.len() > MAX_STORED_JSON_LEN {
        return None;
    }
    serde_json::from_str(json).ok()
}

/// Checks that stored `webauthn-rs` JSON of every kind this module reads decodes without a panic
/// or an unbounded allocation; used by the `webauthn_stored` fuzz target. Returns how many of
/// the three readings (`SecurityKey`, registration state, authentication state) accepted it.
#[doc(hidden)]
#[must_use]
pub fn fuzz_stored_json(format: u16, json: &str) -> usize {
    usize::from(decode_security_key(format, json).is_some())
        + usize::from(decode_json::<SecurityKeyRegistration>(format, STATE_FORMAT, json).is_some())
        + usize::from(
            decode_json::<SecurityKeyAuthentication>(format, STATE_FORMAT, json).is_some(),
        )
}

/// JSON of a `webauthn-rs` value we serialise ourselves.
fn to_json<T: Serialize>(value: &T) -> Result<String, AuthError> {
    serde_json::to_string(value).map_err(|_| AuthError::Internal("webauthn JSON encoding failed"))
}

/// A `WEBAUTHN_LIST` row: `credential_id`, `alg`, `security_key`, `security_key_format`,
/// `sign_count`, `label`, `created_ms`.
type KeyRow = (Vec<u8>, i64, String, i64, i64, String, i64);

/// The account's security keys, oldest first.
pub(crate) async fn list(
    conn: Conn<'_>,
    account_id: AccountId,
) -> Result<Vec<StoredKey>, AuthError> {
    let rows: Vec<KeyRow> =
        fetch_all!(conn, KeyRow, sql::WEBAUTHN_LIST, &account_id.as_bytes()[..])?;
    rows.into_iter()
        .map(
            |(credential_id, alg, security_key, format, sign_count, label, created)| {
                if alg != ALG_ES256 {
                    return Err(AuthError::Internal("a stored security key is not ES256"));
                }
                Ok(StoredKey {
                    credential_id,
                    security_key,
                    security_key_format: u16::try_from(format)
                        .map_err(|_| AuthError::Internal("security_key_format out of range"))?,
                    sign_count: sql::sql_u32(sign_count, "sign_count")?,
                    label,
                    created_ms: sql::sql_u64(created, "created_ms")?,
                })
            },
        )
        .collect()
}

/// How many security keys the account holds.
pub(crate) async fn count(tx: &mut WriteTx, account_id: AccountId) -> Result<u64, AuthError> {
    let (n,): (i64,) = fetch_opt!(
        tx.conn(),
        (i64,),
        sql::WEBAUTHN_COUNT,
        &account_id.as_bytes()[..]
    )?
    .unwrap_or((0,));
    sql::sql_u64(n, "webauthn credential count")
}

/// ADR 0058 point 3: keeps a verified login whose second factor is missing as a pending row named
/// by its `login_id`, when the account holds a security key; does nothing otherwise.
pub(crate) async fn demote_to_pending(
    tx: &mut WriteTx,
    login_id: &Id,
    account_id: AccountId,
    now_ms: u64,
) -> Result<(), AuthError> {
    if count(tx, account_id).await? == 0 {
        return Ok(());
    }
    exec!(
        tx.conn(),
        sql::WEBAUTHN_PENDING_INSERT,
        &login_id.as_bytes()[..],
        &account_id.as_bytes()[..],
        sql::u64_sql(expiry(now_ms)?, "expires_at_ms")?,
    )?;
    Ok(())
}

/// `now_ms` + 60 s.
fn expiry(now_ms: u64) -> Result<u64, AuthError> {
    now_ms
        .checked_add(CEREMONY_TTL_MS)
        .ok_or(AuthError::Internal("clock overflow"))
}

/// Stores a ceremony state (ADR 0077 §2).
async fn put_state(
    tx: &mut WriteTx,
    challenge_id: &[u8; 16],
    account_id: AccountId,
    purpose: i64,
    state: &str,
    now_ms: u64,
) -> Result<(), AuthError> {
    exec!(
        tx.conn(),
        sql::WEBAUTHN_CHALLENGE_INSERT,
        &challenge_id[..],
        &account_id.as_bytes()[..],
        purpose,
        i64::from(STATE_FORMAT),
        state,
        sql::u64_sql(expiry(now_ms)?, "expires_at_ms")?,
    )?;
    Ok(())
}

/// Takes (reads and deletes) ceremony state `challenge_id` of `account_id` and `purpose`, in
/// the caller's transaction (ADR 0077 §2 rules 1 and 2): `None` when there is none, it belongs
/// to another account or purpose, it expired, its format is unknown, it exceeds 64 KiB or it does
/// not decode. The row is gone either way.
async fn take_state<T: DeserializeOwned>(
    tx: &mut WriteTx,
    challenge_id: &[u8],
    account_id: AccountId,
    purpose: i64,
    now_ms: u64,
) -> Result<Option<T>, AuthError> {
    let row: Option<(Vec<u8>, i64, i64, String, i64)> = fetch_opt!(
        tx.conn(),
        (Vec<u8>, i64, i64, String, i64),
        sql::WEBAUTHN_CHALLENGE_TAKE,
        challenge_id
    )?;
    let Some((owner, stored_purpose, format, state, expires)) = row else {
        return Ok(None);
    };
    let live = sql::sql_u64(expires, "expires_at_ms")? > now_ms;
    if owner != account_id.as_bytes() || stored_purpose != purpose || !live {
        return Ok(None);
    }
    let Ok(format) = u16::try_from(format) else {
        return Ok(None);
    };
    Ok(decode_json(format, STATE_FORMAT, &state))
}

/// The bucket of security-key assertions of one account.
fn webauthn_bucket(account_id: AccountId) -> [u8; 33] {
    bucket(BucketKind::Webauthn, &[account_id.as_bytes()])
}

impl<V: VaultPort> AuthService<V> {
    /// The relying party, or [`AuthError::NotFound`] when this server's origin cannot be one.
    fn relying_party(&self) -> Result<&Webauthn, AuthError> {
        self.webauthn.as_ref().ok_or(AuthError::NotFound)
    }

    /// Counts one security-key attempt against the account's bucket.
    async fn hit_webauthn(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        ratelimit::hit(
            tx.conn(),
            &webauthn_bucket(account_id),
            &self.config.rate_limits.webauthn_per_account,
            now_ms,
        )
        .await
    }

    /// `webauthn/enrol/start` (ADR 0058 point 2 as ADR 0077 §9 entry 12 replaces it): creation
    /// options for a new security key, and the enrolment id that names its stored state. A new
    /// enrolment replaces an unfinished one.
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`] without a fresh OPAQUE session;
    /// [`AuthError::Conflict`] at [`MAX_WEBAUTHN_CREDENTIALS`] keys; [`AuthError::NotFound`] when
    /// this server cannot be a relying party; storage errors.
    pub async fn webauthn_enrol_start<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        session: &Session,
        now_ms: u64,
    ) -> Result<WebauthnEnrolStartResponse, AuthError> {
        let rp = self.relying_party()?;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        session.require_fresh_opaque(now_ms)?;
        let account = session.account_id;
        let keys = list(tx.conn(), account).await?;
        if keys.len() >= MAX_WEBAUTHN_CREDENTIALS {
            return Err(AuthError::Conflict);
        }
        let name = store::account_name(tx.conn(), account)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        let exclude: Vec<CredentialID> = keys
            .iter()
            .map(|k| CredentialID::from(k.credential_id.clone()))
            .collect();
        let (options, state) = rp
            .start_securitykey_registration(
                Uuid::from_bytes(account.to_bytes()),
                &name,
                &name,
                Some(exclude),
                None,
                None,
            )
            .map_err(|_| AuthError::Internal("webauthn registration start failed"))?;
        let mut enrolment_id = [0u8; 16];
        rng.fill_bytes(&mut enrolment_id);
        exec!(
            tx.conn(),
            sql::WEBAUTHN_CHALLENGES_DELETE_PURPOSE,
            &account.as_bytes()[..],
            PURPOSE_ENROL,
        )?;
        put_state(
            &mut tx,
            &enrolment_id,
            account,
            PURPOSE_ENROL,
            &to_json(&state)?,
            now_ms,
        )
        .await?;
        tx.commit().await?;
        Ok(WebauthnEnrolStartResponse {
            enrolment_id: Id::from_bytes(enrolment_id),
            options: WebauthnJson::new(to_json(&options)?).map_err(over_limit)?,
        })
    }

    /// `webauthn/enrol/confirm` (ADR 0058 point 2 as ADR 0077 §9 entry 12 replaces it):
    /// verifies the attestation response against the stored state, taken once, and stores the
    /// key under `label`.
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`]; [`AuthError::Unauthorized`] for an unknown, expired or
    /// used enrolment, or a response the ceremony refuses (type, challenge, origin, RP ID hash,
    /// a failing attestation statement); [`AuthError::InvalidRequest`] for a credential that is
    /// not `WebAuthn` JSON; [`AuthError::KeyAlgorithm`] for a key that chose another algorithm
    /// than ES256; [`AuthError::Conflict`] for a key already enrolled or one above the limit;
    /// [`AuthError::NotFound`]; storage errors.
    pub async fn webauthn_enrol_confirm(
        &self,
        session: &Session,
        req: &WebauthnEnrolConfirmRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let rp = self.relying_party()?;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        session.require_fresh_opaque(now_ms)?;
        let account = session.account_id;
        let outcome = self
            .enrol_confirm_locked(&mut tx, rp, account, req, now_ms)
            .await;
        self.settle_single_use(
            tx,
            outcome,
            sql::WEBAUTHN_CHALLENGE_DELETE,
            &req.enrolment_id.as_bytes()[..],
        )
        .await
    }

    /// [`AuthService::webauthn_enrol_confirm`] under the account lock, after the session check.
    async fn enrol_confirm_locked(
        &self,
        tx: &mut WriteTx,
        rp: &Webauthn,
        account: AccountId,
        req: &WebauthnEnrolConfirmRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let state: Option<SecurityKeyRegistration> = take_state(
            tx,
            &req.enrolment_id.as_bytes()[..],
            account,
            PURPOSE_ENROL,
            now_ms,
        )
        .await?;
        let Some(state) = state else {
            return Err(AuthError::Unauthorized);
        };
        let credential: RegisterPublicKeyCredential =
            serde_json::from_str(req.credential.as_str()).map_err(|_| AuthError::InvalidRequest)?;
        let key = rp
            .finish_securitykey_registration(&credential, &state)
            .map_err(|_| AuthError::Unauthorized)?;
        if *key.cred_algorithm() != COSEAlgorithm::ES256 {
            return Err(AuthError::KeyAlgorithm);
        }
        let keys = list(tx.conn(), account).await?;
        let id: &[u8] = key.cred_id().as_ref();
        if keys.len() >= MAX_WEBAUTHN_CREDENTIALS
            || keys.iter().any(|k| k.credential_id == id)
            || WebauthnCredentialId::new(id.to_vec()).is_err()
        {
            return Err(AuthError::Conflict);
        }
        let json = to_json(&key)?;
        let sign_count = enrolled_counter(&json)?;
        exec!(
            tx.conn(),
            sql::WEBAUTHN_INSERT,
            &account.as_bytes()[..],
            id,
            ALG_ES256,
            json.as_str(),
            i64::from(SECURITY_KEY_FORMAT),
            i64::from(sign_count),
            req.label.as_str(),
            sql::u64_sql(now_ms, "created_ms")?,
        )?;
        Ok(())
    }

    /// `webauthn/list`: the caller's security keys, oldest first.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for a recovery-only session; storage errors.
    pub async fn webauthn_list(
        &self,
        session: &Session,
    ) -> Result<WebauthnListResponse, AuthError> {
        if session.kind == SessionKind::Recovery {
            return Err(AuthError::Unauthorized);
        }
        let mut tx = self.db.begin_read().await?;
        let keys = list(tx.conn(), session.account_id).await?;
        tx.finish().await?;
        let credentials = keys
            .into_iter()
            .map(|k| {
                Ok(WebauthnCredentialView {
                    credential_id: WebauthnCredentialId::new(k.credential_id)
                        .map_err(over_limit)?,
                    label: WebauthnLabel::new(k.label).map_err(over_limit)?,
                    created_ms: k.created_ms,
                })
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        Ok(WebauthnListResponse {
            credentials: List::new(credentials).map_err(over_limit)?,
        })
    }

    /// `webauthn/remove`: removes one of the caller's security keys. Needs a fresh OPAQUE
    /// session, like every other 2FA change.
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`]; [`AuthError::NotFound`] for a key the account does
    /// not hold; storage errors.
    pub async fn webauthn_remove(
        &self,
        session: &Session,
        req: &WebauthnRemoveRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, session.account_id.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        session.require_fresh_opaque(now_ms)?;
        let removed = exec!(
            tx.conn(),
            sql::WEBAUTHN_DELETE,
            &session.account_id.as_bytes()[..],
            req.credential_id.as_slice(),
        )?;
        if removed == 0 {
            return Err(AuthError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    /// The account and liveness of pending row `pending_id`, read before its lock is taken.
    async fn peek_pending(
        &self,
        tx: &mut WriteTx,
        pending_id: &Id,
    ) -> Result<Option<AccountId>, AuthError> {
        let row: Option<(Vec<u8>, i64)> = fetch_opt!(
            tx.conn(),
            (Vec<u8>, i64),
            sql::WEBAUTHN_PENDING_PEEK,
            &pending_id.as_bytes()[..]
        )?;
        row.map(|(account, _)| Ok(AccountId::from_bytes(sql::id16(&account, "account_id")?)))
            .transpose()
    }

    /// `webauthn/login/challenge` (ADR 0058 point 3): assertion options for the login demoted to
    /// pending row `pending_id`, with the account's keys as `allowCredentials`. The state is
    /// stored under the `pending_id`; a new challenge replaces the previous one.
    ///
    /// # Errors
    /// [`AuthError::NotFound`] when there is no live pending row (the account has no key, the
    /// row expired or was used) or this server cannot be a relying party; storage errors.
    pub async fn webauthn_login_challenge(
        &self,
        req: &WebauthnLoginChallengeRequest,
        now_ms: u64,
    ) -> Result<WebauthnLoginChallengeResponse, AuthError> {
        let rp = self.relying_party()?;
        let mut tx = self.db.begin_write().await?;
        let Some(account) = self.peek_pending(&mut tx, &req.pending_id).await? else {
            return Err(AuthError::NotFound);
        };
        lock_account(&mut tx, account.as_bytes()).await?;
        let row: Option<(Vec<u8>, i64)> = fetch_opt!(
            tx.conn(),
            (Vec<u8>, i64),
            sql::WEBAUTHN_PENDING_PEEK,
            &req.pending_id.as_bytes()[..]
        )?;
        let live = match row {
            Some((owner, expires)) => {
                owner == account.as_bytes() && sql::sql_u64(expires, "expires_at_ms")? > now_ms
            }
            None => false,
        };
        if !live {
            return Err(AuthError::NotFound);
        }
        let keys = list(tx.conn(), account)
            .await?
            .iter()
            .map(StoredKey::decode)
            .collect::<Result<Vec<SecurityKey>, AuthError>>()?;
        if keys.is_empty() {
            return Err(AuthError::NotFound);
        }
        let (options, state) = rp
            .start_securitykey_authentication(&keys)
            .map_err(|_| AuthError::Internal("webauthn authentication start failed"))?;
        let pending = req.pending_id.to_bytes();
        exec!(tx.conn(), sql::WEBAUTHN_CHALLENGE_DELETE, &pending[..])?;
        put_state(
            &mut tx,
            &pending,
            account,
            PURPOSE_LOGIN,
            &to_json(&state)?,
            now_ms,
        )
        .await?;
        let totp = totp::list(&mut tx, account)
            .await?
            .iter()
            .any(|s| s.last_step.is_some());
        tx.commit().await?;
        Ok(WebauthnLoginChallengeResponse {
            options: WebauthnJson::new(to_json(&options)?).map_err(over_limit)?,
            totp,
        })
    }

    /// `webauthn/login/finish` (ADR 0058 point 3): takes pending row `pending_id` and its
    /// ceremony state once, verifies the assertion and issues the OPAQUE session, as
    /// `login/finish` would have. `source` and `reauth` are as for `login/finish`.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] for an unknown, expired or used pending row or state, an
    /// assertion the ceremony refuses (signature, challenge, origin, RP ID hash, UV) or one from a
    /// key no longer enrolled; [`AuthError::PossibleClone`] for a counter refusal (INV-83);
    /// [`AuthError::InvalidRequest`] for a credential that is not `WebAuthn` JSON;
    /// [`AuthError::RateLimited`]; [`AuthError::CredentialsStale`]; [`AuthError::NotFound`];
    /// storage errors.
    pub async fn webauthn_login_finish<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        req: &WebauthnLoginFinishRequest,
        source: &[u8],
        reauth: Option<&Session>,
        now_ms: u64,
    ) -> Result<LoginFinishResponse, AuthError> {
        let rp = self.relying_party()?;
        let mut tx = self.db.begin_write().await?;
        let Some(account) = self.peek_pending(&mut tx, &req.pending_id).await? else {
            tx.commit().await?;
            return Err(AuthError::Unauthorized);
        };
        lock_account(&mut tx, account.as_bytes()).await?;
        let outcome = self
            .login_finish_locked(&mut tx, rng, rp, account, req, source, reauth, now_ms)
            .await;
        self.settle_single_use(
            tx,
            outcome,
            sql::WEBAUTHN_PENDING_DELETE,
            &req.pending_id.as_bytes()[..],
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments of `webauthn_login_finish` plus its transaction and the locked account"
    )]
    /// [`AuthService::webauthn_login_finish`] under the account lock.
    async fn login_finish_locked<R: CryptoRng + Send + ?Sized>(
        &self,
        tx: &mut WriteTx,
        rng: &mut R,
        rp: &Webauthn,
        account: AccountId,
        req: &WebauthnLoginFinishRequest,
        source: &[u8],
        reauth: Option<&Session>,
        now_ms: u64,
    ) -> Result<LoginFinishResponse, AuthError> {
        let pending_id = &req.pending_id.as_bytes()[..];
        let pending: Option<(Vec<u8>, i64)> = fetch_opt!(
            tx.conn(),
            (Vec<u8>, i64),
            sql::WEBAUTHN_PENDING_TAKE,
            pending_id
        )?;
        let state: Option<SecurityKeyAuthentication> =
            take_state(tx, pending_id, account, PURPOSE_LOGIN, now_ms).await?;
        let pending_live = match pending {
            Some((owner, expires)) => {
                owner == account.as_bytes() && sql::sql_u64(expires, "expires_at_ms")? > now_ms
            }
            None => false,
        };
        let (true, Some(state)) = (pending_live, state) else {
            return Err(AuthError::Unauthorized);
        };
        let credential: PublicKeyCredential =
            serde_json::from_str(req.credential.as_str()).map_err(|_| AuthError::InvalidRequest)?;
        self.hit_webauthn(tx, account, now_ms).await?;
        let result = match rp.finish_securitykey_authentication(&credential, &state) {
            Ok(result) => result,
            Err(WebauthnError::CredentialPossibleCompromise) => {
                return Err(AuthError::PossibleClone {
                    account_id: account.to_bytes(),
                });
            }
            Err(_) => return Err(AuthError::Unauthorized),
        };
        // ADR 0077 §2 rule 4: the account's current rows decide, not the state.
        let asserted: &[u8] = result.cred_id().as_ref();
        let Some(stored) = list(tx.conn(), account)
            .await?
            .into_iter()
            .find(|k| k.credential_id == asserted)
        else {
            return Err(AuthError::Unauthorized);
        };
        let received = result.counter();
        if !counter_accepted(stored.sign_count, received) {
            return Err(AuthError::PossibleClone {
                account_id: account.to_bytes(),
            });
        }
        let mut key = stored.decode()?;
        key.update_credential(&result);
        exec!(
            tx.conn(),
            sql::WEBAUTHN_UPDATE,
            &account.as_bytes()[..],
            asserted,
            to_json(&key)?.as_str(),
            i64::from(SECURITY_KEY_FORMAT),
            i64::from(received),
        )?;
        ratelimit::clear(tx.conn(), &webauthn_bucket(account)).await?;
        let Some(record) = store::credential(tx.conn(), account.as_bytes()).await? else {
            return Err(AuthError::Unauthorized);
        };
        let trust = AccountTrust::load(tx.conn(), account).await?;
        if record.password_epoch < trust.state.password_epoch {
            return Err(AuthError::Unauthorized);
        }
        self.issue_login(tx, rng, account, &record, &trust, source, reauth, now_ms)
            .await
    }
}

/// INV-83 (ADR 0058 point 5) against the counter of record: accepted when both are 0 (no clone
/// detection is possible for that authenticator), when the stored one is 0 (tracking starts), or
/// when the received one is higher; refused when the stored one is above 0 and the received one
/// is at or below it.
#[must_use]
pub(crate) const fn counter_accepted(stored: u32, received: u32) -> bool {
    stored == 0 || received > stored
}

/// The counter a new `SecurityKey` enrolled with, read from the JSON being stored (the facade
/// does not expose it without `danger-credential-internals`). Missing means the JSON's shape is
/// not `webauthn-rs` 0.5.x's, which the fixture test catches first: fail closed.
fn enrolled_counter(json: &str) -> Result<u32, AuthError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| AuthError::Internal("security key JSON"))?;
    value
        .pointer("/cred/counter")
        .and_then(serde_json::Value::as_u64)
        .and_then(|c| u32::try_from(c).ok())
        .ok_or(AuthError::Internal("security key JSON has no counter"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_83_counter_cases() {
        assert!(counter_accepted(0, 0));
        assert!(counter_accepted(0, 5));
        assert!(counter_accepted(5, 6));
        assert!(!counter_accepted(5, 5));
        assert!(!counter_accepted(5, 4));
        assert!(!counter_accepted(5, 0));
    }

    #[test]
    fn relying_party_needs_a_domain() {
        let domain = ServerOrigin::parse("https://vault.example.com").unwrap();
        assert!(relying_party(&domain).is_some());
        let localhost = ServerOrigin::parse("http://localhost:8080").unwrap();
        assert!(relying_party(&localhost).is_some());
        let ip = ServerOrigin::parse("http://127.0.0.1:8080").unwrap();
        assert!(relying_party(&ip).is_none());
    }

    #[test]
    fn stored_json_is_bounded_and_versioned() {
        assert!(decode_security_key(SECURITY_KEY_FORMAT, "{}").is_none());
        assert!(decode_security_key(2, "{}").is_none());
        let big = format!("\"{}\"", "a".repeat(MAX_STORED_JSON_LEN));
        assert!(decode_security_key(SECURITY_KEY_FORMAT, &big).is_none());
        assert_eq!(fuzz_stored_json(SECURITY_KEY_FORMAT, "[]"), 0);
    }
}
