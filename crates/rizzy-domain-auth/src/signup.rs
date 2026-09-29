//! Signup (CRYPTO.md §11.1; §5.9 "Registration"; INV-7).
//!
//! 1. [`AuthService::register_start`]: the login name normalised by the §2 function, the
//!    signup policy (invite-only by default, §5.9), the rate limits per source, per (name,
//!    source) and per name (§5.9, INV-7), and the reservation
//!    of the name for the client-chosen `account_id`; then OPAQUE `ServerRegistration::start`
//!    with `credential_identifier = account_id` under the current `server_setup`.
//! 2. [`AuthService::register_finish`]: the cheap consistency checks of §11.1 step 8
//!    ([`rules::check_signup`]), then every object in one transaction; a byte-identical repeat
//!    for the same `account_id` is success.
//!
//! Registration is an enumeration oracle ("name taken", §5.9): it answers
//! [`AuthError::Conflict`] for a taken name, which is why signup is closed or invite-only by
//! default and rate-limited when open: per source, and per (name, source) with a per-name cap,
//! so probing one name from many sources backs off too (INV-7).

use rizzy_core::ids::AccountId;
use rizzy_core::normalize::LoginName;
use rizzy_core::opaque::{
    CredentialIdentifier, server_registration_finish, server_registration_start,
};
use rizzy_proto::auth::{RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse};
use rizzy_proto::wire::Bytes;
use rizzy_storage::{WriteTx, lock_account};

use crate::config::SignupPolicy;
use crate::error::AuthError;
use crate::ports::{PersonalVault, VaultPort};
use crate::ratelimit::{self, BucketKind, bucket};
use crate::rules;
use crate::sql::{self, exec};
use crate::store::{self, Credential, RecoveryRow};
use crate::trust::AccountTrust;
use crate::{AuthService, account_id};

impl<V: VaultPort> AuthService<V> {
    /// Signup, OPAQUE registration start (CRYPTO.md §11.1 steps 4.2–4.3): checks the signup
    /// policy, normalises the login name, rate-limits per `source` (the client's address, as
    /// the HTTP layer determined it), per (name, `source`) and per name, reserves the name for
    /// `req.account_id`, and returns M2.
    ///
    /// Repeating the call for the same name and id before the signup finished is allowed (a
    /// client that crashed); another id for a reserved name is [`AuthError::Conflict`].
    ///
    /// # Errors
    /// - [`AuthError::SignupRefused`]: signup is closed, or the invite is missing or refused;
    /// - [`AuthError::RateLimited`];
    /// - [`AuthError::InvalidRequest`]: a login name outside §2's rules, a malformed M1;
    /// - [`AuthError::Conflict`]: the name or the id is taken;
    /// - storage errors.
    pub async fn register_start(
        &self,
        req: &RegisterStartRequest,
        source: &[u8],
        now_ms: u64,
    ) -> Result<RegisterStartResponse, AuthError> {
        let name =
            LoginName::parse(req.login_name.as_str()).map_err(|_| AuthError::InvalidRequest)?;
        match &self.config.signup {
            SignupPolicy::Closed => return Err(AuthError::SignupRefused),
            SignupPolicy::Invite(verifier) => {
                let admitted = req
                    .invite
                    .as_ref()
                    .is_some_and(|token| verifier.admits(token.expose_secret(), &name));
                if !admitted {
                    return Err(AuthError::SignupRefused);
                }
            }
            SignupPolicy::Open => {}
        }
        // INV-7 ("unauthenticated login and registration attempts get exponential backoff per
        // (account identifier, source IP) and a per-account cap") and §5.9 ("rate-limited per
        // IP") both apply: the conservative reading counts all three buckets, before the name
        // lookup that answers "name taken".
        let limits = &self.config.rate_limits;
        ratelimit::hit_all(
            &self.db,
            &[
                (
                    bucket(BucketKind::SignupSource, &[source]),
                    limits.signup_per_source,
                ),
                (
                    bucket(
                        BucketKind::SignupNameSource,
                        &[name.as_str().as_bytes(), source],
                    ),
                    limits.signup_per_name_source,
                ),
                (
                    bucket(BucketKind::SignupName, &[name.as_str().as_bytes()]),
                    limits.signup_per_name,
                ),
            ],
            now_ms,
        )
        .await?;
        let account = account_id(&req.account_id);
        let (_, setup) = self.secrets.current_setup()?;
        let response = server_registration_start(
            setup,
            req.registration_request.as_slice(),
            &CredentialIdentifier::for_account(account),
        )
        .map_err(|_| AuthError::InvalidRequest)?;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        match store::account_by_name(tx.conn(), name.as_str()).await? {
            Some(held) if held != account => return Err(AuthError::Conflict),
            Some(_) => {
                if store::credential(tx.conn(), account.as_bytes())
                    .await?
                    .is_some()
                {
                    return Err(AuthError::Conflict);
                }
            }
            None => {
                if store::account_name(tx.conn(), account).await?.is_some() {
                    return Err(AuthError::Conflict);
                }
                exec!(
                    tx.conn(),
                    sql::ACCOUNT_INSERT,
                    &account.as_bytes()[..],
                    name.as_str(),
                    sql::u64_sql(now_ms, "created_at_ms")?,
                )?;
            }
        }
        tx.commit().await?;
        Ok(RegisterStartResponse {
            registration_response: Bytes::new(response)
                .map_err(|_| AuthError::Internal("M2 exceeds its wire limit"))?,
        })
    }

    /// Signup commit (CRYPTO.md §11.1 step 8): checks the bundle self-signature, the state and
    /// the certificate chain and every locator ([`rules::check_signup`]), then stores the OPAQUE
    /// record with the current `setup_id` and the state's `kdf_id` and `password_epoch`, `E_srv`,
    /// `E_id`, the bundle, the state, the certificate, `E_rec` and `H_rec` with the state's
    /// `recovery_epoch`, and the personal vault ([`VaultPort::create_personal_vault`]), in one
    /// transaction.
    ///
    /// The account's name must have been reserved by [`AuthService::register_start`] for the
    /// state's `account_id`. A byte-identical repeat of a finished signup is success.
    ///
    /// # Errors
    /// - [`AuthError::InvalidRequest`]: a check failed, or no signup was started for the id;
    /// - [`AuthError::Conflict`]: the account exists with other objects;
    /// - storage errors.
    pub async fn register_finish(
        &self,
        req: &RegisterFinishRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let checked = rules::check_signup(req, now_ms)?;
        let record = server_registration_finish(req.registration_upload.as_slice())
            .map_err(|_| AuthError::InvalidRequest)?
            .to_bytes();
        let account = checked.account_id;
        let (setup_id, _) = self.secrets.current_setup()?;
        let credential = Credential {
            setup_id,
            record,
            kdf_id: checked.state.kdf_id.get(),
            password_epoch: checked.state.password_epoch,
            e_srv: req.account_key_server_wrap.envelope.as_slice().to_vec(),
        };
        let recovery = req.recovery.as_ref().map(|r| RecoveryRow {
            recovery_epoch: r.recovery_wrap.recovery_epoch,
            e_rec: r.recovery_wrap.envelope.as_slice().to_vec(),
            h_rec: r.recovery_token_hash.to_bytes(),
        });
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        if store::account_name(tx.conn(), account).await?.is_none() {
            return Err(AuthError::InvalidRequest);
        }
        if let Some(held) = store::credential(tx.conn(), account.as_bytes()).await? {
            let same =
                signup_is_repeat(&mut tx, account, req, &held, &credential, recovery.as_ref())
                    .await?;
            let vault = self
                .vault
                .create_personal_vault(&mut tx, account, &req.vault_self_grant, now_ms)
                .await?;
            return if same && vault == PersonalVault::Identical {
                tx.commit().await?;
                Ok(())
            } else {
                Err(AuthError::Conflict)
            };
        }
        store::put_credential(tx.conn(), account, &credential, now_ms).await?;
        store::put_identity(
            tx.conn(),
            account,
            req.identity_secret_keys.identity_epoch,
            req.identity_secret_keys.envelope.as_slice(),
            now_ms,
        )
        .await?;
        store::put_bundle(tx.conn(), account, 1, req.bundle.as_slice(), now_ms).await?;
        exec!(
            tx.conn(),
            sql::STATE_INSERT,
            &account.as_bytes()[..],
            sql::u64_sql(checked.state.state_seq, "state_seq")?,
            req.account_state.as_slice(),
            sql::u64_sql(now_ms, "updated_at_ms")?,
        )?;
        store::put_cert(
            tx.conn(),
            &checked.certificate,
            req.device_certificate.as_slice(),
            now_ms,
        )
        .await?;
        if let Some(row) = &recovery {
            store::put_recovery(tx.conn(), account, row, now_ms).await?;
        }
        match self
            .vault
            .create_personal_vault(&mut tx, account, &req.vault_self_grant, now_ms)
            .await?
        {
            PersonalVault::Created => {}
            PersonalVault::Identical | PersonalVault::Conflict => return Err(AuthError::Conflict),
        }
        tx.commit().await?;
        Ok(())
    }
}

/// Whether a signup commit repeats the one stored for `account`, byte for byte (§11.1 step 8:
/// "treats a byte-identical repeat for the same `account_id` as success").
async fn signup_is_repeat(
    tx: &mut WriteTx,
    account: AccountId,
    req: &RegisterFinishRequest,
    held: &Credential,
    offered: &Credential,
    recovery: Option<&RecoveryRow>,
) -> Result<bool, AuthError> {
    let trust = AccountTrust::load(tx.conn(), account).await?;
    let certs: Vec<Vec<u8>> = trust
        .devices(tx.conn())
        .await?
        .certs
        .into_iter()
        .map(|c| c.wire)
        .collect();
    let identity = store::identity(tx.conn(), account).await?;
    let held_recovery = store::recovery(tx.conn(), account).await?;
    let same_identity = identity.as_ref().map(|(e, b)| (*e, b.as_slice()))
        == Some((
            req.identity_secret_keys.identity_epoch,
            req.identity_secret_keys.envelope.as_slice(),
        ));
    Ok(held == offered
        && trust.state_wire.as_slice() == req.account_state.as_slice()
        && trust.chain_wires.len() == 1
        && trust.head_wire()? == req.bundle.as_slice()
        && same_identity
        && certs == [req.device_certificate.as_slice().to_vec()]
        && held_recovery.as_ref() == recovery)
}
