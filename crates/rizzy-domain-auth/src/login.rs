//! Login (CRYPTO.md §5.9–§5.11, §11.2 steps 2–5, §11.4, §11.15; INV-7, INV-8, INV-59).
//!
//! **Start.** The login name is normalised by the §2 function, then counted against the
//! rate-limit buckets (per (name, source) and per name; or, for a re-authentication from a
//! device-authenticated session of the same account, that device's own bucket, INV-7). The
//! name is looked up and the credential row read under the account's id, or under the fake
//! credential id for an unknown name. With a usable record the real path runs, otherwise the
//! fake-record path of §5.9 with `kdf_id` 1; both call the same `rizzy-core` function, which
//! selects the credential identifier in constant time. The pending `ServerLogin` is sealed as
//! `SERVER_LOGIN_STATE` under the current server data key, with a 60 s expiry in its context,
//! and stored under a random `login_id` (ADR 0010 §5).
//!
//! **Finish.** The lock of the account the state was started for is taken first; then the
//! sealed state is read and deleted in one statement, so it is used at most once (a failure
//! that rolls the transaction back deletes it again in its own transaction), and opened; KE3
//! is checked. Replacing an account's OPAQUE record deletes its pending login states under
//! the same lock, so KE3 always verifies against the record still stored: a login started
//! before a password change or a recovery cannot finish after it (INV-59). Nothing that differs between a real and an unknown
//! account happens before KE3 verified (§5.9): only then does the server load and verify the
//! account's signed state, refuse a record older than it (INV-59), check the TOTP code
//! (§11.15), and issue an OPAQUE session with the account objects of §11.2 step 5.

use rizzy_core::envelope::purpose::ServerLoginStateCtx;
use rizzy_core::ids::LoginId;
use rizzy_core::kdf::KdfId;
use rizzy_core::normalize::LoginName;
use rizzy_core::opaque::{
    CredentialIdentifier, OpaqueContext, OpaqueError, PasswordFile, RegisteredCredential,
    ServerLoginState, server_login_finish, server_login_start,
};
use rizzy_core::rng::CryptoRng;
use rizzy_proto::auth::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
};
use rizzy_proto::objects::AccountKeyServerWrap;
use rizzy_proto::wire::{Bytes, Id, Text};
use rizzy_storage::{WriteTx, lock_account};

use crate::config::LOGIN_STATE_TTL_MS;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::ratelimit::{self, BucketKind, bucket};
use crate::session::{self, Session, SessionKind};
use crate::sql::{self, exec, fetch_opt};
use crate::store::{self, Credential};
use crate::trust::AccountTrust;
use crate::view::{self, ViewScope};
use crate::{AuthService, over_limit};

/// A taken login-state row: credential identifier, data key id, sealed state, expiry.
type StateRow = (Vec<u8>, i64, Vec<u8>, i64);

impl<V: VaultPort> AuthService<V> {
    /// Login start (CRYPTO.md §11.2 steps 2–3): returns `{login_id, KE2, kdf_id,
    /// server_origin}`, identically shaped for real and unknown login names (§5.9).
    ///
    /// `source` is the client's address as the HTTP layer determined it (X-Forwarded-For only
    /// from configured proxies, threat model §7.6 "S"). `reauth` is the caller's
    /// device-authenticated session, when the login is a re-authentication from an enrolled
    /// device (§11.5 step 1, §11.8 step 0): if it is a device session of the account the name
    /// resolves to, the attempt counts against that device's own bucket, which unauthenticated
    /// attempts cannot exhaust (INV-7).
    ///
    /// # Errors
    /// [`AuthError::InvalidRequest`] for a login name outside §2's rules or a malformed KE1;
    /// [`AuthError::RateLimited`]; storage errors.
    pub async fn login_start<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        req: &LoginStartRequest,
        source: &[u8],
        reauth: Option<&Session>,
        now_ms: u64,
    ) -> Result<LoginStartResponse, AuthError> {
        let name =
            LoginName::parse(req.login_name.as_str()).map_err(|_| AuthError::InvalidRequest)?;
        let account = {
            let mut tx = self.db.begin_read().await?;
            let account = store::account_by_name(tx.conn(), name.as_str()).await?;
            tx.finish().await?;
            account
        };
        let limits = &self.config.rate_limits;
        let reauth_device = reauth.and_then(|s| {
            (s.kind == SessionKind::Device && Some(s.account_id) == account)
                .then_some(s.device_id)
                .flatten()
        });
        let buckets = match (reauth_device, account) {
            (Some(device), Some(account)) => vec![(
                bucket(BucketKind::Reauth, &[account.as_bytes(), device.as_bytes()]),
                limits.reauth_per_device,
            )],
            _ => vec![
                (
                    bucket(
                        BucketKind::LoginNameSource,
                        &[name.as_str().as_bytes(), source],
                    ),
                    limits.login_per_name_source,
                ),
                (
                    bucket(BucketKind::LoginName, &[name.as_str().as_bytes()]),
                    limits.login_per_name,
                ),
            ],
        };
        ratelimit::hit_all(&self.db, &buckets, now_ms).await?;

        // The credential identifier the lookup uses: the account's id, or the fake id, so both
        // paths run the same query.
        let fake = CredentialIdentifier::fake(&name);
        let lookup = account.map_or(fake, CredentialIdentifier::for_account);
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, lookup.as_bytes()).await?;
        let credential = store::credential(tx.conn(), lookup.as_bytes()).await?;
        // Decode a record on both paths (the stored one, or a fixed dummy of the same length),
        // so an unknown name does not answer faster by skipping the record's point decoding.
        let stored_record = credential.as_ref().map(|c| c.record.clone());
        let decoded = PasswordFile::from_bytes(stored_record.as_deref().unwrap_or(&dummy_record()));
        let record = account.zip(credential).and_then(|(account_id, c)| {
            let setup = self.secrets.setup(c.setup_id)?;
            let kdf_id = KdfId::from_u16(c.kdf_id).ok()?;
            let password_file = decoded.ok()?;
            Some((
                setup,
                RegisteredCredential {
                    account_id,
                    password_file,
                    kdf_id,
                },
            ))
        });
        let (_, current_setup) = self.secrets.current_setup()?;
        let (setup, record) = match record {
            Some((setup, record)) => (setup, Some(record)),
            None => (current_setup, None),
        };
        // An unknown name gets `kdf_id` 1 while every record is on 1 (§5.9, M1).
        let kdf_id = record.as_ref().map_or(KdfId::DEFAULT, |r| r.kdf_id);
        let context = OpaqueContext::new(kdf_id, &self.config.server_origin);
        let started = server_login_start(rng, setup, &name, record, req.ke1.as_slice(), &context)
            .map_err(|e| match e {
            OpaqueError::MalformedMessage => AuthError::InvalidRequest,
            _ => AuthError::Internal("OPAQUE login start failed"),
        })?;
        let login_id = LoginId::generate(rng);
        let expires_at_ms = now_ms.saturating_add(LOGIN_STATE_TTL_MS);
        let seal_ctx = ServerLoginStateCtx {
            login_id,
            credential_identifier: *started.state.credential_identifier().as_bytes(),
            expires_at_ms,
        };
        let key = self.secrets.current_data_key()?;
        let sealed = key
            .seal_login_state(rng, &seal_ctx, &started.state)
            .map_err(|_| AuthError::Internal("sealing the login state failed"))?;
        exec!(
            tx.conn(),
            sql::LOGIN_STATE_INSERT,
            &login_id.as_bytes()[..],
            &seal_ctx.credential_identifier[..],
            i64::from(key.data_key_id()),
            &sealed[..],
            sql::u64_sql(expires_at_ms, "expires_at_ms")?,
        )?;
        tx.commit().await?;
        Ok(LoginStartResponse {
            login_id: Id::from_bytes(login_id.to_bytes()),
            ke2: Bytes::new(started.ke2).map_err(over_limit)?,
            kdf_id: kdf_id.get(),
            server_origin: Text::new(self.config.server_origin.as_str().to_owned())
                .map_err(over_limit)?,
        })
    }

    /// Login finish (CRYPTO.md §11.2 step 5): checks KE3 against the sealed state, then 2FA,
    /// and issues an OPAQUE session with `account_id`, `E_srv` and its epochs, `E_id`, the
    /// current bundle, the `account-state`, `ACCOUNT_SETTINGS`, the certificates, revocations
    /// and self-grants.
    ///
    /// `source` is the address `login_start` counted; a success clears that (name, source)
    /// bucket. `reauth` binds the new session to the device a re-authentication came from, when
    /// it is a device session of the same account (CRYPTO.md §11.8 step 0 needs to know which
    /// device re-authenticated).
    ///
    /// # Errors
    /// - [`AuthError::Unauthorized`]: an unknown, expired or used `login_id`, a wrong KE3 (a
    ///   wrong password or Secret Key, an unknown account), or a record older than the signed
    ///   state (INV-59). One answer for all of them (§5.9);
    /// - [`AuthError::SecondFactorRequired`]: KE3 verified but the account has 2FA and the
    ///   code is missing or wrong; the login must start again;
    /// - [`AuthError::RateLimited`]: too many TOTP checks for the account;
    /// - [`AuthError::InvalidRequest`]: a malformed KE3;
    /// - storage errors.
    pub async fn login_finish<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        req: &LoginFinishRequest,
        source: &[u8],
        reauth: Option<&Session>,
        now_ms: u64,
    ) -> Result<LoginFinishResponse, AuthError> {
        let mut tx = self.db.begin_write().await?;
        // Take the account lock the state was started under before taking the state, so a
        // credential replacement (which deletes the account's pending login states under the
        // same lock, `store::put_credential`) lands either before the take (the state is gone)
        // or after this finish (INV-59; CRYPTO.md §11.5 step 5, §11.9 step 6).
        let peeked: Option<(Vec<u8>,)> = fetch_opt!(
            tx.conn(),
            (Vec<u8>,),
            sql::LOGIN_STATE_PEEK,
            &req.login_id.as_bytes()[..]
        )?;
        let Some((peeked,)) = peeked else {
            tx.commit().await?;
            return Err(AuthError::Unauthorized);
        };
        let lock = sql::id16(&peeked, "credential_identifier")?;
        lock_account(&mut tx, &lock).await?;
        let outcome = self
            .finish_locked(&mut tx, rng, req, &lock, source, reauth, now_ms)
            .await;
        self.settle_single_use(
            tx,
            outcome,
            sql::LOGIN_STATE_DELETE,
            &req.login_id.as_bytes()[..],
        )
        .await
    }

    /// The part of [`AuthService::login_finish`] under the account lock `lock`: takes the
    /// login state (read and deleted in one statement), checks KE3, INV-59 and 2FA, and issues
    /// the session. The caller commits or discards through
    /// [`AuthService::settle_single_use`], so the state is used at most once on every path.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments of `login_finish` plus its transaction and the locked id"
    )]
    async fn finish_locked<R: CryptoRng + Send + ?Sized>(
        &self,
        tx: &mut WriteTx,
        rng: &mut R,
        req: &LoginFinishRequest,
        lock: &[u8; 16],
        source: &[u8],
        reauth: Option<&Session>,
        now_ms: u64,
    ) -> Result<LoginFinishResponse, AuthError> {
        let Some((credential_identifier, state)) =
            self.take_login_state(tx, &req.login_id, now_ms).await?
        else {
            return Err(AuthError::Unauthorized);
        };
        if credential_identifier != *lock {
            // The row changed between the peek and the take: never, as login ids are random
            // and rows are never updated; refused rather than run under the wrong lock.
            return Err(AuthError::Unauthorized);
        }
        let credential = store::credential(tx.conn(), &credential_identifier).await?;
        let kdf_id = credential
            .as_ref()
            .and_then(|c| KdfId::from_u16(c.kdf_id).ok())
            .unwrap_or(KdfId::DEFAULT);
        let context = OpaqueContext::new(kdf_id, &self.config.server_origin);
        match server_login_finish(state, req.ke3.as_slice(), &context) {
            Ok(()) => {}
            Err(OpaqueError::MalformedMessage) => return Err(AuthError::InvalidRequest),
            Err(_) => return Err(AuthError::Unauthorized),
        }
        // KE3 verified: from here on the client knew the password and the Secret Key of this
        // record, so what follows may differ between accounts (§5.9). The record it verified
        // against is still the stored one: replacing it deletes the pending login states under
        // this lock.
        let account_id = rizzy_core::ids::AccountId::from_bytes(credential_identifier);
        let Some(credential) = credential else {
            return Err(AuthError::Unauthorized);
        };
        let trust = AccountTrust::load(tx.conn(), account_id).await?;
        if credential.password_epoch < trust.state.password_epoch {
            // INV-59: a record older than the signed state (a restore brought it back).
            return Err(AuthError::Unauthorized);
        }
        let code = req
            .totp
            .as_ref()
            .map(rizzy_proto::wire::SecretText::expose_secret);
        // A refused code still counts: the refusal is committed with the take.
        if !self
            .check_second_factor(tx, account_id, code, now_ms)
            .await?
        {
            return Err(AuthError::SecondFactorRequired);
        }
        let device = reauth.and_then(|s| {
            (s.kind == SessionKind::Device && s.account_id == account_id)
                .then_some(s.device_id)
                .flatten()
        });
        let (token, _) = session::create(
            tx.conn(),
            rng,
            account_id,
            device,
            SessionKind::Opaque,
            now_ms,
            self.config.opaque_session_ttl_ms,
        )
        .await?;
        if let Some(name) = store::account_name(tx.conn(), account_id).await? {
            let key = bucket(BucketKind::LoginNameSource, &[name.as_bytes(), source]);
            ratelimit::clear(tx.conn(), &key).await?;
        }
        let devices = trust.devices(tx.conn()).await?;
        let account =
            view::build(&self.vault, tx.conn(), &trust, &devices, ViewScope::Current).await?;
        let wrap = server_wrap(&credential, trust.state.account_key_epoch)?;
        Ok(LoginFinishResponse {
            session_token: token,
            account_id: Id::from_bytes(account_id.to_bytes()),
            account_key_server_wrap: wrap,
            account,
        })
    }
}

/// `E_srv` with its locator. The server keeps `E_srv` at the state's `account_key_epoch`
/// (every rotation replaces it, §11.6 step 4), and the record's `password_epoch` and `kdf_id`.
pub(crate) fn server_wrap(
    credential: &Credential,
    account_key_epoch: u32,
) -> Result<AccountKeyServerWrap, AuthError> {
    Ok(AccountKeyServerWrap {
        account_key_epoch,
        password_epoch: credential.password_epoch,
        kdf_id: credential.kdf_id,
        envelope: Bytes::new(credential.e_srv.clone()).map_err(over_limit)?,
    })
}

impl<V: VaultPort> AuthService<V> {
    /// Reads and deletes the sealed login state `login_id` in one statement (§5.11) and opens
    /// it; `None` for an unknown, used, expired or tampered state.
    async fn take_login_state(
        &self,
        tx: &mut WriteTx,
        login_id: &Id,
        now_ms: u64,
    ) -> Result<Option<([u8; 16], ServerLoginState)>, AuthError> {
        let row: Option<StateRow> = fetch_opt!(
            tx.conn(),
            StateRow,
            sql::LOGIN_STATE_TAKE,
            &login_id.as_bytes()[..]
        )?;
        let Some((credential_identifier, data_key_id, sealed, expires)) = row else {
            return Ok(None);
        };
        let credential_identifier = sql::id16(&credential_identifier, "credential_identifier")?;
        let seal_ctx = ServerLoginStateCtx {
            login_id: LoginId::from_bytes(login_id.to_bytes()),
            credential_identifier,
            expires_at_ms: sql::sql_u64(expires, "expires_at_ms")?,
        };
        let key = self
            .secrets
            .data_key(sql::sql_u32(data_key_id, "data_key_id")?)?;
        Ok(key
            .open_login_state(&seal_ctx, &sealed, now_ms)
            .ok()
            .map(|state| (credential_identifier, state)))
    }
}

/// A registration record of the right length whose client public key is the ristretto255
/// base point (a valid encoding) and whose other fields are zero. Decoding it costs what
/// decoding a stored record costs; it is never used for a login.
fn dummy_record() -> Vec<u8> {
    /// The canonical encoding of the ristretto255 generator (RFC 9496 Appendix A.1), the same
    /// value the `opaque_server` fuzz target uses.
    const BASE_POINT: [u8; 32] = [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ];
    let mut record = vec![0u8; rizzy_core::opaque::REGISTRATION_UPLOAD_LEN];
    for (dst, src) in record.iter_mut().zip(BASE_POINT) {
        *dst = src;
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_record_decodes() {
        assert!(PasswordFile::from_bytes(&dummy_record()).is_ok());
    }
}
