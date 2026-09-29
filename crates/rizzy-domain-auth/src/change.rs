//! Atomic changes of the signed account state that carry credentials, keys or devices
//! (CRYPTO.md §11 "Replacing credentials" and "Secrets before commit"; §11.3 step 5, §11.5,
//! §11.6, §11.8 steps 1–3, §11.9 steps 5–6; ADR 0012 §6).
//!
//! One entry point, [`AuthService::commit_change`], takes an [`AccountChange`]: the new
//! `account-state` and every object the change it describes needs. The server classifies the
//! step from the current verified state to the new one ([`rules::classify`]) and requires
//! exactly the objects that step needs, no more:
//!
//! | The new state… | …needs | Session |
//! |---|---|---|
//! | `password_epoch + 1` (password or SK change, §11.5) | a new OPAQUE record and `E_srv'` | fresh OPAQUE, or recovery-only |
//! | same `password_epoch`, new record (same-password re-registration, §5.8, §6.3) | the record and `E_srv'` | fresh OPAQUE, recovery-only, or a device session |
//! | `account_key_epoch + 1` (standard rotation, §11.6) | `E_srv'`, `E_id'`, a device grant per remaining device, the vault half ([`VaultPort::apply_rotation`]), `E_rec'` if recovery is on, new settings if any | fresh OPAQUE or recovery-only |
//! | `identity_epoch + 1` (full rotation) | all of the above, the new bundle signed by both identity keys, a re-issue of every certificate and revocation | fresh OPAQUE or recovery-only |
//! | `recovery_epoch + 1` (new code) | `E_rec` and `H_rec` | fresh OPAQUE or recovery-only |
//! | recovery switched off | nothing; `E_rec` and `H_rec` are deleted | fresh OPAQUE or recovery-only |
//! | `settings_seq + 1` | the new `ACCOUNT_SETTINGS` | fresh OPAQUE or a device session |
//! | a new durable device | its certificate (enrolment in a recovery, §11.9 step 5; re-enrolment, §11.3 step 5) | fresh OPAQUE or recovery-only |
//! | a revoked device | its `device-revocation` with `last_accepted_device_seq` = H, the head the server still holds; with a rotation, after the suspension of §11.8 step 0, over a fresh re-authentication of another device; without one only in the self-revocation shape of §11.3 step 5 | fresh OPAQUE |
//!
//! The recovery-only session commits only the recovery of §11.9 step 5: a new password
//! (`password_epoch + 1`) and a new code (`recovery_epoch + 1`), optionally with a rotation and
//! the recovering client's own enrolment.
//!
//! The new state is applied by compare-and-swap on `state_seq`; a byte-identical repeat of a
//! committed state is success (the client that crashed after sending resends, §11). After the
//! commit: a password change ends every OPAQUE and recovery session (§11.5 step 5), a
//! recovery ends every session (§11.9 step 6), a full rotation ends the other OPAQUE sessions
//! (the web sessions its revocations cut, §11.6 step 7), and a revocation ends the revoked
//! device's sessions. A new code or switching recovery off closes any pending recovery.

use core::fmt;

use rizzy_core::envelope::purpose::Purpose;
use rizzy_core::ids::{AccountId, DeviceId, KeyType};
use rizzy_core::opaque::{
    CredentialIdentifier, server_registration_finish, server_registration_start,
};
use rizzy_core::sign::{
    AccountState, BundleStep, DeviceCertificate, DeviceRevocation, KeyGrant, Verified,
    VerifiedBundle,
};
use rizzy_proto::auth::RecoveryRegistration;
use rizzy_proto::limits::{MAX_DEVICE_GRANTS, MAX_DEVICE_STATEMENTS};
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, AccountSettings, AccountStatement, DeviceGrant,
    IdentitySecretKeys, KeyEnvelope, OpaqueMessage,
};
use rizzy_proto::wire::{Bytes, Id, List};
use rizzy_storage::{WriteTx, lock_account};

use crate::AuthService;
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::rules::{self, RecoveryTransition, Transition};
use crate::session::{self, Session, SessionKind};
use crate::sql::{self, exec};
use crate::store::{self, Credential, Offered, RecoveryRow};
use crate::trust::{AccountTrust, Devices};

/// The most `RETIRED_SECRET_KEY` envelopes one change may carry. A full rotation retires the
/// two identity keys and, from M6, a mail key; the bound only keeps the request small.
pub const MAX_RETIRED_KEYS: usize = 16;

/// A `RETIRED_SECRET_KEY` envelope (CRYPTO.md §8.4, §11.6 step 3) with its locator, the
/// retired public key's id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredSecretKey {
    /// The retired public key id (§4.4), which files the envelope.
    pub retired_key_id: Id,
    /// The envelope under the new account key.
    pub envelope: KeyEnvelope,
}

/// The recovery objects of a change (CRYPTO.md §11 "Replacing credentials", §11.6 step 5).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum RecoveryUpload {
    /// None: recovery unchanged and no rotation, or recovery switched off.
    #[default]
    None,
    /// A new recovery code: `E_rec` and `H_rec` at `recovery_epoch + 1`.
    Register(RecoveryRegistration),
    /// A rotation that keeps the current code: `E_rec` under the new `account_key_epoch`, the
    /// `recovery_epoch` and `H_rec` unchanged.
    Rewrap(AccountKeyRecoveryWrap),
}

/// One atomic change of the account (see the module docs for which objects each change
/// needs). Built by the server's HTTP layer from the request; every list is bounded by its
/// type.
pub struct AccountChange<R> {
    /// The new `account-state`, `state_seq + 1`.
    pub account_state: AccountStatement,
    /// The new bundle of a full rotation, signed by the new and the preceding identity key.
    pub bundle: Option<AccountStatement>,
    /// A new OPAQUE registration upload, registered through
    /// [`AuthService::reregister_start`] under `credential_identifier = account_id`.
    pub registration_upload: Option<OpaqueMessage>,
    /// `E_srv'`, with a new registration or a rotation.
    pub account_key_server_wrap: Option<AccountKeyServerWrap>,
    /// `E_id'`, with a rotation.
    pub identity_secret_keys: Option<IdentitySecretKeys>,
    /// The recovery objects.
    pub recovery: RecoveryUpload,
    /// The new `ACCOUNT_SETTINGS`, when `settings_seq` moves.
    pub account_settings: Option<AccountSettings>,
    /// Retired secret keys, with a rotation (at most [`MAX_RETIRED_KEYS`]).
    pub retired_secret_keys: Vec<RetiredSecretKey>,
    /// New and re-issued certificates.
    pub device_certificates: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// New and re-issued revocations.
    pub device_revocations: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// Device grants at the new `account_key_epoch`, with a rotation.
    pub device_grants: List<DeviceGrant, MAX_DEVICE_GRANTS>,
    /// The vault half of a rotation.
    pub vault_rotation: Option<R>,
}

impl<R> fmt::Debug for AccountChange<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountChange")
            .field("bundle", &self.bundle.is_some())
            .field("registration_upload", &self.registration_upload.is_some())
            .field("device_certificates", &self.device_certificates.len())
            .field("device_revocations", &self.device_revocations.len())
            .field("device_grants", &self.device_grants.len())
            .field("vault_rotation", &self.vault_rotation.is_some())
            .finish_non_exhaustive()
    }
}

/// The device side of a change after its statements verified.
#[derive(Debug, Default)]
struct DevicePlan {
    /// Certificates for devices the account does not hold yet (enrolments).
    new_certs: Vec<(Verified<DeviceCertificate>, Vec<u8>)>,
    /// Re-issued certificates of a full rotation.
    reissued_certs: Vec<(Verified<DeviceCertificate>, Vec<u8>)>,
    /// Revocations of devices not revoked yet.
    new_revocations: Vec<(Verified<DeviceRevocation>, Vec<u8>)>,
    /// Re-issued revocations of a full rotation.
    reissued_revocations: Vec<(Verified<DeviceRevocation>, Vec<u8>)>,
}

impl DevicePlan {
    /// Every certificate of the change.
    fn all_certs(&self) -> Vec<Verified<DeviceCertificate>> {
        self.new_certs
            .iter()
            .chain(&self.reissued_certs)
            .map(|(c, _)| c.clone())
            .collect()
    }

    /// Every revocation of the change.
    fn all_revocations(&self) -> Vec<Verified<DeviceRevocation>> {
        self.new_revocations
            .iter()
            .chain(&self.reissued_revocations)
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// Whether the change has the self-revocation shape of CRYPTO.md §11.3 step 5: one new
    /// durable device and one revoked durable device.
    fn is_self_revocation(&self, devices: &Devices) -> bool {
        self.new_certs.len() == 1
            && self.new_revocations.len() == 1
            && self.new_revocations.iter().all(|(r, _)| {
                devices
                    .cert(r.device_id)
                    .is_some_and(|c| c.cert.in_device_set())
            })
    }
}

impl<V: VaultPort> AuthService<V> {
    /// OPAQUE re-registration start (CRYPTO.md §11.5 step 3, §11.9 step 5, §5.8): M2 for a new
    /// record under `credential_identifier = account_id`, with the current `server_setup`. The
    /// record is committed with [`AuthService::commit_change`].
    ///
    /// Allowed over a fresh OPAQUE session, the recovery-only session, or a device session (a
    /// same-password re-registration; [`AuthService::commit_change`] enforces what each may
    /// commit).
    ///
    /// # Errors
    /// [`AuthError::FreshSessionRequired`]; [`AuthError::InvalidRequest`] for a malformed M1;
    /// storage errors.
    pub async fn reregister_start(
        &self,
        session: &Session,
        registration_request: &OpaqueMessage,
        now_ms: u64,
    ) -> Result<OpaqueMessage, AuthError> {
        let mut tx = self.db.begin_read().await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        let allowed = session.is_fresh_opaque(now_ms)
            || matches!(session.kind, SessionKind::Recovery | SessionKind::Device);
        if !allowed {
            return Err(AuthError::FreshSessionRequired);
        }
        if session.kind == SessionKind::Device {
            let trust = AccountTrust::load(tx.conn(), session.account_id).await?;
            let devices = trust.devices(tx.conn()).await?;
            let usable = session
                .device_id
                .is_some_and(|d| devices.usable_durable(d, now_ms).is_some());
            if !usable {
                return Err(AuthError::Unauthorized);
            }
        }
        tx.finish().await?;
        let (_, setup) = self.secrets.current_setup()?;
        let response = server_registration_start(
            setup,
            registration_request.as_slice(),
            &CredentialIdentifier::for_account(session.account_id),
        )
        .map_err(|_| AuthError::InvalidRequest)?;
        Bytes::new(response).map_err(|_| AuthError::Internal("M2 exceeds its wire limit"))
    }

    /// Commits one atomic change of the account (see the module docs), under the account lock,
    /// by compare-and-swap on `state_seq`.
    ///
    /// # Errors
    /// - [`AuthError::FreshSessionRequired`]: the session may not make this change;
    /// - [`AuthError::InvalidRequest`]: a statement does not verify, the state makes a step no
    ///   flow makes, an object the step needs is missing or one it does not need is present, a
    ///   locator disagrees with the state, a device-set hash or grant set is wrong;
    /// - [`AuthError::StateConflict`], [`AuthError::StateFork`]: the compare-and-swap lost, or
    ///   a revocation's H is no longer the head (the client fetches and retries);
    /// - [`AuthError::Unauthorized`]: an ended session;
    /// - the vault half's errors; storage errors.
    pub async fn commit_change(
        &self,
        session: &Session,
        change: &AccountChange<V::Rotation>,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let account = session.account_id;
        let mut tx = self.db.begin_write().await?;
        lock_account(&mut tx, account.as_bytes()).await?;
        let session = session::reload(tx.conn(), session, now_ms).await?;
        let trust = AccountTrust::load(tx.conn(), account).await?;
        let devices = trust.devices(tx.conn()).await?;
        // A byte-identical repeat of the applied commit is success (CRYPTO.md §11 "Secrets
        // before commit"). Checked before the bundle: after a full rotation the stored head is
        // the change's own bundle, which is not a successor of itself.
        let repeat = change.account_state.as_slice() == trust.state_wire.as_slice()
            && match &change.bundle {
                Some(bundle) => bundle.as_slice() == trust.head_wire()?,
                None => true,
            };
        if repeat {
            tx.commit().await?;
            return Ok(());
        }
        let (new_head, new_bundle) = match &change.bundle {
            Some(wire) => match trust.head()?.verify_successor(wire.as_slice()) {
                Ok((next, BundleStep::IdentityChanged)) => (next.clone(), Some(next)),
                _ => return Err(AuthError::InvalidRequest),
            },
            None => (trust.head()?.clone(), None),
        };
        let wire = change.account_state.as_slice();
        let new = rules::verify_state_at_head(wire, &new_head, account)?;
        if store::place_offered(&trust.state, &trust.state_wire, &new, wire)? == Offered::Repeat {
            tx.commit().await?;
            return Ok(());
        }
        let step = rules::classify(&trust.state, &new)?;
        if step.identity_changed != new_bundle.is_some() {
            return Err(AuthError::InvalidRequest);
        }
        check_objects(step, &new, change)?;
        let plan = self
            .plan_devices(&mut tx, &trust, &devices, &new_head, &step, change, now_ms)
            .await?;
        let expected =
            devices.device_set_with(account, &plan.all_certs(), &plan.all_revocations())?;
        if expected != new.device_set_hash {
            return Err(AuthError::InvalidRequest);
        }
        authorize(&session, step, change, &plan, &devices, now_ms)?;
        if session.kind == SessionKind::Recovery
            && crate::recovery::pending(&mut tx, account).await?.is_none()
        {
            // The pending recovery was cancelled after the release (§11.9 step 2).
            return Err(AuthError::Unauthorized);
        }
        if step.account_key_rotated {
            check_grants(&session, &new, &new_head, &devices, &plan, change)?;
        }
        let credential = self
            .replaced_credential(&mut tx, account, &new, change)
            .await?;
        self.write_change(
            &mut tx,
            &session,
            &trust,
            &new,
            &step,
            change,
            &plan,
            credential.as_ref(),
            new_bundle.as_ref(),
            now_ms,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Checks every certificate and revocation of the change against the stored ones and
    /// sorts them into a [`DevicePlan`] (module docs; CRYPTO.md §11.6 step 7, §11.8).
    #[expect(
        clippy::too_many_arguments,
        reason = "the verified parts of one change, passed once from `commit_change`"
    )]
    async fn plan_devices(
        &self,
        tx: &mut WriteTx,
        trust: &AccountTrust,
        devices: &Devices,
        head: &VerifiedBundle,
        step: &Transition,
        change: &AccountChange<V::Rotation>,
        now_ms: u64,
    ) -> Result<DevicePlan, AuthError> {
        let account = trust.account_id;
        let mut plan = DevicePlan::default();
        let mut seen: Vec<DeviceId> = Vec::new();
        for wire in &change.device_certificates {
            let cert = rules::verify_certificate(wire.as_slice(), head, account)?;
            if seen.contains(&cert.device_id) {
                return Err(AuthError::InvalidRequest);
            }
            seen.push(cert.device_id);
            match devices.cert(cert.device_id) {
                Some(stored_cert)
                    if step.identity_changed && rules::is_reissue(&stored_cert.cert, &cert) =>
                {
                    plan.reissued_certs.push((cert, wire.as_slice().to_vec()));
                }
                Some(_) => return Err(AuthError::InvalidRequest),
                None if devices.is_revoked(cert.device_id) => {
                    return Err(AuthError::InvalidRequest);
                }
                None => {
                    let fresh = cert.in_device_set()
                        && (cert.expires_at_ms == 0 || cert.expires_at_ms > now_ms);
                    if !fresh {
                        return Err(AuthError::InvalidRequest);
                    }
                    plan.new_certs.push((cert, wire.as_slice().to_vec()));
                }
            }
        }
        if step.identity_changed {
            // Every certificate the account holds is re-issued under the new key (§11.6 step 7).
            let all = devices.certs.iter().all(|c| {
                plan.reissued_certs
                    .iter()
                    .any(|(r, _)| r.device_id == c.cert.device_id)
            });
            if !all || plan.new_certs.len() > 1 {
                return Err(AuthError::InvalidRequest);
            }
        }
        let mut seen: Vec<DeviceId> = Vec::new();
        for wire in &change.device_revocations {
            let revocation = rules::verify_revocation(wire.as_slice(), head, account)?;
            if seen.contains(&revocation.device_id) {
                return Err(AuthError::InvalidRequest);
            }
            seen.push(revocation.device_id);
            if let Some(held) = devices.revocation(revocation.device_id) {
                if !step.identity_changed || held.revocation.statement() != revocation.statement() {
                    return Err(AuthError::InvalidRequest);
                }
                plan.reissued_revocations
                    .push((revocation, wire.as_slice().to_vec()));
                continue;
            }
            let Some(target) = devices.cert(revocation.device_id) else {
                return Err(AuthError::InvalidRequest);
            };
            if devices.is_revoked(revocation.device_id)
                || (!target.cert.in_device_set() && !step.identity_changed)
            {
                return Err(AuthError::InvalidRequest);
            }
            // §11.8 step 3: accepted only if H is still the head the server holds.
            let head_seq = self
                .vault
                .device_head(tx.conn(), account, revocation.device_id)
                .await?;
            if revocation.last_accepted_device_seq != head_seq {
                return Err(AuthError::StateConflict);
            }
            if step.account_key_rotated && target.cert.in_device_set() && !target.suspended {
                return Err(AuthError::InvalidRequest);
            }
            plan.new_revocations
                .push((revocation, wire.as_slice().to_vec()));
        }
        if step.identity_changed {
            let all = devices.revocations.iter().all(|r| {
                plan.reissued_revocations
                    .iter()
                    .any(|(n, _)| n.device_id == r.revocation.device_id)
            });
            if !all {
                return Err(AuthError::InvalidRequest);
            }
        }
        if !step.account_key_rotated
            && !plan.new_revocations.is_empty()
            && !plan.is_self_revocation(devices)
        {
            // A revocation without a rotation: only the self-revocation of §11.3 step 5.
            return Err(AuthError::InvalidRequest);
        }
        Ok(plan)
    }

    /// The credential row after the change: a new record with its `E_srv`, or the current
    /// record with a new `E_srv` (a rotation without re-registration), or `None` when neither
    /// changes.
    async fn replaced_credential(
        &self,
        tx: &mut WriteTx,
        account: AccountId,
        new: &AccountState,
        change: &AccountChange<V::Rotation>,
    ) -> Result<Option<Credential>, AuthError> {
        let Some(wrap) = &change.account_key_server_wrap else {
            return Ok(None);
        };
        let e_srv = wrap.envelope.as_slice().to_vec();
        if let Some(upload) = &change.registration_upload {
            let record = server_registration_finish(upload.as_slice())
                .map_err(|_| AuthError::InvalidRequest)?
                .to_bytes();
            let (setup_id, _) = self.secrets.current_setup()?;
            return Ok(Some(Credential {
                setup_id,
                record,
                kdf_id: new.kdf_id.get(),
                password_epoch: new.password_epoch,
                e_srv,
            }));
        }
        let held = store::credential(tx.conn(), account.as_bytes())
            .await?
            .ok_or(AuthError::Internal("an account without an OPAQUE record"))?;
        Ok(Some(Credential { e_srv, ..held }))
    }

    /// Writes every object of a checked change, applies the vault half, the compare-and-swap
    /// and the session and pending-recovery effects (module docs).
    #[expect(
        clippy::too_many_arguments,
        reason = "the checked parts of one change, passed once from `commit_change`"
    )]
    async fn write_change(
        &self,
        tx: &mut WriteTx,
        session: &Session,
        trust: &AccountTrust,
        new: &Verified<AccountState>,
        step: &Transition,
        change: &AccountChange<V::Rotation>,
        plan: &DevicePlan,
        credential: Option<&Credential>,
        new_bundle: Option<&VerifiedBundle>,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        let account = trust.account_id;
        if let Some(credential) = credential {
            store::put_credential(tx.conn(), account, credential, now_ms).await?;
        }
        if let Some(keys) = &change.identity_secret_keys {
            store::put_identity(
                tx.conn(),
                account,
                keys.identity_epoch,
                keys.envelope.as_slice(),
                now_ms,
            )
            .await?;
        }
        self.write_recovery(tx, account, step, change, now_ms)
            .await?;
        if let Some(settings) = &change.account_settings {
            exec!(
                tx.conn(),
                sql::SETTINGS_UPSERT,
                &account.as_bytes()[..],
                sql::u64_sql(settings.settings_seq, "settings_seq")?,
                settings.envelope.as_slice(),
                sql::u64_sql(now_ms, "updated_at_ms")?,
            )?;
        }
        for retired in &change.retired_secret_keys {
            exec!(
                tx.conn(),
                sql::RETIRED_KEY_UPSERT,
                &account.as_bytes()[..],
                &retired.retired_key_id.as_bytes()[..],
                retired.envelope.as_slice(),
                sql::u64_sql(now_ms, "stored_at_ms")?,
            )?;
        }
        if let (Some(bundle), Some(wire)) = (new_bundle, &change.bundle) {
            store::put_bundle(
                tx.conn(),
                account,
                bundle.bundle_seq,
                wire.as_slice(),
                now_ms,
            )
            .await?;
        }
        for (cert, wire) in plan.new_certs.iter().chain(&plan.reissued_certs) {
            store::put_cert(tx.conn(), cert, wire, now_ms).await?;
        }
        for (revocation, wire) in plan
            .new_revocations
            .iter()
            .chain(&plan.reissued_revocations)
        {
            store::put_revocation(tx.conn(), revocation, wire, now_ms).await?;
            session::end_device(tx.conn(), account, revocation.device_id).await?;
        }
        for grant in &change.device_grants {
            exec!(
                tx.conn(),
                sql::GRANT_UPSERT,
                &account.as_bytes()[..],
                &grant.recipient_device_id.as_bytes()[..],
                i64::from(grant.account_key_epoch),
                &grant.sender_device_id.as_bytes()[..],
                grant.key_grant.as_slice(),
                sql::u64_sql(now_ms, "stored_at_ms")?,
            )?;
        }
        if let (true, Some(rotation)) = (step.account_key_rotated, &change.vault_rotation) {
            self.vault
                .apply_rotation(tx, account, new.account_key_epoch, rotation, now_ms)
                .await?;
        }
        store::cas_state(
            tx.conn(),
            account,
            trust.state.state_seq,
            new,
            change.account_state.as_slice(),
            now_ms,
        )
        .await?;
        if session.kind == SessionKind::Recovery {
            session::end_all(tx.conn(), account).await?;
        } else if step.password_bumped {
            session::end_kind(tx.conn(), account, SessionKind::Opaque).await?;
            session::end_kind(tx.conn(), account, SessionKind::Recovery).await?;
        } else if step.identity_changed {
            session::end_kind_except(tx.conn(), account, SessionKind::Opaque, session).await?;
        }
        Ok(())
    }

    /// Writes the recovery objects and closes a pending recovery when the code changes or
    /// recovery is switched off.
    async fn write_recovery(
        &self,
        tx: &mut WriteTx,
        account: AccountId,
        step: &Transition,
        change: &AccountChange<V::Rotation>,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        match (&change.recovery, step.recovery) {
            (RecoveryUpload::Register(reg), _) => {
                let row = RecoveryRow {
                    recovery_epoch: reg.recovery_wrap.recovery_epoch,
                    e_rec: reg.recovery_wrap.envelope.as_slice().to_vec(),
                    h_rec: reg.recovery_token_hash.to_bytes(),
                };
                store::put_recovery(tx.conn(), account, &row, now_ms).await?;
            }
            (RecoveryUpload::Rewrap(wrap), _) => {
                let held = store::recovery(tx.conn(), account)
                    .await?
                    .filter(|r| r.recovery_epoch == wrap.recovery_epoch)
                    .ok_or(AuthError::InvalidRequest)?;
                let row = RecoveryRow {
                    e_rec: wrap.envelope.as_slice().to_vec(),
                    ..held
                };
                store::put_recovery(tx.conn(), account, &row, now_ms).await?;
            }
            (RecoveryUpload::None, RecoveryTransition::Disabled) => {
                exec!(tx.conn(), sql::RECOVERY_DELETE, &account.as_bytes()[..])?;
            }
            (RecoveryUpload::None, _) => {}
        }
        if step.recovery != RecoveryTransition::Unchanged {
            exec!(
                tx.conn(),
                sql::PENDING_RECOVERY_DELETE,
                &account.as_bytes()[..]
            )?;
        }
        Ok(())
    }
}

/// The objects a step needs, and no others (module docs), with their locators checked against
/// the new state.
fn check_objects<R>(
    step: Transition,
    new: &AccountState,
    change: &AccountChange<R>,
) -> Result<(), AuthError> {
    let invalid = || AuthError::InvalidRequest;
    let registration = change.registration_upload.is_some();
    let rotated = step.account_key_rotated;
    if (step.password_bumped || step.kdf_changed) && !registration {
        return Err(invalid());
    }
    // E_srv' with a new record or a rotation, at the new state's epochs and kdf_id.
    match &change.account_key_server_wrap {
        Some(w) if registration || rotated => {
            if w.account_key_epoch != new.account_key_epoch
                || w.password_epoch != new.password_epoch
                || w.kdf_id != new.kdf_id.get()
            {
                return Err(invalid());
            }
        }
        None if !registration && !rotated => {}
        _ => return Err(invalid()),
    }
    match &change.identity_secret_keys {
        Some(k) if rotated && k.identity_epoch == new.identity_epoch => {}
        None if !rotated => {}
        _ => return Err(invalid()),
    }
    let recovery_ok = match (&change.recovery, step.recovery) {
        (RecoveryUpload::Register(r), RecoveryTransition::NewCode) => {
            r.recovery_wrap.account_key_epoch == new.account_key_epoch
                && r.recovery_wrap.recovery_epoch == new.recovery_epoch
        }
        (RecoveryUpload::Rewrap(w), RecoveryTransition::Unchanged) => {
            rotated
                && new.recovery_enabled
                && w.account_key_epoch == new.account_key_epoch
                && w.recovery_epoch == new.recovery_epoch
        }
        (RecoveryUpload::None, RecoveryTransition::Unchanged) => !(rotated && new.recovery_enabled),
        (RecoveryUpload::None, RecoveryTransition::Disabled) => true,
        _ => false,
    };
    let settings_ok = match &change.account_settings {
        Some(s) => {
            step.settings_changed
                && s.settings_seq == new.settings_seq
                && new.matches_settings(Some(s.envelope.as_slice()))
        }
        None => !step.settings_changed,
    };
    let rotation_only_ok = rotated
        || (change.retired_secret_keys.is_empty()
            && change.device_grants.is_empty()
            && change.vault_rotation.is_none());
    if !recovery_ok
        || !settings_ok
        || !rotation_only_ok
        || (rotated && change.vault_rotation.is_none())
        || change.retired_secret_keys.len() > MAX_RETIRED_KEYS
    {
        return Err(invalid());
    }
    Ok(())
}

/// Whether `session` may make this change (module docs).
fn authorize<R>(
    session: &Session,
    step: Transition,
    change: &AccountChange<R>,
    plan: &DevicePlan,
    devices: &Devices,
    now_ms: u64,
) -> Result<(), AuthError> {
    let credentials = change.registration_upload.is_some()
        || step.account_key_rotated
        || step.recovery != RecoveryTransition::Unchanged;
    let heavy = credentials
        || step.password_bumped
        || !plan.new_certs.is_empty()
        || !plan.new_revocations.is_empty();
    let same_password_reregistration = change.registration_upload.is_some()
        && !step.password_bumped
        && !step.account_key_rotated
        && step.recovery == RecoveryTransition::Unchanged
        && plan.new_certs.is_empty()
        && plan.new_revocations.is_empty();
    match session.kind {
        SessionKind::Recovery => {
            // §11.9 step 5: a new password and a new code, never a revocation.
            let recovery_commit = step.password_bumped
                && step.recovery == RecoveryTransition::NewCode
                && plan.new_revocations.is_empty();
            if recovery_commit {
                Ok(())
            } else {
                Err(AuthError::FreshSessionRequired)
            }
        }
        SessionKind::Opaque if session.is_fresh_opaque(now_ms) => {
            if step.account_key_rotated && !plan.new_revocations.is_empty() {
                // §11.8: the revoker is another durable device, re-authenticated.
                let own = session
                    .device_id
                    .filter(|d| devices.usable_durable(*d, now_ms).is_some())
                    .ok_or(AuthError::FreshSessionRequired)?;
                if plan.new_revocations.iter().any(|(r, _)| r.device_id == own) {
                    return Err(AuthError::InvalidRequest);
                }
            }
            Ok(())
        }
        SessionKind::Device
            if session
                .device_id
                .is_some_and(|d| devices.usable_durable(d, now_ms).is_some())
                && (!heavy || same_password_reregistration) =>
        {
            Ok(())
        }
        _ => Err(AuthError::FreshSessionRequired),
    }
}

/// The device grants of a rotation (CRYPTO.md §11.6 step 6, §10.1): exactly one grant at the
/// new `account_key_epoch` for every durable device of the new set other than the rotating
/// client's own (the session's device, or a device the change enrols), each signed by its
/// sender, a certificate of the account (a device key), or for a kind-4 sender the identity
/// key of the new state, and addressed to the recipient's X25519 key.
fn check_grants<R>(
    session: &Session,
    new: &AccountState,
    head: &VerifiedBundle,
    devices: &Devices,
    plan: &DevicePlan,
    change: &AccountChange<R>,
) -> Result<(), AuthError> {
    let invalid = AuthError::InvalidRequest;
    let final_cert = |id: DeviceId| -> Option<Verified<DeviceCertificate>> {
        plan.new_certs
            .iter()
            .chain(&plan.reissued_certs)
            .find(|(c, _)| c.device_id == id)
            .map(|(c, _)| c.clone())
            .or_else(|| devices.cert(id).map(|c| c.cert.clone()))
    };
    let revoked = |id: DeviceId| {
        devices.is_revoked(id) || plan.new_revocations.iter().any(|(r, _)| r.device_id == id)
    };
    let exempt = |id: DeviceId| {
        session.device_id == Some(id) || plan.new_certs.iter().any(|(c, _)| c.device_id == id)
    };
    let recipients: Vec<Verified<DeviceCertificate>> = devices
        .certs
        .iter()
        .map(|c| c.cert.device_id)
        .chain(plan.new_certs.iter().map(|(c, _)| c.device_id))
        .filter_map(final_cert)
        .filter(|c| c.in_device_set() && !revoked(c.device_id) && !exempt(c.device_id))
        .collect();
    if change.device_grants.len() != recipients.len() {
        return Err(invalid);
    }
    let mut covered: Vec<DeviceId> = Vec::with_capacity(recipients.len());
    for grant in &change.device_grants {
        let recipient_id = DeviceId::from_bytes(grant.recipient_device_id.to_bytes());
        let recipient = recipients
            .iter()
            .find(|c| c.device_id == recipient_id)
            .ok_or(AuthError::InvalidRequest)?;
        if grant.account_key_epoch != new.account_key_epoch || covered.contains(&recipient_id) {
            return Err(AuthError::InvalidRequest);
        }
        covered.push(recipient_id);
        // A durable sender signs with its device key; a kind-4 client (whose certificate the
        // server may not hold, e.g. a web vault recovering) with the identity key (§10.1).
        let sender = final_cert(DeviceId::from_bytes(grant.sender_device_id.to_bytes()))
            .filter(|c| c.in_device_set());
        let verified = match &sender {
            Some(sender) => KeyGrant::verify(grant.key_grant.as_slice(), &sender.device_ed25519),
            None => KeyGrant::verify(grant.key_grant.as_slice(), &head.identity_ed25519),
        }
        .map_err(|_| AuthError::InvalidRequest)?;
        if verified.purpose() != Purpose::AccountKeyDeviceGrant
            || *verified.recipient_key_id() != recipient.device_x25519.key_id(KeyType::DeviceX25519)
        {
            return Err(AuthError::InvalidRequest);
        }
    }
    Ok(())
}
