//! The `rizzy-proto` entry points of the flows whose domain functions take typed arguments:
//! credential and settings changes, suspension, recovery and TOTP enrolment (CRYPTO.md §11
//! "Replacing credentials", §11.5, §11.8 step 0, §11.9, §11.15).
//!
//! Each method takes the request type the server parsed and returns the response type it
//! serialises, and does nothing but convert: every check stays in the typed function it calls
//! ([`AuthService::commit_change`], [`AuthService::recovery_start`], and so on).
//!
//! **No rotation.** [`CommitChangeRequest`] has no rotation fields yet (its docs), so the
//! [`AccountChange`] built here carries no bundle, `E_id'`, retired key, device grant or vault
//! half, and [`AuthService::commit_change`] refuses a state that rotates a key as an invalid
//! request.

use rizzy_core::ids::DeviceId;
use rizzy_core::rng::CryptoRng;
use rizzy_proto::change::{
    CommitChangeRequest, DeviceSuspensionRequest, ReregisterStartRequest, ReregisterStartResponse,
    SuspendDeviceResponse,
};
use rizzy_proto::recovery::{
    RecoveryCancelResponse, RecoveryCompleteResponse, RecoveryRequest, RecoveryStartResponse,
};
use rizzy_proto::totp::{
    TotpDisableRequest, TotpEnrolConfirmRequest, TotpEnrolStartResponse, TotpSecretBytes,
};
use rizzy_proto::wire::List;

use crate::change::{AccountChange, RecoveryUpload};
use crate::error::AuthError;
use crate::ports::VaultPort;
use crate::session::Session;
use crate::{AuthService, device_id};

/// The [`AccountChange`] a [`CommitChangeRequest`] describes, with no rotation (module docs).
fn account_change<R>(req: &CommitChangeRequest) -> AccountChange<R> {
    AccountChange {
        account_state: req.account_state.clone(),
        bundle: None,
        registration_upload: req.registration_upload.clone(),
        account_key_server_wrap: req.account_key_server_wrap.clone(),
        identity_secret_keys: None,
        recovery: req
            .recovery
            .clone()
            .map_or(RecoveryUpload::None, RecoveryUpload::Register),
        account_settings: req.account_settings.clone(),
        retired_secret_keys: Vec::new(),
        device_certificates: req.device_certificates.clone(),
        device_revocations: req.device_revocations.clone(),
        device_grants: List::empty(),
        vault_rotation: None,
    }
}

/// The target device of a suspension request.
const fn target(req: &DeviceSuspensionRequest) -> DeviceId {
    device_id(&req.device_id)
}

impl<V: VaultPort> AuthService<V> {
    /// [`AuthService::reregister_start`] from its request.
    ///
    /// # Errors
    /// As [`AuthService::reregister_start`].
    pub async fn reregister_start_request(
        &self,
        session: &Session,
        req: &ReregisterStartRequest,
        now_ms: u64,
    ) -> Result<ReregisterStartResponse, AuthError> {
        let registration_response = self
            .reregister_start(session, &req.registration_request, now_ms)
            .await?;
        Ok(ReregisterStartResponse {
            registration_response,
        })
    }

    /// [`AuthService::commit_change`] from its request, without a rotation (module docs).
    ///
    /// # Errors
    /// As [`AuthService::commit_change`]; a state that rotates a key is
    /// [`AuthError::InvalidRequest`].
    pub async fn commit_change_request(
        &self,
        session: &Session,
        req: &CommitChangeRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        self.commit_change(session, &account_change(req), now_ms)
            .await
    }

    /// [`AuthService::suspend_device`] from its request: H, for the revocation.
    ///
    /// # Errors
    /// As [`AuthService::suspend_device`].
    pub async fn suspend_device_request(
        &self,
        session: &Session,
        req: &DeviceSuspensionRequest,
        now_ms: u64,
    ) -> Result<SuspendDeviceResponse, AuthError> {
        let last_accepted_device_seq = self.suspend_device(session, target(req), now_ms).await?;
        Ok(SuspendDeviceResponse {
            last_accepted_device_seq,
        })
    }

    /// [`AuthService::unsuspend_device`] from its request.
    ///
    /// # Errors
    /// As [`AuthService::unsuspend_device`].
    pub async fn unsuspend_device_request(
        &self,
        session: &Session,
        req: &DeviceSuspensionRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        self.unsuspend_device(session, target(req), now_ms).await
    }

    /// [`AuthService::recovery_start`] from its request. The answer carries only the end of
    /// the waiting period; the pending recovery's account, which a notifier would need (CRYPTO.md
    /// §11.9 step 2, M3), stays on the server.
    ///
    /// # Errors
    /// As [`AuthService::recovery_start`].
    pub async fn recovery_start_request(
        &self,
        req: &RecoveryRequest,
        source: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryStartResponse, AuthError> {
        let pending = self
            .recovery_start(
                req.login_name.as_str(),
                req.recovery_auth_token.expose_secret(),
                source,
                now_ms,
            )
            .await?;
        Ok(RecoveryStartResponse {
            available_at_ms: pending.available_at_ms,
        })
    }

    /// [`AuthService::recovery_cancel`], answered with whether a recovery was pending.
    ///
    /// # Errors
    /// As [`AuthService::recovery_cancel`].
    pub async fn recovery_cancel_request(
        &self,
        session: &Session,
        now_ms: u64,
    ) -> Result<RecoveryCancelResponse, AuthError> {
        let cancelled = self.recovery_cancel(session, now_ms).await?;
        Ok(RecoveryCancelResponse { cancelled })
    }

    /// [`AuthService::recovery_complete`] from its request.
    ///
    /// # Errors
    /// As [`AuthService::recovery_complete`].
    pub async fn recovery_complete_request<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        req: &RecoveryRequest,
        source: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryCompleteResponse, AuthError> {
        let release = self
            .recovery_complete(
                rng,
                req.login_name.as_str(),
                req.recovery_auth_token.expose_secret(),
                source,
                now_ms,
            )
            .await?;
        Ok(RecoveryCompleteResponse {
            session_token: release.session_token,
            account_id: release.account_id,
            recovery_wrap: release.recovery_wrap,
            account: release.account,
        })
    }

    /// [`AuthService::totp_enrol_start`], with the secret in its wire form.
    ///
    /// # Errors
    /// As [`AuthService::totp_enrol_start`]; [`AuthError::Internal`] if the secret is not the
    /// 20 bytes CRYPTO.md §11.15 generates.
    pub async fn totp_enrol_start_request<R: CryptoRng + Send + ?Sized>(
        &self,
        rng: &mut R,
        session: &Session,
        now_ms: u64,
    ) -> Result<TotpEnrolStartResponse, AuthError> {
        let enrolment = self.totp_enrol_start(rng, session, now_ms).await?;
        let secret = TotpSecretBytes::from_slice(enrolment.secret.expose_secret())
            .map_err(|_| AuthError::Internal("a generated TOTP secret is not 20 bytes"))?;
        Ok(TotpEnrolStartResponse {
            totp_credential_seq: enrolment.totp_credential_seq,
            secret,
        })
    }

    /// [`AuthService::totp_enrol_confirm`] from its request.
    ///
    /// # Errors
    /// As [`AuthService::totp_enrol_confirm`].
    pub async fn totp_enrol_confirm_request(
        &self,
        session: &Session,
        req: &TotpEnrolConfirmRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        self.totp_enrol_confirm(
            session,
            req.totp_credential_seq,
            req.code.expose_secret(),
            now_ms,
        )
        .await
    }

    /// [`AuthService::totp_disable`] from its request.
    ///
    /// # Errors
    /// As [`AuthService::totp_disable`].
    pub async fn totp_disable_request(
        &self,
        session: &Session,
        req: &TotpDisableRequest,
        now_ms: u64,
    ) -> Result<(), AuthError> {
        self.totp_disable(session, req.code.expose_secret(), now_ms)
            .await
    }
}
