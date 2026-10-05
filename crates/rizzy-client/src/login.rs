//! Login on a new device and its enrolment (CRYPTO.md §11.2), and the web vault's ephemeral
//! device (§11.4), as a sans-I/O state machine.
//!
//! ```text
//! start_login ──LoginStartRequest──► host ──LoginStartResponse──► LoginStarted::finish
//!   ──LoginFinishRequest──► host ──LoginFinishResponse──► LoginAwaitingSession::complete
//!   ──► LoggedIn ── enrol ──EnrolDeviceRequest──► host ──ack──► PendingEnrolment::finalize
//!             └─ web_device ──UploadWebDeviceCertificateRequest──► host (kind 4, §11.4)
//! ```
//!
//! A web session reads the account again while it lives ([`web_account_query`],
//! [`verify_web_refresh`]): the certificates of devices and web sessions certified after its
//! login, without which their ops cannot be verified and are dropped.
//!
//! # Checks
//!
//! - Before any stretching: the served `kdf_id` is on the allow-list and the served origin is
//!   the dialled one (§11.2 step 4, [`rizzy_core::opaque::OpaqueContext::for_login`]). The
//!   Context binds the dialled origin, so a relay fails KE2 verification.
//! - A failed OPAQUE finish is [`ClientError::WrongPasswordOrSecretKey`]; nothing says which.
//! - The login answer is verified in full ([`crate::account`]); in addition `E_srv` opens, the
//!   state's `kdf_id` equals the one used, and the state's epochs equal those of `E_srv`'s
//!   context (§11.2 step 6).
//!
//! # Readings
//!
//! - **The login name** is sent in its normalised form ([`LoginName`]); the server normalises
//!   it again (§5.9), so the two agree.
//! - **A lost compare-and-swap** on the enrolment (`state_conflict`) is not retried here: the
//!   host logs in again, and the client rebuilds the enrolment on the fresh state
//!   ([`AccountState::cas_retry`](rizzy_core::sign::AccountState::cas_retry) is the rule).

use core::fmt;

use rizzy_core::envelope::purpose::AccountKeyServerWrapCtx;
use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{AccountKey, DeviceKeys, device_set_hash};
use rizzy_core::normalize::{LoginName, ServerOrigin};
use rizzy_core::opaque::{
    ClientLoginState, ExportKey, LoginHintError, OpaqueContext, PasswordInput, client_login_finish,
    client_login_start,
};
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::statements::WEB_CERT_MAX_LIFETIME_MS;
use rizzy_core::sign::{DeviceCertificate, DeviceKind};
use rizzy_proto::account::{
    AccountStateQuery, AccountView, EnrolDeviceRequest, UploadWebDeviceCertificateRequest,
};
use rizzy_proto::auth::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, TotpCode,
};
use rizzy_proto::wire::{SessionToken, Text};

use crate::account::{Anchor, CertifiedDevice, VerifiedAccount, verify_account_view};
use crate::device::{DeviceState, NewDevice, UnlockedDevice};
use crate::error::{ClientError, internal};
use crate::wire::bytes;

/// What the user enters on a new device (§11.2 step 1).
#[derive(Clone, Copy)]
pub struct LoginInput<'a> {
    /// The server URL the host dials.
    pub server_origin: &'a str,
    /// The login name.
    pub login_name: &'a str,
    /// The Secret Key, as typed or scanned (`RV1-…`).
    pub secret_key: &'a str,
    /// The master password.
    pub password: &'a str,
}

impl fmt::Debug for LoginInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginInput([REDACTED])")
    }
}

/// The login after KE1. Holds `pw_in`; `Debug` redacted.
pub struct LoginStarted {
    /// The dialled origin.
    origin: ServerOrigin,
    /// The Secret Key.
    secret_key: SecretKey,
    /// `pw_in`.
    pw_in: PasswordInput,
    /// The OPAQUE client state.
    state: ClientLoginState,
}

impl fmt::Debug for LoginStarted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginStarted([REDACTED])")
    }
}

/// Steps 1–2: parses the input and starts the OPAQUE login.
///
/// # Errors
/// [`ClientError::InvalidInput`] for an origin, login name or Secret Key that does not parse;
/// [`ClientError::Internal`].
pub fn start_login<R: CryptoRng + ?Sized>(
    rng: &mut R,
    input: &LoginInput<'_>,
) -> Result<(LoginStarted, LoginStartRequest), ClientError> {
    let origin = ServerOrigin::parse(input.server_origin).map_err(|_| ClientError::InvalidInput)?;
    let login_name = LoginName::parse(input.login_name).map_err(|_| ClientError::InvalidInput)?;
    let wire_name =
        Text::new(login_name.as_str().to_owned()).map_err(|_| ClientError::InvalidInput)?;
    let secret_key = SecretKey::parse(input.secret_key).map_err(|_| ClientError::InvalidInput)?;
    let pw_in = PasswordInput::derive(input.password, &secret_key)
        .map_err(|_| ClientError::InvalidInput)?;
    let (state, ke1) = client_login_start(rng, &pw_in).map_err(|_| ClientError::Internal)?;
    Ok((
        LoginStarted {
            origin,
            secret_key,
            pw_in,
            state,
        },
        LoginStartRequest {
            login_name: wire_name,
            ke1: bytes(ke1)?,
        },
    ))
}

impl LoginStarted {
    /// Steps 3–5: checks the server's hints, finishes OPAQUE (the one Argon2id run) and builds
    /// KE3. `totp` is the second factor, if the account has one.
    ///
    /// # Errors
    /// [`ClientError::KdfNotAllowed`], [`ClientError::OriginMismatch`] before any stretching;
    /// [`ClientError::WrongPasswordOrSecretKey`]; [`ClientError::InvalidInput`] for a TOTP
    /// code outside its bounds.
    pub fn finish<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &LoginStartResponse,
        totp: Option<&str>,
    ) -> Result<(LoginAwaitingSession, LoginFinishRequest), ClientError> {
        let totp = totp
            .map(TotpCode::new)
            .transpose()
            .map_err(|_| ClientError::InvalidInput)?;
        let context = OpaqueContext::for_login(
            &self.origin,
            response.kdf_id,
            response.server_origin.as_str(),
        )
        .map_err(|e| match e {
            LoginHintError::KdfNotAllowed(_) => ClientError::KdfNotAllowed,
            _ => ClientError::OriginMismatch,
        })?;
        let fin = client_login_finish(
            rng,
            self.state,
            &self.pw_in,
            response.ke2.as_slice(),
            &context,
        )
        .map_err(|_| ClientError::WrongPasswordOrSecretKey)?;
        Ok((
            LoginAwaitingSession {
                origin: self.origin,
                secret_key: self.secret_key,
                pw_in: self.pw_in,
                export_key: fin.export_key,
                kdf_id: context.kdf_id(),
            },
            LoginFinishRequest {
                login_id: response.login_id,
                ke3: bytes(fin.ke3)?,
                totp,
            },
        ))
    }
}

/// The login after KE3, waiting for the session and the account answer. Holds the
/// `export_key`; `Debug` redacted.
pub struct LoginAwaitingSession {
    /// The dialled origin.
    origin: ServerOrigin,
    /// The Secret Key.
    secret_key: SecretKey,
    /// `pw_in`, for `E_local` at enrolment.
    pw_in: PasswordInput,
    /// OPAQUE's `export_key`.
    export_key: ExportKey,
    /// The `kdf_id` used.
    kdf_id: KdfId,
}

impl fmt::Debug for LoginAwaitingSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginAwaitingSession([REDACTED])")
    }
}

impl LoginAwaitingSession {
    /// Step 6: opens `E_srv` and verifies the whole answer, aborting on any failure.
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`].
    pub fn complete(self, response: LoginFinishResponse) -> Result<LoggedIn, ClientError> {
        let bad = ClientError::InvalidServerResponse;
        let account_id = AccountId::from_bytes(response.account_id.to_bytes());
        let wrap = &response.account_key_server_wrap;
        if wrap.kdf_id != self.kdf_id.get() {
            return Err(bad);
        }
        let ctx = AccountKeyServerWrapCtx {
            account_id,
            account_key_epoch: wrap.account_key_epoch,
            password_epoch: wrap.password_epoch,
            kdf_id: self.kdf_id,
        };
        let account_key = self
            .export_key
            .server_unlock_key(account_id)
            .map_err(|_| ClientError::Internal)?
            .unwrap_account_key(&ctx, wrap.envelope.as_slice())
            .map_err(|_| bad)?;
        let account = verify_account_view(
            &response.account,
            account_id,
            &account_key,
            &Anchor::NewDevice,
        )?;
        let state = account.state();
        if state.kdf_id != self.kdf_id
            || state.account_key_epoch != wrap.account_key_epoch
            || state.password_epoch != wrap.password_epoch
        {
            return Err(bad);
        }
        Ok(LoggedIn {
            origin: self.origin,
            secret_key: self.secret_key,
            pw_in: self.pw_in,
            export_key: self.export_key,
            account,
            account_key,
            session_token: response.session_token,
            reregister: response.reregister,
        })
    }
}

/// A verified OPAQUE login (§11.2 steps 1–6): the bearer session and the verified account.
pub struct LoggedIn {
    /// The dialled origin.
    pub(crate) origin: ServerOrigin,
    /// The Secret Key.
    pub(crate) secret_key: SecretKey,
    /// `pw_in`.
    pub(crate) pw_in: PasswordInput,
    /// OPAQUE's `export_key` of this login: the `server_unlock_key` of `E_srv'` in a rotation
    /// (CRYPTO.md §11.6 step 4, [`crate::rotation`]).
    pub(crate) export_key: ExportKey,
    /// The verified account.
    pub(crate) account: VerifiedAccount,
    /// The account key.
    pub(crate) account_key: AccountKey,
    /// The OPAQUE session's bearer token.
    pub(crate) session_token: SessionToken,
    /// The answer's `reregister` flag (ADR 0031 point 2; [`crate::reregister`]).
    pub(crate) reregister: bool,
}

impl fmt::Debug for LoggedIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoggedIn")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl LoggedIn {
    /// The verified account.
    #[must_use]
    pub const fn account(&self) -> &VerifiedAccount {
        &self.account
    }

    /// The OPAQUE session's bearer token, for the host's transport. Never log it.
    #[must_use]
    pub const fn bearer_token(&self) -> &SessionToken {
        &self.session_token
    }

    /// Step 7: enrols this client as a durable device: new device keys, a certificate signed
    /// with the identity key, `E_local` and `E_dev` (one more Argon2id run), and a new
    /// `account-state` with `state_seq + 1` and the new device set.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a kind-4 `device_kind` (use
    /// [`LoggedIn::web_device`]); [`ClientError::Internal`].
    pub fn enrol<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        device_kind: DeviceKind,
        now_ms: u64,
    ) -> Result<(PendingEnrolment, EnrolDeviceRequest), ClientError> {
        if !device_kind.is_durable() {
            return Err(ClientError::InvalidInput);
        }
        let mut account = self.account;
        let device_id = DeviceId::generate(rng);
        let device_keys = DeviceKeys::generate(rng);
        let own = certify(&account, device_id, &device_keys, device_kind, now_ms, 0)?;
        let mut state = account.pin.state.clone();
        state.state_seq = state
            .state_seq
            .checked_add(1)
            .ok_or(ClientError::Internal)?;
        state.device_set_hash = device_set_hash(
            account.account_id,
            account
                .certificates
                .iter()
                .map(|c| &c.certificate)
                .chain([&own.certificate]),
            account.revocations.iter().map(|r| &r.revocation),
        )
        .map_err(|_| ClientError::InvalidServerResponse)?;
        let state_wire = state
            .sign(account.identity.signing_key())
            .map_err(internal)?;
        let request = EnrolDeviceRequest {
            device_certificate: bytes(own.wire.clone())?,
            account_state: bytes(state_wire.clone())?,
        };
        account.pin.state = state;
        account.pin.state_wire = state_wire;
        account.certificates.push(own.clone());
        let device = DeviceState::create(
            rng,
            NewDevice {
                server_origin: self.origin,
                account_id: account.account_id,
                device_id,
                device_kind,
                secret_key: self.secret_key,
                pw_in: &self.pw_in,
                account_key: &self.account_key,
                password_epoch: account.pin.state.password_epoch,
                device_keys: &device_keys,
                pin: account.pin.clone(),
            },
        )?;
        Ok((
            PendingEnrolment {
                device,
                unlocked: UnlockedDevice {
                    account_id: account.account_id,
                    device_id,
                    account_key: self.account_key,
                    device_keys,
                    local_unlock_key: None,
                },
                account,
                session_token: self.session_token,
                own,
            },
            request,
        ))
    }

    /// The web vault's ephemeral device (§11.4): a kind-4 key pair in memory with a certificate
    /// that expires 12 h after `now_ms`. It is not part of the device set and publishes no new
    /// `account-state`; nothing is persisted.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if `now_ms` + 12 h overflows; [`ClientError::Internal`].
    pub fn web_device<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        now_ms: u64,
    ) -> Result<(WebSession, UploadWebDeviceCertificateRequest), ClientError> {
        let device_id = DeviceId::generate(rng);
        let device_keys = DeviceKeys::generate(rng);
        let expires = now_ms
            .checked_add(WEB_CERT_MAX_LIFETIME_MS)
            .ok_or(ClientError::InvalidInput)?;
        let own = certify(
            &self.account,
            device_id,
            &device_keys,
            DeviceKind::WebEphemeral,
            now_ms,
            expires,
        )?;
        let request = UploadWebDeviceCertificateRequest {
            device_certificate: bytes(own.wire.clone())?,
        };
        let mut account = self.account;
        account.certificates.push(own.clone());
        Ok((
            WebSession {
                unlocked: UnlockedDevice {
                    account_id: account.account_id,
                    device_id,
                    account_key: self.account_key,
                    device_keys,
                    local_unlock_key: None,
                },
                account,
                session_token: self.session_token,
                own_certificate: own,
            },
            request,
        ))
    }
}

/// A certificate for `device_keys`, signed with the verified account's identity key.
fn certify(
    account: &VerifiedAccount,
    device_id: DeviceId,
    device_keys: &DeviceKeys,
    device_kind: DeviceKind,
    created_at_ms: u64,
    expires_at_ms: u64,
) -> Result<CertifiedDevice, ClientError> {
    let certificate = DeviceCertificate {
        account_id: account.account_id,
        device_id,
        identity_epoch: account.identity.epoch(),
        device_ed25519: *device_keys.signing_key().verifying_key(),
        device_x25519: device_keys.public_keys().x25519,
        device_kind,
        created_at_ms,
        expires_at_ms,
    };
    let wire = certificate
        .sign(account.identity.signing_key())
        .map_err(internal)?;
    let certificate = DeviceCertificate::verify(
        &wire,
        account.identity.signing_key().verifying_key(),
        account.identity.epoch(),
    )
    .map_err(internal)?;
    Ok(CertifiedDevice { certificate, wire })
}

/// An enrolment waiting for the server's compare-and-swap.
pub struct PendingEnrolment {
    /// The new device state (pending until finalised).
    device: DeviceState,
    /// The new device's keys.
    unlocked: UnlockedDevice,
    /// The account, with the new state and certificate.
    account: VerifiedAccount,
    /// The OPAQUE session.
    session_token: SessionToken,
    /// This device's certificate.
    own: CertifiedDevice,
}

impl fmt::Debug for PendingEnrolment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingEnrolment")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl PendingEnrolment {
    /// The pending device state, to persist before the upload (§11 "Secrets before commit",
    /// by analogy: `E_local` is written before the certificate is published).
    #[must_use]
    pub const fn pending_device(&self) -> &DeviceState {
        &self.device
    }

    /// After the server applied the new state: the enrolled device.
    #[must_use]
    pub fn finalize(self) -> Enrolled {
        Enrolled {
            device: self.device,
            unlocked: self.unlocked,
            account: self.account,
            session_token: self.session_token,
            own_certificate: self.own,
        }
    }
}

/// A device enrolled by login.
pub struct Enrolled {
    /// The device state.
    pub device: DeviceState,
    /// Its unlocked keys.
    pub unlocked: UnlockedDevice,
    /// The verified account, with this device's certificate and state.
    pub account: VerifiedAccount,
    /// The OPAQUE session's bearer token.
    pub session_token: SessionToken,
    /// This device's certificate.
    pub own_certificate: CertifiedDevice,
}

impl fmt::Debug for Enrolled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enrolled")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

/// The web vault's session: an ephemeral kind-4 device, in memory only (§11.4).
pub struct WebSession {
    /// The ephemeral device's keys.
    pub unlocked: UnlockedDevice,
    /// The verified account, with the ephemeral certificate.
    pub account: VerifiedAccount,
    /// The OPAQUE session's bearer token.
    pub session_token: SessionToken,
    /// The ephemeral certificate.
    pub own_certificate: CertifiedDevice,
}

impl fmt::Debug for WebSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSession")
            .field("unlocked", &self.unlocked)
            .finish_non_exhaustive()
    }
}

/// The account-state query of a web session's refresh: bundles above the pinned one, and the
/// settings unless the session holds those of the pinned state (the query
/// [`crate::unlock::account_state_query`] builds for an enrolled device, on the session's pin).
#[must_use]
pub fn web_account_query(account: &VerifiedAccount) -> AccountStateQuery {
    let pin = &account.pin;
    let held = pin
        .settings
        .as_ref()
        .filter(|s| s.settings_seq == pin.state.settings_seq);
    AccountStateQuery {
        known_bundle_seq: pin.bundle.bundle_seq,
        known_settings_seq: held.map_or(0, |s| s.settings_seq),
    }
}

/// Verifies the account answer a web session reads during its life (CRYPTO.md §11.4), against
/// the pin of its login, with the checks an enrolled device's unlock makes (§11.3 steps 2–3):
/// a lower or forked `account-state` is [`ClientError::Rollback`] or [`ClientError::Fork`], a
/// changed identity key is [`ClientError::IdentityChangeUnconfirmed`] (a web session has no
/// stored pin to confirm a change against: the host logs in again, which anchors the new keys
/// through `E_id`), and a rotated account key is [`ClientError::AccountKeyRotated`] (a web
/// session receives no device grant: the host logs in again). Nothing is adopted on an error.
///
/// The session's own ephemeral certificate must still be served, under its own keys, and the
/// device not revoked: an answer that leaves it out describes another account state than the
/// one the session's ops are verified under.
///
/// # Errors
/// As above; [`ClientError::InvalidServerResponse`] for any other failed check;
/// [`ClientError::InvalidInput`] if `unlocked` is another account's.
pub fn verify_web_refresh(
    account: &VerifiedAccount,
    unlocked: &UnlockedDevice,
    view: &AccountView,
) -> Result<VerifiedAccount, ClientError> {
    if unlocked.account_id != account.account_id {
        return Err(ClientError::InvalidInput);
    }
    let fresh = verify_account_view(
        view,
        account.account_id,
        &unlocked.account_key,
        &Anchor::Enrolled {
            pin: &account.pin,
            confirmed: None,
        },
    )?;
    let own_keys = unlocked.device_keys.public_keys();
    let revoked = fresh
        .revocations
        .iter()
        .any(|r| r.revocation.device_id == unlocked.device_id);
    let certified = fresh.certificates.iter().any(|c| {
        c.certificate.device_id == unlocked.device_id
            && c.certificate.device_ed25519 == own_keys.ed25519
            && c.certificate.device_x25519 == own_keys.x25519
    });
    if revoked || !certified {
        return Err(ClientError::InvalidServerResponse);
    }
    Ok(fresh)
}
