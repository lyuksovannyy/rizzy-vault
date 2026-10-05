//! Moving an OPAQUE record to the server's current setup, and restarting a registration whose
//! setup was retired (CRYPTO.md §5.8 "Rotating `server_setup`" steps 3–4; [ADR 0031] points 2,
//! 3 and 8).
//!
//! # The same-password re-registration (point 2)
//!
//! A login ([`crate::login::LoggedIn::reregister`]) or a device authentication
//! ([`crate::session::DeviceSession::reregister`]) answers `reregister = true` when the
//! account's record names a setup other than the current one. A client that holds the typed
//! password in this unlock then re-registers with it, over that session:
//!
//! ```text
//! start_device_reregistration / LoggedIn::start_reregistration
//!   ──ReregisterStartRequest──► host (account/reregister/start, over the session)
//!   ──ReregisterStartResponse──► ReregistrationStarted::finish_device / finish_login
//!   ──► PendingReregistration::commit_request ──CommitChangeRequest──► host (account/commit)
//!   ──ack──► adopt PendingReregistration::new_pin (the host's refresh, or LoggedIn::adopt_reregistration)
//! ```
//!
//! The new record is registered with the same `pw_in`; the new state is the verified current
//! one with `state_seq + 1` and nothing else changed (`password_epoch` and `kdf_id` unchanged,
//! so `E_local` and the device state stay valid and no pending record is needed); `E_srv'` is
//! the account key under the new `export_key`, at the state's epochs and `kdf_id`. The commit
//! echoes the answer's `setup_id`. The flag carries no `kdf_id` and no setup: the `kdf_id` is
//! the verified state's, which this client's allow-list already accepted.
//!
//! **At most once per unlock**, and never the commit's key material from the server: the host
//! runs it at most once per unlock (a server that sets the flag on every login costs one
//! Argon2id and one `state_seq` per unlock and gains nothing, ADR 0031 "Risks"). A failure
//! (a lost compare-and-swap, a network error) only leaves the record where it was; the next
//! unlock tries again. A client without the typed password (a keystore unlock, M3/M7) waits
//! for the next typed unlock.
//!
//! # A pending registration refused with `setup_retired` (point 8)
//!
//! A pending signup or credential change resends its stored request byte for byte, through
//! any rotation. Only when its setup was retired meanwhile, and the commit was not applied,
//! does the server answer `setup_retired`. The client then reruns `register/start` or
//! `account/reregister/start` with the same `pw_in` and rebuilds only the OPAQUE upload, the
//! echoed `setup_id` and `E_srv'` (the new `export_key` gives a new `server_unlock_key`); every
//! other object of the request stays byte for byte, the signed `account-state` included (its
//! layout covers neither the record nor `E_srv`), and so does every secret of the pending
//! record. In memory that is [`crate::signup::PendingSignup::restart_registration`] and
//! [`crate::credentials::PendingCredentialChange::restart_registration`]; for a request
//! stored across a restart, [`RegistrationRestart`]. A restart happens at most once per
//! pending change; a second `setup_retired` fails with [`ClientError::SetupRetired`].
//!
//! [ADR 0031]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0031-retiring-old-opaque-setups.md

use core::fmt;

use rizzy_core::envelope::purpose::AccountKeyServerWrapCtx;
use rizzy_core::ids::AccountId;
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::AccountKey;
use rizzy_core::opaque::{
    ClientRegistrationState, PasswordInput, client_registration_finish, client_registration_start,
};
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::SecretKey;
use rizzy_proto::auth::{RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse};
use rizzy_proto::change::{CommitChangeRequest, ReregisterStartRequest, ReregisterStartResponse};
use rizzy_proto::objects::{AccountKeyServerWrap, OpaqueMessage};
use rizzy_proto::wire::{List, SecretText, Text};

use crate::account::{AccountPin, VerifiedAccount};
use crate::device::{DeviceState, UnlockedDevice};
use crate::error::{ClientError, internal};
use crate::login::LoggedIn;
use crate::wire::{bytes, id};

/// The locator of an `E_srv` (CRYPTO.md §8.4): the epochs and the `kdf_id` its context names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Locator {
    /// `account_key_epoch`.
    pub(crate) account_key_epoch: u32,
    /// `password_epoch`.
    pub(crate) password_epoch: u32,
    /// `kdf_id`, as the wire carries it.
    pub(crate) kdf_id: u16,
}

impl From<&AccountKeyServerWrap> for Locator {
    fn from(wrap: &AccountKeyServerWrap) -> Self {
        Self {
            account_key_epoch: wrap.account_key_epoch,
            password_epoch: wrap.password_epoch,
            kdf_id: wrap.kdf_id,
        }
    }
}

/// Finishes a restarted registration (point 8): the new OPAQUE upload, and `E_srv'` of
/// `account_key` under the new `export_key` at `locator` (the epochs and `kdf_id` the pending
/// state already names). The `kdf_id` must be on this client's allow-list.
///
/// # Errors
/// [`ClientError::InvalidInput`] when `account_key` is not at `wrap`'s epoch;
/// [`ClientError::KdfNotAllowed`]; [`ClientError::InvalidServerResponse`] for a malformed
/// answer; [`ClientError::Internal`].
pub(crate) fn finish_registration<R: CryptoRng + ?Sized>(
    rng: &mut R,
    state: ClientRegistrationState,
    pw_in: &PasswordInput,
    registration_response: &[u8],
    account_id: AccountId,
    account_key: &AccountKey,
    locator: Locator,
) -> Result<(OpaqueMessage, AccountKeyServerWrap), ClientError> {
    if account_key.epoch() != locator.account_key_epoch {
        return Err(ClientError::InvalidInput);
    }
    let kdf_id = KdfId::from_u16(locator.kdf_id).map_err(|_| ClientError::KdfNotAllowed)?;
    let registration = client_registration_finish(rng, state, pw_in, registration_response, kdf_id)
        .map_err(|_| ClientError::InvalidServerResponse)?;
    let envelope = registration
        .export_key
        .server_unlock_key(account_id)
        .map_err(internal)?
        .wrap_account_key(
            rng,
            &AccountKeyServerWrapCtx {
                account_id,
                account_key_epoch: locator.account_key_epoch,
                password_epoch: locator.password_epoch,
                kdf_id,
            },
            account_key,
        )
        .map_err(internal)?;
    Ok((
        bytes(registration.upload)?,
        AccountKeyServerWrap {
            account_key_epoch: locator.account_key_epoch,
            password_epoch: locator.password_epoch,
            kdf_id: locator.kdf_id,
            envelope: bytes(envelope)?,
        },
    ))
}

/// A registration restarted for a request stored across a process restart (point 8; module
/// docs): the stored `account/commit` of a credential change, or the stored `register/finish`
/// of a signup. Holds `pw_in` and the OPAQUE state; `Debug` redacted.
pub struct RegistrationRestart {
    /// `pw_in` of the pending password and Secret Key.
    pw_in: PasswordInput,
    /// The OPAQUE client state.
    state: ClientRegistrationState,
    /// The registration request (M1).
    m1: OpaqueMessage,
}

impl fmt::Debug for RegistrationRestart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrationRestart([REDACTED])")
    }
}

impl RegistrationRestart {
    /// Starts the registration again with `pw_in` of `password` and the pending `secret_key`.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a password `pw_in` cannot be derived from;
    /// [`ClientError::Internal`].
    pub(crate) fn start<R: CryptoRng + ?Sized>(
        rng: &mut R,
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<Self, ClientError> {
        let pw_in =
            PasswordInput::derive(password, secret_key).map_err(|_| ClientError::InvalidInput)?;
        let (state, m1) = client_registration_start(rng, &pw_in).map_err(internal)?;
        Ok(Self {
            pw_in,
            state,
            m1: bytes(m1)?,
        })
    }

    /// The request for `account/reregister/start` (a credential change's commit).
    #[must_use]
    pub fn reregister_request(&self) -> ReregisterStartRequest {
        ReregisterStartRequest {
            registration_request: self.m1.clone(),
        }
    }

    /// The request for `register/start` (a signup's commit): the login name and the invite
    /// as typed again, and the signup's `account_id`.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a login name or invite out of bounds.
    pub fn register_request(
        &self,
        login_name: &str,
        invite: Option<&str>,
        account_id: AccountId,
    ) -> Result<RegisterStartRequest, ClientError> {
        Ok(RegisterStartRequest {
            invite: invite
                .map(SecretText::new)
                .transpose()
                .map_err(|_| ClientError::InvalidInput)?,
            login_name: Text::new(login_name.to_owned()).map_err(|_| ClientError::InvalidInput)?,
            account_id: id(account_id.to_bytes()),
            registration_request: self.m1.clone(),
        })
    }

    /// Rebuilds the stored commit `request` of a credential change on the answer: its OPAQUE
    /// upload, its `setup_id` and `E_srv'` of the account key of `unlocked` (the keys the
    /// commit is under: the pending record's, unlocked with the pending password). Every other
    /// field stays byte for byte.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a request without a registration or an account key at
    /// another epoch; [`ClientError::KdfNotAllowed`]; [`ClientError::InvalidServerResponse`] for
    /// a malformed answer; [`ClientError::Internal`].
    pub fn rebuild_commit<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &ReregisterStartResponse,
        unlocked: &UnlockedDevice,
        request: &mut CommitChangeRequest,
    ) -> Result<(), ClientError> {
        let (Some(_), Some(wrap)) = (
            &request.registration_upload,
            &request.account_key_server_wrap,
        ) else {
            return Err(ClientError::InvalidInput);
        };
        let (upload, wrap) = finish_registration(
            rng,
            self.state,
            &self.pw_in,
            response.registration_response.as_slice(),
            unlocked.account_id,
            &unlocked.account_key,
            Locator::from(wrap),
        )?;
        request.registration_upload = Some(upload);
        request.setup_id = Some(response.setup_id);
        request.account_key_server_wrap = Some(wrap);
        Ok(())
    }

    /// Rebuilds the stored signup commit `request` on the answer, as
    /// [`RegistrationRestart::rebuild_commit`] does; `unlocked` is the signup's device state
    /// unlocked with the signup's password.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for an account key at another epoch;
    /// [`ClientError::KdfNotAllowed`]; [`ClientError::InvalidServerResponse`] for a malformed
    /// answer; [`ClientError::Internal`].
    pub fn rebuild_signup<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &RegisterStartResponse,
        unlocked: &UnlockedDevice,
        request: &mut RegisterFinishRequest,
    ) -> Result<(), ClientError> {
        let (upload, wrap) = finish_registration(
            rng,
            self.state,
            &self.pw_in,
            response.registration_response.as_slice(),
            unlocked.account_id,
            &unlocked.account_key,
            Locator::from(&request.account_key_server_wrap),
        )?;
        request.registration_upload = upload;
        request.setup_id = response.setup_id;
        request.account_key_server_wrap = wrap;
        Ok(())
    }
}

/// A same-password re-registration between its request and the server's answer (module docs).
/// Holds `pw_in` (on a device) and the OPAQUE state; `Debug` redacted.
pub struct ReregistrationStarted {
    /// `pw_in` of the typed password, on a device; a login's own is borrowed at the finish.
    pw_in: Option<PasswordInput>,
    /// The OPAQUE client state.
    state: ClientRegistrationState,
}

impl fmt::Debug for ReregistrationStarted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReregistrationStarted([REDACTED])")
    }
}

/// Starts the same-password re-registration of an enrolled device whose device authentication
/// answered `reregister` (point 2): `pw_in` of `password` (the master password typed for this
/// unlock, already checked by the offline unlock) and the device's Secret Key. Send the request
/// to `account/reregister/start` over the device session.
///
/// # Errors
/// [`ClientError::InvalidInput`]; [`ClientError::Internal`].
pub fn start_device_reregistration<R: CryptoRng + ?Sized>(
    rng: &mut R,
    device: &DeviceState,
    password: &str,
) -> Result<(ReregistrationStarted, ReregisterStartRequest), ClientError> {
    let pw_in = PasswordInput::derive(password, &device.secret_key)
        .map_err(|_| ClientError::InvalidInput)?;
    let (state, m1) = client_registration_start(rng, &pw_in).map_err(internal)?;
    Ok((
        ReregistrationStarted {
            pw_in: Some(pw_in),
            state,
        },
        ReregisterStartRequest {
            registration_request: bytes(m1)?,
        },
    ))
}

impl LoggedIn {
    /// Whether the server asked for a same-password re-registration (point 2). The host runs
    /// [`LoggedIn::start_reregistration`] at most once per unlock when it is set.
    #[must_use]
    pub const fn reregister(&self) -> bool {
        self.reregister
    }

    /// Starts the same-password re-registration over this login's OPAQUE session (point 2),
    /// with this login's `pw_in`. Send the request to `account/reregister/start` with
    /// [`LoggedIn::bearer_token`].
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub fn start_reregistration<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(ReregistrationStarted, ReregisterStartRequest), ClientError> {
        let (state, m1) = client_registration_start(rng, &self.pw_in).map_err(internal)?;
        Ok((
            ReregistrationStarted { pw_in: None, state },
            ReregisterStartRequest {
                registration_request: bytes(m1)?,
            },
        ))
    }

    /// After the server acknowledged the re-registration's commit: the login's verified
    /// account takes the new state as its pin.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for another account's re-registration.
    pub fn adopt_reregistration(
        &mut self,
        pending: PendingReregistration,
    ) -> Result<(), ClientError> {
        if pending.account_id != self.account.account_id {
            return Err(ClientError::InvalidInput);
        }
        self.account.pin = pending.pin;
        Ok(())
    }
}

impl ReregistrationStarted {
    /// The answer, for an enrolled device: `account` is the account answer this run verified
    /// (`crate::unlock::verify_unlock`) at the device's own `password_epoch`, `unlocked` this
    /// device's keys.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a start made from a login; as
    /// [`ReregistrationStarted::finish_login`].
    pub fn finish_device<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &ReregisterStartResponse,
        account: &VerifiedAccount,
        unlocked: &UnlockedDevice,
    ) -> Result<PendingReregistration, ClientError> {
        let Self { pw_in, state } = self;
        let pw_in = pw_in.ok_or(ClientError::InvalidInput)?;
        if unlocked.account_id != account.account_id {
            return Err(ClientError::InvalidInput);
        }
        build(rng, state, &pw_in, response, account, &unlocked.account_key)
    }

    /// The answer, for a login's re-registration.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] when the account key is not at the state's epoch, or for a
    /// start made on a device; [`ClientError::KdfNotAllowed`];
    /// [`ClientError::InvalidServerResponse`] for a malformed answer; [`ClientError::Internal`].
    pub fn finish_login<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &ReregisterStartResponse,
        login: &LoggedIn,
    ) -> Result<PendingReregistration, ClientError> {
        if self.pw_in.is_some() {
            return Err(ClientError::InvalidInput);
        }
        build(
            rng,
            self.state,
            &login.pw_in,
            response,
            &login.account,
            &login.account_key,
        )
    }
}

/// The commit of a same-password re-registration on `account`'s verified state (module docs).
fn build<R: CryptoRng + ?Sized>(
    rng: &mut R,
    state: ClientRegistrationState,
    pw_in: &PasswordInput,
    response: &ReregisterStartResponse,
    account: &VerifiedAccount,
    account_key: &AccountKey,
) -> Result<PendingReregistration, ClientError> {
    let base = &account.pin.state;
    // `E_srv'` at the verified state's locator; the record's `kdf_id` is the state's.
    let locator = Locator {
        account_key_epoch: base.account_key_epoch,
        password_epoch: base.password_epoch,
        kdf_id: base.kdf_id.get(),
    };
    let (upload, wrap) = finish_registration(
        rng,
        state,
        pw_in,
        response.registration_response.as_slice(),
        account.account_id,
        account_key,
        locator,
    )?;
    let mut next = base.clone();
    next.state_seq = base.state_seq.checked_add(1).ok_or(ClientError::Internal)?;
    let state_wire = next
        .sign(account.identity.signing_key())
        .map_err(internal)?;
    let request = CommitChangeRequest {
        account_state: bytes(state_wire.clone())?,
        registration_upload: Some(upload),
        setup_id: Some(response.setup_id),
        account_key_server_wrap: Some(wrap),
        recovery: None,
        account_settings: None,
        device_certificates: List::empty(),
        device_revocations: List::empty(),
        bundle: None,
        identity_secret_keys: None,
        retired_secret_keys: List::empty(),
        device_grants: List::empty(),
        recovery_rewrap: None,
        vault_rotation: None,
    };
    Ok(PendingReregistration {
        account_id: account.account_id,
        pin: AccountPin {
            bundle: account.pin.bundle.clone(),
            state: next,
            state_wire,
            settings: account.pin.settings.clone(),
        },
        request,
    })
}

/// A same-password re-registration with its commit built (module docs). No secret: the commit
/// carries the OPAQUE upload and `E_srv'`, which are uploaded anyway.
#[derive(Debug)]
pub struct PendingReregistration {
    /// The account.
    account_id: AccountId,
    /// The pin after the commit.
    pin: AccountPin,
    /// The commit.
    request: CommitChangeRequest,
}

impl PendingReregistration {
    /// The commit, for `account/commit` over the session the re-registration started on. A
    /// `state_conflict` is not retried: the record stays where it was until the next unlock.
    #[must_use]
    pub const fn commit_request(&self) -> &CommitChangeRequest {
        &self.request
    }

    /// The pin after the commit. A device adopts it through its next account refresh, which
    /// verifies the served state; a login adopts it with [`LoggedIn::adopt_reregistration`].
    #[must_use]
    pub const fn new_pin(&self) -> &AccountPin {
        &self.pin
    }
}

impl crate::store::record::DeviceRecord {
    /// [`RegistrationRestart`] for this record's stored request (point 8), with `password`, the
    /// pending password (a credential change's new one; a signup's), and this record's Secret
    /// Key. Call it on the promoted record of a credential change
    /// ([`crate::store::record::DeviceRecord::promote_pending`]), whose Secret Key is the
    /// pending one.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a password `pw_in` cannot be derived from;
    /// [`ClientError::Internal`].
    pub fn registration_restart<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        password: &str,
    ) -> Result<RegistrationRestart, ClientError> {
        RegistrationRestart::start(rng, password, &self.secret_key)
    }
}
