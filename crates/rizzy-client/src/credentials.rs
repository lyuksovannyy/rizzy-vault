//! Master password and Secret Key change on an enrolled device (CRYPTO.md §11.5), and
//! following such a change made on another device (§11.3 step 5), as a sans-I/O state machine.
//!
//! ```text
//! (re-authenticate with the current password: start_login … complete, over this device's
//!  session; a rotating change also uploads queued ops and runs a complete Fetch first)
//! start_credential_change ──ReregisterStartRequest──► host (account/reregister/start)
//!   ──ReregisterStartResponse──► CredentialChangeStarted::finish ──► PendingCredentialChange:
//!   show the new Emergency Kit if there is one, confirm_kit ──► pending_record (persisted with
//!   the commit's exact JSON) ──► commit_request ──CommitChangeRequest──► host (account/commit)
//!   ├─ 204 ─────────────► PendingCredentialChange::finalize
//!   └─ state_conflict ──► host re-fetches account-state (and every vault, complete Fetch)
//!                         ──► PendingCredentialChange::on_state_conflict ──► resend, or finalize
//! ```
//!
//! # What is built (§11.5 steps 2–4)
//!
//! - **New inputs.** The new master password, and optionally a new Secret Key generated from
//!   the injected CSPRNG; `pw_in'` from both. A change that changes neither is refused: the
//!   new `pw_in'` is compared with the re-authentication's in constant time.
//! - **OPAQUE registration** under the same `credential_identifier = account_id`, at the
//!   client's preferred `kdf_id` ([`KdfId::DEFAULT`]): `(upload', export_key')`.
//! - **`E_srv'`** under the new `server_unlock_key`, at `password_epoch + 1` and that
//!   `kdf_id`; **`account-state'`** with `state_seq + 1`, `password_epoch + 1` and the `kdf_id`,
//!   signed by the identity key; locally a new `device_salt` and `E_local'` under the new
//!   password (one Argon2id run), in the pending record.
//! - **Rotation** (§11.5 "Rotation"). A Secret Key change runs a standard rotation by default
//!   (`rotate = false` is the explicit opt-out); a password change does not, unless the user
//!   asks ("also rotate keys"). The rotation is [`crate::rotation`]'s, committed in the same
//!   request (`rotation::start_rotation_with`). Its recovery step (§11.6 step 5):
//!   after a Secret Key change a **new recovery code** is issued when recovery is on, because
//!   "the user MAY instead type the current recovery code" does not apply to a rotation
//!   triggered by an SK change; after a password change the current code is typed and kept.
//! - **Full rotation** ([`CredentialChangeInput::full_rotation`]; §11.6 "Full", the "kit was
//!   stolen" choice of §11.9). The rotation that rides with the change also replaces the
//!   identity keys (`identity_epoch + 1`, a new bundle signed by the new and the old identity
//!   key, every certificate and revocation re-issued, §11.6 step 7), exactly as
//!   [`crate::rotation`] builds a full rotation; the new state is signed by the new identity
//!   key. It needs a rotation: a full rotation without `rotate` is refused. The recovery rule
//!   is the one above, unchanged by the level: an SK change issues a new code, a password
//!   change keeps the typed one. Reading (reported): §11.6 step 5 names "kit exposed" among
//!   the triggers that issue a new code; a password change with a full rotation is not one
//!   of them (the kit holds no password), so it keeps the typed code like a standard one.
//!
//! # Secrets before commit (§11)
//!
//! When the change creates a new Secret Key (and with it, perhaps, a new recovery code), the
//! new Emergency Kit ([`PendingCredentialChange::emergency_kit`]) must be confirmed
//! ([`PendingCredentialChange::confirm_kit`]) before the pending record or the commit is
//! released. The pending record (ADR 0026 §2) holds the new Secret Key, the new salt and
//! `kdf_id`, and `E_local'` under the new password; the host persists it with the commit's
//! exact JSON before sending, and adopts it only after the server acknowledged. The recovery
//! code is never persisted.
//!
//! # Following a change made elsewhere (§11.3 step 5; [`follow_credential_change`])
//!
//! After [`crate::unlock::verify_unlock`] answers [`ClientError::PasswordChangedElsewhere`],
//! the host asks for the new password (and the new Secret Key if it changed), runs an OPAQUE
//! login over this device's session, and passes it here: the login must be this device's
//! account, at this device's pin or later, with the account key this device holds (a
//! rotation elsewhere is processed first, §11.3 step 4), and this device must still be a
//! member. `E_local` is then re-created under the new password with a **new `device_salt`**
//! (§11.3 step 5.3), and the device's Secret Key replaced if it changed. `E_dev` is unchanged.
//!
//! # Not in this build (reported)
//!
//! - The "only the new password known" path of §11.3 step 5 (a device whose offline unlock
//!   fails because its `E_local` is still under the old password): the host must unlock with
//!   the old password first.

use core::fmt;

use rizzy_core::envelope::purpose::AccountKeyServerWrapCtx;
use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{AccountKey, DEVICE_SALT_LEN, IdentityKeys, LocalUnlockKey};
use rizzy_core::normalize::LoginName;
use rizzy_core::opaque::{
    ClientRegistrationState, ExportKey, PasswordInput, client_registration_finish,
    client_registration_start,
};
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::{RecoveryCode, SecretKey};
use rizzy_core::sign::{AccountState, CasRetry};
use rizzy_proto::account::{AccountStateQuery, AccountView};
use rizzy_proto::change::{CommitChangeRequest, ReregisterStartRequest, ReregisterStartResponse};
use rizzy_proto::objects::{AccountKeyServerWrap, OpaqueMessage};
use rizzy_proto::wire::{List, SessionToken};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::account::{
    AccountPin, Anchor, CertifiedDevice, RevokedDevice, ServedObjects, verify_public,
};
use crate::device::{DeviceState, LocalWrap, UnlockedDevice, wrap_local};
use crate::error::{ClientError, internal};
use crate::login::LoggedIn;
use crate::rotation::{
    ConflictOutcome, MAX_REBUILDS, PendingRotation, RotationDone, RotationLevel, RotationOptions,
    check_reauth, start_rotation_with,
};
use crate::signup::EmergencyKit;
use crate::store;
use crate::store::record::PendingRecord;
use crate::store::rows::Changeset;
use crate::sync::{Authors, VaultSync};
use crate::wire::bytes;

/// The new credential as the commit and the device state carry it: what a credential change
/// adds to the state it commits, and to the device state once the server acknowledged.
/// Holds secrets; not `Clone`, no `Debug`.
pub(crate) struct CredentialPart {
    /// The Secret Key after the commit (new, or the current one).
    pub(crate) secret_key: SecretKey,
    /// `pw_in'` of the new password and that Secret Key.
    pub(crate) pw_in: PasswordInput,
    /// OPAQUE `RegistrationUpload` of the new record.
    pub(crate) registration_upload: OpaqueMessage,
    /// The new record's `kdf_id`, which the new state names and the device state keeps.
    pub(crate) kdf_id: KdfId,
    /// `password_epoch + 1`.
    pub(crate) password_epoch: u32,
    /// The new `device_salt` (§11.5 step 4).
    pub(crate) device_salt: [u8; DEVICE_SALT_LEN],
    /// The new password's local unlock key, derived once (one Argon2id run).
    pub(crate) local: Option<LocalUnlockKey>,
}

impl CredentialPart {
    /// `E_local'` of `account_key` under the new password's local unlock key, at the new
    /// `password_epoch` and `kdf_id`. The key is derived on the first call and kept.
    pub(crate) fn local_wrap<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        account_id: AccountId,
        device_id: DeviceId,
        account_key: &AccountKey,
    ) -> Result<LocalWrap, ClientError> {
        if self.local.is_none() {
            self.local = Some(
                self.pw_in
                    .local_unlock_key(&self.device_salt, self.kdf_id, account_id, device_id)
                    .map_err(internal)?,
            );
        }
        let local = self.local.as_ref().ok_or(ClientError::Internal)?;
        wrap_local(
            rng,
            local,
            account_id,
            device_id,
            self.kdf_id,
            account_key,
            self.password_epoch,
        )
    }

    /// The device state after the commit: the Secret Key, salt and `kdf_id` replaced (the
    /// caller has already set `E_local'` and `E_dev'`), and the new local unlock key kept for
    /// the rest of the online part (§11.3 step 4.3 needs it if a rotation follows).
    pub(crate) fn apply(self, device: &mut DeviceState, unlocked: &mut UnlockedDevice) {
        device.secret_key = self.secret_key;
        device.device_salt = self.device_salt;
        device.kdf_id = self.kdf_id;
        if self.local.is_some() {
            unlocked.local_unlock_key = self.local;
        }
    }
}

/// A credential for a rotation to commit (`rotation::start_rotation_with`).
pub(crate) struct NewCredential {
    /// What the state and the device state carry.
    pub(crate) part: CredentialPart,
    /// The new registration's `export_key`, for `E_srv'`.
    pub(crate) export_key: ExportKey,
    /// The new recovery code to issue with the rotation, if any.
    pub(crate) recovery_code: Option<RecoveryCode>,
}

/// What the user chose for a credential change (§11.5 steps 2 and "Rotation").
#[derive(Clone, Copy)]
pub struct CredentialChangeInput<'a> {
    /// The login name, for the Emergency Kit.
    pub login_name: &'a str,
    /// The new master password (the current one again for a Secret Key change alone).
    pub new_password: &'a str,
    /// Whether to generate a new Secret Key.
    pub new_secret_key: bool,
    /// Whether to run a standard rotation in the same commit: the default for a Secret Key
    /// change, opt-in ("also rotate keys") for a password change.
    pub rotate: bool,
    /// Whether that rotation is **full**: also new identity keys (CRYPTO.md §11.6 "Full"; the
    /// "kit was stolen" choice). Requires `rotate`.
    pub full_rotation: bool,
    /// The current recovery code, to keep it through the rotation of a **password** change
    /// while recovery is on (§11.6 step 5). `None` otherwise: a Secret Key change with a
    /// rotation issues a new code, and a change without a rotation leaves `E_rec` as it is.
    pub recovery_code: Option<&'a str>,
    /// The host's wall clock, milliseconds since the Unix epoch.
    pub now_ms: u64,
}

impl fmt::Debug for CredentialChangeInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialChangeInput")
            .field("new_secret_key", &self.new_secret_key)
            .field("rotate", &self.rotate)
            .field("full_rotation", &self.full_rotation)
            .field("keeps_recovery_code", &self.recovery_code.is_some())
            .finish_non_exhaustive()
    }
}

/// A credential change between the re-registration request and the server's answer. Holds
/// secrets; `Debug` redacted.
pub struct CredentialChangeStarted {
    /// The re-authentication with the current password (fresh OPAQUE session).
    reauth: LoggedIn,
    /// The normalised login name, for the kit.
    login_name: LoginName,
    /// The Secret Key after the change.
    secret_key: SecretKey,
    /// Whether it is new.
    new_secret_key: bool,
    /// `pw_in'`.
    pw_in: PasswordInput,
    /// The OPAQUE client state.
    registration: ClientRegistrationState,
    /// The rotation to run with the change, if any.
    rotation: Option<RotationLevel>,
    /// The current recovery code to keep, as typed.
    recovery_code: Option<Zeroizing<String>>,
    /// The host clock at the start.
    now_ms: u64,
}

impl fmt::Debug for CredentialChangeStarted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialChangeStarted([REDACTED])")
    }
}

/// Starts a credential change (module docs): checks the re-authentication `reauth` (a fresh
/// OPAQUE login with the current password and Secret Key over this device's session) against
/// this device, derives `pw_in'` and starts the OPAQUE registration. The request goes to
/// `account/reregister/start` over `reauth`'s session.
///
/// # Errors
/// [`ClientError::InvalidInput`] for a login name that does not normalise, a new password
/// the new-password rules refuse, a change that changes neither the password nor the Secret
/// Key, a full rotation asked for without a rotation, or a recovery code given where none is
/// kept (see [`CredentialChangeInput::recovery_code`]); the errors of the re-authentication check
/// ([`ClientError::Rollback`], [`ClientError::Fork`], [`ClientError::IdentityChangeUnconfirmed`],
/// [`ClientError::AccountKeyRotated`], [`ClientError::InvalidServerResponse`]);
/// [`ClientError::Internal`].
pub fn start_credential_change<R: CryptoRng + ?Sized>(
    rng: &mut R,
    reauth: LoggedIn,
    device: &DeviceState,
    unlocked: &UnlockedDevice,
    input: &CredentialChangeInput<'_>,
) -> Result<(CredentialChangeStarted, ReregisterStartRequest), ClientError> {
    check_reauth(&reauth, device, unlocked)?;
    let rotation = match (input.rotate, input.full_rotation) {
        (false, false) => None,
        (true, false) => Some(RotationLevel::Standard),
        (true, true) => Some(RotationLevel::Full),
        // A full rotation is a level of a rotation, not something without one.
        (false, true) => return Err(ClientError::InvalidInput),
    };
    let login_name = LoginName::parse(input.login_name).map_err(|_| ClientError::InvalidInput)?;
    let recovery_on = reauth.account.pin.state.recovery_enabled;
    // A kept code only rides with the rotation of a password change while recovery is on.
    let keeps_code = input.rotate && !input.new_secret_key && recovery_on;
    if keeps_code != input.recovery_code.is_some() {
        return Err(ClientError::InvalidInput);
    }
    let secret_key = if input.new_secret_key {
        SecretKey::generate(rng)
    } else {
        SecretKey::from_slice(reauth.secret_key.expose_secret()).map_err(internal)?
    };
    let pw_in = PasswordInput::derive_for_new_password(input.new_password, &secret_key)
        .map_err(|_| ClientError::InvalidInput)?;
    // Same password and same Secret Key: nothing would change but the epoch.
    if bool::from(pw_in.expose_secret().ct_eq(reauth.pw_in.expose_secret())) {
        return Err(ClientError::InvalidInput);
    }
    let (registration, message) = client_registration_start(rng, &pw_in).map_err(internal)?;
    Ok((
        CredentialChangeStarted {
            reauth,
            login_name,
            secret_key,
            new_secret_key: input.new_secret_key,
            pw_in,
            registration,
            rotation,
            recovery_code: input.recovery_code.map(|c| Zeroizing::new(c.to_owned())),
            now_ms: input.now_ms,
        },
        ReregisterStartRequest {
            registration_request: bytes(message)?,
        },
    ))
}

impl CredentialChangeStarted {
    /// The re-authentication's bearer token, for `account/reregister/start`. Never log it.
    #[must_use]
    pub const fn bearer_token(&self) -> &SessionToken {
        &self.reauth.session_token
    }

    /// The account state the change is built on (from the re-authentication).
    #[must_use]
    pub const fn base_state(&self) -> &AccountState {
        &self.reauth.account.pin.state
    }

    /// Steps 3–4: finishes the registration and builds every object of the commit. `vaults`
    /// holds one [`VaultSync`] per vault of the account, each after the device uploaded its
    /// queued records and ran a complete Fetch; it is read only when the change rotates.
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] for a malformed registration response; the errors
    /// of [`crate::rotation::start_rotation`] when the change rotates;
    /// [`ClientError::Internal`].
    pub fn finish<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &ReregisterStartResponse,
        device: &DeviceState,
        unlocked: &UnlockedDevice,
        vaults: &[&VaultSync],
    ) -> Result<PendingCredentialChange, ClientError> {
        let kdf_id = KdfId::DEFAULT;
        let registration = client_registration_finish(
            rng,
            self.registration,
            &self.pw_in,
            response.registration_response.as_slice(),
            kdf_id,
        )
        .map_err(|_| ClientError::InvalidServerResponse)?;
        let base = &self.reauth.account.pin.state;
        let password_epoch = base
            .password_epoch
            .checked_add(1)
            .ok_or(ClientError::Internal)?;
        let mut device_salt = [0u8; DEVICE_SALT_LEN];
        rng.fill_bytes(&mut device_salt);
        // §11.6 step 5: a rotation triggered by an SK change issues a new code.
        let recovery_code =
            (self.rotation.is_some() && self.new_secret_key && base.recovery_enabled)
                .then(|| RecoveryCode::generate(rng));
        let kit = self.new_secret_key.then(|| {
            EmergencyKit::for_change(
                &self.reauth.origin,
                &self.login_name,
                &self.secret_key,
                recovery_code.as_ref(),
            )
        });
        let confirm_key = if self.new_secret_key {
            Some(SecretKey::from_slice(self.secret_key.expose_secret()).map_err(internal)?)
        } else {
            None
        };
        let part = CredentialPart {
            secret_key: self.secret_key,
            pw_in: self.pw_in,
            registration_upload: bytes(registration.upload)?,
            kdf_id,
            password_epoch,
            device_salt,
            local: None,
        };
        let change = if let Some(level) = self.rotation {
            let options = RotationOptions {
                level,
                revoke: None,
                recovery_code: self.recovery_code.as_deref().map(String::as_str),
                now_ms: self.now_ms,
            };
            Change::Rotation(Box::new(start_rotation_with(
                rng,
                self.reauth,
                device,
                unlocked,
                vaults,
                &options,
                Some(NewCredential {
                    part,
                    export_key: registration.export_key,
                    recovery_code,
                }),
            )?))
        } else {
            Change::Plain(Box::new(PlainChange::build(
                rng,
                self.reauth,
                device,
                part,
                &registration.export_key,
            )?))
        };
        Ok(PendingCredentialChange {
            kit,
            confirm_key,
            confirmed: false,
            change,
        })
    }
}

/// A credential change without a rotation: the new record, `E_srv'` and the new state.
struct PlainChange {
    /// The account.
    account_id: AccountId,
    /// The changing device.
    device_id: DeviceId,
    /// The verified state this attempt is built on.
    base: AccountPin,
    /// The certificates of `base`.
    certificates: Vec<CertifiedDevice>,
    /// The revocations of `base`.
    revocations: Vec<RevokedDevice>,
    /// The identity keys that sign the new state.
    identity: IdentityKeys,
    /// The account key (unchanged).
    account_key: AccountKey,
    /// The new credential.
    credential: CredentialPart,
    /// `E_srv'`.
    e_srv: AccountKeyServerWrap,
    /// The new state and its signed wire form.
    state: (AccountState, Vec<u8>),
    /// The current request.
    request: CommitChangeRequest,
    /// The fresh OPAQUE session's bearer token.
    session_token: SessionToken,
    /// Rebuilds so far.
    rebuilds: u32,
    /// `E_local'` as the pending record holds it.
    prepared: Option<LocalWrap>,
}

impl PlainChange {
    /// Builds the change on the re-authentication's verified state.
    fn build<R: CryptoRng + ?Sized>(
        rng: &mut R,
        reauth: LoggedIn,
        device: &DeviceState,
        credential: CredentialPart,
        export_key: &ExportKey,
    ) -> Result<Self, ClientError> {
        let LoggedIn {
            account,
            account_key,
            session_token,
            ..
        } = reauth;
        let account_id = account.account_id;
        let e_srv = export_key
            .server_unlock_key(account_id)
            .map_err(internal)?
            .wrap_account_key(
                rng,
                &AccountKeyServerWrapCtx {
                    account_id,
                    account_key_epoch: account_key.epoch(),
                    password_epoch: credential.password_epoch,
                    kdf_id: credential.kdf_id,
                },
                &account_key,
            )
            .map_err(internal)?;
        let e_srv = AccountKeyServerWrap {
            account_key_epoch: account_key.epoch(),
            password_epoch: credential.password_epoch,
            kdf_id: credential.kdf_id.get(),
            envelope: bytes(e_srv)?,
        };
        let base = account.pin.clone();
        let mut change = Self {
            account_id,
            device_id: device.device_id,
            state: (base.state.clone(), Vec::new()),
            base,
            certificates: account.certificates,
            revocations: account.revocations,
            identity: account.identity,
            account_key,
            credential,
            request: CommitChangeRequest {
                account_state: bytes(account.pin.state_wire.clone())?,
                registration_upload: None,
                account_key_server_wrap: None,
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
            },
            e_srv,
            session_token,
            rebuilds: 0,
            prepared: None,
        };
        change.assemble()?;
        Ok(change)
    }

    /// The new state on `self.base` and the request carrying it.
    fn assemble(&mut self) -> Result<(), ClientError> {
        let base = &self.base.state;
        let mut state = base.clone();
        state.state_seq = base.state_seq.checked_add(1).ok_or(ClientError::Internal)?;
        state.password_epoch = self.credential.password_epoch;
        state.kdf_id = self.credential.kdf_id;
        let wire = state.sign(self.identity.signing_key()).map_err(internal)?;
        self.request.account_state = bytes(wire.clone())?;
        self.request.registration_upload = Some(self.credential.registration_upload.clone());
        self.request.account_key_server_wrap = Some(self.e_srv.clone());
        self.state = (state, wire);
        Ok(())
    }

    /// As [`PendingRotation::on_state_conflict`], for a change that rotates nothing: the
    /// served state is this change's (committed), or a later position where only `state_seq`
    /// and `device_set_hash` moved (rebuilt on it), or anything else (restart).
    fn on_state_conflict(&mut self, view: &AccountView) -> Result<ConflictOutcome, ClientError> {
        if view.account_state.as_slice() == self.state.1.as_slice() {
            return Ok(ConflictOutcome::Committed);
        }
        let public = match verify_public(
            view,
            self.account_id,
            &Anchor::Enrolled {
                pin: &self.base,
                confirmed: None,
            },
            None,
        ) {
            Ok(public) => public,
            Err(ClientError::IdentityChangeUnconfirmed) => {
                return Err(ClientError::RotationRestart);
            }
            Err(e) => return Err(e),
        };
        match self.base.state.cas_retry(&public.state) {
            CasRetry::Rollback => return Err(ClientError::Rollback),
            CasRetry::Fork => return Err(ClientError::Fork),
            CasRetry::Restart => return Err(ClientError::RotationRestart),
            CasRetry::Reapply => {}
        }
        if self.rebuilds >= MAX_REBUILDS {
            return Err(ClientError::VaultKeepsChanging);
        }
        if public.state.state_seq != self.base.state.state_seq {
            self.base = AccountPin {
                bundle: public.bundle,
                state: public.state,
                state_wire: public.state_wire,
                settings: public.settings,
            };
            self.certificates = public.certificates;
            self.revocations = public.revocations;
        }
        self.assemble()?;
        self.rebuilds += 1;
        Ok(ConflictOutcome::Resend)
    }

    /// `E_local'` once.
    fn prepare<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        device: &DeviceState,
    ) -> Result<LocalWrap, ClientError> {
        if let Some(prepared) = &self.prepared {
            return Ok(prepared.clone());
        }
        let wrap = self.credential.local_wrap(
            rng,
            device.account_id,
            device.device_id,
            &self.account_key,
        )?;
        self.prepared = Some(wrap.clone());
        Ok(wrap)
    }

    /// The pin after the commit.
    fn new_pin(&self) -> AccountPin {
        AccountPin {
            bundle: self.base.bundle.clone(),
            state: self.state.0.clone(),
            state_wire: self.state.1.clone(),
            settings: self.base.settings.clone(),
        }
    }
}

/// The two shapes of a credential change.
enum Change {
    /// With a standard rotation.
    Rotation(Box<PendingRotation>),
    /// Without one.
    Plain(Box<PlainChange>),
}

/// A credential change with every object built, waiting for the kit confirmation (when it
/// creates a new Secret Key) and the commit. Holds secrets; `Debug` shows the shape only.
pub struct PendingCredentialChange {
    /// The new kit, when a new Secret Key was generated.
    kit: Option<EmergencyKit>,
    /// The new Secret Key, for the kit confirmation.
    confirm_key: Option<SecretKey>,
    /// Whether the kit was confirmed.
    confirmed: bool,
    /// The change.
    change: Change,
}

impl fmt::Debug for PendingCredentialChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingCredentialChange")
            .field("new_secret_key", &self.kit.is_some())
            .field("rotates", &self.rotates())
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

impl PendingCredentialChange {
    /// The new Emergency Kit to render, when the change created a new Secret Key: the new
    /// Secret Key, and the new recovery code if the rotation issued one (§11.5 step 4).
    #[must_use]
    pub const fn emergency_kit(&self) -> Option<&EmergencyKit> {
        self.kit.as_ref()
    }

    /// Whether the change rotates the account key and the vault keys.
    #[must_use]
    pub const fn rotates(&self) -> bool {
        matches!(self.change, Change::Rotation(_))
    }

    /// The level of the rotation the change runs, if it rotates.
    #[must_use]
    pub const fn rotation_level(&self) -> Option<RotationLevel> {
        match &self.change {
            Change::Rotation(r) => Some(r.level()),
            Change::Plain(_) => None,
        }
    }

    /// Confirms the kit: `typed` must be the last group of four characters of the new Secret
    /// Key, compared in constant time (§7). A change without a kit needs no confirmation.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] if it does not match.
    pub fn confirm_kit(&mut self, typed: &str) -> Result<(), ClientError> {
        match &self.confirm_key {
            Some(key) if key.matches_last_group(typed) => {
                self.confirmed = true;
                Ok(())
            }
            Some(_) => Err(ClientError::EmergencyKitNotConfirmed),
            None => Ok(()),
        }
    }

    /// Fails until a kit that must be confirmed was.
    fn released(&self) -> Result<(), ClientError> {
        if self.kit.is_some() && !self.confirmed {
            Err(ClientError::EmergencyKitNotConfirmed)
        } else {
            Ok(())
        }
    }

    /// The fresh OPAQUE session's bearer token, for the commit. Never log it.
    #[must_use]
    pub fn bearer_token(&self) -> &SessionToken {
        match &self.change {
            Change::Rotation(r) => r.bearer_token(),
            Change::Plain(p) => &p.session_token,
        }
    }

    /// The commit (§11.5 step 5), after the kit was confirmed when there is one. The same bytes
    /// on every call until a conflict rebuilds it.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`].
    pub fn commit_request(&self) -> Result<&CommitChangeRequest, ClientError> {
        self.released()?;
        Ok(match &self.change {
            Change::Rotation(r) => r.commit_request(),
            Change::Plain(p) => &p.request,
        })
    }

    /// The `account-state` this change commits.
    #[must_use]
    pub fn new_state(&self) -> &AccountState {
        match &self.change {
            Change::Rotation(r) => r.new_state(),
            Change::Plain(p) => &p.state.0,
        }
    }

    /// What to fetch after a `state_conflict` (as [`PendingRotation::state_query`]).
    #[must_use]
    pub fn state_query(&self) -> AccountStateQuery {
        match &self.change {
            Change::Rotation(r) => r.state_query(),
            Change::Plain(p) => {
                let held = p
                    .base
                    .settings
                    .as_ref()
                    .filter(|s| s.settings_seq == p.base.state.settings_seq);
                AccountStateQuery {
                    known_bundle_seq: p.base.bundle.bundle_seq,
                    known_settings_seq: held.map_or(0, |s| s.settings_seq),
                }
            }
        }
    }

    /// The pending record (§11 step 3; ADR 0026 §2): the new Secret Key, salt and `kdf_id`, and
    /// `E_local'` under the new password (one Argon2id run, built once); with a rotation also
    /// `E_dev'` under the new account key. Released only after the kit was confirmed.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`]; [`ClientError::InvalidInput`] for another
    /// device's state; [`ClientError::Internal`].
    pub fn pending_record<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        device: &DeviceState,
        unlocked: &UnlockedDevice,
    ) -> Result<PendingRecord, ClientError> {
        self.released()?;
        match &mut self.change {
            Change::Rotation(r) => r.pending_record(rng, device, unlocked),
            Change::Plain(p) => {
                if device.device_id != p.device_id || unlocked.device_id != p.device_id {
                    return Err(ClientError::InvalidInput);
                }
                let local_wrap = p.prepare(rng, device)?;
                Ok(PendingRecord {
                    secret_key: SecretKey::from_slice(p.credential.secret_key.expose_secret())
                        .map_err(internal)?,
                    device_salt: p.credential.device_salt,
                    kdf_id: p.credential.kdf_id,
                    local_wrap,
                    device_keys_wrap: None,
                })
            }
        }
    }

    /// Handles a `state_conflict` answer (as [`PendingRotation::on_state_conflict`]).
    ///
    /// # Errors
    /// [`ClientError::Rollback`], [`ClientError::Fork`]: go read-only;
    /// [`ClientError::RotationRestart`]: the account changed in a way this change cannot be
    /// rebuilt on; start again; [`ClientError::VaultKeepsChanging`]; the errors of the
    /// verification.
    pub fn on_state_conflict<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        view: &AccountView,
        unlocked: &UnlockedDevice,
        vaults: &[&VaultSync],
    ) -> Result<ConflictOutcome, ClientError> {
        match &mut self.change {
            Change::Rotation(r) => r.on_state_conflict(rng, view, unlocked, vaults),
            Change::Plain(p) => {
                if unlocked.device_id != p.device_id || unlocked.account_id != p.account_id {
                    return Err(ClientError::InvalidInput);
                }
                p.on_state_conflict(view)
            }
        }
    }

    /// The cache writes of the state this change commits (as
    /// [`PendingRotation::store_writes`]); call it before [`PendingCredentialChange::finalize`].
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub fn store_writes(&self) -> Result<Changeset, ClientError> {
        match &self.change {
            Change::Rotation(r) => r.store_writes(),
            Change::Plain(p) => Ok(store::object_writes(
                &p.new_pin(),
                &p.certificates,
                &p.revocations,
                &ServedObjects::default(),
            )),
        }
    }

    /// After the server acknowledged the commit (or [`ConflictOutcome::Committed`]): the device
    /// state takes the new Secret Key, salt, `kdf_id`, `E_local'` (and with a rotation `E_dev'`,
    /// the new account key and vault keys), and pins the new state (§11.5 step 6).
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] if the commit was never released;
    /// [`ClientError::InvalidInput`] for another device's state; as
    /// [`PendingRotation::finalize`]; [`ClientError::Internal`].
    pub fn finalize<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        device: &mut DeviceState,
        unlocked: &mut UnlockedDevice,
        vaults: &mut [&mut VaultSync],
    ) -> Result<RotationDone, ClientError> {
        self.released()?;
        match self.change {
            Change::Rotation(r) => (*r).finalize(rng, device, unlocked, vaults),
            Change::Plain(mut p) => {
                if device.device_id != p.device_id
                    || unlocked.device_id != p.device_id
                    || device.account_id != p.account_id
                {
                    return Err(ClientError::InvalidInput);
                }
                let local_wrap = p.prepare(rng, device)?;
                let pin = p.new_pin();
                let authors = Authors::from_statements(&p.certificates, &p.revocations)?;
                device.local_wrap = local_wrap;
                p.credential.apply(device, unlocked);
                device.pin = pin;
                Ok(RotationDone {
                    authors,
                    dropped_items: Vec::new(),
                })
            }
        }
    }
}

/// Follows a password or Secret Key change made on another device (§11.3 step 5; module docs):
/// `login` is an OPAQUE login with the new password (and the new Secret Key, if it changed) over
/// this device's session. Re-creates `E_local` under the new password with a new
/// `device_salt` (one Argon2id run) and replaces the stored Secret Key; adopts the login's
/// verified state as the pin. The host then persists [`DeviceState::record`] and runs the
/// online part again.
///
/// # Errors
/// [`ClientError::InvalidInput`] for another device's state; [`ClientError::Rollback`],
/// [`ClientError::Fork`], [`ClientError::IdentityChangeUnconfirmed`],
/// [`ClientError::AccountKeyRotated`] (process the rotation first, §11.3 step 4) and
/// [`ClientError::InvalidServerResponse`] (this device is no longer a member) from the check of
/// the login; [`ClientError::Internal`].
pub fn follow_credential_change<R: CryptoRng + ?Sized>(
    rng: &mut R,
    login: LoggedIn,
    device: &mut DeviceState,
    unlocked: &mut UnlockedDevice,
) -> Result<(), ClientError> {
    check_reauth(&login, device, unlocked)?;
    let LoggedIn {
        secret_key,
        pw_in,
        account,
        ..
    } = login;
    let password_epoch = account.pin.state.password_epoch;
    if password_epoch < device.local_password_epoch() {
        return Err(ClientError::Rollback);
    }
    let kdf_id = KdfId::DEFAULT;
    let mut device_salt = [0u8; DEVICE_SALT_LEN];
    rng.fill_bytes(&mut device_salt);
    let local = pw_in
        .local_unlock_key(&device_salt, kdf_id, device.account_id, device.device_id)
        .map_err(internal)?;
    let local_wrap = wrap_local(
        rng,
        &local,
        device.account_id,
        device.device_id,
        kdf_id,
        &unlocked.account_key,
        password_epoch,
    )?;
    device.adopt(&account);
    device.local_wrap = local_wrap;
    device.device_salt = device_salt;
    device.kdf_id = kdf_id;
    device.secret_key = secret_key;
    unlocked.local_unlock_key = Some(local);
    Ok(())
}
