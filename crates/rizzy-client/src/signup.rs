//! Signup in Server mode (CRYPTO.md §11.1), as a sans-I/O state machine.
//!
//! ```text
//! start_signup ──RegisterStartRequest──► host ──RegisterStartResponse──► SignupStarted::finish
//!   ──► PendingSignup: show the Emergency Kit, confirm_kit(last group of the SK)
//!   ──► commit_request() ──RegisterFinishRequest──► host ──ack──► PendingSignup::finalize
//! ```
//!
//! # Secrets before commit (§11, normative)
//!
//! 1. Every secret and object is built in [`SignupStarted::finish`].
//! 2. The kit is shown ([`PendingSignup::emergency_kit`]) and the user re-types the last group
//!    of the Secret Key ([`PendingSignup::confirm_kit`], §7).
//! 3. A durable device persists its pending device state: [`PendingSignup::store_writes`]
//!    gives the host the cache of the signup, with the device-state record in stage 2 and the
//!    commit's exact JSON body (ADR 0026 §2 "Signup pending"), to write before step 4.
//! 4. Only then [`PendingSignup::commit_request`] releases the upload.
//! 5. [`PendingSignup::finalize`] after the server acknowledged.
//!
//! The request is built once and kept, so a resend after a crash is byte-identical, which the
//! server treats as success (§11.1 step 8).
//!
//! # Argon2id runs
//!
//! One for the registration (OPAQUE's KSF), one for `E_local` on a durable device; a web-vault
//! signup (kind 4) runs only the first (§11.1 "Web-vault signup").
//!
//! # What is never uploaded
//!
//! `E_dev` and `E_local` stay in the pending device state; [`RegisterFinishRequest`] has no
//! field that could carry them and rejects unknown fields (§11.1 step 8, INV-1's companion
//! rule of §4.2).

use core::fmt;

use rizzy_core::envelope::purpose::{
    AccountKeyRecoveryWrapCtx, AccountKeyServerWrapCtx, IdentitySecretKeysCtx, VaultKeySelfGrantCtx,
};
use rizzy_core::ids::{AccountId, DeviceId, VaultId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{AccountKey, DeviceKeys, IdentityKeys, VaultKey, device_set_hash};
use rizzy_core::normalize::{LoginName, ServerOrigin};
use rizzy_core::opaque::{
    ClientRegistrationState, PasswordInput, client_registration_finish, client_registration_start,
};
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::{RecoveryCode, SecretKey};
/// The device kind of [`SignupInput`], re-exported so a host that links only this crate (a
/// binding, or `rizzy-server`'s end-to-end tests, ADR 0016 §4 owner decision 4) can name it.
pub use rizzy_core::sign::DeviceKind;
use rizzy_core::sign::{
    AccountState, DeviceCertificate, PublicKeyBundle, SyncMode,
    statements::WEB_CERT_MAX_LIFETIME_MS,
};
use rizzy_proto::auth::{
    RecoveryRegistration, RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse,
};
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, IdentitySecretKeys, VaultSelfGrant,
};
use rizzy_proto::wire::{Fixed, SecretText, Text};
use zeroize::Zeroizing;

use rizzy_proto::limits::MAX_UPLOAD_BODY_LEN;

use crate::account::{AccountPin, CertifiedDevice, ServedObjects};
use crate::device::{DeviceState, NewDevice, UnlockedDevice};
use crate::error::{ClientError, internal};
use crate::store;
use crate::store::record::Stage;
use crate::store::rows::{Changeset, Write};
use crate::wire::{bytes, id};

/// What the user enters to sign up (§11.1 step 1), plus the host's choices.
#[derive(Clone, Copy)]
pub struct SignupInput<'a> {
    /// The server URL the host dials; normalised as a canonical origin (§2).
    pub server_origin: &'a str,
    /// The login name; normalised (§2).
    pub login_name: &'a str,
    /// The new master password. Must be non-empty and free of unassigned code points (§2).
    pub password: &'a str,
    /// The invite token, if the server requires one.
    pub invite: Option<&'a str>,
    /// Whether to issue a recovery code (§11.9; default on).
    pub issue_recovery_code: bool,
    /// This client's kind: 1–3 enrols a durable device, 4 is the web vault.
    pub device_kind: DeviceKind,
    /// The host's wall clock, milliseconds since the Unix epoch.
    pub now_ms: u64,
}

impl fmt::Debug for SignupInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignupInput")
            .field("device_kind", &self.device_kind)
            .finish_non_exhaustive()
    }
}

/// The secrets and keys generated at step 2, carried to [`SignupStarted::finish`].
struct Generated {
    /// The Secret Key.
    secret_key: SecretKey,
    /// The account.
    account_id: AccountId,
    /// The account key, epoch 0.
    account_key: AccountKey,
    /// The identity keys, epoch 0.
    identity: IdentityKeys,
    /// The personal vault.
    vault_id: VaultId,
    /// Its key, epoch 0.
    vault_key: VaultKey,
    /// This device.
    device_id: DeviceId,
    /// Its keys.
    device_keys: DeviceKeys,
    /// The recovery code, unless the user opted out.
    recovery_code: Option<RecoveryCode>,
}

/// Signup between the registration request and the server's answer. Holds secrets; not
/// `Clone`, `Debug` redacted.
pub struct SignupStarted {
    /// The origin.
    origin: ServerOrigin,
    /// The normalised login name.
    login_name: LoginName,
    /// `pw_in`.
    pw_in: PasswordInput,
    /// The OPAQUE client state.
    registration: ClientRegistrationState,
    /// Everything generated.
    generated: Generated,
    /// The device kind.
    device_kind: DeviceKind,
    /// The host clock at the start.
    now_ms: u64,
    /// The invite token, kept for a restart of the registration (ADR 0031 point 8).
    invite: Option<Zeroizing<String>>,
}

impl fmt::Debug for SignupStarted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignupStarted([REDACTED])")
    }
}

/// Steps 1–4.2: validates the input, generates every secret from the injected CSPRNG, derives
/// `pw_in` and starts the OPAQUE registration.
///
/// # Errors
/// [`ClientError::InvalidInput`] for an origin or login name that does not normalise, a
/// password the new-password rules refuse, or an invite token outside its bounds;
/// [`ClientError::Internal`].
pub fn start_signup<R: CryptoRng + ?Sized>(
    rng: &mut R,
    input: &SignupInput<'_>,
) -> Result<(SignupStarted, RegisterStartRequest), ClientError> {
    let origin = ServerOrigin::parse(input.server_origin).map_err(|_| ClientError::InvalidInput)?;
    let login_name = LoginName::parse(input.login_name).map_err(|_| ClientError::InvalidInput)?;
    let wire_name =
        Text::new(login_name.as_str().to_owned()).map_err(|_| ClientError::InvalidInput)?;
    let invite = input
        .invite
        .map(SecretText::new)
        .transpose()
        .map_err(|_| ClientError::InvalidInput)?;
    let secret_key = SecretKey::generate(rng);
    let pw_in = PasswordInput::derive_for_new_password(input.password, &secret_key)
        .map_err(|_| ClientError::InvalidInput)?;
    let account_id = AccountId::generate(rng);
    let account_key = AccountKey::generate(rng, 0);
    let identity = IdentityKeys::generate(rng, 0);
    let vault_id = VaultId::generate(rng);
    let vault_key = VaultKey::generate(rng, vault_id, 0);
    let device_id = DeviceId::generate(rng);
    let device_keys = DeviceKeys::generate(rng);
    let recovery_code = input
        .issue_recovery_code
        .then(|| RecoveryCode::generate(rng));
    let (registration, m1) =
        client_registration_start(rng, &pw_in).map_err(|_| ClientError::Internal)?;
    let request = RegisterStartRequest {
        invite,
        login_name: wire_name,
        account_id: id(account_id.to_bytes()),
        registration_request: bytes(m1)?,
    };
    Ok((
        SignupStarted {
            origin,
            login_name,
            pw_in,
            registration,
            generated: Generated {
                secret_key,
                account_id,
                account_key,
                identity,
                vault_id,
                vault_key,
                device_id,
                device_keys,
                recovery_code,
            },
            device_kind: input.device_kind,
            now_ms: input.now_ms,
            invite: input.invite.map(|i| Zeroizing::new(i.to_owned())),
        },
        request,
    ))
}

impl SignupStarted {
    /// Steps 4.4–5 and 7: finishes the OPAQUE registration and builds every object of the
    /// commit, and for a durable device the pending device state (`E_local`: the second
    /// Argon2id run).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] if the server's registration response is
    /// malformed; [`ClientError::Internal`].
    #[expect(
        clippy::too_many_lines,
        reason = "one flat list of the objects of CRYPTO.md §11.1 step 5, in its order"
    )]
    pub fn finish<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &RegisterStartResponse,
    ) -> Result<PendingSignup, ClientError> {
        let g = self.generated;
        let kdf_id = KdfId::DEFAULT;
        let reg = client_registration_finish(
            rng,
            self.registration,
            &self.pw_in,
            response.registration_response.as_slice(),
            kdf_id,
        )
        .map_err(|_| ClientError::InvalidServerResponse)?;
        let account_id = g.account_id;
        // E_srv.
        let e_srv = reg
            .export_key
            .server_unlock_key(account_id)
            .map_err(internal)?
            .wrap_account_key(
                rng,
                &AccountKeyServerWrapCtx {
                    account_id,
                    account_key_epoch: 0,
                    password_epoch: 0,
                    kdf_id,
                },
                &g.account_key,
            )
            .map_err(internal)?;
        // E_id.
        let e_id = g
            .account_key
            .wrap_identity_keys(
                rng,
                &IdentitySecretKeysCtx {
                    account_id,
                    identity_epoch: 0,
                },
                &g.identity,
            )
            .map_err(internal)?;
        // The key bundle.
        let bundle = PublicKeyBundle {
            account_id,
            identity_epoch: 0,
            bundle_seq: 1,
            identity_ed25519: *g.identity.signing_key().verifying_key(),
            identity_x25519: g.identity.public_keys().x25519,
            mail_x25519: None,
            pq_required: false,
            created_at_ms: self.now_ms,
            prev_bundle_hash: [0; 32],
        };
        let bundle_wire = bundle.sign(g.identity.signing_key()).map_err(internal)?;
        let bundle = PublicKeyBundle::verify_self_signed(&bundle_wire).map_err(internal)?;
        // The device certificate: durable, or the web vault's ephemeral kind 4 (§11.4).
        let expires_at_ms = if self.device_kind.is_durable() {
            0
        } else {
            self.now_ms
                .checked_add(WEB_CERT_MAX_LIFETIME_MS)
                .ok_or(ClientError::InvalidInput)?
        };
        let certificate = DeviceCertificate {
            account_id,
            device_id: g.device_id,
            identity_epoch: 0,
            device_ed25519: *g.device_keys.signing_key().verifying_key(),
            device_x25519: g.device_keys.public_keys().x25519,
            device_kind: self.device_kind,
            created_at_ms: self.now_ms,
            expires_at_ms,
        };
        let certificate_wire = certificate
            .sign(g.identity.signing_key())
            .map_err(internal)?;
        let certificate = DeviceCertificate::verify(
            &certificate_wire,
            g.identity.signing_key().verifying_key(),
            0,
        )
        .map_err(internal)?;
        // A kind-4 certificate is not in the set: the hash is then the empty set's.
        let device_set =
            device_set_hash(account_id, [&certificate], core::iter::empty()).map_err(internal)?;
        // account-state.
        let recovery_epoch = u32::from(g.recovery_code.is_some());
        let state = AccountState {
            account_id,
            state_seq: 1,
            identity_epoch: 0,
            account_key_epoch: 0,
            account_key_id: g.account_key.key_id().map_err(internal)?,
            password_epoch: 0,
            kdf_id,
            recovery_epoch,
            recovery_enabled: g.recovery_code.is_some(),
            sync_mode: SyncMode::Server,
            mail_key_epoch: 0,
            bundle_hash: *bundle.hash(),
            device_set_hash: device_set,
            settings_seq: 0,
            settings_hash: [0; 32],
        };
        let state_wire = state.sign(g.identity.signing_key()).map_err(internal)?;
        // The vault self-grant.
        let grant = g
            .account_key
            .wrap_vault_key(
                rng,
                &VaultKeySelfGrantCtx {
                    account_id,
                    vault_id: g.vault_id,
                    account_key_epoch: 0,
                    vault_key_epoch: 0,
                },
                &g.vault_key,
            )
            .map_err(internal)?;
        // E_rec and H_rec.
        let recovery = match &g.recovery_code {
            Some(code) => {
                let e_rec = code
                    .wrap_key()
                    .map_err(internal)?
                    .wrap_account_key(
                        rng,
                        &AccountKeyRecoveryWrapCtx {
                            account_id,
                            account_key_epoch: 0,
                            recovery_epoch,
                        },
                        &g.account_key,
                    )
                    .map_err(internal)?;
                Some(RecoveryRegistration {
                    recovery_wrap: AccountKeyRecoveryWrap {
                        account_key_epoch: 0,
                        recovery_epoch,
                        envelope: bytes(e_rec)?,
                    },
                    recovery_token_hash: Fixed::from_bytes(
                        code.auth_token().map_err(internal)?.server_hash(),
                    ),
                })
            }
            None => None,
        };
        let request = RegisterFinishRequest {
            registration_upload: bytes(reg.upload)?,
            // ADR 0031 point 3: the setup the registration started under, echoed.
            setup_id: response.setup_id,
            account_key_server_wrap: AccountKeyServerWrap {
                account_key_epoch: 0,
                password_epoch: 0,
                kdf_id: kdf_id.get(),
                envelope: bytes(e_srv)?,
            },
            identity_secret_keys: IdentitySecretKeys {
                identity_epoch: 0,
                envelope: bytes(e_id)?,
            },
            bundle: bytes(bundle_wire)?,
            account_state: bytes(state_wire.clone())?,
            vault_self_grant: VaultSelfGrant {
                vault_id: id(g.vault_id.to_bytes()),
                account_key_epoch: 0,
                vault_key_epoch: 0,
                envelope: bytes(grant)?,
            },
            device_certificate: bytes(certificate_wire.clone())?,
            recovery,
        };
        // `settings_seq = 0` at signup: no settings exist yet.
        let pin = AccountPin {
            bundle,
            state,
            state_wire,
            settings: None,
        };
        let kit = EmergencyKit {
            server_origin: self.origin.as_str().to_owned(),
            login_name: self.login_name.as_str().to_owned(),
            secret_key: g.secret_key.to_formatted(),
            recovery_code: g.recovery_code.as_ref().map(RecoveryCode::to_formatted),
        };
        // Step 7: the pending device state (Argon2id run 2) for a durable device only.
        let (device, secret_key) = if self.device_kind.is_durable() {
            let device = DeviceState::create(
                rng,
                NewDevice {
                    server_origin: self.origin,
                    account_id,
                    device_id: g.device_id,
                    device_kind: self.device_kind,
                    secret_key: g.secret_key,
                    pw_in: &self.pw_in,
                    account_key: &g.account_key,
                    password_epoch: 0,
                    device_keys: &g.device_keys,
                    pin,
                },
            )?;
            (Some(device), None)
        } else {
            (None, Some(g.secret_key))
        };
        Ok(PendingSignup {
            kit,
            secret_key,
            confirmed: false,
            restart: SignupRestart {
                pw_in: self.pw_in,
                login_name: self.login_name,
                invite: self.invite,
                state: None,
                restarted: false,
            },
            request,
            device,
            own_certificate: CertifiedDevice {
                certificate,
                wire: certificate_wire,
            },
            unlocked: UnlockedDevice {
                account_id,
                device_id: g.device_id,
                account_key: g.account_key,
                device_keys: g.device_keys,
                local_unlock_key: None,
            },
            vault_key: g.vault_key,
        })
    }
}

/// The Emergency Kit's contents (CRYPTO.md §7): the one time the Secret Key and the recovery
/// code leave the core (ADR 0013 §3 rule 2). The host renders it and forgets it. Wiped on drop,
/// `Debug` redacted.
pub struct EmergencyKit {
    /// The server URL.
    server_origin: String,
    /// The login name.
    login_name: String,
    /// The Secret Key, formatted `RV1-…`.
    secret_key: Zeroizing<String>,
    /// The recovery code, formatted `RVR1-…`, if issued.
    recovery_code: Option<Zeroizing<String>>,
}

impl fmt::Debug for EmergencyKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EmergencyKit([REDACTED])")
    }
}

impl EmergencyKit {
    /// The server URL.
    #[must_use]
    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }

    /// The login name.
    #[must_use]
    pub fn login_name(&self) -> &str {
        &self.login_name
    }

    /// The Secret Key as printed. A secret: render it, never log it.
    #[must_use]
    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    /// The recovery code as printed, if one was issued. A secret.
    #[must_use]
    pub fn recovery_code(&self) -> Option<&str> {
        self.recovery_code.as_deref().map(String::as_str)
    }
}

/// What restarting a signup's registration needs (ADR 0031 point 8): `pw_in`, the login name
/// and invite of `register/start`, and the restarted OPAQUE state. Holds secrets; no `Debug`.
struct SignupRestart {
    /// `pw_in` of the signup.
    pw_in: PasswordInput,
    /// The normalised login name.
    login_name: LoginName,
    /// The invite token, if the signup had one.
    invite: Option<Zeroizing<String>>,
    /// The OPAQUE client state of the restarted registration, between its request and answer.
    state: Option<ClientRegistrationState>,
    /// Whether the registration was restarted already: at most once (ADR 0031 "Risks").
    restarted: bool,
}

/// Signup with every object built, waiting for the kit confirmation and the commit.
pub struct PendingSignup {
    /// The kit to render.
    kit: EmergencyKit,
    /// The Secret Key of a web-vault signup, which keeps no device state; checked by
    /// [`PendingSignup::confirm_kit`]. A durable device's lives in its device state.
    secret_key: Option<SecretKey>,
    /// Whether the user re-typed the last group of the Secret Key.
    confirmed: bool,
    /// What a restart of the registration needs (ADR 0031 point 8).
    restart: SignupRestart,
    /// The commit, built once; only a restart of the registration replaces its OPAQUE upload,
    /// `setup_id` and `E_srv`.
    request: RegisterFinishRequest,
    /// The pending device state of a durable device.
    device: Option<DeviceState>,
    /// This client's own certificate.
    own_certificate: CertifiedDevice,
    /// The keys of this client, for the session after the commit.
    unlocked: UnlockedDevice,
    /// The personal vault's key.
    vault_key: VaultKey,
}

impl fmt::Debug for PendingSignup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSignup")
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

impl PendingSignup {
    /// The Emergency Kit to render (§11.1 step 6).
    #[must_use]
    pub const fn emergency_kit(&self) -> &EmergencyKit {
        &self.kit
    }

    /// Confirms the kit: `typed` must be the last group of four characters of the Secret Key,
    /// compared in constant time (§7).
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] if it does not match.
    pub fn confirm_kit(&mut self, typed: &str) -> Result<(), ClientError> {
        let sk = match (&self.device, &self.secret_key) {
            (Some(device), _) => &device.secret_key,
            (None, Some(sk)) => sk,
            (None, None) => return Err(ClientError::Internal),
        };
        if sk.matches_last_group(typed) {
            self.confirmed = true;
            Ok(())
        } else {
            Err(ClientError::EmergencyKitNotConfirmed)
        }
    }

    /// The pending device state a durable device persists before the commit (step 7). `None`
    /// for the web vault.
    #[must_use]
    pub const fn pending_device(&self) -> Option<&DeviceState> {
        self.device.as_ref()
    }

    /// The commit (step 8), only after the kit was confirmed. The same bytes on every call, so
    /// a resend is byte-identical.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`].
    pub fn commit_request(&self) -> Result<&RegisterFinishRequest, ClientError> {
        if self.confirmed {
            Ok(&self.request)
        } else {
            Err(ClientError::EmergencyKitNotConfirmed)
        }
    }

    /// ADR 0031 point 8: the commit was refused with `setup_retired` (the server's OPAQUE setup
    /// was retired between `register/start` and the commit, and the commit was not applied).
    /// Starts the registration again with the same `pw_in`; the host sends the request to
    /// `register/start` and passes the answer to [`PendingSignup::on_registration_restarted`].
    /// Everything else of the signup (the Secret Key, the keys, the kit) stays.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] before the kit was confirmed;
    /// [`ClientError::SetupRetired`] when the registration was restarted once already (at most
    /// once, ADR 0031 "Risks"); [`ClientError::InvalidInput`] for an invite out of bounds;
    /// [`ClientError::Internal`].
    pub fn restart_registration<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
    ) -> Result<RegisterStartRequest, ClientError> {
        if !self.confirmed {
            return Err(ClientError::EmergencyKitNotConfirmed);
        }
        if self.restart.restarted {
            return Err(ClientError::SetupRetired);
        }
        let (state, m1) = client_registration_start(rng, &self.restart.pw_in).map_err(internal)?;
        let request = RegisterStartRequest {
            invite: self
                .restart
                .invite
                .as_ref()
                .map(|i| SecretText::new(i.as_str()))
                .transpose()
                .map_err(|_| ClientError::InvalidInput)?,
            login_name: Text::new(self.restart.login_name.as_str().to_owned())
                .map_err(|_| ClientError::InvalidInput)?,
            account_id: id(self.unlocked.account_id.to_bytes()),
            registration_request: bytes(m1)?,
        };
        self.restart.state = Some(state);
        self.restart.restarted = true;
        Ok(request)
    }

    /// The answer to [`PendingSignup::restart_registration`]: rebuilds only the OPAQUE upload,
    /// the echoed `setup_id` and `E_srv` (under the new `export_key`, at the same locator) in
    /// the commit, which [`PendingSignup::commit_request`] then returns. A durable device writes
    /// the new commit body over the stored one (`crate::store::pending_writes`) before it
    /// sends it.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] without a restart; [`ClientError::InvalidServerResponse`]
    /// for a malformed answer; [`ClientError::Internal`].
    pub fn on_registration_restarted<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        response: &RegisterStartResponse,
    ) -> Result<(), ClientError> {
        let state = self.restart.state.take().ok_or(ClientError::InvalidInput)?;
        let (upload, wrap) = crate::reregister::finish_registration(
            rng,
            state,
            &self.restart.pw_in,
            response.registration_response.as_slice(),
            self.unlocked.account_id,
            &self.unlocked.account_key,
            crate::reregister::Locator::from(&self.request.account_key_server_wrap),
        )?;
        self.request.registration_upload = upload;
        self.request.setup_id = response.setup_id;
        self.request.account_key_server_wrap = wrap;
        Ok(())
    }

    /// Step 9: after the server acknowledged the commit, the device state is final.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] if the commit was never released.
    pub fn finalize(self) -> Result<SignedUp, ClientError> {
        if !self.confirmed {
            return Err(ClientError::EmergencyKitNotConfirmed);
        }
        Ok(SignedUp {
            device: self.device,
            unlocked: self.unlocked,
            vault_key: self.vault_key,
            own_certificate: self.own_certificate,
        })
    }
}

/// A finished signup: the device state (durable devices), the unlocked keys and the personal
/// vault's key, ready for a session and the first sync.
pub struct SignedUp {
    /// The final device state; `None` for the web vault.
    pub device: Option<DeviceState>,
    /// The unlocked keys.
    pub unlocked: UnlockedDevice,
    /// The personal vault's key.
    pub vault_key: VaultKey,
    /// This client's own certificate.
    pub own_certificate: CertifiedDevice,
}

impl fmt::Debug for SignedUp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedUp")
            .field("unlocked", &self.unlocked)
            .finish_non_exhaustive()
    }
}

impl PendingSignup {
    /// The cache of a durable device's signup, written **before** the commit is sent
    /// (CRYPTO.md §11 "Secrets before commit" step 3; ADR 0026 §2 "Signup pending", §4 step 3):
    /// the `cache_meta` rows, the device-state record in stage 2, `commit_json` as
    /// `pending_commit`, and the account objects and the self-grant this signup registers.
    ///
    /// `commit_json` is the exact JSON body of [`PendingSignup::commit_request`] the host is
    /// about to send. On restart the host resends those bytes; the server treats a
    /// byte-identical repeat as success (§11.1 step 8), and the answer finalises the record
    /// ([`crate::store::finalize_writes`] with [`DeviceRecord::committed`]).
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] before the kit was confirmed (step 2 comes
    /// first); [`ClientError::InvalidInput`] for a web-vault signup, which keeps no device
    /// state, or an empty or oversized `commit_json`; [`ClientError::Internal`].
    ///
    /// [`DeviceRecord::committed`]: crate::store::record::DeviceRecord::committed
    pub fn store_writes(&self, commit_json: &[u8]) -> Result<Changeset, ClientError> {
        if !self.confirmed {
            return Err(ClientError::EmergencyKitNotConfirmed);
        }
        let device = self.device.as_ref().ok_or(ClientError::InvalidInput)?;
        let record = device.record(Stage::SignupPending)?;
        let mut changeset = store::create_writes(&record)?;
        if commit_json.is_empty() || commit_json.len() > MAX_UPLOAD_BODY_LEN {
            return Err(ClientError::InvalidInput);
        }
        changeset.push(Write::PendingCommit(Some(commit_json.to_vec())));
        let vault_key_id = *self.vault_key.key_id().map_err(internal)?.as_bytes();
        let served = ServedObjects {
            bundles: vec![(
                device.pin.bundle.bundle_seq,
                self.request.bundle.as_slice().to_vec(),
            )],
            identity_secret_keys: Some(self.request.identity_secret_keys.clone()),
            self_grants: vec![(self.request.vault_self_grant.clone(), vault_key_id)],
        };
        changeset.append(store::object_writes(
            &device.pin,
            core::slice::from_ref(&self.own_certificate),
            &[],
            &served,
        ));
        Ok(changeset)
    }
}

impl EmergencyKit {
    /// The kit of a recovery (CRYPTO.md §11.9 step 5): the new Secret Key and the new recovery
    /// code, for the same server and login name.
    pub(crate) fn for_recovery(
        origin: &ServerOrigin,
        login_name: &LoginName,
        secret_key: &SecretKey,
        recovery_code: &RecoveryCode,
    ) -> Self {
        Self {
            server_origin: origin.as_str().to_owned(),
            login_name: login_name.as_str().to_owned(),
            secret_key: secret_key.to_formatted(),
            recovery_code: Some(recovery_code.to_formatted()),
        }
    }
}

impl EmergencyKit {
    /// The kit of a Secret Key change (CRYPTO.md §11.5 step 4, §7 "Changing the SK"): the new
    /// Secret Key, and the new recovery code when the change's rotation issued one. Without a
    /// new code the kit carries none, and the recovery code of the earlier kit stays valid.
    pub(crate) fn for_change(
        origin: &ServerOrigin,
        login_name: &LoginName,
        secret_key: &SecretKey,
        recovery_code: Option<&RecoveryCode>,
    ) -> Self {
        Self {
            server_origin: origin.as_str().to_owned(),
            login_name: login_name.as_str().to_owned(),
            secret_key: secret_key.to_formatted(),
            recovery_code: recovery_code.map(RecoveryCode::to_formatted),
        }
    }
}
