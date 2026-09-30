//! Recovery with the Emergency Kit (CRYPTO.md §11.9; ADR 0008; ADR 0025 §1), as a sans-I/O
//! state machine.
//!
//! ```text
//! start_recovery ──RecoveryRequest──► host (recovery/start, then after the wait
//!   recovery/complete with RecoveryStarted::request) ──RecoveryCompleteResponse──►
//! RecoveryStarted::open ──► Recovered ── start_commit ──ReregisterStartRequest──► host
//!   ──ReregisterStartResponse──► Reregistering::finish ──► PendingRecovery:
//!   show the new Emergency Kit, confirm_kit ──► commit_request ──CommitChangeRequest──► host
//!   ──ack──► PendingRecovery::finalize
//! ```
//!
//! Every request after `recovery/complete` travels over the recovery-only session it returned
//! ([`Recovered::bearer_token`], 10 minutes; §11.9 step 3).
//!
//! # What is checked (§11.9 step 4)
//!
//! The recovery wrap key, derived from the typed code, opens `E_rec` with the context the
//! answer names; the account key it yields must be the one the signed `account-state` commits
//! to; then `E_id`, the bundle, the state, the device set, the settings and every self-grant
//! are verified exactly as on a new device ([`crate::account`], §11.2 step 6). The state must
//! have recovery on, at the epoch of the `E_rec` that opened. Nothing of the answer is used
//! before all of it verified.
//!
//! # What is built (§11.9 step 5)
//!
//! A **new Secret Key**, a **new recovery code** and the OPAQUE registration of the new
//! master password; `E_srv'`, `E_rec'` and `H_rec'`; the recovering client's own enrolment as
//! a durable device (its certificate in the same commit); and, by default, a **standard
//! rotation**: a new account key, a new key for every vault, every wrap-set row the client can
//! open re-wrapped (the rest dropped, ADR 0025 §2 step 3), `E_id'`, the re-encrypted
//! settings, and a device grant, signed by the new device, to every other remaining device.
//! The new `account-state` has `state_seq + 1`, `password_epoch + 1`, `recovery_epoch + 1`
//! and, with the rotation, `account_key_epoch + 1`.
//!
//! "Skip rotation" is the explicit opt-out ([`RecoveryOptions::rotate`]): any copy of the old
//! `E_rec` still opens with the old code and yields the account key, which then stays the
//! account's key.
//!
//! The vault half is built from the answer of `recovery/complete` itself: the heads and the
//! wrap set it serves are one consistent read (ADR 0025 §1), so they are the exact cursor and
//! the covered wrap set the server checks (ADR 0025 §3). A recovering client holds no ops of
//! its own.
//!
//! # Secrets before commit (CRYPTO.md §11)
//!
//! [`PendingRecovery::commit_request`] is released only after the new kit was confirmed
//! ([`PendingRecovery::confirm_kit`]). A recovering client has no device state before the
//! commit, so there is no pending record to write (the rule's step 3 for a client without
//! device state): the confirmed kit is what survives a crash, and the host writes the cache
//! ([`PendingRecovery::store_writes`]) once the server acknowledged. The recovery code is
//! never persisted.
//!
//! # Not in this build (reported)
//!
//! - Recovery by a **web vault** (kind 4): only a durable device recovers here.
//! - The **full rotation** the UI offers "if the user believes the kit was stolen".
//! - A lost compare-and-swap (`state_conflict`) is not retried: the host runs
//!   `recovery/complete` again and rebuilds.

use core::fmt;

use rizzy_core::envelope::purpose::{
    AccountKeyDeviceGrantCtx, AccountKeyRecoveryWrapCtx, AccountKeyServerWrapCtx,
    IdentitySecretKeysCtx,
};
use rizzy_core::ids::{AccountId, DeviceId, VaultId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{
    AccountKey, DeviceKeys, GrantSigner, VaultKey, device_set_hash, seal_account_key_device_grant,
    settings_hash,
};
use rizzy_core::normalize::{LoginName, ServerOrigin};
use rizzy_core::opaque::{
    ClientRegistrationState, PasswordInput, client_registration_finish, client_registration_start,
};
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::{RecoveryCode, SecretKey};
use rizzy_core::sign::{DeviceCertificate, DeviceKind};
use rizzy_proto::auth::RecoveryRegistration;
use rizzy_proto::change::{
    CommitChangeRequest, ReregisterStartRequest, ReregisterStartResponse, VaultRotation,
    VaultRotationUpload,
};
use rizzy_proto::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, DeviceGrant, IdentitySecretKeys, ItemKeyWrap,
    VaultSelfGrant,
};
use rizzy_proto::recovery::{RecoveryCompleteResponse, RecoveryRequest};
use rizzy_proto::vault::SeqVector;
use rizzy_proto::wire::{Fixed, List, SecretFixed, SessionToken, Text};
use zeroize::Zeroizing;

use crate::account::{
    AccountPin, Anchor, CertifiedDevice, RevokedDevice, ServedObjects, VerifiedAccount,
    verify_account_view,
};
use crate::device::{DeviceState, NewDevice, UnlockedDevice};
use crate::error::{ClientError, internal};
use crate::rotation::{build_vault_half, reencrypt_settings};
use crate::signup::EmergencyKit;
use crate::store;
use crate::store::record::Stage;
use crate::store::rows::{Changeset, Write};
use crate::sync::{Authors, wrap_rows};
use crate::wire::{bytes, id};

/// What the user enters to recover (§11.9 step 1), plus the server the host dials.
#[derive(Clone, Copy)]
pub struct RecoveryInput<'a> {
    /// The server URL the host dials.
    pub server_origin: &'a str,
    /// The login name.
    pub login_name: &'a str,
    /// The recovery code from the Emergency Kit (`RVR1-…`).
    pub recovery_code: &'a str,
}

impl fmt::Debug for RecoveryInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryInput([REDACTED])")
    }
}

/// A recovery with its code parsed. Holds the code; `Debug` redacted.
pub struct RecoveryStarted {
    /// The dialled origin.
    origin: ServerOrigin,
    /// The normalised login name.
    login_name: LoginName,
    /// The recovery code.
    code: RecoveryCode,
}

impl fmt::Debug for RecoveryStarted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryStarted([REDACTED])")
    }
}

/// Step 1: parses the input. The request for `recovery/start` and `recovery/complete` is
/// [`RecoveryStarted::request`].
///
/// # Errors
/// [`ClientError::InvalidInput`] for an origin, login name or recovery code that does not
/// parse (a typo in the code fails its check characters here, before anything is sent).
pub fn start_recovery(input: &RecoveryInput<'_>) -> Result<RecoveryStarted, ClientError> {
    let bad = ClientError::InvalidInput;
    Ok(RecoveryStarted {
        origin: ServerOrigin::parse(input.server_origin).map_err(|_| bad)?,
        login_name: LoginName::parse(input.login_name).map_err(|_| bad)?,
        code: RecoveryCode::parse(input.recovery_code).map_err(|_| bad)?,
    })
}

/// One vault of a recovery: its key, and the heads and wrap set `recovery/complete` served.
struct RecoveredVault {
    /// The vault key, opened from the verified self-grant.
    key: VaultKey,
    /// The server's heads: the cursor of the rotation's vault half.
    heads: SeqVector,
    /// The wrap set.
    wraps: Vec<ItemKeyWrap>,
}

impl RecoveryStarted {
    /// `{login_name, recovery_auth_token}` (§11.9 steps 2 and 3): the body of both
    /// `recovery/start` and `recovery/complete`. The code itself never travels; the token
    /// cannot open `E_rec`.
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub fn request(&self) -> Result<RecoveryRequest, ClientError> {
        let token = self.code.auth_token().map_err(internal)?;
        Ok(RecoveryRequest {
            login_name: Text::new(self.login_name.as_str().to_owned())
                .map_err(|_| ClientError::InvalidInput)?,
            recovery_auth_token: SecretFixed::new(Zeroizing::new(*token.expose_secret())),
        })
    }

    /// Step 4: opens `E_rec` and verifies the whole answer (module docs).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] for any failed check.
    pub fn open(self, response: RecoveryCompleteResponse) -> Result<Recovered, ClientError> {
        let bad = ClientError::InvalidServerResponse;
        let account_id = AccountId::from_bytes(response.account_id.to_bytes());
        let wrap = &response.recovery_wrap;
        let account_key = self
            .code
            .wrap_key()
            .map_err(internal)?
            .unwrap_account_key(
                &AccountKeyRecoveryWrapCtx {
                    account_id,
                    account_key_epoch: wrap.account_key_epoch,
                    recovery_epoch: wrap.recovery_epoch,
                },
                wrap.envelope.as_slice(),
            )
            .map_err(|_| bad)?;
        let mut account = verify_account_view(
            &response.account,
            account_id,
            &account_key,
            &Anchor::NewDevice,
        )?;
        let state = account.state();
        if !state.recovery_enabled
            || state.recovery_epoch != wrap.recovery_epoch
            || state.account_key_epoch != wrap.account_key_epoch
        {
            return Err(bad);
        }
        // One served vault per vault of the verified account, each once.
        let mut vault_ids: Vec<VaultId> = account.vault_ids().collect();
        vault_ids.sort();
        let served = response.vaults.into_vec();
        if served.len() != vault_ids.len() {
            return Err(bad);
        }
        let mut vaults = Vec::with_capacity(vault_ids.len());
        for vault_id in vault_ids {
            let mut matching = served
                .iter()
                .filter(|v| v.vault_id.to_bytes() == vault_id.to_bytes());
            let (Some(vault), None) = (matching.next(), matching.next()) else {
                return Err(bad);
            };
            vaults.push(RecoveredVault {
                key: account.take_vault_key(vault_id).ok_or(bad)?,
                heads: vault.heads.clone(),
                wraps: vault.item_key_wraps.as_slice().to_vec(),
            });
        }
        Ok(Recovered {
            origin: self.origin,
            login_name: self.login_name,
            account,
            account_key,
            session_token: response.session_token,
            vaults,
        })
    }
}

/// A verified recovery answer (§11.9 step 4): the account, its key and its vault keys, and the
/// recovery-only session. Not `Clone`; `Debug` shows the account only.
pub struct Recovered {
    /// The dialled origin.
    origin: ServerOrigin,
    /// The login name.
    login_name: LoginName,
    /// The verified account.
    account: VerifiedAccount,
    /// The account key `E_rec` gave.
    account_key: AccountKey,
    /// The recovery-only session's bearer token.
    session_token: SessionToken,
    /// The vaults, ascending by id.
    vaults: Vec<RecoveredVault>,
}

impl fmt::Debug for Recovered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recovered")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

/// The user's and the host's choices for the recovery commit (§11.9 step 5).
#[derive(Clone, Copy)]
pub struct RecoveryOptions<'a> {
    /// The new master password.
    pub new_password: &'a str,
    /// Whether to rotate the account key and the vault keys: the default. `false` is the
    /// explicit "skip rotation" opt-out (module docs).
    pub rotate: bool,
    /// This client's kind; must be durable (1–3).
    pub device_kind: DeviceKind,
    /// The host's wall clock, milliseconds since the Unix epoch.
    pub now_ms: u64,
}

impl fmt::Debug for RecoveryOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryOptions")
            .field("rotate", &self.rotate)
            .field("device_kind", &self.device_kind)
            .finish_non_exhaustive()
    }
}

impl Recovered {
    /// The verified account.
    #[must_use]
    pub const fn account(&self) -> &VerifiedAccount {
        &self.account
    }

    /// The recovery-only session's bearer token, for the host's transport. Never log it.
    #[must_use]
    pub const fn bearer_token(&self) -> &SessionToken {
        &self.session_token
    }

    /// Step 5, first half: generates the new Secret Key and starts the OPAQUE registration of
    /// the new master password. The request goes to `account/reregister/start` over the
    /// recovery-only session.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a web-vault kind or a password the new-password rules
    /// refuse; [`ClientError::Internal`].
    pub fn start_commit<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        options: &RecoveryOptions<'_>,
    ) -> Result<(Reregistering, ReregisterStartRequest), ClientError> {
        if !options.device_kind.is_durable() {
            return Err(ClientError::InvalidInput);
        }
        let secret_key = SecretKey::generate(rng);
        let pw_in = PasswordInput::derive_for_new_password(options.new_password, &secret_key)
            .map_err(|_| ClientError::InvalidInput)?;
        let (registration, message) = client_registration_start(rng, &pw_in).map_err(internal)?;
        Ok((
            Reregistering {
                recovered: self,
                secret_key,
                pw_in,
                registration,
                rotate: options.rotate,
                device_kind: options.device_kind,
                now_ms: options.now_ms,
            },
            ReregisterStartRequest {
                registration_request: bytes(message)?,
            },
        ))
    }
}

/// A recovery between the re-registration request and the server's answer. Holds secrets;
/// `Debug` redacted.
pub struct Reregistering {
    /// The verified answer.
    recovered: Recovered,
    /// The new Secret Key.
    secret_key: SecretKey,
    /// `pw_in` of the new password and the new Secret Key.
    pw_in: PasswordInput,
    /// The OPAQUE client state.
    registration: ClientRegistrationState,
    /// Whether to rotate.
    rotate: bool,
    /// This client's kind.
    device_kind: DeviceKind,
    /// The host clock at the start.
    now_ms: u64,
}

impl fmt::Debug for Reregistering {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Reregistering([REDACTED])")
    }
}

impl Reregistering {
    /// Step 5, second half: finishes the registration and builds every object of the commit
    /// (module docs, "What is built"), and this device's state (`E_local`: one more Argon2id
    /// run).
    ///
    /// # Errors
    /// [`ClientError::InvalidServerResponse`] for a malformed registration response or a
    /// served object that does not fit the verified account; [`ClientError::Internal`].
    #[expect(
        clippy::too_many_lines,
        reason = "one flat list of the objects of CRYPTO.md §11.9 step 5, in its order"
    )]
    pub fn finish<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        response: &ReregisterStartResponse,
    ) -> Result<PendingRecovery, ClientError> {
        let Recovered {
            origin,
            login_name,
            account,
            account_key: old_account_key,
            session_token,
            vaults,
        } = self.recovered;
        let kdf_id = KdfId::DEFAULT;
        let registration = client_registration_finish(
            rng,
            self.registration,
            &self.pw_in,
            response.registration_response.as_slice(),
            kdf_id,
        )
        .map_err(|_| ClientError::InvalidServerResponse)?;
        let account_id = account.account_id;
        let base = &account.pin.state;
        let overflow = ClientError::Internal;
        let password_epoch = base.password_epoch.checked_add(1).ok_or(overflow)?;
        let recovery_epoch = base.recovery_epoch.checked_add(1).ok_or(overflow)?;
        let recovery_code = RecoveryCode::generate(rng);

        // The rotation's keys (§11.6 step 2), or the keys as they are.
        let new_account_key = if self.rotate {
            Some(old_account_key.generate_next(rng).map_err(internal)?)
        } else {
            None
        };
        let account_key = new_account_key.as_ref().unwrap_or(&old_account_key);
        let account_key_epoch = account_key.epoch();

        // This device (§11.2 step 7), certified by the identity key.
        let device_id = DeviceId::generate(rng);
        let device_keys = DeviceKeys::generate(rng);
        let identity = &account.identity;
        let certificate = DeviceCertificate {
            account_id,
            device_id,
            identity_epoch: identity.epoch(),
            device_ed25519: *device_keys.signing_key().verifying_key(),
            device_x25519: device_keys.public_keys().x25519,
            device_kind: self.device_kind,
            created_at_ms: self.now_ms,
            expires_at_ms: 0,
        };
        let certificate_wire = certificate.sign(identity.signing_key()).map_err(internal)?;
        let own = CertifiedDevice {
            certificate: DeviceCertificate::verify(
                &certificate_wire,
                identity.signing_key().verifying_key(),
                identity.epoch(),
            )
            .map_err(internal)?,
            wire: certificate_wire,
        };
        let mut certificates = account.certificates.clone();
        certificates.push(own.clone());
        let revocations: Vec<RevokedDevice> = account.revocations.clone();
        let device_set = device_set_hash(
            account_id,
            certificates.iter().map(|c| &c.certificate),
            revocations.iter().map(|r| &r.revocation),
        )
        .map_err(|_| ClientError::InvalidServerResponse)?;

        // The rotation's objects: the vault halves, E_id', the settings, the grants.
        let mut rotations: Vec<VaultRotation> = Vec::new();
        let mut dropped_items = 0usize;
        let mut vault_keys: Vec<VaultKey> = Vec::with_capacity(vaults.len());
        let mut wraps: Vec<(VaultId, u32, Vec<ItemKeyWrap>)> = Vec::with_capacity(vaults.len());
        let mut self_grants: Vec<(VaultSelfGrant, [u8; 16])> = account.served.self_grants.clone();
        let mut e_id: Option<IdentitySecretKeys> = None;
        let mut settings = None;
        let mut grants: Vec<DeviceGrant> = Vec::new();
        if let Some(new_account_key) = &new_account_key {
            self_grants.clear();
            for vault in vaults {
                // Above every epoch this client saw for the vault (ADR 0025 §3 check 2).
                let epoch = vault
                    .wraps
                    .iter()
                    .map(|w| w.vault_key_epoch)
                    .fold(vault.key.epoch(), u32::max)
                    .checked_add(1)
                    .ok_or(overflow)?;
                let new_key = VaultKey::generate(rng, vault.key.vault_id(), epoch);
                let half = build_vault_half(
                    rng,
                    account_id,
                    &[&vault.key],
                    &vault.wraps,
                    vault.heads,
                    new_account_key,
                    &new_key,
                )?;
                dropped_items = dropped_items.saturating_add(half.dropped_items.len());
                self_grants.push((
                    half.rotation.self_grant.clone(),
                    *new_key.key_id().map_err(internal)?.as_bytes(),
                ));
                wraps.push((
                    new_key.vault_id(),
                    epoch,
                    half.rotation.item_key_wraps.as_slice().to_vec(),
                ));
                rotations.push(half.rotation);
                vault_keys.push(new_key);
            }
            let envelope = new_account_key
                .wrap_identity_keys(
                    rng,
                    &IdentitySecretKeysCtx {
                        account_id,
                        identity_epoch: identity.epoch(),
                    },
                    identity,
                )
                .map_err(internal)?;
            e_id = Some(IdentitySecretKeys {
                identity_epoch: identity.epoch(),
                envelope: bytes(envelope)?,
            });
            settings = reencrypt_settings(rng, &account.pin, &old_account_key, new_account_key)?;
            // §11.6 step 6: a grant for every remaining durable device but this new one.
            for recipient in &account.certificates {
                let c = &recipient.certificate;
                let revoked = revocations
                    .iter()
                    .any(|r| r.revocation.device_id == c.device_id);
                if !c.in_device_set() || revoked {
                    continue;
                }
                let grant = seal_account_key_device_grant(
                    rng,
                    &AccountKeyDeviceGrantCtx {
                        account_id,
                        account_key_epoch,
                        sender_device_id: device_id,
                        recipient_device_id: c.device_id,
                    },
                    new_account_key,
                    &old_account_key,
                    c,
                    GrantSigner::Device(device_keys.signing_key()),
                )
                .map_err(internal)?;
                grants.push(DeviceGrant {
                    account_key_epoch,
                    sender_device_id: id(device_id.to_bytes()),
                    recipient_device_id: id(c.device_id.to_bytes()),
                    key_grant: bytes(grant)?,
                });
            }
        } else {
            for vault in vaults {
                wraps.push((vault.key.vault_id(), vault.key.epoch(), vault.wraps));
                vault_keys.push(vault.key);
            }
        }

        // E_srv', E_rec' and H_rec' (the credential-replacement rule, §11).
        let e_srv = registration
            .export_key
            .server_unlock_key(account_id)
            .map_err(internal)?
            .wrap_account_key(
                rng,
                &AccountKeyServerWrapCtx {
                    account_id,
                    account_key_epoch,
                    password_epoch,
                    kdf_id,
                },
                account_key,
            )
            .map_err(internal)?;
        let e_rec = recovery_code
            .wrap_key()
            .map_err(internal)?
            .wrap_account_key(
                rng,
                &AccountKeyRecoveryWrapCtx {
                    account_id,
                    account_key_epoch,
                    recovery_epoch,
                },
                account_key,
            )
            .map_err(internal)?;
        let recovery = RecoveryRegistration {
            recovery_wrap: AccountKeyRecoveryWrap {
                account_key_epoch,
                recovery_epoch,
                envelope: bytes(e_rec)?,
            },
            recovery_token_hash: Fixed::from_bytes(
                recovery_code.auth_token().map_err(internal)?.server_hash(),
            ),
        };

        // The new state.
        let mut state = base.clone();
        state.state_seq = base.state_seq.checked_add(1).ok_or(overflow)?;
        state.account_key_epoch = account_key_epoch;
        state.account_key_id = account_key.key_id().map_err(internal)?;
        state.password_epoch = password_epoch;
        state.kdf_id = kdf_id;
        state.recovery_epoch = recovery_epoch;
        state.recovery_enabled = true;
        state.device_set_hash = device_set;
        if let Some(new_settings) = &settings {
            state.settings_seq = new_settings.settings_seq;
            state.settings_hash = settings_hash(
                new_settings.settings_seq,
                Some(new_settings.envelope.as_slice()),
            )
            .ok_or(ClientError::Internal)?;
        }
        let state_wire = state.sign(identity.signing_key()).map_err(internal)?;
        let request = CommitChangeRequest {
            account_state: bytes(state_wire.clone())?,
            registration_upload: Some(bytes(registration.upload)?),
            account_key_server_wrap: Some(AccountKeyServerWrap {
                account_key_epoch,
                password_epoch,
                kdf_id: kdf_id.get(),
                envelope: bytes(e_srv)?,
            }),
            recovery: Some(recovery),
            account_settings: settings.clone(),
            device_certificates: List::new(vec![bytes(own.wire.clone())?]).map_err(internal)?,
            device_revocations: List::empty(),
            bundle: None,
            identity_secret_keys: e_id.clone(),
            retired_secret_keys: List::empty(),
            device_grants: List::new(grants).map_err(internal)?,
            recovery_rewrap: None,
            vault_rotation: if rotations.is_empty() {
                None
            } else {
                Some(VaultRotationUpload::new(rotations).map_err(internal)?)
            },
        };
        let pin = AccountPin {
            bundle: account.pin.bundle.clone(),
            state,
            state_wire,
            settings: settings.or_else(|| account.pin.settings.clone()),
        };
        let kit =
            EmergencyKit::for_recovery(&origin, &login_name, &self.secret_key, &recovery_code);
        // The device state under the new password and the key the account has after the commit
        // (`E_local`: one Argon2id run).
        let device = DeviceState::create(
            rng,
            NewDevice {
                server_origin: origin,
                account_id,
                device_id,
                device_kind: self.device_kind,
                secret_key: self.secret_key,
                pw_in: &self.pw_in,
                account_key,
                password_epoch,
                device_keys: &device_keys,
                pin: pin.clone(),
            },
        )?;
        let served = ServedObjects {
            bundles: account.served.bundles.clone(),
            identity_secret_keys: e_id.or_else(|| account.served.identity_secret_keys.clone()),
            self_grants,
        };
        let authors = Authors::from_statements(&certificates, &revocations)?;
        Ok(PendingRecovery {
            kit,
            confirmed: false,
            request,
            session_token,
            device,
            unlocked: UnlockedDevice {
                account_id,
                device_id,
                account_key: match new_account_key {
                    Some(key) => key,
                    None => old_account_key,
                },
                device_keys,
                local_unlock_key: None,
            },
            vault_keys,
            wraps,
            certificates,
            revocations,
            served,
            authors,
            dropped_items,
        })
    }
}

/// A recovery with every object built, waiting for the kit confirmation and the commit.
pub struct PendingRecovery {
    /// The new kit to render.
    kit: EmergencyKit,
    /// Whether the user re-typed the last group of the new Secret Key.
    confirmed: bool,
    /// The commit, built once.
    request: CommitChangeRequest,
    /// The recovery-only session.
    session_token: SessionToken,
    /// This device's state after the commit.
    device: DeviceState,
    /// This device's keys after the commit.
    unlocked: UnlockedDevice,
    /// The vault keys after the commit, ascending by vault id.
    vault_keys: Vec<VaultKey>,
    /// Per vault: the wrap set after the commit and the vault key epoch it is wrapped at.
    wraps: Vec<(VaultId, u32, Vec<ItemKeyWrap>)>,
    /// The device set after the commit.
    certificates: Vec<CertifiedDevice>,
    /// The revocations (unchanged).
    revocations: Vec<RevokedDevice>,
    /// The account objects after the commit, for the cache.
    served: ServedObjects,
    /// The authors after the commit.
    authors: Authors,
    /// How many wrap-set rows the rotation dropped.
    dropped_items: usize,
}

impl fmt::Debug for PendingRecovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRecovery")
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

/// A committed recovery: the new device, its keys, and what its first sync needs.
pub struct RecoveryDone {
    /// The device state.
    pub device: DeviceState,
    /// Its unlocked keys.
    pub unlocked: UnlockedDevice,
    /// The vault keys, ascending by vault id.
    pub vault_keys: Vec<VaultKey>,
    /// The device set after the recovery.
    pub certificates: Vec<CertifiedDevice>,
    /// The revocations.
    pub revocations: Vec<RevokedDevice>,
    /// The authors after the recovery.
    pub authors: Authors,
    /// How many wrap-set rows the rotation could not open and dropped: those items are
    /// unreadable for every device (ADR 0025 §2 step 3).
    pub dropped_items: usize,
}

impl fmt::Debug for RecoveryDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryDone")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl PendingRecovery {
    /// The new Emergency Kit to render (§11.9 step 5): the old one is assumed lost or
    /// compromised.
    #[must_use]
    pub const fn emergency_kit(&self) -> &EmergencyKit {
        &self.kit
    }

    /// Confirms the kit: `typed` must be the last group of four characters of the new Secret
    /// Key, compared in constant time (§7).
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] if it does not match.
    pub fn confirm_kit(&mut self, typed: &str) -> Result<(), ClientError> {
        if self.device.secret_key.matches_last_group(typed) {
            self.confirmed = true;
            Ok(())
        } else {
            Err(ClientError::EmergencyKitNotConfirmed)
        }
    }

    /// The recovery-only session's bearer token. Never log it.
    #[must_use]
    pub const fn bearer_token(&self) -> &SessionToken {
        &self.session_token
    }

    /// The commit (§11.9 step 6), only after the kit was confirmed. The same bytes on every
    /// call.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`].
    pub fn commit_request(&self) -> Result<&CommitChangeRequest, ClientError> {
        if self.confirmed {
            Ok(&self.request)
        } else {
            Err(ClientError::EmergencyKitNotConfirmed)
        }
    }

    /// The cache of the new device (ADR 0026 §1, §3), for the host to create once the server
    /// acknowledged the commit: the `cache_meta` rows, the device-state record, the account
    /// objects after the commit, and per vault the self-grant and the wrap set at the epoch of
    /// the vault key it holds.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`]; [`ClientError::Internal`].
    pub fn store_writes(&self) -> Result<Changeset, ClientError> {
        if !self.confirmed {
            return Err(ClientError::EmergencyKitNotConfirmed);
        }
        let mut changeset = store::create_writes(&self.device.record(Stage::Committed)?)?;
        changeset.append(store::object_writes(
            &self.device.pin,
            &self.certificates,
            &self.revocations,
            &self.served,
        ));
        for (vault_id, epoch, rows) in &self.wraps {
            changeset.push(Write::Wraps {
                vault_id: vault_id.to_bytes(),
                epoch: *epoch,
                wraps: wrap_rows(*vault_id, *epoch, rows),
            });
        }
        Ok(changeset)
    }

    /// After the server acknowledged the commit: the recovered device.
    ///
    /// # Errors
    /// [`ClientError::EmergencyKitNotConfirmed`] if the commit was never released.
    pub fn finalize(self) -> Result<RecoveryDone, ClientError> {
        if !self.confirmed {
            return Err(ClientError::EmergencyKitNotConfirmed);
        }
        Ok(RecoveryDone {
            device: self.device,
            unlocked: self.unlocked,
            vault_keys: self.vault_keys,
            certificates: self.certificates,
            revocations: self.revocations,
            authors: self.authors,
            dropped_items: self.dropped_items,
        })
    }
}
