// SPDX-License-Identifier: AGPL-3.0-only

//! The device state of an enrolled device, and the offline unlock (CRYPTO.md §4.2, §5.6,
//! §11.3 step 1).
//!
//! The device state is what a durable device (kinds 1–3) keeps between runs: `account_id`,
//! `device_id`, the Secret Key, `device_salt`, `kdf_id`, `E_local` with the epochs of its
//! context, `E_dev`, and the pin of the last verified account answer (§5.6 step 1).
//!
//! # The persistent form
//!
//! ADR 0013 §3 rule 2 lets the device state record leave the core "as opaque bytes for the host
//! to persist". [ADR 0026] §2 defines those bytes (record version 1);
//! [`crate::store::record::DeviceRecord`] is the codec, [`DeviceState::record`] the way out and
//! [`crate::store::record::DeviceRecord::to_state`] the way back in. The pin is not in the
//! record: it is rebuilt from the account objects of the cache at each load (ADR 0026 §4
//! step 5).
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md
//!
//! # What never leaves the device
//!
//! `E_local` and `E_dev` are never part of any request type (CRYPTO.md §4.2 "Where each
//! wrapped-key object lives"): no function of this crate copies them into a `rizzy-proto`
//! value, and the request types reject unknown fields.

use core::fmt;

use rizzy_core::envelope::purpose::{
    AccountKeyForwardCtx, AccountKeyKeystoreWrapCtx, AccountKeyLocalWrapCtx, DeviceSecretKeysCtx,
};
use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{
    AccountKey, DEVICE_SALT_LEN, DeviceKeys, KeystoreUnlockSecret, LocalUnlockKey,
};
use rizzy_core::normalize::ServerOrigin;
use rizzy_core::opaque::PasswordInput;
use rizzy_core::rng::CryptoRng;
use rizzy_core::secret_key::SecretKey;
use rizzy_core::sign::DeviceKind;

use crate::account::{AccountPin, VerifiedAccount};
use crate::error::ClientError;
use crate::store::record::{DeviceRecord, Stage};

/// `E_local` with the epochs of its context (CRYPTO.md §11.3 step 4.3: "store its ctx epochs
/// next to it (the reader rebuilds its ctx from those, not from the current state)").
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LocalWrap {
    /// The `ACCOUNT_KEY_LOCAL_WRAP` envelope.
    pub(crate) envelope: Vec<u8>,
    /// The epoch of the wrapped account key.
    pub(crate) account_key_epoch: u32,
    /// The password epoch of the local wrap.
    pub(crate) password_epoch: u32,
}

/// The most `ACCOUNT_KEY_FORWARD` envelopes a device state holds (ADR 0057 §2,
/// `forward_count ≤ 8`). A keystore-only unlock that would write a ninth is refused until a
/// password unlock collapses the chain (owner answer 2).
pub const MAX_FORWARD_COUNT: usize = 8;

/// `E_ks` with the epoch of its context (ADR 0057 §2 `[ks]`): the account key under the
/// keystore unlock secret (`ACCOUNT_KEY_KEYSTORE_WRAP`, CRYPTO.md §8.4). The secret itself is
/// never stored here (INV-82).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KeystoreWrap {
    /// The `ACCOUNT_KEY_KEYSTORE_WRAP` envelope.
    pub(crate) envelope: Vec<u8>,
    /// The epoch of the wrapped account key.
    pub(crate) account_key_epoch: u32,
}

/// One `ACCOUNT_KEY_FORWARD` envelope with the epochs of its context (ADR 0057 §2 `forward`):
/// the account key of `to_account_key_epoch` under the one of `from_account_key_epoch`,
/// written after a keystore unlock that crossed a rotation (CRYPTO.md §11.3 step 4.3).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ForwardWrap {
    /// The `ACCOUNT_KEY_FORWARD` envelope.
    pub(crate) envelope: Vec<u8>,
    /// The epoch of the wrapping (older) account key.
    pub(crate) from_account_key_epoch: u32,
    /// The epoch of the wrapped (newer) account key.
    pub(crate) to_account_key_epoch: u32,
}

/// The state of an enrolled device (see the module docs). Not `Clone`; `Debug` shows ids and
/// the pinned `state_seq` only.
pub struct DeviceState {
    /// The origin this device talks to; bound into device authentication (§5.10).
    pub(crate) server_origin: ServerOrigin,
    /// The account.
    pub(crate) account_id: AccountId,
    /// This device.
    pub(crate) device_id: DeviceId,
    /// Its kind (1–3).
    pub(crate) device_kind: DeviceKind,
    /// The Secret Key, held in plaintext until an OS keystore holds it (§4.2).
    pub(crate) secret_key: SecretKey,
    /// The salt of the local Argon2id run.
    pub(crate) device_salt: [u8; DEVICE_SALT_LEN],
    /// The local `kdf_id`, from this device's own state, never from the server (§5.6).
    pub(crate) kdf_id: KdfId,
    /// `E_local`.
    pub(crate) local_wrap: LocalWrap,
    /// `E_dev`.
    pub(crate) device_keys_wrap: Vec<u8>,
    /// `E_ks`, if keystore unlock is on (ADR 0057 §2).
    pub(crate) keystore_wrap: Option<KeystoreWrap>,
    /// The `ACCOUNT_KEY_FORWARD` chain from `E_local`'s epoch to the current account key,
    /// oldest first; empty unless a keystore unlock crossed a rotation (ADR 0057 §2).
    pub(crate) forward: Vec<ForwardWrap>,
    /// The pin of the last verified account answer.
    pub(crate) pin: AccountPin,
}

impl fmt::Debug for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceState")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("state_seq", &self.pin.state.state_seq)
            .finish_non_exhaustive()
    }
}

/// The inputs of [`DeviceState::create`].
pub(crate) struct NewDevice<'a> {
    /// The origin.
    pub(crate) server_origin: ServerOrigin,
    /// The account.
    pub(crate) account_id: AccountId,
    /// The new device's id.
    pub(crate) device_id: DeviceId,
    /// Its kind; must be durable.
    pub(crate) device_kind: DeviceKind,
    /// The Secret Key, moved in.
    pub(crate) secret_key: SecretKey,
    /// `pw_in` of the current password.
    pub(crate) pw_in: &'a PasswordInput,
    /// The current account key.
    pub(crate) account_key: &'a AccountKey,
    /// The account's current password epoch.
    pub(crate) password_epoch: u32,
    /// The new device keys.
    pub(crate) device_keys: &'a DeviceKeys,
    /// The pin to start from.
    pub(crate) pin: AccountPin,
}

impl DeviceState {
    /// Builds the state of a new durable device: a fresh `device_salt`, `E_local` under the
    /// local unlock key (one Argon2id run) and `E_dev` under the account key (CRYPTO.md §11.1
    /// step 7, §11.2 step 7).
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for a web-vault kind; [`ClientError::Internal`].
    pub(crate) fn create<R: CryptoRng + ?Sized>(
        rng: &mut R,
        new: NewDevice<'_>,
    ) -> Result<Self, ClientError> {
        if !new.device_kind.is_durable() {
            return Err(ClientError::InvalidInput);
        }
        let mut device_salt = [0u8; DEVICE_SALT_LEN];
        rng.fill_bytes(&mut device_salt);
        let kdf_id = KdfId::DEFAULT;
        let local = new
            .pw_in
            .local_unlock_key(&device_salt, kdf_id, new.account_id, new.device_id)
            .map_err(|_| ClientError::Internal)?;
        let local_wrap = wrap_local(
            rng,
            &local,
            new.account_id,
            new.device_id,
            kdf_id,
            new.account_key,
            new.password_epoch,
        )?;
        let device_keys_wrap = new
            .account_key
            .wrap_device_keys(
                rng,
                &DeviceSecretKeysCtx {
                    account_id: new.account_id,
                    device_id: new.device_id,
                },
                new.device_keys,
            )
            .map_err(|_| ClientError::Internal)?;
        Ok(Self {
            server_origin: new.server_origin,
            account_id: new.account_id,
            device_id: new.device_id,
            device_kind: new.device_kind,
            secret_key: new.secret_key,
            device_salt,
            kdf_id,
            local_wrap,
            device_keys_wrap,
            keystore_wrap: None,
            forward: Vec::new(),
            pin: new.pin,
        })
    }

    /// The account.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// This device.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// This device's kind (1–3).
    #[must_use]
    pub const fn device_kind(&self) -> DeviceKind {
        self.device_kind
    }

    /// The server origin this device is enrolled with.
    #[must_use]
    pub const fn server_origin(&self) -> &ServerOrigin {
        &self.server_origin
    }

    /// The pin of the last verified account answer.
    #[must_use]
    pub const fn pin(&self) -> &AccountPin {
        &self.pin
    }

    /// The offline part of an unlock (CRYPTO.md §5.6, §11.3 step 1): `pw_in` from the password
    /// and the stored Secret Key, the local unlock key (one Argon2id run), `E_local` with the
    /// context rebuilt from the epochs stored next to it, then `E_dev`. The `kdf_id` is this
    /// device's own, never the server's.
    ///
    /// A failed unlock never starts an online attempt by itself (§11.3 step 5).
    ///
    /// # Errors
    /// [`ClientError::WrongPasswordOrSecretKey`] when `E_local` does not open;
    /// [`ClientError::InvalidInput`] for an absurdly long password;
    /// [`ClientError::CacheCorrupt`] when `E_dev` does not open under the key `E_local` gave
    /// (damaged state, ADR 0026 §5 (d)).
    pub fn unlock(&self, password: &str) -> Result<UnlockedDevice, ClientError> {
        offline_unlock(
            password,
            &OfflineUnlock {
                account_id: self.account_id,
                device_id: self.device_id,
                secret_key: &self.secret_key,
                device_salt: &self.device_salt,
                kdf_id: self.kdf_id,
                local_wrap: &self.local_wrap,
                forward: &self.forward,
                device_keys_wrap: &self.device_keys_wrap,
            },
        )
    }

    /// The keystore unlock (CRYPTO.md §5.6 step 3, §11.3 step 1; ADR 0057 §2): `secret` is the
    /// keystore unlock secret the OS released after its user-presence check. It opens `E_ks`
    /// with the context rebuilt from the epoch stored next to it, then `E_dev`. No Argon2id runs
    /// and `E_local` is not opened.
    ///
    /// # Errors
    /// [`ClientError::KeystoreUnlockUnavailable`] without `E_ks`, or when `E_ks` does not open
    /// under `secret` (a stale or replaced keystore item): the host falls back to the password;
    /// [`ClientError::InvalidInput`] unless `secret` is 32 bytes; [`ClientError::CacheCorrupt`]
    /// when `E_dev` does not open under the key `E_ks` gave.
    pub fn unlock_keystore(&self, secret: &[u8]) -> Result<UnlockedDevice, ClientError> {
        keystore_unlock(
            secret,
            self.account_id,
            self.device_id,
            self.keystore_wrap.as_ref(),
            &self.device_keys_wrap,
        )
    }

    /// Whether `E_ks` is present (keystore unlock is on).
    #[must_use]
    pub const fn has_keystore(&self) -> bool {
        self.keystore_wrap.is_some()
    }

    /// How many `ACCOUNT_KEY_FORWARD` envelopes the state holds.
    #[must_use]
    pub const fn forward_count(&self) -> usize {
        self.forward.len()
    }

    /// The device-state record of this state (ADR 0026 §2), without a pending record: what
    /// the host persists. `stage` is [`Stage::SignupPending`] only between a signup's kit
    /// confirmation and the server's acknowledgement.
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub fn record(&self, stage: Stage) -> Result<DeviceRecord, ClientError> {
        Ok(DeviceRecord {
            stage,
            server_origin: self.server_origin.clone(),
            account_id: self.account_id,
            device_id: self.device_id,
            device_kind: self.device_kind,
            secret_key: SecretKey::from_slice(self.secret_key.expose_secret())
                .map_err(|_| ClientError::Internal)?,
            device_salt: self.device_salt,
            kdf_id: self.kdf_id,
            device_keys_wrap: self.device_keys_wrap.clone(),
            local_wrap: Some(self.local_wrap.clone()),
            keystore_wrap: self.keystore_wrap.clone(),
            forward: self.forward.clone(),
            pending: None,
        })
    }

    /// The password epoch of `E_local`.
    pub(crate) const fn local_password_epoch(&self) -> u32 {
        self.local_wrap.password_epoch
    }

    /// Adopts a verified account answer as the new pin. The answer passed the rollback and
    /// fork checks against the current pin, so the pinned `state_seq` never goes down.
    pub(crate) fn adopt(&mut self, account: &VerifiedAccount) {
        if account.pin.state.state_seq >= self.pin.state.state_seq {
            self.pin = account.pin.clone();
        }
    }

    /// Re-wraps `E_local`, `E_ks` (if present) and `E_dev` under a new account key after a
    /// password unlock (CRYPTO.md §11.3 step 4.3, or an own rotation). Needs the local unlock key
    /// kept from the password unlock. The forward chain `E_local` now no longer needs is
    /// dropped; `E_ks` is handled by [`DeviceState::rewrap_keystore`] with `keystore`.
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub(crate) fn rewrap<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        local: &LocalUnlockKey,
        keystore: Option<&KeystoreUnlockSecret>,
        account_key: &AccountKey,
        device_keys: &DeviceKeys,
    ) -> Result<(), ClientError> {
        let local_wrap = wrap_local(
            rng,
            local,
            self.account_id,
            self.device_id,
            self.kdf_id,
            account_key,
            self.local_wrap.password_epoch,
        )?;
        let device_keys_wrap = self.wrap_device_keys(rng, account_key, device_keys)?;
        self.set_local_wrap(local_wrap);
        self.device_keys_wrap = device_keys_wrap;
        self.rewrap_keystore(rng, keystore, account_key)
    }

    /// `E_dev` of `device_keys` under `account_key`.
    fn wrap_device_keys<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        account_key: &AccountKey,
        device_keys: &DeviceKeys,
    ) -> Result<Vec<u8>, ClientError> {
        account_key
            .wrap_device_keys(
                rng,
                &DeviceSecretKeysCtx {
                    account_id: self.account_id,
                    device_id: self.device_id,
                },
                device_keys,
            )
            .map_err(|_| ClientError::Internal)
    }

    /// Replaces `E_local` with a wrap of the current account key (a re-wrap, a credential
    /// change, an own rotation). The forward envelopes up to its epoch are no longer needed and
    /// are deleted (CRYPTO.md §11.3 step 4.3: "re-wrap `E_local` and delete the forward
    /// envelopes"); any that start at or after it stay, so the chain still starts at `E_local`.
    pub(crate) fn set_local_wrap(&mut self, local_wrap: LocalWrap) {
        let epoch = local_wrap.account_key_epoch;
        self.forward
            .retain(|step| step.from_account_key_epoch >= epoch);
        self.local_wrap = local_wrap;
    }

    /// The account-key epoch the forward chain reaches: the newest key this state's `E_local`
    /// leads to.
    fn chain_end(&self) -> u32 {
        self.forward
            .last()
            .map_or(self.local_wrap.account_key_epoch, |step| {
                step.to_account_key_epoch
            })
    }

    /// Keeps `E_ks` on the account key `account_key` after the key changed (CRYPTO.md §11.3
    /// step 4.3, an own rotation). With the keystore unlock secret (kept from a keystore unlock,
    /// or attached by the host with [`UnlockedDevice::attach_keystore_secret`]) that opens the
    /// current `E_ks`, `E_ks` is re-wrapped. Without one, `E_ks` is deleted (`has_ks → 0`):
    /// an `E_ks` under a retired key would open a key `E_dev` no longer matches. The host then
    /// sees [`DeviceState::has_keystore`] turn false, deletes its keystore item and may offer to
    /// turn keystore unlock on again.
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub(crate) fn rewrap_keystore<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        keystore: Option<&KeystoreUnlockSecret>,
        account_key: &AccountKey,
    ) -> Result<(), ClientError> {
        let Some(current) = self.keystore_wrap.as_ref() else {
            return Ok(());
        };
        if current.account_key_epoch == account_key.epoch() {
            return Ok(());
        }
        let opens = keystore.is_some_and(|secret| {
            secret
                .unwrap_account_key(
                    &AccountKeyKeystoreWrapCtx {
                        account_id: self.account_id,
                        device_id: self.device_id,
                        account_key_epoch: current.account_key_epoch,
                    },
                    &current.envelope,
                )
                .is_ok()
        });
        self.keystore_wrap = match keystore {
            Some(secret) if opens => Some(self.wrap_keystore(rng, secret, account_key)?),
            _ => None,
        };
        Ok(())
    }

    /// `E_ks` of `account_key` under `secret`.
    fn wrap_keystore<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        secret: &KeystoreUnlockSecret,
        account_key: &AccountKey,
    ) -> Result<KeystoreWrap, ClientError> {
        let envelope = secret
            .wrap_account_key(
                rng,
                &AccountKeyKeystoreWrapCtx {
                    account_id: self.account_id,
                    device_id: self.device_id,
                    account_key_epoch: account_key.epoch(),
                },
                account_key,
            )
            .map_err(|_| ClientError::Internal)?;
        Ok(KeystoreWrap {
            envelope,
            account_key_epoch: account_key.epoch(),
        })
    }

    /// Re-wraps after a **keystore** unlock that crossed a rotation (CRYPTO.md §11.3 step 4.3):
    /// `E_ks` and `E_dev` under `new_key`, `E_local` unchanged, and an `ACCOUNT_KEY_FORWARD`
    /// envelope from `old_key` (the key `E_ks` gave) to `new_key` appended to the chain, which
    /// the next password unlock follows and deletes.
    ///
    /// # Errors
    /// [`ClientError::KeystoreUnlockUnavailable`] when the chain already holds
    /// [`MAX_FORWARD_COUNT`] envelopes (ADR 0057 owner answer 2): nothing is changed, the device
    /// stays read-only on this path and the host asks for the password;
    /// [`ClientError::CacheCorrupt`] when the chain does not end at `old_key`'s epoch;
    /// [`ClientError::Internal`].
    pub(crate) fn rewrap_after_keystore_unlock<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        secret: &KeystoreUnlockSecret,
        old_key: &AccountKey,
        new_key: &AccountKey,
        device_keys: &DeviceKeys,
    ) -> Result<(), ClientError> {
        if self.forward.len() >= MAX_FORWARD_COUNT {
            return Err(ClientError::KeystoreUnlockUnavailable);
        }
        if self.keystore_wrap.is_none() {
            return Err(ClientError::KeystoreUnlockUnavailable);
        }
        if self.chain_end() != old_key.epoch() {
            return Err(ClientError::CacheCorrupt);
        }
        let ctx = AccountKeyForwardCtx {
            account_id: self.account_id,
            device_id: self.device_id,
            from_account_key_epoch: old_key.epoch(),
            to_account_key_epoch: new_key.epoch(),
        };
        let forward = old_key
            .wrap_forward(rng, &ctx, new_key)
            .map_err(|_| ClientError::Internal)?;
        let keystore_wrap = self.wrap_keystore(rng, secret, new_key)?;
        let device_keys_wrap = self.wrap_device_keys(rng, new_key, device_keys)?;
        self.forward.push(ForwardWrap {
            envelope: forward,
            from_account_key_epoch: ctx.from_account_key_epoch,
            to_account_key_epoch: ctx.to_account_key_epoch,
        });
        self.keystore_wrap = Some(keystore_wrap);
        self.device_keys_wrap = device_keys_wrap;
        Ok(())
    }

    /// Turns keystore unlock on (ADR 0057 §2, CRYPTO.md §4.2): a fresh keystore unlock secret
    /// from the injected CSPRNG, and `E_ks` of the unlocked account key under it. The secret is
    /// returned for the host to store in its OS keystore behind a user-presence check
    /// (INV-62); it never enters the record or the cache (INV-82). An `E_ks` already present
    /// is replaced (the host deletes the old keystore item).
    ///
    /// The host stores the secret first and persists the record after; if storing fails it calls
    /// [`DeviceState::disable_keystore`]. A record with `E_ks` is admitted only by floors whose
    /// platform gate is on ([`crate::store::floors::Floors::set_keystore_capable`], INV-81), so
    /// a host without a presence-enforcing keystore cannot persist one.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for keys of another account or device, or keys not of the
    /// newest account key this state's `E_local` and forward chain lead to;
    /// [`ClientError::Internal`].
    pub fn enable_keystore<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
    ) -> Result<KeystoreUnlockSecret, ClientError> {
        if unlocked.account_id != self.account_id
            || unlocked.device_id != self.device_id
            || unlocked.account_key.epoch() != self.chain_end()
        {
            return Err(ClientError::InvalidInput);
        }
        let secret = KeystoreUnlockSecret::generate(rng, self.account_id, self.device_id);
        self.keystore_wrap = Some(self.wrap_keystore(rng, &secret, &unlocked.account_key)?);
        Ok(secret)
    }

    /// Turns keystore unlock off: `E_ks` is deleted (`has_ks → 0`; CRYPTO.md §4.2 "deleted
    /// when the user turns keystore unlock off"). The forward chain stays: only the next
    /// password unlock clears it (ADR 0057 §2). The host deletes its keystore item.
    pub fn disable_keystore(&mut self) {
        self.keystore_wrap = None;
    }

    /// After a **password** unlock and an account answer that verified ([`crate::unlock::verify_unlock`])
    /// without a rotation: re-wraps `E_local` under the account key the forward chain led to and
    /// deletes the chain (CRYPTO.md §11.3 step 4.3, "At the next password unlock …"). Returns
    /// whether the state changed, so the host persists the record. No Argon2id runs: the local
    /// unlock key kept from the unlock is used.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] for keys of another device or without the local unlock
    /// key (a keystore unlock, or [`UnlockedDevice::forget_unlock_key`] ran);
    /// [`ClientError::AccountKeyRotated`] when the pinned state names a newer account key (the
    /// host runs the device-grant path, which collapses the chain too);
    /// [`ClientError::CacheCorrupt`] when the key is not the one the pinned state names;
    /// [`ClientError::Internal`].
    pub fn collapse_forward<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        unlocked: &UnlockedDevice,
    ) -> Result<bool, ClientError> {
        if unlocked.account_id != self.account_id || unlocked.device_id != self.device_id {
            return Err(ClientError::InvalidInput);
        }
        if self.forward.is_empty() {
            return Ok(false);
        }
        let local = unlocked
            .local_unlock_key
            .as_ref()
            .ok_or(ClientError::InvalidInput)?;
        let state = &self.pin.state;
        if state.account_key_epoch > unlocked.account_key.epoch() {
            return Err(ClientError::AccountKeyRotated);
        }
        if !state.matches_account_key(&unlocked.account_key) {
            return Err(ClientError::CacheCorrupt);
        }
        let local_wrap = wrap_local(
            rng,
            local,
            self.account_id,
            self.device_id,
            self.kdf_id,
            &unlocked.account_key,
            self.local_wrap.password_epoch,
        )?;
        self.set_local_wrap(local_wrap);
        Ok(true)
    }
}

/// What the offline unlock reads (CRYPTO.md §5.6): the fields of a device state or of a
/// device-state record ([`DeviceRecord`]), base or pending.
pub(crate) struct OfflineUnlock<'a> {
    /// The account.
    pub(crate) account_id: AccountId,
    /// The device.
    pub(crate) device_id: DeviceId,
    /// The Secret Key.
    pub(crate) secret_key: &'a SecretKey,
    /// The salt of the local Argon2id run.
    pub(crate) device_salt: &'a [u8; DEVICE_SALT_LEN],
    /// The local `kdf_id`.
    pub(crate) kdf_id: KdfId,
    /// `E_local` and the epochs of its context.
    pub(crate) local_wrap: &'a LocalWrap,
    /// The `ACCOUNT_KEY_FORWARD` chain from `E_local`'s epoch, oldest first.
    pub(crate) forward: &'a [ForwardWrap],
    /// `E_dev`.
    pub(crate) device_keys_wrap: &'a [u8],
}

/// The offline unlock (CRYPTO.md §5.6, §11.3 step 1): `pw_in`, the local unlock key (one
/// Argon2id run), `E_local` with its context rebuilt from the stored epochs, then `E_dev`.
///
/// # Errors
/// [`ClientError::WrongPasswordOrSecretKey`] when `E_local` does not open (a wrong password
/// and a damaged `E_local` look the same, ADR 0026 §5 (c)); [`ClientError::InvalidInput`] for
/// an absurdly long password; [`ClientError::CacheCorrupt`] when `E_dev` does not open under
/// the key `E_local` gave (ADR 0026 §5 (d)); [`ClientError::Internal`].
pub(crate) fn offline_unlock(
    password: &str,
    fields: &OfflineUnlock<'_>,
) -> Result<UnlockedDevice, ClientError> {
    let pw_in = PasswordInput::derive(password, fields.secret_key)
        .map_err(|_| ClientError::InvalidInput)?;
    let local = pw_in
        .local_unlock_key(
            fields.device_salt,
            fields.kdf_id,
            fields.account_id,
            fields.device_id,
        )
        .map_err(|_| ClientError::Internal)?;
    let ctx = AccountKeyLocalWrapCtx {
        account_id: fields.account_id,
        device_id: fields.device_id,
        account_key_epoch: fields.local_wrap.account_key_epoch,
        password_epoch: fields.local_wrap.password_epoch,
        kdf_id: fields.kdf_id,
    };
    let account_key = local
        .unwrap_account_key(&ctx, &fields.local_wrap.envelope)
        .map_err(|_| ClientError::WrongPasswordOrSecretKey)?;
    let account_key = follow_forward(
        fields.account_id,
        fields.device_id,
        account_key,
        fields.forward,
    )?;
    let device_keys = account_key
        .unwrap_device_keys(
            &DeviceSecretKeysCtx {
                account_id: fields.account_id,
                device_id: fields.device_id,
            },
            fields.device_keys_wrap,
        )
        .map_err(|_| ClientError::CacheCorrupt)?;
    Ok(UnlockedDevice {
        account_id: fields.account_id,
        device_id: fields.device_id,
        account_key,
        device_keys,
        local_unlock_key: Some(local),
        keystore_secret: None,
    })
}

/// Follows the `ACCOUNT_KEY_FORWARD` chain from the key `E_local` gave to the newest one
/// (CRYPTO.md §5.6 step 3, §11.3 step 4.3). Each envelope must start at the epoch the previous
/// one reached; the caller checks the final key against `state.account_key_id` online.
///
/// # Errors
/// [`ClientError::CacheCorrupt`] for a broken chain or an envelope that does not open: the
/// password was right (`E_local` opened), so the state is damaged (ADR 0026 §5 (d)).
pub(crate) fn follow_forward(
    account_id: AccountId,
    device_id: DeviceId,
    mut account_key: AccountKey,
    forward: &[ForwardWrap],
) -> Result<AccountKey, ClientError> {
    for step in forward {
        if step.from_account_key_epoch != account_key.epoch() {
            return Err(ClientError::CacheCorrupt);
        }
        account_key = account_key
            .unwrap_forward(
                &AccountKeyForwardCtx {
                    account_id,
                    device_id,
                    from_account_key_epoch: step.from_account_key_epoch,
                    to_account_key_epoch: step.to_account_key_epoch,
                },
                &step.envelope,
            )
            .map_err(|_| ClientError::CacheCorrupt)?;
    }
    Ok(account_key)
}

/// The keystore unlock (CRYPTO.md §5.6 step 3): `E_ks` under the released secret, then
/// `E_dev`. The secret is kept in the returned [`UnlockedDevice`] until the online part is
/// done, to re-wrap `E_ks` if it crosses a rotation (§11.3 step 4.3).
///
/// # Errors
/// As [`DeviceState::unlock_keystore`].
pub(crate) fn keystore_unlock(
    secret: &[u8],
    account_id: AccountId,
    device_id: DeviceId,
    keystore_wrap: Option<&KeystoreWrap>,
    device_keys_wrap: &[u8],
) -> Result<UnlockedDevice, ClientError> {
    let keystore_wrap = keystore_wrap.ok_or(ClientError::KeystoreUnlockUnavailable)?;
    let secret = KeystoreUnlockSecret::from_slice(secret, account_id, device_id)
        .map_err(|_| ClientError::InvalidInput)?;
    let account_key = secret
        .unwrap_account_key(
            &AccountKeyKeystoreWrapCtx {
                account_id,
                device_id,
                account_key_epoch: keystore_wrap.account_key_epoch,
            },
            &keystore_wrap.envelope,
        )
        .map_err(|_| ClientError::KeystoreUnlockUnavailable)?;
    let device_keys = account_key
        .unwrap_device_keys(
            &DeviceSecretKeysCtx {
                account_id,
                device_id,
            },
            device_keys_wrap,
        )
        .map_err(|_| ClientError::CacheCorrupt)?;
    Ok(UnlockedDevice {
        account_id,
        device_id,
        account_key,
        device_keys,
        local_unlock_key: None,
        keystore_secret: Some(secret),
    })
}

/// `E_local` of `account_key` under `local`.
pub(crate) fn wrap_local<R: CryptoRng + ?Sized>(
    rng: &mut R,
    local: &LocalUnlockKey,
    account_id: AccountId,
    device_id: DeviceId,
    kdf_id: KdfId,
    account_key: &AccountKey,
    password_epoch: u32,
) -> Result<LocalWrap, ClientError> {
    let ctx = AccountKeyLocalWrapCtx {
        account_id,
        device_id,
        account_key_epoch: account_key.epoch(),
        password_epoch,
        kdf_id,
    };
    let envelope = local
        .wrap_account_key(rng, &ctx, account_key)
        .map_err(|_| ClientError::Internal)?;
    Ok(LocalWrap {
        envelope,
        account_key_epoch: account_key.epoch(),
        password_epoch,
    })
}

/// An unlocked device: the account key and the device keys, in memory only (ADR 0013 §3
/// rule 1: keys stay in Rust, hosts hold a handle). Dropping it wipes them.
pub struct UnlockedDevice {
    /// The account.
    pub(crate) account_id: AccountId,
    /// This device.
    pub(crate) device_id: DeviceId,
    /// The account key.
    pub(crate) account_key: AccountKey,
    /// The device keys.
    pub(crate) device_keys: DeviceKeys,
    /// The local unlock key, kept until the online part is done (§11.3 step 4.3).
    pub(crate) local_unlock_key: Option<LocalUnlockKey>,
    /// The keystore unlock secret, kept until the online part is done (§11.3 step 4.3): set by
    /// a keystore unlock, or attached by the host after a password unlock.
    pub(crate) keystore_secret: Option<KeystoreUnlockSecret>,
}

impl fmt::Debug for UnlockedDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedDevice")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl UnlockedDevice {
    /// The account.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// This device.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The epoch of the account key these keys hold. Public protocol data (it is in the signed
    /// `account-state`); a host compares it with the epochs of pending device grants.
    #[must_use]
    pub const fn account_key_epoch(&self) -> u32 {
        self.account_key.epoch()
    }

    /// Whether these keys came from a keystore unlock, or a keystore unlock secret was attached
    /// (it is kept until [`UnlockedDevice::forget_unlock_key`]).
    #[must_use]
    pub const fn has_keystore_secret(&self) -> bool {
        self.keystore_secret.is_some()
    }

    /// Attaches the keystore unlock secret the OS released, after a **password** unlock, so that
    /// a rotation crossed in the online part re-wraps `E_ks` instead of deleting it (CRYPTO.md
    /// §11.3 step 4.3: "After a password unlock … re-wrap `E_local`, `E_ks` (if present) and
    /// `E_dev`"). Optional: a host that does not want a second presence prompt skips it, and
    /// `E_ks` is then deleted at the re-wrap. A secret that does not open `E_ks` is treated the
    /// same way.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] unless `secret` is 32 bytes.
    pub fn attach_keystore_secret(&mut self, secret: &[u8]) -> Result<(), ClientError> {
        self.keystore_secret = Some(
            KeystoreUnlockSecret::from_slice(secret, self.account_id, self.device_id)
                .map_err(|_| ClientError::InvalidInput)?,
        );
        Ok(())
    }

    /// Drops the local unlock key and the keystore unlock secret once the online part of the
    /// unlock is done.
    pub fn forget_unlock_key(&mut self) {
        self.local_unlock_key = None;
        self.keystore_secret = None;
    }
}
