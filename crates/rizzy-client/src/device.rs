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

use rizzy_core::envelope::purpose::{AccountKeyLocalWrapCtx, DeviceSecretKeysCtx};
use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_core::kdf::KdfId;
use rizzy_core::keys::{AccountKey, DEVICE_SALT_LEN, DeviceKeys, LocalUnlockKey};
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
                device_keys_wrap: &self.device_keys_wrap,
            },
        )
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

    /// Re-wraps `E_local` and `E_dev` under a new account key after grants delivered it
    /// (CRYPTO.md §11.3 step 4.3). Needs the local unlock key kept from the password unlock.
    ///
    /// # Errors
    /// [`ClientError::Internal`].
    pub(crate) fn rewrap<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        local: &LocalUnlockKey,
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
        let device_keys_wrap = account_key
            .wrap_device_keys(
                rng,
                &DeviceSecretKeysCtx {
                    account_id: self.account_id,
                    device_id: self.device_id,
                },
                device_keys,
            )
            .map_err(|_| ClientError::Internal)?;
        self.local_wrap = local_wrap;
        self.device_keys_wrap = device_keys_wrap;
        Ok(())
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

    /// Drops the local unlock key once the online part of the unlock is done.
    pub fn forget_unlock_key(&mut self) {
        self.local_unlock_key = None;
    }
}
