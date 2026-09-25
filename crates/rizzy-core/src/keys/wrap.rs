//! The symmetric wrapped-key objects of M1 (CRYPTO.md §4.2, §8.4, §8.5).
//!
//! Every wrap checks, before sealing, that the context describes the keys being wrapped (the
//! epochs and ids the keys carry). Every unwrap checks, before any crypto, that the unwrapping
//! key is the one the context names, then opens the envelope (commitment first), then checks
//! the plaintext layout. All unwrap failures are the same [`DecryptError`].

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use super::{
    AccountKey, DeviceKeys, IdentityKeys, ItemKey, LocalUnlockKey, RecoveryWrapKey,
    RetiredSecretKey, ServerUnlockKey, VaultKey,
};
use crate::encoding::Reader;
use crate::envelope::purpose::{
    AccountKeyLocalWrapCtx, AccountKeyRecoveryWrapCtx, AccountKeyServerWrapCtx,
    DeviceSecretKeysCtx, IdentitySecretKeysCtx, ItemKeyWrapCtx, RetiredSecretKeyCtx,
    VaultKeySelfGrantCtx,
};
use crate::envelope::{open, seal};
use crate::error::{DecryptError, EncryptError};
use crate::hpke::{HpkeSecretKey, X25519_SECRET_KEY_LEN};
use crate::ids::KeyType;
use crate::secret::{KEY_LEN, Key32};
use crate::sign::{DeviceSigningKey, IdentitySigningKey, SEED_LEN};

/// `wrap_version` of the `ITEM_KEY_WRAP` plaintext (§8.4).
pub const ITEM_KEY_WRAP_VERSION: u8 = 1;

/// `version` of the `DEVICE_SECRET_KEYS` plaintext (§8.4).
pub const DEVICE_SECRET_KEYS_VERSION: u8 = 1;

/// `ITEM_KEY_WRAP` plaintext length: `u8 wrap_version ‖ u32 created_vault_key_epoch ‖ key`.
const ITEM_KEY_WRAP_LEN: usize = 1 + 4 + KEY_LEN;
/// `IDENTITY_SECRET_KEYS` plaintext length: `ed25519_seed ‖ x25519_sk` (§11.1 step 5).
const IDENTITY_SECRET_KEYS_LEN: usize = SEED_LEN + X25519_SECRET_KEY_LEN;
/// `DEVICE_SECRET_KEYS` plaintext length: `u8 version ‖ ed25519_seed ‖ x25519_sk`.
const DEVICE_SECRET_KEYS_LEN: usize = 1 + SEED_LEN + X25519_SECRET_KEY_LEN;
/// `RETIRED_SECRET_KEY` plaintext length: `u8 key_type ‖ secret key`.
const RETIRED_SECRET_KEY_LEN: usize = 1 + X25519_SECRET_KEY_LEN;

const _: () = assert!(
    ITEM_KEY_WRAP_LEN == 37
        && IDENTITY_SECRET_KEYS_LEN == 64
        && DEVICE_SECRET_KEYS_LEN == 65
        && RETIRED_SECRET_KEY_LEN == 33
);

fn account_key_from(plaintext: &[u8], epoch: u32) -> Result<AccountKey, DecryptError> {
    Ok(AccountKey::from_key(Key32::from_slice(plaintext)?, epoch))
}

/// Splits `ed25519_seed ‖ x25519_sk` and rebuilds both keys. Temporary copies are wiped.
fn key_pair_from(bytes: &[u8]) -> Result<(Zeroizing<[u8; SEED_LEN]>, HpkeSecretKey), DecryptError> {
    let mut r = Reader::new(bytes);
    let seed = Zeroizing::new(*r.array::<SEED_LEN>()?);
    let sk = Zeroizing::new(*r.array::<X25519_SECRET_KEY_LEN>()?);
    r.finish()?;
    Ok((seed, HpkeSecretKey::from_x25519_bytes(&sk)?))
}

impl ServerUnlockKey {
    /// Builds `E_srv`: the account key under `server_unlock_key` (`ACCOUNT_KEY_SERVER_WRAP`,
    /// ctx `account_id ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id`).
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another account or account-key epoch.
    pub fn wrap_account_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &AccountKeyServerWrapCtx,
        account_key: &AccountKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.account_id != self.account_id || ctx.account_key_epoch != account_key.epoch() {
            return Err(EncryptError::ContextMismatch);
        }
        seal(rng, &self.key, ctx, account_key.key().expose_secret())
    }

    /// Opens `E_srv`. The account key gets the epoch `ctx` names.
    ///
    /// # Errors
    /// [`DecryptError`], including for a context of another account.
    pub fn unwrap_account_key(
        &self,
        ctx: &AccountKeyServerWrapCtx,
        envelope: &[u8],
    ) -> Result<AccountKey, DecryptError> {
        if ctx.account_id != self.account_id {
            return Err(DecryptError);
        }
        let plaintext = open(&self.key, ctx, envelope)?;
        account_key_from(plaintext.expose_secret(), ctx.account_key_epoch)
    }
}

impl LocalUnlockKey {
    /// Builds `E_local`: the account key under `local_unlock_key` (`ACCOUNT_KEY_LOCAL_WRAP`,
    /// ctx `account_id ‖ device_id ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id`).
    /// Device-local only; never uploaded.
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another account, device or account-key
    /// epoch.
    pub fn wrap_account_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &AccountKeyLocalWrapCtx,
        account_key: &AccountKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.account_id != self.account_id
            || ctx.device_id != self.device_id
            || ctx.account_key_epoch != account_key.epoch()
        {
            return Err(EncryptError::ContextMismatch);
        }
        seal(rng, &self.key, ctx, account_key.key().expose_secret())
    }

    /// Opens `E_local`, with the ctx rebuilt from the epochs stored next to it (§5.6). A wrong
    /// password shows up here as a [`DecryptError`].
    ///
    /// # Errors
    /// [`DecryptError`], including for a context of another account or device.
    pub fn unwrap_account_key(
        &self,
        ctx: &AccountKeyLocalWrapCtx,
        envelope: &[u8],
    ) -> Result<AccountKey, DecryptError> {
        if ctx.account_id != self.account_id || ctx.device_id != self.device_id {
            return Err(DecryptError);
        }
        let plaintext = open(&self.key, ctx, envelope)?;
        account_key_from(plaintext.expose_secret(), ctx.account_key_epoch)
    }
}

impl RecoveryWrapKey {
    /// Builds `E_rec`: the account key under the recovery wrap key
    /// (`ACCOUNT_KEY_RECOVERY_WRAP`, ctx `account_id ‖ u32 account_key_epoch ‖ u32
    /// recovery_epoch`).
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another account-key epoch.
    pub fn wrap_account_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &AccountKeyRecoveryWrapCtx,
        account_key: &AccountKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.account_key_epoch != account_key.epoch() {
            return Err(EncryptError::ContextMismatch);
        }
        seal(rng, &self.key, ctx, account_key.key().expose_secret())
    }

    /// Opens `E_rec`. The caller then checks the key's id against `state.account_key_id`
    /// (§11.9 step 4).
    ///
    /// # Errors
    /// [`DecryptError`].
    pub fn unwrap_account_key(
        &self,
        ctx: &AccountKeyRecoveryWrapCtx,
        envelope: &[u8],
    ) -> Result<AccountKey, DecryptError> {
        let plaintext = open(&self.key, ctx, envelope)?;
        account_key_from(plaintext.expose_secret(), ctx.account_key_epoch)
    }
}

impl AccountKey {
    /// Builds `E_id`: `ed25519_seed ‖ x25519_sk` under the account key
    /// (`IDENTITY_SECRET_KEYS`, ctx `account_id ‖ u32 identity_epoch`).
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another identity epoch than the keys'.
    pub fn wrap_identity_keys<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &IdentitySecretKeysCtx,
        keys: &IdentityKeys,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.identity_epoch != keys.epoch() {
            return Err(EncryptError::ContextMismatch);
        }
        let mut plaintext = Zeroizing::new([0u8; IDENTITY_SECRET_KEYS_LEN]);
        let (seed, sk) = plaintext.split_at_mut(SEED_LEN);
        keys.signing_key()
            .write_seed(seed.try_into().map_err(|_| EncryptError::Internal)?);
        keys.kem_key()
            .write_secret(sk.try_into().map_err(|_| EncryptError::Internal)?);
        seal(rng, self.key(), ctx, plaintext.as_slice())
    }

    /// Opens `E_id`. The keys get the identity epoch `ctx` names. The caller then compares
    /// their public halves with the published bundle (§11.2 step 6).
    ///
    /// # Errors
    /// [`DecryptError`].
    pub fn unwrap_identity_keys(
        &self,
        ctx: &IdentitySecretKeysCtx,
        envelope: &[u8],
    ) -> Result<IdentityKeys, DecryptError> {
        let plaintext = open(self.key(), ctx, envelope)?;
        let (seed, kem) = key_pair_from(plaintext.expose_secret())?;
        Ok(IdentityKeys {
            signing: IdentitySigningKey::from_seed(&seed),
            kem,
            epoch: ctx.identity_epoch,
        })
    }

    /// Builds `E_dev`: `u8 version = 1 ‖ ed25519_seed ‖ x25519_sk` under the account key
    /// (`DEVICE_SECRET_KEYS`, ctx `account_id ‖ device_id`). For local storage only: never
    /// uploaded (§4.2, §11.1 step 8).
    ///
    /// # Errors
    /// [`EncryptError::Internal`] (unreachable).
    pub fn wrap_device_keys<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &DeviceSecretKeysCtx,
        keys: &DeviceKeys,
    ) -> Result<Vec<u8>, EncryptError> {
        let mut plaintext = Zeroizing::new([0u8; DEVICE_SECRET_KEYS_LEN]);
        let (version, rest) = plaintext.split_at_mut(1);
        let (seed, sk) = rest.split_at_mut(SEED_LEN);
        version.copy_from_slice(&[DEVICE_SECRET_KEYS_VERSION]);
        keys.signing_key()
            .write_seed(seed.try_into().map_err(|_| EncryptError::Internal)?);
        keys.kem_key()
            .write_secret(sk.try_into().map_err(|_| EncryptError::Internal)?);
        seal(rng, self.key(), ctx, plaintext.as_slice())
    }

    /// Opens `E_dev`. A `version` other than 1 is rejected.
    ///
    /// # Errors
    /// [`DecryptError`].
    pub fn unwrap_device_keys(
        &self,
        ctx: &DeviceSecretKeysCtx,
        envelope: &[u8],
    ) -> Result<DeviceKeys, DecryptError> {
        let plaintext = open(self.key(), ctx, envelope)?;
        let (version, keys) = plaintext
            .expose_secret()
            .split_first()
            .ok_or(DecryptError)?;
        if *version != DEVICE_SECRET_KEYS_VERSION {
            return Err(DecryptError);
        }
        let (seed, kem) = key_pair_from(keys)?;
        Ok(DeviceKeys {
            signing: DeviceSigningKey::from_seed(&seed),
            kem,
        })
    }

    /// Builds a `VAULT_KEY_SELF_GRANT`: the vault key under this account key (ctx `account_id ‖
    /// vault_id ‖ u32 account_key_epoch ‖ u32 vault_key_epoch`).
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another vault, vault-key epoch or
    /// account-key epoch than the keys'.
    pub fn wrap_vault_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &VaultKeySelfGrantCtx,
        vault_key: &VaultKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.account_key_epoch != self.epoch()
            || ctx.vault_id != vault_key.vault_id()
            || ctx.vault_key_epoch != vault_key.epoch()
        {
            return Err(EncryptError::ContextMismatch);
        }
        seal(rng, self.key(), ctx, vault_key.key().expose_secret())
    }

    /// Opens a `VAULT_KEY_SELF_GRANT`. The vault key gets the vault and epoch `ctx` names; the
    /// current `vault_key_epoch` is learned this way, from the grant that opens under the
    /// verified account key, never from server metadata (§11.6).
    ///
    /// # Errors
    /// [`DecryptError`], including when `ctx` names another account-key epoch than this key's.
    pub fn unwrap_vault_key(
        &self,
        ctx: &VaultKeySelfGrantCtx,
        envelope: &[u8],
    ) -> Result<VaultKey, DecryptError> {
        if ctx.account_key_epoch != self.epoch() {
            return Err(DecryptError);
        }
        let plaintext = open(self.key(), ctx, envelope)?;
        Ok(VaultKey {
            key: Key32::from_slice(plaintext.expose_secret())?,
            vault_id: ctx.vault_id,
            epoch: ctx.vault_key_epoch,
        })
    }

    /// Builds a `RETIRED_SECRET_KEY`: `u8 key_type ‖ secret key` under this account key (ctx
    /// `account_id ‖ retired public key id`).
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another retired key id.
    pub fn wrap_retired_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &RetiredSecretKeyCtx,
        retired: &RetiredSecretKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.retired_key_id != retired.public_key_id() {
            return Err(EncryptError::ContextMismatch);
        }
        let mut plaintext = Zeroizing::new([0u8; RETIRED_SECRET_KEY_LEN]);
        let (key_type, sk) = plaintext.split_at_mut(1);
        key_type.copy_from_slice(&[retired.key_type().to_u8()]);
        retired
            .secret_key()
            .write_secret(sk.try_into().map_err(|_| EncryptError::Internal)?);
        seal(rng, self.key(), ctx, plaintext.as_slice())
    }

    /// Opens a `RETIRED_SECRET_KEY`. The key type must be an X25519 type, and the key's public
    /// key id must be the one `ctx` names, so the plaintext's type byte is bound to the context.
    ///
    /// # Errors
    /// [`DecryptError`].
    pub fn unwrap_retired_key(
        &self,
        ctx: &RetiredSecretKeyCtx,
        envelope: &[u8],
    ) -> Result<RetiredSecretKey, DecryptError> {
        let plaintext = open(self.key(), ctx, envelope)?;
        let mut r = Reader::new(plaintext.expose_secret());
        let key_type = KeyType::from_u8(r.u8()?)?;
        let sk = Zeroizing::new(*r.array::<X25519_SECRET_KEY_LEN>()?);
        r.finish()?;
        let retired = RetiredSecretKey::new(key_type, HpkeSecretKey::from_x25519_bytes(&sk)?)?;
        if retired.public_key_id() != ctx.retired_key_id {
            return Err(DecryptError);
        }
        Ok(retired)
    }
}

impl VaultKey {
    /// Builds an `ITEM_KEY_WRAP`: `u8 wrap_version = 1 ‖ u32 created_vault_key_epoch ‖
    /// item_key` under this vault key (ctx `vault_id ‖ item_id ‖ u32 vault_key_epoch` of this
    /// key). A re-wrap after a rotation copies the item key's creation epoch unchanged.
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another vault or epoch than this key's,
    /// or the item key was created after this key's epoch.
    pub fn wrap_item_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &ItemKeyWrapCtx,
        item_key: &ItemKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.vault_id != self.vault_id()
            || ctx.vault_key_epoch != self.epoch()
            || item_key.created_vault_key_epoch() > self.epoch()
        {
            return Err(EncryptError::ContextMismatch);
        }
        let mut plaintext = Zeroizing::new([0u8; ITEM_KEY_WRAP_LEN]);
        let (version, rest) = plaintext.split_at_mut(1);
        let (created, key) = rest.split_at_mut(4);
        version.copy_from_slice(&[ITEM_KEY_WRAP_VERSION]);
        created.copy_from_slice(&item_key.created_vault_key_epoch().to_be_bytes());
        key.copy_from_slice(item_key.key().expose_secret());
        seal(rng, self.key(), ctx, plaintext.as_slice())
    }

    /// Opens an `ITEM_KEY_WRAP` with the ctx of this key's vault and epoch. Rejects a
    /// `wrap_version` other than 1 and a creation epoch later than the wrapping epoch.
    ///
    /// # Errors
    /// [`DecryptError`], including when `ctx` names another vault or epoch than this key's.
    pub fn unwrap_item_key(
        &self,
        ctx: &ItemKeyWrapCtx,
        envelope: &[u8],
    ) -> Result<ItemKey, DecryptError> {
        if ctx.vault_id != self.vault_id() || ctx.vault_key_epoch != self.epoch() {
            return Err(DecryptError);
        }
        let plaintext = open(self.key(), ctx, envelope)?;
        let mut r = Reader::new(plaintext.expose_secret());
        let version = r.u8()?;
        let created_vault_key_epoch = r.u32()?;
        let key = Key32::from_slice(r.array::<KEY_LEN>()?)?;
        r.finish()?;
        if version != ITEM_KEY_WRAP_VERSION || created_vault_key_epoch > ctx.vault_key_epoch {
            return Err(DecryptError);
        }
        Ok(ItemKey {
            key,
            created_vault_key_epoch,
        })
    }
}
