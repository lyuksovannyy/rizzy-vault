//! The symmetric wrapped-key objects of M1 (CRYPTO.md §4.2, §8.4, §8.5).
//!
//! Every wrap checks, before sealing, that the context describes the keys being wrapped (the
//! epochs and ids the keys carry, and the `kdf_id` an unlock key was stretched with). Every
//! unwrap first compares the context with whatever the unwrapping key records (account,
//! device, `kdf_id`, epoch, vault; the recovery wrap key records nothing, and the account key
//! only its epoch), then opens the envelope (commitment first), then checks the plaintext
//! layout. All unwrap failures are the same [`DecryptError`].
//!
//! **Wrap, step by step.**
//! 1. Compare the context fields the keys record with the keys; on a difference return
//!    [`EncryptError::ContextMismatch`] and seal nothing.
//! 2. Lay the plaintext out in a fixed-size `Zeroizing` buffer (the bare 32-byte key, or the
//!    §8.4 layout for `E_id`, `E_dev`, `RETIRED_SECRET_KEY` and `ITEM_KEY_WRAP`).
//! 3. Seal it with [`seal`] (algorithm `0x01`): a fresh 24-byte nonce from the injected
//!    CSPRNG, the wrapping key's derived id in the header, the purpose and the context in the
//!    AAD, and the key commitment over all of them (§8.3, §9.1). The purpose's fixed plaintext
//!    length is enforced there.
//!
//! **Unwrap, step by step.**
//! 1. Compare the context with what the unwrapping key records; a mismatch is a
//!    [`DecryptError`] before any crypto.
//! 2. [`open`]: strict parse, the purpose's algorithm allow-list, the key id, the commitment
//!    in constant time, then the AEAD tag, then the purpose's exact plaintext length (§9.5,
//!    §8.3, §8.5).
//! 3. Parse the plaintext with the bounded [`Reader`]: every field at its fixed length, no
//!    trailing bytes, the version byte where there is one.
//! 4. Build the typed key, taking its epoch and home from the context the caller rebuilt,
//!    never from an unauthenticated locator (§4.2). The only epoch read from the plaintext is
//!    an item key's creation epoch, which the envelope authenticates.
//!
//! **What this defends against.** A wrap moved to another account, device, vault, item or epoch
//! fails the commitment, because the reader rebuilds the context from where it expected the
//! object (§8.4). A wrap under another key fails the key-id check. A mismatch of any kind looks
//! the same to the caller and to a remote peer: there is no "which check failed" oracle
//! (§9.5, §12.3).
//!
//! **What it leaves to the caller.** Opening `E_srv`, `E_local` or `E_rec` proves the account
//! key was sealed under the caller's unlock key, not that it is the current one: compare it
//! with the signed `account_key_id` ([`crate::sign::AccountState::matches_account_key`]).
//! Opening `E_id` does not prove the identity keys are the published ones: compare
//! [`IdentityKeys::public_keys`] with the verified bundle (§11.2 step 6). Context fields that
//! no key records (for example `password_epoch`, `recovery_epoch`, or the `account_id` of
//! `E_rec`, `E_id` and `E_dev`) must match the verified state or come from the device's own
//! storage.

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

/// `wrap_version` of the `ITEM_KEY_WRAP` plaintext (§8.4). The only value written, and the only
/// value [`VaultKey::unwrap_item_key`] accepts.
pub const ITEM_KEY_WRAP_VERSION: u8 = 1;

/// `version` of the `DEVICE_SECRET_KEYS` plaintext (§8.4). The only value written, and the only
/// value [`AccountKey::unwrap_device_keys`] accepts.
pub const DEVICE_SECRET_KEYS_VERSION: u8 = 1;

/// `ITEM_KEY_WRAP` plaintext length: `u8 wrap_version ‖ u32 created_vault_key_epoch ‖ key`.
const ITEM_KEY_WRAP_LEN: usize = 1 + 4 + KEY_LEN;
/// `IDENTITY_SECRET_KEYS` plaintext length: `ed25519_seed ‖ x25519_sk` (§11.1 step 5).
const IDENTITY_SECRET_KEYS_LEN: usize = SEED_LEN + X25519_SECRET_KEY_LEN;
/// `DEVICE_SECRET_KEYS` plaintext length: `u8 version ‖ ed25519_seed ‖ x25519_sk`.
const DEVICE_SECRET_KEYS_LEN: usize = 1 + SEED_LEN + X25519_SECRET_KEY_LEN;
/// `RETIRED_SECRET_KEY` plaintext length: `u8 key_type ‖ secret key`.
const RETIRED_SECRET_KEY_LEN: usize = 1 + X25519_SECRET_KEY_LEN;

// Compile-time check that the layouts above have the fixed key-wrap lengths of §8.5, which are
// also the `Fixed` plaintext rules of the purpose registry.
const _: () = assert!(
    ITEM_KEY_WRAP_LEN == 37
        && IDENTITY_SECRET_KEYS_LEN == 64
        && DEVICE_SECRET_KEYS_LEN == 65
        && RETIRED_SECRET_KEY_LEN == 33
);

/// Rebuilds the account key from an opened `E_srv`, `E_local` or `E_rec` plaintext, with the
/// `account_key_epoch` of the context it was opened under. Any length other than 32 bytes is a
/// [`DecryptError`] (the envelope layer already enforces it).
fn account_key_from(plaintext: &[u8], epoch: u32) -> Result<AccountKey, DecryptError> {
    Ok(AccountKey::from_key(Key32::from_slice(plaintext)?, epoch))
}

/// Splits `ed25519_seed ‖ x25519_sk` and rebuilds both keys. Temporary copies are wiped.
///
/// Returns the seed (for the caller to turn into a signing key of its role) and the X25519
/// secret key. A short input or trailing bytes are a [`DecryptError`].
fn key_pair_from(bytes: &[u8]) -> Result<(Zeroizing<[u8; SEED_LEN]>, HpkeSecretKey), DecryptError> {
    let mut r = Reader::new(bytes);
    // Copy each half out of the plaintext into its own wiped-on-drop array.
    let seed = Zeroizing::new(*r.array::<SEED_LEN>()?);
    let sk = Zeroizing::new(*r.array::<X25519_SECRET_KEY_LEN>()?);
    r.finish()?;
    Ok((seed, HpkeSecretKey::from_x25519_bytes(&sk)?))
}

impl ServerUnlockKey {
    /// Builds `E_srv`: the account key under `server_unlock_key` (`ACCOUNT_KEY_SERVER_WRAP`,
    /// ctx `account_id ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id`).
    ///
    /// Uploaded to the server (Server mode only) in the same request as the `account-state`
    /// whose epochs and `kdf_id` the context repeats (§11 "Replacing credentials"). The
    /// `password_epoch` is not recorded by this key, so it is the caller's to match the state.
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `ctx` names another account, account-key epoch or
    /// `kdf_id` than the one whose OPAQUE run gave this key.
    pub fn wrap_account_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &AccountKeyServerWrapCtx,
        account_key: &AccountKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.account_id != self.account_id
            || ctx.kdf_id != self.kdf_id
            || ctx.account_key_epoch != account_key.epoch()
        {
            return Err(EncryptError::ContextMismatch);
        }
        seal(rng, &self.key, ctx, account_key.key().expose_secret())
    }

    /// Opens `E_srv`. The account key gets the epoch `ctx` names.
    ///
    /// At login the epochs in `ctx` are the ones the server returned with `E_srv`, and the
    /// `kdf_id` is the one this key's OPAQUE run used. Success does not make them trustworthy:
    /// §11.2 step 6 then requires the key's id to equal `state.account_key_id` and the verified
    /// state's epochs and `kdf_id` to equal the ones used here.
    ///
    /// # Errors
    /// [`DecryptError`], including for a context of another account or `kdf_id`.
    pub fn unwrap_account_key(
        &self,
        ctx: &AccountKeyServerWrapCtx,
        envelope: &[u8],
    ) -> Result<AccountKey, DecryptError> {
        // Pre-check: the key was derived for exactly this account and `kdf_id`.
        if ctx.account_id != self.account_id || ctx.kdf_id != self.kdf_id {
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
    /// [`EncryptError::ContextMismatch`] if `ctx` names another account, device, account-key
    /// epoch or `kdf_id` than this key was stretched with. A reader derives with the `kdf_id`
    /// stored next to `E_local` (§5.6), so a wrap naming another one could never be opened.
    pub fn wrap_account_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &AccountKeyLocalWrapCtx,
        account_key: &AccountKey,
    ) -> Result<Vec<u8>, EncryptError> {
        if ctx.account_id != self.account_id
            || ctx.device_id != self.device_id
            || ctx.kdf_id != self.kdf_id
            || ctx.account_key_epoch != account_key.epoch()
        {
            return Err(EncryptError::ContextMismatch);
        }
        seal(rng, &self.key, ctx, account_key.key().expose_secret())
    }

    /// Opens `E_local`, with the ctx rebuilt from the epochs stored next to it (§5.6). A wrong
    /// password shows up here as a [`DecryptError`].
    ///
    /// The stored epochs may lag the current state after a keystore unlock that crossed a
    /// rotation; the caller then follows the device's `ACCOUNT_KEY_FORWARD` envelopes to the
    /// key whose id is `state.account_key_id` (§11.3 step 4).
    ///
    /// # Errors
    /// [`DecryptError`], including for a context of another account, device or `kdf_id`.
    pub fn unwrap_account_key(
        &self,
        ctx: &AccountKeyLocalWrapCtx,
        envelope: &[u8],
    ) -> Result<AccountKey, DecryptError> {
        // Pre-check: the key was derived for exactly this account, device and `kdf_id`.
        if ctx.account_id != self.account_id
            || ctx.device_id != self.device_id
            || ctx.kdf_id != self.kdf_id
        {
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
    /// Only the account-key epoch can be checked here, because the recovery wrap key records
    /// nothing; `account_id` and `recovery_epoch` must equal the new `account-state`'s (§11
    /// "Replacing credentials"). A rotation that keeps the current code re-wraps with the new
    /// `account_key_epoch` and the unchanged `recovery_epoch` (§11.6 step 5).
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
    /// There is no pre-check (the key records nothing). A context for another account or
    /// epoch fails the commitment. A wrong recovery code gives a different key, which fails the
    /// key-id check earlier, before the commitment is computed (§9.5 step 4). Both return the
    /// same [`DecryptError`].
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
    /// Stored on the server and re-wrapped under the new account key in every rotation (§4.2,
    /// §11.6 step 3). The plaintext has no version byte (§8.4).
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
        // Plaintext: seed (32) ‖ X25519 secret (32), written in place into a wiped buffer. The
        // `try_into` conversions cannot fail: the 64-byte array splits into two 32-byte halves.
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
    /// That comparison is what authenticates the account's own identity keys (§10.3): a server
    /// that substituted the bundle's keys is caught there, not here.
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
    /// Nothing in the context can be checked against the keys ([`DeviceKeys`] records no
    /// `device_id`, the account key no `account_id`): pass this device's own ids. Keeping
    /// `E_dev` off the server is what stops a past holder of the account key from opening it
    /// and reading later grants to this device (§5.10). Re-wrapped under the new account key
    /// after a rotation (§11.3 step 4).
    ///
    /// # Errors
    /// [`EncryptError::Internal`] (unreachable).
    pub fn wrap_device_keys<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &DeviceSecretKeysCtx,
        keys: &DeviceKeys,
    ) -> Result<Vec<u8>, EncryptError> {
        // Plaintext: version (1) ‖ seed (32) ‖ X25519 secret (32), in a wiped buffer. The
        // `try_into` conversions cannot fail: the splits leave exactly 32-byte slices.
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
    /// The version byte is read only after the envelope authenticated the whole plaintext.
    ///
    /// # Errors
    /// [`DecryptError`].
    pub fn unwrap_device_keys(
        &self,
        ctx: &DeviceSecretKeysCtx,
        envelope: &[u8],
    ) -> Result<DeviceKeys, DecryptError> {
        let plaintext = open(self.key(), ctx, envelope)?;
        // version (1) ‖ seed (32) ‖ X25519 secret (32); `key_pair_from` checks the rest.
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
    /// Binding both epochs lets a reader learn the current vault epoch from the one grant that
    /// opens under the current account key (§11.6). A rotation writes a new grant for the new
    /// vault key under the new account key (§11.6 step 3). Stored on the server (§4.2).
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
    /// Build `ctx.account_key_epoch` from the verified `account-state` (§11.2 step 6: each
    /// self-grant opens with the `account_key_epoch` from `state` in its context). Learning the
    /// vault epoch this way is sound in M1–M8, where a vault key rotates only together with the
    /// account key; M9 member removal needs a signed vault statement (§11.6, ADR 0006 risks).
    ///
    /// # Errors
    /// [`DecryptError`], including when `ctx` names another account-key epoch than this key's.
    pub fn unwrap_vault_key(
        &self,
        ctx: &VaultKeySelfGrantCtx,
        envelope: &[u8],
    ) -> Result<VaultKey, DecryptError> {
        // Pre-check: the account key records only its epoch.
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
    /// The context names the retired key by its public key id, which a reader finds in the
    /// header of the old HPKE ciphertext it needs to open.
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
        // Plaintext: key_type (1) ‖ X25519 secret (32), in a wiped buffer.
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
        // An undefined type byte fails here; a defined but non-X25519 type fails in `new`.
        let key_type = KeyType::from_u8(r.u8()?)?;
        let sk = Zeroizing::new(*r.array::<X25519_SECRET_KEY_LEN>()?);
        r.finish()?;
        let retired = RetiredSecretKey::new(key_type, HpkeSecretKey::from_x25519_bytes(&sk)?)?;
        // The public key id covers the type byte, so this ties the plaintext's type to the
        // context the reader rebuilt.
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
    /// The `item_id` is not recorded by any key: pass the item this key belongs to. The wrap
    /// travels with the op or snapshot that first uses the key and is covered by that record's
    /// signature through its hash (§10.2); re-wraps after a rotation are unsigned (§10.2 "What
    /// signatures buy us").
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
        // Plaintext: wrap_version (1) ‖ u32 created_vault_key_epoch (big-endian) ‖ key (32).
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
    /// Afterwards the reader requires the item key's derived id to equal the `key_id` of the
    /// op or snapshot envelope it opens (§11.6 reader rule), and a writer checks
    /// [`ItemKey::is_stale`] before using it (§11.6 writer rule).
    ///
    /// # Errors
    /// [`DecryptError`], including when `ctx` names another vault or epoch than this key's.
    pub fn unwrap_item_key(
        &self,
        ctx: &ItemKeyWrapCtx,
        envelope: &[u8],
    ) -> Result<ItemKey, DecryptError> {
        // Pre-check: the vault key records its vault and epoch.
        if ctx.vault_id != self.vault_id() || ctx.vault_key_epoch != self.epoch() {
            return Err(DecryptError);
        }
        let plaintext = open(self.key(), ctx, envelope)?;
        // wrap_version (1) ‖ u32 created_vault_key_epoch ‖ key (32), no trailing bytes.
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
