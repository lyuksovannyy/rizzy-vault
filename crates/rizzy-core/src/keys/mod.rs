//! The key hierarchy (CRYPTO.md §4.1, §4.2, §4.4; ADR 0006).
//!
//! **Typed keys.** Every key of the hierarchy is its own type, and a key that has an epoch or a
//! home carries it: an [`AccountKey`] knows its `account_key_epoch`, a [`VaultKey`] its vault
//! and `vault_key_epoch`, an [`ItemKey`] the `vault_key_epoch` it was created in (§4.4 "Item-key
//! creation epoch"). Wrapping checks the context against the keys, so a wrap can never be
//! built for a place it does not belong ([`EncryptError::ContextMismatch`](crate::error::EncryptError::ContextMismatch)), and unwrapping
//! gives each key the epoch its context names.
//!
//! **Wrapped-key objects (M1).** Each is an envelope ([`crate::envelope`] `0x01`, or HPKE PSK
//! mode for the device grant) whose context the reader rebuilds from where it expected the
//! object (§8.4):
//!
//! | Object | Wrapping key | Method |
//! |---|---|---|
//! | `E_srv` (`ACCOUNT_KEY_SERVER_WRAP`) | [`ServerUnlockKey`] | [`ServerUnlockKey::wrap_account_key`] |
//! | `E_local` (`ACCOUNT_KEY_LOCAL_WRAP`) | [`LocalUnlockKey`] | [`LocalUnlockKey::wrap_account_key`] |
//! | `E_rec` (`ACCOUNT_KEY_RECOVERY_WRAP`) | [`RecoveryWrapKey`] | [`RecoveryWrapKey::wrap_account_key`] |
//! | `E_id` (`IDENTITY_SECRET_KEYS`) | [`AccountKey`] | [`AccountKey::wrap_identity_keys`] |
//! | `E_dev` (`DEVICE_SECRET_KEYS`) | [`AccountKey`] | [`AccountKey::wrap_device_keys`] |
//! | `VAULT_KEY_SELF_GRANT` | [`AccountKey`] | [`AccountKey::wrap_vault_key`] |
//! | `RETIRED_SECRET_KEY` | [`AccountKey`] | [`AccountKey::wrap_retired_key`] |
//! | `ITEM_KEY_WRAP` | [`VaultKey`] | [`VaultKey::wrap_item_key`] |
//! | `ACCOUNT_KEY_DEVICE_GRANT` | recipient device X25519 + device-grant PSK, signed | [`seal_account_key_device_grant`] |
//!
//! Op, snapshot, settings and export envelopes are sealed with [`crate::envelope::seal`] under
//! [`ItemKey::key`] and [`AccountKey::key`].

use core::fmt;

use rand_core::CryptoRng;
use subtle::ConstantTimeEq as _;

use crate::error::DerivationError;
use crate::hpke::{HpkePublicKey, HpkeSecretKey};
use crate::ids::{KeyType, PublicKeyId, SymmetricKeyId, VaultId};
use crate::secret::Key32;
use crate::sign::{DeviceSigningKey, DeviceVerifyingKey, IdentitySigningKey, IdentityVerifyingKey};

mod derive;
mod grant;
mod wrap;

#[cfg(test)]
mod tests;

pub use derive::{
    AccountFingerprint, DEVICE_SALT_LEN, DeviceSetError, EXPORT_KEY_LEN, LocalUnlockKey,
    RECOVERY_CODE_LEN, RecoveryAuthToken, RecoveryWrapKey, ServerUnlockKey, device_set_hash,
    settings_hash,
};
pub use grant::{
    GrantError, GrantSender, GrantSigner, open_account_key_device_grant,
    seal_account_key_device_grant,
};
pub use wrap::{DEVICE_SECRET_KEYS_VERSION, ITEM_KEY_WRAP_VERSION};

/// An epoch counter would pass `u32::MAX`. Unreachable in practice (§4.4: +1 per rotation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EpochOverflow;

impl fmt::Display for EpochOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("key epoch overflow")
    }
}

impl core::error::Error for EpochOverflow {}

/// Defines a 32-byte symmetric key type with an epoch-free core API.
macro_rules! key_type_common {
    ($name:ident) => {
        impl $name {
            /// The key's symmetric key id (§4.4): what envelope headers under it carry.
            ///
            /// # Errors
            /// [`DerivationError`] (unreachable).
            pub fn key_id(&self) -> Result<SymmetricKeyId, DerivationError> {
                self.key.key_id()
            }

            /// The key material, for sealing envelopes of the purposes this key encrypts.
            #[must_use]
            pub const fn key(&self) -> &Key32 {
                &self.key
            }

            /// Whether this key's derived id equals `id`, compared in constant time. A reader
            /// checks this against an envelope header or `account-state` (§4.4, §11.6).
            #[must_use]
            pub fn matches_key_id(&self, id: &SymmetricKeyId) -> bool {
                self.key_id()
                    .is_ok_and(|own| bool::from(own.as_bytes().ct_eq(id.as_bytes())))
            }
        }
    };
}

/// The account key (§4.2): 32 random bytes, one per `account_key_epoch`.
///
/// It wraps the identity keys, the device keys, the vault self-grants, retired keys and the
/// account settings, and is itself wrapped by `E_srv`, `E_local`, `E_rec` and the device grants.
pub struct AccountKey {
    key: Key32,
    epoch: u32,
}

key_type_common!(AccountKey);

impl AccountKey {
    /// A fresh account key for `epoch` (0 at signup, §4.4).
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, epoch: u32) -> Self {
        Self {
            key: Key32::generate(rng),
            epoch,
        }
    }

    /// A fresh account key for the next epoch (a rotation, §11.6 step 2).
    ///
    /// # Errors
    /// [`EpochOverflow`].
    pub fn generate_next<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<Self, EpochOverflow> {
        let epoch = self.epoch.checked_add(1).ok_or(EpochOverflow)?;
        Ok(Self::generate(rng, epoch))
    }

    /// The `account_key_epoch` of this key.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    pub(crate) const fn from_key(key: Key32, epoch: u32) -> Self {
        Self { key, epoch }
    }
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountKey(epoch {}, [REDACTED])", self.epoch)
    }
}

/// A vault key (§4.2): 32 random bytes per vault and `vault_key_epoch`. Never derived from the
/// account key, so it can be shared (M9).
pub struct VaultKey {
    key: Key32,
    vault_id: VaultId,
    epoch: u32,
}

key_type_common!(VaultKey);

impl VaultKey {
    /// A fresh vault key for `vault_id` at `epoch` (0 when the vault is created, §4.4).
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, vault_id: VaultId, epoch: u32) -> Self {
        Self {
            key: Key32::generate(rng),
            vault_id,
            epoch,
        }
    }

    /// A fresh key for the same vault at the next epoch (§11.6 step 2).
    ///
    /// # Errors
    /// [`EpochOverflow`].
    pub fn generate_next<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<Self, EpochOverflow> {
        let epoch = self.epoch.checked_add(1).ok_or(EpochOverflow)?;
        Ok(Self::generate(rng, self.vault_id, epoch))
    }

    /// The vault this key belongs to.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The `vault_key_epoch` of this key.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VaultKey({:?}, epoch {}, [REDACTED])",
            self.vault_id, self.epoch
        )
    }
}

/// An item key (§4.2): 32 random bytes per item, with the `vault_key_epoch` in which it was
/// created. The creation epoch is authenticated inside `ITEM_KEY_WRAP` and never changes when
/// the key is re-wrapped (§8.4, §11.6).
pub struct ItemKey {
    key: Key32,
    created_vault_key_epoch: u32,
}

key_type_common!(ItemKey);

impl ItemKey {
    /// A fresh item key, created in the vault's current epoch.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, current_vault_key_epoch: u32) -> Self {
        Self {
            key: Key32::generate(rng),
            created_vault_key_epoch: current_vault_key_epoch,
        }
    }

    /// The `vault_key_epoch` this key was created in.
    #[must_use]
    pub const fn created_vault_key_epoch(&self) -> u32 {
        self.created_vault_key_epoch
    }

    /// The writer rule (§11.6, MUST): a key created before the vault's current epoch must not
    /// encrypt anything new; the writer generates a fresh item key and writes a full snapshot.
    #[must_use]
    pub const fn is_stale(&self, current_vault_key_epoch: u32) -> bool {
        self.created_vault_key_epoch < current_vault_key_epoch
    }
}

impl fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ItemKey(created in vault epoch {}, [REDACTED])",
            self.created_vault_key_epoch
        )
    }
}

/// The identity key pair of one `identity_epoch` (§4.2): an Ed25519 signing key and an X25519
/// HPKE key, both from the injected CSPRNG. The secret halves travel only inside `E_id`.
pub struct IdentityKeys {
    signing: IdentitySigningKey,
    kem: HpkeSecretKey,
    epoch: u32,
}

/// The public halves of the identity keys, as the key bundle publishes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityPublicKeys {
    /// Identity Ed25519 key (`key_type` `0x01`).
    pub ed25519: IdentityVerifyingKey,
    /// Identity X25519 key (`key_type` `0x02`).
    pub x25519: HpkePublicKey,
}

impl IdentityKeys {
    /// Fresh identity keys for `identity_epoch` (0 at signup; +1 in a full rotation).
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, identity_epoch: u32) -> Self {
        Self {
            signing: IdentitySigningKey::generate(rng),
            kem: HpkeSecretKey::generate_x25519(rng),
            epoch: identity_epoch,
        }
    }

    /// The identity signing key.
    #[must_use]
    pub const fn signing_key(&self) -> &IdentitySigningKey {
        &self.signing
    }

    /// The identity X25519 secret key (member grants, M9).
    #[must_use]
    pub const fn kem_key(&self) -> &HpkeSecretKey {
        &self.kem
    }

    /// The `identity_epoch` of these keys.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The public halves. After opening `E_id`, a client compares them with the published
    /// bundle's keys and aborts on a mismatch (§10.3, §11.2 step 6).
    #[must_use]
    pub const fn public_keys(&self) -> IdentityPublicKeys {
        IdentityPublicKeys {
            ed25519: *self.signing.verifying_key(),
            x25519: *self.kem.public_key(),
        }
    }
}

impl fmt::Debug for IdentityKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityKeys(epoch {}, [REDACTED])", self.epoch)
    }
}

/// One device's key pair (§4.2): an Ed25519 key (device authentication, ops, grants) and an
/// X25519 key (the recipient of device grants). The secrets travel only inside `E_dev`, which
/// never leaves the device.
pub struct DeviceKeys {
    signing: DeviceSigningKey,
    kem: HpkeSecretKey,
}

/// The public halves of a device's keys, as its certificate lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DevicePublicKeys {
    /// Device Ed25519 key (`key_type` `0x04`).
    pub ed25519: DeviceVerifyingKey,
    /// Device X25519 key (`key_type` `0x05`).
    pub x25519: HpkePublicKey,
}

impl DeviceKeys {
    /// Fresh device keys.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self {
            signing: DeviceSigningKey::generate(rng),
            kem: HpkeSecretKey::generate_x25519(rng),
        }
    }

    /// The device signing key.
    #[must_use]
    pub const fn signing_key(&self) -> &DeviceSigningKey {
        &self.signing
    }

    /// The device X25519 secret key.
    #[must_use]
    pub const fn kem_key(&self) -> &HpkeSecretKey {
        &self.kem
    }

    /// The public halves.
    #[must_use]
    pub const fn public_keys(&self) -> DevicePublicKeys {
        DevicePublicKeys {
            ed25519: *self.signing.verifying_key(),
            x25519: *self.kem.public_key(),
        }
    }

    /// The public key id of the device X25519 key (`0x05`): the key id in the header of every
    /// grant sealed to this device.
    #[must_use]
    pub fn kem_key_id(&self) -> PublicKeyId {
        self.kem.public_key().key_id(KeyType::DeviceX25519)
    }
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKeys({:?}, [REDACTED])", self.signing.key_id())
    }
}

/// A retired X25519 secret key (§11.6 step 3): an old identity or mail key still needed to
/// open old HPKE ciphertext, kept under the current account key as `RETIRED_SECRET_KEY`.
///
/// Only X25519 key types can be retired (`0x02` identity X25519, `0x03` mail X25519): §11.6
/// retires keys "needed for old HPKE ciphertext", and signing keys never decrypt anything.
pub struct RetiredSecretKey {
    key_type: KeyType,
    secret: HpkeSecretKey,
}

impl RetiredSecretKey {
    /// Wraps a retired key of type `key_type`.
    ///
    /// # Errors
    /// [`crate::error::ParseError::InvalidValue`] unless `key_type` is identity X25519 or mail
    /// X25519.
    pub fn new(key_type: KeyType, secret: HpkeSecretKey) -> Result<Self, crate::error::ParseError> {
        if !Self::allowed(key_type) {
            return Err(crate::error::ParseError::InvalidValue);
        }
        Ok(Self { key_type, secret })
    }

    const fn allowed(key_type: KeyType) -> bool {
        matches!(key_type, KeyType::IdentityX25519 | KeyType::MailX25519)
    }

    /// The retired key's type.
    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// The retired secret key.
    #[must_use]
    pub const fn secret_key(&self) -> &HpkeSecretKey {
        &self.secret
    }

    /// The retired public key id, `PublicKeyId(key_type, public_key)`: the `RETIRED_SECRET_KEY`
    /// context field.
    #[must_use]
    pub fn public_key_id(&self) -> PublicKeyId {
        self.secret.public_key().key_id(self.key_type)
    }
}

impl fmt::Debug for RetiredSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RetiredSecretKey({:?}, [REDACTED])", self.key_type)
    }
}
