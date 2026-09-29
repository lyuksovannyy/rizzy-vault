//! The key hierarchy (CRYPTO.md §4.1, §4.2, §4.4; ADR 0006).
//!
//! **Role.** This module is the single home of every key an account owns and of every object
//! that stores one key under another. It has three private parts: `derive` (the §4.3
//! derivations of the unlock keys, the recovery key and token, the device-set and settings
//! hashes and the account fingerprint), `wrap` (the symmetric wrapped-key objects) and `grant`
//! (the signed HPKE device grant that carries a new account key to the other devices after a
//! rotation). Their public items are re-exported here.
//!
//! **The hierarchy in one picture** (CRYPTO.md §4.1 has the full diagram):
//!
//! ```text
//! export_key (OPAQUE) ─HKDF─► server_unlock_key ──── E_srv ───┐
//! pw_in, device_salt ─Argon2id, HKDF─► local_unlock_key ─ E_local ─┤
//! recovery code ─HKDF─► recovery wrap key ─────────── E_rec ───┼─► account key (random, per epoch)
//! previous account key + device X25519 ─ HPKE PSK device grant ┘
//!
//! account key ─► E_id (identity keys), E_dev (device keys, device-local only),
//!                VAULT_KEY_SELF_GRANT (vault keys), RETIRED_SECRET_KEY, ACCOUNT_SETTINGS
//! vault key   ─► ITEM_KEY_WRAP (item key + the vault_key_epoch it was created in)
//! item key    ─► ITEM_OP and ITEM_SNAPSHOT envelopes
//! ```
//!
//! **Typed keys.** Every key of the hierarchy is its own type, and a key that has an epoch or a
//! home carries it: an [`AccountKey`] knows its `account_key_epoch`, a [`VaultKey`] its vault
//! and `vault_key_epoch`, an [`ItemKey`] the `vault_key_epoch` it was created in (§4.4 "Item-key
//! creation epoch"), and an unlock key the account (and device) and the `kdf_id` it was
//! stretched with. Wrapping checks every context field that the keys involved record, so a
//! wrap cannot be built for another epoch, vault, account, device or `kdf_id` than the ones
//! those keys belong to ([`EncryptError::ContextMismatch`](crate::error::EncryptError::ContextMismatch)). Fields no key records (for example the
//! `account_id` of `E_id`, or the `password_epoch` of `E_srv`) are the caller's to get right,
//! and a wrong one makes the object unopenable where it belongs. Unwrapping gives each key the
//! epoch and home its context names; nothing is taken from an unauthenticated locator.
//!
//! **Invariants.**
//! - Generated keys (account, vault, item, identity, device) come only from the injected
//!   CSPRNG (CRYPTO.md §12.1). Vault keys are never derived from the account key, so a vault
//!   can be shared in M9 without re-encryption (ADR 0006 decision 3).
//! - Key material lives in [`Key32`] (heap, wiped on drop) or in the zeroizing key types of
//!   [`crate::sign`] and [`crate::hpke`]. No secret key type here implements `Clone`, `Copy` or
//!   `Display`, and each `Debug` prints only public metadata (epoch, vault id, key type, device
//!   key id) followed by `[REDACTED]` (CRYPTO.md §12.2).
//! - Epochs start where §4.4 says (`generate` takes the caller's epoch: 0 at signup or vault
//!   creation) and a rotation moves them by exactly one: `generate_next` derives the next
//!   epoch from the current key and refuses to wrap past `u32::MAX`.
//! - Key ids are derived from the key, never stored next to it (§4.4), and comparisons against
//!   a received id are constant-time ([`AccountKey::matches_key_id`]).
//!
//! **What this defends against.** A server that moves a wrapped key to another account,
//! device, vault, item or epoch (the context is rebuilt by the reader and bound into the
//! envelope commitment, §8.3, §8.4); a server that names another `kdf_id` for a password-derived
//! wrap (INV-5); a server that serves an old vault epoch (the current `vault_key_epoch` is
//! learned from the self-grant that opens under the verified account key, §11.6); the reuse of
//! a pre-rotation item key for new writes ([`ItemKey::is_stale`], §11.6 writer rule).
//!
//! **What it does not do.** It does not fetch or verify signed state. Comparing an unwrapped
//! account key with the signed `account_key_id`
//! ([`AccountState::matches_account_key`](crate::sign::AccountState::matches_account_key)), comparing
//! the identity public keys from `E_id` with the published bundle, and noticing a withheld
//! wrap are the caller's steps (§11.2 step 6, §11.3 step 4). It cannot protect keys on an
//! unlocked client from malware (CRYPTO.md §1 non-goals), and copies that third-party crates
//! make internally (HKDF state, §12.2 "Limits") are not wiped.
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
//! Op, snapshot and settings envelopes are sealed with [`crate::envelope::seal`] under
//! [`ItemKey::key`] (ops, snapshots) and [`AccountKey::key`] (`ACCOUNT_SETTINGS`). The export
//! file has its own password-derived key ([`crate::export`]).

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
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
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
///
/// Returned by [`AccountKey::generate_next`] and [`VaultKey::generate_next`] instead of
/// wrapping around to 0, which would let a new key reuse the contexts of epoch 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EpochOverflow;

impl fmt::Display for EpochOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("key epoch overflow")
    }
}

impl core::error::Error for EpochOverflow {}

/// Implements the epoch-free core API shared by the 32-byte symmetric key types ([`AccountKey`],
/// [`VaultKey`], [`ItemKey`]): the derived key id, borrowed access to the key material, and a
/// constant-time key-id comparison. The type must have a `key: Key32` field.
macro_rules! key_type_common {
    ($name:ident) => {
        impl $name {
            /// The key's symmetric key id (§4.4): what envelope headers under it carry.
            ///
            /// `HKDF(K, salt = empty, LABEL("key-id/symmetric") ‖ 0x00, 16)`, computed afresh
            /// on each call; the id is public (it sits in every envelope header under the key).
            ///
            /// # Errors
            /// [`DerivationError`] (unreachable).
            pub fn key_id(&self) -> Result<SymmetricKeyId, DerivationError> {
                self.key.key_id()
            }

            /// The key material, for sealing envelopes of the purposes this key encrypts.
            ///
            /// The key is borrowed, not copied; pass it straight to [`crate::envelope::seal`]
            /// or [`crate::envelope::open`] and do not copy its bytes out.
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
///
/// There is exactly one current account key; the signed `account-state` commits to its epoch
/// and its derived id (`account_key_id`). Every path that yields an account key from a stored
/// object (`E_srv`, `E_rec`, the last device grant of a chain) must be followed by the caller's
/// check against that id ([`crate::sign::AccountState::matches_account_key`], §11.2 step 6,
/// §11.3 step 4, §11.9 step 4). The type is not `Clone`; the key is wiped when it is dropped.
pub struct AccountKey {
    /// The 32 key bytes, heap-allocated and wiped on drop.
    key: Key32,
    /// The `account_key_epoch` this key belongs to: 0 at signup, +1 per rotation (§4.4).
    epoch: u32,
}

key_type_common!(AccountKey);

impl AccountKey {
    /// A fresh account key for `epoch` (0 at signup, §4.4).
    ///
    /// The 32 bytes are drawn from the injected CSPRNG straight into the key's heap buffer. For
    /// a rotation use [`AccountKey::generate_next`], which derives the epoch from the current
    /// key instead of trusting a caller-supplied number.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, epoch: u32) -> Self {
        Self {
            key: Key32::generate(rng),
            epoch,
        }
    }

    /// A fresh account key for the next epoch (a rotation, §11.6 step 2).
    ///
    /// The new key is independent of the old one (fresh random bytes, never derived). Keep the
    /// old key until the rotation is committed: the device-grant PSK for every remaining device
    /// is derived from it ([`crate::hpke::HpkePsk::device_grant`], §10.1).
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

    /// Rebuilds an account key from authenticated key bytes and the epoch named by the context
    /// they were opened under. Crate-private, so that outside this crate an epoch is attached
    /// to account-key material only by [`AccountKey::generate`], [`AccountKey::generate_next`]
    /// or a successful unwrap (the `E_srv`, `E_local`, `E_rec` unwraps and
    /// [`open_account_key_device_grant`]).
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
///
/// It is stored as a `VAULT_KEY_SELF_GRANT` under the account key
/// ([`AccountKey::wrap_vault_key`]) and wraps the item keys of its vault
/// ([`VaultKey::wrap_item_key`]). Because it knows its vault and epoch, it refuses to wrap or
/// unwrap an item key for another vault or epoch. The type is not `Clone`; the key is wiped when
/// it is dropped.
pub struct VaultKey {
    /// The 32 key bytes, heap-allocated and wiped on drop.
    key: Key32,
    /// The vault this key belongs to; every `ITEM_KEY_WRAP` under it must name this vault.
    vault_id: VaultId,
    /// The `vault_key_epoch` of this key: 0 when the vault is created, +1 per rotation (§4.4).
    epoch: u32,
}

key_type_common!(VaultKey);

impl VaultKey {
    /// A fresh vault key for `vault_id` at `epoch` (0 when the vault is created, §4.4).
    ///
    /// The bytes come from the injected CSPRNG. For a rotation use
    /// [`VaultKey::generate_next`], which keeps the vault and moves the epoch by exactly one.
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
    /// After a rotation every existing item key is re-wrapped under the new key with its
    /// creation epoch unchanged (§11.6 step 3), and becomes stale for writing
    /// ([`ItemKey::is_stale`]).
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
///
/// It encrypts the item's `ITEM_OP` and `ITEM_SNAPSHOT` envelopes. A reader matches it to an
/// envelope by key id ([`ItemKey::matches_key_id`], §11.6 reader rule); a writer checks
/// [`ItemKey::is_stale`] before encrypting anything new with it (§11.6 writer rule). The type is
/// not `Clone`; the key is wiped when it is dropped.
pub struct ItemKey {
    /// The 32 key bytes, heap-allocated and wiped on drop.
    key: Key32,
    /// The `vault_key_epoch` current when this key was generated. Authenticated inside every
    /// `ITEM_KEY_WRAP` of the key and copied unchanged by re-wraps.
    created_vault_key_epoch: u32,
}

key_type_common!(ItemKey);

impl ItemKey {
    /// A fresh item key, created in the vault's current epoch.
    ///
    /// `current_vault_key_epoch` must be the epoch of the vault key that opens under the
    /// verified account key (§11.6 "Current vault epoch"), never a value from server metadata.
    /// Used for a new item, for an item moved to another vault, and by the writer rule when the
    /// existing key [`is stale`](ItemKey::is_stale).
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
    ///
    /// Why: a device revoked in the rotation that raised the epoch knows every older item key,
    /// so anything new under such a key would be readable by it. The creation epoch this
    /// compares is authenticated inside `ITEM_KEY_WRAP`, so a server cannot make an old key
    /// look fresh.
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
///
/// The signing key signs the key bundle, device certificates and revocations, the
/// `account-state`, and device grants made by a web vault (§10.1, §10.2). The X25519 key is the
/// recipient of member grants from M9. Both are replaced together in a full rotation, never one
/// alone (§10.2 "Identity changes replace both keys").
pub struct IdentityKeys {
    /// The identity Ed25519 signing key (`key_type` `0x01`).
    signing: IdentitySigningKey,
    /// The identity X25519 secret key (`key_type` `0x02`).
    kem: HpkeSecretKey,
    /// The `identity_epoch` these keys belong to: 0 at signup, +1 per full rotation (§4.4).
    epoch: u32,
}

/// The public halves of the identity keys, as the key bundle publishes them.
///
/// Public values: `==` is an ordinary comparison. They are also the input of the account
/// fingerprint ([`AccountFingerprint::compute`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityPublicKeys {
    /// Identity Ed25519 key (`key_type` `0x01`).
    pub ed25519: IdentityVerifyingKey,
    /// Identity X25519 key (`key_type` `0x02`).
    pub x25519: HpkePublicKey,
}

impl IdentityKeys {
    /// Fresh identity keys for `identity_epoch` (0 at signup; +1 in a full rotation).
    ///
    /// Draws the Ed25519 seed first, then the X25519 key pair, both from the injected CSPRNG
    /// (§4.2, §10.1).
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R, identity_epoch: u32) -> Self {
        Self {
            signing: IdentitySigningKey::generate(rng),
            kem: HpkeSecretKey::generate_x25519(rng),
            epoch: identity_epoch,
        }
    }

    /// The identity signing key (bundles, certificates, revocations, `account-state`, and
    /// device grants from a web vault).
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

    /// Retires these identity keys at the end of a full rotation (§11.6 step 3): the X25519
    /// secret key moves into a [`RetiredSecretKey`] of type identity X25519, to be wrapped under
    /// the new account key ([`AccountKey::wrap_retired_key`]) for old HPKE ciphertext. The
    /// signing key is dropped (and wiped): signing keys never decrypt anything, so none is
    /// retired. Nothing is copied: the secret moves.
    ///
    /// # Errors
    /// [`crate::error::ParseError`] (unreachable: identity X25519 is a retirable type).
    pub fn into_retired_x25519(self) -> Result<RetiredSecretKey, crate::error::ParseError> {
        RetiredSecretKey::new(KeyType::IdentityX25519, self.kem)
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
///
/// Keeping `E_dev` local is what makes a device grant useless to anyone who once held an
/// account key (a revoked device, a finished kit thief): opening a grant needs this device's
/// X25519 secret key as well as the PSK (§5.10, §10.1). The type is not `Clone`; both secret
/// keys are wiped when it is dropped.
pub struct DeviceKeys {
    /// The device Ed25519 signing key (`key_type` `0x04`): device authentication, ops,
    /// snapshots and the device grants this device makes.
    signing: DeviceSigningKey,
    /// The device X25519 secret key (`key_type` `0x05`): the recipient of device grants.
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
    /// Fresh device keys: an Ed25519 seed, then an X25519 key pair, both from the injected
    /// CSPRNG. Generated at enrolment (§11.1 step 2, §11.2 step 7) and at re-enrolment under a
    /// new `device_id` (§11.3 step 5).
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

    /// The device X25519 secret key, which opens the device grants sealed to this device
    /// ([`open_account_key_device_grant`]).
    #[must_use]
    pub const fn kem_key(&self) -> &HpkeSecretKey {
        &self.kem
    }

    /// The public halves, which the device certificate lists.
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
///
/// The key type is part of the wrapped plaintext and, through the public key id, of the
/// `RETIRED_SECRET_KEY` context, so an unwrapped key always comes back with the type it was
/// retired as.
pub struct RetiredSecretKey {
    /// `KeyType::IdentityX25519` or `KeyType::MailX25519`; the constructor rejects the rest.
    key_type: KeyType,
    /// The retired X25519 secret key, wiped on drop.
    secret: HpkeSecretKey,
}

impl RetiredSecretKey {
    /// Wraps a retired key of type `key_type`, taking ownership of the secret. Store it with
    /// [`AccountKey::wrap_retired_key`] under the current account key; every rotation re-wraps
    /// the retired keys under the new account key (§11.6 step 3).
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

    /// Whether `key_type` may be retired: the X25519 types only (identity `0x02`, mail `0x03`).
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
