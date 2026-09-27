//! Identifiers (CRYPTO.md §2, §4.3, §4.4).
//!
//! - **Object ids** are 16 random bytes from the injected CSPRNG, created by whoever creates the
//!   object. They are opaque: no UUID version bits. They are public, so they compare with `==`
//!   and print as hex.
//! - **Symmetric key ids** are derived from the key: `HKDF(K, salt = empty,
//!   LABEL("key-id/symmetric") ‖ 0x00, 16)`, for every symmetric key, generated or derived.
//! - **Public key ids** are `SHA-256(LABEL("key-id") ‖ 0x00 ‖ u8(key_type) ‖ public_key)[0..16]`.
//!
//! **Why ids look like this.** Object ids are random rather than counters or hashes of content,
//! so they reveal nothing about the object and can be created offline on any device without
//! coordination; 128 bits make a collision negligible, and the server rejects duplicates
//! (§2). Every id type is its own newtype, so an `ItemId` cannot be passed where a `VaultId`
//! belongs. Ids appear in AAD contexts and signed statements, which is what binds ciphertext to
//! the object it belongs to (§8.4).
//!
//! **Key ids.** Nothing stores a symmetric key id next to its key: the reader derives the id of
//! each key it holds and compares it with an envelope header or with the signed
//! `account_key_id` (§4.4, §9.5). Because a symmetric key id is derived from a secret (and for a
//! password-derived key is a guess verifier costing one Argon2id per guess), it compares in
//! constant time. A public key id binds the key type, so the same 32 bytes under another type
//! give another id; this is what lets a signature container or HPKE header name a key without
//! ambiguity.
//!
//! **Fail closed.** [`KeyType::from_u8`] rejects `0x00`, the reserved post-quantum range
//! `0x10`–`0x1F` and every undefined value, so a parser never guesses the meaning of a key type
//! it does not know (§9.7, §13).

use core::fmt;

use rand_core::CryptoRng;
use sha2::{Digest as _, Sha256};
use subtle::{Choice, ConstantTimeEq};

use crate::error::{DerivationError, ParseError};
use crate::labels;
use crate::secret::Key32;

/// Length of every id and key id.
pub const ID_LEN: usize = 16;

/// Writes `bytes` as lowercase hex, two digits per byte, for the `Debug` impls of the id types.
/// Only public identifiers are passed to it, never key material.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

/// Defines one 16-byte random id type per entry: a `Copy` newtype over `[u8; 16]` with a
/// CSPRNG constructor, byte constructors and accessors, `AsRef<[u8]>`, ordering by bytes, and a
/// hex `Debug`. Equality is ordinary `==`: these ids are public.
macro_rules! random_ids {
    ($( $(#[$doc:meta])* $name:ident; )+) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// Draws a fresh id from the injected CSPRNG (CRYPTO.md §2, §12.1).
            #[must_use]
            pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
                let mut bytes = [0u8; ID_LEN];
                rng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Wraps 16 bytes received from elsewhere (the wire, storage).
            ///
            /// An id read from untrusted input is only a claim: it gains meaning when it is
            /// bound into an AAD context or a signed statement that then verifies.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// Parses an id from exactly 16 bytes.
            ///
            /// # Errors
            /// [`ParseError::InvalidLength`] if `bytes` is not 16 bytes long.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseError> {
                <[u8; ID_LEN]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| ParseError::InvalidLength)
            }

            /// The id's bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            /// The id's bytes, by value.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; ID_LEN] {
                self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "("))?;
                write_hex(f, &self.0)?;
                f.write_str(")")
            }
        }
    )+};
}

random_ids! {
    /// `account_id`. Also the OPAQUE `credential_identifier` of a real account (§5.3).
    AccountId;
    /// `device_id`.
    DeviceId;
    /// `vault_id`.
    VaultId;
    /// `item_id`.
    ItemId;
    /// `op_id` of a sync op.
    OpId;
    /// `snapshot_id` of an item snapshot.
    SnapshotId;
    /// `attachment_id` (M3).
    AttachmentId;
    /// `share_id` (M5). Also the salt of the share derivations (§4.3).
    ShareId;
    /// `message_id` of a stored mail message (M6).
    MessageId;
    /// `pairing_id` (M4).
    PairingId;
    /// `transfer_id` of a re-sync transfer (M4).
    TransferId;
    /// `export_id` of an encrypted export (§11.14).
    ExportId;
    /// `backup_id` of a server-secrets backup (§5.11). Generated by the server.
    BackupId;
    /// `login_id` of a pending OPAQUE login (§5.10). Generated by the server.
    LoginId;
    /// `session_id` of a device-authenticated session (§5.10). Generated by the server.
    SessionId;
}

/// The id of a symmetric key, derived from the key (CRYPTO.md §4.3, §4.4):
/// `HKDF(ikm = K, salt = empty, info = LABEL("key-id/symmetric") ‖ 0x00, 16)`.
///
/// It goes in envelope headers so a reader can find the key; the reader derives the id of each
/// key it holds and compares. Because it is derived from a secret, equality is constant-time.
///
/// It reveals nothing useful about a random key: HKDF under its own label is independent of
/// every other use of the key (CRYPTO.md §1 rule 4). The signed `account-state` commits to the
/// current account key's id (`account_key_id`, §10.2).
#[derive(Clone, Copy, Eq)]
pub struct SymmetricKeyId([u8; ID_LEN]);

impl SymmetricKeyId {
    /// Derives the id of `key`.
    ///
    /// HKDF with `L = 16` is the first 16 bytes of HKDF-Expand's first block. The id is written
    /// into a plain array: it is public by design.
    ///
    /// # Errors
    /// [`DerivationError`], which cannot happen for this fixed output length.
    pub fn derive(key: &Key32) -> Result<Self, DerivationError> {
        let mut id = [0u8; ID_LEN];
        crate::kdf::hkdf_sha256(
            key.expose_secret(),
            None,
            labels::KEY_ID_SYMMETRIC,
            &[],
            &mut id,
        )?;
        Ok(Self(id))
    }

    /// Wraps 16 key-id bytes read from an envelope header or a signed statement.
    ///
    /// Such a value is only a claim; compare it with the id derived from a key the caller holds.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

// Constant-time equality (CRYPTO.md §12.3); `PartialEq` below delegates to it, and `Hash` hashes
// the same bytes, so the type is usable as a map key consistently with `Eq`.
impl ConstantTimeEq for SymmetricKeyId {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SymmetricKeyId {
    /// Constant-time (CRYPTO.md §12.3).
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl core::hash::Hash for SymmetricKeyId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for SymmetricKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKeyId(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

/// Public key types (CRYPTO.md §4.4). `0x10`–`0x1F` are reserved for post-quantum keys and
/// are rejected until they are specified.
///
/// The type byte enters every public key id, and a key bundle lists its keys by type, sorted
/// strictly ascending (§10.2). A bundle carries only `0x01`–`0x03`; device certificates carry
/// `0x04` and `0x05`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum KeyType {
    /// Identity Ed25519 signing key.
    IdentityEd25519 = 0x01,
    /// Identity X25519 key: the recipient of HPKE Base-mode (`alg_id` `0x10`) member grants.
    IdentityX25519 = 0x02,
    /// Mail X25519 key (M6).
    MailX25519 = 0x03,
    /// Device Ed25519 signing key.
    DeviceEd25519 = 0x04,
    /// Device X25519 key: the recipient of device grants.
    DeviceX25519 = 0x05,
}

impl KeyType {
    /// Every defined key type, in ascending order of its byte.
    pub const ALL: [Self; 5] = [
        Self::IdentityEd25519,
        Self::IdentityX25519,
        Self::MailX25519,
        Self::DeviceEd25519,
        Self::DeviceX25519,
    ];

    /// The `u8` encoding.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Parses a `key_type` byte.
    ///
    /// # Errors
    /// [`ParseError::InvalidValue`] for `0x00`, the reserved post-quantum range `0x10`–`0x1F`
    /// and every other undefined value.
    pub const fn from_u8(value: u8) -> Result<Self, ParseError> {
        match value {
            0x01 => Ok(Self::IdentityEd25519),
            0x02 => Ok(Self::IdentityX25519),
            0x03 => Ok(Self::MailX25519),
            0x04 => Ok(Self::DeviceEd25519),
            0x05 => Ok(Self::DeviceX25519),
            _ => Err(ParseError::InvalidValue),
        }
    }
}

/// Length of every public key of the M1 key types (Ed25519 and X25519).
pub const PUBLIC_KEY_LEN: usize = 32;

/// The id of a public key (CRYPTO.md §4.3):
/// `SHA-256(LABEL("key-id") ‖ 0x00 ‖ u8(key_type) ‖ public_key)[0..16]`.
///
/// It names the recipient key in an HPKE envelope header (§9.2), the signer in a signature
/// container (§9.3), and a retired key in the `RETIRED_SECRET_KEY` context. Derived from public
/// data only, so `==` is an ordinary comparison. A 128-bit truncation is enough to name a key;
/// authenticity always comes from the signature or decryption that follows, not from the id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyId([u8; ID_LEN]);

impl PublicKeyId {
    /// Derives the id of a public key of the given type.
    ///
    /// The caller supplies the type; it is part of the hash input, so passing the wrong type
    /// gives an id that matches nothing.
    #[must_use]
    pub fn derive(key_type: KeyType, public_key: &[u8; PUBLIC_KEY_LEN]) -> Self {
        // The id is a prefix of the 32-byte digest, so the copy below writes every byte of it.
        const _: () = assert!(ID_LEN <= 32);
        let digest = Sha256::new()
            .chain_update(labels::KEY_ID.as_bytes())
            .chain_update([0x00, key_type.to_u8()])
            .chain_update(public_key)
            .finalize();
        let digest: [u8; 32] = digest.into();
        // Keep digest[0..16]: `zip` stops at the shorter `id`, so no indexing is needed.
        let mut id = [0u8; ID_LEN];
        id.iter_mut().zip(digest).for_each(|(dst, src)| *dst = src);
        Self(id)
    }

    /// Wraps 16 key-id bytes read from a header, container or statement.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for PublicKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKeyId(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! Id generation from the injected RNG, parsing and `Debug`, the symmetric key id against
    //! an independent HKDF computation and a known answer, the public key id layout, and the
    //! key-type parser's rejection of reserved and undefined values.

    use super::*;
    use crate::test_util::{hex, seeded_rng};

    #[test]
    fn random_ids_come_from_the_injected_rng() {
        let a = AccountId::generate(&mut seeded_rng(3));
        let b = AccountId::generate(&mut seeded_rng(3));
        assert_eq!(a, b);
        let mut rng = seeded_rng(3);
        let first = DeviceId::generate(&mut rng);
        let second = DeviceId::generate(&mut rng);
        assert_ne!(first, second);
        assert_eq!(first.as_bytes(), a.as_bytes());
    }

    #[test]
    fn id_parsing_and_debug() {
        let id = VaultId::from_slice(&[0xab; 16]).unwrap();
        assert_eq!(id.to_bytes(), [0xab; 16]);
        assert_eq!(id.as_ref(), &[0xab; 16]);
        assert_eq!(
            format!("{id:?}"),
            "VaultId(abababababababababababababababab)"
        );
        assert_eq!(ItemId::from_slice(&[0; 15]), Err(ParseError::InvalidLength));
        assert_eq!(ItemId::from_slice(&[0; 17]), Err(ParseError::InvalidLength));
    }

    #[test]
    fn symmetric_key_id_is_hkdf_of_the_key() {
        // Independent computation: HKDF-SHA-256 with a zero-length salt (RFC 5869: HashLen
        // zeros), info = "rizzy-vault/v1/key-id/symmetric" || 0x00, L = 16.
        let key = Key32::from_slice(&[0x11; 32]).unwrap();
        let mut expected = [0u8; 16];
        hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), &[0x11; 32])
            .expand(b"rizzy-vault/v1/key-id/symmetric\x00", &mut expected)
            .unwrap();
        let id = SymmetricKeyId::derive(&key).unwrap();
        assert_eq!(id.as_bytes(), &expected);
        assert_eq!(key.key_id().unwrap(), id);
        // L = 16 is the first 16 bytes of the L = 32 output (HKDF-Expand T(1)).
        let mut long = [0u8; 32];
        hkdf::Hkdf::<Sha256>::new(None, &[0x11; 32])
            .expand(b"rizzy-vault/v1/key-id/symmetric\x00", &mut long)
            .unwrap();
        assert_eq!(&long[..16], id.as_bytes());
        // Known answer, computed independently with Python `cryptography` 41.0.7
        // (`HKDF(SHA256(), length=16, salt=None, info=b"rizzy-vault/v1/key-id/symmetric\0")`)
        // and cross-checked with Python's `hmac` module.
        assert_eq!(id.as_bytes().as_slice(), hex(KEY_ID_OF_0X11).as_slice());
    }

    const KEY_ID_OF_0X11: &str = "3961f732bceb9056d953baad8dbfaecf";

    #[test]
    fn symmetric_key_ids_differ_per_key_and_compare_by_value() {
        let a = Key32::from_slice(&[1; 32]).unwrap().key_id().unwrap();
        let b = Key32::from_slice(&[2; 32]).unwrap().key_id().unwrap();
        assert_ne!(a, b);
        assert_eq!(a, SymmetricKeyId::from_bytes(*a.as_bytes()));
        assert!(bool::from(
            a.ct_eq(&SymmetricKeyId::from_bytes(*a.as_bytes()))
        ));
        assert!(format!("{a:?}").starts_with("SymmetricKeyId("));
    }

    #[test]
    fn public_key_id_layout() {
        let pk = [0x5a; 32];
        let mut msg = b"rizzy-vault/v1/key-id\x00".to_vec();
        msg.push(0x04);
        msg.extend_from_slice(&pk);
        let digest = Sha256::digest(&msg);
        let id = PublicKeyId::derive(KeyType::DeviceEd25519, &pk);
        assert_eq!(id.as_bytes(), &digest[..16]);
        // The key type is bound: same bytes, different type, different id.
        assert_ne!(id, PublicKeyId::derive(KeyType::DeviceX25519, &pk));
    }

    #[test]
    fn key_types_round_trip_and_reserved_values_are_rejected() {
        for kt in KeyType::ALL {
            assert_eq!(KeyType::from_u8(kt.to_u8()), Ok(kt));
        }
        for v in [0x00, 0x06, 0x0f, 0x10, 0x15, 0x1f, 0x20, 0xff] {
            assert_eq!(KeyType::from_u8(v), Err(ParseError::InvalidValue), "{v:#x}");
        }
    }
}
