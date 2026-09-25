//! The `public-key-bundle` statement and the bundle chain (CRYPTO.md §9.6, §10.2, §10.3,
//! §11.3 step 3; ADR 0006 decision 12).
//!
//! Body:
//!
//! ```text
//! account_id ‖ u32 identity_epoch ‖ u64 bundle_seq ‖ u8 n ‖ n × (u8 key_type ‖ bytes(public_key))
//!            ‖ u8 flags (bit 0 = pq_required) ‖ u64 created_at_ms ‖ prev_bundle_hash (32)
//! ```
//!
//! **Entries.** Sorted by `key_type`, strictly ascending, one key per type; parsers reject
//! anything else (§10.2). A bundle holds the account's public keys: the identity Ed25519 key
//! (`0x01`) and the identity X25519 key (`0x02`) are required, the mail X25519 key (`0x03`, M6)
//! is optional. Device keys (`0x04`, `0x05`) are certified by device certificates, never listed
//! in a bundle, and the post-quantum types `0x10`–`0x1F` are rejected until they are specified.
//! Every M1 key is 32 bytes. Flag bits other than bit 0 must be zero.
//!
//! **Signatures.** The bundle is self-signed by the identity Ed25519 key inside it. A bundle
//! whose identity keys differ from its predecessor's (a full rotation, `identity_epoch + 1`) is
//! **also** signed by the preceding identity key, and carries two containers, the new key's
//! first (§9.6).
//!
//! **Chain rules** ([`VerifiedBundle::verify_successor`]).
//! - `bundle_seq` is 1 for the first bundle, and `prev_bundle_hash` is zero exactly then. The
//!   first bundle is made at signup, so its `identity_epoch` is 0 (§4.4).
//! - Each bundle names its immediate predecessor: `prev_bundle_hash = SHA-256` of the
//!   predecessor's full signed message, and `bundle_seq` increases by exactly one per step.
//! - A lower `bundle_seq` than the pinned one is a **rollback**; a different bundle with the
//!   same `bundle_seq`, or one at `bundle_seq + 1` that does not name the pinned bundle, is a
//!   **fork** (a hard alarm, §10.3).
//! - Keeping both identity keys needs the same `identity_epoch` and one signature: a silent
//!   update (a PQ key, a new mail key). Changing either identity key needs `identity_epoch + 1`
//!   and a valid signature by the pinned identity key too; it is a visible "safety number
//!   changed" event ([`BundleStep::IdentityChanged`]).

use core::fmt;
use core::ops::Deref;

use sha2::{Digest as _, Sha256};

use super::{
    CONTAINER_LEN, IdentitySigningKey, IdentityVerifyingKey, SignatureContainer, encode_wire,
    read_key_bytes, signed_message, split_wire,
};
use crate::encoding::{Reader, put_bytes, put_u8, put_u32, put_u64};
use crate::error::{EncodeError, ParseError, SignError, VerifyError};
use crate::hpke::HpkePublicKey;
use crate::ids::{AccountId, ID_LEN, KeyType, PUBLIC_KEY_LEN};
use crate::keys::IdentityPublicKeys;
use crate::labels;

const HASH_LEN: usize = 32;

/// Flag bit 0: `pq_required` (§9.5 rule 3).
pub const FLAG_PQ_REQUIRED: u8 = 0x01;

/// Longest possible M1 bundle body: three 32-byte keys.
const MAX_BODY_LEN: usize = ID_LEN + 4 + 8 + 1 + 3 * (1 + 4 + PUBLIC_KEY_LEN) + 1 + 8 + HASH_LEN;

/// `public-key-bundle` (§10.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyBundle {
    /// The account.
    pub account_id: AccountId,
    /// The identity epoch of the identity keys in this bundle.
    pub identity_epoch: u32,
    /// Position in the chain: 1 for the first bundle.
    pub bundle_seq: u64,
    /// Identity Ed25519 key (`key_type` `0x01`); signs this bundle.
    pub identity_ed25519: IdentityVerifyingKey,
    /// Identity X25519 key (`key_type` `0x02`, HPKE `0x10`).
    pub identity_x25519: HpkePublicKey,
    /// Mail X25519 key (`key_type` `0x03`, M6), if any.
    pub mail_x25519: Option<HpkePublicKey>,
    /// `pq_required` (flag bit 0): classical grants to this account are rejected (§9.5).
    pub pq_required: bool,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// `SHA-256` of the preceding bundle's signed message; zero only for `bundle_seq` 1.
    pub prev_bundle_hash: [u8; HASH_LEN],
}

impl PublicKeyBundle {
    fn validate(&self) -> Result<(), ParseError> {
        let first = self.bundle_seq == 1;
        let no_prev = self.prev_bundle_hash == [0u8; HASH_LEN];
        if self.bundle_seq == 0 || first != no_prev || (first && self.identity_epoch != 0) {
            return Err(ParseError::InvalidValue);
        }
        Ok(())
    }

    /// The two identity public keys.
    #[must_use]
    pub const fn identity_public_keys(&self) -> IdentityPublicKeys {
        IdentityPublicKeys {
            ed25519: self.identity_ed25519,
            x25519: self.identity_x25519,
        }
    }

    pub(crate) fn encode_body(&self) -> Result<Vec<u8>, EncodeError> {
        self.validate().map_err(|_| EncodeError::InvalidField)?;
        let mut entries: Vec<(KeyType, &[u8; PUBLIC_KEY_LEN])> = vec![
            (KeyType::IdentityEd25519, self.identity_ed25519.as_bytes()),
            (KeyType::IdentityX25519, self.identity_x25519.as_bytes()),
        ];
        if let Some(mail) = &self.mail_x25519 {
            entries.push((KeyType::MailX25519, mail.as_bytes()));
        }
        let n = u8::try_from(entries.len()).map_err(|_| EncodeError::TooLong)?;
        let mut out = Vec::with_capacity(MAX_BODY_LEN);
        out.extend_from_slice(self.account_id.as_bytes());
        put_u32(&mut out, self.identity_epoch);
        put_u64(&mut out, self.bundle_seq);
        put_u8(&mut out, n);
        for (key_type, key) in entries {
            put_u8(&mut out, key_type.to_u8());
            put_bytes(&mut out, key)?;
        }
        put_u8(
            &mut out,
            if self.pq_required {
                FLAG_PQ_REQUIRED
            } else {
                0
            },
        );
        put_u64(&mut out, self.created_at_ms);
        out.extend_from_slice(&self.prev_bundle_hash);
        Ok(out)
    }

    pub(crate) fn decode_body(body: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(body);
        let account_id = AccountId::from_bytes(*r.array()?);
        let identity_epoch = r.u32()?;
        let bundle_seq = r.u64()?;
        let n = r.u8()?;
        let (mut ed25519, mut x25519, mut mail) = (None, None, None);
        let mut previous_type: Option<KeyType> = None;
        for _ in 0..n {
            let key_type = KeyType::from_u8(r.u8()?)?;
            if previous_type.is_some_and(|p| p >= key_type) {
                return Err(ParseError::InvalidValue);
            }
            previous_type = Some(key_type);
            let key = read_key_bytes(&mut r)?;
            match key_type {
                KeyType::IdentityEd25519 => {
                    ed25519 = Some(IdentityVerifyingKey::from_bytes(key)?);
                }
                KeyType::IdentityX25519 => x25519 = Some(HpkePublicKey::x25519(*key)),
                KeyType::MailX25519 => mail = Some(HpkePublicKey::x25519(*key)),
                KeyType::DeviceEd25519 | KeyType::DeviceX25519 => {
                    return Err(ParseError::InvalidValue);
                }
            }
        }
        let flags = r.u8()?;
        if flags & !FLAG_PQ_REQUIRED != 0 {
            return Err(ParseError::InvalidValue);
        }
        let bundle = Self {
            account_id,
            identity_epoch,
            bundle_seq,
            identity_ed25519: ed25519.ok_or(ParseError::InvalidValue)?,
            identity_x25519: x25519.ok_or(ParseError::InvalidValue)?,
            mail_x25519: mail,
            pq_required: flags & FLAG_PQ_REQUIRED != 0,
            created_at_ms: r.u64()?,
            prev_bundle_hash: *r.array()?,
        };
        r.finish()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Signs a bundle that keeps the preceding bundle's identity keys, or the first bundle:
    /// one self-signature by the identity key inside it.
    ///
    /// # Errors
    /// [`SignError::WrongKey`] if `identity` is not the bundle's identity Ed25519 key;
    /// [`SignError::Encode`] if a rule of the format is broken.
    pub fn sign(&self, identity: &IdentitySigningKey) -> Result<Vec<u8>, SignError> {
        if identity.verifying_key() != &self.identity_ed25519 {
            return Err(SignError::WrongKey);
        }
        let body = self.encode_body()?;
        let message = signed_message(labels::SIG_PUBLIC_KEY_BUNDLE, &body);
        let container = identity.sign_message(&message)?;
        Ok(encode_wire(&body, &[container])?)
    }

    /// Signs a bundle that changes the identity keys (a full rotation): the self-signature by
    /// the new identity key first, then the signature by the preceding identity key (§9.6).
    ///
    /// # Errors
    /// [`SignError::WrongKey`] if `new_identity` is not the bundle's identity key, or the two
    /// keys are the same; [`SignError::Encode`] if this cannot be an identity change (the first
    /// bundle, or `identity_epoch` 0) or another rule is broken.
    pub fn sign_identity_change(
        &self,
        new_identity: &IdentitySigningKey,
        previous_identity: &IdentitySigningKey,
    ) -> Result<Vec<u8>, SignError> {
        if new_identity.verifying_key() != &self.identity_ed25519
            || previous_identity.verifying_key() == &self.identity_ed25519
        {
            return Err(SignError::WrongKey);
        }
        if self.bundle_seq < 2 || self.identity_epoch == 0 {
            return Err(SignError::Encode(EncodeError::InvalidField));
        }
        let body = self.encode_body()?;
        let message = signed_message(labels::SIG_PUBLIC_KEY_BUNDLE, &body);
        let first = new_identity.sign_message(&message)?;
        let second = previous_identity.sign_message(&message)?;
        Ok(encode_wire(&body, &[first, second])?)
    }

    /// Verifies a bundle on its own: the strict layout and the self-signature by the identity
    /// key inside it. This is what trust on first use pins (§10.3), and what a device checks
    /// against the keys it decrypted from `E_id` (§11.2 step 6).
    ///
    /// A bundle with two containers (an identity change) is accepted here with its second
    /// signature **not yet verified**: that needs the predecessor, and
    /// [`VerifiedBundle::verify_successor`] checks it. It must then have `bundle_seq ≥ 2` and
    /// `identity_epoch ≥ 1`.
    ///
    /// # Errors
    /// [`VerifyError`].
    pub fn verify_self_signed(wire: &[u8]) -> Result<VerifiedBundle, VerifyError> {
        let (body, containers) = split_wire(wire, MAX_BODY_LEN)?;
        let (first, second) = match containers.len() {
            CONTAINER_LEN => (SignatureContainer::from_bytes(containers)?, None),
            len if len == 2 * CONTAINER_LEN => {
                let (a, b) = containers.split_at(CONTAINER_LEN);
                (
                    SignatureContainer::from_bytes(a)?,
                    Some(SignatureContainer::from_bytes(b)?),
                )
            }
            len if len < CONTAINER_LEN => return Err(ParseError::Truncated.into()),
            _ => return Err(ParseError::InvalidLength.into()),
        };
        let bundle = Self::decode_body(body)?;
        let message = signed_message(labels::SIG_PUBLIC_KEY_BUNDLE, body);
        bundle.identity_ed25519.verify_container(&message, &first)?;
        if second.is_some() && (bundle.bundle_seq < 2 || bundle.identity_epoch == 0) {
            return Err(VerifyError::Mismatch);
        }
        Ok(VerifiedBundle {
            hash: Sha256::digest(&message).into(),
            bundle,
            message,
            predecessor_signature: second,
        })
    }
}

/// A bundle whose self-signature verified, with its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    bundle: PublicKeyBundle,
    hash: [u8; HASH_LEN],
    message: Vec<u8>,
    predecessor_signature: Option<SignatureContainer>,
}

/// How a verified successor relates to the pinned bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BundleStep {
    /// The same bundle as the pinned one.
    Unchanged,
    /// The next bundle, with both identity keys kept: accept silently (§10.3).
    Silent,
    /// The next bundle, with new identity keys, signed by the new and the pinned identity key.
    /// A visible "safety number changed" event; the user confirms the new fingerprint
    /// (§10.3, §11.3 step 3).
    IdentityChanged,
}

/// Why a bundle was not accepted as the successor of the pinned one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BundleChainError {
    /// The bundle itself is invalid: layout or self-signature.
    Invalid(VerifyError),
    /// The bundle belongs to another account.
    AccountMismatch,
    /// Its `bundle_seq` is lower than the pinned one: rejected (§10.3 "Rollback").
    Rollback,
    /// Two different bundles at one position of the chain: "the server has shown you two
    /// versions of this person's keys" (§10.3 "Fork"). A hard alarm.
    Fork,
    /// Its `bundle_seq` is more than one above the pinned one: fetch the bundles in between.
    Gap,
    /// The identity keys changed without a valid signature by the pinned identity key.
    IdentityChangeNotSigned,
    /// The `identity_epoch` does not follow the identity keys: not `+1` on a change, or changed
    /// while the keys stayed, or a second signature on a bundle that keeps its keys.
    IdentityEpochMismatch,
}

impl fmt::Display for BundleChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "invalid key bundle: {e}"),
            Self::AccountMismatch => f.write_str("key bundle belongs to another account"),
            Self::Rollback => f.write_str("key bundle is older than the pinned one"),
            Self::Fork => f.write_str("two different key bundles at the same chain position"),
            Self::Gap => f.write_str("key bundles missing between the pinned one and this one"),
            Self::IdentityChangeNotSigned => {
                f.write_str("identity keys changed without the preceding identity key's signature")
            }
            Self::IdentityEpochMismatch => {
                f.write_str("identity epoch does not match the identity key change")
            }
        }
    }
}

impl core::error::Error for BundleChainError {}

impl From<VerifyError> for BundleChainError {
    fn from(e: VerifyError) -> Self {
        Self::Invalid(e)
    }
}

impl VerifiedBundle {
    /// The bundle.
    #[must_use]
    pub const fn bundle(&self) -> &PublicKeyBundle {
        &self.bundle
    }

    /// `SHA-256` of the full signed message: the `bundle_hash` in `account-state` and the next
    /// bundle's `prev_bundle_hash`.
    #[must_use]
    pub const fn hash(&self) -> &[u8; HASH_LEN] {
        &self.hash
    }

    /// Whether the bundle carries a second signature (an identity change), which only
    /// [`VerifiedBundle::verify_successor`] can check.
    #[must_use]
    pub const fn has_predecessor_signature(&self) -> bool {
        self.predecessor_signature.is_some()
    }

    /// Verifies `wire` as the bundle that follows `self`, the pinned bundle (§10.3, §11.3
    /// step 3.1).
    ///
    /// Returns the new bundle and how it relates to the pinned one; the caller pins the new
    /// bundle, and for [`BundleStep::IdentityChanged`] shows the new fingerprint first.
    ///
    /// # Errors
    /// [`BundleChainError`]: [`BundleChainError::Rollback`] and [`BundleChainError::Fork`]
    /// are the alarms of §10.3.
    pub fn verify_successor(&self, wire: &[u8]) -> Result<(Self, BundleStep), BundleChainError> {
        let next = PublicKeyBundle::verify_self_signed(wire)?;
        let (pinned, candidate) = (&self.bundle, &next.bundle);
        if candidate.account_id != pinned.account_id {
            return Err(BundleChainError::AccountMismatch);
        }
        if candidate.bundle_seq < pinned.bundle_seq {
            return Err(BundleChainError::Rollback);
        }
        if candidate.bundle_seq == pinned.bundle_seq {
            return if next.hash == self.hash {
                Ok((next, BundleStep::Unchanged))
            } else {
                Err(BundleChainError::Fork)
            };
        }
        if candidate.bundle_seq - pinned.bundle_seq > 1 {
            return Err(BundleChainError::Gap);
        }
        if candidate.prev_bundle_hash != self.hash {
            return Err(BundleChainError::Fork);
        }
        let keys_changed = candidate.identity_public_keys() != pinned.identity_public_keys();
        let step = if keys_changed {
            if pinned.identity_epoch.checked_add(1) != Some(candidate.identity_epoch) {
                return Err(BundleChainError::IdentityEpochMismatch);
            }
            let signature = next
                .predecessor_signature
                .as_ref()
                .ok_or(BundleChainError::IdentityChangeNotSigned)?;
            pinned
                .identity_ed25519
                .verify_container(&next.message, signature)
                .map_err(|_| BundleChainError::IdentityChangeNotSigned)?;
            BundleStep::IdentityChanged
        } else {
            if candidate.identity_epoch != pinned.identity_epoch
                || next.predecessor_signature.is_some()
            {
                return Err(BundleChainError::IdentityEpochMismatch);
            }
            BundleStep::Silent
        };
        Ok((next, step))
    }

    /// Walks `wires` in order from `self`, each the successor of the one before (§11.3 step
    /// 3.1). Returns the last bundle and whether any step changed the identity keys.
    ///
    /// # Errors
    /// The first [`BundleChainError`] met.
    pub fn verify_chain(&self, wires: &[&[u8]]) -> Result<(Self, bool), BundleChainError> {
        let mut current = self.clone();
        let mut identity_changed = false;
        for wire in wires {
            let (next, step) = current.verify_successor(wire)?;
            identity_changed |= step == BundleStep::IdentityChanged;
            current = next;
        }
        Ok((current, identity_changed))
    }
}

impl Deref for VerifiedBundle {
    type Target = PublicKeyBundle;

    fn deref(&self) -> &PublicKeyBundle {
        &self.bundle
    }
}
