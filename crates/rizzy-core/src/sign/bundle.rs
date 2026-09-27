//! The `public-key-bundle` statement and the bundle chain (CRYPTO.md §9.6, §10.2, §10.3,
//! §11.3 step 3; ADR 0006 decisions 10–12).
//!
//! A key bundle publishes an account's public keys. Senders choose their algorithm from it
//! (§9.5 rule 3, `pq_required`), `account-state` commits to it through `bundle_hash`, and every
//! verifier pins it: the account's own devices, contacts (M9) and the `smtp` role (M6). The
//! bundles of one account form a hash chain, so a verifier that holds one bundle can tell a
//! legitimate successor from a rollback, a fork or a substituted key.
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
//! first (§9.6). The two signing keys are therefore always distinct.
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
//!   update (a PQ key, a new mail key).
//! - An identity change replaces **both** identity keys, the Ed25519 and the X25519 key (§10.2,
//!   §11.6 step 2). It needs `identity_epoch + 1` and a valid signature by the pinned identity
//!   key too, and it is a visible "safety number changed" event
//!   ([`BundleStep::IdentityChanged`]). A bundle that changes only one of the two identity keys
//!   is rejected, whatever its `identity_epoch`; the writer refuses to make one.
//!
//! **Verifying a successor, step by step** ([`VerifiedBundle::verify_successor`]):
//! 1. Verify the candidate on its own: strict layout and the self-signature by the identity key
//!    inside it ([`PublicKeyBundle::verify_self_signed`]).
//! 2. Same account as the pinned bundle.
//! 3. Compare `bundle_seq` with the pinned one: lower is a rollback; equal is either the pinned
//!    bundle again (same hash) or a fork; more than one higher is a gap to fill first.
//! 4. At `bundle_seq + 1`, `prev_bundle_hash` must be the pinned bundle's hash, or it is a fork.
//! 5. Both identity keys kept: the epoch must be unchanged and there must be no second
//!    signature. Identity keys changed: the epoch must be `+1`, both keys must be new, and the
//!    second container must verify under the pinned identity key.
//!
//! **What this defends against.** A server that substitutes an account's keys: a new key is
//! accepted only through a chain from the pin, and an identity change also needs the pinned
//! identity key's signature and is always shown to the user ([`BundleStep::IdentityChanged`]).
//! A server that serves an older, validly signed bundle to strip `pq_required` or withhold the
//! current mail key: rejected as a rollback. A server that shows different bundles to different
//! verifiers: a fork, once a verifier sees both.
//!
//! **What it does not defend against.** First contact: [`PublicKeyBundle::verify_self_signed`]
//! only proves that the bundle's own identity key signed it, so trust on first use is only as
//! good as the first fetch; fingerprints (§10.3) and, post-1.0, key transparency are the answer.
//! A holder of the old identity key, such as a compromised revoked device, can sign a chained
//! identity change; that is why an identity change is always a visible event that the user
//! confirms (§11.3 step 3, §11.6 "Known limitation"). A server that shows one verifier only one
//! branch forever cannot be caught by that verifier alone.
//!
//! Pinning is the caller's: this module returns the verified successor, and the caller stores
//! it (and its `bundle_seq` and hash) as the new pin.

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

/// Length of a `SHA-256` output: `prev_bundle_hash` and the bundle hash.
const HASH_LEN: usize = 32;

/// Flag bit 0: `pq_required` (§9.5 rule 3). Every other flag bit must be zero.
pub const FLAG_PQ_REQUIRED: u8 = 0x01;

/// Longest possible M1 bundle body: three 32-byte keys (identity Ed25519, identity X25519,
/// mail X25519), each as `u8 key_type ‖ bytes(public_key)`. It bounds the length prefix before
/// any parsing. A bundle with a post-quantum key needs a larger bound, which every verifier
/// ships before any bundle carries one (§9.7 step 2).
const MAX_BODY_LEN: usize = ID_LEN + 4 + 8 + 1 + 3 * (1 + 4 + PUBLIC_KEY_LEN) + 1 + 8 + HASH_LEN;

/// `public-key-bundle` (§10.2).
///
/// The fields are public so a writer can build a bundle; the format rules are checked when it
/// is signed and when it is parsed, not on construction. A `PublicKeyBundle` value proves
/// nothing by itself: only a [`VerifiedBundle`] has passed a signature check.
///
/// To publish a bundle that keeps both identity keys (the first bundle, a new mail key, a PQ
/// key), call [`PublicKeyBundle::sign`]; to publish one that replaces them (a full rotation),
/// call [`PublicKeyBundle::sign_identity_change`] with the current bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyBundle {
    /// The account.
    pub account_id: AccountId,
    /// The identity epoch of the identity keys in this bundle: 0 at signup, `+1` on each
    /// identity change (§4.4).
    pub identity_epoch: u32,
    /// Position in the chain: 1 for the first bundle, `+1` for every new bundle, whether or not
    /// the identity keys change (§4.4).
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
    /// The field rules that hold for a bundle on its own, shared by the writer and the parser:
    /// `bundle_seq ≥ 1`, `prev_bundle_hash` is zero exactly when `bundle_seq = 1`, and the first
    /// bundle has `identity_epoch = 0` (§4.4, §10.2). The rules that need the predecessor are in
    /// [`VerifiedBundle::verify_successor`].
    fn validate(&self) -> Result<(), ParseError> {
        let first = self.bundle_seq == 1;
        let no_prev = self.prev_bundle_hash == [0u8; HASH_LEN];
        if self.bundle_seq == 0 || first != no_prev || (first && self.identity_epoch != 0) {
            return Err(ParseError::InvalidValue);
        }
        Ok(())
    }

    /// The two identity public keys, as a device compares them with the keys it derived from
    /// `E_id` (§11.2 step 6) and as the account fingerprint covers them (§10.3).
    #[must_use]
    pub const fn identity_public_keys(&self) -> IdentityPublicKeys {
        IdentityPublicKeys {
            ed25519: self.identity_ed25519,
            x25519: self.identity_x25519,
        }
    }

    /// Encodes the canonical body (layout in the module docs).
    ///
    /// Entries are written in ascending `key_type` order, which is the order the parser
    /// requires: `0x01`, `0x02`, then `0x03` if there is a mail key.
    ///
    /// # Errors
    /// [`EncodeError::InvalidField`] if a [`PublicKeyBundle::validate`] rule is broken.
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

    /// Decodes and validates a body strictly (§10.2).
    ///
    /// Rejects: an unknown or reserved `key_type` (including `0x10`–`0x1F`), a device key type,
    /// entries out of strictly ascending order (so no duplicates), a key that is not 32 bytes,
    /// an identity Ed25519 key that is non-canonical or of small order, a missing identity key,
    /// a flag bit other than bit 0, trailing bytes, and any [`PublicKeyBundle::validate`] rule.
    /// An entry it cannot read is an error, never skipped.
    ///
    /// The identity and mail X25519 keys are taken as raw 32 bytes; a small-order X25519 key
    /// fails later, when a sender seals to it.
    ///
    /// # Errors
    /// [`ParseError`].
    pub(crate) fn decode_body(body: &[u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(body);
        let account_id = AccountId::from_bytes(*r.array()?);
        let identity_epoch = r.u32()?;
        let bundle_seq = r.u64()?;
        let n = r.u8()?;
        let (mut ed25519, mut x25519, mut mail) = (None, None, None);
        let mut previous_type: Option<KeyType> = None;
        // `n` is attacker-chosen, but the loop ends early: each entry must carry a defined key
        // type strictly above the previous one, and the device types fail, so at most three
        // entries are accepted before an error or the end of `n`.
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
        // Flag bits other than `pq_required` must be zero (§10.2).
        let flags = r.u8()?;
        if flags & !FLAG_PQ_REQUIRED != 0 {
            return Err(ParseError::InvalidValue);
        }
        let bundle = Self {
            account_id,
            identity_epoch,
            bundle_seq,
            // Both identity keys are required; the mail key is optional (M6).
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
    /// This function has no predecessor to compare with, so it cannot check that the identity
    /// keys are kept. The caller sets `bundle_seq + 1`, the predecessor's hash and the same
    /// `identity_epoch`; a bundle that changes identity keys but is signed here has no second
    /// signature, and [`VerifiedBundle::verify_successor`] rejects it.
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

    /// Signs a bundle that changes the identity keys (a full rotation, §11.6 step 2) as the
    /// successor of `predecessor`, the current bundle: the self-signature by the new identity
    /// key first, then the signature by the preceding identity key (§9.6).
    ///
    /// The bundle must replace **both** identity keys of `predecessor` (§10.2, §11.6 step 2)
    /// and be its successor, so the writer makes only what
    /// [`VerifiedBundle::verify_successor`] accepts as [`BundleStep::IdentityChanged`].
    ///
    /// # Errors
    /// - [`SignError::WrongKey`] if `new_identity` is not the bundle's identity key,
    ///   `previous_identity` is not `predecessor`'s, or the two are the same key (the bundle
    ///   keeps the Ed25519 identity key).
    /// - [`SignError::Encode`] if the bundle keeps `predecessor`'s identity X25519 key, is not
    ///   its successor (the same account, `bundle_seq + 1`, `prev_bundle_hash` = its hash,
    ///   `identity_epoch + 1`), or another rule of the format is broken.
    ///
    /// Security: `previous_identity` is the superseded identity key. It must be the key of the
    /// current bundle, which the caller fetched and verified; this function checks that it
    /// matches `predecessor`, not that `predecessor` is current.
    pub fn sign_identity_change(
        &self,
        predecessor: &VerifiedBundle,
        new_identity: &IdentitySigningKey,
        previous_identity: &IdentitySigningKey,
    ) -> Result<Vec<u8>, SignError> {
        if new_identity.verifying_key() != &self.identity_ed25519
            || previous_identity.verifying_key() != &predecessor.identity_ed25519
            || self.identity_ed25519 == predecessor.identity_ed25519
        {
            return Err(SignError::WrongKey);
        }
        if self.identity_x25519 == predecessor.identity_x25519
            || self.account_id != predecessor.account_id
            || predecessor.bundle_seq.checked_add(1) != Some(self.bundle_seq)
            || self.prev_bundle_hash != *predecessor.hash()
            || predecessor.identity_epoch.checked_add(1) != Some(self.identity_epoch)
        {
            return Err(SignError::Encode(EncodeError::InvalidField));
        }
        let body = self.encode_body()?;
        let message = signed_message(labels::SIG_PUBLIC_KEY_BUNDLE, &body);
        // Both keys sign the same framed message; the new key's container goes first (§9.6).
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
    /// Security: success says only that the bundle's own identity key signed it. Anyone can
    /// make such a bundle for any `account_id` with a key of their own. Pin it only on first
    /// contact, or after checking its keys against `E_id`; every later bundle goes through
    /// [`VerifiedBundle::verify_successor`].
    ///
    /// # Errors
    /// [`VerifyError`]: [`VerifyError::Malformed`] for a bad layout, a disallowed field or
    /// container bytes that are neither one nor two containers;
    /// [`VerifyError::UnsupportedVersion`] for an unknown statement or container version;
    /// [`VerifyError::WrongSigner`] or [`VerifyError::BadSignature`] if the first container is
    /// not a valid signature by the bundle's identity key; [`VerifyError::Mismatch`] for two
    /// containers on a bundle with `bundle_seq = 1` or `identity_epoch = 0`.
    pub fn verify_self_signed(wire: &[u8]) -> Result<VerifiedBundle, VerifyError> {
        let (body, containers) = split_wire(wire, MAX_BODY_LEN)?;
        // One container, or two for an identity change (§9.6); any other length is malformed.
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
        // The first container is the self-signature, by the (new) identity key in the body.
        bundle.identity_ed25519.verify_container(&message, &first)?;
        // A second signature only makes sense on an identity change, which is never the first
        // bundle and never epoch 0.
        if second.is_some() && (bundle.bundle_seq < 2 || bundle.identity_epoch == 0) {
            return Err(VerifyError::Mismatch);
        }
        // The message is kept so `verify_successor` can check the second container later.
        Ok(VerifiedBundle {
            hash: Sha256::digest(&message).into(),
            bundle,
            message,
            predecessor_signature: second,
        })
    }
}

/// A bundle whose self-signature verified, with its hash.
///
/// Built only by [`PublicKeyBundle::verify_self_signed`] and
/// [`VerifiedBundle::verify_successor`]. It is what a verifier pins, and the `self` of
/// [`VerifiedBundle::verify_successor`] for the next bundle. It dereferences to the
/// [`PublicKeyBundle`], so its fields read directly.
///
/// A second container, if any, is carried unverified until `verify_successor` checks it
/// against the pinned bundle; see [`VerifiedBundle::has_predecessor_signature`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    /// The decoded bundle.
    bundle: PublicKeyBundle,
    /// `SHA-256` of the full signed message: `bundle_hash`, and the next bundle's
    /// `prev_bundle_hash`.
    hash: [u8; HASH_LEN],
    /// The full signed message, kept so the predecessor's signature can be checked over it.
    message: Vec<u8>,
    /// The second container, which an identity change carries for the preceding identity key.
    /// Not verified until [`VerifiedBundle::verify_successor`] runs with the predecessor
    /// pinned.
    predecessor_signature: Option<SignatureContainer>,
}

/// How a verified successor relates to the pinned bundle.
///
/// The caller acts on it: pin the new bundle for [`BundleStep::Silent`], show the new
/// fingerprint and wait for the user for [`BundleStep::IdentityChanged`], nothing for
/// [`BundleStep::Unchanged`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BundleStep {
    /// The same bundle as the pinned one: the same `bundle_seq` and the same hash. The hash
    /// covers the signed message, not the containers, so the containers may differ from the
    /// pinned copy's.
    Unchanged,
    /// The next bundle, with both identity keys kept: accept silently (§10.3).
    Silent,
    /// The next bundle, with both identity keys replaced, signed by the new and the pinned
    /// identity key. A visible "safety number changed" event; the user confirms the new
    /// fingerprint (§10.3, §11.3 step 3).
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
    ///
    /// Raised for a different bundle with the pinned `bundle_seq`, and for a bundle at
    /// `bundle_seq + 1` whose `prev_bundle_hash` is not the pinned bundle's hash (another
    /// branch of the chain).
    Fork,
    /// Its `bundle_seq` is more than one above the pinned one: fetch the bundles in between
    /// and walk them with [`VerifiedBundle::verify_chain`]. Not an alarm by itself.
    Gap,
    /// The identity keys changed without a valid signature by the pinned identity key: the
    /// second container is missing, names another key or does not verify.
    IdentityChangeNotSigned,
    /// The `identity_epoch` does not follow the identity keys: not `+1` on a change, or changed
    /// while the keys stayed, or a second signature on a bundle that keeps its keys.
    IdentityEpochMismatch,
    /// An identity change (`identity_epoch + 1`) that keeps one of the two identity keys. An
    /// identity change replaces both the Ed25519 and the X25519 identity key (§10.2, §11.6
    /// step 2).
    IdentityKeyKept,
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
            Self::IdentityKeyKept => {
                f.write_str("identity change keeps one of the two identity keys")
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
    /// The steps are listed in the module docs. This is the only place a bundle's second
    /// signature is checked, and only one step at a time: for a bundle more than one step
    /// ahead, walk the bundles in between ([`VerifiedBundle::verify_chain`]).
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
        // Equal hashes mean equal signed messages, so the same bundle; anything else at the
        // same position is a second version of it.
        if candidate.bundle_seq == pinned.bundle_seq {
            return if next.hash == self.hash {
                Ok((next, BundleStep::Unchanged))
            } else {
                Err(BundleChainError::Fork)
            };
        }
        // Cannot underflow: `candidate.bundle_seq > pinned.bundle_seq` here.
        if candidate.bundle_seq - pinned.bundle_seq > 1 {
            return Err(BundleChainError::Gap);
        }
        // The immediate successor must name the pinned bundle; one that names anything else
        // belongs to another branch.
        if candidate.prev_bundle_hash != self.hash {
            return Err(BundleChainError::Fork);
        }
        // "Changed" means either identity key differs. Only a change of both is valid.
        let keys_changed = candidate.identity_public_keys() != pinned.identity_public_keys();
        let step = if keys_changed {
            if pinned.identity_epoch.checked_add(1) != Some(candidate.identity_epoch) {
                return Err(BundleChainError::IdentityEpochMismatch);
            }
            if candidate.identity_ed25519 == pinned.identity_ed25519
                || candidate.identity_x25519 == pinned.identity_x25519
            {
                return Err(BundleChainError::IdentityKeyKept);
            }
            // The old key vouches for the new one: the second container must verify under the
            // pinned identity key, over the same signed message.
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
            // Keys kept: a silent update, which never bumps the epoch and never carries a
            // second signature.
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
    /// Pass the bundles with `bundle_seq` above the pinned one, in ascending order. An empty
    /// list returns `self` unchanged; a repeat of the current bundle is an
    /// [`BundleStep::Unchanged`] step and is accepted. When the result says the identity keys
    /// changed, the caller shows the new fingerprint and waits for the user before pinning the
    /// returned bundle (§11.3 step 3.2).
    ///
    /// # Errors
    /// The first [`BundleChainError`] met. The steps that passed before it are not returned,
    /// so the caller keeps its current pin.
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
