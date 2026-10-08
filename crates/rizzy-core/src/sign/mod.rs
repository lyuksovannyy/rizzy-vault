//! Ed25519 signatures and signed statements (CRYPTO.md §9.3, §9.6, §10.2; ADR 0006 decision 10).
//!
//! This module is the one place in `rizzy-core` that makes or checks an Ed25519 signature. It
//! holds the role-typed keys ([`SigningKey`], [`VerifyingKey`]), the 82-byte
//! [`SignatureContainer`], the framing every statement shares, and the generic single-signer
//! sign and verify paths. The statements themselves live in [`bundle`] (the key bundle and its
//! chain) and [`statements`] (every other statement of §10.2).
//!
//! **Library rules (§10.2).**
//! - `ed25519-dalek` 3.0.0, pure Ed25519 (RFC 8032).
//! - Verification always uses `verify_strict`, which rejects small-order keys, small-order `R`
//!   and non-canonical `s`.
//! - Signing only goes through [`SigningKey`], which holds its own public key, so a signature
//!   can never be made with a mismatched public key (RUSTSEC-2022-0093).
//!
//! **Message framing (§10.2).** Every signed message is
//! `LABEL("sig/<type>") ‖ 0x00 ‖ u16(statement_version = 1) ‖ body`, with `body` a fixed
//! canonical layout. The label is never transmitted: the verifier prepends the label of the
//! statement type it expects, so a statement of one type never verifies as another. Labels
//! contain no `0x00` (§2), so the framing is prefix-free.
//!
//! **Wire form (§9.6).** `bytes(u16(statement_version) ‖ body) ‖ container(s)`, where each
//! container is the 82-byte [`SignatureContainer`] of §9.3. Every statement carries exactly one
//! container, except a key bundle that changes the identity keys, which carries two: the new
//! key's first ([`bundle`]). `bundle_hash`, `prev_bundle_hash` and each certificate hash `h_i`
//! that goes into the device-set hash are `SHA-256` of the full signed message (label, `0x00`,
//! version and body), never of the wire. So the same statement with other containers has the
//! same hash.
//!
//! **Signing, step by step** (the crate-private `sign_single`):
//! 1. The statement encodes its canonical body and refuses values the format does not allow,
//!    so a writer never produces a statement every reader would reject.
//! 2. The body length is checked against the statement type's upper bound.
//! 3. The key signs `LABEL ‖ 0x00 ‖ u16(1) ‖ body`.
//! 4. The wire form `bytes(u16(1) ‖ body) ‖ container` is returned.
//!
//! **Verifying, step by step** (the crate-private `verify_single`):
//! 1. The length prefix is compared with the statement type's upper bound before any body byte
//!    is read, then `statement_version` must be 1.
//! 2. The rest must be exactly one container with `sig_format_version` and `sig_alg` `0x01`.
//! 3. The body is decoded strictly: every field in its allowed set, no trailing bytes.
//! 4. The verifier rebuilds the message with the label of the type it expects, checks that the
//!    container names the key it expects, and runs `verify_strict`.
//! 5. Only then is a [`Verified`] returned, carrying `SHA-256` of the signed message.
//!
//! **Two statements are verified against a rebuilt message.** `device-auth` and
//! `device-request` ([`DeviceAuth`], [`DeviceRequest`]) sign values the verifier already holds
//! (its own origin, the challenge it issued, the request it received). They travel as a bare
//! container, and the verifier rebuilds the message from its own values, the same way an
//! envelope reader rebuilds its AAD. The origin is a [`crate::normalize::ServerOrigin`], so
//! signer and verifier always use the one §2 canonical form.
//!
//! Roles are types: [`IdentitySigningKey`] and [`DeviceSigningKey`] are different types, and
//! each statement names the role that signs it, so a device key cannot sign a device
//! certificate by mistake. `key-grant` is the one statement either role signs; it checks the
//! purpose against the signer's role (the §10.2 table) when signing and when verifying
//! ([`KeyGrant`]). The signer key id in a container is `PublicKeyId(key_type, public_key)`
//! (§4.3) with the role's key type (`0x01` or `0x04`).
//!
//! **Invariants.**
//! - Nothing unverified leaves a verifier: [`Verified`] and [`bundle::VerifiedBundle`] are
//!   built only after the signature check passed.
//! - Decoders are pure, bounded before parsing, and never panic. They read through the bounded
//!   [`Reader`], so a length field is checked against its bound and against the bytes
//!   actually present before anything is copied, and no allocation exceeds the input's size
//!   (fuzz target `signed_statements`).
//! - A [`VerifyingKey`] never holds a key that `verify_strict` would reject for every
//!   signature: non-canonical and small-order encodings are refused at parse time.
//! - Randomness is injected ([`SigningKey::generate`]); Ed25519 signing itself is
//!   deterministic (RFC 8032) and draws none.
//!
//! **What this defends against.** A server or network attacker who forges or alters a
//! statement (every body byte is signed), relabels it as another type (the label is the
//! verifier's), or presents a statement of one role as another (the key types differ, and the
//! container's signer key id must be the expected key's). Malleable and small-order signatures
//! (`verify_strict`). Replay of `device-auth` and `device-request` at another server (the
//! canonical origin is signed).
//!
//! **What it does not defend against.** Replay of an old, validly signed statement: freshness
//! is the caller's, through the sequence numbers and chain rules ([`AccountState::is_rollback`],
//! [`AccountState::is_fork`], [`VerifiedBundle::verify_successor`]) and the server's challenge
//! and request-counter state. Picking the right verifying key is the caller's too: from the
//! pinned bundle, a verified certificate or its cached identity key. And whoever holds a
//! signing key, for example on a stolen unlocked device, can sign anything that key's role may
//! sign; revocation and rotation (§11.6, §11.8) are the answer to that, not this module.

use core::fmt;
use core::marker::PhantomData;
use core::ops::Deref;

use ed25519_dalek::Signer as _;
use rand_core::CryptoRng;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::encoding::{Reader, put_bytes};
use crate::error::{EncodeError, ParseError, SignError, VerifyError};
use crate::ids::{ID_LEN, KeyType, PUBLIC_KEY_LEN, PublicKeyId};
use crate::labels::Label;

pub mod bundle;
pub mod statements;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

pub use bundle::{BundleChainError, BundleStep, PublicKeyBundle, VerifiedBundle};
pub use statements::{
    AccountState, CasRetry, DeviceAuth, DeviceCertificate, DeviceKind, DeviceRequest,
    DeviceRevocation, KeyGrant, OpStatement, SnapshotStatement, SyncMode,
};

/// `statement_version` of every statement (§10.2). No other version exists.
pub const STATEMENT_VERSION: u16 = 1;

/// `sig_format_version` of the signature container (§9.3).
pub const SIG_FORMAT_VERSION: u8 = 0x01;

/// `sig_alg` for Ed25519 (§9.3).
pub const SIG_ALG_ED25519: u8 = 0x01;

/// `sig_alg` reserved for a hybrid Ed25519 + ML-DSA signature (§9.3, §13). Rejected.
pub const SIG_ALG_RESERVED_HYBRID: u8 = 0x02;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Length of an Ed25519 seed (the 32-byte secret key of RFC 8032).
pub const SEED_LEN: usize = 32;

/// Length of the signature container: version, algorithm, signer key id, signature (§9.3).
pub const CONTAINER_LEN: usize = 2 + ID_LEN + SIGNATURE_LEN;

// The §9.3 table fixes the container at 82 bytes; this fails the build if a constant drifts.
const _: () = assert!(CONTAINER_LEN == 82);

/// Seals [`SignerRole`]: code outside this module cannot name `Sealed`, so it cannot add a role.
mod sealed {
    /// The supertrait of [`super::SignerRole`]; implemented only for the two role types.
    pub trait Sealed {}
}

/// The role of an Ed25519 key: which key type (§4.4) it is, and so which key id it has.
///
/// Sealed: the roles are [`Identity`] and [`Device`]. The role is a type parameter of
/// [`SigningKey`] and [`VerifyingKey`], so each statement's `sign` and `verify` take exactly the
/// role §10.2 names for it, and a key of the wrong role does not compile. [`KeyGrant`], the one
/// statement either role signs, checks the role against the purpose at run time.
///
/// The key type also enters the key id, `PublicKeyId(key_type, public_key)` (§4.3), so the same
/// 32 bytes used as an identity key and as a device key would have two different ids, and a
/// container made by one role never names the other.
pub trait SignerRole: sealed::Sealed {
    /// The key type of this role's Ed25519 key.
    const KEY_TYPE: KeyType;
    /// The role's name, for `Debug`.
    const NAME: &'static str;
}

/// The identity signing role (`key_type` `0x01`): bundles, certificates, revocations, the
/// account state, and key grants (member grants, M9, and the device grants of a web-vault
/// client).
///
/// An uninhabited marker type: it only ever appears as the `R` of [`SigningKey`] and
/// [`VerifyingKey`].
#[derive(Debug)]
pub enum Identity {}

/// The device signing role (`key_type` `0x04`): ops, snapshots, key grants (device grants and
/// password-verifier grants), device authentication and request signing.
///
/// An uninhabited marker type, like [`Identity`].
#[derive(Debug)]
pub enum Device {}

impl sealed::Sealed for Identity {}
impl sealed::Sealed for Device {}

impl SignerRole for Identity {
    const KEY_TYPE: KeyType = KeyType::IdentityEd25519;
    const NAME: &'static str = "Identity";
}

impl SignerRole for Device {
    const KEY_TYPE: KeyType = KeyType::DeviceEd25519;
    const NAME: &'static str = "Device";
}

/// The identity Ed25519 signing key. Its seed is stored in `E_id`, under the account key
/// (§4.2).
pub type IdentitySigningKey = SigningKey<Identity>;
/// The identity Ed25519 public key, as the key bundle publishes it (`key_type` `0x01`).
pub type IdentityVerifyingKey = VerifyingKey<Identity>;
/// A device Ed25519 signing key. Its seed is stored in `E_dev`, under the account key, on that
/// device only: `E_dev` is never uploaded (§4.2, §5.10).
pub type DeviceSigningKey = SigningKey<Device>;
/// A device Ed25519 public key, as a device certificate carries it (`key_type` `0x04`).
pub type DeviceVerifyingKey = VerifyingKey<Device>;

/// An Ed25519 signing key of role `R`.
///
/// Wraps `ed25519_dalek::SigningKey`, which holds the matching public key and wipes its seed on
/// drop (`zeroize` feature). No `Clone`, `Copy` or `Display`; `Debug` prints only the key id.
///
/// There is no public way to sign arbitrary bytes: signing goes through the `sign` functions of
/// the statement types, which frame the message with their own label (§10.2). So a signing key
/// is never a general signing oracle, and a signature made for one statement type cannot be
/// passed off as another.
///
/// The seed leaves this type only through the crate-private `write_seed`, into a buffer the
/// caller wipes (the `E_id` or `E_dev` plaintext, §4.2).
pub struct SigningKey<R: SignerRole> {
    /// The `ed25519-dalek` key: the seed and the public key derived from it. Zeroized on drop.
    inner: ed25519_dalek::SigningKey,
    /// The public key with its role-typed key id, derived from `inner` once at construction, so
    /// the id a container names always belongs to the key that signed it.
    public: VerifyingKey<R>,
}

impl<R: SignerRole> SigningKey<R> {
    /// Generates a key from a 32-byte seed drawn from the injected CSPRNG (§4.2). The seed
    /// buffer is wiped after use.
    ///
    /// The RNG is the caller's (`rizzy-core` reaches no OS randomness, §12.1): pass the
    /// platform CSPRNG, never a seeded test RNG outside tests.
    #[must_use]
    pub fn generate<G: CryptoRng + ?Sized>(rng: &mut G) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(seed.as_mut_slice());
        Self::from_seed(&seed)
    }

    /// Rebuilds a key from its seed, as stored inside `E_id` or `E_dev`. The caller wipes
    /// `seed`.
    ///
    /// The public key is derived here, once, from the seed; nothing else can set it
    /// (RUSTSEC-2022-0093).
    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let inner = ed25519_dalek::SigningKey::from_bytes(seed);
        let public = VerifyingKey::from_dalek(inner.verifying_key());
        Self { inner, public }
    }

    /// Writes the seed into `out`, a buffer the caller wipes (the `E_id` or `E_dev`
    /// plaintext).
    ///
    /// Security: `out` then holds the secret key. It must be a zeroizing buffer that is
    /// encrypted straight away and never logged.
    pub(crate) fn write_seed(&self, out: &mut [u8; SEED_LEN]) {
        out.copy_from_slice(self.inner.as_bytes());
    }

    /// The public key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey<R> {
        &self.public
    }

    /// The public key id, `PublicKeyId(R::KEY_TYPE, public_key)` (§4.3).
    #[must_use]
    pub const fn key_id(&self) -> PublicKeyId {
        self.public.id
    }

    /// Signs `message` and returns the container. Crate-private: signing happens only through
    /// the statement types, which build the framed message.
    ///
    /// The container names this key's own id, so a verifier that expects another key rejects
    /// it with [`VerifyError::WrongSigner`] before any curve arithmetic.
    ///
    /// # Errors
    /// [`SignError::Internal`] if `ed25519-dalek` reports a failure, which it does not for a
    /// valid signing key.
    pub(crate) fn sign_message(&self, message: &[u8]) -> Result<SignatureContainer, SignError> {
        let signature = self
            .inner
            .try_sign(message)
            .map_err(|_| SignError::Internal)?;
        Ok(SignatureContainer {
            signer: self.public.id,
            signature: signature.to_bytes(),
        })
    }
}

impl<R: SignerRole> fmt::Debug for SigningKey<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningKey<{}>([REDACTED], {:?})",
            R::NAME,
            self.public.id
        )
    }
}

/// An Ed25519 public key of role `R`, with its key id.
///
/// Construction from bytes rejects encodings that do not decompress, non-canonical encodings
/// and small-order ("weak") keys, so a bundle or certificate can never carry a key that
/// `verify_strict` would reject for every signature.
///
/// Public data: `==` and `Hash` compare the 32-byte encoding in variable time, and `Debug`
/// prints it as hex.
pub struct VerifyingKey<R: SignerRole> {
    /// The decompressed `ed25519-dalek` public key.
    inner: ed25519_dalek::VerifyingKey,
    /// `PublicKeyId(R::KEY_TYPE, public_key)` (§4.3), computed once at construction.
    id: PublicKeyId,
    /// The role, at the type level only. `fn() -> R` stores no `R` (the roles are uninhabited)
    /// and keeps the type `Send` and `Sync` whatever `R` is.
    role: PhantomData<fn() -> R>,
}

impl<R: SignerRole> VerifyingKey<R> {
    /// Wraps a key `ed25519-dalek` already accepted and derives its key id for role `R`.
    /// Callers have either checked the key ([`VerifyingKey::from_bytes`]) or derived it from a
    /// seed.
    fn from_dalek(inner: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            id: PublicKeyId::derive(R::KEY_TYPE, inner.as_bytes()),
            inner,
            role: PhantomData,
        }
    }

    /// Parses a 32-byte public key.
    ///
    /// # Errors
    /// [`ParseError::InvalidValue`] if the bytes are not a canonical encoding of a curve point,
    /// or the point has small order.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, ParseError> {
        let inner =
            ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| ParseError::InvalidValue)?;
        // Decompression alone accepts some non-canonical encodings of a point. Re-compressing
        // the point and comparing with the input rejects them, so each key has exactly one
        // encoding and one key id.
        let canonical = inner.to_edwards().compress().to_bytes() == *bytes;
        if !canonical || inner.is_weak() {
            return Err(ParseError::InvalidValue);
        }
        Ok(Self::from_dalek(inner))
    }

    /// The 32-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.inner.as_bytes()
    }

    /// The public key id, `PublicKeyId(R::KEY_TYPE, public_key)` (§4.3).
    #[must_use]
    pub const fn key_id(&self) -> PublicKeyId {
        self.id
    }

    /// Checks one container over `message`: the container must name this key, and the
    /// signature must pass `verify_strict`.
    ///
    /// `message` is the full framed message (label, `0x00`, version, body), which the caller
    /// rebuilt; this function adds nothing to it.
    ///
    /// # Errors
    /// [`VerifyError::WrongSigner`] if the container names another key id;
    /// [`VerifyError::BadSignature`] if `verify_strict` rejects the signature.
    pub(crate) fn verify_container(
        &self,
        message: &[u8],
        container: &SignatureContainer,
    ) -> Result<(), VerifyError> {
        if container.signer != self.id {
            return Err(VerifyError::WrongSigner);
        }
        let signature = ed25519_dalek::Signature::from_bytes(&container.signature);
        self.inner
            .verify_strict(message, &signature)
            .map_err(|_| VerifyError::BadSignature)
    }
}

// `Clone`, `Copy`, `PartialEq`, `Eq` and `Hash` are written by hand: `derive` would require them
// of the role type `R`, which is an uninhabited marker.
impl<R: SignerRole> Clone for VerifyingKey<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: SignerRole> Copy for VerifyingKey<R> {}

impl<R: SignerRole> PartialEq for VerifyingKey<R> {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl<R: SignerRole> Eq for VerifyingKey<R> {}

impl<R: SignerRole> core::hash::Hash for VerifyingKey<R> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl<R: SignerRole> fmt::Debug for VerifyingKey<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey<{}>(", R::NAME)?;
        self.as_bytes()
            .iter()
            .try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

/// The signature container (§9.3):
///
/// | Offset | Size | Field |
/// |---|---|---|
/// | 0 | 1 | `sig_format_version` = `0x01` |
/// | 1 | 1 | `sig_alg` = `0x01` (Ed25519) |
/// | 2 | 16 | signer public key id |
/// | 18 | 64 | signature |
///
/// The signer key id lets a verifier pick the key it expects and reject a container made by
/// any other key before running the curve arithmetic. It is a claim, not a proof: only the
/// signature check under the expected key authenticates anything. Parsing a container checks
/// its layout, never its signature.
///
/// `sig_alg` `0x02` (hybrid Ed25519 + ML-DSA, §13) is reserved and rejected, like every other
/// value but `0x01`. There is no negotiation: a verifier accepts exactly the one algorithm it
/// knows.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureContainer {
    /// The signer's public key id, `PublicKeyId(key_type, public_key)` (§4.3).
    signer: PublicKeyId,
    /// The 64-byte Ed25519 signature `R ‖ s` (RFC 8032).
    signature: [u8; SIGNATURE_LEN],
}

impl SignatureContainer {
    /// Parses exactly one 82-byte container.
    ///
    /// Every `verify` function in this module parses its containers itself, so a verifier
    /// does not need this; it is for inspecting a container, for example its signer key id.
    ///
    /// # Errors
    /// [`VerifyError::Malformed`] for a wrong length ([`ParseError::Truncated`] if shorter,
    /// [`ParseError::TrailingBytes`] if longer); [`VerifyError::UnsupportedVersion`] for a
    /// `sig_format_version` other than `0x01` or a `sig_alg` other than `0x01` (including the
    /// reserved hybrid `0x02`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        let bytes: &[u8; CONTAINER_LEN] = bytes.try_into().map_err(|_| {
            VerifyError::Malformed(if bytes.len() < CONTAINER_LEN {
                ParseError::Truncated
            } else {
                ParseError::TrailingBytes
            })
        })?;
        // The length is exactly 82 from here on, so the reads below cannot fail; they go through
        // the reader anyway, which keeps the parser free of indexing.
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        let alg = r.u8()?;
        if version != SIG_FORMAT_VERSION || alg != SIG_ALG_ED25519 {
            return Err(VerifyError::UnsupportedVersion);
        }
        let signer = PublicKeyId::from_bytes(*r.array::<ID_LEN>()?);
        let signature = *r.array::<SIGNATURE_LEN>()?;
        r.finish()?;
        Ok(Self { signer, signature })
    }

    /// The 82-byte encoding. For [`DeviceAuth`] and [`DeviceRequest`] these bytes are all that
    /// is sent (§9.6).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CONTAINER_LEN] {
        let mut out = [0u8; CONTAINER_LEN];
        let (head, signature) = out.split_at_mut(2 + ID_LEN);
        let (prefix, signer) = head.split_at_mut(2);
        prefix.copy_from_slice(&[SIG_FORMAT_VERSION, SIG_ALG_ED25519]);
        signer.copy_from_slice(self.signer.as_bytes());
        signature.copy_from_slice(&self.signature);
        out
    }

    /// The signer public key id.
    #[must_use]
    pub const fn signer_key_id(&self) -> &PublicKeyId {
        &self.signer
    }

    /// The 64-byte Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

impl fmt::Debug for SignatureContainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureContainer({:?}, ", self.signer)?;
        self.signature
            .iter()
            .try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

/// A statement whose signature has been verified, with `SHA-256` of its full signed message.
///
/// Only the verifiers in this module construct it, so holding one proves the signature and the
/// structural checks passed.
///
/// It proves no more than that: the statement was signed by the key the caller passed to
/// `verify`. Whether that key was the right one, and whether the statement is current rather
/// than replayed, is still the caller's to decide (for example with
/// [`AccountState::is_rollback`] and [`AccountState::is_fork`]). It dereferences to the
/// statement, so its fields read directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified<S> {
    /// The decoded, verified statement.
    statement: S,
    /// `SHA-256` of the full signed message the signature covered.
    message_hash: [u8; 32],
}

impl<S> Verified<S> {
    /// Wraps a statement whose signature over `message` has just verified, and hashes
    /// `message`. Private to this module and its children: call it only after
    /// `verify_container` succeeded.
    fn new(statement: S, message: &[u8]) -> Self {
        Self {
            statement,
            message_hash: Sha256::digest(message).into(),
        }
    }

    /// The statement.
    #[must_use]
    pub const fn statement(&self) -> &S {
        &self.statement
    }

    /// `SHA-256` of the full signed message, `LABEL("sig/<type>") ‖ 0x00 ‖ u16(1) ‖ body`.
    /// For a device certificate this is its `h_i` in the device-set hash (§10.2).
    #[must_use]
    pub const fn message_hash(&self) -> &[u8; 32] {
        &self.message_hash
    }

    /// Unwraps the statement.
    #[must_use]
    pub fn into_statement(self) -> S {
        self.statement
    }
}

impl<S> Deref for Verified<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.statement
    }
}

/// A statement type with a fixed canonical body (§10.2). Crate-private: the public API is the
/// typed `sign` and `verify` functions of each statement.
///
/// Implemented by every single-signer statement that travels in the §9.6 wire form. The key
/// bundle, which may carry two containers, and `device-auth` and `device-request`, which
/// travel as bare containers, have their own paths.
///
/// The two directions must agree: `decode_body(encode_body(s)) == s` for every statement a
/// writer accepts, and the decoder rejects every body the encoder would refuse to write.
pub(crate) trait Statement: Sized {
    /// `LABEL("sig/<type>")`.
    const LABEL: Label;
    /// Upper bound on the body length, checked before any parsing.
    const MAX_BODY_LEN: usize;
    /// Encodes the body, rejecting values the format does not allow.
    fn encode_body(&self) -> Result<Vec<u8>, EncodeError>;
    /// Decodes and validates a body strictly: no trailing bytes, no disallowed values.
    fn decode_body(body: &[u8]) -> Result<Self, ParseError>;
}

/// `LABEL("sig/<type>") ‖ 0x00 ‖ u16(statement_version) ‖ body`, allocated at its final size.
///
/// Both signer and verifier build the message with this one function, so they cannot frame it
/// differently. The result is also what `bundle_hash`, `prev_bundle_hash` and the device-set
/// `h_i` hash.
pub(crate) fn signed_message(label: Label, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.as_bytes().len() + 3 + body.len());
    out.extend_from_slice(label.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&STATEMENT_VERSION.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Encodes `bytes(u16(statement_version) ‖ body) ‖ container(s)` (§9.6).
///
/// The label and `0x00` are not written: the verifier supplies them.
///
/// # Errors
/// [`EncodeError::TooLong`] if `body` does not fit the `u32` length prefix or a size overflows.
pub(crate) fn encode_wire(
    body: &[u8],
    containers: &[SignatureContainer],
) -> Result<Vec<u8>, EncodeError> {
    let versioned_len = body.len().checked_add(2).ok_or(EncodeError::TooLong)?;
    let total = crate::encoding::bytes_encoded_len(versioned_len)?
        .checked_add(
            containers
                .len()
                .checked_mul(CONTAINER_LEN)
                .ok_or(EncodeError::TooLong)?,
        )
        .ok_or(EncodeError::TooLong)?;
    let mut versioned = Vec::with_capacity(versioned_len);
    versioned.extend_from_slice(&STATEMENT_VERSION.to_be_bytes());
    versioned.extend_from_slice(body);
    let mut out = Vec::with_capacity(total);
    put_bytes(&mut out, &versioned)?;
    for container in containers {
        out.extend_from_slice(&container.to_bytes());
    }
    Ok(out)
}

/// Splits a wire statement into its body and its container bytes. Checks the length prefix
/// against `max_body_len` before reading, and the `statement_version`.
///
/// The container bytes are everything after the length-prefixed part, unchecked; the caller
/// parses them and so decides how many containers it accepts.
///
/// # Errors
/// [`VerifyError::Malformed`] with [`ParseError::TooLong`] if the length prefix exceeds
/// `max_body_len + 2`, or [`ParseError::Truncated`] if the input is shorter than the prefix
/// says or holds no version; [`VerifyError::UnsupportedVersion`] for a `statement_version`
/// other than 1.
pub(crate) fn split_wire(wire: &[u8], max_body_len: usize) -> Result<(&[u8], &[u8]), VerifyError> {
    let mut r = Reader::new(wire);
    // `+ 2` for the `u16` version inside the length-prefixed part.
    let versioned = r.bytes_max(max_body_len.saturating_add(2))?;
    let containers = r.rest();
    let mut v = Reader::new(versioned);
    if v.u16()? != STATEMENT_VERSION {
        return Err(VerifyError::UnsupportedVersion);
    }
    Ok((v.rest(), containers))
}

/// Signs a single-signer statement and returns its wire form.
///
/// Steps: encode the body (the statement's rules run here), check it against
/// `S::MAX_BODY_LEN` so a writer never makes what its own verifier would refuse, sign the
/// message framed with `S::LABEL`, and encode the wire form with one container.
///
/// # Errors
/// [`SignError::Encode`] if the body breaks a rule of the format or exceeds the bound;
/// [`SignError::Internal`] if the signature primitive fails (unreachable).
pub(crate) fn sign_single<S: Statement, R: SignerRole>(
    statement: &S,
    key: &SigningKey<R>,
) -> Result<Vec<u8>, SignError> {
    let body = statement.encode_body()?;
    if body.len() > S::MAX_BODY_LEN {
        return Err(SignError::Encode(EncodeError::TooLong));
    }
    let container = key.sign_message(&signed_message(S::LABEL, &body))?;
    Ok(encode_wire(&body, &[container])?)
}

/// Verifies a single-signer statement: exactly one container, a strict decode of the body,
/// then the signature by `key` over the message framed with `S::LABEL`.
///
/// Parsing comes first, as for envelopes (§9.5): the decoders are pure, bounded and
/// non-panicking, a malformed statement is rejected before the signature check, and the fuzz
/// target reaches every decoder. Nothing is returned unless the signature verifies.
///
/// The message is rebuilt from the body bytes as received, not re-encoded from the decoded
/// statement. The decoders are strict and canonical, so the two are the same.
///
/// # Errors
/// [`VerifyError::Malformed`] for a bad layout, a missing or extra container, or a disallowed
/// field value; [`VerifyError::UnsupportedVersion`] for an unknown `statement_version`,
/// `sig_format_version` or `sig_alg`; [`VerifyError::WrongSigner`] if the container names
/// another key; [`VerifyError::BadSignature`] if `verify_strict` fails.
pub(crate) fn verify_single<S: Statement, R: SignerRole>(
    wire: &[u8],
    key: &VerifyingKey<R>,
) -> Result<Verified<S>, VerifyError> {
    let (body, containers) = split_wire(wire, S::MAX_BODY_LEN)?;
    let container = SignatureContainer::from_bytes(containers)?;
    let statement = S::decode_body(body)?;
    let message = signed_message(S::LABEL, body);
    key.verify_container(&message, &container)?;
    Ok(Verified::new(statement, &message))
}

/// Verifies a detached Ed25519 signature over `LABEL(label) ‖ 0x00 ‖ ctx`, for a signed
/// artifact whose public key the caller pins itself rather than looks up by key id.
///
/// This is the one statement shape outside the role-and-container machinery above
/// ([`SignerRole`], [`SignatureContainer`]): the equivalence list (ADR 0038 §1; CRYPTO.md
/// §10.2) is signed by a dedicated offline keypair that is not an identity or device key, has
/// no [`PublicKeyId`], and travels as a bare 64-byte signature appended to the list bytes, not
/// an 82-byte [`SignatureContainer`]. Every other statement in this crate keeps using
/// `sign_single`/`verify_single` with a role-typed [`VerifyingKey`]; this function exists
/// so that a second, equally narrow signed-artifact type does not need its own `ed25519-dalek`
/// dependency outside `rizzy-core` (ADR 0037 §1: "an Ed25519 verify through `rizzy-core`'s
/// existing API").
///
/// `ctx` is the caller's framed body, exactly as it will be hashed and compared again on every
/// future verification: for the equivalence list, `u16(format_version) ‖ list_version ‖
/// published_at_ms ‖ n ‖ groups` (CRYPTO.md §10.2 row "equivalence-list": "`statement_version`
/// is the list's `format_version` (1)", which is this same framing, since [`Label::info`]
/// inserts no version field of its own — the caller provides it as the first bytes of `ctx`).
///
/// `public_key` is checked exactly as [`VerifyingKey::from_bytes`] checks one: it must
/// decompress, be canonically encoded, and not be small-order, so this function never runs
/// `verify_strict` against a key `verify_strict` would reject for every signature.
///
/// # Errors
/// [`VerifyError::Malformed`] if `public_key` is not a canonical, non-weak Ed25519 point;
/// [`VerifyError::BadSignature`] if `verify_strict` rejects the signature.
pub fn verify_detached(
    label: Label,
    ctx: &[u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), VerifyError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| VerifyError::Malformed(ParseError::InvalidValue))?;
    let canonical = key.to_edwards().compress().to_bytes() == *public_key;
    if !canonical || key.is_weak() {
        return Err(VerifyError::Malformed(ParseError::InvalidValue));
    }
    let message = label.info(ctx);
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    key.verify_strict(&message, &signature)
        .map_err(|_| VerifyError::BadSignature)
}

/// Signs `LABEL(label) ‖ 0x00 ‖ ctx` with a detached Ed25519 signature, from a raw 32-byte
/// seed rather than a role-typed [`SigningKey`].
///
/// The counterpart of [`verify_detached`], for the same narrow, pinned-key signed-artifact
/// shape (ADR 0038 §1, §3: the equivalence list, signed offline by a dedicated keypair that is
/// not an identity or device key). Used by the `cargo xtask equivalence-list` signing tool,
/// never by a client: a client only ever verifies.
///
/// The seed is the caller's; this function neither generates nor stores one. The offline
/// signing key lives outside this repository's runtime entirely (ADR 0038 §3), so there is no
/// `E_id`/`E_dev`-style storage for it here.
///
/// # Errors
/// [`SignError::Internal`] if `ed25519-dalek` reports a failure, which it does not for a
/// 32-byte seed.
pub fn sign_detached(
    label: Label,
    ctx: &[u8],
    seed: &[u8; SEED_LEN],
) -> Result<[u8; SIGNATURE_LEN], SignError> {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    let message = label.info(ctx);
    let signature = key.try_sign(&message).map_err(|_| SignError::Internal)?;
    Ok(signature.to_bytes())
}

/// Reads a 32-byte public key encoded as `bytes(public_key)` (a bundle entry).
///
/// Every M1 key type is 32 bytes (§10.2), so any other length is refused rather than skipped.
///
/// # Errors
/// [`ParseError::TooLong`] if the length prefix exceeds 32, [`ParseError::InvalidLength`] if it
/// is below 32, [`ParseError::Truncated`] if the input ends early.
pub(crate) fn read_key_bytes<'a>(r: &mut Reader<'a>) -> Result<&'a [u8; 32], ParseError> {
    r.bytes_max(PUBLIC_KEY_LEN)?
        .try_into()
        .map_err(|_| ParseError::InvalidLength)
}
