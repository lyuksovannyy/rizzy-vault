//! Ed25519 signatures and signed statements (CRYPTO.md §9.3, §9.6, §10.2; ADR 0006 decision 10).
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
//! statement type it expects, so a statement of one type never verifies as another.
//!
//! **Wire form (§9.6).** `bytes(u16(statement_version) ‖ body) ‖ container(s)`, where each
//! container is the 82-byte [`SignatureContainer`] of §9.3. Every statement carries exactly one
//! container, except a key bundle that changes the identity keys, which carries two: the new
//! key's first ([`bundle`]). `bundle_hash`, `prev_bundle_hash` and the device-set hash are
//! `SHA-256` of the full signed message (label, `0x00`, version and body), never of the wire.
//!
//! **Two statements are verified against a rebuilt message.** `device-auth` and
//! `device-request` ([`DeviceAuth`], [`DeviceRequest`]) sign values the verifier already holds
//! (its own origin, the challenge it issued, the request it received). They travel as a bare
//! container, and the verifier rebuilds the message from its own values, the same way an
//! envelope reader rebuilds its AAD.
//!
//! Roles are types: [`IdentitySigningKey`] and [`DeviceSigningKey`] are different types, and
//! each statement names the role that signs it, so a device key cannot sign a device
//! certificate by mistake. The signer key id in a container is
//! `PublicKeyId(key_type, public_key)` (§4.3) with the role's key type (`0x01` or `0x04`).

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

const _: () = assert!(CONTAINER_LEN == 82);

mod sealed {
    pub trait Sealed {}
}

/// The role of an Ed25519 key: which key type (§4.4) it is, and so which key id it has.
///
/// Sealed: the roles are [`Identity`] and [`Device`].
pub trait SignerRole: sealed::Sealed {
    /// The key type of this role's Ed25519 key.
    const KEY_TYPE: KeyType;
    /// The role's name, for `Debug`.
    const NAME: &'static str;
}

/// The identity signing role (`key_type` `0x01`): bundles, certificates, revocations, the
/// account state, and key grants from a web-vault client.
#[derive(Debug)]
pub enum Identity {}

/// The device signing role (`key_type` `0x04`): ops, snapshots, key grants, device
/// authentication and request signing.
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

/// The identity Ed25519 signing key.
pub type IdentitySigningKey = SigningKey<Identity>;
/// The identity Ed25519 public key.
pub type IdentityVerifyingKey = VerifyingKey<Identity>;
/// A device Ed25519 signing key.
pub type DeviceSigningKey = SigningKey<Device>;
/// A device Ed25519 public key.
pub type DeviceVerifyingKey = VerifyingKey<Device>;

/// An Ed25519 signing key of role `R`.
///
/// Wraps `ed25519_dalek::SigningKey`, which holds the matching public key and wipes its seed on
/// drop (`zeroize` feature). No `Clone`, `Copy` or `Display`; `Debug` prints only the key id.
pub struct SigningKey<R: SignerRole> {
    inner: ed25519_dalek::SigningKey,
    public: VerifyingKey<R>,
}

impl<R: SignerRole> SigningKey<R> {
    /// Generates a key from a 32-byte seed drawn from the injected CSPRNG (§4.2). The seed
    /// buffer is wiped after use.
    #[must_use]
    pub fn generate<G: CryptoRng + ?Sized>(rng: &mut G) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(seed.as_mut_slice());
        Self::from_seed(&seed)
    }

    /// Rebuilds a key from its seed, as stored inside `E_id` or `E_dev`. The caller wipes
    /// `seed`.
    pub(crate) fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let inner = ed25519_dalek::SigningKey::from_bytes(seed);
        let public = VerifyingKey::from_dalek(inner.verifying_key());
        Self { inner, public }
    }

    /// Writes the seed into `out`, a buffer the caller wipes (the `E_id` or `E_dev`
    /// plaintext).
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
pub struct VerifyingKey<R: SignerRole> {
    inner: ed25519_dalek::VerifyingKey,
    id: PublicKeyId,
    role: PhantomData<fn() -> R>,
}

impl<R: SignerRole> VerifyingKey<R> {
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureContainer {
    signer: PublicKeyId,
    signature: [u8; SIGNATURE_LEN],
}

impl SignatureContainer {
    /// Parses exactly one 82-byte container.
    ///
    /// # Errors
    /// [`VerifyError::Malformed`] for a wrong length; [`VerifyError::UnsupportedVersion`] for a
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

    /// The 82-byte encoding.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified<S> {
    statement: S,
    message_hash: [u8; 32],
}

impl<S> Verified<S> {
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
pub(crate) fn signed_message(label: Label, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.as_bytes().len() + 3 + body.len());
    out.extend_from_slice(label.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&STATEMENT_VERSION.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Encodes `bytes(u16(statement_version) ‖ body) ‖ container(s)` (§9.6).
pub(crate) fn encode_wire(
    body: &[u8],
    containers: &[SignatureContainer],
) -> Result<Vec<u8>, EncodeError> {
    let versioned_len = body.len().checked_add(2).ok_or(EncodeError::TooLong)?;
    let total = crate::encoding::bytes_encoded_len(versioned_len)?
        .checked_add(containers.len() * CONTAINER_LEN)
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
pub(crate) fn split_wire(wire: &[u8], max_body_len: usize) -> Result<(&[u8], &[u8]), VerifyError> {
    let mut r = Reader::new(wire);
    let versioned = r.bytes_max(max_body_len.saturating_add(2))?;
    let containers = r.rest();
    let mut v = Reader::new(versioned);
    if v.u16()? != STATEMENT_VERSION {
        return Err(VerifyError::UnsupportedVersion);
    }
    Ok((v.rest(), containers))
}

/// Signs a single-signer statement and returns its wire form.
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

/// Reads a 32-byte public key encoded as `bytes(public_key)` (a bundle entry).
pub(crate) fn read_key_bytes<'a>(r: &mut Reader<'a>) -> Result<&'a [u8; 32], ParseError> {
    r.bytes_max(PUBLIC_KEY_LEN)?
        .try_into()
        .map_err(|_| ParseError::InvalidLength)
}
