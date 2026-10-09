//! ES256 (ECDSA P-256, SHA-256) key generation and signing for `WebAuthn` passkey credentials
//! (CRYPTO.md §3; [ADR 0039] §2, §3, §5; [ADR 0009] Amendments, 2026-10-09).
//!
//! [ADR 0039]: ../../../../docs/adr/0039-passkeys-vault-and-extension.md
//! [ADR 0009]: ../../../../docs/adr/0009-crypto-dependency-policy.md
//!
//! **Scope (ADR 0039 §5).** This module is key generation, signing, the raw public-key
//! coordinates a caller needs to build a COSE key, and the two purpose-named SHA-256 calls
//! `WebAuthn` itself requires ([`rp_id_hash`], [`client_data_hash`]) — hashing is cryptography,
//! so it stays here rather than pulling `sha2` into `rizzy-client`, but neither function is a
//! general hash export (CRYPTO.md §1 Rule 2). The `WebAuthn` wire format's *structure* itself —
//! `clientDataJSON`, `authenticatorData`, the hand-written CBOR of ADR 0039 §4 (the COSE `EC2`
//! key map, `attestedCredentialData`, the `"none"` attestation object) — is **not** built here:
//! ADR 0039 §5 assigns "`WebAuthn` wire-format assembly... the hand-written CBOR" to
//! `rizzy-client`, which already owns client-flow orchestration (ADR 0013 §1) and "calls into
//! `rizzy-core` only for key generation, signing and the item-field encryption." Putting CBOR
//! here would duplicate that boundary and give this no-I/O, wasm-portable crate a second job.
//!
//! **Library rules.**
//! - `p256` 0.14.0, the `RustCrypto` P-256 implementation (`ecdsa`, `alloc` features only; never
//!   `getrandom`, `std`, `pem`, `pkcs8` or `serde` — [ADR 0041]).
//! - Key generation draws from the injected [`CryptoRng`] ([ADR 0009] "RNG rules"), the same
//!   bound every other key in this crate uses ([`crate::rng`]).
//! - Signing is always deterministic (RFC 6979 §3.2, built into `ecdsa` 0.17's `Signer` impl):
//!   there is no randomized-signing path here, so the known-answer vectors of
//!   [RFC 6979 Appendix A.2.5] reproduce byte for byte and no nonce can leak through a weak
//!   RNG. `WebAuthn`'s assertion and attestation signature fields are DER-encoded ECDSA
//!   signatures ([WebAuthn L3] §6.5.2, §8.2), so [`Es256SigningKey::sign_der`] returns DER,
//!   never the fixed-size `r ‖ s` form.
//! - Verification always runs through `ecdsa`'s `Verifier`, which rejects a malformed or
//!   non-canonical signature; there is no "verify anyway" path.
//!
//! [ADR 0041]: ../../../../docs/adr/0041-p256-crate-approval.md
//! [RFC 6979 Appendix A.2.5]: https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
//! [WebAuthn L3]: https://www.w3.org/TR/webauthn-3/
//!
//! **What this defends against.** A forged or altered assertion (DER signature over the
//! caller's framed message); a signature made with one credential's key presented for another
//! (the caller binds `credential_id` to the stored key, not this module, which only ever has
//! the one key it was given). **What it does not defend against.** Picking the right stored
//! key for a `credential_id`, and enforcing [INV-64]'s origin/`rpId` binding on
//! `clientDataJSON`: both are the caller's (rizzy-client's), built from the message this
//! module only signs, never inspects.
//!
//! [INV-64]: ../../../../docs/THREAT_MODEL.md#8-security-invariants

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p256::elliptic_curve::Generate as _;
use rand_core::CryptoRng;
use sha2::{Digest as _, Sha256};

use crate::error::{ParseError, SignError, VerifyError};
use crate::secret::SecretArray;

/// Length of a P-256 field element: one coordinate of the public key, or the private scalar
/// (`FieldBytes<NistP256>`, 32 bytes).
pub const COORDINATE_LEN: usize = 32;

/// `SHA-256(rpId)`, the first 32 bytes of every `authenticatorData` (`WebAuthn` L3 §6.1).
/// Named for this one use, not a general hash export (CRYPTO.md §1 Rule 2's composition
/// policy): `rpId` is already-validated ASCII/IDNA text (INV-64 ran in the caller before this
/// is reached), hashed over its UTF-8 bytes exactly as the spec requires.
#[must_use]
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// `SHA-256(clientDataJSON)`, the second half of the signature base
/// (`authenticatorData ‖ clientDataHash`, `WebAuthn` L3 §6.5.2) and the value `attStmt`-less
/// `"none"` attestation never needs beyond that signature base. Named for this one use, same
/// reasoning as [`rp_id_hash`].
#[must_use]
pub fn client_data_hash(client_data_json: &[u8]) -> [u8; 32] {
    Sha256::digest(client_data_json).into()
}

/// An ES256 (ECDSA P-256) signing key for one `WebAuthn` passkey credential (ADR 0039 §2).
///
/// Wraps `p256::ecdsa::SigningKey`, which holds its scalar in a `NonZeroScalar` and zeroizes it
/// on drop; `Debug` prints only the type name (`finish_non_exhaustive`), never the scalar. No
/// `Clone`, `Copy`, `Display` or `serde::Serialize` on this wrapper (CRYPTO.md §12.2), even
/// though the inner `p256` type derives `Clone` for its own API: nothing outside this module
/// duplicates a signing key.
///
/// The raw scalar leaves this type only through [`Es256SigningKey::to_bytes`], into a
/// [`SecretArray`] the caller encrypts straight away (`passkey/<id>/private_key`, concealed by
/// default like `login.password`, ADR 0039 §1) and never logs.
pub struct Es256SigningKey {
    /// The `p256`/`ecdsa` signing key. Zeroizes its scalar on drop (upstream `Drop` impl).
    inner: P256SigningKey,
}

impl Es256SigningKey {
    /// Generates a fresh key from the injected CSPRNG (ADR 0039 §2 "Key generation": "one fresh
    /// keypair per credential... never derived from any other vault secret").
    ///
    /// `rand_core`'s `CryptoRng` (0.10) is `TryCryptoRng<Error = Infallible>`
    /// ([ADR 0009] "RNG rules"), so generation cannot fail here; an OS RNG failure aborts in
    /// the leaf crate that supplied `rng`, before this function is reached.
    ///
    /// [ADR 0009]: ../../../../docs/adr/0009-crypto-dependency-policy.md
    #[must_use]
    pub fn generate<G: CryptoRng + ?Sized>(rng: &mut G) -> Self {
        let inner = match P256SigningKey::try_generate_from_rng(rng) {
            Ok(key) => key,
            // `rand_core::CryptoRng: TryCryptoRng<Error = Infallible>`: this arm is
            // unreachable code, not a failure path, and compiles to nothing.
            Err(error) => match error {},
        };
        Self { inner }
    }

    /// Rebuilds a key from its raw 32-byte scalar, as stored (decrypted) from
    /// `passkey/<id>/private_key`.
    ///
    /// # Errors
    /// [`ParseError::InvalidLength`] if `bytes` is not exactly 32 bytes;
    /// [`ParseError::InvalidValue`] if the bytes are not a valid, non-zero P-256 scalar.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let bytes: &[u8; COORDINATE_LEN] =
            bytes.try_into().map_err(|_| ParseError::InvalidLength)?;
        let inner =
            P256SigningKey::from_bytes(bytes.into()).map_err(|_| ParseError::InvalidValue)?;
        Ok(Self { inner })
    }

    /// The raw 32-byte scalar, copied into a wiping buffer for the caller to encrypt
    /// immediately under the item key, exactly like `login.password` (ADR 0039 §1).
    #[must_use]
    pub fn to_bytes(&self) -> SecretArray<COORDINATE_LEN> {
        // `FieldBytes<NistP256>` is exactly 32 bytes at the type level, so writing it into the
        // `SecretArray`'s own buffer in place cannot fail; `try_init_with` still takes a
        // `Result` for its general case, so the error type is `Infallible` and the `Err` arm
        // below is unreachable code, not a failure path (no `unwrap`/`expect`).
        let repr = self.inner.to_bytes();
        match SecretArray::try_init_with::<core::convert::Infallible>(|buf| {
            buf.copy_from_slice(repr.as_slice());
            Ok(())
        }) {
            Ok(secret) => secret,
            Err(never) => match never {},
        }
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> Es256VerifyingKey {
        Es256VerifyingKey {
            inner: *self.inner.verifying_key(),
        }
    }

    /// Signs `message` deterministically (RFC 6979) and returns the DER-encoded signature
    /// `WebAuthn`'s assertion and attestation signature fields require.
    ///
    /// `message` is the caller's fully framed message (for an assertion,
    /// `authenticatorData ‖ SHA-256(clientDataJSON)`, ADR 0039 §2, §5; `WebAuthn` L3 §6.5.2):
    /// this function adds nothing to it and does not inspect it, so enforcing INV-64 on the
    /// origin inside that message is entirely the caller's.
    ///
    /// # Errors
    /// [`SignError::Internal`] if the signature primitive fails. Unreachable for a key this
    /// type can construct: `ecdsa`'s deterministic signer only fails on an all-zero or
    /// otherwise invalid scalar, which [`Es256SigningKey::generate`] and
    /// [`Es256SigningKey::from_bytes`] both already rule out.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let signature: Signature = self
            .inner
            .try_sign(message)
            .map_err(|_| SignError::Internal)?;
        Ok(signature.to_der().to_bytes().to_vec())
    }
}

impl core::fmt::Debug for Es256SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Es256SigningKey").finish_non_exhaustive()
    }
}

/// An ES256 (ECDSA P-256) public key, as the uncompressed SEC1 coordinates a caller needs to
/// build a COSE `EC2` key map (ADR 0039 §4, built in `rizzy-client`, not here).
///
/// Public data: no secret, so this type derives `Clone`, `Copy`, `PartialEq` and `Eq` freely.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Es256VerifyingKey {
    /// The `p256`/`ecdsa` verifying key.
    inner: P256VerifyingKey,
}

impl Es256VerifyingKey {
    /// Parses an uncompressed SEC1 point (`0x04 ‖ x ‖ y`, 65 bytes), the form
    /// [`Es256VerifyingKey::to_uncompressed_sec1`] writes.
    ///
    /// # Errors
    /// [`ParseError::InvalidValue`] if `bytes` is not a valid, on-curve, uncompressed SEC1
    /// encoding of a P-256 point (including the additive identity, which `ecdsa` also rejects).
    pub fn from_uncompressed_sec1(bytes: &[u8]) -> Result<Self, ParseError> {
        let inner =
            P256VerifyingKey::from_sec1_bytes(bytes).map_err(|_| ParseError::InvalidValue)?;
        Ok(Self { inner })
    }

    /// The uncompressed SEC1 encoding, `0x04 ‖ x ‖ y` (65 bytes): the one COSE `EC2` ES256 keys
    /// need (`-2`/`-3` = x/y, RFC 9053 §7.1.1), and the one `WebAuthn`'s own SEC1 conventions use.
    #[must_use]
    pub fn to_uncompressed_sec1(&self) -> [u8; 1 + 2 * COORDINATE_LEN] {
        let point = self.inner.to_sec1_point(false);
        let bytes: &[u8] = point.as_bytes();
        let mut out = [0u8; 1 + 2 * COORDINATE_LEN];
        // `to_sec1_point(false)` always writes the uncompressed form for an on-curve,
        // non-identity point (every point this type can hold): `0x04` then exactly two
        // coordinates, 65 bytes total. A defensive copy bound is still cheaper than an index.
        let n = bytes.len().min(out.len());
        if let (Some(dst), Some(src)) = (out.get_mut(..n), bytes.get(..n)) {
            dst.copy_from_slice(src);
        }
        out
    }

    /// The x coordinate alone (32 bytes), for a caller building a COSE key field by field.
    #[must_use]
    pub fn x(&self) -> [u8; COORDINATE_LEN] {
        coordinate(&self.to_uncompressed_sec1(), 0)
    }

    /// The y coordinate alone (32 bytes).
    #[must_use]
    pub fn y(&self) -> [u8; COORDINATE_LEN] {
        coordinate(&self.to_uncompressed_sec1(), COORDINATE_LEN)
    }

    /// Verifies a DER-encoded ECDSA signature over `message`, the counterpart of
    /// [`Es256SigningKey::sign_der`].
    ///
    /// Used by this module's own known-answer tests, and available to any caller that wants to
    /// check a passkey assertion independently of the relying party (this project never relies
    /// on it for a security decision: `WebAuthn` assertions are verified by the RP, not by us).
    ///
    /// # Errors
    /// [`VerifyError::BadSignature`] if `der_signature` is malformed or does not verify.
    pub fn verify_der(&self, message: &[u8], der_signature: &[u8]) -> Result<(), VerifyError> {
        let signature =
            Signature::from_der(der_signature).map_err(|_| VerifyError::BadSignature)?;
        self.inner
            .verify(message, &signature)
            .map_err(|_| VerifyError::BadSignature)
    }
}

impl core::fmt::Debug for Es256VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Es256VerifyingKey(")?;
        self.to_uncompressed_sec1()
            .iter()
            .try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

/// Reads `COORDINATE_LEN` bytes of `sec1` starting at `offset`, defaulting to all-zero if the
/// slice is somehow short (unreachable for the fixed 65-byte input this module ever passes, but
/// this keeps the accessor panic-free rather than indexing).
fn coordinate(sec1: &[u8; 1 + 2 * COORDINATE_LEN], offset: usize) -> [u8; COORDINATE_LEN] {
    let mut out = [0u8; COORDINATE_LEN];
    if let Some(src) = sec1.get(1 + offset..1 + offset + COORDINATE_LEN) {
        out.copy_from_slice(src);
    }
    out
}

#[cfg(test)]
mod tests;
