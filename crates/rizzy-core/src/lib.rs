//! `rizzy-core` — the single implementation of rizzy-vault's cryptography and data model.
//!
//! Contract for this crate (enforced in review and CI):
//! - No I/O: no filesystem, network, clock or randomness source is reached directly; callers
//!   inject them. This keeps the crate deterministic in tests and portable to
//!   `wasm32-unknown-unknown` (web vault, browser extension) and to `UniFFI` (mobile).
//! - No `unsafe` code (`unsafe_code = "forbid"` at the workspace level).
//! - No cryptographic construction lands here without an accepted ADR in `docs/adr/`.
//!
//! Status: M1 in progress. The normative byte-level specification is `docs/CRYPTO.md`; section
//! numbers below (§) refer to it. The foundation holds encodings, the label registry, secret
//! types, the RNG bound, identifiers, the KDF table and Argon2id, the symmetric committing
//! envelope with its purpose registry, and Padmé framing. On it sit the HPKE envelopes, the
//! Ed25519 signed statements and the key hierarchy, the OPAQUE wrapper with the Secret Key and
//! recovery code, server-side sealing, the encrypted export, TOTP and the password generator.
//!
//! # Module map
//!
//! | Module | Contents | Spec |
//! |---|---|---|
//! | [`encoding`] | Big-endian integers, `bytes(x)`, `str(x)`, a bounded non-panicking reader, base64url without padding | §2, §9.6 |
//! | [`labels`] | The one registry of every `LABEL(x)` and the `LABEL(x) ‖ 0x00 ‖ ctx` builder | §2, §4.3 |
//! | [`secret`] | Zeroizing secret types with redacted `Debug` and explicit `expose_secret()` | §12.2 |
//! | [`rng`] | The injected `rand_core` 0.10 `CryptoRng` bound and the opaque-ke (`rand_core` 0.6) adapter | §5.1, §12.1 |
//! | [`error`] | [`DecryptError`](error::DecryptError) and the other error types; none carries secrets | §9.5, §12.3 |
//! | [`ids`] | 16-byte random identifiers, symmetric and public key ids, public key types | §2, §4.3, §4.4 |
//! | [`kdf`] | The `kdf_id` table and client allow-list, Argon2id with a wiped block buffer, NFC password normalisation | §6, §12.2 |
//! | [`envelope`] | Symmetric envelope `0x01` (`UtC` + `HtE` over XChaCha20-Poly1305), algorithm and purpose registries, per-purpose contexts, the strict parser | §8, §9 |
//! | [`padding`] | Padmé plaintext framing | §8.5 |
//! | [`hpke`] | HPKE envelopes `0x10` (Base) and `0x12` (PSK), X25519 key types, the device-grant PSK | §4.3, §9.2, §10.1 |
//! | [`sign`] | Ed25519 keys by role, the signature container, every signed statement, the bundle chain | §9.3, §9.6, §10.2, §10.3 |
//! | [`keys`] | Account, vault, item, identity and device keys; the M1 wrapped-key objects; unlock and recovery keys; device-set and settings hashes; fingerprints | §4, §8.4, §10.1 |
//! | [`normalize`] | Login names and `server_origin` | §2 |
//! | [`secret_key`] | The Secret Key and recovery code: generation and the `RV1-`/`RVR1-` format | §7, §11.9, §12.3 |
//! | [`opaque`] | `RizzySuiteV1`, the Argon2id KSF, `pw_in`, the Context, and the one wrapper around every opaque-ke call | §5 |
//! | [`server_seal`] | Server data subkeys and the server-only envelopes; the server-secrets backup key | §5.11 |
//! | [`export`] | The export file key and the `EXPORT_FILE` envelope with its header fields | §11.14 |
//! | [`totp`] | HOTP/TOTP, otpauth URIs, server-side verification | §11.15 |
//! | [`generator`] | Password and passphrase generator with the embedded EFF wordlist | §12.1 |
//!
//! Raw AEAD and HKDF calls stay private to this crate ([ADR 0009], "One entry point per
//! construction"): the public API is envelopes, identifiers and derived values, never a bare
//! primitive.
//!
//! [ADR 0009]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0009-crypto-dependency-policy.md

pub mod encoding;
pub mod envelope;
pub mod error;
pub mod export;
pub mod generator;
pub mod hpke;
pub mod ids;
pub mod kdf;
pub mod keys;
pub mod labels;
pub mod normalize;
pub mod opaque;
pub mod padding;
pub mod rng;
pub mod secret;
pub mod secret_key;
pub mod server_seal;
pub mod sign;
pub mod totp;

#[cfg(test)]
mod test_util;
#[cfg(test)]
mod test_vectors;
