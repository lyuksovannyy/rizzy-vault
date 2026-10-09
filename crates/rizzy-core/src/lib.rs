//! `rizzy-core` — the single implementation of rizzy-vault's cryptography and data model.
//!
//! Every client (the web vault and extension through wasm, the CLI and desktop app natively,
//! mobile through `UniFFI`) and the server link this one crate, so each construction of
//! `docs/CRYPTO.md` exists exactly once, in Rust, and is reviewed and audited once (CRYPTO.md §1
//! goal 6, [ADR 0013]). `docs/CRYPTO.md` is the normative byte-level specification; section
//! numbers (§) in this crate's docs refer to it.
//!
//! # Contract
//!
//! Enforced in review and CI:
//!
//! - **No I/O.** No filesystem, network, clock, environment, process, thread or randomness
//!   source is reached directly; callers inject randomness and time. This keeps the crate
//!   deterministic in tests and portable to `wasm32-unknown-unknown` (web vault, browser
//!   extension) and to `UniFFI` (mobile). Three checks hold it (threat model INV-58,
//!   [ADR 0016] R1): `cargo check-wasm` builds the crate for wasm32; this crate's `clippy.toml`
//!   bans the `std` I/O items of ADR 0016 §5 under `cargo lint`; and `cargo xtask check-deps`
//!   keeps the dependency closure on an allow-list with no getrandom and no direct `rand`.
//! - **No `unsafe` code** (`unsafe_code = "forbid"` at the workspace level and
//!   `#![forbid(unsafe_code)]` in this file). That also rules out FFI to C crypto, `mlock` and a
//!   zeroizing allocator ([ADR 0009]).
//! - **No cryptographic construction lands here without an accepted ADR** in `docs/adr/`. The
//!   compositions that are ours, not a standard's, are listed in CRYPTO.md §1 rule 2; each one is
//!   an M8 audit target, and a new one needs an ADR first.
//! - **One entry point per construction** ([ADR 0009]). Raw AEAD, HKDF and opaque-ke calls stay
//!   private to their modules: the public API is envelopes, identifiers, derived values, flows
//!   and signed statements, never a bare primitive.
//!
//! # Status
//!
//! M1 in progress (ROADMAP §4.2, §4.3). The foundation holds encodings, the label registry,
//! secret types, the RNG bound, identifiers, the KDF table and Argon2id, the symmetric
//! committing envelope with its purpose registry, and Padmé framing. On it sit the HPKE
//! envelopes, the Ed25519 signed statements and the key hierarchy, the OPAQUE wrapper with the
//! Secret Key and recovery code, server-side sealing, the encrypted export, TOTP, the
//! password generator, and the item schema: the schema layer of the item record ([ADR 0018]
//! §2), with the M1 item types, field keys, values and display rules.
//!
//! Not here: the record layer of the item record (ADR 0018 §3–§5: op, snapshot and tombstone
//! data), which is `rizzy-sync`'s. Not here yet: the constructions of later milestones
//! (shares, mail), and pairing and relay (reserved, On-device parked (ADR 0022)). Their
//! envelope purposes are registered so their ids stay reserved, but they have no context type,
//! so nothing can seal or open them until their milestone, or the ADR that revives On-device
//! mode, defines the layout ([`envelope::purpose`]).
//!
//! # Conventions
//!
//! These hold in every module; the module docs say where a module adds to them.
//!
//! - **Injected randomness** (§12.1, [ADR 0009] "RNG rules"). Every function that needs
//!   randomness takes `&mut impl CryptoRng` ([`rng::CryptoRng`], `rand_core` 0.10), supplied by
//!   a leaf crate: in practice `rand_core::UnwrapErr(getrandom::SysRng)`, and a seeded
//!   `ChaCha20Rng` in tests. The trait has no error channel, so an OS RNG failure aborts the
//!   leaf process. Keys, nonces, ids, salts, codes and generated passwords all come from it; no
//!   public function accepts a nonce (threat model INV-12). opaque-ke's `rand_core` 0.6 RNG is
//!   the forwarding adapter [`rng::OpaqueRng`].
//! - **Injected time.** Nothing reads a clock. Functions that need the time take it as an
//!   argument (`now_ms`, `unix_seconds`, `created_at_ms`), and the caller supplies it.
//! - **Secret types** (§12.2, [ADR 0009] "Memory hygiene"). Keys, passwords, `pw_in`, the
//!   Secret Key, recovery codes, TOTP secrets and decrypted plaintext live in types that
//!   zeroize on drop, do not implement `Clone`, `Copy`, `Display` or `serde::Serialize`, print
//!   `[REDACTED]` from `Debug`, and give their bytes out only through an explicit, greppable
//!   `expose_secret()` ([`secret::SecretArray`], [`secret::SecretBytes`] and the typed keys
//!   built on them). Secret buffers are allocated once at their final size, because a
//!   reallocation leaves the old copy behind. §12.2 lists what no type here can wipe: hkdf
//!   0.13's state, some argon2 and opaque-ke internals, JavaScript strings, swap.
//! - **Errors, never panics.** Fallible functions return a typed error ([`error`], or the
//!   module's own error enum) and document it under `# Errors`. The workspace lints warn on
//!   `unwrap`, `expect` and `panic!`, this crate adds `clippy::indexing_slicing` and
//!   `clippy::unreachable`, and `cargo lint` turns every warning into an error. Every
//!   decryption failure is the one [`DecryptError`](error::DecryptError), so there is no "which
//!   check failed" oracle (§9.5, §12.3). No error, and no `Debug` output, carries key material,
//!   plaintext or anything derived from a secret.
//! - **Untrusted input is bounded.** Parsers of envelopes, signed statements, Secret Keys and
//!   recovery codes, Padmé frames, otpauth URIs, login names, origins, item values and field
//!   keys, and the server-side OPAQUE messages check lengths before reading, never panic, and
//!   never allocate in proportion to a length field ([`encoding::Reader`]). Each of these has a
//!   fuzz target under `fuzz/` (§15 item 7).
//! - **Constant time** (§12.3). Every comparison of secret or secret-derived bytes uses
//!   `subtle::ConstantTimeEq` (`ct_eq` in the spec): envelope commitments, Secret Key and
//!   recovery-code check values, the recovery token hash, fingerprints, TOTP codes. `==` on
//!   such bytes is a review blocker. Our code does no secret-indexed table lookup and no branch
//!   on a secret: the Crockford Base32 of the Secret Key, the RFC 4648 Base32 of TOTP secrets
//!   and the generator's selection all use arithmetic or full scans. §12.3 lists the two
//!   accepted residuals (TOTP digit arithmetic, otpauth label and issuer encoding).
//! - **Labels** (§2, §4.3). Every HKDF `info`, signed message, hash domain and HPKE
//!   `info`/`psk_id` starts with `LABEL(x) = "rizzy-vault/v1/" + x`, followed by `0x00` and a
//!   context. [`labels`] is the only place a label is spelled out; adding one amends the §4.3
//!   table in the same change. No key is used directly as a cipher key: each use passes through
//!   HKDF with its own label, so one key never serves two algorithms or two purposes (§1
//!   rule 4).
//! - **Canonical encoding** (§2). Anything signed or used as AAD is built from the fixed
//!   big-endian layouts of [`encoding`], never from a serde encoding, which could change with a
//!   crate update.
//! - **The client decides; fail closed** (§1 rules 5 and 6). Algorithm ids and Argon2id
//!   parameters are compiled in. The server can only name a version from this client's
//!   allow-list ([`kdf::CLIENT_ALLOW_LIST`], each purpose's decrypt allow-list). An unknown
//!   version, a disallowed algorithm, a bad signature or a failed commitment is a hard error;
//!   there is never a fallback to a legacy path.
//! - **Known-answer vectors** (§15 item 1). The JSON files under `tests/vectors/` hold the
//!   normative format vectors (tier A: the M1 derivations, envelope purposes and signed
//!   statements, the Secret Key, recovery-code and Padmé encodings, and the item values, field
//!   keys and tag keys of [ADR 0018]) and a signup → login → unlock transcript (tier B). The
//!   test-only `test_vectors` module replays every file byte for byte on each `cargo test`,
//!   and rebuilds hidden outputs (the commitment, the signed message) from the CRYPTO.md
//!   formulas. Its generator draws inputs from a seeded `ChaCha20Rng`; the random values an
//!   operation draws internally, such as the envelope nonce, are drawn first, stored as inputs
//!   and fed back through the RNG, so tests too never pass a nonce. A crypto change needs
//!   vectors (CLAUDE.md); changing a tier A vector needs a version bump and an ADR note.
//!   Upstream vectors (RFCs), property tests and the test-only hooks that prove the §9.5 checks
//!   fail before any crypto live in the module tests.
//!
//! # Module map
//!
//! | Module | Spec | Purpose | Key invariants |
//! |---|---|---|---|
//! | [`encoding`] | §2, §9.6 | Big-endian integers, `bytes(x)`, `str(x)`, a bounded reader, base64url without padding | Signed and AAD bytes use only these layouts; [`Reader`](encoding::Reader) never panics, copies or allocates |
//! | [`labels`] | §2, §4.3 | The one registry of every `LABEL(x)` and the `LABEL(x) ‖ 0x00 ‖ ctx` builder | Labels are defined only here; each is unique, ASCII and free of `0x00`, so every `info` is prefix-free |
//! | [`secret`] | §12.2 | Zeroizing secret containers | Wiped on drop, no `Clone`, redacted `Debug`, access only through `expose_secret()`, one allocation at final size |
//! | [`rng`] | §5.1, §12.1 | The injected `rand_core` 0.10 `CryptoRng` bound and the opaque-ke (`rand_core` 0.6) adapter | No randomness source is reached from this crate; the adapter only forwards; no other `rand_core` 0.6 use |
//! | [`error`] | §9.5, §12.2, §12.3 | [`DecryptError`](error::DecryptError) and the other error types | One error for every decryption failure; no error carries a secret |
//! | [`ids`] | §2, §4.3, §4.4 | 16-byte random object ids, symmetric and public key ids, public key types | Object ids come from the injected CSPRNG with no UUID bits; key ids are derived from the key, never chosen |
//! | [`kdf`] | §2, §6, §12.2 | The `kdf_id` table and client allow-list, Argon2id, NFC password normalisation, the crate-private HKDF-SHA-256 helper | A [`KdfId`](kdf::KdfId) exists only for an enabled id on the allow-list; the Argon2 block matrix is a zeroizing buffer; argon2's non-wiping entry point is not compiled in |
//! | [`envelope`] | §8, §9 | Symmetric envelope `0x01` (`UtC` + `HtE` over XChaCha20-Poly1305), algorithm and purpose registries, typed contexts, the strict parser | `aad = header ‖ u16(purpose) ‖ ctx`, with purpose and context rebuilt by the reader, never transmitted; the commitment is compared with `ct_eq` before the AEAD runs; no public function takes a nonce |
//! | [`padding`] | §8.5 | Padmé plaintext framing | At least 256 bytes; the reader accepts only the canonical frame; the envelope applies it for padded purposes |
//! | [`hpke`] | §4.3, §9.2, §10.1 | HPKE envelopes `0x10` (Base) and `0x12` (PSK), X25519 key types, the device-grant PSK | The purpose fixes the mode, so a PSK purpose is never sealed in Base mode; the header key id must be the caller's own key; randomness only from the injected RNG |
//! | [`sign`] | §9.3, §9.6, §10.2, §10.3 | Ed25519 keys by role, the signature container, every signed statement, the bundle chain | `verify_strict` only; signing only through a key that holds its own public key; the label is prepended by the verifier, never transmitted; roles are types; the bundle chain rejects rollback and reports forks |
//! | [`passkey`] | ADR 0039 §2, §3, §5 | ES256 (ECDSA P-256) key generation and deterministic signing for WebAuthn passkey credentials; the public key's raw SEC1 coordinates | Keys only from the injected RNG, never derived from another vault secret; signing is always deterministic (RFC 6979), never randomized; the WebAuthn wire format (CBOR, `clientDataJSON`) is `rizzy-client`'s, not built here |
//! | [`keys`] | §4, §8.4, §10.1 | Account, vault, item, identity and device keys; the M1 wrapped-key objects; unlock and recovery keys; device-set and settings hashes; fingerprints | Keys carry their epoch and home; a wrap refuses a context that does not describe its keys; an unwrap checks the key id before any crypto |
//! | [`normalize`] | §2 | Login names and `server_origin` | One normalisation function each, shared by client and server; bounded input; rejects rather than guesses |
//! | [`secret_key`] | §7, §11.9, §12.3 | The Secret Key and recovery code: generation and the `RV1-`/`RVR1-` format | 16 bytes from the injected CSPRNG, never sent to the server; branch-free Base32; the check value is for typos only and compared with `ct_eq` |
//! | [`opaque`] | §5 | `RizzySuiteV1`, the Argon2id KSF, `pw_in`, the Context, and the one wrapper around every opaque-ke call | Every call passes the Argon2id KSF with an allow-listed `kdf_id` and the §5.3 Context; `pw_in` mixes in the Secret Key; unknown login names get the fake-record path (§5.9); the OPAQUE `session_key` is never returned |
//! | [`server_seal`] | §5.11 | Server data subkeys and the server-only envelopes; the server-secrets backup key | Not zero knowledge: protects only against a reader of the database alone; purposes `0x0100`–`0x01FF` are on the server's allow-list only |
//! | [`export`] | §11.14 | The export file key and the `EXPORT_FILE` envelope with its header fields | A separate export password, no Secret Key; the header fields rebuild the key and the context, so a changed header fails to open |
//! | [`totp`] | §11.15 | HOTP/TOTP, otpauth URIs, server-side verification | Allow-lists for algorithm, digits and period, rejected never clamped; no clock; verification accepts ±1 step, refuses replays and compares with `ct_eq` |
//! | [`generator`] | §12.1, §12.3 | Password and passphrase generator with the embedded EFF wordlist | Uniform rejection sampling from the injected CSPRNG; required classes by redrawing whole candidates; constant-time selection; entropy of the space actually sampled |
//! | [`item`] | §8.4 "Op and snapshot plaintexts"; [ADR 0018] §2, §6–§11 | The item schema: item types, the field-key grammar, tag keys, value types with their decoder and encoder, the key registry and writer checks, display rules, item times, list order and sort keys | An invalid value never rejects a record, it shows as unsupported; unknown keys and types are carried, and a writer never invents a value for them; keys and values are zeroizing and never in `Debug`; the key grammar and value decoder never panic or allocate; one encoding per value |
//!
//! [ADR 0009]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0009-crypto-dependency-policy.md
//! [ADR 0013]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0013-shared-client-core.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0018]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0018-item-record-encoding.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod encoding;
pub mod envelope;
pub mod error;
pub mod export;
pub mod generator;
pub mod hpke;
pub mod ids;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod labels;
pub mod normalize;
pub mod opaque;
pub mod padding;
pub mod passkey;
pub mod rng;
pub mod secret;
pub mod secret_key;
pub mod server_seal;
pub mod sign;
pub mod totp;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod test_util;
#[cfg(test)]
mod test_vectors;
