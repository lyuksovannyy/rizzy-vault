# ADR 0009: Cryptographic dependency and memory-hygiene policy

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (applies from the first crypto dependency in `rizzy-core`)

## Context

ROADMAP principle 2 says we use only audited primitives from established crates. The M0 fact sheet shows how limited that promise is in practice:

- **Audits cover older versions.**
  - opaque-ke: NCC 2021, on v0.5.0.
  - RustCrypto AEADs: NCC 2020.
  - dalek: Quarkslab 2019 (L).
  - The versions we would ship have not been audited.
- **Some crates have never been audited:** `hpke` 0.14.1 ("no paid audit"), `ml-kem`, `x-wing`, `aes-gcm-siv`.
- **Two RustCrypto generations coexist.** opaque-ke 4.0.1 pins the previous one: curve25519-dalek 4, digest/sha2 0.10, rand 0.8 / rand_core 0.6. It re-exports `rand` and `generic_array` but not sha2, so naming its SHA-512 needs a direct sha2 0.10 dependency (V, crate source; resolved to 0.10.9 in the M0 scratch build).
- **Default features break our contracts.** In `hpke`, `argon2` and `chacha20poly1305`, the defaults pull `getrandom`, which breaks `cargo check-wasm` and the "no I/O" rule in `rizzy-core`.
- **Crates can fail open.**
  - opaque-ke falls back to weak Argon2 defaults when `ksf` is `None`.
  - argon2 0.6.0 frees its block memory without wiping it (verified in source).
- **`deny.toml` blocks crates we will want.**
  - It bans `openssl`/`openssl-sys`, which blocks `webauthn-rs` (M3): its core crate depends on openssl unconditionally (V).
  - The alternative `webauthn_rp` pulls `rsa` 0.9, which carries RUSTSEC-2023-0071 with no fix (V).
- **The workspace already sets** `unsafe_code = "forbid"`, `cargo deny` (advisories deny, yanked deny, license allow-list, crates.io only), and weekly Dependabot.

## Decision

### Allowed crate families for cryptography

| Family / crate | Use | Pin (M1) |
|---|---|---|
| RustCrypto: `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `argon2`, `subtle`, `zeroize`, `base64ct` | AEAD, KDF, MAC, hash, constant time, wiping, constant-time encoding | `=0.11.0`, `=0.13.0`, `=0.13.0`, `=0.11.0`, `=0.6.0`, `=2.6.1`, `=1.9.0`, `=1.8.3` |
| `sha1` (RustCrypto) | HMAC-SHA-1 for HOTP/TOTP only ([CRYPTO.md §11.15](../CRYPTO.md#1115-totp-m1)), and HIBP range queries from M3. Checklist below | `=0.11.0` (digest 0.11, like `hmac` 0.13) |
| `sha2_010 = { package = "sha2", version = "=0.10.9", default-features = false }` | SHA-512 for the OPAQUE ciphersuite, which is on digest 0.10 ([CRYPTO.md §5.1](../CRYPTO.md#51-ciphersuite-and-key-stretching)). Used nowhere else | `=0.10.9` (from the M0 scratch lockfile; re-check against `Cargo.lock` when it lands) |
| `unicode-normalization` | NFC of master passwords, export passwords and share passphrases. It is on the password path: a Unicode-table change can change `NFC(password)` for code points that were unassigned before, and then the user's password stops working. So it counts as a crypto crate | `=0.1.25` |
| dalek-cryptography: `ed25519-dalek` (and `x25519-dalek`/`curve25519-dalek` transitively) | Signatures, X25519 | `=3.0.0` |
| `opaque-ke` (Meta) | OPAQUE | `=4.0.1` |
| `hpke` (rust-hpke) | HPKE, RFC 9180 | `=0.14.1` |
| `secrecy` (iqlusion) | Secret wrappers | `=0.10.3` |
| `rand_core` | RNG traits (0.10). The opaque-ke adapter implements the 0.6 traits through `opaque_ke::rand`, so there is no direct 0.6 dependency | `=0.10.1` |
| `rand` 0.8 | **Transitive only**, through opaque-ke, with `default-features = false`: no `thread_rng`, no getrandom. Nothing in our code calls it | lockfile-pinned (0.8.8) |
| `getrandom` | OS randomness, **leaf crates only**; feature `sys_rng` for `SysRng` | `0.4` (lockfile-pinned) |
| `chacha20` (RustCrypto), feature `rng`, **dev-dependency only** | `ChaCha20Rng`, the seeded test RNG for the transcript vectors ([CRYPTO.md §15](../CRYPTO.md#15-testing) item 1). It implements rand_core 0.10 and is the crate `chacha20poly1305` 0.11 already depends on | `=0.10.2` |
| Reserved, not in any build: `ml-kem`, `x-wing` | PQ, post-1.0 | – |

Anything else that performs cryptography requires the approval procedure below. That includes any other AEAD, KDF, curve, signature, PAKE, RNG or TLS crate on the client side. `rustls` is the only TLS stack; `deny.toml` already enforces this.

### Required feature sets

These are the settings that keep `rizzy-core` free of I/O and buildable for wasm:

- `opaque-ke`: `default-features = false`, `["ristretto255"]`. Never `argon2`, never `std`.
- `hpke`: `default-features = false`, `["alloc", "x25519", "chacha"]`. Never `mlkem`, never `getrandom`, in M1. We call only the `*_with_rng` functions and `single_shot_open`; `Kem::gen_keypair()` and the RNG-less seal exist only with `getrandom`. `cargo xtask check-deps` ([ADR 0016](0016-workspace-layout.md)) fails if getrandom becomes reachable from `rizzy-core`, which is how CI notices the feature being switched on.
- `argon2`: `default-features = false`, `["zeroize"]`. Never `alloc` (it only exposes the non-wiping `hash_password_into`), never `parallel` (rayon threads, [ADR 0016](0016-workspace-layout.md) R1).
- `sha2` (0.11): `["zeroize"]`.
- `hmac`: `["zeroize"]`.
- `sha1`: `["zeroize"]`.
- `hkdf` 0.13 has no features; its unwiped state is a listed limit ([CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)).
- `chacha20poly1305`: `default-features = false`, `["alloc", "zeroize"]`.
- `ed25519-dalek`: `default-features = false`, `["fast", "zeroize"]`. Never `legacy_compatibility`, never `hazmat`.

### Approving a new crypto crate

The PR that adds the dependency must update this ADR, or supersede it, and [CRYPTO.md §3](../CRYPTO.md#3-primitives). It must answer the following checklist:

1. **Need.** Which construction in CRYPTO.md it implements. A new construction needs its own ADR first.
2. **Provenance.** Maintainer or organisation, repository, release cadence, bus factor, and downloads over 90 days.
3. **Audit history.** Every public audit, with the version it covered and how far our version is from it. "None" is an allowed answer, but it must be written down.
4. **Advisories.** RustSec history, and how quickly past advisories were fixed.
5. **`unsafe` in the crate.** Where it is and why, e.g. SIMD backends or allocation.
6. **Constant-time claims,** and how they are tested.
7. **Builds and hygiene.** The wasm32 build with our feature set passes `cargo check-wasm`. Its license is on the allow-list. It passes `cargo deny check`. Its transitive dependencies are listed.
8. **Test vectors.** Which standard vectors or Wycheproof suites we will run against it ([CRYPTO.md §15](../CRYPTO.md#15-testing)).

The owner approves. From M9 on, when a second maintainer exists, two maintainers must approve.

### Checklist record: `sha1` (M1)

Scope: HMAC-SHA-1 in HOTP/TOTP, and from M3 the SHA-1 prefix of HIBP range queries. Both standards fix SHA-1. No construction of ours may use it.

1. **Need.** RFC 4226 and RFC 6238 default to HMAC-SHA-1, and most otpauth URIs in the wild say `SHA1` ([CRYPTO.md §11.15](../CRYPTO.md#1115-totp-m1)). ROADMAP §4.2 and §4.3 make item TOTP and server TOTP M1 Musts.
2. **Provenance.** RustCrypto `hashes` repository, the same maintainers and release process as `sha2`. 0.11.0 is the digest 0.11 release (V, crate manifest). Download counts and bus factor: U, the approval PR records them.
3. **Audit history.** None found (U).
4. **Advisories.** None known (U); the approval PR checks RustSec.
5. **`unsafe`.** Only in the hardware backends under `src/compress/`: SHA-NI on x86 and the SHA extension on aarch64, selected at run time through `cpufeatures`, and inline assembly on loongarch64. The portable backend, which wasm32 uses, is safe code (V, crate source).
6. **Constant time.** SHA-1 has no secret-dependent branches or table lookups, and HMAC-SHA-1 inherits that. There is no separate timing test.
7. **Builds and hygiene.** Dependencies: `digest` 0.11 (shared with `sha2`), `cfg-if`, and, on x86, x86_64 and aarch64, `cpufeatures` 0.3. License MIT OR Apache-2.0 (V). The approval PR confirms `cargo check-wasm` and `cargo deny check` with feature `zeroize`.
8. **Test vectors.** FIPS 180-4 SHA-1 vectors, RFC 2202 HMAC-SHA-1, RFC 4226 Appendix D, RFC 6238 Appendix B for all three algorithms, and Wycheproof HMAC-SHA1.

### Pinning and updates

- Crypto crates are pinned with `=x.y.z` in `[workspace.dependencies]`, and `Cargo.lock` is committed.
- Dependabot PRs that touch a crypto crate, directly or through the lockfile, are **never auto-merged**. The reviewer reads the changelog and diff, re-runs the vectors, and records the review in the PR.
- A new major version, such as opaque-ke moving to curve25519-dalek 5, gets a short note in this ADR.
- Toolchain bumps that a crypto crate's MSRV forces are fine, but they go in the same PR.

### cargo-deny

- The existing policy stays: advisories deny, yanked deny, crates.io only, and the license allow-list.
- Duplicate crypto crates (two RustCrypto generations) stay `warn`, and are listed here as known debt: block-buffer, const-oid, cpufeatures, crypto-common, curve25519-dalek, digest, fiat-crypto, hkdf, hmac, rand_core and sha2 (plus syn, through proc macros): the 12 duplicates cargo-deny 0.20.2 reports for the M1 crypto set. They stay until opaque-ke moves to the new generation.
- Any `ignore` or ban exception needs the advisory id, the reason, the affected code path, and an expiry milestone.

### Our code

- **No `unsafe`.** Enforced by the workspace lint. This also rules out writing our own global allocator, `mlock` wrappers, or FFI to C crypto.
- **No custom primitives,** and no compositions beyond those listed in [CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules) rule 2: the committing envelope, SK-into-OPAQUE with the Context bindings, signed HPKE grants and their PSKs, the signed account state and bundle chain, device-auth challenge signing and request signing, lazy item-key rotation, the pairing SAS and sealed transfer, the recovery token and wait, the share token scheme, and server-side sealing. That list is also the M8 audit scope for our own code. A new composition needs an ADR and joins the list.
- **One entry point per construction.** Raw AEAD, HKDF and opaque-ke calls stay private to their `rizzy-core` modules, so the public API is envelopes, flows and signed statements. A raw AEAD call outside the envelope module is a review blocker.

### Memory hygiene

- Secrets are held in types that zeroize on drop: `Zeroizing`, `secrecy::SecretBox`, or newtypes deriving `ZeroizeOnDrop`.
- Secret types do not implement `Clone`, `Copy`, `Display` or `Serialize`.
- `Debug` is implemented by hand and prints `[REDACTED]`.
- Exposing a secret requires an explicit `expose_secret()`.
- Secret buffers are allocated once, at their final capacity.
- Argon2 runs with a caller-owned `Zeroizing` block buffer through `hash_password_into_with_memory`.
- No secrets or plaintext in logs, errors or panic messages. Server log fields come from an allow-list.

### RNG rules

- `rizzy-core` and `rizzy-sync` take an injected `rand_core::CryptoRng` (0.10). They have **no direct dependency** on `getrandom` or `rand`, and never call `rand::rng()`/`thread_rng`.
- One transitive exception: `rand` 0.8 through opaque-ke, with default features off, so without `thread_rng` and without getrandom. The `check-deps` allow-list for no-I/O crates ([ADR 0016](0016-workspace-layout.md) R1) names exactly this edge; any other path to `rand`, and any path to getrandom, fails CI. R1 states this exception explicitly.
- Only leaf crates (CLI, server, Tauri shell, UniFFI bindings, wasm bindings) depend on `getrandom` directly. They pass `rand_core::UnwrapErr(getrandom::SysRng)`. Only the wasm bindings crate enables `wasm_js`.
- Server-side libraries may pull getrandom in through third-party crates (sqlx-postgres, mail-auth), but never depend on it themselves; they take an injected RNG ([ADR 0016](0016-workspace-layout.md) R2). getrandom never appears in the dependency closure of `rizzy-core`, `rizzy-sync` or any other no-I/O crate (R1).
- The RNG is never seeded from time. Deterministic RNGs are dev-dependencies only.
- **An RNG failure aborts the process.** rand_core 0.10's `CryptoRng` is `TryCryptoRng<Error = Infallible>`, so there is no error channel: `UnwrapErr` panics, and with `panic = "abort"` the process dies (in wasm, the instance traps). We accept that; there is no fallback source.

### Constant-time rules

- Secret and secret-derived comparisons use `subtle::ConstantTimeEq`: commitments, token hashes, check values.
- Our code does no secret-indexed table lookups and no branching on secrets. This applies to the Base32 and base64 encoders for the SK, the recovery code and share secrets.
- Decryption failures are indistinguishable to remote parties.
- `ed25519-dalek` verification always uses `verify_strict`.
- Signing always goes through `SigningKey`, never with a separately supplied public key (RUSTSEC-2022-0093).

## Consequences

### Positive
- Every crypto dependency has a written rationale and a known audit status.
- Updates are deliberate, not automatic.
- The wasm and no-I/O contracts are enforced by feature sets and by CI (`cargo check-wasm`, `cargo deny`).
- The M8 auditor gets a precise list of what to look at.

### Negative
- Security fixes involve more manual work: exact pins mean a patch release needs a human PR.
- The two-generation duplication stays until opaque-ke catches up.
- Some useful tools are off the table because they need `unsafe`: a zeroizing allocator, `mlock`.

### Risks
- "Audited" is still mostly historical. The M8 audit budget must include the crates, not only our code.
- The approval process will be tempting to skip for "small" crates. Review has to hold the line: any crate that touches key material is a crypto crate.

## Alternatives considered

- **Caret requirements with lockfile-only pinning.** Less work, but a `cargo update` can silently move crypto code.
- **libsodium or ring through FFI.** It needs a C toolchain or `unsafe`, complicates wasm, and ring's API does not cover XChaCha20, Argon2 or OPAQUE (U).
- **Allowing any crate that passes `cargo deny`.** A license and advisory check says nothing about cryptographic quality.
- **A zeroizing global allocator, as Bitwarden's SDK ships one** (V). It needs `unsafe` in our crates, or an extra unreviewed dependency. Deferred as an open question.

## Open questions for the owner

1. **WebAuthn server library (M3).**
   - `webauthn-rs` 0.5.5 is audited by SUSE product security (V; the year is probably 2021, L), but depends on openssl unconditionally, which our `deny.toml` bans.
   - `webauthn_rp` depends on `rsa` 0.9, which has an unfixed advisory.
   - *Recommendation:* a narrowly scoped exception, with written rationale and a check at each milestone for a rustls/RustCrypto-only path. The alternative is dropping WebAuthn 2FA from M3. How to scope it:
     - cargo-deny cannot scope a ban by binary. Its `[bans]` entries scope by `wrappers`, i.e. which crates may depend on the banned crate directly. So the `deny.toml` exception is: `openssl` with `wrappers = ["webauthn-rs-core"]`, and `openssl-sys` with `wrappers = ["openssl", "webauthn-rs-core"]` (keeping only the direct parents M3's lockfile actually shows).
     - "Only the server" is enforced by `cargo xtask check-deps` ([ADR 0016](0016-workspace-layout.md)): a rule that `openssl` and `openssl-sys` are reachable only from `rizzy-server` and the domain crate that does WebAuthn, never from `rizzy-core`, `rizzy-client`, `rizzy-cli`, `rizzy-wasm`, `rizzy-ffi` or `rizzy-desktop`.
     - Cost: a C library in the server image. [ADR 0010](0010-server-shape.md) builds a static musl binary on a distroless base, so OpenSSL has to be built from source through openssl-sys's `vendored` feature or linked dynamically, which changes the image (U, confirm in M3).
2. **cargo-vet** (or cargo-crev) to record reviews of crypto crates? Threat model Q-9 asks for this decision before M1 adds crypto crates. *Recommendation:* decide it then, in M1, and adopt cargo-vet at once for the crypto crates in the table above (about 20 crates, importing published audit sets where they exist), extending it to all dependencies by M8, before the external audit. Until adoption, reviews are recorded in PRs.
3. **Zeroizing global allocator.** *Recommendation:* no for v1.0. It needs `unsafe`, and targeted `Zeroizing` buffers cover the known secrets.
4. **Nightly toolchain for fuzzing only.** *Recommendation:* yes, in a separate scheduled CI job; release builds stay on the pinned 1.94.1.

## References

- [CRYPTO.md §3 Primitives](../CRYPTO.md#3-primitives), [§12 Randomness, memory hygiene and side channels](../CRYPTO.md#12-randomness-memory-hygiene-and-side-channels), [§15 Testing](../CRYPTO.md#15-testing)
- `deny.toml`; the workspace lints in `Cargo.toml`; the contract in `crates/rizzy-core/src/lib.rs`
- The getrandom README (the wasm32 backend must be enabled only in the final crate)
- RustSec: RUSTSEC-2022-0093, RUSTSEC-2023-0071, RUSTSEC-2023-0096, RUSTSEC-2024-0344, RUSTSEC-2026-0097
- [ADR 0003](0003-authentication-opaque.md), [ADR 0005](0005-symmetric-encryption-aead.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md)
