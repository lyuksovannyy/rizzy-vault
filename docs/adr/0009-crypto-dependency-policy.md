# ADR 0009: Cryptographic dependency and memory-hygiene policy

- Status: Partially superseded by [ADR 0019](0019-native-clients.md) ("RNG rules" in part)
- Date: 2026-09-27
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

### Owner decisions (2026-09-25)

The owner answered the open questions on 2026-09-25:

1. **WebAuthn server library (M3)** → A narrowly scoped exception for `webauthn-rs`, with written rationale and a check at each milestone for a rustls/RustCrypto-only path. WebAuthn 2FA stays in M3.
   - `deny.toml`: `openssl` with `wrappers = ["webauthn-rs-core"]`, and `openssl-sys` with `wrappers = ["openssl", "webauthn-rs-core"]`, keeping only the direct parents M3's lockfile actually shows.
   - `cargo xtask check-deps` ([ADR 0016](0016-workspace-layout.md)) enforces that `openssl` and `openssl-sys` are reachable only from `rizzy-server` and the domain crate that does WebAuthn, never from `rizzy-core`, `rizzy-client`, `rizzy-cli`, `rizzy-wasm`, `rizzy-ffi` or `rizzy-desktop`.
   - The cost to the server image (OpenSSL built through openssl-sys's `vendored` feature, or linked dynamically) is confirmed in M3.
2. **cargo-vet** → Adopt cargo-vet in M1, at once for the crypto crates in the table above (about 20 crates, importing published audit sets where they exist), and extend it to all dependencies by M8, before the external audit. Until adoption, reviews are recorded in PRs. This answers the cargo-vet part of [THREAT_MODEL Q-9](../THREAT_MODEL.md#10-open-questions-for-the-owner).
3. **Zeroizing global allocator** → No for v1.0. It needs `unsafe`, and targeted `Zeroizing` buffers cover the known secrets.
4. **Nightly toolchain for fuzzing only** → Yes, in a separate scheduled CI job (weekly and non-blocking for PRs, [CRYPTO.md §16](../CRYPTO.md#16-open-questions-for-the-owner) question 7). Release builds stay on the pinned 1.94.1.

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

None. All were answered by the owner on 2026-09-25; see [Owner decisions (2026-09-25)](#owner-decisions-2026-09-25) in the Decision section. The answers keep the original question numbers, so a reference to "open question N" means owner decision N.

## References

- [CRYPTO.md §3 Primitives](../CRYPTO.md#3-primitives), [§12 Randomness, memory hygiene and side channels](../CRYPTO.md#12-randomness-memory-hygiene-and-side-channels), [§15 Testing](../CRYPTO.md#15-testing)
- `deny.toml`; the workspace lints in `Cargo.toml`; the contract in `crates/rizzy-core/src/lib.rs`
- The getrandom README (the wasm32 backend must be enabled only in the final crate)
- RustSec: RUSTSEC-2022-0093, RUSTSEC-2023-0071, RUSTSEC-2023-0096, RUSTSEC-2024-0344, RUSTSEC-2026-0097
- [ADR 0003](0003-authentication-opaque.md), [ADR 0005](0005-symmetric-encryption-aead.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md)

## Amendments

### 2026-09-26: `blake2` and `poly1305` pinned to switch on their `zeroize` features

Owner decision of 2026-09-26, from the M1 step 1 review (finding hygiene-secrets#5). This entry adds two rows to [Allowed crate families for cryptography](#allowed-crate-families-for-cryptography) and two lines to [Required feature sets](#required-feature-sets), as those sections provide for. It changes nothing else in this ADR.

**Added to the crate table:**

| Family / crate | Use | Pin (M1) |
|---|---|---|
| `blake2` (RustCrypto) | Never called by our code. BLAKE2b inside `argon2`; declared only to switch on its `zeroize` feature | `=0.11.0` |
| `poly1305` (RustCrypto) | Never called by our code. Poly1305 inside `chacha20poly1305`; declared only to switch on its `zeroize` feature | `=0.9.1` |

**Added to the required feature sets:**

- `blake2`: `default-features = false`, `["zeroize"]`.
- `poly1305`: `default-features = false`, `["zeroize"]`.

Both are declared in `[workspace.dependencies]` and as normal dependencies of `rizzy-core`, with a manifest comment that says why. Both versions are the ones `Cargo.lock` and `fuzz/Cargo.lock` had already resolved, so no new package or version enters either lockfile. In each lockfile the changes are the new `rizzy-core → blake2` and `rizzy-core → poly1305` entries and the new `poly1305 → zeroize` edge. Because the two declarations look unused, `cargo xtask check-deps` enforces them: its "ADR 0009 required feature sets" rule fails if `rizzy-core`'s own entry for either crate stops turning on `zeroize`, and it checks the other feature sets of [Required feature sets](#required-feature-sets) the same way.

**Why.** Cargo unifies features per package, so a direct dependency that names a feature turns it on for the transitive copy too. The parents do not forward these two features:

- `argon2` 0.6.0's `zeroize` feature is only `dep:zeroize`. Without blake2's own `zeroize`, the `Drop` of the Blake2b core (the chaining state `h` and the counter `t`) compiles to nothing (V, crate source). The hasher of Argon2's initial hash then ends holding H0, and the hasher in `blake2b_long` ends holding the Argon2 output tag: the local-unlock `a`, the KSF output, and the export and backup key `e`.
- `chacha20poly1305` 0.11.0's `zeroize` feature forwards only `chacha20/zeroize`. Without poly1305's own `zeroize`, the `Poly1305` state, which holds the one-time key halves r and s, is not wiped on drop (V, crate source). That key is used for one nonce only, so it is worth little, but the fix costs nothing.

**What this does not fix.** No feature reaches argon2 0.6.0's `blake2b_long` output buffer (`full_out`) and H' chain blocks, argon2's stack block holding G(H0 ‖ i ‖ l), or hmac 0.13's key block in `new_from_slice`. [CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene) lists them as limits. If `argon2` starts forwarding `blake2/zeroize` and `chacha20poly1305` starts forwarding `poly1305/zeroize`, these two pins become unnecessary, and removing them is a reviewed change like any pin change.

**Checklist record: `blake2` 0.11.0**

1. **Need.** No construction of ours. Argon2id (RFC 9106) is built on BLAKE2b, and `argon2` already depended on this exact crate. It is declared only for the feature ([Memory hygiene](#memory-hygiene)).
2. **Provenance.** RustCrypto Developers, repository `RustCrypto/hashes`: the same repository and authors as `sha2` and `sha1` (V, crate manifests). Release cadence, download counts and bus factor: U.
3. **Audit history.** None found (U).
4. **Advisories.** RustSec has one advisory for the crate, RUSTSEC-2019-0019: HMAC-BLAKE2 used the wrong block size before 0.8.1. It affected the HMAC use only, not the digest, and does not apply to 0.11.0 (V, RustSec advisory-db checkout of 2026-09-25). How quickly it was fixed: U. `cargo deny check` (cargo-deny 0.20.2) reports advisories ok (V, 2026-09-26).
5. **`unsafe`.** One block, in `src/simd.rs` (`as_bytes`, a byte view of the SIMD-style vector type used on every target, wasm32 included). The `zeroize` feature adds no `unsafe` (V, crate source).
6. **Constant time.** BLAKE2b is an add-rotate-xor design with no table lookups and no data-dependent branches (L, a property of the algorithm). There is no separate timing test.
7. **Builds and hygiene.** Dependencies: `digest` 0.11 with `mac`, plus `digest/zeroize` through this feature, which `sha2` and `hmac` already switch on. No new package. License MIT OR Apache-2.0, MSRV 1.85 (V, crate manifest). With the feature on, `cargo check-wasm`, `cargo deny check` and `cargo xtask check-deps` pass, and `cargo tree -e features -p rizzy-core` shows `blake2 [zeroize]` on the host and on wasm32-unknown-unknown, with getrandom outside rizzy-core's normal and build closure on both (V, 2026-09-26).
8. **Test vectors.** Covered through Argon2id: the RFC 9106 §5.3 Argon2id vector (`kdf.rs`) and the transcript vector (`tests/vectors/transcript.json`), which runs Argon2id at `kdf_id` 1. Every known-answer vector still replays byte for byte (V, 2026-09-26). The feature changes only `Drop`.

**Checklist record: `poly1305` 0.9.1**

1. **Need.** No construction of ours. It is the Poly1305 half of XChaCha20-Poly1305 ([CRYPTO.md §3](../CRYPTO.md#3-primitives)) and of HPKE's ChaCha20Poly1305, through `chacha20poly1305`, which already depended on this exact crate. It is declared only for the feature.
2. **Provenance.** RustCrypto Developers, repository `RustCrypto/universal-hashes`: the same organisation and authors as `chacha20poly1305` (V, crate manifests). Release cadence, download counts and bus factor: U.
3. **Audit history.** The NCC Group 2020 review of the RustCrypto AEADs covered `chacha20poly1305` on a much older version. Whether `poly1305` itself was in scope: U.
4. **Advisories.** None in RustSec (V, advisory-db checkout of 2026-09-25, which has no entry for the crate). `cargo deny check` reports advisories ok (V, 2026-09-26).
5. **`unsafe`.** In the AVX2 backend and its run-time detection (`src/backend/avx2*`, `src/backend/autodetect.rs`, x86 and x86_64 only) and in a fuzzing helper compiled only under `cfg(fuzzing)` or `cfg(test)`. **This feature switches on one more block:** the `Drop` impl calls `zeroize::zeroize_flat_type` on the whole state. wasm32 uses the portable `soft` backend (V, crate source).
6. **Constant time.** Upstream writes both backends without secret-dependent branches or lookups (U). There is no separate timing test.
7. **Builds and hygiene.** Dependencies: `universal-hash` 0.6, `zeroize` 1 (optional, now on; already in the tree at `=1.9.0`), and `cpufeatures` 0.3 on x86 and x86_64. No new package. License Apache-2.0 OR MIT, MSRV 1.85 (V, crate manifest). With the feature on, `cargo check-wasm`, `cargo deny check` and `cargo xtask check-deps` pass, and `cargo tree -e features -p rizzy-core` shows `poly1305 [zeroize]` on the host and on wasm32-unknown-unknown (V, 2026-09-26).
8. **Test vectors.** Covered through XChaCha20-Poly1305 and HPKE: the envelope vectors (`tests/vectors/envelopes.json`, including the HPKE PSK device grant) and the transcript's `E_srv` and `E_local`. Every known-answer vector still replays byte for byte (V, 2026-09-26). The feature changes only `Drop`.

cargo-deny's duplicate list is unchanged by this entry: the two crates add no package and no second version.

### 2026-10-05: client TLS for `rv` ([ADR 0030](0030-client-tls-rv.md))

Owner decision of 2026-10-05: ADR 0030 accepted with every recommendation. This entry is the one ADR 0030's "On acceptance" section gives, with its date filled in. It adds rows to [Allowed crate families for cryptography](#allowed-crate-families-for-cryptography) and lines to [Required feature sets](#required-feature-sets), as those sections provide for, and changes nothing else in this ADR.

**2026-10-05: client TLS for `rv` ([ADR 0030](0030-client-tls-rv.md)).** Adds to the crate table: `tokio-rustls` (async adapter; `=0.26.6`), `rustls` (TLS 1.3 client in `rizzy-cli` only; `=0.23.45`), `webpki-roots` (Mozilla roots; `=1.0.9`); `ring`, `rustls-webpki`, `rustls-pki-types`, `untrusted` lockfile-pinned. Required feature sets: `tokio-rustls` `default-features = false, ["ring"]`; `rustls` `default-features = false, ["std", "ring"]`; never `aws_lc_rs`, `fips`, `early-data`. Checklist: (1) Need: TB-1 transport ([THREAT_MODEL](../THREAT_MODEL.md) §3.3), no construction of ours. (2) Provenance: the `rustls` GitHub organisation for the three crates and `rustls-webpki`; `ring` by Brian Smith (V, manifests and repository fields); bus factor and downloads U. (3) Audits: rustls by Cure53 in 2020 on a much older version (U); `ring`, `tokio-rustls`, `webpki-roots`: none found (U). (4) Advisories (V, RustSec): rustls RUSTSEC-2024-0336, -2024-0399, -2026-0285 (fixed in 0.23.45); `ring` RUSTSEC-2025-0009 (fixed 0.17.12), -2025-0010 (informational, < 0.17); `rustls-webpki` RUSTSEC-2023-0053, -2026-0049, -0098, -0099, -0104 (all fixed ≤ 0.103.13); `tokio-rustls` RUSTSEC-2020-0019 (fixed 0.13.1); `untrusted` RUSTSEC-2018-0001; `webpki-roots` none. Time to fix: U. (5) `unsafe`: `rustls` and `webpki-roots` `#![forbid(unsafe_code)]`; `tokio-rustls`, `rustls-webpki` and `untrusted` have no `unsafe` token; `rustls-pki-types` one `transmute` for IPv6 text; `ring` 228 lines plus C and assembly (V, crate source). (6) Constant time: `ring`'s primitives come from BoringSSL and are written constant-time (L); no test of ours. (7) Builds: native only (not in a wasm crate); licenses `tokio-rustls` MIT OR Apache-2.0, `rustls` Apache-2.0 OR ISC OR MIT, `webpki-roots` CDLA-Permissive-2.0, `ring` Apache-2.0 AND ISC, `rustls-webpki` ISC, all allow-listed (V). New package: `tokio-rustls` only; `cargo deny` bans, licenses, sources ok and duplicates unchanged; `cargo xtask check-deps` ok (V, cargo-deny 0.20.2). (8) Tests: ADR 0030 Decision 7.

**Where it is applied.** The three crates are declared in `[workspace.dependencies]` with the pins and feature sets above and used by `rizzy-cli` alone; its test build adds rustls' `tls12` feature, only so a test server can offer TLS 1.2 and be refused. TLS 1.3 only, the explicit `ring` provider and the trust store are set at run time in `crates/rizzy-cli/src/tls.rs`. `cargo xtask check-deps` scans `crates/*/src` for the `dangerous` and `danger` tokens (ADR 0030 Decision 3). The CA file reader has the fuzz target `fuzz/fuzz_targets/ca_pem.rs`. `Cargo.lock` gains `tokio-rustls` 0.26.6 only; `fuzz/Cargo.lock` gains it too, with `rizzy-cli` and the hyper client crates the main lockfile already holds.

### 2026-10-09: `p256` for ES256 WebAuthn passkeys ([ADR 0039](0039-passkeys-vault-and-extension.md), [ADR 0041](0041-p256-crate-approval.md))

Owner decision of 2026-10-08: [ADR 0041](0041-p256-crate-approval.md) accepted `p256` `=0.14.0`, `default-features = false, features = ["ecdsa", "alloc"]`, with the mechanical checks and the remaining **U** items run and resolved in the implementation change, per ADR 0041's own "Owner answers at acceptance." This entry is that run, recorded the way ADR 0041 §"Open questions for the owner" item 2 asks and the 2026-09-26 and 2026-10-05 entries above model. It adds one row to [Allowed crate families for cryptography](#allowed-crate-families-for-cryptography) and one line to [Required feature sets](#required-feature-sets), as those sections provide for, and changes nothing else in this ADR.

**Added to the crate table:**

| Family / crate | Use | Pin (M2) |
|---|---|---|
| `p256` (RustCrypto) | ES256 (COSE alg `-7`, ECDSA P-256/SHA-256) for WebAuthn passkey credentials ([ADR 0039](0039-passkeys-vault-and-extension.md) §3). Transitively: `ecdsa` 0.17.0, `elliptic-curve` 0.14.1, `crypto-bigint` 0.7.5, `primeorder`/`primefield` 0.14.0, `wnaf` 0.14.1, `rfc6979` 0.6.0, `der` 0.8.2, `spki` 0.8.1, `sec1` 0.8.1, `base16ct` 1.0.0, `const-oid` 0.10.2, `cpubits` 0.1.1, `num-traits` 0.2.19, `autocfg` 1.5.1 | `=0.14.0` |

**Added to the required feature sets:**

- `p256`: `default-features = false`, `["ecdsa", "alloc"]`. Never `getrandom`, `std`, `pem`, `pkcs8`, `serde`. Key generation only through `SigningKey::random(&mut rng)` with the injected `rand_core::CryptoRng`; signing is deterministic (RFC 6979) through `SigningKey::sign`/`try_sign`, never `sign_with_rng` or a separately supplied public key (RUSTSEC-2022-0093's rule, [RNG rules](#rng-rules)).

**Checklist, run for real (ADR 0041 §3's pass was best-effort; this is the implementation PR's run):**

1. **Need.** ES256 for WebAuthn credential creation and assertion signing ([ADR 0039](0039-passkeys-vault-and-extension.md) §2–§3); algorithm, curve and hash are fixed by the WebAuthn/COSE specs, no construction of ours (V).
2. **Provenance.** RustCrypto Developers, `RustCrypto/elliptic-curves` (V, crate manifest); same organisation as `ed25519-dalek`'s siblings and the AEAD/KDF/hash crates already pinned. Release cadence, downloads, bus factor beyond "same org": U, as ADR 0041 left it.
3. **Audit history.** None found for `p256`, `elliptic-curve`, `ecdsa`, `crypto-bigint` (U, same position as `hpke`/`blake2`/`poly1305` above).
4. **Advisories.** `cargo deny check` (cargo-deny 0.20.2) reports `advisories ok` with `p256` and its five new direct/transitive crates in the lockfile; no `ignore` or exception was needed (V, 2026-10-09).
5. **`unsafe`.** `p256` and `ecdsa`: zero (V, grep of vendored source, cross-checked against build output: neither appears as an `unsafe`-token hit). `elliptic-curve` 0.14.1: 4 blocks (`src/point/non_identity.rs:63,73`, `src/scalar/nonzero.rs:73,83`; pointer/repr reinterpretation for a non-identity point/scalar invariant). `crypto-bigint` 0.7.5: 18 blocks across 8 files (`uint.rs`, `non_zero.rs`, `odd.rs`, `limb.rs`, `uint/ref_type.rs` and `uint/ref_type/cmp.rs`, `uint/encoding.rs`, `uint/boxed/from.rs`; const-generic limb-array reinterpretation, e.g. `core::slice::from_raw_parts_mut` in `ref_type.rs:73`). `der` 0.8.2: 4 (one per file, `src/string.rs`, `src/bytes.rs`, `src/asn1/sequence.rs`, `src/asn1/octet_string.rs`; `from_utf8_unchecked`-style string/byte reinterpretation on already-validated DER content). `base16ct` 1.0.0: 4 (`src/upper.rs`, `src/lower.rs`; `from_utf8_unchecked` on hex output known to be ASCII). `const-oid` 0.10.2: 1 (`src/lib.rs:320`). None of it is FFI, a C ABI or our own code; all of it is upstream, transitive, and none was spot-checked beyond sampling one or two sites per crate (U for a full line-by-line audit; it is M8 scope like every other transitive `unsafe` this ADR already accepts).
6. **Constant-time claims.** As ADR 0041 §6 says: RustCrypto's `elliptic-curve`/`crypto-bigint` stack aims for constant-time scalar/field arithmetic by construction; no independent test (`dudect` or otherwise) was found or run (U, unchanged from ADR 0041).
7. **Builds and hygiene.** `cargo check -p rizzy-core` and `cargo check-wasm` both pass with `p256` in the tree (V, 2026-10-09). `getrandom` is absent from `rizzy-core`'s and `rizzy-sync`'s normal-and-build closure (`cargo tree -i getrandom -e normal,build`: nothing to print; V, 2026-10-09), confirming R1 holds. License `Apache-2.0 OR MIT` for all seven new/bumped crates, already on `deny.toml`'s allow-list (V, crate manifests). `cargo xtask check-deps` passes (V, 2026-10-09) after two changes: (a) `CORE_EXTERNAL_ALLOW` in `crates/xtask/src/rules.rs` gained the 18 genuinely-compiled new entries (`p256@0.14`, `ecdsa@0.17`, `elliptic-curve@0.14`, `crypto-bigint@0.7`, `primefield@0.14`, `primeorder@0.14`, `wnaf@0.14`, `der@0.8`, `sec1@0.8`, `spki@0.8`, `const-oid@0.10`, `base16ct@1`, `ff@0.14`, `group@0.14`, `num-traits@0.2`, `autocfg@1`, `cpubits@0.1`, plus the already-listed `hybrid-array@0.4`); (b) `cargo xtask check-deps` itself (`crates/xtask/src/metadata.rs`) was fixed to stop treating a *dormant* optional-dependency edge as reached. `cargo metadata`'s resolve graph keeps an edge to an optional dependency even when nothing switches its enabling feature on — observed directly here: `elliptic-curve` 0.14.1 declares `pkcs8` optional, and `primeorder` 0.14.0 declares `serdect` optional (which itself hard-depends on `serde`/`serde_core`/`serde_derive`), neither ever named in the declaring package's own resolved `features`, confirmed against `target/`: no build artifact for `pkcs8`, `serde`, `serde_core`, `serde_derive` or `serdect` exists after building for the host or `wasm32-unknown-unknown`. Counting that edge as "reached" would have forced either allow-listing `serde` in a no-I/O crate's closure — contrary to this very feature set's "never `serde`" line — or leaving `check-deps` permanently red. `Graph::closure` (`crates/xtask/src/metadata.rs`) now has a `Package::activates` liveness test (feature-table-aware: handles bare, `dep:`-namespaced and slash-form strong references, and correctly leaves weak `key?/feat`-only references dormant) with its own unit tests (`metadata::tests::dormant_optional_dependency_is_not_reached`, `activated_optional_dependency_is_still_reached`, `namespaced_dep_syntax_without_implicit_feature_is_still_live`, `weak_reference_alone_does_not_activate_the_dependency`, `strong_slash_reference_activates_the_dependency`) and two `check::tests` integration tests (`r1_dormant_optional_dependency_is_ignored`, `r1_activated_optional_dependency_still_fails`) proving a genuinely-activated forbidden dependency is still caught. Emptying `CORE_EXTERNAL_ALLOW` and re-running `check-deps` enumerated the real closure (88 entries) and confirmed it is exactly the restored allow-list, with no entry lost to the liveness fix.
8. **Test vectors.** RFC 6979 Appendix A.2.5 (P-256/SHA-256 deterministic ECDSA) and CAVP/Wycheproof P-256/SHA-256 vectors, plus WebAuthn-structure vectors for the hand-written CBOR/COSE, as `crates/rizzy-core/tests/vectors/` fixtures (ADR 0041 §8; this ADR's implementation change, tracked separately from this amendment).

**New cargo-deny duplicates.** As ADR 0041 predicted: `base16ct` (0.2.0 and 1.0.0), `const-oid` (0.9.6 and 0.10.2), `crypto-bigint` (0.5.5 and 0.7.5), `der` (0.7.10 and 0.8.2), `elliptic-curve` (0.13.8 and 0.14.1), `ff` (0.13.1 and 0.14.0), `group` (0.13.0 and 0.14.0), `sec1` (0.7.3 and 0.8.1) join the 2026-09-27 duplicate-debt list above, all `warn`, none a new ban or license exception. (`const-oid` was missed in the first pass of this entry; added 2026-10-09 after re-running `cargo deny check bans` and finding it in the output, per ADR 0041 §7's own instruction to record the real list the tool reports.) They stay until `opaque-ke`'s `voprf` stack catches up to the newer RustCrypto generation, the same condition already stated for the original twelve.

**Where it is applied.** `p256` is declared in `[workspace.dependencies]` with the pin and feature set above and as a normal dependency of `rizzy-core` only ([ADR 0039](0039-passkeys-vault-and-extension.md) §5). `Cargo.lock` gains `p256` and the fourteen transitive crates named in the crate-table row above; its duplicate set grows by the eight names in the paragraph above. The ES256 key-generation, signing and COSE/CBOR encoding code this unblocks is `crates/rizzy-core/src/passkey.rs` and its known-answer-vector tests, tracked by [ADR 0039](0039-passkeys-vault-and-extension.md), not by this ADR.
