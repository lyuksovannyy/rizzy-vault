# ADR 0003: Authentication: OPAQUE

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1

## Context

ROADMAP §4.3 requires authentication that never sends a password-equivalent to the server. Bitwarden's design sends a hash derived from the master password, and the server re-hashes it. Whoever captures that hash can log in. ROADMAP §5 already prefers OPAQUE; this ADR fixes the details.

What the options have in common:
- In every PAKE-style design, a server that has its own secrets and a user's record can run an offline dictionary attack against that user. RFC 9807 says this plainly for OPAQUE.
- What differs is what an attacker needs *before* the attack starts, whether they can precompute, and what the DB alone yields.

We also need:
- offline unlock on devices,
- On-device sync mode (M4), where the server must hold nothing crackable,
- wasm, native and UniFFI builds from one crate ([ADR 0013](0013-shared-client-core.md)).

Crate facts (fact sheet, checked 2026-09-25):
- `opaque-ke` 4.0.1 is the latest stable release.
- 4.0.0 synced with RFC 9807 and always creates the dummy record, which fixes a timing leak.
- NCC Group audited v0.5.0 in 2021. 4.x is not audited.
- It is built on the previous RustCrypto generation: curve25519-dalek 4, digest 0.10, voprf 0.5, rand 0.8 / rand_core 0.6. It re-exports `rand` and `generic_array`, but not sha2 (V, crate source).
- With `ksf: None` it silently falls back to Argon2 defaults of 19 MiB, t=2, p=1.

## Decision

1. **Protocol.** OPAQUE per **RFC 9807**, implemented with **`opaque-ke` =4.0.1**, with `default-features = false` and `features = ["ristretto255"]`. We do not enable the crate's `argon2` or `std` features. We do not ship on 4.1.0-pre.
2. **Ciphersuite** (`suite_id = 1`): ristretto255-SHA512 OPRF and `TripleDh<Ristretto255, Sha512>`. This is RFC 9807's first recommended configuration. `Sha512` comes from a direct, renamed dependency on sha2 0.10.9, because opaque-ke does not re-export it ([ADR 0009](0009-crypto-dependency-policy.md)).
3. **KSF.** Our own `RizzyArgon2idKsf`, which runs Argon2id through `argon2` 0.6 with parameters from [ADR 0004](0004-key-derivation-argon2id-secret-key.md) and the all-zero salt RFC 9807 specifies.
   - Its `Default` is the M1 parameter set, so a missing `ksf` fails safe.
   - Every call goes through one wrapper that passes `ksf: Some(..)`.
4. **Password input.** OPAQUE's password input is `pw_in = HKDF(password, salt = Secret Key)`, so the Secret Key is required for every guess ([ADR 0004](0004-key-derivation-argon2id-secret-key.md)).
5. **Context and identifiers.**
   - The Context binds `suite_id`, `kdf_id` and the server origin ([CRYPTO.md §5.3](../CRYPTO.md#53-context-identifiers-and-credential-identifier)). The origin stops a phishing server from relaying the three OPAQUE messages to the real server and walking away with the session it issues. A server reachable under several hostnames configures one canonical origin.
   - `credential_identifier` is the `account_id`, so renaming an account needs no re-registration.
   - Client and server identities are left at their defaults (the public keys).
6. **`export_key`** derives the key that wraps the account key on the server. Devices keep a separate local Argon2id wrap for offline unlock. Each unlock runs Argon2id exactly once. See [ADR 0006](0006-key-hierarchy.md) and [CRYPTO.md §5.4](../CRYPTO.md#54-where-the-unlock-key-comes-from).
7. **Where OPAQUE is used.**
   - OPAQUE runs for: the first login on a device, every web-vault session, re-authentication for sensitive actions, and password change.
   - Enrolled devices authenticate with an Ed25519 device key after a local unlock ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication)).
8. **`server_setup`** (`oprf_seed`, AKE keypair, fake keypair):
   - It lives in a separate 0600 file, not in the database, together with the `enum_key` used by the enumeration defence.
   - The server refuses to start if the setup does not match the records.
   - Rotation uses versioned setups and transparent re-registration ([CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)).
9. **Enumeration.** Login names are normalised once, by one function ([CRYPTO.md §2](../CRYPTO.md#2-conventions)). Unknown names get the fake-record path with a deterministic fake credential id, and a `kdf_id` chosen by a keyed selector so that, during a KDF migration, unknown names flip to the new `kdf_id` at most once, like real accounts ([CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration)). Signup is invite-only by default.
10. **On-device mode** stores no OPAQUE record at all.
11. **2FA** (TOTP in M1, WebAuthn in M3) gates server access only. It never feeds key derivation.

## Consequences

### Positive
- The server never receives a password-equivalent. A stolen DB without `server_setup` allows no offline guessing at all.
- With the Secret Key mixed in, even DB plus `server_setup` allows no offline guessing.
- Stretching happens after the OPRF, as the RFC intends, so an attacker cannot precompute against a targeted user.
- The login flow can carry a KDF-version binding that the server cannot downgrade, and an origin binding that defeats relay phishing of native clients.

### Negative
- A second RustCrypto generation stays in the dependency tree: curve25519-dalek 4 next to 5, sha2 0.10 next to 0.11, and rand_core 0.6 next to 0.10. `cargo deny` reports these as `multiple-versions` warnings, and they increase the audit surface.
- `rizzy-core` needs a small rand_core 0.6 adapter, because opaque-ke takes a 0.6 RNG. It is written against opaque-ke's own `rand` re-export, so there is no separate rand_core 0.6 dependency; `rand` 0.8 (no default features, no getrandom) stays in the tree transitively.
- Binding the origin means a client that dials a non-canonical hostname (a LAN IP, an old domain) cannot log in with OPAQUE, and a Context mismatch fails exactly like a wrong password. So the server returns its canonical origin next to KE2; the client compares it with the origin it dialled and reports a mismatch before running the KSF. That value is unauthenticated and is used only for this message.
- Login takes three messages, and the server keeps short-lived login state (60 s TTL).
- Losing `server_setup` breaks every OPAQUE login. Users with an enrolled device or a recovery code can repair their account; everyone else loses their data.

### Risks
- opaque-ke 4.x has no audit, so the M8 audit must cover it.
- The crate's future: 4.1 is in pre-release (it adds a KEM-based key exchange). Upgrading to it is a new ADR.
- If the owner rejects the Secret Key, a full server compromise enables offline guessing against every account. That is RFC 9807's known limit.

## Alternatives considered

- **Bitwarden-style hashed master password.** It sends a password-equivalent, and ROADMAP §5 rejects it.
- **SRP-6a** (1Password, Proton Pass and AliasVault use it).
  - The server sends the salt before authentication, so a targeted attacker can precompute.
  - It has no RFC-track modern analysis comparable to OPAQUE's.
  - The Rust `srp` crate's stable 0.6.0 is four years old, and 0.7 is still a release candidate.
- **Pre-stretching before OPAQUE** (Argon2id first, then OPAQUE with the `Identity` KSF). It saves one Argon2id at device enrolment. But it re-enables precomputation, needs an unauthenticated salt lookup that leaks whether an account exists, and departs from the RFC.
- **opaque-ke's built-in `argon2` feature.** It binds argon2 0.5 and falls back silently to weak defaults. Rejected in favour of our own KSF type.
- **Passkey-only login (WebAuthn PRF).** Post-1.0 (ROADMAP §4.3 Could). PRF support is incomplete on iOS for roaming authenticators (L).

## Open questions for the owner

1. **Invite-only signup as the default.** Accept it? *Recommendation:* yes. Open signup is an explicit admin opt-in with rate limits.
2. **Re-authentication window.** How long after re-authentication counts as "fresh" for sensitive actions (password change, export, rotation, revocation)? *Recommendation:* 5 minutes.

## References

- [CRYPTO.md §5 OPAQUE integration](../CRYPTO.md#5-opaque-integration), [§5.5 offline attack analysis](../CRYPTO.md#55-offline-attack-analysis), [§11.1 signup](../CRYPTO.md#111-signup-server-mode), [§11.2 login](../CRYPTO.md#112-login-on-a-new-device-server-mode)
- RFC 9807, The OPAQUE Augmented PAKE Protocol
- NCC Group public report on opaque-ke (2021)
- [ADR 0002](0002-own-protocol.md) (own protocol), [ADR 0004](0004-key-derivation-argon2id-secret-key.md), [ADR 0006](0006-key-hierarchy.md), [ADR 0009](0009-crypto-dependency-policy.md)
