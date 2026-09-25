# ADR 0004: Key derivation: Argon2id and the Secret Key

- Status: Accepted
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1

## Context

The master password is the only human-chosen secret. Two things set how hard it is to guess offline:

1. the cost of each guess, set by the KDF parameters;
2. whether the attacker even has something to guess against.

Known failures:
- **Server-supplied KDF parameters.** Bitwarden's client accepted PBKDF2 iteration counts as low as 5,000 from the server (Palant, 2023, L). The ETH Zurich analysis (ePrint 2026/058, L) lists KDF-parameter downgrade as its own attack class.
- **A full server compromise.** Under OPAQUE alone ([ADR 0003](0003-authentication-opaque.md)), someone holding the DB and the server's OPRF secrets can guess offline. For self-hosters that means a leaked backup.

1Password's Secret Key (2SKD) adds 128 random bits that live only on the user's devices and Emergency Kit. ROADMAP §4.3 lists it as "S, M1 decision, M3 ship".

Measured costs (fact sheet §5; single runs on a 2.8 GHz Xeon; argon2 0.6.0):

| Argon2id parameters | Native, 1 thread | wasm (Node 22) |
|---|---|---|
| 64 MiB, t3, p4 | 236 ms | 309 ms |
| 256 MiB, t3, p4 | 986 ms | 1467 ms |
| RFC 9807's 2 GiB profile | – | 16.6 s |

Constraints:
- iOS AutoFill extensions are capped at about 120 MB (L).
- There are no reliable low-end phone numbers (U).

## Decision

1. **Algorithm.** Argon2id v0x13 (RFC 9106), from `argon2` 0.6.0 with `default-features = false` and the `zeroize` feature only (not `alloc`; see [CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)).
2. **Parameter table, compiled into `rizzy-core`.** The server only ever names a `kdf_id`.

   | `kdf_id` | Parameters | Status |
   |---|---|---|
   | 1 | m = 64 MiB, t = 3, p = 4 (RFC 9106's second recommendation) | M1 default **and floor** |
   | 2 | 256 MiB, t3, p4 | Reserved, not enabled |

   A CI-checked unit test asserts that every enabled entry has m ≥ 64 MiB, t ≥ 3 and p = 4.
3. **Client-enforced.**
   - An unknown `kdf_id` is a hard error.
   - No code path builds parameters from numbers the server supplies.
   - `kdf_id` is bound into the OPAQUE Context and into the local-wrap AAD, and it is signed in the account state.
4. **Where Argon2id runs, with which salt:**
   - as the OPAQUE KSF, with a 16-byte zero salt per RFC 9807;
   - for the device-local wrap, with a random 16-byte `device_salt`;
   - for encrypted exports, with a random 16-byte salt;
   - for share passphrases, with the `share_id` as salt.

   ROADMAP §4.3 asks for "Argon2id with per-account salt". On the server path that salt is the per-account OPRF key, which RFC 9807 treats as a secret salt; the Argon2id salt itself is zero. Locally the salt is per device, which is stronger than per account. This deviates from the ROADMAP wording, not its intent (open question 4).
5. **Memory wiping.** We call `hash_password_into_with_memory` with a `Zeroizing` block buffer that we own. argon2 0.6.0's `hash_password_into` frees its 64 MiB block matrix without wiping it (verified in its source). Without the `alloc` feature that function does not exist in our build.
6. **Secret Key: yes, mandatory for every account, derivation in M1.**
   - 128 bits from the CSPRNG, generated on the client.
   - Shown as `RV1-` plus 28 Crockford Base32 characters: 26 for the data and 2 check characters for typo detection.
   - Mixed in as `pw_in = HKDF-SHA-256(ikm = NFC(password), salt = SK, info = "rizzy-vault/v1/opaque/password" ‖ 0x00)`.
   - `pw_in` feeds both OPAQUE and the local Argon2id.
   - Changing the SK runs a standard key rotation by default, because a new SK is usually issued when the Emergency Kit was exposed ([CRYPTO.md §11.5](../CRYPTO.md#115-master-password-or-secret-key-change)).
7. **Normalisation.** Passwords are normalised to Unicode NFC, with no trimming and no case folding.
8. **Upgrade path.** A future `kdf_id` is adopted at the next online password entry: OPAQUE is re-registered with the same password and the local wrap is redone. The server may *ask* for an upgrade but can never force a lower `kdf_id`.

The full constructions are in [CRYPTO.md §5.2](../CRYPTO.md#52-password-input-and-the-secret-key), [§6](../CRYPTO.md#6-kdf-parameters) and [§7](../CRYPTO.md#7-secret-key).

### Owner decisions (2026-09-25)

The owner answered the open questions on 2026-09-25:

1. **Secret Key mandatory from M1** → Yes. The Secret Key is mandatory for every account from M1: the derivation and the Emergency Kit ship in M1 ([CRYPTO.md §7](../CRYPTO.md#7-secret-key)), and only QR transfer and polish are left for M3. ROADMAP §4.3 is updated accordingly.
2. **Freeze `kdf_id` 1 after the M1 phone measurement, even at 1–2 s** → Yes. `kdf_id` 1 (m = 64 MiB, t = 3, p = 4) is kept even at 1–2 s on low-end phones. The M1 spike measures a full OPAQUE login (KSF plus local wrap) in the main-app process on the lowest-end target phones. If that runs out of memory, `kdf_id` 1 is changed before any M1 account exists, or a Server-mode enrolment path that approves a new phone from an existing device is specified first ([CRYPTO.md §6.4](../CRYPTO.md#64-feasibility)).
3. **Normalise master passwords to NFC** → Yes: NFC, no trimming, no case folding. Code points that are unassigned in the pinned Unicode tables are rejected in new master passwords, so a later table update cannot change `NFC(password)` ([CRYPTO.md §16](../CRYPTO.md#16-open-questions-for-the-owner) question 4).
4. **ROADMAP §4.3 row "Argon2id with per-account salt"** → Yes. The row now reads "Argon2id with a secret per-account salt (the OPAQUE OPRF key) on the server path and a per-device salt locally".

## Consequences

### Positive
- The server cannot weaken the KDF.
- With the Secret Key, a stolen DB plus `server_setup` gives an attacker nothing to guess against, and a harvested OPAQUE transcript is useless even to a future quantum attacker.
- Each unlock costs about 0.3 s in a desktop browser and about 0.25 s natively (single-threaded).

### Negative
- A new device or browser needs the Secret Key, typed from the Emergency Kit or transferred from another device. That is real friction.
- On an enrolled device the SK sits next to the local wrap, so 2SKD does not help against device theft. The mitigation is the OS keychain (M3/M7).
- 64 MiB is close to the iOS AutoFill limit. In M7 AutoFill must unlock through `E_ks`, a wrap of the account key under a random secret held in the keychain behind biometry, instead of running Argon2id ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory), [§6.4](../CRYPTO.md#64-feasibility)).

### Risks
- Low-end phones may take 1–2 s or more. This is not measured yet; an M1 spike must measure it before `kdf_id` 1 is frozen.
- Mixing the SK into OPAQUE's input with HKDF is our composition and an audit target for M8.
- Users will lose Emergency Kits. [ADR 0008](0008-account-recovery.md) covers what happens then.

## Alternatives considered

- **PBKDF2-HMAC-SHA256.** Not memory-hard. OWASP needs 600,000 iterations for it (V). This is Bitwarden's legacy path.
- **scrypt** (RFC 9807's configuration 3). Acceptable, but Argon2id is the RFC 9106 recommendation and has the better-maintained crate.
- **RFC 9807's Argon2id profile** (2 GiB, t=1, p=4). 16.6 s in wasm, and impossible on phones.
- **The OWASP minimum** (19 MiB, t2, p1; used by AliasVault). About 5× cheaper per guess than `kdf_id` 1, for no user-visible gain on desktop.
- **Server-supplied parameters with a client minimum** (Bitwarden-style). Rejected: numbers from the server are attack surface. A table of ids is not.
- **1Password-style XOR of two derived keys after the PAKE.** 2SKD works equally well when the secrets are mixed before the PAKE, and mixing before needs only one stretching step.
- **An optional Secret Key.** It doubles the code paths and the analysis, and optional security is the kind users turn off.
- **Shipping the Secret Key in M3** (the ROADMAP's current timing). Every M1 account would then need a forced migration, and until migrated those accounts are the weak ones.

## Open questions for the owner

None. All were answered by the owner on 2026-09-25; see [Owner decisions (2026-09-25)](#owner-decisions-2026-09-25) in the Decision section. The answers keep the original question numbers, so a reference to "open question N" means owner decision N.

## References

- [CRYPTO.md §5.2](../CRYPTO.md#52-password-input-and-the-secret-key), [§5.5](../CRYPTO.md#55-offline-attack-analysis), [§6](../CRYPTO.md#6-kdf-parameters), [§7](../CRYPTO.md#7-secret-key)
- RFC 9106 (Argon2); RFC 9807 §Configurations; the OWASP Password Storage Cheat Sheet
- W. Palant, "Bitwarden design flaw: Server side iterations" (2023)
- Scarlata et al., ePrint 2026/058
- The 1Password Security Design white paper (2SKD)
- [ADR 0003](0003-authentication-opaque.md), [ADR 0006](0006-key-hierarchy.md), [ADR 0008](0008-account-recovery.md)
