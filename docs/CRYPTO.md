# rizzy-vault cryptographic design

- Status: **Proposed** (M0). Nothing here is implemented yet. It becomes normative once the owner accepts ADRs [0003](adr/0003-authentication-opaque.md) to [0009](adr/0009-crypto-dependency-policy.md).
- Date: 2026-09-25
- Scope: every cryptographic construction in rizzy-vault from M1 to v1.0, plus the hooks that M9 (families) and M10 (business) need.
- Audience: the people implementing `rizzy-core`, and the external auditor in M8.

This document holds the full constructions. The ADRs record each decision and link back to the section that implements it. When this document and an ADR disagree, treat it as a bug and fix both in the same PR. Scope comes from [ROADMAP.md](ROADMAP.md) §4.1 and §4.3. Attackers and assets come from the threat model ([THREAT_MODEL.md](THREAT_MODEL.md)).

---

## 1. Goals, non-goals and rules

### Goals

1. **Zero knowledge against the server.** The server never sees a master password, a password-equivalent, the Secret Key, or any key that can decrypt vault data. This holds for vault items, public shares and stored mail. ROADMAP principle 1.
2. **A server breach alone yields nothing to brute-force.** Stealing the database, even together with the server's OPAQUE secrets, must not allow an offline guessing attack on the master password. The Secret Key ([§7](#7-secret-key)) is what makes this true.
3. **The server cannot rearrange data undetected.** It must not be able to swap items, move ciphertext between contexts, downgrade algorithms or KDF parameters, or substitute a user's own keys. Each of these is a named attack class against deployed password managers (Scarlata et al., 2026; see [§14](#14-what-a-malicious-server-can-still-do)).
4. **The org model exists from M1.** Per-user keypairs, per-vault keys and per-item keys ship in M1, so shared vaults in M9 need no re-encryption of existing vaults. ROADMAP principle 3.
5. **Everything is versioned.** Ciphertext, KDF parameters, signed statements and labels all carry a version, so a post-quantum migration does not break existing vaults. ROADMAP principle 4.
6. **One implementation.** All of this lives in `rizzy-core` and runs unchanged on native, wasm32 and UniFFI ([ADR 0013](adr/0013-shared-client-core.md)). No crypto is re-implemented in TypeScript, Kotlin or Swift.

### Non-goals

- **Protecting an unlocked client from malware** running as the same user. Once the vault is unlocked, a keylogger or memory scraper wins.
- **Hiding all metadata from the server.** The server sees account and device counts, item counts, padded sizes, timing, IP addresses, share metadata and mail metadata. [§14](#14-what-a-malicious-server-can-still-do) lists exactly what leaks.
- **Protecting the web vault from the server that serves it.** In Server mode the server delivers the web vault's JavaScript, so a malicious server can deliver a backdoored client. The browser extension, desktop app, mobile apps and CLI are the trust-minimised clients. [§14](#14-what-a-malicious-server-can-still-do) covers this.
- **Forward secrecy for stored data.** A vault is data at rest, and whoever holds the keys can read all of it, past and present.
- **Post-quantum security at v1.0.** v1.0 is PQ-*ready*: symmetric data is fine, and the formats reserve room for PQ algorithms ([§13](#13-post-quantum-readiness)).

### Rules

1. **No custom primitives.** We use standardised algorithms (RFC 9807, 9106, 9180, 8032, 7748, 5869, and XChaCha20-Poly1305 per draft-irtf-cfrg-xchacha), implemented by established crates, and we use them as their specifications intend.
2. **These compositions are ours, and every one is an M8 audit target.** Each combines standard primitives in a way no standard specifies:
   1. the key-committing envelope ([§8.3](#83-key-commitment)): Bellare–Hoang UtC with the AAD folded into the committing PRF (UtC + HtE), instantiated with HKDF-SHA-256;
   2. mixing the Secret Key into the OPAQUE password input with HKDF, and binding `kdf_id` and the server origin into the OPAQUE Context ([§5.2](#52-password-input-and-the-secret-key), [§5.3](#53-context-identifiers-and-credential-identifier));
   3. signed HPKE grants: HPKE (Base or PSK mode) plus an Ed25519 signature, with sender and recipient ids in the AAD, and the PSK derivations ([§10.1](#101-hpke-key-wrapping));
   4. the signed account state, device set and key-bundle chain, including the settings commitment and TOFU rules ([§10.2](#102-ed25519-signatures-and-signed-statements), [§10.3](#103-public-key-authenticity));
   5. device-key challenge signing for sessions ([§5.10](#510-sessions-after-authentication));
   6. lazy item-key rotation with an authenticated creation epoch ([§11.6](#116-key-rotation));
   7. device pairing: commit-then-reveal SAS followed by an HPKE-sealed transfer ([§11.7](#117-new-device-in-on-device-mode));
   8. the recovery token plus waiting period ([§11.9](#119-recovery-with-the-emergency-kit));
   9. the share link token, access token and passphrase scheme ([§11.10](#1110-public-share-link-creation-m5), [§11.11](#1111-public-share-link-opening-m5)).

   Nothing else may be invented. A new construction needs an ADR first, and joins this list. [ADR 0009](adr/0009-crypto-dependency-policy.md) sizes the audit scope from it.
3. **"Audited" is weaker than it sounds.** Almost none of the crate versions we will ship have been audited in that exact version ([§3](#3-primitives)). The rule we enforce is: standard algorithm, established crate with a public audit history or a well-reviewed codebase, pinned version, and our own external audit of the integration in M8 ([ADR 0009](adr/0009-crypto-dependency-policy.md)).
4. **No key is used directly as a cipher key.** Every use of a key passes through HKDF with a unique label, so one key never serves two algorithms or two purposes.
5. **The client decides; the server only names.** Algorithm choices and KDF parameters are compiled into `rizzy-core`. The server can only name a version from the client's allow-list, never supply a raw parameter.
6. **Fail closed.** An unknown version, an algorithm not on the allow-list, a bad signature or a failed commitment is a hard error. There is never a fallback to "try the legacy path".

---

## 2. Conventions

- Key words: **MUST**, **MUST NOT**, **SHOULD** and **MAY** as in RFC 2119.
- `‖` is byte concatenation.
- `u8`, `u16`, `u32` and `u64` are unsigned integers encoded **big-endian** at fixed width.
- `bytes(x)` is `u32(len(x)) ‖ x`. `str(x)` is `bytes(UTF-8(x))`.
- `id` values (account, device, vault, item, op, snapshot, attachment, share, message, pairing, transfer, export) are **16 random bytes** from the CSPRNG, created by the client that creates the object. They are opaque: we set no UUID version bits. The server rejects duplicates. Key ids are the exception: they are derived from the key ([§4.4](#44-identifiers-epochs-and-key-ids)).
- `HKDF(ikm, salt, info, L)` is HKDF-SHA-256 (RFC 5869), Extract then Expand, output `L` bytes. An empty salt means 32 zero bytes, as in RFC 5869.
- `LABEL(x)` is the ASCII string `"rizzy-vault/v1/" + x`.
- Every HKDF `info` in this document has the form `LABEL(x) ‖ 0x00 ‖ ctx`, where `ctx` may be empty. Labels never contain `0x00`, so the encoding is prefix-free.
- `SHA-256(x)` is FIPS 180-4 SHA-256.
- `Argon2id(P, S, kdf_id, T)` is Argon2id version 0x13 (RFC 9106), with password `P`, salt `S`, the cost parameters for `kdf_id` from [§6](#6-kdf-parameters), no secret value `K`, no associated data `X`, and a tag of `T` bytes.
- `NFC(s)` is Unicode Normalization Form C. We apply it to master passwords, export passwords and share passphrases before encoding them as UTF-8. There is no trimming and no case folding.
- **Login names.** `login_name` is the ASCII-lowercased input. After lowercasing it must be 1–254 bytes from `[a-z0-9._+@-]`; anything else is rejected at signup and at login, before any lookup. This one function is used for the account lookup, the uniqueness check, the fake credential id and the fake `kdf_id` ([§5.9](#59-account-enumeration)), so real and unknown names are always handled with the same string. Restricting to ASCII avoids a dependency on Unicode case-folding tables, which change between releases.
- **`server_origin`** is `scheme "://" host [":" port]`, with scheme and host ASCII-lowercased, no trailing slash, and the port omitted when it is the scheme's default. On the client it is the origin the client actually connected to (for the web vault, `location.origin`). On the server it is the configured canonical origin. A server reachable under several hostnames has exactly one canonical origin, and clients must use it.
- `ct_eq(a, b)` is a constant-time comparison using `subtle::ConstantTimeEq`.
- **Canonical encoding.** Anything that is signed or used as AAD uses the fixed binary layouts in this document, never a serde-derived encoding. A serde representation can change with a crate update; these layouts cannot.

---

## 3. Primitives

Versions are the latest stable releases as of 2026-09-25 (fact sheet). Audit status is what we could verify: **V** = verified from primary source, **L** = likely (secondary sources only), **U** = unverified.

| Purpose | Algorithm | Crate (features) | Version | Audit status |
|---|---|---|---|---|
| Login / PAKE | OPAQUE, RFC 9807. OPRF ristretto255-SHA512, 3DH over ristretto255 with SHA-512 | `opaque-ke` (`default-features = false`, `ristretto255`; **not** `argon2`, **not** `std`) | =4.0.1 | NCC Group, 2021 (sponsored by WhatsApp): reviewed v0.5.0, fixes landed in v1.2.0. **4.x is not audited** (V) |
| OPAQUE internals | ristretto255 group, VOPRF, SHA-512 | `curve25519-dalek` 4.x, `voprf` 0.5 and `rand` 0.8 (no default features) are transitive. `sha2` 0.10 is a **direct, renamed** dependency (`sha2_010`), because the ciphersuite names `Sha512` and opaque-ke 4.0.1 does not re-export sha2 (it re-exports only `rand` and `generic_array`, V). All previous RustCrypto generation | `sha2_010` =0.10.9; the rest lockfile-pinned (rand 0.8.8); curve25519-dalek ≥ 4.1.3 (RUSTSEC-2024-0344) | Quarkslab reviewed curve25519-dalek in 2019 (L). voprf: U |
| Password KDF, and the OPAQUE KSF | Argon2id v0x13, RFC 9106 | `argon2` (`default-features = false`, `alloc`, `zeroize`) | 0.6.0 | No audit found (U) |
| Symmetric AEAD | XChaCha20-Poly1305 | `chacha20poly1305` (`default-features = false`, `alloc`, `zeroize`) | 0.11.0 | NCC Group, 2020: "no significant findings", but on a much older version (V) |
| KDF, MAC, commitment | HKDF-SHA-256, HMAC-SHA-256 | `hkdf`, `hmac`, `sha2` | 0.13.0 / 0.13.0 / 0.11.0 | No audit found (U) |
| Hash (key ids, fingerprints, token hashes) | SHA-256 | `sha2` | 0.11.0 | No audit found (U). RUSTSEC-2021-0100 was fixed long ago (V) |
| Public-key wrapping | HPKE, RFC 9180, Base and PSK modes: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 | `hpke` (`default-features = false`, `alloc`, `x25519`, `chacha`) | 0.14.1 | "Nobody has performed a paid audit". Cloudflare reviewed v0.8 internally (V) |
| X25519 (inside HPKE) | X25519, RFC 7748 | `x25519-dalek` (transitive via `hpke`) | 3.0.0 | Quarkslab 2019, light review of a much older major (L). 3.0.0 was released 2026-07-06 |
| Signatures | Ed25519, RFC 8032, verified with `verify_strict` | `ed25519-dalek` (`default-features = false`, `fast`, `zeroize`) | 3.0.0 | Quarkslab 2019 on an older major (L). 3.0.0 is a new major, released 2026-07-06 |
| Constant-time helpers | – | `subtle` | 2.6.1 | Quarkslab 2019 (L) |
| Secret wiping | – | `zeroize`, `secrecy` | 1.9.0 / 0.10.3 | – |
| RNG traits | – | `rand_core` 0.10.1. The adapter for opaque-ke implements rand_core 0.6.4's traits through opaque-ke's `rand` re-export, with no separate dependency ([§5.1](#51-ciphersuite-and-key-stretching)) | 0.10.1 | – |
| OS randomness | getrandom(2), BCryptGenRandom, SecRandomCopyBytes, `crypto.getRandomValues` | `getrandom`, **leaf crates only** (`wasm_js` only in the wasm bindings crate) | 0.4.3 | – |
| Text normalisation | Unicode NFC | `unicode-normalization` | 0.1.25 (resolved in the M0 scratch build; not in the fact sheet) | U. It sits on the password path: a Unicode-table update can change `NFC(password)` for code points that were unassigned before, so it is exact-pinned and bumps are reviewed like crypto ([ADR 0009](adr/0009-crypto-dependency-policy.md)) |
| Constant-time base64 (share fragment) | RFC 4648 §5 base64url | `base64ct` | 1.8.3 (resolved in the M0 scratch build; not in the fact sheet) | U |
| *Reserved, not shipped* | ML-KEM-768 (FIPS 203), X-Wing | `ml-kem`, `x-wing` | 0.3.2 / 0.1.0 | Never audited (V). X-Wing is still an Internet-Draft (draft-10) |

**The honest summary.** The *algorithms* are standard and heavily analysed. The *implementations* come from the two dominant Rust families, RustCrypto and dalek, plus the reference Rust OPAQUE and HPKE crates. The specific versions we will ship have **not** been audited. This is why [ADR 0009](adr/0009-crypto-dependency-policy.md) pins exact versions, and why the M8 external audit must cover these crates' use in our code, not only our code.

**Rejected at the primitive level:**
- **AES-GCM** with random nonces for long-lived keys: NIST SP 800-38D caps random 96-bit IVs at 2^32 messages per key. Its advisory history is also relevant (RUSTSEC-2023-0096).
- **AES-256-GCM-SIV**: the `aes-gcm-siv` crate itself was never audited, and it is not key-committing either (algorithm id reserved, [§9.4](#94-algorithm-registry)).
- **RSA of any kind**: `rsa` 0.9 carries RUSTSEC-2023-0071 (Marvin) with no fix.
- **PBKDF2**, **SRP** (`srp` 0.6.0 is four years old), **BLAKE3** (one hash family is enough; SHA-2 is required by HKDF and OPAQUE anyway).

---

## 4. Key hierarchy

### 4.1 Diagram

```
 master password ──NFC──┐
                        ├── HKDF "opaque/password" ──► pw_in (32 B)
 Secret Key (128 bit) ──┘  (SK is the HKDF salt)          │
                                                          │
          ┌───────────────────────────────────────────────┴──────────────────────────┐
          │ SERVER PATH (new device, web vault, re-auth)          DEVICE PATH (every unlock on an enrolled device)
          ▼                                                                          ▼
  OPAQUE (RFC 9807) with the server                              Argon2id(pw_in, device_salt, kdf_id, 32)
  OPRF ristretto255 → KSF = Argon2id(kdf_id)                                         │
          │ export_key (64 B)                                    HKDF "unlock-key/local"
  HKDF "unlock-key/server"                                                           │
          │ server_unlock_key (32 B)                                 local_unlock_key (32 B)
          │                                                                          │
          └──────── wraps ───────►  ACCOUNT KEY (32 B, random)  ◄─────── wraps ───────┘
                                          ▲  ▲   ▲
               recovery code (128 bit) ───┘  │   └── HPKE PSK-mode grant to each device's X25519 key (after rotation)
               HKDF "recovery/wrap-key"      └────── keystore unlock secret (M3/M7, random, OS keystore): E_ks
                                          │
  ┌──────────────────┬──────────────────┬─┴───────────────┬───────────────────┬────────────────────┐
  │ wraps            │ wraps (self-grant)│ HKDF            │ wraps             │ wraps              │ HKDF
  ▼                  ▼                   ▼                 ▼                   ▼                    ▼
 identity keys     VAULT KEYS          relay key         device secret keys  mail secret key (M6)  local index key (M3)
 Ed25519 (sign)    32 B random,        (On-device mode,  Ed25519 + X25519,   X25519, HPKE          per device
 X25519  (HPKE)    one per vault       per key epoch)    one pair per device recipient key
  │                  │ wraps
  │ public halves    ▼
  │ in a signed     ITEM KEYS (32 B random, one per item; wrap records the creation epoch)
  │ key bundle       │ encrypts                     │ wraps
  ▼                  ▼                              ▼
 M9: vault keys    op payloads, item snapshots    ATTACHMENT KEYS (M3, 32 B random, one per attachment)
 granted to other                                   │ encrypts
 members via HPKE                                   ▼
                                                  attachment chunks

 share secret (32 B random, one per share)   ── lives only in the URL fragment and in the owner's vault ──► share key, link token, access token
 mail message    ── HPKE-sealed at ingress to the recipient's mail X25519 key ──► stored ciphertext
```

### 4.2 Key inventory

| Key | Size | Origin | Stored where, wrapped by | Rotated when |
|---|---|---|---|---|
| Master password | – | User | User's head. Never stored | User changes it ([§11.5](#115-master-password-or-secret-key-change)) |
| Secret Key (SK) | 16 B | CSPRNG at signup | Emergency Kit; each enrolled device's state file (plaintext until an OS keychain is used, M3/M7); optionally the web vault's IndexedDB | User regenerates it (same flow as a password change) |
| `pw_in` | 32 B | HKDF(password, SK) | Never stored | – |
| `export_key` | 64 B | OPAQUE output | Never stored | Each new OPAQUE registration |
| `server_unlock_key` | 32 B | HKDF(export_key) | Never stored | Each new OPAQUE registration |
| `device_salt` | 16 B | CSPRNG per device | Device state file | Each local re-wrap after a password change |
| `local_unlock_key` | 32 B | Argon2id + HKDF | Never stored | Password change |
| **Account key** | 32 B | CSPRNG at signup | Server: `E_srv` (under server_unlock_key). Device: `E_local` (under local_unlock_key), and optionally `E_ks` (under the keystore unlock secret). Server or backup: `E_rec` (under the recovery wrap key) | Device revocation, recovery, SK change, suspected compromise, user request ([§11.6](#116-key-rotation)) |
| Keystore unlock secret (M3/M7) | 32 B | CSPRNG per device | The OS keystore of that device, released only after an OS-enforced user-presence check (threat model INV-62). It opens `E_ks` and nothing else. This is the "local unlock secret" of [ADR 0013](adr/0013-shared-client-core.md) and [ADR 0015](adr/0015-desktop-tauri.md) | On biometric-enrolment change, re-enrolment, or when the user turns keystore unlock off (then `E_ks` is deleted) |
| Identity signing key | Ed25519, 32 B seed | CSPRNG | `E_id` under the account key | Full rotation only |
| Identity KEM key | X25519, 32 B | CSPRNG (`hpke` `gen_keypair_with_rng`) | `E_id` under the account key | Full rotation only |
| **Vault key** | 32 B | CSPRNG per vault | Self-grant under the account key; M9: HPKE grant per member | Account-key rotation, member removal (M9) |
| **Item key** | 32 B | CSPRNG per item | `ITEM_KEY_WRAP` under the vault key; the wrap also records the vault-key epoch the item key was created in ([§8.4](#84-aad-and-purposes)) | Lazily, on the first write after a vault-key rotation ([§11.6](#116-key-rotation)); on moving to another vault |
| Attachment key (M3) | 32 B | CSPRNG per attachment | `ATTACHMENT_KEY_WRAP` under the item key | Never; a changed attachment is a new attachment with a new key |
| Device signing key | Ed25519 | CSPRNG per device | `E_dev` under the account key, **on that device only; never uploaded** | Device re-enrolment |
| Device KEM key | X25519 | CSPRNG per device (`hpke` `gen_keypair_with_rng`) | Same | Same |
| Relay key | 32 B | HKDF(account key, epoch) | Never stored; derived on demand | With the account key |
| Mail secret key (M6) | X25519 | CSPRNG | `MAIL_SECRET_KEY` under the account key | User request, full rotation (`mail_key_epoch + 1`) |
| Recovery code | 16 B | CSPRNG | Emergency Kit only | On every use, and on every account-key rotation unless the user re-types the current code |
| Share secret (M5) | 32 B | CSPRNG per share | URL fragment; the owner's item data (encrypted) | Never. A share is a snapshot; revoke it and create a new one |
| Local index key (M3) | 32 B | HKDF(account key, device) | Never stored | With the account key |

**Where each wrapped-key object lives, by sync mode.** This table is authoritative; [ADR 0011](adr/0011-storage.md) and [ADR 0012](adr/0012-sync-engine.md) follow it.

| Object | Server mode | On-device mode |
|---|---|---|
| `E_srv`, `E_rec`, `H_rec` | Server, `auth` domain | **Not stored** (INV-28). The recovery wrap lives in the M4 backup file ([§11.9](#119-recovery-with-the-emergency-kit)) |
| `E_local`, `E_ks`, `E_dev` | That device only. **Never uploaded**; the API has no field that could carry them | Same |
| `E_id`, `MAIL_SECRET_KEY`, `RETIRED_SECRET_KEY`, `ACCOUNT_SETTINGS` | Server, `auth` domain; devices cache them | Same. They are encrypted under the random account key, so storing them gives nothing to brute-force (INV-28 holds) and reveals nothing the server does not already know |
| Key bundles, `account-state`, device certificates and revocations | Server, `auth` domain | Same |
| `ACCOUNT_KEY_DEVICE_GRANT`, `PASSWORD_VERIFIER_GRANT` | Server, `auth` domain, until the recipient device consumes it | Same |
| `VAULT_KEY_SELF_GRANT` | Server, `vault` domain | **Devices only.** They travel as key records inside `RELAY_BATCH` ([§11.12](#1112-relay-ops-on-device-mode-m4)) and in the pairing transfer ([§11.7](#117-new-device-in-on-device-mode)). On the server they would reveal vault ids, which On-device mode hides ([ADR 0012](adr/0012-sync-engine.md) §11) |
| `ITEM_KEY_WRAP` | Server, `vault` domain: one row per `(vault_id, item_id, item_key_id, vault_key_epoch)`, whether it arrived inside an op record or in a rotation upload | **Devices only.** They travel inside op records, as key records in `RELAY_BATCH`, and in the pairing transfer. On the server they would reveal item ids |
| `ATTACHMENT_KEY_WRAP` (M3) | With the attachment; the M3 attachments ADR decides | Same |

Wrapped-key objects travel with a cleartext locator (ids, epochs and, for `ITEM_KEY_WRAP`, the item key's id) so that the server and the relay can file them. The locator is never trusted: the reader rebuilds the AAD context from where it expected the object, and checks the unwrapped key's derived id against the envelope that uses it.

### 4.3 Derivations

All HKDF is HKDF-SHA-256. The output length is in bytes.

| Output | Construction | L |
|---|---|---|
| `pw_in` | `HKDF(ikm = UTF-8(NFC(password)), salt = SK, info = LABEL("opaque/password") ‖ 0x00, L)` | 32 |
| OPAQUE context | `LABEL("opaque/context") ‖ 0x00 ‖ u16(suite_id = 1) ‖ u16(kdf_id) ‖ str(server_origin)` ([§2](#2-conventions), [§5.3](#53-context-identifiers-and-credential-identifier)) | – |
| Fake credential id | `SHA-256(LABEL("opaque/fake-credential-id") ‖ 0x00 ‖ str(login_name))[0..16]`, `login_name` as in [§2](#2-conventions) | 16 |
| Fake `kdf_id` selector | `u64(HMAC-SHA-256(key = enum_key, msg = LABEL("opaque/fake-kdf") ‖ 0x00 ‖ str(login_name))[0..8])`. `enum_key` is 32 random bytes in the server secrets file ([§5.9](#59-account-enumeration)) | – |
| Symmetric key id | `HKDF(ikm = K, salt = empty, info = LABEL("key-id/symmetric") ‖ 0x00, L)`, for **every** symmetric key, generated or derived ([§4.4](#44-identifiers-epochs-and-key-ids)) | 16 |
| `server_unlock_key` | `HKDF(ikm = export_key, salt = empty, info = LABEL("unlock-key/server") ‖ 0x00 ‖ account_id, L)` | 32 |
| `local_unlock_key` | `a = Argon2id(P = pw_in, S = device_salt, kdf_id, T = 32)`, then `HKDF(ikm = a, salt = empty, info = LABEL("unlock-key/local") ‖ 0x00 ‖ account_id ‖ device_id, L)` | 32 |
| Envelope subkey and commitment | `okm = HKDF(ikm = K, salt = nonce, info = LABEL("envelope/xchacha20poly1305") ‖ 0x00 ‖ aad, 64)`. `k_enc = okm[0..32]`, `commitment = okm[32..64]` ([§8.3](#83-key-commitment)) | 64 |
| Relay key | `HKDF(ikm = account_key, salt = empty, info = LABEL("relay-key") ‖ 0x00 ‖ account_id ‖ u32(account_key_epoch), L)` | 32 |
| Local index key (M3) | `HKDF(ikm = account_key, salt = empty, info = LABEL("local-index-key") ‖ 0x00 ‖ account_id ‖ device_id, L)` | 32 |
| Recovery wrap key | `HKDF(ikm = recovery_code, salt = empty, info = LABEL("recovery/wrap-key") ‖ 0x00, L)` | 32 |
| Recovery auth token | `HKDF(ikm = recovery_code, salt = empty, info = LABEL("recovery/auth-token") ‖ 0x00, L)`. The server stores `SHA-256(token)` | 32 |
| Share passphrase key (M5) | `Argon2id(P = UTF-8(NFC(passphrase)), S = share_id, kdf_id = 1, T = 32)` | 32 |
| Share key (M5) | `HKDF(ikm = share_secret [‖ pp_key], salt = share_id, info = LABEL("share/key") ‖ 0x00, L)` | 32 |
| Share link token (M5) | `HKDF(ikm = share_secret, salt = share_id, info = LABEL("share/link-token") ‖ 0x00, L)`. Proves possession of the URL fragment. The server stores `SHA-256(token)` | 32 |
| Share access token (M5) | `HKDF(ikm = share_secret [‖ pp_key], salt = share_id, info = LABEL("share/access-token") ‖ 0x00, L)`. The server stores `SHA-256(token)` | 32 |
| Export file key | `e = Argon2id(P = UTF-8(NFC(export_password)), S = export_salt (16 B random), kdf_id, T = 32)`, then `HKDF(ikm = e, salt = empty, info = LABEL("export/key") ‖ 0x00 ‖ export_id, L)` | 32 |
| Device-grant PSK | `HKDF(ikm = previous account key, salt = empty, info = LABEL("hpke-psk/device-grant") ‖ 0x00 ‖ account_id ‖ u32(new account_key_epoch) ‖ recipient device_id, L)`. `psk_id = LABEL("hpke-psk/device-grant")` ([§10.1](#101-hpke-key-wrapping)) | 32 |
| Password-verifier PSK (M4) | `HKDF(ikm = account key, salt = empty, info = LABEL("hpke-psk/password-verifier") ‖ 0x00 ‖ account_id ‖ u32(new password_epoch) ‖ recipient device_id, L)`. `psk_id = LABEL("hpke-psk/password-verifier")` | 32 |
| Re-sync PSK (M4) | `HKDF(ikm = account key, salt = empty, info = LABEL("hpke-psk/resync") ‖ 0x00 ‖ account_id ‖ u32(account_key_epoch) ‖ transfer_id ‖ recipient device_id, L)`. `psk_id = LABEL("hpke-psk/resync")` | 32 |
| Pairing key (M4, QR path) | `HKDF(ikm = pairing_secret (32 B), salt = pairing_id, info = LABEL("pairing/key") ‖ 0x00, L)` | 32 |
| Pairing commitment (M4) | `SHA-256(LABEL("pairing/commit") ‖ 0x00 ‖ pairing_id ‖ new-device Ed25519 pk ‖ new-device X25519 pk ‖ r_N)`, where `r_N` is 16 random bytes from the new device ([§11.7](#117-new-device-in-on-device-mode)) | 32 |
| Pairing SAS (M4) | `u32(HKDF(ikm = k_pair, salt = empty, info = LABEL("pairing/sas") ‖ 0x00 ‖ pairing_id ‖ new-device Ed25519 pk ‖ new-device X25519 pk ‖ r_N ‖ r_E, 4)) mod 10^6`, shown as 6 digits. `r_E` is 16 random bytes from the existing device, sent after it received the commitment and before `r_N` is revealed | – |
| Pairing transfer PSK (M4) | `psk = k_pair`, `psk_id = LABEL("hpke-psk/pairing")` | 32 |
| Public key id | `SHA-256(LABEL("key-id") ‖ 0x00 ‖ u8(key_type) ‖ public_key)[0..16]` | 16 |
| Account fingerprint | `SHA-256(LABEL("fingerprint") ‖ 0x00 ‖ account_id ‖ identity_ed25519_pk ‖ identity_x25519_pk)` | 32 |
| Device set hash | `SHA-256(LABEL("device-set") ‖ 0x00 ‖ sorted SHA-256 of each non-revoked device certificate message with device_kind ≠ 4)` ([§10.2](#102-ed25519-signatures-and-signed-statements)) | 32 |
| Settings hash | `SHA-256(ACCOUNT_SETTINGS envelope bytes)`; 32 zero bytes while `settings_seq = 0` | 32 |
| SK check characters | top 10 bits of `SHA-256(LABEL("secret-key/check") ‖ 0x00 ‖ SK)` | – |
| Recovery code check characters | top 10 bits of `SHA-256(LABEL("recovery-code/check") ‖ 0x00 ‖ recovery_code)` | – |

Signature messages use `LABEL("sig/<type>")`; see [§10.2](#102-ed25519-signatures-and-signed-statements). HPKE uses `LABEL("hpke")`; see [§10.1](#101-hpke-key-wrapping).

**Label registry rule.** A label is defined in exactly one place: the `labels` module of `rizzy-core`. A unit test asserts that the list is unique and contains no `0x00` byte. Adding a label means amending this table.

### 4.4 Identifiers, epochs and key ids

- **Symmetric keys.** Every symmetric key K has `key_id = HKDF(K, "key-id/symmetric")[0..16]` ([§4.3](#43-derivations)). One rule covers generated keys (account, vault, item, attachment keys, the keystore unlock secret) and derived keys (`server_unlock_key`, `local_unlock_key`, the recovery wrap key, the relay key, the share key, the export file key, `k_pair`, the local index key). Nothing stores a key id separately; the reader derives the expected id from each key it holds and compares ([§9.5](#95-parsing-and-allow-list-rules)).
  - The key id goes in the envelope header so the reader can find the key.
  - For a password-derived key the key id is a guess verifier, but so is the envelope commitment next to it, and both cost one full Argon2id per guess behind a random per-object salt (`device_salt`, `export_salt`) or a secret one (the OPRF key). The key id adds no cheaper oracle. What must never happen is a key id computed from the password or `pw_in` before stretching.
- **Public keys** have a derived key id ([§4.3](#43-derivations)). `key_type` values:
  - `0x01`: identity Ed25519
  - `0x02`: identity X25519 (HPKE `0x10`)
  - `0x03`: mail X25519
  - `0x04`: device Ed25519
  - `0x05`: device X25519
  - `0x10`–`0x1F`: reserved for PQ keys ([§13](#13-post-quantum-readiness))
- **Epochs** are `u32` counters. Each one increments by exactly 1 when its key rotates:

  | Epoch | Initial value | Notes |
  |---|---|---|
  | `account_key_epoch` | 0 at signup | |
  | `identity_epoch` | 0 at signup | |
  | `password_epoch` | 0 at signup | Also bumped when the SK changes |
  | `recovery_epoch` | 1 at signup if a recovery code is issued, else 0 | 0 means "no recovery code has ever been issued". `recovery_enabled` in `account-state` says whether a code is valid now |
  | `mail_key_epoch` (M6) | 0 | 0 means "no mail key yet"; the first mail key is epoch 1 |
  | `vault_key_epoch` | 0 when the vault is created | One counter per vault |

  Epochs appear in AAD and in the signed `account-state`, so ciphertext from an older epoch cannot be passed off as current.
- **Item-key creation epoch.** Each `ITEM_KEY_WRAP` plaintext records the `vault_key_epoch` at which that item key was generated. Re-wrapping never changes it. Writers use it to detect a stale item key ([§11.6](#116-key-rotation)).
- **Sequence numbers** are `u64` and only increase. Each device persists the highest value it has accepted and rejects anything lower:
  - `state_seq`: 1 at signup, +1 on every change to the signed account state ([§10.2](#102-ed25519-signatures-and-signed-statements)).
  - `settings_seq`: 0 while no `ACCOUNT_SETTINGS` exists, +1 on every settings change. Committed in `account-state`.
  - `bundle_seq`: 1 for the first key bundle, +1 on every new bundle, whether or not the identity keys change.

---

## 5. OPAQUE integration

### 5.1 Ciphersuite and key stretching

```rust
// rizzy-core, sketch — not final code
struct RizzySuiteV1;
impl opaque_ke::CipherSuite for RizzySuiteV1 {
    type OprfCs = opaque_ke::Ristretto255;
    // sha2_010 = { package = "sha2", version = "=0.10.9" }: opaque-ke 4.0.1 is on digest 0.10
    // and does not re-export sha2, so rizzy-core depends on it directly (ADR 0009).
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_010::Sha512>;
    type Ksf = RizzyArgon2idKsf;
}
```

- **Suite.** This is RFC 9807's first recommended configuration: ristretto255-SHA512 OPRF, HKDF-SHA-512, HMAC-SHA-512, 3DH over ristretto255. We give it `suite_id = 1`.
- **KSF.** `RizzyArgon2idKsf { kdf_id: u16 }` implements `opaque_ke::ksf::Ksf` using **argon2 0.6**:
  - It calls `Argon2id(P = oprf_output, S = 16 zero bytes, kdf_id, T = 64)`. The all-zero salt is what RFC 9807 specifies and what opaque-ke's own Argon2 KSF does. The OPRF key already acts as a secret per-user salt, so a zero salt costs nothing.
  - We use our own KSF type rather than opaque-ke's `argon2` feature for three reasons:
    1. opaque-ke's feature binds argon2 **0.5** and its parameters.
    2. If `ksf: None` is passed, opaque-ke silently falls back to `CS::Ksf::default()`, which for `argon2::Argon2` is 19 MiB, t=2, p=1. Our `Default` impl returns `kdf_id = 1`, so even a forgotten `Some(..)` fails safe.
    3. We control memory wiping ([§12.2](#122-memory-hygiene)).
- **Always pass the KSF.** All opaque-ke calls go through one wrapper module in `rizzy-core`, which always passes `ksf: Some(&RizzyArgon2idKsf::new(kdf_id))`. Calling opaque-ke's `finish` functions from anywhere else is a review blocker, and a unit test covers the wrapper. `kdf_id` must come from the client's allow-list ([§6](#6-kdf-parameters)).
- **Crate features.** No `argon2` feature and no `std` feature on opaque-ke. `std` pulls in `getrandom`, and `rizzy-core` must not touch randomness sources itself.
- **RNG adapter.** opaque-ke needs a rand_core **0.6** `CryptoRng + RngCore`. `rizzy-core` provides a ~20-line adapter that implements `opaque_ke::rand::{RngCore, CryptoRng}` (opaque-ke re-exports `rand` 0.8, which re-exports rand_core 0.6) and forwards `fill_bytes` to the injected rand_core 0.10 `CryptoRng`. So there is no separate rand_core 0.6 dependency. The adapter contains no crypto.
- **`rand` 0.8 in the tree.** opaque-ke 4.0.1 depends on `rand` 0.8 with `default-features = false`; it resolves to 0.8.8 and pulls only rand_core 0.6.4, with no `thread_rng` and no getrandom (V, M0 scratch build). `rizzy-core` never calls it. [ADR 0009](adr/0009-crypto-dependency-policy.md) allow-lists exactly this transitive edge.

### 5.2 Password input and the Secret Key

The OPAQUE "password" is `pw_in = HKDF(ikm = UTF-8(NFC(password)), salt = SK, info = LABEL("opaque/password") ‖ 0x00, 32)`. The extract step is `HMAC-SHA-256(key = SK, msg = password)`, a PRF of the password keyed by a 128-bit secret.

Why the SK goes into the OPAQUE input and not only into the vault key:
- RFC 9807 is explicit that a server holding its own OPRF seed can run an offline dictionary attack against any record.
- If the SK only protected the vault key, someone who stole the database together with the `oprf_seed` could still guess passwords against the OPAQUE envelope. A correct guess would give them a working login, the account-key wrap and the recovery surface.
- With the SK inside `pw_in`, every guess also needs the 128-bit SK. [§5.5](#55-offline-attack-analysis) shows the analysis.

This is 1Password's two-secret key derivation (2SKD) moved in front of the PAKE. 1Password XORs two derived keys *after* PBKDF2 and SRP-x; we mix the secrets *before* the PAKE. Either way both secrets are required. Ours needs one stretching step instead of two. This composition is audit target 2.

### 5.3 Context, identifiers and credential identifier

- **Context.** `ctx = LABEL("opaque/context") ‖ 0x00 ‖ u16(suite_id) ‖ u16(kdf_id) ‖ str(server_origin)`. It is passed on both sides: `ClientLoginFinishParameters.context` and `ServerLoginParameters.context`. RFC 9807 says the context SHOULD include the configuration needed to prevent cross-protocol and downgrade attacks.
  - If the server lies about `kdf_id`, the client stretches with different parameters and gets a different `randomized_password`, so the login fails.
  - The server can only name `kdf_id` values that are on the client's allow-list, so the worst a lie achieves is denial of service.
  - **`server_origin`** ([§2](#2-conventions)) stops a relay phish. Without it, a native client pointed at `https://evil.example` could have that server relay KE1, KE2 and KE3 unchanged to the real server. OPAQUE would succeed, because the default server identity is the real server's public key, and the real server would issue its session token over the phisher's connection. With the origin in the Context, the client's KE2 check fails before it sends KE3. [§5.10](#510-sessions-after-authentication) binds the origin into device authentication for the same reason.
  - The Context enters only the AKE transcript, not the OPAQUE envelope. Changing the server's canonical origin therefore needs no re-registration; clients just have to dial the new origin.
  - A Context mismatch fails exactly like a wrong password. So the server returns its canonical origin next to KE2, and a client that dialled a different origin reports "this is not the server's configured address" before running the KSF. That value is unauthenticated and only drives the error message; the Context check is the control.
- **Identifiers.** Both left as defaults (`Identifiers { client: None, server: None }`), so RFC 9807 uses the public keys. The login name is deliberately *not* bound: renaming an account must not require re-registration.
- **`credential_identifier`.** This is the `account_id` (16 bytes) for real accounts. For unknown login names it is the fake credential id from [§4.3](#43-derivations) ([§5.9](#59-account-enumeration)).

### 5.4 Where the unlock key comes from

**Decision: both, on different paths.**

- **Server path.** Used for a new device, the web vault, re-authentication and password change. The key that wraps the account key *on the server* (`E_srv`) is derived from OPAQUE's `export_key`. Using `export_key` for client-only data is exactly what RFC 9807 intends it for.
- **Device path.** Used for every unlock on an enrolled device, online or offline. The key that wraps the account key *on that device* (`E_local`) comes from a local `Argon2id(pw_in, device_salt)`. `E_local` never leaves the device.

**Each unlock runs Argon2id exactly once.**
- On the server path, the single run is OPAQUE's KSF.
- On the device path, the single run is the local derivation. An enrolled device then authenticates to the server with its device key ([§5.10](#510-sessions-after-authentication)), not with OPAQUE, so the password is stretched only once.
- There is one exception: the first login on a new device runs OPAQUE and then one extra local Argon2id to create `E_local`. The same happens once after each password change.

**Why not only export_key?** The device could not unlock offline, because OPAQUE needs the server's OPRF evaluation. Caching anything that lets the device skip the OPRF, such as the OPRF output, would put a password-equivalent on disk.

**Why not only a local Argon2id?** Suppose the server-side account-key wrap were keyed by `Argon2id(pw_in, salt)` instead of by `export_key`. Then the database alone would be an offline-guessing oracle, and OPAQUE's main property, "no offline attack without the OPRF key", would be thrown away. It would also mean two stretching runs per login.

**Why not stretch before OPAQUE** (Argon2id first, then OPAQUE with `Identity` KSF)? It would save the extra Argon2id at enrolment. But the salt would have to be known before login, which allows precomputation against a targeted user and needs an unauthenticated salt lookup that leaks whether an account exists. It also departs from RFC 9807's post-OPRF stretching. Rejected.

### 5.5 Offline attack analysis

Cost figures come from the M0 benchmark (fact sheet §5): `kdf_id` 1 (Argon2id, 64 MiB, t=3, p=4) takes 236 ms single-threaded natively on one 2.8 GHz Xeon vCPU. An attacker running four hashes in parallel on a 4-vCPU box therefore manages about **17 guesses/s per box**. That is a CPU figure; **GPU and ASIC rates were not measured**, and will be higher by a factor we have not quantified. For scale:
- A random 30-bit password falls in about 2 years on one box, or about 18 hours on 1,000 boxes.
- A random 40-bit password takes about 2,000 years on one box.

| Attacker obtains | Without SK (hypothetical) | With SK (this design) |
|---|---|---|
| Server DB only (no `server_setup`) | No offline attack. Every guess needs an online OPRF evaluation; rate-limited | Same |
| Server DB **and** `server_setup` (`oprf_seed`, AKE keys) | **Offline dictionary attack**: OPRF (cheap) + one Argon2id per guess against the envelope. Weak passwords fall | **None.** Each guess also needs the 128-bit SK |
| Server DB + `server_setup` + a CRQC (future) | Same as the row above | None. The SK is symmetric, and every stored HPKE object that carries an account key (pending device grants, password-verifier grants) is sealed in PSK mode with a PSK derived from an account key ([§10.1](#101-hpke-key-wrapping)), so breaking its X25519 is not enough |
| Emergency Kit + an **old** DB backup | – | The account key as of that backup, and with it everything written until the next account-key rotation. Recovery and SK changes rotate the account key by default ([§11.5](#115-master-password-or-secret-key-change), [§11.9](#119-recovery-with-the-emergency-kit)), so data written after them is out of reach |
| Recorded TLS + OPAQUE transcripts + a CRQC | A DLog on the OPRF exchange recovers the per-user OPRF key, then offline guessing (our analysis, U) | None (needs the SK) |
| An enrolled device's disk (state file: `E_local`, `device_salt`, SK) | Offline attack at one Argon2id per guess | **Same.** The SK sits next to `E_local`, so 2SKD does not help here. OS-keychain / Secure Enclave binding (M3/M7) is the mitigation |
| A backup of a device's disk | Same as the device | Same as the device |
| Emergency Kit only | Nothing without the server or a device | Kit + server access = full account via the recovery code, after a waiting period that any enrolled device can cancel ([§11.9](#119-recovery-with-the-emergency-kit)) |
| On-device mode, whole server | Nothing: no OPAQUE record, no `E_srv` and no `E_rec` are stored ([§5.7](#57-on-device-sync-mode)). Pending device and password-verifier grants are sealed to device keys with an account-key PSK, so they give nothing to guess against | Same |

**The conclusion:**
- Without the SK, the security of Server mode against a full server compromise (the database plus the secrets file, i.e. "the backup got leaked") rests entirely on master-password strength.
- With the SK it rests on 128 random bits.
- This is the main reason [§7](#7-secret-key) recommends the SK from M1.

### 5.6 Offline unlock

An enrolled device unlocks without contacting the server:
1. Read the device state: `account_id`, `device_id`, SK, `device_salt`, `kdf_id`, `E_local`, `E_dev`, the last verified signed account state, and the encrypted cache.
2. `pw_in` ← HKDF(password, SK). Compute `local_unlock_key` ([§4.3](#43-derivations)).
3. Open `E_local` (purpose `ACCOUNT_KEY_LOCAL_WRAP`) to get the account key. A wrong password shows up as a commitment or tag failure, reported as "wrong password". A keystore unlock (M3/M7) skips steps 2–3: the OS releases the keystore unlock secret after its user-presence check, and it opens `E_ks` (`ACCOUNT_KEY_KEYSTORE_WRAP`) instead.
4. Open `E_dev` to get the device keys. Read the cache and queue signed ops for later sync.

The `kdf_id` used locally comes from the device's own state, never from the server. A local attempt counter with increasing delay slows down a casual attacker at the keyboard; it does nothing against someone who has copied the disk. The UI must not claim otherwise.

### 5.7 On-device sync mode

In On-device mode (M4) the server stores **no OPAQUE record, no `E_srv` and no `E_rec`**.
- Devices authenticate only with device keys ([§5.10](#510-sessions-after-authentication)).
- New devices join by pairing with an existing device ([§11.7](#117-new-device-in-on-device-mode)).
- Recovery works from a local backup file ([§11.9](#119-recovery-with-the-emergency-kit)).

This makes ROADMAP §4.6's promise true: a server breach yields nothing to brute-force, even for an account without a strong password.

Switching modes:
- **Server → On-device.**
  1. The client first runs a standard key rotation ([§11.6](#116-key-rotation)): new account key and vault keys, with item keys rotating lazily on their next write. Whatever old wraps the server secretly keeps therefore cover nothing written after the switch (threat model INV-31).
  2. The server deletes the OPAQUE record, `E_srv`, `E_rec` and `H_rec`, the vault self-grants and item-key wraps, vault ciphertext and the op log, and returns a deletion receipt signed with its own key. [ADR 0012](adr/0012-sync-engine.md) §10 sets the switch point, and devices that were behind re-sync from a peer.
  3. Recovery moves to the local backup file, where the backup key is wrapped under the recovery wrap key ([§11.9](#119-recovery-with-the-emergency-kit)). The rotation in step 1 has already issued a new recovery code.

  The receipt is a promise, not a proof; the UI says so.
- **On-device → Server.** The client runs a fresh OPAQUE registration (the password is required), uploads `E_srv`, the vault-level key objects from [§4.2](#42-key-inventory) (self-grants, item-key wraps) and a full encrypted snapshot.
  - `E_rec` and `H_rec` need the recovery code, which no client stores; it exists only in the Emergency Kit. The user either types the current code, or the client issues a new one with `recovery_epoch + 1` and a new Emergency Kit, as in [§11.6](#116-key-rotation) step 5. Without either, the account runs in Server mode with `recovery_enabled = 0` until the user fixes it, and the UI says so.

### 5.8 Loss or rotation of the server OPAQUE secrets

`server_setup` is opaque-ke's `ServerSetup`: `oprf_seed`, the server's AKE keypair, and the fake keypair. The same secrets file also holds `enum_key` (32 random bytes, [§5.9](#59-account-enumeration)); losing or rotating `enum_key` only reshuffles which fake `kdf_id` unknown names get. Rules:
- It lives in its own file (mode 0600), outside the database, so a database dump or a database backup alone does not contain it.
- The database stores `SHA-256(server AKE public key)`. The server **refuses to start** if the database has OPAQUE records and the loaded setup does not match. This keeps a restore from silently generating a fresh seed.
- The admin backs it up once, separately from routine database backups. The file never changes unless rotated.

**Losing `server_setup`** makes every OPAQUE login fail, because the envelope no longer opens. Consequences:
- **Users with an enrolled device** still unlock locally and authenticate with device keys. When the admin marks the records invalid, the client re-registers OPAQUE the next time the user enters the password. It already holds the account key, so it just writes a new `E_srv`.
- **Users with only the web vault** go through recovery ([§11.9](#119-recovery-with-the-emergency-kit)). `E_rec` and the recovery token hash do not depend on `server_setup`.
- **Users with neither** have lost their data. The server still holds ciphertext, but nobody can open it.

**Rotating `server_setup`.** This is for a suspected leak only; with the SK, a leak alone is not an offline attack.
1. Add setup #2 and tag every record with its `setup_id`.
2. New registrations use #2.
3. A successful login against a #1 record triggers a transparent re-registration under #2. This costs one extra Argon2id, once.
4. After a grace period set by the admin, delete #1. Accounts that never logged in during the grace period take the device or recovery path.

### 5.9 Account enumeration

- **Login** resists enumeration:
  - Login names are normalised once, by the [§2](#2-conventions) function, before the lookup and before the fake id is computed, so a name is either found or faked under exactly the same string.
  - For an unknown login name, the server runs `ServerLogin::start` with `password_file = None` and the fake credential id. opaque-ke ≥ 4.0.0 always creates the dummy record, which fixes the timing difference. The fake id is deterministic, so repeated probes of the same name get consistent answers.
  - **The `kdf_id` for unknown names** must look like a real account's. While every record is on `kdf_id` 1, it is always 1. Once a newer `kdf_id` exists ([§6.3](#63-upgrade-path)), the server keeps, per `kdf_id` above 1, the fraction of records already on it (recomputed daily), and gives an unknown name the newer `kdf_id` when its fake-`kdf_id` selector ([§4.3](#43-derivations)), divided by 2^64, is below that fraction. The fraction only grows during a migration, so each unknown name flips at most once and never back, exactly like a real account. The selector is keyed with `enum_key`, so a prober cannot predict it. Residual: a fake name flips on a day set by the population curve, a real one when its owner next types the password online. A prober who polls a name daily and knows the owner's habits could tell the two apart. We accept that.
  - Nothing else that differs between real and fake accounts is sent before KE3 verifies.
- **Registration** is an enumeration oracle ("name taken"), and RFC 9807 says to rate-limit it. The M1 default is invite-only signup: an admin-issued invite token, bound to a login name. Open signup is opt-in, rate-limited per IP, and SHOULD use an email flow that answers the same way whether or not the name exists.
- **Recovery** answers "invalid recovery code" in the same way, with the same timing, for unknown names and for wrong codes. The lookup by name happens before a constant-time hash comparison, and a dummy comparison runs when the name is unknown.

### 5.10 Sessions after authentication

- **After an OPAQUE login.**
  - The server issues a random 32-byte bearer token and stores only `SHA-256(token)`.
  - The OPAQUE `session_key` is used only for OPAQUE's own key confirmation.
  - TLS carries the transport.
  - `ServerLogin` state is kept server-side, keyed by a random `login_id`, with a 60 s TTL.
- **After an unlock on an enrolled device**, the device authenticates with its key:
  1. The server sends a 32-byte random `challenge` with a 60 s TTL.
  2. The client returns `Ed25519(device_sk, LABEL("sig/device-auth") ‖ 0x00 ‖ u16(1) ‖ str(server_origin) ‖ account_id ‖ device_id ‖ challenge)`.
  3. The server checks the signature with `verify_strict` against the registered, non-revoked device key.
  4. The origin binding stops a signature for server A from being replayed at server B.
- **Device secret keys are wrapped under the account key** (`E_dev`), so device authentication requires a local unlock first. A stolen, locked device cannot talk to the server as that device. `E_dev` never leaves the device: anyone who once held the account key (a revoked device, a finished kit thief) could otherwise open it from server data and read every later grant addressed to that device. Background sync while locked (M3/M7) needs the device key in the OS keystore, which is a separate decision.
- **Binding tokens to the device key.** Native clients hold a device key, so they can sign each request, or a session nonce, and a stolen bearer token alone becomes useless. Whether to do this from M1 is threat-model Q-7 and belongs to the API ADR; nothing in this document prevents it.
- **Server-side 2FA** (TOTP in M1, WebAuthn in M3) gates *server access only*. It never enters key derivation. An attacker who defeats 2FA still needs the password and the SK to decrypt anything.

---

## 6. KDF parameters

### 6.1 Parameter table

This table is compiled into `rizzy-core`. The server sends only a `kdf_id`.

| `kdf_id` | Algorithm | m (KiB) | t | p | Status |
|---|---|---|---|---|---|
| 0 | – | – | – | – | Invalid, always rejected |
| **1** | Argon2id v0x13 | **65 536 (64 MiB)** | **3** | **4** | **M1 default and floor.** This is RFC 9106's second recommended option |
| 2 | Argon2id v0x13 | 262 144 (256 MiB) | 3 | 4 | Reserved, **not enabled**. Enabling it needs evidence that every client, including iOS AutoFill, can run it |

- **Output length.** 64 bytes when used as the OPAQUE KSF (Nh for SHA-512), 32 bytes elsewhere.
- **Salts.**
  - The OPAQUE KSF uses 16 zero bytes, per RFC 9807.
  - The local wrap uses a random 16-byte `device_salt`.
  - Exports use a random 16-byte salt stored in the file header.
  - Share passphrases use the 16-byte `share_id`.

### 6.2 Client-enforced floor

- Clients accept only `kdf_id` values in their compiled allow-list. M1 accepts only `{1}`.
- There is no code path that builds Argon2 parameters from server-supplied numbers.
- A unit test iterates the table and asserts that every enabled entry has `m ≥ 65 536`, `t ≥ 3` and `p = 4`. This makes the floor a CI-checked invariant.
- An unknown `kdf_id` from the server is a hard error: "the server asked for KDF settings this client does not allow". It is never a fallback.

This closes the attack Palant reported against Bitwarden in 2023 (L): the client accepted server-supplied PBKDF2 iteration counts as low as 5,000. It also closes the KDF-downgrade class in Scarlata et al. 2026 (L).

### 6.3 Upgrade path

1. A release adds `kdf_id` 2 to the table and marks it "preferred".
2. At the next event where the user types the password online, the client silently re-registers OPAQUE with the same password and the new `kdf_id`. This is the password-change flow without changing the password. The client also re-wraps `E_local`.
3. The server can *request* an upgrade through a policy flag. The client decides, and never moves *down*.
4. The old `kdf_id` stays on the allow-list until a later major release. Before removing it, the server's count of records per `kdf_id` must be close to zero. Stragglers then go through recovery.

### 6.4 Feasibility

Measured in M0 (fact sheet §5) on an Intel Xeon at 2.80 GHz with 4 vCPU, argon2 0.6.0, release/LTO. Each figure is a single run.

| Parameters | Native, 1 thread | Native, `parallel` | wasm32 (Node 22) |
|---|---|---|---|
| 19 MiB, t2, p1 (OWASP minimum) | 46 ms | 45 ms | 74 ms |
| **64 MiB, t3, p4 (`kdf_id` 1)** | 236 ms | 116 ms | **309 ms** |
| 256 MiB, t3, p4 | 986 ms | 966 ms | 1467 ms |
| 2 GiB, t1, p4 (RFC 9807's own profile) | – | – | 16.6 s |

- **Desktop and browser.** About 0.3 s in wasm is fine for an unlock. wasm gets no speedup from p=4; the lanes run sequentially.
- **iOS AutoFill.** The extension has a memory cap of about 120 MB (L). 64 MiB fits but leaves little room; Bitwarden warns above 64 MiB (L). In M7 the AutoFill extension SHOULD unlock through `E_ks` ([§4.2](#42-key-inventory)): the keystore unlock secret, held in the keychain behind biometry and bound to the Secure Enclave where possible, opens a wrap of the account key, and no Argon2id runs (threat model Q-13, AR-17, INV-62).
- **Low-end Android and iOS.** No reliable numbers exist (U). **An M1 spike must measure** 64 MiB/t3/p4 on the oldest devices we intend to support before `kdf_id` 1 is frozen. The expected result is 1–2 s, which we would accept.
- **RFC 9807's 2 GiB profile** is not feasible for us, and neither is anything above 64 MiB on phones.

---

## 7. Secret Key

**Recommendation: yes, mandatory for every account, with the derivation shipping in M1.** ROADMAP §4.3 says "M1 decision, M3 ship". We recommend shipping the crypto in M1 and leaving only UX polish, such as QR transfer between devices, for M3. The reasons:

1. It is what makes goal 2 true ([§5.5](#55-offline-attack-analysis)). For self-hosters the realistic threat is a leaked backup that contains both the database and the secrets file, and a malicious admin is a listed attacker for M9 family instances.
2. Adding it later means pushing every M1 account through a forced re-registration, and until they finish, those accounts are the weak ones.
3. The Emergency Kit, already a Must in M1, already assumes a Secret Key.
4. The cost is friction. A new browser or device needs the SK, typed from the kit or scanned from another device. 1Password has shown this is tolerable.

An optional SK would double the code paths and the analysis. **Rejected.** This remains an owner decision; see [§16](#16-open-questions-for-the-owner).

**Generation.** 16 bytes from the injected CSPRNG, on the client, at signup. The server never sees it.

**Format.**
- `RV1-` followed by 28 characters of Crockford Base32 (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`), grouped by fours: `RV1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.
- The first 26 characters encode the 128 SK bits followed by 2 zero bits.
- The last 2 characters encode the SK check value from [§4.3](#43-derivations): 10 bits, for typo detection only.
- Parsing is case-insensitive, maps `O`→`0` and `I`/`L`→`1`, and ignores dashes and spaces.
- A parse is rejected if the pad bits are non-zero or the check value does not match.
- The encoder and decoder MUST NOT index lookup tables with secret bits; they use arithmetic mapping ([§12.3](#123-side-channels)).

**Storage.**
- The Emergency Kit.
- Every enrolled device's state file. It cannot be encrypted under the account key, because unlocking needs it first. Until the OS keychain is used (desktop M3, mobile M7) it is protected only by file permissions; [§5.5](#55-offline-attack-analysis) states the consequence.
- The web vault asks for it on every new browser. It MAY keep it in IndexedDB if the user ticks "this is my browser".

**Changing the SK** uses the password-change flow ([§11.5](#115-master-password-or-secret-key-change)) and produces a new Emergency Kit.

**Emergency Kit.** It is generated **on the client only**, as printable HTML/PDF. It contains:
- the server URL,
- the login name,
- the Secret Key,
- the recovery code, if enabled ([§11.9](#119-recovery-with-the-emergency-kit)),
- a blank line for the master password.

It says in plain words that **anyone with this sheet and access to your server can take over your account**, and that losing both the sheet and the master password, with no device left, means the data is gone. Signup cannot finish until the user confirms the kit is saved by re-typing the last group of the SK.

---

## 8. Item and field encryption

### 8.1 AEAD choice

**XChaCha20-Poly1305** (`chacha20poly1305` 0.11.0), inside the committing envelope described in [§8.3](#83-key-commitment).

| | XChaCha20-Poly1305 | AES-256-GCM-SIV |
|---|---|---|
| Nonce | 192-bit random, safe | 96-bit. Nonce-misuse resistant, but random-nonce bounds are 2^32 messages of ≤ 8 GiB (RFC 8452, L) |
| Speed without AES hardware (old ARM, wasm) | Fast and constant-time in software | Software AES is slower. Constant-time needs a bitsliced backend |
| Crate audit | NCC 2020, on an old version (V) | The `aes-gcm-siv` code was never audited; only its `aes`/`polyval` dependencies were covered (V) |
| Key-committing | No | No (U) |
| Standard | The XChaCha draft expired and never became an RFC (V/L). It is widely deployed (libsodium, Bitwarden SDK V2) | RFC 8452 |

Neither is committing, so we add commitment ourselves either way. The better software story and audit history decide it. AES-256-GCM-SIV gets a reserved algorithm id and no implementation.

**Encryption granularity.** There is no per-field envelope. A sync op, meaning one save of one item (one or more field writes under one dot, as defined in [ADR 0012](adr/0012-sync-engine.md)), is one envelope, and an item snapshot is one envelope. Per-field envelopes would leak the field count and field sizes and multiply the AAD cases. Field identity is inside the plaintext, which the envelope authenticates. Selective sharing (M5) builds a new snapshot containing only the chosen fields under the share key.

### 8.2 Nonces

- **Generation.** Every envelope gets a fresh 24-byte nonce, drawn inside `rizzy-core` from the injected CSPRNG. No public API accepts a caller-supplied nonce (threat model INV-12). There are no counters: devices do not share nonce state.
- **Bound.** With random 192-bit nonces, the chance of any collision stays at 2^-32 or below until about **2^80 messages per key** (draft-irtf-cfrg-xchacha-03, L). The busiest key in the system, an item key, sees perhaps 10^4–10^6 envelopes in its life.
- **Defence in depth.** The subkey is derived from `(K, nonce)` ([§8.3](#83-key-commitment)). A nonce collision under the same key therefore repeats both subkey and nonce only for that pair. It does not leak across other messages.

### 8.3 Key commitment

**The problem.** AES-GCM, ChaCha20-Poly1305 and XSalsa20-Poly1305 are not key-committing. An attacker who knows a set of candidate keys can build **one ciphertext that decrypts validly under all of them**. If the keys come from a password and the attacker can learn whether decryption succeeded, which is exactly what a sync server sees when a client accepts or rejects data, each crafted ciphertext tests many password guesses at once. This is the **partitioning oracle** attack (Len, Grubbs, Ristenpart, USENIX Security 2021, L): 124 crafted ciphertexts recovered a Shadowsocks password 20% of the time, against about 60,000 online guesses otherwise. Early OPAQUE prototypes that used non-committing envelopes were affected. The same property enabled "Invisible Salamanders" (Dodis et al., CRYPTO 2018, L).

In our design several keys depend on low-entropy secrets:
- `local_unlock_key` on the device,
- the share key when a passphrase is used,
- the export file key.

Every other key is random. We commit **every** symmetric envelope anyway: it costs one HKDF, and there is then no "which envelopes need it" rule to get wrong.

**The construction.** This is Bellare and Hoang's UtC ("Unique-then-Commit") transform with the AAD folded into the committing PRF input, which is their HtE ("Hash-then-Encrypt") step applied on top: UtC + HtE (EUROCRYPT 2022, L). The committing PRF is HKDF-SHA-256. Plain UtC feeds only `(K, nonce)` to the PRF and commits to the key; folding in the AAD makes it commit to the whole context. This is the construction and the notion the M8 audit must check:

```
aad        = header ‖ u16(purpose) ‖ ctx                       (§8.4, §9.1)
okm        = HKDF(ikm = K, salt = nonce, info = LABEL("envelope/xchacha20poly1305") ‖ 0x00 ‖ aad, 64)
k_enc      = okm[0..32]
commitment = okm[32..64]
ct ‖ tag   = XChaCha20-Poly1305.Encrypt(key = k_enc, nonce = nonce, aad = aad, plaintext)
envelope   = header ‖ nonce ‖ commitment ‖ ct ‖ tag
```

Decryption:
1. Parse strictly ([§9.5](#95-parsing-and-allow-list-rules)).
2. Recompute `okm`.
3. `ct_eq(commitment, okm[32..64])`. If it fails, return `DecryptError` **without running the AEAD**.
4. Open the AEAD. If it fails, return the same `DecryptError`.

**Properties.**
- The commitment covers `(K, nonce, aad)`. Two different keys, or a different AAD under the same key, produce the same 256-bit commitment only through an HMAC-SHA-256 collision, which gives about 128-bit commitment security.
- Decryption is deterministic: given `(K, nonce, aad, ciphertext)` there is at most one plaintext. So committing to `(K, nonce, aad)` also commits to the message. In the paper's terms this is the CMT-4 notion reached through CMT-3 (L; the M8 audit confirms the claim for our instantiation).
- There is no ciphertext expansion beyond the 32-byte commitment.

**Alternatives we rejected:**
- **CTX** (Chan and Rogaway, ePrint 2022/1260, L). It needs the raw Poly1305 tag recomputed from the ciphertext, which RustCrypto's AEAD API does not expose, so we would have to compose ChaCha20 and Poly1305 by hand.
- **The zero-block padding fix** (Albertini et al., USENIX Security 2022, L). It gives only about 64-bit commitment against collision-finding.
- **A separate HMAC over the whole envelope.** It works, but it costs a second pass over the data and adds a second key to manage. UtC + HtE gets the same guarantee with one small HKDF.

### 8.4 AAD and purposes

Every envelope binds three things:
1. its **header**, which contains format version, algorithm id and key id,
2. a **purpose** (`u16`),
3. a **context**, the fields that say *where* this ciphertext belongs.

The purpose is **not transmitted**. The reader rebuilds `u16(purpose) ‖ ctx` from where it expected the object to be. A ciphertext moved anywhere else fails the commitment.

| Purpose | Id | Key / algorithm | Context fields (in order) | First used |
|---|---|---|---|---|
| `ACCOUNT_KEY_SERVER_WRAP` (`E_srv`) | 0x0001 | server_unlock_key / 0x01 | account_id ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id | M1 |
| `ACCOUNT_KEY_LOCAL_WRAP` (`E_local`) | 0x0002 | local_unlock_key / 0x01 | account_id ‖ device_id ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id | M1 |
| `ACCOUNT_KEY_RECOVERY_WRAP` (`E_rec`) | 0x0003 | recovery wrap key / 0x01 | account_id ‖ u32 account_key_epoch ‖ u32 recovery_epoch | M1 |
| `ACCOUNT_KEY_DEVICE_GRANT` | 0x0004 | recipient device X25519 / 0x12 (PSK: device-grant PSK) | account_id ‖ u32 account_key_epoch (new) ‖ sender device_id ‖ recipient device_id | M1 (rotation) |
| `PASSWORD_VERIFIER_GRANT` | 0x0005 | recipient device X25519 / 0x12 (PSK: password-verifier PSK) | account_id ‖ u32 password_epoch (new) ‖ sender device_id ‖ recipient device_id | M4 |
| `ACCOUNT_KEY_KEYSTORE_WRAP` (`E_ks`) | 0x0006 | keystore unlock secret / 0x01 | account_id ‖ device_id ‖ u32 account_key_epoch | M3/M7 |
| `IDENTITY_SECRET_KEYS` (`E_id`) | 0x0010 | account key / 0x01 | account_id ‖ u32 identity_epoch | M1 |
| `DEVICE_SECRET_KEYS` (`E_dev`) | 0x0011 | account key / 0x01 | account_id ‖ device_id | M1 |
| `MAIL_SECRET_KEY` | 0x0012 | account key / 0x01 | account_id ‖ u32 mail_key_epoch | M6 |
| `RETIRED_SECRET_KEY` | 0x0013 | account key / 0x01 | account_id ‖ retired public key id (16) | M1 (rotation) |
| `ACCOUNT_SETTINGS` | 0x0014 | account key / 0x01 | account_id ‖ u64 settings_seq. Freshness: [§10.2](#102-ed25519-signatures-and-signed-statements) | M1 |
| `VAULT_KEY_SELF_GRANT` | 0x0020 | account key / 0x01 | account_id ‖ vault_id ‖ u32 account_key_epoch ‖ u32 vault_key_epoch | M1 |
| `VAULT_KEY_MEMBER_GRANT` | 0x0021 | grantee identity X25519 / 0x10 | vault_id ‖ u32 vault_key_epoch ‖ granter account_id ‖ grantee account_id | M9 |
| `ITEM_KEY_WRAP` | 0x0030 | vault key / 0x01 | vault_id ‖ item_id ‖ u32 vault_key_epoch (of the wrapping vault key). Plaintext: `u8 wrap_version = 1 ‖ u32 created_vault_key_epoch ‖ item_key (32)` | M1 |
| `ITEM_OP` | 0x0031 | item key / 0x01 | vault_id ‖ item_id ‖ u16 item_schema_version ‖ op_id ‖ device_id ‖ u64 device_seq ‖ u64 hlc ‖ SHA-256(canonical op header) | M1 |
| `ITEM_SNAPSHOT` | 0x0032 | item key / 0x01 | vault_id ‖ item_id ‖ u16 item_schema_version ‖ snapshot_id ‖ SHA-256(canonical snapshot header) | M1 |
| `ATTACHMENT_CHUNK` | 0x0033 | attachment key / 0x03 (reserved) | defined by the M3 attachments ADR | M3 |
| `ATTACHMENT_KEY_WRAP` | 0x0034 | item key / 0x01 | vault_id ‖ item_id ‖ attachment_id | M3 |
| `RELAY_BATCH` | 0x0040 | relay key / 0x01 | account_id ‖ sender device_id ‖ u64 batch_seq ‖ u32 account_key_epoch | M4 |
| `PAIRING_TRANSFER` | 0x0041 | pairing key / 0x01 | pairing_id ‖ u8 direction (1 = new→existing, 2 = existing→new) ‖ u32 message_index. Only the three messages before the SAS ([§11.7](#117-new-device-in-on-device-mode)) | M4 |
| `PAIRING_TRANSFER_SEALED` | 0x0042 | new device's X25519 / 0x12 (PSK = `k_pair`) | pairing_id ‖ u32 chunk_index ‖ u32 total_chunks | M4 |
| `RESYNC_TRANSFER` | 0x0043 | stale device's X25519 / 0x12 (PSK: re-sync PSK) | account_id ‖ transfer_id ‖ sender device_id ‖ recipient device_id ‖ u32 chunk_index ‖ u32 total_chunks | M4 |
| `SHARE_SNAPSHOT` | 0x0050 | share key / 0x01 | share_id ‖ u8 flags (bit 0 = passphrase) | M5 |
| `MAIL_MESSAGE` | 0x0060 | recipient mail X25519 / 0x10 | account_id ‖ alias_id ‖ message_id ‖ u64 received_at_ms | M6 |
| `EXPORT_FILE` | 0x0070 | export file key / 0x01 | export_id ‖ u64 created_at_ms ‖ u16 kdf_id ‖ export_salt | M1 |
| `BACKUP_FILE` | 0x0071 | backup key / 0x01 | defined by the M4 backup ADR | M4 |
| `LOCAL_CACHE_INDEX` | 0x0090 | local index key / 0x01 | account_id ‖ device_id | M3 |

**Op and snapshot headers.** The canonical op header and snapshot header, including the version vector, the causal context and the author `device_id`, are defined by [ADR 0012](adr/0012-sync-engine.md). The rule here is: **every field of an op or snapshot header that the server can see is covered by the AAD**, through the header hash, and the most important ones are also listed explicitly. This satisfies ROADMAP's "AAD binds item ID + version": the version is `(device_id, device_seq, hlc)` for an op and the covered version vector for a snapshot. Because the author `device_id` is inside the header hash, a vault member (M9) cannot strip another member's snapshot signature and re-sign the envelope as their own.

**Item keys and staleness.** The `ITEM_KEY_WRAP` plaintext carries the epoch in which the item key was *created*, and re-wrapping during a rotation copies it unchanged. That makes "this item key predates the last rotation" an authenticated fact that any device holding the vault key can read, rather than server metadata or one device's memory. The writer and reader rules are in [§11.6](#116-key-rotation). The item key's own key id is derived from the key ([§4.4](#44-identifiers-epochs-and-key-ids)); a reader checks that it equals the `key_id` in the op or snapshot envelope header.

**Attachment keys (M3).** Each attachment has its own random key, wrapped under the item key with `ATTACHMENT_KEY_WRAP`, so an attachment can be shared or deleted without touching the item's other data. The chunked envelope (algorithm 0x03) is the M3 attachments ADR's to define.

**Why item AAD has no `account_id`.** Vaults become shareable between accounts in M9, so an item belongs to a vault, not to an account. `vault_id` is 128 random bits and each vault key belongs to exactly one vault, so moving an item's ciphertext into another account's vault already fails: wrong `vault_id`, wrong key. This meets the intent of threat-model INV-13 without binding items to one owner.

**Security-relevant settings live under `ACCOUNT_SETTINGS`, never in server-visible fields.** These include user-defined domain-equivalence groups, per-URI match modes, autofill rules and pinned contact keys ([§10.3](#103-public-key-authenticity)). A server that could edit "bank.com ≡ evil.example" would have a phishing primitive; this is the "unbound settings" attack class. Authenticity is not enough: every older `ACCOUNT_SETTINGS` envelope still opens under the same account key, so the server could serve one that brings back a deleted equivalence group or drops a pin. The signed `account-state` therefore commits to `settings_seq` and the settings hash ([§10.2](#102-ed25519-signatures-and-signed-statements)), and clients reject anything else.

### 8.5 Plaintext framing and padding

Plaintexts of `ITEM_OP`, `ITEM_SNAPSHOT`, `SHARE_SNAPSHOT`, `RELAY_BATCH`, `PAIRING_TRANSFER_SEALED`, `RESYNC_TRANSFER` and `MAIL_MESSAGE` are framed as:

```
u32(data_len) ‖ data ‖ zero bytes up to padded_len
padded_len = max(256, Padmé(4 + data_len))
```

- **Padmé.** This is the padding from the PURBs paper (Nikitin et al., PETS 2019; not re-verified for this document). It leaks O(log log L) bits of length for at most about 12% overhead.
- **The reader** rejects frames where `data_len > len - 4` or where any padding byte is non-zero.
- **Key-wrap envelopes** are fixed-size and unpadded. A wrapped symmetric key's plaintext is the 32-byte key, except `ITEM_KEY_WRAP`, whose plaintext is the 37-byte layout in [§8.4](#84-aad-and-purposes).

---

## 9. Envelope format

### 9.1 Symmetric envelope (algorithm 0x01)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `format_version` = 0x01 |
| 1 | 1 | `alg_id` = 0x01 |
| 2 | 16 | `key_id` of the key K, derived from K ([§4.4](#44-identifiers-epochs-and-key-ids)) |
| 18 | 24 | `nonce` |
| 42 | 32 | `commitment` |
| 74 | n | ciphertext, n = plaintext length |
| 74 + n | 16 | Poly1305 tag |

- `header` = bytes `[0, 18)`.
- `aad = header ‖ u16(purpose) ‖ ctx`.
- Overhead: **90 bytes**.
- M1 limit: plaintext ≤ 16 MiB. Larger objects, i.e. attachments, use the reserved chunked algorithm 0x03 from M3.

### 9.2 HPKE envelope (algorithms 0x10 and 0x12)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `format_version` = 0x01 |
| 1 | 1 | `alg_id` = 0x10 (Base mode) or 0x12 (PSK mode) |
| 2 | 16 | `key_id` of the **recipient public key** ([§4.3](#43-derivations)) |
| 18 | 32 | `enc` (HPKE encapsulated key = ephemeral X25519 public key) |
| 50 | n | ciphertext |
| 50 + n | 16 | tag |

- HPKE parameters: KEM 0x0020 DHKEM(X25519, HKDF-SHA256), KDF 0x0001 HKDF-SHA256, AEAD 0x0003 ChaCha20Poly1305. Mode `mode_base` (0x00) for `alg_id` 0x10, `mode_psk` (0x01) for `alg_id` 0x12. The two layouts are identical; the purpose fixes which one is allowed ([§9.5](#95-parsing-and-allow-list-rules)).
- Calls (hpke 0.14.1): `hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(&mode, &pk_R, info, pt, aad, &mut rng)` to seal, `hpke::single_shot_open(&mode, &sk_R, &enc, info, ct, aad)` to open. `mode` is `OpModeS::Base` / `OpModeR::Base`, or `OpModeS::Psk(PskBundle::new(psk, psk_id)?)` and the matching `OpModeR::Psk`, with `psk` and `psk_id` from [§4.3](#43-derivations). The variants without `_with_rng` exist only with hpke's `getrandom` feature, which we never enable.
- `info = LABEL("hpke") ‖ 0x00 ‖ u16(purpose)`.
- `aad = header ‖ u16(purpose) ‖ ctx`.
- Overhead: **66 bytes**.

HPKE envelopes carry **no** separate commitment. The key comes from a Diffie-Hellman with the recipient's static key, plus in PSK mode a 256-bit PSK derived from a random key, never from a password, so there is no partitioning oracle. Each envelope is addressed to exactly one recipient key id. Where authorship matters, a signature covers the envelope ([§10.1](#101-hpke-key-wrapping)).

### 9.3 Signature container

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `sig_format_version` = 0x01 |
| 1 | 1 | `sig_alg` = 0x01 (Ed25519) |
| 2 | 16 | signer public key id |
| 18 | 64 | signature |

`sig_alg` 0x02 is reserved for a hybrid Ed25519 + ML-DSA signature ([§13](#13-post-quantum-readiness)).

### 9.4 Algorithm registry

| `alg_id` | Construction | Status |
|---|---|---|
| 0x00 | invalid | always rejected |
| **0x01** | XChaCha20-Poly1305 with the HKDF-SHA-256 UtC + HtE commitment ([§8.3](#83-key-commitment)) | **M1**: encrypt and decrypt |
| 0x02 | AES-256-GCM-SIV with the same commitment | reserved, not implemented |
| 0x03 | chunked/streaming variant of 0x01 for attachments | reserved for the M3 ADR |
| **0x10** | HPKE Base, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 | **M1**: encrypt and decrypt |
| 0x11 | HPKE Base, X-Wing (X25519 + ML-KEM-768) / HKDF-SHA256 / ChaCha20Poly1305 | reserved, post-1.0 |
| **0x12** | HPKE PSK mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 | **M1**: encrypt and decrypt (device grants) |
| 0x13 | HPKE PSK mode, X-Wing / HKDF-SHA256 / ChaCha20Poly1305 | reserved, post-1.0 |
| 0x14–0x1F | further hybrid/PQ KEMs | reserved |
| 0xF0–0xFE | test-only algorithms | rejected by release builds (`cfg(test)` only) |
| 0xFF | reserved for a future multi-byte id extension | rejected |

### 9.5 Parsing and allow-list rules

1. **Order of checks.**
   1. Length first: ≥ 90 bytes for 0x01, ≥ 66 bytes for 0x10 and 0x12.
   2. `format_version` must be 0x01.
   3. `alg_id` must be in `ALLOWED_DECRYPT[purpose]`.
   4. `key_id` must equal the key id of a key the caller holds for this purpose: for a symmetric key, the id derived from it ([§4.4](#44-identifiers-epochs-and-key-ids)), computed after deriving the key where the key is itself derived; for HPKE, the id of the caller's own public key.

   Only then does any crypto run. A failure at any step returns the same `DecryptError`. Details go only to local debug logs, and never include key material.
2. **Per-purpose allow-lists.** Each purpose has an **encrypt algorithm** (exactly one) and a **decrypt allow-list**. In M1:
   - every symmetric purpose: `{0x01}`;
   - `ACCOUNT_KEY_DEVICE_GRANT`, `PASSWORD_VERIFIER_GRANT`, `PAIRING_TRANSFER_SEALED`, `RESYNC_TRANSFER`: `{0x12}`;
   - `VAULT_KEY_MEMBER_GRANT`, `MAIL_MESSAGE`: `{0x10}`.

   A symmetric purpose never accepts an HPKE algorithm, a PSK-mode purpose never accepts Base mode, and vice versa. Base mode on a PSK purpose would silently drop the PSK's protection.
3. **No negotiation.** The server never chooses an algorithm. The only asymmetric choice is made by the *sender*, from the recipient's **signed** key bundle ([§10.2](#102-ed25519-signatures-and-signed-statements)). A bundle MAY set `pq_required`, after which classical grants to that recipient are rejected.
4. **Sunsetting an algorithm.**
   1. Release N stops encrypting with it.
   2. Clients re-encrypt the objects they own in the background.
   3. The server reports how many objects of each `alg_id` remain. This is metadata it already sees.
   4. Release N+k removes the algorithm from the decrypt allow-list.

   There is no "legacy decrypt mode" switch.
5. **Fuzzing.** The parser is a pure function `&[u8] -> Result<EnvelopeRef<'_>, ParseError>`. It never panics, never allocates in proportion to a length field, and is fuzzed ([§15](#15-testing)).

### 9.6 Encoding for transport and storage

- **Storage.** Raw bytes: `BLOB` in SQLite, `bytea` in PostgreSQL, raw in the client cache.
- **JSON APIs.** base64url without padding (RFC 4648 §5).
- **Signed statements.** Carried as `bytes(statement) ‖ signature container`. A key bundle that changes the identity keys carries two containers, the new key's first ([§10.2](#102-ed25519-signatures-and-signed-statements)).
- **Files** (export, M4 backup). Written as JSON, with the envelope base64url-encoded in a `data` field and the header fields repeated in clear for tooling. The repeated header fields are informational only: the bytes that are bound come from the envelope and the ctx, and the tests assert that the two agree.

### 9.7 How a migration lands (PQ example)

1. Implement `alg_id` 0x11 in `rizzy-core`, decrypt-only first.
2. Add key type `0x10` (X-Wing public key) to the key bundle schema ([§10.2](#102-ed25519-signatures-and-signed-statements)).
3. Clients publish a new bundle (`bundle_seq + 1`, same identity keys, so contacts accept it silently, [§10.3](#103-public-key-authenticity)) that includes the PQ key.
4. Senders use 0x11 (Base purposes) or 0x13 (PSK purposes) for any recipient whose bundle advertises the PQ key.
5. Long-lived HPKE objects are re-issued: member vault grants (M9) and pending device grants.
6. New mail uses 0x11. Old mail ages out under retention.
7. Once the server's per-algorithm counts reach zero, `pq_required` becomes the default and 0x10 and 0x12 leave the allow-list.

None of this changes the symmetric envelopes. They are already fine against quantum attackers.

---

## 10. Asymmetric cryptography

### 10.1 HPKE key wrapping

- **Suite and modes.** RFC 9180 **Base mode and PSK mode**, never Auth or AuthPSK. Suite as in [§9.2](#92-hpke-envelope-algorithms-0x10-and-0x12), crate `hpke` 0.14.1 with `default-features = false` and features `alloc`, `x25519`, `chacha`.
  - The defaults would enable `getrandom` and `mlkem`. The first breaks the wasm build and the no-I/O rule; the second switches on X-Wing, which is still a draft. `cargo xtask check-deps` fails if getrandom becomes reachable from `rizzy-core` ([ADR 0016](adr/0016-workspace-layout.md) R1), which also catches the `getrandom` feature being switched on.
  - Keys are generated with `<X25519HkdfSha256 as hpke::Kem>::gen_keypair_with_rng(&mut rng)`, where `rng` is the injected rand_core 0.10 `CryptoRng`. `Kem::gen_keypair()` exists only with the `getrandom` feature and is not available in our build.
- **Which purposes use PSK mode, and why.** `ACCOUNT_KEY_DEVICE_GRANT`, `PASSWORD_VERIFIER_GRANT`, `PAIRING_TRANSFER_SEALED` and `RESYNC_TRANSFER` carry an account key, a password verifier or a whole vault, and some of them sit on the server for weeks until an offline device consumes them. Each uses a PSK the legitimate recipient already has ([§4.3](#43-derivations)):
  - device grants: HKDF of the *previous* account key, which every remaining device holds and the new epoch's attacker does not;
  - password-verifier grants and re-sync: HKDF of the current account key;
  - pairing: `k_pair` from the QR code.

  So opening one needs both the recipient's X25519 private key and the PSK. A DB snapshot plus a future quantum computer breaks the X25519 half but not the PSK. A revoked device knows the previous account key but not the recipient's X25519 private key, which never leaves that device ([§5.10](#510-sessions-after-authentication)). All PSKs are 32 bytes derived from 256-bit keys, which meets RFC 9180's minimum PSK entropy (RFC text not re-verified for this document). rust-hpke 0.14.1 implements PSK mode for DHKEM(X25519) and for X-Wing (V, crate source), so the PQ upgrade path (0x13) exists.
  - A device several rotations behind opens its pending grants in epoch order: each grant's PSK comes from the key the previous grant delivered. The server keeps every unconsumed grant for that device.
- **Why not Auth mode.** HPKE's Auth and AuthPSK modes authenticate the sender's KEM key, but PQ KEMs in rust-hpke do not support them (per the crate's own source: "Use Base or Psk operation mode"), and Auth mode's sender-authentication properties are weaker than a signature (U). Where authorship matters we add an Ed25519 signature.
- **Signed grants** (`ACCOUNT_KEY_DEVICE_GRANT`, `PASSWORD_VERIFIER_GRANT`, `VAULT_KEY_MEMBER_GRANT`):
  - The AAD `ctx` names the sender and the recipient by id: `device_id` for device grants, `account_id` for member grants ([§8.4](#84-aad-and-purposes)).
  - The envelope header names the recipient public key id ([§9.2](#92-hpke-envelope-algorithms-0x10-and-0x12)).
  - The sender signs `LABEL("sig/key-grant") ‖ 0x00 ‖ u16(1) ‖ u16(purpose) ‖ sender public key id ‖ recipient public key id ‖ bytes(hpke_envelope)`. The sender *key* id appears only here.
  - The recipient checks that the signing key belongs to the sender named in the AAD: a device certificate for that `device_id` in the current signed device set, or the pinned identity key for that `account_id`. Stripping the signature and re-signing with another key fails this check.
  - Re-sealing the plaintext to a third party requires the plaintext, and the third party would see the original sender id.
- **Unsigned seals.** `MAIL_MESSAGE` is sealed by the server's `smtp` role and carries no sender signature. The server sees mail at ingress anyway; what `smtp` must get right is the recipient key, which it pins ([§11.13](#1113-mail-ingress-m6)).

### 10.2 Ed25519 signatures and signed statements

**Library rules.**
- `ed25519-dalek` 3.0.0, pure Ed25519 (RFC 8032).
- Verification always uses `verify_strict`, which rejects small-order and non-canonical inputs.
- Signing always goes through a `SigningKey`, which holds the matching public key. This rules out the double-public-key signing oracle from RUSTSEC-2022-0093.

**Message format.** Every signed message is `LABEL("sig/<type>") ‖ 0x00 ‖ u16(statement_version = 1) ‖ body`. `body` is the fixed layout below.

| Statement (`<type>`) | Body | Signed by |
|---|---|---|
| `public-key-bundle` | account_id ‖ u32 identity_epoch ‖ u64 bundle_seq ‖ u8 n ‖ n × (u8 key_type ‖ bytes(public_key)) ‖ u8 flags (bit 0 = `pq_required`) ‖ u64 created_at_ms ‖ prev_bundle_hash (32 B: the hash of the immediately preceding bundle; zero only for `bundle_seq` 1) | The identity Ed25519 key inside the bundle (self-signature). When the identity keys differ from the preceding bundle's (`identity_epoch + 1`), **also** the preceding identity key |
| `device-certificate` | account_id ‖ device_id ‖ u32 identity_epoch ‖ device Ed25519 pk (32) ‖ device X25519 pk (32) ‖ u8 device_kind (1 desktop/CLI, 2 extension, 3 mobile, 4 web-ephemeral) ‖ u64 created_at_ms ‖ u64 expires_at_ms (0 = none; for kind 4 at most created_at_ms + 12 h) | Identity key of that `identity_epoch` |
| `device-revocation` | account_id ‖ device_id ‖ u64 last_accepted_device_seq ‖ u64 revoked_at_ms | Identity key |
| `account-state` | account_id ‖ u64 state_seq ‖ u32 identity_epoch ‖ u32 account_key_epoch ‖ u32 password_epoch ‖ u16 kdf_id ‖ u32 recovery_epoch ‖ u8 recovery_enabled ‖ u8 sync_mode ‖ u32 mail_key_epoch ‖ bundle_hash (32) ‖ device_set_hash (32) ‖ u64 settings_seq ‖ settings_hash (32) | The identity key of the state's own `identity_epoch`. After a full rotation that is the **new** key |
| `op` | bytes(canonical op header) ‖ SHA-256(op envelope) ‖ SHA-256(`ITEM_KEY_WRAP` envelope carried with the op), or 32 zero bytes in place of the second hash when the op carries no wrap. The body and the wrap are signed by hash so the server can delete a compacted op's body and keep its signed header ([ADR 0012](adr/0012-sync-engine.md) §3, §7). A receiver that holds the body or the wrap checks it against the signed hash before anything else | Device key of the authoring device |
| `snapshot` | bytes(canonical snapshot header) ‖ bytes(snapshot envelope) ‖ bytes(`ITEM_KEY_WRAP` envelope carried with the snapshot, or empty) | Device key |
| `key-grant` | see [§10.1](#101-hpke-key-wrapping) | Device key (device grants) or identity key (member grants, M9) |
| `device-auth` | see [§5.10](#510-sessions-after-authentication) | Device key |

`bundle_hash` and `prev_bundle_hash` are `SHA-256` over the full signed message.

**Bundles are a chain.** Every bundle names its immediate predecessor, and `bundle_seq` orders bundles within an identity epoch as well as across epochs. A new bundle is published whenever a public key changes: identity keys (full rotation), a PQ key ([§9.7](#97-how-a-migration-lands-pq-example)), the mail key (M6). Every verifier, whether own device, contact (M9) or `smtp` (M6), pins the highest `bundle_seq` it has accepted and rejects lower ones, so the server cannot serve an older validly signed bundle to strip `pq_required` or withhold the current mail key. How other people's clients treat an identity-key change is in [§10.3](#103-public-key-authenticity).

**Device set.** `device_set_hash` = `SHA-256(LABEL("device-set") ‖ 0x00 ‖ h_1 ‖ … ‖ h_n)`. Here `h_i` is the SHA-256 of the signed message of each non-revoked device certificate **with `device_kind` ≠ 4**, and the list is sorted bytewise. Enrolling or revoking a durable device therefore always publishes a new `account-state` with `state_seq + 1`. The server applies state updates as compare-and-swap on `state_seq`: when two devices enrol at once, one of them retries. The server cannot hide a device without rolling back the signed state, which any device that has seen the newer state detects (threat model INV-14, INV-25).

**Web-vault certificates (`device_kind` 4) are never in the device set.** Putting them in would mean a state CAS and a "new device" alarm on every web login, and a set that only grows, because expired certificates are never revoked. Instead, peers accept an op or snapshot from a kind-4 device only if (a) its certificate verifies under the identity key of the current `identity_epoch`, (b) `expires_at_ms ≤ created_at_ms + 12 h`, and (c) the op's HLC, read as milliseconds (its top 48 bits), is ≤ `expires_at_ms`. [ADR 0012](adr/0012-sync-engine.md) already checks (c) against the HLC so that replicas agree. The server refuses uploads from an expired certificate. Ending a web session early is server-enforced only (threat model AR-9), with one exception: a switch to On-device mode signs a `device-revocation` for every unexpired kind-4 certificate ([ADR 0012](adr/0012-sync-engine.md) §10), and peers reject later ops from it. Otherwise the certificate dies after 12 h regardless. Every other `device_kind` must be in the set, or its ops are rejected.

**Settings freshness.** `settings_hash` is `SHA-256` over the current `ACCOUNT_SETTINGS` envelope, or 32 zero bytes while `settings_seq = 0`.
- Every settings change writes a new envelope with `settings_seq + 1` and publishes a new `account-state` (`state_seq + 1`) carrying the new `settings_seq` and hash, in one compare-and-swap on `state_seq`.
- The loser of a concurrent change re-fetches, re-applies its edit on top of the newer settings, and retries.
- Clients reject an `ACCOUNT_SETTINGS` envelope whose hash differs from the verified state's `settings_hash`, and reject a state whose `settings_seq` is lower than the one they persisted. This is threat model INV-25; without it the server could serve an older, validly encrypted settings object that restores a deleted equivalence group or drops a contact pin.

**Which identity key verifies what.** A device caches the identity public key of the newest `identity_epoch` it has accepted. After a full rotation, it rejects any certificate, bundle or `account-state` signed only by a superseded identity key (threat model INV-30). The step from the old key to the new one is [§11.3](#113-unlock-on-an-enrolled-device) step 3.

**What signatures buy us:**
- **Device registrations.** A device joins the account only with a certificate signed by the identity key, and the identity key is available only to someone who has unlocked the account. The server cannot inject a device into the user's device set.
- **Ops and relay traffic.** Every op names its authoring device. Peers reject ops from devices outside the signed device set (except kind-4 devices under the rule above) or revoked, and ops past a revocation's `last_accepted_device_seq`. The signature also covers the item-key wrap that travels with an op, so the wrap's author is known. In M9 this is what stops one vault member from forging edits as another.
- **Account state.** `kdf_id`, epochs, recovery status, sync mode, the current bundle, the device set and the settings version are signed. The server cannot change them, and a device that has seen `state_seq = n` rejects anything lower.

### 10.3 Public key authenticity

**This matters from M5 (recipient verification) and above all from M9 (shared vaults).** In M1–M4 the only public keys a client uses belong to its own account, and those are authenticated for free:
- **Own identity keys.** After login the client decrypts `E_id`, derives the public keys, and compares them to the published bundle. A mismatch means server tampering, and the client aborts. After a full rotation elsewhere, an enrolled device moves to the new key only through [§11.3](#113-unlock-on-an-enrolled-device) step 3, with the user confirming the new fingerprint.
- **Own devices.** Certificates chain to that verified identity key.
- **Mail (M6).** The `smtp` role runs in its own container with no DB access ([ADR 0010](adr/0010-server-shape.md)) and gets the recipient's bundle from `api`. An attacker who controls only `api` or the DB could hand it a bundle with a freshly minted identity key and their own mail key; a self-signature check alone cannot notice. So `smtp` pins each account's identity key on first use and accepts later bundles only through the chain rules below ([§11.13](#1113-mail-ingress-m6)). A malicious `smtp` itself reads mail at ingress anyway (threat model AR-2).

For **other people's keys** (M9 invites and member grants):

1. **Fingerprints (safety numbers).**
   - Take the first 30 bytes of the account fingerprint ([§4.3](#43-derivations)).
   - Split them into six 5-byte chunks. Render each chunk as `u40 mod 100000`, padded to 5 digits: 30 digits per account.
   - A pair of users compares both accounts' 30 digits, concatenated in `account_id` order: 60 digits in 12 groups, plus a QR code. This is the Signal-style numeric fingerprint.
2. **TOFU with pinning.**
   - The first bundle seen for a contact is pinned in the user's encrypted `ACCOUNT_SETTINGS` (whose freshness the signed state guarantees, [§10.2](#102-ed25519-signatures-and-signed-statements)): the identity Ed25519 key, the identity X25519 key, the highest `bundle_seq` seen and that bundle's hash.
   - **Silent update.** A later bundle is accepted without asking only if it chains from the pinned one (`prev_bundle_hash` links, `bundle_seq` increasing by one per step, every self-signature valid) **and keeps both identity keys**. That covers adding a PQ key and rotating the mail key.
   - **Identity change.** A bundle that changes either identity key is a visible "safety number changed" event at every contact, even when the previous identity key signed it. A full rotation exists because the old key may be compromised, for example on a stolen device, and whoever holds it can sign a chained bundle carrying their own keys. A verified contact drops to unverified, and threat model INV-17 blocks new grants to that contact until the user re-verifies the fingerprint.
   - **Fork.** Two different bundles with the same `prev_bundle_hash` or the same `bundle_seq` are a hard alarm: "the server has shown you two versions of this person's keys". No grants go to that contact until the user resolves it out of band.
   - **Rollback.** A bundle with a lower `bundle_seq` than the pinned one is rejected.
3. **Invites (M9)** must verify the fingerprint, or explicitly accept TOFU with a visible "not verified" badge, *before* any vault key is granted. The server-mediated invite acceptance that let a server hijack an org vault in the ETH analysis (L) must not be reproducible: grants are made only to keys the granter has verified or pinned.
4. **Key transparency** (an append-only, verifiable log of bundles, in the style of Proton's KT work, L) is a **Could** for post-1.0. It is the only real fix for first-contact substitution at scale.

---

## 11. Flows

Endpoint paths are illustrative; the API specification owns them. The cryptographic content of each message is normative.

### 11.1 Signup (Server mode)

1. The user enters: server URL, login name, master password, invite token (if the server requires one).
2. The client generates, all from the injected CSPRNG:
   - `account_id`, `SK`, account key
   - identity Ed25519 seed and identity X25519 keypair
   - personal `vault_id`, vault key
   - `device_id`, device Ed25519 and X25519 keys, `device_salt`
   - the recovery code, unless the user opted out
3. `pw_in` ← HKDF(password, SK).
4. **OPAQUE registration**, using `ksf: Some(&RizzyArgon2idKsf::new(1))` (Argon2id run 1):
   1. `ClientRegistration::start(rng06, pw_in)` → `M1`
   2. `POST /api/v1/register/start {invite, login_name, account_id, M1}`
   3. Server: `ServerRegistration::start(&setup, M1, credential_identifier = account_id)` → `M2`
   4. Client: `ClientRegistration::finish(rng06, pw_in, M2, params)` → `(upload, export_key)`
5. The client builds:
   - `E_srv` = Envelope(`server_unlock_key`, `ACCOUNT_KEY_SERVER_WRAP`, account key)
   - `E_id` = Envelope(account key, `IDENTITY_SECRET_KEYS`, `ed25519_seed ‖ x25519_sk`)
   - the key bundle (`bundle_seq = 1`, `prev_bundle_hash` zero) with its self-signature
   - the device certificate
   - `account-state` with `state_seq = 1`, `kdf_id = 1`, `account_key_epoch = identity_epoch = password_epoch = 0`, `recovery_epoch = 1` and `recovery_enabled = 1` (both 0 if the user opted out), `mail_key_epoch = 0`, `settings_seq = 0` with a zero `settings_hash`, `bundle_hash`, and `device_set_hash` over this first device ([§4.4](#44-identifiers-epochs-and-key-ids))
   - the vault self-grant (`VAULT_KEY_SELF_GRANT`, epochs 0 and 0)
   - `E_dev` = Envelope(account key, `DEVICE_SECRET_KEYS`, device secret keys), **for local storage only**
   - `E_rec` = Envelope(recovery wrap key, `ACCOUNT_KEY_RECOVERY_WRAP`, account key) and `H_rec = SHA-256(recovery_auth_token)`
6. `POST /api/v1/register/finish` with exactly these objects: the OPAQUE `upload`, `E_srv`, `E_id`, the bundle, `account-state`, the vault self-grant, the device certificate, and `E_rec` with `H_rec`. **`E_dev` is never uploaded**: it is written locally in step 7. The API has no field that could carry it, and the server rejects requests with unknown fields. The server:
   - checks the bundle self-signature and the certificate chain (cheap consistency checks),
   - stores everything in one transaction,
   - records the `setup_id` and `kdf_id` with the OPAQUE record.
7. The client writes its device state: `account_id`, `device_id`, SK, `device_salt`, `kdf_id`, `E_dev`, the verified state, and `E_local` = Envelope(`local_unlock_key`, `ACCOUNT_KEY_LOCAL_WRAP`, account key). Computing `local_unlock_key` is Argon2id run 2, once.
8. The client renders the Emergency Kit. Signup finishes only when the user confirms it is saved.

### 11.2 Login on a new device (Server mode)

1. The user enters: server URL, login name, SK (typed, or QR from another device), master password.
2. `ClientLogin::start(rng06, pw_in)` → `KE1`. `POST /api/v1/login/start {login_name, KE1}`.
3. The server finds the record, or uses the fake path ([§5.9](#59-account-enumeration)). It calls `ServerLogin::start(rng, &setup, record_or_none, KE1, credential_identifier, ServerLoginParameters { context: ctx(kdf_id, server_origin), identifiers: default })` and returns `{login_id, KE2, kdf_id, server_origin}`.
4. The client checks that `kdf_id` is on its allow-list and that `server_origin` equals the origin it dialled; otherwise it aborts with the matching error. It then calls `ClientLogin::finish(rng06, pw_in, KE2, params { context: ctx(kdf_id, dialled origin), identifiers: default, ksf: Some(..) })` → `(KE3, export_key)`.
   - This is the one Argon2id run.
   - A failure is shown as "wrong password or Secret Key". Nothing reveals which one was wrong.
5. `POST /api/v1/login/finish {login_id, KE3, totp?}`. The server runs `ServerLogin::finish`, checks 2FA, and issues a session. The response contains:
   - `account_id`, the epochs and `E_srv`
   - `E_id`, the current bundle, `account-state`, `ACCOUNT_SETTINGS`
   - device certificates, revocations
   - the vault self-grants
6. The client verifies, aborting on any failure:
   - `E_srv` opens.
   - `E_id` opens, and the derived public keys equal the bundle's keys.
   - The `account-state` signature is valid under that identity key, and `state.identity_epoch` equals the bundle's.
   - `state.account_id` equals the `account_id` in use.
   - `state.bundle_hash` equals SHA-256 of the served bundle.
   - Every served certificate verifies under the identity key, and `state.device_set_hash` equals the hash computed from the served non-revoked certificates with `device_kind` ≠ 4. Without this check the server could hide an enrolled device, such as an attacker's, from the new device's device list.
   - `state.settings_hash` equals SHA-256 of the served `ACCOUNT_SETTINGS` (or `settings_seq = 0` and none is served).
   - `state.kdf_id` equals the `kdf_id` used.
   - The epochs in `state` equal those used in the `E_srv` context.
   - Each self-grant opens with the `account_key_epoch` from `state` in its context.
7. **Enrolment.** The client generates the device keys and signs the device certificate with the identity key. It writes `E_dev` and `E_local` locally (one more Argon2id run, once); neither is uploaded. It uploads the certificate together with a new `account-state` (`state_seq + 1`, new `device_set_hash`), which the server applies by compare-and-swap.
8. The server pushes "new device enrolled" to every other device. Each verifies the certificate against the signed device set and shows a notification with a one-click revoke.

### 11.3 Unlock on an enrolled device

1. **Offline part.** As in [§5.6](#56-offline-unlock): one Argon2id run (or a keystore unlock through `E_ks`), then open `E_dev`.
2. **Online part.**
   1. Authenticate with the device key ([§5.10](#510-sessions-after-authentication)).
   2. Fetch `account-state`, every bundle with `bundle_seq` above the cached one, the device certificates and revocations, and `ACCOUNT_SETTINGS` if `settings_seq` changed.
   3. If the state's `identity_epoch` is higher than the cached one, run step 3 before anything else. Otherwise verify the state with the cached identity key.
   4. Check, as in [§11.2](#112-login-on-a-new-device-server-mode) step 6: `account_id`, `bundle_hash`, `device_set_hash`, `settings_hash`.
   5. If `state_seq` or `settings_seq` is lower than the stored value, warn "possible rollback by the server" and go read-only.
3. **If `identity_epoch` increased** (a full rotation happened elsewhere):
   1. Walk the fetched bundles from the cached `bundle_seq` upwards. Each must name its predecessor in `prev_bundle_hash`, carry a valid self-signature, and, where the identity keys change, also a valid signature by the preceding identity key.
   2. Show the new identity fingerprint ([§10.3](#103-public-key-authenticity)) and require the user to confirm it on this device. A revoked-but-compromised device holds the old identity key and could have produced this chain ([§11.6](#116-key-rotation), "Known limitation"); the user's confirmation, ideally against another of their devices, is the check.
   3. Verify the new `account-state` and this device's re-issued certificate under the new identity key.
   4. Only then replace the cached identity key and bundle. From now on, statements signed only by the old key are rejected (threat model INV-30).

   If the user declines or any check fails, the device stays read-only, keeps the old key, and shows why.
4. **If `account_key_epoch` increased** (a rotation happened elsewhere):
   1. Fetch this device's `ACCOUNT_KEY_DEVICE_GRANT`s for every epoch between the cached and the current one, and open them in epoch order with the device X25519 key and the device-grant PSK ([§10.1](#101-hpke-key-wrapping)).
   2. Verify each grant's signature chains to a device certificate in the current signed device set.
   3. Re-wrap `E_local` under the **same** `local_unlock_key`, `E_ks` if present, and `E_dev`. No Argon2id is needed.
   4. Fetch the new `E_id` and self-grants (Server mode), or read them from the rotation's key records in the relay (On-device mode, [§11.6](#116-key-rotation) step 9).
5. **If `password_epoch` increased** (password or SK changed elsewhere):
   - **Server mode.**
     1. Prompt immediately for the new password, and the new SK if it changed.
     2. Run an OPAQUE login ([§11.2](#112-login-on-a-new-device-server-mode) steps 2–6).
     3. Re-create `E_local` with a new `device_salt`.
   - **On-device mode** (no OPAQUE record exists):
     1. Open this device's `PASSWORD_VERIFIER_GRANT` for the new `password_epoch` (device X25519 key plus password-verifier PSK) and check its signature against the changing device's certificate. It carries the changing device's new `E_local` record (`device_id`, `device_salt`, `kdf_id`, envelope) and, if the SK changed, the new SK.
     2. Prompt for the new password. Compute `pw_in'` with the new SK and check it by opening the carried `E_local` record: Argon2id with that record's salt, then HKDF with that record's `device_id`. It must yield the account key this device already holds.
     3. Re-create this device's own `E_local` with a new `device_salt` (the second Argon2id run), and store the new SK.
   - In both modes: if the user cannot provide the new password, lock and delete `E_local` and `E_ks`. The encrypted cache stays.
   - **Only the new password known.** Step 1 then fails, because `E_local` is still under the old password. In Server mode the client falls back to an OPAQUE login with the new password and SK ([§11.2](#112-login-on-a-new-device-server-mode) steps 2–6), which yields the account key from `E_srv`, and then continues with this step. In On-device mode the verifier grant is sealed to the device key inside `E_dev`, so the device needs the old password once, or a keystore unlock; the UI asks for "the password you used before" and says why. A user who remembers neither pairs the device again from another device.

   The old password stops working on this device as soon as the device is online.

### 11.4 Web vault

- **Server mode.** Every session is an OPAQUE login ([§11.2](#112-login-on-a-new-device-server-mode) steps 1–6). There is no `E_local` and no durable device.
- **Signing ops.** The web vault generates an **ephemeral device** key pair in memory, with a certificate signed by the identity key, `device_kind = 4`, and `expires_at` = now + 12 h, so that its ops are signed.
  - The certificate is uploaded, but it is **not** part of the signed device set and publishes no new `account-state`. Peers verify it by the identity-key chain and its expiry against the op's HLC ([§10.2](#102-ed25519-signatures-and-signed-statements)).
  - A web login does not trigger the "new device enrolled" alarm of [§11.2](#112-login-on-a-new-device-server-mode) step 8. The server sends enrolled devices an informational "web vault session started" notice instead. It is not signed, so a malicious server can suppress it (threat model AR-9).
- **Storage.** Nothing is persisted, except the SK if the user opted in.
- **On-device mode.** The web vault is disabled (ROADMAP §4.6).

### 11.5 Master password or Secret Key change

**Server mode:**
1. **Re-authenticate.** On an unlocked, online device, run an OPAQUE login with the current password. The server marks the session fresh for 5 minutes.
2. **New inputs.** The user enters the new password. Optionally, generate a new SK. Compute `pw_in'`.
3. **OPAQUE registration** under the same `credential_identifier = account_id`, with the current preferred `kdf_id` → `(upload', export_key')`.
4. **Build the new state:**
   - `E_srv'` under the new `server_unlock_key`, with context `password_epoch + 1`.
   - `account-state'` with `state_seq + 1` and `password_epoch + 1`.
5. **Commit.** `POST` everything as one atomic replace. The server swaps the record, deletes the old `E_srv`, and ends all *OPAQUE* sessions. Device sessions continue, and those devices pick up the new epoch ([§11.3](#113-unlock-on-an-enrolled-device) step 5).
6. **Locally.** Create a new `device_salt` and a new `E_local` (Argon2id). If the SK changed, produce a new Emergency Kit.

**On-device mode** (M4). There is no OPAQUE record, so the other devices need another way to learn the new password's verifier:
1. **Re-authenticate.** A local unlock with the current password on this device within the last 5 minutes.
2. **New inputs.** As above.
3. **Build:**
   - this device's new `E_local` (new `device_salt`, one Argon2id run);
   - `account-state'` with `state_seq + 1` and `password_epoch + 1`;
   - for every other device in the signed device set, a `PASSWORD_VERIFIER_GRANT`: HPKE PSK mode to that device's X25519 key ([§10.1](#101-hpke-key-wrapping)), carrying this device's new `E_local` record (`device_id`, `device_salt`, `kdf_id`, envelope) and the new SK if it changed, signed as a `key-grant`.
4. **Commit.** Upload the state (compare-and-swap) and the grants to the `auth` domain. Receiving devices follow [§11.3](#113-unlock-on-an-enrolled-device) step 5.
5. **Backup file.** The M4 backup file's password wrap is under the old password and SK. The client re-wraps it in the next backup it writes. Older backup files still open with the old password and SK, and the UI says so.
6. If the SK changed, produce a new Emergency Kit.

The verifier grants carry a password-derived wrap, but sealed to device keys with a PSK from the account key. The server holds nothing it can test a password guess against (threat model INV-28), even with a future quantum computer.

**Argon2id runs.** Server mode: three on the changing device (re-authentication, registration, local wrap), as threat model INV-6 lists. On-device mode: two on the changing device (re-authentication, local wrap) and two on each other device (checking the carried record, its own local wrap).

**Rotation.**
- **Password change:** the account key is **not** rotated by default. If the password was changed because it leaked, the UI offers "also rotate keys", which runs [§11.6](#116-key-rotation) (threat model INV-19). A malicious server could keep the old `E_srv`, but opening it needs the old password *and* the SK.
- **SK change:** runs a standard rotation ([§11.6](#116-key-rotation)) **by default**, with an explicit opt-out. A new SK is usually issued because the Emergency Kit was exposed. Without a rotation, any old `E_srv` in a DB backup still opens with the old SK and the old password, and yields the current account key. The client already holds the account key and is re-registering anyway; the extra cost is O(items) small re-wraps.

### 11.6 Key rotation

**Triggers:** device revocation ([§11.8](#118-device-revocation)), recovery ([§11.9](#119-recovery-with-the-emergency-kit)), an SK change ([§11.5](#115-master-password-or-secret-key-change)), a switch to On-device mode ([§5.7](#57-on-device-sync-mode)), suspected compromise, or the user asking for it. There are two levels:
- **Standard:** account key and vault keys.
- **Full:** also the identity keys. This is the default when a lost or stolen device is revoked.

1. **Re-authenticate.** A fresh OPAQUE session in Server mode; an unlocked device in On-device mode.
2. **Generate new keys:** account key' (`account_key_epoch + 1`), and for each owned vault a vault key' (`vault_key_epoch + 1`). For full rotation, also new identity keys (`identity_epoch + 1`).
3. **Re-wrap**:
   - every item key under its vault key' (`ITEM_KEY_WRAP` at the new `vault_key_epoch`), **copying its `created_vault_key_epoch` unchanged**. This is O(items) small envelopes, and item contents are not re-encrypted.
   - vault self-grants under account key' (context `account_key_epoch + 1`, `vault_key_epoch + 1`).
   - `E_id` under account key'.
   - retired secret keys, i.e. old identity and old mail keys needed for old HPKE ciphertext, under account key' as `RETIRED_SECRET_KEY`.
   - `MAIL_SECRET_KEY` (M6) and `ACCOUNT_SETTINGS` under account key'. The settings get `settings_seq + 1`.
4. **Server wrap** (Server mode): `E_srv'` under the `export_key` from step 1.
5. **Recovery.** A new recovery code, `E_rec'` and `H_rec'`, `recovery_epoch + 1`, and a new Emergency Kit the user must save. The old code stops working. The user MAY instead type the current recovery code to keep it; the client then derives the wrap key from it.
6. **Device grants.** For each remaining device: an `ACCOUNT_KEY_DEVICE_GRANT`, sealed in HPKE PSK mode to that device's X25519 key with the device-grant PSK derived from the *old* account key ([§10.1](#101-hpke-key-wrapping)), and signed as a `key-grant` by the rotating device.
7. **Identity (full rotation only).**
   - A new bundle (`bundle_seq + 1`, `prev_bundle_hash` = the old bundle), signed by the new *and* the old identity key.
   - New device certificates for every remaining device, signed by the new identity key.
8. **State.** `account-state'` with every changed epoch, `settings_seq`, `bundle_hash` and `device_set_hash`, signed by the identity key of the new `identity_epoch`: the **new** key in a full rotation, the unchanged key in a standard one. The committed vectors cover both cases.
9. **Upload.**
   - **Server mode:** everything in one atomic request. The server deletes the superseded wraps, except that the re-wrapped item keys *replace* the old `ITEM_KEY_WRAP` rows ([§4.2](#42-key-inventory)).
   - **On-device mode:** the account-level objects (state, bundle, certificates, grants, `E_id'`, retired keys, mail key, settings) go to the `auth` domain in one compare-and-swap. The vault-level objects (self-grants', re-wrapped item keys) go out as key records in a `RELAY_BATCH` under the **new** relay key ([§11.12](#1112-relay-ops-on-device-mode-m4)); other devices can open it once they have opened their grant. A device that misses the batch before the TTL is stale and re-syncs from a peer, which transfers the same objects.
10. **Other devices** pick up the change at their next unlock ([§11.3](#113-unlock-on-an-enrolled-device) steps 3 and 4). The relay key changes automatically, because it is derived from the account key and epoch.

**Lazy item-key rotation.** Old item keys stay readable, because they were re-wrapped in step 3, but they must not encrypt anything new: the revoked device knows them. The rules:
- **Current vault epoch.** A device learns a vault's current `vault_key_epoch` from the self-grant that opens under the account key of the `account_key_epoch` in the verified `account-state`, never from server metadata. The self-grant's context binds both epochs. In M1–M8 a vault key rotates only together with the account key, so exactly one vault key per vault opens under the current account key. M9 member removal rotates a vault key alone, and the M9 ADR must carry `vault_key_epoch` in a signed vault statement.
- **Writer rule (MUST).** Before encrypting an op or snapshot under an item key, the writer opens the item's current `ITEM_KEY_WRAP`. If `created_vault_key_epoch` is lower than the current `vault_key_epoch`, it generates a fresh item key (`created_vault_key_epoch` = current), carries the new wrap with the op, and writes a full snapshot under the new key. This holds for every writer, including a device enrolled after the rotation that never saw the old epoch, and it holds when the server hides the fresh wrap and serves only the re-wrapped old one.
- **Reader rule.** The `key_id` in an op or snapshot envelope header must equal the key id derived from an item key the reader unwrapped for that item. An op under an unknown item key waits for its wrap and, if the wrap never arrives, is reported like a missing op.
- "Re-encrypt everything now" is an explicit action that costs O(vault size).

**Known limitation.** A *compromised* revoked device holds the old identity key and could race its own "rotation". Remaining devices accept a rotation only if its grants are signed by a device in the new signed device set, and they show the new identity fingerprint for the user to confirm on each device ([§11.3](#113-unlock-on-an-enrolled-device) step 3). The details belong to the M4 ADR on device management. Revocation never takes back data the device already had.

### 11.7 New device in On-device mode

This is an outline. M4 fixes it in its own ADR. It is audit target 7 ([§1](#1-goals-non-goals-and-rules)).

**Attacker.** Someone who photographed the QR code (so knows `pairing_secret` and `k_pair`) and controls the relay. The SAS must stop them from pairing their own keys, and the transfer must stay unreadable to them even when the user pairs the real device.

**QR path** (primary). The QR carries the pairing secret over an out-of-band channel, the camera. A commit-then-reveal SAS authenticates the new device's keys, and all key material then goes to those keys only:
1. The existing device E shows a QR code containing:
   - `version`, `server_origin`, `account_id`, E's `device_id`
   - `pairing_id` (16 B), `pairing_secret` (32 B)
   - `bundle_hash`

   The `pairing_secret` never reaches the server.
2. **Commit.** The new device N derives `k_pair`, generates its device keys and a random 16-byte `r_N`, and computes the commitment `c_N` ([§4.3](#43-derivations)) over its two public keys and `r_N`. It sends `Envelope(k_pair, PAIRING_TRANSFER, direction 1, message 0)` over the relay, carrying N's public keys, device name and `c_N`. `r_N` stays secret for now.
3. **Challenge.** E opens the first direction-1 message 0 it receives for this `pairing_id`, which proves the sender holds the QR secret, and ignores every later one. It generates a random 16-byte `r_E` and sends it in `Envelope(k_pair, PAIRING_TRANSFER, direction 2, message 0)`.
4. **Reveal.** N sends `r_N` in `Envelope(k_pair, PAIRING_TRANSFER, direction 1, message 1)`. E checks it against `c_N` and aborts on a mismatch.
5. **Compare.** Both devices show the 6-digit pairing SAS over `k_pair`, `pairing_id`, N's public keys, `r_N` and `r_E` ([§4.3](#43-derivations)). The user confirms on **both** devices that the digits match (threat model INV-29, ROADMAP §4.6). On a mismatch or a timeout, both abort and E discards the pairing secret.
   - **Why this ordering.** Each side's contribution is fixed before it sees the other's. Whoever reached E first had to commit to their keys and `r_N` before E chose `r_E`, so E's code is uniformly random to them. On N's side, the attacker must hand N some `r_E'` before N reveals `r_N`, so N's code is uniformly random too. Each attempt succeeds with probability 10^-6, and each needs a new QR. This is the standard commit-then-reveal SAS pattern (Vaudenay, CRYPTO 2005; not re-verified for this document). An earlier draft let E send a bare nonce that N accepted from anyone holding `k_pair`; an attacker could then grind that nonce (about 10^6 HKDF calls) so that N's code matched E's. The commitment removes that freedom.
6. **Certify.** Only after confirmation does E sign N's device certificate.
7. **Transfer.** Everything E sends from now on is **sealed to the X25519 key the SAS covered**: `PAIRING_TRANSFER_SEALED` envelopes, HPKE PSK mode with `psk = k_pair` ([§10.1](#101-hpke-key-wrapping)), context `pairing_id ‖ u32 chunk_index ‖ u32 total_chunks`. Opening a chunk needs both N's private key and the QR secret, so the attacker above learns nothing even from a correctly confirmed pairing. `total_chunks` is fixed when E starts sending and bound into every chunk, so the relay cannot silently drop the tail.
   - **Chunk 1:** the account key, the SK, N's certificate, the signed `account-state` and bundle, and E's `E_local` record (`device_id`, `device_salt`, `kdf_id`, envelope), used as a password verifier.
   - **Chunks 2 to `total_chunks`:** every current `VAULT_KEY_SELF_GRANT` and `ITEM_KEY_WRAP`, then what [ADR 0012](adr/0012-sync-engine.md) §9 lists: a fresh signed snapshot of every item, all tombstones, the per-device high-water marks and the per-sender `batch_seq` cursors.
   - N fetches the account-level objects (`E_id`, retired keys, mail key, `ACCOUNT_SETTINGS`) from the `auth` domain, as in Server mode ([§4.2](#42-key-inventory)), and verifies them against the transferred state.
8. **Verify.** N checks that the bundle hashes to the QR's `bundle_hash`, that `E_id` opens and matches the bundle, and that the state verifies. It asks for the master password and verifies it by opening E's `E_local` record, then creates its own `E_local` (two Argon2id runs, once).
9. **Finish.** N refuses to finish enrolment until chunks 1 to `total_chunks` have all arrived and opened. E publishes the new `account-state` with N added to the device set. The relay deletes the pairing session after 10 minutes.

**Short-code path** (no camera). This needs a PAKE (e.g. CPace or SPAKE2) or the same commit-then-reveal SAS. **Not specified here, and no crate has been chosen.** It is an M4 ADR item. The same rules apply to it: no key material moves before both devices confirm the SAS, and all of it is sealed to the confirmed key.

**Stale re-sync** ([ADR 0012](adr/0012-sync-engine.md) §9) uses the same chunked transfer as step 7, as `RESYNC_TRANSFER`: HPKE PSK mode to the stale device's certified X25519 key, with the re-sync PSK from the account key, and the chunk count bound in the context. There is no SAS, because both devices are already in the signed device set. A stale device first opens any pending device grants, so both sides hold the same account key.

### 11.8 Device revocation

1. **Sign the revocation.** A remaining device (unlocked, fresh re-auth) signs a `device-revocation` with `last_accepted_device_seq` equal to the highest op sequence it has seen from that device. It also signs a new `account-state` whose `device_set_hash` no longer includes the revoked device.
2. **Server.** It deletes the revoked device's sessions, rejects its device authentication, and in On-device mode removes it from the relay acknowledgement set.
3. **Rotate** ([§11.6](#116-key-rotation)): full rotation for a lost or stolen device, standard rotation for a device that was wiped and handed over.
4. **Peers.** They reject that device's ops with `device_seq > last_accepted_device_seq`.

Revocation protects **future** data only. The UI says this in one sentence.

### 11.9 Recovery with the Emergency Kit

**Server mode:**
1. The user enters: login name, recovery code (`RVR1-` format, same encoding as the SK, check label `recovery-code/check`).
2. `POST /api/v1/recovery/start {login_name, recovery_auth_token}`. The server rate-limits, compares `SHA-256(token)` in constant time, and treats unknown names identically ([§5.9](#59-account-enumeration)).
   - On success it opens a **pending recovery**.
   - It notifies every enrolled device, and the account email if the server has mail configured.
   - It starts the waiting period: default **72 h**, admin-configurable from 0 to 30 days. A single-user instance may set 0.
   - Any enrolled device with a device-authenticated session can cancel the pending recovery.
3. After the wait: `POST /api/v1/recovery/complete {login_name, recovery_auth_token}`. The server returns `E_rec`, the epochs, `E_id`, the bundle, the state, the device certificates, the self-grants and the item-key wraps, plus a recovery-only session with a 10-minute TTL that covers the rotation upload in step 5.
   - The waiting period is server-enforced. A malicious server could skip it, but that gains the server nothing, because it still lacks the code.
   - What the wait defends against is a thief holding the printed kit (threat model Q-15).
4. The client derives the recovery wrap key and opens `E_rec` to get the account key. It then opens `E_id` and verifies the bundle and state as in [§11.2](#112-login-on-a-new-device-server-mode) step 6.
5. The client generates a **new SK and a new recovery code**. The old kit is assumed lost or compromised. The user sets a new master password. The client then:
   - runs a **standard rotation** ([§11.6](#116-key-rotation)) **by default**: new account key and vault keys, item keys re-wrapped, PSK-mode device grants to every remaining device;
   - registers OPAQUE and builds new `E_srv`, `E_rec` and `H_rec`, with `password_epoch + 1` and `recovery_epoch + 1`, and a new signed state;
   - enrols itself as a device, as in [§11.2](#112-login-on-a-new-device-server-mode) step 7.

   "Skip rotation" is an explicit opt-out. Why rotate by default: any copy of the old `E_rec` opens with the old code and yields the account key. Routine DB backups taken before the recovery hold such copies, and so does a server that ignored the deletion. Without a rotation, kit thief plus old backup equals every future write. The cost is O(items) small re-wraps; the client already holds the account key and is re-registering anyway.
6. The server replaces everything atomically, ends every session, and notifies every device and the account email that "this account was recovered".
7. Other devices must log in again with the new password and SK ([§11.3](#113-unlock-on-an-enrolled-device) steps 4 and 5).

If the user believes the kit was stolen, the UI offers a full rotation instead, which also replaces the identity keys.

**On-device mode.** There is no server copy. The M4 encrypted backup file holds the vault envelopes plus the backup key, wrapped twice:
1. under `HKDF(Argon2id(pw_in, backup_salt))`, i.e. password **and** SK, and
2. under the recovery wrap key.

So a new device can recover with the backup file plus either (password + SK) or the recovery code. No backup file and no device means the data is gone. A recovery through the recovery code issues a new code and SK and rotates the account key by default, as in Server mode.

**No escrow.** Nothing in v1.0 lets anyone but the user recover an account. Emergency access (M9) and org admin recovery (M10) need their own ADRs and explicit user consent ([ADR 0008](adr/0008-account-recovery.md)).

### 11.10 Public share link: creation (M5)

1. The owner picks the fields to share, the expiry, max views, and an optional passphrase or recipient emails.
2. The client generates `share_id` (16 B) and `share_secret` (32 B).
3. With a passphrase: `pp_key = Argon2id(NFC(pp), share_id, 1, 32)`.
4. The client derives `share_key`, `link_token` and `access_token` ([§4.3](#43-derivations)). It builds the snapshot from the chosen fields only, frames it with padding, and encrypts it as `Envelope(share_key, SHARE_SNAPSHOT, share_id ‖ flags)`.
5. `POST /api/v1/shares` with `{share_id, envelope, SHA-256(link_token), SHA-256(access_token), expiry, max_views, flags, recipient_emails?}`. **This is everything the server stores**, plus an owner reference, created_at, view count and revoked flag.
6. The link is `https://<server>/s/<b64url(share_id)>#1<flag digit><b64url(share_secret)>`. The fragment is never sent to the server.
7. The owner's copy of `share_secret` goes into the item's encrypted data, so the link can be shown again. Revoking deletes the server row.

### 11.11 Public share link: opening (M5)

1. The recipient page reads `location.hash`, then immediately calls `history.replaceState` to strip it. It sets `Referrer-Policy: no-referrer`.
2. If the flag says so, the page asks for the passphrase and computes `pp_key`, taking about 0.3 s in wasm.
3. Only after the recipient clicks "Reveal" does the page derive `link_token` and `access_token` and send `POST /api/v1/shares/<id>/open {link_token, access_token, email_otp?}`. Nothing is fetched and no view is counted before that click, so link-preview bots and mail scanners do not burn views (threat model INV-33).
4. The server compares both token hashes in constant time and checks expiry, revocation and views.
   - **Wrong `link_token`:** the caller does not hold the URL fragment. The answer is "not found", rate-limited per IP and per share, and it **never counts toward the burn**. The `share_id` sits in the URL path, which proxies, access logs, link-preview fetchers and history sync all see; without this split, anyone with only the path could burn any share with 10 bad requests (threat model Q-20, AR-23).
   - **Right `link_token`, wrong `access_token`:** a wrong passphrase. After **10 such failures** the share is burned.
   - **Both right:** the server increments `views` atomically and returns the envelope.
   - Because `access_token` depends on the passphrase, **passphrase guessing is online-only**. Someone holding just the link cannot download the ciphertext to guess offline. The server holds the ciphertext but not `share_secret`, so it cannot guess either. For a share without a passphrase both tokens come from `share_secret` alone, so the burn never triggers for an honest client.
5. The client checks the commitment, decrypts, and renders.

**Limits.** Honest limits, stated in the UI:
- View limits and email restriction are enforced by the server, so a malicious server can ignore them.
- A recipient can copy what they see.
- The recipient page is JavaScript served by the same server ([§14](#14-what-a-malicious-server-can-still-do)).

### 11.12 Relay ops (On-device mode, M4)

1. Each op is created as in Server mode:
   - an `ITEM_OP` envelope under the item key;
   - an `op` signature by the authoring device;
   - a strictly increasing `device_seq` per device.
2. **Batching.** Records are grouped into a batch. The plaintext is `n × (u8 record_type ‖ bytes(record))`, framed and padded ([§8.5](#85-plaintext-framing-and-padding)), and sealed as `Envelope(relay_key, RELAY_BATCH, account_id ‖ sender device_id ‖ batch_seq ‖ account_key_epoch)`. `batch_seq` is strictly increasing per device. Record types:
   - `0x01`: a signed op record ([ADR 0012](adr/0012-sync-engine.md) §3), including its item-key wrap when it carries one;
   - `0x02`: a key record: one `VAULT_KEY_SELF_GRANT` or `ITEM_KEY_WRAP` envelope with its cleartext locator ([§4.2](#42-key-inventory)). Rotations use these ([§11.6](#116-key-rotation) step 9). Key records are authenticated by their own AEAD and by the batch envelope, which only account devices can produce.

   [ADR 0012](adr/0012-sync-engine.md) §8 uses both record types.
3. **What the server sees:** the batch header (account, sender device, `batch_seq`, epoch), the padded size, and timing. It does not see item ids or op counts. It stores the batch until every active device has acknowledged it or the TTL expires ([ADR 0012](adr/0012-sync-engine.md)).
4. **Receivers:**
   1. Open the batch, which authenticates the header to account members.
   2. Verify every op signature against a non-revoked device certificate.
   3. Drop duplicates by `op_id`, and by `(device_id, device_seq)` against per-device high-water marks.
   4. Hold ops with a sequence gap until the gap fills or the TTL passes, then report "missing ops from device X".
   5. Reject ops from revoked devices past `last_accepted_device_seq`.
5. **Replay and withholding.** Replaying old batches has no effect, because of the high-water marks. Withholding in the *middle* of a device's stream shows up as a gap. Withholding a *suffix*, or freezing a device on an old state, looks exactly like silence and is not detected until devices compare heads (threat model AR-5). The planned mitigation is the "vault state fingerprint" Should in threat model §5.6.

### 11.13 Mail ingress (M6)

1. The `smtp` role receives the message and runs spam and abuse filtering **on plaintext**, before encryption (ROADMAP §4.8). This includes rspamd over localhost HTTP and SPF/DKIM/DMARC checks.
2. It resolves alias → account through `api` ([ADR 0010](adr/0010-server-shape.md)) and gets the account's current key bundle plus the chain since the `bundle_seq` it last saw. A self-signature alone proves nothing, because anyone can mint one. So `smtp` keeps a small **pin store** on its own volume, never in the DB: per account, the identity Ed25519 key and the highest `bundle_seq` it has accepted.
   - First mail for an account: verify the self-signature and pin (TOFU).
   - Later: accept a bundle only if it chains from the pinned one by `prev_bundle_hash`, with increasing `bundle_seq`, valid self-signatures and, where the identity keys change, the preceding identity key's signature ([§10.2](#102-ed25519-signatures-and-signed-statements)). Anything else is refused with a temporary SMTP failure and logged for the admin.
   - It then takes the mail X25519 key.

   An attacker who controls `api` or the DB but not `smtp` can no longer substitute the mail key for accounts `smtp` has already seen. They still win on first contact, if the pin store is wiped, or if they also hold a superseded identity key (a stolen device's), because `smtp` has no user to confirm an identity change and must accept a correctly chained one. Clients check that every `MAIL_MESSAGE` header names their current (or a retired) mail key id and alert otherwise; that only catches a careless substitution, since an attacker can re-seal to the real key after reading.
3. It builds the plaintext `bytes(metadata) ‖ raw MIME`, framed and padded, where the metadata holds the authentication results, spam score, envelope-from and rcpt-to. It seals `HPKE(mail_pk, MAIL_MESSAGE, account_id ‖ alias_id ‖ message_id ‖ received_at_ms)`.
4. Every plaintext buffer lives in a `Zeroizing<Vec<u8>>` and is dropped immediately. The ciphertext is stored with only alias id, receive time, size bucket and retention date in clear.

**Honest limits:**
- The server sees every message in plaintext at ingress, and so does rspamd, whose logging must be configured not to store bodies.
- Encryption protects stored mail from a *later* breach only.
- There is no forward secrecy: whoever gets the mail secret key can read all stored mail. Short retention limits the exposure.

### 11.14 Encrypted export (M1)

- **Key.** The user chooses an **export password**, separate from the master password; the SK is not used, so the file is portable. `export_salt`, `export_id` and `created_at` are generated, and the file key is derived as in [§4.3](#43-derivations).
- **File.** JSON: `{"format":"rizzy-vault-export","version":1,"kdf_id":1,"export_salt":…,"export_id":…,"created_at":…,"data":"<b64url Envelope(file_key, EXPORT_FILE, …)>"}`.
- **Import.** The importer rejects any `kdf_id` not on its allow-list.
- **Plaintext export** (JSON or CSV) exists, behind the "scary warning" from ROADMAP §4.2.

---

## 12. Randomness, memory hygiene and side channels

### 12.1 Randomness

- **Injection.** `rizzy-core` and `rizzy-sync` never reach a randomness source themselves. Every function that needs randomness takes `&mut impl rand_core::CryptoRng` (rand_core 0.10). This is the "no I/O" contract in `crates/rizzy-core/src/lib.rs`. In rand_core 0.10, `CryptoRng` is `TryCryptoRng<Error = Infallible>`: it has no error channel, and hpke's `*_with_rng` functions take the same trait.
- **Platform crates** (CLI, server, Tauri shell, UniFFI bindings, wasm bindings) supply an RNG backed by `getrandom` 0.4, i.e. the OS CSPRNG: getrandom's `SysRng` (feature `sys_rng`) wrapped in rand_core's `UnwrapErr`. On `wasm32-unknown-unknown` the **wasm bindings crate alone** enables getrandom's `wasm_js` feature, which uses `crypto.getRandomValues`. The getrandom README says not to enable it in libraries.
- **CI enforcement.** `cargo check-wasm` fails if a dependency pulls getrandom into `rizzy-core` without a backend. This was reproduced in M0 with hpke's default features.
- **opaque-ke** gets its rand_core 0.6 RNG through the adapter in [§5.1](#51-ciphersuite-and-key-stretching), written against `opaque_ke::rand`. No other rand_core 0.6 use is allowed.
- **What the RNG produces:** all keys, nonces, ids, salts, recovery codes, share secrets, pairing secrets and challenges. Nothing is derived from time, counters or ids where this document says "random".
- **No direct `rand` dependency in `rizzy-core`**: no `rand::rng()` and no `thread_rng`. `rand` 0.8.8 is present only transitively through opaque-ke, with default features off, which leaves out `thread_rng` and getrandom ([§5.1](#51-ciphersuite-and-key-stretching)). RUSTSEC-2026-0097 is a reminder that convenience RNG paths have their own bugs. Deterministic RNGs (e.g. a seeded ChaCha20 RNG) are dev-dependencies for test vectors only.
- **An RNG failure aborts the process.** `UnwrapErr` panics on an OS RNG error, and release builds use `panic = "abort"`, so the process dies (in wasm, the instance traps). There is no fallback and no retry with a weaker source. A failing OS CSPRNG is not a condition we can recover from safely.

### 12.2 Memory hygiene

- **Wrapper types.** All secret material lives in types that zeroize on drop: `Zeroizing<[u8; N]>`, `secrecy::SecretBox`, or our own newtypes deriving `ZeroizeOnDrop`. This covers passwords, `pw_in`, SK, `export_key`, unlock keys, account/vault/item keys, private keys, recovery codes, share secrets and plaintext buffers.
- **No accidental copies.**
  - Secret types do **not** implement `Clone`, `Copy`, `Display` or `serde::Serialize`.
  - `Debug` is implemented by hand and prints `[REDACTED]`. This is compatible with the workspace lint `missing_debug_implementations`.
  - Exposing a secret takes an explicit `expose_secret()` call, which is easy to grep for.
  - Secret `Vec`s are allocated at their final capacity; a reallocation leaves the old copy behind.
- **Argon2 memory is our job.** `argon2` 0.6.0's `hash_password_into` allocates the m-KiB block matrix internally and frees it **without wiping it**, even with the `zeroize` feature; that feature wipes only the initial and final hash. This was verified by reading `src/block.rs` and `src/lib.rs`. Our KSF and local KDF therefore call `hash_password_into_with_memory` with our own `Zeroizing<Vec<argon2::Block>>`, which is wiped on drop. There is a test for this.
- **Crate features.** `chacha20poly1305`, `argon2` and `ed25519-dalek` are built with their `zeroize` features.
- **Logs and panics.**
  - No secret or plaintext is ever logged, formatted into an error, or included in a panic message.
  - Release builds use `panic = "abort"`, as the workspace profile already sets.
  - Every native binary disables core dumps at startup (threat model INV-60). Otherwise an abort, or an RNG failure ([§12.1](#121-randomness)), writes the process memory, keys and plaintext included, to disk.
  - Server logging uses an allow-list of fields. Request and response bodies on auth, key and share endpoints are never logged.
- **Limits we cannot fix; the UI and docs say so:**
  - **JavaScript strings** (the password field's `value`) are immutable and garbage-collected, so they cannot be wiped. The web client copies the password into a `Uint8Array` via `TextEncoder`, passes it to wasm, and zeroes the array. The string itself lives until GC.
  - **wasm linear memory** can be wiped from Rust, but the engine may copy it when memory grows (U). A 64 MiB Argon2 run grows the memory, and wasm memory never shrinks.
  - **No `mlock`.** It needs `unsafe` or a libc wrapper, and does not exist in wasm. Swap and hibernation files can hold secrets. We assume OS full-disk encryption.
  - **Allocators.** Bitwarden's SDK ships a zeroizing global allocator. Writing one needs `unsafe` (`GlobalAlloc`), which the workspace forbids. This is an open question ([ADR 0009](adr/0009-crypto-dependency-policy.md)).

### 12.3 Side channels

- **Constant-time comparisons.** Every comparison of secret or secret-derived values uses `subtle::ConstantTimeEq`: envelope commitments, token hashes (share, recovery), SK and recovery-code check values, and fingerprints when compared programmatically. `==` on such bytes is a review blocker.
- **Tags inside libraries.** Tag checks inside `chacha20poly1305`, `hmac` and opaque-ke are the libraries' own constant-time code.
- **No secret-dependent branches or lookups** in our code. This includes the Crockford Base32 encoder and decoder for the SK and recovery code (arithmetic mapping, no tables) and base64url for share fragments (`base64ct`).
- **Server-side token lookups** go by `SHA-256(token)` as an index key. Index timing reveals at most hash-prefix information, which is useless to an attacker.
- **Argon2id** uses data-independent addressing in its first half-pass. That is why the algorithm is Argon2id and not Argon2d.
- **Only the hard failure is observable.** A decryption failure returns the same error, and to a remote peer the same response, whether the commitment or the tag failed. [§8.3](#83-key-commitment) removes the multi-key oracle; this removes the "which check failed" oracle.

---

## 13. Post-quantum readiness

**What is already PQ-safe at v1.0:** everything symmetric.
- 256-bit keys, XChaCha20-Poly1305, HKDF-SHA-256.
- Grover leaves about 128-bit security.
- **A personal vault at rest is protected only by symmetric crypto.** The account key is wrapped by password- or recovery-derived symmetric keys. Personal vault keys are self-granted symmetrically. The HPKE objects that carry an account key or a vault (pending device grants, password-verifier grants, pairing and re-sync transfers) use PSK mode with a PSK derived from symmetric secrets ([§10.1](#101-hpke-key-wrapping)), so a quantum computer that breaks their X25519 still lacks the PSK. Without PSK mode this claim would be false for as long as any device grant sat unconsumed on the server.
- The recovery wrap was deliberately made symmetric, not HPKE, for this reason ([ADR 0008](adr/0008-account-recovery.md)).

**What is exposed to harvest-now-decrypt-later (HNDL):**

| Object | Exposure | Mitigation in v1.0 |
|---|---|---|
| OPAQUE transcripts | A CRQC plus broken TLS recordings allows a DLog on the OPRF, then offline password guessing | The SK makes guessing infeasible ([§5.5](#55-offline-attack-analysis)) |
| `ACCOUNT_KEY_DEVICE_GRANT`, `PASSWORD_VERIFIER_GRANT` (HPKE X25519, PSK mode) | Breaking X25519 alone reveals nothing: the PSK comes from the previous (or current) account key | PSK mode. Grants are also deleted once consumed |
| `PAIRING_TRANSFER_SEALED`, `RESYNC_TRANSFER` (M4) | Same | PSK mode (`k_pair` from the QR; the account key). Transient on the relay |
| `MAIL_MESSAGE` (HPKE X25519) | Stored mail becomes readable | Short retention. PQ HPKE post-1.0 |
| `VAULT_KEY_MEMBER_GRANT` (M9) | Shared vault keys | M9 decision: should ship with 0x11 if X-Wing is an RFC by then |
| Ed25519 signatures | Forgery with a CRQC, in the future only; no HNDL | `sig_alg` 0x02 reserved for hybrid Ed25519 + ML-DSA |

**Status of PQ components (as of 2026-09-25):**
- ML-KEM is FIPS 203 (final).
- X-Wing is draft-connolly-cfrg-xwing-kem-10, not an RFC.
- draft-ietf-hpke-pq is at -05 (L).
- `ml-kem` 0.3.2 and `x-wing` 0.1.0 have never been audited. `x-wing`'s README says "draft 06" while `hpke` 0.14.1 says draft-10, and we have not resolved the mismatch.

**Decision.** Hybrid PQ key wrapping (X-Wing via HPKE, `alg_id` 0x11) is a **Could, post-1.0** (ROADMAP §4.3). Nothing PQ ships in M1.

**What must exist from M1** so the migration in [§9.7](#97-how-a-migration-lands-pq-example) is an additive release, not a format break:
1. `alg_id` in every envelope, and per-purpose allow-lists ([§9](#9-envelope-format)).
2. Key bundles that hold a typed *list* of keys with a `pq_required` flag, not fixed `x25519` and `ed25519` fields ([§10.2](#102-ed25519-signatures-and-signed-statements)).
3. `sig_alg` in the signature container.
4. `rizzy-core` HPKE code written against a KEM enum, not against X25519 directly.
5. Labels versioned (`rizzy-vault/v1/…`).

The OPAQUE question stays open. There is no standard PQ OPAQUE. opaque-ke 4.1.0-pre adds a KEM-based `TripleDhKem`, which hardens the key exchange but not the OPRF. The SK is our PQ answer for password guessing.

---

## 14. What a malicious server can still do

The threat model's §5 and §8 ([THREAT_MODEL.md](THREAT_MODEL.md)) state the matching invariants (INV-1 to INV-69). This section maps the five attack classes from Scarlata, Torrisi, Backendal and Paterson, "Zero Knowledge (About) Encryption", ePrint 2026/058 (L; we read secondary coverage only, the paper itself was not reachable), to this design.

| Attack class | What we do | What remains |
|---|---|---|
| 1. Key escrow / account recovery | No escrow and no admin reset in v1.0. Recovery needs a 128-bit code that only the user holds, plus a cancellable waiting period | Kit + server access = account after the wait if no device cancels (by design; the kit says so) |
| 2. Unbound item-level encryption, swappable settings | AAD binds purpose, vault, item, op/snapshot header and epochs. Security settings sit in `ACCOUNT_SETTINGS`, and the signed state commits to their `settings_seq` and hash, so an older settings object is rejected. KDF id and epochs are signed and bound into the OPAQUE context. Item keys carry an authenticated creation epoch, so a stale key is never reused for new writes | The server can **withhold** ops. Only withholding in the middle of a device's stream shows up as a sequence gap; withholding a suffix, or freezing a device on an old state, looks like silence and stays hidden until devices compare heads (threat model AR-5; the "vault state fingerprint" Should in threat model §5.6 is the planned mitigation). It can **roll a fresh device back** to an older, validly signed state (existing devices detect it through `state_seq`). It can delete data |
| 3. Sharing and orgs: key substitution | Own keys are verified by decryption; device certificates chain to the identity key; the device set is signed and checked on login; bundles form a chain with `bundle_seq`; an identity-key change is a visible "safety number changed" event, and a fork is a hard alarm; fingerprints, TOFU pinning and signed grants (M9); `smtp` pins identity keys (M6); pairing uses a commit-then-reveal SAS and seals the transfer to the confirmed key (M4) | First-contact substitution when users skip fingerprint checks. Key transparency is post-1.0 |
| 4. Backward compatibility / downgrade | One algorithm per purpose, allow-lists, no negotiation, no legacy decrypt path | – |
| 5. KDF parameter downgrade | Compiled-in `kdf_id` table with a CI-checked floor | – |

**Beyond those five:**
- **Web-vault delivery.** In Server mode the server serves the web vault's JavaScript, and the share-open page's. A malicious or compromised server can serve a client that exfiltrates the password, SK and share fragments. 1Password's white paper admits the same (L). The fixes in progress, WAICT (Cloudflare/Mozilla) and WEBCAT (Freedom of the Press Foundation), are not deployable for ordinary users today (L). **The browser extension, desktop app, mobile apps and CLI do not load code from the server; recommend them.** A later mitigation could have the extension serve the web vault from its own package.
- **Metadata the server sees:**
  - login names and IP addresses
  - device count and kinds
  - vault and item counts
  - Padmé-padded sizes and timing of edits
  - share metadata (expiry, views, recipient emails)
  - alias ids and mail receive times and size buckets
  - sync mode
- **Availability.** The server can refuse service or delete everything. Backups (M4) are the answer; cryptography is not.

---

## 15. Testing

All of this lands with the code in M1. None of it is optional.

1. **Known-answer vectors (ours).**
   - `crates/rizzy-core/tests/vectors/*.json` is generated once from a seeded test RNG and committed. It covers every derivation in [§4.3](#43-derivations) (including every symmetric key id and every HPKE PSK), every envelope purpose in [§8.4](#84-aad-and-purposes), every signed statement in [§10.2](#102-ed25519-signatures-and-signed-statements) (including a standard and a full rotation's `account-state` and two-signature bundle), SK and recovery-code encoding, Padmé framing, and full signup → login → unlock transcripts.
   - Changing a vector requires a version bump and an ADR note.
2. **Upstream vectors.** Run against our pinned crates, not just trusted from their CI:
   - RFC 5869 (HKDF), RFC 9106 (Argon2id)
   - draft-irtf-cfrg-xchacha-03 (XChaCha20-Poly1305)
   - RFC 7748 (X25519), RFC 8032 (Ed25519)
   - RFC 9180 (HPKE, through hpke's `kat` test data for our suite, in Base and PSK mode)
   - RFC 9807 (OPAQUE, through opaque-ke's test vectors)
3. **Wycheproof.** Run the Wycheproof suites for XChaCha20-Poly1305, ChaCha20-Poly1305, HKDF-SHA-256, HMAC-SHA-256, X25519 and Ed25519 at a pinned commit of the repository. File names are to be confirmed in M1 (U).
4. **Property tests** (proptest):
   - encrypt/decrypt round-trips for all purposes;
   - any single-bit flip anywhere in an envelope → `DecryptError`;
   - wrong purpose, wrong ctx field, wrong key or wrong epoch → `DecryptError`, with the commitment check failing *before* the AEAD;
   - truncation at every length → error, never a panic;
   - `alg_id` outside the purpose's allow-list → rejected before any crypto;
   - parse → serialise is the identity.
5. **Negative protocol tests**, using a "malicious server" test double:
   - It returns `kdf_id` 0 or 2 (not allowed) → the client aborts before running the KSF.
   - It swaps item A's envelope into item B → rejected.
   - It serves an older `account-state` → rollback warning.
   - It substitutes the bundle public key → login aborts.
   - It hides an enrolled device from a new device's certificate list → `device_set_hash` mismatch, login aborts.
   - It serves a state whose `account_id` or `bundle_hash` does not match → login aborts.
   - It serves an older, validly encrypted `ACCOUNT_SETTINGS` that restores a deleted equivalence group or removes a pinned contact → rejected against `settings_hash` and `settings_seq`.
   - It serves an older, validly signed bundle (lower `bundle_seq`), or two bundles with the same predecessor → rejected, or fork alarm.
   - It replays ops → deduplicated. It withholds a middle op → gap reported.
   - After a revocation and rotation, a device enrolled *after* the rotation writes to an item; the server serves only the re-wrapped old item key → the writer generates a fresh item key, and no pre-rotation item key opens the new op.
   - It strips the SK from the flow → the login fails.
   - It passes `ksf: None` → our `Default` still uses `kdf_id` 1.
   - A phishing server relays OPAQUE messages to the real server under a different origin → the client's KE2 check fails.
   - Enumeration across a simulated KDF migration: the `kdf_id` answers for real and unknown names behave alike (each flips at most once, never back).
   - A kind-4 (web) certificate signs an op with an HLC past `expires_at_ms` → rejected.
   - A caller holding only a share's `share_id` sends 10 bad `link_token`s → the share is not burned.
   - Canary: the `E_dev`, `E_local` and `E_ks` envelope bytes never appear in any request body or server row (with threat model INV-15).

   Each test is tagged with the ETH attack class it covers.
6. **Pairing tests** (M4), with an attacker that holds the QR secret and controls the relay:
   - it reaches E first and tries to make both SAS codes match by choosing what it relays → matches only at the 10^-6 rate over many runs (statistical test with a reduced SAS space);
   - the user pairs the real N correctly → the attacker, holding the QR secret and all relay traffic, learns no key material;
   - the relay drops the last chunks → N refuses to finish enrolment.
7. **Fuzzing** (cargo-fuzz). Targets:
   - envelope parser
   - signature container and signed-statement parsers
   - SK and recovery-code parsers
   - share-URL fragment parser
   - Padmé frame parser
   - export-file parser

   cargo-fuzz needs nightly, while the repository pins 1.94.1, so fuzzing runs as a separate scheduled job with its own toolchain (owner decision, [§16](#16-open-questions-for-the-owner)). ROADMAP §4.1 lists fuzzing as a Should for M1–M6.
8. **Cross-platform equality.** The same vector files are run:
   - natively on Linux, macOS and Windows (CI already covers all three);
   - as wasm32 under Node via `wasm-bindgen-test`;
   - from M7, through UniFFI in Kotlin and Swift smoke tests.

   Output must match byte for byte. A difference is a release blocker.
9. **Memory tests.** A test asserts that the Argon2 block buffer and the `Zeroizing` wrappers are wiped after use, by inspecting the buffer through a test-only hook.
10. **Parameter invariants.** Unit tests assert:
    - the `kdf_id` floor;
    - label uniqueness;
    - purpose-id uniqueness;
    - every purpose has exactly one encrypt algorithm, and PSK-mode purposes accept only PSK-mode algorithms.

---

## 16. Open questions for the owner

1. **Secret Key in M1, mandatory.** ROADMAP says "M1 decision, M3 ship". *Recommendation:* ship the derivation and the Emergency Kit in M1, mandatory for all accounts, and leave only QR transfer and polish for M3 ([§7](#7-secret-key)). Without it, goal 2 is false for any account with a guessable password.
2. **Recovery code on by default, behind a waiting period.** *Recommendation:* on by default, with an opt-out that shows "forgetting your password = data loss". Use it with a server-enforced **72 h waiting period** that any enrolled device can cancel, and notify every device and the email. Admins can lower the wait, down to 0 for single-user instances. Without the wait, kit + server access = immediate account takeover (threat model Q-15).
3. **Freeze `kdf_id` 1 = 64 MiB / t3 / p4** only after the M1 low-end phone measurement. *Recommendation:* keep it even at 1–2 s on old phones. If it fails outright (out of memory), add a phone-only path through the OS keystore rather than lowering the floor.
4. **Password normalisation: NFC, no trimming.** *Recommendation:* NFC. Other password managers differ (U), which matters only for importing *master* passwords. We never do that. A related choice: code points that are unassigned in the pinned Unicode tables could change their NFC form once assigned. *Recommendation:* reject unassigned code points in new master passwords (this needs a Unicode general-category table, and which crate provides it is U, confirm in M1), and review every `unicode-normalization` bump like a crypto bump ([ADR 0009](adr/0009-crypto-dependency-policy.md)).
5. **Remember the SK in the web vault's browser storage.** *Recommendation:* opt-in checkbox, default off.
6. **Sign every op from M1.** It costs one Ed25519 signature per op and adds complexity, but M9 needs it and the op format would otherwise change later. *Recommendation:* yes.
7. **Fuzzing on nightly** in a separate scheduled CI job ([§15](#15-testing)). *Recommendation:* yes, weekly, and non-blocking for PRs.
8. **AES-256-GCM-SIV** stays a reserved id with no code. *Recommendation:* yes. Revisit only if a platform shows XChaCha20 is too slow, which we do not expect.
9. **Padmé padding for items from M1** (ROADMAP lists size padding as a Should in M4). *Recommendation:* yes in M1. It is free now and a format change later.
10. **Full rotation (including identity keys) as the default on device revocation.** *Recommendation:* yes for "lost/stolen", standard for "wiped and handed over". The UI asks which.
11. **Rotate the account key by default on recovery and on an SK change** ([§11.5](#115-master-password-or-secret-key-change), [§11.9](#119-recovery-with-the-emergency-kit)). Both flows assume the old kit is exposed, and old `E_rec` / `E_srv` copies in DB backups would otherwise keep yielding the current account key. *Recommendation:* yes, with an explicit "skip rotation" opt-out. A plain password change keeps "also rotate keys" as an offer, not a default.
12. **Share burn rule** (threat model Q-20). *Recommendation:* split the link token from the access token ([§11.11](#1111-public-share-link-opening-m5)): only failures with a valid link token count toward the 10-attempt burn, and everything else is rate-limited per IP.
13. **ASCII-only login names** (`[a-z0-9._+@-]`, [§2](#2-conventions)). Internationalised names would need Unicode case folding, whose tables change between releases, on the enumeration-sensitive lookup path. *Recommendation:* ASCII for v1.0.
14. **A pin store for the `smtp` role** (M6, [§11.13](#1113-mail-ingress-m6)). It is a small file on `smtp`'s own volume, which [ADR 0010](adr/0010-server-shape.md) §4 provides; it holds pins, no secrets and no DB data. *Recommendation:* yes. Without it, whoever controls `api` or the DB can substitute every account's mail key.

Dependency-policy questions (webauthn-rs and the openssl ban, cargo-vet, a zeroizing allocator) are in [ADR 0009](adr/0009-crypto-dependency-policy.md).

---

## 17. References

Confidence as in the M0 fact sheet: V = verified, L = likely, U = unverified.

- **RFC 9807**, The OPAQUE Augmented PAKE Protocol (IRTF CFRG, Informational). Number V; configuration text V from the draft source.
- **RFC 9106**, Argon2 (L). **RFC 9180**, HPKE (L). **RFC 5869**, HKDF. **RFC 8032**, Ed25519. **RFC 7748**, X25519. **RFC 8452**, AES-GCM-SIV (L). **RFC 4648**, Base64url. **RFC 2119**, requirement key words.
- draft-irtf-cfrg-xchacha-03, XChaCha20-Poly1305: expired, never an RFC (V/L).
- draft-connolly-cfrg-xwing-kem-10 (L). draft-ietf-hpke-pq-05 (L). FIPS 203, ML-KEM (L/V).
- NIST SP 800-38D §8.3, the random-IV limit for GCM (L).
- OWASP Password Storage Cheat Sheet (V).
- Len, Grubbs, Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021, ePrint 2020/1491 (L).
- Dodis, Grubbs, Ristenpart, Woodage, "Fast Message Franking: From Invisible Salamanders to Encryptment", CRYPTO 2018 (L).
- Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, "How to Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX Security 2022, ePrint 2020/1456 (L).
- Bellare, Hoang, "Efficient Schemes for Committing Authenticated Encryption", EUROCRYPT 2022 (L).
- Chan, Rogaway, CTX, ePrint 2022/1260 (L).
- Scarlata, Torrisi, Backendal, Paterson, "Zero Knowledge (About) Encryption: A Comparative Security Analysis of … Cloud-based Password Managers", ePrint 2026/058 (L).
- Backendal, Haller, Paterson, "MEGA: Malleable Encryption Goes Awry", IEEE S&P 2023 (L).
- W. Palant, "Bitwarden design flaw: Server side iterations", 2023-01-23 (L).
- 1Password Security Design white paper: 2SKD, Secret Key, the "Beware of the leopard" appendix (L).
- Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs" (Padmé), PETS 2019 (not re-verified for this document).
- S. Vaudenay, "Secure Communications over Insecure Channels Based on Short Authenticated Strings", CRYPTO 2005: the commit-then-reveal SAS pattern (not re-verified for this document).
- rust-hpke 0.14.1 source: `OpModeS::Psk` / `PskBundle`, `gen_keypair_with_rng`, `single_shot_seal_with_rng`, `single_shot_open`; `gen_keypair` only with the `getrandom` feature (V).
- rand_core 0.10.1 source: `CryptoRng` is `TryCryptoRng<Error = Infallible>`; `UnwrapErr` (V). getrandom 0.4.3: `SysRng` behind the `sys_rng` feature (V).
- opaque-ke 4.0.1 source: re-exports `rand` and `generic_array`, not sha2; depends on `rand` 0.8 with default features off (V).
- NCC Group, public report on the WhatsApp opaque-ke cryptographic implementation review, 2021 (V).
- NCC Group, RustCrypto AES-GCM and ChaCha20+Poly1305 review, 2020 (V).
- Quarkslab, security audit of dalek libraries, 2019 (L).
- getrandom README and changelog, wasm32 backends (V).
- argon2 0.6.0 source, `src/block.rs` and `src/lib.rs`: the block memory is not zeroized (V).
- Related ADRs: [0002](adr/0002-own-protocol.md), [0003](adr/0003-authentication-opaque.md), [0004](adr/0004-key-derivation-argon2id-secret-key.md), [0005](adr/0005-symmetric-encryption-aead.md), [0006](adr/0006-key-hierarchy.md), [0007](adr/0007-ciphertext-envelope.md), [0008](adr/0008-account-recovery.md), [0009](adr/0009-crypto-dependency-policy.md), [0010](adr/0010-server-shape.md), [0011](adr/0011-storage.md), [0012](adr/0012-sync-engine.md), [0013](adr/0013-shared-client-core.md), [0015](adr/0015-desktop-tauri.md), [0016](adr/0016-workspace-layout.md).
