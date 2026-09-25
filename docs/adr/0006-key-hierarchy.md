# ADR 0006: Key hierarchy, per-user keypairs and key wrapping

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1

## Context

ROADMAP principle 3 and hard truth 7 say it plainly: if the org key model does not exist from M1, M9 becomes a rewrite. The hierarchy has to support all of the following:

- master-password change without re-encrypting the vault;
- key rotation after a device is revoked;
- offline unlock;
- On-device mode (M4), where the server holds nothing crackable;
- public shares (M5), mail sealed to the user's public key at ingress (M6), and shared vaults (M9).

What the reference designs do:
- **1Password and Bitwarden** wrap vault keys to per-user RSA keys.
- **Proton Pass** uses a per-vault key and a per-item key, with an OpenPGP user key (L).
- **AliasVault** encrypts the vault directly under an Argon2id-derived key, with no hierarchy (V).

What attackers have exploited (Scarlata et al., 2026, L):
- unauthenticated public keys,
- objects that are not bound to their context,
- server-mediated key distribution.

## Decision

The full construction, with every HKDF label, is in [CRYPTO.md §4](../CRYPTO.md#4-key-hierarchy) and [§10](../CRYPTO.md#10-asymmetric-cryptography).

1. **Account key.** 32 random bytes. It is wrapped these ways:
   - `E_srv`, on the server, under an HKDF of OPAQUE's `export_key`. Server mode only.
   - `E_local`, on each device, under `HKDF(Argon2id(pw_in, device_salt))`.
   - `E_ks` (M3/M7, optional), on each device, under a random secret the OS keystore releases only after a user-presence check. This is the one object behind biometric unlock and iOS AutoFill.
   - `E_rec`, under the recovery-code key ([ADR 0008](0008-account-recovery.md)).

   Where each wrapped-key object lives in Server mode and in On-device mode is fixed in one table ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)).
2. **Identity keys, per user, generated at signup in M1.**
   - An Ed25519 signing key and an X25519 HPKE key.
   - The private halves are wrapped under the account key.
   - The public halves are published in a self-signed, typed, versioned **key bundle**. Each new bundle also chains to its predecessor.
3. **Vault keys.** 32 random bytes per vault.
   - The user's own vaults are self-granted, wrapped symmetrically under the account key.
   - From M9, other members receive HPKE grants signed by the granter.
   - Vault keys are never derived from the account key, so they can be shared.
4. **Item keys.** 32 random bytes per item, wrapped under the vault key. They encrypt the item's ops and snapshots. The wrap's plaintext also records the vault-key epoch in which the item key was created, so staleness is authenticated (decision 11). From M3, each attachment gets its own random key, wrapped under the item key (`ATTACHMENT_KEY_WRAP`), so an attachment can be shared or deleted on its own ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)).
5. **Device keys.** Each device has its own Ed25519 and X25519 pair. Its certificate is signed by the identity key, and its private keys are wrapped under the account key in `E_dev`, which stays on that device and is never uploaded. The keys are used for:
   - authenticating the device to the server,
   - signing ops,
   - receiving rotation grants.
6. **Relay key.** `HKDF(account_key, account_id ‖ account_key_epoch)`, used for On-device-mode relay batches. It rotates with the account key.
7. **Share keys.** Derived from a random 32-byte share secret that lives only in the URL fragment and in the owner's vault. An optional passphrase is mixed in through Argon2id.
8. **Mail key** (M6). A separate X25519 key per user. The `smtp` role seals messages to it with HPKE.
9. **Key wrapping to public keys.**
   - HPKE, RFC 9180: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305.
   - **Base mode** for member grants (M9) and mail. **PSK mode** for everything that carries an account key or a vault between one user's devices: device grants after a rotation, password-verifier grants (On-device mode), pairing and re-sync transfers. The PSK comes from a secret the recipient already holds (the previous account key, the current account key, or the QR pairing secret), so a stored grant needs both the device's X25519 key and that secret. A future quantum computer that breaks X25519 still lacks the PSK ([CRYPTO.md §10.1](../CRYPTO.md#101-hpke-key-wrapping)).
   - Crate: `hpke` 0.14.1 with `default-features = false` and features `alloc`, `x25519`, `chacha`. Keys are generated with `gen_keypair_with_rng` and the injected RNG.
   - Sender authenticity comes from an Ed25519 signature over the HPKE envelope: the sender's device key, or the identity key for a device grant from the web vault. The AAD context names the sender and the recipient by id (`device_id` for device grants, `account_id` for member grants). The envelope header names the recipient public key id; the sender public key id is in the signed message ([CRYPTO.md §10.1](../CRYPTO.md#101-hpke-key-wrapping)). A device grant's delivered key must match the account key id committed in the signed account state.
10. **Signatures.** `ed25519-dalek` 3.0.0, always verified with `verify_strict`. Signed statements use fixed binary layouts with domain-separated labels:
    - key bundle,
    - device certificate and device revocation,
    - account security state (`kdf_id`, epochs, the current account key's id, recovery status, sync mode, the current bundle's hash, a hash of the durable device set, `settings_seq` and a hash of the encrypted settings, `state_seq`),
    - ops and snapshots, including the item-key wrap that travels with them,
    - key grants and device authentication.

    Committing to the settings makes them fresh, not just authentic: the server cannot serve an older, validly encrypted settings object. Web-vault certificates are short-lived (12 h) and stay out of the device set; peers check them against the identity key and their expiry ([CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)).
11. **Rotation.**
    - Account and vault keys rotate on device revocation, recovery, an SK change, a switch to On-device mode, or suspected compromise. Recovery and SK changes rotate by default with an explicit opt-out ([ADR 0008](0008-account-recovery.md)).
    - Item keys are re-wrapped straight away, keeping their recorded creation epoch, and rotated lazily. A writer **must** generate a fresh item key when the key's creation epoch is older than the vault's current epoch, which it reads from the self-grant that opens under the verified account key, never from server metadata. This holds for a device enrolled after the rotation and when the server serves only the re-wrapped old key.
    - Identity keys rotate only in a full rotation. The new bundle is signed by both the old and the new key, and the new `account-state` by the new key.
    - A master-password change does **not** rotate the account key by default; the UI offers it.
12. **Authenticity of public keys.**
    - The user's own keys are verified by decrypting the private keys and comparing. After a full rotation elsewhere, each of the user's devices shows the new identity fingerprint and moves to the new key only after the user confirms it ([CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device)).
    - Bundles form a chain: each names its predecessor's hash and carries a `bundle_seq`, and every verifier rejects a lower `bundle_seq` than it has seen.
    - Other users' keys (M9) are pinned on first use and checked with Signal-style numeric fingerprints. A new bundle is accepted silently only if it chains from the pin **and keeps both identity keys** (a new PQ key, a new mail key). Any identity-key change is a visible "safety number changed" event: a verified contact drops to unverified and no new grants go to it until the user re-verifies (threat model INV-17), even when the old identity key signed the change, because full rotation exists for the case where that key is compromised. Two bundles with the same predecessor are a fork alarm ([CRYPTO.md §10.3](../CRYPTO.md#103-public-key-authenticity)).
    - The `smtp` role (M6) pins each account's identity key too, so an attacker controlling only the API or DB cannot substitute the mail key.
    - Key transparency is a post-1.0 Could.

## Consequences

### Positive
- A master-password change re-wraps one key.
- Moving an item to another vault generates a new item key and writes a fresh signed snapshot in the destination vault, which is O(item size). The source vault's ops are not carried over, and members of the source vault keep only what they already had. Re-wrapping the old key alone would not work: the item AAD binds `vault_id`, and from M9 every member of the source vault holds the old key.
- Sharing a vault means one HPKE grant per member, with no re-encryption.
- M9 needs no data migration: every key type it relies on exists from M1.
- A server cannot inject a device, hide one from a newly enrolled device, substitute the user's own public keys, swap wrapped keys between contexts, or get a revoked device's item keys reused for new writes.
- The personal vault at rest depends only on symmetric crypto, which is good for PQ readiness. The HPKE grants that carry an account key between devices use PSK mode, so that stays true while a grant waits on the server for an offline device.

### Negative
- There are more objects to store and more code paths than in a flat design.
- Rotation is O(items) re-wraps; a full re-encryption is O(vault size) and must be requested explicitly.
- Signing every op costs one Ed25519 signature per op.
- Every identity-key change interrupts the user's contacts with a "safety number changed" event. That is the price of not trusting a possibly compromised old key.
- In On-device mode, vault-level key objects (self-grants, item-key wraps) live only on devices and travel inside relay batches, so relay batches carry key records next to op records ([ADR 0012](0012-sync-engine.md) §8, [CRYPTO.md §11.12](../CRYPTO.md#1112-relay-ops-on-device-mode-m4)).

### Risks
- Public-key substitution on first contact remains possible from M5/M9 until users verify fingerprints or key transparency exists.
- A compromised device that is later revoked holds the old identity key and can race a rotation ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation)). The M4 device-management ADR must settle this.
- A malicious server can roll a *fresh* device back to an older, validly signed account state. Devices that have already seen a newer state detect it.
- From M9, removing a member rotates one vault key without rotating the account key, so the old self-grant still opens. The M9 ADR must put `vault_key_epoch` into a signed vault statement, or the lazy item-key rule can be fooled into treating an old vault key as current.

## Alternatives considered

- **A flat key**: vault encrypted directly under a password-derived key (AliasVault). Password change becomes re-encrypt-everything, and there is no path to sharing.
- **RSA-OAEP-2048 user keys** (1Password, Bitwarden, AliasVault). Larger keys, a padding-oracle history, and RUSTSEC-2023-0071 is unfixed in the Rust `rsa` crate.
- **OpenPGP** (Proton). A large format and parser surface for no gain over HPKE.
- **HPKE Auth mode** for sender authentication. The PQ KEMs in rust-hpke do not support it. A signature is also more explicit.
- **Vault keys derived from the account key.** Cheaper, but they could never be shared without re-encryption.
- **Per-field keys.** They leak the field structure and multiply the AAD cases; per-item keys already give per-item sharing.
- **An asymmetric recovery wrap** (HPKE to a key derived from the recovery code). It would allow rotation without the code, but it puts a long-lived, harvest-now-decrypt-later-exposed wrap of the account key on the server. See [ADR 0008](0008-account-recovery.md).

## Open questions for the owner

1. **Full rotation (including identity keys) as the default** when a lost or stolen device is revoked? *Recommendation:* yes. Use standard rotation for a device that was wiped and handed over.
2. **Sign every op from M1?** *Recommendation:* yes. Otherwise M9 forces a change to the op format.

## References

- [CRYPTO.md §4 Key hierarchy](../CRYPTO.md#4-key-hierarchy), [§10 Asymmetric cryptography](../CRYPTO.md#10-asymmetric-cryptography), [§11 Flows](../CRYPTO.md#11-flows)
- RFC 9180 (HPKE); RFC 8032 (Ed25519); RFC 7748 (X25519)
- Scarlata et al., ePrint 2026/058
- [ADR 0003](0003-authentication-opaque.md), [ADR 0005](0005-symmetric-encryption-aead.md), [ADR 0007](0007-ciphertext-envelope.md), [ADR 0008](0008-account-recovery.md), [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md)
