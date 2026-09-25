# ADR 0005: Symmetric encryption: AEAD and key commitment

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1

## Context

ROADMAP §4.3 asks for XChaCha20-Poly1305 (or AES-256-GCM-SIV) with AAD that binds the item ID and version. Every vault object is symmetric ciphertext, and so are the key wraps, sync ops, snapshots, shares and exports.

Facts that shape the choice:

- **Nonce limits.**
  - AES-GCM with random 96-bit nonces is capped at 2^32 messages per key (NIST SP 800-38D, L). Devices do not share counters, so our nonces must be random.
  - XChaCha20's 192-bit nonce allows about 2^80 messages per key at a 2^-32 collision probability (L).
- **No commitment.** None of AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 and AES-GCM-SIV is key-committing (the last is U). One ciphertext can be built to decrypt under many keys. When those keys come from a password and the attacker can observe success, this becomes a **partitioning oracle** (Len, Grubbs, Ristenpart, USENIX Security 2021, L). Early OPAQUE prototypes had this bug.
- **Where our keys come from.**
  - Password-derived: the local unlock key, the passphrase-protected share key, the export key.
  - Random: every other key.
- **Crate audits.**
  - `chacha20poly1305` 0.11.0: NCC 2020, on an old version (V).
  - `aes-gcm-siv` 0.12.1: never audited itself (V).
- **Platforms.** wasm and older ARM have no AES instructions.
- **Bitwarden SDK V2** chose XChaCha20-Poly1305 for the same random-nonce reason (V).

## Decision

1. **AEAD.** XChaCha20-Poly1305 from `chacha20poly1305` 0.11.0 (`default-features = false`, features `alloc` and `zeroize`). Every encryption uses a random 24-byte nonce from the injected CSPRNG.
2. **Key commitment for every symmetric envelope.** We use Bellare and Hoang's UtC transform with the AAD folded into the committing PRF, i.e. UtC followed by their HtE step (UtC + HtE; EUROCRYPT 2022, L), with HKDF-SHA-256 as the committing PRF. It commits to `(K, nonce, AAD)`, and because decryption is deterministic, also to the message:
   ```
   okm = HKDF-SHA-256(ikm = K, salt = nonce, info = "rizzy-vault/v1/envelope/xchacha20poly1305" ‖ 0x00 ‖ aad, 64)
   k_enc = okm[0..32]; commitment = okm[32..64]
   ct ‖ tag = XChaCha20-Poly1305(k_enc, nonce, aad, pt)
   ```
   On decryption, `commitment` is compared in constant time **before** the AEAD runs. Both failures return the same error.
3. **AAD.** The AAD is `header ‖ u16(purpose) ‖ ctx`.
   - `header` is the format version, algorithm id and key id.
   - `ctx` holds the ids and epochs that pin the object to its place: account, device, vault, item, op id, device sequence, HLC, the hash of the canonical op or snapshot header, and so on.
   - The purpose is not transmitted; the reader rebuilds it.
   - Each purpose and its `ctx` fields are listed in [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes).
4. **Granularity.** One envelope per sync op (one save of one item, possibly several field writes, [ADR 0012](0012-sync-engine.md)) or per item snapshot. There are no per-field envelopes.
5. **Padding.** Item, share, relay and mail plaintexts are framed and padded with Padmé, minimum 256 bytes ([CRYPTO.md §8.5](../CRYPTO.md#85-plaintext-framing-and-padding)).
6. **AES-256-GCM-SIV** gets a reserved algorithm id (0x02) and no implementation.

## Consequences

### Positive
- There are no nonce-management rules across devices.
- The construction runs fast and in constant time in software (wasm, old ARM).
- About 128-bit commitment security removes partitioning oracles and "invisible salamander" ambiguity everywhere, including on password-derived keys.
- The server cannot move a ciphertext into another item, vault, epoch or purpose.

### Negative
- Each envelope costs 32 bytes for the commitment and 24 for the nonce: 90 bytes in total per envelope ([ADR 0007](0007-ciphertext-envelope.md)).
- One extra HKDF runs per encryption and decryption. This is negligible next to I/O.
- The commitment wrapper is our composition. It follows published transforms (UtC + HtE), but the instantiation and the claimed notion must be audited in M8.

### Risks
- XChaCha20-Poly1305 has no RFC; the CFRG draft expired (V/L). The construction is widely deployed (libsodium, Bitwarden SDK V2) and RustCrypto implements it, so we accept this.
- If an implementer calls the AEAD directly with a raw key, commitment is silently lost. The mitigation: the AEAD type is private to `rizzy-core`'s envelope module, so the only public API is the envelope.

## Alternatives considered

- **AES-256-GCM with random nonces.** The 2^32 per-key limit and no commitment rule it out. The crate also has a history of misuse bugs (RUSTSEC-2023-0096).
- **AES-256-GCM-SIV.** Its crate code is unaudited. It is not committing. It has worse bounds with random nonces and runs slower in wasm.
- **XAES-256-GCM** (C2SP; Bitwarden SDK V2 lists it). We found no established Rust implementation with an audit history (U), and it is still not committing.
- **CTX** (Chan and Rogaway). It needs the raw Poly1305 tag, which means composing ChaCha20 and Poly1305 by hand.
- **Padding-fix commitment** (Albertini et al., 2022). Only about 64-bit commitment security.
- **A separate HMAC over the whole ciphertext** (encrypt-then-MAC). Correct, but it costs a second pass over the data and a second key for the same guarantee.
- **Committing only password-derived envelopes.** It saves 32 bytes on most objects, but creates a rule that someone will eventually apply wrongly.

## Open questions for the owner

1. **Padmé padding from M1**, even though ROADMAP lists size padding as a Should for M4? *Recommendation:* yes. Adding it later is a format change.

## References

- [CRYPTO.md §8 Item and field encryption](../CRYPTO.md#8-item-and-field-encryption), [§8.3 Key commitment](../CRYPTO.md#83-key-commitment), [§9.1 envelope layout](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)
- draft-irtf-cfrg-xchacha-03
- Len, Grubbs, Ristenpart, USENIX Security 2021 (ePrint 2020/1491)
- Bellare and Hoang, EUROCRYPT 2022
- Albertini et al., USENIX Security 2022 (ePrint 2020/1456)
- NIST SP 800-38D; RFC 8452
- [ADR 0006](0006-key-hierarchy.md), [ADR 0007](0007-ciphertext-envelope.md), [ADR 0012](0012-sync-engine.md)
