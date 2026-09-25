# ADR 0007: Versioned ciphertext envelope and crypto agility

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1

## Context

ROADMAP principle 4 says everything is versioned. §4.3 asks for a ciphertext envelope carrying an algorithm id, key id, nonce and ciphertext, and hybrid post-quantum key wrapping must be possible later without breaking vaults.

Downgrade to legacy modes is one of the ETH Zurich attack classes (L). Examples:
- LastPass's unauthenticated AES-CBC;
- the legacy paths in Bitwarden and Dashlane.

Agility done badly is itself an attack surface. Negotiated algorithms and "try the old format too" are exactly how downgrades happen.

Bitwarden's SDK V2 uses COSE, with private-use algorithm ids for XChaCha20-Poly1305 and padded content types (V).

## Decision

1. **Our own fixed binary envelope**, not a general container format. Layouts:

   | Type | Layout | Overhead |
   |---|---|---|
   | Symmetric (alg 0x01) | `u8 version=0x01 ‖ u8 alg_id ‖ key_id[16] ‖ nonce[24] ‖ commitment[32] ‖ ct ‖ tag[16]` | 90 B |
   | HPKE (alg 0x10 Base, 0x12 PSK) | `u8 version=0x01 ‖ u8 alg_id ‖ recipient_key_id[16] ‖ enc[32] ‖ ct ‖ tag[16]` | 66 B |
   | Signature container | `u8 version=0x01 ‖ u8 sig_alg ‖ signer_key_id[16] ‖ sig[64]` | – |

2. **Binding.** The 18-byte header is always part of the AAD. The **purpose** (`u16`) and **context** are *not* transmitted; the reader rebuilds them from where it expected the object to be ([ADR 0005](0005-symmetric-encryption-aead.md)).
   - **Key ids.** A symmetric key's id is `HKDF(K, "key-id/symmetric")`, truncated to 16 bytes, for every key, whether generated or derived from a password, the recovery code, the QR secret or another key. A public key's id is a truncated SHA-256 of its type and bytes. One rule, nothing stored separately, nothing left undefined ([CRYPTO.md §4.4](../CRYPTO.md#44-identifiers-epochs-and-key-ids)). For a password-derived key the id is a guess verifier exactly as costly as the envelope commitment next to it: one full Argon2id behind a random or secret salt.
3. **Algorithm registry.**

   | Id | Meaning |
   |---|---|
   | 0x01 | XChaCha20-Poly1305 with the committing wrapper |
   | 0x02 | reserved: AES-256-GCM-SIV |
   | 0x03 | reserved: chunked attachments (M3) |
   | 0x10 | HPKE Base mode, X25519 / HKDF-SHA256 / ChaCha20Poly1305 |
   | 0x11 | reserved: HPKE Base mode with X-Wing |
   | 0x12 | HPKE PSK mode, X25519 / HKDF-SHA256 / ChaCha20Poly1305 |
   | 0x13 | reserved: HPKE PSK mode with X-Wing |
   | 0x14–0x1F | reserved: PQ |
   | 0xF0–0xFE | test-only, rejected in release builds |
   | 0x00, 0xFF | invalid |

   Signature algorithms: `sig_alg` 0x01 is Ed25519; 0x02 is reserved for hybrid Ed25519 + ML-DSA.
4. **Allow-lists.**
   - Each purpose has exactly one encrypt algorithm and a decrypt allow-list. In M1 that is `{0x01}` for symmetric purposes, `{0x12}` for the purposes that carry an account key or a vault between one user's devices (device grants, password-verifier grants, pairing and re-sync transfers), and `{0x10}` for member grants and mail. A PSK purpose never accepts Base mode, which would silently drop the PSK ([CRYPTO.md §9.5](../CRYPTO.md#95-parsing-and-allow-list-rules)).
   - Checks run in a fixed order: length, version, the purpose's allow-list, then key id. Only after all four does any crypto run.
   - There is one error for every failure.
5. **No negotiation, no legacy paths.**
   - The server never picks an algorithm.
   - For asymmetric wraps, the sender picks from the recipient's *signed* key bundle, which can set `pq_required`.
   - Sunsetting an algorithm: release N stops encrypting with it; clients re-encrypt in the background; release N+k drops it from the decrypt allow-list.
6. **Encoding.**
   - Raw bytes in the database (`BLOB`/`bytea`) and in the client cache.
   - base64url without padding in JSON.
   - Export and backup files are JSON, with the envelope in a `data` field.
7. **Strict parser.** The parser is a pure, non-panicking function that never allocates in proportion to a length field. It is fuzzed from M1.
8. **Signed statements** are fixed binary layouts: `LABEL("sig/<type>") ‖ 0x00 ‖ u16 statement_version ‖ body`. They are never serde-derived.

The exact layouts, registry and migration procedure are in [CRYPTO.md §9](../CRYPTO.md#9-envelope-format).

## Consequences

### Positive
- There is one small parser to fuzz and audit.
- A downgrade is impossible unless an algorithm is still on the allow-list, and anything on the list is by definition acceptable.
- A PQ migration is additive: implement 0x11 and 0x13, publish PQ keys in bundles, re-issue long-lived grants, then retire 0x10 and 0x12 ([CRYPTO.md §9.7](../CRYPTO.md#97-how-a-migration-lands-pq-example)).
- Moving an envelope to another context fails, because the context is rebuilt by the reader and never trusted from the wire.

### Negative
- It is a custom format. External tools cannot read it; we document it here and ship test vectors.
- A one-byte algorithm id limits us to about 240 usable algorithms. 0xFF is kept as an extension escape.
- Allow-list changes need a client release. That is intentional.

### Risks
- If the purpose table in code and in [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) drift apart, interoperability breaks. Mitigation: unit tests assert purpose-id uniqueness and one encrypt algorithm per purpose, and committed vectors cover every purpose.

## Alternatives considered

- **COSE (RFC 9052)**, as used by Bitwarden SDK V2 with the `coset` 0.4.2 crate.
  - It is standard and extensible, but it brings a CBOR parser surface.
  - Optional headers and many algorithms make downgrade *possible*, and our allow-lists would have to fight that.
  - COSE has no key commitment, so we would still need a private-use algorithm.
  - Revisit it only if interoperability, for example with CXF/CXP, ever needs it.
- **JWE/JOSE.** It has a long history of algorithm-confusion bugs, and base64 JSON is bloated for vault objects.
- **PASETO v4.local.** It is a token format with footer and implicit-assertion semantics, not a key-wrapping and storage envelope. No crate for it has been reviewed by us.
- **No versioning, just an implicit current algorithm.** It violates ROADMAP principle 4 and makes a PQ migration a rewrite.
- **Negotiating algorithms with the server.** This is the downgrade vector itself.

## Open questions for the owner

None. This ADR follows from ROADMAP principle 4 together with [ADR 0005](0005-symmetric-encryption-aead.md).

## References

- [CRYPTO.md §9 Envelope format](../CRYPTO.md#9-envelope-format), [§8.4 AAD and purposes](../CRYPTO.md#84-aad-and-purposes), [§13 Post-quantum readiness](../CRYPTO.md#13-post-quantum-readiness)
- RFC 9180 (HPKE); RFC 4648 §5 (base64url); RFC 9052 (COSE)
- Scarlata et al., ePrint 2026/058 (downgrade class)
- [ADR 0005](0005-symmetric-encryption-aead.md), [ADR 0006](0006-key-hierarchy.md), [ADR 0009](0009-crypto-dependency-policy.md)
