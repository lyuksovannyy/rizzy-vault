# ADR 0035: A private CA file holds CA certificates only

- Status: Proposed
- Date: 2026-10-05
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0030](0030-client-tls-rv.md) Decision 5 in part (its second and third sentences), on acceptance.

## Context

[ADR 0030](0030-client-tls-rv.md) (Accepted) lets `rv` replace Mozilla's roots with a private CA file (Decision 4) and says the file "is not a pin either" (Decision 5): pinning needs a custom verifier, which Decision 3 bans. Decision 5 then gives a reason that is only half true: a self-signed server certificate in the CA file "does not work" because `rustls-webpki` refuses a `cA=true` leaf and "has no support for self-signed certificates".

- A self-signed `cA=true` certificate used as the end entity is refused: `verify_cert.rs` returns `CaUsedAsEndEntity` for `(Role::EndEntity, true, _)` (V, rustls-webpki 0.103.15 source).
- A self-signed `cA=false` certificate is accepted as both trust anchor and end entity. `anchor_from_trusted_cert` performs "no additional checks", including on `cA`; the sentence on self-signed certificates in `trust_anchor.rs` is advice to callers, not a check (V, 0.103.15 source). The acceptance itself was seen in the review of commit c011f5f (L: reported; the committed tests no longer reach it, since `rv` now refuses such a file first).

So, relying on the verifier alone, a CA file holding the server's own `cA=false` certificate would act as a certificate pin, against Decision 5's intent. `rustls-webpki` exposes no accessor for `basicConstraints`, and an X.509 parsing crate would be a new crypto-adjacent dependency under [ADR 0009](0009-crypto-dependency-policy.md). Commit c011f5f already enforces the intent in `rv` (V, code read for this ADR).

## Decision

1. **Only CA certificates.** Every `CERTIFICATE` block of the CA file must carry `basicConstraints` (OID 2.5.29.19) with `cA` = DER `TRUE` (`0xFF`), RFC 5280 §4.2.1.9. Anything else (`cA` absent or `FALSE`, no `basicConstraints`, a v1 certificate without extensions, DER the check cannot read) refuses the whole file with `CliError::BadInput` ("… is not a CA certificate (cA=true); a server certificate cannot be trusted directly"), when the file is read and before any byte is sent. ADR 0030 Decision 4's other limits are unchanged.
2. **Mechanism:** `is_ca_certificate` in `crates/rizzy-cli/src/tls.rs`, called by `parse_ca_pem` before `RootCertStore::add`. It is a read-only DER walk of the standard X.509 path (Certificate → TBSCertificate → optional `[0]` version → six fixed fields → `[3]` extensions → the `basicConstraints` extension → its `cA` BOOLEAN), single-byte tags and definite lengths of at most four bytes only, bounds-checked, no allocation, no `unsafe`, failing closed (`None` → not a CA). It decides one bit; `RootCertStore::add` still parses the certificate in full. No X.509 crate is added.
3. **The handshake rule stays:** a `cA=true` certificate served as the end entity is refused by `rustls-webpki` (`CaUsedAsEndEntity`). With point 1, both kinds of self-signed server certificate are refused, and the file is never a pin.
4. **Tests and fuzzing.** Unit tests: the walk accepts the test CA and the self-signed `cA=true` fixture and refuses the issued leaf and a self-signed `cA=false` fixture, every truncation of the CA certificate, and malformed DER lengths and tags. Integration (`crates/rizzy-cli/tests/tls.rs`): a self-signed `cA=false` certificate in the CA file, and the issued leaf in the CA file, end in `BadInput` with no request reaching the server; a self-signed `cA=true` one fails the handshake as `BadCertificate`. Fixtures `self-signed-leaf.{pem,key}` are documented in `crates/rizzy-cli/tests/fixtures/tls/README.md`. Fuzz target `ca_pem` runs `parse_ca_pem` on each input as is and wrapped in one `CERTIFICATE` block, so the walk sees arbitrary DER.

**What this ADR supersedes:** ADR 0030 Decision 5, its second sentence ("The CA file is not a pin either: …") and third sentence ("A self-signed server certificate placed there does not work: …"), replaced by the text in "On acceptance", which binds as Decision text of this ADR. Decision 5's first and last sentences stay binding.

## Consequences

### Positive
- The "no pin" rule holds by our own check, not by an inaccurate reading of the verifier; operators get a clear error before connecting.
- No new dependency.

### Negative
- About 100 lines of hand-written DER reading (with its docs) in a leaf crate, to review and keep fuzzed.
- An operator who wants to trust one self-signed certificate must make a small CA ([self-hosting.md §6](../self-hosting.md#6-tls-the-reverse-proxy-and-ports)).

### Risks
- The walk may misread an unusual but valid encoding (e.g. multi-byte tags) and refuse a real CA; it fails closed, so the cost is a refusal, not trust. Signal: a user report of a CA certificate refused here.
- A future `rustls-webpki` that exposes `basicConstraints` or rejects self-signed anchors would make the walk replaceable; review on each bump.

## Alternatives considered
- **Accept a self-signed `cA=false` certificate as a pin.** Simple for operators, but it is pinning, which ADR 0030 open question 4 declined for M1, and breaks on every key rotation. Rejected.
- **An X.509 parsing crate** (e.g. `x509-parser`, U): a full parser for one bit, and a new dependency needing ADR 0009's approval. Not taken; revisit if more certificate fields are needed.
- **Keep Decision 5's text:** leaves an Accepted reason that is wrong for `cA=false`.

## Open questions for the owner

1. **Is the hand-written walk acceptable** under the rule "no home-made crypto"? It verifies nothing cryptographic and only narrows what the file may hold. Recommendation: yes.

## On acceptance

1. **ADR 0030 Decision 5**, second and third sentences. Current text:
   > The CA file is not a pin either: it must hold a CA certificate (`cA=true`) that issues a separate leaf (`cA=false`). A self-signed server certificate placed there does not work: `rustls-webpki` refuses a `cA=true` leaf (`CaUsedAsEndEntity`, `verify_cert.rs`), and upstream states it "has no support for self-signed certificates" (`trust_anchor.rs`) (V, 0.103.15 source).

   Replacement:
   > The CA file is not a pin either: every certificate in it must be a CA certificate (`basicConstraints` `cA=true`) that issues a separate server certificate (`cA=false`); `rv` refuses a file holding any other certificate with `CliError::BadInput` before any connection, by its own read-only DER check ([ADR 0035](0035-ca-file-ca-certificates-only.md)), because `rustls-webpki` would accept a self-signed `cA=false` certificate as both trust anchor and end entity. A self-signed `cA=true` server certificate is refused at the handshake: `rustls-webpki` refuses a CA certificate as the end entity (`CaUsedAsEndEntity`, `verify_cert.rs`) (V, 0.103.15 source).
2. **Status lines:** ADR 0030 → "Partially superseded by [ADR 0035](0035-ca-file-ca-certificates-only.md) (Decision 5 in part)"; this ADR → Accepted; both index rows follow.
3. **Other docs:** none. `docs/rv.md` ("TLS and a private CA") and `docs/self-hosting.md` §6 already state the corrected reason (V, grep for "self-signed").

## References
- [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0020](0020-partial-supersession.md) point 9, [ADR 0030](0030-client-tls-rv.md) Decisions 3–5, 7; [THREAT_MODEL A4](../THREAT_MODEL.md#a4-network-attacker-mitm); [rv.md](../rv.md#tls-and-a-private-ca).
- Code (V, c011f5f): `crates/rizzy-cli/src/tls.rs`, `crates/rizzy-cli/tests/tls.rs`, `crates/rizzy-cli/tests/fixtures/tls/README.md`, `fuzz/fuzz_targets/ca_pem.rs`.
- rustls-webpki 0.103.15 `src/trust_anchor.rs`, `src/verify_cert.rs` (V, local registry); RFC 5280 §4.1, §4.2.1.9 (L, as cited in `tls.rs`).
