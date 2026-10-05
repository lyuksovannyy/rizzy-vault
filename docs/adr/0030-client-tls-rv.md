# ADR 0030: Client-side TLS for `rv`

- Status: Partially superseded by [ADR 0035](0035-ca-file-ca-certificates-only.md) (Decision 5 in part)
- Date: 2026-10-01
- Deciders: project owner
- Milestone: M1

## Context

ROADMAP §4.2 makes the CLI client (`rv`) an M1 **Must**. The server runs on a VPS or in a container, and TLS ends at the operator's reverse proxy ([ADR 0010](0010-server-shape.md) §4; [ADR 0028](0028-api-v1-http-conventions.md) point 9: the listener is plain HTTP only on a trusted hop and "never published directly"). `rv` refuses every `https://` origin (`CliError::TlsUnavailable` in `crates/rizzy-cli/src/http.rs`) and dials `http://` only on loopback, so today it cannot reach a real deployment.

[ADR 0009](0009-crypto-dependency-policy.md#allowed-crate-families-for-cryptography) puts "any other … TLS crate on the client side" under its [approval procedure](0009-crypto-dependency-policy.md#approving-a-new-crypto-crate). [ADR 0013](0013-shared-client-core.md) §2 already fixes "Rust HTTP client, rustls" for `rv`; `deny.toml` bans OpenSSL. [ADR 0019](0019-native-clients.md) §5 reuses `rv`'s HTTP client in the Windows and Linux bindings (M3) and requires that "self-hosted servers with private CAs must still be reachable".

Threats ([THREAT_MODEL](../THREAT_MODEL.md#a4-network-attacker-mitm) A4, ASM-5): with intact TLS a network attacker sees metadata; with a certificate the client accepts, it can register a user against itself, and relay an enrolled device's challenge (request signing, Q-7, limits what it gains). For `rv`, TLS is the only server authentication on the everyday path, so the trust store is a security boundary.

Facts (V = read in the local registry, `cargo info`, the RustSec checkout `advisory-db-3157b0e258782691` at commit 3461c0d of 2026-10-01, or a scratch build reverted afterwards; U = unverified):
- `Cargo.lock` already holds `rustls` 0.23.45 (features `std`, `ring`, `tls12`), `ring` 0.17.14, `rustls-webpki` 0.103.15, `rustls-pki-types` 1.15.1, `untrusted` 0.9.0 and `webpki-roots` 1.0.9, all through sqlx's `tls-rustls-ring-webpki` in the server (V). `rv` alone (`cargo tree -p rizzy-cli`) has none of them (V).
- Latest releases: `tokio-rustls` 0.26.6, `rustls` 0.23.45 (0.24.0-dev.1 is a pre-release), `webpki-roots` 1.0.9, `rustls-native-certs` 0.8.4, `rustls-platform-verifier` 0.7.1 (V, `cargo info`).
- The `ring` provider of rustls 0.23.45 offers TLS 1.3 suites AES-256-GCM-SHA384, AES-128-GCM-SHA256, ChaCha20-Poly1305-SHA256, and key exchange X25519, P-256, P-384; no post-quantum hybrid (that is the `aws-lc-rs` provider) (V, `src/crypto/ring/mod.rs`).
- Cargo unifies features per build: in a `--workspace` build sqlx turns `rustls/tls12` on for `rv` too (V, `cargo tree -e features`). A feature cannot keep TLS 1.2 out; only the run-time configuration can.

## Decision

1. **Crates** (all in `[workspace.dependencies]`, used by `rizzy-cli` only; a leaf, so [ADR 0016](0016-workspace-layout.md) is unchanged):
   - `tokio-rustls = { version = "=0.26.6", default-features = false, features = ["ring"] }`: never `aws_lc_rs`, `fips`, `early-data`, `logging`.
   - `rustls = { version = "=0.23.45", default-features = false, features = ["std", "ring"] }`: declared directly so the pin holds; 0.23.45 is the first release fixed for RUSTSEC-2026-0285 (V).
   - `webpki-roots = { version = "=1.0.9", default-features = false }`.
   - Lockfile-pinned, transitive: `ring` ≥ 0.17.12 (RUSTSEC-2025-0009), `rustls-webpki` ≥ 0.103.13 (RUSTSEC-2026-0049/-0098/-0099/-0104), `rustls-pki-types`, `untrusted`, and `getrandom` 0.2 (ring's OS RNG for the TLS handshake only; [ADR 0009 RNG rules](0009-crypto-dependency-policy.md#rng-rules) govern our RNG, which stays `UnwrapErr(SysRng)`).
   - Not used: `rustls-native-certs`, `rustls-platform-verifier` (Alternatives).
2. **Protocol.** TLS 1.3 only: `ClientConfig::builder_with_provider(ring::default_provider())` then `.with_protocol_versions(&[&TLS13])`; the provider is passed explicitly, never installed process-wide. Suites and groups: the three suites and three groups above, in the provider's order. ALPN `http/1.1` only. SNI on (rustls omits it for IP literals). Early data off. No client certificates. Session tickets stay in the in-memory cache of the process; nothing TLS-related is written to disk. `key_log` stays `NoKeyLog`: `SSLKEYLOGFILE` is not honoured.
3. **Trust.** The default roots are `webpki-roots` (Mozilla's set, compiled in; 121 anchors in 1.0.9, V). Verification is rustls' `WebPkiServerVerifier`: chain, validity, the origin's host name or IP. No revocation checking (no CRL or OCSP fetching). The rustls `dangerous()` APIs must not appear in first-party code; `cargo xtask check-deps` scans for the tokens `dangerous` and `danger::` in `crates/*/src` as it scans for `unsafe`.
4. **Private CA.** `--ca-file <PATH>` on every command that dials, else the environment variable `RIZZY_CLI_CA_FILE` (the setting; `rv` has no settings file, open question 3). When given, its certificates **replace** the public roots (open question 2). The file is read whole, at most 64 KiB, at most 16 `CERTIFICATE` blocks, other PEM sections ignored, at least one required; each must become a trust anchor through `RootCertStore::add`. Any failure is `CliError::BadInput` before a byte is sent. The parse wrapper gets a fuzz target (`fuzz/fuzz_targets/ca_pem.rs`).
5. **No certificate pinning** in M1 (open question 4). The CA file is not a pin either: it must hold a CA certificate (`cA=true`) that issues a separate leaf (`cA=false`). A self-signed server certificate placed there does not work: `rustls-webpki` refuses a `cA=true` leaf (`CaUsedAsEndEntity`, `verify_cert.rs`), and upstream states it "has no support for self-signed certificates" (`trust_anchor.rs`) (V, 0.103.15 source). `self-hosting.md` says so on acceptance.
6. **Origins.** `https://` to any host; `http://` only to `localhost` or a loopback address, as now (THREAT_MODEL A4 mitigations). No redirects are followed, no HTTP proxy (`HTTPS_PROXY`) in M1. A TLS failure maps to one fixed `CliError::Tls` kind naming the origin, with the rustls error kind and no response data.
7. **Tests.** Loopback integration tests with a `tokio-rustls` acceptor and committed test PEM fixtures (open question 5): handshake with `--ca-file`; refusal of an unknown CA, a wrong host name, an expired certificate, and a server limited to TLS 1.2; refusal of the test certificate under the public roots; refusal of a self-signed `cA=true` server certificate placed in the CA file (Decision 5); PEM limits. rustls' own vectors are upstream's; we run none of our own.

## Consequences

### Positive

- `rv` reaches real deployments; the M1 Must is unblocked.
- One package enters `Cargo.lock` (`tokio-rustls`); everything else is already shipped and reviewed with the server.
- Behaviour is identical on every OS, independent of the host's trust store.

### Negative

- Operators with a corporate or private CA must pass `--ca-file`; the OS store is ignored. A bare self-signed server certificate is not enough: the operator needs a small CA that issues the leaf (Decision 5).
- Root updates and distrust events reach `rv` only through a reviewed `webpki-roots` bump.
- Servers behind a proxy that offers only TLS 1.2 are unreachable.
- No post-quantum key exchange: recorded traffic plus a future CRQC exposes tokens, ciphertext and OPAQUE transcripts (bounded by the Secret Key, [CRYPTO.md §5.5](../CRYPTO.md#55-offline-attack-analysis)).

### Risks

- A revoked certificate stays trusted until it expires. ACME certificates are short-lived (L). Signal for a new ADR: a mis-issuance incident, or the M3 bindings (ADR 0019 spike S4) needing the platform verifier.
- `ring` C and assembly code (156 C/asm/Perl/header files, 228 Rust lines with `unsafe`, V) enters `rv`'s binary. It was already in the server.

## Alternatives considered

- **`rustls-platform-verifier` 0.7.1.** The OS verifier and its revocation checks; corporate CAs work unchanged. Lost: +20 packages beyond this decision (jni, security-framework, schannel, walkdir, …; V, scratch lockfile), 26 `unsafe` lines in the crate and about 400 in `security-framework` (V), and behaviour that differs per OS. Better suited to the M3 desktop bindings.
- **`rustls-native-certs` 0.8.4.** Reads the OS store into rustls: +7 packages (V), `openssl-probe` with `unsafe` env writes (V), and a store any local admin or malware can extend silently.
- **TLS 1.2 as well.** Wider proxy compatibility; costs a second handshake and its downgrade surface. Caddy, the shipped proxy, negotiates 1.3 (U).
- **The `aws-lc-rs` provider.** Gives X25519MLKEM768; costs a second, large C crypto library and a CMake/NASM build, beside `ring` which the server already ships.
- **Keep loopback only** (SSH tunnel to the VPS). No new crate, but unusable as a daily client.

## Open questions for the owner

Answered on acceptance (2026-10-05): the owner accepted the ADR with every recommendation below; the Decision already states them.

1. **TLS 1.2.** Recommendation: TLS 1.3 only. Allow 1.2 only if a real deployment needs it.
2. **Private CA replaces or adds to the roots?** Recommendation: replaces. A self-hoster's CA file names exactly whom `rv` trusts; adding would keep 121 public CAs able to impersonate the server.
3. **Where the CA path lives.** Recommendation: flag plus `RIZZY_CLI_CA_FILE` for M1, no new file; storing it in the device state ([ADR 0026](0026-client-device-state-and-cache.md)) is a format change for a later ADR.
4. **Pinning.** Recommendation: none in M1. A private CA (Decision 4, replacing the public roots) already limits trust to the operator's own issuer; a public-CA deployment relies on the Mozilla roots. A key or SPKI pin would need a custom verifier (the `dangerous()` API that Decision 3 bans) and breaks on ACME key rotation (U). Revisit with a new ADR if a user needs to pin a public-CA deployment.
5. **Test fixtures.** Recommendation: committed PEM fixtures with long validity, generated once outside the repository; `rcgen` as a dev-dependency would be another crypto crate under ADR 0009.

## On acceptance

The accepting change adds this dated entry to ADR 0009 `## Amendments`, a §3 row to CRYPTO.md, the manifests of Decision 1, `rv.md` and `self-hosting.md` text, and removes `CliError::TlsUnavailable`:

> **2026-MM-DD: client TLS for `rv` ([ADR 0030](0030-client-tls-rv.md)).** Adds to the crate table: `tokio-rustls` (async adapter; `=0.26.6`), `rustls` (TLS 1.3 client in `rizzy-cli` only; `=0.23.45`), `webpki-roots` (Mozilla roots; `=1.0.9`); `ring`, `rustls-webpki`, `rustls-pki-types`, `untrusted` lockfile-pinned. Required feature sets: `tokio-rustls` `default-features = false, ["ring"]`; `rustls` `default-features = false, ["std", "ring"]`; never `aws_lc_rs`, `fips`, `early-data`. Checklist: (1) Need: TB-1 transport ([THREAT_MODEL](../THREAT_MODEL.md) §3.3), no construction of ours. (2) Provenance: the `rustls` GitHub organisation for the three crates and `rustls-webpki`; `ring` by Brian Smith (V, manifests and repository fields); bus factor and downloads U. (3) Audits: rustls by Cure53 in 2020 on a much older version (U); `ring`, `tokio-rustls`, `webpki-roots`: none found (U). (4) Advisories (V, RustSec): rustls RUSTSEC-2024-0336, -2024-0399, -2026-0285 (fixed in 0.23.45); `ring` RUSTSEC-2025-0009 (fixed 0.17.12), -2025-0010 (informational, < 0.17); `rustls-webpki` RUSTSEC-2023-0053, -2026-0049, -0098, -0099, -0104 (all fixed ≤ 0.103.13); `tokio-rustls` RUSTSEC-2020-0019 (fixed 0.13.1); `untrusted` RUSTSEC-2018-0001; `webpki-roots` none. Time to fix: U. (5) `unsafe`: `rustls` and `webpki-roots` `#![forbid(unsafe_code)]`; `tokio-rustls`, `rustls-webpki` and `untrusted` have no `unsafe` token; `rustls-pki-types` one `transmute` for IPv6 text; `ring` 228 lines plus C and assembly (V, crate source). (6) Constant time: `ring`'s primitives come from BoringSSL and are written constant-time (L); no test of ours. (7) Builds: native only (not in a wasm crate); licenses `tokio-rustls` MIT OR Apache-2.0, `rustls` Apache-2.0 OR ISC OR MIT, `webpki-roots` CDLA-Permissive-2.0, `ring` Apache-2.0 AND ISC, `rustls-webpki` ISC, all allow-listed (V). New package: `tokio-rustls` only; `cargo deny` bans, licenses, sources ok and duplicates unchanged; `cargo xtask check-deps` ok (V, cargo-deny 0.20.2). (8) Tests: ADR 0030 Decision 7.

CRYPTO.md §3 gains: "Transport (`rv`) | TLS 1.3, ring provider, Mozilla roots or a private CA | `tokio-rustls`, `rustls` (`std`, `ring`), `webpki-roots` | =0.26.6 / =0.23.45 / =1.0.9 | rustls: Cure53 2020 on an older version (U)".

## References

- [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0010](0010-server-shape.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md), [ADR 0019](0019-native-clients.md), [ADR 0026](0026-client-device-state-and-cache.md), [ADR 0028](0028-api-v1-http-conventions.md)
- [THREAT_MODEL A4](../THREAT_MODEL.md#a4-network-attacker-mitm), [CRYPTO.md §3](../CRYPTO.md#3-primitives), [ROADMAP](../ROADMAP.md), [`rv` guide](../rv.md)
- RustSec advisories as listed in On acceptance (V); crate sources in the local cargo registry (V); RFC 8446 (TLS 1.3)
