# ADR 0002: Own protocol, not Bitwarden-API compatible

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1

## Context

[ROADMAP §1](../ROADMAP.md#1-what-we-are-building-one-paragraph) and [§5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation) recommend our own protocol and say we offer import, not wire compatibility. The alternative is attractive, and it should be rejected on its merits, not by default. If we spoke the Bitwarden server API, as Vaultwarden does, every Bitwarden client (extension, desktop, mobile, CLI) would work against our server on day one. [ROADMAP §6.2](../ROADMAP.md#6-risks--hard-truths) says clients are the real cost of this project, so that is the biggest shortcut available.

Speaking the Bitwarden API would force the following on us:

- **Authentication with a password hash.** The client derives a master-password hash from the master key and sends it. The server re-hashes it and compares (structure V, from the Bitwarden white-paper snapshot; exact iteration counts L). That is a password-equivalent on the wire. OPAQUE exists to remove it ([ADR 0003](0003-authentication-opaque.md), [THREAT_MODEL INV-1](../THREAT_MODEL.md#8-security-invariants)).
- **KDF parameters named by the server.**
  - Palant (2023, L) showed Bitwarden clients accepted PBKDF2 iteration counts as low as 5,000 when the server supplied them.
  - Bitwarden's SDK `main` still declares `PBKDF2_MIN_ITERATIONS = 5000` (V).
  - Compatibility means accepting server-supplied parameters above *their* floors, not ours ([ADR 0004](0004-key-derivation-argon2id-secret-key.md), [THREAT_MODEL §5.1](../THREAT_MODEL.md#51-kdf-parameter-downgrade)).
- **Their key hierarchy and formats** (V):
  - an email-salted master key;
  - a user symmetric key under AES-256-CBC + HMAC-SHA256;
  - RSA-2048 OAEP user and org keys.

  None of our requirements are there: no Secret Key, no signed identity or device keys, no key commitment. Bitwarden's SDK is moving to a COSE-based "V2" format with XChaCha20-Poly1305 (V), so the target moves. The legacy formats stay, because old clients need them.
- **Their sync model.** Clients download the vault through a full-sync endpoint; there is no client-side op log or version vector (U; general knowledge of the API, not re-verified for this ADR). On-device mode ([ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4)) and our merge rules ([ADR 0012](0012-sync-engine.md)) cannot exist behind that API.
- **Their feature set.** Their clients have no alias mailbox, no transparency page, and none of our share-link design. Anything we add is invisible to them.
- **Someone else's attack surface.** Scarlata et al. (ePrint 2026/058, L) report 12 malicious-server attacks against Bitwarden. A compatible server inherits the client-side half of each attack that the server cannot fix.

Vaultwarden already fills the "self-hosted, Bitwarden-compatible server" niche. A second one adds nothing.

## Decision

1. **Own protocol.** rizzy-vault speaks its own HTTP API and uses its own cryptography ([CRYPTO.md](../CRYPTO.md)).
   - The server implements no Bitwarden endpoint, accepts no Bitwarden login and parses no Bitwarden `EncString`.
   - Our clients do not talk to Bitwarden or Vaultwarden servers.
2. **Interoperability comes from import and export, on the client.**
   - **M1 importers** ([ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), Must):
     - Bitwarden JSON (unencrypted)
     - 1Password 1PUX
     - KeePass KDBX and XML
     - generic CSV
     - Chrome and Firefox CSV
   - **M1 exporters:** our encrypted JSON ([CRYPTO.md §11.14](../CRYPTO.md#1114-encrypted-export-m1)), and plaintext JSON or CSV behind a warning.
   - **Import runs only on the client**, in the `rizzy-import` crate ([ADR 0016](0016-workspace-layout.md)). That crate does no I/O, builds for wasm32 and is fuzzed ([ROADMAP §4.1](../ROADMAP.md#41-foundations--project-hygiene-m0)). The server never receives an import file. Imported items are encrypted under our envelope straight away.
   - **Importers only read.** A legacy format never becomes a decrypt path for our own data ([THREAT_MODEL §5.2](../THREAT_MODEL.md#52-envelope-and-algorithm-downgrade)). Legacy primitives that an importer needs, for example KDBX's own KDF and cipher, live in `rizzy-import`, never in `rizzy-core`, and go through [ADR 0009](0009-crypto-dependency-policy.md)'s approval procedure.
3. **API shape and versioning.**
   - **Paths.** Every endpoint lives under `/api/v1/`. One endpoint is unversioned: `GET /api/meta`. It returns:
     - the server version and the API versions it serves;
     - the sync modes the admin allows;
     - the minimum client version per platform.
   - **From v1.0, changes inside `v1` are additive only** (point 5 covers the time before):
     - new endpoints;
     - new optional request fields;
     - new response fields, which clients ignore if they do not know them.

     Removing or renaming a field, changing a type or tightening validation is a breaking change, and it needs `/api/v2/`.
   - **Overlap.** Once `v2` ships, the server serves `v1` and `v2` side by side for at least two server releases or six months, whichever is longer. Store-distributed clients update slowly. A removed version answers `410 Gone` with a machine-readable error code.
   - **Client identification.** Clients send `Rizzy-Client: <platform>/<version>`. The server may refuse clients below the minimum version with a machine-readable `client_too_old` error. It never falls back to older behaviour for them.
   - **Encoding.** JSON over HTTPS. Binary fields (envelopes, signed statements, OPAQUE messages) are base64url without padding ([CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage)). The server treats envelopes as opaque bytes.
   - **One definition of the types.** Request and response types are Rust types in `rizzy-proto` ([ADR 0016](0016-workspace-layout.md)), shared by the server and every client.
     - An OpenAPI 3.1 description is generated from them and checked in; CI fails if the checked-in file is stale.
     - The schema derive sits behind a non-default `openapi` feature of `rizzy-proto` that only `xtask` enables ([ADR 0016](0016-workspace-layout.md) §3). It never ships in a client or in the wasm bundle.
     - The generator is chosen in M1.
4. **Three version numbers that move independently:**
   - the API version (this ADR);
   - the envelope and algorithm version ([ADR 0007](0007-ciphertext-envelope.md));
   - the KDF version ([ADR 0004](0004-key-derivation-argon2id-secret-key.md)).

   The API version describes the shape of HTTP messages only. It never selects a cryptographic algorithm or parameter. Those are compiled into the client and authenticated ([CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules), rule 5).
5. **Before v1.0, a breaking change forces a client update.** Our own store-distributed clients ship before M8: the extension in M2, mobile in M7. They are exactly the clients point 3's overlap protects, so "anything goes until v1.0" would break them. Until the v1.0 release:
   - `v1` may change incompatibly, but only in a server release that also raises the minimum client version per platform in `/api/meta`.
   - A client below the minimum shows an "update required" state instead of failing. If it has a local cache, it keeps offline read access and writes nothing until it is updated. The web vault comes from the same server, so it always matches.
   - A server release that raises the minimum for a store-distributed client ships only after that client version is live in its store. Self-hosters upgrade servers on their own schedule, and store review can take days.
   - Each change is noted in the changelog. There is no stability promise to third parties.

   At v1.0, `v1` freezes and point 3 applies in full: additive changes only, `/api/v2` for breaking ones, and the overlap.

## Consequences

### Positive

- We can build what the threat model requires: OPAQUE, the Secret Key, signed identity and device keys, key-committing envelopes, client-enforced KDF floors, signed ops and On-device mode.
- No legacy format sits on the decrypt path, so there is no downgrade class to defend ([THREAT_MODEL §5.2](../THREAT_MODEL.md#52-envelope-and-algorithm-downgrade)).
- Users can still leave Bitwarden, 1Password and KeePass, through import, which the ROADMAP already requires.
- The API changes on our schedule, not Bitwarden's.

### Negative

- **We build and maintain every client:**
  - web vault and CLI (M1);
  - extension (M2);
  - desktop (M3);
  - mobile (M7).

  [ROADMAP §6.2](../ROADMAP.md#6-risks--hard-truths) says this is where most of the time goes. While our clients are immature, there is no fallback client.
- Users who want Bitwarden's apps should run Vaultwarden, and the README says so.
- No third-party client exists for our API, and none will before the API is stable.
- Importers are a large surface for hostile input: 1PUX, KDBX and many CSV dialects. They need fuzzing, and tests against real export files ([ROADMAP §7](../ROADMAP.md#7-definition-of-done-for-v10-end-of-m8)).

### Risks

- The "Bitwarden-style" description may make people expect compatibility. The README must say plainly that we are not compatible.
- Bitwarden JSON, 1PUX and KDBX can change. Importer tests run against real, dated exports, so a format change shows up as a failing test.
- If our clients slip, there will be pressure to add a Bitwarden compatibility shim. The second alternative below explains why that shim brings back the attacks this design removes.

## Alternatives considered

- **Full Bitwarden API compatibility** (the Vaultwarden approach). We would get clients for free. But it forces password-hash authentication, server-named KDF parameters, Bitwarden's key hierarchy and formats, and whole-vault sync. That rules out OPAQUE, the Secret Key and On-device mode, and it duplicates Vaultwarden.
- **Dual stack: our protocol plus a Bitwarden-compatible shim.** Every account used through the shim needs:
  - a password-equivalent verifier on the server;
  - Bitwarden-format key wraps next to ours;
  - server-readable KDF settings.

  Those are exactly the downgrade paths in [THREAT_MODEL §5.1](../THREAT_MODEL.md#51-kdf-parameter-downgrade) and [§5.2](../THREAT_MODEL.md#52-envelope-and-algorithm-downgrade). A shim also doubles the API surface we test and audit.
- **Fork Bitwarden's clients and point them at our protocol.** Their client codebase is large, built around Bitwarden's data model and crypto, and tracks Bitwarden's own server. Its licensing would need separate review (U). We would maintain a diverging fork of a moving target, instead of building thin clients around our own core ([ADR 0013](0013-shared-client-core.md)).
- **gRPC or another binary RPC instead of JSON over HTTPS.** It gives stricter typing and smaller messages. But it is harder to use from a browser extension and from `curl` when a self-hoster is debugging. Ciphertext dominates message size either way, and JSON with generated types is enough.

## Open questions for the owner

1. **Importing Bitwarden's password-protected JSON export.** This needs Bitwarden's KDF and AES-CBC-HMAC decryption in `rizzy-import`. It spares users from leaving an unencrypted export file on disk. *Recommendation:* not in M1, which supports plain Bitwarden JSON only. Add it in M3 if users ask, confined to `rizzy-import`.
2. **Session binding for native clients** ([THREAT_MODEL Q-7](../THREAT_MODEL.md#10-open-questions-for-the-owner); [CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication) leaves this to the API ADR). *Recommendation:*
   - From M1, native clients sign every request, or a per-session nonce, with the device key, so a stolen bearer token alone is useless.
   - The web vault keeps short-lived bearer tokens.
   - The change is additive to `v1`, and it costs less now than later.
3. **Deprecation window.** *Recommendation:* the rule above, two server releases or six months, whichever is longer. Confirm it, or pick other numbers.
4. **Before v1.0: forced client update (point 5), or the `/api/v2` overlap from M2 on.** The forced update keeps the pre-1.0 API cheap to fix. Its cost is an "update required" state for users whose clients lag. Applying the overlap rule from M2 protects those users, at the price of carrying old API versions before the API has settled. *Recommendation:* the forced update, with the store-first release rule.

## References

- [ROADMAP](../ROADMAP.md) §1, §4.2, §5 (row "Protocol"), §6.2
- [THREAT_MODEL](../THREAT_MODEL.md) §5.1, §5.2, INV-1, Q-7
- [CRYPTO.md](../CRYPTO.md) §1 (rules), §5.10, §9.6, §11.14
- [ADR 0003](0003-authentication-opaque.md), [ADR 0004](0004-key-derivation-argon2id-secret-key.md), [ADR 0007](0007-ciphertext-envelope.md), [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md)
- W. Palant, "Bitwarden design flaw: Server side iterations", 2023-01-23 (L)
- Bitwarden `sdk-internal`, `bitwarden-crypto/src/keys/kdf.rs` (`PBKDF2_MIN_ITERATIONS = 5000`) and the V2 COSE formats (V)
- Bitwarden security white paper, key hierarchy and authentication structure (V, pre-2023 snapshot)
- Scarlata, Torrisi, Backendal, Paterson, "Zero Knowledge (About) Encryption", ePrint 2026/058 (L)
