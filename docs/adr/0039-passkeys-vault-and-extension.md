# ADR 0039: Passkeys in the vault and in the browser extension

- Status: Proposed
- Date: 2026-10-07
- Deciders: project owner
- Milestone: M2

## Context

The owner moved "Passkey storage (store WebAuthn credentials in vault) and use in the browser extension" from M7 to M2 on 2026-10-07 ([ROADMAP §4.10](../ROADMAP.md#410-mobile--passkeys-m7); native-app passkey use via the OS stays M7). This is the ADR [ADR 0018](0018-item-record-encoding.md) owner decision 6 already anticipated: "Reserve both a standalone type (`0x000A`) and a `passkey/` list on Login? **Yes.** The M7 passkey ADR uses one and releases the other." Moving the milestone does not change that delegation; this ADR exercises it now.

**What already binds.**
- [ADR 0018](0018-item-record-encoding.md) (Accepted) §7 reserves the prefixes `passkey.` and `passkey/` for the item that ships this; §8 reserves item type `0x000A` "Passkey, standalone" and notes both reservations are live until this ADR picks one.
- [ADR 0009](0009-crypto-dependency-policy.md) (Partially superseded by [ADR 0019](0019-native-clients.md) in part; otherwise Accepted) fixes the approved crypto crates and the checklist for adding a new one. **Neither of the two signature algorithms WebAuthn needs is fully covered today:** Ed25519 is already pinned (`ed25519-dalek` 3.0.0), but ECDSA over P-256 (COSE alg `-7`, "ES256"), which essentially every relying party (RP) requires, is **not** in the allowed-crate table. This ADR identifies that gap; it does not itself approve the new crate (see [§3](#3-signature-algorithms-and-the-new-dependency-gate)).
- [THREAT_MODEL](../THREAT_MODEL.md) [A7](../THREAT_MODEL.md#a7-malicious-web-page-scripts-against-the-extension), "Passkey provider (M7)" and [INV-64](../THREAT_MODEL.md#8-security-invariants), with its own "Note on INV-64" already flagging that the invariant's origin-binding rules must be checked and possibly widened "before M7." Since the feature now ships at M2, every place that note and INV-64 itself say "M7" needs saying "M2" instead (see [On acceptance](#on-acceptance)).
- [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) (this milestone's companion ADR) fixes where the extension's core instance lives and how content scripts and the background communicate; the passkey provider described here runs inside that same architecture, with the extra step of intercepting `navigator.credentials` in the page's main world ([THREAT_MODEL](../THREAT_MODEL.md) A7).
- [ADR 0037](0037-url-matching-and-autofill-rules.md) owns PSL-based registrable-domain checks; INV-64's `rpId` check reuses that exact logic, not a second implementation.
- [ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8), Could, post-1.0: "Login with passkey (PRF extension to derive unlock key)." That is a **different** feature (using a passkey to unlock the vault itself) from this ADR's scope (storing and presenting passkeys *for other sites*), and stays out of scope here.
- [ROADMAP §4.10](../ROADMAP.md#410-mobile--passkeys-m7), Should, M8: "Passkey import/export via FIDO Credential Exchange Protocol (CXP/CXF) when stable." Out of scope for M2; noted so the item representation does not foreclose it.

## Decision

### 1. Item representation: the `passkey/` list, not the standalone type

**Recommendation and decision: use the `passkey/<id>/…` list on the Login item type. Release `0x000A` to unassigned.**

Reasoning:
- A passkey is, in practice, an alternative or additional credential for a site a user already has, or is creating, a Login item for. Attaching it to the existing Login keeps one item per site with one autofill surface (username, password, TOTP, and now passkey, together), matching how the extension's inline menu already presents candidates ([ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4) and how 1Password and Bitwarden model the same feature today (general product knowledge, **L**, not independently re-verified for this ADR).
- A standalone `0x000A` item would need its own autofill-candidate path next to Login's, doubling the matching and fill-UI logic ([ADR 0037](0037-url-matching-and-autofill-rules.md)) for no benefit: a passkey has no independent "home" the way a Secure Note or Card does.
- The list form already supports multiple passkeys per Login (rare but real: a site can offer several passkeys for one account), with `<id>` the usual random element id ([ADR 0018](0018-item-record-encoding.md) §7).

**Field keys** (fulfilling ADR 0018's reservation, not superseding it):

| Key | Value type | Notes |
|---|---|---|
| `passkey/<id>/rp_id` | Text | The registrable-domain-or-suffix the credential was created for. Never written from page-supplied data at use time; only at creation, after the INV-64 check |
| `passkey/<id>/user_handle` | Bytes | The RP's opaque user handle, ≤ 64 bytes per the WebAuthn spec (**L**, byte limit not independently re-verified) |
| `passkey/<id>/credential_id` | Bytes | Opaque credential id the RP references on every assertion |
| `passkey/<id>/private_key` | Bytes | The raw private scalar/seed, concealed by default like `login.password` ([ADR 0018](0018-item-record-encoding.md) §7's concealed-by-default list gains this key, see [On acceptance](#on-acceptance)) |
| `passkey/<id>/public_key_cose` | Bytes | The COSE-encoded public key this ADR hands-writes ([§4](#4-webauthn-message-assembly-no-new-cbor-dependency)) |
| `passkey/<id>/alg` | Enum (`u16`) | COSE algorithm id of this credential: `1` = ES256 (`-7`), `2` = EdDSA/Ed25519 (`-8`). Values chosen as small positive integers per ADR 0018's Enum convention, mapped to the real COSE negative ids only at the WebAuthn boundary |
| `passkey/<id>/discoverable` | Bool | Always `0x01` for M2: every credential we create is a discoverable (resident) credential, since that is what lets a passkey be offered without the RP first asking for a username |
| `passkey/<id>/created_ms` | U64 | Local display time, same convention as `import.created_ms` |

`item.name` and the existing Login username/URL fields continue to label the item in the UI; no new top-level item field is needed beyond the list.

### 2. WebAuthn registration and assertion in the extension

- **Interception point.** As [THREAT_MODEL](../THREAT_MODEL.md) A7 already describes for this exact feature: the extension injects a script into the page's main world that overrides `navigator.credentials.create`/`.get` (and the `PublicKeyCredential` feature-detection statics), and relays the call, over `postMessage` into the isolated-world content script and from there to the background ([ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4), **never** trusting any field of the intercepted call for the RP origin (next bullet).
- **Origin and `rpId` ([INV-64](../THREAT_MODEL.md#8-security-invariants)).** The background takes the caller's origin from the browser's own sender information (`sender.origin`), never from the page-supplied `postMessage` payload. It requires HTTPS. It checks the requested `rpId` equals the origin's host, or is a registrable-domain suffix of it per the PSL ([ADR 0037](0037-url-matching-and-autofill-rules.md) §3), and is never a bare public suffix. `clientDataJSON`'s `origin`, `crossOrigin` and `topOrigin` fields are set from that verified origin, never echoed from the request. Cross-origin iframes are refused by default, mirroring [ADR 0037](0037-url-matching-and-autofill-rules.md) §5's rule for password fills.
- **User verification and presence.** Every assertion and every registration runs only while the vault is unlocked (which already required the master password, an OPAQUE login, or a future keystore-gated unlock, [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §3) **and** after an explicit user gesture choosing the credential in the extension-origin inline menu or popup, mirroring [ADR 0037](0037-url-matching-and-autofill-rules.md) §5's gesture-only rule. `authenticatorData` flags are set `UP=1` (user present: the gesture), `UV=1` (user verified: the unlock already authenticated the user), `BE=1`/`BS=1` (backup eligible/backup state: these are explicitly backed-up, synced credentials).
- **Signature counter.** The signature counter in `authenticatorData` is fixed at `0` and never incremented. This is the standard signal relying parties use to recognise a synced, multi-device credential rather than a single hardware-bound one (general WebAuthn/passkey ecosystem convention; **L**, not independently re-verified against spec text for this ADR, but consistent with how every other synced-passkey provider behaves). A non-zero, incrementing counter would be actively misleading here: several devices sharing one vault could not keep it consistent without a new sync primitive, and RPs do not expect one from a synced credential.
- **Key generation.** One fresh keypair per credential, generated with the same injected `rand_core::CryptoRng` every other `rizzy-core` key uses ([ADR 0009](0009-crypto-dependency-policy.md) "RNG rules"), never derived from any other vault secret: a passkey's private key has no reason to be re-derivable, and making it so would only create a new key-compromise blast radius to reason about.

### 3. Signature algorithms and the new-dependency gate

| COSE alg | Name | Status in this project | Needed because |
|---|---|---|---|
| `-7` | ES256 (ECDSA P-256, SHA-256) | **Not yet an approved dependency.** [ADR 0009](0009-crypto-dependency-policy.md)'s crate table has no P-256/ECDSA crate | Essentially every relying party's `pubKeyCredParams` lists ES256, and many require it; a provider that cannot produce ES256 credentials cannot create passkeys for most real sites (**L**, general WebAuthn ecosystem knowledge, not re-verified against a survey of RPs for this ADR) |
| `-8` | EdDSA (Ed25519) | Already approved (`ed25519-dalek` 3.0.0, [ADR 0009](0009-crypto-dependency-policy.md)) | Costs no new dependency, but fewer RPs accept it |

**This ADR does not approve a P-256 crate.** Doing so is [ADR 0009](0009-crypto-dependency-policy.md)'s own gate, and that ADR requires its checklist to be answered in the PR that adds the dependency. What follows is this ADR's best-effort pass at that checklist, so the owner and the eventual approval PR start from something, with every unverified claim marked:

1. **Need.** COSE alg `-7` / ES256 for WebAuthn credential creation and assertion signing ([§2](#2-webauthn-registration-and-assertion-in-the-extension)). No construction of ours; the algorithm, curve and hash are all fixed by the WebAuthn/COSE specs, not chosen by us.
2. **Provenance.** Candidate: `p256` (RustCrypto, the same family as `ed25519-dalek`'s sibling crates and the AEAD/KDF crates already pinned). Exact version, maintainer activity and download counts: **U**, not checked for this ADR.
3. **Audit history.** **U.** RustCrypto's elliptic-curve crates have had informal and partial reviews in the past (general reputation, **L**), but no specific audit of `p256` was located for this ADR.
4. **Advisories.** **U**, not checked against RustSec for this ADR; the approval PR must run this check.
5. **`unsafe` in the crate.** **U.**
6. **Constant-time claims.** RustCrypto's elliptic-curve crates generally aim for constant-time scalar operations via the `elliptic-curve`/`crypto-bigint` stack already transitively present through `opaque-ke` ([ADR 0009](0009-crypto-dependency-policy.md) crate table); whether `p256` specifically meets our bar is **U**.
7. **Builds and hygiene.** Whether `p256` builds for `wasm32-unknown-unknown` with a `default-features = false` set that avoids `getrandom`, matching the R1 no-I/O rule this feature's own code must live under ([§5](#5-crate-and-module-boundaries)): **U**.
8. **Test vectors.** FIPS 186-5 / RFC 6979 (deterministic ECDSA) or the WebAuthn test vectors a conformance suite publishes would be the natural choice: **U**, not identified for this ADR.

**This checklist is intentionally incomplete.** It is handed to whoever drives the implementation PR as a starting point, not a substitute for actually running it. Until it is answered and the owner approves the dependency, **no ES256 code is merged**, per [ADR 0009](0009-crypto-dependency-policy.md)'s own rule ("the PR that adds the dependency must update this ADR, or supersede it... the owner approves").

### 4. WebAuthn message assembly: no new CBOR dependency

The WebAuthn spec requires `attestationObject` to be a CBOR map and `authenticatorData` to embed a CBOR-encoded COSE public key. Rather than add a general-purpose CBOR crate — which [ADR 0018](0018-item-record-encoding.md) already rejected for our own item records on determinism and audit-surface grounds — this ADR recommends the same approach: **hand-write the small, fixed set of CBOR structures WebAuthn actually needs** (a COSE `EC2` key map for ES256, a COSE `OKP` key map for EdDSA, and the handful of top-level maps `attestationObject` requires for `"none"` attestation, which is all M2 needs — we are not a hardware authenticator claiming a certified attestation chain). This is new, interoperability-mandated wire format, not a new "composition" over our own primitives in [CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules) Rule 2's sense, so it does not need to join that list; it does need known-answer vectors checked against real browser behaviour in the M2 implementation ([§8](#8-tests), noted under Consequences).

### 5. Crate and module boundaries

- **Key generation and signing** (ES256 once approved, EdDSA already approved) live in `rizzy-core`, next to every other primitive, under the same no-`unsafe`, no-I/O, wasm32 rules ([ADR 0016](0016-workspace-layout.md) R1). The passkey-rs family of crates [ADR 0016](0016-workspace-layout.md) §4 already flagged ("Known conflict ahead... depend on getrandom 0.2 non-optionally... cannot enter an R1 crate as they are") is **not used**: this ADR's design needs no CTAP/FIDO-authenticator crate at all, only raw signature primitives we already use or are gating in ([§3](#3-signature-algorithms-and-the-new-dependency-gate)), which resolves that flagged conflict by not needing the conflicting crates in the first place.
- **WebAuthn wire-format assembly** (`clientDataJSON`, `authenticatorData`, the hand-written CBOR of [§4](#4-webauthn-message-assembly-no-new-cbor-dependency)) lives in `rizzy-client`, which already owns client-flow orchestration ([ADR 0013](0013-shared-client-core.md) §1); it calls into `rizzy-core` only for key generation, signing and the item-field encryption every other field already goes through (no new envelope purpose: `passkey/<id>/private_key` is `ITEM_OP`/`ITEM_SNAPSHOT` data under the item key, exactly like `login.password`).
- **Interception and messaging** (the page-world override, the content-script relay, the background's origin check, the long-lived context holding the unlocked vault) live in `apps/extension`, under [ADR 0036](0036-browser-extension-architecture-and-key-custody.md)'s architecture, with no new Rust crate.
- **`rizzy-wasm`** exposes the coarse calls ("create passkey," "get assertion for RP X") that `rizzy-client`'s state machine implements, matching [ADR 0013](0013-shared-client-core.md) §3 rule 6 ("the API is coarse").

### 6. PRF extension and export/import: explicitly deferred

- **PRF extension.** Not implemented in M2. Deriving an unlock key from a passkey ([ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8), Could, post-1.0) is a different feature (using a passkey *to unlock the vault*) from storing and presenting passkeys *for other sites*, which is all ROADMAP §4.10's M2 row asks for. Revisit with that post-1.0 item.
- **CXF import/export.** Not implemented in M2 ([ROADMAP §4.10](../ROADMAP.md#410-mobile--passkeys-m7), Should, M8). The field-key design above does not foreclose it: a future CXF importer, in `rizzy-import` ([ADR 0016](0016-workspace-layout.md) §3), would build the same `passkey/<id>/…` fields from a parsed CXF payload.

## Consequences

### Positive

- Passkeys live next to the Login they belong to, with no second autofill path to build or audit.
- No CTAP/FIDO-authenticator crate, and no new "composition" for CRYPTO.md's audit-scope list: the only new primitive is a signature algorithm, gated through the existing ADR 0009 process.
- The INV-64 origin/`rpId` check reuses `rizzy-match`'s PSL logic exactly, so there is one registrable-domain implementation in the whole project, not two.

### Negative

- ES256 support is blocking: without it the feature is not useful for most real sites, so the ADR 0009 approval of a P-256 crate is on the M2 critical path, not an optional follow-up.
- Hand-writing WebAuthn's CBOR structures, even a small fixed set, is new parser/encoder surface that needs its own fuzz target and known-answer vectors against real browser WebAuthn behaviour, which nothing in this repository currently exercises.
- `0x000A` is released but not reused for anything else without a fresh ADR; the type-id table keeps the number permanently retired in practice, even though the ADR 0018 table marks "unassigned" slots as reusable in principle.

### Risks

- **A P-256 implementation bug or timing leak** would be a real vulnerability in a primitive this project did not need before. Mitigation: the ADR 0009 checklist, run properly before merge, and M8 audit scope growing to include it.
- **Browser WebAuthn API surface drift** (Chromium and Firefox evolving `navigator.credentials` behavior, or tightening what a content script may override) could break the interception approach. Signal: either browser's release notes on WebAuthn/credential-management changes; mitigation is the same "update the extension" path every other browser-API dependency already has.
- **Relying parties that require attestation statements stronger than `"none"`** (rare, mostly enterprise RPs) will reject our credentials. Accepted for M2: the overwhelming majority of consumer RPs accept `"none"` attestation from recognised password-manager passkey providers (**L**, general ecosystem knowledge).

## Alternatives considered

- **Standalone `0x000A` item type.** Rejected per [§1](#1-item-representation-the-passkey-list-not-the-standalone-type): doubles the autofill-candidate and fill-UI surface for no benefit at this stage. Could be revisited if a future need (a site-less passkey, or an org-shared passkey with no accompanying Login) ever arises, which would need a fresh ADR to un-release `0x000A`.
- **A FIDO/CTAP authenticator crate family** (the "passkey-rs" crates [ADR 0016](0016-workspace-layout.md) §4 already flagged). Rejected: they target roaming/CTAP authenticators and pull `getrandom` 0.2 non-optionally, which cannot enter an R1 crate; our design needs none of their CTAP machinery since the extension talks the JavaScript-level WebAuthn API directly, not CTAP.
- **ES256-only, dropping EdDSA support entirely.** Rejected as unnecessary: EdDSA costs nothing extra (already pinned) and some RPs prefer or require it; supporting both at credential-creation time, defaulting to whichever the RP's `pubKeyCredParams` ranks first, costs little once ES256 exists.
- **Implementing attestation beyond `"none"`.** Rejected for M2: a self-attestation or packed-attestation statement would need an attestation certificate chain we have no reason to hold, and no RP relevant to this product's audience requires it.

## Open questions for the owner

1. **Approve the P-256 (ES256) crate addition**, following [ADR 0009](0009-crypto-dependency-policy.md)'s process, with the checklist in [§3](#3-signature-algorithms-and-the-new-dependency-gate) completed properly (not this ADR's best-effort pass). *Recommendation:* approve `p256` (RustCrypto) pending that completed checklist, since no viable alternative exists in the approved-crate family.
2. **Attestation format.** *Recommendation:* `"none"` attestation only for M2, as [§6](#6-prf-extension-and-exportimport-explicitly-deferred) area and Alternatives discuss; revisit only if a real user need for a stronger-attestation RP surfaces.
3. **Multiple passkeys per Login, UI treatment.** This ADR's data model supports it ([§1](#1-item-representation-the-passkey-list-not-the-standalone-type)); whether the M2 UI exposes "add another passkey" on day one or waits is a product decision, not a security one. *Recommendation:* ship with the data model ready, UI for a second passkey can follow.

## On acceptance

The owner makes these edits in the change that accepts this ADR; none is made now:
1. **[THREAT_MODEL.md](../THREAT_MODEL.md) §7's "Passkey provider (M7)" heading and INV-64's "From" column** change "M7" to "M2," since the feature now ships at M2. The "Note on INV-64" following INV-64 is resolved by this ADR's §2 and removed or rewritten to say so, rather than continuing to ask the owner to decide it "before M7."
2. **[THREAT_MODEL.md](../THREAT_MODEL.md) [AST-9](../THREAT_MODEL.md#2-assets)**: "Passkeys (M7)" becomes "Passkeys (M2 in the extension; M7 for native OS providers)."
3. **[ADR 0018](0018-item-record-encoding.md)** is **not** edited: it is Accepted and immutable, and its owner decision 6 already provides for exactly this choice being made by "the M7 passkey ADR" (now this M2 one). Its §7 reserved-prefix table and §8 item-type table stay as written; this ADR's §1 is the record of which reservation is used.
4. **[ADR 0009](0009-crypto-dependency-policy.md)** gains the P-256/ECDSA crate row and feature-set line once the dependency-approval PR (open question 1) completes the checklist; this ADR does not add that row itself.

## References

- [ROADMAP](../ROADMAP.md) §3 (M2, M7 rows), §4.3, §4.10
- [THREAT_MODEL.md](../THREAT_MODEL.md) [A7](../THREAT_MODEL.md#a7-malicious-web-page-scripts-against-the-extension), [AST-9](../THREAT_MODEL.md#2-assets), [INV-64](../THREAT_MODEL.md#8-security-invariants) and its Note, [INV-41](../THREAT_MODEL.md#8-security-invariants) (the mobile analogue, M7)
- [CRYPTO.md](../CRYPTO.md) §1 (Rule 2), §8.4
- [ADR 0009](0009-crypto-dependency-policy.md) (crate table, approval checklist, RNG rules), [ADR 0013](0013-shared-client-core.md) §1, §3, [ADR 0016](0016-workspace-layout.md) §3–§4 (Known conflict ahead), [ADR 0018](0018-item-record-encoding.md) §1, §7, §8, owner decision 6, [ADR 0036](0036-browser-extension-architecture-and-key-custody.md), [ADR 0037](0037-url-matching-and-autofill-rules.md) §3
- WebAuthn Level 3 (W3C REC, cited by [THREAT_MODEL](../THREAT_MODEL.md) §11 as V/L already); COSE key and algorithm registries (IANA); general passkey-ecosystem conventions on synced-credential signature counters and `"none"` attestation acceptance (**L**, not independently re-verified for this ADR — confirm against current browser/RP behaviour in the M2 implementation)
