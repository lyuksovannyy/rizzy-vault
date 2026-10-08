# ADR 0036: Browser extension: architecture and key custody

- Status: Partially superseded by [ADR 0040](0040-extension-fill-request-from-inline-menu.md) (§4, first bullet, in part)
- Date: 2026-10-07
- Deciders: project owner
- Milestone: M2

## Context

The owner moved the browser extension, URL matching and passkey storage/use in the browser from M7 to M2 on 2026-10-07 ([ROADMAP §3](../ROADMAP.md#3-milestones) M2 row; [§4.4](../ROADMAP.md#44-url-matching--autofill-m2), [§4.10](../ROADMAP.md#410-mobile--passkeys-m7)). ROADMAP §4.4, Must, M2: "Browser extension: Chromium (MV3) + Firefox — inline menu, fill, save/update on submit, generator in field." This ADR is the key-custody and architecture decision that [ADR 0014](0014-ui-stack.md) (UI stack) deliberately left open for the extension ("the content script is plain TypeScript whatever we pick") and that [ADR 0013](0013-shared-client-core.md) §4 already partly answers but did not freeze as a binding decision ("Lifetimes are confirmed in M2 (U)").

**What already binds.**
- [ADR 0013](0013-shared-client-core.md) (Accepted) §2, §3, §4: the core is `rizzy-client` through `rizzy-wasm`, the same backend as the web vault. Rule 1 ("keys stay in Rust") holds only if every handle and the KDF output stay in **one wasm instance**; the core is never split across contexts. §4 names the candidates: "one long-lived context holds the instance: an offscreen document on Chromium, the background page on Firefox," never the MV3 service worker, which Chromium terminates when idle (about 30 s, general knowledge, U). If neither context survives, the fallback is the one *named exception* in §3 rule 2: unlocked key state goes out as opaque bytes into `storage.session`, restored when the long-lived context restarts, never into `storage.local` or IndexedDB ([INV-63](../THREAT_MODEL.md#8-security-invariants)).
- [ADR 0026](0026-client-device-state-and-cache.md) (Accepted), Milestone line: "M2 (extension, IndexedDB)". §3 "IndexedDB (M2)": "holds the same logical stores, keyed identically, with the same blobs" as the SQLite cache. §2 defines `device_state` with `u8(device_kind: 1–3)`, parsed and rejected outside that range.
- [THREAT_MODEL.md](../THREAT_MODEL.md) §7.2 (STRIDE, browser extension), A7 (malicious page scripts), A8 (stolen device, extension has no OS keystore), [INV-36](../THREAT_MODEL.md#8-security-invariants) to [INV-42](../THREAT_MODEL.md#8-security-invariants), INV-63, INV-64, INV-68.
- [CRYPTO.md](../CRYPTO.md) §11.2–§11.3 (durable-device enrolment and unlock) versus §11.4 (web vault: ephemeral per-session device key, no `E_local`, nothing persisted but an opt-in SK).
- [ADR 0016](0016-workspace-layout.md) §3: `rizzy-match` (M2, URL normalisation, PSL, signed equivalence lists) is a planned R1 crate, no I/O, used by every client. `rizzy-wasm` already exists (M1).
- [ADR 0018](0018-item-record-encoding.md) §7 reserves `passkey.` and `passkey/` field-key prefixes for the M7 ADR; this ADR's companion [ADR 0039](0039-passkeys-vault-and-extension.md) is that ADR, moved to M2.

**What is not yet decided**, and is this ADR's job:
1. Is the extension a **durable device** (its own `device_id`, `E_local`, `E_dev`, enrolled per [CRYPTO.md §11.2](../CRYPTO.md#112-login-on-a-new-device-server-mode)) or an **ephemeral client** like the web vault ([§11.4](../CRYPTO.md#114-web-vault))?
2. Which context holds the core, concretely, and what the service worker, popup, options page and content script may each do.
3. How unlock, auto-lock and the encrypted cache work for a device that has no OS keystore ([A8](../THREAT_MODEL.md#a8-stolen-or-lost-device)).
4. The messaging contract between content scripts (untrusted input, per [INV-40](../THREAT_MODEL.md#8-security-invariants)) and the core.
5. Crate and package boundaries: whether the extension needs a new Rust crate, or reuses `rizzy-wasm` and `packages/core`.

## Decision

### 1. Durable device, not ephemeral

**The extension enrols as a durable device**, kind 1–3 client in [CRYPTO.md §11](../CRYPTO.md#11-flows)'s sense, running [§11.2](../CRYPTO.md#112-login-on-a-new-device-server-mode) (new-device login and enrolment) and [§11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) (unlock), never [§11.4](../CRYPTO.md#114-web-vault) (the web vault's ephemeral per-session device key). This matches [ADR 0013](0013-shared-client-core.md) §2's capability table, which gives the extension IndexedDB persistence for "wrapped device state and ciphertext" — something the web vault explicitly does not get — and [THREAT_MODEL](../THREAT_MODEL.md) A8, which already describes "the browser extension has no OS keystore at all. Its SK, `E_local` and `E_dev` live in the browser profile on disk" as an existing fact about a durable device, not a hypothetical.

Consequences of this choice:
- The extension has its own `device_id`, device Ed25519/X25519 keypair, `device_salt`, and persists `E_dev`, `E_local` and (M3+, if a platform ever exposes a strength-equivalent store to an extension, which none does today) no `E_ks`.
- It runs one Argon2id evaluation per unlock ([CRYPTO.md §5.6](../CRYPTO.md#56-offline-unlock)), not an OPAQUE login on every session like the web vault.
- Its ops are signed by its own device key and show up in the signed device set and the "new device enrolled" notification ([CRYPTO.md §11.2](../CRYPTO.md#112-login-on-a-new-device-server-mode) step 8), unlike a kind-4 web-vault certificate.

**Device kind value.** The extension uses `device_kind` **2**, which [CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements) (`device-certificate`) and `rizzy-core` (`DeviceKind::Extension = 2`) already assign to the browser extension (1 desktop/CLI, 2 extension, 3 mobile, 4 web-ephemeral). [ADR 0026](0026-client-device-state-and-cache.md) §2 already parses `device_kind` in `1–3`, so the extension's `device_state` needs no new value. Kind 4 is never used: it is left out of the signed device set ([CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)), which is exactly what a durable device must not be.

### 2. Which context holds the core

- **Long-lived context:** an **offscreen document** on Chromium (`chrome.offscreen`, `reasons: ["WORKERS"]` or the closest justification the API accepts), the **background page** on Firefox (MV3 `background.scripts`, which Firefox keeps non-ephemeral unlike Chromium's event page). This context loads `rizzy-wasm` once and holds every `UnlockedVault`/`Session` handle, exactly as [ADR 0013](0013-shared-client-core.md) §4 describes for the web vault's dedicated Worker, but for the whole extension lifetime instead of one tab's.
- **The MV3 service worker never holds the core.** It is message-routing only: it relays messages between the popup, options page, inline-menu iframe and content scripts and the long-lived context, and it is the only context both browsers guarantee can be woken on demand (`chrome.runtime.onMessage`, alarms). It holds no key material, ever (**MUST**).
- **Popup, options page, inline-menu iframe** run their own short-lived scripts (React, per [ADR 0014](0014-ui-stack.md) §1) that never load `rizzy-wasm` directly. They reach the core only through `packages/core`'s messaging-backed client, which the content script does not value-import ([ADR 0014](0014-ui-stack.md) §2, "no-restricted-imports").
- **Confirming survival (M2 spike, required before this ADR can be Accepted as written).** Whether the offscreen document and the Firefox background page in practice stay alive across the session is still unconfirmed ("Lifetimes are confirmed in M2 (U)", ADR 0013 §4). This ADR's fallback is the one already named in ADR 0013 §3 rule 2: if either is torn down while the user expects to stay unlocked, the extension restores unlocked state from `storage.session`, cleared on lock and on browser close, never from `storage.local` or IndexedDB (INV-63). The spike that confirms or refutes this is in scope for the implementation PR, not for this ADR.

### 3. Device enrolment, unlock, auto-lock, cache

- **Enrolment** follows [CRYPTO.md §11.2](../CRYPTO.md#112-login-on-a-new-device-server-mode) unchanged: server URL, login name, SK, master password; one Argon2id run for the OPAQUE login, a second for the local wrap at enrolment. The Emergency Kit flow does not re-run; the extension is a later device, not a signup.
- **Unlock** follows [§11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device): the offline part (open `E_dev`, one Argon2id run against `E_local`) happens inside the long-lived context; the online part authenticates with the device key as any durable client does ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication)).
- **Auto-lock.** A configurable idle timeout (default to be set with the M2 UI; recommend 15 minutes, matching common password-manager defaults, **U**, not verified against a standard), lock on `chrome.idle` / `browser.idle` reaching `locked` or `idle`, and an explicit "lock now" action in the popup. Locking zeroizes every handle in the long-lived context ([ADR 0013](0013-shared-client-core.md) §3 rule 1) and clears `storage.session` if that fallback was in use.
- **Encrypted local cache.** The extension uses [ADR 0026](0026-client-device-state-and-cache.md) §3's IndexedDB form unchanged: the same logical stores (`cache_meta`, `device_state`, `pending_commit`, `account_objects`, `vaults`, `wraps`, `ops`, `snapshots`), the same blobs, the same "columns are indexes, never facts" re-verification rule on load. `rizzy-wasm` exposes the same `store` module API that `rv` calls through sqlx, fed by an IndexedDB adapter written in the long-lived context (not in TypeScript: the adapter only moves bytes in and out of IndexedDB object stores; it parses nothing). No new persistent format is introduced.
- **No OS keystore.** The extension has no platform keystore to bind a biometric unlock secret to ([THREAT_MODEL](../THREAT_MODEL.md) A8, AR-14): it offers no keystore-gated unlock (`E_ks` stays unused for this client kind), consistent with [INV-62](../THREAT_MODEL.md#8-security-invariants)'s "where the OS cannot enforce presence, keystore unlock is not offered."

### 4. Messaging contract

- **Content script → background → long-lived context.** The content script (framework-free TypeScript, no wasm, per [ADR 0014](0014-ui-stack.md) §2) sends only: detected-field reports, a chosen fill request (after the user picks a credential in the extension-origin inline menu), and submitted-credential reports for save/update prompts. It never asks for or receives the master password, SK, or any decrypted item field beyond what the user is filling.
- **The background treats every content-script message as untrusted** ([INV-40](../THREAT_MODEL.md#8-security-invariants)): it takes the sender's origin from the browser's own sender information (`sender.origin`/`sender.tab.url`), never from the message body, validates the message shape, and only then forwards a well-formed request to the long-lived context.
- **Long-lived context → content script.** Only the chosen fill's values cross, at fill time, never a list of candidates with their secrets (list views show title/username/icon only, per [ADR 0013](0013-shared-client-core.md) §3 rule 3). The content script performs the actual DOM write.
- **Popup/options page ↔ long-lived context.** Coarse, one-call-per-action messages ("unlock", "lock", "list items", "save item", "generate password"), matching [ADR 0013](0013-shared-client-core.md) §3 rule 6. No primitive crypto call is ever exposed across a message boundary.
- **No `externally_connectable` for web origins** ([INV-40](../THREAT_MODEL.md#8-security-invariants)). Not even the configured server's own origin, because a malicious server controls that origin ([§4.2.1](../THREAT_MODEL.md#421-the-web-vault-delivery-problem)).

### 5. What a compromised page or content script can and cannot get

| Attacker position | Can get | Cannot get |
|---|---|---|
| Malicious page script (no extension bug) | Values filled into that page's own visible, same-origin fields after the user's fill gesture ([NG-12](../THREAT_MODEL.md#14-non-goals)); can try to draw a fake extension UI or clickjack the inline menu | The master password or SK (never requested in page-injected UI, [INV-40](../THREAT_MODEL.md#8-security-invariants)); any field the user did not choose to fill; any key material (held only in the long-lived context) |
| A compromised/malicious content script (extension supply-chain bug confined to that script) | Whatever the page DOM exposes, and whatever the background accepts from it before validation | Direct access to `rizzy-wasm` memory (the content script never loads it); unlocked keys (held only in the long-lived context, never in `storage.local`/IndexedDB in cleartext, INV-63) |
| A bug in the background (service worker) message router | Can relay or drop messages | Cannot read key material; it never holds any |
| Full compromise of the extension's own trusted contexts (background, offscreen/background-page, popup) — equivalent to malware on an unlocked device | Everything: this is [NG-1](../THREAT_MODEL.md#14-non-goals), game over, same as any other client | — |

### 6. Crate and package boundaries

- **No new Rust crate.** The extension reuses `rizzy-wasm` (M1, already a leaf over `rizzy-client`, [ADR 0016](0016-workspace-layout.md) §3) and `packages/core` (the typed TypeScript wrapper, [ADR 0014](0014-ui-stack.md) §4). The same size-budgeted wasm bundle that serves the web vault serves the extension's long-lived context; `rizzy-match` (M2, URL normalisation and PSL) is linked in the same way.
- **`apps/extension`** (already named in [ADR 0016](0016-workspace-layout.md) §7 and [ADR 0014](0014-ui-stack.md) Context) holds: the MV3 manifest(s) for Chromium and Firefox, the service worker, the offscreen-document/background-page script, the popup and options-page React apps, the inline-menu iframe app, and the framework-free content script. None of it joins the Cargo workspace.
- **IndexedDB adapter.** A small TypeScript module inside `apps/extension` (not `packages/core`, which stays platform-neutral) that implements the host-provided storage capability [ADR 0013](0013-shared-client-core.md) §2 names for the extension row, calling `rizzy-wasm`'s `store` bindings with raw bytes it never interprets.

### Owner answers at acceptance (2026-10-07)

The owner accepted this ADR with the recommendations of "Open questions for the owner": the device kind is 2 (§1); auto-lock defaults to 15 minutes idle, user-configurable; the Chromium offscreen document uses reason `WORKERS`, and the justification string the Chrome Web Store accepts is recorded with the M2 code.

## Consequences

### Positive

- One wasm backend (`rizzy-wasm`) and one cache format (ADR 0026) serve the web vault, the CLI and the extension; no new persistent format, no new crate.
- The extension is a durable, auditable device: its edits are attributed and visible in the device list, unlike a web-vault session.
- The MV3 service worker's termination, which would be fatal if it held keys, is harmless because it never does.

### Negative

- A second Rust-host context (offscreen document / background page) to keep alive, confirm, and fall back from, on top of the web vault's Worker.
- The extension carries the whole wasm bundle into a second surface; the size budget ([ADR 0013](0013-shared-client-core.md) §4) now has two consumers to watch.
- No OS keystore means the extension stays at the Argon2id-floor offline-guessing exposure of [THREAT_MODEL](../THREAT_MODEL.md) AR-14 for as long as it ships.

### Risks

- If the M2 spike shows neither offscreen document nor Firefox background page survives reliably, the `storage.session` fallback becomes the common case rather than a rare one, which widens INV-63's "readable by any code in the extension's trusted contexts" exposure ([ADR 0013](0013-shared-client-core.md) Risks). Signal: the spike's own measurement.
- Browser API changes (Chromium narrowing offscreen-document justifications, Firefox changing MV3 background-page persistence) could force a redesign. Mitigation: the fallback above already exists for exactly this.

## Alternatives considered

- **Treat the extension as ephemeral, like the web vault (CRYPTO §11.4).** Rejected: it throws away the one advantage the extension has over the web vault (store-delivered code, not server-delivered), and ADR 0013's own capability table already gives it durable storage. An ephemeral extension device would also need a new flow this ADR would have to invent, where a durable one already has §11.2–§11.3.
- **Hold keys in the popup only, closing them on popup close.** Rejected: popups close on every outside click, which would mean re-entering the master password after nearly every fill — unusable, and it does not solve the "where do unlocked keys live between popup opens" problem at all.
- **A native-messaging host process for key custody**, as some extensions use for OS keystore access. Rejected for M2: it needs an installed companion binary, which raises the friction of installing the extension alone, and no OS exposes a hardware-bound secret to it any more readily than to the extension itself (no keystore story improves).

## Open questions for the owner

1. *Resolved before acceptance:* the device kind is 2 (§1, "Device kind value").
2. **Auto-lock default timeout.** *Recommendation:* 15 minutes idle, user-configurable, consistent across the extension and the future desktop/mobile clients (an M3/M7 decision to align, not re-decide, per client).
3. **Chromium offscreen-document justification.** `chrome.offscreen` requires a `reason` from a fixed enum; none of them is written for "hold a wasm instance". *Recommendation:* use `WORKERS` (closest fit: "the extension needs to use a worker") and record the exact justification string actually accepted in the M2 spike notes; revisit if the Chrome Web Store review rejects it.

## What this ADR supersedes

Nothing. [ADR 0026](0026-client-device-state-and-cache.md) stays binding as written: the extension uses `device_kind` 2, inside §2's `1–3`, and its IndexedDB cache is exactly §3's "IndexedDB (M2)" row. No Accepted ADR needs superseding: [ADR 0013](0013-shared-client-core.md) §2 and §4 already describe the extension's storage and context rules in a way this ADR narrows (picks the offscreen document / background page option, confirms the `storage.session` fallback) rather than contradicts, and [ADR 0014](0014-ui-stack.md)'s extension rows (§2 content-script rules, §5 component sharing) are unchanged.

## References

- [ROADMAP](../ROADMAP.md) §3 (M2 row, M7 row), §4.4, §4.10
- [THREAT_MODEL.md](../THREAT_MODEL.md) §3.1, §3.3 (TB-9), §7.2, A7, A8, A10, [INV-36](../THREAT_MODEL.md#8-security-invariants) to INV-42, INV-62, INV-63, INV-64, INV-68
- [CRYPTO.md](../CRYPTO.md) §5.6, §5.10, §11.2, §11.3, §11.4
- [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0013](0013-shared-client-core.md) §2–§4, [ADR 0014](0014-ui-stack.md) §1–§2, §4, [ADR 0016](0016-workspace-layout.md) §3, §7, [ADR 0018](0018-item-record-encoding.md) §7, [ADR 0019](0019-native-clients.md) §2.2, [ADR 0022](0022-server-mode-only.md), [ADR 0026](0026-client-device-state-and-cache.md) §2–§4, [ADR 0039](0039-passkeys-vault-and-extension.md)
- Chromium `chrome.offscreen` API docs; Firefox WebExtensions `background` key docs (M2 spike confirms exact lifetime behaviour; general platform knowledge, U, not re-verified for this ADR)
