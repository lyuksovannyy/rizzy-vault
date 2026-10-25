# ADR 0111: The extension's unlocked state: no `storage.session` fallback, and idle and screen-lock auto-lock on Chromium and Firefox

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M2
- Supersedes: on acceptance, in part: [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) (§2 first and fourth bullets, §3 "Auto-lock" bullet, Negative first bullet, Risks); [ADR 0013](0013-shared-client-core.md) (§3 rule 2, extension sub-bullet; §4, "Lifetimes are confirmed in M2" sub-bullet; Risks, "Extension context lifetimes" bullet); [ADR 0019](0019-native-clients.md) (§1.4, ADR 0013 §2 capability table, row "Key storage for local unlock", Extension cell). §6 names the exact parts and gives their replacement text ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

The 2026-10-25 gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md), item **S5**, "erratum") found two majors in [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) (Accepted). Raw findings: [G04.md](../reviews/2026-10-25-raw/G04.md), G04-13 and G04-14.

### G04-13: the `storage.session` fallback cannot be built as decided

ADR 0036 §2, fourth bullet: "**Confirming survival (M2 spike, required before this ADR can be Accepted as written).** … if either is torn down while the user expects to stay unlocked, the extension restores unlocked state from `storage.session`, cleared on lock and on browser close". ADR 0013 §3 rule 2 names it as an exception: "the unlocked key state goes out as opaque bytes into `storage.session`, and comes back in when the extension's long-lived context restarts".

What stands against it (V unless marked):

1. **The precondition was accepted open.** The spike measured one thing: "a real unlocked session, left idle for 6 minutes … `chrome.offscreen.hasDocument()` still reports `true` … **Passed.** Still not measured: longer soaks (hours), real memory pressure, and Firefox" ([apps/extension/README.md](../../apps/extension/README.md), "The ADR 0036 §2 survival spike"; `e2e/lifetime.spec.ts`).
2. **The snapshot has no format.** No ADR says what the "opaque bytes" hold (account and vault keys? `pw_in`?), whether they are wrapped, under what key, or how a stale or foreign version is refused. That is a key-custody and persistent-format decision the ADR gate requires. The code has none: "`DurableSession` has no "resume from an opaque snapshot" constructor yet … a present-but-unusable snapshot is treated as stale and cleared" (`apps/extension/src/core-host/core-context.ts`, `startCoreContext`). `saveUnlockedSnapshot` in `core-host/session-store.ts` has no caller anywhere in `apps/extension`, so no build has ever written a snapshot.
3. **The writer cannot reach the store.** On Chromium the long-lived context is the offscreen document, and "a `chrome.offscreen` document's own `chrome` object has no `idle` or `storage` namespace at all — both are `undefined`" (README, "Offscreen documents have no `idle` or `storage`", measured). Chrome's reference agrees: "The `runtime` API is the only extensions API supported by offscreen documents" ([chrome.offscreen](https://developer.chrome.com/docs/extensions/reference/api/offscreen), V, read 2026-10-25). A snapshot would have to be relayed through the service worker, which ADR 0036 §2 forbids from holding key material: "It holds no key material, ever (**MUST**)".
4. **A wrap would not help.** A wrap key held in `storage.session` next to the snapshot protects nothing. A wrap key held in memory dies with the context the fallback exists to survive. No context that survives the offscreen document may hold keys. So any snapshot is, in effect, unwrapped key material in `storage.session`, which only the browser's in-memory, trusted-contexts-only access level protects. [CRYPTO.md](../CRYPTO.md) has no construction for it, and CLAUDE.md forbids inventing one.

### G04-14: idle and screen-lock auto-lock does not run on Chromium

ADR 0036 §3: "lock on `chrome.idle` / `browser.idle` reaching `locked` or `idle`". The code registers that listener only in the long-lived context, feature-detected: "`if (ext.idle !== undefined)`" (`core-host/listener.ts`), so on Chromium it never runs. The README calls this "A real, reported residual, not a design change: ADR 0036 §3's idle-based lock simply has no effect inside a Chromium offscreen document". `apps/extension/src/background/service-worker.ts` has no `idle` listener, though `manifest.chromium.json` already requests `"idle"`. On Chromium, the primary M2 browser, locking the OS screen does not lock the vault. Only the message-activity timer (`AutoLockTimer`, `core-host/lifecycle.ts`) runs.

### Two further facts found while preparing this ADR

- **The user's auto-lock setting is ignored on Chromium.** `readAutoLockMs` returns `DEFAULT_AUTO_LOCK_MS` when `ext.storage === undefined`, which is always true in the offscreen document; and the Firefox idle listener's detection interval is computed from `DEFAULT_AUTO_LOCK_MS`, not from the setting (`listener.ts`, V). ADR 0036 "Owner answers": "auto-lock defaults to 15 minutes idle, user-configurable".
- **Firefox has no long-lived context under MV3.** ADR 0036 §2 rests on "the **background page** on Firefox (MV3 `background.scripts`, which Firefox keeps non-ephemeral unlike Chromium's event page)". MDN says the opposite: "In Manifest V3, only non-persistent background scripts or a page are supported", and for the manifest key `persistent`, "Setting to `true` in Manifest V3 results in an error … `false` indicates the background page may be unloaded from memory when idle" ([Background scripts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Background_scripts), [manifest `background`](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background), V, read 2026-10-25). `manifest.firefox.json` is MV3 (V). So the Firefox build's core lives in an event page that the browser unloads when idle; how soon is U (an idle timeout of about 30 s is commonly cited, not verified). Every unload destroys the wasm instance. This is the case the fallback was meant for, on the browser where nobody measured it.

### What binds

- [ADR 0013](0013-shared-client-core.md) §3 rule 1 ("keys stay in Rust") and §4: one wasm instance, never split, never in the MV3 service worker.
- [THREAT_MODEL.md](../THREAT_MODEL.md) [INV-63](../THREAT_MODEL.md#8-security-invariants): unlocked key material "exists only in memory … or `storage.session` left at its default trusted-contexts access level". INV-63 *permits* `storage.session`; it does not require it. Dropping it narrows the invariant and needs no goal change.
- [ROADMAP](../ROADMAP.md) §4.4, Must, M2: "Browser extension: Chromium (MV3) + Firefox". The ROADMAP fixes MV3 for Chromium only. It does not fix the Firefox manifest version.

## Decision

### 1. No unlocked state outside the long-lived context

1. The extension writes no key material to any extension storage area: not `storage.local`, `storage.sync`, `storage.session` or IndexedDB. "Key material" is INV-63's list: account, vault, item and device private keys, `pw_in` and unlock keys, plus decrypted fields. The `storage.session` exception of ADR 0013 §3 rule 2 is removed (§6 B).
2. **A torn-down long-lived context means locked.** When the offscreen document (Chromium) or the background page (Firefox) is closed, crashes, is discarded or reloads, every handle in it is gone. The next context starts locked, exactly as after a browser start. There is no resume, no snapshot, no retry that restores keys. The user unlocks again (one Argon2id run, [CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device)).
3. The service worker recreates the offscreen document on the next message, as `ensureOffscreenDocument` does today. A popup or options request answered by a fresh context gets the existing locked status. A content-script request gets the existing locked refusal. This ADR adds no new error code.
4. **Code removal.** `core-host/session-store.ts` (`saveUnlockedSnapshot`, `restoreUnlockedSnapshot`, `clearUnlockedSnapshot`, `hasSessionStorage`, the key `rizzy.unlocked_snapshot.v1`) is deleted, with its imports and the restore branch of `startCoreContext`. No migration or clean-up step is needed: no build ever wrote that key (Context, G04-13 point 2), and `storage.session` is cleared when the browser closes (U, general knowledge, as ADR 0013 already marks it).
5. `storage.session` stays unused by the extension. A later use for non-secret state needs its own ADR.

### 2. Which context is the long-lived one

1. **Chromium (MV3).** The offscreen document, created with `reasons: ["WORKERS"]` (unchanged). Chrome documents that only `AUDIO_PLAYBACK` sets a lifetime limit: "All other reasons don't set lifetime limits" ([chrome.offscreen](https://developer.chrome.com/docs/extensions/reference/api/offscreen), V). The 6-minute soak passed (V). Hours-long survival and survival under memory pressure are not measured; §1.2 makes a teardown safe, and §7 step 6 measures how often it happens.
2. **Firefox: Manifest V2 with a persistent background page** (subject to Open question 1). `manifest.firefox.json` becomes `"manifest_version": 2` with `"background": { "page": "src/core-host/background-page.html", "persistent": true }`. The page loads `background-page.ts`'s bundle with one `<script type="module">` (Firefox support for a module script in an MV2 background page: U; if unsupported, the bundle is emitted as one classic script, with no other change). MDN: a persistent background page is "kept in memory from when the extension is loaded or the browser starts until the extension is unloaded or disabled, or the browser is closed", and after an extension-process crash "persistent background scripts running at the time of the crash are reloaded automatically" (V). A reload starts locked (§1.2). The other MV2 manifest changes are mechanical and change no permission: `action` becomes `browser_action`; `host_permissions` entries move into `permissions`; `web_accessible_resources` becomes the same four paths as a plain list; `content_security_policy` becomes the string `"script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'"` (whether Firefox MV2 needs or accepts `'wasm-unsafe-eval'` there: U, settled by the build in §7 step 5). `strict_min_version` stays `115.0`.
3. The service worker never holds the core (ADR 0036 §2, unchanged). Firefox under MV2 has no service worker; the background page is the only background context, as today.

### 3. Idle and screen-lock auto-lock

Three lock triggers, all calling the same `lock()` in the long-lived context (idempotent today: `session?.lock(); session = undefined`, V): the activity timeout, the OS idle state, and "lock now". The timeout and "lock now" are unchanged. The OS idle state works as follows.

**Constants** (in `core-host/lifecycle.ts`, shared by both browsers):

| Name | Value | Meaning |
|---|---|---|
| `autoLockMinutes` | the user's setting, through `clampAutoLockMinutes` (1–180, default 15; V, existing) | both the activity timeout and the idle detection interval |
| `idleIntervalSeconds` | `autoLockMinutes * 60` (60–10 800) | passed to `setDetectionInterval` and `queryState`; always above the API's floor (15 s per the current code comment, U) |
| `IDLE_POLL_MS` | 30 000 | Chromium only: how often the offscreen document asks for the idle state while unlocked |

A state of `"idle"` or `"locked"` locks. `"active"`, any other string, or no answer does not.

#### 3.1 Chromium: the service worker detects, the offscreen document locks

The service worker has `chrome.idle`; the offscreen document does not. The service worker only relays a state; it holds nothing secret, so ADR 0036 §2's MUST is kept.

1. **Push.** `background/service-worker.ts` registers `chrome.idle.onStateChanged` **synchronously at the top level of the module**, next to the existing `onMessage` listener (Chrome: handlers "should be declared in the global scope … registered synchronously on initial script execution", [service-worker events](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/events), V). On `"idle"` or `"locked"` it calls `chrome.offscreen.hasDocument()`; if `true` it sends `{ type: "idle_state", state }` with `chrome.runtime.sendMessage`. If `false` it does nothing: it never creates the document to lock it, since a missing document is already locked. A failed send is dropped; the poll (item 3) covers it.
2. **Interval.** After registering its listeners, the service worker reads the setting from `storage.local` and calls `chrome.idle.setDetectionInterval(idleIntervalSeconds)` on every start of the worker, and again from `storage.onChanged` when the setting key changes. Whether the interval survives a worker restart is U, so it is never assumed to.
3. **Poll.** Whether `onStateChanged` wakes a terminated service worker is **U** (not found in Chrome's reference, not measured). So the lock must not depend on it. While a session is unlocked, the offscreen document sends `{ type: "idle_status_query" }` to the service worker every `IDLE_POLL_MS` (a `runtime` message, which the offscreen document can send and which wakes the worker, ADR 0036 §2). The worker answers `{ type: "idle_status", state, autoLockMinutes }`, where `state` is `await chrome.idle.queryState(idleIntervalSeconds)` ("Returns "locked" if the system is locked, "idle" if the user has not generated any input for a specified number of seconds", [chrome.idle](https://developer.chrome.com/docs/extensions/reference/api/idle), V). The poll starts when an unlock succeeds and stops in `lock()`. One more query is sent once when the offscreen document starts, for `autoLockMinutes` only.
4. **Setting.** On every `idle_status` answer the offscreen document runs `autoLockMinutes` through `clampAutoLockMinutes` and, if it differs from the timer's current value, calls the existing `AutoLockTimer.setTimeoutMs`. This fixes the ignored setting (Context) through the same channel.
5. **Senders.** The offscreen document's listener accepts `idle_state` and handles `idle_status` answers only from the extension's own pages (`isOwnExtensionPage`, existing), never from a content-script sender. The service worker answers `idle_status_query` only when `sender.id === chrome.runtime.id` and `sender.tab === undefined`, the same check as its existing relays. Neither type is on the content-script message list, so the content-script relay refuses both before any handler runs. An own extension page that sends `idle_state` can only cause a lock, which it can already do with `lock`.
6. **Validation.** A message is acted on only if `state` is exactly `"idle"` or `"locked"`. A malformed `idle_status` answer, a rejected send, or no answer within `IDLE_POLL_MS` is ignored and does not lock: the next poll retries, and the activity timeout still runs. No error is shown, logged with a value, or returned.
7. **No version field.** These messages pass only between contexts of one installed build; an extension update reloads every context (L, general knowledge). The `type` string is the whole contract; a change to it is a code change in one build.
8. The offscreen document no longer touches `ext.idle` on Chromium. The feature-detected block in `listener.ts` stays only for Firefox (§3.2).

**Bound.** Unless the service worker cannot run at all, an unlocked Chromium extension locks within `IDLE_POLL_MS` plus one message round-trip after `chrome.idle.queryState` would report `"idle"` or `"locked"`, whether or not the push reached it (INV-124, §5).

#### 3.2 Firefox: the background page detects and locks

The persistent background page (§2.2) has `browser.idle` (MDN: background scripts can "use any WebExtension APIs" they have permission for, V; `"idle"` is already in `manifest.firefox.json`, V). It registers `browser.idle.onStateChanged` itself and locks on `"idle"` or `"locked"`. It calls `setDetectionInterval(idleIntervalSeconds)` at start and on `storage.onChanged`, using the setting (`readAutoLockMs`, which has `storage` there), not `DEFAULT_AUTO_LOCK_MS`. No relay and no poll: the page stays loaded, so it receives the event. Firefox's `IdleState` values are `"active"`, `"idle"`, `"locked"` ([MDN idle.IdleState](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/idle/IdleState), V); whether Firefox reports `"locked"` on every desktop OS is U.

### 4. What locking clears

Unchanged from ADR 0036 §3 and the code: every handle in the long-lived context is zeroized (ADR 0013 §3 rule 1), and the pending save prompts, save-prompt locations, passkey ceremonies, inline-menu instances and offers are cleared. The step "clears `storage.session` if that fallback was in use" goes away with the fallback.

### 5. Invariant

**INV-124** (provisional number): "On every supported browser, when the OS idle API reports `idle` (no input for the auto-lock interval) or `locked`, an unlocked extension locks: within 30 s on Chromium whether or not its service worker was running, and on the event on Firefox. Teardown of the long-lived context leaves the extension locked; no unlocked state is restored." Verified by: the e2e tests of §7 steps 2 and 4, and the manual screen-lock check of §7 step 7.

### 6. What this ADR supersedes

Each part below is replaced in full by the text after it. Nothing else in ADRs 0013, 0019 and 0036 changes. ADR 0036's Context, which describes the fallback as it was decided, stays as history.

None of these parts is named by an earlier Accepted supersession (V): ADRs 0040, 0043 and 0076 name only ADR 0036 §4; ADR 0022 names only ADR 0013 rule 2's pairing-QR sub-bullet; ADR 0019 §1.2 names ADR 0013 Risks only for its first bullet's closing paragraph, and restates the §2 capability table in its own §1.4. Shares after this ADR, counted with `wc -w` from `## Decision` to `## Consequences` (V for the counts as run, 2026-10-25): ADR 0036, 238 words named here plus at most 205 for §4 (ADRs 0040, 0043, 0076), at most 443 of 1,435 (31 %); ADR 0013, 152 words named here plus about 381 for ADRs 0019 and 0022, about 533 of 1,737 (31 %). Both stay below half ([ADR 0020](0020-partial-supersession.md) point 9, "Limit").

**A. ADR 0036 §2, first bullet** ("**Long-lived context:** … instead of one tab's."). Replaced by:

> - **Long-lived context:** an **offscreen document** on Chromium (MV3; `chrome.offscreen`, `reasons: ["WORKERS"]`), a **persistent background page** on Firefox (Manifest V2, `"background": { "page": …, "persistent": true }`; MV3 Firefox supports only non-persistent background pages, [ADR 0111](0111-extension-session-and-idle-lock.md) §2). This context loads `rizzy-wasm` once and holds every `UnlockedVault`/`Session` handle, exactly as [ADR 0013](0013-shared-client-core.md) §4 describes for the web vault's dedicated Worker, but for the whole extension lifetime instead of one tab's.

**B. ADR 0013 §3 rule 2, extension sub-bullet** ("**extension only (M2):** the unlocked key state goes out as opaque bytes into `storage.session` … It is used only if M2 shows the long-lived context cannot be kept alive;"). Replaced by:

>    - **extension only (M2):** none. Unlocked key state never leaves the long-lived context's wasm instance (§4) and is never written to any extension storage area, `storage.session` included. When that context is torn down, the extension is locked ([ADR 0111](0111-extension-session-and-idle-lock.md) §1);

**C. ADR 0036 §2, fourth bullet** ("**Confirming survival (M2 spike, …)** … not for this ADR."). Replaced by:

> - **When the long-lived context is torn down, the extension is locked.** There is no `storage.session` fallback and no restore of unlocked state from any storage. The next context starts locked and the user unlocks again ([ADR 0111](0111-extension-session-and-idle-lock.md) §1). The M2 spike measured a 6-minute Chromium soak; longer soaks, memory pressure and Firefox are measured under ADR 0111 §7 to report how often a teardown happens, not to make it safe.

**D. ADR 0036 §3, "Auto-lock" bullet** ("**Auto-lock.** A configurable idle timeout … if that fallback was in use."). Replaced by:

> - **Auto-lock.** A configurable timeout (default 15 minutes, 1–180, the owner's answer at acceptance); a lock when the OS idle API reports `idle` for that same interval or `locked`; and an explicit "lock now" action in the popup. On Chromium the service worker reads `chrome.idle` and relays the state to the offscreen document, which has no `idle` API; it pushes on `onStateChanged`, and the offscreen document also polls it every 30 s while unlocked. On Firefox the background page uses `browser.idle` itself ([ADR 0111](0111-extension-session-and-idle-lock.md) §3). Locking zeroizes every handle in the long-lived context ([ADR 0013](0013-shared-client-core.md) §3 rule 1).

**E. ADR 0013 §4, "Lifetimes are confirmed in M2 (U)" sub-bullet**. Replaced by:

>   - **A torn-down context is locked.** If the offscreen document or the Firefox background page is torn down, the unlocked state is gone and the extension is locked. Nothing restores it from `storage.session`, `storage.local` or IndexedDB ([INV-63](../THREAT_MODEL.md#8-security-invariants); [ADR 0111](0111-extension-session-and-idle-lock.md) §1).

**F. ADR 0019 §1.4, the restated ADR 0013 §2 capability table, row "Key storage for local unlock", Extension (M2) cell.** Replaced by:

> none. Unlocked keys stay in memory in the long-lived context only (ADR 0013 §4; ADR 0111 §1, INV-63)

**G. ADR 0036 Negative, first bullet.** Replaced by:

> - A second Rust-host context (offscreen document / background page) to keep alive, on top of the web vault's Worker. When it is torn down the user unlocks again ([ADR 0111](0111-extension-session-and-idle-lock.md) §1).

**H. ADR 0036 Risks, both bullets.** Replaced by:

> - If the offscreen document or the Firefox background page is torn down often (memory pressure, browser policy), users re-enter the master password often. That costs usability, not security. Signal: the teardown counts of ADR 0111 §7 step 6, or user reports.
> - Browser API changes (Chromium narrowing offscreen-document reasons or lifetimes, Firefox ending Manifest V2) could force a redesign. Mitigation: a new ADR; a key snapshot in storage is not the fallback.

**I. ADR 0013 Risks, "Extension context lifetimes" bullet.** Replaced by:

> - **Extension context lifetimes.** If the offscreen document or the Firefox background page is torn down often, the extension locks often. Unlocked key state never leaves Rust memory to survive it ([ADR 0111](0111-extension-session-and-idle-lock.md) §1).

### 7. Implementation plan and tests

Every step is gated on this ADR being Accepted. Tests use the existing runners (`vitest` in `apps/extension/test`, Playwright in `apps/extension/e2e`). No new dependency.

1. **Remove the fallback** (§1.4). Delete `session-store.ts` and its uses. Extend `e2e/storage.spec.ts` (INV-63): `storage.session` has zero keys after unlock, after a worker restart and after lock; the existing secret search over every area stays.
2. **Teardown locks** (§1.2). New e2e in `e2e/lifetime.spec.ts`: unlock; from the service worker call `chrome.offscreen.closeDocument()`; open the popup: it shows the locked view, a fill request gets the locked refusal, the storage dump holds no secret, and unlocking with the password works again.
3. **Service-worker relay** (§3.1 items 1, 2, 5). Unit tests with the fake `ext` in `test/support`: the `idle.onStateChanged` listener is registered during module evaluation, before any `await`; `idle`/`locked` with a document sends exactly one `idle_state`; `active` sends nothing; no document means no message and no `createDocument` call; `setDetectionInterval` gets `autoLockMinutes * 60` at start and after a `storage.onChanged` of the setting; `idle_status_query` from a content-script sender gets no answer.
4. **Offscreen poll and lock** (§3.1 items 3–6, 8). Unit tests with the injectable `Clock`: no poll while locked; a poll every `IDLE_POLL_MS` once unlocked; an answer `idle` or `locked` locks, `active`, a malformed answer and a rejected send do not; `idle_state` from a content-script sender is ignored; a new `autoLockMinutes` reaches `setTimeoutMs` after `clampAutoLockMinutes`; `lock()` stops the poll. E2E (Chromium): set auto-lock to 1 minute; unlock; keep the activity timer from firing by sending `get_status` from an extension page every 20 s (extension messages, not OS input); stop the service worker (`ServiceWorker.stopAllWorkers`, as `storage.spec.ts` does); assert the popup shows locked within 60 s + 30 s + 15 s slack. Whether headless Chromium in CI reports `idle` after the interval is U; this test is the spike that settles it, and if it cannot, the test is replaced by the manual check in step 7, recorded in the README, not dropped silently.
5. **Firefox MV2** (§2.2, §3.2), after Open question 1. Convert `manifest.firefox.json`; add `background-page.html`; build and load it in Firefox ESR 115 and current release; run `web-ext lint` if already available in the toolchain (not added as a dependency). Unit test: the Firefox listener's `setDetectionInterval` uses the setting, not the default.
6. **Teardown measurement.** Extend the lifetime spike to a multi-hour soak on Chromium (run detached, per the track brief) and a manual Firefox soak; the README records the counts. They inform Risks; they gate nothing.
7. **Manual checklist** (README and release checklist): on Windows, macOS and Linux, Chromium and Firefox, lock the OS screen while unlocked; on return the extension is locked (within 30 s on Chromium).
8. **Docs in the same change as the code:** remove the README's "real, reported residual" paragraph and the storage-fallback wording; update the comments in `lifecycle.ts`, `listener.ts` and `e2e/storage.spec.ts` that quote the old INV-63.

### 8. On acceptance (doc edits, not made in this change)

1. ADR 0036 Status line: add "[ADR 0111](0111-extension-session-and-idle-lock.md) (§2 first and fourth bullets, §3 "Auto-lock" bullet, Negative first bullet, Risks)". ADR 0013 Status line: add "ADR 0111 (§3 rule 2 in part, §4 in part, Risks in part)". ADR 0019 Status: "Partially superseded by ADR 0111 (§1.4 in part)". Owner's act.
2. [THREAT_MODEL.md](../THREAT_MODEL.md) INV-63, replaced by: "In the browser extension, unlocked key material (account, vault, item and device private keys, `pw_in`, unlock keys) exists only in memory in the long-lived context of ADR 0036 §2 (the offscreen document on Chromium, the background page on Firefox). The MV3 service worker routes messages and holds no key material (ADR 0036 §2, a MUST). It is never written to `storage.local`, `storage.sync`, `storage.session` or IndexedDB. Only wrapped device state is persisted. A torn-down long-lived context is locked (ADR 0111)." Verified-by column: "Test that inspects every extension storage area after unlock, after a worker restart, after lock and after an offscreen-document teardown; review checklist: the service worker imports no `@rizzy-vault/core`." This also closes G04-15.
3. THREAT_MODEL §8: add INV-124 (§5) with its final number; §7.2 "Key custody in the extension (M2)" paragraph and the References row on "`chrome.storage` access levels": drop the `storage.session` reliance.
4. [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (Proposed) restates rule 2 in full; its item 20 is replaced by §6 B's text before either ADR is accepted (Open question 2).
5. CLAUDE.md's Accepted list and the [ADR index](README.md) row, by the owner.
6. [CRYPTO.md](../CRYPTO.md): no change (it does not mention `storage.session` or idle lock; V, grep 2026-10-25).

## Consequences

### Positive

- No unlocked key material in any browser storage area, at any time. INV-63 gets narrower and testable, and no new key-custody format is invented.
- Locking the OS screen locks the extension on Chromium, the primary M2 browser, without the service worker holding anything, and without relying on the unverified wake-up behaviour of `onStateChanged`.
- The user's auto-lock setting takes effect on Chromium, and sets the idle interval on Firefox.
- The Firefox build gets a context that actually lives as long as the browser session (V, MDN), instead of an event page.

### Negative

- After a teardown of the long-lived context (crash, discard, extension update), the user re-enters the master password and waits for one Argon2id run.
- While unlocked on Chromium, the offscreen document wakes the service worker every 30 s; the worker never gets to sleep for long. Cost: CPU and memory of a running worker (not measured).
- Screen-lock detection on Chromium can lag by up to 30 s when the push is missed.
- Firefox moves to Manifest V2: two manifest formats to maintain, and a dependency on Mozilla keeping MV2 (L/U).

### Risks

- Chromium may tear the offscreen document down far more often than the soak showed (hours, memory pressure). Signal: §7 step 6 counts. Response: a new ADR; not a key snapshot.
- Mozilla may end MV2 support. Signal: an AMO or Mozilla announcement. Response: a new ADR for Firefox under MV3 (the event page locks when unloaded, or another design).
- The CI e2e for idle may not be able to produce an OS idle state headless (§7 step 4, U). Then idle lock rests on unit tests and the manual check.

## Alternatives considered

- **Define the snapshot fully (contents, wrap, version byte, Chromium writer).** Rejected: every placement of a wrap key either sits beside the snapshot or dies with the context it was meant to outlive (Context, point 4), so the wrap adds no protection and the snapshot is, in effect, unwrapped keys in `storage.session`. On Chromium it also needs the service worker to carry key bytes, against ADR 0036 §2's MUST.
- **Keep the fallback for Firefox only.** Rejected: same format problem, and on MV3 Firefox it would be the common case (every event-page unload), so `storage.session` would hold the keys most of the time.
- **Firefox stays MV3 and locks on every event-page unload.** Kept as the answer to Open question 1 if the owner prefers MV3 everywhere; likely unusable, since the page unloads after a short idle (U) and each unload means a new Argon2id unlock.
- **Keep the Firefox MV3 event page alive with an open port or periodic events.** Rejected: MDN says a background page "does not unload until all visible views and message ports are closed" (V), but nothing long-lived holds such a port on Firefox, and timers to fake activity are the kind of browser-behaviour bet this ADR removes.
- **Idle detection by push only, or by `chrome.alarms`.** Push only: rests on the U wake-up behaviour. Alarms: also wake the service worker, at a 30 s minimum ("Chrome limits alarms to at most once every 30 seconds", [chrome.alarms](https://developer.chrome.com/docs/extensions/reference/api/alarms), V), and add a permission. The offscreen poll gives the same bound with an existing message path.

## Open questions for the owner

1. **Firefox manifest version.** Recommendation: **Manifest V2 with a persistent background page** (§2.2). The ROADMAP fixes MV3 only for Chromium. MV3 Firefox has no persistent background (V), so it either locks after every short idle or needs a fallback this ADR rejects. Trade-off: a second manifest format and Mozilla's MV2 policy (they have said they have no plan to remove MV2, L, not re-read).
2. **Order with ADR 0096.** ADR 0096 (Proposed) restates ADR 0013 §3 rule 2 with the `storage.session` entry as item 20. Recommendation: accept this ADR first, or together, and drop item 20 from ADR 0096 (replace it with §6 B's "none" text) before accepting ADR 0096.

## References

- [ADR 0013](0013-shared-client-core.md) §3 rules 1–2, §4, Risks; [ADR 0019](0019-native-clients.md) §1.2, §1.4; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0022](0022-server-mode-only.md); [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §2, §3, Owner answers; [ADR 0040](0040-extension-fill-request-from-inline-menu.md), [ADR 0043](0043-inline-menu-instance-token.md), [ADR 0076](0076-autocomplete-driven-autofill.md) (§4 only); [ADR 0089](0089-extension-frames-and-save-dialog.md) (Proposed, content-script message list); [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (Proposed).
- [THREAT_MODEL.md](../THREAT_MODEL.md) INV-63, §7.2; [ROADMAP.md](../ROADMAP.md) §3 M2, §4.4.
- Gap review [S5](../reviews/2026-10-25-adr-gap-review.md); raw [G04-13, G04-14, G04-15](../reviews/2026-10-25-raw/G04.md).
- Code read at `f3492b2` (V): `apps/extension/src/background/service-worker.ts`, `src/core-host/{listener,lifecycle,core-context,session-store,offscreen,background-page}.ts`, both manifests, `e2e/{lifetime,storage}.spec.ts`, `apps/extension/README.md`.
- Chrome extension reference, read 2026-10-25 (V): [chrome.offscreen](https://developer.chrome.com/docs/extensions/reference/api/offscreen), [chrome.idle](https://developer.chrome.com/docs/extensions/reference/api/idle), [chrome.alarms](https://developer.chrome.com/docs/extensions/reference/api/alarms), [service-worker events](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/events).
- MDN, read 2026-10-25 (V): [Background scripts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Background_scripts), [manifest `background`](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background), [idle.IdleState](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/idle/IdleState), [storage.session](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage/session).
- Not verified (U unless marked): `onStateChanged` waking a terminated service worker; persistence of `setDetectionInterval` across worker restarts; the 15 s detection floor; the ~30 s Chromium worker and Firefox event-page idle timeouts; `storage.session` cleared on browser close; an extension update reloading every context (L); module scripts in a Firefox MV2 background page; `'wasm-unsafe-eval'` in Firefox MV2 CSP; Firefox reporting `locked` on every OS; headless Chromium reporting `idle` in CI; Mozilla's MV2 plans (L).
