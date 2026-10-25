# ADR 0110: Vault lock settings on every client, and passkey user verification under them

- Status: Proposed
- Date: 2026-10-25 (redrafted the same day to the owner's answers)
- Deciders: project owner
- Milestone: M2 (web vault and extension); M3 (macOS app); mobile with its own ADR (M7)
- Supersedes: on acceptance, in part: [ADR 0039](0039-passkeys-vault-and-extension.md) (§2, the bullet "User verification and presence", in full); [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) ("Owner answers at acceptance (2026-10-07)", the paragraph, in full, for its auto-lock clause). §0 quotes both and gives the full replacement text. ADR 0036 §3's "Auto-lock" bullet is replaced by [ADR 0111](0111-extension-session-and-idle-lock.md) §6 D, whose text carries this ADR's settings; this ADR does not replace it a second time.
- Scope: client-side only. No server, wire, API or server-storage change.

## Owner answers (2026-10-25)

The owner, on this ADR, verbatim:

> "so ensure that this one is client side change only (so web vault, ext, os-related clients) will all have by default 5 minute idle time to lock the vault and include options there to disable vault locking (displays first warning dialog that requires confirm after 5 seconds of wait), lock vault after N minutes of idling (default 5 minutes), lock after restart (def: on), lock when fall asleep/hybernation (def: on). also if vault locking is disabled, other options will be non editable and dimmed (aka disabled)"

What this redraft does with it: §1–§4 are new (the settings, the dialog, the storage, what each client can honour). The passkey part (§5–§10) now uses the lock settings as the freshness bound for `UV` instead of a fixed 2-minute window. The 2-minute decision is removed; a short re-verification window survives only for the case where the user has weakened locking (§6). On ADR 0111 the owner said: "prefer latest Manifest V3, but if V2 has mandatory abilities that V3 does not - stick to V2 as you recommended". ADR 0111 applies that rule; §4 here relies on its outcome.

## Context

### Locking today (V unless marked)

- **No Accepted ADR defines the web vault's lock timer.** A grep of `docs/adr` for "auto-lock", "idle lock" and `IDLE_LOCK` finds only ADR 0036, ADR 0037 (an unrelated open question), ADR 0075 (which quotes the code) and Proposed drafts. The timer is code: `apps/web/src/autolock.ts`, `IDLE_LOCK_MS = 15 * 60_000`, "A product choice of this M1 web vault". Activity is `keydown`, `pointerdown`, `wheel` and `touchstart` in the tab, and "a lock means a new OPAQUE login to continue". [CRYPTO.md §11.4](../CRYPTO.md#114-web-vault): "No secret is persisted, except the SK if the user opted in. The one other value kept in browser storage is the non-secret theme choice".
- **The extension's timer** is [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §3 ("a configurable idle timeout (default to be set with the M2 UI; recommend 15 minutes […], **U**), lock on `chrome.idle` / `browser.idle` reaching `locked` or `idle`") plus its "Owner answers at acceptance": "auto-lock defaults to 15 minutes idle, user-configurable". ADR 0036 does not name a storage key. The code stores one number in `storage.local` under `rizzy.auto_lock_minutes`, clamped to 1–180 (`core-host/lifecycle.ts`, written by `options/main.tsx`). The activity timer counts popup and options-page requests only (`handlePopupRequest` calls `autoLock?.activity()`), not content-script messages. [ADR 0111](0111-extension-session-and-idle-lock.md) (Proposed) fixes where the idle state is read and drops the `storage.session` fallback, so no extension storage area ever holds keys.
- **Native clients** have no lock code yet. [ADR 0057](0057-device-state-v2-keystore.md) (Accepted, M3) adds the OS-keystore wrap `E_ks` for a keystore-gated *unlock*; it does not keep a session unlocked. [ROADMAP](../ROADMAP.md) lists "Biometric unlock, auto-lock timeout, screenshot blocking" for mobile at M7.
- [THREAT_MODEL](../THREAT_MODEL.md) A5b, "Vault unlocked", What we do: "Auto-lock timeout. Lock on OS lock and sleep." NG-1: locking shortens the exposure window; it claims no protection against someone at an unlocked device.

### What each platform can detect

| Event | Chromium extension | Firefox extension | Web vault (any browser) | macOS app (M3) |
|---|---|---|---|---|
| No input for N minutes | `chrome.idle` `"idle"` (V, ADR 0111 §3.1) and the popup/options activity timer | `browser.idle` `"idle"` (V, MDN) and the activity timer | input events in the tab only | OS idle time (L) |
| Screen lock | `chrome.idle` `"locked"`: "'locked' if the system is locked" ([chrome.idle](https://developer.chrome.com/docs/extensions/reference/api/idle), V via ADR 0111) | MDN: "'locked' if the screen is locked or the screensaver activates" ([idle.onStateChanged](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/idle/onStateChanged), V, read 2026-10-25). MDN's compatibility data says only that Firefox "reports 'active' or 'idle' as appropriate" since version 51 (browser-compat-data `webextensions/api/idle.json`, V). Whether it reports `"locked"` on each OS is **U** | nothing (the Idle Detection API is Chromium-only behind a permission prompt, L; not used) | screen-lock notifications (L) |
| Sleep / hibernation | no API: `chrome.idle` has no suspend event (L). Many OSes lock the screen on sleep, which then shows as `"locked"` (**U**) | no API (L) | no API | `NSWorkspace` will-sleep / did-wake notifications (L) |
| Browser or app restart | the long-lived context is gone: locked (ADR 0111 §1.2) | same | the page and its Worker are gone: locked (a new OPAQUE login) | the process is gone: locked |

No browser API reports a system suspend. A context that keeps running timers can see one afterwards: while the machine sleeps, timers stop, and the first tick after wake finds that the wall clock jumped. That is the only sleep signal a web page or extension has (§4.2).

### The passkey gap (the original subject)

The owner said "start" on 2026-10-25, after the ADR gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)). This ADR closes review item **S2: G04-20** (raw finding with quotes in [G04.md](../reviews/2026-10-25-raw/G04.md), "G04-20 [major]").

**What binds today.** [ADR 0039](0039-passkeys-vault-and-extension.md) (Accepted) §2, "User verification and presence":

> Every assertion and every registration runs only while the vault is unlocked (which already required the master password, an OPAQUE login, or a future keystore-gated unlock, ADR 0036 §3) **and** after an explicit user gesture choosing the credential in the extension-origin inline menu or popup […]. `authenticatorData` flags are set `UP=1` (user present: the gesture), `UV=1` (user verified: the unlock already authenticated the user), `BE=1`/`BS=1` […].

The code does exactly that: `crates/rizzy-client/src/passkey/wire.rs` writes `FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS` (`0x1D`) on every assertion and `… | FLAG_AT` (`0x5D`) on every registration, and nothing in the extension reads the request's `userVerification` member (`apps/extension/src/content/passkey-page-shim.ts` relays neither `publicKey.userVerification` nor `authenticatorSelection.userVerification`).

**The gap (G04-20).** The review's words: "an RP that asks `userVerification: "required"` for a step-up (payment, account recovery) treats UV as 'the user proved identity for this ceremony'. The extension asserts that on a single click while the vault is merely unlocked, which may be up to the auto-lock timeout (15 min default, user-configurable) after the last password entry, at an unattended browser. ADR 0034 handles the analogous export threat with a fresh re-authentication. Here THREAT_MODEL's passkey section and INV-64 address only origin/rpId binding and name neither a mitigation […] nor an accepted residual. Its 'Verified by' has no UV test."

- [THREAT_MODEL](../THREAT_MODEL.md) "Passkey provider (M2; ADR 0039)" lists five mitigations, all about the origin and `rpId`; [INV-64](../THREAT_MODEL.md#8-security-invariants) is the same, and its "Verified by" is "Table-driven tests: `evil.example` requesting `rpId` `bank.com`; `rpId` `co.uk` and `github.io`; an `http` origin; a cross-origin iframe; an origin forged in the page's message." No line names `UV`.
- [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §3: auto-lock is "a configurable idle timeout (default to be set with the M2 UI; recommend 15 minutes […], **U**)", plus lock on `chrome.idle` reaching `locked` or `idle`.
- [ADR 0034](0034-export-reauth-and-plaintext-hold.md) point 2 is the project's precedent for freshness: "One re-authentication allows one export within 5 minutes (`REAUTH_WINDOW_MS`) […] The host's clock decides; a clock that went back counts as not fresh."
- [INV-40](../THREAT_MODEL.md#8-security-invariants): "The extension never asks for the master password or Secret Key in page-injected UI." THREAT_MODEL §A7: "unlock happens only in the toolbar popup or an extension page." The passkey-consent iframe ([ADR 0043](0043-inline-menu-instance-token.md)) is extension-origin but sits inside the page's layout, where the page can draw a pixel-identical fake, so it is page-injected UI for INV-40's purpose. A master-password field inside it is therefore not an option this ADR may choose.
- Current ceremony plumbing (code, not ADR text): a pending ceremony lives in `core-host/passkey-ceremony.ts` with `PASSKEY_CEREMONY_TTL_MS = 2 * 60 * 1000`, single use, bound to `(tabId, origin)`, cleared on lock; the page shim waits `min(publicKey.timeout, 60 000 ms)` and on decline, timeout or no match calls the browser's own `navigator.credentials` instead.

**What WebAuthn says (external facts).** `userVerification` is a `UserVerificationRequirement` with values `"required"`, `"preferred"`, `"discouraged"`, defaulting to `"preferred"`, and an unknown value is ignored as if absent (WebAuthn L3 §5.8.6 and the IDL defaults; **L**, not re-read for this ADR). For `"required"` the client must fail the ceremony if the authenticator cannot verify the user; an RP verifying an assertion for `"required"` must check that `UV` is set (WebAuthn L3 §7.2 step "If user verification is required …"; **L**). The `UV` bit is bit 2 (`0x04`) of the flags byte (§6.1; **V** via `wire.rs`, which cites it). How other password-manager passkey providers handle UV (some re-prompt for the master password or a PIN when `"required"`, some treat the unlock as UV) is general product knowledge, **U**.

## Decision

### 0. What this ADR supersedes

| Part, quoted | Replaced by |
|---|---|
| [ADR 0039](0039-passkeys-vault-and-extension.md) §2, the whole bullet beginning "**User verification and presence.** Every assertion and every registration runs only while the vault is unlocked" and ending "`BE=1`/`BS=1` (backup eligible/backup state: these are explicitly backed-up, synced credentials)." | Text A below. |
| [ADR 0036](0036-browser-extension-architecture-and-key-custody.md), "Owner answers at acceptance (2026-10-07)", the paragraph beginning "The owner accepted this ADR with the recommendations" and ending "recorded with the M2 code." | Text B below. |

**Text A**, replacing the ADR 0039 bullet in full:

> - **User verification and presence.** Every assertion and every registration runs only while the vault is unlocked ([ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §3, under the lock settings of [ADR 0110](0110-passkey-user-verification.md) §1) **and** after an explicit user gesture choosing the credential in the extension-origin inline menu or popup, mirroring [ADR 0037](0037-url-matching-and-autofill-rules.md) §5's gesture-only rule. Whether the unlock counts as user verification depends on those lock settings: [ADR 0110](0110-passkey-user-verification.md) §6 decides when `UV` is set and when a request with `userVerification: "required"` needs a master-password verification in the toolbar popup. `authenticatorData` flags are `UP=1` (user present: the gesture), `UV` as ADR 0110 §6 sets it, `BE=1`/`BS=1` (backup eligible/backup state: these are explicitly backed-up, synced credentials).

**Text B**, replacing the ADR 0036 paragraph in full:

> The owner accepted this ADR with the recommendations of "Open questions for the owner": the device kind is 2 (§1); the Chromium offscreen document uses reason `WORKERS`, and the justification string the Chrome Web Store accepts is recorded with the M2 code. Auto-lock is user-configurable, with the settings and defaults of [ADR 0110](0110-passkey-user-verification.md) §1 (lock after 5 minutes idle by default; owner answer of 2026-10-25).

Not superseded, and why:
- **ADR 0036 §3, "Auto-lock" bullet.** [ADR 0111](0111-extension-session-and-idle-lock.md) §6 D replaces it in full, and its replacement text defers to this ADR's §1 for the settings. Replacing it here as well would give one part two replacements. Open question 4 asks the owner to accept the two ADRs together.
- **The web vault's lock.** No ADR holds it (Context), so there is nothing to supersede. On acceptance, CRYPTO.md §11.4's "Storage" bullet is amended to name the settings record (On acceptance, item 4). That is a fix to a doc's mechanism, not a change of goal.
- [ADR 0057](0057-device-state-v2-keystore.md), [ADR 0013](0013-shared-client-core.md), INV-40, INV-63 and INV-64 do not change.

### 1. The lock settings

One settings group, **"Locking"**, with the same four controls, labels, defaults and rules on the web vault (Settings view), the extension (options page) and native clients (the macOS app's settings at M3; mobile when its ADR lands). Strings come from `packages/i18n`. The English text:

| Control | Kind | Default | Values |
|---|---|---|---|
| **Lock the vault automatically** (the master toggle) | switch | on | on / off |
| **Lock after N minutes idle** | select | 5 | 1, 2, 5, 10, 15, 30, 60, 240 (minutes); no free entry |
| **Lock when the browser restarts** (extension, web vault) / **Lock when the app restarts** (native) | switch | on | see §4.1 |
| **Lock when the computer sleeps or hibernates** | switch | on | on / off; helper text "Also locks when the screen locks, where this device reports it." |

1. **Idle** means no user input for N minutes, as each client measures it (§4.3). The value list is fixed: short values for shared machines, 4 hours as the longest bounded choice, and anything longer is "off". The code's previous bounds (1–180, default 15) go away.
2. **Master toggle off.** The three sub-options are shown **dimmed and disabled**: still rendered and in the tab order, `aria-disabled="true"`, activation ignored, and described (`aria-describedby`) by the line "Turn on automatic locking to change these." They keep their stored values and show them; nothing is cleared. With the master toggle off, no automatic lock runs: no idle lock, and no sleep or screen-lock lock. The vault still locks on "Lock now", on sign-out and on session end ([ADR 0075](0075-session-listing-and-ending.md)), and whenever its keys are gone (restart, §4.1). Locking off does not extend any server-side lifetime (the session token's TTL, or the web vault's 12-hour ephemeral device certificate, CRYPTO.md §11.4). When one ends, the client locks or asks for a login as today.
3. **Master toggle on** (from off) takes effect at once, without a dialog. The sub-options become editable with the values they kept. The idle deadline is re-checked at once against the time since the last input (§4.3), so a vault that has been idle for longer than N locks immediately.
4. **Off** goes through the dialog of §2. The toggle changes only on Confirm.
5. **Every change applies at once** to the running session. A new N re-checks the deadline immediately; switching sleep detection on starts it.
6. **"Lock now"** stays available everywhere, whatever the settings.

### 2. The turn-off warning dialog

1. Activating the master toggle while it is on opens a modal `role="alertdialog"` with `aria-modal="true"`, `aria-labelledby` set to the title and `aria-describedby` to the body. The toggle stays on while the dialog is open.
2. **Text** (English; i18n keys `lock.disable.title`, `lock.disable.body`, `lock.disable.confirm`, `lock.disable.cancel`, `lock.disable.wait`, `lock.disable.ready`):
   - Title: "Turn off automatic locking?"
   - Body: "Your vault will stay unlocked on this device until you lock it yourself or close it. Anyone who uses this device while it is unlocked can see, copy and change everything in your vault. Passkey sign-ins that ask for verification will ask for your master password. This setting applies to this device only."
   - Buttons: **Cancel**, labelled "Keep locking on", and **Confirm**, labelled "Turn off locking".
3. **Countdown.** Confirm is disabled for `LOCK_DISABLE_CONFIRM_DELAY_MS = 5 000` from the moment the dialog opens, measured on the monotonic clock (`performance.now()` or the platform's equivalent), not the wall clock. While disabled it stays focusable, has `aria-disabled="true"`, ignores activation (click, Enter, Space), and its label shows the remaining whole seconds: "Turn off locking (5)", "(4)" … "(1)", then "Turn off locking". Reopening the dialog restarts the countdown at 5.
4. **Announcements.** One visually hidden `aria-live="polite"` region announces "You can confirm in 5 seconds." when the dialog opens and "You can now turn off locking." when the delay ends. It does not announce every second.
5. **Keyboard.** Initial focus is on **Cancel**, which works at once. Escape is Cancel. Tab cycles within the dialog only. On close, focus returns to the master toggle.
6. **Cancel, Escape, closing the popup, page or app, or a lock while the dialog is open** all leave locking on. Only Confirm, after the delay, writes `auto_lock: false` (§3).
7. Turning locking back on needs no dialog (§1 point 3).

### 3. Where the settings are stored

1. **Per device, local only, not synced, never sent to the server.** The right lock policy is a property of the device: a shared office PC and a personal laptop differ. Syncing it would need a server-stored or vault-item format, which the owner ruled out ("client side change only"). And a synced "locking off" would let one device, or anyone who can write the synced value, weaken locking on every device. The settings are not secret and are not encrypted.
2. **One record, one key, on all clients:** key `rizzy.lock_settings`, value a JSON text of at most 256 bytes:

   ```json
   {"v":1,"auto_lock":true,"idle_minutes":5,"lock_on_restart":true,"lock_on_sleep":true}
   ```

   | Client | Store |
   |---|---|
   | Web vault | `localStorage` of the web vault's origin |
   | Extension | `storage.local`, the string under that key. Chromium: read by the service worker and relayed to the offscreen document, which has no `storage` (ADR 0111 §3.1). Firefox: read by the background page. |
   | macOS app (M3) | the app's local preferences (the `UserDefaults` standard domain, not iCloud key-value storage), same key and value |

3. **Parsing** is one function in `rizzy-client` (`lock_settings.rs`), exported through `rizzy-wasm` and later `rizzy-ffi`, so every client applies identical rules. The record is untrusted input, so it gets a fuzz target (`client_lock_settings`). If the text is longer than 256 bytes, is not JSON or not an object, has `v` other than exactly `1`, lacks a field or has one of the wrong type, or has an `idle_minutes` outside §1's list, the whole record is replaced by the **defaults** (`auto_lock: true`, 5, `true`, `true`). Unknown extra fields are ignored. `lock_on_restart: false` is read as `true` on every client today (§4.1); the field exists so that a later ADR can enable it without a format change. A broken record therefore never weakens locking.
4. **Version.** `v: 1` is this ADR's format. A later format uses `v: 2`, and its ADR says how v1 is read. A v1 reader treats `v: 2` as broken and uses the defaults.
5. **Migration (extension only).** If `rizzy.lock_settings` is absent and the code-only key `rizzy.auto_lock_minutes` holds an integer, the first read writes a v1 record with `auto_lock: true`, `idle_minutes` set to the largest list value not above it (at least 1), both switches on, and removes the old key. Otherwise the defaults apply. The web vault has no stored value to migrate.
6. **Writes** come only from that client's settings UI. The extension's long-lived context and the web vault's and native app's lock controllers re-read the record on `storage.onChanged`, the `storage` event or the preferences change notification.

### 4. What each client can honour

#### 4.1 Lock after restart

Keeping a vault unlocked across a restart means key material outlives the process that held it. ADR 0111 §1 forbids every extension storage area from holding keys and drops the `storage.session` fallback. The web vault persists no secret (CRYPTO.md §11.4). A native app could only do it by unlocking from the OS keystore at start without the user, which [ADR 0057](0057-device-state-v2-keystore.md) does not decide for this purpose and this ADR does not invent. So on **every client today** the option is shown **on and disabled** (`aria-disabled="true"`), with the line:

- extension and web vault: "This browser cannot keep the vault unlocked after a restart."
- native: "This app cannot keep the vault unlocked after it restarts."

Its stored value is always written as `true`. A client may make the option editable only after an Accepted ADR defines key storage that survives a restart (Open question 3). For the web vault, a page reload counts as a restart.

#### 4.2 Lock when the computer sleeps or hibernates

1. **Where the platform reports it, use it.** Extension: a `"locked"` idle state locks when this option is on (ADR 0111 §3). macOS app: the OS will-sleep and screen-lock notifications (L; the M3 app records the exact API). This is why the helper text names screen lock.
2. **Everywhere, a timer-gap check** runs in the context that holds the keys: the web vault's lock controller next to `watchIdle`, the extension's long-lived context, and the native app's lock controller as a backstop. A tick every `SLEEP_TICK_MS = 10 000` reads the wall clock (`Date.now()`). If it moved forward by **at least `SLEEP_GAP_MS = 120 000`** since the previous tick, the device slept (or the clock jumped), and the vault locks when this option is on. A backward jump resets the baseline and does not lock.
3. **Why these numbers.** A tick cannot run while the machine sleeps, so any sleep of 2 minutes or more is caught at the first tick after wake. Browsers delay timers in background pages. Chrome's "intensive throttling" aligns chained timers in hidden pages to once a minute (L, not re-read); whether the Chromium offscreen document or Firefox's background page is throttled is **U**. 120 s leaves twice that margin, so a throttled but awake context does not lock. A sleep shorter than 2 minutes is not detected, but the idle deadline still bounds it (§4.3). A false positive (a forward clock correction, a starved process) costs one unlock, never an unlocked vault.
4. **Web vault:** there is no screen-lock signal (Context table), so only point 2 applies. The shared helper text ("where this device reports it") stays true.

#### 4.3 Lock after N minutes idle

1. The deadline is N minutes after the last input. It is checked on every `SLEEP_TICK_MS` tick against **both** the monotonic clock and the wall clock, and the vault locks when either says N minutes have passed. A plain `setTimeout` may not count time spent asleep (this differs by platform, **U**), so a timer alone is not enough.
2. Input means: on the web vault, the existing tab events (`keydown`, `pointerdown`, `wheel`, `touchstart`); on the extension, popup and options-page requests plus the OS idle state (`"idle"` for N minutes locks, ADR 0111 §3); on native clients, the OS idle time.
3. With the master toggle off, no deadline runs and no tick locks.

### 5. The requirement the extension reads

1. The page shim relays one more optional field, `userVerification`, in both requests: for `create` from `publicKey.authenticatorSelection.userVerification`, for `get` from `publicKey.userVerification`. It is a string of at most 16 UTF-16 code units; anything else (not a string, longer, absent) is not relayed.
2. The background maps it to a requirement: `"required"` → **Required**; `"discouraged"` → **Discouraged**; `"preferred"`, absent, or any other value → **Preferred** (the WebAuthn default, §Context).
3. The value is page-supplied, and that is acceptable: the page is the RP's own script, so a malicious page can only lower the requirement of its own ceremony, which yields an honest `UV=0` (§3), never a false `UV=1`. INV-64's rule that the origin and `rpId` never come from page data is unchanged.

### 6. `UV` under the lock settings

1. **The lock policy is the freshness bound.** While the vault is unlocked and the policy is **bounding**, the unlock counts as user verification: every ceremony is signed with `UV=1`, whatever the request's requirement. The policy is bounding if and only if automatic locking is on **and** `idle_minutes ≤ UV_POLICY_MAX_IDLE_MINUTES = 15` (Open question 1), and the session's last unlock was by master password (point 4). The vault is then unlocked only if someone typed the master password, and gave input within the last N ≤ 15 minutes. That is the meaning this ADR gives `UV`.
2. **Not bounding** (locking off, or 30, 60 or 240 minutes): the unlock alone is not user verification. A recent master-password verification is: `verified_at` (point 4), fresh within `UV_FRESH_MS = 300 000` (5 minutes, the default idle time and [ADR 0034](0034-export-reauth-and-plaintext-hold.md)'s `REAUTH_WINDOW_MS`).
3. **The sleep and restart options do not enter the rule.** A restart always locks (§4.1). With sleep detection off, a sleep longer than N still passes the idle deadline (§4.3), so the bound holds.
4. **`verified_at: Option<u64>`** (milliseconds since the Unix epoch, host clock) is held in the unlocked core session of the long-lived context and nowhere else; it is never written to any storage area. Lock, auto-lock and the end of the context drop it with the session. It is set to `now` by two events only: a successful unlock **with the master password** (the local unlock of [CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device), `StoredDevice::unlock(password)`, or the master-password OPAQUE login at enrolment), and a successful re-verification (§7). Nothing else sets it: not the device-key online authentication, not a keystore-gated unlock (`unlock_keystore`, until an Accepted ADR states that the keystore's gate verifies the user and amends this list), not a recovery-code flow. A session unlocked by any of those is never bounding either. `verified_at` is fresh at `now` if and only if it is `Some(t)` and `0 ≤ now − t ≤ UV_FRESH_MS`; a clock that went back is not fresh (ADR 0034 point 2).
5. **Decided at signing time, in Rust.** `passkey_assertion` and `create_passkey` gain three arguments: the requirement, `now_ms`, and the current lock settings (the parsed record of §3 as the host holds it at that moment). The rule is one function in `rizzy-client`. No earlier evaluation (at request time, at the consent click) is used.

| Policy | Requirement | `verified_at` fresh | Result |
|---|---|---|---|
| bounding | any | – | Sign. `UV=1`. |
| not bounding | Required | yes | Sign. `UV=1`. |
| not bounding | Required | no | Do not sign. The call returns `UvRequired` (§7 starts the re-verification). Never `UV=0`. |
| not bounding | Preferred | yes | Sign. `UV=1`. |
| not bounding | Preferred | no | Sign. `UV=0`. No prompt (Open question 2). |
| not bounding | Discouraged | yes / no | Sign. `UV=1` / `UV=0`. No prompt. |

The flags byte is exactly one of:

| Ceremony | `UV=1` | `UV=0` |
|---|---|---|
| Assertion (`UP`, `BE`, `BS`; never `AT`, never `ED`) | `0x1D` | `0x19` |
| Registration (`UP`, `BE`, `BS`, `AT`; never `ED`) | `0x5D` | `0x59` |

`UP` is always 1 (the gesture). `BE`/`BS` and the zero signature counter of ADR 0039 §2 do not change. Under the default settings (on, 5 minutes) every ceremony gets `UV=1` and nobody is prompted. That is today's behaviour, now bounded by a 5-minute idle lock instead of 15.

6. **Weakening never buys `UV`.** Turning locking off or raising N above 15 makes the policy not bounding, which can only lower `UV` or add a prompt. Making it bounding again (locking on, or N ≤ 15) re-checks the idle deadline at once (§1 points 3 and 5), so a vault idle for longer than the new N locks before it can sign as bounding.

### 7. Re-verification for "required" in the toolbar popup

The master password is entered only in the toolbar popup, the surface unlock already uses (INV-40, THREAT_MODEL §A7). Never in the consent iframe, the inline menu, or any window or tab the extension opens.

1. **Consent label.** When the request is Required, the policy is not bounding and `verified_at` is not fresh at the time the consent iframe is shown, the approve button reads "Verify and use passkey" (registration: "Verify and save passkey") and the iframe states that the rizzy toolbar button will ask for the master password. This is advisory only: the decision is §6's, at signing.
2. **Approve → `UvRequired`.** Today the approval `take()`s the ceremony (destructively) and signs. The ceremony store gains a non-destructive `peek` with the same expiry and live-binding checks, and the approval becomes: `peek`; run the core call of §6; on a result, delete the record (single use, as now); on `UvRequired`, move the record (same `ceremonyToken`, same `(tabId, origin)` binding, same TTL counted from creation, `PASSKEY_CEREMONY_TTL_MS`) from `pending` to `awaiting_verification`, with `uv_attempts = 0` and the user's choice from the click (the chosen `passkeyRef` for a sign-in, the chosen vault for a registration) stored in the record, so the popup never chooses anything. The consent iframe shows "Waiting for verification in the rizzy toolbar button" and a Cancel button (Cancel = the existing decline). The background sets the toolbar badge text for that tab to `"!"` and calls `action.openPopup()` where the browser offers it; if that call is missing or fails, nothing else happens (the iframe's text tells the user to click the button). Whether `openPopup()` works without a user gesture in the background differs by browser and version (**U**).
3. **Popup view.** When the popup opens and its active tab has a ceremony in `awaiting_verification`, the popup shows the verification view before anything else: the verified origin, the `rpId`, the credential's user name, the kind (sign in / save passkey), a master-password field and Verify / Cancel buttons. It fetches this with a popup message `passkey_verify_pending` (reply: `{ ceremonyToken, origin, rpId, userName, kind }` or `none`).
4. **Submit.** The popup sends `passkey_verify_submit { ceremonyToken, masterPassword }`. The background accepts it only from the popup (sender is an extension page whose URL is the popup's, with no `sender.tab`); a content-script or iframe sender is refused like any malformed message. `masterPassword` is bounded as the popup's `unlock` message bounds it, held in a zeroizing buffer once in Rust, never logged. The long-lived context then, in this order:
   1. looks up the ceremony; missing, expired, or not `awaiting_verification` → `uv_ceremony_gone`;
   2. re-checks the ceremony's binding against the tab's **live** URL, as the approval path already does; changed → decline the ceremony, reply `uv_ceremony_gone`;
   3. verifies the password by running the same local unlock primitive (`StoredDevice::unlock(password)`) against the device record the current session was unlocked from, then drops (zeroizes) the opened keys; nothing is compared with or replaced in the running session;
   4. wrong password → `uv_attempts += 1`; below `UV_MAX_ATTEMPTS = 5` reply `uv_wrong_password` (the ceremony stays `awaiting_verification`); at 5 decline the ceremony (the page gets the browser's own authenticator, as for every decline) and reply `uv_attempts_exhausted`;
   5. correct password → set `verified_at = now`, take the ceremony (single use), and run §6's signing call with the same `now` (so the result is `UV=1`), deliver the result to the tab exactly as an approval does today, clear the badge, reply `uv_ok`; the popup closes.
5. **Cancel** in the popup or in the consent iframe declines the ceremony (`uv_cancelled` to the popup), clears the badge, and the page gets the browser's own authenticator.
6. **Reply codes** (popup ↔ background, extension-internal, shipped in one bundle, so no version field): `uv_ok`, `uv_wrong_password`, `uv_attempts_exhausted`, `uv_ceremony_gone`, `uv_cancelled`, `uv_locked` (the vault locked meanwhile). The popup shows a fixed sentence for each; none echoes input.
7. **One verification at a time per tab.** A tab has at most one ceremony in `awaiting_verification`: when a second one in the same tab reaches that state, the older one is declined. `passkey_verify_pending` therefore has at most one answer per tab.

### 8. Crash, lock, timeout and retry

- **Lock or auto-lock** while `awaiting_verification`: the ceremony store is cleared on lock as today; the popup's next submit gets `uv_locked`; the badge is cleared. `verified_at` goes with the session.
- **Long-lived context or service worker restart:** pending ceremonies and `verified_at` are memory-only and gone. A submit gets `uv_ceremony_gone`. The page's shim timer still runs and falls back to the browser's authenticator. No result is produced from a lost ceremony.
- **Page timeout first:** the shim waits at most `min(publicKey.timeout, 60 000 ms)` (current code). If it fires first, the page has already called the browser's authenticator; a later successful verification still sets `verified_at` and signs only if the ceremony record is still unexpired and bound, and the shim has already forgotten the timed-out request's nonce (it deletes it when its timer fires, current code), so the late result is dropped and no second credential reaches the page. The ceremony TTL (2 minutes) bounds the record either way.
- **Crash between verification and signing** (inside one core call, §7 step 4.5): the ceremony was taken, nothing was delivered; the page times out to the browser's authenticator. The user retries the passkey; `verified_at` survived unless the context died, so the retry within `UV_FRESH_MS` needs no prompt.
- **Signing fails after a correct password** (e.g. a stored key that will not parse): `verified_at` stays set (the user did verify), the ceremony is consumed, the page receives the same failure path as today's signing failure.
- **Idempotence:** a second `passkey_verify_submit` with the same token after `uv_ok` finds no ceremony and gets `uv_ceremony_gone`; it never signs twice.

### 9. Invariants (provisional numbers)

> **INV-123.** A passkey provider sets `UV` in `authenticatorData` only when (a) the vault was unlocked with the master password and its lock settings are bounding (automatic locking on, idle time at most `UV_POLICY_MAX_IDLE_MINUTES`) at signing, or (b) a master-password verification (a password unlock or a re-verification in the toolbar popup) succeeded in the same unlocked session no more than `UV_FRESH_MS` before signing, by the host clock, a clock that went back counting as not fresh. A request with `userVerification: "required"` is never answered with `UV=0`: it is either verified or not signed. The master password for re-verification is entered only in the toolbar popup. *Milestone:* M2. *Verified by:* Rust unit tests of §6's table and its boundaries (15 minutes bounding, 30 not, locking off not; `UV_FRESH_MS` fresh, one millisecond more stale, clock back stale; a keystore-unlocked session not bounding); extension unit tests that a non-popup sender cannot submit a verification and that five wrong passwords decline; the e2e of the Implementation plan, step 6.

> **INV-127** (number assigned at acceptance). Every client applies the lock settings of ADR 0110 §1 from one per-device record. A missing, oversized, malformed or unknown-version record means the defaults (locking on, 5 minutes, restart on, sleep on). The settings UI turns locking off only through the delayed-confirm dialog of §2. No client keeps a vault unlocked across a restart. *Milestone:* M2 (web vault, extension), M3 (macOS). *Verified by:* the `lock_settings` parser tests and fuzz target; the dialog and dimmed-state e2e; the restart e2e (Implementation plan, steps 1, 5).

Mobile providers (M7) are out of scope. There the OS's own per-ceremony verification applies and the M7 ADR decides; mobile adopts §1–§3 when its ADR lands.

### 10. Accepted residuals (new THREAT_MODEL AR rows, numbers next free at acceptance)

> **Passkey user verification by the lock policy.** With the default settings the extension sets `UV=1` for any ceremony while the vault is unlocked, without asking again. Someone at the unlocked browser within the idle time (at most 15 minutes when the policy is bounding) gets `UV=1` assertions, including for `userVerification: "required"`, with one click. With locking weakened, an unattended unlocked browser yields `UP=1, UV=0` for `"preferred"` and `"discouraged"`, and an RP that accepts a passkey without `UV` as a full login is exposed for as long as the vault stays unlocked, as with a filled password (NG-1). A page-opened window can imitate the re-verification prompt; the toolbar popup, anchored to the browser's own toolbar, is the defence, as for unlock. Accepted because the owner chose the lock policy as the bound, and a prompt on every ceremony would make passkeys slower than the password they replace.

> **Locking can be turned off, and the settings sit in unprotected local storage.** A user may disable automatic locking after the 5-second warning; the vault then stays unlocked until it is closed. The record is plain `localStorage`, `storage.local` or app preferences: server-served web vault code, a script with access to the extension's `storage.local` (content scripts can use `storage.local`, L) or local malware can rewrite it, to "off" included, without the dialog. Mitigations: a broken record means the defaults; weakening never yields more `UV` (§6 point 6); NG-1 already concedes an attacker with that access. Sleep detection misses sleeps under 2 minutes and may lock on a clock jump.

## Consequences

**Positive**
- One lock model on every client, with the owner's defaults (5 minutes; restart and sleep on), and an honest UI where a platform cannot honour an option.
- `UV=1` now means "this vault would have locked after at most 15 idle minutes" or "the master password was typed within 5 minutes". G04-20 closes with a mitigation, a residual and tests. The flags stay honest for `"preferred"` and `"discouraged"`.
- Client-side only: no server, wire or server-storage change, no new crypto, no new secret. The re-verification reuses the local unlock primitive (one Argon2id run per attempt, which also rate-limits guessing). INV-40 is kept.

**Negative**
- The default drops from 15 to 5 minutes, so users unlock more often.
- "Lock after restart" is a control nobody can change yet (§4.1). It is shown so that the model is the same on every client, and so that the user sees why.
- Sleep detection is a heuristic; sleeps under 2 minutes go unnoticed (the idle time still bounds them).
- More client state: a settings record with a parser and a fuzz target, a dialog, one ceremony state (`awaiting_verification`), two popup messages, six reply codes, a badge.
- **Compatibility (U).** With locking weakened, an RP that asks `"preferred"` but rejects `UV=0` treats rizzy-vault users as unverified. Under a bounding policy this cannot happen.

**Neutral**
- Imported passkeys ([ADR 0074](0074-passkey-cxf-import-export.md), [ADR 0084](0084-bare-cxf-passkey-export.md)) follow the same rule; nothing about a credential records how it was verified.
- WebAuthn security keys for rizzy-vault's own login ([ADR 0082](0082-security-keys-user-presence-only.md)) are unrelated: there rizzy-vault is the RP.

## Alternatives considered

- **A fixed 2-minute `UV` window after the last master-password entry** (this ADR's first draft). Replaced at the owner's direction: the lock policy is the bound. A 5-minute window survives only for weakened locking (§6 point 2).
- **Keep `UV=1` from the unlock in every case.** Not chosen: with locking off, `"required"` would mean "unlocked at some point since the browser started".
- **Sync the lock settings through the encrypted account settings** (as the identity-generator defaults are synced, `ACCOUNT_SETTINGS`). Rejected: a vault-format change, which the owner ruled out, for a policy that is per device (§3 point 1).
- **Hide the sub-options when locking is off, or hide the restart option where it cannot work.** Rejected: the owner asked for dimmed and disabled controls, and a hidden control explains nothing.
- **Keep the vault unlocked across a restart with a wrapped key in browser storage.** Rejected for the reason in ADR 0111's Context, point 4: the wrap key either sits beside the blob or dies with the context.
- **Detect sleep with the Page Lifecycle `freeze`/`resume` events or `visibilitychange`.** Not chosen: they also fire for discarded and hidden tabs, not only for system sleep, and they do not exist in the extension's background contexts (L).
- **Re-type the master password in the consent iframe.** Rejected: the iframe is inside the page, which can draw a pixel-identical fake and harvest the password; INV-40 forbids it. Changing INV-40 is a goal change the owner would have to make.
- **Open a dedicated extension window (`windows.create` with an extension page) for the password.** Allowed by THREAT_MODEL §A7 ("or an extension page"), works without `openPopup()`, but a page can open a lookalike window with `window.open`, and users are not trained to check a popup window's URL. The toolbar popup is the surface users already unlock in. Kept as the fallback if a later answer makes the popup impractical.
- **Refuse `"required"` outright** (fall back to the browser's authenticator). Simple and honest, but makes rizzy-vault passkeys unusable for exactly the RPs that care most.
- **Per-ceremony PIN or OS biometric.** Needs an OS keystore integration the extension does not have; a later keystore ADR can add it to §6 point 4's list.

## Open questions for the owner

1. **Which idle times count as "bounding" for `UV`?** *Recommendation:* **at most 15 minutes** (1, 2, 5, 10, 15), the previous Accepted default. With 30, 60, 240 or locking off, `"required"` asks for the master password in the toolbar popup (§7) and a verification counts for 5 minutes. Alternatives: bounding only at 5 minutes or less; or never bounding, so that `"required"` always asks unless a verification is under 5 minutes old.
2. **What does `"preferred"` get when the policy is not bounding and no fresh verification exists?** *Recommendation:* **`UV=0`, no prompt** (§6). `"preferred"` is the WebAuthn default, so a prompt would ask on most sign-ins of a user who weakened locking.
3. **Lock after restart.** *Recommendation:* **shown on and disabled on every client**, with the explanatory line (§4.1), until an Accepted key-storage ADR exists. The only plausible route is a native-only ADR (an OS-keystore item opened at app start without a user gesture). Not recommended now: it would turn every restart into an unlock without the user.
4. **Accept together with ADR 0111.** *Recommendation:* **yes, the same day.** ADR 0111 §6 D replaces ADR 0036 §3's Auto-lock bullet with text that refers to this ADR, and this ADR relies on ADR 0111's "no keys in extension storage" for §4.1. Either one accepted alone leaves a cross-reference to a Proposed ADR.
5. **Screen lock under the sleep option.** *Recommendation:* **yes:** a `"locked"` state locks when "Lock when the computer sleeps or hibernates" is on. Many OSes lock the screen on sleep, and the vault cannot tell the two apart. Alternative: a fifth switch, "Lock when the screen locks".

## On acceptance

Not made now. The owner's acceptance triggers them, in one docs change:
1. [ADR 0039](0039-passkeys-vault-and-extension.md) Status line: "Partially superseded by ADR 0110 (§2, "User verification and presence")". [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) Status line: add "ADR 0110 ("Owner answers at acceptance", in full)". Set by the owner (ADR 0020 points 3, 4, 9).
2. [THREAT_MODEL](../THREAT_MODEL.md) "Passkey provider (M2; ADR 0039)": add a sixth mitigation bullet: "`UV` is set only while the lock settings bound the unlocked time to at most 15 idle minutes, or within `UV_FRESH_MS` of a master-password verification; otherwise `userVerification: "required"` is re-verified in the toolbar popup or not signed ([INV-123](#8-security-invariants), [ADR 0110](adr/0110-passkey-user-verification.md))." A5b "What we do": "Auto-lock after 5 minutes idle by default; lock on OS lock and sleep where detected (ADR 0110). The user may turn locking off after a delayed warning."
3. THREAT_MODEL §8: add INV-123 and INV-127 (§9) with their final numbers; add "; the `UV` cases of INV-123" to INV-64's "Verified by". §9: add the two residuals of §10.
4. [CRYPTO.md §11.4](../CRYPTO.md#114-web-vault), "Storage": "… The other values kept in browser storage are the non-secret theme choice and the non-secret lock settings record of ADR 0110 §3. They reveal nothing about the vault."
5. [docs/adr/README.md](README.md): the row's status column; the CLAUDE.md status list (the lead's change).
6. The answers to the open questions, recorded here as owner answers, with `UV_POLICY_MAX_IDLE_MINUTES`, `UV_FRESH_MS` and §6's table adjusted if the answers differ.

## Implementation plan

Only after acceptance. Tests use the existing runners (Rust unit tests, `vitest`, Playwright in `apps/web/e2e` and `apps/extension/e2e`, and the existing axe helpers in `e2e/a11y.ts`). No new dependency.
1. **`rizzy-client`, `lock_settings.rs`.** The record type, `parse` (§3 rules), `encode`, `is_bounding` and the `IDLE_MINUTES` list. Tests: the default record round-trips byte for byte; each broken case gives the defaults (257 bytes, `v: 2`, `idle_minutes: 3`, `"auto_lock": "no"`, a missing field, an array, invalid UTF-8); `lock_on_restart: false` reads as `true`; an unknown field is ignored. Fuzz target `client_lock_settings`.
2. **`rizzy-client` passkey code (`passkey/wire.rs`, `passkey.rs`).** `authenticator_data_*` take a `UserVerified` flag instead of hard-coding `FLAG_UV`; a `UvRequirement` parser (§5); the §6 decision function. Tests: flag bytes `0x1D`/`0x19`/`0x5D`/`0x59`; §6's table as a table test; bounding at 15, not at 30 or with locking off; freshness at `t` and `t + UV_FRESH_MS` (fresh), `t + UV_FRESH_MS + 1` and `t − 1` (stale), `None` (stale); a keystore-unlocked session is not bounding; parser cases `"required"`, `"discouraged"`, `"preferred"`, `"REQUIRED"` (→ Preferred), absent.
3. **Lock controllers** (web vault, next to `autolock.ts`; extension long-lived context, ADR 0111 §3). Unit tests with an injected clock: the idle deadline fires by the monotonic and by the wall clock; a 120 s wall-clock jump locks with sleep on and not with sleep off; a 119 s jump and a backward jump do not lock; with the master toggle off no trigger locks; a settings change re-checks the deadline at once; the extension migration of `rizzy.auto_lock_minutes` (3 → 2, 180 → 60, 0 → 1, absent → defaults).
4. **Settings UI** (the web vault's Settings view and the extension's options page, one shared component in `packages/ui`). Unit tests: the dimmed state sets `aria-disabled` and ignores activation; the restart switch is on and disabled, with its line; with fake timers, Confirm ignores click, Enter and Space before 5 000 ms and works at 5 000 ms; Cancel works at 0 ms.
5. **E2E: dialog timing and dimmed state** (web vault and extension). Open the dialog: Confirm is `aria-disabled`, and a click at 4.5 s changes nothing; the label counts down; the live region's two messages appear; at 5 s or later Confirm turns locking off, and the three sub-options become `aria-disabled="true"` while staying visible and focusable. Turning locking on again shows no dialog and restores the kept values. Escape and Cancel at 0 s leave locking on. Reopening restarts the countdown at 5. Restart: unlock, then reload (web vault) or close the offscreen document (extension, ADR 0111 §7 step 2): the vault is locked. Idle: with `idle_minutes: 1` and no input, the vault locks after one minute plus one tick.
6. **E2E: passkeys** (`apps/extension/e2e/passkey.spec.ts`, `webauthn-verify.ts`). Defaults + Required → `UV=1`, no prompt. Locking off + Required → popup → `UV=1`. Locking off + Preferred → `UV=0`, no prompt. Locking off, re-verified, then a second Required within 5 minutes → `UV=1` without a prompt.
7. **Accessibility.** axe (the existing `a11y.ts`) on the Locking group in both states and on the open dialog: zero violations. A keyboard walk: Tab reaches every control, the dimmed ones included; Space on the master toggle opens the dialog; focus starts on Cancel; Tab stays inside the dialog; Escape closes it and returns focus to the toggle.
8. **macOS (M3)** implements §1–§4 against the same record, in its own repository, through `rizzy-ffi`.

## References

- [ADR 0034](0034-export-reauth-and-plaintext-hold.md), [ADR 0036](0036-browser-extension-architecture-and-key-custody.md), [ADR 0039](0039-passkeys-vault-and-extension.md), [ADR 0043](0043-inline-menu-instance-token.md), [ADR 0057](0057-device-state-v2-keystore.md), [ADR 0075](0075-session-listing-and-ending.md), [ADR 0111](0111-extension-session-and-idle-lock.md).
- [THREAT_MODEL](../THREAT_MODEL.md) A5b, A7, NG-1, INV-40, INV-63, INV-64; [CRYPTO.md](../CRYPTO.md) §11.3, §11.4; the gap review, item S2 (G04-20).
- Code read for this ADR: `apps/web/src/autolock.ts`; `apps/extension/src/core-host/lifecycle.ts`, `core-context.ts`, `listener.ts`, `passkey-ceremony.ts`; `apps/extension/src/options/main.tsx`; `apps/extension/src/content/passkey-page-shim.ts`; `crates/rizzy-client/src/passkey/wire.rs`.
- External: [chrome.idle](https://developer.chrome.com/docs/extensions/reference/api/idle); MDN [idle.onStateChanged](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/idle/onStateChanged) and [idle.queryState](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/idle/queryState); [browser-compat-data `webextensions/api/idle.json`](https://github.com/mdn/browser-compat-data/blob/main/webextensions/api/idle.json) (all read 2026-10-25). WebAuthn L3 §5.8.6, §6.1, §7.2 (L).
