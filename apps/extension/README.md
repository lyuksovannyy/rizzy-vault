# rizzy-vault browser extension

Chromium (MV3) and Firefox, per [ADR 0036](../../docs/adr/0036-browser-extension-architecture-and-key-custody.md),
[ADR 0037](../../docs/adr/0037-url-matching-and-autofill-rules.md) and
[ADR 0038](../../docs/adr/0038-equivalent-domain-list.md). ROADMAP
[§4.4](../../docs/ROADMAP.md#44-url-matching--autofill-m2).

## Status (M2)

**End to end, against a real server: enrol, unlock, autofill a matching page (never a
look-alike one), save a newly submitted login, see it from a second, independent web-vault
session, sync, lock. Also end to end: register and sign in with a passkey through a consent UI,
falling back to the native authenticator on decline — see "M2 passkeys" below.** `rizzy-wasm` now exports the durable-device enrolment/unlock and
`store`-module bindings this file used to describe as the one load-bearing gap
(`cacheStoreNames`, `CacheStore`, `enrolDevice`, `unlockDurableDevice`, `DurableSession`, landed
in `packages/core/src/index.ts`); `src/core-host/bindings.ts` wraps them (host glue only — every
crypto and store decision still happens inside `DurableSession`/`rizzy-wasm`).

- **Works today:** both manifests build; enrolment and unlock through the popup's own form,
  never a mocked backend; the IndexedDB `CacheStore` adapter (`src/cache/idb.ts`) — flat
  (store, key, value) records, bytes only, one object store per `cacheStoreNames()` entry,
  matching ADR 0026 §3 exactly; `rizzy-match`-backed autofill candidates, scoped to the sender's
  own browser-vouched-for URL (`src/core-host/content-handler.ts` validates a `fields_detected`
  message's claimed `pageUrl` against `sender.tab.url` before it ever reaches the matcher); the
  gesture-only fill through the extension-origin inline-menu iframe, which sends the chosen-fill
  request directly to the long-lived context on its own trusted click rather than through the
  content script, re-validated there against a freshly recomputed candidate list (bug 8 below);
  save/update-on-submit
  (offered, never auto-saved) **for a login form whose document survives long enough for the
  extension to answer** (see the residual immediately below); the password/passphrase
  generator; the item list with search, detail, reveal-and-copy with clipboard clearing; "open
  web vault"; lock, and the messaging/sender/lifecycle plumbing the "found empirically" sections
  below cover.
- **A known residual, not fixed here:** a login form whose submit commits a real top-level
  navigation *before* the extension's `save_prompt` answer comes back gets no save/update offer
  at all — found directly while writing `e2e/autofill-and-save.spec.ts` (see bug 7 below). The
  pending offer itself survives in the long-lived context (`addPendingSavePrompt`'s token), but
  nothing re-shows it on whatever page loads next. Real login forms almost always take a visible
  round-trip before navigating, so this is a tight-timing edge case rather than the common case,
  but it is not nothing: a slow enough network, or a form that resolves synchronously, can hit
  it. A full fix is an on-load "is there a pending offer for my origin?" check the content
  script runs on every page, which this change does not add.
- **Not attempted:** Firefox Playwright coverage (no automatable unpacked-extension flow, same
  as before — this also means `pushApplyFill`'s direct-`ext.tabs` branch, the one Firefox's
  `background-page.ts` actually takes, has no e2e coverage of its own; only the Chromium relay
  branch is exercised, by the autofill-and-save spec); a longer-running soak test of whether the
  offscreen document/Firefox background page survive a real session (see "The ADR 0036 §2
  survival spike" below); regex, per-URI match
  mode and user-defined equivalence-group settings UI (the matcher and core support them; no
  options-page surface edits them yet; every item matches via the account default, Base domain).

### Bugs found only by the end-to-end Playwright spec (`e2e/autofill-and-save.spec.ts`)

None of these showed up in the unit tests, the scaffold-only E2E spec, or a casual manual check
— each one needed the real enrol → sync → match → fill → save → sync → verify chain running
against a real server and a real Chromium build before it was visible at all. Fixed here, kept
documented because the next change through this code should know why the fix looks the way it
does:

1. **`account-config.ts` used `chrome.storage.local`, which does not exist in a Chromium
   `chrome.offscreen` document.** `saveAccountConfig` silently no-op'd there, so `get_status`
   reported `enrolled: false` forever — even immediately after a successful `enrol` (the popup's
   "Set up" form never left itself). Rewritten to use IndexedDB, in a small database of its own
   (not the durable-device cache's), the same API `cache/idb.ts` already depends on working
   inside that context.
2. **`enrolDevice`'s wrapper never called `DurableSession.authenticate()`.** `unlockDevice`
   already did, right after its own offline part; `enrolDevice` returned a session that could
   enrol and cache but not sign a request, so the first `sync()` after enrolling failed with
   `wrong_state` (`DeviceSession::syncStart`'s `AuthStage::Done` check). Device-cert upload
   during enrolment authenticates the *upload* over the login's OPAQUE session (CRYPTO.md §11.2
   step 7) — a separate thing from the device signing its own later requests.
3. **A freshly enrolled device's cache starts empty.** Enrolment (CRYPTO.md §11.2) carries
   device certificates and account state, never an initial items pull, so without something
   calling `sync()`, matching had nothing to match against. Fixed the same way the web vault's
   own `VaultView` does it (`apps/web/src/views/VaultView.tsx`'s "one sync on mount"): `App.tsx`
   fires one `sync()` the instant the popup transitions into "unlocked."
4. **The inline-menu iframe's `src` was assigned after `appendChild`.** Queues *two*
   navigations — the default `about:blank` first, then the real one — so `"load"` (registered
   `{ once: true }`) fired for the wrong one, and `postMessage`'s target-origin check silently
   dropped the candidate list (`chrome-extension://…` targeted at a window still carrying the
   *page's* own origin). Fixed by setting `src` before the element is attached: a detached
   iframe queues no navigation at all, so insertion starts exactly one.
5. **The content script's own `MutationObserver` reacted to its own DOM writes.** Showing or
   hiding the inline-menu iframe (or the save-prompt banner) is itself a `childList` mutation
   under `document.documentElement`, so without a filter, showing the menu re-triggered
   detection, which could recreate the menu, mutating the DOM again — an unbounded loop that
   could tear the menu out from under a click already in flight. `isOwnOverlayMutation` now
   ignores a mutation batch that adds or removes only the extension's own marked elements.
   `report()` itself is otherwise a plain re-run. `report()` still runs on *content* mutations.
6. **`ItemsView` fetched the item list exactly once, on mount.** A device that stays on the
   Items view the whole time a sync completes (never switching to Generator and back, which
   remounts it) kept showing "No items." forever, even right after the popup's own "Synced."
   message. `App.tsx` now bumps an `itemsRevision` counter after every sync that completes;
   `ItemsView` takes it as a prop and refetches when it changes.
7. **A login form whose submit navigates before the extension answers gets no save prompt.**
   `content-script.ts`'s capturing `"submit"` listener reads the fields and sends
   `credentials_submitted` correctly, but if the browser's default form submission commits a
   real navigation first, the document (and the pending `.then()`) is torn down before the
   `save_prompt` answer arrives — confirmed by comparing against a form with
   `onsubmit="return false"` (the save prompt appears every run) versus one without it (it
   never does). Not a production bug *for this exact case*: it is the test fixture that changed
   (see `e2e/autofill-and-save.spec.ts`'s `loginPageHtml` comment), because the production path
   is sound once the document survives. It is still a real residual for an unusually fast
   real-world form — see the Status section's "known residual" above.
8. **A real vulnerability, found by security review of this change, not by the Playwright
   spec: `fill_chosen` revealed a decrypted item's credentials for any `itemId` the content
   script named, with the only check being that the claimed `pageUrl`'s origin matched the
   sender's own — no check that the item was ever a match for that origin, and no gesture
   evidence crossing from the iframe's trusted click to the long-lived context at all.** A
   compromised content script (THREAT_MODEL A7) could have requested a fill with zero clicks.
   Fixed by removing `fill_chosen`/`fill_values` from the content-script contract entirely: the
   extension-origin inline-menu iframe now sends the chosen-fill request (`inline_menu_fill_chosen`)
   **directly** to the long-lived context on the same trusted click, identified as that
   privileged sender by `sender.origin` (the extension's own, set by the browser, never
   forgeable by the content script) rather than by anything the message claims
   (`messaging/sender.ts`'s `isInlineMenuSender`; a content script sending the exact same
   message type is routed through the ordinary, unprivileged content-script path instead and
   refused as an unknown message). Before revealing anything, the background re-runs the
   matcher for that sender's own tab URL and requires the claimed item to be among the result
   (`core-host/content-handler.ts`'s `selectFillCandidate`), re-checking the equivalence-only
   second confirmation there too rather than trusting the iframe's UI alone. The revealed values
   are pushed to the content script as `apply_fill`, never back to the iframe. See
   [ADR 0036](../../docs/adr/0036-browser-extension-architecture-and-key-custody.md) §4's
   "chosen-fill request" bullet (added the same day) for the full rationale, and
   `test/sender.test.ts`/`test/content-handler.test.ts`/`test/listener-routing.test.ts` for the
   regression coverage (content-script sender refused; non-candidate `itemId` refused;
   equivalence-only candidate without confirmation refused).
9. **A second real bug, found while implementing bug 8's fix, by running it against a real
   Chromium build rather than trusting the type signatures: a `chrome.offscreen` document has no
   `chrome.tabs` access at all.** The fixed design pushes the revealed values to the content
   script with `ext.tabs.sendMessage(tabId, ...)` from the long-lived context — but on Chromium
   that context *is* the offscreen document, and calling `ext.tabs.sendMessage` there threw
   `TypeError: Cannot read properties of undefined (reading 'sendMessage')`: the inline-menu
   iframe's own `chrome.runtime.sendMessage` call then hung forever, because the offscreen
   document's listener let the exception escape as an unhandled rejection instead of ever calling
   `sendResponse`. The same class of gap as the already-documented `idle`/`storage` restriction
   (bug under "Offscreen documents have no `idle` or `storage`" below), just never hit before
   because nothing in this codebase had called `ext.tabs` from inside the long-lived context
   until this fix needed to. Fixed two ways together: `types/webext.d.ts` types `tabs` optional
   on `WebExtNamespace`, same as `idle`/`storage`; and `core-host/content-handler.ts`'s
   `pushApplyFill` feature-detects it, relaying through the MV3 service worker (which does have
   `tabs`, like every other extension page) via a new internal-only message,
   `relay_apply_fill`, when it is missing. `background/service-worker.ts` is the only thing that
   accepts that relay, and only from this extension's own non-tab sender (the offscreen document
   itself) — it is never exposed to a content script or the inline-menu iframe. Also fixed
   `core-host/listener.ts`'s dispatch to the privileged handler to `.catch` a rejection into a
   `content_error` response rather than let it become another unhandled-rejection hang, since
   that was the proximate symptom that made this bug reproducible at all (without it, the same
   silent hang can recur for any other future exception on this path, not only this one).

One non-bug worth recording so the next reader does not re-litigate it: the "look-alike host"
half of the E2E spec uses `127.0.0.1` vs. `localhost` (different host strings) to prove no
match, not two different ports on the same host — a different-port page on `127.0.0.1` *does*
get offered the other `127.0.0.1` item's autofill candidate, correctly, per ADR 0037 point 5/
point 33 ("any other port ... is never part of the registrable-domain computation"): Base
domain mode excludes port everywhere, including the exact-host fallback an IP literal uses.
Confirmed against `crates/rizzy-match/src/modes.rs` directly; no code change follows from it.

### The inline-menu iframe (ADR 0036 §4/§5, §75)

The candidate list the content script offers on a detected login form now renders inside an
`<iframe>` loaded from this extension's own `chrome-extension://` origin
([`src/inline-menu/index.html`](src/inline-menu/index.html),
[`main.ts`](src/inline-menu/main.ts)), not a plain element injected into the page's own DOM (the
earlier shortcut). The page's own JS has no same-origin access to that document at all, so it
cannot call `.click()` on a candidate itself — closing a critical gap in the prior version,
where it could (INV-36, INV-40).

The content script and the iframe talk over `window.postMessage`
([`src/inline-menu/protocol.ts`](src/inline-menu/protocol.ts)) for exactly two things: showing
the candidate list, and tearing the menu down again once a pick is made. The actual fill request
no longer travels that path at all (bug 8 above): the iframe's own `click` handler, after
checking `event.isTrusted`, sends `inline_menu_fill_chosen` **directly** to the long-lived
context (`ext.runtime.sendMessage`, identified by `sender.origin`, never relayed by the content
script), and only afterwards tells the content script to tear the menu down via the same
`postMessage` channel as before. One documented, accepted residual, narrower now than it used to
be: because the content script's `window` is the same object the page's own script runs in
(isolated worlds share the DOM/BOM), the *iframe cannot tell the content script's `show` message
apart from a forged one the page's own script sent the same way* — only the reverse direction
(the iframe's teardown message) is unforgeable, because it alone depends on
`event.source`/`event.origin`, which the browser sets from the real sending document and no page
script can fake. A forged `show` message can only ever display fabricated `itemId`s the attacker
invented (real ones are never otherwise observable from the page), and picking one leads
nowhere: the fill request's own `itemId` is re-checked against the user's real vault items in
the long-lived context, never resolved from anything the content script forwarded. Nothing can
be filled without a real click inside the iframe, and the iframe is now the only thing that can
ever ask for a fill at all. `protocol.ts`'s own comment covers this in full.

`web_accessible_resources` (both manifests) lists exactly `src/inline-menu/index.html`, matched
to `http://*/*`/`https://*/*` — the one new manifest surface this adds, and the minimum: once
that document has loaded, its own subsequent module-script fetches are ordinary same-extension
loads the embedding page never mediates, so nothing else needs listing.

### Offscreen documents have no `idle` or `storage`

Measured empirically against a real Chromium build, not documented in Chrome's own API
reference at the time of writing: a `chrome.offscreen` document's own `chrome` object has no
`idle` or `storage` namespace at all — both are `undefined`, unlike every other extension page
(popup, options, the service worker). `types/webext.d.ts` types both optional on
`WebExtNamespace` accordingly.

This was a real, previously-shipping bug, not only a type-safety gap: `core-host/listener.ts`'s
`installCoreContextListener` used to call `ext.idle.setDetectionInterval(...)` *before*
registering the one `ext.runtime.onMessage` listener this extension depends on for everything.
That `TypeError` aborted the function before the listener was ever installed, so every
popup/options/content-script message landed in a context with nothing listening, and
`ext.runtime.sendMessage` resolved to `undefined` forever — the offscreen document existed
(`chrome.offscreen.hasDocument()` reported `true` the whole time) but never answered anything.
Found by the "popup opens and shows the locked state" E2E test once that test actually asserted
on the error banner (see "The ADR 0036 §2 survival spike" below). Fixed by registering the
listener as this function's first statement, unconditionally, then feature-detecting `ext.idle`/
`ext.storage` for everything optional: idle-triggered lock and the `storage.session` fallback
degrade to "not available in this context" rather than crash, and the timeout-based
`AutoLockTimer` alone still locks on inactivity either way. A real, reported residual, not a
design change: ADR 0036 §3's idle-based lock simply has no effect inside a Chromium offscreen
document specifically, on this evidence.

### The offscreen document creation race

`ensureOffscreenDocument` (`background/service-worker.ts`) is called from three places that can
overlap: `onInstalled`, `onStartup`, and either the content-script relay path or the
popup/options transport's `ensure_core` priming call. Two concurrent callers both observing
`hasDocument() === false` and both calling `chrome.offscreen.createDocument` throws ("Only a
single offscreen document may be created"), so every caller now shares one in-flight creation
promise (reset once it settles, so a later, non-concurrent call still re-checks `hasDocument()`
fresh) rather than racing independent attempts.

### Firefox has no service worker

`core-host/listener.ts` (shared by `offscreen.ts` on Chromium and `background-page.ts` on
Firefox) now takes an `acceptContentScripts` flag: `false` on Chromium, where
`background/service-worker.ts` is the one context that validates a raw content-script message
and forwards it here; `true` on Firefox, where there is no separate service worker, so this
listener is the only context a real content-script message ever reaches and must validate it
itself. Previously this flag did not exist and the listener always ignored a raw content-script
sender, so field detection, the inline-menu offer and fill did not work on the Firefox build at
all — fixed here.

### The ADR 0036 §2 survival spike

`e2e/extension.spec.ts` measured, against a real build: the service worker's
`chrome.offscreen.createDocument({ reasons: ["WORKERS"], ... })` call succeeds without error on
the first content-script message, and `chrome.offscreen.hasDocument()` reports `true`
immediately after — **offscreen-document creation itself works as designed.** One Playwright
quirk found along the way: `context.pages()`/`backgroundPages()` never list the offscreen
document, so the spec asks the service worker itself (`chrome.offscreen.hasDocument()`) rather
than scanning Playwright's page list.

**Now measured** (`e2e/lifetime.spec.ts`, Chromium): a real unlocked session, left idle for 6
minutes (comfortably past several service-worker suspend/wake cycles, and short of
`DEFAULT_AUTO_LOCK_MS`'s 15-minute default so the result is not just "auto-lock hadn't fired
yet") — `chrome.offscreen.hasDocument()` still reports `true`, fetched from a *freshly looked
up* service worker handle (the worker itself may have been suspended and restarted any number
of times during the wait), and the popup still shows the unlocked view with no error. **Passed.**
Still not measured: longer soaks (hours), real memory pressure, and Firefox (its background
page is the long-lived context directly, with no separate service worker and no Playwright flow
to load/introspect it — `not_done`, same residual as the rest of this file's Firefox gaps).

### M2 passkeys (ADR 0039)

**End to end, against a real server and a real self-signed-HTTPS test relying party
(`e2e/passkey.spec.ts`, Chromium): register an ES256 passkey through the consent UI, verify the
attestation's public key independently (hand-rolled CBOR, `e2e/webauthn-verify.ts`), sign in
with it and verify that assertion's signature against the same key, decline falls back to the
real native `navigator.credentials` call, and the stored passkey shows up in the web vault
(rp id, the item's username, a created date, no private-key reveal) and can be deleted through
the confirm dialog.**

- **Page-world shim** (`src/content/passkey-page-shim.ts`), injected by a `document_start`
  relay content script (`src/content/passkey-relay.ts`) as a `<script src>` web-accessible
  resource (not a manifest `MAIN`-world entry — this project's Firefox floor does not reliably
  support that key): overrides `navigator.credentials.create`/`.get`, forwards to the relay over
  `window.postMessage`, and falls back to the browser's own original (saved-before-override)
  implementation on decline, timeout, or no match — never a rizzy-vault-specific error the page
  did not ask for.
- **Consent UI** (`src/passkey-consent/`), an extension-origin iframe reusing the exact sender
  class `isInlineMenuSender` already vouches for the inline-menu fill iframe (ADR 0040): a
  trusted click (`event.isTrusted`) is the only thing that can approve or pick a candidate; the
  ceremony is bound to the tab/origin at offer time and re-checked at approval time
  (`passkey-ceremony.ts`'s `take()`), so a navigation invalidates it (unlike the save prompt,
  which survives one).
- **Long-lived context** (`core-context.ts`'s `offerPasskeyCreate`/`offerPasskeyGet`/
  `approvePasskeyCeremony`): calls `createPasskey` + `addPasskey`/`editItem` + `sync()` for a
  create, or `DurableSession.passkeyAssertion` for a sign-in. Any failure (a Rust
  `rp_id_rejected`, a locked device, an unknown/expired/mismatched ceremony token) answers
  `apply_passkey_result`'s `outcome: "fallback"` — the page's shim then calls the real native
  method, never surfaced to the page as an error of its own.
- **Known limitation, reported honestly:** a sign-in assertion's `userHandle` is always omitted
  (`null`) in the response `navigator.credentials.get()` resolves with. `@rizzy-vault/core` has
  no call that reads a stored passkey's `user_handle` back out once written (only at creation
  time) — `not_done`. Legal under the WebAuthn spec (`userHandle` is nullable), but a relying
  party that requires it for a fully "typeless" discoverable sign-in (no `allowCredentials`,
  identifying the account purely from the response) will not accept this response.

**Bugs found only by the real E2E chain**, the same way the autofill bugs above were — each one
invisible to the unit tests or a casual manual check:

1. **A created passkey never reached the server.** `runCreatePasskey` wrote the new/updated
   Login through `DurableSession.createItem`/`editItem` (a local, durable write) but never
   called `session.sync()` afterwards — and nothing else in this long-lived context syncs on its
   own; sync only happens when the popup opens/unlocks or its own "Sync" button is clicked. A
   passkey created silently through the ceremony (no popup involved at all) could sit unsynced
   indefinitely. Fixed by syncing right after the write, best-effort (a sync failure — offline, a
   server error — is swallowed, not surfaced as a ceremony failure: the credential this ceremony
   returns to the page is real and usable locally either way, and sync will catch up later).
2. **The web vault's own E2E server binary served a stale embedded build.** `target/debug/
   rizzy-vault --features embed-web` bundles whatever `apps/web/dist` existed at `cargo build`
   time; rebuilding `apps/web/src` alone (the passkey `PasskeyLine`/`fields.ts` grouping) does
   nothing until `npm run build` (web) and the `cargo build ... --features embed-web` step both
   re-run. Running against the stale binary showed every `passkey/<id>/<attribute>` as its own
   raw, ungrouped field row — including a masked-but-"Reveal"-button `private_key` row, which
   would have been a real violation of "no private key reveal" had it been a code bug rather
   than a stale build. `e2e/server.ts`'s own module doc already named the two-step rebuild; this
   is a reminder to actually run both after a web-side change, not a code fix.

Firefox: not automated, same reason as the rest of this file (no Playwright-automatable
unpacked-extension flow) — the create/get interception and the consent UI are plain
`postMessage`/DOM code with nothing Chromium-specific in it, but that is untested, not proven.

## Architecture

```
inline-menu iframe  <--postMessage (show)--  content script (page)  --validated msg-->  service worker
(chrome-extension:// origin,                                                              (router, no keys; also
 unreachable from the page's JS)                                                          creates the offscreen
      --postMessage (trusted click only)-->                                               document eagerly)
                                                                                                |  chrome.offscreen
                                                                                                v  .createDocument
                                                                     offscreen document (Chromium) / background
                                                                     page (Firefox) = the ONE long-lived context
                                                                     holding @rizzy-vault/core (ADR 0036 §2);
                                                                     auto-lock timer; storage.session fallback
                                                                                                ^
                                        popup / options page  --PopupRequest (direct, primed by ensure_core)--+
```

- **`src/messaging/`** — the typed contract (`contract.ts`), the untrusted-input validator with
  size limits (`validate.ts`), and sender-identity checks that read `sender.origin`/
  `sender.tab.url`, never the message body (`sender.ts`) — ADR 0036 §4, INV-40.
- **`src/background/service-worker.ts`** — Chromium only. Routes a validated content-script
  message to the long-lived context and back; creates the offscreen document eagerly
  (`onInstalled`/`onStartup`) and on the popup/options transport's `ensure_core` priming call
  (`src/background/ensure-core.ts`). Never imports `@rizzy-vault/core`; holds no keys.
- **`src/core-host/`** — the long-lived context. `offscreen.ts` (Chromium) and
  `background-page.ts` (Firefox) are thin, browser-specific bootstraps over shared logic
  (`listener.ts`, `core-context.ts`, `content-handler.ts`); `bindings.ts` wraps
  `@rizzy-vault/core`'s durable-device surface (host glue only); `account-config.ts` persists
  the enrolled server origin/login name in its own small IndexedDB database (see "Bugs found"
  above for why not `chrome.storage`); `lifecycle.ts` is the injectable-clock auto-lock timer;
  `session-store.ts` is the `storage.session` fallback (ADR 0013 §3 rule 2). This is the one
  directory allowed to import `@rizzy-vault/core` for value (enforced by `eslint.config.mjs`).
  `listener.ts` validates a raw content-script message itself on Firefox
  (`acceptContentScripts: true`) since there is no service worker there.
- **`src/core/client.ts`** — the popup/options messaging-backed client (placement note inside
  the file).
- **`src/cache/`** — the IndexedDB `CacheStore` adapter (`idb.ts`) and the ADR 0026 §3 store-name
  constants (`stores.ts`), moving bytes only.
- **`src/content/content-script.ts`** — framework-free TypeScript, no wasm, no React
  (ADR 0014 §2). Top frame only. Creates the inline-menu iframe; never fills without a trusted
  click reported back from it.
- **`src/inline-menu/`** — the extension-origin inline-menu iframe app (`index.html`, `main.ts`)
  and its `postMessage` protocol with the content script (`protocol.ts`). See "The inline-menu
  iframe" above.
- **`src/popup/`, `src/options/`** — React over `packages/ui`/`packages/core` types.

## Permissions (Chromium manifest; justify each, per CLAUDE.md)

| Permission | Why |
|---|---|
| `storage` | `storage.session` (unlocked-state fallback, ADR 0013 §3 rule 2) and `storage.local` (the auto-lock timeout setting, not secret). |
| `offscreen` | Creates the one long-lived document that holds the wasm core (ADR 0036 §2). |
| `idle` | `chrome.idle`/`browser.idle` → lock on `"idle"` or `"locked"` (ADR 0036 §3), alongside the timeout-based auto-lock timer (`core-host/lifecycle.ts`); wired in `core-host/listener.ts`. |

No `tabs`, no `<all_urls>` host permission, no `externally_connectable` (ADR 0036 §4 last
bullet, explicitly including the configured server's own origin). `content_scripts.matches` is
`http://*/*` and `https://*/*` only, which already lets Chrome run the script on those pages
without a separate host permission.

**`web_accessible_resources`** (not a `permissions` entry, but the same "justify every manifest
surface" standard): `[{ "resources": ["src/inline-menu/index.html"], "matches": ["http://*/*",
"https://*/*"] }]` in both manifests. The one file any http(s) page may load as a resource — the
inline-menu iframe's own entry page — needed so `content-script.ts` can set an `<iframe src="…">`
pointed at it at all ("The inline-menu iframe" above). Nothing else the extension ships is
listed.

Firefox's manifest omits `offscreen` (no such API) and otherwise matches.

## The Chrome Web Store justification string

Recorded here per [ADR 0036](../../docs/adr/0036-browser-extension-architecture-and-key-custody.md)
"Owner answers at acceptance" (`reasons: ["WORKERS"]` is the closest fit the fixed enum offers).
Exact string used in `src/background/service-worker.ts`:

> Hosts the rizzy-vault wasm core (a WebAssembly module performing cryptographic work) for the
> life of the browsing session, since the MV3 service worker is torn down too often to hold key
> material. Closest fit of the fixed reason enum: WORKERS.

This has not been submitted to the Chrome Web Store yet (the extension is not store-ready, per
Status above); revisit if a real review rejects it, as the ADR anticipates.

## Content Security Policy

`extension_pages`: `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'`.
`'wasm-unsafe-eval'` is required for `@rizzy-vault/core`'s wasm module (the same reason the web
vault's INV-49 CSP allows it for the core Worker). No remote code, no `'unsafe-inline'`.

## Building and testing

```sh
pnpm --filter @rizzy-vault/extension run build:chromium   # dist/chromium (unpacked, loadable)
pnpm --filter @rizzy-vault/extension run build:firefox    # dist/firefox
pnpm --filter @rizzy-vault/extension run test             # Vitest: messaging, sender, auto-lock, cache, account-config
pnpm --filter @rizzy-vault/extension run e2e              # Playwright, Chromium only; see below
```

`build-wasm` (`cargo xtask build-wasm`, run from the repository root) must have produced
`packages/core/generated/` before `@rizzy-vault/core` — and so this package — can type-check or
build; the root `pnpm run build` and the project gate already order this correctly.

### Running the Playwright suite

`e2e/autofill-and-save.spec.ts` drives the real stack end to end: `rizzy-vault` itself (`e2e/
server.ts`), a real account created through the web vault's own signup UI (`e2e/account.ts`),
and this extension's own popup/content-script/inline-menu, with `chromium.launchPersistentContext`
(`headless: true, channel: "chromium"` — the default headless *shell* Playwright otherwise
launches cannot load an unpacked extension at all; the installed full Chromium's headless mode
can). Before running it:

```sh
pnpm run build:wasm && pnpm run build                                        # from the repo root
cargo build -p rizzy-server --bin rizzy-vault --features embed-web           # the web vault signup UI
pnpm --filter @rizzy-vault/extension run build:chromium
pnpm --filter @rizzy-vault/extension run e2e
```

`RIZZY_VAULT_BIN` overrides the binary path (`e2e/server.ts`); a binary built without
`embed-web` fails the test outright (its web vault page has no signup form) rather than being
skipped. `e2e/extension.spec.ts`'s other seven specs need no server at all.

`e2e/passkey.spec.ts` needs the same `embed-web` server plus `openssl` on `PATH` (it generates
its own throwaway self-signed cert, `e2e/https-server.ts` — INV-64 and `rizzy_client::passkey::
verify_rp_id` both require `https:` literally, no loopback exception). Rebuilding
`apps/web/src` without re-running *both* `npm run build` (web) and the `cargo build ...
--features embed-web` step leaves the server binary serving a stale embedded build — see "M2
passkeys," bug 2.

`e2e/lifetime.spec.ts` idles for 6 real minutes by design (`test.setTimeout(8 * 60 * 1000)`);
run it on its own (`npx playwright test lifetime.spec.ts`) rather than as part of a quick local
loop.

## Icons

Not included in this change (`not_done`): the manifests declare no `icons` key, so Chromium and
Firefox fall back to a generic puzzle-piece icon. Add production icon assets before any store
submission.
