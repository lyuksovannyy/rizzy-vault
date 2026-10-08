# rizzy-vault browser extension

Chromium (MV3) and Firefox, per [ADR 0036](../../docs/adr/0036-browser-extension-architecture-and-key-custody.md),
[ADR 0037](../../docs/adr/0037-url-matching-and-autofill-rules.md) and
[ADR 0038](../../docs/adr/0038-equivalent-domain-list.md). ROADMAP
[§4.4](../../docs/ROADMAP.md#44-url-matching--autofill-m2).

## Status (M2, in progress)

**The one load-bearing gap: `rizzy-wasm` has no durable-device enrolment/unlock or `store`-module
bindings.** `crates/rizzy-wasm` today exports only the web vault's ephemeral flow (CRYPTO.md
§11.4). Porting `rv`'s reference implementation of §11.2/§11.3 and the IndexedDB-facing side of
[ADR 0026](../../docs/adr/0026-client-device-state-and-cache.md) (`crates/rizzy-cli/src/enrol.rs` +
`device.rs` + `db.rs`, ~3,700 lines) to wasm bindings is a bounded task of its own, not something
this change attempted — see [`src/core/bindings.ts`](src/core/bindings.ts) for the exact
TypeScript surface that port fills in. Until then:

- **Works today:** both manifests build; the messaging contract, its validator and sender
  checks (now including a validating listener on the Firefox background page itself, not only
  the Chromium service worker — see "Firefox has no service worker" below); the MV3 service
  worker as a message-routing-only relay that also creates the offscreen document eagerly
  (`onInstalled`/`onStartup`), race-safely (concurrent callers share one in-flight
  `createDocument` attempt — see "The offscreen document creation race" below), and on the
  popup/options transport's first call, not only on first content-script contact; the
  long-lived context's lifecycle (auto-lock timer, whose timeout is the options page's saved,
  validated and bounded value, not a hard-coded default; `chrome.idle`/`browser.idle` lock where
  that API exists; `storage.session` fallback save/restore/clear where that API exists — see
  "Offscreen documents have no `idle` or `storage`" below); the IndexedDB object-store layout
  (bytes-only, matching ADR 0026 §3 exactly); the content script's field detection (visibility
  *and* topmost checks, ADR 0037 §5) and gesture-only fill plumbing, now through the
  extension-origin inline-menu iframe described below; the popup's locked state and the
  password/passphrase generator (no device state needed).
- **Blocked on the gap above:** unlock, item list/detail/reveal/save, autofill with a real
  candidate (the matcher stub always returns none), the save/update-on-submit prompt, "open web
  vault" (needs the account's `server_origin`).
- **Separately delivered:** URL matching (`rizzy-match`). The content script and background
  call a documented stub ([`src/match/stub.ts`](src/match/stub.ts)) that always returns no
  candidates; wiring in the real crate is the integration step's job. The background validates
  that a `fields_detected` message's claimed `pageUrl` actually shares the sender's own,
  browser-vouched-for origin before it ever reaches `decide()`
  ([`src/core-host/content-handler.ts`](src/core-host/content-handler.ts)).
- **Not attempted:** Firefox Playwright coverage (no automatable unpacked-extension flow);
  clipboard-copy of a *vault item's* secret (the generator's copy works; an item's does not
  exist yet, since items cannot be listed).

### The inline-menu iframe (ADR 0036 §4/§5, §75)

The candidate list the content script offers on a detected login form now renders inside an
`<iframe>` loaded from this extension's own `chrome-extension://` origin
([`src/inline-menu/index.html`](src/inline-menu/index.html),
[`main.ts`](src/inline-menu/main.ts)), not a plain element injected into the page's own DOM (the
earlier shortcut). The page's own JS has no same-origin access to that document at all, so it
cannot call `.click()` on a candidate itself — closing a critical gap in the prior version,
where it could (INV-36, INV-40).

The content script and the iframe talk over `window.postMessage`
([`src/inline-menu/protocol.ts`](src/inline-menu/protocol.ts)), not through the background's own
messaging contract. One documented, accepted residual: because the content script's `window` is
the same object the page's own script runs in (isolated worlds share the DOM/BOM), the *iframe
cannot tell the content script's `show` message apart from a forged one the page's own script
sent the same way* — only the reverse direction (the iframe's `pick` reply) is unforgeable,
because it alone depends on `event.source`/`event.origin`, which the browser sets from the real
sending document and no page script can fake. A forged `show` message can only ever display
fabricated `itemId`s the attacker invented (real ones are never otherwise observable from the
page); picking one leads nowhere, since `fill_chosen` still resolves `itemId` against the user's
real vault items in the long-lived context. Nothing can be filled without a real click inside
the iframe. `protocol.ts`'s own comment covers this in full.

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
than scanning Playwright's page list. **Not measured** (needs a longer-running, manual or CI
soak test, not a single Playwright spec): whether the offscreen document or the Firefox
background page stay alive for the length of a real session, or get torn down under memory
pressure — the open question ADR 0036 §2 actually cares about. The `storage.session` fallback
this change ships is exactly the mitigation for that case either way.

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
  (`listener.ts`, `core-context.ts`, `content-handler.ts`); `lifecycle.ts` is the
  injectable-clock auto-lock timer; `session-store.ts` is the `storage.session` fallback
  (ADR 0013 §3 rule 2). This is the one directory allowed to import `@rizzy-vault/core` for
  value (enforced by `eslint.config.mjs`). `listener.ts` validates a raw content-script message
  itself on Firefox (`acceptContentScripts: true`) since there is no service worker there.
- **`src/core/`** — `bindings.ts` (the missing-bindings contract, see Status) and `client.ts`
  (the popup/options messaging-backed client; placement note inside the file).
- **`src/cache/`** — the IndexedDB adapter (`idb.ts`) and the ADR 0026 §3 store/key-path
  constants (`stores.ts`), moving bytes only.
- **`src/match/stub.ts`** — the unwired matcher interface, ADR 0037's vocabulary.
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
pnpm --filter @rizzy-vault/extension run test             # Vitest: messaging, sender, auto-lock, cache mapping
pnpm --filter @rizzy-vault/extension run e2e              # Playwright, Chromium only; build:chromium first
```

`build-wasm` (`cargo xtask build-wasm`, run from the repository root) must have produced
`packages/core/generated/` before `@rizzy-vault/core` — and so this package — can type-check or
build; the root `pnpm run build` and the project gate already order this correctly.

## Icons

Not included in this change (`not_done`): the manifests declare no `icons` key, so Chromium and
Firefox fall back to a generic puzzle-piece icon. Add production icon assets before any store
submission.
