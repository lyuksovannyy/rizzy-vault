# ADR 0014: UI stack for the web platforms

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (web vault, minimal) / M2 (extensions) / M3 (design system) / M5 (share page)

## Context

**Scope.** This ADR covers the UI code for the web platforms: the web vault, the Chromium and Firefox MV3 extensions, and the share recipient page. The admin panel is not in it (below). It chooses no desktop or mobile stack, layout or backend; their own ADRs do (owner decision 4). Where its components or checks reach those clients (§2, §4, §5), it names the change that must act. The desktop and mobile ADRs:
- [ADR 0015](0015-desktop-tauri.md) (Accepted) binds desktop today. Its point 2 has the Tauri webview render "the shared UI (ADR 0014)" and talk to Rust only over IPC.
- [ADR 0013](0013-shared-client-core.md) §5 and [ADR 0016](0016-workspace-layout.md) §7 (Accepted) bind mobile today: UniFFI bindings, and `apps/android` and `apps/ios` (M7).
- [ADR 0019](0019-native-clients.md) (Native desktop and mobile clients in separate repositories; Proposed, parked until the M3 spikes) carries the owner's native-client decision (owner decision 3).

This ADR holds whichever of them binds. It narrows no ROADMAP row and contradicts no Accepted ADR, so it can be accepted on its own for the M1 scaffolding gate ([README](README.md#gates)), before ADR 0019 or without it. Landing `rizzy-wasm`, its M1 backend, also needs an Accepted ADR on generator-emitted `unsafe` (§4).

The relevant ROADMAP rows:
- [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation) "UI stack": "TypeScript + one framework for web/extension/desktop", because "Extension ecosystem, hiring, and component libraries are JS-first. Rust stays where security lives." This ADR picks the framework for the web vault and the extensions. The desktop part of the row follows the desktop ADR. This ADR does not change the row.
- [ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3), Must, M3: one design system with a "component library shared by web vault + extension + desktop"; keyboard-only use, screen-reader labels, WCAG AA contrast. This ADR builds that library for the web surfaces (§5). What desktop shares follows the desktop ADR. This ADR does not narrow the row.
- [ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2), Must, M2: a browser extension for Chromium (MV3) and Firefox. Should, M3: a Safari extension.
- [ROADMAP §4.1](../ROADMAP.md#41-foundations--project-hygiene-m0), Won't: "Monorepo tooling beyond Cargo + one JS package manager".

The UI surfaces:

| Surface | From | Notes |
|---|---|---|
| Web vault | M1 | Served by the `web` role under a strict CSP ([INV-49](../THREAT_MODEL.md#8-security-invariants)). Server-mode accounts only: [ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4) disables it in On-device mode (below) |
| Extension popup, options page, inline menu | M2 | MV3 CSP; loaded from the local package. The inline menu runs in an extension-origin iframe (INV-40) |
| Extension content script | M2 | Runs in every page. Must be tiny; no framework |
| Share recipient page | M5 | Tiny, no account; possibly on a separate origin ([THREAT_MODEL Q-4](../THREAT_MODEL.md#10-open-questions-for-the-owner)) |

**Not in this ADR:**
- Desktop and mobile clients: ADR 0015 (desktop) and ADR 0013 §5 with ADR 0016 §7 (mobile, M7) while they bind.
- A Safari build of the extension (ROADMAP §4.4, Should, M3). Whether Safari can host the wasm core (`wasm-unsafe-eval` in its extension CSP) is U. Its key custody needs its own ADR first: [ADR 0013](0013-shared-client-core.md) §4 places the extension's core only in Chromium's offscreen document or Firefox's background page.
- The admin panel ([ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should, M3). It is a web UI in this repository on the admin listener ([ADR 0010](0010-server-shape.md) §1), and it renders user-controlled strings with admin rights, so stored XSS there acts as the admin ([THREAT_MODEL §7.19](../THREAT_MODEL.md#719-admin-panel-and-admin-api-m3), [INV-69](../THREAT_MODEL.md#8-security-invariants)). Its stack and directory are decided before M3 admin work starts, by a revision of this ADR while it is Proposed or by a new ADR once it is Accepted. Whatever it uses must meet INV-69, auto-escape, and follow §2's raw-HTML-sink ban.

**The web vault and On-device accounts.** An On-device account has no OPAQUE record ([CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode)). [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration) forbids any difference between real and fake accounts before KE3, so the server cannot answer "this account is On-device". Such a user would just see "wrong password or Secret Key". §6 decides how the web vault points them elsewhere.

The security requirements on UI code ([THREAT_MODEL §7.1](../THREAT_MODEL.md#71-web-vault-m1), INV-35, INV-42, INV-49, INV-68):
- no inline script, no `eval` (only `wasm-unsafe-eval`), no third-party origins;
- auto-escaping, and no raw-HTML sinks;
- only `http(s)` URLs are ever opened from item fields;
- untrusted rich content only inside sandboxed iframes;
- secret input fields set `spellcheck="false"` and `autocomplete` values that discourage browser saving, and a reveal keeps spell-check off ([INV-68](../THREAT_MODEL.md#8-security-invariants), from M1).

The framework matters less than it seems: the content script is plain TypeScript whatever we pick, and extension assets load from the local package, so runtime size costs start-up time, not download time.

## Decision

### 1. Language and framework

- **TypeScript in strict mode** for all UI code this ADR covers: `apps/web`, `apps/extension`, `apps/share` and `packages/*`.
- **React** for the web vault and the extension pages (popup, options page, inline menu) (owner decision 1).
- **No framework** for the extension content script and the share recipient page (§2, owner decision 2).

The comparison that led to React:

| | Svelte 5 | React | SolidJS |
|---|---|---|---|
| Runtime size | small; compiled output | the largest of the three: react + react-dom are tens of KB gzipped (U) | the smallest (U) |
| Rendering model | compiled, signal-based ("runes") | virtual DOM | compiled, fine-grained signals, no virtual DOM |
| Accessible headless components | Bits UI, Melt UI (U; maturity not assessed) | React Aria (Adobe), Radix (U; maturity not assessed). The deepest set | Kobalte, Corvu (U). The thinnest set |
| Ecosystem (virtual lists, forms, i18n, testing) | medium. Some libraries were still catching up with the Svelte 5 rewrite (U) | the largest | small |
| Contributor and hiring pool | medium | the largest, by a wide margin (U) | small |
| Raw-HTML escape hatch | `{@html x}`: short, easy to miss in review | `dangerouslySetInnerHTML`: loud and easy to grep | the `innerHTML` prop |
| Lint rule that bans it | `svelte/no-at-html-tags` (eslint-plugin-svelte, U) | `react/no-danger` (eslint-plugin-react, U) | `solid/no-innerhtml` (eslint-plugin-solid, U) |
| `javascript:` URLs in `href` | not blocked | recent versions block or warn (U) | not blocked |
| Strict CSP (no eval, no inline script) | works when compiled ahead of time. Runtime-injected styles, e.g. from transitions, need checking (U) | works; avoid runtime CSS-in-JS | works; same caveat as Svelte |

**What decided it.** Under our lint rules and CSP all three are safe enough, so security did not decide.
- **React** wins on accessibility primitives, library depth and contributor pool; the M3 accessibility Must is hard to meet from scratch. It costs runtime size and verbosity.
- **Svelte 5** was a close second: small output and simple code, but a smaller accessibility ecosystem.
- **SolidJS** is technically excellent, but has the smallest ecosystem and contributor pool, which matters most for a project that needs outside help ([ROADMAP §6.1](../ROADMAP.md#6-risks--hard-truths)).

### 2. Rules for the web-platform UI code

These rules bind the code §1 lists. While ADR 0015 binds, they also apply to these components when its webview renders them.

ESLint enforces these in CI from M1:
- **No raw-HTML sinks.** `react/no-danger`, plus `no-restricted-properties` / `no-restricted-syntax` for:
  - `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` and `document.writeln`;
  - `Range.prototype.createContextualFragment`, `Element.setHTMLUnsafe`, `Document.parseHTMLUnsafe` and `DOMParser.prototype.parseFromString`;
  - the `srcdoc` property and React's `srcDoc` prop, outside the sandboxed-frame helper (below).

  The list is a minimum: a new HTML-parsing API joins it when it appears. The same rules apply to the framework-free code.
- No `eval`, no `new Function`, no string arguments to `setTimeout` or `setInterval`.
- **One `openUrl` / `SafeLink` helper** that allows only `http:` and `https:` ([INV-42](../THREAT_MODEL.md#8-security-invariants)). Outside the helper, `no-restricted-properties` / `no-restricted-syntax` ban dynamic `href` values, `window.open`, `location.assign` / `location.replace`, assignment to `location` or `location.href`, and the `url` argument of `chrome.*` / `browser.*` `tabs.create`, `tabs.update` and `windows.create`.
- **No runtime CSS-in-JS.** Styles are static CSS files: CSS Modules or a zero-runtime tool. An import ban keeps runtime CSS-in-JS libraries out.
- **The content script is framework-free TypeScript.** `no-restricted-imports` keeps framework and UI packages, and value imports of `packages/core`, out of it; type-only imports of `packages/core` are allowed (the rule's type-import option, U). Its job and its limits:
  - It detects login fields, and positions and injects the extension-origin iframe.
  - It performs the fill the user chose.
  - It reports submitted credentials to the background for save/update ([ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2)).
  - It renders no UI of its own that can trigger a fill or ask for the master password or Secret Key, and the background treats its messages as untrusted ([INV-40](../THREAT_MODEL.md#8-security-invariants)).
  - Its DOM work per page is bounded, and matching runs in the background ([THREAT_MODEL §7.2](../THREAT_MODEL.md#72-browser-extension-m2) D).
  - It holds no wasm core instance. It reaches the core only through extension messaging to the one long-lived context ([ADR 0013](0013-shared-client-core.md) §4: "the core is never split across contexts").
- **The share recipient page (M5) is framework-free TypeScript** (owner decision 2). The same import rule applies to `apps/share`, except that it may value-import `packages/core`, its only route to the core (ADR 0013 §4), and may use the token CSS from `packages/ui` (custom properties only; no components, no JS). One further `packages/ui` exception, for rich content, is below.
- **The generated wasm-bindgen output is reachable only through `packages/core`'s wrapper** (ADR 0013 §4: "UI code imports only `packages/core`"). `packages/core`'s `exports` field does not export the generated files, and a `no-restricted-imports` pattern bans deep imports of them outside `packages/core`.

Other checks enforce these, because ESLint cannot check them, or only in part:
- **No third-party origins.** No CDN, self-hosted fonts, no analytics. For the web vault, the INV-49 CSP forbids third-party origins and its header test checks the CSP. Review covers the rest.
- **Design tokens reach CSS as custom properties (§5).** A CSS lint rule where one fits (tool chosen in M1), otherwise review.
- **Other ways to open a URL** from an item field: review, plus a unit test of the `openUrl` / `SafeLink` helper (INV-42).
- **Secret input fields** ([INV-68](../THREAT_MODEL.md#8-security-invariants), from M1).
  - Every secret input (master password, Secret Key, recovery code, export password, share passphrase, revealed secret fields) is rendered only by one secret-field component in `packages/ui`. It sets `spellcheck="false"` and `autocomplete` values that discourage browser saving, and keeps them when a reveal switches `type` to `text`.
  - The share page uses an equivalent helper of its own in `apps/share`, so the share passphrase needs no further import exception.
  - Checked by INV-68's DOM tests (component or Playwright) on the component and the share-page helper, before and after reveal. Where a lint rule can be written, it bans `type="password"` inputs outside them. Lint cannot tell a revealed `type="text"` field apart, so review covers the rest.
  - Browsers may ignore `autocomplete` hints (U), so the web vault's login copy also tells users not to let the browser save the master password (THREAT_MODEL §7.1).
- **Untrusted rich content** (M5 shares, M6 mail HTML) renders only in sandboxed iframes, without `allow-scripts` and without `allow-same-origin` (INV-35).
  - It reaches a frame only through one reviewed sandboxed-frame helper in `packages/ui`: framework-free TypeScript, with a thin React wrapper.
  - The helper is the only code allowed to set `srcdoc` or to load a blob URL into a frame. It always sets `sandbox` without those two tokens.
  - If the share page ever renders rich content, it imports this one module, besides the token CSS, and nothing else from `packages/ui`: the further exception named above.
  - Checked in review and by Playwright tests that target the helper, plus a lint rule on the `sandbox` attribute where one can be written.
  - Until Trusted Types are a check, the CSP is the backstop: the INV-49 CSP and the MV3 extension CSP forbid inline script, and a `srcdoc` frame inherits its parent's CSP (U).
- **Trusted Types** (`require-trusted-types-for 'script'`) are a goal, not yet a check. They are turned on where browsers support them once the M1 spike shows React works with them (U). The directive joins the web role's header test in the change that turns it on; INV-49's header test does not cover it today.

### 3. Tooling

These carry out four of [THREAT_MODEL A9](../THREAT_MODEL.md#a9-supply-chain)'s JS mitigations: one package manager, a committed lockfile, install scripts disabled, exact versions. The install-script allow-list is the one mechanism A9 does not name, so A9 is edited to match (On acceptance).

- **pnpm workspaces.** The pnpm version is pinned in the `packageManager` field of the root `package.json`. The lockfile is committed, and CI runs `pnpm install --frozen-lockfile`.
- **Install scripts.** Dependency lifecycle scripts do not run on install, pnpm's default since v10 (U). The allow-list (pnpm's `onlyBuiltDependencies`, U) starts empty. Each entry is handled like a `deny.toml` exception: owner-approved, justified in the PR, and reviewed again on every version bump of that package.
- **Exact versions.** Every dependency in every `package.json` has an exact version specifier, with no ranges; workspace packages use pnpm's `workspace:` protocol (U). pnpm's `save-exact` setting (U) writes exact specifiers, and a CI check rejects ranges.
- **Build and test:** Vite to build, Vitest for unit tests, Playwright for end-to-end tests, including extension tests against adversarial pages ([THREAT_MODEL §8.6](../THREAT_MODEL.md#86-autofill-and-urls)).
- **No Nx, Turborepo or Lerna** ([ROADMAP §4.1](../ROADMAP.md#41-foundations--project-hygiene-m0), Won't).
- **A JS dependency policy that mirrors `deny.toml`** lands with the first package in M1: a licence allow-list, an advisory check, and review of new dependencies.
- **Left to M1:** the dependency-policy tool and the exact-version check.

### 4. Monorepo layout for JavaScript

```
apps/
  web/          web vault (M1)
  extension/    MV3 for Chromium and Firefox (M2)
  share/        share recipient page, framework-free (M5)
packages/
  core/         the only way UI code reaches Rust. M1 backend: rizzy-wasm (ADR 0013 §4)
  ui/           design system: the token source (hand-written CSS in M1, generated
                from the neutral source in M3), and the React components for the
                web surfaces (minimal in M1, full in M3; §5)
  i18n/         message catalogues and helpers (M3)
  config/       shared tsconfig, ESLint and Vite presets (M1)
```

- **`packages/core`** wraps the wasm bindings in a typed TypeScript API. In M1 its one backend is `rizzy-wasm`. The web vault runs the core in one dedicated Worker, the extension in its one long-lived context ([ADR 0013](0013-shared-client-core.md) §4). §2's import rules keep components from calling wasm exports directly and the core out of the content script.
- **`rizzy-wasm` also waits for an Accepted ADR on generator-emitted `unsafe`.** rustc drops `unsafe_code` diagnostics whose span lies in an external macro expansion, even under `forbid` (V, rustc source), and wasm-bindgen's generated glue almost certainly contains such `unsafe` (L). ADR 0013 owner decision 1 was taken on the opposite premise. `rizzy-wasm` lands only after an Accepted ADR settles the question. If that ADR does not accept generated `unsafe`, the web core that ADR 0013 §4 sets is itself in question, and the M1 web vault waits for a new ADR on it. Accepting this ADR does not settle it.
- **A desktop backend is not decided here.** If ADR 0015 still binds when M3 desktop work starts, its webview reaches Rust over Tauri IPC and never loads `rizzy-wasm` (ADR 0015 point 2). `packages/core` then needs a second backend, added by its own change (a revision of this ADR while it is Proposed, a new ADR once it is Accepted), which also decides whether the desktop views reuse the web vault's views.
- **This ADR creates no desktop or mobile directory under `apps/`.** ADR 0016 §7 governs `apps/`.
- As with crates, a directory is created only when real code goes into it.

### 5. Design system

- **One token set:** colour, spacing, type, radius, light and dark. Its source of truth is a platform-neutral data file in `packages/ui`, so any client can consume it. The file format and the generator are chosen in M3.
- **Until then (M1–M2),** `packages/ui` holds a minimal hand-written set of CSS custom properties. M3 replaces it with the neutral source and generated CSS, and keeps the property names where possible.
- **Web:** the tokens compile to CSS custom properties.
- **Components are React, shared across the web vault and the extension pages.** The share page uses the token CSS with plain CSS of its own (the named exception in §2).
- **Other clients:** what they share follows their own ADR. Under ADR 0015 the Tauri webview renders these components.
- **Accessibility.**
  - Accessible headless primitives are wrapped in `packages/ui`, so a replacement stays local.
  - A CI check computes the contrast of every token pair declared for text and controls, and fails below WCAG AA (M3). It covers the declared pairs only. Undeclared pairs, and platform high-contrast or increased-contrast modes, need a check of their own on each client, set by that client's ADR or by the change that adds the client.
  - **Web vault and extension pages:** `packages/ui` components use only declared token pairs, checked in review. From M3, Playwright runs an automated contrast check on the rendered pages, including under forced-colors (Windows High Contrast) emulation (U). The components respect `forced-colors` and `prefers-contrast`.
  - **Share recipient page** (M5): its plain CSS uses only declared token pairs, checked in review. The M5 change that adds `apps/share` extends the Playwright contrast and forced-colors check to it, and the page respects `forced-colors` and `prefers-contrast`.
  - **Desktop and mobile:** under ADR 0015, the change that adds the Tauri backend (§4) extends the contrast and forced-colors checks to the three desktop webviews. The M7 mobile change sets the mobile check. Until then, contrast on those clients is not verified.

### 6. Web vault login and On-device accounts

The web vault serves Server-mode accounts only, and the server cannot tell an On-device account apart before KE3 (Context). So, from M1:
- The login screen always states that On-device accounts must use the extension, desktop, mobile or CLI client.
- The login failure message repeats it.
- Checked by a Playwright test that the notice appears on the login screen and in the failure message.

### Owner decisions (2026-09-25, 2026-09-26)

1. **Framework** → React (2026-09-25).
2. **Share recipient page (M5)** → framework-free TypeScript (2026-09-26). It renders one decrypted snapshot, so keeping it tiny keeps it auditable.
3. **Desktop** → reversed the same day. The answer recorded earlier on 2026-09-26 was: desktop "reuses the `apps/web` views: one SPA with two shells, over the two backends of `packages/core`". Later on 2026-09-26 the owner decided that desktop and mobile clients are native, in separate repositories, over the one Rust core through generated bindings ([ADR 0019](0019-native-clients.md), Proposed).
   - The web platforms stay in this repository, with React and strict TypeScript (answer 1) and the framework-free share page (answer 2).
4. **Scope** → yes (2026-09-26): this ADR decides only the web platforms and leaves desktop to the desktop ADR (ADR 0015 while it binds, ADR 0019 if accepted).

### On acceptance

The change that accepts this ADR makes these edits. None is made now.

- **[THREAT_MODEL A9](../THREAT_MODEL.md#a9-supply-chain), JS mitigations:** "install scripts disabled" → "install scripts disabled, except an owner-approved allow-list that starts empty (ADR 0014 §3)". The rest of the bullet is unchanged.

## Consequences

### Positive

- One component set across the web surfaces, and one platform-neutral token source that any client can consume.
- The security rules are framework-independent. ESLint, the INV-49 header test and Playwright enforce most of them in CI; review covers the rest (§2).
- Mainstream tooling (pnpm, Vite, Playwright) keeps contributor onboarding cheap.
- `packages/core` is the one reviewed entry point from UI code to the wasm core, with one backend in M1.
- The ADR does not wait for the desktop decision: it can be accepted for the M1 scaffolding gate without ADR 0019. Landing `rizzy-wasm` also needs an Accepted ADR on generator-emitted `unsafe` (§4).

### Negative

- A JavaScript toolchain and an npm dependency tree join the supply chain ([THREAT_MODEL A9](../THREAT_MODEL.md#a9-supply-chain)), with their own policy, lockfile discipline and review.
- React bundles are larger than Svelte or Solid bundles would be, and the code is more verbose.
- Two languages in the repository: a contributor to a UI feature that touches core behaviour needs both.
- Desktop stays open here. If ADR 0015 still binds when M3 desktop work starts, `packages/core` gains a second backend through a later change (§4), and the web UI must also work in three desktop webviews.

### Risks

- An accessibility library we build on could be abandoned. Mitigation: wrap it in `packages/ui`, so a replacement stays local.
- A React major release can force a migration across every web surface at once. Pin majors, and upgrade deliberately.
- A client that hard-codes token values instead of using the generated files drifts from the token source. Mitigation: generated token files and review.

## Alternatives considered

- **Rust UI (Leptos, Dioxus, Yew).** It would share code with the core directly, but extension APIs, accessibility libraries and the contributor pool are JS-first ([ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation)). Rendering through wasm gains no security: the DOM is the same DOM.
- **Vue.** Comparable to Svelte in size and ergonomics, with a larger ecosystem (U). Not shortlisted, because ROADMAP named Svelte and React.
- **Angular.** A complete framework with its own accessibility kit (the CDK, U), heavier than the three above. Not shortlisted.
- **Web Components (Lit).** Standards-based and small, but accessibility primitives have to be built by hand, and shadow DOM complicates accessibility and testing (U).
- **No framework.** Right for the content script and the share page (owner decision 2). Too costly for a full vault UI with a design system.
- **A different framework per web surface.** Ruled out by ROADMAP §4.5 (one shared design system).
- **Deciding desktop here** (the earlier answer 3: one SPA, two shells). Reversed by the owner's native-client decision. This ADR leaves desktop to the desktop ADR (owner decision 4), so it binds nothing that either outcome would have to undo.

## Open questions for the owner

None open. Questions 1–4 are answered; the answers keep their numbers under [Owner decisions](#owner-decisions-2026-09-25-2026-09-26) (answer 3 was reversed the same day).

4. **This ADR leaves desktop to the desktop ADR** (ADR 0015 while it binds, ADR 0019 if accepted), and decides only the web platforms? This follows from reversing answer 3. Answered yes (owner decision 4). *Recommendation:* yes. This ADR can then be accepted for the M1 gate before ADR 0019 or without it. A no puts a desktop decision back here, which would have to hold under both ADR 0015 and ADR 0019.

## References

- [README](README.md) (gates); [ROADMAP](../ROADMAP.md) §4.1, §4.4, §4.5, §4.6, §4.9, §5 (row "UI stack"), §6.1
- [CRYPTO.md](../CRYPTO.md) §5.7, §5.9 (On-device accounts and the web vault login)
- [THREAT_MODEL](../THREAT_MODEL.md) §7.1, §7.2, §7.19, §8.6, A9, INV-35, INV-40, INV-42, INV-49, INV-68, INV-69, Q-4
- [ADR 0001](0001-record-architecture-decisions.md) point 3, [ADR 0010](0010-server-shape.md) §1, [ADR 0013](0013-shared-client-core.md), [ADR 0015](0015-desktop-tauri.md), [ADR 0016](0016-workspace-layout.md), [ADR 0019](0019-native-clients.md)
- Framework, library and lint-rule names and properties in the table: general knowledge, not re-verified for this ADR (U). Verify them in the M1 spike.
- pnpm settings in §3 (`onlyBuiltDependencies`, `save-exact`, the `workspace:` protocol, the v10 default) and the type-import option of `no-restricted-imports` in §2: general knowledge, not verified (U). Verify them in M1.
- Safari extension CSP support for `wasm-unsafe-eval`: not verified (U).
- rustc dropping `unsafe_code` diagnostics in external macro expansions: checked in the rustc 1.94.1 source (V, 2026-09-26). That wasm-bindgen glue contains such `unsafe`: inferred from its exported `extern "C"` symbols, not yet confirmed by expansion (L).
