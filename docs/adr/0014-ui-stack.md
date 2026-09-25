# ADR 0014: UI stack

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (web vault, minimal) / M2 (extension) / M3 (design system, desktop)

## Context

The relevant ROADMAP rows:
- [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation): "TypeScript + one framework for web/extension/desktop". The reason given: "Extension ecosystem, hiring, and component libraries are JS-first. Rust stays where security lives."
- [ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3), Must, M3: one design system shared by the web vault, the extension and desktop. Keyboard-only use, screen-reader labels, WCAG AA contrast.
- [ROADMAP §4.1](../ROADMAP.md#41-foundations--project-hygiene-m0), Won't: "Monorepo tooling beyond Cargo + one JS package manager".

The UI surfaces:

| Surface | From | Notes |
|---|---|---|
| Web vault | M1 | Served by the `web` role under a strict CSP ([INV-49](../THREAT_MODEL.md#8-security-invariants)). Server-mode accounts only: [ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4) disables it in On-device mode (below) |
| Extension popup, options page, inline menu | M2 | MV3 CSP; loaded from the local package. The inline menu runs in an extension-origin iframe (INV-40) |
| Extension content script | M2 | Runs in every page. Must be tiny; no framework |
| Desktop (Tauri) | M3 | The same UI, on WebView2, WKWebView and WebKitGTK ([ADR 0015](0015-desktop-tauri.md)) |
| Share recipient page | M5 | Tiny, no account; possibly on a separate origin ([THREAT_MODEL Q-4](../THREAT_MODEL.md#10-open-questions-for-the-owner)) |

**The web vault and On-device accounts.** An On-device account has no OPAQUE record ([CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode)). [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration) forbids any difference between real and fake accounts before KE3, so the server cannot answer "this account is On-device". Such a user who opens the web vault would just see "wrong password or Secret Key", which looks like a password problem. So:
- the web vault's login screen always states that On-device accounts must use the extension, desktop, mobile or CLI;
- the login failure message repeats it.

The security requirements on UI code ([THREAT_MODEL §7.1](../THREAT_MODEL.md#71-web-vault-m1), INV-35, INV-42, INV-49):
- no inline script, no `eval` (only `wasm-unsafe-eval`), no third-party origins;
- auto-escaping, and no raw-HTML sinks;
- only `http(s)` URLs are ever opened from item fields;
- untrusted rich content only inside sandboxed iframes.

The framework matters less than it seems in two places. The content script is plain TypeScript whatever we pick. And extension and desktop assets load from local disk, so the framework's runtime size costs start-up time, not download time.

## Decision

### 1. Language and framework

- **TypeScript in strict mode** for all UI code.
- **One component framework** for the web vault, the extension pages and desktop.
- **Recommendation: React.** The final pick is open question 1.

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

**What decides it.** Under our lint rules and CSP, all three are safe enough, so security does not decide.
- **React** wins on accessibility primitives, library depth and contributor pool. The M3 accessibility Must is hard to meet from scratch. React costs runtime size and verbosity.
- **Svelte 5** is a close second. It wins on small output and simple code, but has the smaller accessibility ecosystem.
- **SolidJS** is technically excellent, but has the smallest ecosystem and contributor pool. That matters most for a project that needs outside help ([ROADMAP §6.1](../ROADMAP.md#6-risks--hard-truths)).

### 2. Rules for every framework

ESLint enforces these in CI from M1:
- **No raw-HTML sinks.** The framework's rule from the table, plus `no-restricted-properties` / `no-restricted-syntax` for `innerHTML`, `outerHTML`, `insertAdjacentHTML` and `document.write`.
- No `eval`, no `new Function`, no string arguments to `setTimeout` or `setInterval`.
- **One `openUrl` / `SafeLink` helper** that allows only `http:` and `https:` ([INV-42](../THREAT_MODEL.md#8-security-invariants)). A lint rule bans dynamic `href` values outside it.
- **No runtime CSS-in-JS.** Styles are static CSS files: CSS Modules or a zero-runtime tool. Design tokens are CSS custom properties.
- **No third-party origins.** No CDN, fonts are self-hosted, no analytics.
- **Untrusted rich content** (M5 shares, M6 mail HTML) renders only in sandboxed iframes, without `allow-scripts` and without `allow-same-origin` (INV-35).
- **The content script is framework-free TypeScript.** It only injects the extension-origin iframe and performs the fill (INV-40).
- **Trusted Types** (`require-trusted-types-for 'script'`) are turned on where browsers support them, once the chosen framework is shown to work with them (U).

### 3. Tooling (proposal)

- **pnpm workspaces.** The pnpm version is pinned in the `packageManager` field of the root `package.json`. The lockfile is committed, and CI runs `pnpm install --frozen-lockfile`.
- **Install scripts.** Dependency lifecycle scripts do not run on install, except for an explicit allow-list. This is pnpm's default since v10 (U).
- **Build and test:** Vite to build, Vitest for unit tests. Playwright for end-to-end tests, including extension tests against adversarial pages ([THREAT_MODEL §8.6](../THREAT_MODEL.md#86-autofill-and-urls)).
- **No Nx, Turborepo or Lerna** ([ROADMAP §4.1](../ROADMAP.md#41-foundations--project-hygiene-m0), Won't).
- **A JS dependency policy that mirrors `deny.toml`** lands with the first package in M1: a licence allow-list, an advisory check, and review of new dependencies. The tool is chosen in M1.

### 4. Monorepo layout for JavaScript (proposal)

```
apps/
  web/          web vault (M1)
  extension/    MV3 for Chromium and Firefox (M2)
  desktop/      Tauri shell; src-tauri/ holds the Rust side (M3, ADR 0015)
  share/        share recipient page (M5)
packages/
  core/         the only way UI code reaches Rust (M1). Two backends behind one interface:
                rizzy-wasm in the browser and extension, Tauri IPC on desktop (ADR 0013)
  ui/           design system: tokens and components (minimal in M1, full in M3)
  i18n/         message catalogues and helpers (M3)
  config/       shared tsconfig, ESLint and Vite presets (M1)
```

- Rust stays under `crates/` ([ADR 0016](0016-workspace-layout.md)).
- `apps/android` and `apps/ios` arrive in M7, with native UI over `rizzy-ffi` ([ADR 0013](0013-shared-client-core.md)).
- As with crates, a directory is created only when real code goes into it.

## Consequences

### Positive

- One design system and one component set across three surfaces, as ROADMAP §4.5 requires.
- The security rules are framework-independent and enforced by CI, so the framework choice does not weaken them.
- Mainstream tooling (pnpm, Vite, Playwright) keeps contributor onboarding cheap.
- `packages/core` gives the web and desktop builds the same UI code over different backends.

### Negative

- A JavaScript toolchain and an npm dependency tree join the supply chain ([THREAT_MODEL A9](../THREAT_MODEL.md#a9-supply-chain)). It needs its own policy, lockfile discipline and review.
- If React is chosen, bundles are larger than with Svelte or Solid, and the code is more verbose.
- Two languages in the repository: every contributor to a UI feature that touches core behaviour needs both.

### Risks

- An accessibility library we build on could be abandoned. Mitigation: wrap it in `packages/ui`, so a replacement stays local.
- A framework major release (a Svelte 6, a React 20) can force a migration across every surface at once. Pin majors, and upgrade deliberately.
- WebKitGTK on Linux desktop may lag behind the browsers we test the web vault on ([ADR 0015](0015-desktop-tauri.md)).

## Alternatives considered

- **Rust UI (Leptos, Dioxus, Yew).** It would share code with the core directly. But extension APIs, accessibility component libraries and the contributor pool are JS-first ([ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation)). Rendering through wasm gains no security, because the DOM is the same DOM.
- **Vue.** Comparable to Svelte in size and ergonomics, with a larger ecosystem than Svelte (U). It was not shortlisted, because ROADMAP named Svelte and React. It could replace Svelte in the comparison if the owner prefers it.
- **Angular.** A complete framework with its own accessibility kit (the CDK, U). It is heavier than the three above. It is not shortlisted.
- **Web Components (Lit).** Standards-based and small. But accessibility primitives have to be built by hand, and shadow DOM complicates accessibility and testing (U).
- **No framework.** Right for the content script and perhaps the share page (open question 2). Too costly for a full vault UI with a design system.
- **A different framework per surface.** Ruled out by ROADMAP §4.5 (one shared design system).

## Open questions for the owner

1. **Framework: React (recommended) or Svelte 5?** The deciding question is who writes most of the UI.
   - If it is the owner alone, and the owner prefers Svelte, Svelte's productivity may outweigh React's ecosystem.
   - If the project wants outside contributors and the fastest route to WCAG AA, pick React.

   **Owner answer 2026-09-25: React.** Questions 2 and 3 are still open, so this ADR stays Proposed.
2. **The share recipient page (M5): framework-free TypeScript?** *Recommendation:* yes. It renders one decrypted snapshot. Keeping it tiny keeps it auditable, and it is served on every open ([THREAT_MODEL §4.2.1](../THREAT_MODEL.md#421-the-web-vault-delivery-problem)).
3. **Desktop reuses `apps/web` views** (one SPA, two shells) rather than being a separate app. *Recommendation:* yes, one SPA over `packages/core`'s two backends.

## References

- [ROADMAP](../ROADMAP.md) §4.1, §4.5, §4.6, §5 (row "UI stack"), §6.1, §6.5
- [CRYPTO.md](../CRYPTO.md) §5.7, §5.9 (On-device accounts and the web vault login)
- [THREAT_MODEL](../THREAT_MODEL.md) §4.2.1, §7.1, §7.2, §8.6, A9, INV-35, INV-40, INV-42, INV-49, Q-4
- [ADR 0013](0013-shared-client-core.md), [ADR 0015](0015-desktop-tauri.md), [ADR 0016](0016-workspace-layout.md)
- Framework, library and lint-rule names and properties in the table: general knowledge, not re-verified for this ADR (U). Verify them in the M1 spike before the owner decides.
