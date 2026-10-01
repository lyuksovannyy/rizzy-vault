# @rizzy-vault/web

The web vault ([ROADMAP](../../docs/ROADMAP.md) §4.2, minimal UI in M1): React and strict
TypeScript ([ADR 0014](../../docs/adr/0014-ui-stack.md)), served by the `web` role of
`rizzy-vault` from memory when the server is built with `embed-web`
([ADR 0010](../../docs/adr/0010-server-shape.md) §4).

## How it is put together

- **One core Worker** (`src/core-worker.ts`) holds the only wasm instance, every handle and
  every key, runs Argon2id, and carries each `/api/v1` request the Rust core builds to the
  vault's own origin ([ADR 0013](../../docs/adr/0013-shared-client-core.md) §4,
  [ADR 0028](../../docs/adr/0028-api-v1-http-conventions.md)). There is no cryptography in
  TypeScript.
- **The UI thread** (`src/App.tsx`, `src/views/`) talks to it through `src/core-client.ts`
  and `src/protocol.ts`, and imports only types from `@rizzy-vault/core` (an ESLint rule).
  Typed secrets cross as UTF-8 byte arrays whose buffers are transferred and zeroed by the core.
- **Nothing is persisted** ([CRYPTO.md](../../docs/CRYPTO.md) §11.4): every session is an
  OPAQUE login, so a lock or a reload means logging in again. It locks itself after 15 minutes
  without input (`src/autolock.ts`), after one last sync of unsent changes bounded to 10 s. A
  lock never waits on the network or the clipboard. Every request has a 60 s deadline, and a
  lock aborts the requests in flight (`src/bounded-fetch.ts`).
- **Secret fields** are rendered only by `SecretField` of `@rizzy-vault/ui` (INV-68). Item
  URLs open only through `src/SafeLink.tsx` (`http:` and `https:` only, INV-42). Copied values
  are cleared from the clipboard after 30 s, on lock and on `pagehide`; a clear the browser
  refuses (no focus) is retried on refocus. The vault reads the clipboard back only when it
  already holds the clipboard-read permission, and never asks for it (`src/clipboard.ts`).
- **CSP** (INV-49, `WEB_CSP` in `crates/rizzy-server/src/http/security.rs`): no inline script
  or style, `'self'` only, `'wasm-unsafe-eval'` for the core, and
  `require-trusted-types-for 'script'`; the Worker's URL goes through the one Trusted Types
  policy (`src/trusted-types.ts`), which admits only that URL.
- **Fixed output names** (`assets.ts`): the server embeds exactly these files; the build fails
  on any other.

## Build and test

From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm run build:wasm     # rizzy-wasm → packages/core/generated (needs wasm-bindgen-cli, locked version)
pnpm run build          # packages/core, then apps/web → apps/web/dist
pnpm run lint           # the ADR 0014 §2 rules (eslint.config.mjs)
pnpm run test           # Vitest, every package
pnpm run e2e            # builds rizzy-vault with embed-web, then Playwright (Chromium) against it
```

Playwright needs its Chromium build: `pnpm --filter @rizzy-vault/web exec playwright install chromium`.
