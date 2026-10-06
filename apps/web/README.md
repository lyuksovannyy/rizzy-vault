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

## The item editor

`src/views/ItemEditor.tsx` creates and edits every M1 item type, with a full editor of its
websites (URIs), custom fields (text, hidden, boolean) and tags, not only its fixed fields.

- **Idempotent save.** Adding a website or custom field mints its element id on the client
  (`newElementId` of `@rizzy-vault/core`) the moment the row is added to the form, not when
  Save is pressed, and sends that same id on every attempt to save the row. Writing the same
  element id's attributes a second time changes nothing (ADR 0018 §6), so retrying a save
  after an unclear outcome — the same pending rows, submitted again — cannot create a second
  website or field. See `packages/core/test/e2e.test.ts`'s "idempotent save" case and
  `crates/rizzy-wasm/src/items.rs`'s module docs.
- **Reorder.** A row not yet saved is reordered with plain array moves in the form (no network
  call). A row that is already part of the item is reordered with one small `editItem` call
  per move (`op: "move"`), applied immediately so the list the user sees always matches what
  the move was computed against.
- **Concealed fields never prefetch.** A concealed fixed field or custom field's input starts
  empty on edit; an empty input keeps the stored value, and a "Clear" checkbox is the only way
  to remove it. The value is read from the input element on save, never kept in React state.
- **The generator** (`GeneratorPane`, and `<PasswordGenerateSlot>` next to the login password
  and every hidden custom field, `@rizzy-vault/ui`) takes every option of `rizzy-core`'s own
  generator — length, each character class as Off/Allowed/Required, "avoid look-alike
  characters", an exclude list, a custom symbol set for passwords; word count, separator,
  capitalisation and a number for passphrases — and generates and checks entropy through
  `generatePasswordWithOptions`/`generatePassphraseWithOptions`/`passwordEntropy`/
  `passphraseEntropy` only; no generation or entropy arithmetic runs in this app. The options
  and the generator page's short history of values live only in `generator-memory.ts`'s React
  state, shared by every slot in the session and thrown away when the vault locks
  (`VaultView` unmounts on lock; never written to storage or synced). `generator-constants.ts`
  mirrors `rizzy-core`'s bounds, defaults and `generator_*` wording so this UI-thread code never
  imports a runtime value from `@rizzy-vault/core` (ADR 0013 §4); `generator-constants.test.ts`
  is the check that the mirror has not drifted. `generator-flow.ts` holds the plain calls to
  the core (`export-flow.ts`'s pattern), tested in `generator-flow.test.ts` against the real
  core: a normal option reaches the right call, an impossible combination is refused with
  exactly the core's own message, and the editor's fill is a pure DOM write.

## Export and import

`src/views/TransferPane.tsx`, with its steps in `src/export-flow.ts` and the countdown in
`src/hold.ts` (owner decision 2026-10-05; [ADR 0027](../../docs/adr/0027-export-payload.md)).
The core enforces every gate below itself (`rizzy-client`'s `export::gate`); the view collects
and shows them.

- **Every export** first asks for the Secret Key and master password again: an OPAQUE login of
  the same account, which allows one export within five minutes (`reauth_required` otherwise).
  A wrong password allows nothing.
- **Encrypted export**: under a password for this export file, typed twice, which is needed to
  import the file. It is not the master password; it must not be empty.
- **Plaintext export** (JSON or CSV): a dialog shows ADR 0027 §5's warning verbatim (with the
  CSV addition), counts down 10 seconds with the confirm button disabled, and needs the typed
  `EXPORT PLAINTEXT`. Closing and opening the dialog starts the count over, in the view and in
  the core (`plaintext_export_hold` before it ends).
- **Import** recognises the file's format from its bytes (`detectImportFormat` of
  `@rizzy-vault/core`): our encrypted export then asks for that file's password; our plaintext
  JSON and other products' files need nothing more; our CSV export and unknown files are
  refused with a message. The format can still be chosen by hand.

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
