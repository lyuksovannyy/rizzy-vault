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

## The shell and item views (redesign, in progress)

`src/views/VaultView.tsx`, `ItemsPane.tsx` and `ItemView.tsx` were restyled into a sidebar/list/
detail shell, "1Password feel" as inspiration only (no copied look, icons or text). This is a
first slice; see "Not yet done" below for what the full redesign still needs.

- **The shell** (`VaultView.tsx`): a left sidebar — All items, Favorites, one entry per
  creatable item type, Trash, then Generator, Export and import, Devices, Two-factor — and a
  top bar with the sync state and the Lock button. On screens narrower than 48rem (`app.css`)
  the sidebar becomes a slide-over opened by a menu button, closed by its own backdrop or by
  choosing anything in it. The sidebar's filter is a pure function, `inScope` (`ItemsPane.tsx`),
  applied on top of the existing free-text search; `emptyState` picks each section's empty
  message. Both are covered by `test/items-pane.test.ts`.
  - Screenshot, in words: a narrow column on the left lists "All items" (a four-square icon),
    "Favorites" (a star), then "Login"/"Secure note"/"Card"/"Identity" each with its own
    line-icon, then "Trash" (a bin); a divider; then "Generator", "Export and import",
    "Devices", "Two-factor". The active entry has a solid accent background. To its right, a
    top bar shows "Synced" (or a pending-change count) and a "Lock" button; below it, the
    search box and item count sit above the list.
- **The item list** (`ItemsPane.tsx`): a type icon, title, the username or type as a subtitle,
  and a favorite star per row (an outline star kept in the layout but hidden for a non-favorite
  row, so rows do not shift when one is favorited); a live item count next to the search box;
  an empty state with a section-specific message (no redundant second "create" button, since
  the "New {type}" buttons above the list already offer one for every type whenever they are
  shown at all).
- **The item detail** (`ItemView.tsx`): a header with the type icon, the name and a favorite
  toggle (an icon-only button, reusing the editor's own `editItem`/`item.favorite` write —
  module docs in `ItemView.tsx` — so this is the existing write path, not a new one); a website
  field's `SafeLink` now has a same-safe-URL icon-only open button beside it
  (`SafeLink.tsx`'s `SafeOpenButton`, the only other place besides `SafeLink` itself allowed a
  dynamic `href`, per `eslint.config.mjs`); the one-time code has an SVG countdown ring (static
  `stroke-dasharray`/`stroke-dashoffset` attributes, not the banned `style` prop).
- **Icons** (`packages/ui/src/icons.tsx`): inline SVG React components, `aria-hidden`, carrying
  no text of their own — a button's accessible name still comes only from its visible label, so
  swapping an icon never changes what a screen reader announces or what a Playwright
  `getByRole` selector matches.

### Colour contrast (item 7 of the redesign brief)

The token pairs declared in `packages/ui/src/tokens.css` (WCAG 2.1 contrast ratio, computed
from the sRGB hex values; AA requires 4.5:1 for normal text and 3:1 for large text/UI, which
every pair here clears with margin to spare):

| Pair | Light | Dark |
| --- | --- | --- |
| `--color-text` on `--color-bg` | 16.57:1 | 15.77:1 |
| `--color-text` on `--color-surface` | 17.74:1 | 14.27:1 |
| `--color-text-muted` on `--color-bg` | 7.50:1 | 9.20:1 |
| `--color-on-accent` on `--color-accent` | 6.54:1 | 8.02:1 |
| `--color-on-danger` on `--color-danger` | 6.54:1 | 10.09:1 |
| `--color-warning-text` on `--color-warning-bg` | 10.64:1 | 10.57:1 |

### Not yet done

This slice covers items 1–3 of the redesign brief (the shell, the item list, the item detail)
and the contrast table of item 7, over the existing `prefers-color-scheme` light/dark tokens.
Still open, left for a follow-up change:

- **Item 1.** A single "New item" type-picker control (today each creatable type has its own
  "New {type}" button, which is equivalent but not one dropdown); an account menu in the top
  bar; folding Devices and Two-factor into one "Settings" entry.
- **Item 1 (Tags).** A "Tags" sidebar entry with per-tag counts was not built: `ItemSummary`
  (`@rizzy-vault/core`) carries no `tags` field today (only `id`, `itemType`, `title`,
  `username`, `favorite`, `hasTotp`, `trashed`), so listing tags without fetching every item's
  full field list would need a core/wasm API change — out of scope for a UI-only redesign.
  Search is therefore still title/username only (the same limit holds for a website-search).
- **Item 4.** The item editor (`ItemEditor.tsx`) was not restyled.
- **Item 5.** No toast system and no accessible confirm-dialog component yet; the trash/purge/
  lock-with-unsaved-changes confirmations are still `window.confirm`.
- **Item 6.** The auth screens (login, signup, unlock, 2FA prompt, Emergency Kit) were not
  restyled.
- **Item 7.** A manual light/dark toggle in Settings, and storing that preference, were not
  built: [CRYPTO.md §11.4](../../docs/CRYPTO.md#114-web-vault) states plainly "Nothing is
  persisted" for the web vault's storage, and neither it nor
  [ADR 0026](../../docs/adr/0026-client-device-state-and-cache.md) says whether that line
  covers a non-secret UI preference like a theme choice or only session/key material; that is
  worth a direct answer from the owner before writing to `localStorage` (even wrapped in
  `try`/`catch`, for a non-secret preference only) or keeping the choice in memory for the
  session, as the task's own fallback asks.
- **Item 8.** No keyboard shortcuts (`/`, Ctrl/Cmd+K, arrow-key list navigation, `N`, a `?`
  help dialog) yet.
- **Item 9.** No phone-width single-pane-with-back-navigation layout; the list and detail panes
  still both show side by side down to roughly 360px, which gets cramped below ~400px.
- Vitest coverage for keyboard navigation, toasts and the confirm dialog, and Playwright specs
  for keyboard navigation and phone width, depend on items 5, 8 and 9 above and were not added
  yet either.

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
