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
detail shell, "1Password feel" as inspiration only (no copied look, icons or text). Slice 1
built the shell, the item list and the item detail; slice 2 (this change) added toasts, an
accessible confirm dialog, keyboard shortcuts, a phone-width single-pane layout, the single
"New item" menu, the account menu and the Settings view. See "Not yet done" below for what
still remains.

- **The shell** (`VaultView.tsx`): a left sidebar — All items, Favorites, one entry per
  creatable item type, Trash, then Generator, Export and import, Settings — and a top bar with
  the sync state, a Sync button and the account menu (Settings, Lock). On screens narrower than
  48rem (`app.css`) the sidebar becomes a slide-over opened by a menu button, closed by its own
  backdrop, Escape, or by choosing anything in it. The sidebar's filter is a pure function,
  `inScope` (`ItemsPane.tsx`), applied on top of the existing free-text search; `emptyState`
  picks each section's empty message. Both are covered by `test/items-pane.test.ts`.
- **The item list** (`ItemsPane.tsx`): a type icon, title, the username or type as a subtitle,
  and a favorite star per row (an outline star kept in the layout but hidden for a non-favorite
  row, so rows do not shift when one is favorited); a live item count next to the search box;
  an empty state with a section-specific message; a single "New item" button opening a
  type-picker menu (replacing the old per-type button row). The list supports roving-tabindex
  keyboard navigation (see "Keyboard shortcuts" below).
- **The item detail** (`ItemView.tsx`): a header with the type icon, the name and a favorite
  toggle (an icon-only button, reusing the editor's own `editItem`/`item.favorite` write —
  module docs in `ItemView.tsx` — so this is the existing write path, not a new one); a website
  field's `SafeLink` now has a same-safe-URL icon-only open button beside it
  (`SafeLink.tsx`'s `SafeOpenButton`, the only other place besides `SafeLink` itself allowed a
  dynamic `href`, per `eslint.config.mjs`); the one-time code has an SVG countdown ring (static
  `stroke-dasharray`/`stroke-dashoffset` attributes, not the banned `style` prop). Moving an
  item to trash, and deleting it for good, now confirm through the accessible dialog below
  instead of `window.confirm`.
- **Icons** (`packages/ui/src/icons.tsx`): inline SVG React components, `aria-hidden`, carrying
  no text of their own — a button's accessible name still comes only from its visible label, so
  swapping an icon never changes what a screen reader announces or what a Playwright
  `getByRole` selector matches.

### Toasts and the confirm dialog (`@rizzy-vault/ui`)

- **`Toast.tsx`** (`ToastProvider`/`useToast`): success/error/info notices, bottom-right, each
  auto-dismissing (errors stay up longer) with its own dismiss button. Error toasts sit in their
  own `aria-live="assertive"` region; success/info toasts sit in a separate `aria-live="polite"`
  region, so a success notice never interrupts a screen reader mid-sentence over an error. The
  queue itself is a pure reducer, `toastReducer` (`packages/ui/test/toast.test.ts`); errors that
  already have their own accessible inline text (`ErrorText`, `common.tsx`) were kept as inline
  field errors rather than moved to a toast, per the task's own either/or.
- **`ConfirmDialog.tsx`**: `role="dialog"`, `aria-modal="true"`, a focus trap, initial focus on
  the *safe* action (never the destructive one), Escape and a labelled backdrop button both
  cancel. Replaces `window.confirm` for: moving an item to trash, deleting it for good
  (`ItemView.tsx`), locking with unsaved changes (`VaultView.tsx`), and turning two-factor
  authentication off (`TwoFactorPane.tsx`). The trap's cyclic arithmetic, `nextFocusIndex`, is
  unit-tested directly (`packages/ui/test/confirm-dialog.test.ts`); there is no jsdom dependency
  in this workspace, so the trap/Escape/backdrop behaviour itself is covered by Playwright
  instead (`e2e/vault.spec.ts`'s trash confirmation).

### Keyboard shortcuts (`src/shortcuts.ts`)

| Key | Does |
| --- | --- |
| `/` or Ctrl/Cmd+K | Focus the search box |
| ↑ / ↓ | Move the item-list selection |
| Enter | Open the selected item (native button activation) |
| Esc | Close a dialog, popover or the mobile sidebar |
| `N` | New item |
| `?` | Show the shortcuts help dialog |

Shortcuts never fire while typing in a form control or a `contenteditable` element — except
Escape (always) and the Ctrl/Cmd+K chord (always, by convention). `shortcutFor`/
`isTypingTarget`/`moveListSelection` are pure functions, unit-tested in
`test/shortcuts.test.ts`; the actual key dispatch lives in `VaultView.tsx`'s one `keydown`
listener, exercised end to end by `e2e/keyboard-nav.spec.ts`.

### Phone width

Below 48rem, `ItemsPane.tsx` shows one pane at a time: the item list, or the open item/editor
with a "Back" button, never both — `.items-detail-open` in `app.css` removes whichever pane is
not current from layout entirely, so neither can force horizontal scroll. The sidebar's own
48rem slide-over (above) is the third pane. Tablet widths (above 48rem) keep the list and
detail side by side, unchanged. Covered by `e2e/phone.spec.ts` at 375×812.

### The single "New item" menu, the account menu, and Settings

- **New item** (`ItemsPane.tsx`): one button with a type-picker menu, replacing the old row of
  "New {type}" buttons. The `N` shortcut starts a new item of the first creatable type directly.
- **Account menu** (`VaultView.tsx`'s top bar): Settings and Lock. There is no separate sign-out
  action — every M1 session is an OPAQUE login with no durable session to sign out of beyond
  locking (module docs above).
- **Settings** (`SettingsView.tsx`): one sidebar entry grouping Two-factor (`TwoFactorPane.tsx`,
  unchanged), Devices (`DevicesPane.tsx`, unchanged) and a new Appearance group (below).

### Appearance (theme), memory-only

`src/theme.ts`'s `ThemeProvider`/`useThemeContext`: "system" (default), "light" or "dark",
applied as `data-theme` on `document.documentElement` (`packages/ui/src/tokens.css` reads it).
Kept in memory only for the session — **no** `localStorage`, `sessionStorage` or `IndexedDB` —
pending the owner's answer on whether CRYPTO.md §11.4's "nothing is persisted" covers a
non-secret UI preference like this one (see "Not yet done" below, carried over from slice 1).

### Tags (`rizzy-wasm` → `@rizzy-vault/core` → `src/fields.ts`, `ItemsPane.tsx`, `VaultView.tsx`)

`ItemSummary` now also carries `tags` (the item's tag names, display order) and `websiteHost`
(the host of its first website, if any — never the full URI, never userinfo, path or query:
`website_host` in `crates/rizzy-wasm/src/items.rs`, unit-tested against
`https://user:pass@example.com/x?token=abc` → `example.com` and other edge cases). Both are
plaintext already shown elsewhere in the item (a tag, a website address), carried at the same
"smallest useful size" as the existing `username`/`favorite` summary fields (ADR 0013 §3 rule
3, ADR 0018 §6–§7), so no new ADR was needed for this extension.

- **Sidebar** (`VaultView.tsx`): a "Tags" group below Trash, one button per tag with its count
  (`tagCounts`, `fields.ts`), shown only when at least one item has a tag. Choosing a tag sets
  a new sidebar scope, `{ kind: "tag", tag }` (`ItemsPane.tsx`'s `Scope`/`inScope`).
  `tagCounts`/`inScope` are pure and unit-tested (`test/fields.test.ts`, `test/items-pane.test.ts`).
- **Search** (`matches`, `fields.ts`): now also matches the website host and any tag name, case
  insensitively, alongside the existing title/username.

### The item editor, restyled (item 4 of the redesign brief)

`ItemEditor.tsx`'s markup, class names, accessible names and every Playwright selector over it
are unchanged — only `app.css` changed, giving the existing `.item-editor`, `.field-edit`,
`.secret-edit`, `.list-row`/`.custom-field-row` and `.row-actions` classes (until now
unstyled, bare block layout) a consistent flex-row layout matching the rest of the shell: an
input grows to fill its row, a website/custom-field/tag row's move-up/down buttons and its
"Remove" checkbox sit together on one line, and a secret field's generate button and "Clear"
checkbox line up under the input the same way everywhere. Covered by the existing Playwright
specs that exercise the editor (`e2e/vault.spec.ts`'s generate-popover and two-websites specs);
no new test was needed since no behaviour changed.

### The auth screens: Caps Lock hint (item 6 of the redesign brief, partial)

Login, signup, unlock and the Emergency Kit already used the centered `.panel narrow` card and
`SecretField`'s own "Show"/"Hide" toggle before this change, so what was missing was the Caps
Lock hint. Added to `SecretField` itself (`packages/ui/src/SecretField.tsx`), not
copied into each screen: every masked secret input across the app — login, signup, unlock, the
item editor's password fields — now shows "Caps Lock is on." while it is on and the field is
still masked, reading only `KeyboardEvent.getModifierState("CapsLock")` on `keydown`/`keyup`,
never the key itself (so this cannot see or log a character of the secret). Covered by
`e2e/vault.spec.ts`'s Caps Lock spec, which dispatches a synthetic `keydown`/`keyup` with
`modifierCapsLock` set directly — Playwright's `keyboard.press("CapsLock")` does not reliably
toggle the real OS modifier in a headless browser, and the hint only cares what
`getModifierState` reports, so the synthetic event exercises the same code path a real Caps
Lock press would. The rest of item 6 — a numbered-steps layout for the Emergency Kit screen —
was not built; see "Not yet done".

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

Slice 1 covered items 1–3 of the redesign brief and the contrast table of item 7; the centered
card and "Show"/"Hide" toggle item 6 asks for were already present before this change. Slice 2
(this change) covered
item 1's Tags (above), item 4's CSS pass (above), item 5 (toasts, the confirm dialog), item 6's
Caps Lock hint (above), item 8 (keyboard shortcuts), item 9 (phone width), and the "New item"/
account-menu/Settings part of item 1 and 7's theme selector. Still open, left for a follow-up
change:

- **Item 6 (remainder).** The Emergency Kit screen was not restyled into a numbered-steps
  layout.
- **Item 7 (persistence).** The owner has not yet said whether CRYPTO.md §11.4's "nothing is
  persisted" covers a non-secret UI preference like the theme choice; until that is answered it
  stays in memory only, per the task's own fallback (`src/theme.ts` module docs), so it resets
  to "system" on every reload or lock.

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
