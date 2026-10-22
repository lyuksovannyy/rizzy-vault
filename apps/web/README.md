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
- **User-facing text** comes from the typed English catalogue of `@rizzy-vault/i18n`
  ([its README](../../packages/i18n/README.md): how to add a key, how a locale would be added).
  So far that is every error code's wording (`src/messages.ts` looks up `errors.<code>`), the
  login and unlock screen (`LoginView.tsx`) and the two-factor prompt (`TotpDialog.tsx`); the
  other views still hold literal English, and move over view by view.

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

## Conflicts: keep both / pick one

When two devices edit the same field before either has seen the other's edit, the sync engine
keeps both values ([ADR 0012](../../docs/adr/0012-sync-engine.md) §4, ADR 0018 §6) and the item
view marks the field "conflict" ([ROADMAP](../../docs/ROADMAP.md) §4.5). Its "Resolve
conflict" button opens `src/views/ConflictChooser.tsx` (wording and rules in
`src/conflicts.ts`, tested by `test/conflicts.test.ts`):

- **What it shows.** "Edited on X and Y at the same time", then each distinct value with the
  device and date that wrote it, the value shown now first. A concealed value (a password, a
  hidden field) stays masked until the user reveals that one value; the listing never carries
  it (ADR 0013 §3 rule 3). A value cleared on one device shows as "(cleared)".
- **Pick one.** "Use this value" writes that value back to the field ("Keep it cleared" for a
  cleared one). **Keep both** (text fields only) leaves the shown value in the field and moves
  every other value into a new custom field labelled "<field> (from <device>)", hidden when the
  field is concealed, or, for a website, into a new website.
- **How it syncs.** A resolution is an ordinary edit (`rizzy-client`'s `conflicts` module): it
  goes out with the next sync and ends the conflict on every device. If two devices resolve the
  same conflict at once with different choices, the field conflicts again, visibly; nothing is
  dropped. A resolution names the value by its listed position and id, so a sync between the
  listing and the click is refused ("This conflict has changed…") instead of resolving to a
  value the user did not see.
- **End to end:** `e2e/conflict.spec.ts` races two browser contexts of one account offline on
  the same password, resolves the first conflict by "pick one" and the second by "keep both",
  and checks that each resolution reaches the other session.

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
  authentication off (`TwoFactorPane.tsx`). The trap is `packages/ui/src/focusTrap.ts`'s
  `trapTab`, shared with every other modal dialog (shortcuts help, large type, the second-factor
  prompt, the plaintext-export dialog). Its cyclic arithmetic, `nextFocusIndex`, is
  unit-tested directly (`packages/ui/test/confirm-dialog.test.ts`); there is no jsdom dependency
  in this workspace, so the trap/Escape/backdrop behaviour itself is covered by Playwright
  instead (`e2e/vault.spec.ts`'s trash confirmation, `e2e/a11y.spec.ts`'s trap check on every
  dialog).

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
  unchanged), Devices (`DevicesPane.tsx`, unchanged), Website matching (below), a new
  Appearance group (below), "What the server stores" (below) and "Getting started", which
  re-opens the guide below.

### Website matching (ADR 0037 §6–§7, ADR 0042)

`src/views/MatchingPane.tsx`, helpers in `src/match-settings.ts`: the account-level match default
(the mode every website whose own match is "Account default" uses), the account's own
equivalence groups (add: two or more domains, each a site's own registrable domain — a public
suffix such as `co.uk` or a subdomain such as `www.example.com` is refused with
`equivalence_domain_rejected`; remove), the signed global list's groups with a Turn off / Turn on
switch each (none today: no signed list ships yet, and the pane says so), and "Check a website",
which asks the core what autofill would offer on an address under these settings. All of it is
the account's encrypted `ACCOUNT_SETTINGS`, committed with a new signed account state; the core
reads, checks and writes it (`VaultSession.changeMatchSettings`). The server takes a settings
change only within five minutes of the login (a fresh OPAQUE session, CRYPTO.md §11 "Replacing
credentials"); later, the change fails with "Log in again to do this." Covered by
`e2e/match-settings.spec.ts` and `test/match-settings.test.ts`.

### What the server stores (transparency, ROADMAP §4.5)

`src/views/TransparencyPane.tsx`, worded in `src/transparency.ts`: what the server holds for the
account and how (THREAT_MODEL §3.4, only the rows this server holds today: no shares, aliases,
mail or `icons` yet), how long it is kept (the 30-day Trash, tombstones and signed change
headers for the life of the vault, logs and backups: ADR 0012 §5 and §7, ADR 0021 §6, AR-11),
and the item, Trash and enrolled-device counts this browser already has from the vault it
fetched. The counts are labelled as the browser's own, not a server report. There are no
byte sizes and no server call of its own: no Accepted ADR defines a transparency endpoint
(ADR 0028 item 1 lists `GET /api/v1/devices/grants` as the only `GET`, and item 14's
`/api/meta` holds nothing about any account), and ADR 0048's `bytes_used` is Proposed.

### The getting-started guide (onboarding, ROADMAP §4.5)

`src/views/OnboardingView.tsx`, with its steps in `src/onboarding.ts`. It opens right after
signup, in place of the item list, and Settings' "Getting started" group opens it again. Three
steps, each with "Skip this step", and "Close the guide" at any step:

1. **Keep your Emergency Kit safe.** A confirmation only: the kit is shown once, at signup (ADR
   0008 point 1, CRYPTO.md §7), and the core refuses a second showing (`already_shown`), so the
   guide never displays the Secret Key or the recovery code. It says plainly that without a copy
   the account cannot be opened once the session ends. "Continue" waits for the box to be ticked.
2. **Import from another password manager.** The import form of "Export and import"
   (`TransferPane.tsx` `ImportForm`, unchanged), with the list of formats it reads.
3. **Install the browser extension.** Static instructions (load the unpacked Chromium build, or
   the Firefox build as a temporary add-on; the extension is not in the stores yet) and the
   values its "Set up this device" form asks for, with this server's origin and the login name
   filled in. No link, no request.

Then a summary of how each step ended. Each new step moves the focus to its heading, and the
step list marks the current step with `aria-current="step"`. The guide adds no endpoint, wire
field or stored value: CRYPTO.md §11.4 lets the web vault keep only the opted-in Secret Key and
the theme choice in browser storage, so "the guide is done" is remembered nowhere. The guide
shows after signup only, never after a login. Covered by `test/onboarding.test.ts` and
`e2e/onboarding.spec.ts`.

### Appearance (theme)

`src/theme.ts`'s `ThemeProvider`/`useThemeContext`: "system" (default), "light" or "dark",
applied as `data-theme` on `document.documentElement` (`packages/ui/src/tokens.css` reads it).
Remembered in `localStorage` under `rizzy-vault.theme`, as allowed by CRYPTO.md §11.4
(owner decision of 2026-10-07): besides the opted-in Secret Key, the only value the web vault keeps in
browser storage, and not a secret. A missing, unreadable or unknown stored value means "system"; a storage that throws
(private windows, blocked site data) leaves the choice in memory only.

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

The same pairs, declared in `packages/ui/tokens/tokens.json`, are checked by `cargo xtask
generate-tokens --check` in CI, which fails below AA. The rendered pages are checked too (next
section).

### Markdown in Secure Notes (ADR 0062, INV-88)

A Secure Note's notes show rendered from their Markdown in the item view (`src/markdown.ts`
parses, `src/views/NoteMarkdown.tsx` renders). Only Secure Notes: a Login's, Card's or
Identity's notes stay plain text (ADR 0062 §2), and so do the CLI, the extension and the
native clients. The editor keeps the plain textarea, and Copy and export always give the stored
source unchanged (§12).

- **What renders** (§5, a deliberate subset, not CommonMark): `#` to `######` headings; paragraphs,
  where a single newline is a line break; `**bold**` or `__bold__`, `*italic*` or `_italic_`,
  `~~struck~~` and ``code`` within one line; fenced code blocks (the language hint is dropped; no
  highlighting); `>` quotes and `-`/`*`/`+` or `1.` lists, one level each; and `---` rules. A
  backslash makes the next punctuation character literal; `_` inside a word (`snake_case`) stays as
  typed.
- **What does not.** Links (`[text](url)`, `<url>`, bare URLs), images, raw HTML, HTML entities,
  tables, footnotes and task boxes are shown as the literal text typed (§5–§7; owner answers 2
  and 7). A note never holds a clickable link, so nothing in it is focusable and `SafeLink` is
  not involved.
- **How it stays safe.** The parser outputs a closed AST with no HTML, link, image, style or
  attribute variant; the renderer maps each variant to one fixed element with one fixed class,
  through `switch`es with no default branch (a new variant is a compile error), and never builds
  an HTML string or uses a raw-HTML sink (§3, §6–§9). The tokenizer is linear with no
  backtracking pattern (§10); a note over the 64 KiB stored-value limit, or any parser
  exception, shows the plain stored text (§11). The CSP is unchanged and only a backstop (§13).
- **Tests.** `test/markdown.test.ts` (every construct, the deviations, literal fallbacks,
  fail-closed, pathological 64 KiB inputs), `test/note-markdown.test.ts` (exact markup, a hostile
  corpus, and a seeded property test that rendered markup stays inside the allow-list of
  `e2e/attack/markdown-allow-list.ts`), `test/markdown-fuzz.test.ts` (a seeded mutation fuzzer: the
  parser is TypeScript, so cargo-fuzz under `fuzz/` cannot reach it), and
  `e2e/markdown-note.spec.ts` (INV-88 in the browser: a hostile note runs nothing, holds no sink
  and nothing outside the allow-list, its URLs go nowhere; Copy returns the source; other types
  stay plain). `RIZZY_NIGHTLY=1` widens the property and fuzz budgets with a fresh seed
  (`RIZZY_NIGHTLY_SEED` replays one).

### Accessibility checks (ROADMAP §4.5, ADR 0014 §5)

`e2e/a11y.ts` holds the checks; [CONTRIBUTING.md](../../CONTRIBUTING.md#what-the-accessibility-checks-cover)
says how they fit with the token check and the extension's audit.

- **What is audited.** `e2e/a11y.spec.ts`: login, signup, the getting-started guide's steps,
  the vault list, the new-item menu, the editor (new and edit) and its generator popover, the
  item view (and a revealed password), large type, the trash confirmation, the command palette
  with results, the shortcuts help, the account menu, the generator, export and import with the
  plaintext-export dialog, Settings (two-factor, devices, appearance, "What the server stores",
  getting started), the trash, unlock, two-factor setup and the login's code prompt; then the
  dark theme, forced colours (light and dark) and phone width; and a Secure Note rendered from
  its Markdown, in each of those modes. `e2e/conflict.spec.ts` audits a conflicted item and the
  open conflict chooser.
- **What each audit checks.** axe-core (`@axe-core/playwright`, a dev dependency) runs every
  WCAG 2.0/2.1/2.2 A and AA rule and its best-practice rules: every control named, form fields
  labelled, text alternatives, one main landmark, an h1 and no skipped heading levels, document
  language and title, no duplicate ids that ARIA references, nothing focusable hidden from the
  accessibility tree, named dialogs, valid ARIA, target size, colour contrast of the rendered
  text. Any violation fails; `REQUIRED_RULES` fails a run in which axe did not evaluate one of
  the rules this list relies on. Then Chromium's own accessibility tree (CDP): every visible,
  focusable element is exposed and has a name. Every modal dialog must keep Tab and Shift+Tab
  inside it. Under forced colours, axe's contrast rule is replaced by "nothing opts out with
  `forced-color-adjust: none`" (Chromium reports the author's text colour there, not the
  painted system colour; see `a11y.ts`).
- **Keyboard only.** `e2e/keyboard-nav.spec.ts` walks the same screens with Tab, Enter, Space,
  Escape, the arrow keys and typing; `tabTo` fails when a control is not reached within its
  bound.
- **What is not covered.** Real screen readers (NVDA, JAWS, VoiceOver, Orca): the rules catch
  missing names, labels and structure, not whether the result reads well, so a UI change still
  needs a manual pass with one. Firefox and Safari (Chromium only). Contrast of colours the token
  file does not declare as a pair, outside what axe measures on the audited screens. The native
  clients' toolkits: their checks live in their own repositories (ADR 0019 §6); this repository
  only keeps their generated token files in sync (`cargo xtask generate-tokens --check`).

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

## Build and test

From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm run build:wasm     # rizzy-wasm → packages/core/generated (needs wasm-bindgen-cli, locked version)
pnpm run build          # packages/core, then apps/web → apps/web/dist
pnpm run lint           # the ADR 0014 §2 rules (eslint.config.mjs)
pnpm run test           # Vitest, every package
pnpm run e2e            # builds rizzy-vault with embed-web, then Playwright (Chromium) against it
pnpm --filter @rizzy-vault/web run e2e e2e/a11y.spec.ts   # only the accessibility audit
```

Playwright needs its Chromium build: `pnpm --filter @rizzy-vault/web exec playwright install chromium`.
