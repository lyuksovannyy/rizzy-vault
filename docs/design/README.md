# Design language

The visual and motion design of rizzy-vault's clients: what the web vault and the browser
extension look like and how they move, and what the native desktop and mobile apps take from the
same source. It implements the design-system row of [ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3)
("1Password feel"), within the UI stack of [ADR 0014](../adr/0014-ui-stack.md) (React, static
CSS, no runtime CSS-in-JS) and the token pipeline of ADR 0014 §5 and
[ADR 0019](../adr/0019-native-clients.md) §13. UI work inside that stack needs no ADR
([adr/README.md](../adr/README.md)).

**Inspired by, never a clone.** ROADMAP §1 asks for the polish of 1Password, not its look. This
design takes no asset, icon, illustration, logo, colour scheme or layout signature from it or any
other product: the palette, the indigo brand accent, the icon set (packages/ui `icons.tsx`) and
the motion curves are this project's own.

**Where it lives.**

| What | File |
|---|---|
| Token source (every client) | [`packages/ui/tokens/tokens.json`](../../packages/ui/tokens/tokens.json) |
| Generator and its checks | [`crates/xtask/src/tokens.rs`](../../crates/xtask/src/tokens.rs) (`cargo xtask generate-tokens [--check]`) |
| Web tokens (generated) | [`packages/ui/src/tokens.css`](../../packages/ui/src/tokens.css) |
| Native tokens (generated) | [`packages/ui/tokens/generated/`](../../packages/ui/tokens/generated/) (`Tokens.swift`, `Tokens.kt`, `Tokens.xaml`, `Tokens.qml`) |
| Shared keyframes, skeleton, reduced-motion rules | [`packages/ui/src/motion.css`](../../packages/ui/src/motion.css) |
| Web vault styles | [`apps/web/src/app.css`](../../apps/web/src/app.css) |
| Extension styles | [`apps/extension/src/surface.css`](../../apps/extension/src/surface.css) |
| Motion checks (e2e) | [`apps/web/e2e/motion.spec.ts`](../../apps/web/e2e/motion.spec.ts) |
| Review screenshots | [`screenshots/`](screenshots/) (from [`apps/web/e2e/design-screenshots.spec.ts`](../../apps/web/e2e/design-screenshots.spec.ts)) |

Never edit a generated file. Change `tokens.json`, run `cargo xtask generate-tokens`, commit
both. CI's `generate-tokens --check` fails on a stale file, on a contrast pair below WCAG AA and
on a motion token that breaks a limit below.

## 1. Principles

1. **Calm and trustworthy.** A password manager is opened many times a day, often in a hurry.
   Quiet surfaces, one accent colour, no decoration that competes with the data.
2. **The data is the interface.** Titles, usernames and the fields of the open item carry the
   strongest type. Labels are muted; chrome recedes.
3. **Motion explains, never performs.** Every animation answers "where did this come from?" or
   "did that work?". None is there to be watched. Short, decelerating, interruptible.
4. **Accessible by construction.** Contrast pairs are checked in the generator, not in review;
   reduced motion is a token redefinition, not a list of exceptions; forced colours keep every
   state visible.
5. **One source, every client.** Colour, spacing, type, radius, elevation and motion come from one
   token file; a value is never typed twice.
6. **Security surfaces stay still.** What the extension frames into a web page never fades or
   slides (§8.6).

## 2. Colour

Two themes, light and dark, chosen by `prefers-color-scheme` or forced by the user in Settings
(`data-theme` on the root, `apps/web/src/theme.ts`). Dark is not an inverted light theme: its
surfaces get lighter as they rise (bg → surface → surface-raised), because shadows read poorly on
dark backgrounds.

| Role | Light | Dark | Use |
|---|---|---|---|
| `bg` | `#f4f5f8` | `#0e1014` | The page behind everything |
| `surface` | `#ffffff` | `#161920` | Panels, the sidebar, inputs |
| `surface-raised` | `#ffffff` | `#1e222b` | Dialogs, menus, popovers, toasts |
| `surface-hover` | `#eceef3` | `#232833` | Hover tint of rows and quiet buttons; icon wells |
| `border` | `#dcdfe6` | `#2b303b` | Decorative dividers and panel edges (not a control boundary) |
| `border-strong` | `#858b99` | `#6f7686` | Boundaries of inputs and secondary buttons (≥3:1, WCAG 1.4.11) |
| `text` | `#14161b` | `#eceef3` | Body text |
| `text-muted` | `#525866` | `#a8aebb` | Labels, hints, secondary lines |
| `accent` | `#4051d8` | `#8e9aff` | The brand indigo: primary actions, the selected marker, focus |
| `accent-hover` | `#3242c2` | `#a9b2ff` | Primary hover |
| `accent-subtle` | `#e8ebff` | `#252b4f` | Selected row / current section fill, the item icon well |
| `on-accent` | `#ffffff` | `#0a0f33` | Text on `accent` |
| `danger` / `on-danger` | `#c0271d` / `#ffffff` | `#ff9e94` / `#3b0400` | Destructive actions, errors |
| `success` / `on-success` | `#147a4a` / `#ffffff` | `#6ad49c` / `#00341b` | Success toasts and marks |
| `warning-bg` / `warning-text` | `#fff3d1` / `#4a3500` | `#3a2c00` / `#ffe08a` | Warnings (the Emergency Kit notice) |
| `focus` | `#4051d8` | `#8e9aff` | The focus ring |

**Contrast (WCAG 2.2 AA, both themes).** Every pair the UI draws is declared in
`contrast-pairs` and checked by the generator: 4.5:1 for text (text, text-muted, accent, danger
and success on every surface they sit on, on-accent/on-danger/on-success on their fills, text and
text-muted on the selected fill), 3:1 for the focus ring and control boundaries (focus on every
surface, border-strong on bg/surface/surface-raised). `border` is decorative and deliberately
undeclared. The lowest declared ratio today is 3.1:1 (border-strong on light bg); every text pair
is at least 4.9:1. Rendered pages are audited by axe in both themes (`e2e/a11y.spec.ts`).

**Colour is never the only signal.** The selected item has an accent edge, the current section
an accent bar and weight, the current onboarding step a filled numbered dot and weight, an error
its words.

## 3. Typography

The platform's own UI font (`system-ui` stack) and monospace stack: no web font is shipped
(nothing to load past the CSP's `font-src 'self'`, nothing to licence, native rendering per OS).

| Token | Size | Use |
|---|---|---|
| `font-size-caption` | 0.75rem | Group labels (uppercase, +0.06em), badges, tags, the extension's page host |
| `font-size-small` | 0.875rem | Field labels, hints, buttons marked `small`, the extension popup body |
| `font-size-body` | 1rem | Body text, inputs |
| `font-size-heading` | 1.125rem | Section headings, the command palette's search field |
| `font-size-title` | 1.375rem | Page titles, the open item's title |
| `font-size-display` | 1.75rem | Reserved for empty states and onboarding hero lines |

Weights: `regular` 400 (body), `medium` 500 (labels, buttons, row titles), `semibold` 600
(headings, the current step). Line height: `line-height-body` 1.5, `line-height-tight` 1.25 for
headings. Headings take −0.01em tracking. Secrets and codes use `font-mono`; the large-type view
colour-codes digits and symbols (and spaces them into cells, so colour is not the only cue).

## 4. Space, radius, elevation

**Spacing** is a 4px-based scale: `space-1` 0.25rem, `2` 0.5, `3` 0.75, `4` 1, `5` 1.25,
`6` 1.5, `8` 2, `10` 2.5, `12` 3rem. Padding inside a control is 2–3; between controls 2; between
groups 4–6; page gutters 4 (phone) to 6.

**Radius:** `radius-1` 6px (inputs, buttons), `radius-2` 10px (rows, menus, toasts),
`radius-3` 14px (panels, dialogs), `radius-full` (pills: tags, badges, step dots).

**Elevation** has three levels, each a soft two-layer shadow in light and a deeper single
shadow in dark, paired with the surface step above:

| Level | Token | Surfaces |
|---|---|---|
| 1 | `shadow-1` | Resting panels, popup rows |
| 2 | `shadow-2` | Menus, popovers, toasts, the login card |
| 3 | `shadow-3` | Modal dialogs, the command palette, the phone slide-over |

Forced colours drop shadows; anything raised then gets a `CanvasText` border (§9).

## 5. Iconography

- One set, packages/ui `icons.tsx`: inline SVG on a 24-unit grid, 2-unit stroke, round caps
  and joins, no fill, `currentColor`, sized `1em` so an icon follows its text. No icon font, no
  third-party origin. New icons follow the same grid and stroke and are drawn for this project,
  never copied or traced from another product's set.
- Icons are decorative (`aria-hidden`) next to a visible or accessible name; an icon-only button
  carries an `aria-label`.
- Item-type icons sit in a 2rem rounded well (`surface-hover`; `accent-subtle` with an accent
  glyph for the open item). A site's favicon (ADR 0052) replaces the type icon at the same size,
  so a row never shifts when it loads.
- Icons inherit the text colour of their control; the muted colour for passive icons, accent only
  for the selected/current state.

## 6. Components (web vault and extension)

- **Buttons.** Primary: accent fill, deepening on hover. Secondary: surface with a
  `border-strong` edge, `surface-hover` on hover. Danger: the danger fill, raised on hover.
  Link buttons: underlined text. Every button settles to `scale(var(--motion-scale-press))` while
  pressed (1 under reduced motion). Minimum target 24×24px (WCAG 2.5.8).
- **Inputs.** `border-strong` boundary, muted placeholder, a darker edge on hover, the focus
  colour as border plus a 2px focus outline.
- **Sidebar.** Quiet entries that tint on hover; the current section takes the accent-subtle fill,
  an inset accent bar at its start edge and medium weight, its icon in accent.
- **Item list.** Flat rows (no box per row), an icon well, a medium-weight title and a muted
  second line. Hover tints; the open item has the accent-subtle fill and an accent edge.
- **Item detail.** A raised panel; title at `title` size beside the accent icon well; field
  labels small and muted, values at body size, actions at the row's end.
- **Dialogs, menus, popovers, the command palette.** `surface-raised` with elevation 2 (menus,
  popovers) or 3 (dialogs). The scrim is near-black at 60%. Palette results use the list's row
  style; the highlighted result has the accent-subtle fill plus the focus outline.
- **Toasts.** Raised, bottom-end, a coloured status disc (success / danger / accent-subtle for
  info) and the message; the words carry the meaning.
- **Onboarding.** The three steps as a numbered track; the current step's dot is filled with the
  accent, done and pending steps are outlined.
- **Loading.** `.rv-skeleton` (motion.css): a muted block with a highlight that sweeps at most
  three times and then rests.

## 7. Motion

### 7.1 Tokens

| Token | Value | Use |
|---|---|---|
| `motion-duration-instant` | 90ms | Press feedback, palette row highlight |
| `motion-duration-fast` | 150ms | Hover and focus colour changes, menus opening |
| `motion-duration-base` | 220ms | Dialogs, popovers, toasts, scrims, list rows |
| `motion-duration-slow` | 320ms | Opening an item, screen entrances, the phone slide-over opening |
| `motion-duration-shimmer` | 1400ms | One sweep of the loading skeleton |
| `motion-duration-reduced` | 120ms | The crossfade every motion becomes under reduced motion |
| `motion-easing-standard` | `cubic-bezier(0.2, 0, 0, 1)` | Colour and state changes |
| `motion-easing-emphasized` | `cubic-bezier(0.16, 1, 0.3, 1)` | Entrances: fast start, long gentle settle |
| `motion-easing-decelerate` | `cubic-bezier(0, 0, 0.2, 1)` | Things arriving from off-screen |
| `motion-easing-accelerate` | `cubic-bezier(0.4, 0, 1, 1)` | Things leaving (the slide-over closing) |
| `motion-distance-1` / `2` / `3` | 4px / 8px / 16px | Pop-in offset / rise-in offset / slide-in offset |
| `motion-scale-enter` | 0.96 | Pop-in start scale |
| `motion-scale-press` | 0.97 | Pressed button |
| `motion-stagger-step` | 30ms | Delay between list rows entering |
| `motion-stagger-max-items` | 8 | Rows that stagger; the rest enter with the 8th |
| `motion-loop-max-iterations` | 3 | The most any looping animation repeats |

Limits the generator enforces (`tokens.rs`, "Motion"): no duration over 5000ms; shimmer ×
loop count ≤ 5000ms; stagger step × max items ≤ 240ms; the reduced crossfade ≤ 200ms; easings
with `x1`/`x2` in [0, 1] and a bounded overshoot.

### 7.2 Choreography

- **Enter, don't exit.** Entrances animate; exits are immediate (React unmounts the element). An
  exit animation would keep a closed dialog in the accessibility tree and delay the next action.
  The one exception is the phone slide-over, which slides out on the accelerate curve, faster
  than it came in.
- **Keyframes** (motion.css): `rv-fade-in` (scrims), `rv-rise-in` (panels, rows, toasts, notices:
  8px up and in), `rv-pop-in` (dialogs, menus, popovers, the palette: 4px up and from 0.96 scale,
  anchored at the trigger's corner), `rv-slide-in-end` (the opened item: 16px from the list's
  side), `rv-nudge` (an error message: ±4px once), `rv-settle` (a success mark). All use
  `animation-fill-mode: backwards`, so nothing keeps a transform after it has arrived (a lingering
  transform would make fixed-position dialogs inside it lose the viewport).
- **Lists stagger, with a cap.** Rows rise in 30ms apart, rows 8 and later all at 210ms, so even a
  long list is fully in place within 430ms.
- **Opening an item** is the one shared-element-like step: the detail pane is keyed by the item,
  so each open slides it in from the list side while the selected row takes its fill in the same
  beat. It reads as "this row became that pane" without the cost or risk of a real shared-element
  transition (no View Transitions API, no DOM cloning).
- **Dialogs and the palette**: scrim fades (base, standard), panel pops (base, emphasized).
  Menus and popovers pop at fast/base from their trigger's corner (`transform-origin`).
- **Toasts** rise from the stack's edge; the success disc settles in.
- **Focus, hover, press.** Colours change over `fast` on the standard curve; press scales over
  `instant`. Focus outlines appear immediately: a focus ring never waits for an animation.
- **Feedback.** Success: a toast and its settling mark. Error: the message nudges once, in the
  danger colour, with words. Nothing shakes a whole form or dialog.
- **Loading.** A skeleton block sweeps at most three times (4.2 s) and then rests; a spinner, if
  ever used, follows the same cap.
- **Running clocks** (the TOTP ring) glide one step a second because they show time, not to
  decorate; under reduced motion they step.
- **Never:** parallax, motion tied to scrolling, zooming the whole view, auto-playing loops,
  bounces or springs that overshoot by more than the emphasized curve, motion over 5 s.

### 7.3 Implementation rules

- CSS transitions and animations only, on transform and opacity (and colours), from the tokens.
  The Web Animations API is available for a future case CSS cannot express; no animation library
  is used or needed (no new dependency).
- No inline styles from script for motion: the web vault's CSP is `style-src 'self'` (INV-49);
  every rule is in a static stylesheet.
- A new animation uses a motion.css keyframe or adds one there built only from the distance and
  scale tokens, so reduced motion keeps working with no extra rule.

## 8. Platforms

### 8.1 Web vault
Everything above; `apps/web/src/app.css` over `tokens.css` and `motion.css`.

### 8.2 Extension popup and options page
`apps/extension/src/surface.css` (imported by each entry, emitted by Vite as an extension-origin
stylesheet; the `extension_pages` CSP sets no `style-src`). The popup (22rem wide) uses the web
vault's palette, rows and buttons, and the fade/rise entrance of motion.css; the current tab is
shown as the selected one.

### 8.3 Security surfaces framed into pages: no entrance motion
The inline menu, the save dialog and the passkey consent prompt are extension-origin documents
the content script frames into an untrusted page. Their clickjacking gates (INV-36;
`content/menu-visibility.ts`, the inline menu's IntersectionObserver v2 check) judge visibility.
They therefore **never animate opacity, transform or visibility**: a fade-in would read as "not
visible" to those gates, and a user who learns that menus fade in cannot tell a page's
half-transparent overlay attack from the real thing. They get the palette, type and hover/focus
colour transitions only. The content script's own iframe styling is unchanged.

### 8.4 Native apps (later; tokens only today)
The generator already writes Swift, Kotlin (Compose), XAML (WinUI 3) and QML (Qt 6 Quick) token
files; no native client consumes them yet (ADR 0019 §6). Mapping:

| Token | Swift | Kotlin | XAML | QML |
|---|---|---|---|---|
| Colours | `Color` per theme | `Color` per theme | `Color`/`SolidColorBrush` in theme dictionaries | `color` per theme |
| Durations | `TimeInterval` (seconds) | `Int` (ms) | `x:Double` (ms) | `int` (ms) |
| Easings | `(Double, Double, Double, Double)` for `Animation.timingCurve` | `CubicBezierEasing` | `"x1,y1 x2,y2"` for `KeySpline` | `[x1, y1, x2, y2, 1, 1]` for `Easing.Bezier` |
| Distances, spacing, type sizes, radii, shadows | CSS-unit strings | same | same | same |
| Scales, counts | `Double` / `Int` | `Float` / `Int` | `x:Double` / `x:Int32` | `real` / `int` |

Converting rem/px to points/dp and shadows to each toolkit's elevation model is a design call
for each client's own ADR. Native clients honour the OS setting (Reduce Motion, "Show animations
in Windows", Remove animations, Qt's `Application.styleHints`) the same way as the web: every
transition becomes `motionDurationReduced` as a crossfade, with no distance, scale, stagger or
loop. Platform conventions (sheets, navigation transitions) take precedence over this document
where the OS defines them.

## 9. Accessibility

- **Reduced motion (WCAG 2.3.3).** Under `prefers-reduced-motion: reduce`, tokens.css redefines
  the motion tokens: durations ≤ 120ms, distances 0px, scales 1, stagger 0ms, shimmer off, loops
  0. Every animation therefore becomes a short crossfade without movement; the phone slide-over
  and the TOTP ring's glide are switched off outright. `e2e/motion.spec.ts` walks the main
  surfaces with reduced motion emulated and fails if any animation or transition runs longer than
  `--motion-duration-reduced`, has a delay, or loops.
- **No motion over 5 s (WCAG 2.2.2)** and no infinite loops: generator-checked, and checked again
  on the rendered page with motion allowed.
- **No vestibular triggers:** no parallax, no scroll-linked motion, no large-area zoom or spin;
  the largest travel is 16px (and the phone slide-over, which reduced motion removes).
- **Contrast (WCAG AA)** in both themes: generator-checked token pairs, plus axe on every screen
  (light, dark, forced colours, phone; `e2e/a11y.spec.ts`, `apps/extension/e2e/a11y.spec.ts`).
  The audits wait for entrance animations to finish, so contrast is measured on what the user
  reads, not on a half-faded frame.
- **Forced colours.** Nothing sets `forced-color-adjust: none` (audited). State that only a fill
  or shadow carried (selected row, current section, palette highlight, current step, raised
  surfaces) gets a `Highlight` or `CanvasText` border under `forced-colors: active`.
- **Focus** is always a visible 2px outline in the focus colour (≥3:1 against every surface), never
  removed without a replacement (the palette draws it around its whole field).
- **Keyboard:** no change to tab order or behaviour; `e2e/keyboard-nav.spec.ts` stays the check.

## 10. Screenshots

[`screenshots/`](screenshots/) holds the web vault's key screens in light and dark for review,
named `web-<screen>-<theme>-<before|after>.png` (1180×760, about 1.9 MB in all). The "after"
set covers login, onboarding, the vault with an item open, the editor, the new-item menu, the
command palette, a confirm dialog and the unlock screen. To keep the folder small, the "before"
set (the M1/M2 styling this design replaced) keeps the four screens that changed most: login,
the vault with an item open, the command palette and the confirm dialog.

| Screen | Before | After |
|---|---|---|
| Login (light) | [before](screenshots/web-login-light-before.png) | [after](screenshots/web-login-light-after.png) |
| Login (dark) | [before](screenshots/web-login-dark-before.png) | [after](screenshots/web-login-dark-after.png) |
| Item open (light) | [before](screenshots/web-vault-item-light-before.png) | [after](screenshots/web-vault-item-light-after.png) |
| Item open (dark) | [before](screenshots/web-vault-item-dark-before.png) | [after](screenshots/web-vault-item-dark-after.png) |
| Command palette (light) | [before](screenshots/web-palette-light-before.png) | [after](screenshots/web-palette-light-after.png) |
| Command palette (dark) | [before](screenshots/web-palette-dark-before.png) | [after](screenshots/web-palette-dark-after.png) |
| Confirm dialog (light) | [before](screenshots/web-dialog-light-before.png) | [after](screenshots/web-dialog-light-after.png) |
| Confirm dialog (dark) | [before](screenshots/web-dialog-dark-before.png) | [after](screenshots/web-dialog-dark-after.png) |

The extension popup has no screenshots yet (its Playwright harness loads the unpacked
extension; adding a capture there is a follow-up). Regenerate
the "after" set (against a built server, see `apps/web/e2e/server.ts`) with:

```sh
cd apps/web
RIZZY_DESIGN_SCREENSHOTS=after pnpm exec playwright test e2e/design-screenshots.spec.ts
```

The spec is skipped unless that variable is set, so the e2e gate never rewrites the committed
images. Screenshots are taken with animations finished (Playwright `animations: "disabled"`).
