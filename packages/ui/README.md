# @rizzy-vault/ui

The web design system of [ADR 0014](../../docs/adr/0014-ui-stack.md) §5
([ADR 0019](../../docs/adr/0019-native-clients.md) §13 for the other toolkits):

- `tokens/tokens.json`: the one platform-neutral token source (colour incl. light/dark, spacing,
  type, radius, shadow) and its declared WCAG AA contrast pairs. `cargo xtask generate-tokens
  --check` (in CI) fails when a pair is below its `min-ratio` in either theme, and refuses a
  `min-ratio` below 3:1, so no pair can be declared into passing below AA.
- `src/tokens.css`: generated from `tokens/tokens.json` by `cargo xtask generate-tokens`, as CSS
  custom properties. Every M1 property name is kept, so nothing that reads this file changed.
  `cargo xtask generate-tokens --check` fails if it (or any file below) is stale.
- `tokens/generated/Tokens.{swift,kt,xaml,qml}`: the same source, generated for the other
  toolkits ADR 0019 §13 names. No client in this repository consumes them yet (the native clients
  live in their own repositories, ADR 0019 §6); they exist for the release workflow's token
  bundle (ADR 0019 §7) and so `--check` catches drift today.
- `SecretField`: the **one** component that renders a secret input (master password, Secret
  Key, recovery code, export password, revealed secret fields), as ADR 0014 §2 and INV-68
  require. It sets `spellcheck="false"` and `autocomplete="off"` (plus `autocorrect` and
  `autocapitalize` off) and keeps them when a reveal switches `type` to `text`. ESLint bans
  `type="password"` everywhere else (`eslint.config.js`). The Playwright tests of `apps/web`
  check the attributes before and after reveal.

- `ConfirmDialog`, and `trapTab` (`src/focusTrap.ts`): the focus trap every modal dialog of the
  web vault uses, so Tab never walks out of an `aria-modal` dialog into the page behind it.

Source only: Vite compiles it into each app; there is no build step here.
