# @rizzy-vault/ui

The web design system of [ADR 0014](../../docs/adr/0014-ui-stack.md) §5, minimal in M1:

- `src/tokens.css`: the hand-written M1 token set as CSS custom properties (colour, spacing,
  type, radius; light and dark). M3 replaces it with the platform-neutral token source and
  generated CSS, keeping the property names where possible.
- `SecretField`: the **one** component that renders a secret input (master password, Secret
  Key, recovery code, export password, revealed secret fields), as ADR 0014 §2 and INV-68
  require. It sets `spellcheck="false"` and `autocomplete="off"` (plus `autocorrect` and
  `autocapitalize` off) and keeps them when a reveal switches `type` to `text`. ESLint bans
  `type="password"` everywhere else (`eslint.config.js`). The Playwright tests of `apps/web`
  check the attributes before and after reveal.

Source only: Vite compiles it into each app; there is no build step here.
