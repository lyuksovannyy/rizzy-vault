# @rizzy-vault/i18n

Message catalogues and helpers for the web surfaces: the `packages/i18n/` of
[ADR 0014](../../docs/adr/0014-ui-stack.md) §4, for the [ROADMAP](../../docs/ROADMAP.md) §4.5 row
"Localization framework (i18n from day one of M3, English only at first)". It is a scaffold:
English is the only locale, and nothing picks a locale yet.

- `src/en.ts`: the English catalogue, one `as const` object from key to text. It is the source
  locale: its keys are the type `MessageKey`.
- `src/translate.ts`: `LOCALES` (`["en"]`), `Locale`, `Catalogue`, `CATALOGUES`, and `t`.
- No third-party library (no i18next, no FormatJS): named placeholders are all the messages
  need so far, and a new JS dependency needs the owner's approval (ADR 0014 §3).

Source only, like `@rizzy-vault/ui`: Vite compiles it into each app. `pnpm run build` here only
type-checks the package, tests included, which is what turns the `@ts-expect-error` lines of
`test/translate.test.ts` into checks.

## Using it

```ts
import { t } from "@rizzy-vault/i18n";

t("login.title"); // "Log in to rizzy-vault"
t("common.unknownError", { code }); // "Something went wrong (<code>)."
```

The compiler checks every call: an unknown key is an error, and so is a missing, extra or
misnamed placeholder value. The placeholders of a message are read from the type of its
English text.

`t` returns plain text. React escapes it when it renders; it is never HTML, so it never goes
into a raw-HTML sink (ADR 0014 §2, which ESLint enforces anyway). Values are inserted verbatim in
one pass: a value is not scanned for placeholders, and `$` patterns do not apply.

`isMessageKey(key)` tells whether a computed string is a key (own keys only, so `"constructor"`
is not). The web vault's `messageFor(code)` (`apps/web/src/messages.ts`) uses it to look up
`errors.<code>`.

## Adding a message

1. Add an entry to `src/en.ts`, in the section of the view that shows it. The key is
   `<area>.<name>` (`login.title`, `totp.prompt`). Reuse a key only when the meaning is the same
   (`action.cancel`), not merely the words.
2. `errors.<code>` words one stable error code (ADR 0013 §3 rule 4: errors are codes; the host
   words them). Its `<code>` is the code exactly, and it has no placeholder: no error message
   includes a value the user typed (INV-48).
3. A placeholder is `{name}`: a letter, then letters, digits or `_`. Braces mean nothing else
   (`test/catalogue.test.ts` checks this). Texts are trimmed, with no runs of spaces.
4. Use it with `t("<key>")` in the component instead of the literal. The visible text must stay
   what it was; the Playwright tests find elements by it.
5. When another locale exists, give it the entry too: the build fails until you do.

Plurals and number, date or list formatting are not supported: no message needs them yet. When
one does, add the smallest helper it needs here (`Intl.PluralRules` and `Intl.NumberFormat` are
built into the browser), with tests.

## How a locale would be added

Not done yet: which locales ship, and how one is chosen, are the owner's call. The steps:

1. Add its code to `LOCALES` in `src/translate.ts` (`["en", "de"] as const`).
2. Add `src/de.ts` with `export const de: Catalogue = { … }`. A missing key, or one English does
   not have, is a compile error.
3. Add it to `CATALOGUES`; until then the build fails. `test/catalogue.test.ts` then checks the new
   catalogue too: the same keys, the same placeholders as English, well-formed texts.
4. Choose the locale. This is a separate change: `translator(locale)` returns that locale's
   `t`, which a React context could provide instead of the module-level English `t`. The web
   vault keeps nothing between sessions ([CRYPTO.md](../../docs/CRYPTO.md#114-web-vault) §11.4), so the choice
   would come from the browser's language or a setting held in memory, and `<html lang>` in
   `apps/web/index.html` follows it.
