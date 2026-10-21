// SPDX-License-Identifier: AGPL-3.0-only

// The locale list, the catalogue types and `t` (README.md). English is the only locale
// (ROADMAP §4.5, "English only at first"); adding one is a type-checked change (README.md, "Adding
// a locale"). No third-party library: named placeholders are all the messages need so far.
import { en } from "./en.ts";

/** Every locale this build ships. English is the source locale and the fallback. */
export const LOCALES = ["en"] as const;

/** A locale this build ships. */
export type Locale = (typeof LOCALES)[number];

/** The locale every surface uses today. */
export const DEFAULT_LOCALE: Locale = "en";

/** Every message key: the keys of the English catalogue (`en.ts`). */
export type MessageKey = keyof typeof en;

/** A full catalogue: one text per key. A locale's catalogue missing a key, or holding one
 *  English does not, does not compile. */
export type Catalogue = { readonly [K in MessageKey]: string };

/** The catalogue of each locale. A locale in `LOCALES` without one here does not compile. */
export const CATALOGUES: { readonly [L in Locale]: Catalogue } = { en };

/** The names of the `{name}` placeholders in the text type `S`. */
export type PlaceholderNames<S extends string> = S extends `${string}{${infer Name}}${infer Rest}`
  ? Name | PlaceholderNames<Rest>
  : never;

/** The values a message's placeholders take. The English text decides which there are; every
 *  locale's text must use the same ones (`test/catalogue.test.ts`). */
export type MessageParams<K extends MessageKey> = {
  readonly [P in PlaceholderNames<(typeof en)[K]>]: string | number;
};

/** `t`'s arguments after the key: none for a message without placeholders, else the values. */
export type MessageArgs<K extends MessageKey> = [PlaceholderNames<(typeof en)[K]>] extends [never]
  ? []
  : [params: MessageParams<K>];

/** Looks up a message and fills its placeholders. */
export type Translate = <K extends MessageKey>(key: K, ...args: MessageArgs<K>) => string;

/** A placeholder: `{`, a name, `}`. The name is a letter, then letters, digits or `_`. */
const PLACEHOLDER = /\{([A-Za-z][A-Za-z0-9_]*)\}/g;

/** The placeholder names in `text`, in order of appearance, repeats included. */
export function placeholders(text: string): string[] {
  return Array.from(text.matchAll(PLACEHOLDER), (m) => m[1] ?? "");
}

/**
 * Fills each `{name}` in `text` from `params`, in one pass: a value is inserted as it is and
 * never scanned for placeholders itself, and no `$` pattern of `String.prototype.replace`
 * applies to it. A placeholder without a value stays as written (the types rule that out for
 * `t`). Numbers are written with `String(n)`; no locale needs other digits yet.
 */
export function interpolate(
  text: string,
  params: Readonly<Record<string, string | number>> | undefined,
): string {
  if (params === undefined) {
    return text;
  }
  return text.replace(PLACEHOLDER, (whole, name: string) => {
    const value = Object.hasOwn(params, name) ? params[name] : undefined;
    return value === undefined ? whole : String(value);
  });
}

/** Whether `key` is a message key. Own keys only: `"constructor"` or `"toString"` is not. */
export function isMessageKey(key: string): key is MessageKey {
  return Object.hasOwn(en, key);
}

/** The `t` of `locale`. */
export function translator(locale: Locale): Translate {
  const catalogue = CATALOGUES[locale];
  return <K extends MessageKey>(key: K, ...args: MessageArgs<K>): string => {
    const [params] = args as readonly [Readonly<Record<string, string | number>>?];
    return interpolate(catalogue[key], params);
  };
}

/** The text of `key` in the default locale, placeholders filled: `t("login.title")`,
 *  `t("common.unknownError", { code })`. */
export const t: Translate = translator(DEFAULT_LOCALE);
