// SPDX-License-Identifier: AGPL-3.0-only

// @rizzy-vault/i18n: message catalogues and helpers for the web surfaces (ADR 0014 §4), English
// only (ROADMAP §4.5). README.md says how to add a key and how a locale would be added.
export { en } from "./en.ts";
export {
  CATALOGUES,
  DEFAULT_LOCALE,
  LOCALES,
  interpolate,
  isMessageKey,
  placeholders,
  t,
  translator,
  type Catalogue,
  type Locale,
  type MessageArgs,
  type MessageKey,
  type MessageParams,
  type PlaceholderNames,
  type Translate,
} from "./translate.ts";
