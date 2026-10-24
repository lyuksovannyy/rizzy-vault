// SPDX-License-Identifier: AGPL-3.0-only

// The identity generator's fixed values (ADR 0079 §3, §8, Open question 7), mirrored from
// `@rizzy-vault/core`'s `agePresets()`, `DEFAULT_IDENTITY_DEFAULTS`, `IDENTITY_MIN_AGE` /
// `IDENTITY_MAX_AGE` and `IDENTITY_ERROR_MESSAGES`, plus the labels this client gives them.
//
// They are copied, not imported, for the reason `generator-constants.ts` gives: the UI thread
// holds no wasm and imports only types from `@rizzy-vault/core` (ADR 0013 §4). The values come
// from Rust (`crates/rizzy-client/src/identity_gen.rs`); `identity-constants.test.ts` checks
// this copy against the real core, so a drift fails a test instead of going stale. The draw,
// the bundled data and every check stay in the core: these only shape the form.
import type { IdentityDefaults } from "@rizzy-vault/core";

/** The youngest and oldest ages a range may hold (ADR 0079 §3). */
export const IDENTITY_MIN_AGE = 18;
export const IDENTITY_MAX_AGE = 99;

/** One age preset (ADR 0079 §3) with the label this client shows. */
export interface AgePresetOption {
  readonly id: string;
  readonly min: number;
  readonly max: number;
  readonly label: string;
}

/** The twelve presets, in the core's order; the first is the first-time default. */
export const AGE_PRESETS: readonly AgePresetOption[] = [
  { id: "18-27", min: 18, max: 27, label: "18–27" },
  { id: "28-65", min: 28, max: 65, label: "28+" },
  { id: "21-25", min: 21, max: 25, label: "21–25" },
  { id: "26-30", min: 26, max: 30, label: "26–30" },
  { id: "31-35", min: 31, max: 35, label: "31–35" },
  { id: "36-40", min: 36, max: 40, label: "36–40" },
  { id: "41-45", min: 41, max: 45, label: "41–45" },
  { id: "46-50", min: 46, max: 50, label: "46–50" },
  { id: "51-55", min: 51, max: 55, label: "51–55" },
  { id: "56-60", min: 56, max: 60, label: "56–60" },
  { id: "61-65", min: 61, max: 65, label: "61–65" },
  { id: "any", min: 21, max: 65, label: "Any (21–65)" },
];

/** The first-time defaults (ADR 0079 §3): a drawn sex, 18–27, name and birthday, no domain. */
export const DEFAULT_IDENTITY_DEFAULTS: IdentityDefaults = {
  sex: "random",
  country: null,
  ageMin: 18,
  ageMax: 27,
  emailStyle: "name",
  emailDomain: null,
};

/** The core's sentences for its `identity_*` codes. */
export const IDENTITY_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  identity_unsupported_country: "This country is not supported.",
  identity_age_range: `Enter an age from ${IDENTITY_MIN_AGE} to ${IDENTITY_MAX_AGE}, minimum first.`,
  identity_email_domain: "Enter a domain name such as example.com.",
  identity_email_domain_not_ascii: "Enter the domain in its ASCII form (xn--…).",
  identity_date: "The date on this device is out of range.",
  identity_unknown_field: "This field cannot be generated.",
  identity_invalid_option: "These generator options are not valid.",
};

/** The sentence for an `identity_*` code, as the core words it. */
export function identityErrorMessage(code: string): string {
  return IDENTITY_ERROR_MESSAGES[code] ?? "The identity could not be generated.";
}

/**
 * The keys the generator fills (ADR 0079 §3), in the form's order, with the name its Regenerate
 * button and the live region use ("Regenerate first name", "First name regenerated").
 */
export const GENERATED_FIELDS: readonly { readonly key: string; readonly name: string }[] = [
  { key: "identity.sex", name: "sex" },
  { key: "identity.title", name: "title" },
  { key: "identity.first_name", name: "first name" },
  { key: "identity.last_name", name: "last name" },
  { key: "identity.birthday", name: "birthday" },
  { key: "identity.email", name: "email" },
  { key: "identity.phone", name: "phone" },
  { key: "identity.username", name: "username" },
  { key: "identity.address1", name: "address line 1" },
  { key: "identity.city", name: "city" },
  { key: "identity.state", name: "state or province" },
  { key: "identity.postal_code", name: "postal code" },
  { key: "identity.country", name: "country" },
];

/** The generated keys alone. */
export const GENERATED_KEYS: readonly string[] = GENERATED_FIELDS.map((f) => f.key);

/** The spoken name of a generated key, or the key itself. */
export function generatedName(key: string): string {
  return GENERATED_FIELDS.find((f) => f.key === key)?.name ?? key;
}

/** The notice the create form shows (ADR 0079 §7, "Collision with reality"). */
export const COLLISION_NOTICE =
  "Generated details are random and may match real people or places. Don't use them where you must give your real details.";

/** The email field's hint while no domain is set (ADR 0079 §8). */
export const NO_DOMAIN_HINT = "Set an email domain to generate addresses";

/** The INV-65 note (ADR 0079 §8): a name-style address on a catch-all domain is guessable. */
export const CATCH_ALL_NOTE =
  "A name-style address on a catch-all domain is easy to guess; the nickname style is harder to guess.";
