// SPDX-License-Identifier: AGPL-3.0-only

// The "New identity" form's own logic (ADR 0079 §10), kept pure so it is unit-tested apart from
// React (`identity-form.test.ts`): which generated values a redraw may write, the age picker's
// three modes, and the starting options. The draw itself is the core's (`IdentityDraft` in
// packages/core, reached through the Worker's handle calls, `protocol.ts`).
//
// **Who owns a field.** Each generated key (and the item name) has an origin:
// - `generated`: it holds the last draw, so any redraw that returns it may replace it;
// - `edited`: the user typed in it, so only its own Regenerate button replaces it (and makes
//   it `generated` again), never a picker change or Regenerate all;
// - `blank`: "Start blank" emptied it. A picker change leaves it empty (the user is entering
//   real details); Regenerate all, or its own Regenerate, fills it again.
//
// The core's `regenerate` returns every field, so the merge below decides what is written
// (`rizzy-client`'s `regenerate_field` docs). The item name follows the first and last names
// while the user has not typed one (the core's `itemName` is "First Last").
import type { IdentityDefaults, IdentityEmailStyle, IdentityGeneratorOptions, IdentitySex } from "@rizzy-vault/core";

import {
  AGE_PRESETS,
  DEFAULT_IDENTITY_DEFAULTS,
  GENERATED_KEYS,
  IDENTITY_MAX_AGE,
  IDENTITY_MIN_AGE,
  generatedName,
} from "./identity-constants.ts";

/** The item name's key: a form value like the generated ones. */
export const ITEM_NAME = "item.name";

/** Who owns a field's value (module docs). */
export type FieldOrigin = "generated" | "edited" | "blank";

/** The generated part of the form: values and their origins, by key. */
export interface IdentityForm {
  readonly values: Readonly<Record<string, string>>;
  readonly origin: Readonly<Record<string, FieldOrigin>>;
}

/** What asked for a redraw. */
export type RedrawScope =
  /** A picker change (sex, country, age, email style): only `generated` fields are written. */
  | { readonly kind: "picker" }
  /** Regenerate all: `generated` and `blank` fields; never `edited` ones. */
  | { readonly kind: "all" }
  /** One field's own Regenerate: that field always, plus the `generated` dependents. */
  | { readonly kind: "field"; readonly key: string };

/** "First Last", from the form's names: the item name while the user has not typed one. */
export function nameOf(values: Readonly<Record<string, string>>): string {
  return [values["identity.first_name"] ?? "", values["identity.last_name"] ?? ""]
    .filter((s) => s !== "")
    .join(" ");
}

/** The form a fresh draw opens with: every generated key and the item name `generated`. */
export function formFromDraft(fields: Readonly<Record<string, string>>, itemName: string): IdentityForm {
  const values: Record<string, string> = {};
  const origin: Record<string, FieldOrigin> = {};
  for (const key of GENERATED_KEYS) {
    values[key] = fields[key] ?? "";
    origin[key] = "generated";
  }
  values[ITEM_NAME] = itemName;
  origin[ITEM_NAME] = "generated";
  return { values, origin };
}

/** Whether `scope` may write a field of `origin`. */
function writes(scope: RedrawScope, key: string, origin: FieldOrigin | undefined): boolean {
  if (scope.kind === "field" && scope.key === key) {
    return true;
  }
  return origin === "generated" || origin === undefined || (scope.kind === "all" && origin === "blank");
}

/**
 * Writes a redraw into the form (module docs): returns the new form and the generated keys whose
 * value it changed (the field a Regenerate button named is always listed).
 */
export function mergeDraft(
  form: IdentityForm,
  fields: Readonly<Record<string, string>>,
  scope: RedrawScope,
): { readonly form: IdentityForm; readonly written: readonly string[] } {
  const values: Record<string, string> = { ...form.values };
  const origin: Record<string, FieldOrigin> = { ...form.origin };
  const written: string[] = [];
  for (const key of GENERATED_KEYS) {
    if (!writes(scope, key, form.origin[key])) {
      continue;
    }
    const next = fields[key] ?? "";
    if (next !== (form.values[key] ?? "") || (scope.kind === "field" && scope.key === key)) {
      written.push(key);
    }
    values[key] = next;
    origin[key] = "generated";
  }
  if (writes(scope, ITEM_NAME, form.origin[ITEM_NAME])) {
    values[ITEM_NAME] = nameOf(values);
    origin[ITEM_NAME] = "generated";
  }
  return { form: { values, origin }, written };
}

/** The user typed `value` into `key`: it is theirs now; a `generated` item name follows the names. */
export function typed(form: IdentityForm, key: string, value: string): IdentityForm {
  const values: Record<string, string> = { ...form.values, [key]: value };
  const origin: Record<string, FieldOrigin> = { ...form.origin, [key]: "edited" };
  if (key !== ITEM_NAME && origin[ITEM_NAME] === "generated") {
    values[ITEM_NAME] = nameOf(values);
  }
  return { values, origin };
}

/** "Start blank": every value still `generated` is emptied; typed values stay. */
export function startBlank(form: IdentityForm): IdentityForm {
  const values: Record<string, string> = { ...form.values };
  const origin: Record<string, FieldOrigin> = { ...form.origin };
  for (const key of [...GENERATED_KEYS, ITEM_NAME]) {
    if (origin[key] === "generated" || origin[key] === undefined) {
      values[key] = "";
      origin[key] = "blank";
    }
  }
  return { values, origin };
}

/** Whether the user typed in `key`. */
export function isEdited(form: IdentityForm, key: string): boolean {
  return form.origin[key] === "edited";
}

/** "a", "a and b", "a, b and c". */
function listed(names: readonly string[]): string {
  if (names.length <= 1) {
    return names.join("");
  }
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1] ?? ""}`;
}

/** Upper-cases the first letter. */
function capitalized(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** What the polite live region says after a redraw (ADR 0079 §10: "First name regenerated"). */
export function announcement(scope: RedrawScope, written: readonly string[]): string {
  if (scope.kind === "field") {
    return `${capitalized(generatedName(scope.key))} regenerated`;
  }
  if (scope.kind === "all") {
    return "All generated fields regenerated, except the ones you edited";
  }
  if (written.length === 0) {
    return "No field regenerated: you edited every field this changes";
  }
  return `${capitalized(listed(written.map(generatedName)))} regenerated`;
}

// ---------------------------------------------------------------------------------------------
// The age picker (ADR 0079 §3 "Age presets and modes", §10).

/** The age select's values besides the preset ids. */
export const AGE_CUSTOM = "custom";
export const AGE_EXACT = "exact";

/** The age picker's state: the select's value and the texts of its number inputs. */
export interface AgeChoice {
  /** A preset id, {@link AGE_CUSTOM} or {@link AGE_EXACT}. */
  readonly select: string;
  readonly min: string;
  readonly max: string;
  readonly exact: string;
}

/** An age range, `IDENTITY_MIN_AGE <= min <= max <= IDENTITY_MAX_AGE`. */
export interface AgeRange {
  readonly min: number;
  readonly max: number;
}

/** Which number input a problem belongs to. */
export type AgeInput = "min" | "max" | "exact";

/** The picker as it opens on `range` (§10): the first preset with the same bounds, else
 * "Exact age" when `min = max`, else "Custom range". */
export function ageChoiceFor(range: AgeRange): AgeChoice {
  const preset = AGE_PRESETS.find((p) => p.min === range.min && p.max === range.max);
  const select = preset !== undefined ? preset.id : range.min === range.max ? AGE_EXACT : AGE_CUSTOM;
  return { select, min: String(range.min), max: String(range.max), exact: String(range.min) };
}

/** A typed age: whole decimal years in 18–99, else `undefined`. */
export function parseAge(text: string): number | undefined {
  const t = text.trim();
  if (!/^\d{1,2}$/u.test(t)) {
    return undefined;
  }
  const n = Number.parseInt(t, 10);
  return n >= IDENTITY_MIN_AGE && n <= IDENTITY_MAX_AGE ? n : undefined;
}

/** The sentence for an age outside 18–99. */
export const AGE_BOUNDS_ERROR = `Enter an age from ${IDENTITY_MIN_AGE} to ${IDENTITY_MAX_AGE}.`;
/** The sentence for a minimum above the maximum. */
export const AGE_ORDER_ERROR = "Max must not be below Min.";

/** The range a choice stands for, or the problem of each input that is not valid (§10: nothing
 * is redrawn until it is). */
export function ageRangeOf(
  choice: AgeChoice,
): { readonly ok: true; readonly range: AgeRange } | { readonly ok: false; readonly problems: Partial<Record<AgeInput, string>> } {
  if (choice.select === AGE_EXACT) {
    const n = parseAge(choice.exact);
    return n === undefined ? { ok: false, problems: { exact: AGE_BOUNDS_ERROR } } : { ok: true, range: { min: n, max: n } };
  }
  if (choice.select === AGE_CUSTOM) {
    const min = parseAge(choice.min);
    const max = parseAge(choice.max);
    const problems: Partial<Record<AgeInput, string>> = {};
    if (min === undefined) {
      problems.min = AGE_BOUNDS_ERROR;
    }
    if (max === undefined) {
      problems.max = AGE_BOUNDS_ERROR;
    }
    if (min !== undefined && max !== undefined && min > max) {
      problems.max = AGE_ORDER_ERROR;
    }
    return min !== undefined && max !== undefined && min <= max
      ? { ok: true, range: { min, max } }
      : { ok: false, problems };
  }
  const preset = AGE_PRESETS.find((p) => p.id === choice.select) ?? AGE_PRESETS[0];
  return { ok: true, range: { min: preset?.min ?? IDENTITY_MIN_AGE, max: preset?.max ?? IDENTITY_MAX_AGE } };
}

/** The select changed to `select`: a custom mode starts from the last valid range `from`. */
export function selectAge(choice: AgeChoice, select: string, from: AgeRange): AgeChoice {
  if (select === AGE_CUSTOM) {
    return { ...choice, select, min: String(from.min), max: String(from.max) };
  }
  if (select === AGE_EXACT) {
    return { ...choice, select, exact: String(from.min) };
  }
  return { ...choice, select };
}

// ---------------------------------------------------------------------------------------------
// Starting options.

/** The country a new identity starts with: the synced default if it is bundled, else the region
 * of the browser's first language that has a bundled one, else `US`, else the first bundled. */
export function defaultCountry(
  synced: string | null,
  languages: readonly string[],
  codes: readonly string[],
): string {
  if (synced !== null && codes.includes(synced)) {
    return synced;
  }
  for (const lang of languages) {
    const region = regionOf(lang);
    if (region !== undefined && codes.includes(region)) {
      return region;
    }
  }
  return codes.includes("US") ? "US" : (codes[0] ?? "US");
}

/** A language tag's region (`en-GB` → `GB`), or its likely one (`de` → `DE`). */
function regionOf(tag: string): string | undefined {
  try {
    const locale = new Intl.Locale(tag);
    return (locale.region ?? locale.maximize().region)?.toUpperCase();
  } catch {
    return undefined;
  }
}

/** The settings a new identity starts from: the synced defaults (or the first-time ones), with
 * this session's last-used age range over them (`identity-memory.ts`). */
export function startingDefaults(synced: IdentityDefaults | null, lastAge: AgeRange | undefined): IdentityDefaults {
  const base = synced ?? DEFAULT_IDENTITY_DEFAULTS;
  return lastAge === undefined ? base : { ...base, ageMin: lastAge.min, ageMax: lastAge.max };
}

/** The picker values the generator is called with. */
export interface GeneratorChoice {
  readonly sex: IdentitySex | "random";
  readonly country: string;
  readonly age: AgeRange;
  readonly emailStyle: IdentityEmailStyle;
  readonly emailDomain: string | null;
}

/** The core's options for a choice (today is the Worker's clock). */
export function optionsOf(choice: GeneratorChoice): IdentityGeneratorOptions {
  return {
    sex: choice.sex,
    country: choice.country,
    ageMin: choice.age.min,
    ageMax: choice.age.max,
    emailStyle: choice.emailStyle,
    emailDomain: choice.emailDomain,
  };
}

/** The value of `identity.sex` as the sex radio reads it: a drawn `male`/`female`, else none. */
export function drawnSex(value: string | undefined): IdentitySex | undefined {
  return value === "male" || value === "female" ? value : undefined;
}
