// How the web vault lays out items: the fixed fields of each writable M1 item type (ADR 0018
// §7), their labels, and the grouping of a field list into fixed fields, URIs, custom fields
// and tags. Which fields are concealed is the core's answer (`FieldView.concealed`), never
// this module's; `secret` below only picks the input used to *type* a new value.
import type { FieldView, ItemChange, ItemType } from "@rizzy-vault/core";

/** A fixed field of an item type. */
export interface FixedField {
  readonly key: string;
  readonly label: string;
  /** Typed in the secret-field component (INV-68). */
  readonly secret?: boolean;
  /** A multi-line text. */
  readonly multiline?: boolean;
}

/** The item types this web vault creates (the writable M1 types of ADR 0018 §7). */
export const CREATABLE_TYPES: readonly { readonly type: ItemType; readonly label: string }[] = [
  { type: "login", label: "Login" },
  { type: "note", label: "Secure note" },
  { type: "card", label: "Card" },
  { type: "identity", label: "Identity" },
];

const NAME: FixedField = { key: "item.name", label: "Title" };
const NOTES: FixedField = { key: "item.notes", label: "Notes", multiline: true };

/** The fixed fields of each type, in display order. */
export const FIXED_FIELDS: Readonly<Partial<Record<ItemType, readonly FixedField[]>>> = {
  login: [
    NAME,
    { key: "login.username", label: "Username" },
    { key: "login.password", label: "Password", secret: true },
    { key: "login.totp", label: "One-time password secret (TOTP)", secret: true },
    NOTES,
  ],
  note: [NAME, NOTES],
  card: [
    NAME,
    { key: "card.holder", label: "Cardholder" },
    { key: "card.brand", label: "Brand" },
    { key: "card.number", label: "Number", secret: true },
    { key: "card.exp_month", label: "Expiry month" },
    { key: "card.exp_year", label: "Expiry year" },
    { key: "card.code", label: "Security code", secret: true },
    { key: "card.pin", label: "PIN", secret: true },
    NOTES,
  ],
  identity: [
    NAME,
    { key: "identity.title", label: "Title (Mr, Ms, …)" },
    { key: "identity.first_name", label: "First name" },
    { key: "identity.middle_name", label: "Middle name" },
    { key: "identity.last_name", label: "Last name" },
    { key: "identity.company", label: "Company" },
    { key: "identity.email", label: "Email" },
    { key: "identity.phone", label: "Phone" },
    { key: "identity.username", label: "Username" },
    { key: "identity.address1", label: "Address line 1" },
    { key: "identity.address2", label: "Address line 2" },
    { key: "identity.address3", label: "Address line 3" },
    { key: "identity.city", label: "City" },
    { key: "identity.state", label: "State or province" },
    { key: "identity.postal_code", label: "Postal code" },
    { key: "identity.country", label: "Country" },
    { key: "identity.ssn", label: "Social security number", secret: true },
    { key: "identity.passport_number", label: "Passport number", secret: true },
    { key: "identity.drivers_license", label: "Driver's license" },
    NOTES,
  ],
};

/** `uri/<id>/match`'s wire values (ADR 0037 §4, Accepted M2), for the editor's select and the
 * item detail view. `0x0000` ("absent") falls back to the account-level match default
 * (ADR 0037 §6); this web vault has no UI for that account setting yet (see ROADMAP §4.4 and
 * the M2 report), so it is shown as "Account default" without naming which mode that resolves
 * to. `0x0005` (Regex) is a value `rizzy-match` accepts and stores, but its own matching
 * decision reports `NotSupported` for it today (`crates/rizzy-match/src/modes.rs`): the editor
 * must not claim it works. */
export const MATCH_MODE_OPTIONS: readonly { readonly value: number; readonly label: string }[] = [
  { value: 0x0000, label: "Account default" },
  { value: 0x0001, label: "Base domain" },
  { value: 0x0002, label: "Host" },
  { value: 0x0003, label: "Starts with" },
  { value: 0x0004, label: "Exact" },
  { value: 0x0005, label: "Regex (advanced)" },
  { value: 0x0006, label: "Never" },
];

/** The wire value of `uri/<id>/match` this build does not yet evaluate for matching
 * (`crates/rizzy-match/src/modes.rs`'s `MatchOutcome::NotSupported`). */
export const MATCH_MODE_REGEX = 0x0005;

/** The label for a `uri/<id>/match` displayed value (`undefined` or out of range shows as
 * "Account default" and "Unknown" respectively, never a thrown error: ADR 0018 §6, "invalid
 * values never reject anything", applies to display too). */
export function matchModeLabel(value: string | undefined): string {
  const n = value === undefined ? 0 : Number.parseInt(value, 10);
  return MATCH_MODE_OPTIONS.find((o) => o.value === n)?.label ?? `Unknown (${value ?? ""})`;
}

/** The label of a fixed key, or the key itself. */
export function labelOf(key: string): string {
  for (const fields of Object.values(FIXED_FIELDS)) {
    const found = fields?.find((f) => f.key === key);
    if (found !== undefined) {
      return found.label;
    }
  }
  if (key === "item.favorite") {
    return "Favorite";
  }
  return key;
}

/** A list element (URI or custom field) gathered from its attributes. */
export interface Element {
  readonly list: string;
  readonly element: string;
  readonly attributes: ReadonlyMap<string, FieldView>;
}

/** An item's fields, grouped for display. */
export interface Grouped {
  /** Fixed keys (`item.name`, `login.password`, …) except `item.type` and `item.favorite`. */
  readonly fixed: readonly FieldView[];
  readonly favorite: boolean;
  readonly uris: readonly Element[];
  readonly custom: readonly Element[];
  /** `passkey/<id>/…` elements (ADR 0039 §1) — never exposes `user_handle`/`credential_id`/
   * `public_key_cose` as text (they are `kind: "bytes"`, `FieldView.value` always `undefined`
   * for those, `apps/extension/src/core-host/bindings.ts`'s `StoredPasskey` doc has the same
   * note): only `rp_id`/`created_ms`/`alg`/`discoverable` ever carry a displayable value. */
  readonly passkeys: readonly Element[];
  readonly tags: readonly string[];
  /** Fields of other lists or unknown keys, shown as they are. */
  readonly other: readonly FieldView[];
}

/** Groups a field list (module docs). The core gives elements in their display order. */
export function group(fields: readonly FieldView[]): Grouped {
  const fixed: FieldView[] = [];
  const other: FieldView[] = [];
  const tags: string[] = [];
  const elements = new Map<string, { list: string; element: string; attributes: Map<string, FieldView> }>();
  let favorite = false;
  for (const f of fields) {
    if (f.tag !== undefined) {
      tags.push(f.tag);
    } else if (f.list !== undefined && f.element !== undefined && f.attribute !== undefined) {
      if (f.list === "uri" || f.list === "field" || f.list === "passkey") {
        const id = `${f.list}/${f.element}`;
        let e = elements.get(id);
        if (e === undefined) {
          e = { list: f.list, element: f.element, attributes: new Map() };
          elements.set(id, e);
        }
        e.attributes.set(f.attribute, f);
      } else {
        other.push(f);
      }
    } else if (f.key === "item.favorite") {
      favorite = f.value === "true";
    } else if (f.key !== "item.type") {
      fixed.push(f);
    }
  }
  const all = [...elements.values()];
  return {
    fixed,
    favorite,
    uris: all.filter((e) => e.list === "uri"),
    custom: all.filter((e) => e.list === "field"),
    passkeys: all.filter((e) => e.list === "passkey"),
    tags,
    other,
  };
}

/** A fixed field the user edited: the typed text, and whether the field held a value. */
export interface FixedEdit {
  readonly key: string;
  readonly text: string;
  /** The value shown before the edit; `undefined` for a concealed or absent value. */
  readonly before: string | undefined;
  /** Whether the item held this field (concealed or not). */
  readonly present: boolean;
  /** A concealed field: an empty input means "keep", never "clear". */
  readonly concealed: boolean;
}

/**
 * The changes for the fixed fields of an edit, writing only the keys the user changed (ADR 0018
 * §11). A visible field emptied by the user is cleared; a concealed field left empty is kept,
 * and is cleared only through its own "Clear" control (a `clear` change the caller adds).
 */
export function fixedChanges(edits: readonly FixedEdit[]): ItemChange[] {
  const out: ItemChange[] = [];
  for (const e of edits) {
    if (e.concealed) {
      if (e.text !== "") {
        out.push({ op: "set", key: e.key, value: e.text });
      }
    } else if (e.text === "") {
      if (e.present) {
        out.push({ op: "clear", key: e.key });
      }
    } else if (e.text !== e.before) {
      out.push({ op: "set", key: e.key, value: e.text });
    }
  }
  return out;
}

/** Case-insensitive search over the title, username, website host and tags. */
export function matches(
  item: {
    title: string;
    username: string | undefined;
    websiteHost?: string | undefined;
    tags?: readonly string[];
  },
  query: string,
): boolean {
  const q = query.trim().toLocaleLowerCase();
  if (q === "") {
    return true;
  }
  return (
    item.title.toLocaleLowerCase().includes(q) ||
    (item.username?.toLocaleLowerCase().includes(q) ?? false) ||
    (item.websiteHost?.toLocaleLowerCase().includes(q) ?? false) ||
    (item.tags?.some((tag) => tag.toLocaleLowerCase().includes(q)) ?? false)
  );
}

/** Every distinct tag over `items`, with how many items carry it, most-used first and
 * alphabetical among ties. Used for the sidebar's Tags section (item 6). */
export function tagCounts(items: readonly { readonly tags: readonly string[] }[]): readonly {
  readonly tag: string;
  readonly count: number;
}[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    for (const tag of item.tags) {
      counts.set(tag, (counts.get(tag) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag));
}
