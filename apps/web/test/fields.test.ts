// Edits write only the keys the user changed (ADR 0018 §11); concealed fields are never
// cleared by an empty input; grouping and search.
import type { FieldView } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { FIXED_FIELDS, fixedChanges, group, labelOf, matches } from "../src/fields.ts";

/** A field view with defaults. */
function f(key: string, more: Partial<FieldView> = {}): FieldView {
  return {
    key,
    list: undefined,
    element: undefined,
    attribute: undefined,
    tag: undefined,
    kind: "text",
    concealed: false,
    value: undefined,
    conflict: false,
    ...more,
  };
}

describe("fixedChanges", () => {
  it("writes only what changed", () => {
    expect(
      fixedChanges([
        { key: "item.name", text: "Same", before: "Same", present: true, concealed: false },
        { key: "login.username", text: "new", before: "old", present: true, concealed: false },
        { key: "item.notes", text: "", before: "had notes", present: true, concealed: false },
        { key: "login.password", text: "", before: undefined, present: true, concealed: true },
        { key: "login.totp", text: "JBSWY3DP", before: undefined, present: false, concealed: true },
        { key: "card.holder", text: "", before: undefined, present: false, concealed: false },
      ]),
    ).toEqual([
      { op: "set", key: "login.username", value: "new" },
      { op: "clear", key: "item.notes" },
      { op: "set", key: "login.totp", value: "JBSWY3DP" },
    ]);
  });
});

describe("group", () => {
  it("sorts fields into fixed, URIs, custom fields and tags", () => {
    const g = group([
      f("item.type", { kind: "enum", value: "1" }),
      f("item.name", { value: "Example" }),
      f("item.favorite", { kind: "bool", value: "true" }),
      f("login.password", { concealed: true }),
      f("uri/a/value", { list: "uri", element: "a", attribute: "value", value: "https://x" }),
      f("uri/a/order", { list: "uri", element: "a", attribute: "order", kind: "sort_key" }),
      f("field/b/label", { list: "field", element: "b", attribute: "label", value: "PIN" }),
      f("field/b/value", { list: "field", element: "b", attribute: "value", concealed: true }),
      f("tag/776f726b", { list: "tag", element: "776f726b", tag: "work", kind: "bool", value: "true" }),
      f("pwhist/c/value", { list: "pwhist", element: "c", attribute: "value", value: "old" }),
    ]);
    expect(g.fixed.map((x) => x.key)).toEqual(["item.name", "login.password"]);
    expect(g.favorite).toBe(true);
    expect(g.uris).toHaveLength(1);
    expect(g.uris[0]?.attributes.get("value")?.value).toBe("https://x");
    expect(g.custom[0]?.attributes.get("label")?.value).toBe("PIN");
    expect(g.tags).toEqual(["work"]);
    expect(g.other.map((x) => x.key)).toEqual(["pwhist/c/value"]);
  });
});

describe("layout", () => {
  it("names fields and marks the concealed ones the schema conceals", () => {
    expect(labelOf("login.password")).toBe("Password");
    expect(labelOf("x.unknown")).toBe("x.unknown");
    // ADR 0018 §7's concealed list, for the types this vault creates.
    const secret = Object.values(FIXED_FIELDS)
      .flatMap((fields) => fields ?? [])
      .filter((x) => x.secret === true)
      .map((x) => x.key)
      .sort();
    expect(secret).toEqual(
      [
        "card.code",
        "card.number",
        "card.pin",
        "identity.passport_number",
        "identity.ssn",
        "login.password",
        "login.totp",
      ].sort(),
    );
  });

  it("searches title and username, case-insensitively", () => {
    const item = { title: "Example Bank", username: "Alice@Example.com" };
    expect(matches(item, "")).toBe(true);
    expect(matches(item, "bank")).toBe(true);
    expect(matches(item, "ALICE")).toBe(true);
    expect(matches(item, "bob")).toBe(false);
    expect(matches({ title: "x", username: undefined }, "y")).toBe(false);
  });
});
