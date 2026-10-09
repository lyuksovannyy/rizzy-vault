// Edits write only the keys the user changed (ADR 0018 §11); concealed fields are never
// cleared by an empty input; grouping and search.
import type { FieldView } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import {
  FIXED_FIELDS,
  fixedChanges,
  group,
  labelOf,
  MATCH_MODE_OPTIONS,
  MATCH_MODE_REGEX,
  matchModeLabel,
  matches,
  tagCounts,
} from "../src/fields.ts";

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
    // Imported password history is grouped for the history view, never shown as raw fields.
    expect(g.pwhist).toHaveLength(1);
    expect(g.pwhist[0]?.attributes.get("value")?.value).toBe("old");
    expect(g.other).toEqual([]);
  });

  // ADR 0039 §1's `passkey/<id>/…` list: grouped the same way as `uri`/`field`, by element id —
  // never left to fall into `other` (`fields.ts`'s own `Grouped.passkeys` doc). The Bytes
  // attributes (`user_handle`, `credential_id`, `public_key_cose`) carry no text value at all
  // (`FieldView.value` is always `undefined` for `kind: "bytes"`, `crates/rizzy-wasm/src/
  // items.rs`'s own "Bytes and order keys have no text"), so this test's bytes attribute uses
  // `value: undefined` to match what the real core actually returns.
  it("groups passkey/<id>/… fields by element, never into other", () => {
    const g = group([
      f("passkey/d/rp_id", { list: "passkey", element: "d", attribute: "rp_id", value: "example.com" }),
      f("passkey/d/created_ms", { list: "passkey", element: "d", attribute: "created_ms", kind: "number", value: "1000" }),
      f("passkey/d/credential_id", { list: "passkey", element: "d", attribute: "credential_id", kind: "bytes", value: undefined }),
    ]);
    expect(g.passkeys).toHaveLength(1);
    expect(g.passkeys[0]?.attributes.get("rp_id")?.value).toBe("example.com");
    expect(g.passkeys[0]?.attributes.get("created_ms")?.value).toBe("1000");
    expect(g.other).toEqual([]);
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

  it("also searches website host and tags, case-insensitively", () => {
    const item = {
      title: "Example",
      username: undefined,
      websiteHost: "Example.com",
      tags: ["Work", "Finance"],
    };
    expect(matches(item, "example.com")).toBe(true);
    expect(matches(item, "WORK")).toBe(true);
    expect(matches(item, "finance")).toBe(true);
    expect(matches(item, "personal")).toBe(false);
    expect(matches({ title: "x", username: undefined }, "y")).toBe(false);
  });
});

describe("tagCounts", () => {
  it("counts tags across items, most-used first, alphabetical among ties", () => {
    const items = [
      { tags: ["work", "urgent"] },
      { tags: ["work"] },
      { tags: ["personal"] },
      { tags: [] },
    ];
    expect(tagCounts(items)).toEqual([
      { tag: "work", count: 2 },
      { tag: "personal", count: 1 },
      { tag: "urgent", count: 1 },
    ]);
  });

  it("is empty when no item has a tag", () => {
    expect(tagCounts([{ tags: [] }])).toEqual([]);
  });
});

// `uri/<id>/match`'s wire values (ADR 0037 §4, Accepted M2): the editor's select options and
// the item detail view's label, for every assigned value and the absent/account-default case.
describe("MATCH_MODE_OPTIONS / matchModeLabel", () => {
  it("has exactly one option per assigned wire value, 0x0000 through 0x0006", () => {
    expect(MATCH_MODE_OPTIONS.map((o) => o.value)).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });

  it("labels the absent case as the account default, not a specific mode", () => {
    expect(matchModeLabel(undefined)).toBe("Account default");
    expect(matchModeLabel("0")).toBe("Account default");
  });

  it("labels every assigned value", () => {
    expect(matchModeLabel("1")).toBe("Base domain");
    expect(matchModeLabel("2")).toBe("Host");
    expect(matchModeLabel("3")).toBe("Starts with");
    expect(matchModeLabel("4")).toBe("Exact");
    expect(matchModeLabel("6")).toBe("Never");
  });

  it("flags Regex as not evaluated by this build, never as a working mode", () => {
    expect(matchModeLabel(String(MATCH_MODE_REGEX))).toMatch(/advanced/i);
  });

  it("never throws on an unassigned or malformed value — shows as unknown instead (ADR 0018 §6: invalid values never reject anything)", () => {
    expect(matchModeLabel("7")).toBe("Unknown (7)");
    expect(matchModeLabel("not a number")).toContain("Unknown");
  });
});
