// SPDX-License-Identifier: AGPL-3.0-only

// Edits write only the keys the user changed (ADR 0018 §11); concealed fields are never
// cleared by an empty input; grouping and search.
import type { FieldView } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import {
  CREATABLE_TYPES,
  FIXED_FIELDS,
  SSH_DEFAULT_PORT,
  UNSUPPORTED_ITEM,
  canEditFields,
  compareFavoriteFirst,
  fixedChanges,
  group,
  isMultiline,
  labelOf,
  MATCH_MODE_OPTIONS,
  MATCH_MODE_REGEX,
  matchModeLabel,
  matches,
  orderFixed,
  tagCounts,
  typeLabel,
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

// ADR 0055 §1: the fixed keys of each M3 type, and the six the core conceals (§4; ADR 0078 §7
// retired the Bank account type and its two). The web vault's `secret` flag picks the input a
// new value is typed in; it must match the core's list.
const M3_KEYS: Readonly<Record<string, readonly (readonly [string, boolean])[]>> = {
  "ssh-key": [
    ["ssh.host", false],
    ["ssh.port", false],
    ["ssh.username", false],
    ["ssh.private_key", true],
    ["ssh.public_key", false],
    ["ssh.passphrase", true],
  ],
  "api-credential": [
    ["api.name", false],
    ["api.key", true],
    ["api.secret", true],
    ["api.endpoint", false],
  ],
  "software-license": [
    ["license.name", false],
    ["license.key", true],
    ["license.seats", false],
    ["license.expires", false],
  ],
  wifi: [
    ["wifi.ssid", false],
    ["wifi.password", true],
    ["wifi.security_type", false],
  ],
};

describe("the M3 item types (ADR 0055)", () => {
  it("are creatable, each with its own keys and the six concealed ones typed as secrets", () => {
    expect(CREATABLE_TYPES.map((t) => t.type)).toEqual([
      "login",
      "note",
      "card",
      "identity",
      "ssh-key",
      "api-credential",
      "software-license",
      "wifi",
    ]);
    let secrets = 0;
    for (const [type, keys] of Object.entries(M3_KEYS)) {
      const fields = FIXED_FIELDS[type as keyof typeof FIXED_FIELDS] ?? [];
      expect(fields.map((x) => x.key)).toEqual(["item.name", ...keys.map(([k]) => k), "item.notes"]);
      for (const [key, secret] of keys) {
        expect(fields.find((x) => x.key === key)?.secret === true, key).toBe(secret);
        secrets += secret ? 1 : 0;
      }
    }
    expect(secrets).toBe(6);
    // Labels are unique within a type, so each input has its own accessible name.
    for (const fields of Object.values(FIXED_FIELDS)) {
      const labels = (fields ?? []).map((x) => x.label);
      expect(new Set(labels).size).toBe(labels.length);
    }
  });

  it("type an SSH private key in a multi-line field, and show port 22 when none is set", () => {
    expect(isMultiline("ssh.private_key")).toBe(true);
    expect(isMultiline("item.notes")).toBe(true);
    expect(isMultiline("ssh.public_key")).toBe(false);
    expect(isMultiline("login.password")).toBe(false);
    expect(SSH_DEFAULT_PORT).toBe("22");
    expect(FIXED_FIELDS["ssh-key"]?.find((x) => x.key === "ssh.port")?.placeholder).toBe("22");
  });

  it("show a type this build does not know generically, with no field edits (ADR 0018 §8, §11)", () => {
    expect(typeLabel("wifi")).toBe("Wi-Fi");
    expect(typeLabel("unknown")).toBe(UNSUPPORTED_ITEM);
    // `passkey` is a name the core reserves but no type this build creates.
    expect(typeLabel("passkey")).toBe(UNSUPPORTED_ITEM);
    expect(canEditFields("ssh-key")).toBe(true);
    expect(canEditFields("unknown")).toBe(false);
    expect(canEditFields("passkey")).toBe(false);
  });

  it("no longer create or edit the Bank account type ADR 0078 retired", () => {
    // The wasm names a `0x0009` item `unknown` (ADR 0078 §5), so it shows as unsupported.
    expect(CREATABLE_TYPES.some((t) => (t.type as string) === "bank-account")).toBe(false);
    expect(Object.keys(FIXED_FIELDS)).not.toContain("bank-account");
    const keys = Object.values(FIXED_FIELDS).flatMap((fields) => (fields ?? []).map((x) => x.key));
    expect(keys.filter((k) => k.startsWith("bank."))).toEqual([]);
    expect(typeLabel("unknown")).toBe("Unsupported item, update rizzy-vault");
    expect(canEditFields("unknown")).toBe(false);
  });

  it("order an item's fixed fields as the editor does, unknown keys last", () => {
    const fixed = [
      f("ssh.username"),
      f("newer.key"),
      f("ssh.private_key"),
      f("item.name"),
      f("ssh.host"),
    ];
    expect(orderFixed("ssh-key", fixed).map((x) => x.key)).toEqual([
      "item.name",
      "ssh.host",
      "ssh.username",
      "ssh.private_key",
      "newer.key",
    ]);
    expect(orderFixed("unknown", fixed).map((x) => x.key)).toEqual(fixed.map((x) => x.key));
  });
});

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
    // ADR 0018 §7's concealed list, extended by ADR 0055 §4, for the types this vault creates.
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
        "ssh.private_key",
        "ssh.passphrase",
        "api.key",
        "api.secret",
        "license.key",
        "wifi.password",
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

// The item list's and the command palette's shared ordering (ItemsPane.tsx, CommandPalette.tsx;
// ROADMAP §4.2/§4.5 "favorites first").
describe("compareFavoriteFirst", () => {
  it("puts every favorite before every non-favorite, regardless of input order", () => {
    const items = [
      { favorite: false, title: "Bravo" },
      { favorite: true, title: "Zulu" },
      { favorite: false, title: "Alpha" },
      { favorite: true, title: "Yankee" },
    ];
    expect(items.sort(compareFavoriteFirst).map((i) => i.title)).toEqual([
      "Yankee",
      "Zulu",
      "Alpha",
      "Bravo",
    ]);
  });

  it("breaks ties within a group by title, case-insensitively", () => {
    const items = [{ favorite: false, title: "bravo" }, { favorite: false, title: "Alpha" }];
    expect(items.sort(compareFavoriteFirst).map((i) => i.title)).toEqual(["Alpha", "bravo"]);
  });

  it("is a no-op on an already-sorted single-item or empty list", () => {
    expect([].sort(compareFavoriteFirst)).toEqual([]);
    expect([{ favorite: true, title: "Solo" }].sort(compareFavoriteFirst)).toEqual([
      { favorite: true, title: "Solo" },
    ]);
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
