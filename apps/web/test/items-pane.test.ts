// `ItemsPane`'s pure helpers: the sidebar's item filter (`inScope`, `Scope`) and the empty-state
// text and call-to-action (`emptyState`), including their combination with the existing
// free-text search (`matches`, fields.ts) the way the pane itself applies them (ItemsPane.tsx
// module docs: "the sidebar's item filters ... on top of the free-text search below").
import type { ItemSummary } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { matches } from "../src/fields.ts";
import { type Scope, emptyState, inScope } from "../src/views/ItemsPane.tsx";

function item(over: Partial<ItemSummary>): ItemSummary {
  return {
    id: "1",
    itemType: "login",
    title: "Example",
    username: undefined,
    favorite: false,
    hasTotp: false,
    trashed: false,
    tags: [],
    websiteHost: undefined,
    ...over,
  };
}

describe("inScope", () => {
  it("'all' passes everything", () => {
    expect(inScope(item({}), { kind: "all" })).toBe(true);
    expect(inScope(item({ favorite: true, itemType: "card" }), { kind: "all" })).toBe(true);
  });

  it("'favorites' keeps only favorites", () => {
    expect(inScope(item({ favorite: true }), { kind: "favorites" })).toBe(true);
    expect(inScope(item({ favorite: false }), { kind: "favorites" })).toBe(false);
  });

  it("'type' keeps only that item type", () => {
    const card = item({ itemType: "card" });
    expect(inScope(card, { kind: "type", itemType: "card" })).toBe(true);
    expect(inScope(card, { kind: "type", itemType: "login" })).toBe(false);
  });

  it("'tag' keeps only items carrying that tag", () => {
    const tagged = item({ tags: ["work", "urgent"] });
    expect(inScope(tagged, { kind: "tag", tag: "work" })).toBe(true);
    expect(inScope(tagged, { kind: "tag", tag: "personal" })).toBe(false);
    expect(inScope(item({}), { kind: "tag", tag: "work" })).toBe(false);
  });
});

describe("sidebar filter + search together (what ItemsPane renders)", () => {
  const items: ItemSummary[] = [
    item({ id: "a", title: "Alpha Bank", username: "alice", favorite: true, itemType: "login" }),
    item({ id: "b", title: "Beta Card", username: undefined, favorite: false, itemType: "card" }),
    item({ id: "c", title: "Alpha Note", username: undefined, favorite: false, itemType: "note" }),
  ];

  const shown = (scope: Scope, query: string) =>
    items.filter((i) => inScope(i, scope)).filter((i) => matches(i, query)).map((i) => i.id);

  it("favorites narrows before the search text is applied", () => {
    expect(shown({ kind: "favorites" }, "")).toEqual(["a"]);
    expect(shown({ kind: "favorites" }, "alpha")).toEqual(["a"]);
    expect(shown({ kind: "favorites" }, "beta")).toEqual([]);
  });

  it("a type filter combines with search", () => {
    expect(shown({ kind: "type", itemType: "login" }, "")).toEqual(["a"]);
    expect(shown({ kind: "all" }, "alpha")).toEqual(["a", "c"]);
    expect(shown({ kind: "type", itemType: "note" }, "alpha")).toEqual(["c"]);
    expect(shown({ kind: "type", itemType: "note" }, "beta")).toEqual([]);
  });
});

describe("emptyState", () => {
  it("the trash takes priority over every other message", () => {
    expect(emptyState({ kind: "favorites" }, true, true, true)).toEqual({ text: "The trash is empty." });
  });

  it("an empty vault offers to create a login by default", () => {
    expect(emptyState({ kind: "all" }, false, false, false)).toEqual({ text: "No items yet.", cta: "login" });
  });

  it("an empty vault filtered to a type offers that type", () => {
    expect(emptyState({ kind: "type", itemType: "card" }, false, false, false)).toEqual({
      text: "No items yet.",
      cta: "card",
    });
  });

  it("a vault with items but no favorites explains favorites, with no call to action", () => {
    expect(emptyState({ kind: "favorites" }, false, true, false)).toEqual({
      text: "No favorites yet. Star an item to find it here.",
    });
  });

  it("a vault with items but none of a type offers to create one", () => {
    expect(emptyState({ kind: "type", itemType: "identity" }, false, true, false)).toEqual({
      text: "Nothing of this type yet.",
      cta: "identity",
    });
  });

  it("a non-empty 'all' list with no search match offers no call to action", () => {
    expect(emptyState({ kind: "all" }, false, true, true)).toEqual({ text: "Nothing matches." });
  });

  it("the vault has favorites, but the current scope (not favorites) is empty: still 'nothing of this scope'", () => {
    expect(emptyState({ kind: "type", itemType: "card" }, false, true, false, false)).toEqual({
      text: "Nothing of this type yet.",
      cta: "card",
    });
  });

  it("favorites exist and match nothing in-scope yet (no search): 'no favorites yet', not the vault-empty copy", () => {
    expect(emptyState({ kind: "favorites" }, false, true, false, false)).toEqual({
      text: "No favorites yet. Star an item to find it here.",
    });
  });

  it("favorites exist in-scope but none match the search: says so, not 'no favorites yet'", () => {
    expect(emptyState({ kind: "favorites" }, false, true, true, true)).toEqual({
      text: "No favorites match your search.",
    });
  });

  it("items of this type exist in-scope but none match the search: says so, not 'nothing of this type yet'", () => {
    expect(emptyState({ kind: "type", itemType: "card" }, false, true, true, true)).toEqual({
      text: "Nothing of this type matches your search.",
    });
  });

  it("an 'all' scope with no search match still says 'Nothing matches.' whether or not searching", () => {
    expect(emptyState({ kind: "all" }, false, true, true, true)).toEqual({ text: "Nothing matches." });
  });
});
