// SPDX-License-Identifier: AGPL-3.0-only

// `palette.ts`'s pure ranking logic for the command palette (Ctrl/Cmd+K, ROADMAP §4.2/§4.5): no
// DOM in this workspace's Vitest (module docs of `@rizzy-vault/ui`'s `Toast.tsx`), so this tests
// the plain functions `CommandPalette.tsx` renders from.
import type { ItemSummary } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { MAX_PALETTE_ITEMS, actionLabel, actionsFor, itemRowsFor, matchesLabel } from "../src/palette.ts";

function item(over: Partial<ItemSummary>): ItemSummary {
  return {
    id: "1",
    vaultId: "v",
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

describe("actionsFor", () => {
  it("a login with a username and a TOTP offers every action, open first", () => {
    expect(actionsFor(item({ itemType: "login", username: "alice", hasTotp: true }))).toEqual([
      "open",
      "copy-username",
      "copy-password",
      "copy-totp",
    ]);
  });

  it("a login with no username and no TOTP still offers to copy the password", () => {
    expect(actionsFor(item({ itemType: "login", username: undefined, hasTotp: false }))).toEqual([
      "open",
      "copy-password",
    ]);
  });

  it("an empty-string username is the same as no username (ADR 0018 §6 'absent')", () => {
    expect(actionsFor(item({ itemType: "login", username: "" }))).toEqual(["open", "copy-password"]);
  });

  it("a non-login with a username offers to copy it, but never a password", () => {
    expect(actionsFor(item({ itemType: "card", username: "alice" }))).toEqual(["open", "copy-username"]);
  });

  it("a secure note with nothing else offers only 'open'", () => {
    expect(actionsFor(item({ itemType: "note", username: undefined, hasTotp: false }))).toEqual(["open"]);
  });

  it("hasTotp alone (no username, not a login) still offers to copy the TOTP code", () => {
    expect(actionsFor(item({ itemType: "card", username: undefined, hasTotp: true }))).toEqual([
      "open",
      "copy-totp",
    ]);
  });
});

describe("actionLabel", () => {
  it("has a distinct, human label for every action", () => {
    expect(actionLabel("open")).toBe("Open");
    expect(actionLabel("copy-username")).toBe("Copy username");
    expect(actionLabel("copy-password")).toBe("Copy password");
    expect(actionLabel("copy-totp")).toBe("Copy TOTP code");
  });
});

describe("itemRowsFor", () => {
  const items: ItemSummary[] = [
    item({ id: "a", title: "Alpha Bank", username: "alice", favorite: false, itemType: "login" }),
    item({
      id: "b",
      title: "Zeta Bank",
      username: undefined,
      favorite: true,
      itemType: "login",
      websiteHost: "zeta.example",
    }),
    item({ id: "c", title: "Beta Card", username: undefined, favorite: false, itemType: "card", tags: ["work"] }),
    item({ id: "d", title: "Alpha Note", username: undefined, favorite: false, itemType: "note" }),
    item({ id: "e", title: "Trashed Bank", username: undefined, favorite: true, itemType: "login", trashed: true }),
  ];

  it("an empty or blank query surfaces no item rows — the palette shows only navigation then", () => {
    expect(itemRowsFor(items, "")).toEqual([]);
    expect(itemRowsFor(items, "   ")).toEqual([]);
  });

  /** The distinct items `itemRowsFor` surfaces, in order, dropping the per-action duplicates —
   * isolates the search-matching behaviour from the row-expansion behaviour the tests below
   * check separately. */
  const matchedIds = (query: string) => [...new Set(itemRowsFor(items, query).map((r) => r.item.id))];

  it("searches title, username, website host and tag, case-insensitively — the same fields as the item list", () => {
    expect(matchedIds("bank")).toEqual(["b", "a"]);
    expect(matchedIds("ALICE")).toEqual(["a"]);
    expect(matchedIds("zeta.example")).toEqual(["b"]);
    expect(matchedIds("work")).toEqual(["c"]);
    expect(itemRowsFor(items, "nonexistent")).toEqual([]);
  });

  it("never surfaces a trashed item, even if its text matches", () => {
    expect(itemRowsFor(items, "Trashed")).toEqual([]);
  });

  it("ranks matched items favorites-first, then title, before expanding each into its action rows", () => {
    const rows = itemRowsFor(items, "bank");
    // "Zeta Bank" (favorite; login, no username, no TOTP: open + copy-password) before
    // "Alpha Bank" (not; login with a username: open + copy-username + copy-password).
    expect(rows).toEqual([
      { action: "open", item: items[1] },
      { action: "copy-password", item: items[1] },
      { action: "open", item: items[0] },
      { action: "copy-username", item: items[0] },
      { action: "copy-password", item: items[0] },
    ]);
  });

  it("expands each matched item into one row per action it offers, in actionsFor's order", () => {
    const rows = itemRowsFor(items, "Alpha");
    // "Alpha Bank" (login, has a username) then "Alpha Note" (nothing extra), title order among
    // non-favorites.
    expect(rows).toEqual([
      { action: "open", item: items[0] },
      { action: "copy-username", item: items[0] },
      { action: "copy-password", item: items[0] },
      { action: "open", item: items[3] },
    ]);
  });

  it("caps the number of distinct items before expanding, even when more match", () => {
    const many: ItemSummary[] = Array.from({ length: MAX_PALETTE_ITEMS + 5 }, (_, i) =>
      item({ id: `m${i}`, title: `Match ${i}`, itemType: "note" }),
    );
    const rows = itemRowsFor(many, "Match");
    const distinctIds = new Set(rows.map((r) => r.item.id));
    expect(distinctIds.size).toBe(MAX_PALETTE_ITEMS);
  });
});

describe("matchesLabel", () => {
  it("is case-insensitive substring matching, like the item search", () => {
    expect(matchesLabel("Favorites", "favor")).toBe(true);
    expect(matchesLabel("Favorites", "FAVOR")).toBe(true);
    expect(matchesLabel("Favorites", "zzz")).toBe(false);
  });

  it("an empty or blank query matches every label", () => {
    expect(matchesLabel("Trash", "")).toBe(true);
    expect(matchesLabel("Trash", "  ")).toBe(true);
  });
});
