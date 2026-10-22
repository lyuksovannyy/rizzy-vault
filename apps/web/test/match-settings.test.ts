// SPDX-License-Identifier: AGPL-3.0-only

// The Website matching settings' pure helpers (`match-settings.ts`, ADR 0042) and the shape check
// of a settings change crossing to the Worker (`protocol.ts`'s `isSettingsChange`). No DOM in this
// workspace's Vitest; `MatchingPane.tsx` renders from these, and the e2e test drives it.
import type { ItemSummary, MatchDecisionResult } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { ACCOUNT_DEFAULT_OPTIONS, checkedItems, groupLabel, parseGroupDomains } from "../src/match-settings.ts";
import { MAX_GROUP_DOMAINS, METHODS, isSettingsChange } from "../src/protocol.ts";

function item(id: string, title: string): ItemSummary {
  return {
    id,
    itemType: "login",
    title,
    username: undefined,
    favorite: false,
    hasTotp: false,
    trashed: false,
    tags: [],
    websiteHost: undefined,
  };
}

function decision(candidates: { itemId: string; needsWarning: boolean }[]): MatchDecisionResult {
  return {
    pageHost: "example.net",
    pagePort: undefined,
    candidates: candidates.map((c) => ({ ...c, uriId: `${c.itemId}-uri`, savedHost: "example.com" })),
    warnings: [],
  };
}

describe("parseGroupDomains", () => {
  it("splits on commas, spaces and new lines and drops empties and exact repeats", () => {
    expect(parseGroupDomains(" example.com,example.net\n\nexample.org  example.com ,")).toEqual([
      "example.com",
      "example.net",
      "example.org",
    ]);
    expect(parseGroupDomains("   ")).toEqual([]);
  });

  it("keeps case and form for the core to normalise and judge", () => {
    expect(parseGroupDomains("Example.COM, co.uk")).toEqual(["Example.COM", "co.uk"]);
  });

  it("stops one past the group bound so the core still refuses an oversized group", () => {
    const many = Array.from({ length: 200 }, (_, i) => `site${i}.example`).join(",");
    expect(parseGroupDomains(many)).toHaveLength(MAX_GROUP_DOMAINS + 1);
  });
});

describe("ACCOUNT_DEFAULT_OPTIONS", () => {
  it("offers every mode but Account default itself, Base domain first", () => {
    expect(ACCOUNT_DEFAULT_OPTIONS.map((o) => o.value)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(ACCOUNT_DEFAULT_OPTIONS[0]?.label).toBe("Base domain");
  });
});

describe("checkedItems", () => {
  it("titles each offered item once, direct over through-a-group", () => {
    const items = [item("a", "Alpha"), item("b", "Beta")];
    expect(
      checkedItems(
        decision([
          { itemId: "a", needsWarning: true },
          { itemId: "a", needsWarning: false },
          { itemId: "b", needsWarning: true },
          { itemId: "gone", needsWarning: false },
        ]),
        items,
      ),
    ).toEqual([
      { id: "a", title: "Alpha", viaGroup: false, savedHost: "example.com" },
      { id: "b", title: "Beta", viaGroup: true, savedHost: "example.com" },
    ]);
    expect(checkedItems(decision([]), items)).toEqual([]);
  });

  it("labels a group by its domains", () => {
    expect(groupLabel(["example.com", "example.net"])).toBe("example.com, example.net");
  });
});

describe("isSettingsChange", () => {
  it("accepts each change kind", () => {
    expect(isSettingsChange({ kind: "matchDefault", mode: 2 })).toBe(true);
    expect(isSettingsChange({ kind: "addUserGroup", domains: ["example.com", "example.net"] })).toBe(true);
    expect(isSettingsChange({ kind: "removeUserGroup", id: "ab" })).toBe(true);
    expect(isSettingsChange({ kind: "disableGlobalGroup", id: "ab" })).toBe(true);
    expect(isSettingsChange({ kind: "enableGlobalGroup", id: "ab" })).toBe(true);
  });

  it("refuses anything else", () => {
    expect(isSettingsChange(null)).toBe(false);
    expect(isSettingsChange("matchDefault")).toBe(false);
    expect(isSettingsChange({ kind: "matchDefault", mode: "2" })).toBe(false);
    expect(isSettingsChange({ kind: "matchDefault", mode: 1.5 })).toBe(false);
    expect(isSettingsChange({ kind: "addUserGroup", domains: "example.com" })).toBe(false);
    expect(isSettingsChange({ kind: "addUserGroup", domains: [1, 2] })).toBe(false);
    expect(
      isSettingsChange({ kind: "addUserGroup", domains: Array.from({ length: MAX_GROUP_DOMAINS + 1 }, () => "a.example") }),
    ).toBe(false);
    expect(isSettingsChange({ kind: "removeUserGroup", id: 5 })).toBe(false);
    expect(isSettingsChange({ kind: "dropEverything" })).toBe(false);
  });

  it("the Worker serves the three settings calls", () => {
    for (const m of ["matchSettings", "matchCandidates", "changeMatchSettings"]) {
      expect(METHODS).toContain(m);
    }
  });
});
