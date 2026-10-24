// SPDX-License-Identifier: AGPL-3.0-only

// The Website matching settings' pure helpers (`match-settings.ts`, ADR 0042) and the shape check
// of a settings change crossing to the Worker (`protocol.ts`'s `isSettingsChange`). No DOM in this
// workspace's Vitest; `MatchingPane.tsx` renders from these, and the e2e test drives it.
import type { ItemSummary, MatchDecisionResult } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { readFileSync } from "node:fs";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  ACCOUNT_DEFAULT_OPTIONS,
  GROUP_LABEL_MAX_DOMAINS,
  checkedItems,
  groupLabel,
  groupSummary,
  leadDomain,
  parseGroupDomains,
} from "../src/match-settings.ts";
import { GlobalGroupRow, GroupDomains } from "../src/views/MatchingPane.tsx";
import { MAX_GROUP_DOMAINS, METHODS, isSettingsChange } from "../src/protocol.ts";

function item(id: string, title: string): ItemSummary {
  return {
    id,
    vaultId: "v",
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

/** The committed default site groups (ADR 0080, `data/equivalence/groups.txt`): what the pane
 * will list once the owner signs a list from them. No list ships in this build, so the e2e test
 * cannot show them; these render the pane's rows from the real seed instead. */
function seedGroups(): string[][] {
  const text = readFileSync(new URL("../../../data/equivalence/groups.txt", import.meta.url), "utf8");
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"))
    .map((line) =>
      (line.split("|")[2] ?? "")
        .split(",")
        .map((d) => d.trim())
        .filter((d) => d !== "")
        .sort(),
    );
}

describe("long group labels (ADR 0080)", () => {
  const airbnb = seedGroups().find((g) => g.includes("airbnb.com")) ?? [];

  it("names a short group in full and a long one by its lead domain and a count", () => {
    expect(groupSummary(["apple.com", "icloud.com"])).toEqual({ label: "apple.com, icloud.com", hidden: 0 });
    const three = ["a.example", "b.example", "c.example"];
    expect(three).toHaveLength(GROUP_LABEL_MAX_DOMAINS);
    expect(groupSummary(three).hidden).toBe(0);
    expect(airbnb).toHaveLength(53);
    expect(groupSummary(airbnb)).toEqual({ label: "airbnb.com and 52 more", hidden: 52 });
  });

  it("leads with the brand's .com when most members share its name, else the first domain", () => {
    expect(leadDomain(airbnb)).toBe("airbnb.com");
    expect(leadDomain(["ebay.co.uk", "ebay.com", "ebay.de", "other.example"])).toBe("ebay.com");
    // No shared name, or no .com of it: the first domain, as the list sorts them.
    expect(leadDomain(["bing.com", "live.com", "xbox.com", "msn.com"])).toBe("bing.com");
    expect(leadDomain(["shop.de", "shop.fr", "zz.example", "yy.example"])).toBe("shop.de");
    expect(leadDomain([])).toBe("");
  });

  it("gives every committed default group a distinct label, so every switch has its own name", () => {
    const groups = seedGroups();
    expect(groups).toHaveLength(22);
    const labels = groups.map((g) => groupSummary(g).label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("renders a long group as one line plus a disclosure listing every site", () => {
    const html = renderToStaticMarkup(createElement(GroupDomains, { domains: airbnb }));
    expect(html).toContain("<span>airbnb.com and 52 more</span>");
    expect(html).toMatch(/<details><summary aria-label="All 53 sites in the group airbnb.com and 52 more">/);
    expect(html).not.toMatch(/<details open/);
    expect(html).toContain('aria-label="Sites in the group airbnb.com and 52 more"');
    expect(html.match(/<li>/g)).toHaveLength(53);
    for (const domain of ["airbnb.com", "airbnb.co.uk", "airbnb.de"]) {
      expect(html).toContain(`<li>${domain}</li>`);
    }
  });

  it("renders a short group with no disclosure", () => {
    const html = renderToStaticMarkup(createElement(GroupDomains, { domains: ["apple.com", "icloud.com"] }));
    expect(html).toBe("<span>apple.com, icloud.com</span>");
  });

  it("names each switch after the group's label, on and off", () => {
    const row = (disabled: boolean) =>
      renderToStaticMarkup(
        createElement(GlobalGroupRow, {
          group: { id: "ab", domains: airbnb, disabled },
          busy: false,
          onChange: () => undefined,
        }),
      );
    expect(row(false)).toContain('aria-label="Turn off the group airbnb.com and 52 more"');
    expect(row(true)).toContain('aria-label="Turn on the group airbnb.com and 52 more"');
    expect(row(true)).toContain('class="group-domains muted"');
    expect(row(false)).toContain('class="group-domains"');
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
