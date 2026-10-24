// SPDX-License-Identifier: AGPL-3.0-only

// Pure helpers of the Website matching settings (ADR 0037 §6–§7, ADR 0042; `MatchingPane.tsx`):
// reading the domains a user typed for a new equivalence group, the account-default choices,
// and what a "check a website" decision shows. Every rule that matters (normalisation, the
// public-suffix refusal, the limits) is the core's; these only shape input and output.
import type { ItemSummary, MatchDecisionResult } from "@rizzy-vault/core";

import { MATCH_MODE_OPTIONS } from "./fields.ts";
import { MAX_GROUP_DOMAINS } from "./protocol.ts";

/** The modes an account default can be: every URI mode but "Account default" itself. */
export const ACCOUNT_DEFAULT_OPTIONS = MATCH_MODE_OPTIONS.filter((o) => o.value !== 0x0000);

/** The domains typed for a new group: split on commas, spaces and new lines, empty entries
 * dropped, exact repeats dropped (the core still refuses two that normalise the same, like
 * `Example.com` and `example.com`). At most one more than {@link MAX_GROUP_DOMAINS} is kept,
 * so an oversized group still reaches the core's own refusal without building a huge message. */
export function parseGroupDomains(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/[\s,]+/u)) {
    const domain = part.trim();
    if (domain !== "" && !out.includes(domain)) {
      out.push(domain);
      if (out.length > MAX_GROUP_DOMAINS) {
        break;
      }
    }
  }
  return out;
}

/** One group as a line of text. */
export function groupLabel(domains: readonly string[]): string {
  return domains.join(", ");
}

/** Groups up to this many domains are named in full; a longer one is summarised (ADR 0080
 * "Negative": a 53-domain group needs a summarised label and a disclosure). */
export const GROUP_LABEL_MAX_DOMAINS = 3;

/** The domain a long group is named after: the `.com` of its most common first label when that
 * label is shared by two or more members (`airbnb.com` for Airbnb's 53 country sites), else
 * its first domain. Display only: matching never depends on it. */
export function leadDomain(domains: readonly string[]): string {
  const counts = new Map<string, number>();
  for (const domain of domains) {
    const label = domain.split(".")[0] ?? domain;
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  let best: string | undefined;
  let bestCount = 1;
  for (const [label, count] of counts) {
    if (count > bestCount) {
      best = label;
      bestCount = count;
    }
  }
  const brandCom = best === undefined ? undefined : `${best}.com`;
  if (brandCom !== undefined && domains.includes(brandCom)) {
    return brandCom;
  }
  return domains[0] ?? "";
}

/** A group's label: every domain for a short group, or "<lead> and <n> more" for a longer one,
 * with `hidden` the number of domains the label leaves out (shown by the disclosure). */
export function groupSummary(domains: readonly string[]): { readonly label: string; readonly hidden: number } {
  if (domains.length <= GROUP_LABEL_MAX_DOMAINS) {
    return { label: groupLabel(domains), hidden: 0 };
  }
  const hidden = domains.length - 1;
  return { label: `${leadDomain(domains)} and ${hidden} more`, hidden };
}

/** One row of a "check a website" answer. */
export interface CheckedItem {
  readonly id: string;
  readonly title: string;
  /** Offered only through an equivalence group: the extension warns before such a fill. */
  readonly viaGroup: boolean;
  /** The saved website's own host. */
  readonly savedHost: string;
}

/** The items a decision offers, once each, titled from `items` (a candidate whose item is not
 * listed is left out); an item offered both directly and through a group counts as direct. */
export function checkedItems(
  decision: MatchDecisionResult,
  items: readonly ItemSummary[],
): CheckedItem[] {
  const out = new Map<string, CheckedItem>();
  for (const c of decision.candidates) {
    const item = items.find((i) => i.id === c.itemId);
    if (item === undefined) {
      continue;
    }
    const held = out.get(c.itemId);
    if (held === undefined || (held.viaGroup && !c.needsWarning)) {
      out.set(c.itemId, { id: c.itemId, title: item.title, viaGroup: c.needsWarning, savedHost: c.savedHost });
    }
  }
  return [...out.values()];
}
