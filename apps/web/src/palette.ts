// SPDX-License-Identifier: AGPL-3.0-only

// Pure search/ranking logic for the command palette (Ctrl/Cmd+K; `CommandPalette.tsx`;
// ROADMAP §4.2/§4.5 "quick-access / command palette"). Kept apart from the component so it is
// unit-tested without rendering anything (the project's existing pattern: `ItemsPane.tsx`'s
// `inScope`/`emptyState`, `shortcuts.ts`).
//
// The palette runs only over the `ItemSummary[]` the vault already holds decrypted in memory
// (the same list `ItemsPane` loads): it never sends a query to the server, and the search over
// title/username/website host/tag reuses `fields.ts`'s `matches`, the exact fields the item
// list already searches, so the two never drift apart.
import type { ItemSummary } from "@rizzy-vault/core";

import { compareFavoriteFirst, matches } from "./fields.ts";

/** One command the palette can run against a matched item. `"open"` is always offered; the
 * others only when the item actually carries that data (`actionsFor`). */
export type PaletteItemAction = "open" | "copy-username" | "copy-password" | "copy-totp";

/** One row of the palette's item results: one action against one item. */
export interface PaletteItemRow {
  readonly action: PaletteItemAction;
  readonly item: ItemSummary;
}

/** How many distinct items a search keeps, before each is expanded into its action rows: a
 * large vault searched by one keystroke must not turn into an unbounded DOM and an unbounded
 * `aria-activedescendant` walk. The item list itself has no such cap — this is the palette's
 * own trade-off for a result set meant to be scanned in a glance, not browsed at length. */
export const MAX_PALETTE_ITEMS = 6;

/** The actions `item` offers, in display order: "open" always first, then the copy actions it
 * has real data for.
 *
 * Username and password are offered independently of each other: a username is offered
 * whenever the item carries one (`ItemSummary.username`, any item type — e.g. a Card's
 * cardholder-as-username convention some imports use), while a password is offered for every
 * Login regardless of whether `login.password` was ever actually written. `ItemSummary` does
 * not say whether that field is present — knowing for certain would mean fetching every matched
 * item's full field list on every keystroke — so this is a deliberate, bounded simplification:
 * copying a login with no password set fails the same way the item view's own "Copy" button
 * would (the core's `reveal` rejects with `unknown_item`; `CommandPalette.tsx` shows the error
 * and leaves the palette open, exactly like any other failed action). TOTP is offered exactly
 * when the item itself says it carries one (`ItemSummary.hasTotp`), which the core already
 * tracks precisely. */
export function actionsFor(item: ItemSummary): readonly PaletteItemAction[] {
  const actions: PaletteItemAction[] = ["open"];
  if (item.username !== undefined && item.username !== "") {
    actions.push("copy-username");
  }
  if (item.itemType === "login") {
    actions.push("copy-password");
  }
  if (item.hasTotp) {
    actions.push("copy-totp");
  }
  return actions;
}

/** The label of one action, for its listbox row's visible and accessible name. */
export function actionLabel(action: PaletteItemAction): string {
  switch (action) {
    case "open":
      return "Open";
    case "copy-username":
      return "Copy username";
    case "copy-password":
      return "Copy password";
    case "copy-totp":
      return "Copy TOTP code";
  }
}

/** The item rows a `query` surfaces over `items` (title/username/URL host/tag — `fields.ts`'s
 * `matches`, module docs): favorites first, then title (`compareFavoriteFirst`, the same order
 * the item list itself uses — "favorites first in the palette", ROADMAP §4.2/§4.5), capped to
 * `MAX_PALETTE_ITEMS` distinct items before each is expanded into its action rows
 * (`actionsFor`).
 *
 * A blank `query` surfaces no item rows at all: a fresh command palette shows only its
 * navigation commands (`CommandPalette.tsx`), the same way a code editor's command palette
 * shows commands, not every open file, until the user types something. A trashed item is never
 * surfaced, even if `items` happens to include one (callers load the active, non-trash list, so
 * this is a defensive floor, not the only guard). */
export function itemRowsFor(items: readonly ItemSummary[], query: string): readonly PaletteItemRow[] {
  if (query.trim() === "") {
    return [];
  }
  const ranked = items
    .filter((i) => !i.trashed && matches(i, query))
    .sort(compareFavoriteFirst)
    .slice(0, MAX_PALETTE_ITEMS);
  const rows: PaletteItemRow[] = [];
  for (const item of ranked) {
    for (const action of actionsFor(item)) {
      rows.push({ action, item });
    }
  }
  return rows;
}

/** Whether `label` matches `query` (case-insensitive substring; the same shape as `fields.ts`'s
 * `matches`), for filtering the palette's navigation commands as the user types. A blank query
 * matches every label. */
export function matchesLabel(label: string, query: string): boolean {
  const q = query.trim().toLocaleLowerCase();
  return q === "" || label.toLocaleLowerCase().includes(q);
}
