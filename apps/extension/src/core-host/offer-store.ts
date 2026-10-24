// SPDX-License-Identifier: AGPL-3.0-only

// The inline-menu offer records (ADR 0076 §4.1 step 3, §4.2), in the long-lived context's memory
// only. An offer is what one inline menu disclosed before the user clicked: per candidate, the
// custom fields (by token and the element id `rizzy-client` resolved) and whether a TOTP code
// fills. A fill request that names an offer takes its scope from the record here, never from the
// message:
//
// - an offer lives at most 120 s and is used once;
// - it belongs to one tab and one page URL (a tab that navigated no longer matches: "dropped
//   when the tab navigates");
// - a tab holds at most 4 open offers (the oldest is dropped);
// - `clear()` drops every offer on lock.
//
// Pure apart from the injected random source and clock, so it is unit tested in Node
// (`test/offer-store.test.ts`).
import type { FillOnly, FillScope } from "../messaging/contract.ts";

/** ADR 0076 §4.1: an offer lives at most 120 s. */
export const OFFER_TTL_MS = 120_000;
/** ADR 0076 §4.1: a tab has at most 4 open offers. */
export const MAX_OFFERS_PER_TAB = 4;

/** What one candidate of an offer fills besides username and password. */
export interface OfferedItem {
  readonly fillsTotp: boolean;
  /** The custom tokens disclosed for this item, each with the element id resolved for it. */
  readonly custom: readonly { readonly token: string; readonly element: string }[];
}

/** One offer record. */
export interface OfferRecord {
  readonly tabId: number;
  readonly pageUrl: string;
  readonly scope: FillScope;
  readonly items: ReadonlyMap<string, OfferedItem>;
  readonly createdMs: number;
}

/** Why a fill request's offer is refused (ADR 0076 §4.2). */
export type OfferRefusal = "missing" | "expired" | "other_tab" | "navigated" | "not_offered" | "only_mismatch";

export interface OfferStore {
  /** Records an offer and returns its id (16 random bytes, lowercase hex). */
  create(record: Omit<OfferRecord, "createdMs">): string;
  /** Takes the offer for a fill: refuses a missing, expired, used, other-tab, navigated offer,
   * one that does not hold `itemId`, or whose `only` differs from the request's. Any take that
   * finds the offer uses it up, refused or not. */
  take(offerId: string, tabId: number, pageUrl: string, itemId: string, only: FillOnly | undefined): OfferRecord | OfferRefusal;
  /** Drops every offer (lock). */
  clear(): void;
  /** Open offers, for tests. */
  size(): number;
}

/** A store over `randomBytes` (fills a 16-byte array) and `now` (ms). */
export function createOfferStore(randomBytes: (out: Uint8Array<ArrayBuffer>) => void, now: () => number): OfferStore {
  const offers = new Map<string, OfferRecord>();
  const sweep = () => {
    const t = now();
    for (const [id, record] of offers) {
      if (t - record.createdMs > OFFER_TTL_MS) {
        offers.delete(id);
      }
    }
  };
  return {
    create(record) {
      sweep();
      const bytes = new Uint8Array(16);
      randomBytes(bytes);
      const id = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
      const ofTab = [...offers].filter(([, r]) => r.tabId === record.tabId);
      while (ofTab.length >= MAX_OFFERS_PER_TAB) {
        const oldest = ofTab.shift();
        if (oldest !== undefined) {
          offers.delete(oldest[0]);
        }
      }
      offers.set(id, { ...record, createdMs: now() });
      return id;
    },
    take(offerId, tabId, pageUrl, itemId, only) {
      const record = offers.get(offerId);
      if (record === undefined) {
        return "missing";
      }
      offers.delete(offerId);
      if (now() - record.createdMs > OFFER_TTL_MS) {
        return "expired";
      }
      if (record.tabId !== tabId) {
        return "other_tab";
      }
      if (record.pageUrl !== pageUrl) {
        return "navigated";
      }
      if (!record.items.has(itemId)) {
        return "not_offered";
      }
      if (record.scope.only !== only) {
        return "only_mismatch";
      }
      return record;
    },
    clear() {
      offers.clear();
    },
    size() {
      sweep();
      return offers.size;
    },
  };
}
