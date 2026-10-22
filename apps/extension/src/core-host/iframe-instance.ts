// SPDX-License-Identifier: AGPL-3.0-only

// The per-instance token store for the inline-menu and passkey-consent iframes (ADR 0043). The
// content script mints one token per iframe it builds (`crypto.randomUUID()`, ADR 0043 point 1)
// and registers it here over the already-trusted content-script channel (point 2); the iframe
// receives it only in the targeted `postMessage` show message (point 3) and must send it back
// with every privileged request, which `listener.ts` checks against this store for the
// sender's own `sender.tab.id` (point 4). A clone of `src/inline-menu/index.html` embedded
// anywhere in the tab's frame tree passes `isInlineMenuSender` but is never fed a token, so it
// can never pass this.
//
// Pure and synchronous, with an injected clock, the same shape as `passkey-ceremony.ts`'s
// store (`core-context.ts` is the one real caller, and clears it on lock). Unlike that store,
// this one never mints its own token: the content script does (ADR 0043 point 1), so a token
// arriving here is untrusted input, shape-checked by `validate.ts` before it ever reaches
// `register`, and refused here if it is already taken.
//
// In-flight requests (ADR 0043 point 5; Open question 4, whose recommendation stands): a
// `revoke` refuses every LATER `acquire` at once, but the entry itself is deleted only once
// every request already admitted with that token has settled (`release`). A revoke therefore
// never aborts a click the background has already accepted, and never lets a later one through.

/** The safety-net TTL (ADR 0043 point 2 and Open question 1's recommendation, 30 minutes).
 * Teardown revocation is the normal path; this only bounds a revoke message that never arrived
 * (a crashed tab, a lost message). The value itself is unverified against real usage (U, ADR
 * 0043 Risks). */
export const IFRAME_INSTANCE_TTL_MS = 30 * 60 * 1000;

/** Live registrations one tab may hold at once. A tab normally holds one inline-menu token and
 * at most one passkey-consent token; a rebuild briefly overlaps the old and the new one until the
 * old one's revoke lands. The oldest registration of that same tab is evicted first, so one tab
 * (even one with a compromised content script) never evicts another tab's tokens this way. */
export const MAX_IFRAME_INSTANCES_PER_TAB = 8;

/** Live registrations across every tab. Past this, the registration that expires soonest is
 * evicted, so the store stays bounded however many tabs are open. */
export const MAX_IFRAME_INSTANCES = 512;

interface StoredInstance {
  readonly tabId: number;
  /** Recorded for the store's own bookkeeping only (ADR 0043 point 2): the use-time check is
   * deliberately tab-scoped, `sender.tab.id` alone. */
  readonly trustedOrigin: string;
  readonly expiresAtMs: number;
  revoked: boolean;
  inFlight: number;
}

export interface IframeInstanceStore {
  /** Binds `token` to the registering content script's own browser-vouched `tabId` and
   * `trustedOrigin`. Returns `false`, registering nothing, if the token is already known: a
   * collision or a replayed registration never rebinds or refreshes an existing entry. */
  register(token: string, tabId: number, trustedOrigin: string, nowMs: number): boolean;
  /** The use-time check (ADR 0043 point 4): `true` only for a live, unexpired, unrevoked
   * registration whose tab is exactly `liveTabId`, and then counts one request in flight until
   * {@link IframeInstanceStore.release}. Every `true` must be paired with exactly one
   * `release`. */
  acquire(token: string, liveTabId: number, nowMs: number): boolean;
  /** Ends one request `acquire` admitted, deleting the entry if it was revoked meanwhile and
   * this was the last request in flight. */
  release(token: string): void;
  /** Teardown (ADR 0043 point 5): no later `acquire` succeeds for `token`. Only the tab that
   * registered it can revoke it; a revoke from any other tab is ignored. The entry itself is
   * deleted at once when nothing is in flight, else when the last in-flight request settles. */
  revoke(token: string, tabId: number): void;
  /** Drops every registration (`core-context.ts`'s `lock`): nothing here outlives a lock. */
  clear(): void;
  /** How many entries the store holds, revoked-but-in-flight ones included (for the bound
   * tests). */
  size(): number;
}

export function createIframeInstanceStore(
  ttlMs: number = IFRAME_INSTANCE_TTL_MS,
  maxPerTab: number = MAX_IFRAME_INSTANCES_PER_TAB,
  maxTotal: number = MAX_IFRAME_INSTANCES,
): IframeInstanceStore {
  // Insertion-ordered, so the first entry found for a tab is that tab's oldest registration.
  const entries = new Map<string, StoredInstance>();

  function pruneExpired(nowMs: number): void {
    for (const [token, stored] of entries) {
      if (stored.expiresAtMs < nowMs && stored.inFlight === 0) {
        entries.delete(token);
      }
    }
  }

  function evictOldestOfTab(tabId: number): void {
    for (const [token, stored] of entries) {
      if (stored.tabId === tabId) {
        entries.delete(token);
        return;
      }
    }
  }

  function evictSoonestExpiring(): void {
    let victim: string | undefined;
    let victimExpiry = Number.POSITIVE_INFINITY;
    for (const [token, stored] of entries) {
      if (stored.expiresAtMs < victimExpiry) {
        victim = token;
        victimExpiry = stored.expiresAtMs;
      }
    }
    if (victim !== undefined) {
      entries.delete(victim);
    }
  }

  return {
    register(token, tabId, trustedOrigin, nowMs) {
      pruneExpired(nowMs);
      if (entries.has(token)) {
        return false;
      }
      let ofTab = 0;
      for (const stored of entries.values()) {
        if (stored.tabId === tabId) {
          ofTab += 1;
        }
      }
      if (ofTab >= maxPerTab) {
        evictOldestOfTab(tabId);
      }
      if (entries.size >= maxTotal) {
        evictSoonestExpiring();
      }
      entries.set(token, { tabId, trustedOrigin, expiresAtMs: nowMs + ttlMs, revoked: false, inFlight: 0 });
      return true;
    },
    acquire(token, liveTabId, nowMs) {
      const stored = entries.get(token);
      if (stored === undefined) {
        return false;
      }
      if (stored.expiresAtMs < nowMs) {
        if (stored.inFlight === 0) {
          entries.delete(token);
        }
        return false;
      }
      if (stored.revoked || stored.tabId !== liveTabId) {
        return false;
      }
      stored.inFlight += 1;
      return true;
    },
    release(token) {
      const stored = entries.get(token);
      if (stored === undefined || stored.inFlight === 0) {
        return;
      }
      stored.inFlight -= 1;
      if (stored.inFlight === 0 && stored.revoked) {
        entries.delete(token);
      }
    },
    revoke(token, tabId) {
      const stored = entries.get(token);
      if (stored === undefined || stored.tabId !== tabId) {
        return;
      }
      if (stored.inFlight === 0) {
        entries.delete(token);
        return;
      }
      stored.revoked = true;
    },
    clear() {
      entries.clear();
    },
    size() {
      return entries.size;
    },
  };
}
