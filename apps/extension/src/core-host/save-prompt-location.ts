// The save-prompt-by-location index (ROADMAP §4.4 "save/update on submit"; the fix for the
// save-prompt race `apps/extension/README.md`'s residual note describes). Pure and
// synchronous — no session, no wasm, no `crypto.randomUUID` of its own — so it is
// unit-testable directly, the same way `core-host/content-handler.ts`'s `selectFillCandidate`
// is: `core-context.ts` is the one caller, supplying the real clock, the real registrable
// domain (`@rizzy-vault/core`'s `registrableDomainOf`, never reimplemented here — ADR 0037 §1
// keeps every PSL-aware decision in one place) and the real token.
//
// A login form's `submit` handler sends `credentials_submitted` and the content script renders
// the save/update banner from that call's own response, but when the page navigates away right
// after submitting — the common case for a real login form — the document, and the pending
// microtask holding that response, are torn down before the banner can ever render, and the
// offer is lost with it. This index lets a *later* page load of the same tab and registrable
// domain (`check_save_prompt`, sent unconditionally on every content-script load) find the
// still-live offer and show the prompt there instead.
//
// This module never holds credentials, only a token reference into `core-context.ts`'s own
// `pendingSavePrompts` map: "credentials in the pending offer stay in the long-lived context
// only" (ROADMAP §4.4) is true of this index by construction, not by convention.

interface Entry {
  readonly token: string;
  readonly expiresAtMs: number;
}

export interface SavePromptLocationIndex {
  /** Indexes `token` by `tabId`/`registrableDomain`, expiring `ttlMs` after `nowMs`. A no-op
   * when either `tabId` or `registrableDomain` is `undefined` (module docs on why each can be:
   * some senders carry no tab id, some pages have no registrable domain) — the offer's
   * immediate, same-page token path still works either way; only this recovery path is
   * unavailable for that one offer. */
  remember(tabId: number | undefined, registrableDomain: string | undefined, token: string, nowMs: number): void;
  /** The token indexed for `tabId`/`registrableDomain`, if any and not yet expired at `nowMs`.
   * Single-use regardless of outcome (found, not found, or expired): the entry is always
   * removed before this returns, so a later call for the same tab and domain within the TTL
   * never replays an already-delivered offer a second time. */
  take(tabId: number | undefined, registrableDomain: string | undefined, nowMs: number): string | undefined;
  /** Drops every entry (`core-context.ts`'s `lock`): the index outlives nothing past a lock,
   * same as the credentials it only ever points at. */
  clear(): void;
}

function key(tabId: number, registrableDomain: string): string {
  return `${tabId}::${registrableDomain}`;
}

export function createSavePromptLocationIndex(ttlMs: number): SavePromptLocationIndex {
  const entries = new Map<string, Entry>();
  return {
    remember(tabId, registrableDomain, token, nowMs) {
      if (tabId === undefined || registrableDomain === undefined) {
        return;
      }
      entries.set(key(tabId, registrableDomain), { token, expiresAtMs: nowMs + ttlMs });
    },
    take(tabId, registrableDomain, nowMs) {
      if (tabId === undefined || registrableDomain === undefined) {
        return undefined;
      }
      const k = key(tabId, registrableDomain);
      const entry = entries.get(k);
      entries.delete(k);
      if (entry === undefined || entry.expiresAtMs < nowMs) {
        return undefined;
      }
      return entry.token;
    },
    clear() {
      entries.clear();
    },
  };
}
