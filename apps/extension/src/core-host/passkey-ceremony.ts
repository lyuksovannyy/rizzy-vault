// SPDX-License-Identifier: AGPL-3.0-only

// The passkey consent ceremony's pending-request store (ADR 0039 §2; ADR 0040's pattern applied
// to passkeys instead of a fill). Pure and synchronous — no session, no wasm, no
// `crypto.randomUUID` of its own — unit-testable the same way `save-prompt-location.ts` and
// `content-handler.ts`'s `selectFillCandidate` already are. `core-context.ts` is the one real
// caller, supplying the real clock and the real token.
//
// Why a navigation cancels a pending ceremony, unlike a save-prompt offer (task instructions;
// contrast `save-prompt-location.ts`'s module docs, which exist *precisely* to survive a
// navigation): a save prompt's values are the user's own, already-submitted form data — a stale
// offer surviving a page load costs nothing more than "show it again, since nothing secret is
// at stake yet, and the one credential it would save is usually the same one that just
// originated the offer." A passkey consent ceremony's *approval* either creates a brand-new
// credential or signs with an existing one; honoring an approval click whose binding has since
// moved to a different page (a different origin, a different `rpId` story) would be approving
// something the user never actually saw when they clicked. `boundTo` below is exactly the
// request-time binding — `tabId` plus the origin derived from `sender.tab.url` at request
// time — and `checkBinding` re-derives that same origin from the *live* `sender.tab.url` the
// approval message's own sender carries (never a cached value), the same "never trust a cached
// candidate list" rule `content-handler.ts`'s `handleInlineMenuFillRequest` already applies to
// fill requests. A real cross-document navigation already tears down the consent iframe's own
// JS execution context before it could ever send an approval (it is appended into the page's
// own DOM, exactly like `InlineMenu`); this check also catches the narrower case of a
// same-document navigation that changes the tab's top-level origin without destroying the
// iframe synchronously (e.g. `window.location = otherOrigin` mid-flight) — belt and suspenders,
// not the only thing standing between a page and a stale approval.

export type PasskeyCeremonyKind = "create" | "get";

export interface PasskeyCreateCeremony {
  readonly kind: "create";
  readonly origin: string;
  readonly rpId: string;
  readonly rpName: string;
  readonly userIdB64: string;
  readonly userName: string;
  readonly userDisplayName: string;
  readonly challengeB64: string;
  /** ADR 0110 §5: the page's relayed `userVerification`, handed raw to Rust at signing. */
  readonly userVerification?: string;
}

export interface PasskeyGetCandidate {
  /** `${itemId}:${elementId}` — the one opaque reference the consent UI and the approval message
   * carry for "which stored passkey," never the credential id or any other secret-adjacent byte
   * string (`core-context.ts`'s own doc on why `passkeyRef` exists at all). */
  readonly passkeyRef: string;
  readonly itemTitle: string;
  readonly userName: string;
}

export interface PasskeyGetCeremony {
  readonly kind: "get";
  readonly origin: string;
  readonly rpId: string;
  readonly challengeB64: string;
  readonly candidates: readonly PasskeyGetCandidate[];
  /** ADR 0110 §5, as for {@link PasskeyCreateCeremony}. */
  readonly userVerification?: string;
}

export type PasskeyCeremonyRequest = PasskeyCreateCeremony | PasskeyGetCeremony;

/** The user's choice from the approval click (ADR 0110 §7 point 2), kept with a ceremony that
 * waits for verification so the popup never chooses anything: the passkey of a sign-in, the vault
 * of a registration. */
export interface PasskeyCeremonyChoice {
  readonly passkeyRef?: string;
  readonly vaultId?: string;
}

/** A ceremony in `awaiting_verification` (ADR 0110 §7 point 2). */
export interface AwaitingCeremony {
  readonly ceremonyToken: string;
  readonly request: PasskeyCeremonyRequest;
  readonly tabId: number;
  readonly boundOrigin: string;
  readonly choice: PasskeyCeremonyChoice;
  readonly uvAttempts: number;
}

/** ADR 0110 §7 point 4.4: the wrong master passwords one waiting ceremony allows. */
export const UV_MAX_ATTEMPTS = 5;

interface StoredCeremony {
  readonly request: PasskeyCeremonyRequest;
  readonly tabId: number;
  readonly boundOrigin: string;
  /** Counted from creation; moving to `awaiting_verification` does not extend it (§7 point 2). */
  readonly expiresAtMs: number;
  state: "pending" | "awaiting_verification";
  choice: PasskeyCeremonyChoice;
  uvAttempts: number;
}

export interface PasskeyCeremonyStore {
  /** Registers a new pending ceremony, returning its token. `tabId`/`boundOrigin` are the
   * browser-vouched sender info at request time (`core-context.ts` never accepts a caller-chosen
   * token or binding). */
  create(request: PasskeyCeremonyRequest, tabId: number, boundOrigin: string, nowMs: number): string;
  /** Looks the ceremony up and immediately removes it (single-use regardless of outcome, same as
   * `save-prompt-location.ts`'s `take`): an approval or decline can only ever be acted on once,
   * so a duplicate or replayed message for the same token always sees "not found" the second
   * time. Returns `undefined` for an unknown token, an expired one, or one that fails
   * {@link checkBinding} against the approval's own live sender info. */
  take(token: string, liveTabId: number, liveOrigin: string, nowMs: number): PasskeyCeremonyRequest | undefined;
  /** ADR 0110 §7 point 2: the approval's non-destructive look-up, with {@link take}'s expiry and
   * binding checks. Only a `pending` ceremony is returned and kept; an expired one, or one whose
   * binding no longer matches (a navigation), is dropped as {@link take} would, and an
   * `awaiting_verification` one is neither returned nor touched. The caller deletes the record
   * ({@link remove}) once the ceremony produced a result, so it stays single use. */
  peek(token: string, liveTabId: number, liveOrigin: string, nowMs: number): PasskeyCeremonyRequest | undefined;
  /** Drops one ceremony, in any state. */
  remove(token: string): void;
  /** Whether `token` is an unexpired ceremony in `awaiting_verification`. */
  isAwaiting(token: string, nowMs: number): boolean;
  /** ADR 0110 §7 point 2: moves an unexpired `pending` ceremony to `awaiting_verification` with
   * `uvAttempts = 0` and `choice`, same token, binding and expiry. §7 point 7: an older ceremony
   * of the same tab already waiting is dropped, and its token returned so the caller declines it.
   * `undefined` when `token` is not an unexpired `pending` ceremony. */
  awaitVerification(token: string, choice: PasskeyCeremonyChoice, nowMs: number): { readonly declined: readonly string[] } | undefined;
  /** The unexpired ceremony `token` in `awaiting_verification`, if any. */
  awaiting(token: string, nowMs: number): AwaitingCeremony | undefined;
  /** The one unexpired ceremony of `tabId` in `awaiting_verification` (§7 point 7), if any. */
  awaitingForTab(tabId: number, nowMs: number): AwaitingCeremony | undefined;
  /** Counts one wrong master password for a waiting ceremony; returns the new count (0 when the
   * ceremony is not waiting any more). */
  recordFailedVerification(token: string): number;
  /** Drops every expired ceremony; returns the tabs of those that were waiting for verification,
   * whose badge the caller clears. */
  sweep(nowMs: number): readonly number[];
  /** The tabs with a ceremony waiting for verification, expired or not (lock clears their badge). */
  awaitingTabs(): readonly number[];
  /** Drops every pending ceremony (`core-context.ts`'s `lock`): nothing here outlives a lock,
   * same as `pendingSavePrompts`. */
  clear(): void;
}

/** `core-context.ts`'s TTL for a pending ceremony — generous enough for a real user to read the
 * consent prompt and click, short enough that an abandoned tab does not accumulate state
 * forever. This module's own choice (not independently verified against a UX standard, "U"). */
export const PASSKEY_CEREMONY_TTL_MS = 2 * 60 * 1000;

function checkBinding(stored: StoredCeremony, liveTabId: number, liveOrigin: string): boolean {
  return stored.tabId === liveTabId && stored.boundOrigin === liveOrigin;
}

export function createPasskeyCeremonyStore(ttlMs: number = PASSKEY_CEREMONY_TTL_MS): PasskeyCeremonyStore {
  const entries = new Map<string, StoredCeremony>();
  return {
    create(request, tabId, boundOrigin, nowMs) {
      const token = crypto.randomUUID();
      entries.set(token, { request, tabId, boundOrigin, expiresAtMs: nowMs + ttlMs, state: "pending", choice: {}, uvAttempts: 0 });
      return token;
    },
    peek(token, liveTabId, liveOrigin, nowMs) {
      const stored = entries.get(token);
      if (stored === undefined || stored.state !== "pending") {
        return undefined;
      }
      if (stored.expiresAtMs < nowMs || !checkBinding(stored, liveTabId, liveOrigin)) {
        entries.delete(token);
        return undefined;
      }
      return stored.request;
    },
    remove(token) {
      entries.delete(token);
    },
    isAwaiting(token, nowMs) {
      const stored = entries.get(token);
      return stored !== undefined && stored.state === "awaiting_verification" && stored.expiresAtMs >= nowMs;
    },
    awaitVerification(token, choice, nowMs) {
      const stored = entries.get(token);
      if (stored === undefined || stored.state !== "pending" || stored.expiresAtMs < nowMs) {
        return undefined;
      }
      const declined: string[] = [];
      for (const [other, entry] of entries) {
        if (other !== token && entry.tabId === stored.tabId && entry.state === "awaiting_verification") {
          entries.delete(other);
          declined.push(other);
        }
      }
      stored.state = "awaiting_verification";
      stored.choice = { ...choice };
      stored.uvAttempts = 0;
      return { declined };
    },
    awaiting(token, nowMs) {
      const stored = entries.get(token);
      if (stored === undefined || stored.state !== "awaiting_verification") {
        return undefined;
      }
      if (stored.expiresAtMs < nowMs) {
        entries.delete(token);
        return undefined;
      }
      return awaitingView(token, stored);
    },
    awaitingForTab(tabId, nowMs) {
      for (const [token, stored] of entries) {
        if (stored.tabId === tabId && stored.state === "awaiting_verification" && stored.expiresAtMs >= nowMs) {
          return awaitingView(token, stored);
        }
      }
      return undefined;
    },
    recordFailedVerification(token) {
      const stored = entries.get(token);
      if (stored === undefined || stored.state !== "awaiting_verification") {
        return 0;
      }
      stored.uvAttempts += 1;
      return stored.uvAttempts;
    },
    sweep(nowMs) {
      const tabs: number[] = [];
      for (const [token, stored] of entries) {
        if (stored.expiresAtMs < nowMs) {
          entries.delete(token);
          if (stored.state === "awaiting_verification") {
            tabs.push(stored.tabId);
          }
        }
      }
      return tabs;
    },
    awaitingTabs() {
      return [...entries.values()].filter((e) => e.state === "awaiting_verification").map((e) => e.tabId);
    },
    take(token, liveTabId, liveOrigin, nowMs) {
      const stored = entries.get(token);
      entries.delete(token);
      if (stored === undefined || stored.expiresAtMs < nowMs) {
        return undefined;
      }
      if (!checkBinding(stored, liveTabId, liveOrigin)) {
        return undefined;
      }
      return stored.request;
    },
    clear() {
      entries.clear();
    },
  };
}

function awaitingView(ceremonyToken: string, stored: StoredCeremony): AwaitingCeremony {
  return {
    ceremonyToken,
    request: stored.request,
    tabId: stored.tabId,
    boundOrigin: stored.boundOrigin,
    choice: stored.choice,
    uvAttempts: stored.uvAttempts,
  };
}

/**
 * Whether `candidate` is one of `ceremony`'s own offered candidates (`get` only) — re-checked at
 * approval time against the ceremony this token actually stored, never trusted outright from the
 * consent UI's own click (the same "re-check server-side" rule `content-handler.ts`'s
 * `selectFillCandidate` already applies to the inline menu's equivalence confirmation).
 */
export function isOfferedCandidate(ceremony: PasskeyGetCeremony, passkeyRef: string): boolean {
  return ceremony.candidates.some((c) => c.passkeyRef === passkeyRef);
}
