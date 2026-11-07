// SPDX-License-Identifier: AGPL-3.0-only

// The toolbar popup's master-password re-verification of a passkey ceremony (ADR 0110 §7 points
// 3–5, 7; §8). Pure orchestration over injected parts (the ceremony store, the session, the
// clock, the tab's live URL, the signing call, the delivery to the tab and the badge), so the
// rules are unit-testable without a wasm core or a browser; `core-context.ts` supplies the real
// ones. The master password reaches `DurableSession.reverify` and nothing else: it is never kept,
// compared, logged or echoed (the reply is one of six fixed codes, §7 point 6).
import type { PasskeyResultPayload, PasskeyVerificationView, UvReplyCode } from "../messaging/contract.ts";
import { type AwaitingCeremony, type PasskeyCeremonyStore, UV_MAX_ATTEMPTS } from "./passkey-ceremony.ts";

/** The part of the unlocked session a verification uses (`DurableSession.reverify`). */
export interface ReverifyingSession {
  reverify(password: string, nowMs?: number): void;
}

export interface PasskeyVerifyDeps {
  readonly store: PasskeyCeremonyStore;
  readonly now: () => number;
  /** The unlocked session, or `undefined` while locked. */
  readonly session: () => ReverifyingSession | undefined;
  /** The live URL of `tabId`, or `undefined` when it is gone or unreadable. */
  readonly liveTabUrl: (tabId: number) => Promise<string | undefined>;
  /** §6's signing call for a verified ceremony, at `nowMs` (the verification's own `now`, so
   * it signs with `UV=1`), with the choice stored at the approval click. `undefined` for no
   * result. */
  readonly sign: (ceremony: AwaitingCeremony, nowMs: number) => Promise<PasskeyResultPayload | undefined>;
  /** Delivers `result` to the tab exactly as an approval does; `undefined` is the decline (the
   * page gets the browser's own authenticator). */
  readonly deliver: (tabId: number, ceremonyToken: string, result: PasskeyResultPayload | undefined) => Promise<void>;
  /** Clears the toolbar badge of `tabId`. */
  readonly clearBadge: (tabId: number) => Promise<void>;
}

/** §7 point 3: what the popup shows for its active tab, or `undefined` (none, or locked). */
export function pendingVerification(deps: PasskeyVerifyDeps, tabId: number): PasskeyVerificationView | undefined {
  if (deps.session() === undefined) {
    return undefined;
  }
  const ceremony = deps.store.awaitingForTab(tabId, deps.now());
  if (ceremony === undefined) {
    return undefined;
  }
  const { request } = ceremony;
  const userName =
    request.kind === "create"
      ? request.userName
      : (request.candidates.find((c) => c.passkeyRef === ceremony.choice.passkeyRef)?.userName ?? "");
  return { ceremonyToken: ceremony.ceremonyToken, origin: ceremony.boundOrigin, rpId: request.rpId, userName, kind: request.kind };
}

function originOf(url: string | undefined): string | undefined {
  if (url === undefined) {
    return undefined;
  }
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

/** Declines a waiting ceremony: drops it, gives the page the browser's own authenticator, and
 * clears the badge. */
async function decline(deps: PasskeyVerifyDeps, ceremony: AwaitingCeremony): Promise<void> {
  deps.store.remove(ceremony.ceremonyToken);
  await deps.deliver(ceremony.tabId, ceremony.ceremonyToken, undefined);
  await deps.clearBadge(ceremony.tabId);
}

/** §7 point 4, in its order: look-up, the live binding, the password, then the signature. */
export async function submitVerification(deps: PasskeyVerifyDeps, ceremonyToken: string, password: string): Promise<UvReplyCode> {
  if (deps.session() === undefined) {
    return "uv_locked";
  }
  const now = deps.now();
  // 1. Missing, expired, or not waiting.
  const ceremony = deps.store.awaiting(ceremonyToken, now);
  if (ceremony === undefined) {
    return "uv_ceremony_gone";
  }
  // 2. The binding against the tab's live URL, as the approval path checks it.
  const liveOrigin = originOf(await deps.liveTabUrl(ceremony.tabId));
  if (liveOrigin !== ceremony.boundOrigin) {
    await decline(deps, ceremony);
    return "uv_ceremony_gone";
  }
  // The look-up awaited: the vault may have locked, or the ceremony settled, meanwhile.
  const session = deps.session();
  if (session === undefined) {
    return "uv_locked";
  }
  if (!deps.store.isAwaiting(ceremonyToken, now)) {
    return "uv_ceremony_gone";
  }
  // 3. The local unlock against this device's own state; the keys it opens are dropped.
  try {
    session.reverify(password, now);
  } catch {
    // 4. A wrong password (or one the core refuses outright) counts as one attempt.
    const attempts = deps.store.recordFailedVerification(ceremonyToken);
    if (attempts >= UV_MAX_ATTEMPTS) {
      await decline(deps, ceremony);
      return "uv_attempts_exhausted";
    }
    return "uv_wrong_password";
  }
  // 5. Verified: take the ceremony (single use) and sign with the same `now`.
  if (deps.store.take(ceremonyToken, ceremony.tabId, liveOrigin, now) === undefined) {
    return "uv_ceremony_gone";
  }
  let result: PasskeyResultPayload | undefined;
  try {
    result = await deps.sign(ceremony, now);
  } catch {
    result = undefined;
  }
  await deps.deliver(ceremony.tabId, ceremonyToken, result);
  await deps.clearBadge(ceremony.tabId);
  return result !== undefined ? "uv_ok" : "uv_ceremony_gone";
}

/** §7 point 5: the popup's Cancel declines the ceremony, if it still waits. */
export async function cancelVerification(deps: PasskeyVerifyDeps, ceremonyToken: string): Promise<UvReplyCode> {
  const ceremony = deps.store.awaiting(ceremonyToken, deps.now());
  if (ceremony !== undefined) {
    await decline(deps, ceremony);
  }
  return "uv_cancelled";
}
