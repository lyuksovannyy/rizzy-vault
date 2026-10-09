// The long-lived context's message handling, shared between the Chromium offscreen document
// (`offscreen.ts`) and the Firefox background page (`background-page.ts`) — ADR 0036 §2: "one
// long-lived context holds the instance... for the whole extension lifetime." This is the ONE
// place that may import `@rizzy-vault/core` for value, not type (ADR 0036 §4; eslint
// restriction in `eslint.config.mjs`, which actually allows every file under `core-host/`). The
// MV3 service worker (`background/service-worker.ts`) never imports this module: it only relays
// messages to whichever entry point is running.
import { generatePassphraseWithOptions, generatePasswordWithOptions, registrableDomainOf } from "@rizzy-vault/core";

import { readAccountConfig, saveAccountConfig } from "./account-config.ts";
import { createSavePromptLocationIndex } from "./save-prompt-location.ts";
import {
  type AddPasskeyInput,
  type DurableSession,
  type MatchCandidate,
  type MatchFrameInfo,
  addPasskeyChange,
  cacheStoreNames,
  createPasskey,
  decideCandidates,
  enrolDevice,
  findItemForUpdate,
  initCore,
  itemCredentials,
  newElementId,
  newLoginChangeset,
  newLoginWithPasskeyChangeset,
  sessionPasskeyCandidatesForRpId,
  toContractItemSummary,
  unlockDevice,
  updateLoginChangeset,
} from "./bindings.ts";
import { ExtensionCache } from "../cache/idb.ts";
import { AutoLockTimer, readAutoLockMs } from "./lifecycle.ts";
import {
  type PasskeyCeremonyRequest,
  createPasskeyCeremonyStore,
  isOfferedCandidate,
} from "./passkey-ceremony.ts";
import { base64ToBytes, bytesToBase64 } from "../messaging/bytes.ts";
import { clearUnlockedSnapshot, hasSessionStorage, restoreUnlockedSnapshot } from "./session-store.ts";
import type {
  ItemFieldSummary,
  PasskeyCandidateSummary,
  PasskeyResultPayload,
  PopupRequest,
  PopupResponse,
} from "../messaging/contract.ts";

let session: DurableSession | undefined;
let cache: ExtensionCache | undefined;
let autoLock: AutoLockTimer | undefined;

/** Opens the one durable-device cache (ADR 0026 §3), creating its object stores on first use.
 * `cacheStoreNames()` needs `initCore()` to have resolved first (it calls the core's own
 * readiness check), so this always awaits that first; both are memoised, so a second caller
 * reuses the same open database rather than racing a second `indexedDB.open`. */
async function ensureCache(): Promise<ExtensionCache> {
  if (cache !== undefined) {
    return cache;
  }
  await initCore();
  cache = await ExtensionCache.open(cacheStoreNames());
  return cache;
}

/** Starts the long-lived context: tries the `storage.session` fallback restore (ADR 0036 §2),
 * then starts the auto-lock timer if something was restored. Call once, at module load. */
export async function startCoreContext(ext: WebExtNamespace): Promise<void> {
  const autoLockMs = await readAutoLockMs(ext);
  autoLock = new AutoLockTimer(() => {
    void lock(ext);
  }, autoLockMs);
  if (!hasSessionStorage(ext)) {
    // No fallback on this browser build: nothing to restore, stay locked, same as a fresh
    // start.
    return;
  }
  const snapshot = await restoreUnlockedSnapshot(ext);
  if (snapshot !== undefined) {
    // `DurableSession` has no "resume from an opaque snapshot" constructor yet (only
    // `enrolDevice`/`unlockDurableDevice`, each a real crypto operation): a real restore would
    // need one (`not_done`, tracked honestly rather than faked). Until it exists, a
    // present-but-unusable snapshot is treated as stale and cleared, same as before this
    // change — the fallback plumbing stays ready for the day a real snapshot can go in it.
    await clearUnlockedSnapshot(ext);
  }
}

async function lock(ext: WebExtNamespace): Promise<void> {
  session?.lock();
  session = undefined;
  autoLock?.stop();
  // Every submitted credential this context still holds for an unanswered save/update prompt,
  // and the location index pointing at it (`save-prompt-location.ts`'s own module docs), stop
  // existing on lock: "credentials in the pending offer stay in the long-lived context only"
  // means they do not outlive it either, once the master key that would let anyone use them is
  // gone anyway.
  pendingSavePrompts.clear();
  savePromptLocations.clear();
  passkeyCeremonies.clear();
  if (hasSessionStorage(ext)) {
    await clearUnlockedSnapshot(ext);
  }
}

/** Locks from outside a `PopupRequest` — the `chrome.idle`/`browser.idle` listener ADR 0036 §3
 * names alongside the timeout-based {@link AutoLockTimer}. Exported so `listener.ts` can wire it
 * without reaching into this module's private `lock`. */
export function lockFromIdleState(ext: WebExtNamespace): Promise<void> {
  return lock(ext);
}

/** The unlocked session, for `content-handler.ts`'s matching and fill (both run in this same
 * long-lived context, ADR 0037 §1). `undefined` while locked or not yet enrolled. */
export function currentSession(): DurableSession | undefined {
  return session;
}

interface PendingSavePrompt {
  readonly action: "save" | "update";
  readonly pageUrl: string;
  readonly usernameValue: string;
  readonly passwordValue: string;
  readonly updateItemId?: string;
  /** The matching item's title, stored once at submit time so the save-prompt-race path
   * (`checkPendingSavePromptByLocation`) can answer with it later without re-matching against
   * whatever the vault's state happens to be by then. Set only when `action` is `"update"`,
   * same as the immediate response `offerSavePrompt` already returns. */
  readonly itemTitle?: string;
}

/** Submitted-credential reports awaiting a save/update decision (ADR 0036 §4: zeroized once the
 * prompt is answered or dismissed, never written to `storage.local`/IndexedDB). In-memory only,
 * keyed by a one-time token handed to the content script — never the item/field data itself.
 * The one source of truth for a pending offer's credentials: `savePromptLocations`
 * (`save-prompt-location.ts`) is only ever a token reference into this map, never a second
 * copy of the values. */
const pendingSavePrompts = new Map<string, PendingSavePrompt>();

function takePendingSavePrompt(token: string): PendingSavePrompt | undefined {
  const pending = pendingSavePrompts.get(token);
  pendingSavePrompts.delete(token);
  return pending;
}

function addPendingSavePrompt(pending: PendingSavePrompt): string {
  const token = crypto.randomUUID();
  pendingSavePrompts.set(token, pending);
  return token;
}

/** How long a save-prompt offer stays reachable by tab and registrable domain after the form
 * that produced it was submitted (ROADMAP §4.4 "save/update on submit"; `README.md`'s residual
 * note on the save-prompt race this fixes). Deliberately short: a stale offer reachable for too
 * long after the user has moved on is the wrong default for a security prompt. */
const SAVE_PROMPT_LOCATION_TTL_MS = 2 * 60 * 1000;

/** The save-prompt offer's *location* index (`save-prompt-location.ts`'s own module docs) —
 * never its credentials, which stay solely in {@link pendingSavePrompts} above. Cleared on lock
 * (`lock`, above) along with the credentials it only ever points at. */
const savePromptLocations = createSavePromptLocationIndex(SAVE_PROMPT_LOCATION_TTL_MS);

/** `registrableDomainOf`'s own doc: `undefined` for a bare public suffix or a URL that fails to
 * parse at all — never thrown onward; a location-keyed offer simply does not exist for such a
 * page. An IP-literal host still gets one (itself), so a self-hosted/intranet login keys fine. */
function registrableDomainOrUndefined(pageUrl: string): string | undefined {
  try {
    return registrableDomainOf(pageUrl);
  } catch {
    return undefined;
  }
}

/** Indexes `token`'s offer by `tabId`/`pageUrl`'s registrable domain, in addition to the token
 * itself (`offerSavePrompt`'s own immediate-response path, unchanged). A no-op when `tabId` is
 * unavailable (`messaging/contract.ts`'s `ContentScriptForward.trustedTabId` doc: some senders
 * genuinely carry none) or `pageUrl` has no registrable domain — the immediate, same-page path
 * still works either way; only the race-recovery path is unavailable for that one offer. */
function rememberPendingOfferByLocation(tabId: number | undefined, pageUrl: string, token: string): void {
  savePromptLocations.remember(tabId, registrableDomainOrUndefined(pageUrl), token, Date.now());
}

/**
 * `content-handler.ts`'s `check_save_prompt` handling: the still-pending offer, if any, for
 * `tabId`'s current page at `pageUrl` — the save-prompt race's recovery path
 * (`save-prompt-location.ts`'s own module docs). The location index is single-use regardless of
 * outcome, so a later page load of the same tab and domain within the TTL never replays an
 * already-delivered offer a second time; its expiry check runs on read, not only via a timer
 * this context's own host (an MV3 service worker's offscreen document, or Firefox's background
 * page) may suspend before a `setTimeout` ever fires.
 */
export function checkPendingSavePromptByLocation(
  tabId: number | undefined,
  pageUrl: string,
): { readonly token: string; readonly suggestion: "save" | "update"; readonly itemTitle?: string } | undefined {
  const token = savePromptLocations.take(tabId, registrableDomainOrUndefined(pageUrl), Date.now());
  if (token === undefined) {
    return undefined;
  }
  // The credentials live only in `pendingSavePrompts`, looked up but not consumed here (module
  // docs): the user still answers through the ordinary `save_prompt_resolved` → `resolveSavePrompt`
  // path, from whichever page is now showing the banner, exactly as the immediate-response path
  // already works. A token the direct path already resolved (a narrow timing window: the
  // original page did show and resolve the banner just before navigating) is simply gone from
  // that map by now, and this returns `undefined` rather than resurrect it.
  const pending = pendingSavePrompts.get(token);
  if (pending === undefined) {
    return undefined;
  }
  return {
    token,
    suggestion: pending.action,
    ...(pending.itemTitle !== undefined ? { itemTitle: pending.itemTitle } : {}),
  };
}

/** Runs the save or update a resolved save-prompt token named (`content-handler.ts`'s
 * `save_prompt_resolved` handling). `"dismiss"` and a stale/unknown token both resolve
 * successfully with nothing written — there is nothing left to clean up either way, since
 * {@link takePendingSavePrompt} already removed the entry before this is called. */
async function applySavePromptAction(pending: PendingSavePrompt, action: "save" | "update" | "dismiss"): Promise<void> {
  if (action === "dismiss" || session === undefined) {
    return;
  }
  if (action === "save") {
    await session.createItem("login", newLoginChangeset(pending.pageUrl, pending.usernameValue, pending.passwordValue));
  } else if (pending.updateItemId !== undefined) {
    await session.editItem(pending.updateItemId, updateLoginChangeset(pending.usernameValue, pending.passwordValue));
  }
}

/** `content-handler.ts`'s `save_prompt_resolved` handling, in one call: looks up and consumes
 * the token, then (unless `"dismiss"` or the token is unknown/already used) runs the create or
 * edit. Returns `false` for an unknown/already-resolved token, so the caller can tell that apart
 * from a real failure thrown out of `createItem`/`editItem`. */
export async function resolveSavePrompt(token: string, action: "save" | "update" | "dismiss"): Promise<boolean> {
  const pending = takePendingSavePrompt(token);
  if (pending === undefined) {
    return false;
  }
  await applySavePromptAction(pending, action);
  return true;
}

/** `content-handler.ts`'s `fields_detected` handling: candidates for `pageUrl`, or `undefined`
 * while locked (an honest empty list with no candidates, never a placeholder one). */
export function matchCandidatesFor(
  pageUrl: string,
  frame: MatchFrameInfo,
): { candidates: readonly MatchCandidate[]; warnings: readonly string[] } | undefined {
  if (session === undefined) {
    return undefined;
  }
  return decideCandidates(session, pageUrl, frame);
}

/** `content-handler.ts`'s own title/username lookup for one match candidate (ADR 0013 §3 rule
 * 3: list views never carry more than title/username). `undefined` while locked, or if the item
 * no longer exists (deleted between the match decision and this lookup). */
export function itemSummaryFor(itemId: string): { title: string; username: string } | undefined {
  if (session === undefined) {
    return undefined;
  }
  try {
    const item = session.item(itemId);
    return { title: item.title, username: item.username ?? "" };
  } catch {
    return undefined;
  }
}

/** `content-handler.ts`'s `handleInlineMenuFillRequest`: the chosen item's username/password,
 * by kind (ADR 0036 §4: only the chosen candidate's values ever cross this boundary, and only
 * after candidate-membership and equivalence confirmation have already passed). `undefined`
 * while locked. */
export function revealCredentialsForFill(itemId: string): { username?: string; password: string } | undefined {
  if (session === undefined) {
    return undefined;
  }
  const { username, password } = itemCredentials(session, itemId);
  return { ...(username !== "" ? { username } : {}), password };
}

/** The passkey consent ceremony's pending-request store (`core-host/passkey-ceremony.ts`'s own
 * module docs) — cleared on lock, alongside every other in-memory secret-adjacent state this
 * long-lived context holds (`lock`, above). */
const passkeyCeremonies = createPasskeyCeremonyStore();

/** `content-handler.ts`'s `passkey_create_request` handling (ADR 0039 §2): registers a pending
 * "save a passkey" ceremony and returns what the consent UI needs to display, or `undefined`
 * while locked — never calls {@link createPasskey} itself (module docs: that only happens once
 * the user approves, `approvePasskeyCeremony`). `rpId` defaults to the verified origin's own
 * host when the page supplied none (`rpIdHint`), matching how a real browser's own WebAuthn
 * implementation resolves an absent `rp.id` — `createPasskey`'s own INV-64 check (Rust) is still
 * what actually decides whether this `rpId` is allowed for `origin`, not this default.
 */
export function offerPasskeyCreate(
  origin: string,
  tabId: number,
  rpIdHint: string | undefined,
  rpName: string,
  userIdB64: string,
  userName: string,
  userDisplayName: string,
  challengeB64: string,
): { readonly ceremonyToken: string; readonly rpId: string; readonly rpName: string; readonly userName: string } | undefined {
  if (session === undefined) {
    return undefined;
  }
  const rpId = rpIdHint ?? hostOf(origin);
  if (rpId === undefined) {
    return undefined;
  }
  const request: PasskeyCeremonyRequest = {
    kind: "create",
    origin,
    rpId,
    rpName,
    userIdB64,
    userName,
    userDisplayName,
    challengeB64,
  };
  const ceremonyToken = passkeyCeremonies.create(request, tabId, origin, Date.now());
  return { ceremonyToken, rpId, rpName, userName };
}

/** `content-handler.ts`'s `passkey_get_request` handling: registers a pending "sign in with a
 * passkey" ceremony with every candidate whose stored `rp_id` matches, or `undefined` while
 * locked or when nothing matches (ADR 0039 §2's consent prompt needs at least one real choice —
 * an empty list falls straight back to the native authenticator, `content-handler.ts`'s own
 * decision, not this function's). */
export function offerPasskeyGet(
  origin: string,
  tabId: number,
  rpIdHint: string | undefined,
  challengeB64: string,
): { readonly ceremonyToken: string; readonly rpId: string; readonly candidates: readonly PasskeyCandidateSummary[] } | undefined {
  if (session === undefined) {
    return undefined;
  }
  const rpId = rpIdHint ?? hostOf(origin);
  if (rpId === undefined) {
    return undefined;
  }
  const matches = sessionPasskeyCandidatesForRpId(session, rpId);
  if (matches.length === 0) {
    return undefined;
  }
  const candidates: PasskeyCandidateSummary[] = matches.map((m) => ({
    passkeyRef: `${m.itemId}:${m.elementId}`,
    itemTitle: m.itemTitle,
    userName: m.userName,
  }));
  const request: PasskeyCeremonyRequest = { kind: "get", origin, rpId, challengeB64, candidates };
  const ceremonyToken = passkeyCeremonies.create(request, tabId, origin, Date.now());
  return { ceremonyToken, rpId, candidates };
}

/** `origin`'s host, port excluded (`URL.hostname`, never `URL.host`, which includes a non-default
 * port) — `rp_id` is never port-qualified (ADR 0037's "port is never part of the
 * registrable-domain computation," which `rizzy_client::passkey::verify_rp_id`'s own `origin.
 * host()` comparison relies on too): a mismatch here would make every default-`rpId` ceremony on
 * a non-default port (every one of this project's own E2E tests, and most real sites on a
 * dev/staging port) fail Rust's exact-host-match with a `rp_id` this function minted *with* a
 * port — found while writing `e2e/passkey.spec.ts` against a real `https://localhost:<port>`
 * test RP, not merely inferred. */
function hostOf(origin: string): string | undefined {
  try {
    return new URL(origin).hostname;
  } catch {
    return undefined;
  }
}

function splitPasskeyRef(passkeyRef: string): { readonly itemId: string; readonly elementId: string } | undefined {
  const i = passkeyRef.indexOf(":");
  if (i < 0) {
    return undefined;
  }
  return { itemId: passkeyRef.slice(0, i), elementId: passkeyRef.slice(i + 1) };
}

/**
 * `content-handler.ts`'s `passkey_ceremony_approved` handling: looks up and consumes
 * `ceremonyToken` (single-use, and bound to `liveTabId`/`liveOrigin` — `passkey-ceremony.ts`'s
 * own doc on why a navigation invalidates it), then runs the real ceremony — `createPasskey` +
 * an immediate `createItem`/`editItem` for a `create`, or `DurableSession.passkeyAssertion` for
 * a `get` — and returns the page-facing result. `undefined` means "fall back to the native
 * authenticator": an unknown/expired/mismatched token, a locked device, or any failure along the
 * way, never distinguished further to the caller (`core-host/content-handler.ts` always answers
 * the content script with `apply_passkey_result`'s `outcome: "fallback"` either way — ADR 0039
 * §2's "Decline, timeout or no match" rule treats every one of these the same).
 */
export async function approvePasskeyCeremony(
  ceremonyToken: string,
  liveTabId: number,
  liveOrigin: string,
  chosenPasskeyRef: string | undefined,
): Promise<PasskeyResultPayload | undefined> {
  const request = passkeyCeremonies.take(ceremonyToken, liveTabId, liveOrigin, Date.now());
  if (request === undefined || session === undefined) {
    return undefined;
  }
  try {
    if (request.kind === "create") {
      return await runCreatePasskey(session, request);
    }
    return runGetPasskey(session, request, chosenPasskeyRef);
  } catch {
    // Any failure (a Rust `rp_id_rejected`/`invalid_input`, a write error, a bad `passkeyRef`):
    // fall back, never surface the raw error to the page (ADR 0039 §2 names no error channel
    // back to the page at all — only "fallback to the native authenticator").
    return undefined;
  }
}

/** `content-handler.ts`'s `passkey_ceremony_declined` handling: single-use consume, same
 * binding check, no further action — the caller still pushes `apply_passkey_result`'s
 * `outcome: "fallback"` to the tab either way. */
export function declinePasskeyCeremony(ceremonyToken: string, liveTabId: number, liveOrigin: string): void {
  passkeyCeremonies.take(ceremonyToken, liveTabId, liveOrigin, Date.now());
}

async function runCreatePasskey(
  s: DurableSession,
  request: Extract<PasskeyCeremonyRequest, { kind: "create" }>,
): Promise<PasskeyResultPayload> {
  const created = createPasskey(request.origin, request.rpId, base64ToBytes(request.challengeB64));
  const passkeyInput: AddPasskeyInput = {
    elementId: newElementId(),
    rpId: request.rpId,
    userHandle: base64ToBytes(request.userIdB64),
    credentialId: created.credentialId,
    privateKey: created.privateKey,
    publicKeyCose: created.publicKeyCose,
    createdMs: Date.now(),
  };
  // ADR 0039 §1: attach to an existing Login for this `rpId` if the user already has one
  // (`sessionPasskeyCandidatesForRpId`'s own exact-`rp_id` equality — the same relation a second
  // passkey on that Login would need), otherwise save a brand-new Login, title defaulted from
  // the RP's own display name, exactly as `newLoginChangeset` already defaults a saved-from-
  // submit Login's title from the page's own host.
  const existing = sessionPasskeyCandidatesForRpId(s, request.rpId)[0];
  if (existing !== undefined) {
    await s.editItem(existing.itemId, [addPasskeyChange(passkeyInput)]);
  } else {
    await s.createItem("login", newLoginWithPasskeyChangeset(request.rpName, request.userName, passkeyInput));
  }
  try {
    // Pushes the new/updated Login to the server right away, rather than waiting for the popup
    // to next open (the only other place this long-lived context syncs today) or for the next
    // device's own pull: a passkey is only useful for signing in once it has actually left this
    // one device. Best-effort: the local write above already succeeded (the credential this
    // ceremony returns to the page is real and usable locally either way), so a sync failure
    // here — offline, a server error — is swallowed, not surfaced as a ceremony failure the page
    // would see as "fallback to the native authenticator," which would be misleading (the
    // passkey *was* created).
    await s.sync();
  } catch {
    // Not fatal (module doc above) — never logged with any item/credential detail (CLAUDE.md:
    // never log secrets), and this catch intentionally has nothing else to do.
  }
  return {
    credentialIdB64: bytesToBase64(created.credentialId),
    clientDataJsonB64: bytesToBase64(created.clientDataJson),
    attestationObjectB64: bytesToBase64(created.attestationObject),
  };
}

function runGetPasskey(
  s: DurableSession,
  request: Extract<PasskeyCeremonyRequest, { kind: "get" }>,
  chosenPasskeyRef: string | undefined,
): PasskeyResultPayload | undefined {
  if (chosenPasskeyRef === undefined || !isOfferedCandidate(request, chosenPasskeyRef)) {
    return undefined;
  }
  const ref = splitPasskeyRef(chosenPasskeyRef);
  if (ref === undefined) {
    return undefined;
  }
  const assertion = s.passkeyAssertion(ref.itemId, ref.elementId, request.origin, request.rpId, base64ToBytes(request.challengeB64));
  return {
    credentialIdB64: bytesToBase64(assertion.credentialId),
    clientDataJsonB64: bytesToBase64(assertion.clientDataJson),
    authenticatorDataB64: bytesToBase64(assertion.authenticatorData),
    signatureB64: bytesToBase64(assertion.signatureDer),
    // `userHandle` is deliberately absent (`StoredPasskey`'s own doc, `bindings.ts`): no
    // `@rizzy-vault/core` call returns it back once stored, only at creation time. Legal per the
    // WebAuthn spec (`AuthenticatorAssertionResponse.userHandle` is nullable), but an RP that
    // requires it for a fully "typeless" discoverable sign-in will not accept this response —
    // `not_done`, reported honestly rather than worked around.
  };
}

/** `content-handler.ts`'s `credentials_submitted` handling: offers "save" when no saved item
 * matches the submitted page, "update" (naming the matching item) otherwise. `undefined` while
 * locked, or when nothing worth saving was captured (no password). */
export function offerSavePrompt(
  pageUrl: string,
  usernameValue: string | undefined,
  passwordValue: string | undefined,
  tabId: number | undefined,
): { readonly token: string; readonly suggestion: "save" | "update"; readonly itemTitle?: string } | undefined {
  if (session === undefined || passwordValue === undefined || passwordValue === "") {
    return undefined;
  }
  const username = usernameValue ?? "";
  const existing = findItemForUpdate(session, pageUrl);
  if (existing === undefined) {
    const token = addPendingSavePrompt({ action: "save", pageUrl, usernameValue: username, passwordValue });
    rememberPendingOfferByLocation(tabId, pageUrl, token);
    return { token, suggestion: "save" };
  }
  const token = addPendingSavePrompt({
    action: "update",
    pageUrl,
    usernameValue: username,
    passwordValue,
    updateItemId: existing.id,
    itemTitle: existing.title,
  });
  rememberPendingOfferByLocation(tabId, pageUrl, token);
  return { token, suggestion: "update", itemTitle: existing.title };
}

function mapFields(fields: readonly { key: string; kind: ItemFieldSummary["kind"]; concealed: boolean; value: string | undefined }[]): readonly ItemFieldSummary[] {
  return fields.map((f) => ({ key: f.key, kind: f.kind, concealed: f.concealed, value: f.value }));
}

/** Handles one popup/options request (ADR 0036 §4: "coarse, one-call-per-action messages").
 * `ext` is used for the `"lock"` branch's `storage.session` clear and the auto-lock timer's
 * start; the account-config read/write (`account-config.ts`) needs no `ext` — it is IndexedDB,
 * not `chrome.storage`, precisely so it keeps working inside the Chromium offscreen document. */
export async function handlePopupRequest(ext: WebExtNamespace, request: PopupRequest): Promise<PopupResponse> {
  autoLock?.activity();
  switch (request.type) {
    case "get_status": {
      // Independent of the wasm core/cache init: a status check must answer instantly and must
      // not fail just because `init()` has not run yet. "Enrolled" is read from the one
      // non-secret fact `account-config.ts` saves at enrolment (the server origin), from its own
      // small IndexedDB database — not the durable-device cache, and not `chrome.storage`.
      const { serverOrigin } = await readAccountConfig();
      return {
        type: "status",
        locked: session === undefined,
        enrolled: serverOrigin !== undefined,
        ...(serverOrigin !== undefined ? { serverOrigin } : {}),
      };
    }
    case "enrol": {
      try {
        const store = await ensureCache();
        const existing = await readAccountConfig();
        if (existing.serverOrigin !== undefined) {
          return { type: "error", code: "already_enrolled" };
        }
        const newSession = await enrolDevice(
          {
            serverOrigin: request.serverOrigin,
            loginName: request.loginName,
            secretKey: request.secretKey,
            masterPassword: request.masterPassword,
            ...(request.totp !== undefined ? { totp: request.totp } : {}),
          },
          store,
        );
        session = newSession;
        await saveAccountConfig(request.serverOrigin, request.loginName);
        autoLock?.start();
        return { type: "enrolled" };
      } catch (e) {
        return { type: "error", code: errorCode(e, "enrol_failed") };
      }
    }
    case "unlock": {
      try {
        const store = await ensureCache();
        const { serverOrigin } = await readAccountConfig();
        if (serverOrigin === undefined) {
          return { type: "error", code: "not_enrolled" };
        }
        session = await unlockDevice(serverOrigin, store, request.masterPassword);
        autoLock?.start();
        return { type: "unlocked" };
      } catch (e) {
        return { type: "error", code: errorCode(e, "unlock_failed") };
      }
    }
    case "lock":
      await lock(ext);
      return { type: "locked" };
    case "sync": {
      if (session === undefined) {
        return { type: "error", code: "locked" };
      }
      try {
        await session.sync();
        return { type: "synced" };
      } catch (e) {
        return { type: "error", code: errorCode(e, "sync_failed") };
      }
    }
    case "list_items":
      if (session === undefined) {
        return { type: "error", code: "locked" };
      }
      return { type: "items", items: session.items().map(toContractItemSummary) };
    case "item_fields":
      if (session === undefined) {
        return { type: "error", code: "locked" };
      }
      try {
        return { type: "fields", fields: mapFields(session.fields(request.itemId)) };
      } catch (e) {
        return { type: "error", code: errorCode(e, "item_fields_failed") };
      }
    case "reveal_field":
      if (session === undefined) {
        return { type: "error", code: "locked" };
      }
      try {
        return { type: "revealed", value: session.reveal(request.itemId, request.fieldId) };
      } catch (e) {
        return { type: "error", code: errorCode(e, "reveal_failed") };
      }
    case "generate_password":
      try {
        // Independent of enrolment/unlock (the generator is a general utility, ROADMAP §4.4),
        // but still needs the wasm module loaded — `initCore()` is memoised, so this is a no-op
        // once enrol/unlock/status-with-cache has already run it.
        await initCore();
        const value =
          request.options.kind === "password"
            ? generatePasswordWithOptions({ length: request.options.length })
            : generatePassphraseWithOptions({ words: request.options.length });
        return { type: "generated", value: value.value };
      } catch {
        return { type: "error", code: "generate_failed" };
      }
  }
}

function errorCode(e: unknown, fallback: string): string {
  if (e instanceof Error) {
    const code = (e as unknown as { code?: unknown }).code;
    if (typeof code === "string") {
      return code;
    }
  }
  return fallback;
}
