// SPDX-License-Identifier: AGPL-3.0-only

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
  type ItemChange,
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
  itemIcon,
  newElementId,
  newLoginChangeset,
  newLoginWithPasskeyChangeset,
  saveTargets,
  saveVault,
  sessionPasskeyCandidatesForRpId,
  toContractItemSummary,
  vaultLabel,
  unlockDevice,
  updateLoginChangeset,
} from "./bindings.ts";
import { ExtensionCache } from "../cache/idb.ts";
import { AutoLockTimer, readAutoLockMs } from "./lifecycle.ts";
import { createIframeInstanceStore } from "./iframe-instance.ts";
import { type OfferRecord, type OfferRefusal, type OfferedItem, createOfferStore } from "./offer-store.ts";
import {
  type PasskeyCeremonyRequest,
  createPasskeyCeremonyStore,
  isOfferedCandidate,
} from "./passkey-ceremony.ts";
import { base64ToBytes, bytesToBase64 } from "../messaging/bytes.ts";
import { clearUnlockedSnapshot, hasSessionStorage, restoreUnlockedSnapshot } from "./session-store.ts";
import type {
  CapturedCustomField,
  FillOnly,
  FillScope,
  FillValues,
  ItemFieldSummary,
  OfferCandidate,
  PasskeyCandidateSummary,
  PasskeyResultPayload,
  PopupRecoveryNotice,
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
  iframeInstances.clear();
  offers.clear();
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
  /** ADR 0076 §5.1: the submitted form's custom-token fields, for the extension-origin save
   * dialog only (never the page-DOM banner, §5.2). Held in memory, dropped with the prompt. */
  readonly customFields?: readonly CapturedCustomField[];
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

/** The longest website host an `item_icon` request may carry (the core bounds it again). */
const MAX_WEBSITE_HOST_CHARS = 1024;

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
): { readonly token: string; readonly suggestion: "save" | "update"; readonly itemTitle?: string; readonly dialog?: true } | undefined {
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
    // ADR 0076 §5.2: the same dialog/banner choice as the immediate answer made.
    ...(hasDialogRows(pending) || severalSaveTargets(pending.action) ? { dialog: true as const } : {}),
  };
}

/** ADR 0081 §A8: a new login with two or more vaults to save to is asked in the extension-origin
 * dialog, whose picker preselects the Personal vault; vault names never enter the page DOM. */
function severalSaveTargets(action: "save" | "update"): boolean {
  if (action !== "save" || session === undefined) {
    return false;
  }
  try {
    return saveTargets(session).length > 1;
  } catch {
    return false;
  }
}

/** Whether a pending prompt's captured custom fields give save-dialog rows (ADR 0076 §5.3). */
function hasDialogRows(pending: PendingSavePrompt): boolean {
  if (session === undefined || pending.customFields === undefined || pending.customFields.length === 0) {
    return false;
  }
  try {
    return session.customSavePlan(pending.action === "update" ? pending.updateItemId : undefined, pending.customFields).length > 0;
  } catch {
    return false;
  }
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
    // ADR 0081 §A8: the page-DOM banner offers no picker (vault names never enter the page), so
    // it saves to the Personal vault; with several vaults the dialog asks (`wantsDialog`).
    await session.createItem(
      saveVault(session, undefined),
      "login",
      newLoginChangeset(pending.pageUrl, pending.usernameValue, pending.passwordValue),
    );
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
): { pageHost: string; pagePort: number | undefined; candidates: readonly MatchCandidate[]; warnings: readonly string[] } | undefined {
  if (session === undefined) {
    return undefined;
  }
  return decideCandidates(session, pageUrl, frame);
}

/** `content-handler.ts`'s own title/username lookup for one match candidate (ADR 0013 §3 rule
 * 3: list views never carry more than title/username). `undefined` while locked, or if the item
 * no longer exists (deleted between the match decision and this lookup). */
export function itemSummaryFor(itemId: string): { title: string; username: string; vault?: string } | undefined {
  if (session === undefined) {
    return undefined;
  }
  try {
    const item = session.item(itemId);
    // ADR 0081 §A7: every list row shows its vault, the inline menu's candidate rows too; the
    // label ("Personal", a name, "Untitled vault") is the popup's (`vaultLabel`).
    const vault = session.vaults().find((v) => v.id === item.vaultId);
    return {
      title: item.title,
      username: item.username ?? "",
      ...(vault === undefined ? {} : { vault: vaultLabel(vault) }),
    };
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

/** `content-handler.ts`'s `handleInlineMenuGeneratePasswordRequest` (gap 32 in the M2 gap
 * audit, ADR 0040's trusted-click pattern applied to the generator): the same
 * `generatePasswordWithOptions` the popup's own `generate_password` handler (below) calls, with
 * its own default length — this one-button inline affordance offers no length/kind picker of its
 * own (ROADMAP §4.4's generator is the popup's; duplicating a picker into the small iframe menu
 * is unneeded surface, YAGNI). Independent of enrolment/unlock, same as the popup's handler:
 * `initCore()` is memoised, so this is a no-op once anything else has already loaded the wasm
 * module. Never throws — `handleInlineMenuGeneratePasswordRequest` catches and reports a plain
 * refusal, matching every other inline-menu-iframe request's `ContentErrorMessage` fallback. */
export async function generatePasswordForFill(): Promise<string> {
  await initCore();
  return generatePasswordWithOptions({}).value;
}

/** The passkey consent ceremony's pending-request store (`core-host/passkey-ceremony.ts`'s own
 * module docs) — cleared on lock, alongside every other in-memory secret-adjacent state this
 * long-lived context holds (`lock`, above). */
const passkeyCeremonies = createPasskeyCeremonyStore();

/** The inline-menu/passkey-consent iframe instance tokens (ADR 0043; `core-host/iframe-instance.ts`'s
 * own module docs) — cleared on lock like {@link passkeyCeremonies}. A registration needs no
 * unlocked session (the iframe shows nothing privileged while locked anyway, and every request it
 * could send is refused while locked regardless), so these four never check `session`. */
const iframeInstances = createIframeInstanceStore();

/** `register_iframe_instance` (ADR 0043 point 2): `tabId`/`trustedOrigin` are the browser-vouched
 * sender info of the content script that minted `instanceToken`. */
export function registerIframeInstance(instanceToken: string, tabId: number, trustedOrigin: string): boolean {
  return iframeInstances.register(instanceToken, tabId, trustedOrigin, Date.now());
}

/** `revoke_iframe_instance` (ADR 0043 point 5). */
export function revokeIframeInstance(instanceToken: string, tabId: number): void {
  iframeInstances.revoke(instanceToken, tabId);
}

/** The use-time check (ADR 0043 point 4), for `listener.ts`'s `isInlineMenuSender` branch:
 * every `true` must be paired with one {@link releaseIframeInstance} once that request settles. */
export function acquireIframeInstance(instanceToken: string, liveTabId: number): boolean {
  return iframeInstances.acquire(instanceToken, liveTabId, Date.now());
}

export function releaseIframeInstance(instanceToken: string): void {
  iframeInstances.release(instanceToken);
}

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
): {
  readonly ceremonyToken: string;
  readonly rpId: string;
  readonly rpName: string;
  readonly userName: string;
  readonly vaults?: readonly { readonly id: string; readonly label: string }[];
  readonly defaultVaultId?: string;
} | undefined {
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
  // ADR 0081 §A8: a passkey that saves a new login offers the vault picker (Personal
  // preselected); one added to an existing login stays in that login's vault.
  const attaches = sessionPasskeyCandidatesForRpId(session, rpId).length > 0;
  const targets = attaches ? [] : saveTargets(session);
  const personal = targets.find((v) => v.id === session?.personalVaultId) ?? targets[0];
  return {
    ceremonyToken,
    rpId,
    rpName,
    userName,
    ...(targets.length > 1 && personal !== undefined
      ? { vaults: targets.map((v) => ({ id: v.id, label: vaultLabel(v) })), defaultVaultId: personal.id }
      : {}),
  };
}

/** `content-handler.ts`'s `passkey_get_request` handling: registers a pending "sign in with a
 * passkey" ceremony with every candidate whose stored `rp_id` matches — and, when the page's own
 * `navigator.credentials.get()` call named `allowCredentials` (`allowCredentialIdsB64`, gap
 * 35(b) in the M2 gap audit), only the ones among those matches whose `credentialId` the page
 * actually listed. `undefined` while locked or when nothing matches (ADR 0039 §2's consent
 * prompt needs at least one real choice — an empty list falls straight back to the native
 * authenticator, `content-handler.ts`'s own decision, not this function's).
 *
 * An empty `allowCredentialIdsB64` means "any discoverable credential for this `rpId`"
 * (`PasskeyGetRequestMessage`'s own doc, mirroring the WebAuthn spec's own "omitted or empty
 * `allowCredentials` means a discoverable-credential request") — every `rp_id` match is offered,
 * same as before this gap was filled. A non-empty list narrows to the intersection: this is the
 * one place that intersection is computed, so `passkey_assertion` itself never has to (`crate::
 * device::DeviceSession::passkey_assertion`'s own doc: "This call does **not** check
 * `passkey_id` against the page's `allowCredentials`").
 */
export function offerPasskeyGet(
  origin: string,
  tabId: number,
  rpIdHint: string | undefined,
  challengeB64: string,
  allowCredentialIdsB64: readonly string[],
): { readonly ceremonyToken: string; readonly rpId: string; readonly candidates: readonly PasskeyCandidateSummary[] } | undefined {
  if (session === undefined) {
    return undefined;
  }
  const rpId = rpIdHint ?? hostOf(origin);
  if (rpId === undefined) {
    return undefined;
  }
  let matches = sessionPasskeyCandidatesForRpId(session, rpId);
  if (allowCredentialIdsB64.length > 0) {
    const allowed = new Set(allowCredentialIdsB64);
    matches = matches.filter((m) => allowed.has(bytesToBase64(m.credentialId)));
  }
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
  // The item part is an item reference, `<vault hex>:<item hex>` (ADR 0081 §A7); the element
  // id after the last colon has none.
  const i = passkeyRef.lastIndexOf(":");
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
  vaultId?: string,
): Promise<PasskeyResultPayload | undefined> {
  const request = passkeyCeremonies.take(ceremonyToken, liveTabId, liveOrigin, Date.now());
  if (request === undefined || session === undefined) {
    return undefined;
  }
  try {
    if (request.kind === "create") {
      return await runCreatePasskey(session, request, vaultId);
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
  vaultId: string | undefined,
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
    await s.createItem(
      saveVault(s, vaultId),
      "login",
      newLoginWithPasskeyChangeset(request.rpName, request.userName, passkeyInput),
    );
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
    // Gap 35(a) in the M2 gap audit: `DurableSession.passkeyAssertion` now reads the stored
    // `user_handle` back alongside the credential id (`crates/rizzy-wasm/src/device.rs`'s
    // `passkey_assertion`, never the private key) and returns it on every assertion, so this is
    // always set, not conditionally — an RP that requires `userHandle` for a fully "typeless"
    // discoverable sign-in (WebAuthn's own nullable field, but some RPs do require it in
    // practice) now gets it.
    userHandleB64: bytesToBase64(assertion.userHandle),
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
  customFields?: readonly CapturedCustomField[],
): { readonly token: string; readonly suggestion: "save" | "update"; readonly itemTitle?: string; readonly dialog?: true } | undefined {
  if (session === undefined || passwordValue === undefined || passwordValue === "") {
    return undefined;
  }
  const username = usernameValue ?? "";
  const existing = findItemForUpdate(session, pageUrl, username);
  const custom = customFields !== undefined && customFields.length > 0 ? { customFields } : {};
  // ADR 0076 §5.2–§5.3: when a captured custom field gives a dialog row, consent is asked in
  // the extension-origin save dialog, never in the page-DOM banner.
  const dialog = (itemId: string | undefined) => {
    if (customFields === undefined || customFields.length === 0 || session === undefined) {
      return {};
    }
    try {
      return session.customSavePlan(itemId, customFields).length > 0 ? { dialog: true as const } : {};
    } catch {
      return {};
    }
  };
  if (existing === undefined) {
    const token = addPendingSavePrompt({ action: "save", pageUrl, usernameValue: username, passwordValue, ...custom });
    rememberPendingOfferByLocation(tabId, pageUrl, token);
    return { token, suggestion: "save", ...(severalSaveTargets("save") ? { dialog: true as const } : dialog(undefined)) };
  }
  const token = addPendingSavePrompt({
    action: "update",
    pageUrl,
    usernameValue: username,
    passwordValue,
    updateItemId: existing.id,
    itemTitle: existing.title,
    ...custom,
  });
  rememberPendingOfferByLocation(tabId, pageUrl, token);
  return { token, suggestion: "update", itemTitle: existing.title, ...dialog(existing.id) };
}

/** One row of the extension-origin save dialog (ADR 0076 §5.3). Never a value. */
export interface SaveDialogRow {
  readonly index: number;
  readonly kind: "add" | "update";
  readonly label: string;
  readonly concealed: boolean;
  readonly checked: boolean;
}

/** What the save dialog shows for the pending prompt `token` (ADR 0076 §5.2: it fetches its
 * choices from here directly, by the save-prompt token). `undefined` when there is no such
 * prompt or the device is locked. The prompt stays pending. */
export function saveDialogChoices(
  token: string,
): { readonly suggestion: "save" | "update"; readonly itemTitle?: string; readonly pageHost: string; readonly rows: readonly SaveDialogRow[] } | undefined {
  const pending = pendingSavePrompts.get(token);
  if (pending === undefined || session === undefined) {
    return undefined;
  }
  let pageHost = "";
  try {
    pageHost = new URL(pending.pageUrl).hostname;
  } catch {
    // An unparsable URL was refused before it was stored; an empty host is shown otherwise.
  }
  const rows = session
    .customSavePlan(pending.action === "update" ? pending.updateItemId : undefined, pending.customFields ?? [])
    .map((r) => ({ index: r.index, kind: r.kind, label: r.label, concealed: r.concealed, checked: r.checked }));
  // ADR 0081 §A8: a new login's vault picker, the Personal vault preselected every time.
  const targets = pending.action === "save" ? saveTargets(session) : [];
  const personal = targets.find((v) => v.id === session?.personalVaultId) ?? targets[0];
  return {
    suggestion: pending.action,
    ...(pending.itemTitle !== undefined ? { itemTitle: pending.itemTitle } : {}),
    pageHost,
    rows,
    ...(targets.length > 1 && personal !== undefined
      ? { vaults: targets.map((v) => ({ id: v.id, label: vaultLabel(v) })), defaultVaultId: personal.id }
      : {}),
  };
}

/** The longest Display Name the save dialog may set, in UTF-16 code units. */
export const MAX_SAVE_DIALOG_LABEL_LEN = 256;

/**
 * Resolves the pending prompt `token` from the save dialog (ADR 0076 §5.3–§5.4): the login's
 * save or update as the banner would, plus the custom rows the user ticked (`chosen`, by row
 * index, with the Display Name the user left in an "add" row). The rows are recomputed here
 * from the prompt and the vault, never taken from the message: a save never sets or changes an
 * existing field's id, adds a field only under its own token, and every write runs W1–W5 in
 * `rizzy-client`. Returns `false` for no such prompt.
 */
export async function resolveSaveDialog(
  token: string,
  action: "save" | "update" | "dismiss",
  chosen: readonly { readonly index: number; readonly label: string }[],
  vaultId?: string,
): Promise<boolean> {
  const pending = takePendingSavePrompt(token);
  if (pending === undefined) {
    return false;
  }
  if (action === "dismiss" || session === undefined || action !== pending.action) {
    return true;
  }
  const captured = pending.customFields ?? [];
  const rows = session.customSavePlan(pending.action === "update" ? pending.updateItemId : undefined, captured);
  const extra: ItemChange[] = [];
  for (const pick of chosen) {
    const row = rows.find((r) => r.index === pick.index);
    const field = captured[pick.index];
    if (row === undefined || field === undefined) {
      continue;
    }
    if (row.kind === "add") {
      const label = pick.label.trim();
      if (label === "" || label.length > MAX_SAVE_DIALOG_LABEL_LEN) {
        continue; // W5: a new field needs a Display Name; the dialog never sends an empty one.
      }
      extra.push({
        op: "addCustomField",
        element: newElementId(),
        label,
        kind: field.masked ? "hidden" : "text",
        value: field.value,
        autocomplete: field.token,
      });
    } else if (row.element !== undefined) {
      extra.push({ op: "set", key: `field/${row.element}/value`, value: field.value });
    }
  }
  if (pending.action === "save") {
    await session.createItem(saveVault(session, vaultId), "login", [
      ...newLoginChangeset(pending.pageUrl, pending.usernameValue, pending.passwordValue),
      ...extra,
    ]);
  } else if (pending.updateItemId !== undefined) {
    await session.editItem(pending.updateItemId, [...updateLoginChangeset(pending.usernameValue, pending.passwordValue), ...extra]);
  }
  return true;
}

/** The inline-menu offer records (ADR 0076 §4.1; `offer-store.ts`), cleared on lock. */
const offers = createOfferStore(
  (out) => crypto.getRandomValues(out),
  () => Date.now(),
);

/** Truncates a Display Name to the offer's 256-character bound, by code point. */
function offerLabel(label: string): string {
  let out = "";
  for (const ch of label) {
    if (out.length + ch.length > 256) {
      break;
    }
    out += ch;
  }
  return out;
}

/** Whether an item can produce a TOTP code (ADR 0076 §1.3 rule (g), `hasTotp`). */
export function hasTotpFor(itemId: string): boolean {
  if (session === undefined) {
    return false;
  }
  try {
    return session.autofillOffer(itemId, []).fillsTotp;
  } catch {
    return false;
  }
}

/**
 * Builds and records the offer for one inline menu (ADR 0076 §4.1 step 3): per current candidate,
 * whether a click fills a TOTP code (the step has a TOTP target and the item a time-based
 * secret) and which custom fields it fills, by Display Name. `undefined` while locked.
 */
export function createOffer(
  tabId: number,
  pageUrl: string,
  scope: FillScope,
  candidateIds: readonly string[],
): { readonly offerId: string; readonly candidates: readonly OfferCandidate[] } | undefined {
  if (session === undefined) {
    return undefined;
  }
  const stepHasTotp = scope.only === "totp" || scope.totp === true;
  const items = new Map<string, OfferedItem>();
  const candidates: OfferCandidate[] = [];
  for (const itemId of candidateIds) {
    let offer: ReturnType<DurableSession["autofillOffer"]>;
    try {
      offer = session.autofillOffer(itemId, scope.custom ?? []);
    } catch {
      continue;
    }
    const fillsTotp = stepHasTotp && offer.fillsTotp;
    items.set(itemId, { fillsTotp, custom: offer.custom.map((c) => ({ token: c.token, element: c.element })) });
    candidates.push({
      itemId,
      fillsTotp,
      customFill: offer.custom.map((c) => ({ label: offerLabel(c.label), concealed: c.concealed })),
    });
  }
  const offerId = offers.create({ tabId, pageUrl, scope, items });
  return { offerId, candidates };
}

/** Takes an offer for a fill (ADR 0076 §4.2; `offer-store.ts`'s `take`). */
export function takeOffer(offerId: string, tabId: number, pageUrl: string, itemId: string, only: FillOnly | undefined): OfferRecord | OfferRefusal {
  return offers.take(offerId, tabId, pageUrl, itemId, only);
}

/**
 * The values of one offered fill (ADR 0076 §4.2): one coarse call into `rizzy-client` with the
 * offer record's own scope and the elements it recorded. `undefined` while locked or when
 * nothing would be filled.
 */
export function fillValuesFor(itemId: string, record: OfferRecord): FillValues | undefined {
  if (session === undefined) {
    return undefined;
  }
  const item = record.items.get(itemId);
  if (item === undefined) {
    return undefined;
  }
  const plan = session.fillPlan(itemId, {
    only: record.scope.only,
    totp: item.fillsTotp && record.scope.only !== "totp",
    custom: item.custom,
    usernameToken: record.scope.usernameToken,
    passwordToken: record.scope.passwordToken,
  });
  const values: FillValues = {
    ...(plan.username !== undefined ? { username: plan.username } : {}),
    ...(plan.password !== undefined ? { password: plan.password } : {}),
    ...(plan.totp !== undefined && item.fillsTotp ? { totp: plan.totp } : {}),
    ...(plan.custom.length > 0 ? { custom: plan.custom } : {}),
  };
  return Object.keys(values).length === 0 ? undefined : values;
}

function mapFields(fields: readonly { key: string; kind: ItemFieldSummary["kind"]; concealed: boolean; value: string | undefined }[]): readonly ItemFieldSummary[] {
  return fields.map((f) => ({ key: f.key, kind: f.kind, concealed: f.concealed, value: f.value }));
}

/** The pending-recovery notice of `s`'s last account answer, for the popup's banner (ADR
 * 0045): advisory only (INV-70), never read by anything but the banner. */
function recoveryNoticeOf(s: DurableSession | undefined): PopupRecoveryNotice | undefined {
  const notice = s?.recoveryNotice;
  if (notice === undefined) {
    return undefined;
  }
  return {
    openedAtMs: notice.openedAtMs,
    availableAtMs: notice.availableAtMs,
    ...(notice.lastRecoveryAtMs !== undefined ? { lastRecoveryAtMs: notice.lastRecoveryAtMs } : {}),
  };
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
      const notice = recoveryNoticeOf(session);
      return {
        type: "status",
        locked: session === undefined,
        enrolled: serverOrigin !== undefined,
        ...(serverOrigin !== undefined ? { serverOrigin } : {}),
        ...(notice !== undefined ? { recoveryNotice: notice } : {}),
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
        const notice = recoveryNoticeOf(session);
        return { type: "synced", ...(notice !== undefined ? { recoveryNotice: notice } : {}) };
      } catch (e) {
        return { type: "error", code: errorCode(e, "sync_failed") };
      }
    }
    case "list_items":
      if (session === undefined) {
        return { type: "error", code: "locked" };
      }
      {
        const vaults = session.vaults();
        return { type: "items", items: session.items().map((i) => toContractItemSummary(i, vaults)) };
      }
    case "item_icon": {
      // ADR 0052 point 6: only while unlocked, and only the hostname leaves (the core refuses
      // anything that is not one, and sends nothing for it).
      if (session === undefined) {
        return { type: "error", code: "locked" };
      }
      if (typeof request.websiteHost !== "string" || request.websiteHost.length > MAX_WEBSITE_HOST_CHARS) {
        return { type: "error", code: "invalid_input" };
      }
      try {
        const { serverOrigin } = await readAccountConfig();
        if (serverOrigin === undefined) {
          return { type: "error", code: "not_enrolled" };
        }
        const png = await itemIcon(serverOrigin, request.websiteHost);
        return { type: "icon", png: png === undefined ? null : bytesToBase64(png) };
      } catch (e) {
        return { type: "error", code: errorCode(e, "item_icon_failed") };
      }
    }
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
