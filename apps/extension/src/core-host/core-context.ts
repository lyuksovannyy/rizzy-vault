// The long-lived context's message handling, shared between the Chromium offscreen document
// (`offscreen.ts`) and the Firefox background page (`background-page.ts`) — ADR 0036 §2: "one
// long-lived context holds the instance... for the whole extension lifetime." This is the ONE
// place that may import `@rizzy-vault/core` for value, not type (ADR 0036 §4; eslint
// restriction in `eslint.config.mjs`, which actually allows every file under `core-host/`). The
// MV3 service worker (`background/service-worker.ts`) never imports this module: it only relays
// messages to whichever entry point is running.
import { generatePassphraseWithOptions, generatePasswordWithOptions } from "@rizzy-vault/core";

import { readAccountConfig, saveAccountConfig } from "./account-config.ts";
import {
  type DurableSession,
  type MatchCandidate,
  type MatchFrameInfo,
  cacheStoreNames,
  decideCandidates,
  enrolDevice,
  findItemForUpdate,
  initCore,
  itemCredentials,
  newLoginChangeset,
  toContractItemSummary,
  unlockDevice,
  updateLoginChangeset,
} from "./bindings.ts";
import { ExtensionCache } from "../cache/idb.ts";
import { AutoLockTimer, readAutoLockMs } from "./lifecycle.ts";
import { clearUnlockedSnapshot, hasSessionStorage, restoreUnlockedSnapshot } from "./session-store.ts";
import type { ItemFieldSummary, PopupRequest, PopupResponse } from "../messaging/contract.ts";

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
}

/** Submitted-credential reports awaiting a save/update decision (ADR 0036 §4: zeroized once the
 * prompt is answered or dismissed, never written to `storage.local`/IndexedDB). In-memory only,
 * keyed by a one-time token handed to the content script — never the item/field data itself. */
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

/** `content-handler.ts`'s `credentials_submitted` handling: offers "save" when no saved item
 * matches the submitted page, "update" (naming the matching item) otherwise. `undefined` while
 * locked, or when nothing worth saving was captured (no password). */
export function offerSavePrompt(
  pageUrl: string,
  usernameValue: string | undefined,
  passwordValue: string | undefined,
): { readonly token: string; readonly suggestion: "save" | "update"; readonly itemTitle?: string } | undefined {
  if (session === undefined || passwordValue === undefined || passwordValue === "") {
    return undefined;
  }
  const username = usernameValue ?? "";
  const existing = findItemForUpdate(session, pageUrl);
  if (existing === undefined) {
    const token = addPendingSavePrompt({ action: "save", pageUrl, usernameValue: username, passwordValue });
    return { token, suggestion: "save" };
  }
  const token = addPendingSavePrompt({
    action: "update",
    pageUrl,
    usernameValue: username,
    passwordValue,
    updateItemId: existing.id,
  });
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
