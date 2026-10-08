// The long-lived context's message handling, shared between the Chromium offscreen document
// (`offscreen.ts`) and the Firefox background page (`background-page.ts`) — ADR 0036 §2: "one
// long-lived context holds the instance... for the whole extension lifetime." This is the ONE
// place that may import `@rizzy-vault/core` for value, not type (ADR 0036 §4; eslint
// restriction in `eslint.config.mjs`). The MV3 service worker (`background/service-worker.ts`)
// never imports this module: it only relays messages to whichever entry point is running.
import { generatePassphraseWithOptions, generatePasswordWithOptions } from "@rizzy-vault/core";

import { BindingsNotImplemented, lockDevice, unlockDevice } from "../core/bindings.ts";
import { AutoLockTimer, readAutoLockMs } from "./lifecycle.ts";
import { clearUnlockedSnapshot, hasSessionStorage, restoreUnlockedSnapshot } from "./session-store.ts";
import type { PopupRequest, PopupResponse } from "../messaging/contract.ts";

/** Whether the core holds an unlocked device right now. `unlockDevice` never actually succeeds
 * today (`core/bindings.ts`), so this is always `false` in practice; it is still real state
 * (not a constant) so the rest of this module, and its tests, do not special-case "always
 * locked" — that special case disappears on its own once the binding lands. */
let locked = true;

let autoLock: AutoLockTimer | undefined;

/** Starts the long-lived context: tries the `storage.session` fallback restore (ADR 0036 §2),
 * then starts the auto-lock timer if something was restored. Call once, at module load. The
 * timeout itself is the options page's saved, validated and bounded value
 * (`lifecycle.ts`'s `readAutoLockMs`), not the hard-coded default. */
export async function startCoreContext(ext: WebExtNamespace): Promise<void> {
  const autoLockMs = await readAutoLockMs(ext);
  autoLock = new AutoLockTimer(() => {
    void lock(ext);
  }, autoLockMs);
  if (!hasSessionStorage(ext)) {
    // No fallback on this browser build: nothing to restore, stay locked, same as a fresh
    // start. Recorded so the M2 spike notes (ADR 0036 §2) have a real signal, not a guess.
    return;
  }
  const snapshot = await restoreUnlockedSnapshot(ext);
  if (snapshot !== undefined) {
    // A real restore would reconstruct the unlocked handle from `snapshot` here. Until
    // `unlockDevice` exists, a present-but-unusable snapshot is treated as stale: it is
    // cleared rather than kept around pretending to be live state.
    await clearUnlockedSnapshot(ext);
  }
}

async function lock(ext: WebExtNamespace): Promise<void> {
  lockDevice();
  locked = true;
  autoLock?.stop();
  if (hasSessionStorage(ext)) {
    await clearUnlockedSnapshot(ext);
  }
}

/** Locks from outside a `PopupRequest` — the `chrome.idle`/`browser.idle` listener ADR 0036 §3
 * names alongside the timeout-based {@link AutoLockTimer} ("lock on `chrome.idle`/
 * `browser.idle` reaching `locked` or `idle`"). Exported so `listener.ts` can wire it without
 * reaching into this module's private `lock`. */
export function lockFromIdleState(ext: WebExtNamespace): Promise<void> {
  return lock(ext);
}

/** Handles one popup/options request (ADR 0036 §4: "coarse, one-call-per-action messages").
 * Every branch that would need an unlocked device answers with
 * {@link BindingsNotImplemented}'s code until `core/bindings.ts` is real; `generate_password`
 * and `get_status` work today because they need no device state. `ext` is needed only for the
 * `"lock"` branch's `storage.session` clear; every other branch ignores it. */
export async function handlePopupRequest(ext: WebExtNamespace, request: PopupRequest): Promise<PopupResponse> {
  autoLock?.activity();
  switch (request.type) {
    case "get_status":
      return { type: "status", locked };
    case "unlock":
      try {
        unlockDevice({ deviceStateRecord: new Uint8Array(0), masterPassword: request.masterPassword });
        // unlockDevice never returns today (see core/bindings.ts); this line is unreachable
        // but kept so the type of `locked`'s assignment below type-checks once it does return.
        locked = false;
        autoLock?.start();
        return { type: "unlocked" };
      } catch (e) {
        return { type: "error", code: e instanceof BindingsNotImplemented ? e.code : "unlock_failed" };
      }
    case "lock":
      await lock(ext);
      return { type: "locked" };
    case "list_items":
      return locked ? { type: "error", code: "locked" } : { type: "items", items: [] };
    case "reveal_field":
      return { type: "error", code: "locked" };
    case "generate_password":
      try {
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
