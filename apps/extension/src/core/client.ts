// SPDX-License-Identifier: AGPL-3.0-only

// The messaging-backed client the popup and options page use to reach the long-lived context
// (ADR 0036 §4: "they reach the core only through packages/core's messaging-backed client").
//
// Placement note (documented, conservative reading): `packages/core` today is a *direct* wasm
// wrapper (`packages/core/src/index.ts` calls `initWasm`/`init` itself) that the web vault loads
// inside its own dedicated Worker — it is not a messaging transport, and nothing in
// `@rizzy-vault/core` is extension-aware. Turning it into one, or adding a second export shape
// to it, would change a module the web vault already ships on. Given the ADR gate's "min
// scope" and the risk of touching shared, already-shipped code for a wording match, this client
// lives in `apps/extension` instead, built from the same typed message shapes
// (`messaging/contract.ts`) `core-context.ts` answers with. If the owner wants the literal
// `packages/core`-relocation, moving this file there later is a pure move, since it already
// depends on nothing extension-specific beyond the injected `transport`.
import type { PopupRecoveryNotice, PopupRequest, PopupResponse } from "../messaging/contract.ts";
import { ENSURE_CORE_MESSAGE } from "../background/ensure-core.ts";
import { base64ToBytes } from "../messaging/bytes.ts";

export type Transport = (request: PopupRequest) => Promise<PopupResponse>;

/** A pending-recovery notice from a response, or `undefined` for none or one of the wrong
 * shape (ADR 0045; it only ever feeds the banner, INV-70). */
export function recoveryNotice(value: unknown): PopupRecoveryNotice | undefined {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const v = value as Record<string, unknown>;
  const opened = v["openedAtMs"];
  const available = v["availableAtMs"];
  const last = v["lastRecoveryAtMs"];
  if (typeof opened !== "number" || typeof available !== "number" || (last !== undefined && typeof last !== "number")) {
    return undefined;
  }
  return { openedAtMs: opened, availableAtMs: available, ...(typeof last === "number" ? { lastRecoveryAtMs: last } : {}) };
}

export class ClientError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ClientError";
    this.code = code;
  }
}

/** One call per action (ADR 0036 §4), each throwing {@link ClientError} on an `"error"`
 * response rather than returning a tagged union the UI has to switch on for every call. */
/** {@link ExtensionClient.removalCheck}'s answer (`messaging/contract.ts`'s `removal_check`). */
export interface RemovalCheck {
  readonly unlocked: boolean;
  readonly refusal?: string;
  readonly uploaded?: boolean;
  readonly unsentChanges?: number;
  readonly unsentSnapshots?: number;
}

export class ExtensionClient {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  async status(): Promise<{
    locked: boolean;
    enrolled: boolean;
    serverOrigin?: string;
    recoveryNotice?: PopupRecoveryNotice;
    alarms?: readonly string[];
  }> {
    const response = await this.#transport({ type: "get_status" });
    if (response.type !== "status") {
      throw this.#unexpected(response);
    }
    const notice = recoveryNotice(response.recoveryNotice);
    const alarms = Array.isArray(response.alarms) ? response.alarms.filter((a) => typeof a === "string") : [];
    return {
      locked: response.locked,
      enrolled: response.enrolled,
      ...(response.serverOrigin !== undefined ? { serverOrigin: response.serverOrigin } : {}),
      ...(notice !== undefined ? { recoveryNotice: notice } : {}),
      ...(alarms.length > 0 ? { alarms } : {}),
    };
  }

  /** "Remove this device", step 1: the refusal under an alarm, or the upload of the unsent own
   * rows (while unlocked) and what removal would still lose. Deletes nothing. */
  async removalCheck(): Promise<RemovalCheck> {
    const response = await this.#transport({ type: "removal_check" });
    if (response.type !== "removal_check") {
      throw this.#unexpected(response);
    }
    return {
      unlocked: response.unlocked,
      ...(response.refusal !== undefined ? { refusal: response.refusal } : {}),
      ...(response.uploaded !== undefined ? { uploaded: response.uploaded } : {}),
      ...(response.unsentChanges !== undefined ? { unsentChanges: response.unsentChanges } : {}),
      ...(response.unsentSnapshots !== undefined ? { unsentSnapshots: response.unsentSnapshots } : {}),
    };
  }

  /** "Remove this device", step 2, after the user confirmed: deletes the local data. */
  async removeDevice(): Promise<void> {
    const response = await this.#transport({ type: "remove_device" });
    if (response.type !== "removed") {
      throw this.#unexpected(response);
    }
  }

  async enrol(input: {
    readonly serverOrigin: string;
    readonly loginName: string;
    readonly secretKey: string;
    readonly masterPassword: string;
    readonly totp?: string;
  }): Promise<void> {
    const response = await this.#transport({ type: "enrol", ...input });
    if (response.type !== "enrolled") {
      throw this.#unexpected(response);
    }
  }

  async unlock(masterPassword: string): Promise<void> {
    const response = await this.#transport({ type: "unlock", masterPassword });
    if (response.type !== "unlocked") {
      throw this.#unexpected(response);
    }
  }

  async lock(): Promise<void> {
    const response = await this.#transport({ type: "lock" });
    if (response.type !== "locked") {
      throw this.#unexpected(response);
    }
  }

  /** Syncs; returns the pending-recovery notice of the sync's account answer, if it had one
   * (ADR 0045; advisory only, INV-70). */
  async sync(): Promise<PopupRecoveryNotice | undefined> {
    const response = await this.#transport({ type: "sync" });
    if (response.type !== "synced") {
      throw this.#unexpected(response);
    }
    return recoveryNotice(response.recoveryNotice);
  }

  async listItems(): Promise<
    ReadonlyArray<{ itemId: string; title: string; username: string; websiteHost?: string }>
  > {
    const response = await this.#transport({ type: "list_items" });
    if (response.type !== "items") {
      throw this.#unexpected(response);
    }
    return response.items;
  }

  /** The icon of an item's website host (ADR 0052 point 6): PNG bytes, or `null` for none.
   * Throws {@link ClientError} with `server_rate_limited` when the role asks to wait. */
  async itemIcon(websiteHost: string): Promise<Uint8Array | null> {
    const response = await this.#transport({ type: "item_icon", websiteHost });
    if (response.type === "icon") {
      return response.png === null ? null : base64ToBytes(response.png);
    }
    throw this.#unexpected(response);
  }

  async itemFields(
    itemId: string,
  ): Promise<ReadonlyArray<{ key: string; kind: string; concealed: boolean; value: string | undefined }>> {
    const response = await this.#transport({ type: "item_fields", itemId });
    if (response.type !== "fields") {
      throw this.#unexpected(response);
    }
    return response.fields;
  }

  async revealField(itemId: string, fieldId: string): Promise<string> {
    const response = await this.#transport({ type: "reveal_field", itemId, fieldId });
    if (response.type !== "revealed") {
      throw this.#unexpected(response);
    }
    return response.value;
  }

  async generatePassword(kind: "password" | "passphrase", length: number): Promise<string> {
    const response = await this.#transport({ type: "generate_password", options: { kind, length } });
    if (response.type !== "generated") {
      throw this.#unexpected(response);
    }
    return response.value;
  }

  #unexpected(response: PopupResponse): ClientError {
    return new ClientError(response.type === "error" ? response.code : `unexpected_response:${response.type}`);
  }
}

/** The real transport: one `chrome.runtime.sendMessage` round trip per call, exactly what
 * `core-host/listener.ts` answers directly (no service-worker hop for popup/options, ADR 0036
 * §4) — except for a one-time priming call first (see `primeCore` below). */
export function createRuntimeTransport(ext: WebExtNamespace): Transport {
  let primed: Promise<void> | undefined;
  /** Makes sure the offscreen document exists before the first real request ever reaches
   * `ext.runtime.sendMessage` (fixes "popup opens before any content script has run on
   * Chromium": nothing but the content-script path used to call `ensureOffscreenDocument`).
   * Firefox has no offscreen document to create — nothing in `background/service-worker.ts`
   * runs there, and `background-page.ts`'s listener simply ignores a message type it does not
   * recognise — so a timeout or any other failure here is swallowed, never surfaced to the
   * caller, on either browser: this call is a best-effort nudge, not a request with its own
   * error semantics. */
  const primeCore = (): Promise<void> => {
    primed ??= ext.runtime.sendMessage(ENSURE_CORE_MESSAGE).then(
      () => undefined,
      () => undefined,
    );
    return primed;
  };
  return async (request) => {
    await primeCore();
    return (await ext.runtime.sendMessage(request)) as PopupResponse;
  };
}
