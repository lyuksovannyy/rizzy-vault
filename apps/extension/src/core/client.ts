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
import type { PopupRequest, PopupResponse } from "../messaging/contract.ts";
import { ENSURE_CORE_MESSAGE } from "../background/ensure-core.ts";

export type Transport = (request: PopupRequest) => Promise<PopupResponse>;

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
export class ExtensionClient {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  async status(): Promise<{ locked: boolean; enrolled: boolean; serverOrigin?: string }> {
    const response = await this.#transport({ type: "get_status" });
    if (response.type !== "status") {
      throw this.#unexpected(response);
    }
    return {
      locked: response.locked,
      enrolled: response.enrolled,
      ...(response.serverOrigin !== undefined ? { serverOrigin: response.serverOrigin } : {}),
    };
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

  async sync(): Promise<void> {
    const response = await this.#transport({ type: "sync" });
    if (response.type !== "synced") {
      throw this.#unexpected(response);
    }
  }

  async listItems(): Promise<ReadonlyArray<{ itemId: string; title: string; username: string }>> {
    const response = await this.#transport({ type: "list_items" });
    if (response.type !== "items") {
      throw this.#unexpected(response);
    }
    return response.items;
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
