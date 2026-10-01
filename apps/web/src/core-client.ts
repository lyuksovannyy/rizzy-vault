// The UI thread's end of the core Worker (ADR 0013 §4): typed calls over `postMessage`.
//
// The UI imports no wasm and holds no key. `call` sends one call and resolves with its value,
// or rejects with a `CallError` carrying the stable code. Byte-array arguments (typed secrets,
// import files) are transferred, so the UI keeps no copy of them.
// Only types come from packages/core here: the UI thread loads no wasm (`eslint.config.js`).

import {
  type CoreApi,
  type FromWorker,
  type Method,
  type ToWorker,
  BAD_MESSAGE,
  isFromWorker,
  transferables,
} from "./protocol.ts";

/** The part of a `Worker` this module uses, so tests can pass a fake. */
export interface WorkerPort {
  postMessage(message: ToWorker, transfer: Transferable[]): void;
  addEventListener(type: "message", listener: (event: MessageEvent<unknown>) => void): void;
}

/** Asks the user for the second factor; `null` when they cancel. */
export type TotpPrompt = () => Promise<string | null>;

/** A failed call: the core's stable code (packages/core `CoreError`), or one of `protocol.ts`. */
export class CallError extends Error {
  /** The stable code, such as `wrong_password_or_secret_key`. */
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "CallError";
    this.code = code;
  }
}

/** The awaited result type of a {@link CoreApi} method. */
type Result<M extends Method> = Awaited<ReturnType<CoreApi[M]>>;

/** A typed client of the core Worker. */
export class CoreClient {
  readonly #port: WorkerPort;
  readonly #pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: CallError) => void }
  >();
  #next = 1;
  #dead: string | undefined;
  #prompt: TotpPrompt = () => Promise.resolve(null);

  constructor(port: WorkerPort) {
    this.#port = port;
    port.addEventListener("message", (event) => this.#receive(event.data));
  }

  /** Sets who answers the Worker's second-factor prompts. */
  setTotpPrompt(prompt: TotpPrompt): void {
    this.#prompt = prompt;
  }

  /**
   * Fails every pending and later call with `code`: the Worker could not load or died
   * (`error` event of the Worker), so no answer will come.
   */
  fail(code: string): void {
    this.#dead = code;
    for (const waiter of this.#pending.values()) {
      waiter.reject(new CallError(code));
    }
    this.#pending.clear();
  }

  /** Calls `method` in the Worker. */
  call<M extends Method>(method: M, ...args: Parameters<CoreApi[M]>): Promise<Result<M>> {
    const id = this.#next++;
    const dead = this.#dead;
    if (dead !== undefined) {
      return Promise.reject(new CallError(dead));
    }
    return new Promise<Result<M>>((resolve, reject) => {
      this.#pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
      this.#port.postMessage({ kind: "call", id, method, args }, transferables(args));
    });
  }

  /** Handles one message from the Worker. */
  #receive(data: unknown): void {
    if (!isFromWorker(data)) {
      return;
    }
    const m: FromWorker = data;
    if (m.kind === "ask-totp") {
      void this.#prompt().then(
        (code) => this.#port.postMessage({ kind: "totp", id: m.id, code }, []),
        () => this.#port.postMessage({ kind: "totp", id: m.id, code: null }, []),
      );
      return;
    }
    const waiter = this.#pending.get(m.id);
    if (waiter === undefined) {
      return;
    }
    this.#pending.delete(m.id);
    if (m.ok) {
      waiter.resolve(m.value);
    } else {
      waiter.reject(new CallError(m.code === "" ? BAD_MESSAGE : m.code));
    }
  }
}

/** The stable code of anything a call rejected with. */
export function codeOf(e: unknown): string {
  return e instanceof CallError ? e.code : "unknown";
}

/** Encodes a typed secret as UTF-8 bytes for the core (packages/core `SecretInput`). */
export function secretBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
