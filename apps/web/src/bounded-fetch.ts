// The core Worker's transport: every request gets a deadline, and a lock aborts every request in
// flight. Without them, one stalled request (a dead TCP path, a proxy holding the connection)
// holds the Worker's one call queue (`core-worker.ts`), and every later call, the login after a
// lock included, waits behind it until the browser gives up, which can take minutes.
//
// Each request runs through packages/core's `fetchTransport` with a `fetch` that carries an
// `AbortSignal`. The deadline runs until the whole answer is read: aborting the signal also
// fails the reading of a body already under way. An aborted or timed-out request therefore
// fails like any network failure, as `transport_failed`, and the core treats it as a request
// whose outcome is unknown, as it does for any network failure (ADR 0028).

import type { Transport } from "@rizzy-vault/core";

/** How long one request may take, from sending to the last byte of the answer. */
export const REQUEST_TIMEOUT_MS = 60_000;

/** Timer functions, injectable for tests. */
export interface DeadlineTimers {
  set(f: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

const browserTimers: DeadlineTimers = {
  set: (f, ms) => setTimeout(f, ms),
  clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/** Makes the transport over one `fetch` (packages/core's `fetchTransport`, bound to an origin). */
export type TransportOver = (fetchImpl: typeof fetch) => Transport;

/** A transport with a deadline per request, and `abortAll` (module docs). */
export class BoundedTransport {
  readonly #make: TransportOver;
  readonly #inner: typeof fetch;
  readonly #timeoutMs: number;
  readonly #timers: DeadlineTimers;
  /** The controllers of the requests in flight. */
  readonly #inFlight = new Set<AbortController>();

  constructor(
    make: TransportOver,
    inner: typeof fetch,
    timeoutMs: number = REQUEST_TIMEOUT_MS,
    timers: DeadlineTimers = browserTimers,
  ) {
    this.#make = make;
    this.#inner = inner;
    this.#timeoutMs = timeoutMs;
    this.#timers = timers;
  }

  /** The transport to hand to packages/core. */
  readonly transport: Transport = async (request) => {
    const controller = new AbortController();
    this.#inFlight.add(controller);
    const timer = this.#timers.set(() => controller.abort(), this.#timeoutMs);
    const fetchImpl: typeof fetch = (input, init) =>
      this.#inner(input, { ...init, signal: controller.signal });
    try {
      return await this.#make(fetchImpl)(request);
    } finally {
      this.#timers.clear(timer);
      this.#inFlight.delete(controller);
    }
  };

  /** Aborts every request in flight (on lock). */
  abortAll(): void {
    for (const controller of this.#inFlight) {
      controller.abort();
    }
    this.#inFlight.clear();
  }

  /** The number of requests in flight (for tests). */
  get inFlight(): number {
    return this.#inFlight.size;
  }
}
