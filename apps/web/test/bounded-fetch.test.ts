// Every Worker request has a deadline, and a lock aborts the requests in flight, so a stalled
// server cannot hold the Worker's queue (`bounded-fetch.ts`).
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Transport } from "@rizzy-vault/core";

import { BoundedTransport, REQUEST_TIMEOUT_MS } from "../src/bounded-fetch.ts";

/** A fetch that never answers until its signal aborts. */
const stalledFetch: typeof fetch = (_input, init) =>
  new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
  });

/** A transport like packages/core's: a failed fetch becomes `transport_failed`. */
const over =
  (fetchImpl: typeof fetch): Transport =>
  async (request) => {
    let response: Response;
    try {
      response = await fetchImpl(`https://vault.example${request.path}`, { method: request.method });
    } catch {
      throw new Error("transport_failed");
    }
    return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
  };

const request: Parameters<Transport>[0] = { method: "GET", path: "/api/meta", headers: {}, body: undefined };

afterEach(() => {
  vi.useRealTimers();
});

describe("BoundedTransport", () => {
  it("fails a request that outlives its deadline", async () => {
    vi.useFakeTimers();
    const bounded = new BoundedTransport(over, stalledFetch);
    const answer = bounded.transport(request);
    const check = expect(answer).rejects.toThrow("transport_failed");
    expect(bounded.inFlight).toBe(1);
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);
    await check;
    expect(bounded.inFlight).toBe(0);
  });

  it("abortAll fails every request in flight at once", async () => {
    const bounded = new BoundedTransport(over, stalledFetch, 1_000_000);
    const one = bounded.transport(request);
    const two = bounded.transport(request);
    bounded.abortAll();
    await expect(one).rejects.toThrow("transport_failed");
    await expect(two).rejects.toThrow("transport_failed");
    expect(bounded.inFlight).toBe(0);
  });

  it("passes answers through and releases the request", async () => {
    let signal: AbortSignal | undefined;
    const ok: typeof fetch = (_input, init) => {
      signal = init?.signal ?? undefined;
      return Promise.resolve(new Response(new Uint8Array([1, 2, 3]), { status: 200 }));
    };
    const bounded = new BoundedTransport(over, ok);
    const answer = await bounded.transport(request);
    expect(answer.status).toBe(200);
    expect([...answer.body]).toEqual([1, 2, 3]);
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(bounded.inFlight).toBe(0);
  });

  it("allows a minute per request", () => {
    expect(REQUEST_TIMEOUT_MS).toBe(60_000);
  });
});
