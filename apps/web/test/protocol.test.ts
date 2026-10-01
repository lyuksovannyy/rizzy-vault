// The UI ↔ Worker messages: shape checks, transfers, the client's call and second-factor
// round trips.
import { describe, expect, it } from "vitest";

import { CallError, CoreClient, type WorkerPort, codeOf } from "../src/core-client.ts";
import {
  type FromWorker,
  METHODS,
  type ToWorker,
  isFromWorker,
  isToWorker,
  transferables,
} from "../src/protocol.ts";

/** A port whose messages the test sees and answers. */
function fakePort() {
  const sent: { message: ToWorker; transfer: Transferable[] }[] = [];
  let listener: ((event: MessageEvent<unknown>) => void) | undefined;
  const port: WorkerPort = {
    postMessage: (message, transfer) => sent.push({ message, transfer }),
    addEventListener: (_type, l) => {
      listener = l;
    },
  };
  const reply = (data: FromWorker | unknown) => listener?.({ data } as MessageEvent<unknown>);
  return { port, sent, reply };
}

describe("message checks", () => {
  it("accepts only our calls", () => {
    expect(isToWorker({ kind: "call", id: 1, method: "items", args: [false] })).toBe(true);
    expect(isToWorker({ kind: "totp", id: 1, code: null })).toBe(true);
    expect(isToWorker({ kind: "call", id: 1, method: "constructor", args: [] })).toBe(false);
    expect(isToWorker({ kind: "call", id: 1, method: "__proto__", args: [] })).toBe(false);
    expect(isToWorker({ kind: "call", id: 1.5, method: "items", args: [] })).toBe(false);
    expect(isToWorker({ kind: "call", id: 1, method: "items", args: "x" })).toBe(false);
    expect(isToWorker({ kind: "totp", id: 1, code: 5 })).toBe(false);
    expect(isToWorker(null)).toBe(false);
    expect(isToWorker("call")).toBe(false);
    expect(METHODS).toContain("login");
    expect(new Set(METHODS).size).toBe(METHODS.length);
  });

  it("accepts only the Worker's answers", () => {
    expect(isFromWorker({ kind: "result", id: 1, ok: true, value: 1 })).toBe(true);
    expect(isFromWorker({ kind: "result", id: 1, ok: false, code: "locked" })).toBe(true);
    expect(isFromWorker({ kind: "result", id: 1, ok: false })).toBe(false);
    expect(isFromWorker({ kind: "ask-totp", id: 2 })).toBe(true);
    expect(isFromWorker({ kind: "other", id: 2 })).toBe(false);
  });

  it("transfers byte arrays, once each", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3]);
    const out = transferables(["x", a, [b, { nested: a }], 5]);
    expect(out).toEqual([a.buffer, b.buffer]);
  });
});

describe("CoreClient", () => {
  it("resolves and rejects calls by id, transferring secrets", async () => {
    const { port, sent, reply } = fakePort();
    const client = new CoreClient(port);
    const secret = new TextEncoder().encode("pw");
    const first = client.call("exportEncrypted", secret);
    const second = client.call("items", false);
    expect(sent.map((s) => s.message.kind)).toEqual(["call", "call"]);
    expect(sent[0]?.transfer).toEqual([secret.buffer]);
    reply({ kind: "result", id: 2, ok: true, value: [] });
    reply({ kind: "result", id: 1, ok: false, code: "locked" });
    await expect(second).resolves.toEqual([]);
    const error = await first.catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CallError);
    expect(codeOf(error)).toBe("locked");
    expect(codeOf(new Error("x"))).toBe("unknown");
  });

  it("answers the second-factor prompt, or cancels it", async () => {
    const { port, sent, reply } = fakePort();
    const client = new CoreClient(port);
    client.setTotpPrompt(() => Promise.resolve("123456"));
    reply({ kind: "ask-totp", id: 7 });
    await new Promise((r) => setTimeout(r, 0));
    expect(sent.at(-1)?.message).toEqual({ kind: "totp", id: 7, code: "123456" });
    client.setTotpPrompt(() => Promise.reject(new Error("closed")));
    reply({ kind: "ask-totp", id: 8 });
    await new Promise((r) => setTimeout(r, 0));
    expect(sent.at(-1)?.message).toEqual({ kind: "totp", id: 8, code: null });
  });

  it("fails pending and later calls when the Worker dies", async () => {
    const { port } = fakePort();
    const client = new CoreClient(port);
    const pending = client.call("items", false);
    client.fail("core_crashed");
    await expect(pending).rejects.toMatchObject({ code: "core_crashed" });
    await expect(client.call("status")).rejects.toMatchObject({ code: "core_crashed" });
  });

  it("ignores messages that are not the Worker's", () => {
    const { port, reply } = fakePort();
    new CoreClient(port);
    expect(() => reply({ kind: "result", id: 99, ok: true, value: 1 })).not.toThrow();
    expect(() => reply("garbage")).not.toThrow();
  });
});
