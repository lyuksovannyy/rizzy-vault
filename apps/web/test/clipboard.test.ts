// The clipboard is cleared after the timeout, only if it still holds our value, or when it
// cannot be read; a failed clear is retried on focus, and nothing asks for clipboard-read
// (THREAT_MODEL A14; `clipboard.ts`).
import { describe, expect, it } from "vitest";

import {
  CLEAR_AFTER_MS,
  ClipboardGuard,
  type ClipboardPort,
  type RetrySignals,
  type Timers,
} from "../src/clipboard.ts";

/** A fake clipboard, a manual timer and manual retry signals. */
function setup(options: { granted?: boolean } = {}) {
  const granted = options.granted ?? true;
  let text = "";
  let failWrites = 0;
  let reads = 0;
  let readNever = false;
  const clipboard: ClipboardPort = {
    writeText: (t) => {
      if (failWrites > 0) {
        failWrites -= 1;
        return Promise.reject(new Error("Document is not focused"));
      }
      text = t;
      return Promise.resolve();
    },
    readText: () => {
      reads += 1;
      // A read that waits on a browser prompt nobody answers.
      return readNever ? new Promise<string>(() => undefined) : Promise.resolve(text);
    },
    readGranted: () => Promise.resolve(granted),
  };
  const scheduled: { f: () => void; ms: number; cleared: boolean }[] = [];
  const timers: Timers = {
    set: (f, ms) => {
      const t = { f, ms, cleared: false };
      scheduled.push(t);
      return t;
    },
    clear: (h) => {
      if (h !== undefined) {
        (h as { cleared: boolean }).cleared = true;
      }
    },
  };
  const listeners = new Set<() => void>();
  const signals: RetrySignals = {
    subscribe(retry) {
      listeners.add(retry);
      return () => listeners.delete(retry);
    },
  };
  const settle = () => new Promise((r) => setTimeout(r, 0));
  const fire = async () => {
    for (const t of scheduled) {
      if (!t.cleared) {
        t.cleared = true;
        t.f();
      }
    }
    await settle();
  };
  const focus = async () => {
    for (const l of [...listeners]) {
      l();
    }
    await settle();
  };
  return {
    guard: new ClipboardGuard(clipboard, timers, signals),
    read: () => text,
    set: (t: string) => {
      text = t;
    },
    failNextWrites: (n: number) => {
      failWrites = n;
    },
    hangReads: () => {
      readNever = true;
    },
    reads: () => reads,
    listeners,
    scheduled,
    fire,
    focus,
  };
}

describe("ClipboardGuard", () => {
  it("clears our value after the timeout", async () => {
    const s = setup();
    await s.guard.copy("secret");
    expect(s.read()).toBe("secret");
    expect(s.scheduled[0]?.ms).toBe(CLEAR_AFTER_MS);
    expect(CLEAR_AFTER_MS).toBe(30_000);
    await s.fire();
    expect(s.read()).toBe("");
    expect(s.guard.pending).toBe(false);
  });

  it("leaves a value the user copied since, when it may read", async () => {
    const s = setup();
    await s.guard.copy("secret");
    s.set("something else");
    await s.fire();
    expect(s.read()).toBe("something else");
    expect(s.guard.pending).toBe(false);
  });

  it("never reads without the permission, and clears anyway", async () => {
    const s = setup({ granted: false });
    await s.guard.copy("secret");
    await s.fire();
    expect(s.reads()).toBe(0);
    expect(s.read()).toBe("");
  });

  it("keeps a clear that failed, and retries it on focus", async () => {
    const s = setup({ granted: false });
    await s.guard.copy("secret");
    s.failNextWrites(1);
    await s.fire();
    expect(s.read()).toBe("secret");
    expect(s.guard.pending).toBe(true);
    expect(s.listeners.size).toBe(1);
    await s.focus();
    expect(s.read()).toBe("");
    expect(s.guard.pending).toBe(false);
    expect(s.listeners.size).toBe(0);
  });

  it("keeps retrying until a write succeeds", async () => {
    const s = setup({ granted: false });
    await s.guard.copy("secret");
    s.failNextWrites(2);
    await s.guard.clearNow();
    await s.focus();
    expect(s.read()).toBe("secret");
    expect(s.guard.pending).toBe(true);
    await s.focus();
    expect(s.read()).toBe("");
    expect(s.guard.pending).toBe(false);
  });

  it("a newer copy replaces the pending clear and its retries", async () => {
    const s = setup();
    await s.guard.copy("one");
    s.failNextWrites(1);
    await s.guard.clearNow();
    expect(s.listeners.size).toBe(1);
    await s.guard.copy("two");
    expect(s.listeners.size).toBe(0);
    expect(s.scheduled[0]?.cleared).toBe(true);
    await s.guard.clearNow();
    expect(s.read()).toBe("");
  });

  it("clearNow without a copy does nothing", async () => {
    const s = setup();
    s.set("unrelated");
    await s.guard.clearNow();
    expect(s.read()).toBe("unrelated");
  });

  it("a hanging read holds only the clear, not its caller's other work", async () => {
    const s = setup();
    await s.guard.copy("secret");
    s.hangReads();
    let other = false;
    void s.guard.clearNow();
    other = true;
    await s.focus();
    expect(other).toBe(true);
    expect(s.guard.pending).toBe(true);
  });
});
