// SPDX-License-Identifier: AGPL-3.0-only

// The service worker's idle relay (ADR 0111 §3.1 items 1, 2, 3, 5; §7 step 3), with a recording
// fake `chrome` installed before `service-worker.ts` is imported: the `idle.onStateChanged`
// listener exists once the module has evaluated; `idle`/`locked` with an offscreen document sends
// exactly one `idle_state`; `active` sends nothing; no document means no message and no
// `createDocument`; `setDetectionInterval` gets `idle_minutes * 60` at start and after a
// `storage.onChanged` of `rizzy.lock_settings`, which also pushes one `lock_settings`; an
// `idle_status_query` from a content script gets no answer, one from the offscreen document gets
// the state and the record; the migration message writes only while the record is absent.
import { beforeAll, describe, expect, it, vi } from "vitest";

type Listener = (...args: never[]) => unknown;

function recordingEvent() {
  const listeners: Listener[] = [];
  return {
    listeners,
    event: {
      addListener: (l: Listener) => void listeners.push(l),
      removeListener: () => undefined,
    },
  };
}

const ID = "abcdefabcdefabcdefabcdefabcdefab";
const OWN_URL = "chrome-extension://" + ID + "/src/core-host/offscreen.html";
const RECORD10 = '{"v":1,"auto_lock":true,"idle_minutes":10,"lock_on_restart":true,"lock_on_sleep":true}';

const onMessage = recordingEvent();
const onStateChanged = recordingEvent();
const onChanged = recordingEvent();
const sent: unknown[] = [];
const intervals: number[] = [];
const local = new Map<string, unknown>([["rizzy.lock_settings", RECORD10]]);
let hasDocument = false;
let createDocument = 0;
/** The order of the module's first calls: a listener registered before the first storage read
 * was registered synchronously, before any `await`. */
const order: string[] = [];

const fake = {
  runtime: {
    id: ID,
    getURL: (p: string) => "chrome-extension://" + ID + "/" + p,
    sendMessage: async (m: unknown) => {
      sent.push(m);
      return undefined;
    },
    onMessage: onMessage.event,
    onInstalled: recordingEvent().event,
    onStartup: recordingEvent().event,
    connect: () => {
      throw new Error("unused");
    },
    onConnect: recordingEvent().event,
  },
  storage: {
    session: { get: async () => ({}), set: async () => undefined, remove: async () => undefined, clear: async () => undefined },
    local: {
      get: async (keys: string[]) => (order.push("storage.local.get"), Object.fromEntries(keys.filter((k) => local.has(k)).map((k) => [k, local.get(k)]))),
      set: async (items: Record<string, unknown>) => {
        for (const [k, v] of Object.entries(items)) {
          local.set(k, v);
        }
      },
      remove: async (k: string) => void local.delete(k),
      clear: async () => local.clear(),
    },
    onChanged: onChanged.event,
  },
  idle: {
    setDetectionInterval: (s: number) => void intervals.push(s),
    queryState: async (s: number) => (s === 600 ? "idle" : "active"),
    onStateChanged: {
      addListener: (l: Listener) => {
        onStateChanged.event.addListener(l);
        order.push("idle.onStateChanged");
      },
      removeListener: () => undefined,
    },
  },
  offscreen: {
    hasDocument: async () => hasDocument,
    createDocument: async () => {
      createDocument += 1;
      hasDocument = true;
    },
    closeDocument: async () => {
      hasDocument = false;
    },
  },
  tabs: { query: async () => [], create: async () => undefined, sendMessage: async () => undefined },
};

async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await Promise.resolve();
  }
}

/** Dispatches a runtime message to the service worker's listener; resolves to its answer, or
 * `"no answer"` when it neither answers synchronously nor keeps the channel open. */
async function dispatch(message: unknown, sender: object): Promise<unknown> {
  const listener = onMessage.listeners[0] as unknown as (m: unknown, s: object, r: (x: unknown) => void) => unknown;
  let answer: unknown = "no answer";
  let done: () => void = () => undefined;
  const answered = new Promise<void>((r) => (done = r));
  const keep = listener(message, sender, (x) => {
    answer = x;
    done();
  });
  if (keep === true) {
    await answered;
  }
  return answer;
}

beforeAll(async () => {
  vi.stubGlobal("chrome", fake);
  await import("../src/background/service-worker.ts");
  await settle();
});

describe("the service worker's idle relay (ADR 0111 §3.1)", () => {
  it("registers idle.onStateChanged during module evaluation, before any await", () => {
    expect(onStateChanged.listeners).toHaveLength(1);
    expect(onMessage.listeners).toHaveLength(1);
    expect(order.indexOf("idle.onStateChanged")).toBe(0);
    expect(order.indexOf("storage.local.get")).toBeGreaterThan(0);
  });

  it("sets the detection interval from the record at start", () => {
    expect(intervals[0]).toBe(600);
  });

  it("relays idle and locked only to an existing document, and nothing for active", async () => {
    const fire = onStateChanged.listeners[0] as unknown as (s: string) => void;
    sent.length = 0;
    hasDocument = false;
    fire("idle");
    await settle();
    expect(sent).toEqual([]);
    expect(createDocument).toBe(0);
    hasDocument = true;
    fire("idle");
    await settle();
    fire("active");
    await settle();
    fire("locked");
    await settle();
    expect(sent).toEqual([
      { type: "idle_state", state: "idle" },
      { type: "idle_state", state: "locked" },
    ]);
    expect(createDocument).toBe(0);
  });

  it("a storage change of the record resets the interval and pushes exactly one lock_settings", async () => {
    const one = '{"v":1,"auto_lock":true,"idle_minutes":1,"lock_on_restart":true,"lock_on_sleep":true}';
    local.set("rizzy.lock_settings", one);
    sent.length = 0;
    intervals.length = 0;
    hasDocument = true;
    const changed = onChanged.listeners[0] as unknown as (c: object, a: string) => void;
    changed({ "rizzy.lock_settings": { newValue: one } }, "local");
    await settle();
    expect(intervals).toEqual([60]);
    expect(sent).toEqual([{ type: "lock_settings", settings: one }]);
    changed({ other: { newValue: 1 } }, "local");
    changed({ "rizzy.lock_settings": { newValue: one } }, "sync");
    await settle();
    expect(sent).toHaveLength(1);
    local.set("rizzy.lock_settings", RECORD10);
  });

  it("answers idle_status_query from the offscreen document only", async () => {
    const tabSender = { id: ID, tab: { id: 3, url: "https://example.com/" }, url: "https://example.com/" };
    expect(await dispatch({ type: "idle_status_query" }, tabSender)).not.toMatchObject({ type: "idle_status" });
    expect(await dispatch({ type: "idle_status_query" }, { id: "other", url: "chrome-extension://other/x.html" })).toBe(
      "no answer",
    );
    expect(await dispatch({ type: "idle_status_query" }, { id: ID, url: OWN_URL })).toEqual({
      type: "idle_status",
      state: "idle",
      settings: RECORD10,
    });
  });

  it("sends the legacy value while the record is absent; a migration writes only then", async () => {
    const own = { id: ID, url: OWN_URL };
    local.delete("rizzy.lock_settings");
    local.set("rizzy.auto_lock_minutes", 30);
    expect(await dispatch({ type: "idle_status_query" }, own)).toEqual({
      type: "idle_status",
      state: "active",
      settings: null,
      legacy: 30,
    });
    const migrated = '{"v":1,"auto_lock":true,"idle_minutes":30,"lock_on_restart":true,"lock_on_sleep":true}';
    await dispatch({ type: "lock_settings_migrate", settings: migrated }, own);
    expect(local.get("rizzy.lock_settings")).toBe(migrated);
    expect(local.has("rizzy.auto_lock_minutes")).toBe(false);
    await dispatch({ type: "lock_settings_migrate", settings: RECORD10 }, own);
    expect(local.get("rizzy.lock_settings")).toBe(migrated);
    local.set("rizzy.lock_settings", RECORD10);
  });
});
