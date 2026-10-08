// `ensureOffscreenDocument` (`src/background/service-worker.ts`) must never let two concurrent
// callers both see `hasDocument() === false` and both call `chrome.offscreen.createDocument` —
// the second such call throws ("Only a single offscreen document may be created"). This is the
// one place that call is raced: a content-script message and the popup/options transport's
// `ensure_core` priming call can arrive together, and `onInstalled`/`onStartup` can fire
// alongside either.
//
// Importing `service-worker.ts` runs its module-level `webext()` call and registers listeners
// on the real `chrome`/`browser` global, so a minimal stub is installed on `globalThis.chrome`
// before the dynamic import below; the exported `ensureOffscreenDocument` is then exercised with
// its own fake `ext` parameter, independent of that module-level global.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

function fakeEvent<L>(): WebExtEvent<L> {
  return { addListener: () => undefined, removeListener: () => undefined };
}

function minimalGlobalStub(): WebExtNamespace {
  return {
    runtime: {
      id: "abcdefabcdefabcdefabcdefabcdefab",
      getURL: (path) => `chrome-extension://stub/${path}`,
      sendMessage: async () => undefined,
      onMessage: fakeEvent(),
      onInstalled: fakeEvent(),
      onStartup: fakeEvent(),
      connect: () => {
        throw new Error("not used by this test");
      },
      onConnect: fakeEvent(),
    },
    storage: {
      session: { get: async () => ({}), set: async () => undefined, remove: async () => undefined, clear: async () => undefined },
      local: { get: async () => ({}), set: async () => undefined, remove: async () => undefined, clear: async () => undefined },
    },
    idle: { setDetectionInterval: () => undefined, queryState: async () => "active", onStateChanged: fakeEvent() },
    tabs: { query: async () => [], create: async () => undefined },
  };
}

interface FakeOffscreen {
  readonly ext: WebExtNamespace;
  readonly counters: { createDocument: number; hasDocument: number };
}

function fakeOffscreenExt(hasDocumentInitially: boolean): FakeOffscreen {
  let hasDocument = hasDocumentInitially;
  const counters = { createDocument: 0, hasDocument: 0 };
  const ext: WebExtNamespace = {
    ...minimalGlobalStub(),
    offscreen: {
      hasDocument: async () => {
        counters.hasDocument += 1;
        return hasDocument;
      },
      createDocument: async () => {
        counters.createDocument += 1;
        hasDocument = true;
      },
      closeDocument: async () => {
        hasDocument = false;
      },
    },
  };
  return { ext, counters };
}

describe("ensureOffscreenDocument", () => {
  let ensureOffscreenDocument: (ext: WebExtNamespace) => Promise<void>;

  beforeAll(async () => {
    vi.stubGlobal("chrome", minimalGlobalStub());
    ({ ensureOffscreenDocument } = await import("../src/background/service-worker.ts"));
  });

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  it("creates the document once when none exists", async () => {
    const { ext, counters } = fakeOffscreenExt(false);
    await ensureOffscreenDocument(ext);
    expect(counters.createDocument).toBe(1);
  });

  it("is a no-op when the document already exists", async () => {
    const { ext, counters } = fakeOffscreenExt(true);
    await ensureOffscreenDocument(ext);
    expect(counters.createDocument).toBe(0);
  });

  it("is a no-op on Firefox (no offscreen API)", async () => {
    const ext: WebExtNamespace = minimalGlobalStub();
    expect(ext.offscreen).toBeUndefined();
    await expect(ensureOffscreenDocument(ext)).resolves.toBeUndefined();
  });

  it("serializes two concurrent callers into exactly one createDocument call", async () => {
    const { ext, counters } = fakeOffscreenExt(false);
    await Promise.all([ensureOffscreenDocument(ext), ensureOffscreenDocument(ext)]);
    expect(counters.createDocument).toBe(1);
  });

  it("re-checks hasDocument on a later call after the in-flight attempt settled", async () => {
    const { ext, counters } = fakeOffscreenExt(false);
    await ensureOffscreenDocument(ext);
    expect(counters.createDocument).toBe(1);
    // The document now exists (the fake's `createDocument` flips its internal flag): a later,
    // non-concurrent call must not create a second one.
    await ensureOffscreenDocument(ext);
    expect(counters.createDocument).toBe(1);
  });
});
