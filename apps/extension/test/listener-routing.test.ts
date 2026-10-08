// `installCoreContextListener`'s `acceptContentScripts` routing (`core-host/listener.ts`):
// `false` (Chromium: the service worker owns content-script validation) must ignore a raw
// content-script sender outright; `true` (Firefox: no service worker exists) must validate and
// handle it directly. Pure logic against a fake `WebExtNamespace` — no real browser APIs.
import { describe, expect, it, vi } from "vitest";

import { installCoreContextListener } from "../src/core-host/listener.ts";

type MessageListener = (message: unknown, sender: WebExtMessageSender, sendResponse: (response?: unknown) => void) => boolean | void;

function fakeEvent<L>(): WebExtEvent<L> & { listeners: L[] } {
  const listeners: L[] = [];
  return {
    listeners,
    addListener: (l: L) => {
      listeners.push(l);
    },
    removeListener: (l: L) => {
      const i = listeners.indexOf(l);
      if (i >= 0) {
        listeners.splice(i, 1);
      }
    },
  };
}

function fakeStorageArea(): WebExtStorageArea {
  const data = new Map<string, unknown>();
  return {
    get: async (keys) => {
      if (keys === undefined || keys === null) {
        return Object.fromEntries(data);
      }
      const out: Record<string, unknown> = {};
      for (const k of Array.isArray(keys) ? keys : [keys]) {
        if (data.has(k)) {
          out[k] = data.get(k);
        }
      }
      return out;
    },
    set: async (items) => {
      for (const [k, v] of Object.entries(items)) {
        data.set(k, v);
      }
    },
    remove: async (keys) => {
      for (const k of Array.isArray(keys) ? keys : [keys]) {
        data.delete(k);
      }
    },
    clear: async () => {
      data.clear();
    },
  };
}

const EXT_ID = "abcdefabcdefabcdefabcdefabcdefab";

function fakeExt(): WebExtNamespace {
  return {
    runtime: {
      id: EXT_ID,
      getURL: (path) => `chrome-extension://${EXT_ID}/${path}`,
      sendMessage: async () => undefined,
      onMessage: fakeEvent<MessageListener>(),
      onInstalled: fakeEvent<() => void>(),
      onStartup: fakeEvent<() => void>(),
      connect: () => {
        throw new Error("not used by this test");
      },
      onConnect: fakeEvent(),
    },
    storage: { session: fakeStorageArea(), local: fakeStorageArea() },
    idle: {
      setDetectionInterval: () => undefined,
      queryState: async () => "active",
      onStateChanged: fakeEvent(),
    },
    tabs: { query: async () => [], create: async () => undefined },
  };
}

function installedListener(ext: WebExtNamespace): MessageListener {
  const onMessage = ext.runtime.onMessage as WebExtEvent<MessageListener> & { listeners: MessageListener[] };
  const listener = onMessage.listeners[0];
  if (listener === undefined) {
    throw new Error("installCoreContextListener did not register a listener");
  }
  return listener;
}

const fieldsDetected = { type: "fields_detected", pageUrl: "https://example.com", isTopFrame: true, fields: [] };

describe("installCoreContextListener: acceptContentScripts routing", () => {
  it("ignores a real content-script sender when acceptContentScripts is false (Chromium)", () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(fieldsDetected, { id: EXT_ID, tab: { url: "https://example.com" } }, sendResponse);
    expect(result).toBeUndefined();
    expect(sendResponse).not.toHaveBeenCalled();
  });

  it("validates and handles a real content-script sender when acceptContentScripts is true (Firefox)", () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: true });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(fieldsDetected, { id: EXT_ID, tab: { url: "https://example.com" } }, sendResponse);
    expect(result).toBe(true);
    expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ type: "candidates" }));
  });

  it("ignores a sender from a different extension even when accepting content scripts", () => {
    // Chrome would never actually deliver this (no `externally_connectable`), but
    // `isContentScriptSender`'s id check means it is not even routed as a content script here:
    // it falls through to the `isOwnExtensionPage` branch, which also rejects the id, so
    // nothing responds at all — a stricter outcome than the old "accept any `sender.tab`,
    // then reject inside the try/catch" path, not a weaker one.
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: true });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(fieldsDetected, { id: "some-other-extension", tab: { url: "https://example.com" } }, sendResponse);
    expect(result).toBeUndefined();
    expect(sendResponse).not.toHaveBeenCalled();
  });

  it("still answers a popup get_status request when acceptContentScripts is true", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: true });
    const sendResponse = vi.fn();
    const result = installedListener(ext)({ type: "get_status" }, { id: EXT_ID }, sendResponse);
    expect(result).toBe(true);
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith({ type: "status", locked: true }));
  });

  // Regression test for a real bug found while writing this change's E2E coverage: measured
  // empirically against a real Chromium build, a `chrome.offscreen` document's own `chrome`
  // object has no `idle` or `storage` namespace at all (both `undefined`), unlike every other
  // extension page. The previous code called `ext.idle.setDetectionInterval` *before*
  // registering the `onMessage` listener below, so that `TypeError` aborted
  // `installCoreContextListener` before the listener was ever installed: every popup, options
  // and content-script message landed in a context with nothing listening, and
  // `ext.runtime.sendMessage` resolved to `undefined` forever (the exact failure the "popup
  // opens and shows the locked state" E2E test caught). `fakeExt` normally supplies both
  // namespaces (every other test in this file keeps exercising that common case); this one
  // omits them to prove the listener still registers and answers without either.
  it("still registers and answers get_status when ext.idle and ext.storage are both absent", async () => {
    // `idle`/`storage` omitted entirely, not set to `undefined` (`exactOptionalPropertyTypes`
    // in `tsconfig.json` distinguishes the two): an object missing an optional property is a
    // valid `WebExtNamespace`, matching what the real `chrome` object inside an offscreen
    // document actually looks like.
    const { idle, storage, ...withoutIdleOrStorage } = fakeExt();
    void idle;
    void storage;
    const ext: WebExtNamespace = withoutIdleOrStorage;
    expect(() => installCoreContextListener(ext, { acceptContentScripts: false })).not.toThrow();
    const sendResponse = vi.fn();
    const result = installedListener(ext)({ type: "get_status" }, { id: EXT_ID }, sendResponse);
    expect(result).toBe(true);
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith({ type: "status", locked: true }));
  });
});
