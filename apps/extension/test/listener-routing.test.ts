// `installCoreContextListener`'s `acceptContentScripts` routing (`core-host/listener.ts`):
// `false` (Chromium: the service worker owns content-script validation) must ignore a raw
// content-script sender outright; `true` (Firefox: no service worker exists) must validate and
// handle it directly. Pure logic against a fake `WebExtNamespace` — no real browser APIs.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { installCoreContextListener } from "../src/core-host/listener.ts";
import { FakeIndexedDBFactory } from "./support/fake-idb.ts";

// `get_status` now reads `account-config.ts`'s own IndexedDB database directly (never
// `ext.storage` — see that module's doc comment for why), so every test below that reaches
// `handlePopupRequest` needs a `globalThis.indexedDB`, same as a real extension page has. This
// environment (`vite.config.ts`'s `environment: "node"`) has none by default; a fresh fake per
// test keeps one test's "enrolled" state from leaking into the next.
beforeEach(() => {
  (globalThis as { indexedDB: IDBFactory }).indexedDB = new FakeIndexedDBFactory() as unknown as IDBFactory;
});

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
    tabs: { query: async () => [], create: async () => undefined, sendMessage: async () => undefined },
  };
}

const EXT_ORIGIN = `chrome-extension://${EXT_ID}`;

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

  it("validates and handles a real content-script sender when acceptContentScripts is true (Firefox)", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: true });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(fieldsDetected, { id: EXT_ID, tab: { url: "https://example.com" } }, sendResponse);
    expect(result).toBe(true);
    // Locked (nothing enrolled/unlocked in this test's fake extension), so a locked
    // `content_error`, not `candidates` — `handleContentScriptRequest` is async now
    // (`core-context.ts`'s `save_prompt_resolved` handling needs to await a core call), so the
    // response arrives on a later microtask.
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ type: "content_error" })));
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
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith({ type: "status", locked: true, enrolled: false }));
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
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith({ type: "status", locked: true, enrolled: false }));
  });
});

const inlineMenuFillChosen = { type: "inline_menu_fill_chosen", itemId: "item-1", confirmedEquivalence: false };

// The security fix this suite now also covers: `inline_menu_fill_chosen` must only ever be
// honoured from the one sender `isInlineMenuSender` vouches for (the extension-origin
// inline-menu iframe), never from a real content script sending the exact same message shape.
describe("installCoreContextListener: inline_menu_fill_chosen routing (ADR 0040)", () => {
  it("refuses a real content-script sender's inline_menu_fill_chosen, even when acceptContentScripts is true", async () => {
    // A content script's `sender.origin` is the page's own (or absent) — never this
    // extension's — so `isInlineMenuSender` never matches it; `isContentScriptSender` does, and
    // routes it through ordinary content-script validation instead, where
    // `parseFromContentScript` refuses the unknown type. The one message type this extension
    // grants a decrypted credential for is never reachable by a content script's own message,
    // however it shapes it.
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: true });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(inlineMenuFillChosen, { id: EXT_ID, tab: { url: "https://example.com/login" } }, sendResponse);
    expect(result).toBe(true);
    await vi.waitFor(() =>
      expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ type: "content_error" })),
    );
  });

  it("ignores a content-script sender's inline_menu_fill_chosen when acceptContentScripts is false (Chromium)", () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(inlineMenuFillChosen, { id: EXT_ID, tab: { url: "https://example.com/login" } }, sendResponse);
    expect(result).toBeUndefined();
    expect(sendResponse).not.toHaveBeenCalled();
  });

  it("routes a genuine inline-menu-iframe sender to the privileged handler regardless of acceptContentScripts", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const sender: WebExtMessageSender = { id: EXT_ID, origin: EXT_ORIGIN, tab: { url: "https://example.com/login" } };
    const result = installedListener(ext)(inlineMenuFillChosen, sender, sendResponse);
    expect(result).toBe(true);
    // Locked (nothing enrolled/unlocked in this test's fake extension), so a locked
    // `content_error` — proof this reached `handleInlineMenuFillRequest` at all (a sender this
    // listener did not recognise would get no response, as the two tests above show).
    await vi.waitFor(() =>
      expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ type: "content_error" })),
    );
  });

  it("refuses a malformed inline-menu-iframe request (missing confirmedEquivalence)", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const sender: WebExtMessageSender = { id: EXT_ID, origin: EXT_ORIGIN, tab: { url: "https://example.com/login" } };
    const result = installedListener(ext)({ type: "inline_menu_fill_chosen", itemId: "item-1" }, sender, sendResponse);
    expect(result).toBe(true);
    expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ type: "content_error" }));
  });
});

const inlineMenuGeneratePasswordChosen = { type: "inline_menu_generate_password_chosen" };

// Gap 32 in the M2 gap audit: the generator's own privileged request, same ADR 0040 sender gate
// as `inline_menu_fill_chosen` just above — mirrors that describe block's three routing cases.
describe("installCoreContextListener: inline_menu_generate_password_chosen routing (ADR 0040)", () => {
  it("refuses a real content-script sender's inline_menu_generate_password_chosen, even when acceptContentScripts is true", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: true });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(
      inlineMenuGeneratePasswordChosen,
      { id: EXT_ID, tab: { url: "https://example.com/login" } },
      sendResponse,
    );
    expect(result).toBe(true);
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ type: "content_error" })));
  });

  it("ignores a content-script sender's inline_menu_generate_password_chosen when acceptContentScripts is false (Chromium)", () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(
      inlineMenuGeneratePasswordChosen,
      { id: EXT_ID, tab: { url: "https://example.com/login" } },
      sendResponse,
    );
    expect(result).toBeUndefined();
    expect(sendResponse).not.toHaveBeenCalled();
  });

  it("routes a genuine inline-menu-iframe sender to the privileged handler, never back through the iframe (ADR 0040)", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const sender: WebExtMessageSender = { id: EXT_ID, origin: EXT_ORIGIN, tab: { id: 7, url: "https://example.com/login" } };
    const result = installedListener(ext)(inlineMenuGeneratePasswordChosen, sender, sendResponse);
    expect(result).toBe(true);
    // Whatever the outcome (wasm may or may not be available in this test environment), the
    // response must never carry a generated value itself (ADR 0040: "never back to the
    // iframe") — only ever the plain dispatch acknowledgement or a content_error.
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalled());
    const response = sendResponse.mock.calls[0]?.[0];
    expect(["inline_menu_generate_password_dispatched", "content_error"]).toContain(
      (response as { type?: string } | undefined)?.type,
    );
    expect(response).not.toHaveProperty("value");
    expect(response).not.toHaveProperty("password");
  });
});

// `passkey_ceremony_approved`/`passkey_ceremony_declined` (ADR 0039 §2) reuse the exact same
// `isInlineMenuSender` gate as `inline_menu_fill_chosen` (`messaging/contract.ts`'s own doc on
// why): a real content script can never reach `handlePasskeyCeremonyApproval` either, only the
// extension-origin consent iframe can.
describe("installCoreContextListener: passkey_ceremony routing (ADR 0039 §2, ADR 0040's pattern)", () => {
  const approved = { type: "passkey_ceremony_approved", ceremonyToken: "tok-1" };

  it("refuses a real content-script sender's passkey_ceremony_approved, even when acceptContentScripts is true", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: true });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(approved, { id: EXT_ID, tab: { url: "https://example.com/login" } }, sendResponse);
    expect(result).toBe(true);
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ type: "content_error" })));
  });

  it("routes a genuine passkey-consent-iframe sender to the privileged handler", async () => {
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const sender: WebExtMessageSender = { id: EXT_ID, origin: EXT_ORIGIN, tab: { id: 1, url: "https://example.com/login" } };
    const result = installedListener(ext)(approved, sender, sendResponse);
    expect(result).toBe(true);
    // No pending ceremony exists in this test's fake extension, so `handlePasskeyCeremonyApproval`
    // still answers an acknowledgement (never a secret) — proof this reached the privileged
    // handler at all, same reasoning as the inline-menu-fill-request test above.
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith({ type: "passkey_ceremony_dispatched" }));
  });

  it("ignores a passkey-consent-iframe sender's ceremony message when acceptContentScripts is false and sender.tab is unset", () => {
    // `sender.tab` unset means `isInlineMenuSender` cannot match (module docs: it needs a real
    // http(s) tab to be embedded in) — falls through to `isOwnExtensionPage`, which also
    // mishandles an unrecognised message shape as "nothing to do" (returns `undefined`).
    const ext = fakeExt();
    installCoreContextListener(ext, { acceptContentScripts: false });
    const sendResponse = vi.fn();
    const result = installedListener(ext)(approved, { id: EXT_ID, origin: EXT_ORIGIN }, sendResponse);
    expect(result).toBeUndefined();
    expect(sendResponse).not.toHaveBeenCalled();
  });
});
