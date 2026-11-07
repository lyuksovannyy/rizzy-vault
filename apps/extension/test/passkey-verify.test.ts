// SPDX-License-Identifier: AGPL-3.0-only

// ADR 0110 §5, §7, §8 (INV-123 "Verified by"): the shim's userVerification relaying rules, the
// ceremony store's peek / take / awaiting_verification / one-per-tab rules, the popup's
// verification (five wrong passwords decline, the live binding, the same `now` at signing), the
// popup-only sender check, and the service worker's badge relay sender check.
import { describe, expect, it, vi } from "vitest";

import { handleUvRelay } from "../src/background/uv-relay.ts";
import { isPasskeyRequestFromPage, PASSKEY_PAGE_REQUEST, relayableUserVerification } from "../src/content/passkey-protocol.ts";
import {
  type AwaitingCeremony,
  type PasskeyCreateCeremony,
  type PasskeyGetCeremony,
  UV_MAX_ATTEMPTS,
  createPasskeyCeremonyStore,
} from "../src/core-host/passkey-ceremony.ts";
import {
  type PasskeyVerifyDeps,
  type ReverifyingSession,
  cancelVerification,
  pendingVerification,
  submitVerification,
} from "../src/core-host/passkey-verify.ts";
import { setUvBadge } from "../src/core-host/uv-badge.ts";
import { MAX_USER_VERIFICATION_LEN, type PasskeyResultPayload, isPasskeyVerifyRequest } from "../src/messaging/contract.ts";
import { OFFSCREEN_PATH, POPUP_PATH, isOffscreenDocumentSender, isPopupSender } from "../src/messaging/sender.ts";
import { MessageRejected, parseFromContentScript } from "../src/messaging/validate.ts";
import { isPasskeyConsentShowMessage, PASSKEY_CONSENT_SHOW } from "../src/passkey-consent/protocol.ts";

const TTL = 2 * 60 * 1000;
const ORIGIN = "https://example.com";
const TAB = 7;

const createRequest: PasskeyCreateCeremony = {
  kind: "create",
  origin: ORIGIN,
  rpId: "example.com",
  rpName: "Example",
  userIdB64: "dXNlci0x",
  userName: "alice",
  userDisplayName: "Alice",
  challengeB64: "Y2hhbGxlbmdl",
  userVerification: "required",
};

const getRequest: PasskeyGetCeremony = {
  kind: "get",
  origin: ORIGIN,
  rpId: "example.com",
  challengeB64: "Y2hhbGxlbmdl",
  candidates: [
    { passkeyRef: "item-1:el-1", itemTitle: "Example", userName: "alice" },
    { passkeyRef: "item-2:el-2", itemTitle: "Example", userName: "bob" },
  ],
  userVerification: "required",
};

describe("ADR 0110 §5: the shim relays userVerification as a short string only", () => {
  it("relays a string of at most 16 UTF-16 code units unchanged, anything else not at all", () => {
    expect(MAX_USER_VERIFICATION_LEN).toBe(16);
    expect(relayableUserVerification("required")).toBe("required");
    expect(relayableUserVerification("REQUIRED")).toBe("REQUIRED");
    expect(relayableUserVerification("")).toBe("");
    expect(relayableUserVerification("x".repeat(16))).toBe("x".repeat(16));
    for (const other of ["x".repeat(17), undefined, null, 1, true, ["required"], { toString: () => "required" }]) {
      expect(relayableUserVerification(other)).toBeUndefined();
    }
    // 16 code units, 8 characters outside the BMP: still relayed (code units, not characters).
    expect(relayableUserVerification("🙂".repeat(8))).toBe("🙂".repeat(8));
    expect(relayableUserVerification("🙂".repeat(9))).toBeUndefined();
  });

  it("the page-request and background validators refuse a longer or non-string value", () => {
    const page = {
      type: PASSKEY_PAGE_REQUEST,
      nonce: "n1",
      kind: "get",
      challengeB64: "Y2hhbGxlbmdl",
      allowCredentialIdsB64: [],
    };
    expect(isPasskeyRequestFromPage({ ...page, userVerification: "required" })).toBe(true);
    expect(isPasskeyRequestFromPage({ ...page, userVerification: "x".repeat(17) })).toBe(false);
    expect(isPasskeyRequestFromPage({ ...page, userVerification: 1 })).toBe(false);
    const background = {
      type: "passkey_get_request",
      pageUrl: "https://example.com/login",
      challengeB64: "Y2hhbGxlbmdl",
      allowCredentialIdsB64: [],
    };
    expect(parseFromContentScript({ ...background, userVerification: "discouraged" })).toMatchObject({ userVerification: "discouraged" });
    expect(parseFromContentScript(background)).not.toHaveProperty("userVerification");
    expect(() => parseFromContentScript({ ...background, userVerification: "x".repeat(17) })).toThrow(MessageRejected);
    expect(() => parseFromContentScript({ ...background, userVerification: false })).toThrow(MessageRejected);
    const create = {
      type: "passkey_create_request",
      pageUrl: "https://example.com/signup",
      rpName: "Example",
      userIdB64: "dXNlci0x",
      userName: "alice",
      userDisplayName: "Alice",
      challengeB64: "Y2hhbGxlbmdl",
      algs: [-7],
    };
    expect(parseFromContentScript({ ...create, userVerification: "required" })).toMatchObject({ userVerification: "required" });
    expect(() => parseFromContentScript({ ...create, userVerification: "required".repeat(3) })).toThrow(MessageRejected);
  });

  it("the consent iframe accepts verifyFirst as a boolean only", () => {
    const show = {
      type: PASSKEY_CONSENT_SHOW,
      pageOrigin: ORIGIN,
      instanceToken: "3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e",
      ceremonyToken: "c1",
      kind: "create",
      rpId: "example.com",
    };
    expect(isPasskeyConsentShowMessage({ ...show, verifyFirst: true })).toBe(true);
    expect(isPasskeyConsentShowMessage(show)).toBe(true);
    expect(isPasskeyConsentShowMessage({ ...show, verifyFirst: "yes" })).toBe(false);
  });
});

describe("ADR 0110 §7 point 2: peek, take and awaiting_verification", () => {
  it("peek keeps the record, take removes it", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(createRequest, TAB, ORIGIN, 1000);
    expect(store.peek(token, TAB, ORIGIN, 1001)).toEqual(createRequest);
    expect(store.peek(token, TAB, ORIGIN, 1002)).toEqual(createRequest);
    expect(store.take(token, TAB, ORIGIN, 1003)).toEqual(createRequest);
    expect(store.peek(token, TAB, ORIGIN, 1004)).toBeUndefined();
    expect(store.take(token, TAB, ORIGIN, 1004)).toBeUndefined();
  });

  it("peek has take's expiry and binding checks, and drops what fails them", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const expired = store.create(createRequest, TAB, ORIGIN, 1000);
    expect(store.peek(expired, TAB, ORIGIN, 1000 + TTL + 1)).toBeUndefined();
    expect(store.take(expired, TAB, ORIGIN, 1000)).toBeUndefined();
    const navigated = store.create(createRequest, TAB, ORIGIN, 1000);
    expect(store.peek(navigated, TAB, "https://evil.example", 1001)).toBeUndefined();
    expect(store.peek(navigated, TAB, ORIGIN, 1001)).toBeUndefined();
    const otherTab = store.create(createRequest, TAB, ORIGIN, 1000);
    expect(store.peek(otherTab, TAB + 1, ORIGIN, 1001)).toBeUndefined();
  });

  it("moves a pending ceremony to awaiting_verification with the choice, same token and TTL", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const token = store.create(getRequest, TAB, ORIGIN, 1000);
    expect(store.awaitVerification(token, { passkeyRef: "item-2:el-2" }, 1001)).toEqual({ declined: [] });
    expect(store.isAwaiting(token, 1002)).toBe(true);
    // Not offered to a second approval any more, and not moved twice.
    expect(store.peek(token, TAB, ORIGIN, 1002)).toBeUndefined();
    expect(store.awaitVerification(token, {}, 1002)).toBeUndefined();
    expect(store.awaiting(token, 1002)).toMatchObject({
      ceremonyToken: token,
      tabId: TAB,
      boundOrigin: ORIGIN,
      choice: { passkeyRef: "item-2:el-2" },
      uvAttempts: 0,
    });
    // The TTL still counts from creation.
    expect(store.awaiting(token, 1000 + TTL + 1)).toBeUndefined();
  });

  it("keeps one waiting ceremony per tab: the older one is declined", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const first = store.create(createRequest, TAB, ORIGIN, 1000);
    const elsewhere = store.create(createRequest, TAB + 1, ORIGIN, 1000);
    const second = store.create(getRequest, TAB, ORIGIN, 1000);
    store.awaitVerification(first, {}, 1001);
    store.awaitVerification(elsewhere, {}, 1001);
    expect(store.awaitVerification(second, { passkeyRef: "item-1:el-1" }, 1002)).toEqual({ declined: [first] });
    expect(store.awaiting(first, 1003)).toBeUndefined();
    expect(store.awaitingForTab(TAB, 1003)?.ceremonyToken).toBe(second);
    expect(store.awaitingForTab(TAB + 1, 1003)?.ceremonyToken).toBe(elsewhere);
  });

  it("sweeps expired ceremonies and names the tabs that waited", () => {
    const store = createPasskeyCeremonyStore(TTL);
    const waiting = store.create(createRequest, TAB, ORIGIN, 1000);
    store.create(createRequest, TAB + 1, ORIGIN, 1000);
    store.awaitVerification(waiting, {}, 1001);
    expect(store.awaitingTabs()).toEqual([TAB]);
    expect(store.sweep(1500)).toEqual([]);
    expect(store.sweep(1000 + TTL + 1)).toEqual([TAB]);
    expect(store.awaitingTabs()).toEqual([]);
  });
});

/** The parts `passkey-verify.ts` runs over, recording what happens. */
function harness(options: { liveUrl?: string; locked?: boolean; password?: string; signFails?: boolean } = {}) {
  const store = createPasskeyCeremonyStore(TTL);
  let now = 5_000;
  const delivered: { tabId: number; token: string; result: PasskeyResultPayload | undefined }[] = [];
  const badgesCleared: number[] = [];
  const signedAt: number[] = [];
  const reverifiedAt: number[] = [];
  let locked = options.locked === true;
  const session: ReverifyingSession = {
    reverify: (password, nowMs) => {
      if (password !== (options.password ?? "right")) {
        throw Object.assign(new Error("wrong_password_or_secret_key"), { code: "wrong_password_or_secret_key" });
      }
      reverifiedAt.push(nowMs ?? -1);
    },
  };
  const result: PasskeyResultPayload = { credentialIdB64: "Y3JlZA==", clientDataJsonB64: "e30=" };
  const deps: PasskeyVerifyDeps = {
    store,
    now: () => now,
    session: () => (locked ? undefined : session),
    liveTabUrl: async () => options.liveUrl ?? "https://example.com/login",
    sign: async (_ceremony: AwaitingCeremony, nowMs: number) => {
      signedAt.push(nowMs);
      if (options.signFails === true) {
        throw new Error("write failed");
      }
      return result;
    },
    deliver: async (tabId, token, r) => {
      delivered.push({ tabId, token, result: r });
    },
    clearBadge: async (tabId) => {
      badgesCleared.push(tabId);
    },
  };
  const waiting = (request = createRequest as PasskeyCreateCeremony | PasskeyGetCeremony, choice = {}) => {
    const token = store.create(request, TAB, ORIGIN, now);
    store.awaitVerification(token, choice, now);
    return token;
  };
  return {
    store,
    deps,
    delivered,
    badgesCleared,
    signedAt,
    reverifiedAt,
    result,
    waiting,
    advance: (ms: number) => {
      now += ms;
    },
    lock: () => {
      locked = true;
    },
    now: () => now,
  };
}

describe("ADR 0110 §7 points 3–5: the popup's verification", () => {
  it("shows the waiting ceremony of the tab, with the chosen account, and nothing while locked", () => {
    const h = harness();
    expect(pendingVerification(h.deps, TAB)).toBeUndefined();
    const token = h.waiting(getRequest, { passkeyRef: "item-2:el-2" });
    expect(pendingVerification(h.deps, TAB)).toEqual({ ceremonyToken: token, origin: ORIGIN, rpId: "example.com", userName: "bob", kind: "get" });
    expect(pendingVerification(h.deps, TAB + 1)).toBeUndefined();
    h.lock();
    expect(pendingVerification(h.deps, TAB)).toBeUndefined();
  });

  it("signs with the verification's own now after the right password, once", async () => {
    const h = harness();
    const token = h.waiting();
    h.advance(10);
    expect(await submitVerification(h.deps, token, "right")).toBe("uv_ok");
    expect(h.reverifiedAt).toEqual([h.now()]);
    expect(h.signedAt).toEqual([h.now()]);
    expect(h.delivered).toEqual([{ tabId: TAB, token, result: h.result }]);
    expect(h.badgesCleared).toEqual([TAB]);
    // Single use: a second submit finds nothing.
    expect(await submitVerification(h.deps, token, "right")).toBe("uv_ceremony_gone");
    expect(h.signedAt).toHaveLength(1);
  });

  it("five wrong passwords decline the ceremony; four keep it waiting", async () => {
    const h = harness();
    const token = h.waiting();
    for (let i = 1; i < UV_MAX_ATTEMPTS; i += 1) {
      expect(await submitVerification(h.deps, token, `wrong ${i}`)).toBe("uv_wrong_password");
      expect(h.store.isAwaiting(token, h.now())).toBe(true);
    }
    expect(h.delivered).toEqual([]);
    expect(await submitVerification(h.deps, token, "wrong 5")).toBe("uv_attempts_exhausted");
    expect(h.store.isAwaiting(token, h.now())).toBe(false);
    expect(h.delivered).toEqual([{ tabId: TAB, token, result: undefined }]);
    expect(h.badgesCleared).toEqual([TAB]);
    expect(h.signedAt).toEqual([]);
    // Even the right password now finds nothing to sign.
    expect(await submitVerification(h.deps, token, "right")).toBe("uv_ceremony_gone");
    expect(h.signedAt).toEqual([]);
  });

  it("a wrong password then the right one signs", async () => {
    const h = harness();
    const token = h.waiting();
    expect(await submitVerification(h.deps, token, "wrong")).toBe("uv_wrong_password");
    expect(await submitVerification(h.deps, token, "right")).toBe("uv_ok");
    expect(h.delivered).toEqual([{ tabId: TAB, token, result: h.result }]);
  });

  it("declines when the tab's live URL left the bound origin, before checking the password", async () => {
    const h = harness({ liveUrl: "https://evil.example/" });
    const token = h.waiting();
    expect(await submitVerification(h.deps, token, "right")).toBe("uv_ceremony_gone");
    expect(h.reverifiedAt).toEqual([]);
    expect(h.delivered).toEqual([{ tabId: TAB, token, result: undefined }]);
    expect(h.badgesCleared).toEqual([TAB]);
  });

  it("answers uv_locked while locked and uv_ceremony_gone for an unknown, expired or pending one", async () => {
    const locked = harness({ locked: true });
    expect(await submitVerification(locked.deps, "any", "right")).toBe("uv_locked");
    const h = harness();
    expect(await submitVerification(h.deps, "unknown", "right")).toBe("uv_ceremony_gone");
    const pending = h.store.create(createRequest, TAB, ORIGIN, h.now());
    expect(await submitVerification(h.deps, pending, "right")).toBe("uv_ceremony_gone");
    const expired = h.waiting();
    h.advance(TTL + 1);
    expect(await submitVerification(h.deps, expired, "right")).toBe("uv_ceremony_gone");
    expect(h.reverifiedAt).toEqual([]);
  });

  it("Cancel declines a waiting ceremony and clears the badge", async () => {
    const h = harness();
    const token = h.waiting();
    expect(await cancelVerification(h.deps, token)).toBe("uv_cancelled");
    expect(h.delivered).toEqual([{ tabId: TAB, token, result: undefined }]);
    expect(h.badgesCleared).toEqual([TAB]);
    expect(await submitVerification(h.deps, token, "right")).toBe("uv_ceremony_gone");
  });

  it("a failed signature after the verification delivers the fallback", async () => {
    const h = harness({ signFails: true });
    const token = h.waiting();
    expect(await submitVerification(h.deps, token, "right")).toBe("uv_ceremony_gone");
    expect(h.delivered).toEqual([{ tabId: TAB, token, result: undefined }]);
  });
});

const EXT_ID = "abcdefabcdefabcdefabcdefabcdefab";
const EXT = `chrome-extension://${EXT_ID}`;
const POPUP_URL = `${EXT}/${POPUP_PATH}`;
const OFFSCREEN_URL = `${EXT}/${OFFSCREEN_PATH}`;

describe("ADR 0110 §7 point 4: only the toolbar popup may submit a verification", () => {
  it("accepts the popup, as the toolbar popup or opened at its own URL", () => {
    expect(isPopupSender({ id: EXT_ID, url: POPUP_URL, origin: EXT }, EXT_ID, POPUP_URL)).toBe(true);
    expect(isPopupSender({ id: EXT_ID, url: `${POPUP_URL}#x`, tab: { id: 3, url: POPUP_URL } }, EXT_ID, POPUP_URL)).toBe(true);
  });

  it("refuses a content script, the inline menu, the consent iframe, the options page and others", () => {
    const page = { id: 3, url: "https://example.com/login" };
    const refused: WebExtMessageSender[] = [
      // A content script.
      { id: EXT_ID, url: "https://example.com/login", origin: "https://example.com", tab: page },
      // The inline-menu iframe and the passkey consent iframe: extension pages framed in a page.
      { id: EXT_ID, url: `${EXT}/src/inline-menu/index.html`, origin: EXT, tab: page },
      { id: EXT_ID, url: `${EXT}/src/passkey-consent/index.html`, origin: EXT, tab: page },
      // The popup document framed in a web page (it is not web-accessible, but checked anyway).
      { id: EXT_ID, url: POPUP_URL, origin: EXT, tab: page },
      // The options page, the offscreen document, a sender with no URL, another extension.
      { id: EXT_ID, url: `${EXT}/src/options/index.html` },
      { id: EXT_ID, url: OFFSCREEN_URL },
      { id: EXT_ID },
      { id: "another-extension", url: POPUP_URL },
    ];
    for (const sender of refused) {
      expect(isPopupSender(sender, EXT_ID, POPUP_URL), JSON.stringify(sender)).toBe(false);
    }
  });

  it("validates the three popup messages' shapes", () => {
    expect(isPasskeyVerifyRequest({ type: "passkey_verify_pending", tabId: 3 })).toBe(true);
    expect(isPasskeyVerifyRequest({ type: "passkey_verify_pending", tabId: "3" })).toBe(false);
    expect(isPasskeyVerifyRequest({ type: "passkey_verify_submit", ceremonyToken: "c", masterPassword: "pw" })).toBe(true);
    expect(isPasskeyVerifyRequest({ type: "passkey_verify_submit", ceremonyToken: "c", masterPassword: 1 })).toBe(false);
    expect(isPasskeyVerifyRequest({ type: "passkey_verify_submit", ceremonyToken: "c", masterPassword: "x".repeat(4097) })).toBe(false);
    expect(isPasskeyVerifyRequest({ type: "passkey_verify_submit", ceremonyToken: "", masterPassword: "pw" })).toBe(false);
    expect(isPasskeyVerifyRequest({ type: "passkey_verify_cancel", ceremonyToken: "c" })).toBe(true);
    expect(isPasskeyVerifyRequest({ type: "unlock", masterPassword: "pw" })).toBe(false);
  });
});

/** A namespace with a recording toolbar action and `tabs.get`. */
function relayExt(withAction: boolean) {
  const badges: { tabId?: number; text: string }[] = [];
  const openPopup = vi.fn(async () => undefined);
  const sent: unknown[] = [];
  const ext = {
    runtime: {
      id: EXT_ID,
      getURL: (path: string) => `${EXT}/${path}`,
      sendMessage: async (message: unknown) => {
        sent.push(message);
        return undefined;
      },
    },
    tabs: { get: async (tabId: number) => ({ id: tabId, url: "https://example.com/login" }) },
    ...(withAction
      ? {
          action: {
            setBadgeText: async (details: { tabId?: number; text: string }) => {
              badges.push(details);
            },
            openPopup,
          },
        }
      : {}),
  } as unknown as WebExtNamespace;
  return { ext, badges, openPopup, sent };
}

describe("ADR 0110 §7 point 2: the badge relay", () => {
  const offscreen: WebExtMessageSender = { id: EXT_ID, url: OFFSCREEN_URL };

  it("sets the badge and tries openPopup for the offscreen document", async () => {
    const { ext, badges, openPopup } = relayExt(true);
    const sendResponse = vi.fn();
    expect(handleUvRelay(ext, { type: "relay_uv_badge", tabId: 4, on: true, openPopup: true }, offscreen, sendResponse)).toBe(true);
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith({ ok: true }));
    expect(badges).toEqual([{ tabId: 4, text: "!" }]);
    expect(openPopup).toHaveBeenCalledTimes(1);
    expect(handleUvRelay(ext, { type: "relay_uv_badge", tabId: 4, on: false, openPopup: false }, offscreen, vi.fn())).toBe(true);
    await vi.waitFor(() => expect(badges).toEqual([{ tabId: 4, text: "!" }, { tabId: 4, text: "" }]));
  });

  it("answers the live tab URL to the offscreen document", async () => {
    const { ext } = relayExt(true);
    const sendResponse = vi.fn();
    expect(handleUvRelay(ext, { type: "relay_tab_url", tabId: 4 }, offscreen, sendResponse)).toBe(true);
    await vi.waitFor(() => expect(sendResponse).toHaveBeenCalledWith({ url: "https://example.com/login" }));
  });

  it("ignores both relays from any other sender", () => {
    const { ext, badges, openPopup } = relayExt(true);
    const page = { id: 3, url: "https://example.com/login" };
    const others: WebExtMessageSender[] = [
      { id: EXT_ID, url: "https://example.com/login", origin: "https://example.com", tab: page },
      { id: EXT_ID, url: `${EXT}/src/passkey-consent/index.html`, origin: EXT, tab: page },
      { id: EXT_ID, url: POPUP_URL },
      { id: EXT_ID, url: OFFSCREEN_URL, tab: page },
      { id: EXT_ID },
      { id: "another-extension", url: OFFSCREEN_URL },
    ];
    for (const sender of others) {
      const sendResponse = vi.fn();
      expect(handleUvRelay(ext, { type: "relay_uv_badge", tabId: 4, on: true, openPopup: true }, sender, sendResponse)).toBe(false);
      expect(handleUvRelay(ext, { type: "relay_tab_url", tabId: 4 }, sender, sendResponse)).toBe(false);
      expect(sendResponse).not.toHaveBeenCalled();
    }
    expect(badges).toEqual([]);
    expect(openPopup).not.toHaveBeenCalled();
    expect(isOffscreenDocumentSender(offscreen, EXT_ID, OFFSCREEN_URL)).toBe(true);
  });

  it("ignores a malformed relay", () => {
    const { ext } = relayExt(true);
    expect(handleUvRelay(ext, { type: "relay_uv_badge", tabId: "4", on: true, openPopup: true }, offscreen, vi.fn())).toBe(false);
    expect(handleUvRelay(ext, { type: "relay_tab_url" }, offscreen, vi.fn())).toBe(false);
  });

  it("setUvBadge uses the context's own action, or relays without one", async () => {
    const own = relayExt(true);
    await setUvBadge(own.ext, 9, true);
    expect(own.badges).toEqual([{ tabId: 9, text: "!" }]);
    expect(own.sent).toEqual([]);
    const offscreenCtx = relayExt(false);
    await setUvBadge(offscreenCtx.ext, 9, false);
    expect(offscreenCtx.sent).toEqual([{ type: "relay_uv_badge", tabId: 9, on: false, openPopup: false }]);
  });
});
