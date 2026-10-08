// Sender checks (ADR 0036 §4, INV-40): origin comes only from `sender`, never the message body;
// only this extension's own content scripts and pages are accepted.
import { describe, expect, it } from "vitest";

import {
  SenderRejected,
  extensionOriginOf,
  isContentScriptSender,
  isInlineMenuSender,
  isOwnExtensionPage,
  trustedOriginOf,
} from "../src/messaging/sender.ts";

const EXT_ID = "abcdefabcdefabcdefabcdefabcdefab";

describe("trustedOriginOf", () => {
  it("returns the tab's origin for a content script of this extension", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, tab: { url: "https://example.com/login?x=1" } };
    expect(trustedOriginOf(sender, EXT_ID)).toBe("https://example.com");
  });

  it("ignores a claimed origin in the message body: only sender.tab.url is read", () => {
    // There is no `origin` field for the caller to pass here at all — trustedOriginOf's
    // signature takes no message body, which is the test: the API makes the mistake
    // impossible, not just discouraged.
    const sender: WebExtMessageSender = { id: EXT_ID, tab: { url: "https://real-bank.com/" } };
    expect(trustedOriginOf(sender, EXT_ID)).toBe("https://real-bank.com");
  });

  it("rejects a sender from a different extension", () => {
    const sender: WebExtMessageSender = { id: "other-extension", tab: { url: "https://example.com" } };
    expect(() => trustedOriginOf(sender, EXT_ID)).toThrow(SenderRejected);
  });

  it("rejects a sender with no tab (not a content script)", () => {
    const sender: WebExtMessageSender = { id: EXT_ID };
    expect(() => trustedOriginOf(sender, EXT_ID)).toThrow(SenderRejected);
  });

  it("rejects a non-http(s) tab URL", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, tab: { url: "chrome://extensions" } };
    expect(() => trustedOriginOf(sender, EXT_ID)).toThrow(SenderRejected);
    const file: WebExtMessageSender = { id: EXT_ID, tab: { url: "file:///etc/passwd" } };
    expect(() => trustedOriginOf(file, EXT_ID)).toThrow(SenderRejected);
  });

  it("rejects a missing tab URL", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, tab: {} };
    expect(() => trustedOriginOf(sender, EXT_ID)).toThrow(SenderRejected);
  });
});

describe("isOwnExtensionPage", () => {
  it("accepts this extension's own page (popup/options/offscreen): no tab", () => {
    expect(isOwnExtensionPage({ id: EXT_ID }, EXT_ID)).toBe(true);
  });

  it("rejects a content script sender (has a tab) even from this extension", () => {
    expect(isOwnExtensionPage({ id: EXT_ID, tab: { url: "https://example.com" } }, EXT_ID)).toBe(false);
  });

  it("rejects a different extension's page", () => {
    expect(isOwnExtensionPage({ id: "other" }, EXT_ID)).toBe(false);
  });

  it("rejects a sender with no id at all (a page could never produce one; the browser sets it)", () => {
    expect(isOwnExtensionPage({}, EXT_ID)).toBe(false);
  });

  it("accepts this extension's own page even when it is open in an ordinary tab (not tab-less)", () => {
    // E.g. the popup's `index.html` opened directly in a tab, as a test does, rather than
    // through `chrome.action` — `sender.tab` is set, but `sender.tab.url` is this extension's
    // own origin, never an http(s) page a content script could have run on.
    const sender: WebExtMessageSender = { id: EXT_ID, tab: { url: `chrome-extension://${EXT_ID}/src/popup/index.html` } };
    expect(isOwnExtensionPage(sender, EXT_ID)).toBe(true);
  });
});

describe("isContentScriptSender", () => {
  it("accepts this extension's content script on an http(s) page", () => {
    expect(isContentScriptSender({ id: EXT_ID, tab: { url: "https://example.com/login" } }, EXT_ID)).toBe(true);
  });

  it("rejects one of this extension's own pages hosted in a tab (tab.url is chrome-extension://)", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, tab: { url: `chrome-extension://${EXT_ID}/src/popup/index.html` } };
    expect(isContentScriptSender(sender, EXT_ID)).toBe(false);
  });

  it("rejects a sender with no tab at all", () => {
    expect(isContentScriptSender({ id: EXT_ID }, EXT_ID)).toBe(false);
  });

  it("rejects a different extension's content script", () => {
    expect(isContentScriptSender({ id: "other", tab: { url: "https://example.com" } }, EXT_ID)).toBe(false);
  });

  // The fix for the real vulnerability this suite exists for: before this check tightened,
  // `sender.tab.url` being http(s) was the whole test, so the inline-menu iframe (genuinely
  // embedded in an http(s) tab, but sending from this extension's own origin) was
  // indistinguishable here from the content script actually running in that same page —
  // letting a compromised content script masquerade as the privileged sender simply by also
  // satisfying "has a tab, tab is http(s)". `sender.origin` is the one field only the browser
  // sets, from the document that truly called `sendMessage`.
  it("rejects a sender whose origin does not match its own tab's origin (the inline-menu iframe's shape)", () => {
    const sender: WebExtMessageSender = {
      id: EXT_ID,
      origin: `chrome-extension://${EXT_ID}`,
      tab: { url: "https://example.com/login" },
    };
    expect(isContentScriptSender(sender, EXT_ID)).toBe(false);
  });

  it("still accepts a real content script whose origin matches its own tab's origin", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, origin: "https://example.com", tab: { url: "https://example.com/login" } };
    expect(isContentScriptSender(sender, EXT_ID)).toBe(true);
  });
});

describe("extensionOriginOf", () => {
  it("derives this extension's own origin from runtime.getURL", () => {
    const ext = { runtime: { getURL: (path: string) => `chrome-extension://${EXT_ID}/${path}` } } as WebExtNamespace;
    expect(extensionOriginOf(ext)).toBe(`chrome-extension://${EXT_ID}`);
  });
});

describe("isInlineMenuSender", () => {
  const EXT_ORIGIN = `chrome-extension://${EXT_ID}`;

  it("accepts the inline-menu iframe: this extension's own origin, embedded in a real http(s) tab", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, origin: EXT_ORIGIN, tab: { url: "https://example.com/login" } };
    expect(isInlineMenuSender(sender, EXT_ID, EXT_ORIGIN)).toBe(true);
  });

  // The defect this whole change fixes: a content script's sender has the page's own origin,
  // never this extension's — so it can never satisfy this check, however it shapes its message.
  it("rejects a real content script (its origin is the page's own, not the extension's)", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, origin: "https://example.com", tab: { url: "https://example.com/login" } };
    expect(isInlineMenuSender(sender, EXT_ID, EXT_ORIGIN)).toBe(false);
  });

  it("rejects a sender with no tab at all (one of this extension's own top-level pages)", () => {
    expect(isInlineMenuSender({ id: EXT_ID, origin: EXT_ORIGIN }, EXT_ID, EXT_ORIGIN)).toBe(false);
  });

  it("rejects a missing sender.origin: unlike isContentScriptSender, this never falls back", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, tab: { url: "https://example.com/login" } };
    expect(isInlineMenuSender(sender, EXT_ID, EXT_ORIGIN)).toBe(false);
  });

  it("rejects a different extension's origin", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, origin: "chrome-extension://some-other-id", tab: { url: "https://example.com" } };
    expect(isInlineMenuSender(sender, EXT_ID, EXT_ORIGIN)).toBe(false);
  });

  it("rejects a non-http(s) tab (not a real embedding page)", () => {
    const sender: WebExtMessageSender = { id: EXT_ID, origin: EXT_ORIGIN, tab: { url: `chrome-extension://${EXT_ID}/popup.html` } };
    expect(isInlineMenuSender(sender, EXT_ID, EXT_ORIGIN)).toBe(false);
  });
});
