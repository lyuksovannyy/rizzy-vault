// Sender checks (ADR 0036 §4, INV-40): origin comes only from `sender`, never the message body;
// only this extension's own content scripts and pages are accepted.
import { describe, expect, it } from "vitest";

import { SenderRejected, isContentScriptSender, isOwnExtensionPage, trustedOriginOf } from "../src/messaging/sender.ts";

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
});
