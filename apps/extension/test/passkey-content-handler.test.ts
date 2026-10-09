// `handleContentScriptRequest`'s passkey cases (ADR 0039 §2) and `handlePasskeyCeremonyApproval`
// (ADR 0040's pattern applied to a ceremony): same style as `content-handler.test.ts` — no
// session is ever set up in this module's test environment, so every case that would otherwise
// need one exercises the "locked" path, which is still real coverage of every check that runs
// *before* the locked check (pageUrl-vs-sender, HTTPS, ES256).
import { describe, expect, it, vi } from "vitest";

import { handleContentScriptRequest, handlePasskeyCeremonyApproval } from "../src/core-host/content-handler.ts";
import type { PasskeyCreateRequestMessage, PasskeyGetRequestMessage } from "../src/messaging/contract.ts";

function createRequest(overrides: Partial<PasskeyCreateRequestMessage> = {}): PasskeyCreateRequestMessage {
  return {
    type: "passkey_create_request",
    pageUrl: "https://example.com/login",
    rpName: "Example",
    userIdB64: "dXNlci0x",
    userName: "alice",
    userDisplayName: "Alice",
    challengeB64: "Y2hhbGxlbmdl",
    algs: [-7],
    ...overrides,
  };
}

function getRequest(overrides: Partial<PasskeyGetRequestMessage> = {}): PasskeyGetRequestMessage {
  return {
    type: "passkey_get_request",
    pageUrl: "https://example.com/login",
    challengeB64: "Y2hhbGxlbmdl",
    allowCredentialIdsB64: [],
    ...overrides,
  };
}

describe("handleContentScriptRequest: passkey_create_request", () => {
  it("refuses a pageUrl that does not match the sender-derived trustedOrigin", async () => {
    const response = await handleContentScriptRequest(createRequest({ pageUrl: "https://attacker.example/" }), "https://example.com", 1);
    expect(response.type).toBe("content_error");
  });

  it("refuses when no trusted tab id is available", async () => {
    const response = await handleContentScriptRequest(createRequest(), "https://example.com");
    expect(response.type).toBe("content_error");
  });

  it("refuses an http origin (INV-64)", async () => {
    const response = await handleContentScriptRequest(createRequest({ pageUrl: "http://example.com/login" }), "http://example.com", 1);
    expect(response).toEqual({ type: "content_error", code: "passkey_create_request: origin is not https" });
  });

  it("refuses a request with no ES256 in pubKeyCredParams", async () => {
    const response = await handleContentScriptRequest(createRequest({ algs: [-257] }), "https://example.com", 1);
    expect(response).toEqual({ type: "content_error", code: "passkey_create_request: no ES256 in pubKeyCredParams" });
  });

  it("refuses when the device is locked (no session set up by this test)", async () => {
    const response = await handleContentScriptRequest(createRequest(), "https://example.com", 1);
    expect(response).toEqual({ type: "content_error", code: "passkey_create_request: the device is locked" });
  });
});

describe("handleContentScriptRequest: passkey_get_request", () => {
  it("refuses a pageUrl that does not match the sender-derived trustedOrigin", async () => {
    const response = await handleContentScriptRequest(getRequest({ pageUrl: "https://attacker.example/" }), "https://example.com", 1);
    expect(response.type).toBe("content_error");
  });

  it("refuses an http origin (INV-64)", async () => {
    const response = await handleContentScriptRequest(getRequest({ pageUrl: "http://example.com/login" }), "http://example.com", 1);
    expect(response).toEqual({ type: "content_error", code: "passkey_get_request: origin is not https" });
  });

  it("refuses when the device is locked (no session set up by this test)", async () => {
    const response = await handleContentScriptRequest(getRequest(), "https://example.com", 1);
    expect(response).toEqual({
      type: "content_error",
      code: "passkey_get_request: the device is locked, or no stored passkey matches this rpId",
    });
  });
});

describe("handlePasskeyCeremonyApproval", () => {
  it("refuses a tab URL that does not even parse as a URL", async () => {
    const ext = { tabs: { sendMessage: vi.fn(async () => undefined) } } as unknown as WebExtNamespace;
    const response = await handlePasskeyCeremonyApproval(ext, 1, "not-a-url", {
      type: "passkey_ceremony_approved",
      ceremonyToken: "tok-1",
    });
    expect(response).toEqual({ type: "content_error", code: "passkey_ceremony: the sender's tab URL does not parse" });
  });

  it("always pushes a fallback apply_passkey_result for an unknown/expired ceremony token", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const ext = { tabs: { sendMessage } } as unknown as WebExtNamespace;
    const response = await handlePasskeyCeremonyApproval(ext, 1, "https://example.com/login", {
      type: "passkey_ceremony_approved",
      ceremonyToken: "no-such-token",
    });
    expect(response).toEqual({ type: "passkey_ceremony_dispatched" });
    expect(sendMessage).toHaveBeenCalledWith(1, { type: "apply_passkey_result", ceremonyToken: "no-such-token", outcome: "fallback" });
  });

  it("pushes a fallback apply_passkey_result on an explicit decline", async () => {
    const sendMessage = vi.fn(async () => undefined);
    const ext = { tabs: { sendMessage } } as unknown as WebExtNamespace;
    const response = await handlePasskeyCeremonyApproval(ext, 1, "https://example.com/login", {
      type: "passkey_ceremony_declined",
      ceremonyToken: "tok-1",
    });
    expect(response).toEqual({ type: "passkey_ceremony_dispatched" });
    expect(sendMessage).toHaveBeenCalledWith(1, { type: "apply_passkey_result", ceremonyToken: "tok-1", outcome: "fallback" });
  });
});
