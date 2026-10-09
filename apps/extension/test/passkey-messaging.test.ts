// Passkey messages at the real extension-messaging boundary (ADR 0039 §2, INV-40):
// `parseFromContentScript` for the two new content-script-originated request types, and the
// privileged-sender-only validators `core-host/listener.ts` uses directly, mirroring
// `messaging.test.ts`'s own coverage of the fill-request/relay equivalents.
import { describe, expect, it } from "vitest";

import {
  isApplyPasskeyResultMessage,
  isPasskeyCeremonyMessage,
  isRelayPasskeyResultMessage,
} from "../src/messaging/contract.ts";
import { MessageRejected, parseFromContentScript } from "../src/messaging/validate.ts";

const createRequest = {
  type: "passkey_create_request",
  pageUrl: "https://example.com/login",
  rpName: "Example",
  userIdB64: "dXNlci0x",
  userName: "alice",
  userDisplayName: "Alice",
  challengeB64: "Y2hhbGxlbmdl",
  algs: [-7],
};

const getRequest = {
  type: "passkey_get_request",
  pageUrl: "https://example.com/login",
  challengeB64: "Y2hhbGxlbmdl",
  allowCredentialIdsB64: [],
};

describe("parseFromContentScript: passkey_create_request", () => {
  it("accepts a well-formed request", () => {
    expect(parseFromContentScript(createRequest)).toEqual(createRequest);
  });

  it("accepts an optional rpIdHint", () => {
    const message = { ...createRequest, rpIdHint: "example.com" };
    expect(parseFromContentScript(message)).toEqual(message);
  });

  it("refuses algs that are not an array", () => {
    expect(() => parseFromContentScript({ ...createRequest, algs: -7 })).toThrow(MessageRejected);
  });

  it("refuses a missing userName", () => {
    const { userName, ...rest } = createRequest;
    void userName;
    expect(() => parseFromContentScript(rest)).toThrow(MessageRejected);
  });

  it("refuses an rpName over its own length budget", () => {
    expect(() => parseFromContentScript({ ...createRequest, rpName: "a".repeat(300) })).toThrow(MessageRejected);
  });
});

describe("parseFromContentScript: passkey_get_request", () => {
  it("accepts a well-formed request", () => {
    expect(parseFromContentScript(getRequest)).toEqual(getRequest);
  });

  it("accepts a non-empty allowCredentialIdsB64", () => {
    const message = { ...getRequest, allowCredentialIdsB64: ["aWQx", "aWQy"] };
    expect(parseFromContentScript(message)).toEqual(message);
  });

  it("refuses too many allowCredentialIdsB64 entries", () => {
    const message = { ...getRequest, allowCredentialIdsB64: Array.from({ length: 17 }, () => "aWQ") };
    expect(() => parseFromContentScript(message)).toThrow(MessageRejected);
  });

  it("refuses a missing challengeB64", () => {
    const { challengeB64, ...rest } = getRequest;
    void challengeB64;
    expect(() => parseFromContentScript(rest)).toThrow(MessageRejected);
  });
});

// Defence in depth, same reasoning as `messaging.test.ts`'s own
// "inline_menu_fill_chosen is not a content-script message at all": the privileged
// ceremony-approval message is deliberately not one of `FromContentScript`'s own variants.
describe("parseFromContentScript: passkey_ceremony_approved is not a content-script message at all", () => {
  it("is refused as an unknown type", () => {
    expect(() => parseFromContentScript({ type: "passkey_ceremony_approved", ceremonyToken: "tok-1" })).toThrow(MessageRejected);
  });
});

describe("isPasskeyCeremonyMessage", () => {
  it("accepts a well-formed approval with no chosenPasskeyRef (a create ceremony)", () => {
    expect(isPasskeyCeremonyMessage({ type: "passkey_ceremony_approved", ceremonyToken: "tok-1" })).toBe(true);
  });

  it("accepts a well-formed approval with a chosenPasskeyRef (a get ceremony)", () => {
    expect(isPasskeyCeremonyMessage({ type: "passkey_ceremony_approved", ceremonyToken: "tok-1", chosenPasskeyRef: "item-1:el-1" })).toBe(
      true,
    );
  });

  it("accepts a well-formed decline", () => {
    expect(isPasskeyCeremonyMessage({ type: "passkey_ceremony_declined", ceremonyToken: "tok-1" })).toBe(true);
  });

  it("rejects a missing ceremonyToken", () => {
    expect(isPasskeyCeremonyMessage({ type: "passkey_ceremony_approved" })).toBe(false);
  });

  it("rejects an unknown type", () => {
    expect(isPasskeyCeremonyMessage({ type: "passkey_ceremony_maybe", ceremonyToken: "tok-1" })).toBe(false);
  });

  it("rejects a non-object", () => {
    expect(isPasskeyCeremonyMessage(null)).toBe(false);
  });
});

const okResult = { credentialIdB64: "aWQ", clientDataJsonB64: "Y2Rq", authenticatorDataB64: "YWQ", signatureB64: "c2lnbg" };

describe("isApplyPasskeyResultMessage", () => {
  it("accepts a fallback outcome with no result", () => {
    expect(isApplyPasskeyResultMessage({ type: "apply_passkey_result", ceremonyToken: "tok-1", outcome: "fallback" })).toBe(true);
  });

  it("accepts an ok outcome with a result", () => {
    expect(isApplyPasskeyResultMessage({ type: "apply_passkey_result", ceremonyToken: "tok-1", outcome: "ok", result: okResult })).toBe(
      true,
    );
  });

  it("rejects an ok outcome with no result", () => {
    expect(isApplyPasskeyResultMessage({ type: "apply_passkey_result", ceremonyToken: "tok-1", outcome: "ok" })).toBe(false);
  });

  it("rejects a fallback outcome that still carries a result", () => {
    expect(
      isApplyPasskeyResultMessage({ type: "apply_passkey_result", ceremonyToken: "tok-1", outcome: "fallback", result: okResult }),
    ).toBe(false);
  });
});

describe("isRelayPasskeyResultMessage", () => {
  it("accepts a well-formed relay", () => {
    expect(isRelayPasskeyResultMessage({ type: "relay_passkey_result", tabId: 7, ceremonyToken: "tok-1", outcome: "fallback" })).toBe(
      true,
    );
  });

  it("rejects a non-numeric tabId", () => {
    expect(isRelayPasskeyResultMessage({ type: "relay_passkey_result", tabId: "7", ceremonyToken: "tok-1", outcome: "fallback" })).toBe(
      false,
    );
  });

  it("rejects a different message type", () => {
    expect(isRelayPasskeyResultMessage({ type: "apply_passkey_result", tabId: 7, ceremonyToken: "tok-1", outcome: "fallback" })).toBe(
      false,
    );
  });
});
