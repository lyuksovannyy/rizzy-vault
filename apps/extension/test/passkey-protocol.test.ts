// The page-world shim <-> relay content script channel (`content/passkey-protocol.ts`): no
// sender authentication (module docs there on why), but every field is still shape- and
// length-bounded before `passkey-relay.ts` ever forwards it into the real extension-messaging
// boundary (`passkey_create_request`/`passkey_get_request`, validated a second time there by
// `messaging/validate.ts`) — defence in depth, same "every message boundary is bounded" rule
// this project applies everywhere else.
import { describe, expect, it } from "vitest";

import {
  PASSKEY_PAGE_REQUEST,
  PASSKEY_PAGE_RESPONSE,
  isPasskeyRequestFromPage,
  isPasskeyResponseToPage,
} from "../src/content/passkey-protocol.ts";

const createRequest = {
  type: PASSKEY_PAGE_REQUEST,
  nonce: "n1",
  kind: "create",
  rpName: "Example",
  userIdB64: "dXNlci0x",
  userName: "alice",
  userDisplayName: "Alice",
  challengeB64: "Y2hhbGxlbmdl",
  algs: [-7],
};

const getRequest = {
  type: PASSKEY_PAGE_REQUEST,
  nonce: "n2",
  kind: "get",
  challengeB64: "Y2hhbGxlbmdl",
  allowCredentialIdsB64: [],
};

describe("isPasskeyRequestFromPage", () => {
  it("accepts a well-formed create request", () => {
    expect(isPasskeyRequestFromPage(createRequest)).toBe(true);
  });

  it("accepts a well-formed get request", () => {
    expect(isPasskeyRequestFromPage(getRequest)).toBe(true);
  });

  it("accepts a create request with an optional rpIdHint", () => {
    expect(isPasskeyRequestFromPage({ ...createRequest, rpIdHint: "example.com" })).toBe(true);
  });

  it("rejects an unknown kind", () => {
    expect(isPasskeyRequestFromPage({ ...createRequest, kind: "update" })).toBe(false);
  });

  it("rejects a create request missing rpName", () => {
    const { rpName, ...rest } = createRequest;
    void rpName;
    expect(isPasskeyRequestFromPage(rest)).toBe(false);
  });

  it("rejects algs that are not integers", () => {
    expect(isPasskeyRequestFromPage({ ...createRequest, algs: [-7.5] })).toBe(false);
  });

  it("rejects a non-array allowCredentialIdsB64", () => {
    expect(isPasskeyRequestFromPage({ ...getRequest, allowCredentialIdsB64: "not-an-array" })).toBe(false);
  });

  it("rejects a non-object", () => {
    expect(isPasskeyRequestFromPage(null)).toBe(false);
    expect(isPasskeyRequestFromPage("request")).toBe(false);
  });

  it("rejects a different type string", () => {
    expect(isPasskeyRequestFromPage({ ...createRequest, type: "something-else" })).toBe(false);
  });
});

describe("isPasskeyResponseToPage", () => {
  it("accepts a fallback outcome with no result", () => {
    expect(isPasskeyResponseToPage({ type: PASSKEY_PAGE_RESPONSE, nonce: "n1", outcome: "fallback" })).toBe(true);
  });

  it("accepts an ok outcome with a minimal result", () => {
    expect(
      isPasskeyResponseToPage({
        type: PASSKEY_PAGE_RESPONSE,
        nonce: "n1",
        outcome: "ok",
        result: { credentialIdB64: "aWQ", clientDataJsonB64: "Y2Rq" },
      }),
    ).toBe(true);
  });

  it("rejects an ok outcome with no result", () => {
    expect(isPasskeyResponseToPage({ type: PASSKEY_PAGE_RESPONSE, nonce: "n1", outcome: "ok" })).toBe(false);
  });

  it("rejects an ok outcome whose result is missing credentialIdB64", () => {
    expect(
      isPasskeyResponseToPage({
        type: PASSKEY_PAGE_RESPONSE,
        nonce: "n1",
        outcome: "ok",
        result: { clientDataJsonB64: "Y2Rq" },
      }),
    ).toBe(false);
  });

  it("rejects an unknown outcome", () => {
    expect(isPasskeyResponseToPage({ type: PASSKEY_PAGE_RESPONSE, nonce: "n1", outcome: "maybe" })).toBe(false);
  });
});
