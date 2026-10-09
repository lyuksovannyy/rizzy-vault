// The relay content script <-> passkey-consent iframe channel (`passkey-consent/protocol.ts`),
// the same asymmetric-trust pattern as `inline-menu/protocol.ts`'s own tested validators
// (`inline-menu-protocol.test.ts`) — this validator only bounds the shape before display; the
// actual approval boundary is `messaging/contract.ts`'s `isPasskeyCeremonyMessage`, tested in
// `passkey-messaging.test.ts`.
import { describe, expect, it } from "vitest";

import {
  PASSKEY_CONSENT_DONE,
  PASSKEY_CONSENT_SHOW,
  isPasskeyConsentDoneMessage,
  isPasskeyConsentShowMessage,
} from "../src/passkey-consent/protocol.ts";

const createOffer = {
  type: PASSKEY_CONSENT_SHOW,
  pageOrigin: "https://example.com",
  ceremonyToken: "tok-1",
  kind: "create",
  rpId: "example.com",
  rpName: "Example",
  userName: "alice",
};

const getOffer = {
  type: PASSKEY_CONSENT_SHOW,
  pageOrigin: "https://example.com",
  ceremonyToken: "tok-2",
  kind: "get",
  rpId: "example.com",
  candidates: [{ passkeyRef: "item-1:el-1", itemTitle: "Example", userName: "alice" }],
};

describe("isPasskeyConsentShowMessage", () => {
  it("accepts a well-formed create offer", () => {
    expect(isPasskeyConsentShowMessage(createOffer)).toBe(true);
  });

  it("accepts a well-formed get offer with candidates", () => {
    expect(isPasskeyConsentShowMessage(getOffer)).toBe(true);
  });

  it("accepts a get offer with an empty candidates array", () => {
    expect(isPasskeyConsentShowMessage({ ...getOffer, candidates: [] })).toBe(true);
  });

  it("rejects an unknown kind", () => {
    expect(isPasskeyConsentShowMessage({ ...createOffer, kind: "delete" })).toBe(false);
  });

  it("rejects a missing ceremonyToken", () => {
    const { ceremonyToken, ...rest } = createOffer;
    void ceremonyToken;
    expect(isPasskeyConsentShowMessage(rest)).toBe(false);
  });

  it("rejects a malformed candidate entry", () => {
    expect(isPasskeyConsentShowMessage({ ...getOffer, candidates: [{ passkeyRef: "x" }] })).toBe(false);
  });

  it("rejects a non-object", () => {
    expect(isPasskeyConsentShowMessage(null)).toBe(false);
    expect(isPasskeyConsentShowMessage("offer")).toBe(false);
  });
});

describe("isPasskeyConsentDoneMessage", () => {
  it("accepts the teardown message", () => {
    expect(isPasskeyConsentDoneMessage({ type: PASSKEY_CONSENT_DONE })).toBe(true);
  });

  it("rejects anything else", () => {
    expect(isPasskeyConsentDoneMessage({ type: "something-else" })).toBe(false);
    expect(isPasskeyConsentDoneMessage(null)).toBe(false);
  });
});
