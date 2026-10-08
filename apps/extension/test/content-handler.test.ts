// `handleContentScriptRequest` must never hand `decide()` a `pageUrl` the sender-validation step
// did not itself vouch for (THREAT_MODEL.md row 2, "a compromised/malicious content script").
// Pure logic, no browser APIs: `decide()` (the stub) is deterministic and synchronous.
import { describe, expect, it } from "vitest";

import { handleContentScriptRequest } from "../src/core-host/content-handler.ts";
import type { FieldsDetectedMessage } from "../src/messaging/contract.ts";

function fieldsDetected(pageUrl: string): FieldsDetectedMessage {
  return { type: "fields_detected", pageUrl, isTopFrame: true, fields: [] };
}

describe("handleContentScriptRequest: fields_detected origin check", () => {
  it("accepts a pageUrl whose origin matches the sender-derived trustedOrigin", () => {
    const response = handleContentScriptRequest(fieldsDetected("https://example.com/login?x=1"), "https://example.com");
    expect(response.type).toBe("candidates");
  });

  it("refuses a pageUrl whose origin does not match trustedOrigin", () => {
    const response = handleContentScriptRequest(fieldsDetected("https://attacker.example/"), "https://example.com");
    expect(response).toEqual({
      type: "content_error",
      code: "fields_detected: pageUrl does not match the sender's own origin",
    });
  });

  it("refuses a pageUrl that does not even parse as a URL", () => {
    const response = handleContentScriptRequest(fieldsDetected("not-a-url"), "https://example.com");
    expect(response.type).toBe("content_error");
  });
});
