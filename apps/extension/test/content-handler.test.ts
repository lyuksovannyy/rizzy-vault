// `handleContentScriptRequest` must never hand `decide()` a `pageUrl` the sender-validation step
// did not itself vouch for (THREAT_MODEL.md row 2, "a compromised/malicious content script").
// Pure logic, no browser APIs: `decide()` (the stub) is deterministic and synchronous.
import { describe, expect, it } from "vitest";

import { handleContentScriptRequest, handleInlineMenuFillRequest, selectFillCandidate } from "../src/core-host/content-handler.ts";
import type { CheckSavePromptMessage, FieldsDetectedMessage } from "../src/messaging/contract.ts";
import type { MatchCandidate } from "../src/core-host/bindings.ts";

function fieldsDetected(pageUrl: string): FieldsDetectedMessage {
  return { type: "fields_detected", pageUrl, isTopFrame: true, fields: [] };
}

function checkSavePrompt(pageUrl: string): CheckSavePromptMessage {
  return { type: "check_save_prompt", pageUrl };
}

describe("handleContentScriptRequest: fields_detected origin check", () => {
  it("accepts a pageUrl whose origin matches the sender-derived trustedOrigin", async () => {
    const response = await handleContentScriptRequest(fieldsDetected("https://example.com/login?x=1"), "https://example.com");
    // Locked (no session set up by this test), so a locked `content_error`, never `candidates`
    // with a placeholder list — the same "no device, no candidates" rule the stub it replaced
    // documented, now because the device is genuinely locked rather than genuinely unwired.
    expect(response.type).toBe("content_error");
  });

  it("refuses a pageUrl whose origin does not match trustedOrigin", async () => {
    const response = await handleContentScriptRequest(fieldsDetected("https://attacker.example/"), "https://example.com");
    expect(response).toEqual({
      type: "content_error",
      code: "fields_detected: pageUrl does not match the sender's own origin",
    });
  });

  it("refuses a pageUrl that does not even parse as a URL", async () => {
    const response = await handleContentScriptRequest(fieldsDetected("not-a-url"), "https://example.com");
    expect(response.type).toBe("content_error");
  });
});

// The save-prompt race fix's wire-up (`core-host/save-prompt-location.ts` holds the actual
// index logic, tested directly there): nothing was ever `credentials_submitted` in this test
// file (no session, no offer), so every one of these must answer "nothing pending", never an
// error — a plain cache-miss is the ordinary case on most page loads, not a failure.
describe("handleContentScriptRequest: check_save_prompt", () => {
  it("answers no_pending_save_prompt when nothing was ever offered for this tab", async () => {
    const response = await handleContentScriptRequest(checkSavePrompt("https://example.com/dashboard"), "https://example.com", 1);
    expect(response).toEqual({ type: "no_pending_save_prompt" });
  });

  it("answers no_pending_save_prompt when no trusted tab id is available at all", async () => {
    const response = await handleContentScriptRequest(checkSavePrompt("https://example.com/dashboard"), "https://example.com");
    expect(response).toEqual({ type: "no_pending_save_prompt" });
  });

  it("never refuses check_save_prompt for an origin mismatch (module docs: there is no trusted value to compare pageUrl against here)", async () => {
    const response = await handleContentScriptRequest(checkSavePrompt("https://attacker.example/"), "https://example.com", 1);
    expect(response).toEqual({ type: "no_pending_save_prompt" });
  });
});

// The fix for the security review's finding: `selectFillCandidate` is the one place that
// decides whether an `inline_menu_fill_chosen` request's `itemId` is actually among the
// candidates freshly recomputed for the sender's own tab, and whether an equivalence-only match
// still needs its second confirmation (ADR 0037 §5). Pure and synchronous, so no session or
// locked-device plumbing is needed to exercise it directly.
describe("selectFillCandidate", () => {
  const plainCandidate: MatchCandidate = { itemId: "item-1", uriId: "uri-1", needsWarning: false, savedHost: "example.com" };
  const warningCandidate: MatchCandidate = { itemId: "item-2", uriId: "uri-2", needsWarning: true, savedHost: "example.net" };

  it("accepts an itemId that is a current candidate with no warning needed", () => {
    expect(selectFillCandidate([plainCandidate], "item-1", false)).toEqual({ ok: true });
  });

  // The vulnerability this change fixes: the previous code revealed credentials for ANY
  // claimed itemId, with no check it was even a match for the sender's own page.
  it("refuses an itemId that is not among the current candidates", () => {
    const result = selectFillCandidate([plainCandidate], "some-other-item-never-offered", false);
    expect(result).toEqual({ ok: false, code: "inline_menu_fill_chosen: itemId is not a current candidate for this tab" });
  });

  // A look-alike/phishing page's own URL never produces this item as a candidate at all
  // (`decideMatchCandidates` upstream) — from this function's point of view that is simply an
  // empty (or non-matching) candidate list, refused the same way as any other non-membership.
  it("refuses any itemId when the candidate list is empty (e.g. a look-alike origin matched nothing)", () => {
    const result = selectFillCandidate([], "item-1", false);
    expect(result.ok).toBe(false);
  });

  it("refuses an equivalence-only candidate without confirmedEquivalence", () => {
    const result = selectFillCandidate([warningCandidate], "item-2", false);
    expect(result).toEqual({ ok: false, code: "inline_menu_fill_chosen: equivalence-only candidate needs confirmedEquivalence" });
  });

  it("accepts an equivalence-only candidate once confirmedEquivalence is true", () => {
    expect(selectFillCandidate([warningCandidate], "item-2", true)).toEqual({ ok: true });
  });

  it("never requires confirmedEquivalence for a candidate that does not need the warning", () => {
    expect(selectFillCandidate([plainCandidate], "item-1", true)).toEqual({ ok: true });
  });
});

describe("handleInlineMenuFillRequest", () => {
  it("refuses when the device is locked (no session set up by this test)", async () => {
    const ext = { tabs: { sendMessage: async () => undefined } } as unknown as WebExtNamespace;
    const response = await handleInlineMenuFillRequest(ext, 1, "https://example.com/login", {
      type: "inline_menu_fill_chosen",
      itemId: "item-1",
      confirmedEquivalence: false,
    });
    expect(response.type).toBe("content_error");
  });

  it("refuses a tab URL that does not even parse as a URL", async () => {
    const ext = { tabs: { sendMessage: async () => undefined } } as unknown as WebExtNamespace;
    const response = await handleInlineMenuFillRequest(ext, 1, "not-a-url", {
      type: "inline_menu_fill_chosen",
      itemId: "item-1",
      confirmedEquivalence: false,
    });
    expect(response).toEqual({ type: "content_error", code: "inline_menu_fill_chosen: the sender's tab URL does not parse" });
  });
});
