// SPDX-License-Identifier: AGPL-3.0-only

// `core/client.ts`'s `revocationRetry` (ADR 0091 §2): the popup's question to the long-lived
// context after a sync refused `server_revocation_pending`. It sends the retry count, reads the
// time and the banner's sentence, and reads an answer of any other shape as the end of the
// schedule (the popup then reports the refusal), never as a retry.
import { describe, expect, it } from "vitest";

import { ExtensionClient } from "../src/core/client.ts";
import type { PopupRequest, PopupResponse } from "../src/messaging/contract.ts";
import { REVOCATION_PENDING, REVOCATION_REFUSED } from "../src/popup/revocation.ts";

const SENTENCE = "Another of your devices is removing a device. Changes are paused for up to 10 minutes.";

/** A client whose transport answers `answer` and records the requests. */
function clientAnswering(answer: unknown): { client: ExtensionClient; seen: PopupRequest[] } {
  const seen: PopupRequest[] = [];
  const client = new ExtensionClient(async (request) => {
    seen.push(request);
    return answer as PopupResponse;
  });
  return { client, seen };
}

describe("revocationRetry", () => {
  it("asks with the retry count and reads the time and the sentence", async () => {
    const { client, seen } = clientAnswering({ type: "revocation_retry", retryAtMs: 15_000, notice: SENTENCE });
    expect(await client.revocationRetry(3)).toEqual({ retryAtMs: 15_000, notice: SENTENCE });
    expect(seen).toEqual([{ type: "revocation_retry", retriesDone: 3 }]);
  });

  it("reads the end of the schedule", async () => {
    const { client } = clientAnswering({ type: "revocation_retry", notice: SENTENCE });
    expect(await client.revocationRetry(41)).toEqual({ retryAtMs: undefined, notice: SENTENCE });
  });

  it("reads any other shape as the end of the schedule", async () => {
    for (const answer of [
      { type: "revocation_retry", retryAtMs: "15000", notice: SENTENCE },
      { type: "revocation_retry", retryAtMs: Number.NaN, notice: SENTENCE },
      { type: "revocation_retry", retryAtMs: 15_000 },
      { type: "revocation_retry", retryAtMs: 15_000, notice: "" },
      { type: "revocation_retry", retryAtMs: 15_000, notice: 7 },
    ]) {
      expect((await clientAnswering(answer).client.revocationRetry(0)).retryAtMs, JSON.stringify(answer)).toBeUndefined();
    }
  });

  it("throws the long-lived context's error code", async () => {
    const { client } = clientAnswering({ type: "error", code: "locked" });
    await expect(client.revocationRetry(0)).rejects.toThrow("locked");
  });

  it("names the code and the refusal the popup reports", () => {
    expect(REVOCATION_PENDING).toBe("server_revocation_pending");
    expect(REVOCATION_REFUSED).toContain("removing a device");
  });
});
