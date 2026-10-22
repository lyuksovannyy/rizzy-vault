// SPDX-License-Identifier: AGPL-3.0-only

// The breach check's words and the vault-wide report (ADR 0053; `src/breach.ts`): what a result
// and a failure say, and how the report walks the items, waits on a rate limit, stops on an
// unavailable check and on cancel.
import { describe, expect, it } from "vitest";

import {
  type BreachResult,
  MAX_RATE_LIMIT_RETRIES,
  PRIVACY_NOTE,
  RATE_LIMIT_WAIT_MS,
  type ReportState,
  failureText,
  isUnavailable,
  resultText,
  runReport,
} from "../src/breach.ts";
import { METHODS } from "../src/protocol.ts";

const items = [
  { id: "a", title: "Alpha" },
  { id: "b", title: "Bravo" },
  { id: "c", title: "Charlie" },
];

/** A check answering from a table, recording the ids it was asked for. */
function table(answers: Record<string, BreachResult | null | string>): {
  check: (id: string) => Promise<BreachResult | null>;
  asked: string[];
} {
  const asked: string[] = [];
  return {
    asked,
    check: async (id) => {
      asked.push(id);
      const a = answers[id];
      if (typeof a === "string") {
        throw { code: a };
      }
      return a ?? null;
    },
  };
}

describe("words", () => {
  it("say what leaves the browser and what a result means", () => {
    expect(PRIVACY_NOTE).toMatch(/first 5 characters of a hash/);
    expect(PRIVACY_NOTE).toMatch(/never leaves/);
    expect(resultText({ found: false, count: 0 })).toBe("Not found in known data breaches.");
    expect(resultText({ found: true, count: 1 })).toMatch(/seen once/);
    expect(resultText({ found: true, count: 52256179 })).toMatch(/seen 52,256,179 times/);
  });

  it("read a switched-off check, a rate limit and an outage apart", () => {
    expect(failureText("server_not_found")).toMatch(/not enabled on this server/);
    expect(failureText("server_rate_limited")).toMatch(/Too many checks/);
    expect(failureText("server_internal")).toMatch(/unavailable/);
    expect(failureText("transport_failed")).toMatch(/unavailable/);
    expect(isUnavailable("server_not_found")).toBe(true);
    expect(isUnavailable("server_internal")).toBe(true);
    expect(isUnavailable("server_rate_limited")).toBe(false);
  });

  it("are Worker methods", () => {
    expect(METHODS).toContain("breachCheckItem");
    expect(METHODS).toContain("breachCheckPassword");
  });
});

describe("the report", () => {
  it("checks every item and lists the breached ones", async () => {
    const { check, asked } = table({ a: { found: true, count: 3 }, b: null, c: { found: false, count: 0 } });
    const states: ReportState[] = [];
    const last = await runReport(items, check, async () => {}, () => false, (s) => states.push(s));
    expect(asked).toEqual(["a", "b", "c"]);
    expect(last.status).toBe("done");
    expect(last.checked).toBe(3);
    expect(last.withPassword).toBe(2);
    expect(last.hits).toEqual([{ id: "a", title: "Alpha", count: 3 }]);
    expect(states[0]?.status).toBe("running");
    expect(states.at(-1)).toEqual(last);
  });

  it("waits and retries the same item after a rate limit", async () => {
    let calls = 0;
    const waits: number[] = [];
    const check = async (id: string) => {
      calls += 1;
      if (id === "b" && calls < 4) {
        throw { code: "server_rate_limited" };
      }
      return { found: false, count: 0 };
    };
    const last = await runReport(items, check, async (ms) => void waits.push(ms), () => false, () => {});
    expect(last.status).toBe("done");
    expect(last.checked).toBe(3);
    expect(waits).toEqual([RATE_LIMIT_WAIT_MS, RATE_LIMIT_WAIT_MS]);
  });

  it("gives up after too many rate limits in a row", async () => {
    const { check } = table({ a: "server_rate_limited" });
    let waits = 0;
    const last = await runReport(items, check, async () => void (waits += 1), () => false, () => {});
    expect(last.status).toEqual({ failed: "server_rate_limited" });
    expect(waits).toBe(MAX_RATE_LIMIT_RETRIES);
  });

  it("stops on an unavailable check", async () => {
    const { check, asked } = table({ a: { found: false, count: 0 }, b: "server_not_found" });
    const last = await runReport(items, check, async () => {}, () => false, () => {});
    expect(last.status).toEqual({ failed: "server_not_found" });
    expect(asked).toEqual(["a", "b"]);
    expect(last.checked).toBe(1);
  });

  it("stops when cancelled", async () => {
    const { check, asked } = table({});
    let n = 0;
    const last = await runReport(items, check, async () => {}, () => (n += 1) > 2, () => {});
    expect(last.status).toBe("cancelled");
    expect(asked).toEqual(["a", "b"]);
  });
});
