// `account-config.ts`: the fix for a real bug (see that module's doc comment) where
// `chrome.storage.local` silently no-ops inside a Chromium `chrome.offscreen` document, so
// `saveAccountConfig` never persisted anything there and `readAccountConfig` always reported
// "not enrolled" — even immediately after a successful `enrol`. This uses IndexedDB instead
// (`test/support/fake-idb.ts`, the same fake `cache/idb.ts`'s own tests use — no real
// `indexedDB` in vitest's `environment: "node"`), so these tests exercise the exact storage
// layer the fix depends on, not a mock of it.
import { beforeEach, describe, expect, it } from "vitest";

import { readAccountConfig, saveAccountConfig } from "../src/core-host/account-config.ts";
import { FakeIndexedDBFactory } from "./support/fake-idb.ts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fake(): any {
  return new FakeIndexedDBFactory();
}

describe("account-config.ts", () => {
  let factory: ReturnType<typeof fake>;

  beforeEach(() => {
    factory = fake();
  });

  it("reports undefined for both fields on a fresh profile", async () => {
    await expect(readAccountConfig(factory)).resolves.toEqual({ serverOrigin: undefined, loginName: undefined });
  });

  it("round-trips what it saved", async () => {
    await saveAccountConfig("https://vault.example.com", "alice", factory);
    await expect(readAccountConfig(factory)).resolves.toEqual({
      serverOrigin: "https://vault.example.com",
      loginName: "alice",
    });
  });

  it("a later save overwrites the earlier one (one device, one account at a time)", async () => {
    await saveAccountConfig("https://first.example.com", "alice", factory);
    await saveAccountConfig("https://second.example.com", "bob", factory);
    await expect(readAccountConfig(factory)).resolves.toEqual({
      serverOrigin: "https://second.example.com",
      loginName: "bob",
    });
  });

  it("survives being read by a second, independent call against the same factory — the exact shape handlePopupRequest uses: save during enrol, then read again for the immediately-following status check", async () => {
    await saveAccountConfig("https://vault.example.com", "alice", factory);
    const first = await readAccountConfig(factory);
    const second = await readAccountConfig(factory);
    expect(first).toEqual(second);
    expect(first.serverOrigin).toBe("https://vault.example.com");
  });
});
