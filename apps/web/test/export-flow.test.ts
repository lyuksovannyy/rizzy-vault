// The export and import steps (owner decision 2026-10-05): no export without a fresh
// re-authentication, the file's password typed twice, and the import format recognised.
import { describe, expect, it } from "vitest";

import { CallError } from "../src/core-client.ts";
import { type Caller, confirmIdentity, encryptedExport, importPlan } from "../src/export-flow.ts";

/** A fake core: one re-authentication allows one export, as the real one. */
function fakeCore(): { client: Caller; calls: string[] } {
  const calls: string[] = [];
  let fresh = false;
  const call = (method: string, ...args: unknown[]): Promise<unknown> => {
    calls.push(method);
    switch (method) {
      case "reauthenticate": {
        const password = new TextDecoder().decode(args[1] as Uint8Array);
        if (password !== "master password") {
          return Promise.reject(new CallError("wrong_password_or_secret_key"));
        }
        fresh = true;
        return Promise.resolve(undefined);
      }
      case "reauthFresh":
        return Promise.resolve(fresh);
      case "exportEncrypted":
        if (!fresh) {
          return Promise.reject(new CallError("reauth_required"));
        }
        fresh = false;
        return Promise.resolve({ file: new Uint8Array([1]), items: 1, unresolved: 0 });
      default:
        return Promise.reject(new CallError("wrong_state"));
    }
  };
  return { client: { call } as unknown as Caller, calls };
}

describe("the export gate", () => {
  it("asks the core for nothing without a re-authentication", async () => {
    const { client, calls } = fakeCore();
    await expect(encryptedExport(client, "file pw", "file pw")).rejects.toMatchObject({
      code: "reauth_required",
    });
    expect(calls).not.toContain("exportEncrypted");
  });

  it("refuses a wrong master password, and still exports nothing", async () => {
    const { client, calls } = fakeCore();
    await expect(confirmIdentity(client, "RV1-…", "wrong")).rejects.toMatchObject({
      code: "wrong_password_or_secret_key",
    });
    await expect(encryptedExport(client, "file pw", "file pw")).rejects.toMatchObject({
      code: "reauth_required",
    });
    expect(calls).not.toContain("exportEncrypted");
  });

  it("allows one export per re-authentication", async () => {
    const { client } = fakeCore();
    await confirmIdentity(client, "RV1-…", "master password");
    const out = await encryptedExport(client, "file pw", "file pw");
    expect(out.items).toBe(1);
    await expect(encryptedExport(client, "file pw", "file pw")).rejects.toMatchObject({
      code: "reauth_required",
    });
  });

  it("wants the file's password twice, the same", async () => {
    const { client, calls } = fakeCore();
    await confirmIdentity(client, "RV1-…", "master password");
    await expect(encryptedExport(client, "file pw", "file pwd")).rejects.toMatchObject({
      code: "passwords_differ",
    });
    expect(calls).not.toContain("exportEncrypted");
  });
});

describe("the import plan", () => {
  it("opens our encrypted export with its password and refuses what has no reader", () => {
    expect(importPlan("rizzy-encrypted")).toEqual({ kind: "encrypted" });
    expect(importPlan("rizzy-json")).toEqual({ kind: "file", format: "rizzy-json" });
    expect(importPlan("1pux")).toEqual({ kind: "file", format: "1pux" });
    expect(importPlan("rizzy-csv")).toEqual({ kind: "refused", code: "rizzy_csv_not_importable" });
    expect(importPlan("unknown")).toEqual({ kind: "refused", code: "unrecognised_format" });
  });
});
