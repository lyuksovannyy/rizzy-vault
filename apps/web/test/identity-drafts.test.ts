// SPDX-License-Identifier: AGPL-3.0-only

// The Worker's identity draft handles (`identity-drafts.ts`): a redraw replaces and frees its
// draft, a release or a lock frees, a stale handle finds nothing, and the oldest draft is freed
// past the limit, so a forgotten release cannot grow the Worker's memory.
import { describe, expect, it } from "vitest";

import { DraftRegistry, MAX_IDENTITY_DRAFTS } from "../src/identity-drafts.ts";
import { isIdentityDefaults, isIdentityOptions, isSettingsChange, METHODS } from "../src/protocol.ts";

/** A draft that records its own freeing. */
function fake(name: string, freed: string[]) {
  return { name, free: () => freed.push(name) };
}

describe("DraftRegistry", () => {
  it("adds, replaces, releases and clears, freeing each draft once", () => {
    const freed: string[] = [];
    const reg = new DraftRegistry<ReturnType<typeof fake>>();
    const a = reg.add(fake("a", freed));
    const b = reg.add(fake("b", freed));
    expect(a).not.toBe(b);
    expect(reg.get(a)?.name).toBe("a");
    const a2 = reg.replace(a, fake("a2", freed));
    expect(freed).toEqual(["a"]);
    expect(reg.get(a)).toBeUndefined();
    expect(reg.get(a2)?.name).toBe("a2");
    expect(a2).not.toBe(a);
    reg.release(b);
    reg.release(b);
    reg.release(12345);
    expect(freed).toEqual(["a", "b"]);
    reg.clear();
    expect(freed).toEqual(["a", "b", "a2"]);
    expect(reg.size).toBe(0);
    expect(reg.get(a2)).toBeUndefined();
  });

  it("frees the oldest draft past the limit and never reuses a handle", () => {
    const freed: string[] = [];
    const reg = new DraftRegistry<ReturnType<typeof fake>>();
    const handles: number[] = [];
    for (let i = 0; i < MAX_IDENTITY_DRAFTS + 3; i++) {
      handles.push(reg.add(fake(String(i), freed)));
    }
    expect(reg.size).toBe(MAX_IDENTITY_DRAFTS);
    expect(freed).toEqual(["0", "1", "2"]);
    expect(new Set(handles).size).toBe(handles.length);
    expect(reg.get(handles[0] ?? 0)).toBeUndefined();
  });
});

describe("identity messages", () => {
  const options = { sex: "random", country: "US", ageMin: 18, ageMax: 27, emailStyle: "name", emailDomain: null };
  const defaults = { sex: "male", country: null, ageMin: 30, ageMax: 30, emailStyle: "nickname", emailDomain: "example.com" };

  it("are calls the Worker serves", () => {
    for (const m of ["identityGenerate", "identityRegenerate", "identityRelease", "identityCountries", "identityDefaults", "normalizeEmailDomain"]) {
      expect(METHODS).toContain(m);
    }
  });

  it("checks the options' shape", () => {
    expect(isIdentityOptions(options)).toBe(true);
    expect(isIdentityOptions({ ...options, emailDomain: undefined })).toBe(true);
    expect(isIdentityOptions({ ...options, sex: "other" })).toBe(false);
    expect(isIdentityOptions({ ...options, ageMin: 1.5 })).toBe(false);
    expect(isIdentityOptions({ ...options, emailStyle: "x" })).toBe(false);
    expect(isIdentityOptions({ ...options, emailDomain: "a".repeat(5000) })).toBe(false);
    expect(isIdentityOptions({ ...options, country: 5 })).toBe(false);
    expect(isIdentityOptions(null)).toBe(false);
  });

  it("takes the identity defaults as a settings change", () => {
    expect(isIdentityDefaults(defaults)).toBe(true);
    expect(isSettingsChange({ kind: "identityDefaults", defaults })).toBe(true);
    expect(isSettingsChange({ kind: "identityDefaults", defaults: { ...defaults, emailDomain: undefined } })).toBe(false);
    expect(isSettingsChange({ kind: "identityDefaults", defaults: { ...defaults, sex: "x" } })).toBe(false);
    expect(isSettingsChange({ kind: "identityDefaults" })).toBe(false);
  });
});
