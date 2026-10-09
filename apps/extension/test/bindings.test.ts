// `selectUpdateCandidate` is the save-vs-update decision core of `findItemForUpdate`
// (gap 33 in the M2 gap audit): "same host, same username -> update" vs. "same host, different
// username -> save as a new item" vs. "a look-alike host is never an update target". Pure and
// synchronous (no `DurableSession`, no wasm), the same reason `content-handler.ts`'s
// `selectFillCandidate` is tested directly rather than through a real session — see that
// function's own test file.
import { describe, expect, it } from "vitest";

import { selectUpdateCandidate } from "../src/core-host/bindings.ts";
import type { MatchCandidate } from "../src/core-host/bindings.ts";

function candidate(itemId: string, needsWarning: boolean, savedHost = "example.com"): MatchCandidate {
  return { itemId, uriId: `${itemId}-uri`, needsWarning, savedHost };
}

describe("selectUpdateCandidate", () => {
  // Same registrable domain, but the account on file has a different username: this must never
  // be treated as an update target, or submitting a second account's login on a site the user
  // already has one item for would silently overwrite that other account's saved password.
  it("same host, different username -> no update target (save as a new item)", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "bob")).toBeUndefined();
  });

  // Same registrable domain and the same username on file: this is the one case `findItemForUpdate`
  // exists to recognise, and it must return that exact item.
  it("same host, same username -> that item (update it)", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "alice")).toBe("item-1");
  });

  // A look-alike/merely-equivalent host (ADR 0037 §5, `needsWarning: true`) is never an update
  // target even when the username matches exactly: overwriting a saved password because the user
  // submitted a form on a different, only-"equivalent" domain is worse than one extra save prompt.
  it("look-alike host (equivalence-only match) -> never an update target, even with a matching username", () => {
    const candidates = [candidate("item-1", true)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "alice")).toBeUndefined();
  });

  it("no candidates at all -> no update target", () => {
    expect(selectUpdateCandidate([], () => "alice", "alice")).toBeUndefined();
  });

  // A direct match takes priority over an equivalence-only one for the same item id: the
  // "checked" de-dup must not let a later, worse (`needsWarning`) listing of the same uriId/itemId
  // mask an earlier good one, and vice versa it must not re-check an itemId it already rejected.
  it("skips an equivalence-only duplicate once the same itemId already matched via a direct candidate", () => {
    const candidates = [candidate("item-1", false), candidate("item-1", true)];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice")).toBe("item-1");
  });

  // If the first (direct) listing for an itemId fails the username check, a later equivalence-only
  // listing for the SAME itemId must not be re-tried and must not somehow succeed — it is skipped
  // outright by the `needsWarning` rule, and the itemId is already marked checked regardless.
  it("does not fall through to a later equivalence-only listing of an itemId already checked", () => {
    const candidates = [candidate("item-1", false), candidate("item-1", true)];
    const usernameOf = () => "bob";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice")).toBeUndefined();
  });

  // Two different saved items on the same host: only the one whose username matches is picked,
  // not simply "the first candidate".
  it("picks the matching item among several candidates for different items", () => {
    const candidates = [candidate("item-1", false), candidate("item-2", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : "bob");
    expect(selectUpdateCandidate(candidates, usernameOf, "bob")).toBe("item-2");
  });

  // `usernameOf` returning `undefined` (the lookup itself failed, e.g. `session.item` threw) must
  // be treated as "no username", matching only an explicit empty-string `username` — never as a
  // wildcard that matches everything.
  it("treats a failed username lookup as empty, not as a wildcard match", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = () => undefined;
    expect(selectUpdateCandidate(candidates, usernameOf, "alice")).toBeUndefined();
    expect(selectUpdateCandidate(candidates, usernameOf, "")).toBe("item-1");
  });
});
