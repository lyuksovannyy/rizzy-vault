// SPDX-License-Identifier: AGPL-3.0-only

// `selectUpdateCandidate` is the save-vs-update decision core of `findItemForUpdate`
// (gap 33 in the M2 gap audit; finding 1 of the 2026-10-09 review): "same full host, same
// username -> update" vs. "same full host, different username -> save as a new item" vs.
// "a look-alike host is never an update target" vs. "a different full host sharing only the
// registrable domain is never an update target either". Pure and synchronous (no
// `DurableSession`, no wasm), the same reason `content-handler.ts`'s `selectFillCandidate` is
// tested directly rather than through a real session — see that function's own test file.
//
// Update overwrites the matched item's live password (`core-context.ts`'s `applySavePromptAction`,
// unconditional once a token names an `updateItemId`) — unlike autofill, it is not reversible by
// a second click. ADR 0037 §4's `BaseDomain` mode (the account default, and the only mode this
// extension's items currently resolve to, `sessionItemUris`) narrows only to the *registrable*
// domain, on purpose, for fill candidates: `accounts.example.com` and `example.com` are the same
// site for autofill. That is the wrong granularity for a destructive overwrite: a credential
// submitted on `blog.example.com` must never silently replace a password saved for
// `admin.example.com`, even though both share the registrable domain `example.com` and even if
// the submitted username happens to match. So `selectUpdateCandidate` applies one more, narrower
// gate on top of the ordinary `BaseDomain` candidate set, specific to the update decision: the
// candidate's own saved host (`MatchCandidate.savedHost`) must equal the page's own host
// (`pageHost`, `MatchDecisionResult.pageHost` — both already the same normalised, A-label,
// port-excluded form, ADR 0037 §2/§5) exactly, byte for byte. A saved `example.com` item does
// not update from a `www.example.com` submission either, under this same rule; that costs an
// extra save prompt (and possibly a duplicate item) rather than risk the wrong overwrite — the
// trade-off ADR 0037's own Negative consequences accept for autofill (reversible) does not carry
// over to update (not reversible).
import { describe, expect, it } from "vitest";

import { selectUpdateCandidate } from "../src/core-host/bindings.ts";
import type { MatchCandidate } from "../src/core-host/bindings.ts";

function candidate(itemId: string, needsWarning: boolean, savedHost = "example.com"): MatchCandidate {
  return { itemId, uriId: `${itemId}-uri`, needsWarning, savedHost };
}

describe("selectUpdateCandidate", () => {
  // Same full host, but the account on file has a different username: this must never be
  // treated as an update target, or submitting a second account's login on a site the user
  // already has one item for would silently overwrite that other account's saved password.
  it("same host, different username -> no update target (save as a new item)", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "bob", "example.com")).toBeUndefined();
  });

  // Same full host and the same username on file: this is the one case `findItemForUpdate`
  // exists to recognise, and it must return that exact item.
  it("same host, same username -> that item (update it)", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com")).toBe("item-1");
  });

  // A look-alike/merely-equivalent host (ADR 0037 §5, `needsWarning: true`) is never an update
  // target even when the username matches exactly: overwriting a saved password because the user
  // submitted a form on a different, only-"equivalent" domain is worse than one extra save prompt.
  it("look-alike host (equivalence-only match) -> never an update target, even with a matching username", () => {
    const candidates = [candidate("item-1", true)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com")).toBeUndefined();
  });

  it("no candidates at all -> no update target", () => {
    expect(selectUpdateCandidate([], () => "alice", "alice", "example.com")).toBeUndefined();
  });

  // A direct match takes priority over an equivalence-only one for the same item id: the
  // "checked" de-dup must not let a later, worse (`needsWarning`) listing of the same uriId/itemId
  // mask an earlier good one, and vice versa it must not re-check an itemId it already rejected.
  it("skips an equivalence-only duplicate once the same itemId already matched via a direct candidate", () => {
    const candidates = [candidate("item-1", false), candidate("item-1", true)];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com")).toBe("item-1");
  });

  // If the first (direct) listing for an itemId fails the username check, a later equivalence-only
  // listing for the SAME itemId must not be re-tried and must not somehow succeed — it is skipped
  // outright by the `needsWarning` rule, and the itemId is already marked checked regardless.
  it("does not fall through to a later equivalence-only listing of an itemId already checked", () => {
    const candidates = [candidate("item-1", false), candidate("item-1", true)];
    const usernameOf = () => "bob";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com")).toBeUndefined();
  });

  // Two different saved items on the same host: only the one whose username matches is picked,
  // not simply "the first candidate".
  it("picks the matching item among several candidates for different items", () => {
    const candidates = [candidate("item-1", false), candidate("item-2", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : "bob");
    expect(selectUpdateCandidate(candidates, usernameOf, "bob", "example.com")).toBe("item-2");
  });

  // `usernameOf` returning `undefined` (the lookup itself failed, e.g. `session.item` threw) must
  // be treated as "no username", matching only an explicit empty-string `username` — never as a
  // wildcard that matches everything.
  it("treats a failed username lookup as empty, not as a wildcard match", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = () => undefined;
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com")).toBeUndefined();
    expect(selectUpdateCandidate(candidates, usernameOf, "", "example.com")).toBe("item-1");
  });

  // Finding 1 (2026-10-09 review): a different subdomain of the SAME registrable domain — the
  // exact "same BaseDomain-mode registrable domain, different full host" shape `rizzy-match`
  // itself treats as one site for autofill (`crates/rizzy-client/src/matching.rs`'s own
  // `same_registrable_domain_matches_by_default` test, page "example.com" vs. saved
  // "login.example.com") — must never be an update target, even with a matching username. An
  // item saved for `a.example.com` is untouched by a submission on `b.example.com`.
  it("different subdomain of the same registrable domain -> no update target, even with a matching username", () => {
    const candidates = [candidate("item-1", false, "a.example.com")];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "b.example.com")).toBeUndefined();
  });

  // The same shape, but for a domain a single owner does not control end to end: a shared
  // hosting apex not (yet) split in the Public Suffix List, where unrelated tenants each get a
  // subdomain (the `psl`/PSL mechanism ADR 0037 §3 relies on to prevent exactly this for a
  // *registered* platform like `github.io`; an apex the PSL has not caught up to yet gets no
  // such split, so `rizzy-match`'s own registrable-domain gate alone cannot tell two tenants
  // apart). The host check must still refuse it, independent of PSL coverage.
  it("different tenant on a shared, not-yet-PSL-split hosting domain -> no update target, even with a matching username", () => {
    const candidates = [candidate("item-1", false, "tenant-one.example-hosting.test")];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "tenant-two.example-hosting.test")).toBeUndefined();
  });

  // The host gate is per-candidate (per saved URI), not per-item: a second saved URI for the
  // SAME item, on the page's own host, must still be found and picked, even though an earlier
  // listing for that item (a different saved URI) was on the wrong host. Confirms the host check
  // does not get folded into the `checked` de-dup in a way that poisons the whole item.
  it("a second saved URI for the same item, on the page's own host, is still picked after an earlier one on a different host", () => {
    const candidates = [candidate("item-1", false, "a.example.com"), candidate("item-1", false, "b.example.com")];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "b.example.com")).toBe("item-1");
  });

  // Two different items: the one whose username matches is on the WRONG host, and the one on the
  // RIGHT host has a different username. Neither must be picked — proves the host and username
  // checks are both applied to the SAME candidate, not satisfied independently across different
  // candidates.
  it("never picks an item by combining one candidate's host match with a different candidate's username match", () => {
    const candidates = [candidate("item-1", false, "wrong.example.com"), candidate("item-2", false, "b.example.com")];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : "bob");
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "b.example.com")).toBeUndefined();
  });
});
