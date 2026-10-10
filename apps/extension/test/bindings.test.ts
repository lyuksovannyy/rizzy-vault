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
// a second click. ADR 0037 §4's `BaseDomain` mode (the account default, and the mode every URI
// below is given, since none carries a stored `match` override) narrows only to the *registrable*
// domain, on purpose, for fill candidates: `accounts.example.com` and `example.com` are the same
// site for autofill. That is the wrong granularity for a destructive overwrite: a credential
// submitted on `blog.example.com` must never silently replace a password saved for
// `admin.example.com`, even though both share the registrable domain `example.com` and even if
// the submitted username happens to match. So `selectUpdateCandidate` applies one more, narrower
// gate on top of the ordinary `BaseDomain` candidate set, specific to the update decision: the
// candidate's own saved host and port (`MatchCandidate.savedHost`/`savedPort`) must equal the
// page's own host and port (`pageHost`/`pagePort`, `MatchDecisionResult.pageHost`/`pagePort` —
// all already the same normalised, A-label form, ADR 0037 §2/§5) exactly, byte for byte for the
// host and value-equal for the port. A saved `example.com` item does not update from a
// `www.example.com` submission either, under this same rule; that costs an extra save prompt
// (and possibly a duplicate item) rather than risk the wrong overwrite — the trade-off ADR 0037's
// own Negative consequences accept for autofill (reversible) does not carry over to update (not
// reversible). The same is true of the port (ADR 0037 §2 rule 5: a non-default port is part of
// the same-site comparison): a page at `https://example.com:8443` must never update an item saved
// for `https://example.com:9000`, even though `BaseDomain` mode — these fixtures' own mode, and
// the candidate set this gate narrows on top of — does not tell the two ports apart at all.
import type { FieldView } from "@rizzy-vault/core";
import { MatchMode } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { itemUriFields, matchModeOf, selectUpdateCandidate } from "../src/core-host/bindings.ts";
import type { MatchCandidate } from "../src/core-host/bindings.ts";

/** A field view with defaults (same fixture shape as `apps/web/test/fields.test.ts`'s `f`). */
function f(key: string, more: Partial<FieldView> = {}): FieldView {
  return {
    key,
    list: undefined,
    element: undefined,
    attribute: undefined,
    tag: undefined,
    kind: "text",
    concealed: false,
    value: undefined,
    conflict: false,
    ...more,
  };
}

function candidate(
  itemId: string,
  needsWarning: boolean,
  savedHost = "example.com",
  savedPort: number | undefined = undefined,
): MatchCandidate {
  return { itemId, uriId: `${itemId}-uri`, needsWarning, savedHost, savedPort };
}

// Finding 3 (2026-10-09 review): `itemUriFields`/`sessionItemUris` used to hardcode every URI's
// mode to `MatchMode.BaseDomain`, discarding a stored `uri/<id>/match` override. That is live
// today, not hypothetical: `apps/web/src/views/ItemEditor.tsx` already writes `match` (including
// `0x0006` Never, listed in `apps/web/src/fields.ts`'s `MATCH_MODE_OPTIONS`), so a user can mark
// a website Never in the web vault, sync, and have the extension go on offering it for autofill
// anyway unless this module actually reads the register back.
describe("matchModeOf", () => {
  it("resolves absent (never written) to the account default, BaseDomain", () => {
    expect(matchModeOf(undefined)).toBe(MatchMode.BaseDomain);
  });

  it("resolves the explicit account-default sentinel (wire 0x0000) to BaseDomain", () => {
    expect(matchModeOf("0")).toBe(MatchMode.BaseDomain);
  });

  it("round-trips every assigned wire value (ADR 0037 §4) decoded as decimal", () => {
    expect(matchModeOf("1")).toBe(MatchMode.BaseDomain);
    expect(matchModeOf("2")).toBe(MatchMode.Host);
    expect(matchModeOf("3")).toBe(MatchMode.StartsWith);
    expect(matchModeOf("4")).toBe(MatchMode.Exact);
    expect(matchModeOf("5")).toBe(MatchMode.Regex);
    expect(matchModeOf("6")).toBe(MatchMode.Never);
  });

  // The whole point of this finding: a stored "Never" override must survive, not get silently
  // replaced by BaseDomain.
  it("honors a stored Never override rather than discarding it", () => {
    expect(matchModeOf("6")).not.toBe(MatchMode.BaseDomain);
    expect(matchModeOf("6")).toBe(MatchMode.Never);
  });

  // A well-formed but unassigned Enum value (ADR 0037 §4 row `0x0007`-`0xFFFF`: a real mode a
  // newer client may have meant) must never reach `decideMatchCandidates` as a raw number:
  // `crates/rizzy-wasm/src/matching.rs`'s `mode_of` turns an unrecognised wire value into
  // `invalid_input`, which would fail the *entire* batch call, not just this one URI. Narrowing
  // to `Never` (never offered) rather than widening to `BaseDomain` keeps INV-38's
  // narrowing-only rule on an unknown-but-real value too.
  it("narrows an unassigned wire value to Never instead of passing it through or widening it", () => {
    expect(matchModeOf("7")).toBe(MatchMode.Never);
    expect(matchModeOf("65535")).toBe(MatchMode.Never);
  });

  // Unparseable text is corrupt or otherwise not a value any client meant to set — not a real,
  // deliberate Enum value the way an unassigned number above might be — so it is treated the
  // same as "no override" (BaseDomain), not narrowed to Never: a corrupt register must not
  // silently disable autofill for a URI with no explanation anywhere.
  it("resolves unparseable text to BaseDomain, the same as no override at all", () => {
    expect(matchModeOf("not a number")).toBe(MatchMode.BaseDomain);
  });
});

describe("itemUriFields", () => {
  it("pairs a URI's value with its sibling match attribute, decoded to a MatchModeValue", () => {
    const fields = [
      f("uri/a/value", { list: "uri", element: "a", attribute: "value", value: "https://x.example/" }),
      f("uri/a/match", { list: "uri", element: "a", attribute: "match", kind: "enum", value: "6" }),
    ];
    expect(itemUriFields(fields)).toEqual([
      { uriId: "a", value: "https://x.example/", mode: MatchMode.Never },
    ]);
  });

  it("resolves to BaseDomain when a URI has no match register at all (never written)", () => {
    const fields = [f("uri/a/value", { list: "uri", element: "a", attribute: "value", value: "https://x.example/" })];
    expect(itemUriFields(fields)).toEqual([
      { uriId: "a", value: "https://x.example/", mode: MatchMode.BaseDomain },
    ]);
  });

  it("handles several URIs with independent match overrides, regardless of field order", () => {
    const fields = [
      f("uri/a/match", { list: "uri", element: "a", attribute: "match", kind: "enum", value: "2" }),
      f("uri/a/value", { list: "uri", element: "a", attribute: "value", value: "https://a.example/" }),
      f("uri/b/value", { list: "uri", element: "b", attribute: "value", value: "https://b.example/" }),
      f("uri/b/match", { list: "uri", element: "b", attribute: "match", kind: "enum", value: "0" }),
    ];
    expect(itemUriFields(fields)).toEqual([
      { uriId: "a", value: "https://a.example/", mode: MatchMode.Host },
      { uriId: "b", value: "https://b.example/", mode: MatchMode.BaseDomain },
    ]);
  });

  it("ignores a match register whose URI has no value (not a real row to match against)", () => {
    const fields = [f("uri/a/match", { list: "uri", element: "a", attribute: "match", kind: "enum", value: "6" })];
    expect(itemUriFields(fields)).toEqual([]);
  });

  it("ignores fields from other lists and attributes (order, passkeys, other items' plain fields)", () => {
    const fields = [
      f("uri/a/order", { list: "uri", element: "a", attribute: "order", kind: "sort_key" }),
      f("uri/a/value", { list: "uri", element: "a", attribute: "value", value: "https://a.example/" }),
      f("login.username", { value: "alice" }),
    ];
    expect(itemUriFields(fields)).toEqual([{ uriId: "a", value: "https://a.example/", mode: MatchMode.BaseDomain }]);
  });
});

describe("selectUpdateCandidate", () => {
  // Same full host, but the account on file has a different username: this must never be
  // treated as an update target, or submitting a second account's login on a site the user
  // already has one item for would silently overwrite that other account's saved password.
  it("same host, different username -> no update target (save as a new item)", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "bob", "example.com", undefined)).toBeUndefined();
  });

  // Same full host and the same username on file: this is the one case `findItemForUpdate`
  // exists to recognise, and it must return that exact item.
  it("same host, same username -> that item (update it)", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", undefined)).toBe("item-1");
  });

  // A look-alike/merely-equivalent host (ADR 0037 §5, `needsWarning: true`) is never an update
  // target even when the username matches exactly: overwriting a saved password because the user
  // submitted a form on a different, only-"equivalent" domain is worse than one extra save prompt.
  it("look-alike host (equivalence-only match) -> never an update target, even with a matching username", () => {
    const candidates = [candidate("item-1", true)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : undefined);
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", undefined)).toBeUndefined();
  });

  it("no candidates at all -> no update target", () => {
    expect(selectUpdateCandidate([], () => "alice", "alice", "example.com", undefined)).toBeUndefined();
  });

  // A direct match takes priority over an equivalence-only one for the same item id: the
  // "checked" de-dup must not let a later, worse (`needsWarning`) listing of the same uriId/itemId
  // mask an earlier good one, and vice versa it must not re-check an itemId it already rejected.
  it("skips an equivalence-only duplicate once the same itemId already matched via a direct candidate", () => {
    const candidates = [candidate("item-1", false), candidate("item-1", true)];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", undefined)).toBe("item-1");
  });

  // If the first (direct) listing for an itemId fails the username check, a later equivalence-only
  // listing for the SAME itemId must not be re-tried and must not somehow succeed — it is skipped
  // outright by the `needsWarning` rule, and the itemId is already marked checked regardless.
  it("does not fall through to a later equivalence-only listing of an itemId already checked", () => {
    const candidates = [candidate("item-1", false), candidate("item-1", true)];
    const usernameOf = () => "bob";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", undefined)).toBeUndefined();
  });

  // Two different saved items on the same host: only the one whose username matches is picked,
  // not simply "the first candidate".
  it("picks the matching item among several candidates for different items", () => {
    const candidates = [candidate("item-1", false), candidate("item-2", false)];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : "bob");
    expect(selectUpdateCandidate(candidates, usernameOf, "bob", "example.com", undefined)).toBe("item-2");
  });

  // `usernameOf` returning `undefined` (the lookup itself failed, e.g. `session.item` threw) must
  // be treated as "no username", matching only an explicit empty-string `username` — never as a
  // wildcard that matches everything.
  it("treats a failed username lookup as empty, not as a wildcard match", () => {
    const candidates = [candidate("item-1", false)];
    const usernameOf = () => undefined;
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", undefined)).toBeUndefined();
    expect(selectUpdateCandidate(candidates, usernameOf, "", "example.com", undefined)).toBe("item-1");
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
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "b.example.com", undefined)).toBeUndefined();
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
    expect(
      selectUpdateCandidate(candidates, usernameOf, "alice", "tenant-two.example-hosting.test", undefined),
    ).toBeUndefined();
  });

  // The host gate is per-candidate (per saved URI), not per-item: a second saved URI for the
  // SAME item, on the page's own host, must still be found and picked, even though an earlier
  // listing for that item (a different saved URI) was on the wrong host. Confirms the host check
  // does not get folded into the `checked` de-dup in a way that poisons the whole item.
  it("a second saved URI for the same item, on the page's own host, is still picked after an earlier one on a different host", () => {
    const candidates = [candidate("item-1", false, "a.example.com"), candidate("item-1", false, "b.example.com")];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "b.example.com", undefined)).toBe("item-1");
  });

  // Two different items: the one whose username matches is on the WRONG host, and the one on the
  // RIGHT host has a different username. Neither must be picked — proves the host and username
  // checks are both applied to the SAME candidate, not satisfied independently across different
  // candidates.
  it("never picks an item by combining one candidate's host match with a different candidate's username match", () => {
    const candidates = [candidate("item-1", false, "wrong.example.com"), candidate("item-2", false, "b.example.com")];
    const usernameOf = (id: string) => (id === "item-1" ? "alice" : "bob");
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "b.example.com", undefined)).toBeUndefined();
  });

  // Regression (the bug this file's test suite grows for): the SAME host on two different
  // explicit ports — `BaseDomain` mode (the candidate set this gate narrows on top of) does not
  // tell these two sites apart at all, so the port check here is the only thing that does.
  // Without it, a page at `https://example.com:8443` could silently overwrite a password saved
  // for `https://example.com:9000`.
  it("same host, different explicit ports -> no update target, even with a matching username", () => {
    const candidates = [candidate("item-1", false, "example.com", 9000)];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", 8443)).toBeUndefined();
  });

  // Same host, same explicit port -> still an update target, same as the portless case.
  it("same host, same explicit port -> that item (update it)", () => {
    const candidates = [candidate("item-1", false, "example.com", 8443)];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", 8443)).toBe("item-1");
  });

  // A page with no explicit port (`undefined`, its scheme's default) must never match a
  // candidate saved on an explicit, different port, or vice versa: `undefined` means "the
  // default port", not "any port".
  it("an explicit port never matches a page with no explicit port (the default)", () => {
    const candidates = [candidate("item-1", false, "example.com", 8443)];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", undefined)).toBeUndefined();
  });

  // A second saved URI for the same item, on the page's own host AND port, is still picked after
  // an earlier one on the same host but a different port — the port check is per-candidate too,
  // not folded into the `checked` de-dup.
  it("a second saved URI for the same item, on the page's own host and port, is still picked after an earlier one on the same host but a different port", () => {
    const candidates = [
      candidate("item-1", false, "example.com", 9000),
      candidate("item-1", false, "example.com", 8443),
    ];
    const usernameOf = () => "alice";
    expect(selectUpdateCandidate(candidates, usernameOf, "alice", "example.com", 8443)).toBe("item-1");
  });
});
