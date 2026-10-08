// The matcher's interface, unwired (per the M2 plan: "the rizzy-match unit runs in parallel and
// will be wired in by the integration step"). `decide` here NEVER reimplements matching in
// TypeScript — ADR 0037 §1 puts every matching rule in `rizzy-match` (Rust, no I/O, wasm-clean)
// precisely so one bug fix covers every client. This module exists so `background/router.ts`
// and the content script have a stable call shape to compile and test against today; swapping
// its body for a real call into the integrated `rizzy-match` binding should need no change on
// either side of this interface, only inside this one function.
//
// Vocabulary matches ADR 0037 exactly: match-mode values (§4's table), `matchedVia`'s
// equivalence-warning flag (§5), and the narrowing-only registrable-domain gate's existence
// (never its implementation, which has no business being here).
import type { MatchCandidateSummary } from "../messaging/contract.ts";

/** `uri/<id>/match`'s enum values (ADR 0037 §4). `0x0000` ("account default") is resolved by
 * the caller before `decide` is invoked, per ADR 0037 §6: `decide` only ever sees `0x0001`
 * through `0x0006`. */
export const MatchMode = {
  BaseDomain: 0x0001,
  Host: 0x0002,
  StartsWith: 0x0003,
  Exact: 0x0004,
  Regex: 0x0005,
  Never: 0x0006,
} as const;
export type MatchModeValue = (typeof MatchMode)[keyof typeof MatchMode];

/** One saved URI to match against, as `rizzy-match` would receive it once wired (ADR 0037 §2,
 * §4). `value` is the URI's saved string, or the regex source for {@link MatchMode.Regex}. */
export interface ItemUriInput {
  readonly itemId: string;
  readonly uriId: string;
  readonly value: string;
  readonly mode: MatchModeValue;
}

/** What the content script reports about the frame asking for candidates (ADR 0037 §5: "same
 * registrable domain" top-frame iframes are treated as the top frame; any other iframe gets no
 * automatic candidates — that narrowing happens in the real `rizzy-match`, not here). */
export interface FrameInfo {
  readonly isTopFrame: boolean;
  readonly frameOrigin: string;
}

export interface MatchResult {
  readonly candidates: readonly MatchCandidateSummary[];
  readonly warnings: readonly string[];
}

/**
 * Unwired stub: always returns no candidates and one warning explaining why, regardless of
 * input. Never throws (a background router can call it unconditionally without a try/catch
 * that exists only for this stub), and never guesses at a match — returning a plausible-looking
 * candidate from placeholder logic would be worse than returning none, because nothing downstream
 * would know to distrust it.
 *
 * `pageUrl` and `frameInfo` are accepted (not `_`-prefixed) so a lint rule or a future change
 * cannot silently "fix" an unused-parameter warning by deleting them before the real
 * `rizzy-match` call is wired in; they are intentionally unread here.
 */
export function decide(
  pageUrl: string,
  frameInfo: FrameInfo,
  itemUris: readonly ItemUriInput[],
): MatchResult {
  void pageUrl;
  void frameInfo;
  void itemUris;
  return {
    candidates: [],
    warnings: ["match/stub.ts: rizzy-match is not wired in yet; no candidates can be offered"],
  };
}
