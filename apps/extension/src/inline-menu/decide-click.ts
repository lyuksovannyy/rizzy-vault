// `main.ts`'s click-handler decision (ADR 0037 §5), pulled into its own dependency-free module —
// not left inline in `main.ts` — so it is unit-testable without a `document` (`main.ts` throws
// at module load if `#list` is missing, which a plain `vitest` `node` environment has no DOM to
// provide at all; `test/decide-click.test.ts` imports only this file, the same pattern
// `content/own-overlay-mutation.ts` already uses for the same reason).
//
// This is insurance against a real bug that briefly existed here: a hardcoded
// `confirmedEquivalence: true` on the fill branch, caught only by code review, not by any test,
// because nothing exercised this decision directly before this file existed.
import type { InlineMenuCandidate } from "./protocol.ts";

/**
 * `warn` means "first click on an equivalence-only candidate: show the warning, do not fill
 * yet." `fill` means "request the fill now," carrying `confirmedEquivalence` straight from
 * `candidate.needsWarning` — `true` only when this candidate ever needed the warning in the
 * first place (and, by the time `fill` is returned, the user has already clicked through it
 * once), never a constant, so a fresh server-side match that disagrees with this candidate's
 * own `needsWarning` is still the thing that decides whether confirmation was really given
 * (`core-host/content-handler.ts`'s `selectFillCandidate` re-checks it). A hardcoded `true`
 * would silently defeat that re-check: if the background's fresh match disagrees with this
 * candidate's own (e.g. the equivalence list or the page changed between the report and this
 * click) and now says `needsWarning: true` where this candidate's own, possibly-stale
 * `needsWarning` was `false`, a hardcoded `true` would claim "confirmed" for a warning the user
 * was never shown — exactly the guarantee ADR 0037 §5 exists to enforce server-side, not only
 * trust from this UI.
 */
export function decideClick(
  candidate: Pick<InlineMenuCandidate, "itemId" | "needsWarning">,
  confirmed: ReadonlySet<string>,
): { readonly action: "warn" } | { readonly action: "fill"; readonly confirmedEquivalence: boolean } {
  if (candidate.needsWarning && !confirmed.has(candidate.itemId)) {
    return { action: "warn" };
  }
  return { action: "fill", confirmedEquivalence: candidate.needsWarning };
}
