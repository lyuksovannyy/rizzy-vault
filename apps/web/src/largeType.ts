// SPDX-License-Identifier: AGPL-3.0-only

// Pure character classification for the item view's large-type password display
// (`views/LargeType.tsx`; ROADMAP §4.5 "large-type password display"): splits an
// already-revealed value into one cell per character, with digits, letters and symbols told
// apart so each is easy to read and tell apart at a glance — the same job 1Password's "Large
// Type" window does, useful for typing a password into another device by eye. Kept apart from
// the component so it is unit-tested without rendering anything (the project's existing
// pattern: `palette.ts`, `shortcuts.ts`).
//
// This module never touches the Worker or any secret storage: it only reshapes a string its
// caller already holds (`views/ItemView.tsx`'s module docs: "revealing nothing new beyond the
// existing reveal path").

/** One character's class, for its cell's styling. */
export type CharKind = "digit" | "letter" | "symbol";

const DIGIT = /^[0-9]$/;
// `\p{L}` matches any Unicode letter, not only ASCII, since an imported or passphrase-mode
// password may hold non-ASCII letters.
const LETTER = /^\p{L}$/u;

/** The class of one character (module docs): a digit, a Unicode letter, or everything else
 * (punctuation, space, emoji, …) as a symbol. */
export function charKind(ch: string): CharKind {
  if (DIGIT.test(ch)) {
    return "digit";
  }
  if (LETTER.test(ch)) {
    return "letter";
  }
  return "symbol";
}

/** One large-type cell: a character and its class. */
export interface CharCell {
  readonly ch: string;
  readonly kind: CharKind;
}

/** Splits `value` into its large-type cells, in order (module docs). Normalizes to NFC first,
 * so a decomposed accented letter — e.g. an imported password holding "e" + U+0301 COMBINING
 * ACUTE ACCENT as two separate code points — becomes its single precomposed code point ("é")
 * before splitting, rather than a bare base letter and a lone, cell-less combining mark (review
 * finding). Best-effort: a combining mark with no precomposed form (there is no single code
 * point for every base+mark pair) still lands in its own cell after normalizing, same as before.
 * Then iterates by Unicode code point — not by UTF-16 code unit (`value.split("")` or indexing
 * would split a surrogate-pair character, such as most emoji, into two cells) — so every
 * character is exactly one cell. */
export function charCells(value: string): readonly CharCell[] {
  return [...value.normalize("NFC")].map((ch) => ({ ch, kind: charKind(ch) }));
}
