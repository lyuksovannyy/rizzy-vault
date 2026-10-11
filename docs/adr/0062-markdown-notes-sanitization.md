# ADR 0062: Markdown-in-notes rendering: sanitization and rendering rules

- Status: Proposed
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1) lists, Could, M3: "Markdown in secure notes." `item.notes` is already a Text field on every item type, not only Secure Note ([ADR 0018](0018-item-record-encoding.md) §7's field table: "The notes are a Secure Note's body. Conflicts are whole-field; there is no text merge"). Today the web vault renders it, like every field, as plain text through `FieldValue` (`apps/web/src/views/ItemView.tsx`; V, read 2026-10-11). This ADR decides how it renders as HTML instead, on the item type the ROADMAP row actually names.

**Why this is a security decision.** ADR 0018's Risks already name it: "a parser bug that rejects valid records stalls a device's chain" and, separately, "we own a parser for untrusted plaintext; from M9, a vault member is the author" (ADR 0018 §"Negative"). Until M9 the author is always the viewing account. From M9 ([ROADMAP](../ROADMAP.md), shared vaults) a co-author's notes render in another member's browser: unsanitized rendering becomes stored XSS between vault members at that point. Deciding the rendering contract now, while the author and the viewer are the same account, avoids a breaking change to the contract later.

**Scope boundary.** [THREAT_MODEL INV-35](../THREAT_MODEL.md#8-security-invariants) and [ADR 0019](0019-native-clients.md) §5.1 already govern untrusted rich content, but only share payloads and mail HTML (M5/M6) — content whose author is not the viewing account. `item.notes` is not in their scope; this ADR does not touch either. ADR 0019 §5.1's separate, general rule ("Text is plain text: every view that shows item … data renders plain text") already covers `item.notes` on native clients and keeps covering it: this ADR renders notes only in the web vault (`apps/web`). The CLI (`rv`), the browser extension and native clients continue to show the stored Markdown source as plain text, unchanged.

**No third-party JS dependency exists in this workspace today.** Read 2026-10-11, V: `apps/web/package.json`, `packages/ui/package.json`, `packages/core/package.json` and the root `package.json` declare no runtime dependency beyond React and workspace packages. [ADR 0014](0014-ui-stack.md) §3's JS dependency policy, which would license- and advisory-check a new package, is explicitly "Left to M1" and was never built. A Markdown-and-sanitizer library would be the first third-party runtime dependency the web vault ever takes on, before that governance exists, for a Could-have row.

**The web vault's CSP.** `WEB_CSP` (`crates/rizzy-server/src/http/security.rs` line 33, V): `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'`. Its module doc says plainly "a change to it is a security change" and that Trusted Types already ship "where the browser supports them" — ADR 0014 §2's text calling Trusted Types "a goal, not yet a check" is stale against shipped code (one-line observation; not corrected here, since this ADR edits no ADR 0014 text and changes no header).

## Decision

1. **No new cryptographic construction.** `item.notes` crosses the wire and is stored exactly as today, under the existing item-field envelope (ADR 0007, ADR 0018). This ADR governs only how already-decrypted plaintext renders in the browser.
2. **Scope.** Markdown rendering applies to the `item.notes` field's value on **Secure Note items only**, in the web vault's read view, matching [ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1)'s row ("Markdown in secure notes", Could, M3) exactly. `item.notes` is the same Text field key on Login, Card, Identity and other item types ([ADR 0018](0018-item-record-encoding.md) §7); `FieldValue` keeps rendering it as plain text there, unchanged. Editing keeps the existing plain `<textarea>` (ADR 0018 §7 "whole-field" notes: there is no WYSIWYG editor and no text merge). The CLI, extension and native clients are unaffected (Context).
3. **Mechanism: a hand-written, restricted-subset parser to a closed AST, rendered to React elements. No HTML string is ever produced.** A new module in `apps/web` parses the stored text into a TypeScript discriminated union with one variant per allow-listed construct (§5) and nothing else. The renderer is a `switch` over that union with **no default branch**: an unhandled variant is a compile error, not a rendering hole. No step calls `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `setHTMLUnsafe` or any other sink [ADR 0014](0014-ui-stack.md) §2 bans — the closed AST is itself the mandatory sanitization pass, applied unconditionally on every render path, because no code path can reach the renderer without going through the parser's fixed variant set.
4. **No new runtime dependency.** The parser and renderer use no npm package beyond the existing `react`. This keeps ADR 0014 §3's dependency-policy tooling genuinely deferred (Open question 1) and keeps the audit surface for this Could-have feature to code this project reviews itself.
5. **Allow-listed constructs.** Only these; anything else in the source is a literal text node (React escapes it; nothing special about `<`, `&` or a literal `javascript:` string survives as anything but visible text):

   | Markdown | Renders as | Note |
   |---|---|---|
   | `# … ######` | `h1`–`h6` | one `#`-run at line start |
   | blank-line-separated text | `p`, with `br` for each internal line break | single newline → `br` (deliberate deviation from CommonMark's two-trailing-spaces rule: notes are typed, not authored as CommonMark) |
   | `**x**` / `__x__` | `strong` | |
   | `*x*` / `_x_` | `em` | |
   | `~~x~~` | `del` | |
   | `` `x` `` | `code` (inline) | |
   | ` ``` ` fenced block | `pre > code` | content is a literal text node, never re-parsed; language hint, if any, is dropped (no syntax highlighting in v1) |
   | `> x` (per line) | `blockquote` | one level; no nested blockquote in v1 (Open question 2) |
   | `-`/`*`/`+ x` or `1. x` | `ul`/`ol > li` | one level; no nested list in v1 |
   | `---` alone | `hr` | |

   Images, tables, footnotes, task-list checkboxes, raw inline/block HTML, bracketed links (`[text](url)`) and autolinked bare URLs have no production rule and are not recognized; their source text renders as plain text.
6. **No clickable links, structurally.** `[text](url)` and bare URLs have no production rule (§5), so the AST has no link variant and no node ever renders an `<a>` element from note content. A typed URL is inert: it shows as the literal source string, exactly like any other unrecognized construct. This leaves `SafeLink` and `safeHttpUrl` (`apps/web/src/SafeLink.tsx`, `apps/web/src/safe-url.ts`) untouched: `SafeLink` takes only a `url` prop and always displays that same URL as its children, with no separate label prop, so a `[text](url)` construct could not route through it without first changing that component and its one call site (`FieldValue` in `ItemView.tsx`) — out of scope for a Could-have feature (Consequences, Risks).
7. **No images, structurally, not by a toggle.** `img` has no production rule (§5), so none is ever emitted; there is no "remote images off by default" setting to turn on. Backstop, not primary: `img-src 'self'` would block a remote source even if one were ever emitted by a bug.
8. **No inline styles, structurally.** No node ever carries a `style` attribute or a `class` built from note content; every element gets this module's own fixed CSS class. Backstop: `style-src 'self'` with no `'unsafe-inline'` blocks an inline `style` attribute's effect even on a bug.
9. **No script execution, structurally.** No node kind corresponds to `script`, an event-handler attribute, or any HTML at all — the AST has no "raw HTML" variant to begin with (§3). Backstop: `script-src 'self' 'wasm-unsafe-eval'`, no `'unsafe-inline'`, no `'unsafe-eval'`.
10. **The tokenizer is a single linear pass with no backtracking regular expression**, so a pathological input cannot cause catastrophic backtracking. `item.notes` is already capped at 64 KiB (ADR 0018 Risks), bounding the work regardless.
11. **Parse failure fails closed.** Any exception, or any construct the tokenizer does not recognize, falls back to one plain text node holding the original stored string — never to an unsanitized HTML string, and never a crash of the item view.
12. **Copy and export are unaffected.** `FieldValue`'s copy action, and every export path, return the stored Markdown source text unchanged. Rendering is read-only presentation; the stored bytes and ADR 0018's whole-field merge model do not change.
13. **No CSP change.** `WEB_CSP` (Context) is unmodified; this Decision is designed to need nothing from it beyond what already ships.
14. **Proposed INV-88** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.):

    | Id | Text | Milestone | Verification |
    |---|---|---|---|
    | INV-88 | The web vault renders a Secure Note's `item.notes` Markdown through a closed, hand-written parser to a fixed allow-listed element set (ADR 0062 §5). No raw HTML, script, event-handler attribute, inline style, image or clickable link ever reaches the DOM from it (ADR 0062 §6–§9). | M3 | Playwright test rendering a note built from an XSS-payload corpus (script tags, event-handler attributes, bracketed and bare URLs, raw HTML blocks, oversized/pathological input) and asserting no script execution and no disallowed element in the rendered DOM, mirroring INV-35's own test method. |

### On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it.

1. **THREAT_MODEL.md §8** gains the INV-88 row (Decision §14) in the security-invariants table, after INV-69.
2. **THREAT_MODEL.md, "A16. Malicious import files and shared content," mitigations:** "Field values are always rendered as text ([INV-35](#8-security-invariants))." becomes "Field values are always rendered as text ([INV-35](#8-security-invariants)), except a Secure Note's `item.notes`, which the web vault renders through the closed parser-to-AST pipeline of ADR 0062 (INV-88); that pipeline has no raw-HTML, script or link-element production rule, so an imported field value still cannot reach an HTML sink through it." A16's "XSS if a field value reaches an HTML sink" risk line is otherwise unchanged: it still applies to every other field and item type.

## Consequences

### Positive
- No new runtime dependency and no new sink: the web vault's dependency count and raw-HTML-sink surface are unchanged, so the M8 external audit sees one more small, hand-written module, not a transitive tree.
- The rendering contract is settled before M9 multi-author notes make bad sanitization a stored-XSS bug between vault members, not just a theoretical one.
- Every guarantee in §6–§9 is structural (what the AST can contain), with the existing CSP as a named backstop, not the other way around.
- Scope matches the ROADMAP row exactly (Secure Note, not every item type), so this ADR needs no owner sign-off on a scope change.

### Negative
- A restricted, non-CommonMark-compliant subset: no tables, images, clickable links, task lists, nested lists/blockquotes, syntax highlighting or raw HTML. Content pasted from elsewhere (e.g., a GitHub-flavored table or a `[text](url)` link) degrades to plain paragraphs or literal text, brackets and all.
- New hand-written parsing code to maintain and test, instead of a widely used library's existing corpus and track record.
- The single-newline-as-`br` rule is a deliberate deviation from CommonMark (§5); a contributor who expects strict CommonMark will read it as a bug without this note.
- Login, Card, Identity and other item types keep plain-text notes; a user who wants Markdown on those needs a ROADMAP change first (Open question 6).
- No clickable links in v1 (§6); a note that is just a pasted URL or a `[text](url)` link shows literal text, not something to click (Open question 7).

### Risks
- **"Don't write your own parser" is real advice.** A subtle escaping bug in an untested input class is the realistic failure mode. Mitigation: the closed AST with no default branch (§3) turns a missed construct into inert text, not an injection, and the INV-88 Playwright suite (§14) plus a unit-test suite (TDD: every allowed construct, an empty note, unterminated fences, mismatched list markers, CRLF, unicode, a literal `<script>` string, a pathological long line) must pass before this ships.
- **Widening the allow-list is a security decision,** not routine maintenance. Adding tables, images, clickable links or raw HTML later needs a new ADR, not a casual PR, because each widens the AST's production rules or (for links) reopens whether `SafeLink` needs a label prop.

## Alternatives considered

- **`react-markdown` + `remark-gfm` + `rehype-sanitize`** (AST-to-React over the unified/remark/rehype ecosystem, with a hast-sanitize allow-list schema). More featureful and backed by a wide existing test corpus (U: not independently verified in this session). Rejected as primary: it would be this workspace's first third-party runtime dependency, pulled in before ADR 0014 §3's dependency-policy tooling exists to vet it, for a Could-have row (Open question 1).
- **`markdown-it` + `DOMPurify`, HTML-string pipeline.** Same dependency cost, plus it needs a `dangerouslySetInnerHTML` call — on ADR 0014 §2's banned-sink list — and a reviewed lint exception the AST-to-React route avoids entirely.
- **Sandboxed iframe, the ADR 0019 §5.1 / INV-35 pattern.** Built for content whose author is not the viewer (a stranger's share or mail). Until M9 `item.notes` is always the viewing account's own text, so isolating it buys little today against the cost of a cross-frame messaging surface.
- **Keep notes as plain text indefinitely.** Not a real alternative: the ROADMAP row is a standing Could, not a Won't.
- **Add a label prop to `SafeLink` now, to support `[text](url)`.** Rejected for v1: it changes a component ADR 0014 §2 names as the vault's one link-rendering path, for a Could-have feature, with no ROADMAP line asking for notes to carry links (§6, Open question 7).

## Open questions for the owner

1. **Take on the first third-party JS runtime dependency now, to use a vetted library, and stand up ADR 0014 §3's deferred dependency-policy tooling to vet it?** *Recommendation: no.* The hand-written route (§3–§4) meets the ROADMAP row without opening either cost for a Could-have feature.
2. **Allow one level of nested list or blockquote in v1?** *Recommendation: no.* Flat covers the common secure-note case (a short checklist, a quoted recovery phrase); nesting multiplies tokenizer states and tests for a Could-have feature.
3. **INV-88's final number.** Resolved: allocated as INV-88, the batch's proposed INV ids reconciled in ADR-number order; confirm at acceptance in case an ADR lands out of order.
4. **Allow same-origin images later, routed through the M3 icon-proxy's re-encoding?** *Recommendation: never for notes.* That would reintroduce the network-loading risk §7 closes, for a feature no ROADMAP row asks for.
5. **Raise the 64 KiB `item.notes` limit now that Markdown syntax eats into it?** *Recommendation: no, not here.* Raising a frozen limit is its own version bump (ADR 0018); nothing in this Decision needs more bytes than plain notes already could hold.
6. **Widen this ADR's rendering to every item type's `item.notes`, beyond the ROADMAP §4.2 "Markdown in secure notes" row?** *Recommendation: no, not without a ROADMAP edit first.* That is a scope change CLAUDE.md reserves to the owner via ROADMAP, not something this ADR decides on its own (§2).
7. **Add bracketed-link (`[text](url)`) support, which needs a label prop on `SafeLink`?** *Recommendation: no, not for v1.* `SafeLink` is the vault's one link-rendering path (ADR 0014 §2); changing it for a Could-have feature, with no ROADMAP line asking for links in notes, is its own decision (§6, Alternatives considered).

## References

- [ROADMAP](../ROADMAP.md) §4.2 (row "Markdown in secure notes", Could, M3)
- [ADR 0014](0014-ui-stack.md) §2 (raw-HTML-sink ban, the one `SafeLink`/`openUrl` helper, Trusted Types), §3 (JS dependency policy, "Left to M1")
- [ADR 0018](0018-item-record-encoding.md) §7 (`item.notes` field, whole-field merge), Risks ("Markdown notes in M3", the 64 KiB limit), Negative ("a vault member is the author" from M9)
- [ADR 0019](0019-native-clients.md) §5.1 (native-client plain-text rule and INV-35 scope; unaffected)
- [THREAT_MODEL](../THREAT_MODEL.md) INV-35 (M5/M6 scope; unaffected), INV-42 (link-scheme rule; unaffected — no link construct in v1, §6), INV-49 (web vault CSP), §4.2.1 (the web-vault delivery problem), "A16. Malicious import files and shared content" (mitigations bullet amended On acceptance)
- Code (all read 2026-10-11, V): `apps/web/src/fields.ts`, `apps/web/src/views/ItemView.tsx` (`FieldValue`, the one `SafeLink` call site), `apps/web/src/SafeLink.tsx` (no label prop — Decision §6), `apps/web/src/safe-url.ts`, `apps/web/package.json`, `packages/ui/package.json`, `package.json` (no third-party runtime dependency exists), `crates/rizzy-server/src/http/security.rs` lines 1–40 (`WEB_CSP`)
