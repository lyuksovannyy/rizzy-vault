# ADR 0043: A per-instance token for the inline-menu and passkey-consent iframes

- Status: Proposed
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M2

## Context

[THREAT_MODEL.md](../THREAT_MODEL.md) A7 "Sixth adversarial round" and the security assessment
`clone-assessment.json` (2026-10-11) found that `src/inline-menu/index.html` is
`web_accessible_resources` to any http(s) origin ([ADR 0036](0036-browser-extension-architecture-and-key-custody.md)
§6) with no per-frame or per-instance identity. `messaging/sender.ts`'s `isInlineMenuSender`
(lines 120–123) authorizes a privileged request from **any** document whose `sender.id`/
`sender.origin` are this extension's own — never whether it is the one `content-script.ts`'s
`InlineMenu` constructor built. `sender.tab.id`/`.url` are the TAB's own values regardless of
nesting depth (`sender.ts` lines 23–26's own documented limitation), so sender information alone
cannot tell two extension-origin documents in the same tab apart.

**Reproduced (V):** a clone of `src/inline-menu/index.html`, embedded anywhere in a tab's frame
tree — including nested inside an unrelated third-party subframe — passes `isInlineMenuSender`
and, on one ordinary trusted click of its own "Generate password" button (`inline-menu/main.ts`,
built unconditionally, gap 32), pushes a generated password into the real `InlineMenu` instance's
anchored field via `apply_fill`. No occlusion trick needed: Gates A/B/C never instrument a clone.
`test.fixme`, `apps/extension/e2e/adversarial-fill-requests.spec.ts:4045`.

**Bounded (V):** no stored secret is reachable. `inline_menu_fill_chosen` needs a real `itemId`,
which travels only in a `postMessage` targeted at the *real* iframe's own `contentWindow`, never
broadcast or in a DOM attribute. `passkey_ceremony_approved`/`_declined` additionally need
`ceremonyToken` (`core-host/passkey-ceremony.ts`): single-use, 2-minute TTL, bound at creation to
the real request's `(tabId, origin)`, never exposed to page-world JS — a passkey-consent clone
can only invent one, which `passkeyCeremonies.take()` rejects. So the inline-menu clone is a
critical integrity/consent-bypass bug (forced write, no secret disclosure, reachable from any tab
via any embedded third-party frame); the passkey-consent clone is defense-in-depth only.

## Decision

The content script mints a per-instance token when it builds an inline-menu or passkey-consent
iframe; every message in the "inline-menu sender class" must then carry a token the background
can still vouch for.

1. **Mint.** `InlineMenu`'s constructor and `passkey-relay.ts`'s consent-iframe builder each
   generate one token (`crypto.randomUUID()`, ≥128 random bits) before setting the iframe's `src`.
2. **Register over the already-trusted content-script channel.** A new `FromContentScript`
   message, `register_iframe_instance { instanceToken }`, goes through the exact path
   `fields_detected` already uses — `isContentScriptSender`/`trustedOriginOf`, never
   `isInlineMenuSender` — through `parseFromContentScript`/`validate.ts`'s byte budget like any
   other content-script message. The background binds the token to `(sender.tab.id,
   sender.frameId, trustedOrigin)` and a TTL (recommend 30 min; Open questions), in a bounded
   store shaped like `passkeyCeremonies`. `frameId` scopes the registration to the exact
   content-script instance that minted it (a tab can run the content script, and build an
   `InlineMenu`, in more than one frame); it is never re-checked against the *iframe's* own
   `frameId`/`documentId` at use time (Alternative 1) — the token is what use-time validation
   checks.
3. **Deliver to the iframe only over the existing targeted `postMessage`.**
   `InlineMenuShowMessage`/`PasskeyConsentShowMessage` gain one field, `instanceToken`, delivered
   exactly as `candidates`/the ceremony offer already are — never via `src`, an attribute, or any
   channel a page sharing the tab's frame tree can read. `isInlineMenuFillRequestMessage`/
   `isInlineMenuGeneratePasswordRequestMessage`/`isPasskeyCeremonyMessage` gain a required
   `instanceToken` field, shape-validated first.
4. **Require and check.** `core-host/listener.ts`'s `isInlineMenuSender` branch, for all three
   message kinds, looks up `message.instanceToken` and refuses unless a live, unexpired,
   unrevoked registration exists for that exact `sender.tab.id`. A clone is never fed a token
   (step 3) and so can never pass this. A mismatch answers with the **same** `content_error` shape
   already used for every other rejection on this path — same code, same timing — so a clone
   learns nothing about candidate count or liveness, matching how THREAT_MODEL.md's A7 already
   reads INV-37 for this module (outer, page-observable behaviour independent of `candidates`).
5. **Single-instance lifetime.** `InlineMenu#destroy()`/the consent-iframe's teardown send
   `revoke_iframe_instance { instanceToken }` over the same channel, deleted immediately —
   covering a pick, a blur, and `wireInlineMenu`'s destroy-and-rebuild; a rebuild mints a fresh
   token. `destroy()` still runs only after `requestFill`/`respond` settles (the existing
   ordering fix), so revocation never strands an in-flight request: the measured
   click→`apply_fill` round trip is 0.6–5.2 ms (THREAT_MODEL.md A7), 50–400× faster than the
   250 ms rebuild debounce. This also closes the second adversarial round's "unrelated DOM
   mutation racing a rebuild" residual, left open there precisely because closing it needed this
   protocol change.
6. **`ceremonyToken` is unchanged, an independent second layer** — `instanceToken` sits beside it,
   never in place of it.
7. **Tests required** (`adversarial-fill-requests.spec.ts`): the `test.fixme` at line 4045 becomes
   a passing `test`; a clone nested in an unrelated third-party subframe is refused the same way;
   a replayed token from an already-destroyed instance, an expired token, and a token registered
   for a different tab are each refused; teardown revokes before a later message can use that
   token; a real click still fills during a concurrent rebuild (point 5's race). The store itself
   needs unit tests mirroring `passkey-ceremony.test.ts`. Firefox and Chromium already use
   `runtime.sendMessage`/`onMessage` and targeted `postMessage` identically today (V) — no new,
   version-gated API, so no separate support spike is needed.

## Consequences

### Positive
- Closes the `test.fixme` bypass at every nesting depth, not only a same-origin clone.
- Adds defense-in-depth to the passkey-consent reuse of `isInlineMenuSender`.
- Reuses a shape this codebase already built and shipped (`ceremonyToken`).

### Negative
- Two new message types, one new field on two `postMessage` shapes and three privileged request
  types, and one more small bounded store to clear on lock.

### Risks
- A future sender class that forgets to require `instanceToken` reopens this gap for itself
  (mitigation: one shared check); the 30-minute TTL (point 2) is unverified (U).

## What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9. The owner sets the superseded ADRs'
status lines at acceptance, not now.

| Part, quoted | Replaced by |
|---|---|
| [ADR 0040](0040-extension-fill-request-from-inline-menu.md)'s own replacement of [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, first bullet (currently binding): "sends only: detected-field reports and submitted-credential reports. The chosen fill request comes from the inline-menu iframe (ADR 0040)." | "…and a per-instance registration/revocation message for an inline-menu or passkey-consent iframe it is about to build or tear down (ADR 0043). The chosen fill request comes from the inline-menu iframe (ADR 0040)." |
| [ADR 0040](0040-extension-fill-request-from-inline-menu.md) point 1, sentence: "The iframe is an extension page, so the long-lived context identifies it from the browser's sender information (`sender.origin` is the extension's own origin and `sender.tab` is the tab it is embedded in), never from message fields." | Unchanged, plus: "and the message must carry an `instanceToken` matching a live registration for that sender's own tab (ADR 0043), since sender information alone cannot tell two extension-origin documents in the same tab apart." |
| [ADR 0040](0040-extension-fill-request-from-inline-menu.md) point 3, sentence: "The long-lived context runs the matcher again for the browser-vouched top-frame URL of the sender's tab and requires the requested item to be among the candidates." | Unchanged, plus: "and requires the message's `instanceToken` to match a live registration for that same tab (ADR 0043); a mismatch is refused before the matcher result is used." |

Everything else in ADR 0036 and ADR 0040 stays binding. Replaced share of ADR 0040's Decision: two
sentences and one row's first-cell text out of 216 words (`## Decision` to `## Consequences`,
`awk`+`wc -w`, 2026-10-11, V) — under half, so a partial supersession applies.

## Alternatives considered

1. **`sender.frameId`/`documentId` binding on the iframe's own sender.** Rejected for now:
   `frameId` population for a nested extension-origin iframe on current Firefox, and
   `documentId`'s Firefox availability at all, are not independently verified (U); `documentId` is
   also Chromium-only. A value the browser assigns, of unconfirmed parity, versus one this
   extension mints and fully controls. Revisit if that parity is confirmed.
2. **`use_dynamic_url: true`.** Rejected as ineffective, not merely weaker: once the real iframe
   has rendered once, any script sharing the tab's frame tree — including a third-party subframe
   sibling — can read its `src` attribute (an ordinary, always-permitted cross-origin DOM read)
   and reuse that URL for its own clone. Also Chromium-specific.
3. **Narrowing `web_accessible_resources.matches`** away from `["http://*/*","https://*/*"]`.
   Rejected: the menu must be embeddable from whatever http(s) origin the user visits, since it
   has to appear on any site with a password field.

## Open questions for the owner

1. **The safety-net TTL (point 2).** *Recommendation:* 30 minutes. Teardown-revocation is the
   normal path; this only bounds a lost revoke message.
2. **A separate rate limit for register/revoke?** *Recommendation:* no — one pair per menu
   show/hide is already bounded by the existing 250 ms detection debounce.
3. **Scope.** Covers exactly the three message kinds in point 4. *Recommendation:* any future
   extension-origin-iframe sender class added later uses the same check from the start.

## References

- [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0040](0040-extension-fill-request-from-inline-menu.md); [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, §5, §6; [ADR 0039](0039-passkeys-vault-and-extension.md) §2
- [THREAT_MODEL.md](../THREAT_MODEL.md) A7 ("Sixth adversarial round"), INV-36, INV-37, INV-40
- `clone-assessment.json` (2026-10-11, this repository's own security assessment, V/L/U as cited)
- `apps/extension/src/messaging/sender.ts` lines 23–26, 91–123; `core-host/passkey-ceremony.ts`; `apps/extension/e2e/adversarial-fill-requests.spec.ts:4045`
