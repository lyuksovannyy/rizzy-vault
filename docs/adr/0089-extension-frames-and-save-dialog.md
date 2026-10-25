# ADR 0089: Extension-origin frames: one content-script message list, the save-dialog instance token, the save-prompt token and the save dialog's visibility gates

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (browser extension: the save dialog of [ADR 0076](0076-autocomplete-driven-autofill.md) §5; the reconciled message list also binds the M2 code already shipped)

## Context

The owner said "start" on 2026-10-25, after the ADR gap review
([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)), to fixing
the gaps it lists. This ADR answers review item **C1** (raw finding G08-1), item **S3** (G08-3 and
G08-2), and the minors **G08-4** and **G08-5**. The raw findings, with quotes and file:line, are in
[docs/reviews/2026-10-25-raw/G08.md](../reviews/2026-10-25-raw/G08.md).

**C1 / G08-1: two binding "sends only" lists.** [ADR 0036](0036-browser-extension-architecture-and-key-custody.md)
§4, first bullet, originally said the content script "sends only: detected-field reports, a chosen
fill request (after the user picks a credential in the extension-origin inline menu), and
submitted-credential reports for save/update prompts". [ADR 0040](0040-extension-fill-request-from-inline-menu.md)
replaced that list in its "What this ADR supersedes" row 1. Two Accepted ADRs then each replaced
ADR 0040's replacement, and neither names the other:

- [ADR 0043](0043-inline-menu-instance-token.md) "What this ADR supersedes", row 1, replaced it by:
  "sends only: detected-field reports, submitted-credential reports, and a per-instance
  registration/revocation message for an inline-menu or passkey-consent iframe it is about to
  build or tear down (ADR 0043). The chosen fill request comes from the inline-menu iframe (ADR 0040)."
- [ADR 0076](0076-autocomplete-driven-autofill.md) §9, the row whose first cell is "[ADR 0040] 'What
  this ADR supersedes', the table row whose first cell is '[ADR 0036] §4, first bullet: …'", replaced
  it by: "sends only: detected-field reports and submitted-form reports (ADR 0076 §5.1 says what a
  submitted-form report may carry). The chosen fill request comes from the inline-menu iframe (ADR 0040)."

Under [ADR 0020](0020-partial-supersession.md) point 9 both texts bind at once, and each "only"
forbids a message the other requires: 0043's list has no submitted-form report with custom fields,
and 0076's list has no register/revoke message. ADR 0076 §9 also replaced ADR 0040 point 2 with
"The content script sends only detected-field reports and submitted-form reports …", again without
the register/revoke message. [HANDOFF.md](../HANDOFF.md) open question 1 records the interim rule:
"Until a small reconciling ADR settles it, implementations treat **both** as binding: 0043's
register/revoke message plus 0076's offer messages."

While drafting, a third gap in the same list was found (V, `apps/extension/src/messaging/contract.ts:189-197`):
the shipped `FromContentScript` union also carries `save_prompt_resolved` (the page-DOM banner's
answer), `check_save_prompt` (the save-prompt location check after a navigation), and
`passkey_create_request`/`passkey_get_request` (the passkey relay of
[ADR 0039](0039-passkeys-vault-and-extension.md), which "relays the call, over `postMessage` into the
isolated-world content script and from there to the background"). Neither "sends only" list names
them. Original ADR 0036 covered the first two only loosely ("submitted-credential reports for
save/update prompts"), and the passkey relay only through ADR 0039 itself. One exhaustive list
closes all three.

**S3 / G08-3: the save dialog has no clickjacking gate.** ADR 0076 §5.2 puts custom-field consent
"only in an extension-origin surface, a save dialog iframe built like the inline menu". Its
Negative consequences say "A second extension-origin iframe (the save dialog) to build and
clickjack-harden like the inline menu", but no Decision rule requires it, and its §6 table has
only "Clickjacking the menu | Unchanged M2 mitigations (`menu-visibility.ts`, IntersectionObserver
v2 where available)". In the code (V), `save-dialog/main.ts:171-175` `finish()` checks only
`event.isTrusted`. The inline menu has three gates (V: the `apps/extension/src/content/menu-visibility.ts`
module doc, `content-script.ts:276`, `inline-menu/main.ts:25-66, 216-232, 321-328`):

- **Gate A** (content script, every animation frame while the frame lives): one ok/bad sample per
  tick from `rectsMatch` (geometry against the expected rect, 1 px tolerance),
  `isVisibilityChainOk` (opacity, visibility, display, filter, clip-path, mask, mix-blend-mode,
  content-visibility, on the frame and every ancestor up to `documentElement`), `isTopLayerClear`
  and `isPointHitOk` (top-layer and hit-test occlusion). Fail-closed. It sets the frame's
  `pointer-events` from the sample and records the sample with `recordSample`.
- **Gate B** (content script, authoritative, when `apply_fill` arrives after the round trip):
  `isFillAllowed(state, now, 1000)` refuses unless a good sample has been seen and no bad sample
  falls in the trailing 1000 ms window (`DEFAULT_MENU_VISIBILITY_WINDOW_MS`).
- **Gate C** (inside the iframe): an IntersectionObserver v2 with `{ threshold: 1,
  trackVisibility: true, delay: 100 }`; a click is refused when the latest entry for the clicked
  element says `isVisible === false` (`isHiddenByIov2`). Firefox has no IOv2, so there Gates A and B
  carry the whole defence.

A page that overlays the save dialog, or makes it transparent, can turn a user's click into "save" of
page-chosen values under a page-chosen autocomplete id, and ADR 0076 §5.3 checks new text-field rows
by default. [THREAT_MODEL.md](../THREAT_MODEL.md) INV-36 covers only "the save dialog's choices
cannot be changed by the page", not clickjacking (G08-3).

**S3 / G08-2: the save-prompt token is undefined.** ADR 0076 §5.2: "The dialog fetches its choices
from the long-lived context directly, by the save-prompt token." No ADR defines that token: no
format, lifetime, single-use rule, tab binding or refusal. ADR 0076 §5.1 says the values are
zeroized "when the prompt is resolved or times out" without a timeout value. ADR 0043 gives
per-instance tokens to "an inline-menu or passkey-consent iframe" only, and says "sender
information alone cannot tell two extension-origin documents in the same tab apart". The code (V):
`core-context.ts:159-171` mints the save-prompt token with `crypto.randomUUID()` and keeps the
pending prompt in a `Map` with no timeout (cleared on lock, deleted on take);
`save-dialog/protocol.ts:39-40` accepts any string of at most 256 characters as the token;
`content-handler.ts` `handleSaveDialogRequest`/`handleSaveDialogResolve` look the token up with no
tab check; `listener.ts:192-195` wraps both in `admit(message.instanceToken, …)`, an ADR 0043
instance-token check that no Accepted text requires for the save dialog. Only the location index
(`SAVE_PROMPT_LOCATION_TTL_MS`, 2 minutes, `core-context.ts:177`) has a lifetime.

**G08-4: W5's order-only exemption.** ADR 0076 §2.3 W5: "a write that creates a custom field, or edits
any attribute of an existing one other than removing it, must leave its displayed `label` holding at
least one non-whitespace character." The code (V, `crates/rizzy-client/src/autofill.rs:240`,
`t.content |= attribute != ATTR_ORDER`; test `autofill/tests.rs:168-171`, "An order-only write is a
layout write, not an edit") lets a write that touches only `field/<id>/order` through. Under the ADR
text, reordering an "Unnamed field" is refused. A `kind`-only write is *not* exempt in the code.

**G08-5: a fifth offer.** ADR 0076 §4.1 step 3: "A tab has at most 4 open offers." The code (V,
`core-host/offer-store.ts:74`, `while (ofTab.length >= MAX_OFFERS_PER_TAB)`) evicts the oldest; a
refusing implementation would leave the newest menu unusable instead.

## Decision

### 1. The content script's messages: one exhaustive list

The content script (top frame only, `window.top === window`, as today) sends to the background
exactly these `FromContentScript` messages and no other:

1. **detected-field report** (`fields_detected`), including the fill scope of ADR 0076 §4.1;
2. **submitted-form report** (`credentials_submitted`): the submitted username and password and, under
   ADR 0076 §5.1, at most 8 values of fields with a custom autocomplete token;
3. **save-prompt answer from the page-DOM banner** (`save_prompt_resolved`), for a prompt offered
   *without* a dialog only (§3.6);
4. **save-prompt location check** (`check_save_prompt`) after a navigation;
5. **passkey relay request** (`passkey_create_request`, `passkey_get_request`) under ADR 0039;
6. **iframe-instance registration and revocation** (`register_iframe_instance`,
   `revoke_iframe_instance`) for every extension-origin iframe it builds or tears down: the inline
   menu, the passkey consent and the save dialog (§2).

The chosen fill request, the offer request, the generator request, the passkey ceremony answers and
the save dialog's request and resolve come from the extension-origin iframes, never from the content
script. A content-script message of any other type is refused by `parseFromContentScript` with the
existing `content_error` shape. A new type needs an Accepted ADR that supersedes this list.

### 2. The save dialog is an ADR 0043 instance

1. **Mint.** The content script's save-dialog builder (`SaveDialog`'s constructor) mints an
   `instanceToken` exactly as ADR 0043 point 1 does (`crypto.randomUUID()`, a canonical lowercase v4
   UUID of 36 characters; the `getRandomValues` fallback of `content/instance-token.ts` where
   `randomUUID` is absent) before setting the iframe's `src`.
2. **Register** with `register_iframe_instance { instanceToken }` over the content-script channel,
   bound to `(sender.tab.id, trustedOrigin)` with the ADR 0043 TTL (30 min) and the same store bounds
   (8 per tab, 512 in total, `iframe-instance.ts:27-37`). The iframe's `src` is set only after the
   registration is acknowledged. If it is refused, no dialog is shown, and the prompt falls back to
   the banner without custom fields (ADR 0076 §5.2's "until the dialog exists" behaviour).
3. **Deliver** the `instanceToken` and the save-prompt token only in `SaveDialogShowMessage`, by
   `postMessage` targeted at the dialog's own `contentWindow` with the extension origin as
   `targetOrigin`. Never in `src`, an attribute, a URL fragment or a broadcast.
4. **Require and check.** `save_dialog_request` and `save_dialog_resolve` must carry the
   `instanceToken`. The listener refuses unless a live, unexpired, unrevoked registration exists for
   that exact `sender.tab.id`, with the same `content_error` shape as ADR 0043 point 4.
5. **Revoke** with `revoke_iframe_instance` when the dialog is torn down: after a resolve settles,
   on dismiss, on navigation of the tab, on lock, and when a newer prompt replaces it.

### 3. The save-prompt token

1. **Format.** A canonical lowercase v4 UUID from `crypto.randomUUID()` in the long-lived context
   (122 random bits), with the same validator as an instance token (`isInstanceToken`'s pattern
   `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`). Every message that
   carries it (`save_prompt_resolved`, `SaveDialogShowMessage`, `save_dialog_request`,
   `save_dialog_resolve`) is refused at shape validation unless the field matches that pattern
   exactly. The token names a pending prompt. It is not a key, and it is never logged.
2. **Binding.** The pending prompt records `tabId = sender.tab.id` of the `credentials_submitted`
   message that created it. A message naming the token is honoured only when its own `sender.tab.id`
   equals that `tabId` (for the dialog, the tab of the iframe, which the instance check of §2.4
   already pins).
3. **Lifetime.** 600 s from creation, absolute, never extended by a request. On expiry the entry is
   zeroized and deleted (the "times out" of ADR 0076 §5.1). It is also zeroized and deleted on lock,
   when the tab is closed, and when the long-lived context restarts (memory only, nothing persisted).
   The location index keeps its own 120 s (`SAVE_PROMPT_LOCATION_TTL_MS`) and only ever points at a
   live entry.
4. **Bounds.** At most 1 pending prompt per tab: a new `credentials_submitted` in the same tab
   zeroizes and replaces the older prompt and revokes its dialog instance. At most 64 pending prompts
   in total; at the cap, the oldest is zeroized and dropped.
5. **Use.** `save_dialog_request` is read-only and repeatable while the entry is live. It returns the
   rows of ADR 0076 §5.3 (Display Names, kind, concealment and the checked default, never values).
   `save_dialog_resolve` and `save_prompt_resolved` **take** the entry (delete it before any write)
   once they have passed every check of §3.2 and, for the dialog, §4.3. The outcome then stands,
   whatever happens next (save, update, dismiss, a write error, an action that does not match the
   prompt). A second resolve for the same token is refused.
6. **One answering surface.** A prompt offered with a dialog (`dialog: true` in the offer) can be
   answered only by `save_dialog_resolve`; `save_prompt_resolved` for it is refused, so a page that
   can drive the banner DOM never answers a dialog prompt. A prompt offered without a dialog can be
   answered only by `save_prompt_resolved`, and never saves custom fields.
7. **Refusal.** A token that is unknown, expired, already used or bound to another tab gets one
   refusal, the same in shape, code and text for all four cases, with no early exit that tells them
   apart: `save_dialog_request: unknown or already-resolved token` (or `save_dialog_resolve: …`,
   `save_prompt_resolved: …` with the same suffix). The dialog then shows "This save prompt has
   expired. Nothing was saved." and closes when the user dismisses it.

### 4. The save dialog's visibility gates

The save dialog gets the inline menu's three gates, with the same functions and constants:

1. **Gate A.** While the dialog lives, the content script samples it every animation frame with
   `rectsMatch` (expected rect: the fixed box the builder sets, 360 × 300 CSS px, 16 px from the
   right and bottom edges of the viewport, clamped to the viewport; 1 px tolerance),
   `isVisibilityChainOk`, `isTopLayerClear` and `isPointHitOk`. It sets the frame's
   `pointer-events` from each sample and records each with `recordSample`. The frame gets the
   inline menu's styling rules: maximum z-index, no opacity or transform animation.
2. **Gate C, in the dialog.** An IntersectionObserver v2 with `{ threshold: 1, trackVisibility:
   true, delay: 100 }` observes each button and checkbox. A click, or a checkbox change, is ignored
   unless `event.isTrusted` is true and the latest IOv2 entry for that element is not
   `isVisible === false`. Where IOv2 is absent (Firefox), only `isTrusted` is checked here.
3. **Gate B, authoritative, after the round trip.** On a `save_dialog_resolve` that passed §2.4 and
   §3.2, the long-lived context has `save_dialog_gate { instanceToken }` sent to frame 0 of that tab
   (on Chromium the offscreen document routes it through the background service worker, which
   alone can call `tabs.sendMessage`; on Firefox the background page sends it) and waits for
   `save_dialog_gate_result { allowed: boolean }`. The 1000 ms below runs from the send. The content script answers
   `allowed: true` only if it holds a live dialog with that `instanceToken` and
   `isFillAllowed(state, now, 1000)` is true. No answer within 1000 ms, or `allowed: false`,
   refuses the resolve with `save_dialog_resolve: not visible` and does **not** take the token, so
   the user can click again on a visible dialog. The dialog then shows "The dialog was covered or
   hidden when you clicked. Nothing was saved." Gate B runs before the take of §3.5.
4. **The checked defaults** of ADR 0076 §5.3 stay, because the gates now guard the click that
   accepts them.

### 5. W5 and layout writes

A write that touches only `field/<id>/order` is a layout write, not an edit, for W5. A write to any
other attribute, `kind` included, is an edit. This is what the code does today (Context).

### 6. A fifth open offer

When a tab already has 4 open offers, creating a fifth first zeroizes and drops the tab's oldest open
offer (by creation time). A fill request naming a dropped offer gets the same refusal as an expired or
used `offerId` (ADR 0076 §4.1). The inline menu then shows "This menu is out of date. Click the field
again." and fills nothing. It does not request a new offer by itself.

### 7. Invariant

**INV-112.** Every extension-origin iframe (inline menu, passkey consent, save dialog) acts only on
messages that carry a live per-instance token registered by the content script for the sender's own
tab, and a click in one takes effect only when the frame passed the visibility gates for that click
(Gates A and B, and Gate C where the browser has IOv2). The content script sends only the messages of
ADR 0089 §1. Tested by the extension unit tests and the e2e tests of §10.

### 8. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9:

| Part, quoted | Replaced by |
|---|---|
| [ADR 0043](0043-inline-menu-instance-token.md) "What this ADR supersedes", row 1, its "Replaced by" cell: "sends only: detected-field reports, submitted-credential reports, and a per-instance registration/revocation message for an inline-menu or passkey-consent iframe it is about to build or tear down (ADR 0043). The chosen fill request comes from the inline-menu iframe (ADR 0040)." | The text marked **R1** below. |
| [ADR 0076](0076-autocomplete-driven-autofill.md) §9, the row whose first cell is "[ADR 0040] 'What this ADR supersedes', the table row whose first cell is '[ADR 0036] §4, first bullet: …'", its "Replaced by" cell: "Its replacement text becomes: "sends only: detected-field reports and submitted-form reports ([ADR 0076] §5.1 says what a submitted-form report may carry). The chosen fill request comes from the inline-menu iframe ([ADR 0040])."" | **R1**. ADR 0036 §4, first bullet, therefore reads: "**Content script → background → long-lived context.** The content script (framework-free TypeScript, no wasm, per [ADR 0014](0014-ui-stack.md) §2) " followed by R1, followed by its unchanged last sentence "It never asks for or receives the master password, SK, or any decrypted item field beyond what the user is filling." |
| [ADR 0076](0076-autocomplete-driven-autofill.md) §9, the row whose first cell is "[ADR 0040] point 2 (…)", its "Replaced by" cell: ""**A fill request from a content script is refused.** The content script sends only detected-field reports and submitted-form reports (ADR 0036 §4, first bullet, without the fill request). A submitted-form report carries the submitted username and password and, under [ADR 0076] §5.1, at most 8 values of fields with a custom autocomplete token, which are offered for saving only in an extension-origin dialog."" | "**A fill request from a content script is refused.** The content script sends only the messages ADR 0036 §4, first bullet, lists ([ADR 0089](0089-extension-frames-and-save-dialog.md) §1); a fill request is not among them. A submitted-form report carries the submitted username and password and, under [ADR 0076](0076-autocomplete-driven-autofill.md) §5.1, at most 8 values of fields with a custom autocomplete token, which are offered for saving only in the extension-origin save dialog ([ADR 0089](0089-extension-frames-and-save-dialog.md) §2–§4)." |
| [ADR 0043](0043-inline-menu-instance-token.md) Decision point 1: "**Mint.** `InlineMenu`'s constructor and `passkey-relay.ts`'s consent-iframe builder each generate one token (`crypto.randomUUID()`, 122 random bits — a v4 UUID's 128 bits minus the 4 version bits and 2 variant bits RFC 4122 fixes) before setting the iframe's `src`." | "**Mint.** `InlineMenu`'s constructor, `passkey-relay.ts`'s consent-iframe builder and the save-dialog builder ([ADR 0089](0089-extension-frames-and-save-dialog.md) §2) each generate one token (`crypto.randomUUID()`, 122 random bits — a v4 UUID's 128 bits minus the 4 version bits and 2 variant bits RFC 4122 fixes) before setting the iframe's `src`." |
| [ADR 0043](0043-inline-menu-instance-token.md) Decision point 3, first sentence: "`InlineMenuShowMessage`/`PasskeyConsentShowMessage` gain one field, `instanceToken`, delivered exactly as `candidates`/the ceremony offer already are — never via `src`, an attribute, or any channel a page sharing the tab's frame tree can read." | "`InlineMenuShowMessage`/`PasskeyConsentShowMessage`/`SaveDialogShowMessage` carry one field, `instanceToken`, delivered exactly as `candidates`/the ceremony offer/the save-prompt token are — never via `src`, an attribute, or any channel a page sharing the tab's frame tree can read." |
| [ADR 0043](0043-inline-menu-instance-token.md) Decision point 4, first sentence: "`core-host/listener.ts`'s `isInlineMenuSender` branch, for all three message kinds, looks up `message.instanceToken` and refuses unless a live, unexpired, unrevoked registration exists for that exact `sender.tab.id`." | "`core-host/listener.ts`'s `isInlineMenuSender` branch, for every message kind an extension-origin iframe sends (the fill request, the offer request, the generator request, the passkey ceremony answers, `save_dialog_request` and `save_dialog_resolve`), looks up `message.instanceToken` and refuses unless a live, unexpired, unrevoked registration exists for that exact `sender.tab.id`." |
| [ADR 0076](0076-autocomplete-driven-autofill.md) §5.1, last sentence: "The long-lived context holds the values in memory only and zeroizes them when the prompt is resolved or times out, as it does for the submitted password today." | "The long-lived context holds the values in memory only, with the submitted username and password, under the save-prompt token of [ADR 0089](0089-extension-frames-and-save-dialog.md) §3, and zeroizes them when the prompt is resolved, replaced or times out (600 s), on lock, and on a restart." |
| [ADR 0076](0076-autocomplete-driven-autofill.md) §5.2, sentence: "The dialog fetches its choices from the long-lived context directly, by the save-prompt token." | "The dialog is an [ADR 0043](0043-inline-menu-instance-token.md) instance ([ADR 0089](0089-extension-frames-and-save-dialog.md) §2). It fetches its choices from the long-lived context directly, by its instance token and the save-prompt token ([ADR 0089](0089-extension-frames-and-save-dialog.md) §3), and a click in it counts only through the visibility gates of [ADR 0089](0089-extension-frames-and-save-dialog.md) §4." |
| [ADR 0076](0076-autocomplete-driven-autofill.md) §6, the row "Clickjacking the menu \| Unchanged M2 mitigations (`menu-visibility.ts`, IntersectionObserver v2 where available) \| Unchanged" | Two rows: "\| Clickjacking the menu \| Unchanged M2 mitigations (`menu-visibility.ts`, IntersectionObserver v2 where available) \| Unchanged \|" and "\| Clickjacking the save dialog (overlay, transparency, a timed flip) to save page-chosen values \| The inline menu's Gates A, B and C ([ADR 0089](0089-extension-frames-and-save-dialog.md) §4); Gate B runs after the round trip, before the save-prompt token is taken \| As for the menu: an overlay every gate misses, and Firefox without IOv2 \|" |
| [ADR 0076](0076-autocomplete-driven-autofill.md) §2.3 W5: "**W5 `LabelRequired`:** a write that creates a custom field, or edits any attribute of an existing one other than removing it, must leave its displayed `label` holding at least one non-whitespace character. This makes the Display Name required (R3). `field/<id>/label` *is* the Display Name; there is no second key." | "**W5 `LabelRequired`:** a write that creates a custom field, or edits any attribute of an existing one other than removing it, must leave its displayed `label` holding at least one non-whitespace character. A write that touches only `field/<id>/order` is a layout write, not an edit, and W5 does not apply to it; a write to any other attribute, `kind` included, is an edit. This makes the Display Name required (R3). `field/<id>/label` *is* the Display Name; there is no second key." |
| [ADR 0076](0076-autocomplete-driven-autofill.md) §4.1 step 3, last sentence: "A tab has at most 4 open offers." | "A tab has at most 4 open offers; creating a fifth first zeroizes and drops the tab's oldest open offer, and a fill request naming it is refused like an expired one ([ADR 0089](0089-extension-frames-and-save-dialog.md) §6)." |

**R1**, the one replacement text for ADR 0036 §4, first bullet, between its unchanged opening and its
unchanged last sentence: "sends only: detected-field reports; submitted-form reports
([ADR 0076](0076-autocomplete-driven-autofill.md) §5.1 says what a submitted-form report may carry);
the page-DOM banner's answer to a save prompt offered without a dialog, and the save-prompt location
check after a navigation; passkey relay requests ([ADR 0039](0039-passkeys-vault-and-extension.md));
and a per-instance registration or revocation message for an inline-menu, passkey-consent or
save-dialog iframe it is about to build or tear down ([ADR 0043](0043-inline-menu-instance-token.md),
[ADR 0089](0089-extension-frames-and-save-dialog.md) §1–§2). No other message. The chosen fill
request comes from the inline-menu iframe ([ADR 0040](0040-extension-fill-request-from-inline-menu.md)),
and the save dialog's requests come from the save-dialog iframe."

Everything else in ADRs 0036, 0040, 0043 and 0076 stays binding.

### 9. On acceptance (doc edits, not made now)

1. Status lines: ADR 0036 adds "[ADR 0089] (§4, first bullet, in part)"; ADR 0043 becomes
   "Partially superseded by [ADR 0089] ('What this ADR supersedes' row 1; Decision points 1, 3 and 4
   in part)"; ADR 0076 adds "[ADR 0089] (§2.3 W5; §4.1 step 3, §5.1, §5.2 and §6 in part; §9, two
   rows)". The README index rows follow. (Owner's act, ADR 0020 points 3, 4 and 9.)
2. [THREAT_MODEL.md](../THREAT_MODEL.md): add INV-112 to §8; extend the A7 bullet for ADR 0076 with
   the save-dialog gates and tokens; add "save dialog clickjacked or cloned" to the INV-36 test
   column.
3. [HANDOFF.md](../HANDOFF.md): close open question 1 (the "treat both as binding" rule).
4. [docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md): mark C1, S3,
   G08-4 and G08-5 as answered by ADR 0089.
5. CLAUDE.md's Accepted list (by the lead).

### 10. Implementation plan

Extension only. No Rust change: §5 matches the code.

1. `messaging/contract.ts`: validate save-prompt token fields with the instance-token pattern (§3.1);
   add `save_dialog_gate` and `save_dialog_gate_result` to `MESSAGE_TYPES` and `validate.ts`'s byte
   budget. Unit tests: a 37-character token, an uppercase one and a v1 UUID are refused.
2. `core-context.ts`: pending prompts record `tabId`, `createdMs` and `dialog`; a 600 s expiry
   sweep; 1 per tab and 64 in total; the take only after §3.2 and Gate B; `save_prompt_resolved`
   refused for a dialog prompt. Unit tests with an injected clock: expiry at 600 s and not at 599 s,
   another tab, used, replaced, the cap, and the four refusals compared byte for byte.
3. `content-script.ts` `SaveDialog`: register before `src` (a refusal falls back to the banner),
   Gate A sampling and `isFillAllowedNow`, the `save_dialog_gate` answer, revocation on every
   teardown path.
4. `save-dialog/main.ts`: Gate C with the inline menu's IOv2 options.
5. `offer-store.ts` keeps its eviction; `inline-menu/main.ts` shows the out-of-date text (§6).
6. E2E (`apps/extension/e2e/`, Chromium; Firefox where the harness runs it): a save dialog under
   `opacity: 0`, one under a page overlay, and one flipped visible only for the click each save
   nothing, and the token is still live afterwards; a cloned save-dialog page in a subframe cannot
   fetch rows or resolve; a forged `save_prompt_resolved` for a dialog prompt is refused; a fifth
   offer evicts the first, and a click on the first menu fills nothing.
7. A contract test that the `FromContentScript` union equals the list of §1.

## Consequences

### Positive

- One binding "sends only" list instead of two contradictory ones, and the shipped union can be
  tested against it.
- The save dialog gets the inline menu's clone and clickjacking defences, as Decision rules a
  reviewer can check.
- The save-prompt token has a format, a lifetime, a tab binding, single use and one refusal.
- The two minors are settled the way the code already behaves.

### Negative

- A pending prompt now expires after 600 s; a user who leaves it open longer must submit again.
- Gate B adds one long-lived context → content script round trip (at most 1000 ms) to each save.
- On Firefox the save dialog has no IOv2 gate, as for the inline menu.

### Risks

- A Gate A false positive (a benign page animation) can refuse a real save click. The token stays
  live, so the user can click again.
- Refusing `save_prompt_resolved` for dialog prompts may strand a flow the code relies on today
  (unverified, U).

## Alternatives considered

- **Keep both lists binding** (HANDOFF's interim rule). Rejected: two "only" lists that each forbid
  what the other requires are not a rule a reviewer can apply.
- **Gate B in the dialog only.** Rejected: the dialog cannot see how the embedding page styles its
  `<iframe>`. Gate B must run where Gate A runs and after the round trip, as for the menu.
- **Bind the save-prompt token to the dialog's instance token** instead of to the tab. Rejected for
  now: the tab binding plus the instance check already pins the sender, and it keeps the banner path
  working with the same token.
- **A new token format (16 random bytes, hex).** Rejected: the v4 UUID gives 122 bits, matches
  ADR 0043 and the shipped code, and one validator serves both tokens.
- **Refuse a fifth offer.** Rejected: it leaves the newest menu, the one the user sees, unusable.

## Open questions for the owner

1. **Pending save-prompt lifetime.** 600 s absolute (recommended), or 120 s to match the location
   index (shorter exposure, but a dialog left open for two minutes then saves nothing)?
2. **Exempt `kind`-only writes from W5 too**, as the review suggested? Recommendation: no. Keep the
   code's order-only exemption; a kind change is a content edit.

## References

- [ADR 0020](0020-partial-supersession.md), [ADR 0036](0036-browser-extension-architecture-and-key-custody.md),
  [ADR 0039](0039-passkeys-vault-and-extension.md), [ADR 0040](0040-extension-fill-request-from-inline-menu.md),
  [ADR 0043](0043-inline-menu-instance-token.md), [ADR 0076](0076-autocomplete-driven-autofill.md)
- [THREAT_MODEL.md](../THREAT_MODEL.md) A7, INV-36 to INV-40
- [docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) C1, S3;
  [G08.md](../reviews/2026-10-25-raw/G08.md) G08-1 to G08-5
