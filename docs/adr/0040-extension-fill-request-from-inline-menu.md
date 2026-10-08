# ADR 0040: The extension's fill request comes from the inline menu, not the content script

- Status: Accepted
- Date: 2026-10-08
- Deciders: project owner
- Milestone: M2

## Context

[ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, first bullet, says the content script sends "a chosen fill request (after the user picks a credential in the extension-origin inline menu)", and the third bullet says "Only the chosen fill's values cross, at fill time … The content script performs the actual DOM write."

The first M2 implementation followed this literally. The security review of 2026-10-08 found that it breaks [INV-36](../THREAT_MODEL.md#8-security-invariants) ("Nothing is filled without a trusted user gesture") against the attacker ADR 0036 §5 names in its second row, a compromised content script:

- The user's click is checked (`event.isTrusted`) only inside the extension-origin inline-menu iframe. The long-lived context that decrypts the values never saw any evidence of it.
- A content script could send "fill item X" with no click at all, and the long-lived context answered with the decrypted username and password.
- Nothing checked that item X was one of the matcher's candidates for that page ([ADR 0037](0037-url-matching-and-autofill-rules.md) §4–§5).

## Decision

1. **The inline-menu iframe sends the fill request itself.** Its click handler requires `event.isTrusted`. The iframe is an extension page, so the long-lived context identifies it from the browser's sender information (`sender.origin` is the extension's own origin and `sender.tab` is the tab it is embedded in), never from message fields. The popup may send the same request for the active tab.
2. **A fill request from a content script is refused.** The content script sends only detected-field reports and submitted-credential reports (ADR 0036 §4, first bullet, without the fill request).
3. **The candidate set is recomputed before anything is decrypted.** The long-lived context runs the matcher again for the browser-vouched top-frame URL of the sender's tab and requires the requested item to be among the candidates. An equivalence-only candidate still needs the second explicit confirmation of ADR 0037 §5, and the long-lived context checks it again rather than trusting the iframe.
4. **Values still go only to the content script, at fill time,** which performs the DOM write (ADR 0036 §4, third bullet, unchanged). They never go back to the iframe. Where the long-lived context cannot reach tabs itself (a Chromium offscreen document has no `chrome.tabs`), it asks the service worker to relay that one message; the service worker forwards it and keeps nothing.

## Consequences

- A compromised content script can no longer obtain any secret without a trusted click in an extension-origin document, and never for an item that does not match its page.
- One more message path (iframe → long-lived context) and one relay (long-lived context → service worker → tab) to test and keep size-limited.

## What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9:

| Part, quoted | Replaced by |
|---|---|
| [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, first bullet: "sends only: detected-field reports, a chosen fill request (after the user picks a credential in the extension-origin inline menu), and submitted-credential reports" | "sends only: detected-field reports and submitted-credential reports. The chosen fill request comes from the inline-menu iframe ([ADR 0040](0040-extension-fill-request-from-inline-menu.md))." |

Everything else in ADR 0036 stays binding.

## References

- [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, §5
- [ADR 0037](0037-url-matching-and-autofill-rules.md) §4, §5
- [THREAT_MODEL.md](../THREAT_MODEL.md) A7, INV-36, INV-40
