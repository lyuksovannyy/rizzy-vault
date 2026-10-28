# ADR 0067: Send-style text/file share

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M5

## Context

ROADMAP §4.7 M5, row 8 (Should): `| S | "Send"-style arbitrary text/file share (Bitwarden Send equivalent) | M5 |`. Every other M5 row (create/expiry/max-views/revoke, recipient page, field choice, owner's list, email restriction, passphrase) is about sharing an existing vault *item*. Row 8 is not: a Send has no item behind it, only owner-typed content.

The mechanism already exists for the item case. [ADR 0063](0063-share-snapshot-format.md) fixes the snapshot plaintext layout and the flags byte; [ADR 0064](0064-share-api-storage-lifecycle.md) adds `POST /api/v1/shares` (create), `.../open` (reveal), `.../list` and `.../revoke`, and the `shares` table; [ADR 0065](0065-share-page-origin-csp.md) fixes the recipient page's origin and CSP; [ADR 0066](0066-share-email-otp-verification.md) adds email-restricted recipients. [CRYPTO.md §11.10](../CRYPTO.md#1110-public-share-link-creation-m5)/[§11.11](../CRYPTO.md#1111-public-share-link-opening-m5) already specify creation and opening, and `ShareSnapshot = 0x0050` (purpose, `Padded` framing, `M::M5`) and the three `share/*` HKDF labels are already in `crates/rizzy-core/src/{envelope/purpose.rs,labels.rs}` (V, 5a78bb5) — written ahead of any accepted M5 ADR, as scaffolding only.

Two things in that mechanism assume an item: §11.10 step 1 ("the owner picks the fields to share") and step 7 ("the owner's copy of `share_secret` goes into the item's encrypted data, so the link can be shown again"). A Send has no fields to pick and no item to hold the secret in. This ADR covers exactly that gap, for text; ROADMAP's "file" half needs the M3 attachments ADR first.

Forces: CLAUDE.md's no-home-made-crypto rule; CRYPTO.md principle 1 (zero knowledge) and its metadata-minimization framing in §14; [THREAT_MODEL.md A12](../THREAT_MODEL.md#a12-share-link-leakage-m5) (share-link leakage) and [G-8](../THREAT_MODEL.md#13-security-goals) (share links); [ADR 0028](0028-api-v1-http-conventions.md) item 7 (body limits; `POST /api/v1/shares` is not in its large-body list).

## Decision

1. **Ship text-only Send in M5.** Reuse the Share API (ADR 0064) and the `SHARE_SNAPSHOT` envelope (purpose `0x0050`, algorithm `0x01`, `Padded` framing) exactly as ADR 0063 defines them. No new table, no new purpose id, no new label, no new algorithm id, no change to CRYPTO.md §4.3 or §8.4.
2. **Dependency, not supersession.** This ADR has no mechanism of its own; it only says how the item case's steps 1 and 7 change when there is no item. It cannot be Accepted before ADRs 0063, 0064, 0065 and 0066 are Accepted. It supersedes nothing, because none of them is Accepted yet (ADR 0020 point 9 applies only to Accepted ADRs).
3. **Creation.** The owner types or pastes text instead of picking item fields. CRYPTO.md §11.10 steps 2–6 run unchanged: `share_id`, `share_secret`, optional passphrase, `share_key`/`link_token`/`access_token` (§4.3, same labels), `POST /api/v1/shares`, link assembly. The only change is the plaintext that goes into the frame: the owner's text takes the place of an item's field entries, carried under [ADR 0063](0063-share-snapshot-format.md) §1's record-layer grammar (`field_key`/`value` pairs, `n ≥ 1`) rather than an ADR-0018 item-field set; the exact entry shape is ADR 0063's to fix jointly with this ADR (point 4 below and point 7), not restated here.
4. **Requirement: a server-invisible discriminator; exact placement left to ADR 0063.** The recipient page and the owner's own client need to agree that a given snapshot is free text, not field data. This ADR's requirement is that the discriminator be server-invisible — readable only after decryption. That rules out the flags byte on two independent grounds: the flags byte is sent to the server at creation (§11.10 step 5) and is part of `SHARE_SNAPSHOT`'s AAD context (CRYPTO.md §8.4), so a flags-based discriminator would tell the server which shares are Sends for free, for no functional gain (CRYPTO.md principle 1, §14's "what a malicious server can still do"); and point 1 above commits this ADR to no change to CRYPTO.md §8.4, which already fixes the flags byte's content (`u8 flags (bit 0 = passphrase)`) — a flags-byte discriminator would need to change that row. The discriminator therefore belongs in the plaintext, inside the encrypted frame. Exactly where within `SHARE_SNAPSHOT`'s plaintext layout — a leading kind byte or equivalent — is [ADR 0063](0063-share-snapshot-format.md)'s call, not this ADR's: 0063 owns that layout, and this ADR has no mechanism to bind a sibling Proposed ADR's Decision (ADR 0020 point 9 lets a new ADR supersede named parts of an *Accepted* ADR only; nothing lets one Proposed ADR dictate another's content). This ADR states the server-invisibility requirement and leaves the exact plaintext placement to be settled jointly with 0063, before either is Accepted (Open question 1).
5. **No item, so no step-7 restash: show-once.** The client renders the full link once, in the creation dialog, with a persistent notice that it cannot be shown again, and then discards `share_secret`. ADR 0064's `shares/list` (metadata only: `created_at`, expiry, `max_views`, `views`, `revoked`) still lists a Send, and `.../revoke` still works (owner-session-authenticated, not secret-authenticated) — only re-display of the link is lost.
6. **Owner-side labeling needs no API change.** The owner's client labels a `shares/list` row "field share" when a locally held item carries that `share_id`/`share_secret` pair (as §11.10 step 7 already requires for every field share), and "Send" otherwise. Purely a client heuristic.
7. **Text size cap: 512 KiB of UTF-8, client-enforced, before encryption.** `POST /api/v1/shares` is not on ADR 0028 item 7's large-body list, so it keeps the 1 MiB body cap; this ADR does not extend item 7. Budget: 1 MiB body minus ~2 KiB for the other JSON fields (`share_id`, two token hashes, expiry, flags) ≈ 1,046,528 B for the base64url-encoded envelope (§9.6, 4/3 inflation) ⇒ ≤ 784,896 B of raw envelope ⇒ ≤ 784,806 B of padded frame (90-byte overhead, §9.1) ⇒ ≤ ~700,715 B of `data` after Padmé's ≤12% overhead and the 4-byte length prefix (§8.5). 512 KiB (524,288 B) is a round number comfortably under that with margin for the estimate. The client rejects invalid UTF-8 before encrypting; no NFC normalization (this is content, not a credential compared cryptographically, unlike passphrases). **Entry split:** ADR 0063 §1 reuses ADR 0018 §10's per-value cap of 65,536 bytes (type byte included), so a 512 KiB Send cannot fit in one entry's value — it spans multiple entries. The exact split (sequential chunk entries, a repeated key, or otherwise) is ADR 0063's to settle jointly with this ADR (ADR 0063 Open question 6), not fixed here; this ADR's only constraint is the 512 KiB total.
8. **Rendering: plain text only.** The recipient page sets the text as `textContent`, never parses it as HTML or Markdown, and triggers no network fetch from it. This is a new rendering surface, not ADR 0062's (notes Markdown, M3, item-bound) — cited, not reused. Proposed INV-92 (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): *a Send's plaintext is rendered as text content only by the recipient page; it is never parsed as markup and never used to construct a URL, attribute or script context.*
9. **File-based Send: deferred, not cancelled.** Needs, in order: (a) the M3 attachments ADR Accepted and shipped — a defined chunked envelope (algorithm `0x03`): `ATTACHMENT_CHUNK` (`0x0033`) exists in CRYPTO.md §8.4 today only as a "defined by the M3 attachments ADR" placeholder. `ATTACHMENT_KEY_WRAP` (`0x0034`) is not a placeholder — it is already fully specified there, wrapped under the *item* key, context `vault_id ‖ item_id ‖ attachment_id` — but that is exactly the problem for a Send, which has no item: a share-scoped, item-less key-wrap variant (new context fields, possibly a new purpose id) is a new decision for that future ADR, not this one; (b) ADR 0028 item 7's large-body table extended to whatever endpoint carries file-Send chunks, itself a partial-supersession of an Accepted ADR, left to that future ADR. This ADR defines neither. Until then the web vault's Send UI is text-only; a disabled "attach a file" affordance is a product choice, not fixed here.
10. **Everything else about a share is unchanged for a Send:** expiry (1h/1d/7d/30d/custom), max views, manual revoke, optional passphrase (ADR 0063's flags bit 0), email-restricted recipients with one-time code (ADR 0066), recipient-page origin and CSP (ADR 0065), and worker-side purge on expiry (ROADMAP §4.7, `worker` role) all apply with no Send-specific branch.

## Consequences

### Positive

- No new storage, no new wire format, no new crypto primitive: the only genuinely new code is the item-less creation path and the show-once UI.
- The discriminator lives in the plaintext, never the flags byte (point 4), so the server stays as blind to "is this a Send" as it already is to item-field content — a small metadata-minimization win for free.
- Every existing M5 safety property (expiry, burn, passphrase, email restriction, revoke) covers a Send without a special case.

### Negative

- Show-once is a real UX regression from item shares, which can be re-displayed from the item. A Send, once the creation dialog is dismissed without copying the link, is gone.
- 512 KiB is a conservative, client-only constant, not derived from any product requirement; it may need revisiting.
- The recipient page now has two render modes (fields vs. free text) and must pick the right one from the plaintext discriminator ADR 0063 places (point 4).

### Risks

- A future PR that ships file-based Send by inventing an ad hoc per-share wrap ahead of the M3 attachments ADR would be exactly the home-made crypto CLAUDE.md forbids. Signal: any diff that adds chunking or a new key-wrap purpose under `crates/rizzy-server/src/http/api.rs`'s `shares` routes before that ADR is Accepted.

## Alternatives considered

- **A new `sends` table and a new purpose id.** Rejected: duplicates storage and crypto scaffolding that already works for arbitrary byte content; the only real difference from a field share is the missing item to restash the secret in (point 5 handles that without new storage).
- **Flags-byte discriminator.** Rejected per point 4: it would leak content-shape metadata to the server for no functional gain, and it would need a CRYPTO.md §8.4 change this ADR does not make (point 1), when the plaintext already has room for the same bit. Only the exact position within the plaintext is left to ADR 0063 (Open question 1).
- **A hidden, reserved local item type to hold the Send's secret for redisplay.** Would need an [ADR 0018](0018-item-record-encoding.md) §8 item-type reservation, and raises sync-visibility and local-index ([ADR 0056](0056-local-index-recently-used-search.md)) questions a text-only M5 feature does not need answered. Deferred past M5, if ever.
- **Shipping file-based Send now against an inline, ad hoc chunk cipher.** Rejected outright: no home-made crypto (CLAUDE.md); waits for the M3 attachments ADR.

## Open questions for the owner

1. **Confirm the server-invisibility requirement for the Send/field discriminator (point 4): is ruling out the flags byte correct, leaving only the exact position within `SHARE_SNAPSHOT`'s plaintext layout to ADR 0063?** This must be settled jointly with 0063 before either ADR is Accepted. *Recommendation:* yes — a flags-byte discriminator would leak content-shape metadata to the server for no functional gain and would need a CRYPTO.md §8.4 change this ADR does not make (point 1).
2. **Is 512 KiB the right text cap?** *Recommendation:* yes for M5; it is a client constant, changeable later without a new ADR, unlike the 1 MiB wire limit it stays under.
3. **Final invariant number for point 8's proposed INV.** Resolved: allocated as INV-92, the batch's proposed INV ids reconciled in ADR-number order; confirm at acceptance in case an ADR lands out of order.
4. **Ship a disabled "attach a file (coming later)" affordance in the M5 UI?** *Recommendation:* yes, as a product nicety; it blocks nothing in this ADR.

## References

- [ADR 0018](0018-item-record-encoding.md) §8 (rejected alternative's dependency), [ADR 0020](0020-partial-supersession.md) points 7 and 9, [ADR 0028](0028-api-v1-http-conventions.md) item 7, [ADR 0054](0054-attachments-envelope-and-api.md) (M3 attachments, file-case dependency), [ADR 0056](0056-local-index-recently-used-search.md), [ADR 0062](0062-markdown-notes-sanitization.md) (cited, not reused), [ADR 0063](0063-share-snapshot-format.md), [ADR 0064](0064-share-api-storage-lifecycle.md), [ADR 0065](0065-share-page-origin-csp.md), [ADR 0066](0066-share-email-otp-verification.md)
- [CRYPTO.md](../CRYPTO.md) §4.3, §8.4, §8.5, §9.1, §9.6, §11.10, §11.11
- [THREAT_MODEL.md](../THREAT_MODEL.md) [G-8](../THREAT_MODEL.md#13-security-goals), [A12](../THREAT_MODEL.md#a12-share-link-leakage-m5)
- [ROADMAP.md](../ROADMAP.md) §4.7, row 8
- Code (V, 5a78bb5): `crates/rizzy-core/src/envelope/purpose.rs` (`ShareSnapshot = 0x0050`), `crates/rizzy-core/src/labels.rs` (`share/key`, `share/link-token`, `share/access-token`), `crates/rizzy-server/src/http/api.rs` (resource-grouped route table ADR 0028 item 1 describes; `shares` would join it)
