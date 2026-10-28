# ADR 0063: Share snapshot plaintext layout and link/fragment grammar

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M5
- Supersedes: [ADR 0018](0018-item-record-encoding.md) §7 in part (see "What this ADR supersedes" below)

## Context

[ROADMAP §4.7](../ROADMAP.md#47-public-sharing-m5) (M5) asks for, among other rows:
- row 1 (Must): "Create share link for one item; item encrypted with a random key; key lives **only in the URL fragment** (`#…`), never sent to the server";
- row 4 (Must): "Choose which fields are included (e.g. share password but not notes/TOTP)";
- row 7 (Should): "Optional extra passphrase on share (out-of-band)".

[CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) already writes the `SHARE_SNAPSHOT` purpose (`0x0050`) and its context, `share_id ‖ u8 flags (bit 0 = passphrase)`, and [§11.10](../CRYPTO.md#1110-public-share-link-creation-m5)/[§11.11](../CRYPTO.md#1111-public-share-link-opening-m5) describe creation and opening, including the link `https://<server>/s/<b64url(share_id)>#1<flag digit><b64url(share_secret)>`. None of this binds yet: [CLAUDE.md](../../CLAUDE.md)'s ADR gate needs an Accepted ADR for a persistent format and a cryptographic context before code ships, and no ADR owns this plaintext or the fragment grammar. [ADR 0018](0018-item-record-encoding.md) §3 "Record kinds" reserves `record_kind = 0x04` for this data and says only: "The M5 ADR defines it. The recommendation is displayed values only: no dots, history or VV, because device ids and edit history are not the recipient's business." This is that ADR.

Code already reserves the pieces this ADR fills in (V, read 2026-10-11): `Purpose::ShareSnapshot = 0x0050` in `crates/rizzy-core/src/envelope/purpose.rs` — its module doc says a purpose "can be sealed or opened" only once it has a context type, which `ShareSnapshot` does not have yet; `RecordKind::RESERVED_SHARE_SNAPSHOT: u8 = 0x04` in `crates/rizzy-sync/src/record.rs`, with no encoder or parser; the labels `share/key`, `share/link-token`, `share/access-token` in `crates/rizzy-core/src/labels.rs`; and the field key `share/<share_id>/secret` in `crates/rizzy-core/src/item/schema.rs`. [CRYPTO.md §4.3](../CRYPTO.md#43-derivations) already derives `share_key`, the link token, the access token and `pp_key`, and [§8.5](../CRYPTO.md#85-plaintext-framing-and-padding) already lists `SHARE_SNAPSHOT` among the Padmé-framed purposes, confirming [ADR 0005](0005-symmetric-encryption-aead.md) point 5 ("item, share, relay and mail plaintexts are framed and padded with Padmé") applies here (Accepted). [ADR 0007](0007-ciphertext-envelope.md) (Accepted) is the generic, non-transmitted purpose-and-context binding this plaintext fills in; it does not list `0x0050` itself and nothing in it is replaced.

[THREAT_MODEL.md](../THREAT_MODEL.md) INV-32–INV-35, Q-4, Q-20, AR-23 and asset A12 ("Share-link leakage") set the constraints: the share secret exists only in the fragment and the owner's own encrypted item; the share ID is public and a path-only holder must not be able to burn a share; a passphrase makes guessing online-only, capped at 10 attempts.

**Out of scope, decided by sibling M5 ADRs in this batch (cited by number, not yet filed):** the `/api/v1/shares` endpoints, table and lifecycle (ADR 0064); the recipient page's origin and CSP (ADR 0065, THREAT_MODEL Q-4); the item-less "Send" share, which reuses this ADR's record kind for text instead of an item (ADR 0067). **Also out of scope, owned elsewhere and not re-decided here:** which paths exist at all, including the `/s/<share_id>` pattern, which is the web role's route table (ADR 0049), not ADR 0065 — ADR 0065 is scoped to that route's origin and CSP only, per the Out-of-scope entry above.

## Decision

No new cryptographic construction, label, algorithm id or purpose id. This ADR partially supersedes one Accepted ADR, named below, and no other. This ADR: (1) defines the `SHARE_SNAPSHOT` plaintext body under the already-reserved `record_kind = 0x04`, reusing [ADR 0018](0018-item-record-encoding.md)'s field-key and value encoding verbatim, except where named below; (2) fixes the `flags` byte CRYPTO.md §8.4 already names; (3) fixes the link fragment's grammar byte-for-byte; (4) partially supersedes [ADR 0018](0018-item-record-encoding.md) §7's "Concealed by default" bullet, named below.

### What this ADR supersedes

- **[ADR 0018](0018-item-record-encoding.md) §7, the "Concealed by default" bullet.** Replaced in full by: "**Concealed by default,** and left out of an M5 share unless chosen: `login.password`, `login.totp`, `card.number`, `card.code`, `card.pin`, `identity.ssn`, `identity.passport_number` and hidden custom fields. `share/…` is never included in a share snapshot, whatever the owner chooses (ADR 0063 §1)." Everything else in ADR 0018 §7 — the grammar, the length rules, the field table, the reserved-prefix bullet — stays binding, unnamed and unchanged.
  - *Why a supersession and not a reading of the existing bullet:* ADR 0018 §7 lists `share/…` beside `login.password` and the other concealed fields, i.e. opt-outable-but-choosable. §1 below hard-rejects any `share/…` field_key at the record layer, below the schema layer where ADR 0018 places the owner's choice, so it is a narrowing, not an application, of that bullet. The motivation is INV-32–INV-35 and asset A12: a share snapshot must never carry another share's secret, so there is no safe UI that offers `share/<share_id>/secret` as a choosable field. This narrowing needs the owner's acceptance of this ADR to take effect (see Open questions).

### 1. Plaintext body (`record_kind` 0x04)

```
SHARE_SNAPSHOT data
  u8  record_kind = 0x04
  u16 n ‖ n × ( str(field_key) ‖ bytes(value) )      1 ≤ n ≤ 1,024
```

- `field_key` and `bytes(value)` are exactly [ADR 0018](0018-item-record-encoding.md) §7 and §6: the same grammar, the same value-type byte, the same canonical order (strictly ascending, no duplicates, §4).
- **Record layer** (generic, in `rizzy-sync/src/record.rs` next to the other record kinds): rejects `record_kind ≠ 0x04`; `n = 0` or `n > 1,024`; a count or length running past the end or leaving trailing bytes; a `field_key` breaking ADR 0018 §7's grammar, outside 1–160 bytes (ADR 0018 §5 rule 2, §10), equal to `@lifecycle`, or starting with `share/` (per "What this ADR supersedes" above); a value exceeding 65,536 bytes (ADR 0018 §10); keys not strictly ascending or repeated. It does not know what an item is (ADR 0018 §2's layer split) and never interprets a value's bytes — a length check is not content inspection, and ADR 0018 §5 rule 2 already requires it. `n ≥ 1` is deliberate: the two-key rule below is the item-share writer's, not the record layer's, so a Send snapshot (ADR 0067) can carry a single entry.
- **Writer rule for an item share** (`rizzy-client`'s share-creation path, using the schema layer's field-key definitions in `rizzy-core/src/item`, not the record parser): MUST include `item.type` and `item.name` ([ADR 0018](0018-item-record-encoding.md) §7) among the entries, plus the displayed value of every field the owner chose, excluding every `share/…` field regardless of choice (ADR 0018 §7, as superseded above). An unrecognised value is kept and shown as "unsupported value" (ADR 0018 §6, unchanged). ADR 0067's Send object carries no `item.type` and defines its own entries under this same `record_kind`; nothing here requires `item.type` for a Send snapshot.
- No dot, HLC, version vector or device id is ever carried (ADR 0018 §3's recommendation, now binding).
- ADR 0067's Send also needs a server-invisible discriminator inside this plaintext, so a reader can tell a Send's free text from an item's field set without the server learning which (ADR 0067 Decision point 4, Open question 1). This ADR does not yet fix its exact position (a leading kind byte or equivalent); it is settled jointly with ADR 0067 before either is Accepted (Open question 6, below).
- **Size:** reuse [ADR 0018](0018-item-record-encoding.md) §10's limits for `record_kind = 0x04` in full, not just the whole-body bound: one value ≤ 65,536 bytes (type byte included), a field_key 1–160 bytes, ≤ 1,024 entries, `data` ≤ 1 MiB, checked before decoding. A smaller cap would need data this ADR does not have.
- Framing: [CRYPTO.md §8.5](../CRYPTO.md#85-plaintext-framing-and-padding) Padmé, 256-byte floor, already listed for this purpose.

### 2. `flags` (CRYPTO.md §8.4 context)

- Bit 0 (LSB) = 1 if the share requires a passphrase, else 0. Bits 1–7 are reserved and MUST be 0.
- The writer (`rizzy-client`) MUST clear bits 1–7. A reader (the recipient page, and the server's own copy of `flags` from ADR 0064's create endpoint) MUST reject a `flags` byte with any reserved bit set, with the same error as an unrecognised algorithm id (CRYPTO.md §9.5 rule 1), before the AAD is built. Accepting a reserved bit would let the AAD byte (0–255) disagree with the fragment's single decimal digit (0–9) below, which can never represent more.
- Effect of bit 0, unchanged from CRYPTO.md: the opener derives `pp_key = Argon2id(NFC(passphrase), share_id, kdf_id = 1, 32)` ([§4.3](../CRYPTO.md#43-derivations) "Share passphrase key") before `share_key`/`access_token` ([§11.10](../CRYPTO.md#1110-public-share-link-creation-m5) steps 3–4, [§11.11](../CRYPTO.md#1111-public-share-link-opening-m5) step 2). No new derivation.
- The plaintext `flags` field that ADR 0064's create request stores MUST be byte-identical to the AAD's `flags`; this ADR does not otherwise define that request.

### 3. Link fragment grammar

```
share-fragment = version flag secret
version        = "1"                               ; the fragment grammar's own version, independent of the
                                                     ; envelope's format_version (CRYPTO.md §9.1)
flag           = "0" / "1"                          ; the flags byte above, as one decimal digit
secret         = 43( ALPHA / DIGIT / "-" / "_" )    ; base64url w/o padding of the 32-byte share_secret
```

- Exactly 45 characters, nothing else in the fragment. The path's `<b64url(share_id)>` (22 characters, 16 bytes) is unchanged from CRYPTO.md §11.10 step 6. Which paths exist, including this one, is owned by ADR 0049's route table, not this ADR or ADR 0065 (ADR 0065 is scoped to that route's origin and CSP, per Context "Out of scope").
- `secret` decodes through the existing `rizzy_core::encoding::b64url_decode_into` (verified: rejects padding, an out-of-alphabet character, an impossible length and non-zero trailing bits), so one valid fragment per `share_secret` holds without new decoder code.
- Parser (new, `rizzy-core/src/share_link.rs`): rejects a fragment whose length is not exactly 45, whose `flag` is not `"0"`/`"1"`, or whose `secret` fails the check above. A `version` that is a single ASCII digit but not `"1"` reports "update required", the ADR 0018 §11 reader rule for an unknown format version, not a generic "malformed link"; a `version` character that is not a digit at all is malformed.
- This is the "share-URL fragment parser" [CRYPTO.md §15](../CRYPTO.md#15-testing) item 7 already lists as a fuzz target; this ADR gives it the grammar to fuzz against.

### 4. Placement and tests

- `rizzy-sync/src/record.rs`: the `record_kind = 0x04` encoder/parser, next to `RecordKind::RESERVED_SHARE_SNAPSHOT`.
- `rizzy-core/src/envelope/purpose.rs`: a `ShareSnapshotCtx { share_id: [u8; 16], flags: u8 }` context type (17 bytes) — the first context type `Purpose::ShareSnapshot` gets.
- `rizzy-core/src/share_link.rs` (new): fragment build and parse.
- `rizzy-client`'s share-creation path: the item-share writer rule (§1) that requires `item.type` and `item.name` and excludes every `share/…` field, built on the `rizzy-core/src/item` schema layer's existing field-key definitions.
- Normative vectors join [CRYPTO.md §15](../CRYPTO.md#15-testing) item 1(A): one item share per M1 item type (a concealed-by-default field excluded, then included on request; a `share/…` field never included even on request), plus one negative vector per §1's record-layer rejection rule above (ADR 0018 §12 style), including a 161-byte field_key, a value just over 65,536 bytes, and a `share/<share_id>/secret` entry. Property test: encode → parse → encode is the identity; truncation at every length is rejected, never panics (ADR 0018 §5 style).

### On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it.

1. **ADR 0018 is partially superseded** ("What this ADR supersedes" above). Its status line, and its Status cell in [docs/adr/README.md](README.md), gain "Partially superseded by [ADR 0063](0063-share-snapshot-format.md) (§7 in part)", after any earlier entry and separated from it by a semicolon (ADR 0020 point 9). Its text is not otherwise edited.

## Consequences

### Positive
- Fills three forward-declared gaps (ADR 0018 §3, the two code reservations, CRYPTO.md's unbaked ctx/link text) with no new primitive, label, algorithm id or purpose id to audit.
- A byte-exact body and fragment give the M8 audit and the already-listed fuzz target something concrete to check.
- The record layer stays permissive (ADR 0018 §2 style), so ADR 0067's Send needs no new record kind.
- Closing the `share/…` gap at the record layer (not only in client UI) means a buggy or malicious writer cannot leak another share's secret into a snapshot, whatever the schema layer intended to offer.

### Negative
- One more parser (`share_link.rs`) and one more record-layer arm to fuzz and audit, alongside ADR 0018's.
- The one-digit `flag` caps a future flags byte at values 0–9; a bit beyond 0 needs a new fragment-grammar `version`, not just a registry entry.
- `item.type`/`item.name` being mandatory is a schema-layer, not record-layer, rule, so only an end-to-end test catches a writer that omits them; the record parser alone would accept such a snapshot.
- Partial supersession spreads ADR 0018 §7 over two documents; a reader of ADR 0018 §7 must also read this ADR's "What this ADR supersedes" (ADR 0020 point 9 risk).

### Risks
- If ADR 0067 needs different order or size rules for Send under `record_kind = 0x04`, it must partially supersede this ADR's §1 rather than quietly diverge. Signal: that ADR's own review surfacing a conflict before M5 code lands.
- A sender that fails to clear reserved `flags` bits (bug, not malice) gets rejected by its own recipient page rather than silently accepted; intended fail-closed behaviour, noted here so it is not mistaken for a defect later.

## Alternatives considered

- **CBOR or JSON for the snapshot body.** Rejected for the reasons ADR 0018's Alternatives already give for item records: no new dependency, one parsing style, no new plaintext-audit surface.
- **`flags` as two hex characters in the fragment** (room for 256 values). Rejected: not what CRYPTO.md §11.10 step 6 already specifies, and nothing needs more than one bit yet; a future bit gets its own ADR and `version` digit regardless.
- **`share_secret` in the URL path instead of the fragment.** Rejected outright: the path reaches the server, proxy logs and `Referer` headers (INV-32, A12); only the fragment is never sent.
- **Ignore reserved `flags` bits** instead of rejecting them. Rejected: it would let the AAD and the one-digit fragment silently disagree once a future ADR used bit 1, against CRYPTO.md §9.5's fail-closed "no negotiation" rule.
- **Leave `share/…` choosable, as ADR 0018 §7 currently reads, and rely only on the writer rule to exclude it.** Rejected: a schema-layer-only exclusion is one bug away from a leaked secret, and ADR 0020 point 9 exists exactly so a narrowing like this is named rather than silently asserted.

## Open questions for the owner

**Proposed INV-89** (allocated across the 2026-10-11 batch in ADR-number order, replacing the draft's placeholder `INV-S1`. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): A `SHARE_SNAPSHOT` plaintext carries only field-key/value entries under `record_kind = 0x04`; it never carries a dot, HLC, version vector, history entry or device id, so a recipient learns nothing about which device, or when, a field was last written.

1. **Are `item.type` and `item.name` mandatory in every item share?** *Recommendation:* yes — the recipient needs a title and a rendering hint, and the link is already shared out of band, so the name adds little exposure beyond that. ADR 0067's Send carries neither, under the same record kind.
2. **Reject a `flags` byte with a reserved bit set, or carry it through unchanged (CRYPTO.md §9.5 fail-closed vs. ADR 0018 §6's "unknown is kept, never rejected")?** *Recommendation:* reject. `flags` is a fixed AAD field, not a forward-compatible value type, and the one-digit fragment cannot represent an unknown bit anyway.
3. **Reuse ADR 0018 §10's numeric limits for `record_kind = 0x04` as-is, or pick a smaller cap for shares?** *Recommendation:* reuse as-is; revisit together with ADR 0018 §10's own M3 review.
4. **Which number does the proposed invariant above get in THREAT_MODEL.md's registry?** Resolved: allocated as INV-89, the batch's proposed INV ids reconciled in ADR-number order; confirm at acceptance in case an ADR lands out of order.
5. **Accept the partial supersession of ADR 0018 §7's "Concealed by default" bullet ("What this ADR supersedes"), so `share/…` is excluded from every M5 share regardless of owner choice?** *Recommendation:* yes. Letting the owner "choose" to include `share/<share_id>/secret` would let one share link leak another share's secret (INV-32–INV-35, asset A12); no UI copy makes that a safe choice, so the record layer should refuse it outright rather than trust the schema layer alone.
6. **Where does the plaintext carry the server-invisible Send/field discriminator ADR 0067 needs, and what does a Send's entry set look like under this §1 grammar?** Not fixed by this ADR today. *Recommendation:* decided jointly with ADR 0067 before either is Accepted.

## References

- [ROADMAP.md](../ROADMAP.md) §4.7 (M, rows 1 and 4; S, row 7)
- [THREAT_MODEL.md](../THREAT_MODEL.md) INV-32–INV-35, Q-4, Q-20, AR-23, asset A12
- [CRYPTO.md](../CRYPTO.md) §4.3, §8.4, §8.5, §9.5, §9.6, §11.10, §11.11, §15 item 7
- [ADR 0005](0005-symmetric-encryption-aead.md) point 5, [ADR 0007](0007-ciphertext-envelope.md), [ADR 0018](0018-item-record-encoding.md) §2–§7, §10, §3 "Record kinds", [ADR 0020](0020-partial-supersession.md) point 9 (the mechanism this ADR uses to narrow ADR 0018 §7)
- ADR 0064 (Share API, storage and lifecycle), ADR 0065 (Share recipient page origin and CSP), ADR 0067 (Send-style text/file share) — all Proposed, this batch, cited by number only: not yet filed
- ADR 0049 (Web role: a fixed, enumerable route table — compiled-in assets and share links), cited for path ownership only: Proposed, not yet filed, title and scope not independently re-verified against its own text in this change (U)
- `crates/rizzy-core/src/envelope/purpose.rs`, `crates/rizzy-sync/src/record.rs`, `crates/rizzy-core/src/labels.rs`, `crates/rizzy-core/src/item/schema.rs`, `crates/rizzy-core/src/encoding.rs` (V, read 2026-10-11)
