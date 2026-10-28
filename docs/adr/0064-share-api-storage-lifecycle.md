# ADR 0064: Share API, storage and lifecycle

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M5

## Context

[ROADMAP §4.7](../ROADMAP.md#47-public-sharing-m5), Must, M5: create a share link for one item with a random key living only in the URL fragment; expiry and max-views and manual revoke; a recipient view page that needs no account; chosen fields only; "owner sees list of active shares + view count." [CRYPTO.md §11.10](../CRYPTO.md#1110-public-share-link-creation-m5) and [§11.11](../CRYPTO.md#1111-public-share-link-opening-m5) already fix the client-side flow and the four derivations (share key, link token, access token, passphrase key, [§4.3](../CRYPTO.md#43-derivations), V) and the `SHARE_SNAPSHOT` purpose `0x0050` ([§8.4](../CRYPTO.md#84-aad-and-purposes), V). Nothing here needs a new construction. What is missing, and what this ADR fixes, is the **server side**: the HTTP endpoints and their session/body rules under [ADR 0028](0028-api-v1-http-conventions.md), and the storage row under [ADR 0011](0011-storage.md).

`rizzy-domain-share` is already planned ([ADR 0016](0016-workspace-layout.md) §3, M5, V): "Share envelopes, token hashes, expiry, view counts", depending only on `proto, storage, bus` — **not** `core`. Unlike `rizzy-domain-vault`, it cannot verify a signature; the share envelope is an opaque, size-capped `BLOB` the server never parses, which is safe because nothing server-side needs to read it (the owner's client built it, the recipient's client checks the envelope's key commitment, [CRYPTO.md §8.3](../CRYPTO.md#83-key-commitment)).

[ADR 0011](0011-storage.md) point 5 fixes the table prefix `share_`; its own "What is stored, by sync mode" row for `share` is itself superseded — the live text is [ADR 0022](0022-server-mode-only.md) §2 "What is stored", `share` row (V): "share envelopes, link-token and access-token hashes, expiry, view counts." Point 6 allows exactly one cross-domain foreign key, to `auth_accounts(id)`; point 4 bans JSON columns, so a list (`recipient_emails`) needs a child table, not a column. [docs/HANDOFF.md](../HANDOFF.md) gap 24 and [ADR 0028](0028-api-v1-http-conventions.md) item 15 are **not** this ADR's concern: the anonymous recipient page's route is a web-role route-table row, owned by ADR 0049 (this batch, Proposed), not a second supersession of item 15.

**A real contradiction inside CRYPTO.md, found while drafting this ADR (checked, V):** §11.10 step 5 lists the server's stored fields as "…plus an owner reference, created_at, view count **and revoked flag**", but step 7 says "Revoking deletes the server row." A flag and a deletion cannot both be true. §11.11's "burn" (10 wrong-`access_token` failures) has the same ambiguity. This ADR resolves it (Decision, "Lifecycle") against the Accepted invariant that already requires deletion, and names the correction CRYPTO.md needs on acceptance.

Threats: [THREAT_MODEL §7.6](../THREAT_MODEL.md#76-api-role-m1) "D" (share spam, storage exhaustion), "I" (IDOR on shares), "R" (share creation in the security event log); [Q-20](../THREAT_MODEL.md#10-open-questions-for-the-owner)/[AR-23](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)/INV-33 (the link-token/access-token split and the burn) and **INV-34** (delete at expiry, revoke or max views, "whether or not anyone visits" — already Accepted, V), all already adopted into CRYPTO.md §11.11.

## Decision

### Crate and module

The domain logic lives in `rizzy-domain-share` (new, [ADR 0016](0016-workspace-layout.md) §3). `rizzy-server/src/http/api.rs` gains a `shares` resource group in its module table, mapping `rizzy-proto` request/response types onto `rizzy-domain-share` calls, exactly as `rizzy-domain-vault` is wired in today (V, `crates/rizzy-domain-vault/src/lib.rs`). The recipient page is served from `rizzy-server/src/http/web.rs`'s existing module, as a new route-table row (ADR 0049), not from this crate.

### Endpoints

Four new paths, resource `shares`, verb last, `POST` only, no path parameter — every id is a body field, so item 1's own rationale ("no id list, cursor or token reaches a URL", INV-52) holds for these as it does for the first 27:

| Method, path | Request → response | Session |
|---|---|---|
| `POST /api/v1/shares/create` | `CreateShareRequest{share_id, envelope, link_token_hash, access_token_hash, flags, expires_at_ms, max_views, recipient_emails?}` → `CreateShareResponse{created_at_ms}` | OPAQUE or device (as `vault/upload`) |
| `POST /api/v1/shares/list` | no body → `ListSharesResponse{shares: [{share_id, created_at_ms, expires_at_ms, max_views, views, flags}]}` | OPAQUE or device |
| `POST /api/v1/shares/revoke` | `RevokeShareRequest{share_id}` → 204 | OPAQUE or device |
| `POST /api/v1/shares/open` | `OpenShareRequest{share_id, link_token, access_token, email_otp?}` → `OpenShareResponse{envelope}` | none |

`create`'s `account_id` comes from the session, never the body (an `IDOR`-by-construction prevention, THREAT_MODEL §7.6 "I"). `list` and `revoke` act only on the caller's own rows; `revoke` on a `share_id` that does not exist, or belongs to another account, answers `404 not_found` (uniform error, item 3), never a distinguishing code. `email_otp` is reserved for ADR 0066, which this ADR does not duplicate. The `flags` byte, its bit layout and the snapshot's plaintext are ADR 0063's; this ADR stores `flags` as an opaque clear `u8`, needed because `SHARE_SNAPSHOT`'s AAD context is `share_id ‖ flags` (CRYPTO.md §8.4) and the owner's `list` view shows it. No new error code: `open` reuses `not_found` for a wrong `link_token`, an unknown, expired, revoked or burned share (all indistinguishable, by design, matching §5.9's account-enumeration stance); `401 unauthorized` for a right `link_token` with a wrong `access_token`, matching OPAQUE's own wrong-credential code.

**Retry safety.** `create`'s class is Upload: a byte-identical retry (same `share_id`, `envelope`, both hashes and the same `share_recipients` set) by the same account answers success without a second insert; anything else at an existing `share_id` — a non-identical retry, or a different account entirely — is `409 record_conflict` (ADR 0021 §9's existing code, reused), the same answer in both cases so a caller cannot use the distinction to probe whether a `share_id` from a link it holds is still live. `list` is Reads-class and `revoke` is Set-to-a-value-class, safe to retry. `open` is Single-use: every accepted attempt (right-or-wrong tokens) consumes a failure or a view, so a client must not blindly retry it on a connection failure — the recipient's explicit "Reveal" click (CRYPTO.md §11.11 step 3, already required) is the only safe retry trigger. These four assignments widen the **Endpoints**, **A repeat** and **Owner** cells of [ADR 0028](0028-api-v1-http-conventions.md)'s existing "Retry after an unknown outcome" rows "Reads", "Upload", "Set to a value" and "Single use" — a change to that Decision text under [ADR 0020](0020-partial-supersession.md) point 9 ("a table row, by the exact text of its first cell"), named below under "What this ADR supersedes" with full replacement text for each row, as 0031 and 0032 named "item 3 in part" for the same table's sibling, the error-code list, to add one code each.

**Body limits, unchanged.** `create`, `revoke` and `open` fall under item 7's default "1 MiB for every endpoint"; `list` takes no body, so it is one of item 7's "0 for the body-less endpoints" rows (item 2: a no-body request is still `POST`). None needs the upload-limit category. Because `create`'s request (which carries the envelope) is itself capped at 1 MiB, the stored envelope, and so `open`'s response, can never exceed that — no new body-limit category, item 7 is not superseded. **Unverified:** ADR 0048 (this batch, Proposed, not yet a file in this repository) is expected to count share envelope bytes toward the account's byte quota the way it counts `vault/upload` bytes; its actual scope, as cited elsewhere in this batch, enumerates "vault op/snapshot bytes now, mail and attachment bytes as those domains ship" without naming share bytes. This ADR does not rely on that quota to bound share storage (Open question 6).

### What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9:

- [ADR 0028](0028-api-v1-http-conventions.md) item 1, the whole bullet (79 of ADR 0028's 3,026 Decision words, V):

  > **Paths and methods.** The 36 endpoints of `rizzy-server` `http/api.rs` (module table), under `/api/v1/`, grouped by resource (`register`, `login`, `device-auth`, `account`, `devices`, `healing`, `recovery`, `totp`, `vault`, `attachments`, `shares`), verb last (`start`, `finish`, `commit`, `create`, `list`, `revoke`, `open`, …). `POST` for everything, including reads that carry a body; `GET` (and `HEAD`) only for `GET /api/v1/devices/grants`. No endpoint takes a path parameter: every id, `share_id` included, is a body field. *Why:* a request body never goes in a URL, so no id list, cursor or token reaches a URL or an access log (INV-52); one method keeps the signing rule simple; a uniform rule needs no per-endpoint exception as the table grows. This ADR adds 4 endpoints (`shares`) on top of base 27 plus sibling ADR 0054's 5 (`attachments`, same batch, ADR-number order), for 36; ADR 0066 (+1) and ADR 0068 (+3) add their own deltas after this one, for a cumulative 40. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.

- [ADR 0028](0028-api-v1-http-conventions.md) "Retry after an unknown outcome" table, rows "Reads", "Upload", "Set to a value" and "Single use" (these four rows' old text totals 109 words; with item 1 that is 188 of 3,026 Decision words, 6.2%, V — far under the half limit):

  | Class | Endpoints | A repeat | Owner |
  |---|---|---|---|
  | Reads | `account/state`, `vault/fetch`, `devices/grants`, `GET /api/meta`, `shares/list` | changes nothing | – |
  | Upload | `vault/upload`, `shares/create` | a byte-identical record is answered success as an acknowledgement (`vault/upload`: `already_stored`; `shares/create`: the same `CreateShareResponse`); a different record at that dot, or a different account entirely, is `record_conflict` | [ADR 0021](0021-server-compaction.md) §9 "Already stored"; ADR 0064 "Retry safety" (`shares/create`) |
  | Set to a value | `devices/suspend`, `devices/unsuspend`, `devices/grants/ack`, `shares/revoke` | same result (suspend returns the same head; a repeated `shares/revoke` answers `not_found` once the row is gone, read as already revoked) | CRYPTO.md §11.8, §10.1; ADR 0064 "Retry safety" (`shares/revoke`) |
  | Single use | `login/*`, `device-auth/*`, `register/start`, `account/reregister/start`, `totp/*`, `shares/open` | not safe to repeat blindly: the login state and the challenge are taken once, a TOTP code is accepted once, and `shares/open` consumes a failure or a view on every accepted attempt; the client restarts the flow, reads `account/state` first, or for `shares/open` waits for the next explicit "Reveal" click (CRYPTO.md §11.11 step 3) | CRYPTO.md §5.10, §5.11, §11.15; CRYPTO.md §11.11 step 3 (`shares/open`) |

- [ADR 0022](0022-server-mode-only.md) §2, "What is stored" table, row `share (M5)` (16 of ADR 0022's 2,564 Decision words, 0.6%, V):

  | Domain | Stored |
  |---|---|
  | `share` (M5) | share envelopes, link-token and access-token hashes ([CRYPTO.md §11.10](../CRYPTO.md#1110-public-share-link-creation-m5)), expiry, view counts, recipient emails (`share_recipients`, this ADR) |

### Storage

`share_shares` (prefix `share_`, [ADR 0011](0011-storage.md) point 5), migration `crates/rizzy-storage/migrations/{sqlite,postgres}/0008_share_initial.sql` (highest today is `0005`, V; sibling ADRs 0047 and 0048, same batch, take `0006` and `0007` ahead of this one in ADR-number order):

```
id                BLOB    PRIMARY KEY CHECK (length(id) = 16)       -- share_id, client-generated
account_id        BLOB    NOT NULL REFERENCES auth_accounts(id)
                           ON DELETE CASCADE                        -- the point-6 cross-domain FK
envelope          BLOB    NOT NULL                                  -- Envelope(share_key, SHARE_SNAPSHOT, …), opaque
link_token_hash   BLOB    NOT NULL CHECK (length(link_token_hash) = 32)
access_token_hash BLOB    NOT NULL CHECK (length(access_token_hash) = 32)
flags             INTEGER NOT NULL CHECK (flags BETWEEN 0 AND 255)
expires_at_ms     INTEGER NOT NULL CHECK (expires_at_ms >= 0)
max_views         INTEGER NOT NULL CHECK (max_views >= 1)
views             INTEGER NOT NULL DEFAULT 0 CHECK (views >= 0 AND views <= max_views)
access_failures   INTEGER NOT NULL DEFAULT 0 CHECK (access_failures >= 0 AND access_failures <= 10)
created_at_ms     INTEGER NOT NULL CHECK (created_at_ms >= 0)
```
`CREATE INDEX share_shares_account ON share_shares (account_id)` for `list`. `share_recipients(share_id BLOB NOT NULL REFERENCES share_shares(id) ON DELETE CASCADE, email TEXT NOT NULL CHECK (length(email) > 0), PRIMARY KEY (share_id, email))` holds the optional restriction list (point 4 bans a JSON column for it). **Basis for the clear-text column:** [ADR 0011](0011-storage.md)'s "No plaintext" bullet (not superseded by ADR 0022, V) already names "share recipient emails (M5)" among the allowed clear-text metadata, but conditions it on a THREAT_MODEL change in the same PR, and THREAT_MODEL §3.4's share row today lists only "Share ciphertexts, expiry, view counts" — no recipient-email entry. This ADR discharges that condition: it adds a `share_recipients` row to THREAT_MODEL §3.4 and widens ADR 0022 §2's `share` row (above), both on acceptance, so the column is sanctioned the moment this ADR binds, not before. STRICT tables, `_ms` timestamps, `account_id` naming: all as `0002_vault_initial.sql` and `0001_auth_initial.sql` already do (V). The `<=` bound on `views` and `access_failures` (not `<`) is deliberate: a row CHECK fires on the `UPDATE` that reaches the boundary, before the matching `DELETE` runs in the same transaction (Lifecycle); `<` would make the boundary `UPDATE` itself fail, so the last allowed view and the 10th failure could never be recorded.

The task brief that preceded this ADR named columns `owner_account_id`, `share_id`, `expiry`, `recipient_emails`, `created_at` and a `revoked` flag. Corrected here to the house naming (`account_id`, `id`, `expires_at_ms`, `created_at_ms`), `recipient_emails` moved to its own table (no JSON columns), `access_failures` added (needed to count the burn and absent from that list), and `revoked` dropped (see Lifecycle).

### Lifecycle

**Revoke, burn and view-exhaustion are all the same event: the row is deleted.** This resolves the CRYPTO.md contradiction (Context) in favour of step 7's "revoking deletes the server row," and matches **INV-34** (Accepted, THREAT_MODEL §8.5), which already requires deletion "at expiry, revoke or maximum views... whether or not anyone visits." INV-34's text does not yet name the burn (10 wrong-`access_token` failures) as a trigger, or rule out a flagged-inactive row; rather than mint a new, separately-numbered invariant for content INV-34 already mostly covers, this ADR extends INV-34 itself (on acceptance, below) to name the burn and the no-tombstone rule explicitly. Keeping a tombstone would only prolong exposure of ciphertext, hashes and `recipient_emails` for no benefit (ADR 0011 "No plaintext"), and it collapses "revoked", "burned", "view limit reached" and "never existed" into one answer, `not_found` (THREAT_MODEL §7.6 "I"). **On acceptance, CRYPTO.md §11.10 step 5 drops "and revoked flag" from its stored-fields list**, matching step 7 exactly.

- **`create`:** insert under `lock_account(account_id)` (ADR 0011 "Transactions and concurrency"), same as a vault self-grant.
- **`list`:** a plain read, no lock (as `vault/fetch`).
- **`revoke`:** `lock_account(account_id)` from the session, then `DELETE FROM share_shares WHERE id = ? AND account_id = ?`; zero rows affected is `404 not_found`.
- **`open`:** the per-`(share_id, source)` and per-`source` rate-limit hit (Rate limiting, below) is checked, and its own write committed, **before** any lookup, lock or transaction below — matching `recovery_start`'s order (`hit_recovery` before `db.begin_write()`, V, `recovery.rs`) — so an anonymous flood of bogus `share_id`s is throttled before it can take a database write transaction or the account lock. Only then: look up the row by `id`; on no match, substitute the same all-zero id `check_recovery_code` uses so the unknown-id path runs the identical queries. `lock_account` on whichever id resulted, re-read under the lock and under `WHERE expires_at_ms > now` (an unknown, just-deleted or now-expired id's re-read is empty), then compare both hashes in constant time against the row's values or, for the all-zero or empty-re-read path, against a fixed dummy hash (as `DUMMY_HASH` does there) — an unknown `share_id` and a wrong `link_token` on a real one are then the same code path, not just the same answer. Wrong `link_token` → `404`, never touches `access_failures`. Right `link_token`, wrong `access_token` → `UPDATE … SET access_failures = access_failures + 1`; if the new value reaches 10, `DELETE` in the same transaction; answer `401` either way. Both right → `UPDATE … SET views = views + 1 RETURNING envelope`; if the new value reaches `max_views`, `DELETE` in the same transaction before commit, still returning the envelope read before the delete.
- **Expiry sweep:** the `worker` role's job already names this ("Scheduled deletion: expired shares…", [ADR 0022](0022-server-mode-only.md) §2, replacing [ADR 0010](0010-server-shape.md) §1's `worker` row, V, both Accepted) — not a new decision, only its concrete mechanism: delete from `share_shares` where `expires_at_ms` has passed, on `worker`'s existing interval, independent of whether anyone ever opens the share again.
- **Token-hash comparison:** reuses the technique of `RecoveryAuthToken::matches_server_hash` (`crates/rizzy-core/src/keys/derive.rs`, `Sha256::digest(..).ct_eq(..)`, V) but cannot call it (`rizzy-domain-share` has no `rizzy-core` dependency, ADR 0016 §3), so it hashes with `sha2` and compares with `subtle::ConstantTimeEq` directly. Both are already workspace dependencies — `subtle = "=2.6.1"` is in root `Cargo.toml` `[workspace.dependencies]` and in ADR 0009's allowed RustCrypto-family table (V, both read) — so `rizzy-domain-share` only adds a `Cargo.toml` edge to an already-approved, already-pinned crate.
- **Rate limiting:** CRYPTO.md §11.11 requires "rate-limited per IP and per share" for a wrong `link_token`. `rizzy-domain-auth/src/ratelimit.rs`'s bucket pattern (hashed key, exponential backoff, V) is `pub(crate)` and tied to `rizzy-domain-auth`; R4 forbids `rizzy-domain-share` depending on it, so `rizzy-domain-share` implements its own copy, keyed by `(share_id, source)` and by `source` alone, over a new `share_rate_limits` table of the same shape, checked and committed before `open`'s lookup (above). Exact `max_attempts`/base/cap numbers are Open question 4.

### On acceptance

None of these edits is made now; the PR that accepts this ADR makes them.

1. **Status lines** (the owner's act, [ADR 0020](0020-partial-supersession.md) point 9): [ADR 0028](0028-api-v1-http-conventions.md)'s line gains a third entry, "; [ADR 0064](0064-share-api-storage-lifecycle.md) (item 1; 'Retry after an unknown outcome' rows 'Reads', 'Upload', 'Set to a value', 'Single use', in part)"; [ADR 0022](0022-server-mode-only.md)'s line (today plain "Accepted") becomes "Partially superseded by [ADR 0064](0064-share-api-storage-lifecycle.md) (§2, table row 'share (M5)', in part)".
2. **[docs/adr/README.md](README.md):** rows 0028, 0022 and 0064 updated to match.
3. **THREAT_MODEL.md §3.4:** gains a row "Share recipient emails (M5) | Stored | Restricts who may open a share; optional ([ADR 0064](0064-share-api-storage-lifecycle.md))".
4. **THREAT_MODEL.md INV-34** reworded from "At expiry, revoke or maximum views, the server deletes the share ciphertext, whether or not anyone visits." to: "At expiry, an owner revoke, the 10th wrong-`access_token` failure (burn) or the view that reaches `max_views`, the server deletes the share row (envelope, token hashes, flags and recipient emails) — in the same transaction as the triggering request, or within one `worker` sweep interval of `expires_at_ms` for an expiry nobody opens — never retained as a flagged-inactive row."; its "Verified by" cell gains "; domain test for revoke, burn and view-exhaustion" next to the existing "Worker test."
5. **CRYPTO.md §11.10 step 5** drops "and revoked flag" from the stored-fields list, matching step 7.

## Consequences

### Positive

- No new cryptographic construction anywhere; every primitive is CRYPTO.md §4.3/§8.4, already written.
- Deleting on every end-of-life keeps the share domain's stored metadata to exactly what CRYPTO.md §11.10 step 5 (corrected) lists, for exactly as long as the share is reachable.
- The API shape (an opaque envelope plus flags, no item assumed) is reusable by ADR 0067's Send without a new endpoint family.
- Reusing `not_found` and `401` keeps item 3's error-code set closed.

### Negative

- `open`'s check-then-write takes the owning account's lock, so a burst of opens against one account's shares briefly serialises against that account's vault writes too (ADR 0011 "one lock per account"); fine at personal-instance scale, the only scale M5 targets.
- Checking the rate limit before the lock does not remove the resource cost of the lookup itself: an anonymous flood of distinct bogus `share_id`s still spends one throttled read per source, which is the rate limit's job to bound, not this ADR's to re-bound.
- A second, share-domain-owned rate-limit implementation duplicates `rizzy-domain-auth`'s bucket logic (R4 forbids sharing it), a small, accepted maintenance cost.
- Hard-deleting on revoke/burn/exhaustion means the owner's `list` cannot show "this share was burned" after the fact — only that it is gone.

### Risks

- If a future domain needs to know a share's history (an audit feature, M9+), the hard-delete design has nothing to show it; the signal is a feature request for share history, which would need its own ADR (a tombstone table, not reviving the `revoked` flag on the live row).
- `cargo xtask check-deps` (ADR 0016 §5) has not been run against this new edge; if it or `cargo deny check` objects for a reason this ADR did not anticipate, the fallback is a local constant-time byte compare (same primitive, no crate), not a weaker one.

## Alternatives considered

- **A `revoked` flag, soft-delete** (CRYPTO.md §11.10 step 5 as literally written). Rejected: INV-34 already requires deletion, and keeping the row only prolongs exposure of ciphertext and recipient emails.
- **`share_id` as a path parameter** (`/shares/<id>/open`, matching CRYPTO.md's "illustrative" path in §11.11). Rejected: CRYPTO.md §11's own text says its paths are "illustrative; the API specification owns them"; a path parameter breaks item 1's literal-path routing and its INV-52 rationale, for a value the body carries just as well.
- **Importing `rizzy-domain-auth`'s rate-limit module.** Rejected by R4 (no domain-to-domain dependency); a `rizzy-bus` event or a shared, non-domain crate could de-duplicate the bucket logic later, out of scope here.
- **Counting failed opens in a generic rate-limit bucket (with its own window reset) instead of a row column.** Rejected: CRYPTO.md's burn must be permanent once 10 failures occur; a bucket that quietly resets after `window_ms` would let the burn be evaded by waiting.

## Open questions for the owner

1. **Table names.** `share_shares` / `share_recipients` / `share_rate_limits`, or different names under the same `share_` prefix? *Recommendation:* keep these; they are unambiguous and `cargo xtask check-tables` only checks the prefix.
2. **INV-34 rewording** (On acceptance item 4). *Recommendation:* yes, in the PR that accepts this ADR, per ADR 0020 point 7.
3. **Acceptance order with ADR 0049.** The `/s/<share_id>` page route needs ADR 0049 (Proposed) Accepted first, or this ADR's endpoints have no recipient page to call them. *Recommendation:* accept 0049 at or before this ADR.
4. **Rate-limit numbers** for the new `share_rate_limits` buckets (max attempts before backoff, base and cap). *Recommendation:* mirror `rizzy-domain-auth`'s `RateRule` defaults for login attempts; tune after real traffic.
5. **A per-account cap on concurrently active shares.** *Recommendation:* none for M5; the per-`(share_id, source)`/`source` rate-limit buckets already bound anonymous `open` spam; revisit if abused.
6. **Does ADR 0048's byte quota count share bytes?** Its scope as cited elsewhere in this batch does not name them, and neither ADR's file exists yet in this repository to check directly (both Proposed, drafted in parallel). *Recommendation:* confirm with ADR 0048 before accepting either, or add share bytes to its scope explicitly; this ADR does not depend on that quota.

## References

- [ROADMAP §4.7](../ROADMAP.md#47-public-sharing-m5)
- [ADR 0011](0011-storage.md) points 4-6, "No plaintext"; [ADR 0022](0022-server-mode-only.md) §2 ("What is stored" `share` row; the `worker`-role row replacing [ADR 0010](0010-server-shape.md) §1); [ADR 0016](0016-workspace-layout.md) §3 `rizzy-domain-share`; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0028](0028-api-v1-http-conventions.md) items 1, 3, 6, 7, "Retry after an unknown outcome"; [ADR 0021](0021-server-compaction.md) §9; ADR 0048, ADR 0049, ADR 0063, ADR 0065, ADR 0066, ADR 0067 (this M5 batch, all Proposed and not present as files in this repository at the reviewed revision — cited by number, not linked; their cross-ADR claims, including ADR 0048's quota scope, are unverified, see Open question 6)
- [CRYPTO.md](../CRYPTO.md) §4.3, §8.3, §8.4, §11.10, §11.11
- [THREAT_MODEL.md](../THREAT_MODEL.md) §7.6, §3.4, Q-20, AR-23, INV-33, INV-34 (reworded on acceptance, above)
- Code and manifests read for this ADR (V): `crates/rizzy-domain-vault/src/lib.rs`; `crates/rizzy-domain-auth/src/{recovery,ratelimit}.rs`; `crates/rizzy-core/src/keys/derive.rs`; `crates/rizzy-storage/migrations/{sqlite,postgres}/{0001_auth_initial,0002_vault_initial}.sql`; `crates/rizzy-server/src/http/api.rs`; root `Cargo.toml` `[workspace.dependencies]`; [ADR 0009](0009-crypto-dependency-policy.md)'s crate table
- [docs/HANDOFF.md](../HANDOFF.md) gap 24 (not this ADR's concern, see Context)

<!-- Blocker check: all seven blockers verified against cited sources (THREAT_MODEL.md §3.4/§7.6/§8.5/§9/§10, ADR 0011, ADR 0020, ADR 0022, ADR 0028, ADR 0031, ADR 0032, CRYPTO.md §11.10/§11.11, recovery.rs) and found accurate; none was wrong, all seven applied above. -->
