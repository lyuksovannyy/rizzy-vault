# ADR 0069: SMTP ingress architecture: own listener vs MTA handoff, and the smtp↔api protocol

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M6

## Context

[ROADMAP §4.8](../ROADMAP.md#48-aliases--email-receiving-m6) (Must) asks for an inbound SMTP receiver, "own SMTP listener, or front with Postfix/Haraka and hand off — receive only." [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation)'s decision table leaves "Mail ingress" to "decide in M6 spike", leaning toward the own-listener route. This ADR makes that call and, unlike ADR 0010, fixes the bytes.

[ADR 0010](0010-server-shape.md) §1 names the `smtp` role (receive-only, no DB, inbound on 2525→25) and already assumes it listens itself, not a front MTA: the role table's "Inbound" column is "port 25 on the host (2525 in the container, §4)" for `smtp` directly. §2 names two internal calls, `resolve` and `deliver`, by behaviour and a bearer secret on an isolated network, but never their wire bytes. §4 allocates a pin-store volume holding, per account, "the pinned identity key and the highest accepted `bundle_seq`", but not the file's layout. [ADR 0016](0016-workspace-layout.md) §3 already plans a `rizzy-smtp-ingress` lib crate (deps: core, proto only) for M6, and its isolation rule R3 forbids that crate from depending on `rizzy-storage`, sqlx, any `rizzy-domain-*` crate or `rizzy-bus`. No code exists yet: `crates/rizzy-server/src/http/mod.rs` builds the public router for `api` and `web` only (V), and there is no `crates/rizzy-smtp-ingress` directory.

[CRYPTO.md §11.13](../CRYPTO.md#1113-mail-ingress-m6) fixes the pin-store's crypto content (TOFU, chain-from-pin verification) and the `MAIL_MESSAGE` plaintext/seal, but not the file's bytes, and names the stored metadata "size bucket" where ADR 0010 §2 said "padded size" — two names for what must be one quantity, and [THREAT_MODEL](../THREAT_MODEL.md) INV-46 and §6.2 use "padded size" too (§4 below resolves all four occurrences). [THREAT_MODEL](../THREAT_MODEL.md) INV-44 fixes the two calls' *existence* and no-DB-credential rule; INV-45 forbids plaintext mail on disk, in logs or in queues; INV-46 bounds what `api` may see to alias id, receive time, size bucket, retention date; INV-47 and INV-65 fix the resolve-reply and RCPT-rate-limit behaviour `smtp` itself must show a sending MTA. [ADR 0028](0028-api-v1-http-conventions.md) fixes `/api/` conventions; it does not reach this internal listener, which is new.

## Decision

### 1. Own listener, not an MTA handoff

`smtp` runs its own minimal, receive-only SMTP listener inside `rizzy-smtp-ingress`, built on tokio (L: version 1.53.1 per ADR 0010's fact sheet, not re-read from `Cargo.toml` for this ADR), not Postfix or Haraka in front. Grammar: HELO/EHLO, MAIL FROM, RCPT TO, DATA, RSET, NOOP, QUIT; no PIPELINING, no CHUNKING/BDAT, no AUTH, no SMTPUTF8 (ASCII addresses only). Opportunistic STARTTLS (open question 1). This is this ADR's own choice, not from RFC 5321 (U: not re-read for this ADR).

The grammar is hand-rolled inside `rizzy-smtp-ingress`, continuously fuzzed, rather than taken from a third-party SMTP-server crate: the accepted surface is seven commands with no relay, queue or AUTH path, which is smaller than what the general-purpose crates available today implement (U: no specific crate surveyed; a crate audit is a fair alternative if the owner wants one before M6 coding starts). MIME parsing uses `mail-parser` (ROADMAP's own choice), a non-crypto dependency reviewed under CONTRIBUTING.md, not ADR 0009. Three new fuzz targets join the existing ones (`fuzz/fuzz_targets/`, V for the directory and its naming convention: `server_config.rs`, `server_headers.rs`, …): `smtp_command` (the line-oriented command parser), `smtp_mime` (the `rizzy-smtp-ingress` wrapper around `mail-parser`, not `mail-parser` internals), `smtp_pin_store` (the §5 file parser below).

### 2. Why own listener wins: INV-45

Postfix and Haraka are built to spool accepted mail to disk before and during delivery; running one as a pure in-memory handoff receiver (as ADR 0010's alternatives note allows "either way") means configuring a mature MTA against its own design to never touch disk, and auditing that it never does, for every release. `rizzy-vault`'s own listener gets to INV-45 ("never writes plaintext mail to disk, logs or queues") by construction: there is no spool because we never wrote one. That is the concrete reason to prefer it over "the role model works either way" (ADR 0010, Alternatives).

### 3. The internal listener

`api` binds a second listener, reachable only on the `ingress` network ([ADR 0010](0010-server-shape.md) §4), distinct from the public listener and from the admin listener. New settings (code follows this ADR, not added now): `RIZZY_INTERNAL_LISTEN` (default `127.0.0.1:8081`, same pattern as `RIZZY_LISTEN`) and `RIZZY_SMTP_SHARED_SECRET_FILE`, read by both `api` and `smtp`. The shared-secret file is **not** `RIZZY_SECRETS_FILE`: ADR 0010 §2's startup refusal names "the secrets file, CRYPTO.md §5.11" specifically, and this is a separate, smaller mount holding one bearer token, so `smtp`'s refusal check still passes. `smtp` sends `Authorization: Bearer <token>`; `api` hashes the presented token (SHA-256) and compares it to a stored hash with `subtle::ConstantTimeEq` (`subtle = "=2.6.1"`, V: `Cargo.toml` `[workspace.dependencies]`, already pinned). That is the generic comparison primitive CRYPTO.md §2 names as `ct_eq`; §5.11 fixes only the SHA-256 storage form ("session tokens are stored as `SHA-256(token)`"), and says nothing about how a comparison is performed, so it is not cited for the comparison itself. The choice fits here because there is exactly one secret to compare against, unlike the session-token lookup (`rizzy-domain-auth::session::load_by_hash`, V: read for this ADR), which matches a presented hash against a DB-indexed set of rows by `WHERE token_hash = ?` rather than comparing bytes in the application.

Adopted from [ADR 0028](0028-api-v1-http-conventions.md), by item number, because nothing else fixes an error shape for this listener: item 3's `{"error":"<code>"}` body and status table (`unauthorized` 401, `invalid_request` 400, `not_found` 404, `rate_limited` 429, `internal` 500), plus `409` for whichever code names a `deliver` rejection once a 409 code exists for it (today none does; the sibling storage-quota ADR 0048's `quota_exceeded`, cited in References below, is the candidate once Accepted — `deliver` does not invent its own code ahead of that); item 7's pattern of a named body-size setting (here, sized to §4 below, not the public 1 MiB/32 MiB tiers); item 9's no-response-compression rule. Not adopted: the `Rizzy-Client` header and `/api/meta` (one binary ships both roles; no client-version skew to negotiate); the device-request signature (`smtp` holds no device key, INV-44); ADR 0033's JSON-vs-protobuf question (moot — both calls are JSON here too).

### 4. Wire types, in `rizzy-proto`

New module, `rizzy-proto::mail`, reusing existing wire primitives ([`wire::Bytes`], [`wire::Id`], [`wire::List`], [`wire::Text`]) and limits (`MAX_BUNDLES`, `MAX_ACCOUNT_STATEMENT_LEN`, `MAX_PLAINTEXT_LEN`). One new limit, from [CRYPTO.md §9.2](../CRYPTO.md#92-hpke-envelope-algorithms-0x10-and-0x12) (V: "Overhead: 66 bytes", stated once for both alg ids 0x10 and 0x12):

```
MAX_MAIL_CIPHERTEXT_LEN = MAX_PLAINTEXT_LEN + 66   // HPKE envelope, MAIL_MESSAGE framed plaintext at its §8.5 ceiling
```

**`resolve`** — `POST /internal/v1/smtp/resolve`:

| Request field | Type | |
|---|---|---|
| `alias_address` | `Text<AliasAddressRule>`, MAX 254 (this ADR's choice, not an RFC limit, U) | lowercased by `smtp` first, mirroring CRYPTO.md §2's login-name normalization |
| `since_bundle_seq` | `Option<u64>` | absent on first contact for this account (no sentinel value; `bundle_seq`'s numbering base is CRYPTO.md §4.4's, not re-verified here) |

| Response field | Type | |
|---|---|---|
| `result` | `"accept"` \| `"reject"` | one handler, one branch, so unknown and disabled aliases share the exact code path (INV-47); only `result` differs |
| `alias_id` | `Id` | present only when `accept` |
| `bundle` | `List<Bytes<MAX_ACCOUNT_STATEMENT_LEN>, MAX_BUNDLES>` | present only when `accept`; signed `public-key-bundle` statements since `since_bundle_seq` |

Rate limiting on `resolve` (ADR 0010 §2's "`api` rate-limits `resolve`, so a compromised `smtp` cannot enumerate aliases quickly") is keyed, as its primary mechanism, by the bearer-secret principal presented on this call — in practice the one `smtp` role for the deployment, identified by the shared secret above, not by any field `resolve` carries. A bucket keyed on the normalized `alias_address` instead would give a compromised or malicious `smtp` a fresh, unthrottled bucket for every new address it tries: it would bound repeated probing of one known alias but would do nothing to slow a walk across the address space, which is exactly the slow enumeration G-11 and AR-21 accept (Q-19) as the residual risk. The per-(account, source) counter rows ADR 0010 §5 specifies, in `rizzy-domain-auth::ratelimit` (file confirmed to exist in the crate, V; its generic `bucket`/`hit` API takes already-known fields, confirmed by reading it for this ADR), do not fit as that primary mechanism either: `account` is exactly what `resolve` has not yet determined when the call arrives, so no account-keyed bucket can run before the lookup it is meant to gate. *Secondary*, and layered on top: a per-`alias_address` bucket (the same `ratelimit` module, a new `BucketKind`) still bounds repeated probing of one address once it is known, which the principal-keyed bucket alone does not. Either bucket tripping answers `rate_limited` (§3); `smtp` maps that to a temporary (4xx) SMTP failure, the same class of answer as `deliver`'s race below. Neither bucket keys on whether `alias_address` exists — both fire on the presented address or the principal alone, before `resolve`'s own accept/reject branch runs — so a rate-limited answer carries no signal about alias existence and INV-47's uniform reply for unknown and disabled aliases is unaffected.

`api` keeps ADR 0010 §2's `deliver(alias_id, ciphertext, padded size)` signature as written — nothing is removed — but never trusts the claimed `padded_size`. Before any arithmetic it checks `ciphertext.len() >= 66 + 256` (the §9.2 overhead plus §8.5's padding floor) and reads `format_version = 0x01` and `alg_id ∈ {0x10, 0x12}` from the envelope header, refusing `invalid_request` on any failure — so the subtraction below never underflows and never runs on an envelope shape §9.2 doesn't cover (including a future PQ algorithm with different overhead, §13). Only then does it recompute `ciphertext.len() - 66` and refuse the request (`invalid_request`) on any mismatch with the claimed `padded_size`, before storing anything.

**`deliver`** — `POST /internal/v1/smtp/deliver`:

| Request field | Type | |
|---|---|---|
| `alias_id` | `Id` | from a prior `accept` |
| `ciphertext` | `Bytes<MAX_MAIL_CIPHERTEXT_LEN>` | HPKE envelope, purpose `MAIL_MESSAGE` |
| `padded_size` | `u32` | the Padmé `padded_len` CRYPTO.md §8.5 defines for the plaintext frame |

The stored value is what CRYPTO.md §11.13 step 4 calls "size bucket"; THREAT_MODEL.md INV-46 and §6.2 both call the same quantity "padded size", as does ADR 0010 §2's `deliver` signature above — one name in CRYPTO.md against three elsewhere (THREAT_MODEL's TB-7 and INV-44 rows also say "padded size" in passing, already matching), for what must be the one quantity `api` derives this way, never one `smtp` asserts. **This ADR adopts "padded size"** as the name; the PR that accepts this ADR corrects CRYPTO.md §11.13 step 4's "size bucket" to "padded size" to match. CRYPTO.md is a design doc, not an ADR, so this is ADR 0020 point 7 ("on a mechanism, an Accepted ADR wins, and the other docs are fixed in the same PR"), not point 9's ADR-to-ADR partial supersession — unlike ADR 0028's open question 5, which leaves a same-kind ADR-wording fix (ADR 0025's) to a later ADR under point 9, conditional on the owner wanting it; this fix is unconditional and lands with this ADR's own acceptance PR. Response: `{"result":"ok"}`, or an error per item 3 above — `not_found` if the alias was disabled between `resolve` and `deliver` (a race within one SMTP session; `smtp` maps it to a temporary (4xx) SMTP failure, not a permanent one, since the sender already got an `accept` at RCPT time).

INV-65's per-source-IP RCPT rate limit and tarpit run inside `rizzy-smtp-ingress` itself, in-process (an in-memory sharded map, reset on restart — acceptable at personal scale, as other in-process state in this codebase is). `smtp` has no DB and no network path to one (INV-44), and the limit must act at RCPT time, before any `resolve` call ever reaches `api` — a round trip to `api` for this counter would also hand the sending IP to a component the threat model never gives it (ADR 0010 §2's `resolve` signature carries no IP field). ADR 0016 R3's dependency ban is the resulting crate-boundary consequence, not the reason.

### 5. The pin-store file

One file per account under the pin-store volume ([ADR 0010](0010-server-shape.md) §4), path `<pin_store_dir>/<account_id as lowercase hex>.pin`, format:

```
u8  format_version = 1
[u8; 32] identity Ed25519 public key
u64 (big-endian) highest accepted bundle_seq
```

41 bytes, fixed length, **plaintext, unsealed and unauthenticated by design**: ADR 0010 §4 is explicit that "the pin store holds no secrets and no DB data, so the §2 startup checks still pass," and sealing or MACing it would put a key inside `smtp`, which is exactly the secret-boundary §4 avoids and the kind of new construction this ADR must not introduce. `smtp` writes it by writing a temp file in the same directory, `fsync`-ing it, renaming it over the final path (atomic on one filesystem), then `fsync`-ing the directory — never in place. A file of the wrong length, bad `format_version`, or absent is treated as "never pinned" (TOFU, as CRYPTO.md §11.13 step 2 already allows for "a wiped pin store"), and the event is logged for the admin so a wipe or corruption is visible, not silent. Concurrent deliveries for one account are serialized by an in-process, per-`account_id` async lock inside `rizzy-smtp-ingress`, so two overlapping messages cannot interleave a read-modify-write of the same pin file.

### 6. Proposed invariants

For the owner to fold into [THREAT_MODEL.md §8.7](../THREAT_MODEL.md#87-mail) on acceptance, allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.

- **Proposed INV-96 (mail-ingress size integrity).** `api` never stores or acts on a client-claimed plaintext or padded size for mail; it always derives the stored size solely from the received ciphertext's length. Extends INV-46.
- **Proposed INV-97 (pin-store fail-safe).** The `smtp` pin-store file is plaintext and unauthenticated; a file that fails its length or `format_version` check is treated as absent (TOFU), never as a cached stale pin, and the event is logged for the admin. Extends INV-44's area without weakening CRYPTO.md §11.13's chain-from-pin check.

## Consequences

### Positive

- `smtp` reaches INV-45 by construction: there is no MTA spool to disable or audit.
- One listener, one process model to operate; no LMTP/milter handoff protocol to design, pin and fuzz on top of the SMTP grammar itself.
- `resolve` and `deliver` get a reviewable, testable wire contract instead of being invented ad hoc when M6 coding starts; both reuse existing `rizzy-proto` limits rather than adding new size tiers.
- The pin-store format is small enough to read, write and corrupt-test exhaustively (41 fixed bytes).

### Negative

- All SMTP-protocol parsing risk sits in our own code and our own fuzz corpus, with no upstream crate to share CVE discovery with.
- `rizzy-proto::mail` lands in the wasm32 client closure with every other `rizzy-proto` type ([ADR 0016](0016-workspace-layout.md) §3), even though no client ever calls `resolve` or `deliver`; this ADR does not design a feature gate for it.
- A second listener and a second shared-secret mount is one more thing for profile-B operators to configure correctly.
- A principal-keyed `resolve` bucket is one bucket for the whole deployment's `smtp` role: a burst of legitimate mail and an enumeration attempt share it, which the secondary per-`alias_address` bucket does not fix either, since it is additive, not a replacement.

### Risks

- A bug in the hand-rolled command parser is a receive-only-SMTP-facing memory-safety or logic bug with no upstream patch to pull; the mitigation is the fuzz targets in §1 and `unsafe`-forbidden Rust, not external review.
- If STARTTLS cert/key handling (open question 1) is deferred past M6 coding start, `smtp` offers no STARTTLS at all until it lands (opportunistic TLS was always the sender's choice either way, THREAT_MODEL §6.1), which the docs must say plainly if it happens.

## Alternatives considered

**Postfix or Haraka as a handoff receiver**, `smtp` only consuming already-filtered mail over LMTP or a milter. Rejected: both spool to disk by default (§2 above), so INV-45 becomes "configure and continuously verify that a general-purpose MTA never spools", not "there is no spool." It would also add a second protocol (LMTP or milter) between the front MTA and `smtp`, on top of SMTP itself, for ADR 0010's isolation rules to cover.

**An existing Rust SMTP-server crate** inside `rizzy-smtp-ingress`. Not chosen here for want of a survey (U): most general-purpose SMTP-server crates carry relay, queueing and AUTH surface this role must refuse, widening the audited surface rather than narrowing it. Left as part of open question 2 rather than decided against with evidence.

**A single shared pin-store file (one row per account) instead of one file per account.** Rejected: one file needs its own internal locking and a parser that must stay correct for every other account while one account's row is corrupt; per-account files make corruption and the TOFU fallback (§5) a property of one account only.

**Keying the `resolve` rate limit on `alias_address` alone.** Rejected as the primary mechanism (§4): it resets with every new address tried, so it bounds probing one alias but not a walk across many. Kept as a secondary bucket layered on the principal-keyed one.

## Open questions for the owner

1. **STARTTLS cert and key for `smtp`.** No reverse proxy fronts port 25 (ADR 0010 §4: `smtp` joins only `ingress` and `mail`, plus its published port), so opportunistic STARTTLS needs a certificate and private key inside the `smtp` container, via rustls (`deny.toml` bans `openssl`). *Recommendation:* an operator-supplied cert/key pair on its own read-only mount (`RIZZY_SMTP_TLS_CERT_FILE`, `RIZZY_SMTP_TLS_KEY_FILE`), no ACME client in `rizzy-vault` (consistent with ADR 0010 owner decision 3). Neither file is the §5.11 secrets file or the §3 shared-secret file above, so none of the existing startup checks are affected either way.
2. **Hand-rolled grammar vs a surveyed SMTP-server crate** (§1 and Alternatives). *Recommendation:* hand-roll for M6, because the accepted grammar is deliberately smaller than what a general-purpose crate offers; revisit only if a fuzzing campaign against the hand-rolled parser turns up a backlog the project can't keep up with.
3. **Operator-configurable message-size cap** (ROADMAP §4.8 "Size limits, attachment limits"), smaller than `MAX_MAIL_CIPHERTEXT_LEN`. Out of scope here. *Recommendation:* a later ADR or, if it needs no wire or format change, a plain `RIZZY_MAIL_MAX_BYTES` setting under CONTRIBUTING.md's no-ADR-needed path, checked in `smtp` before it ever calls `deliver`.
4. **One principal-keyed `resolve` bucket per deployment vs per `api` replica or per `ingress`-network connection.** This ADR keys on the bearer-secret principal, which in profile C is shared across `api` replicas the same way the §5 counter rows already are (ADR 0010 §5). *Recommendation:* keep one deployment-wide bucket; revisit only if profile C measurements show legitimate mail bursts tripping it.

## References

- [ADR 0010](0010-server-shape.md) §1, §2, §4, §5 (role table, internal calls, pin-store volume, rate-limit state) — stays binding in full; this ADR fixes shapes it names but leaves unspecified
- [ADR 0016](0016-workspace-layout.md) §3 (planned `rizzy-smtp-ingress` crate), R3 (isolation), R5 (who depends on domain crates)
- [ADR 0020](0020-partial-supersession.md) point 7 (mechanism vs. the other docs, invoked for the "padded size"/"size bucket" fix above, since CRYPTO.md is a design doc, not an ADR); point 9 — not otherwise invoked: this ADR supersedes no named part of any Accepted ADR, and it is not the ADR-to-ADR case ADR 0028's open question 5 defers
- [ADR 0028](0028-api-v1-http-conventions.md) items 3, 7, 9
- [ADR 0033](0033-protobuf-api-encoding.md) (JSON only for M1, recommendation unchanged here)
- [CRYPTO.md](../CRYPTO.md) §2 (`ct_eq`, the comparison primitive §3 uses), §8.5 (framing and padding), §9.2 (HPKE overhead, V), §11.13 (mail ingress flow; step 4's wording corrected to "padded size" on acceptance), §5.11 (token storage form only — not the comparison)
- [THREAT_MODEL.md](../THREAT_MODEL.md) G-11, INV-44, INV-45, INV-46, INV-47, INV-65, TB-7, AR-21, Q-18, Q-19, §6.2
- [ROADMAP.md](../ROADMAP.md) §4.8, §5 ("Mail ingress" row)
- ADR 0068 (this batch): alias identity model and no-enumeration lookup — owns `alias_address` semantics; this ADR only fixes `resolve`'s wire bytes
- ADR 0070 (this batch): `mail-auth` crate approval under ADR 0009 — not run here; this ADR treats SPF/DKIM/DMARC verification as internal to step 1 of `smtp`'s pipeline, already described in THREAT_MODEL §6.1
- ADR 0048 (this batch): per-account storage quota and its wire error code — a `deliver` rejection for over-quota reuses that code once accepted; not defined here
- `crates/rizzy-proto/src/{wire.rs,limits.rs}`, `crates/rizzy-server/src/{config.rs,http/mod.rs}` (read 2026-10-11, V): confirm the wire primitives, existing limits, settings list and public-router scope this ADR builds on
- `crates/rizzy-domain-auth/src/{ratelimit.rs,session.rs}` (read 2026-10-11, V): confirm `ratelimit`'s bucket/hit API and that `session::load_by_hash` compares by DB lookup (`WHERE token_hash = ?`), not an application-level `ct_eq`, for the §3 citation fix above
