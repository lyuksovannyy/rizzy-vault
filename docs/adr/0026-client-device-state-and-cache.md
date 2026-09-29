# ADR 0026: Client device state and encrypted local cache

- Status: Proposed
- Date: 2026-09-29
- Deciders: project owner
- Milestone: M1 (`rv`) / M2 (extension, IndexedDB) / M3 (`rizzy-ffi`, `E_ks`)

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1) makes "Offline read access on clients (encrypted local cache)" an M1 Must. The local cache and the device-state record are persistent formats, so they need an Accepted ADR ([ADR 0020](0020-partial-supersession.md), docs/adr/README.md "The ADR-first rule"). None exists, so `rizzy-client` keeps `DeviceState` and `VaultSync` in memory only, and `rv` cannot stay enrolled between runs (V: `crates/rizzy-client/src/lib.rs` "Cache policy", `device.rs` "Not a persistent format", at 3087233).

What binds (Accepted):
- [ADR 0011](0011-storage.md) "Clients": clients persist "only ciphertext: the same envelopes, plus their local wraps", through a storage interface that `rizzy-client` defines; SQLite through sqlx (`sqlite` driver only) on CLI, desktop and mobile; IndexedDB in the extension; nothing in the web vault.
- [ADR 0019](0019-native-clients.md) §3, §5: the cache "exists once, in Rust"; sqlx sits in the binding leaves (`rizzy-ffi`, `rizzy-ffi-cpp`), and `rizzy-cli` from M1 ([ADR 0016](0016-workspace-layout.md) R5 as §1.4 restates it). `rizzy-client` stays no-I/O (R1).
- [ADR 0013](0013-shared-client-core.md) §3 rule 2: "the device state record goes out as opaque bytes for the host to persist". It holds the Secret Key unwrapped until an OS keystore is used ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)).
- [CRYPTO.md](../CRYPTO.md) §5.6 (what offline unlock reads), §11 "Secrets before commit" step 3 (the pending record), §11.3 step 4 (`E_local` ctx epochs stored next to it; grants acknowledged only after persisting), §9.6 (raw bytes in the client cache).
- [ADR 0012](0012-sync-engine.md) §7 "Freshness": clients persist the highest VV they accepted per item and the last verified `account-state` (INV-25). [ADR 0018](0018-item-record-encoding.md) §5: the record rules run on "a load from the local store" too; §10 "Newest snapshot": keep each item's ops since its newest snapshot.
- [THREAT_MODEL](../THREAT_MODEL.md): AST-19 and A8 (stolen device or backup), INV-61 (backup exclusion), INV-63 (extension: only wrapped state persisted), INV-56 and INV-60 (`rv`).

Forces: no new cryptography and no new crypto crate ([ADR 0009](0009-crypto-dependency-policy.md)); the file is read back as untrusted input; a crash must never make a device reuse a `device_seq` it may have sent (two different ops with one dot is equivocation that other replicas report).

## Decision

### 1. What is persisted, and what never is

| Persisted | Form |
|---|---|
| Device-state record (§2): stage, origin, ids, kind, SK, `device_salt`, `kdf_id`, `E_dev`, `E_local` (if present) with its ctx epochs, the pending record | one opaque byte string |
| Account objects: bundles, the newest verified `account-state` wire form, `ACCOUNT_SETTINGS`, device certificates and revocations, `E_id`, alarm evidence | signed or enveloped bytes as served |
| Per vault: `VAULT_KEY_SELF_GRANT`, the wrap set (`ITEM_KEY_WRAP` rows), `wraps_after_epoch`, the last restore generation | as served |
| Every accepted op statement (header kept forever); op bodies since each item's newest snapshot; the newest snapshot record(s) per item and every tombstone | as served |
| Own records: signed ops not yet acknowledged, own snapshots not yet uploaded, each with the restore generation of its first send ([ADR 0021](0021-server-compaction.md) §2) | as built |
| Device counters: next `device_seq`, the HLC | integers |

**Never persisted** in M1: any decrypted value, the merge state (`ItemMerge`), decrypted op data, any unwrapped key, the password, `pw_in`, unlock keys, the recovery code, bearer tokens, `session_id`s and request counters. The merge state is rebuilt at each unlock (§4). Sessions live in memory; each process run device-authenticates again ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication)), so no counter can repeat across runs. So the cache holds what the server holds ([THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode)), plus the device-only wraps and the SK that §4.2 already places there, plus own records the server will see.

**No extra encryption layer in M1.** Every sensitive byte is already an envelope under a vault, item or account key, or a wrap under `local_unlock_key`. `LOCAL_CACHE_INDEX` (0x0090) stays reserved for the M3 local index ([CRYPTO.md §4.3](../CRYPTO.md#43-derivations)); anything derived from plaintext that a later milestone persists (search index, "recently used") goes under it, by that milestone's ADR.

### 2. Device-state record (record version 1)

Notation of [CRYPTO.md §2](../CRYPTO.md#2-conventions):

```text
device_state = u16(record_version = 1) ‖ u8(stage: 1 committed | 2 signup-pending)
             ‖ str(server_origin) ‖ account_id (16) ‖ device_id (16) ‖ u8(device_kind: 1–3)
             ‖ secret_key (16) ‖ device_salt (16) ‖ u16(kdf_id) ‖ bytes(E_dev)
             ‖ u8(has_local: 0 | 1) ‖ [u32(local_account_key_epoch) ‖ u32(local_password_epoch) ‖ bytes(E_local)]
             ‖ u8(pending: 0 | 1) ‖ [pending]
pending      = secret_key' (16) ‖ device_salt' (16) ‖ u16(kdf_id') ‖ u32(account_key_epoch')
             ‖ u32(password_epoch') ‖ bytes(E_local') ‖ bytes(E_dev' or empty)
```

- **Parsing.** Total length ≤ `MAX_DEVICE_STATE_LEN` = 4096 bytes, checked first; `server_origin` through the one parser of §2; `device_kind` 1–3; each `kdf_id` on the client allow-list; each envelope ≤ 256 bytes (`MAX_KEY_ENVELOPE_LEN`) and parsed by `rizzy_core::envelope::parse`; no trailing byte; a `stage` or flag outside its values is refused; `stage = 2` requires `has_local = 1` and `pending = 0`. One state has one encoding.
- **Without `E_local`** (`has_local = 0`): the state of CRYPTO.md §11.3 step 5 after "lock and delete `E_local` and `E_ks`". It cannot unlock; the only path it offers is §11.3 step 5 "I changed my password on another device". The cache stays.
- **Signup pending** (`stage = 2`, §11.1 step 7): the base fields are the ones signup is about to register; `pending_commit` (§3) holds the byte-identical `RegisterFinishRequest`. On restart the client resends it; the server treats a byte-identical repeat as success (§11.1 step 8), and the answer finalises the record to `stage = 1` (§11.1 step 9). Nothing else runs in stage 2.
- **Pending record** (§11 step 3): the new SK, the new account key as `E_local'` under the post-commit password, and `E_dev'` when the account key rotates. The commit request itself is stored beside it (§3, `pending_commit`) so a restart resends identical bytes. The recovery code is never stored.
- **Not in v1:** `E_ks` and `ACCOUNT_KEY_FORWARD` (M3/M7). They arrive as record version 2 with a v1→v2 upgrade in `rizzy-client`.
- **Where it lives.** The bytes go to the host (ADR 0013 rule 2). `rv` stores them in its cache database (§3, table `device_state`); the OS keyring stays allowed by ADR 0013 §2 without a format change. The extension stores the same bytes in IndexedDB (INV-63).

### 3. Cache schema (cache format 1)

One SQLite file per account, `<hex(account_id)>.sqlite3`, in the platform's local, non-roaming data directory (`rv`: `$XDG_DATA_HOME/rizzy-vault/`, or the platform equivalent), directory 0700, file 0600, excluded from backups where the OS allows and documented for `rv` (INV-61). Every integer that is a `u64` in [CRYPTO.md §2](../CRYPTO.md#2-conventions) is stored as its 8-byte big-endian `BLOB`, so bytewise order is numeric order; ids are 16-byte `BLOB`s.

```sql
cache_meta(k TEXT PRIMARY KEY, v BLOB NOT NULL)         -- format, server_origin, account_id, device_id,
                                                         -- next_device_seq, hlc
device_state(id INTEGER PRIMARY KEY CHECK (id = 1), record BLOB NOT NULL)
pending_commit(id INTEGER PRIMARY KEY CHECK (id = 1), request BLOB NOT NULL)
account_objects(kind INTEGER, key BLOB, bytes BLOB NOT NULL, PRIMARY KEY (kind, key))
vaults(vault_id BLOB PRIMARY KEY, self_grant BLOB NOT NULL, wraps_after_epoch INTEGER,
       restore_generation BLOB)
wraps(vault_id BLOB, item_id BLOB, item_key_id BLOB, vault_key_epoch INTEGER, envelope BLOB NOT NULL,
      PRIMARY KEY (vault_id, item_id, item_key_id))
ops(vault_id BLOB, device_id BLOB, device_seq BLOB, item_id BLOB NOT NULL, statement BLOB NOT NULL,
    body BLOB, key_wrap BLOB, own INTEGER NOT NULL, sent_generation BLOB,
    PRIMARY KEY (vault_id, device_id, device_seq))
snapshots(vault_id BLOB, snapshot_id BLOB, item_id BLOB NOT NULL, statement BLOB NOT NULL,
          envelope BLOB NOT NULL, key_wrap BLOB, own INTEGER NOT NULL, sent_generation BLOB,
          PRIMARY KEY (vault_id, snapshot_id))
```

- `account_objects.kind`: 1 bundle (key `u64 bundle_seq`), 2 `account-state` (key empty; the newest verified only), 3 `ACCOUNT_SETTINGS` (key `u64 settings_seq`), 4 device certificate (key `device_id`), 5 device revocation (key `device_id`), 6 `E_id` (key `u32 identity_epoch`), 7 alarm (key `u8 kind`: 1 rollback, 2 fork, 3 unconfirmed identity change; bytes: the conflicting signed statements). `own`: 0 served, 1 own and never sent, 3 own, sent and unanswered, 2 own and acknowledged. `sent_generation` (16 bytes) is set on own rows only, from 1 to 3, in the transaction that records the first send: the restore generation of the last response before it (ADR 0021 §2). It is never changed by a resend; a crash between that write and the send counts as sent, the conservative side.
- `pending_commit.request` is the exact JSON body to send: a `CommitChangeRequest`, or a `RegisterFinishRequest` in stage 2 (§2). It is ≤ `MAX_UPLOAD_BODY_LEN` = 256 MiB, the largest `RIZZY_MAX_UPLOAD_BYTES` [ADR 0028](0028-api-v1-http-conventions.md) item 7 allows, one constant in `rizzy-proto` limits for both ADRs; it is parsed back only through `rizzy-proto` (fuzzed by `proto_json`).
- **Columns are indexes, never facts.** Every row is parsed and verified on load as if it were a Fetch answer; a column that disagrees with the parsed statement (ids, `device_seq`, key id, epoch) refuses the row and the load. Each blob is length-checked against its `rizzy-proto` limit before it is parsed.
- **Settings:** `journal_mode=DELETE`, `synchronous=FULL`, `secure_delete=ON` (best-effort hygiene only: the rollback journal, SSD remapping, copy-on-write filesystems and snapshots can keep old pages, such as an old `E_local`; nothing relies on it, see Risks), `foreign_keys=ON`, writes in `BEGIN IMMEDIATE`, `busy_timeout` 5 s; a second `rv` on the same account fails with "in use".
- **IndexedDB (M2)** holds the same logical stores, keyed identically, with the same blobs. The web vault keeps no cache; it persists only the opt-in Secret Key of CRYPTO.md §11.4 (ADR 0011 "Clients"), which this ADR does not define.

### 4. Write order and load

1. An own op or snapshot is written (`own = 1`, `next_device_seq` advanced) in one transaction; it moves to `own = 3` with its `sent_generation` in a transaction committed **before** the upload request that carries it is handed to the host. `next_device_seq` = max(stored, highest own `device_seq` held, own head in the last Fetch) + 1; it never decreases.
2. A Fetch or upload answer is applied in memory, then persisted in one transaction (records, heads, `wraps_after_epoch`, restore generation, pin, pruning of bodies ADR 0018 §10 no longer needs) before the next request is released.
3. A pending record and `pending_commit` are written before the commit is sent, and removed in the transaction that finalises it (§11 step 5). Grants are acknowledged only after the re-wrapped objects are written (§11.3 step 4.5).
4. An alarm is written in the transaction that detects it and cleared only by the flow that resolves it, so a restart never lifts read-only mode.
5. **Load** (after the offline unlock; a state with `has_local = 0` or `stage = 2` does not unlock, §2): parse the device state, open `E_local` and `E_dev`, then verify every account object and every record through the same code as a Fetch (signatures, headers, wraps, envelopes, ADR 0018 §5 rules) and rebuild the logs and merges. The persisted VV is the verified headers' VV (ADR 0012 §7 "Freshness").

`rizzy-client` owns all of this: a module `store` with the record codec, the row model, the schema and migrations as SQL text constants, and the changeset each step returns. The leaves run it with sqlx (`rv` in M1, `rizzy-ffi` in M3); IndexedDB goes through `rizzy-wasm`.

### 5. Versioning and migration

- `cache_meta.format` = `u16` 1. Migrations are ordered SQL steps in `rizzy-client`, each run in one transaction with the format bump (SQLite DDL is transactional), so no plaintext-bearing copy is made. A format or record version newer than the build knows is refused: "update required", read nothing, write nothing (ADR 0002 point 5).
- A cache that fails to load is never dropped silently: dropping it resets rollback detection (INV-25). There is **no "reset local data" that keeps the enrolment**: it would lose the alarms, the pinned identity and account-state, the VV floors and the `device_seq` counter, so a server could lift read-only mode (§4 step 4, INV-25, CRYPTO.md §11.3 step 3) or make the device sign a used dot. The only recovery is "remove this device": the client uploads nothing more, and the file is deleted; the next use is a new enrolment (CRYPTO.md §11.2) with a new `device_id`, so no dot can repeat, and the old `device_id` is revoked from another device. While an alarm is active the app refuses removal and names the alarm; a file deleted by hand is a new device with the first-Fetch trust every new device has.

### 6. Tests and fuzzing

- Known-answer vector of a device-state record; round-trip property tests of the record and every row codec; a canonical-form test.
- Fuzz targets `client_device_state` (the record parser) and `client_cache_load` (the loader over arbitrary rows, including column/statement mismatches).
- Known-answer vectors also for `has_local = 0` and `stage = 2`; `client_cache_load` covers `own` and `sent_generation` mismatches.
- Crash injection: fail after each write of §4 steps 1–3 and of signup (§2), reload, and assert no `device_seq` is reused, every sent own row keeps its first `sent_generation`, and no commit or `register/finish` is resent differently.

## Consequences

### Positive

- `rv` stays enrolled and reads offline; one format serves CLI, extension and native apps.
- A stolen cache yields what AST-19 already lists and nothing more: no decrypted state is on disk.
- Reloading through the Fetch verifier means a tampered file is detected like a malicious server.

### Negative

- Every unlock decrypts and re-merges the vault; for thousands of items this is seconds of CPU (U, unmeasured).
- Server-visible metadata (item ids, HLC times, device ids) is in cleartext on the device, as on the server.
- Two sqlx executors (`rv`, `rizzy-ffi`) run the same schema; they are thin but duplicated.

### Risks

- Deleting a row does not erase it from the medium (journal, SSD, snapshots, backups that ignored the exclusion). An old `E_local` may survive a password change and open with the old password. The recourse after a suspected old-password leak is a rotation (CRYPTO.md §11.6), not local deletion.
- A device whose cache stops loading must be removed and enrolled again (§5), which costs a new device and a revocation.
- If load time becomes a problem (signal: M3 measurements above 1 s on a 5,000-item vault), persisting merge state needs a new ADR, under `LOCAL_CACHE_INDEX` or a new purpose in CRYPTO.md.

## Alternatives considered

- **Persist the merge state under `LOCAL_CACHE_INDEX` now.** Faster unlock, but that purpose's ctx (`account_id ‖ device_id`) binds no row, so one sealed blob could replace another; fixing that is a CRYPTO.md change. Deferred.
- **Whole-file encryption (SQLCipher).** A new cryptographic dependency (ADR 0009) and a second SQLite build next to sqlx's; it hides only metadata the server already holds.
- **serde (JSON, CBOR) for the device-state record.** Rejected for the reason of CRYPTO.md §2 "Canonical encoding": a format must not drift with a crate update.
- **Persist bearer tokens** (the threat model's CLI row permits a 0600 file). Rejected for M1: device authentication costs one round trip and leaves no token or counter on disk.

## Open questions for the owner

1. **Shared executor.** Keep the sqlx code in each leaf, or add a small `rizzy-client-sqlite` crate (an ADR 0016 change)? Recommendation: in each leaf for M1; revisit in M3 when `rizzy-ffi` arrives.
2. **A narrower reset.** Keep `device_state`, `cache_meta`, `account_objects`, every op and snapshot statement and own row, and drop only bodies, envelopes and wraps for re-download? Recommendation: not in M1; add it only if M3 shows load failures that removal handles badly, since every kept part must itself still verify.
3. **Trashed-item bodies.** Keep ops of trashed items like any other? Recommendation: yes; retention is ADR 0012 §5's.
4. **`rv` data directory.** `$XDG_DATA_HOME` on Linux, `~/Library/Application Support` on macOS, `%LOCALAPPDATA%` on Windows, overridable by `RIZZY_CLI_DATA_DIR`? Recommendation: yes.

## References

- [CRYPTO.md](../CRYPTO.md) §2, §4.2, §4.3, §5.6, §5.10, §8.4, §9.6, §11, §11.1, §11.2, §11.3, §11.4, §11.6; [THREAT_MODEL.md](../THREAT_MODEL.md) §3.4, AST-19, A8, INV-25, INV-56, INV-60, INV-61, INV-63; [ROADMAP.md](../ROADMAP.md) §4.2.
- [ADR 0002](0002-own-protocol.md), [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md) §7, [ADR 0013](0013-shared-client-core.md) §2–§3, [ADR 0016](0016-workspace-layout.md), [ADR 0018](0018-item-record-encoding.md) §5, §10, [ADR 0019](0019-native-clients.md) §3, §5, [ADR 0021](0021-server-compaction.md) §2, [ADR 0025](0025-rotation-vault-half.md), [ADR 0028](0028-api-v1-http-conventions.md) item 7.
- Code (V, 3087233): `crates/rizzy-client/src/{lib,device,account,sync}.rs`; `crates/rizzy-proto/src/{limits,vault}.rs`.
- SQLite `secure_delete` and transactional DDL: SQLite documentation (L, not re-read for this ADR).
