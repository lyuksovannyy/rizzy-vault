# ADR 0096: Secrets that cross the client binding (ADR 0013 §3 rule 2, restated in full), and KeePass KDBX import inside the web vault's one core Worker

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M1 (transport credentials, the second-factor code, the invite token, the 2FA enrolment secret, import files) / M2 (a new passkey's private key) / M3 (KDBX import, the breach-check candidate, the local unlock secret) / M5 (shares)
- Supersedes: on acceptance, in part: [ADR 0013](0013-shared-client-core.md) (§3 rule 2); [ADR 0019](0019-native-clients.md) (§3 in part: the bullet "**Secrets cross as bytes.**"); [ADR 0029](0029-kdbx-import.md) (point 4 in part). §3 names the exact parts and gives their replacement text ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** On 2026-10-25, after the ten-reviewer ADR gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)), the owner said "start": begin fixing the gaps. This ADR fixes themes **C10** (finding **G01-20**, [raw/G01.md](../reviews/2026-10-25-raw/G01.md)) and **C9** (finding **G04-5**, [raw/G04.md](../reviews/2026-10-25-raw/G04.md)).

### C10: rule 2's closed list is not what crosses

[ADR 0013](0013-shared-client-core.md) §3 rule 2 (Accepted) opens "**Named exceptions, and only these:**" and closes "Adding an exception changes this ADR." Its sub-bullets, as in force ([ADR 0022](0022-server-mode-only.md) removed the pairing-QR one), are: the master password in; the Secret Key and recovery code out once for the Emergency Kit; the Secret Key in on a new device; the recovery code in; the export password in; the device state record out; the local unlock secret out to the keystore; share secrets and the share passphrase; the extension's `storage.session` snapshot; an explicit plaintext export. [ADR 0019](0019-native-clients.md) §3 (Accepted) keeps the list and adds "**Secrets cross as bytes.** Every named exception of rule 2 (…) crosses as a byte array, never as a string".

But §2 of the same ADR keeps transport in the host ("The state machine returns effects: HTTP requests to send"), so every credential an HTTP request carries must leave Rust. What the code passes across the binding today and the list does not name (V, `crates/rizzy-wasm`, `packages/core` and `apps/web` at `262bbd0`):

| Crossing | Direction, form | Code |
|---|---|---|
| The session bearer token, as the `Authorization` value | out, string, every session request (also the old token in the sign-out after a refresh) | `crates/rizzy-wasm/src/http.rs:65–81`, `:124` ("A secret: never log"), `:167–224`; `device.rs:805–808`, `:1486`; `session.rs:1670–1683`; `packages/core/src/index.ts:239–258` |
| The `device-request` signature and counter | out, string, every device-session request | `http.rs:78–81`, `:141–146`; `device.rs:783–811` |
| The 2FA enrolment secret (`otpauth://` URI and Base32) | out, strings, once per enrolment | `session.rs:1686–1714`, `:2498–2527`; `packages/core/src/index.ts:2233`; `apps/web/src/views/TwoFactorPane.tsx:19–74` |
| The second-factor TOTP code | in, string | `device.rs:274`, `login.rs:267`, `session.rs:1740` |
| The invite token | in, string | `signup.rs:149–176`; `crates/rizzy-proto/src/auth.rs:41–42` ("a secret") |
| A candidate password for the breach check | in, bytes | `breach.rs:72` |
| A new passkey's private key (32 bytes) | out, bytes, once | `passkey.rs:9–19`, `:90–94`; `packages/core/src/index.ts:692–704` ("this module zeroes neither") |
| An import file (another product's plaintext export, or ours) | in, bytes, not zeroed by the binding or by `packages/core` | `session.rs:1377–1410`; `packages/core/src/index.ts:2026–2028` |

`crates/rizzy-wasm/src/lib.rs:45–58` ("Rules of the boundary") already documents the bearer token as "the transport's credential, ADR 0028 item 4, not a key of rule 1" and the passkey key as crossing "once" — a crate-level reading, not binding text. From M3 the KeePass KDBX password and key file must go in too ([ADR 0029](0029-kdbx-import.md) point 4). [CLAUDE.md](../../CLAUDE.md) counts tokens as secrets ("Never log secrets … tokens"). So an implementer who follows rule 2 cannot build §2, and one who follows the code has no rule for the lifetime, storage or logging of what crosses. [THREAT_MODEL](../THREAT_MODEL.md) TB-10 calls the binding an audit boundary, so this list is what the audit checks.

What the code already does for typed secrets (V): the binding takes a `&mut [u8]`, copies it into a `Zeroizing` string and zeroes the slice (`crates/rizzy-wasm/src/secret.rs:1–40`); `packages/core` zeroes its arrays in a `finally` (`withSecrets`, `packages/core/src/index.ts:179–190`); the web UI transfers byte-array arguments to the core Worker, "so the UI keeps no copy of them" (`apps/web/src/core-client.ts:5–7`, `apps/web/src/protocol.ts:8–10`); the core Worker does the HTTP transport itself (`apps/web/src/core-worker.ts:3–6`), so the token never reaches the UI thread; requests use `redirect: "error"`, `credentials: "omit"`, `cache: "no-store"` (`http.rs:23–25`). JavaScript strings cannot be wiped ([CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene), "JavaScript strings"); a `fetch` header value is a string.

### C9: KDBX cancellation against one core Worker

[ADR 0029](0029-kdbx-import.md) point 4 (Accepted): "**Argon2 cannot be cancelled** (one blocking call in `argon2` 0.6.0): the caller runs `import` where it can be killed, a Web Worker in the browser and a worker thread or process natively, and the product cap of point 5 bounds the wait." [ADR 0013](0013-shared-client-core.md) §4: "**Web vault:** one dedicated Worker holds the whole `rizzy-client` instance and every handle, and runs the KDF", and "the core is never split across contexts". The web vault creates exactly one Worker and never terminates it (V: `apps/web/src/main.tsx:19` is the only `new Worker`; no `terminate` in `apps/web/src`), and runs every import inside it (`apps/web/src/core-worker.ts:410–419`). ADR 0029 point 5 itself speaks of "a trap of the wasm instance that holds the unlocked vault", and its Negative consequences leave "whether to import in an instance it then discards" to "ADR 0013's concern, not decided here". So one implementer kills the vault Worker to cancel (and loses the session), another spawns a second instance and passes plaintext between them, which ADR 0013 rules out.

Facts that decide it:
- `argon2` 0.6.0 has no incremental API: `hash_password_into`, `hash_password_into_with_memory` and `fill_memory` each run the whole computation (V: `argon2-0.6.0/src/lib.rs:285–341`). Splitting it would be our own Argon2, which CLAUDE.md forbids.
- A Worker runs one task at a time: while a synchronous wasm call runs, it receives no message, so a `keep_going` callback inside that call cannot see a "cancel" posted by the UI thread (L: the HTML event-loop model). Observing one would need a `SharedArrayBuffer` and `Atomics`, which need cross-origin isolation; the server sends no `Cross-Origin-Opener-Policy` or `Cross-Origin-Embedder-Policy` header (V: no match in `crates/rizzy-server/src`), and even then Argon2 itself cannot stop.
- The wasm caps of ADR 0029 point 5 bound the Argon2 run: memory ≤ 256 MiB and memory × iterations ≤ 4 GiB-passes. ADR 0013's measurement (Argon2id, 64 MiB, t = 3, about 309 ms in wasm on the M0 machine) is about 0.6 GiB-passes per second, so the cap is about 7 s there (L: arithmetic from that one measurement; Argon2d and slower devices not measured). AES-KDF on wasm at its 100,000,000-round cap is not measured (U, ADR 0029 Negative).
- No KDBX code exists yet: `rizzy-import` refuses a KDBX file (`ImportError::KdbxNotSupported`, `crates/rizzy-import/src/error.rs:33–35`). The extension has no import at all (V: no `importFile` in `apps/extension/src`).

## Decision

### 1. Which secrets cross the binding, and how

ADR 0013 §3 rule 2 is restated in full (§3 part A). It is a closed list: a secret crosses a binding (`rizzy-wasm`, `rizzy-ffi`, `rizzy-ffi-cpp`) only as one of its 21 entries, in the direction, form and lifetime the entry gives, and every host handles it by the common rules (a)–(f). Rule 3 still governs item plaintext (list summaries, revealed values, fill values, item TOTP codes, generated passwords and passphrases, password history, attachment bytes); those are not entries of rule 2. Values that are not secrets (signed statements, ciphertext, public keys, WebAuthn assertions) are not entries either. Each entry's code reference is in Context. Entry 20 is the text of [ADR 0111](0111-extension-session-and-idle-lock.md) §6 B, so this ADR depends on ADR 0111 (Proposed), which is to be accepted before it (owner answer of 2026-10-25).

Two forms exist. **Bytes**: a byte array (`Uint8Array`, `Data`, `ByteArray`, `byte[]`, `std::span<uint8_t>`) that the binding wipes when it takes it and the host wipes after the call (ADR 0019 §3, restated in §3 part B). **String**: allowed only for the entries marked so, because the platform API that consumes the value takes a string (a `fetch` or HTTP-stack header, a text field, a QR encoder); the host bounds its lifetime instead, since a string cannot be wiped.

### 2. The KDBX import runs in the core context that holds the vault

Decided in §3 part C:
- **One core context.** `kdbx::probe` and `kdbx::import` run where the unlocked vault is: in the web vault, the one core Worker of ADR 0013 §4. No second wasm instance is created for an import, and no Worker is terminated to cancel one. Nothing an import produces crosses `postMessage` except the counts-only report (INV-48).
- **The cancel point is before the cost.** The web vault calls `probe`, shows its `KdbxCost` (version, KDF, AES-KDF rounds or Argon2 memory, iterations and parallelism), and asks the user to confirm before it asks for the KDBX password. After the confirmation, `import` runs to its end: the web vault's `keep_going` always returns `true`. The wasm caps of ADR 0029 point 5 bound the run.
- **Lock during an import.** A `lock` that arrives while `import` runs is handled when the call returns, like any call queued behind a long one (`apps/web/src/core-worker.ts:8–13`); the UI thread hides every vault view at once when the user locks or the auto-lock fires, without waiting for the Worker.
- **Native hosts** run `import` on a worker thread and get a real cancel through `keep_going` at defined points; an Argon2 call already running completes.
- **A new error kind**, `ImportError::KdbxCancelled`, is returned when `keep_going` returns `false`. It is returned before any item exists, so nothing is written. `rizzy-ffi` maps it to the binding code `import_cancelled`; `rizzy-wasm` never returns it (its `keep_going` never refuses).
- **Memory.** The vault instance keeps the import's peak (ADR 0029 point 5: the input, then two payload buffers of at most 128 MiB, or 256 MiB of Argon2 blocks on wasm32, wiped and dropped) as grown linear memory until the page is reloaded. This is accepted: the pages are wiped, and a discarded instance would cost the session or a second instance (Alternatives).

### 3. What this ADR supersedes

Three parts, each replaced in full by the text after it. Nothing else in ADRs 0013, 0019 and 0029 changes. None of these parts is named by an earlier Accepted supersession other than the one ADR 0022 sub-bullet the replacement already leaves out (V: ADR 0019 §1.2's table carries rule 2 forward unchanged; ADR 0022 §1 names only its pairing-QR sub-bullet). With every supersession in force, the replaced share of ADR 0013's Decision stays below half (about 700 of 1,738 words, counted with `wc -w`; ADR 0020 point 9 "Limit").

**A. ADR 0013 §3 rule 2, in full** (from "2. **Named exceptions, and only these:**" to "Adding an exception changes this ADR."). Replaced by:

> 2. **Named exceptions, and only these.** A secret crosses a binding only as one of the entries below, in the direction, form and lifetime the entry gives. Every host handles every entry by these rules:
>    - (a) **Never logged or reported:** not in console output, log files, error messages, crash, telemetry or analytics reports, or any `toString`/`Debug`-like output the host defines. An error that concerns a secret names the entry, never its value.
>    - (b) **Never persisted,** except where the entry says so.
>    - (c) **Never in a URL,** a query string, a cookie or browser history; the one exception is the share secret in a share URL's fragment (entry 8, entry 15).
>    - (d) **Kept in the context that needs it.** A typed secret goes once from the UI to the context that holds the core (the web vault's core Worker; the extension's long-lived context; on a native client the same process). In the web vault it goes as a byte array whose buffer is transferred, so no copy stays behind; where the channel cannot transfer (the extension's JSON-based runtime messaging), the sender keeps no reference after sending. A transport credential (entries 17 and 18) never leaves the context that sends the request.
>    - (e) **Bytes** entries cross as a byte array, never as a string: going in, the binding wipes the array it was given when it takes the value, and the host wipes its own array after the call, on success and on error; going out, the host wipes the array as soon as it has used it (rendered, written, passed on). **String** entries keep no host reference after the entry's lifetime, are copied into no longer-lived state (an application store, a cache, a history), and are left to the garbage collector, since a string cannot be wiped.
>    - (f) The Rust copy of every entry is a zeroizing type with a redacted `Debug`.
>
>    **In, as bytes:**
>    1. The master password (M1), typed into host UI: at signup, login, unlock, a password change (the current and the new one) and the re-authentication before a plaintext export; for one call.
>    2. The Secret Key (M1), typed on a new device; for one call.
>    3. The recovery code (M1), for recovery ([CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit)) and when the user keeps the current code during a rotation ([§11.6](../CRYPTO.md#116-key-rotation)); for one call.
>    4. The export password (M1), for an encrypted export and its import ([§11.14](../CRYPTO.md#1114-encrypted-export-m1)), and for the encrypted CXF export and its import ([ADR 0074](0074-passkey-cxf-import-export.md)); for one call.
>    5. A candidate password for the breach check (M3, [§11.16](../CRYPTO.md#1116-breach-check-hibp-k-anonymity-m3)); for one call.
>    6. The KeePass KDBX password and key file (M3, [ADR 0029](0029-kdbx-import.md)): the password as the UTF-8 the user typed, not normalised; the key file as its bytes, which the host refuses above 16 MiB before it reads the file whole (the core checks again, ADR 0029 point 5); for one `import` call.
>    7. The share passphrase (M5), when a share is created or opened ([§11.10–§11.11](../CRYPTO.md#1110-public-share-link-creation-m5)); for one call.
>    8. The share secret (M5), from the URL fragment when a share is opened; for one call.
>
>    **In, as strings:**
>    9. The second-factor TOTP code (M1, [§11.15](../CRYPTO.md#1115-totp-m1)), typed at login, at the enrolment confirmation and at 2FA disable; for one call. A string: it is valid only for its time step, and the host drops it when the call returns.
>    10. The invite token (M1, [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration)), typed or pasted at signup; for one call. A string: it is single-use, and the host drops it when the signup flow ends.
>
>    **Out, as bytes, once:**
>    11. The Secret Key and the recovery code, to render an Emergency Kit (M1): once per kit, at signup and whenever a flow issues a new kit. The host renders the kit, may hand it to the platform's print or save dialog at the user's request, and wipes the arrays; it stores neither.
>    12. A freshly generated passkey's private key (M2, [ADR 0039](0039-passkeys-vault-and-extension.md) §1), once, from the call that creates the passkey, for the item write that stores it as the new item's `passkey/<id>/private_key` field in the same user action. The host passes it to that write and then wipes its array; it never logs or holds it for anything else. A stored passkey's private key never crosses.
>    13. A per-device *local unlock secret* goes out to the platform keystore for biometric unlock (M3, M7). It opens only `E_ks`, the keystore wrap of the account key on that one device ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)), and it is not the account key. Persisted only in that keystore.
>    14. An explicit plaintext export (M1), after re-authentication and the warning of [ADR 0027](0027-export-payload.md) §5 (with [ADR 0034](0034-export-reauth-and-plaintext-hold.md)), as one byte buffer that the host writes to the file the user chose and then wipes. That file is the user's; nothing else of it is persisted by the host.
>    15. Share secrets (M5) go out as part of the share URL, in its fragment.
>
>    **Out, as strings:**
>    16. The 2FA enrolment secret (M1, [§11.15](../CRYPTO.md#1115-totp-m1)): the `otpauth://totp/` URI, for a QR code, and the Base32 secret, for manual entry. Lifetime: from the `totp/enrol/start` answer until `totp/enrol/confirm` succeeds, the user cancels, the screen is left or the session locks, whichever comes first. Shown only on the enrolment screen; never persisted; copied to the clipboard only on the user's explicit action.
>    17. The session bearer token (M1), as the `Authorization` value `Bearer <43 base64url characters>` ([ADR 0028](0028-api-v1-http-conventions.md) item 4) of one request the core built, including the old token of a sign-out after a session refresh. The host's transport reads it once, sets it on that one request, and drops it when the request settles. It sends no cookie, follows no redirect and caches nothing for that request (`credentials: "omit"`, `redirect: "error"`, `cache: "no-store"` on the web, the equivalent settings of each native HTTP stack). A string: every HTTP stack takes header values as strings.
>    18. The `device-request` signature and counter (M1, device sessions), as the `Rizzy-Request-Signature` and `Rizzy-Request-Counter` values of one request ([ADR 0028](0028-api-v1-http-conventions.md) item 5; [CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication)), handled exactly as entry 17. Alone it authorises nothing beyond the one request whose method, path, body and counter it signs, but with the token it authenticates that request.
>
>    **Opaque bytes the host persists:**
>    19. The device state record goes out as opaque bytes for the host to persist. It holds the Secret Key unwrapped until an OS keychain is used ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)). The web vault has no device state record.
>    20. **extension only (M2):** none. Unlocked key state never leaves the long-lived context's wasm instance (§4) and is never written to any extension storage area, `storage.session` included. When that context is torn down, the extension is locked ([ADR 0111](0111-extension-session-and-idle-lock.md) §1);
>
>    **In, as bytes, plaintext in bulk:**
>    21. An import file (M1): another product's export, or our own plaintext JSON ([ADR 0027](0027-export-payload.md) §6), as one byte array for one import call. The core holds its plaintext only during that call; the host transfers the array to the core context and wipes it after the call. (An encrypted export file and a KDBX file are ciphertext under rule 5; they follow the same transfer and wipe.)
>
>    Adding an entry, or changing an entry's direction, form or lifetime, changes this rule: it needs a new ADR.

**B. ADR 0019 §3, the bullet "**Secrets cross as bytes.**", in full** ("Every named exception of rule 2 (master password, Secret Key, recovery code, export password, local unlock secret, share secrets and passphrase) crosses as a byte array, never as a string, so the host can zero its array after the call. This mirrors the web client's zeroed `Uint8Array` ([CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)). It removes the glue's own string copies. It does not remove the host's original, because typed input is a host string first."). Replaced by:

> - **Secrets cross as bytes.** Every entry of ADR 0013 §3 rule 2 (as [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) §3 restates it) marked "as bytes" crosses as a byte array, never as a string, so the host can zero its array after the call. This mirrors the web client's zeroed `Uint8Array` ([CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)). It removes the glue's own string copies. It does not remove the host's original, because typed input is a host string first. The entries marked "as strings" (the second-factor code, the invite token, the 2FA enrolment secret, the bearer token and the request signature) cross as strings because the host API that consumes each takes a string; rule 2 bounds their lifetime instead.

**C. ADR 0029 point 4, the sentence:**

> **Argon2 cannot be cancelled** (one blocking call in `argon2` 0.6.0): the caller runs `import` where it can be killed, a Web Worker in the browser and a worker thread or process natively, and the product cap of point 5 bounds the wait.

Replaced by:

> **Argon2 cannot be cancelled** (one blocking call in `argon2` 0.6.0), so a host's cancel reaches `import` only through `keep_going`, which `import` consults every 65,536 AES-KDF rounds, once after the KDF returns, and once after decryption, before the XML mapping; when it returns `false`, `import` wipes what it holds and returns `ImportError::KdbxCancelled`, before any item exists. `probe` and `import` run in the context that holds the unlocked vault, never in a second instance, and no context is killed to cancel them. **Web vault:** in the one core Worker of [ADR 0013](0013-shared-client-core.md) §4, each as one synchronous call. A Worker sees no message while a call runs, so its `keep_going` always returns `true`: the user's only cancel point is the confirmation of `probe`'s `KdbxCost`, which comes before the KDBX password is asked for, and the wasm32 caps of point 5 bound the run. A lock requested meanwhile runs when the call returns, and the UI thread hides every vault view at once. **Native hosts:** `import` runs on a host worker thread, never the UI thread, and `keep_going` returns `false` once the user cancels (an atomic flag the UI thread sets), so AES-KDF stops within 65,536 rounds and the later checks stop the rest, while an Argon2 call already running completes within point 5's caps and its block buffer is wiped and dropped. `rv` has no cancel other than ending the process, and an `rv` ended before `import` returns has written nothing.

### 4. On acceptance (doc edits, not made in this change)

1. The owner appends to ADR 0013's status line "; [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (§3 rule 2)", sets ADR 0019's to "Partially superseded by [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (§3 in part)" and ADR 0029's to "Partially superseded by [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (point 4 in part)"; the README rows of 0013, 0019, 0029 and 0096 mirror them, and CLAUDE.md's list of Accepted ADRs gains 0096.
2. [THREAT_MODEL.md](../THREAT_MODEL.md) TB-10 row gains: "What crosses it is ADR 0013 §3 rule 2's closed list of 21 entries, with their host rules ([ADR 0096](adr/0096-binding-secrets-and-kdbx-worker.md)); the bearer token and request signature cross on every request, as strings."
3. [CRYPTO.md](../CRYPTO.md) §12.2, the bullet "**JavaScript strings**", gains: "The bearer token and the request signature (`fetch` headers), the second-factor code, the invite token and the 2FA enrolment secret cross as strings by necessity; ADR 0096 bounds their lifetime instead."
4. CRYPTO.md §11.15 (TOTP) gains: "The enrolment secret leaves the core only for display, as the `otpauth://` URI and Base32 text, until the enrolment is confirmed or abandoned (ADR 0013 §3 rule 2 entry 16)."
5. [ROADMAP.md](../ROADMAP.md): none. ADR 0029's Negative sentence "the client decides whether to import in an instance it then discards (ADR 0013's concern, not decided here)" is answered by §2; it is Consequences text and is not edited.

### 5. Implementation plan and tests

**Part 1, the binding list (M1; before the next web-vault release).** One `fix(wasm,core,web)` change:
1. `crates/rizzy-wasm/src/lib.rs` "Rules of the boundary": list the 21 entries by number with this ADR's reference (documentation only).
2. `crates/rizzy-wasm` `importFile`, `importEncrypted` and `importCxfEncrypted` take the file as `&mut [u8]` and wipe it once parsed, and `packages/core` wipes the caller's array in a `finally` (entry 21; today they do not, `index.ts:2026–2039`); the passkey write path wipes the private-key array after the item write, on success and on error (entry 12; today "this module zeroes neither", `index.ts:692–704`). Tests (vitest): after each call, success and error, the caller's array is all zeroes.
3. `apps/web`: the 2FA enrolment state (`TwoFactorPane.tsx`) is cleared on lock, on leaving the screen and on confirm or cancel (entry 16). Test: a lock while the enrolment is shown leaves no `otpauthUri` or `secret` in the component state.
4. Lint: `no-console` as an error for the non-test sources of `packages/core`, `apps/web` and `apps/extension` in `eslint.config.mjs`, so that no secret is logged through the console (common rule (a)); those sources have no `console` call today (V, `grep`), so nothing needs an exception.
5. Rust tests, where missing: `Debug` of `HttpRequest`, `SignedRequest`, `TwoFactorEnrolment` and `CreatedPasskey` prints no token, signature, secret or key (each has a hand-written `Debug` today, `session.rs:2506–2510`, `passkey.rs:80–84`; the test pins it).
6. Native hosts (`rizzy-ffi`, `rizzy-ffi-cpp`, M3): the same entries, the same forms; ADR 0019 §4.5's C++ "one secrets module" holds entries 1–10 and 11–14 on that side.

**Part 2, KDBX (M3, inside the ADR 0029 implementation).**
1. `rizzy-import`: `ImportError::KdbxCancelled`; `keep_going` at the three points of §3 part C. Tests: `keep_going` returning `false` at each point gives `KdbxCancelled` and no `Import`; on an AES-KDF file the callback runs once per 65,536 rounds (counted) and a `false` stops within that many; the wipe of the composite and transformed keys on that path (a `Zeroizing` type, by construction).
2. `rizzy-wasm`: `probeKdbx(file)` returning the cost as a plain view, and `importKdbx(vaultId, file, password, keyFile, acceptedCost, nowMs)` with `keep_going = || true`, `password` and `keyFile` taken as `&mut [u8]` and wiped (entries 6 and 21). Tests: the arrays are zero after the call; a cost above the accepted one is `KdbxCostNotAccepted` before any KDF work.
3. `apps/web`: the cost confirmation before the password prompt; no cancel control once `import` starts, and a progress state that says it cannot be stopped; a lock during the call hides the views at once and locks when the call returns. Test: a lock queued during an import is applied after it, and no view stays visible meanwhile.
4. Measurement, recorded in the implementing PR: on the M0 machine in wasm, Argon2d at 256 MiB × 16 iterations (the 4 GiB-pass cap) and AES-KDF at 100,000,000 rounds. Open question 2 uses it.
5. `rizzy-ffi`: a cancel call that sets the flag of §3 part C from another host thread, and the binding error code `import_cancelled`.

## Consequences

### Positive

- Rule 2 lists what the code passes, with one rule per entry, so the TB-10 audit has a closed list to check and a host has a rule for the bearer token's lifetime and logging.
- ADR 0013's one-Worker design survives KDBX import unchanged: no second instance, no key or plaintext between instances, no lost session.
- Native hosts get a real cancel at defined points.

### Negative

- In the web vault, a KDBX import cannot be stopped once confirmed, and the core Worker answers nothing (lock included) until it returns: about 7 s at the Argon2 cap (L), unmeasured for AES-KDF (U).
- The web vault's linear memory keeps the import's peak until the page is reloaded.
- Five entries cross as strings that cannot be wiped; the rule bounds their lifetime only.
- Part 1 needs small code changes in `packages/core` and `apps/web` (wipes the code skips today).

### Risks

- If the measurement shows AES-KDF at its cap takes minutes in wasm, the non-cancellable wait is too long (open question 2).
- A platform HTTP stack that logs request headers (a debug proxy setting, a verbose native networking log) would log the token; each native host must check its stack's logging in M3.

## Alternatives considered

- **A short-lived second Worker for the KDBX work** (holding only the file and the password, or only the outer header and the password). It gives a real cancel (terminate it), but either the decrypted entries (plaintext of every entry) or the derived 32-byte KDBX key would cross `postMessage` between two instances, which ADR 0013 §4 rules out ("the core is never split across contexts"); `rizzy-import` would need a public KDF entry point and key type, which ADR 0029 point 3 forbids ("exposes no cipher, KDF or key type"); and a second instance holds up to 256 MiB more. It buys a cancel of a run the wasm cap bounds to seconds (L). Kept as open question 1's alternative.
- **Terminate the vault Worker to cancel.** Loses the session and every unsent op (the web vault is not durable), forces a new login, and frees the heap without wiping it.
- **Cooperative cancel through `SharedArrayBuffer` and `Atomics`.** Needs cross-origin isolation headers the server does not send, and still cannot stop Argon2 mid-run.
- **Our own interruptible Argon2.** Home-made cryptography; forbidden by CLAUDE.md and ADR 0009.
- **Every entry as bytes.** Headers, text fields and QR encoders take strings, so the host would make the string anyway; the bytes form would add a copy, not remove one.
- **Leave rule 2 as it is and document the extra crossings in `rizzy-wasm` only.** Code comments do not bind, and rule 2 says "only these".

## Open questions for the owner

1. **No cancel once a web-vault KDBX import starts** (§2, §3 part C), with the cost confirmation as the cancel point. Accept it, or take the second-Worker alternative (a key-only Worker that returns the 32-byte KDBX key, with a superseding change to ADR 0029 point 3 and ADR 0013 §4)? Recommendation: accept; the wait is bounded to seconds at the Argon2 cap (L), and no key or plaintext crosses between instances.
2. **The web vault's AES-KDF cap.** If the Part 2 measurement shows 100,000,000 AES-KDF rounds take more than 60 s in wasm on the M0 machine, should the web vault pass a lower `KdbxLimits` rounds cap (ADR 0029 point 4 lets a caller lower a cap, never raise it), set to the rounds that take 60 s there? Recommendation: yes; a file above it is refused as `TooLarge`, and the user can import it with `rv` or a native app, or export XML.
3. **Entry 12, the new passkey's private key.** Keep it, or replace it in M3 by one coarse call that creates the passkey and writes the item in Rust, so that no private key ever crosses (a later ADR removes the entry)? Recommendation: replace it in M3; rule 6 already asks for one call per user action, and the key then never reaches JavaScript.

## References

- [ADR 0013](0013-shared-client-core.md) §2, §3, §4; [ADR 0019](0019-native-clients.md) §1.2, §3, §4.5; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0022](0022-server-mode-only.md) §1; [ADR 0027](0027-export-payload.md) §5, §6; [ADR 0028](0028-api-v1-http-conventions.md) items 4, 5; [ADR 0029](0029-kdbx-import.md) points 3–5, Negative; [ADR 0034](0034-export-reauth-and-plaintext-hold.md); [ADR 0036](0036-browser-extension-architecture-and-key-custody.md); [ADR 0039](0039-passkeys-vault-and-extension.md) §1, §5; [ADR 0074](0074-passkey-cxf-import-export.md).
- [THREAT_MODEL.md](../THREAT_MODEL.md) TB-10, INV-48, INV-63; [CRYPTO.md](../CRYPTO.md) §4.2, §5.9, §5.10, §11.6, §11.9–§11.11, §11.14–§11.16, §12.2.
- Gap review: [2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) C9, C10; [G01](../reviews/2026-10-25-raw/G01.md) G01-20; [G04](../reviews/2026-10-25-raw/G04.md) G04-5.
- Code (V, at `262bbd0`): `crates/rizzy-wasm/src/{lib,http,device,login,signup,session,secret,breach,passkey,generator}.rs`; `packages/core/src/index.ts`; `apps/web/src/{main.tsx,core-client.ts,core-worker.ts,protocol.ts,views/TwoFactorPane.tsx}`; `crates/rizzy-import/src/error.rs`; `argon2` 0.6.0 `src/lib.rs` (cargo registry).
- The HTML event-loop model (a Worker runs one task at a time) and the cross-origin isolation requirement of `SharedArrayBuffer` (L: general knowledge, not re-read for this ADR).
