# ADR 0105: Secret Key QR: payload, encoding, display gate and scanner validation

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (web vault and macOS app) / M7 (mobile scanners)
- Supersedes: [ADR 0013](0013-shared-client-core.md) §3 rule 2 in part (two sub-bullets, §6), on acceptance.

## Context

Trigger: the 2026-10-25 ADR gap review ([summary](../reviews/2026-10-25-adr-gap-review.md), item M7 "**Secret Key QR transfer payload.** | ROADMAP M3 | G10-21"), and the owner's instruction "start" of 2026-10-25.

- **ROADMAP §4.3** (Must): "**Secret Key / 2SKD** (1Password-style 128-bit device-held key mixed into KDF), mandatory for every account ([ADR 0004](0004-key-derivation-argon2id-secret-key.md)) … | M1 (derivation, Emergency Kit) / M3 (QR transfer, polish)". The row says "QR transfer" and nothing more.
- **ADR 0004** owner decision 1 (Accepted): "only QR transfer and polish are left for M3". [CRYPTO.md §7](../CRYPTO.md#7-secret-key): "Only UX polish, such as QR transfer between devices, is left for M3", and a new device needs the SK "typed from the kit or scanned from another device". [CRYPTO.md §11.2](../CRYPTO.md#112-login-on-a-new-device-server-mode) step 1: "The user enters: server URL, login name, SK (typed, or QR from another device), master password." So the documented intent is a QR shown by **another device**, not a QR printed on the kit.
- **Review G10-21 [major]** ([raw](../reviews/2026-10-25-raw/G10.md)): "CRYPTO.md has no QR encoding. The only "QR" format left is the parked pairing QR (CRYPTO.md:237, ADR 0022)." "The QR carries the Secret Key, the account's second secret. Several points are undecided: whether it also carries the server URL or login name (a phishing vector), whether it is shown only on an unlocked enrolled device, its expiry, and a screenshot or camera-roll warning." Suggested resolution: "fix the payload as exactly the CRYPTO §7 `RV1-` string, with no URL, and state who may display it and where."
- **Device pairing is parked.** [ADR 0022](0022-server-mode-only.md) (Accepted) parked On-device mode, including "pairing over the relay (QR or short code, SAS, sealed transfer)", and removed the pairing-QR sub-bullet from ADR 0013 §3 rule 2. Its HKDF labels stay reserved and dormant (CRYPTO.md §4.3 row "Pairing key (QR path), reserved (parked, ADR 0022)" and the rows after it). This ADR does not revive them.
- **The Emergency Kit.** [ADR 0008](0008-account-recovery.md) point 1 (Accepted): "generated on the client only (HTML/PDF). It contains: the server URL and login name; the Secret Key …; the recovery code; a blank line for the master password; the sentence "Anyone with this sheet and access to your server can take over your account."" The kit formats built today are the web vault's printable HTML (`apps/web/src/kit.ts`: "It holds no script and no style, and carries a CSP that loads nothing (`default-src 'none'`)") and `rv`'s text output (`crates/rizzy-cli/src/commands.rs`: "`signup`, `secret-key` and `recovery complete` print the Emergency Kit once"; "There is no clipboard output, by the owner's decision of 2026-10-01"). No kit has a QR (V, read).
- **SK text format** (CRYPTO.md §7, Accepted via ADR 0004): "`RV1-` followed by 28 characters of Crockford Base32 … grouped by fours"; 26 data characters (128 bits plus 2 zero pad bits) and 2 check characters (a 10-bit check value, "for typo detection only"); "A parse is rejected if the pad bits are non-zero or the check value does not match"; the codec uses "arithmetic mapping" (§12.3). The code exists: `crates/rizzy-core/src/secret_key.rs` (`CodeParseError::{TooLong, WrongPrefix, InvalidCharacter, WrongLength, NonZeroPadding, CheckMismatch}`, `MAX_INPUT_LEN = 128`) with the KAT `00..0f` → `RV1-000G-40R4-0M30-E209-185G-R38E-1W28` (V, read).
- **Binding rules.** [ADR 0013](0013-shared-client-core.md) §3 rule 2 (Accepted) lists the only secrets that may cross a binding; "Adding an exception changes this ADR." It has "the Secret Key and recovery code go out once, to render the Emergency Kit (M1);" and "the Secret Key goes in when typed on a new device (M1);". Neither covers a QR. [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (Proposed) would replace rule 2 in full; its entries 2 and 11 are the same two cases.
- **Re-authentication precedent.** [ADR 0034](0034-export-reauth-and-plaintext-hold.md) points 1–3 (Accepted): an OPAQUE login of the session's account; "One re-authentication allows one export within 5 minutes (`REAUTH_WINDOW_MS` …)"; "a refusal spends nothing"; "a clock that went back counts as not fresh"; permission tokens "which have no public constructor". Code: `crates/rizzy-client/src/export/gate.rs` (V, read).
- **Threats.** [THREAT_MODEL A14](../THREAT_MODEL.md#a14-shoulder-surfing-clipboard-and-screen-capture) lists "screen recording, screenshots, app-switcher thumbnails, and screen sharing during calls"; its mitigations already include window capture exclusion on native desktops and screenshot blocking on mobile. An SK alone does not open the vault (the master password is also needed, CRYPTO.md §5.5), but its leak removes the second factor that protects a weak master password after a server breach (goal G-4).
- **Side channels.** CRYPTO.md §12.3: "No secret-dependent branches or lookups in our code. This includes the Crockford Base32 encoder and decoder for the SK". A QR encoder (Reed–Solomon over GF(256), mask penalty scoring) and any image decoder are data-dependent by construction (L, general knowledge of ISO/IEC 18004).
- **Dependencies.** [HANDOFF](../HANDOFF.md) lists "`qrcode` (rv) + a JS QR library | Secret Key QR transfer, M3 | none — ADR 0004 already covers the string format". No QR crate is in the workspace today (U: only the HANDOFF row was read, `Cargo.lock` was not searched).

## Decision

### 1. What the QR carries

1. **Only the Secret Key**, as the **SK QR payload v1**: the ASCII bytes `RV1-` followed by the 28 Crockford Base32 symbols of CRYPTO.md §7, uppercase, **with no further separators**. Exactly 32 bytes (`SK_QR_PAYLOAD_LEN = 32`). Example, from the existing KAT: SK bytes `00 01 … 0f` → `RV1-000G40R40M30E209185GR38E1W28`.
2. **Never in it:** the master password, the recovery code, the server URL or origin, the login name, the account id, a device id, a token, a timestamp or any other field. No URI scheme (`rizzyvault:`, `https:`, `otpauth:`): a URI would put the SK in a URL and make OS camera apps hand it to a URL handler, and a server URL inside the code would let a forged code point a new device at another server.
3. **Versioning.** The leading token is the version; `RV1-` is payload v1 and the only one. A future payload uses a different leading token and needs a new ADR; v1 scanners refuse it (§4, `UnknownVersion`). The 10-bit SK check value is the payload checksum; the QR's own Reed–Solomon code covers read errors.
4. **The recovery code is never rendered as a QR**, by any client, on any surface: with server access it opens the account by itself (ADR 0008 point 2, CRYPTO.md §11.9).

### 2. Encoding

1. **QR Code Model 2** (ISO/IEC 18004), one segment in **alphanumeric mode** (all 32 bytes are in that mode's 45-character set of digits, uppercase letters, space and `$%*+-./:`), **error-correction level M**, **version 2 (25 × 25 modules)**, all fixed: the encoder never picks another mode, version or level. Version 2-M holds 38 alphanumeric characters (L: the standard's capacity table as commonly reproduced; confirmed by test T3). No ECI header, no structured append, no FNC1.
2. **Mask:** chosen by the standard's penalty rule. The mask is not part of this format; a compliant decoder reads it from the format information.
3. **Encoder location:** `rizzy-client`, module `secret_key_qr`, one encoder for every host. Hosts never encode the SK themselves and never receive it as text for this purpose. The encoder crate is chosen at implementation under CLAUDE.md's dependency rules (justification, `cargo deny check`, exact pin in `[workspace.dependencies]`). Requirements: pure Rust, no I/O, builds for `wasm32-unknown-unknown`, no default features it does not need, `#![forbid(unsafe_code)]` preferred (U for any given candidate). It is not a crypto crate under ADR 0009, but it handles a secret: every buffer we own is `Zeroizing`; buffers inside the crate are a residual (§7, open question 3).
4. **Output: `SkQrMatrix`**, in memory only, never persisted or serialised: `width: u8` (always 25) and `modules: Zeroizing<Vec<u8>>` of `width × width` bytes, row-major, top row first, left to right, `1` = dark, `0` = light, without the quiet zone. Across a binding it is the byte array `[width] ‖ modules` (626 bytes), under ADR 0013 rule 2 as replaced in §6. It zeroizes on drop, and its `Debug` prints `SkQrMatrix(25x25, redacted)`.
5. **Rendering (host):** a 4-module light quiet zone on every side (33 × 33 modules), dark modules black (`#000`) on white (`#fff`) in every theme including dark mode, at least 6 device-independent pixels per module (at least 198 × 198 px), nearest-neighbour scaling, no anti-aliasing. Web vault: drawn on a `<canvas>` by script; no `<img>`, no `data:` or `blob:` URL, no SVG in the DOM, so `WEB_CSP` is unchanged. Native: drawn into a view. The QR's accessible name is "Secret Key QR code" and never contains the value.

### 3. Where it is shown, and the display gate

1. **Surface.** A screen "Show Secret Key as QR code" in the security settings of a client that **holds the SK in its device state record** (CRYPTO.md §7 "Storage"): the macOS desktop app (M3), the mobile apps (M7), and the web vault only where the user stored the SK in that browser ("this is my browser", if implemented). Elsewhere the option is not offered, and the core refuses with `SecretKeyNotHeld`. Not in `rv`: it already prints the kit as text, and a terminal QR is out of scope. **Not on the Emergency Kit** at M3; ADR 0008 point 1 is unchanged (open question 1).
2. **Gate: `SkQrGate`** in `rizzy-client::secret_key_qr`, built like ADR 0034's `ExportGate` but separate from it:
   - `accept_reauth(…)` takes a fresh OPAQUE login of the session's account, with the master password typed now and the SK from the device state record. A login of another account → `WrongPasswordOrSecretKey`, and nothing is recorded. Biometric or keystore unlock is **not** a re-authentication.
   - `authorize(now_ms) -> Result<SkQrAuth, SkQrError>` succeeds only if an unspent re-authentication recorded at `reauth_at_ms` satisfies `reauth_at_ms ≤ now_ms ≤ reauth_at_ms + REAUTH_WINDOW_MS` (the existing 5-minute constant; a clock that went back is not fresh). Success **spends** it; a refusal spends nothing.
   - A re-authentication made for an export never authorises a QR, and one made for the QR never authorises an export: each gate keeps its own.
   - `SkQrAuth` has no public constructor, is not `Clone`, and is consumed by `secret_key_qr(auth) -> Result<SkQrMatrix, SkQrError>`. One authorisation gives one matrix and one display.
   - The gate lives in the unlocked session, is dropped by a lock, and is never persisted.
3. **Errors (`SkQrError`; the same names in every binding):** `ReauthRequired` (none, stale or spent), `WrongPasswordOrSecretKey`, `SecretKeyNotHeld`, `Locked`. None carries a secret.
4. **Display lifetime.** The QR is shown for at most **`SK_QR_DISPLAY_MS = 60_000`** from first paint, with a visible countdown. It is removed earlier by any of: the user's "Done"; the vault locking; the page or window becoming hidden (`visibilitychange` to hidden, minimise, app to background); navigation away; on desktop, the window losing focus. Removal clears the canvas or view and wipes the host's matrix array; the core kept no copy once the matrix crossed out. Showing it again needs a new re-authentication. There is no "extend" action.
5. **Shown next to the QR, as plain text:** the server origin and the login name (not secret, and on the kit too), so the user can enter them on the new device; and this warning, verbatim (`SK_QR_WARNING`): "This code is your Secret Key. Scan it only from the Secret Key field of Rizzy Vault on your new device. Don't photograph it, screenshot it, share your screen while it is shown, or scan it with another app." The SK text itself is **not** shown on this screen.
6. **Screenshots and screen sharing.** The macOS app excludes its window from capture while the QR is on screen (`NSWindow.sharingType = .none`, U until M3, as THREAT_MODEL A14 already says); Windows and Linux follow ADR 0019 when they ship. Mobile apps block screenshots app-wide (A14). The web vault cannot block capture and relies on the warning (§7).
7. **Clipboard and export.** No copy, save, share, drag or print action for the QR or the SK on this screen, and no context-menu item of ours. (A browser's own "Save image" on a canvas cannot be fully removed: §7.)
8. **Crash and retry.** Nothing in §3 is persisted. A crash, reload or lock while the QR is shown loses the matrix and the authorisation; the user re-authenticates to show it again. The server sees only the re-authentication login, so there is nothing to retry or clean up.

### 4. Scanner validation

1. **Where:** a "Scan QR code" action on the Secret Key field of the new-device login (CRYPTO.md §11.2 step 1), on hosts with a camera. Nowhere else: not at recovery, re-authentication or signup.
2. **Camera.** Frames are decoded in memory by the host's decoder (a platform API or a pinned library chosen at implementation, running locally, never over the network). No frame is stored, logged or sent. The camera stops at the first accepted payload, on cancel, when the page or app is hidden, and after **`SK_QR_SCAN_MAX_MS = 120_000`**.
3. **Into the core as bytes.** The decoded payload goes to `rizzy_core::secret_key::SecretKey::from_qr_payload(&[u8]) -> Result<SecretKey, SkQrPayloadError>` as a byte array (ADR 0013 rule 2 as replaced in §6); the host wipes its array and drops any decoder string at once. The core checks in this order and returns the first failure:
   1. length > **`SK_QR_MAX_INPUT = 64`** bytes → `TooLong`, without reading further;
   2. starts with the bytes `RVR1-` → `RecoveryCode`;
   3. starts with `RV`, then 0–3 bytes in `A`–`Z`, then 1–3 bytes in `0`–`9`, then `-`, and does not start with `RV1-` → `UnknownVersion`;
   4. does not start with the exact bytes `RV1-` (case-sensitive) → `NotSecretKey`;
   5. length ≠ 32, or any of bytes 4 to 31 is not in the uppercase alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no `O`/`I`/`L` mapping, no lower case, no separators) → `Malformed`;
   6. the CRYPTO.md §7 decoding of the 28 symbols finds non-zero pad bits or a check-value mismatch → `CheckMismatch`.

   Steps 1–4 look only at the public prefix. Steps 5–6 reuse the §7 codec (arithmetic mapping, constant-time check-value comparison, §12.3).
4. **On a refusal** the host shows a fixed message for the error code and keeps scanning, changing the message at most once per second. It never shows, logs or acts on the decoded content, which may be another person's secret or a phishing URL; a scanned URL is never opened. `RecoveryCode` shows "This is a recovery code. It can't be scanned; use account recovery instead." `UnknownVersion` shows "This code is from a newer version. Update Rizzy Vault or type the Secret Key."
5. **On success** the field shows "Secret Key scanned", never the value. The SK is then held exactly as a typed SK in that form (same lifetime, same wipe) and enters the login as the "Secret Key in" exception (§6).
6. **Untrusted input:** `from_qr_payload` gets a fuzz target (`fuzz/fuzz_targets/sk_qr_payload.rs`).

### 5. What is not decided here

No server change, endpoint, migration, sealing purpose or settings tag. The parked pairing protocol (ADR 0022) stays parked: this QR moves the SK only and enrols nothing.

**Provisional invariant INV-120:** "A Secret Key QR carries only the SK QR payload v1 (`RV1-` and 28 symbols). It is rendered only through `SkQrGate` after a fresh master-password re-authentication, at most once per re-authentication and for at most 60 s. The recovery code is never rendered as a QR. A scanner accepts nothing but payload v1."

### 6. What this ADR supersedes

Two sub-bullets of [ADR 0013](0013-shared-client-core.md) §3 rule 2, each a whole bullet, each replaced in full by the text after it (ADR 0020 point 9). No Accepted ADR names either one: ADR 0022 and ADR 0019 name only the pairing-QR sub-bullet (V, ADR 0019's word-count table, "§3 rule 2, pairing QR sub-bullet 30"). Nothing else in ADR 0013 changes; the replaced share is about 25 of ADR 0013's 1,740 words.

**A.** The sub-bullet "the Secret Key and recovery code go out once, to render the Emergency Kit (M1);". Replaced by:

> - the Secret Key and recovery code go out once, to render the Emergency Kit (M1); and the Secret Key goes out as the module matrix of its QR code, once per authorisation of the Secret Key QR gate, for the host to draw and then wipe; the host never turns it into text, an image file or a URL, and stores nothing ([ADR 0105](0105-secret-key-qr.md), M3);

**B.** The sub-bullet "the Secret Key goes in when typed on a new device (M1);". Replaced by:

> - the Secret Key goes in when typed on a new device (M1), or when scanned there from a Secret Key QR, as the bytes of the scanned payload ([ADR 0105](0105-secret-key-qr.md), M3);

**If ADR 0096 is Accepted before this ADR,** rule 2 is then ADR 0096's text. At this ADR's acceptance, this section instead names ADR 0096 §3 part A's entry 2 and entry 11, each replaced in full by:

> 2. The Secret Key (M1), typed on a new device, or scanned there from a Secret Key QR as the bytes of the scanned payload ([ADR 0105](0105-secret-key-qr.md), M3); for one call.

> 11. The Secret Key and the recovery code, to render an Emergency Kit (M1): once per kit, at signup and whenever a flow issues a new kit. The host renders the kit, may hand it to the platform's print or save dialog at the user's request, and wipes the arrays; it stores neither. The Secret Key also goes out as the module matrix of its QR code ([ADR 0105](0105-secret-key-qr.md), M3), once per authorisation of the Secret Key QR gate; the host draws it, never as text, an image file or a URL, wipes the matrix when the display ends, and stores nothing.

### 7. Residuals

- The shown or scanned image is equivalent to the SK. A camera, screenshot or screen share during the 60 s captures it, as a photo of the kit does. The master password is still needed (CRYPTO.md §5.5).
- QR encoding and decoding branch on, and index tables with, the SK's bits, in third-party code; this departs from the intent of CRYPTO.md §12.3. It is one-shot and local, on a device that is about to show the SK on screen anyway (open question 3).
- Web vault: no capture blocking; the decoder's output string and the canvas pixels cannot be wiped (as typed input, CRYPTO.md §12.2); the browser's own "Save image" on a canvas.
- OS camera apps pointed at the QR may offer to search the web for plain text (behaviour per OS: U). The warning says not to scan with another app; no URI scheme is used, so no app is launched.

## Consequences

**Positive**
- One payload, one encoder and one validator for every host: two implementers produce the same QR contents and refuse the same inputs with the same codes.
- The payload reuses the Accepted `RV1` codec and its check value. No new format, no new crypto, no server change.
- No phishing lever: a forged code can at most supply a wrong SK, which fails the login (`WrongPasswordOrSecretKey`); it cannot change the server or the account.
- Display is gated like an export (fresh master password, 5 minutes, single use) and lasts at most a minute.

**Negative**
- A new third-party dependency in `rizzy-client` (the encoder), and a decoder on each scanning host, each to justify under CLAUDE.md.
- The QR is not encrypted: it is exactly as sensitive as the printed SK. Encrypting it needs a second secret, which on the same screen gains nothing, and through a pairing exchange is the protocol ADR 0022 parked.
- No SK text on the QR screen and no kit QR: a user without a camera types the SK from the kit.
- The web vault can offer the QR only where it stores the SK, which may be nowhere at M3.

**Risks**
- A chosen encoder handles mode, version or level differently from §2 (caught by T3 and T4).
- Users photograph the QR "to keep it"; only the warning mitigates this.

## On acceptance (not made now)

1. The owner adds "; [ADR 0105](0105-secret-key-qr.md) (§3 in part)" to ADR 0013's status line (or, if ADR 0096 was Accepted first, the matching entry to ADR 0096's line), and sets this ADR's README row.
2. CRYPTO.md §7: a "Secret Key QR" paragraph with §1–§4 (payload v1, encoding parameters, gate, scanner check order and error codes); §11.2 step 1 links it; §12.3 records the QR residual as the owner decides (question 3); §15 lists the vectors of T1–T2.
3. THREAT_MODEL A14: the QR screen's mitigations (§3.4–§3.7) and residuals (§7); INV-120 assigned, or renumbered, in §8.
4. HANDOFF dependency table: the "`qrcode` (rv) + a JS QR library" row points to this ADR, with the encoder in `rizzy-client` (not `rv`) and a decoder per scanning host.
5. Optional, the owner's act: link this ADR from the ROADMAP §4.3 row.

## Implementation plan and tests

1. **`rizzy-core`:** `SecretKey::qr_payload(&self) -> Zeroizing<[u8; 32]>`, `SecretKey::from_qr_payload`, `SkQrPayloadError::{TooLong, RecoveryCode, UnknownVersion, NotSecretKey, Malformed, CheckMismatch}`, constants `SK_QR_PAYLOAD_LEN` and `SK_QR_MAX_INPUT`. No new dependency.
   - **T1 KAT (payload):** `00..0f` → `RV1-000G40R40M30E209185GR38E1W28`; `ff` × 16 → `RV1-ZZZZZZZZZZZZZZZZZZZZZZZZZW8C`. Both are derived from the V vectors in `secret_key.rs` by removing the group dashes, and are cross-checked by the independent Python implementation already used there. Round trip for 10,000 random SKs.
   - **T2 refusal vectors** (expected codes, derived here, not yet run): 65 bytes → `TooLong`; `RVR1-208H44RM2MB1E60S38DHR78Y3WQP` → `RecoveryCode`; `RV2-000G40R40M30E209185GR38E1W28` and `RVX1-000G40R40M30E209185GR38E1W28` → `UnknownVersion`; `rv1-000g40r40m30e209185gr38e1w28`, `https://example.com/` and the empty input → `NotSecretKey`; `RV1-000G-40R4-0M30-E209-185G-R38E-1W28` (dashed, 38 bytes), `RV1-000G40R40M30E209185GR38E1W2` (31 bytes) and `RV1-O00G40R40M30E209185GR38E1W28` (letter `O`) → `Malformed`; `RV1-000G40R40M30E209185GR38E1W29` (check) and `RV1-000G40R40M30E209185GR38E1X28` (pad bit) → `CheckMismatch`.
   - Fuzz target `sk_qr_payload`: no panic; the length cap holds; an accepted input re-encodes to the same 32 bytes.
2. **`rizzy-client`:** the encoder dependency (after approval), `secret_key_qr::{SkQrGate, SkQrAuth, SkQrMatrix, SkQrError, SK_QR_DISPLAY_MS, SK_QR_SCAN_MAX_MS, SK_QR_WARNING}`.
   - **T3 encoding:** width 25 for every SK; the format information decodes to level M; the data codewords for the T1 SK equal a hand-derived alphanumeric bit stream (mode `0010`, 9-bit count 32, character pairs in 11 bits, terminator, pad bytes `0xEC 0x11`).
   - **T4 independent decode:** the T1 SK's matrix, rendered to a PNG fixture, decodes with an independent decoder (for example `zbarimg` or ZXing, run once when the fixture is made and recorded in the test comment, as the Python vector is) to the exact payload. Plus a committed golden matrix as a regression test (not independent).
   - **T5 gate:** no re-auth → `ReauthRequired`; re-auth at t: authorise at t + 300,000 ms → ok, at t + 300,001 ms → `ReauthRequired`; a second authorise → `ReauthRequired`; clock went back → `ReauthRequired`; another account's login → `WrongPasswordOrSecretKey` and nothing spent; no SK in device state → `SecretKeyNotHeld`; after lock → `Locked`; an export re-auth does not authorise a QR and the reverse.
   - **T6 hygiene:** the `Debug` output of `SkQrMatrix`, `SkQrAuth` and every error contains no payload symbol; the matrix is zeroized on drop.
3. **Bindings (`rizzy-wasm`; `rizzy-ffi` for macOS):** the matrix out as bytes `[width] ‖ modules`; the payload in as bytes; binding smoke tests (ADR 0019 §10).
4. **Web vault:** the settings screen (only with a stored SK), canvas rendering, countdown, removal triggers and warning; the scanner on the login SK field. **E2E (Playwright):** the QR is not offered without a stored SK; after re-auth the canvas appears with no `<img>`, `data:` or `blob:` URL and no SK text in the DOM; it is cleared after 60 s (fake clock), on `visibilitychange` and on lock; a second show needs a new re-auth; the scanner, fed a fake camera stream of the T4 fixture (Chromium fake video capture: L), logs in, and fed each T2 vector shows the fixed message and never the content.
5. **macOS app** (its own repository): capture exclusion while shown, the same lifetime rules; tests there.

## Alternatives considered

- **Payload with server URL and login name.** 1Password's setup code is reported to carry the sign-in address, email and Secret Key (L). Rejected: a forged code could send a new device to another server, and these fields are not secret, so they are shown as text beside the QR instead.
- **A URI (`rizzyvault://…`).** Rejected: it puts the SK in a URL and hands it to OS URL routing.
- **Binary payload (the raw 16 bytes in byte mode).** Rejected: it loses the check value and the visible version token, and saves nothing that matters at 32 bytes.
- **The dashed kit form (38 characters).** Rejected: it fills version 2-M exactly, with no margin; the compact form is just as unambiguous.
- **An encrypted QR** (under a key from a typed short code, or the parked pairing key). Rejected: it needs a password-based construction CRYPTO.md does not define, or ADR 0022's parked pairing protocol.
- **A QR on the Emergency Kit.** Left to the owner (question 1).
- **Encoding in each host** (CoreImage, a JS library). Rejected: several encoders to test, and the SK would cross out as text.

## Open questions for the owner

1. **ROADMAP intent: device-to-device only, or also a QR on the Emergency Kit?** *Recommendation:* device-to-device only at M3, as CRYPTO.md §7 and §11.2 describe; the kit stays as ADR 0008 point 1 says. If the owner wants a kit QR, this ADR adds a supersession of ADR 0008 point 1's first sentence and its bullet list, replaced in full by: "1. **The Emergency Kit is generated on the client only** (HTML/PDF). It contains: the server URL and login name; the Secret Key ([ADR 0004](0004-key-derivation-argon2id-secret-key.md)), as text and as a Secret Key QR ([ADR 0105](0105-secret-key-qr.md) §1–§2, drawn as inline SVG in the kit file); the recovery code, as text only; a blank line for the master password; the sentence "Anyone with this sheet and access to your server can take over your account."" In that case `rv`'s text kit gets no QR.
2. **May the web vault show the QR at all?** It can only where it stores the SK. *Recommendation:* yes, under the same gate; until the Windows and Linux apps ship it is the only surface there.
3. **Accept the data-dependent QR encoding and decoding residual (§7) against CRYPTO.md §12.3?** *Recommendation:* accept it and record it in §12.3 as "Accepted residual: Secret Key QR", like the otpauth one. The alternative, our own constant-time QR encoder, is a lot of code against a one-shot local leak on a device about to show the SK.
4. **Order with ADR 0096.** *Recommendation:* accept ADR 0096 first and apply §6's ADR 0096 variant; otherwise §6 A–B as written, with ADR 0096 updated before its acceptance to carry the QR text in its entries 2 and 11.

## References

- [ROADMAP §4.3](../ROADMAP.md), [ADR 0004](0004-key-derivation-argon2id-secret-key.md), [ADR 0008](0008-account-recovery.md), [ADR 0013](0013-shared-client-core.md) §3, [ADR 0019](0019-native-clients.md), [ADR 0020](0020-partial-supersession.md) point 9, [ADR 0022](0022-server-mode-only.md), [ADR 0034](0034-export-reauth-and-plaintext-hold.md), [ADR 0096](0096-binding-secrets-and-kdbx-worker.md) (Proposed).
- [CRYPTO.md](../CRYPTO.md) §4.3, §5.5, §7, §11.2, §12.2, §12.3, §15; [THREAT_MODEL.md](../THREAT_MODEL.md) A14, G-4.
- [Gap review](../reviews/2026-10-25-adr-gap-review.md) M7; [G10 raw findings](../reviews/2026-10-25-raw/G10.md) G10-21.
- Code read (V): `crates/rizzy-core/src/secret_key.rs`, `crates/rizzy-client/src/export/gate.rs`, `apps/web/src/kit.ts`, `crates/rizzy-cli/src/commands.rs`.
- External, not verified: the ISO/IEC 18004 capacity table and alphanumeric set (L); `NSWindow.sharingType` (U); OS camera-app handling of plain-text QR codes (U); Chromium fake video capture (L); 1Password setup-code contents (L).
