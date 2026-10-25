# ADR 0110: Passkey user verification: the `UV` flag reflects a recent master-password verification, and `userVerification: "required"` gets one in the toolbar popup

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M2
- Supersedes: on acceptance, in part: [ADR 0039](0039-passkeys-vault-and-extension.md) (§2, the bullet "User verification and presence", in full). §0 quotes it and gives the full replacement text.

## Context

The owner said "start" on 2026-10-25, after the ADR gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)). This ADR closes review item **S2: G04-20** (raw finding with quotes in [G04.md](../reviews/2026-10-25-raw/G04.md), "G04-20 [major]").

**What binds today.** [ADR 0039](0039-passkeys-vault-and-extension.md) (Accepted) §2, "User verification and presence":

> Every assertion and every registration runs only while the vault is unlocked (which already required the master password, an OPAQUE login, or a future keystore-gated unlock, ADR 0036 §3) **and** after an explicit user gesture choosing the credential in the extension-origin inline menu or popup […]. `authenticatorData` flags are set `UP=1` (user present: the gesture), `UV=1` (user verified: the unlock already authenticated the user), `BE=1`/`BS=1` […].

The code does exactly that: `crates/rizzy-client/src/passkey/wire.rs` writes `FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS` (`0x1D`) on every assertion and `… | FLAG_AT` (`0x5D`) on every registration, and nothing in the extension reads the request's `userVerification` member (`apps/extension/src/content/passkey-page-shim.ts` relays neither `publicKey.userVerification` nor `authenticatorSelection.userVerification`).

**The gap (G04-20).** The review's words: "an RP that asks `userVerification: "required"` for a step-up (payment, account recovery) treats UV as 'the user proved identity for this ceremony'. The extension asserts that on a single click while the vault is merely unlocked, which may be up to the auto-lock timeout (15 min default, user-configurable) after the last password entry, at an unattended browser. ADR 0034 handles the analogous export threat with a fresh re-authentication. Here THREAT_MODEL's passkey section and INV-64 address only origin/rpId binding and name neither a mitigation […] nor an accepted residual. Its 'Verified by' has no UV test."

- [THREAT_MODEL](../THREAT_MODEL.md) "Passkey provider (M2; ADR 0039)" lists five mitigations, all about the origin and `rpId`; [INV-64](../THREAT_MODEL.md#8-security-invariants) is the same, and its "Verified by" is "Table-driven tests: `evil.example` requesting `rpId` `bank.com`; `rpId` `co.uk` and `github.io`; an `http` origin; a cross-origin iframe; an origin forged in the page's message." No line names `UV`.
- [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §3: auto-lock is "a configurable idle timeout (default to be set with the M2 UI; recommend 15 minutes […], **U**)", plus lock on `chrome.idle` reaching `locked` or `idle`.
- [ADR 0034](0034-export-reauth-and-plaintext-hold.md) point 2 is the project's precedent for freshness: "One re-authentication allows one export within 5 minutes (`REAUTH_WINDOW_MS`) […] The host's clock decides; a clock that went back counts as not fresh."
- [INV-40](../THREAT_MODEL.md#8-security-invariants): "The extension never asks for the master password or Secret Key in page-injected UI." THREAT_MODEL §A7: "unlock happens only in the toolbar popup or an extension page." The passkey-consent iframe ([ADR 0043](0043-inline-menu-instance-token.md)) is extension-origin but sits inside the page's layout, where the page can draw a pixel-identical fake, so it is page-injected UI for INV-40's purpose. A master-password field inside it is therefore not an option this ADR may choose.
- Current ceremony plumbing (code, not ADR text): a pending ceremony lives in `core-host/passkey-ceremony.ts` with `PASSKEY_CEREMONY_TTL_MS = 2 * 60 * 1000`, single use, bound to `(tabId, origin)`, cleared on lock; the page shim waits `min(publicKey.timeout, 60 000 ms)` and on decline, timeout or no match calls the browser's own `navigator.credentials` instead.

**What WebAuthn says (external facts).** `userVerification` is a `UserVerificationRequirement` with values `"required"`, `"preferred"`, `"discouraged"`, defaulting to `"preferred"`, and an unknown value is ignored as if absent (WebAuthn L3 §5.8.6 and the IDL defaults; **L**, not re-read for this ADR). For `"required"` the client must fail the ceremony if the authenticator cannot verify the user; an RP verifying an assertion for `"required"` must check that `UV` is set (WebAuthn L3 §7.2 step "If user verification is required …"; **L**). The `UV` bit is bit 2 (`0x04`) of the flags byte (§6.1; **V** via `wire.rs`, which cites it). How other password-manager passkey providers handle UV (some re-prompt for the master password or a PIN when `"required"`, some treat the unlock as UV) is general product knowledge, **U**.

## Decision

### 0. What this ADR supersedes

| Part, quoted | Replaced by |
|---|---|
| [ADR 0039](0039-passkeys-vault-and-extension.md) §2, the whole bullet beginning "**User verification and presence.** Every assertion and every registration runs only while the vault is unlocked" and ending "`BE=1`/`BS=1` (backup eligible/backup state: these are explicitly backed-up, synced credentials)." | The text below. |

Replacement text for that bullet, in full:

> - **User verification and presence.** Every assertion and every registration runs only while the vault is unlocked ([ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §3) **and** after an explicit user gesture choosing the credential in the extension-origin inline menu or popup, mirroring [ADR 0037](0037-url-matching-and-autofill-rules.md) §5's gesture-only rule. The unlock alone is not user verification for a ceremony: [ADR 0110](0110-passkey-user-verification.md) decides when `UV` is set and when a request with `userVerification: "required"` needs a fresh master-password verification in the toolbar popup. `authenticatorData` flags are `UP=1` (user present: the gesture), `UV` as ADR 0110 §3 sets it, `BE=1`/`BS=1` (backup eligible/backup state: these are explicitly backed-up, synced credentials).

Nothing else in ADR 0039, ADR 0036, ADR 0043 or INV-40 changes.

### 1. The requirement the extension reads

1. The page shim relays one more optional field, `userVerification`, in both requests: for `create` from `publicKey.authenticatorSelection.userVerification`, for `get` from `publicKey.userVerification`. It is a string of at most 16 UTF-16 code units; anything else (not a string, longer, absent) is not relayed.
2. The background maps it to a requirement: `"required"` → **Required**; `"discouraged"` → **Discouraged**; `"preferred"`, absent, or any other value → **Preferred** (the WebAuthn default, §Context).
3. The value is page-supplied, and that is acceptable: the page is the RP's own script, so a malicious page can only lower the requirement of its own ceremony, which yields an honest `UV=0` (§3), never a false `UV=1`. INV-64's rule that the origin and `rpId` never come from page data is unchanged.

### 2. Verification state: `verified_at`

1. The unlocked core session (the `rizzy-wasm` session object of the extension's long-lived context, [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §2) holds one value, `verified_at: Option<u64>` (milliseconds since the Unix epoch by the host clock). It is never persisted: not in `storage.session`, not in the unlocked-state snapshot (`rizzy.unlocked_snapshot.v1`), not anywhere else. A session restored from `storage.session` starts with `verified_at = None`. Lock, auto-lock and the end of the long-lived context drop it with the session.
2. It is set to the host's `now` by exactly two events:
   - a successful unlock **with the master password** (the local unlock of [CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device), `StoredDevice::unlock(password)`, or the master-password OPAQUE login at enrolment);
   - a successful **re-verification** (§4).
3. Nothing else sets it. In particular, not the device-key online authentication, not a restore from `storage.session`, not a keystore-gated unlock (`unlock_keystore`) until an Accepted ADR states that the keystore's gate itself verifies the user (a biometric or OS PIN check) and amends this list, and not a recovery-code flow.
4. **Fresh.** `verified_at` is fresh at time `now` iff it is `Some(t)` and `0 ≤ now − t ≤ UV_FRESH_MS`. A `now` earlier than `t` (a clock that went back) is not fresh, as in [ADR 0034](0034-export-reauth-and-plaintext-hold.md) point 2.
5. **`UV_FRESH_MS = 120 000`** (2 minutes), a constant, not a setting; [open question 1](#open-questions-for-the-owner) asks the owner to confirm the window. A verification does not get spent: every ceremony signed while it is fresh carries `UV=1`.

### 3. The flags, decided at signing time

Freshness is evaluated **once per ceremony, inside the same core call that signs** (`passkey_assertion` / `create_passkey` gain the requirement and `now_ms` arguments). No earlier evaluation (at request time, at the consent click) is used.

| Requirement | `verified_at` fresh at signing | Result |
|---|---|---|
| Required | yes | Sign. `UV=1`. |
| Required | no | Do not sign. The call returns `UvRequired` (§4 starts the re-verification). Never `UV=0`. |
| Preferred | yes | Sign. `UV=1`. |
| Preferred | no | Sign. `UV=0`. No prompt ([open question 2](#open-questions-for-the-owner)). |
| Discouraged | yes | Sign. `UV=1`. |
| Discouraged | no | Sign. `UV=0`. No prompt. |

The flags byte is therefore exactly one of:

| Ceremony | `UV=1` | `UV=0` |
|---|---|---|
| Assertion (`UP`, `BE`, `BS`; never `AT`, never `ED`) | `0x1D` | `0x19` |
| Registration (`UP`, `BE`, `BS`, `AT`; never `ED`) | `0x5D` | `0x59` |

`UP` stays 1 always (the gesture); `BE`/`BS` and the zero signature counter of ADR 0039 §2 are unchanged. The `UV` decision is the same for a registration and an assertion.

### 4. Re-verification for "required" in the toolbar popup

The master password is entered only in the toolbar popup, the surface unlock already uses (INV-40, THREAT_MODEL §A7). Never in the consent iframe, the inline menu, or any window or tab the extension opens.

1. **Consent label.** When the request is Required and `verified_at` is not fresh at the time the consent iframe is shown, the approve button reads "Verify and use passkey" (registration: "Verify and save passkey") and the iframe states that the rizzy toolbar button will ask for the master password. This is advisory only: the decision is §3's, at signing.
2. **Approve → `UvRequired`.** The consent approval reaches the core call of §3. If it returns `UvRequired`, the background moves the pending ceremony (same record, same `ceremonyToken`, same `(tabId, origin)` binding, same TTL counted from creation, `PASSKEY_CEREMONY_TTL_MS`) from `pending` to `awaiting_verification`, with `uv_attempts = 0`. The ceremony is **not** taken. The consent iframe shows "Waiting for verification in the rizzy toolbar button" and a Cancel button (Cancel = the existing decline). The background sets the toolbar badge text for that tab to `"!"` and calls `action.openPopup()` where the browser offers it; if that call is missing or fails, nothing else happens (the iframe's text tells the user to click the button). Whether `openPopup()` works without a user gesture in the background differs by browser and version (**U**).
3. **Popup view.** When the popup opens and its active tab has a ceremony in `awaiting_verification`, the popup shows the verification view before anything else: the verified origin, the `rpId`, the credential's user name, the kind (sign in / save passkey), a master-password field and Verify / Cancel buttons. It fetches this with a popup message `passkey_verify_pending` (reply: `{ ceremonyToken, origin, rpId, userName, kind }` or `none`).
4. **Submit.** The popup sends `passkey_verify_submit { ceremonyToken, masterPassword }`. The background accepts it only from the popup (sender is an extension page whose URL is the popup's, with no `sender.tab`); a content-script or iframe sender is refused like any malformed message. `masterPassword` is bounded as the popup's `unlock` message bounds it, held in a zeroizing buffer once in Rust, never logged. The long-lived context then, in this order:
   1. looks up the ceremony; missing, expired, or not `awaiting_verification` → `uv_ceremony_gone`;
   2. re-checks the ceremony's binding against the tab's **live** URL, as the approval path already does; changed → decline the ceremony, reply `uv_ceremony_gone`;
   3. verifies the password by running the same local unlock primitive (`StoredDevice::unlock(password)`) against the device record the current session was unlocked from, then drops (zeroizes) the opened keys; nothing is compared with or replaced in the running session;
   4. wrong password → `uv_attempts += 1`; below `UV_MAX_ATTEMPTS = 5` reply `uv_wrong_password` (the ceremony stays `awaiting_verification`); at 5 decline the ceremony (the page gets the browser's own authenticator, as for every decline) and reply `uv_attempts_exhausted`;
   5. correct password → set `verified_at = now`, take the ceremony (single use), and run §3's signing call with the same `now` (so the result is `UV=1`), deliver the result to the tab exactly as an approval does today, clear the badge, reply `uv_ok`; the popup closes.
5. **Cancel** in the popup or in the consent iframe declines the ceremony (`uv_cancelled` to the popup), clears the badge, and the page gets the browser's own authenticator.
6. **Reply codes** (popup ↔ background, extension-internal, shipped in one bundle, so no version field): `uv_ok`, `uv_wrong_password`, `uv_attempts_exhausted`, `uv_ceremony_gone`, `uv_cancelled`, `uv_locked` (the vault locked meanwhile). The popup shows a fixed sentence for each; none echoes input.
7. **One verification at a time per tab.** A tab has at most one pending ceremony (ADR 0043's single-instance rule); a second ceremony request in that tab while one is `awaiting_verification` declines the first.

### 5. Crash, lock, timeout and retry

- **Lock or auto-lock** while `awaiting_verification`: the ceremony store is cleared on lock as today; the popup's next submit gets `uv_locked`; the badge is cleared. `verified_at` goes with the session.
- **Long-lived context or service worker restart:** pending ceremonies and `verified_at` are memory-only and gone. A submit gets `uv_ceremony_gone`. The page's shim timer still runs and falls back to the browser's authenticator. No result is produced from a lost ceremony.
- **Page timeout first:** the shim waits at most `min(publicKey.timeout, 60 000 ms)` (current code). If it fires first, the page has already called the browser's authenticator; a later successful verification still sets `verified_at` and signs only if the ceremony record is still pending and bound, and the relay drops a response whose request nonce has already timed out, so no second credential reaches the page. The ceremony TTL (2 minutes) bounds the record either way.
- **Crash between verification and signing** (inside one core call, §4 step 4.5): the ceremony was taken, nothing was delivered; the page times out to the browser's authenticator. The user retries the passkey; `verified_at` survived unless the context died, so the retry within `UV_FRESH_MS` needs no prompt.
- **Signing fails after a correct password** (e.g. a stored key that will not parse): `verified_at` stays set (the user did verify), the ceremony is consumed, the page receives the same failure path as today's signing failure.
- **Idempotence:** a second `passkey_verify_submit` with the same token after `uv_ok` finds no ceremony and gets `uv_ceremony_gone`; it never signs twice.

### 6. Invariant INV-123 (provisional number)

> **INV-123.** A passkey provider sets `UV` in `authenticatorData` only when a master-password verification (a password unlock or a re-verification in the toolbar popup) succeeded in the same unlocked session no more than `UV_FRESH_MS` before signing, by the host clock, a clock that went back counting as not fresh. A request with `userVerification: "required"` is never answered with `UV=0`: it is either re-verified or not signed. The master password for re-verification is entered only in the toolbar popup. *Milestone:* M2. *Verified by:* Rust unit tests of the flag table (§3) and the freshness boundary (`UV_FRESH_MS` fresh, `UV_FRESH_MS + 1` not, clock back not, restored session not); extension unit tests that a non-popup sender cannot submit a verification and that five wrong passwords decline; e2e: Required + stale → popup → `UV=1`, Preferred + stale → `UV=0` with no prompt.

Mobile providers (M7) are out of scope here: there, the OS's own per-ceremony verification applies and the M7 ADR decides.

### 7. Accepted residual (new THREAT_MODEL AR, number next free at acceptance)

> Passkey user verification by a recent master password. The extension sets `UV=1` for any passkey ceremony within `UV_FRESH_MS` (2 minutes) of the last master-password verification in the unlocked session, without asking again. Someone at the unlocked browser in that window gets `UV=1` assertions, including for `userVerification: "required"`, with one click. Outside the window, an unattended unlocked browser still yields `UP=1, UV=0` assertions for RPs that ask `"preferred"` or `"discouraged"`, and an RP that accepts a passkey without `UV` as a full login is exposed for the whole auto-lock period, as with a filled password (NG-1). The re-verification prompt can be imitated by a page-opened window; the toolbar popup, anchored to the browser's own toolbar, is the defence, as for unlock. Accepted because a per-ceremony prompt for every sign-in would make passkeys slower than the password they replace, and the window is short.

## Consequences

**Positive**
- `UV=1` now means what an RP's step-up assumes: someone typed the master password within the last two minutes. G04-20 closes with a mitigation, a residual and a test.
- The flags are honest for `"preferred"` and `"discouraged"` too; the RP decides what `UV=0` is worth.
- INV-40 is kept: the password is still typed only in the toolbar popup. No new crypto, no new secret, no persistent or server format: the verification reuses the existing local unlock primitive (one Argon2id run per attempt, which also rate-limits guessing).

**Negative**
- **Compatibility (U).** An RP that asks `"preferred"` but in practice rejects or downgrades `UV=0` (asks a password as a second factor, or refuses) now does so for rizzy-vault users who have not typed the master password in the last 2 minutes. Real platform authenticators usually verify on every ceremony, so such RPs may exist (**U**). Open question 2 decides this.
- **UX.** A `"required"` ceremony more than 2 minutes after unlock costs a switch to the toolbar popup and one Argon2id run (≈ the unlock time). On browsers where `openPopup()` does not work from the background (**U**), the user must click the toolbar button themselves.
- **Timeout.** The page's 60-second cap (current shim code) now includes typing the password; a slow user sees the browser's own authenticator dialog. Raising the cap is an implementation tuning, not decided here.
- More extension state: one ceremony state (`awaiting_verification`), two popup messages, six reply codes, a badge.

**Neutral**
- Imported passkeys ([ADR 0074](0074-passkey-cxf-import-export.md), [ADR 0084](0084-bare-cxf-passkey-export.md)) follow the same rule; nothing about a credential records how it was verified.
- WebAuthn security keys for rizzy-vault's own login ([ADR 0082](0082-security-keys-user-presence-only.md)) are unrelated: there rizzy-vault is the RP.

## Alternatives considered

- **Keep `UV=1` from the unlock and record a residual only** (review's second route). Not chosen: it leaves `"required"` meaning "unlocked up to the auto-lock timeout ago", which is the step-up gap itself. It is open question 1's option C.
- **Re-type the master password in the consent iframe.** Rejected: the iframe is inside the page, which can draw a pixel-identical fake and harvest the password; INV-40 forbids it. Changing INV-40 is a goal change the owner would have to make.
- **Open a dedicated extension window (`windows.create` with an extension page) for the password.** Allowed by THREAT_MODEL §A7 ("or an extension page"), works without `openPopup()`, but a page can open a lookalike window with `window.open`, and users are not trained to check a popup window's URL. The toolbar popup is the surface users already unlock in. Kept as the fallback if open question 1's answer makes the popup impractical.
- **Always prompt for `"required"` (window 0).** The strictest reading of WebAuthn. Open question 1, option A.
- **Refuse `"required"` outright** (fall back to the browser's authenticator). Simple and honest, but makes rizzy-vault passkeys unusable for exactly the RPs that care most.
- **Per-ceremony PIN or OS biometric.** Needs an OS keystore integration the extension does not have; a later keystore ADR can add it to §2 point 3's list.

## Open questions for the owner

1. **How fresh must the verification be?** (a) **Option B, a window of `UV_FRESH_MS` = 2 minutes** (this ADR); (b) option A, always re-verify a `"required"` ceremony (window 0); (c) option C, keep today's "unlock = UV" and record it as an accepted residual; or B with another length (5 minutes would match `REAUTH_WINDOW_MS` and `FRESH_SESSION_MS`). *Recommendation:* **B with 2 minutes.** A user who has just unlocked to sign in is not asked twice; a browser left unlocked for longer cannot pass a step-up with a click. A is the most correct but asks for the password on almost every step-up; C keeps the gap.
2. **What does `"preferred"` get when the verification is not fresh?** (a) **`UV=0`, no prompt** (this ADR); (b) prompt as for `"required"`. *Recommendation:* **(a).** `"preferred"` is also the WebAuthn default, so (b) would prompt on most passkey sign-ins and make the window the only thing between the user and a password prompt every 2 minutes; (a) is honest and lets the RP decide. If owner testing finds major RPs that reject `UV=0` under `"preferred"` (**U**), revisit.

## On acceptance

Not made now; the owner's acceptance triggers them, in one docs change:
1. [ADR 0039](0039-passkeys-vault-and-extension.md) Status line: "Partially superseded by ADR 0110 (§2, "User verification and presence")", set by the owner (ADR 0020 points 3, 4, 9).
2. [THREAT_MODEL](../THREAT_MODEL.md) "Passkey provider (M2; ADR 0039)": add a sixth mitigation bullet: "`UV` is set only within `UV_FRESH_MS` of a master-password verification; `userVerification: "required"` outside it is re-verified in the toolbar popup or not signed ([INV-123](#8-security-invariants), [ADR 0110](adr/0110-passkey-user-verification.md))."
3. THREAT_MODEL §8: add the INV-123 row (§6), with its final number; add to INV-64's "Verified by" "; the `UV` cases of INV-123".
4. THREAT_MODEL §9: add the accepted residual of §7 with the next free AR number.
5. [docs/adr/README.md](README.md): the row's status column; the CLAUDE.md status list (the lead's change).
6. The answers to the open questions, recorded in this ADR as owner answers, with `UV_FRESH_MS` and §3's "Preferred, not fresh" row adjusted if the answers differ.

## Implementation plan

Only after acceptance; one track, M2.
1. **`rizzy-client` (`passkey/wire.rs`, `passkey.rs`).** `authenticator_data_assertion` / `_registration` take a `UserVerified` flag instead of hard-coding `FLAG_UV`; a `UvRequirement` enum with a parser for §1 point 2; `fn is_fresh(verified_at: Option<u64>, now_ms: u64) -> bool` with `UV_FRESH_MS`. Tests: known-answer flag bytes `0x1D`/`0x19`/`0x5D`/`0x59`; the §3 table as a table test; freshness at `t`, `t + UV_FRESH_MS` (fresh), `t + UV_FRESH_MS + 1` (stale), `t − 1` (stale), `None` (stale); parser cases `"required"`, `"discouraged"`, `"preferred"`, `"REQUIRED"` (→ Preferred), absent.
2. **`rizzy-wasm` session.** `verified_at` set on password unlock only; `verify_user(password, now_ms)`; `passkey_assertion` / `create_passkey` take the requirement and `now_ms` and return `UvRequired` without producing a signature. Tests: a session restored from a snapshot has `verified_at = None`; a keystore unlock does not set it; Required + stale returns `UvRequired` and no bytes; wrong password leaves `verified_at` unchanged.
3. **Extension.** Shim and `passkey-protocol.ts`: the bounded `userVerification` field; `passkey-ceremony.ts`: the `awaiting_verification` state and `uv_attempts`; `core-context.ts`: §4's flow; messaging contract: `passkey_verify_pending` / `passkey_verify_submit` with the popup-only sender check; popup verification view; consent iframe labels; badge. Unit tests: protocol guard (17-unit string dropped), store transitions (approve → awaiting → ok; TTL expiry while awaiting; lock clears; second request declines the first), sender check (content-script and iframe senders refused), five wrong passwords decline, binding change between approve and submit declines.
4. **e2e (`apps/extension/e2e/passkey.spec.ts`, `webauthn-verify.ts`).** `webauthn-verify.ts` asserts the flags byte. Cases: Required right after unlock (no prompt, `UV=1`); Required with a stale verification (popup view appears, password typed, `UV=1`); Preferred stale (`UV=0`, no prompt); wrong password five times (falls back to the browser's authenticator); lock while awaiting (`uv_locked`). Staleness in e2e needs a controllable clock in the long-lived context; the implementer uses an injected clock that only the test build can set and documents it.
5. **Docs.** `wire.rs` module comment; the On-acceptance edits if not already made.

## References

- Review: [2026-10-25 gap review](../reviews/2026-10-25-adr-gap-review.md) S2; [G04.md](../reviews/2026-10-25-raw/G04.md) G04-20.
- [ADR 0039](0039-passkeys-vault-and-extension.md) §2; [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §2, §3; [ADR 0043](0043-inline-menu-instance-token.md); [ADR 0034](0034-export-reauth-and-plaintext-hold.md) points 1–2; [ADR 0020](0020-partial-supersession.md) points 3, 4, 9; [ADR 0089](0089-extension-frames-and-save-dialog.md) (Proposed; its content-script message list is unchanged, the two new messages come from the popup).
- [THREAT_MODEL](../THREAT_MODEL.md) §A7, "Passkey provider", INV-40, INV-63, INV-64, NG-1; [CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device).
- WebAuthn Level 3 §5.8.6 (`UserVerificationRequirement`), §6.1 (flags), §7.2 (assertion verification): **L**, not re-read for this ADR.
