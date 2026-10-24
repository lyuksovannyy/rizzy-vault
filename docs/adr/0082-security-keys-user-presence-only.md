# ADR 0082: Security keys: user presence only (`danger-user-presence-only-security-keys`)

- Status: Proposed
- Date: 2026-10-24
- Deciders: project owner
- Milestone: M3 (`rizzy-domain-auth`, `Cargo.toml` `[workspace.dependencies]`, `apps/web/e2e`)
- Supersedes: [ADR 0077](0077-webauthn-rs-integration-fixes.md) (§2 in part, §7, §9 entries 4, 5, 6, 9 and 13, §10 in part, "Owner answers at acceptance" in part), on acceptance. §2 lists the exact parts and their replacement text.

## Context

[ADR 0058](0058-webauthn-2fa-second-factor.md) added WebAuthn security keys as a server-side second factor; point 4 as accepted read "`UV` not required, `UP` required". [ADR 0077](0077-webauthn-rs-integration-fixes.md) §7 replaced that point (§9 entry 13) with `webauthn-rs`'s default security-key policy and kept `danger-user-presence-only-security-keys` off (§2, §9 entries 4–6 and 9). Its open question 4 offered user presence only as the alternative; the owner accepted the recommendation, the facade default, on 2026-10-23. The implementation (`wip/m3-webauthn`, integrated and full-gated, [docs/HANDOFF.md](../HANDOFF.md) §1) found that the default cannot enrol a key in Chrome or Edge.

**What the facade emits.** Without the feature, `Webauthn::start_securitykey_registration` builds the creation options with `authenticatorSelection.userVerification = "preferred"` and the `credProtect` extension at `userVerificationRequired` with `enforceCredentialProtectionPolicy = false`; `start_securitykey_authentication` requests `"preferred"`. With the feature's builder switch on, registration sends no `credProtect` and `userVerification = "discouraged"` (the policy `UserVerificationPolicy::Discouraged_DO_NOT_USE`, serialised as `"discouraged"`), and authentication requests `"discouraged"` (V, `webauthn-rs` 0.5.5 `src/lib.rs`, the `cred_protect` and `policy` bindings of both functions; `webauthn-rs-proto` 0.5.5 `src/options.rs`). `start_securitykey_registration` takes no extension or policy argument, and the only way to change either is `WebauthnBuilder::danger_set_user_presence_only_security_keys`, which exists only under `#[cfg(feature = "danger-user-presence-only-security-keys")]` (V, `src/lib.rs`). The feature is declared `danger-user-presence-only-security-keys = []`: it enables no dependency, and that setter is the only item it gates (V, the crate manifest and every use of the feature name in `src/`).

**What Chromium does with it.** Chromium refuses `navigator.credentials.create()` with `NotSupportedError` ("Requested protection policy is inconsistent or incongruent with other requested parameters") whenever `extensions.credentialProtectionPolicy` is `"userVerificationRequired"` and `authenticatorSelection.userVerification` is not `"required"`. The browser checks this itself, before any authenticator is asked. The implementation track verified it on 2026-10-24 with a Chrome DevTools Protocol virtual CTAP 2.1 authenticator: the facade's options fail, while UV `"required"`, `credProtect` at `userVerificationOptionalWithCredentialIDList`, and no `credProtect` at all each enrol (V as reported by the implementation track; this ADR did not re-run it). Edge is Chromium-based and behaves the same (L). The integrated web e2e works around it, test-only, by deleting the two `credProtect` members from `webauthn/enrol/start`'s answer before the page sees it (`withoutCredProtect` in [`apps/web/e2e/security-key.spec.ts`](../../apps/web/e2e/security-key.spec.ts), V); the product code was left as ADR 0077 requires. So, as accepted, WebAuthn 2FA cannot be enrolled in the two most used desktop browsers.

**The owner's decision (2026-10-24), verbatim:** "Security keys don't enrol in Chrome or Edge: A", where A is "Touch only, no PIN: enable webauthn-rs's danger-user-presence-only-security-keys feature; keys need a touch, no PIN — what ADR 0058 originally said". This ADR records that decision and names the parts of ADR 0077 it replaces.

**What the core then enforces at login.** `webauthn-rs-core` refuses an assertion without UV only when the request policy or the credential's stored `registration_policy` is `Required`, or when the stored policy is `Preferred` and the credential performed UV at enrolment (V, `webauthn-rs-core` 0.5.5 `src/core.rs`, the `match (&policy, &cred.registration_policy)` in `verify_credential_internal`). A credential enrolled with the switch on stores `Discouraged_DO_NOT_USE`, so it is never asked for UV. A credential enrolled under ADR 0077 §7 stores `Preferred`; if it performed UV at enrolment, the core keeps requiring UV for it. No release has shipped WebAuthn 2FA (V: the repository has no release tag), so such rows exist only on development instances.

**Constraints.** [ADR 0059](0059-webauthn-rs-crate-approval.md) and ADR 0077 forbid every `danger-*` feature except `danger-allow-state-serialisation`, so enabling another one needs an Accepted ADR ([CLAUDE.md](../../CLAUDE.md), the ADR gate). Calling `webauthn-rs-core` directly to send `userVerificationOptionalWithCredentialIDList` was rejected by ADR 0059 and ADR 0077 B2 (b). `cargo xtask check-deps`'s ADR 0030 Decision 3 scan reports the word tokens `danger` and `dangerous` in first-party Rust; `danger_set_user_presence_only_security_keys` is one word token, so the call is not reported (V, `crates/xtask/src/unsafe_scan.rs` `word_tokens`/`is_word`, `crates/xtask/src/rules.rs` `DANGER_WORDS`). The crate's documentation warns that with this feature "newer keys will confusingly force a User Verification on registration, but will then not prompt for this during usage", and that the RP "MUST communicate to the user that the UV *may* occur on registration and then will not occur again" (V, `webauthn-rs` 0.5.5 `src/lib.rs` crate docs).

## Decision

### 1. User presence only

`webauthn-rs` is declared with the feature `danger-user-presence-only-security-keys` added to its two existing features, and `rizzy-domain-auth`'s relying party (`webauthn::relying_party`) calls `WebauthnBuilder::danger_set_user_presence_only_security_keys(true)`. As a result:

- **UP on every ceremony, UV never required.** The key proves possession with a touch. The password and Secret Key have already authenticated the user before KE3 verifies, which is ADR 0058's original reasoning for point 4.
- **Enrolment** requests `userVerification = "discouraged"` and sends no `credProtect` extension. The other creation options are unchanged (ADR 0077 §9 entry 12): attestation `"none"`, `pubKeyCredParams` ES256 then RS256, `excludeCredentials`, the `security-key` hint, and the facade's `uvm` and `credProps` extension requests.
- **Assertions** request `userVerification = "discouraged"`. One that carries UV is accepted like one that does not. One without UP is refused.
- **Credentials enrolled before the switch** keep the `Preferred` policy stored in their `security_key`, and the crate keeps requiring UV for those that performed UV at enrolment. No migration and no rewrite of `security_key` is made for them: no release holds any. Removing and re-adding such a key gives it the new policy.
- **Nothing else changes.** The ceremony state (ADR 0077 §2, and the invariant its §11 item 3 adds), the counter rule (INV-83), RP ID and origin (INV-84), the `openssl` confinement (INV-85), attestation (§5), algorithms (§6) and `deny.toml` stay as they are. No `danger-*` feature other than the two named in §2 entries 3 to 5 is enabled.

The feature adds no dependency and does not change `Cargo.lock` (V, manifest above). The implementation PR re-runs `cargo deny check` and `cargo xtask check-deps` and records the new declaration under ADR 0009's 2026-10-22 Amendments entry, as the 2026-10-24 checklist re-run did.

### 2. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9, each named part of ADR 0077 stops binding when this ADR is Accepted and is replaced by the text given, which binds as Decision text of this ADR. Everything not named stays binding. Where an ADR 0077 §9 entry is named, its replacing text is the whole entry, so that the part of ADR 0009, 0058 or 0059 it rewrites keeps exactly one binding text. ADR 0077's Context (N2), its open question 4 and its "Alternatives considered" and Consequences bullets on UV and PINs are history, not Decision text, and are left as written. About 490 of ADR 0077's 4,130 Decision words are replaced, well within ADR 0020 point 4's limit.

**[ADR 0077](0077-webauthn-rs-integration-fixes.md)**

1. *"Owner answers at acceptance (2026-10-23)", second sentence* ("The recommendations of the "Open questions for the owner" stand.") is replaced by: "The recommendations of the "Open questions for the owner" stand for questions 1 to 3 and 5 to 7. Question 4 is answered with its alternative: `danger-user-presence-only-security-keys`, user presence only, as ADR 0058 point 4 originally read (owner decision of 2026-10-24, [ADR 0082](0082-security-keys-user-presence-only.md))."
2. *§2, first paragraph* (two sentences: "`webauthn-rs` is declared with …" and "No other `danger-*` feature is enabled: …") is replaced by: "`webauthn-rs` is declared with `features = ["attestation", "danger-allow-state-serialisation", "danger-user-presence-only-security-keys"]`. No other `danger-*` feature is enabled: `danger-credential-internals` and every future one stay off. `danger-user-presence-only-security-keys` is used only as [ADR 0082](0082-security-keys-user-presence-only.md) §1 gives it."
3. *§9 entry 4* is replaced by: "4. *Amendments, 2026-10-22 entry, the "Added to the required feature sets" bullet* is replaced by: "- `webauthn-rs`: `default-features = false`, `["attestation", "danger-allow-state-serialisation", "danger-user-presence-only-security-keys"]`. Never `resident-key-support`, `conditional-ui`, `workaround-google-passkey-specific-issues` or any other `danger-*` feature; `danger-allow-state-serialisation` is used only to keep ceremony state in `auth_` rows under [ADR 0077](0077-webauthn-rs-integration-fixes.md) §2, and `danger-user-presence-only-security-keys` only to make security keys user-presence-only under [ADR 0082](0082-security-keys-user-presence-only.md) §1.""
4. *§9 entry 5* is replaced by: "5. *Decision, "Recommendation", the fenced TOML declaration* (a standalone code block, named whole as the smallest part, like a sentence) is replaced by:
   ```toml
   webauthn-rs = { version = "=0.5.5", default-features = false, features = ["attestation", "danger-allow-state-serialisation", "danger-user-presence-only-security-keys"] }
   ```"
5. *§9 entry 6* is replaced by: "6. *Decision, "Recommendation", the sentence beginning "Never `resident-key-support`"* is replaced by: "Never `resident-key-support` (discoverable passkeys as a sole factor are ROADMAP §4.3's post-1.0 "Could," out of this ADR's and ADR 0058's scope), `conditional-ui` or `workaround-google-passkey-specific-issues` (passkey-specific, not security-key 2FA), and never a `danger-*` feature (each is named for exactly what CRYPTO.md Rule 6, fail closed, forbids weakening) except two: `danger-allow-state-serialisation`, which adds only `Serialize`/`Deserialize` to the in-progress ceremony state types and is used only to keep that state in `auth_` rows under ADR 0077 §2; and `danger-user-presence-only-security-keys`, which gates only the builder method that makes security keys user-presence-only and is used only as ADR 0082 §1 gives it.""
6. *§9 entry 9* is replaced by: "9. *Owner answer 1* is replaced by: "1. `webauthn-rs` `=0.5.5` is approved, with `default-features = false, features = ["attestation", "danger-allow-state-serialisation", "danger-user-presence-only-security-keys"]`, confined to `rizzy-domain-auth`.""
7. *§7* (the whole subsection, heading included) is replaced by:
   "### 7. User verification: user presence only (`danger-user-presence-only-security-keys`)

   ADR 0058 point 4 is replaced (§9 entry 13). `rizzy-domain-auth` builds its relying party with `WebauthnBuilder::danger_set_user_presence_only_security_keys(true)` ([ADR 0082](0082-security-keys-user-presence-only.md) §1). UP is required on every ceremony and UV never is: enrolment requests `userVerification = "discouraged"` and sends no `credProtect` extension, and assertions request `"discouraged"`. This is ADR 0058's floor. A key with a PIN is not asked for it at login; whether a key asks for its PIN at enrolment despite `"discouraged"` is the key's own behaviour, outside our control."
8. *§9 entry 13* is replaced by: "13. *Point 4* is replaced in full by: "4. **Non-discoverable; user presence only.** The password and Secret Key already authenticated the user before KE3 verifies, so the key need only prove possession: `UP` is required on every ceremony and `UV` is never required. `rizzy-domain-auth` builds its `webauthn-rs` relying party with `danger_set_user_presence_only_security_keys(true)` ([ADR 0082](0082-security-keys-user-presence-only.md) §1): enrolment requests `userVerification = "discouraged"` and no `credProtect` extension, and assertions request `userVerification = "discouraged"`. A credential enrolled this way asserts with UP alone, whether or not the key performed UV. Credentials are server-side (non-discoverable): no usernameless/account-chooser flow, since the account is already known.""
9. *§10, the bullet beginning "UV (N2)"* is replaced by: "- UV ([ADR 0082](0082-security-keys-user-presence-only.md)): the enrolment options carry `userVerification` `"discouraged"` and no `credProtect` member, and the assertion options carry `"discouraged"`; a credential that performed UV at enrolment asserts with UP alone and is accepted; a credential enrolled with UP alone asserts with UP alone; an assertion without UP is refused."

### 3. Tests and checks the implementation PR adds

- `rizzy-domain-auth` (`tests/auth/webauthn.rs`): §2 entry 9's cases (the replaced ADR 0077 §10 bullet) replace `user_verification_follows_enrolment`'s first half (a UV-enrolled key asserting with UP alone is now accepted), on both engines; a test reads the enrolment and assertion options and checks `"discouraged"` and the absence of `credProtect`.
- Web e2e: the test-only `withoutCredProtect` interception and its header comment are removed from `apps/web/e2e/security-key.spec.ts`. Enrolment, login and removal run with Chromium's virtual authenticator against the server's real options. The accessibility audit and the keyboard walk stay as they are.
- The module docs of `crates/rizzy-domain-auth/src/webauthn.rs` ("User verification (§7)") follow §1.
- Firefox and Safari are not covered by the e2e and have not been tried. The implementation PR records any manual check it makes, with browser, version and key.

## Consequences

### Positive

- Security keys enrol in Chrome and Edge. The options no longer contain the `credProtect` request Chromium refuses; the CDP check enrolled with no `credProtect` (with `"preferred"`). `"discouraged"` with no `credProtect` is not the combination the browser refuses (L), and the e2e without interception confirms it.
- The second factor is what ADR 0058 accepted: a touch, no PIN. Keys without a PIN and keys with one behave alike.
- The e2e tests the product's own options. The test-only rewrite of a server response goes away.
- No new dependency, no `Cargo.lock` change, no `deny.toml` change, no new persistent format.

### Negative

- A second `danger-*` feature is enabled. Its effect is one builder method, and §1 uses it in exactly one place.
- PIN-capable keys do not ask for their PIN at login. ADR 0077's "a PIN-protected key adds the PIN as a third proof" is lost. Someone who already holds the master password and the Secret Key needs only physical possession of the key, not its PIN.
- Without `credProtect`, the authenticator applies its default protection level to the credential. For a non-discoverable credential this changes little: using it still needs the credential id, which the server sends only after KE3 verifies (ADR 0058 point 3).
- INV-83, INV-84, INV-85 and ADR 0077 §11 item 3's ceremony-state invariant are unchanged. Nothing here weakens the counter rule or the RP binding.

### Risks

- **PIN prompt at enrolment.** Some newer keys may still ask for their PIN when they are added, then never at login. The crate's documentation warns this confuses users (Context). Signal: user reports. Response: open question 1's hint.
- **Firefox and Safari.** Untested. A browser that refuses `"discouraged"` for security keys, or treats the missing `credProtect` differently, would block enrolment there (U). Signal: a manual check or a user report. Response: a new ADR.
- **The feature changes or goes away** in a later `webauthn-rs` release. Signal: the build fails on the version bump, which needs an ADR 0009 checklist re-run anyway.
- **Development rows enrolled under ADR 0077 §7** keep asking for UV if they performed it. Signal: a developer's login refused with `UserNotVerified`. Response: remove and re-add the key; there are no production rows.

## Alternatives considered

- **Keep ADR 0077 §7 (UV `"preferred"`, `credProtect` UV-required).** Chromium refuses it, so Chrome and Edge users cannot enrol a key at all. Lost.
- **UV `"required"`.** Enrols in Chromium, but every key needs a PIN or biometric, and a key without one cannot be used, or the browser asks the user to create a PIN. That is stricter than ADR 0058's floor and was not the owner's choice. Lost.
- **`credProtect` at `userVerificationOptionalWithCredentialIDList`.** Chromium accepts it, but the facade cannot send it: there is no setter (Context). Sending it needs `webauthn-rs-core` directly, which ADR 0059 and ADR 0077 B2 (b) rejected. Lost.
- **The web client strips or lowers `credProtect` before calling `create()`** (option (b) in [docs/HANDOFF.md](../HANDOFF.md) §1). It works because the server does not enforce the extension, but every client (web, extension, and the future native ones) would have to rewrite the server's options the same way, and what the server's ceremony state records as requested would differ from what the browser sent. That is the e2e's test-only workaround, not a design. Lost.
- **Wait for an upstream fix** in `webauthn-rs`. There is no date, and WebAuthn 2FA would stay unusable in Chrome and Edge until then. Lost.

## Open questions for the owner

1. **Tell users at enrolment that the key may ask for its PIN once?** The crate's documentation says the RP must say so (Context). *Recommendation:* yes. Add one sentence to the "Add security key" dialog: "Your key may ask for its PIN while it is being added. Signing in will only need a touch." It is shown in the web vault, and in each native client when they gain the feature. It changes no protocol.

## References

- [ADR 0058](0058-webauthn-2fa-second-factor.md) point 4 (as accepted); [ADR 0059](0059-webauthn-rs-crate-approval.md); [ADR 0077](0077-webauthn-rs-integration-fixes.md) §2, §7, §9, §10 and open question 4; [ADR 0009](0009-crypto-dependency-policy.md) (Amendments, 2026-10-22 entry); [ADR 0020](0020-partial-supersession.md) points 4 and 9; [ADR 0030](0030-client-tls-rv.md) Decision 3.
- [CRYPTO.md §11.17](../CRYPTO.md#1117-webauthn-2fa-m3); [THREAT_MODEL.md §8](../THREAT_MODEL.md#8-security-invariants) (INV-83 to INV-85); [docs/HANDOFF.md](../HANDOFF.md) §1 (2026-10-23/24 batch, the WebAuthn blocker).
- `webauthn-rs` 0.5.5 `src/lib.rs` (`WebauthnBuilder::danger_set_user_presence_only_security_keys`, `start_securitykey_registration`, `start_securitykey_authentication`, crate docs) and `Cargo.toml` (`[features]`); `webauthn-rs-core` 0.5.5 `src/core.rs` (`verify_credential_internal`); `webauthn-rs-proto` 0.5.5 `src/options.rs` (`UserVerificationPolicy`). V, read in the local cargo registry for this ADR.
- Chromium's `NotSupportedError` for `credProtect` `userVerificationRequired` without UV `"required"`: V as reported by the implementation track (`wip/m3-webauthn`, CDP virtual CTAP 2.1 authenticator, 2026-10-24); Chromium source not read for this ADR.
- W3C WebAuthn Level 3 (`userVerification`), CTAP 2.1 (`credProtect` extension): L.
