# ADR 0008: Account recovery: Emergency Kit

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1

## Context

In a zero-knowledge design, "forgot my password" either means the data is gone or there is some other secret that can unlock the account key. ROADMAP §4.3 makes the choice:

- An Emergency Kit (printable Secret Key plus recovery code) is a Must for M1.
- "No recovery = data gone, and the UI says so plainly."
- A server-side reset that can decrypt vaults is a **Won't, ever**.
- Org admin recovery arrives in M10, using explicit, consented escrow.

Escrow and account-recovery paths are the first attack class in the ETH Zurich analysis. Examples include Bitwarden's org admin reset and LastPass's recovery (L). Whatever we build must not give the server, or an admin, a way in.

## Decision

1. **The Emergency Kit is generated on the client only** (HTML/PDF). It contains:
   - the server URL and login name;
   - the Secret Key ([ADR 0004](0004-key-derivation-argon2id-secret-key.md));
   - the recovery code;
   - a blank line for the master password;
   - the sentence "Anyone with this sheet and access to your server can take over your account."

   The server never sees the SK or the recovery code in the clear. Signup finishes only after the user confirms the kit is saved.
2. **Recovery code.**
   - 128 bits from the CSPRNG.
   - Shown as `RVR1-` plus 28 Crockford Base32 characters, using the same encoding and check scheme as the SK.
   - **On by default**, with an explicit opt-out: "forgetting your password = data loss".
3. **Recovery wrap is symmetric.**
   - `E_rec = Envelope(HKDF(code, "recovery/wrap-key"), ACCOUNT_KEY_RECOVERY_WRAP, account_key)`.
   - The server stores `SHA-256(HKDF(code, "recovery/auth-token"))` to authorise a recovery request.
   - A 128-bit code needs no PAKE and no rate-limit crutch, although the endpoint is rate-limited anyway.
4. **Single-use and rotating.**
   - Using the code issues a **new Secret Key and a new recovery code**, which means a new kit. The old kit is assumed lost or compromised.
   - Using the code also **rotates the account key and the vault keys by default** (a standard rotation, [CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation)). "Skip rotation" is an explicit opt-out. Reason: every copy of the old `E_rec` opens with the old code and yields the account key. Routine DB backups taken before the recovery hold such copies, and so does a server that ignored the deletion. Without a rotation, a kit thief with an old backup reads everything written after the recovery too.
   - Rotating the account key for any other reason also issues a new code, unless the user types the current code to keep it.
5. **Waiting period.** A valid code opens a *pending* recovery, and every enrolled device and the account email (if mail is configured) are notified.
   - After a **72 h** wait, admin-configurable from 0 to 30 days, the server releases `E_rec`.
   - Any enrolled device can cancel the pending recovery.
   - The wait is server-enforced. It protects against a kit thief, not against the server, and the server gains nothing by skipping it because it does not have the code.
6. **Recovery flow (Server mode):**
   1. The user presents login name and recovery code.
   2. After the wait, the server returns `E_rec`.
   3. The client unwraps the account key and verifies the identity keys, the bundle and the signed state.
   4. The user sets a new master password, and the client generates a new SK and code.
   5. By default the client runs a standard rotation: new account key and vault keys, item keys re-wrapped, a PSK-mode grant to each remaining device. It enrols itself as a device.
   6. The client re-registers OPAQUE and uploads the new wraps and state atomically.
   7. The server ends every session and notifies all devices and the account email.

   Unknown names and wrong codes get the same response and timing.
7. **On-device mode.** There is no server copy. The encrypted backup file (M4) holds the backup key wrapped twice: under (password + SK) and under the recovery code. No backup file and no device means the data is gone. A recovery through the code issues a new code and SK and rotates the account key by default, as in Server mode.
8. **No escrow in v1.0.**
   - No admin reset.
   - No server-held key that can decrypt a vault.
   - **No email-based reset of anything**, neither the data nor the OPAQUE record, `E_srv`, `E_rec` or 2FA. Email is only a notification channel. The only ways back into an account are the master password plus the SK, an enrolled device, or the recovery code ([CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit)). A mailbox-controlled login reset would let whoever controls the user's mailbox, or the instance's outbound mail, replace the OPAQUE record, lock the owner out and get a session that can delete the vault or cancel a pending recovery. That is the server-mediated reset path of ETH class 1. If a login reset is ever wanted, it needs its own ADR, must be authorised by a statement signed with the account's identity key, and is bounded by threat model INV-66.

   Emergency access (M9) and org recovery (M10) each need their own ADR, with explicit user consent and a construction the user can inspect.

Flows are in [CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit). Key material is in [§4.3](../CRYPTO.md#43-derivations).

## Consequences

### Positive
- A forgotten master password is survivable for anyone who kept the kit.
- The server and the admin gain nothing: an offline attack on `E_rec` means brute-forcing a 128-bit code.
- The recovery wrap is symmetric, so it is not exposed to harvest-now-decrypt-later.
- Every recovery is loud and slow: all devices and the account email are notified, and there is a 72 h window to cancel.
- Because recovery rotates the account key by default, old `E_rec` and `E_srv` copies in DB backups stop covering anything written after the recovery.

### Negative
- **The kit is a bearer credential.** Kit plus network access to the server equals full account takeover, with no password needed, once the wait passes without a cancel. Users must store it like a passport.
- A user who genuinely forgot the password waits 72 h, unless the admin lowered the wait.
- Rotating the account key usually means printing a new kit.
- Recovery costs O(items) small re-wraps and one grant per remaining device. The remaining devices have to log in again with the new password and SK anyway.
- Users who opt out, or lose both the kit and the password with no device left, lose their data. That is the intended trade.

### Risks
- Users will photograph the kit into cloud photo libraries. The UI can warn but not prevent it.
- A user with no enrolled device left, and no email configured, gets no alarm. For them the wait delays a kit thief but does not stop one.
- The admin can set the wait to 0, which brings back immediate takeover with a stolen kit.
- A user who opts out of the rotation leaves every pre-recovery backup able to yield the current account key with the old code.

## Alternatives considered

- **No recovery code, only the SK and password** (roughly 1Password's personal model). Simpler, but ROADMAP asks for a recovery code, and forgotten master passwords are the most common support case.
- **Admin or server reset with key escrow** (Bitwarden org reset). This is ETH attack class 1 and a ROADMAP Won't for v1.0. It is M10 only, with consent.
- **An asymmetric recovery wrap** (HPKE to a key derived from the code). It would allow rotation without the code, but it leaves a long-lived X25519-wrapped account key on the server, exposed to a future quantum attacker.
- **Shamir or social recovery.** It belongs with M9 emergency access, and needs contacts and key authenticity that do not exist yet.
- **Recovery without rotating the account key** (the earlier draft of this ADR). Cheaper, but a kit thief plus any pre-recovery DB backup keeps the current account key. Rejected as the default; kept as an explicit opt-out.
- **Recovery without a waiting period.** Simpler and faster for honest users, but a stolen kit becomes an instant takeover. Rejected, following threat-model Q-15.
- **Email confirmation as the second step.** Many self-hosted instances have no outbound mail, so we use email only as an extra notification channel.
- **Passkey (PRF) recovery.** Post-1.0; iOS support is incomplete (L).

## Open questions for the owner

1. **Recovery code on by default?** *Recommendation:* yes, with the opt-out described above.
2. **Require the current 2FA factor during recovery?** *Recommendation:* no. Recovery is the last resort, often after losing the phone that holds the TOTP. Notification is the safeguard.
3. **Waiting period.** Is the default of 72 h, cancellable by any enrolled device and admin-configurable down to 0, acceptable? *Recommendation:* yes. This answers threat-model Q-15.
4. **Rotate the account key by default on recovery**, with an explicit "skip rotation" opt-out? *Recommendation:* yes (decision 4). The same default applies to an SK change ([CRYPTO.md §11.5](../CRYPTO.md#115-master-password-or-secret-key-change)).
5. **No email-based reset of the login or the data** (threat model Q-16, INV-66). *Recommendation:* confirm decision 8: there is none in v1.0. A login reset, if ever wanted, gets its own ADR with a threat analysis and an identity-key-signed authorisation.

## References

- [CRYPTO.md §7 Secret Key](../CRYPTO.md#7-secret-key), [§11.9 Recovery](../CRYPTO.md#119-recovery-with-the-emergency-kit), [§13 Post-quantum readiness](../CRYPTO.md#13-post-quantum-readiness)
- ROADMAP §4.3 (Emergency Kit, no server-side reset), §4.11 (emergency access), §4.12 (admin recovery)
- Scarlata et al., ePrint 2026/058 (escrow and recovery class)
- [ADR 0004](0004-key-derivation-argon2id-secret-key.md), [ADR 0006](0006-key-hierarchy.md)
