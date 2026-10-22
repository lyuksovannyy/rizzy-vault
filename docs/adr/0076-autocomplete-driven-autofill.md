# ADR 0076: Autocomplete-driven autofill: field detection, TOTP-code fill and custom-field autocomplete ids

- Status: Accepted
- Date: 2026-10-22
- Deciders: project owner
- Milestone: M3 (`rizzy-core`, `rizzy-client`, `rizzy-wasm`, web vault editor, browser extension)
- Supersedes: [ADR 0018](0018-item-record-encoding.md) (§7 in part), [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) (§4 in part) and [ADR 0040](0040-extension-fill-request-from-inline-menu.md) (point 2; "What this ADR supersedes" in part), on acceptance. §9 lists the exact parts.

## Context

**The owner's request (2026-10-21), verbatim:** "its good to have adaptation that checks for autocomplete="X" fields which will at the end fulfill them using manager's saved data, so lets say: usual managers detect common username, password and totp (some of them overdetect totp in places where its not an totp) fields, our manager must do the same (except overdetection), it must respect autocomplete field and if autocomplete has custom value like "custominput" it will as well save for it a value if entered in manager, custom fields can be added, each custom field uses Display Name (required) and optional "autocomplete id" under its config which allows to mark which autocomplete value must field have in order to autofill it. also ensure that manager wont allow autocomplete collisions, like username, password, totp, etc that are reserved for manager it self and wont allow same autocomplete values in custom fields per saved profile".

That breaks down into six requirements:
- **R1.** Detect username, password and TOTP fields, and honour the page's `autocomplete` attribute.
- **R2.** Do not over-detect TOTP fields.
- **R3.** A custom field has a required Display Name and an optional autocomplete id. A page field whose `autocomplete` equals that id gets the custom field's value.
- **R4.** Values the manager owns (username, password, TOTP and the like) are reserved: no custom field may use them.
- **R5.** Within one item, no two custom fields share an autocomplete id.
- **R6.** If the user typed a value into a field with a custom token, the manager can save it.

**Scope.** [ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2) has the M2 Must row "Browser extension: Chromium (MV3) + Firefox — inline menu, fill, save/update on submit, generator in field" and the M3 Could row "Heuristic multi-step login form support". It has no row for TOTP-code fill or custom-field fill. The ROADMAP is the source of truth for scope, and an ADR does not add any ([ADR 0020](0020-partial-supersession.md) point 7). Open question 1 asks the owner for the row. This ADR can be reviewed without it, but its code cannot be merged until the row exists.

**What already binds** (Accepted):
- **[ADR 0018](0018-item-record-encoding.md) §7** defines custom fields as `field/<id>/label` · `/kind` · `/value` · `/order` only. `kind` is 1 text, 2 hidden or 3 boolean, and hidden values are concealed by default. §6 says "`order`, `match` and `kind` are layout attributes and never make an element exist", so any other attribute is a content attribute. `rizzy-core`'s `order.rs` reads it the same way ("Unknown attributes are content"). Under §11, an unknown key that fits the grammar is merged, snapshotted and exported byte for byte, and "an edit writes only the keys the user changed". §7 also says "A new key needs a line in the ADR that ships it, never a version bump". `rizzy-client`'s `lists.rs` removes a list element by writing Cleared to every current register under the element's prefix, unknown attributes included (only `Writers::NotInM1` keys are skipped), so a removal on an old client also clears an attribute that old client does not know (V, `crates/rizzy-client/src/lists.rs:633-648`).
- **[ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4**, with [ADR 0040](0040-extension-fill-request-from-inline-menu.md):
  - The content script sends detected-field reports and submitted-credential reports only.
  - The fill request comes from the extension-origin inline-menu iframe, on an `event.isTrusted` click.
  - The long-lived context recomputes the candidate set for the browser-vouched top-frame URL before it decrypts anything.
  - Only the chosen fill's values cross, to the content script, at fill time.
  - List views show title, username and icon only ([ADR 0013](0013-shared-client-core.md) §3 rule 3).
- **[ADR 0037](0037-url-matching-and-autofill-rules.md) §5** sets the fill rules: gesture-only fill, no HTTPS → HTTP fill, no fill into cross-origin iframes, no fill into hidden fields, the equivalence-only warning and the exact host shown.
- **[ADR 0013](0013-shared-client-core.md) §3**: rule 3 lets a secret value cross only when the user reveals it, and rule 6 requires one coarse call per user action.
- **[ADR 0012](0012-sync-engine.md) §4 step 5 and ADR 0018 §6**: concurrent writes to one register keep every value. The displayed value is the one highest in (`hlc`, `device_id`, `seq`). A list sorts by `order`, then by element id. Two devices that set the same autocomplete id on two fields at the same time therefore both keep it after the merge. No write check can prevent that, so the fill must resolve it deterministically.
- **[CRYPTO.md §11.15](../CRYPTO.md#1115-totp-m1)** fixes TOTP: SHA1, SHA256 or SHA512; 6–8 digits; a period of 1–300 s; one implementation in `rizzy-core`. `rizzy-wasm`'s `Session::totp(id, now_ms)` already returns the code computed from `login.totp` and never the secret (V, `crates/rizzy-wasm/src/session.rs:809-834`). An HOTP URI is refused there (`totp_params()` is `None`). Item summaries carry `has_totp` (V, `crates/rizzy-wasm/src/items.rs:265`).
- **[THREAT_MODEL](../THREAT_MODEL.md) A7** (malicious page scripts), **INV-36** (nothing is filled without a trusted user gesture), **INV-37** (no HTTPS → HTTP fill, no fill into cross-origin iframes, no fill into hidden fields), **INV-40** (fill UI in an extension-origin context; every content-script message is untrusted).

**Today's extension** (V, read on this branch):
- `apps/extension/src/content/login-step.ts` classifies each top-frame `<input>` from `InputFacts`: type, the raw `autocomplete` string, hints (name, id, placeholder, aria-label, label texts), `visible`, `editable` and `form`.
  - The identifier signal is strong for `username` and `webauthn`; weak for `email`, `type=email` or an identifier hint; never for `one-time-code`, `new-password`, `current-password` or a `NOT_IDENTIFIER_HINT` such as otp, 2fa, verification or code.
  - The first visible, editable password field makes the step a password step, whatever its `autocomplete` says.
  - The steps are `username_and_password`, `username` and `password`.
- `messaging/contract.ts` carries the multi-step narrowing in `InlineMenuFillRequestMessage.only` (`"username" | "password"`). The long-lived context applies it in `narrowFillValues` (`core-host/content-handler.ts:291`). `FillValues` holds `username` and `password` only, keyed by kind and never by field id.
- Limits: `MAX_MESSAGE_BYTES` 64 KiB, `MAX_FIELD_VALUE_LEN` 4096, `MAX_FIELDS_PER_REPORT` 64, `MAX_TITLE_LEN` 256.
- The save/update banner renders in the page's own DOM, a documented residual (`content-script.ts:1180-1189`): the page can call `.click()` on it, or change its state, without a trusted event.

**The WHATWG autofill grammar** (V, [HTML Living Standard, "Autofill"](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill), read 2026-10-22):
- The attribute is an ordered set of space-separated tokens, matched ASCII case-insensitively.
- It is either the single token `off`, the single token `on`, or autofill detail tokens. In order, those are:
  - optionally a `section-*` token;
  - optionally `shipping` or `billing`;
  - either one autofill field name, or optionally one of `home` `work` `mobile` `fax` `pager` followed by a contact field name;
  - optionally `webauthn`.
- `one-time-code` is "One-time code used for verifying user identity". iOS uses it for SMS codes too, so the token alone does not mean TOTP (L, general knowledge).
- A token outside the grammar makes the attribute non-conforming. The browser's own autofill then treats it as if it were absent or `on` (L).

## Decision

### 1. Detection

The content script keeps detecting in the top frame only, against the visibility and topmost gate (A7, INV-37), as `login-step.ts` does today. What follows changes how each `<input>` is classified. It never widens what may be filled, which §4 governs.

**1.1 Parsing the `autocomplete` attribute.** Parsing is a pure function in `login-step.ts` (or a sibling module), unit tested in Node:

1. A missing or empty attribute, one longer than 256 characters, or one with more than 8 tokens is **none**.
2. ASCII-lowercase the value and split it on ASCII whitespace. A single `on` is **none**, and a single `off` is **off**.
3. If the last token is `webauthn`, set the webauthn flag and drop the token.
4. If the remaining tokens form WHATWG autofill detail tokens (the order above, the field and contact names of §3 table rows 2–4), the result is **standard(F)**, where F is the field name.
5. Otherwise, if exactly one token remains, the webauthn flag is clear, and the token matches §2's `ac_id` grammar and is not in §3's reserved set, the result is **custom(t)**.
6. Otherwise it is **none**. Anti-autofill junk such as `nope` or `false` falls under rule 5. That is harmless: such a token fills nothing unless the user gave a custom field exactly that id.

**1.2 Roles.** Each visible, editable `<input>` gets at most one role in the detected step:

| Parsed attribute | Role |
|---|---|
| standard(`username`), or the webauthn flag | Identifier, strong signal (as today) |
| standard(`email`), standard(`tel`), standard(`tel-national`) | Identifier, weak signal (today's `type=email`/`type=tel` rules apply) |
| standard(`current-password`) | The password target |
| standard(`new-password`) | Never the target of a saved password. The inline menu offers the generator there (ROADMAP §4.4 "generator in field"). Open question 5 |
| standard(`one-time-code`) on type text, tel, number or password | The TOTP target, unless the field's own hints carry a §1.3 rule (c) delivery word (sms, text message, phone, e-mail, …). A password-type input with this token is never the password target |
| any other standard(F) (address, card, name, birthday, transaction tokens) | No role. Never a username, password, TOTP or custom target |
| none, off | Today's username/password heuristics (`login-step.ts`, unchanged), then the TOTP heuristic of §1.3 |
| custom(t) | Today's username/password heuristics, but **not** the TOTP heuristic. The field is also a custom target for `t` (§4.3) |

- **`off` counts as absent for detection.** Sites put `off` on login and 2FA fields to stop the browser's own autofill, and browsers ignore `off` on login fields (L, general knowledge). Nothing is filled because of detection alone, since every fill still needs a click (INV-36).
- **The heuristics apply only where the page declared no WHATWG field name** (none, off or custom). A declared field name always wins, so a field marked `cc-csc` or `postal-code` is never offered a TOTP, however it looks.
- **Custom tokens do not switch off the username/password heuristics.** Junk tokens on real login fields are common, so switching them off would break logins that work today. §4.3 resolves the overlap per item instead.

**1.3 The TOTP heuristic (attribute none or off).** A field is a TOTP target only if **every** rule holds:
- (a) Type text, tel or number; visible and editable; not the step's username or password target.
- (b) Its hints match `totp|2fa|two-?factor|2-?step|two-?step|mfa|tfa|otp|one-?time|authenticator|auth(entication)?[-_ ]?code|verification[-_ ]?code|verify[-_ ]?code`. The word `code` alone is not enough.
- (c) Its hints do not match `sms|text ?message|texted|phone|mobile|e-?mail|sent to|cvc|cvv|csc|card|security ?code|\bpin\b|zip|postal|post ?code|captcha|coupon|promo|voucher|gift|referral|invite|backup|recovery|search`. A negative always wins.
- (d) It is numeric-shaped: `inputmode="numeric"`, or type tel or number, or `maxlength`/`minlength` within 6–8. If `maxlength` is set, it is between 6 and 8.
- (e) It is the only field in its form, or among the form-less fields, that passes (a)–(d).
- (f) Its form does not look like a sign-up, checkout or contact form: `NOT_LOGIN_FORM_HINT` does not match, and the form has no visible `new-password` field.
- (g) When the menu would be shown, at least one ADR 0037 candidate for the top-frame URL has a valid time-based `login.totp` (`hasTotp`, §4.1). Otherwise no menu appears at that field.

Rule (g) is the main defence against over-detection (R2): a TOTP offer appears only where a saved login for this site can actually produce a code. Rules (a)–(f) keep it off fields that are not TOTP inputs even on such sites.

**1.4 Negative cases** never offer a TOTP fill. Each case is a test fixture (§10):
1. Card security code: `cc-csc`; hints cvc, cvv, csc or "security code"; `maxlength` 3–4.
2. Card number and expiry (`cc-*`).
3. SMS verification ("code we sent to your phone", sms, `tel` context), including `one-time-code` with SMS hints.
4. Email verification codes.
5. PINs: hint `pin` (also India's 6-digit "PIN code" postal field), `maxlength` 4, password-type PIN fields.
6. Postal and ZIP codes, including 6-digit numeric ones (`postal-code`, zip, postal, postcode).
7. Phone numbers and `tel-*` tokens.
8. Captchas, coupon, promo and gift-card codes, referral and invite codes.
9. Backup and recovery-code fields.
10. Split-digit inputs (six `maxlength=1` boxes). Rule (e) excludes them, so they are never filled. Filling them is a later change.
11. A field whose only hint is "code".
12. Sign-up, checkout and contact forms.
13. Hidden, off-screen, covered, read-only or disabled fields, and fields in any iframe.
14. A site's TOTP step when no candidate holds a time-based secret (HOTP included).

### 2. Item format: `field/<id>/autocomplete` and the Display Name

**2.1 The key.** `field/<id>/autocomplete` is a new attribute of the custom-field list, value type Text. It holds the field's **autocomplete id**.
- It is a **content attribute** under ADR 0018 §6, unchanged: only `order`, `match` and `kind` are layout attributes. So a field whose only non-empty attribute is its autocomplete id still exists. It shows as an unnamed field with an empty value and fills nothing. Old and new clients therefore agree on which fields exist.
- It is **not concealed**. It is a name, like `label`. Whether an M5 share carries it is for the share ADR to decide.
- Writers write Cleared to remove it, never an empty Text (ADR 0018 §6).
- No `item_schema_version` bump (ADR 0018 §11).

**2.2 Grammar** (RFC 5234):

```
ac_id = 1*64( %x61-7A / DIGIT / "-" / "_" / "." )   ; lowercase ASCII token, 1–64 bytes
```

The id must also not be in the reserved set (§3), and must not begin with `section-`. It holds no whitespace, because whitespace separates tokens in the HTML attribute, and no uppercase, because the page side is matched after ASCII-lowercasing. The web and CLI editors lowercase ASCII input before writing. `rizzy-client` rejects, and never normalises, a non-conforming id it is asked to write.

**2.3 Writer checks.** `rizzy-client` runs these on every write path that can set or keep a custom field: add, edit, conflict resolution ("pick one" and "keep both"), history restore, import and the CLI. Every client therefore enforces them identically. The grammar and the reserved set are a pure function in `rizzy-core`'s `item` schema module, which owns value meaning (ADR 0018 §2). The item-state checks are in `rizzy-client`. Errors are typed codes that never echo the id or the label (ADR 0013 §3 rule 4, ADR 0018 §2):
- **W1 `AutocompleteInvalid`:** the id breaks §2.2.
- **W2 `AutocompleteReserved`:** the id is in §3's set.
- **W3 `AutocompleteDuplicate`:** after the write, another existing custom field of the same item displays the same id. The check applies to a write that sets an id. A write that leaves an existing merge-made duplicate in place (§2.5) is not refused, so an unrelated edit never locks the item.
- **W4 `AutocompleteKind`:** an id is set on a boolean (3) or unknown kind, or a field that has an id is changed to such a kind in an op that does not also clear the id.
- **W5 `LabelRequired`:** a write that creates a custom field, or edits any attribute of an existing one other than removing it, must leave its displayed `label` holding at least one non-whitespace character. This makes the Display Name required (R3). `field/<id>/label` *is* the Display Name; there is no second key.

**2.4 Existing label-less fields.** Fields that M1–M3 clients or importers wrote without a label stay valid data. They are shown as "Unnamed field". They still display and copy. They cannot be given an autocomplete id until they are named, and they never fill (§4.3). An edit to one prompts for a name (W5). Importers keep a source field's empty name, rather than invent one (open question 4).

**2.5 Merge-made duplicates.** Two devices can concurrently set the same id on two different fields of one item. The merge then keeps both.
- **Resolution at fill time** is deterministic on every replica. Of the existing fields that display a given fillable id (§4.3), only the **first in list order** fills: `order`, then element id (ADR 0018 §6). The others are *shadowed*.
- **A visible warning.** The editor marks every shadowed field: "Autocomplete id `x` is also used by '<Display Name of the winner>'; only that field is filled. Change or clear one." The inline menu lists only the winner.
- **Resolving it** is an ordinary edit: changing or clearing one id passes W3.
- **A conflicting register.** When one field's own autocomplete register holds several concurrent values, its displayed value counts (ADR 0018 §6). The editor shows the conflict as for any field.

**2.6 Old clients**, which do not know this key:
- They carry it byte for byte, merge it, snapshot it and export it in rizzy's own export (ADR 0018 §11).
- An edit of the field's label or value keeps it.
- Removing the field clears it (`lists.rs`).
- They never set it, so they cannot create a duplicate. They do not enforce W5.

None of this needs a forced update.

### 3. Reserved values

The manager owns this set R. No custom field may use a value in it (W2), and none is ever matched as a custom token (§1.1 rule 5, §4.3):

| # | Values | Why reserved |
|---|---|---|
| 1 | `on`, `off`, `webauthn`, `shipping`, `billing`, `home`, `work`, `mobile`, `fax`, `pager`, and any value beginning with `section-` | WHATWG keywords and prefix tokens: they qualify a field and never name one |
| 2 | `username`, `current-password`, `new-password`, `one-time-code` | The login roles the manager fills from `login.username`, `login.password`, the generator and `login.totp` |
| 3 | Every other WHATWG autofill field name: `name`, `honorific-prefix`, `given-name`, `additional-name`, `family-name`, `honorific-suffix`, `nickname`, `organization-title`, `organization`, `street-address`, `address-line1`, `address-line2`, `address-line3`, `address-level4`, `address-level3`, `address-level2`, `address-level1`, `country`, `country-name`, `postal-code`, `cc-name`, `cc-given-name`, `cc-additional-name`, `cc-family-name`, `cc-number`, `cc-exp`, `cc-exp-month`, `cc-exp-year`, `cc-csc`, `cc-type`, `transaction-currency`, `transaction-amount`, `language`, `bday`, `bday-day`, `bday-month`, `bday-year`, `sex`, `url`, `photo` | The meanings are standard. Future Identity and Card autofill (`identity.*`, `card.*`, ADR 0018 §7) would own them |
| 4 | WHATWG contact names: `tel`, `tel-country-code`, `tel-national`, `tel-area-code`, `tel-local`, `tel-local-prefix`, `tel-local-suffix`, `tel-extension`, `email`, `impp` | As row 3. `email` and `tel` are also identifier signals today (§1.2). Open question 3 |
| 5 | Manager aliases: `password`, `totp`, `otp`, `2fa`, `mfa`, `passkey` | The owner's "username, password, totp, etc". Non-standard spellings that pages use for those roles |

- **The set is frozen by this ADR.** Changing it needs a new ADR. Shrinking it later is compatible: it only allows more ids. Growing it can turn a stored id unusable.
- **A stored id that a later reserved set covers** is never filled as custom. The editor shows it with W2's error until the user changes it.
- **Why the whole WHATWG list:** relaxing the set later breaks nothing, whereas tightening it would orphan stored data. It also keeps a custom field from shadowing a field the manager or a future item-type autofill owns.

### 4. Fill

Every ADR 0037 §5 rule applies unchanged: gesture-only fill, no HTTPS → HTTP, the top frame only (a same-origin iframe counts as the top frame), visible fields only, the equivalence-only confirmation and the exact host. TOTP and custom fills are offered only from the inline menu, not from the popup. Each step is its own click: nothing chains a TOTP fill after a password fill, and no code is copied to the clipboard automatically.

**4.1 Scope and offer.** The content script describes the step it detected as a **fill scope**:

```ts
interface FillScope {
  only?: "username" | "password" | "totp"; // today's narrowing; "totp" = a TOTP-only step
  totp?: true;                 // the step also has a TOTP target (only absent, "username" or "password")
  custom?: readonly string[];  // distinct custom tokens on the step's visible, editable fields, document order, ≤ 16
  usernameToken?: string;      // the custom token the step's username target carries, if any (also in `custom`)
  passwordToken?: string;      // likewise for the password target
}
```

1. **The content script** passes the scope to the inline-menu iframe over the existing `postMessage` channel, as it passes `only` today. `CandidatesMessage` summaries gain `hasTotp: boolean`, a non-secret flag like `needsWarning`. The content script opens a menu at a TOTP-only step only if a candidate has it.
2. **The iframe asks the long-lived context directly** with a new `inline_menu_offer_request { scope }`, validated as an inline-menu sender (`isInlineMenuSender`, ADR 0040 point 1).
3. **The long-lived context recomputes the candidates** for the sender tab's browser-vouched URL (ADR 0040 point 3). It answers the iframe, never the content script, with `inline_menu_offer`:

   ```ts
   {
     offerId: string;   // 16 random bytes, lowercase hex
     pageHost: string;
     candidates: readonly {
       itemId: string;
       fillsTotp: boolean;
       customFill: readonly { label: string; concealed: boolean }[]; // ≤ 16, label ≤ 256 chars
     }[];
   }
   ```

   The offer record (tab id, scope, and per item the element ids chosen under §4.3) stays in the long-lived context's memory only. It lives at most 120 s, is used once, and is dropped on lock and when the tab navigates. A tab has at most 4 open offers.
4. **The iframe shows the disclosure** in each candidate row, before the click: "Also fills: one-time code · <Display Name> · <Display Name> (hidden)". Display Names are rendered as text. Values are never shown. A custom field is never filled unless its Display Name appeared in the row the user clicked.

**4.2 The fill request.** `InlineMenuFillRequestMessage` gains `offerId?: string`, and `only` gains `"totp"`.
- **Without `offerId`,** the request is exactly today's username/password fill. `only: "totp"` is refused.
- **With `offerId`,** the long-lived context takes the scope from its own offer record, never from the message. It refuses the request when the offer is missing, expired, used, belongs to another tab, does not hold `itemId`, or has an `only` that differs from the message's.
- **It then checks the item afresh,** rerunning the matcher and confirming `itemId` is still a candidate and an equivalence-only match is still confirmed (ADR 0040 point 3, unchanged). Then **one coarse `rizzy-client` call**, through `rizzy-wasm` (ADR 0013 §3 rule 6), returns only the values to write:
  - **username and password:** as `narrowFillValues` does today, by `only`.
  - **TOTP:** if `only` is `"totp"` or `totp` is set, and the item has a valid time-based `login.totp`, the code at the long-lived context's `Date.now()`, from the CRYPTO.md §11.15 implementation, current step only, no look-ahead. **The secret never leaves `rizzy-wasm`.** A TOTP-only request for an item without a code sends nothing.
  - **Custom:** for each token in the offer, the value of the element the offer recorded for it, if that element still exists and still satisfies §4.3. A field edited since the offer is re-checked, and dropped if it no longer qualifies.
  - **Role precedence:** if the username or password target carries a token that resolved to a custom field, the custom value goes instead of the role value, and the role value is not sent.

**4.3 Which custom fields fill.** All of these must hold on the item, by displayed values:
- the field exists;
- its kind is text (1) or hidden (2). Boolean and unknown kinds never fill;
- its label is non-empty;
- its autocomplete id passes §2.2 and is not in R;
- it is the first in list order among the fields with that id (§2.5);
- its value is a non-empty Text of at most `MAX_FIELD_VALUE_LEN` (4096) UTF-16 code units. A longer one is left out of the disclosure and not filled;
- the id equals the page token exactly. The page token is ASCII-lowercased; nothing else is normalised, and there is no prefix or substring match.

A hidden custom field crosses only on this click, which is the reveal gesture for it under ADR 0013 §3 rule 3, in the same way the fill click reveals `login.password` (ADR 0036 §4). Its row says "(hidden)".

**4.4 The values message (INV-40).** `FillValues` (in `ApplyFillMessage` and `RelayApplyFillMessage`) becomes:

```ts
interface FillValues {
  username?: string;
  password?: string;
  totp?: string;                                                // /^[0-9]{6,8}$/
  custom?: readonly { token: string; value: string }[];         // 1–16 entries, distinct tokens, ac_id grammar, not in R
}
```

- **Validation (`isFillValues`):**
  - at least one member present;
  - every string at most `MAX_FIELD_VALUE_LEN`;
  - `totp` matches its pattern;
  - `custom` within bounds;
  - unknown members refused;
  - the whole message under `MAX_MESSAGE_BYTES`.
- **Validation of the new requests:** the scope and offer messages get the same treatment. Custom tokens must pass the grammar, not be in R and be distinct. Each token list holds at most 16. `offerId` must be 32 lowercase hex digits.
- **Keyed by kind and token, never by DOM field id,** as ADR 0040 keeps it.
- **The content script's `applyFill`** writes:
  - `totp` into the step's TOTP target;
  - each `custom` value into the first field of the step's form, in document order, whose current parsed token (§1.1) equals the token;
  - into a role target carrying a token, the custom value for that token if one arrived, else the role value.

  It runs today's checks again at write time on every target: connected, not read-only, not disabled, visible and topmost. A value whose field fails them, or that no field carries any more, is dropped and written nowhere else.

### 5. Save and update (R6)

**5.1 What the content script captures at submit.** It extends `CredentialsSubmittedMessage` with `customFields?: readonly { token: string; value: string; masked: boolean }[]`. Each entry comes from a field of the submitted form that:
- is visible and editable at submit, and is an `<input>`. `type=hidden` is never captured;
- parses to custom(t) (§1.1), so never a reserved or standard token. Junk tokens such as `nope` do qualify, and the user leaves them unticked (§5.3). TOTP and one-time-code fields are never captured, because their values do not repeat;
- is not the username or password the existing flow captures;
- has a non-empty value of at most 4096 code units.

`masked` is `true` for `type=password`. At most 8 entries are sent. Beyond that, the rest are dropped. The long-lived context holds the values in memory only and zeroizes them when the prompt is resolved or times out, as it does for the submitted password today.

**5.2 Where consent is given.** Custom-field choices are shown **only in an extension-origin surface**, a save dialog iframe built like the inline menu, never in the page-DOM banner. The banner's state can be changed by page script (`content-script.ts:1180`), and a page that could tick "save" would choose what the manager stores. The dialog fetches its choices from the long-lived context directly, by the save-prompt token. Until the dialog exists, custom fields are not offered, and the banner saves username and password only, as today.

**5.3 What the dialog offers,** one checkbox row per entry:
- **Save of a new item:** "Add custom field <Display Name>". The Display Name is pre-filled with the token and editable; an empty one cannot be saved (W5). The new field's autocomplete id is the token. Its kind is hidden when `masked`, else text.
- **Update of a matching item that has no field with that id:** the same row.
- **Update of a matching item whose fillable field with that id (§4.3) holds a different value:** "Update <Display Name>". The previous value goes to field history.
- **An equal value:** no row.

Defaults (open question 6):
- new text fields are **checked**;
- masked fields are **unchecked**, and the row says "(hidden)";
- updates of an existing value are **unchecked**.

**5.4 What a save may never do.** It never sets or changes the autocomplete id of an existing field: a page that could tag an existing secret field would harvest it on the next fill. It never writes a reserved id. It always runs W1–W5. The op stays within ADR 0018 §10 (≤ 1,024 writes, ≤ 65,536 bytes per value).

### 6. Security analysis

| Threat | Mitigation | Residual |
|---|---|---|
| A7: a hostile page renames its inputs' `autocomplete` to harvest custom fields | Fill only on a trusted click in the extension-origin menu (INV-36, ADR 0040). The menu discloses every custom field that will fill, by Display Name with "(hidden)" marks, from the long-lived context directly (§4.1). Only items that match the page fill (ADR 0040 point 3), so a page reaches only custom fields saved for its own site or an equivalence group, under the existing confirmation. Only fields the user gave an id are ever fillable. Exact token match | A page on a matching site, including one reached through a subdomain takeover under *Base domain* (THREAT_MODEL A6 residual), can ask for every token it guesses and receives those values after one disclosed click. That is NG-12, as A7 puts it: "after a fill on the right origin, the page owns the value" |
| A7: hidden, off-screen or covered target; DOM swapped between click and fill | `applyFill` re-checks visibility, topmost and editability per target at write time (§4.4). A token moved to a new field after the menu showed fills only a visible field carrying that token, and the value is still the disclosed one | Unchanged from M2 (THREAT_MODEL A7 residuals) |
| Clickjacking the menu | Unchanged M2 mitigations (`menu-visibility.ts`, IntersectionObserver v2 where available) | Unchanged |
| TOTP | Only the current 6–8-digit code crosses, never the secret (§4.2). A gesture per step. No HTTPS → HTTP fill. Top frame only. A phishing domain matches no item, so it is offered nothing | A matching page receives a valid code for about one period, as it would if the user typed it |
| Over-detection (R2) | §1.3 rules (a)–(g), the §1.4 negative fixtures, and the rule that a declared WHATWG name always wins | A 2FA field with no hints and no token gets no offer. The popup's existing TOTP copy remains |
| A compromised content script (ADR 0036 §5, row 2) | It cannot open an offer or a fill without a trusted click in the iframe, and the iframe's disclosure comes from the long-lived context, so it cannot hide which fields a click will fill | It can claim any scope, so one disclosed click yields the clicked item's disclosed custom values and code, the same class as ADR 0040's residual for the password |
| Save path: a page plants or overwrites data | Consent only in the extension-origin dialog (§5.2). Existing ids are never changed. Overwrites are unchecked by default and kept in field history. Limits apply | A user who ticks a row stores what the page's form held. The page knew that value already |
| Collisions | Reserved set R (§3), W1–W5 in `rizzy-client` for every client, deterministic first-in-order resolution with a warning (§2.5) | Merge-made duplicates exist until the user resolves them, and fill stays deterministic meanwhile |
| Resource exhaustion through messages | Every new list is bounded (16 tokens, 16 disclosures, 8 captures, 4 offers per tab, 120 s lifetime). Existing message caps apply | None new |

No cryptographic change: TOTP uses the existing CRYPTO.md §11.15 implementation, and no key, algorithm or envelope changes. The new key is user content under ADR 0018 §2: it never appears in logs, errors or `Debug` output.

### 7. Crate and package ownership

- **`rizzy-core` (`item` schema):**
  - the `ac_id` grammar and the reserved set R, as one pure function returning a typed error;
  - `field/<id>/autocomplete` added to `classify` as known: Text, any writer, shown;
  - no I/O, so it builds for `wasm32`.
- **`rizzy-client`:**
  - W1–W5 on every write path;
  - shadowed-duplicate detection for the editor;
  - the fill-plan call of §4.2: TOTP code, custom matching, role precedence, narrowing;
  - the save-plan for §5.3.
- **`rizzy-wasm`:**
  - bindings for setting and clearing the id, the editor's warnings, the offer (Display Names and flags only) and the fill plan;
  - generated glue refreshed with `cargo xtask expand-bindings`.
- **`apps/web`:** in the item editor, a required Display Name and an optional "Autocomplete id" input under each custom field's settings. The id input shows W1–W5 errors inline and the §2.5 warning.
- **`apps/extension`:**
  - detection (§1), the scope, offer and fill messages (§4), the save dialog (§5) and the validators;
  - no new crate or dependency.
- **`rv` (CLI):** setting the id on a custom field is optional in this ADR. If it is added, it goes through the same `rizzy-client` checks.

### 8. Rollout

1. The owner accepts this ADR and adds the ROADMAP row (open question 1).
2. `rizzy-core` grammar and reserved set, with `rizzy-client` W1–W5, duplicate detection and its tests. Readers that do not use the key yet are unaffected.
3. `rizzy-wasm` bindings and the web editor UI. From here users can set ids.
4. Extension detection (§1), behind the existing fill path: TOTP fill first, then custom fill with the offer and disclosure (§4).
5. The extension-origin save dialog and custom-field capture (§5).

Each step is its own change. Steps 2–3 are useful on their own: they store ids and nothing fills them yet. No `item_schema_version` bump and no forced update.

### 9. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9:

| Part, quoted | Replaced by |
|---|---|
| [ADR 0018](0018-item-record-encoding.md) §7, the table row whose first cell is "`field/<id>/label` · `/kind` · `/value` · `/order`" | The row: "\| `field/<id>/label` · `/kind` · `/value` · `/order` · `/autocomplete` \| Text · Enum · Text or Bool · SortKey · Text \| all \| Custom fields. `kind`: 1 text, 2 hidden, 3 boolean (whose value is a Bool). An unknown kind displays as hidden. `label` is the field's Display Name; writers require it to be non-empty when they create or edit a custom field ([ADR 0076](0076-autocomplete-driven-autofill.md) §2.3 W5). `autocomplete` is the field's autocomplete id: lowercase `ac_id` grammar, not reserved, unique among the item's custom fields, allowed on text and hidden kinds only; it is a content attribute and not concealed (ADR 0076 §2, §3) \|" |
| [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, third bullet ("**Long-lived context → content script.** Only the chosen fill's values cross, at fill time, never a list of candidates with their secrets (list views show title/username/icon only, per [ADR 0013](0013-shared-client-core.md) §3 rule 3). The content script performs the actual DOM write.") | "**Long-lived context → content script.** Only the chosen fill's values cross, at fill time: as the fill's scope allows, the username and the password, the current TOTP code (never the TOTP secret), and the values of the custom fields the inline menu disclosed before the click ([ADR 0076](0076-autocomplete-driven-autofill.md) §4). Never a list of candidates with their secrets: list views show title/username/icon only, per [ADR 0013](0013-shared-client-core.md) §3 rule 3, plus a has-TOTP flag. The extension-origin inline-menu iframe alone also receives, per candidate, the Display Names and the concealment of the custom fields a fill would write, never their values. The content script performs the actual DOM write." |
| [ADR 0040](0040-extension-fill-request-from-inline-menu.md) point 2 ("**A fill request from a content script is refused.** The content script sends only detected-field reports and submitted-credential reports (ADR 0036 §4, first bullet, without the fill request).") | "**A fill request from a content script is refused.** The content script sends only detected-field reports and submitted-form reports (ADR 0036 §4, first bullet, without the fill request). A submitted-form report carries the submitted username and password and, under [ADR 0076](0076-autocomplete-driven-autofill.md) §5.1, at most 8 values of fields with a custom autocomplete token, which are offered for saving only in an extension-origin dialog." |
| [ADR 0040](0040-extension-fill-request-from-inline-menu.md) "What this ADR supersedes", the table row whose first cell is "[ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, first bullet: "sends only: detected-field reports, a chosen fill request (after the user picks a credential in the extension-origin inline menu), and submitted-credential reports"" | Its replacement text becomes: "sends only: detected-field reports and submitted-form reports ([ADR 0076](0076-autocomplete-driven-autofill.md) §5.1 says what a submitted-form report may carry). The chosen fill request comes from the inline-menu iframe ([ADR 0040](0040-extension-fill-request-from-inline-menu.md))." |

Everything else in ADRs 0018, 0036 and 0040 stays binding, including ADR 0018 §6 (only `order`, `match` and `kind` are layout attributes), ADR 0036 §4's first-bullet sentence "It never asks for or receives the master password, SK, or any decrypted item field beyond what the user is filling", and ADR 0040 points 1, 3 and 4. ADR 0037 and ADR 0013 are not superseded: §4 adds rules for new values and narrows none of theirs.

### 10. Tests

- **`rizzy-core`:**
  - grammar table tests: boundaries 1 and 64 bytes, uppercase, whitespace, non-ASCII, a `section-` prefix;
  - a test that R equals §3's list exactly;
  - a property test that every accepted id is lowercase ASCII and round-trips;
  - the validator added to the existing item-schema fuzz target (untrusted synced input).
- **`rizzy-client`:**
  - W1–W5 on every write path (add, edit, conflict pick and keep-both, history restore, import);
  - an unrelated edit of an item holding a merge-made duplicate succeeds;
  - a property test: two replicas concurrently set the same id on two fields; after the merge both converge, the same field wins on both, and the warning names the other;
  - an old-client simulation: the unknown key is carried, kept on label edit, and cleared on removal;
  - fill-plan tests: exact match only, the reserved and invalid stored ids never fill, boolean, unknown-kind and label-less fields never fill, values over 4096 are left out, role precedence;
  - TOTP-code vectors through the fill plan, reusing CRYPTO.md §15 TOTP vectors;
  - the secret never in the result.
- **`rizzy-wasm`:** binding tests, and the expansion baseline refreshed with its `unsafe` counts reviewed.
- **Web (Playwright):**
  - setting and clearing an id;
  - the W1, W2, W3 and W5 errors shown inline;
  - the duplicate warning after a simulated concurrent merge;
  - "Unnamed field" display.
- **Extension unit tests:**
  - the §1.1 parser table (on, off, webauthn, `section-*`, shipping and billing, contact prefixes, junk, more than 8 tokens, over 256 characters);
  - the §1.2 role table;
  - the §1.3 heuristic, with every §1.4 negative case as an HTML fixture;
  - contract validators for every new message: oversize, bad token, reserved token, duplicate tokens, a bad `totp` format, unknown members, a bad `offerId`.
- **Extension e2e, with adversarial pages (INV-36, INV-37):**
  - a TOTP step fills only on its own click;
  - no TOTP menu when no candidate has a code;
  - custom fill with a visible disclosure, "(hidden)" shown;
  - a page that renames a token after the menu showed;
  - hidden, off-screen and covered custom targets not filled;
  - a cross-origin iframe never filled;
  - HTTPS-saved items on an HTTP page;
  - an expired or reused `offerId` refused;
  - save-dialog opt-in, including a page that cannot change the dialog's choices;
  - the page-DOM banner never offering custom fields.

### On acceptance

The PR that accepts this ADR makes these edits. None is made now.
1. **Status lines and the README index:**
   - ADR 0018 → "Partially superseded by [ADR 0076](0076-autocomplete-driven-autofill.md) (§7 in part)";
   - ADR 0036 → append "; [ADR 0076](0076-autocomplete-driven-autofill.md) (§4 in part)";
   - ADR 0040 → "Partially superseded by [ADR 0076](0076-autocomplete-driven-autofill.md) (point 2; "What this ADR supersedes" in part)".
2. **THREAT_MODEL A7 Mitigations:** add a bullet for TOTP-code and custom-field fill:
   - the code only, never the secret;
   - disclosure from the long-lived context before the click;
   - exact token match;
   - the extension-origin save dialog.

   Add the §1.4 negatives and the §10 adversarial cases to the INV-36 and INV-37 test columns.
3. **`rizzy-core`'s `schema.rs` key table comment** gains the new row when step 2 of §8 lands.

## Consequences

### Positive

- The owner's six requirements map onto one decision. TOTP is offered only where a saved login can produce a code, so the over-detection the owner named is ruled out by construction, not tuned.
- Every client enforces collisions identically, because the checks live in `rizzy-core` and `rizzy-client`, not in UI code.
- A disclosed custom field is the only kind that can fill, and the disclosure comes from the trusted context. That holds even against a compromised content script.
- No new crate, dependency, crypto, `item_schema_version` or forced update. Old clients keep the data intact.

### Negative

- More message surface: the offer request, the offer, the extended scope and values, the save dialog. Each needs validators, size limits and adversarial e2e tests.
- A second extension-origin iframe (the save dialog) to build and clickjack-harden like the inline menu.
- The Display Name requirement adds friction for label-less imported fields when they are edited.
- Reserving all WHATWG names forbids some ids users might want, `email` for example (open question 3).
- `new-password` respect can stop a saved-password fill on sites that mislabel their login field (open question 5).

### Risks

- **Heuristic drift.** Sites whose 2FA field has neither a token nor an OTP hint get no offer. The signal is user reports. A heuristic change that keeps every §1.4 negative is a code change, not a new ADR.
- **WHATWG may add autofill field names.** A stored custom id could then collide with a new standard meaning. It still fills as custom, because R is frozen here, until a new ADR grows R, after which it stops filling and shows an error (§3). The signal is a new field name in the HTML standard.
- **A browser exposing page-visible state of the new iframes,** as THREAT_MODEL A7's accepted trade-offs record for the inline menu.

## Alternatives considered

- **Heuristics everywhere, ignoring `autocomplete`.** Rejected: the owner asked to respect the attribute, and a declared `cc-csc` or `postal-code` is the strongest negative signal there is.
- **Honour `autocomplete="off"` by not offering anything.** Rejected: sites put `off` on login and 2FA fields to stop browser autofill, not to refuse a password manager, and every fill already needs a click. Browsers ignore `off` on login fields (L).
- **TOTP only through `autocomplete="one-time-code"`.** Rejected as too narrow: many 2FA fields lack the token. §1.3 keeps the heuristic but requires rule (g), a candidate that has a code. Open question 7 offers token-only.
- **Treat a custom token as switching off the username/password heuristics.** Rejected: junk tokens such as `nope` on real login fields are common, and today's logins would break.
- **Take the last token of a multi-token attribute as the custom token** (`section-a custominput`). Rejected for now: non-conforming, rare, and ambiguous with WHATWG's grammar. §1.1 requires exactly one token. Relaxing this later is compatible.
- **A new key for the Display Name.** Rejected: `field/<id>/label` already is the field's name. A second one would split what old clients show.
- **Make `autocomplete` a layout attribute,** so that an id alone does not make a field exist. Rejected: it would supersede ADR 0018 §6 as well, and old clients, which read unknown attributes as content, would show different fields than new ones.
- **Extend ADR 0018 §7 instead of superseding its row,** following the precedent of ADR 0039 and ADR 0055 ("A new key needs a line in the ADR that ships it"). Not chosen, because W5 changes what the row means for `label`, not only which keys exist. Open question 2.
- **Refuse every write to an item that holds a duplicate.** Rejected: merge-made duplicates would lock unrelated edits. §2.5 resolves them deterministically and warns.
- **Fill no field while its id is duplicated.** Safer in theory, but a merge race silently disables a working fill. The first-in-list-order rule is deterministic on every replica and comes with a warning. Open question 8.
- **Carry custom tokens and Display Names through the content script,** as candidates travel today. Rejected: a compromised content script could then hide the disclosure. §4.1 has the iframe ask the long-lived context directly.
- **Offer custom fields in today's page-DOM save banner.** Rejected: page script can change its state (`content-script.ts:1180`). §5.2.
- **Fill `<textarea>` and boolean (checkbox) custom fields.** Deferred: different DOM semantics and more surface. This ADR fills text and hidden kinds into `<input>` only.
- **Auto-copy the TOTP code to the clipboard after a password fill** (a common manager behaviour, U). Not in this ADR. It is a clipboard decision with its own exposure (ADR 0013 §3 rule 3).

## Open questions for the owner

Each recommendation is a safe default the ADR can be accepted with as written.

1. **The ROADMAP row.** This ADR needs scope. *Recommendation:* add to §4.4: "S | Autocomplete-aware autofill: TOTP-code fill with strict detection; custom fields with an autocomplete id (fill and opt-in save) | M3".
2. **Supersede the ADR 0018 §7 row, or extend §7 by this ADR's own line** (the ADR 0039 and ADR 0055 route)? *Recommendation:* supersede the row as §9 does, because W5 changes the row's meaning for `label`. If the owner prefers extension, §9's first entry becomes a plain new-key line, and W5 stays a writer rule of this ADR.
3. **How broad is the reserved set?** *Recommendation:* all of §3, `email` and `tel` included. Relaxing later is compatible, tightening is not. The alternative is reserving only rows 1, 2 and 5.
4. **Display Name for imported label-less fields.** *Recommendation:* importers keep the empty label (fidelity), the field shows as "Unnamed field" and fills nothing, and the next edit asks for a name. The alternative is importers writing "Custom field N", which invents data.
5. **Respect `new-password`,** so the saved password never goes there, only the generator? *Recommendation:* yes, as §1.2 says. The alternative is offering the saved password too where a page has no other password field.
6. **Save-dialog defaults.** *Recommendation:* new text fields checked; masked fields and updates of existing values unchecked. The stricter alternative is everything unchecked.
7. **The TOTP heuristic for fields without `one-time-code`.** *Recommendation:* on, with every rule of §1.3. The alternative is token-only, which never over-detects but misses many real 2FA fields.
8. **Duplicate ids after a merge.** *Recommendation:* the first in list order fills, with a warning (§2.5). The alternative is that neither fills until the user resolves the duplicate.
9. **TOTP and custom fill from the popup.** *Recommendation:* not in this ADR. It needs the popup to show the same disclosure, so it is a later change.

## References

- [ADR 0012](0012-sync-engine.md) §4 step 5, §5 · [ADR 0013](0013-shared-client-core.md) §3 rules 3, 4, 6 · [ADR 0018](0018-item-record-encoding.md) §2, §6, §7, §10, §11 · [ADR 0020](0020-partial-supersession.md) points 7, 9 · [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §4, §5 · [ADR 0037](0037-url-matching-and-autofill-rules.md) §5 · [ADR 0039](0039-passkeys-vault-and-extension.md) · [ADR 0040](0040-extension-fill-request-from-inline-menu.md) · [ADR 0055](0055-m3-item-type-field-keys.md) (the extension route)
- [CRYPTO.md §11.15](../CRYPTO.md#1115-totp-m1), [§15](../CRYPTO.md#15-testing)
- [THREAT_MODEL.md](../THREAT_MODEL.md) A6 residual risk, A7, NG-12, INV-36, INV-37, INV-40
- [ROADMAP.md §4.4](../ROADMAP.md#44-url-matching--autofill-m2)
- Code read on this branch (V): `apps/extension/src/content/login-step.ts`, `content/content-script.ts`, `messaging/contract.ts`, `core-host/content-handler.ts`, `inline-menu/protocol.ts`; `crates/rizzy-core/src/item/schema.rs`, `item/order.rs`; `crates/rizzy-client/src/lists.rs`; `crates/rizzy-wasm/src/session.rs`, `items.rs`
- WHATWG HTML Living Standard, "Autofill" (§4.10.19.7): the token grammar, the field and contact names, `on`/`off`, `webauthn`. <https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill> (V, read 2026-10-22)
- Browsers ignore `autocomplete="off"` on login fields; iOS uses `one-time-code` for SMS codes (L, general knowledge, not checked against vendor documentation for this ADR)
- Other managers over-detecting TOTP fields: the owner's statement (U)
