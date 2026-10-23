# ADR 0079: Identity generator: pre-filled new identities, the `identity.sex` and `identity.birthday` keys, bundled name and address data, and the masked-email seam

- Status: Proposed
- Date: 2026-10-23
- Deciders: project owner
- Milestone: M3 (generator, two new keys, bundled data, web vault and `rv`; needs the ROADMAP row in "On acceptance" item 1) / M6, after v1.0 (the masked-email seam in §9, designed here and built by nothing in this ADR)
- Supersedes: none, in full or in part ([ADR 0020](0020-partial-supersession.md) point 9). It extends without superseding: [ADR 0018](0018-item-record-encoding.md) §7, under that section's own rule that "a new key needs a line in the ADR that ships it, never a version bump" (the route [ADR 0055](0055-m3-item-type-field-keys.md) and [ADR 0039](0039-passkeys-vault-and-extension.md) used); and, only if Open question 7 is answered as recommended, [ADR 0042](0042-account-settings-matching-layout.md) §2's tag registry, under its own rule that "a new setting gets a line here by ADR amendment, no version bump". No Accepted text is contradicted; §11 lists what was checked.

## Context

### What the owner asked for

The owner's instructions of 2026-10-23, verbatim:

> (1) "identity must have ability to have pre-filled data in it when creating including in future mask email that will be implemented and display its latest messages and confirm code recognizing (default + custom user defined)."
>
> (2) "new identities must have prefilled all data, sex picker (male, female), pre-generated first and last names (download list of names from internet and categorized by countries), email consists from (first and last name + bday or randomized nickname) @ maskeddomain, bday (user selects bday range: 18-27 or 28), country (selection), address (generated based on country, postcode and other fields are apart) as well province/state etc.."

Two further answers of 2026-10-23, given after this draft was written, verbatim:

> (3) Age: "18-27 or 28, presets like aliasvault's and ability to set custom age range or custom age".
>
> (4) Email domain picker: "the mail one works similar to aliasvault if registered masked mail domain is recognized - make its domain part as button which opens selector for different registered domain mails".

How the Decision takes them is in "Owner answers (2026-10-23, before acceptance)" at the end of the Decision.

Instruction (1) has two parts on different schedules. Pre-filled data on creation can ship before v1.0. Masked email, its "latest messages" view and confirmation-code recognition are [ROADMAP §4.8](../ROADMAP.md#48-aliases--email-receiving-m6) (M6), which the owner scheduled **after v1.0** on 2026-10-22. This ADR therefore designs the seam for them (§9) and builds nothing of mail.

### Where it sits in the ROADMAP

- [§4.2](../ROADMAP.md#42-core-vault-m1), Must, M1: "Item types: Login, Secure Note, Card, Identity". The Identity type exists. Generating its contents is not in that row.
- [§4.8](../ROADMAP.md#48-aliases--email-receiving-m6), Must, M6: "Generate alias identity (random name, username, alias address, password) from item creation and from the extension on sign-up forms". This is the closest row, but it is M6, after v1.0, and it is built around an alias address.
- §4.8, Should, M6: "Extract OTP / verification links from mail and offer them in autofill". This is the owner's "confirm code recognizing".

No row covers a pre-v1.0 identity generator, so the task is out of scope until a row is added ([CLAUDE.md](../../CLAUDE.md) "Before you start" 1). "On acceptance" item 1 proposes the row. Adding it is the owner's ROADMAP edit, not this ADR's.

### What exists today (V, read in this worktree)

- **Identity keys.**
  - [ADR 0018](0018-item-record-encoding.md) §7 defines 18 Text keys for the Identity type: `identity.title`, `.first_name`, `.middle_name`, `.last_name`, `.company`, `.email`, `.phone`, `.username`, `.address1`, `.address2`, `.address3`, `.city`, `.state`, `.postal_code`, `.country`, `.ssn`, `.passport_number`, `.drivers_license`.
  - `ssn` and `passport_number` are concealed by default.
  - They are the `IDENTITY_*` constants in `crates/rizzy-core/src/item/schema.rs` (lines 163–198).
  - There is **no key for sex and none for a birthday.** For that reason, the AliasVault importer maps `alias.gender` and `alias.birthdate` to the custom fields "Gender" and "Birth Date" ("no ADR 0018 field", `crates/rizzy-import/src/aliasvault.rs` lines 66–67).
- **Unknown keys.**
  - A key that fits the ADR 0018 §7 grammar but has no registry entry classifies as `KeyClass::Unknown` (`schema.rs` line 676).
  - It is merged, snapshotted and exported byte for byte. An M1 writer writes it only as Cleared in an edit, or copies it verbatim (ADR 0018 §11).
  - The web vault lists such fields under "other", "shown as they are" (`apps/web/src/fields.ts` line 238).
- **The password generator** (`crates/rizzy-core/src/generator/`).
  - It takes the caller's `&mut impl CryptoRng` and draws uniform indices by rejection sampling ([CRYPTO.md §12.1](../CRYPTO.md#121-randomness)).
  - It embeds the EFF large wordlist with `include_bytes!`. `wordlist.rs` pins the file's SHA-256 in a test, validates the file at compile time, and gives it a `NAME` and a `VERSION`.
  - The list is CC BY 4.0. Its attribution, and the owner's decision of 2026-09-26 to keep it, are in `THIRD_PARTY_NOTICES.md`.
- **Generator memory.** The web generator's options are session-only React state (`apps/web/src/generator-memory.ts`). That module says that persisting them "needs a new persisted item shape, which ADR 0013 §3 and the ADR gate ... reserve for an Accepted ADR."
- **Crate rules.**
  - `rizzy-core` and `rizzy-client` do no I/O and build for `wasm32-unknown-unknown`.
  - `rizzy-client` already depends on `rand_core` and `rizzy-core`, and has `chacha20` as a dev-dependency for seeded tests.
  - The server depends on `rizzy-client` only as a dev-dependency, for its tests ([ADR 0016](0016-workspace-layout.md) §3–§4; `crates/rizzy-server/Cargo.toml` lines 71–73).
- **Wasm size.**
  - The current `rizzy_core_bg.wasm` is 3,988,124 bytes, or 1,364,057 bytes gzipped (V, measured from the integration build of 2026-10-23).
  - ADR 0013 §4 sets a size budget "after the first measurement". `crates/xtask/src/bindings.rs` reports the size, but no budget number exists yet.
- **Masked email (Proposed only).**
  - [ADR 0068](0068-alias-identity-model.md) (Proposed, M6) links a vault item to an alias through an encrypted item field, `alias.id` (Bytes, 16). Its Types column says **Login** only.
  - [THREAT_MODEL INV-65](../THREAT_MODEL.md#8-security-invariants) requires every generated alias local part to carry at least 64 bits from the CSPRNG, and "human-readable parts (names, words, digits chosen to look human) do not count toward it".
  - THREAT_MODEL §4 A11 (Mitigations) says outright: "'Random name' aliases in the style `firstname.lastname99` are guessable and do not meet that bar."
  - The owner's email shape, "first and last name + bday ... @ maskeddomain", conflicts with that invariant once the domain is our masked-email domain (Open question 3).
- **Autofill.** [ADR 0076](0076-autocomplete-driven-autofill.md) §3 row 3 reserves WHATWG tokens such as `sex`, `bday`, `bday-day`, `bday-month`, `bday-year`, `country`, `country-name`, `postal-code`, `address-level1` and `address-line1` for "Future Identity and Card autofill (`identity.*`, `card.*`, ADR 0018 §7)". The two keys added here are what `sex` and `bday` will fill from. Identity autofill itself is not decided here.

### Constraints

- **Not secrets.** Generated identities are not secrets. Once saved they are ordinary vault plaintext ([THREAT_MODEL AST-7](../THREAT_MODEL.md#2-assets): "Item plaintext: … identities …"), encrypted like every item. Before saving they are form state.
- **Data ships to clients.** The bundled name and place lists ship to every client that contains the generator: the web vault, the extension (same wasm, ADR 0036) and `rv`.
  - They must carry no personal data beyond what public name and place lists contain.
  - Their licences must allow redistribution under AGPL-3.0-only ([ADR 0017](0017-licensing.md)).
- **No new crate.** The data conversion uses only crates already in the workspace, as `cargo xtask equivalence-list` does (`crates/xtask/src/equivalence_list.rs`).

## Decision

### 1. Two new item keys

Both are added under ADR 0018 §7's own provision. Neither needs an `item_schema_version` bump (ADR 0018 §11).

| Key | Value | Types | Writers | Concealed | Notes |
|---|---|---|---|---|---|
| `identity.sex` | Text | Identity | any | no | Writers that pick from the UI write exactly `male` or `female`, lowercase ASCII. Readers show those two as localized labels ("Male", "Female") and any other text as entered, like every Text key. Absent means not set |
| `identity.birthday` | Text | Identity | any | no | A calendar date. Writers that pick from a date control write the RFC 3339 `full-date` form `YYYY-MM-DD` (for example `1998-04-17`). Readers that parse that form show a localized date and offer a date control. Any other text (an import such as `04/17/1998`) is shown and edited as entered, never silently rewritten |

**Why Text, not Enum or U64.**

- **Older clients can read it.** An older client shows an unknown key's Text value as it is, so a `male` or `1998-04-17` written by a newer client stays readable everywhere. The precedents are `card.exp_month`, `ssh.port` and `license.expires`, all Text "stored as entered" (ADR 0055 §1).
- **A birthday has no time zone.** It is a civil date. A U64 of Unix milliseconds would shift by a day between time zones and would need a rule for that.
- **Room to grow.** The WHATWG `sex` token is free text, and the owner's two values may grow later without a schema change.

**Existing keys the generator fills.** Each keeps its type: Text, "as entered" (ADR 0018 §6).

- **`identity.country`.**
  - The generator writes the ISO 3166-1 alpha-2 code in upper case, for example `DE`.
  - Readers that recognise a two-letter code, in any case, show the country's name next to it. This also covers the importer that writes `us` (`crates/rizzy-import/src/tests.rs` line 446).
  - Any other text is shown as entered.
  - A code serves both WHATWG `country` (a code) and `country-name` (a name) for later autofill.
- **`identity.state`.**
  - The generator writes the subdivision in the form addresses use in that country: the postal abbreviation where that is the custom (US `CA`, CA `ON`, AU `NSW`), and the name elsewhere (DE `Bayern`).
  - The data file (§5) carries both the ISO 3166-2 code and this form. Only the form is written.
- **`identity.address1`.**
  - The generator writes the street line in the country's order: `Hauptstraße 12`, `12 Main Street`, `12 rue Victor Hugo`.
  - The generator leaves `address2` and `address3` empty.
- **`identity.postal_code` and `identity.city`** are already separate keys, so the existing layout meets the owner's "postcode and other fields are apart".

**No split street keys.** Separate `identity.street` and `identity.house_number` keys were rejected.

- The line form is what the 1PUX and Bitwarden importers, the WHATWG `address-line1` and `street-address` tokens, and every user who types an address all use.
- A split would need a mapping in both directions and would gain the generator nothing.

**What older clients see.** A client that predates these two registry entries classifies `identity.sex` and `identity.birthday` as `KeyClass::Unknown`.

- Both keys are merged, synced, exported, and imported from our own export byte for byte (ADR 0018 §11).
- The web vault lists them under "other" with their raw text.
- An older client cannot edit them, only clear them by deleting the field.
- No server change, new value type or new item type is needed.

**Local index.** Neither key is added to [ADR 0056](0056-local-index-recently-used-search.md) §2's display-safe cleartext list. ADR 0056 is unchanged, so both keys stay encrypted at rest on the device.

### 2. Where the generator lives

The generator is a new module, `rizzy_client::identity_gen`: a pure, sans-I/O function that takes the caller's `&mut impl rand_core::CryptoRng` and builds for `wasm32-unknown-unknown`.

- **Not `rizzy-core`.**
  - The bundled data is a few hundred KiB of client-only content.
  - Every client links `rizzy-client` (wasm, `rv`, the planned native bindings). The server binary does **not**: it uses `rizzy-client` only as a dev-dependency for tests ([ADR 0016](0016-workspace-layout.md) §3–§4). The server binary therefore does not carry the data.
  - `rizzy-core` stays the smaller crypto audit surface.
  - There is no new crate, no new dependency edge and no new external crate.
- **Reused from `rizzy-core`.**
  - The password generator's uniform-index routine: rejection sampling, [CRYPTO.md §12.1](../CRYPTO.md#121-randomness).
  - The embedded EFF wordlist, for nicknames (§4).
  - The implementation makes both reachable through a small `pub` accessor. Neither changes.
- **No clock.** The caller passes today's civil date (`year`, `month`, `day`). The leaf crate reads it from the platform clock: `Date` in the web vault, the local date in `rv`.
- **Not constant-time.**
  - The password generator copies words with a constant-time scan because the chosen word is the secret (CRYPTO.md §12.3). An identity is shown to the user at once and is not a secret, so plain indexing is used.
  - The one exception is §9's M6 random token. It must be unguessable, but once the address is in use it is not secret either. It is drawn from the same CSPRNG. This ADR does not defend against a timing side channel on its index inside the user's own browser.

### 3. The interface and what "all data" includes

```text
generate_identity(rng, data, options, today) -> Result<GeneratedIdentity, IdentityGenError>
regenerate_field(rng, data, options, today, field, current: &GeneratedIdentity)
    -> Result<GeneratedIdentity, IdentityGenError>

options:
  sex          Male | Female | Random            Random draws one of the two (§4 step 1)
  country      ISO 3166-1 alpha-2 in the bundled set (§6), else IdentityGenError::UnsupportedCountry
  age          AgeRange { min: u8, max: u8 }     18 <= min <= max <= 99, else IdentityGenError::AgeRange.
                                                 A preset, a custom range and an exact age n (as [n, n])
                                                 all reach the generator as this one pair (below)
  email_style  NameAndBirthday | Nickname
  email_domain Option<domain>                    LDH A-label syntax, 2+ labels, each 1-63 bytes,
                                                 total <= 253 bytes, lower-cased; else
                                                 IdentityGenError::EmailDomain. No IDNA: a U-label
                                                 is refused with a message to enter its xn-- form
  title        bool                              Open question 4
  phone        bool                              Open question 5

age_presets() -> &'static [AgePreset]            AgePreset { id: &'static str, min: u8, max: u8 }
```

**Age presets and modes** (the owner's answer (3), "Owner answers (2026-10-23, before acceptance)").

- The age picker has three modes. Each one produces the `AgeRange` above, so the generator, the draw (§4 step 4) and the vectors see only `min` and `max`:
  - **Preset:** one row of the list below.
  - **Custom range:** any `min` and `max` with 18 ≤ `min` ≤ `max` ≤ 99.
  - **Exact age:** one age `n`, 18 ≤ `n` ≤ 99, passed as `[n, n]`. The birthday is then uniform over the 365 or 366 dates whose completed age today is `n`.
- The preset list is a constant in `rizzy_client::identity_gen`, `AGE_PRESETS`, exported through the bindings as `age_presets()`. Every client shows the same list in the same order and localizes only the label.

| Order | `id` | Label (English) | `min` | `max` | Origin |
|---|---|---|---|---|---|
| 1 | `18-27` | 18–27 | 18 | 27 | The owner's "18-27". The first-time default |
| 2 | `28-65` | 28+ | 28 | 65 | The owner's "28", read as "28 and over". The upper bound 65 is AliasVault's own maximum (`DEFAULT_MAX_AGE`, below) |
| 3–11 | `21-25`, `26-30`, `31-35`, `36-40`, `41-45`, `46-50`, `51-55`, `56-60`, `61-65` | 21–25 … 61–65 | as labelled | as labelled | AliasVault's nine five-year presets, same bounds and order |
| 12 | `any` | Any (21–65) | 21 | 65 | AliasVault's "Random" preset, which means its default range 21–65 |

- **What AliasVault has** (V, read 2026-10-23 at commit `4f0208ed7dbafb3656bc54e16fdef437316c4689` of github.com/aliasvault/aliasvault):
  - `core/rust/src/identity_generator/mod.rs` line 35: `const AGE_RANGES: &[&str] = &["random", "21-25", "26-30", "31-35", "36-40", "41-45", "46-50", "51-55", "56-60", "61-65"];`. Lines 29–32: `DEFAULT_MIN_AGE = 21`, `DEFAULT_MAX_AGE = 65`. "random" means that default range (line 34's comment, and `random_birth_date`, line 195).
  - `apps/web/src/pages/settings/IdentityGenerator.tsx` lines 124–131: a settings select, "Age Range", showing each id as its own label and "random" as "Random". The choice is stored as the vault setting `DefaultIdentityAgeRange` (default `random`, `core/client/src/database/repositories/SettingsRepository.ts` lines 62–63).
  - AliasVault has **no 18–27 preset, no 28+ preset and no exact-age mode.** Its `BirthdateOptions` (a target year ± a deviation, `mod.rs` lines 55–63) is an API option the settings UI does not offer.
- **How "28" maps.** The "28+" preset is 28–65. "Exactly 28" is the Exact-age mode with `n = 28`. Both readings of the owner's "28" are therefore one click or one number away.
- **One deliberate difference from AliasVault.** AliasVault turns "21-25" into whole birth *years* around a middle age (`age_range_to_birthdate_options_at`, `mod.rs` lines 175–185: target year = current year − 23, deviation 2). Birth years are then `current − 25` to `current − 21`, so an AliasVault "21–25" identity is 20 today when its birthday in the youngest year has not come yet; its own test only checks a birth-year difference of `20..=26` (`tests.rs` lines 187–197). This ADR keeps §4 step 4: the **completed age today** is always inside `[min, max]`. The labels match AliasVault's; the draw is exact.
- **The default.** 18–27 the first time; after that the last-used range (preset, custom or exact). Where that is remembered is Open question 7.

**Output.**

- `GeneratedIdentity` is a list of `(field key, String)` pairs, the shape the create op already takes from the editor.
- Nothing is written until the user saves. Saving is the ordinary create op, which "writes no field the user left blank" (ADR 0018 §6).
- The generator never writes a field itself.

**Filled by default** (subject to Open questions 4 and 5):

- `identity.sex`, `identity.first_name`, `identity.last_name`, `identity.birthday`
- `identity.username`: the nickname.
- `identity.email`: only when a domain is known (§8).
- `identity.address1`, `identity.city`, `identity.state`, `identity.postal_code`, `identity.country`
- `identity.title`: derived from sex (Open question 4).
- `identity.phone`: fictional ranges only (Open question 5).

**Never generated.**

- `identity.ssn`, `identity.passport_number` and `identity.drivers_license`. A random number in a real national-ID format can belong to a real person, and generating one invites fraud.

**Left empty:** `identity.middle_name`, `identity.company`, `identity.address2` and `identity.address3` (Open question 4).

**Item name.** `item.name` defaults to "First Last" so the item has a title in the list. This is the editor's default, not a generated field.

### 4. Draw procedure (normative for the known-answer vectors)

`uniform(n)` is the password generator's uniform index in `0..n`. Draws happen in this order, and a step that does not apply draws nothing:

1. **Sex.** If `Random`, `uniform(2)`: 0 is male, 1 is female.
2. **First name.** `uniform(len)` over `first.<sex>`.
3. **Last name.** `uniform(len)` over `last.<sex>` if the country's data is split by sex (§5), else over `last`.
4. **Birthday.** Every date whose completed age today lies in `[min, max]` is equally likely:
   - `hi` is today minus `min` years.
   - `lo` is today minus `max + 1` years, plus 1 day.
   - Subtracting years from 29 February gives 28 February.
   - The birthday is `lo + uniform(days(lo..=hi))`.
   - Day arithmetic is the proleptic-Gregorian days-from-civil conversion, hand-written with no dependency (the public-domain algorithm by H. Hinnant, L).
5. **Street.** `uniform` over `street`. The house number is `lo_n + uniform(hi_n - lo_n + 1)`, from the country's `@number` range. The country's `@address` pattern formats the line.
6. **City and subdivision.** `uniform` over `city`. If the country's data pairs a city with its subdivision, that subdivision is used. Otherwise a separate `uniform` is drawn over `subdivision`.
7. **Postcode.** `uniform` over the subdivision's patterns if the data has them (US and CA in faker-js, §6), else over the country's patterns. Each `#` is `uniform(10)`, and each `?` is `uniform(26)` over A–Z.
8. **Phone**, if enabled and the country has a fictional range (§7). `uniform` over its patterns, then `uniform(10)` for each `#`.
9. **Nickname.** Two EFF words, each `uniform(7776)`, joined with nothing, plus `uniform(100)` as two digits, for example `crispywalrus42`.
10. **Email local part.**
    - `NameAndBirthday`: the separator is `uniform(3)` over `.`, `_` and empty; the suffix is `uniform(3)` over the birthday's `YYYY`, `YY` and `DDMM`. The local part is `ascii(first) sep ascii(last) suffix`.
    - `Nickname`: the nickname from step 9.
    - The local part is lowercase `[a-z0-9._-]`, with no leading, trailing or doubled `.`, and at most 64 octets (RFC 5321 §4.5.3.1.1, L). A longer one is cut from the last-name end.
    - `@domain` is appended only if a domain is known (§8).

**Regenerating one field.** `regenerate_field` redraws the steps of the field it is asked for, plus the steps that depend on that field:

- First name, last name or birthday: the email too, if the current email is still the generated one.
- Sex: the first name, a sex-split last name and the title.
- Country: every step except the birthday and the nickname.

The UI decides which fields the user has not yet touched (§10) and passes only those.

**Determinism.** For a given RNG stream, data version, options and `today`, the output is fixed, and known-answer vectors pin it (§12). Changing the data file means a new data `VERSION` with new vectors.

### 5. Bundled data: format and integrity

The data is one UTF-8 file, `crates/rizzy-client/src/identity_gen/identity-data-v1.txt`, embedded with `include_str!`.

- It is human-readable, so a data update is a reviewable diff.
- It is the compiled output of the xtask (§6) and is never edited by hand.

```text
# identity-data v1. Generated by `cargo xtask identity-data`; do not edit. Provenance: data/identity/SOURCES.md
@country DE
@name Germany                                 CLDR English territory name
@title.male Herr
@title.female Frau
@address {street} {number}                    or {number} {street}, per country
@number 1 199
@postcode #####                               one line per pattern
@phone <pattern>                              fictional ranges only (§7); absent = no phone
[first.female]                                one entry per line: display|ascii
Anna|anna
[first.male]
Jürgen|juergen
[last]                                        or [last.female] and [last.male] where surnames are sex-split
[street]
[city]                                        city, or city|subdivision-code where paired
[subdivision]                                 iso-3166-2|written form
DE-BY|Bayern
```

- **Name and version.** `NAME = "identity-data"` and `VERSION = 1`, like `wordlist::NAME` and `VERSION`.
- **Parsing.**
  - The parser is hand-written and size-limited: the whole file is at most the budget below.
  - It returns `IdentityDataError` and never panics on any byte input.
  - A unit test parses the embedded file and pins its SHA-256. A fuzz target feeds the parser arbitrary bytes.
  - The embedded file is parsed once per process and cached as a lazily built, read-only index, in a `std::sync::OnceLock` (no `unsafe`).
- **Content rules.** The xtask checks these, and a unit test checks them again:
  - Every entry is NFC.
  - Display forms are 1–40 bytes of letters, spaces, hyphens and apostrophes.
  - The ascii form is 1–32 bytes of `[a-z-]`, with no leading or trailing hyphen.
  - No list has duplicates.
  - Every list has at least 50 entries, except subdivisions.
  - Every country present has every `@` directive above, except `@phone`, which is optional.
- **The ascii column.**
  - The xtask computes it from a committed transliteration table, which folds Latin diacritics: `ü`→`ue` and `ß`→`ss` for German, `é`→`e` in general.
  - `rizzy-client` therefore needs no Unicode tables at runtime.
- **Caps per country.**
  - 400 first names per sex, 800 last names (per sex where split), 400 streets, 400 cities and every subdivision.
  - Where upstream orders a list by frequency, the cap keeps the most frequent entries. Otherwise it keeps a fixed-seed sample. `SOURCES.md` records the seed and the rule.
- **Size budget.**
  - The embedded file is at most **384 KiB**. A unit test enforces this on its length, and `cargo xtask expand-bindings` reports it next to the module size.
  - Estimate with the v1 country set (§6, Open question 6): 15–30 KiB per country, about 250–350 KiB in total, which adds roughly 100–130 KiB to the gzipped wasm. That is under 10 % of the current gzipped module.
  - The estimate is U: it comes from faker-js file sizes (for example, `de/person/last_name.ts` is 25,096 bytes) and is measured when the xtask first runs.
  - If the budget cannot hold the chosen set, the fallback is Alternative D, a lazily loaded asset. The owner decides that, not the implementer.

### 6. Sources, licences and the xtask

The owner's "download list of names from internet" is done **once, by `cargo xtask identity-data`**, which a maintainer runs. CI and clients never run it.

- The output and a provenance manifest are committed.
- Clients never download anything at runtime.

**Accepted sources:**

| Source | Used for | Licence | Status |
|---|---|---|---|
| **@faker-js/faker**, `src/locales/<locale>/person` and `/location`, pinned to a release tag (10.6.0 at the time of writing) | first names by sex, last names, street names and patterns, city names, house-number ranges, postcode patterns, US and CA postcode-by-state | MIT ("Faker - Copyright (c) 2022-2025", plus the faker.js copyright of Marak Squires, 2011–2020) | Licence V (`LICENSE` read 2026-10-23). Version V (`package.json`). Locale coverage V for `de` (`first_name.ts` split into `generic`, `female`, `male`), `it` and `ru` (split into `female`, `male`), `en_US` (`postcode_by_state.ts`, `street_name.ts`), `en_GB`, `en_CA`, `en_AU`, `en_IE`, `de_AT`, `de_CH`, `fr` and `sv` (`street_pattern.ts`). Other locales U until the xtask runs. Faker does not document where each upstream list comes from (U). The lists are names and place names, not person records |
| **Unicode CLDR** (`cldr-json` `cldr-localenames-full` territories, `common/subdivisions/<lang>.xml`), pinned release | country names, ISO 3166-2 subdivision codes and names | Unicode License v3 ("Permission is hereby granted … to deal in the Data Files … without restriction"; the notice is required) | V: licence text read 2026-10-23; `en/territories.json` has `"DE": "Germany"`; `subdivisions/en.xml` has `debw` → "Baden-Württemberg". `Unicode-3.0` is already on ADR 0017 §5's allow-list (V) |
| **EFF large wordlist**, already embedded in `rizzy-core` | nicknames (§4 step 9) | CC BY 4.0; attribution already in `THIRD_PARTY_NOTICES.md` | V. No new obligation |

**Rejected or deferred:**

| Source | Why |
|---|---|
| `philipperemy/name-dataset` (PyPI `names-dataset`) | **Rejected.** Its README says its 730K first names and 983K last names were "extracted from the Facebook massive dump (533M users)" (V, README read 2026-10-23). That is leaked personal data, whatever licence the repository carries |
| Wikipedia name lists | **Rejected for v1.** CC BY-SA 4.0. Creative Commons declared GPLv3 a "BY-SA–Compatible License" for 4.0, one way only (V, creativecommons.org compatible-licenses page, read 2026-10-23). It names GPLv3, not AGPLv3. Whether the material can reach an AGPL-3.0-only work through GPLv3 §13 is a legal reading this ADR does not make (U). The share-alike terms would also attach to the data file |
| Python Faker (`joke2k/faker`) | MIT (V, `LICENSE.txt` read). Usable as a second source for locales faker-js lacks. Not needed for the recommended v1 set |
| Government name statistics (for example, US SSA baby names) | US federal works are generally public domain (17 U.S.C. §105, L). The SSA page returned HTTP 403 to this check (U). They give more realistic frequencies, one country at a time. Deferred: a later data version can add them per country, each with its own provenance lines |
| GeoNames postal-code dump | CC BY 4.0 (V, `export/zip/readme.txt`). Its GB file, however, "Contains Royal Mail data Royal Mail copyright and database right" (V). It would give real city–postcode pairs, which is the realism trade-off §7 declines for v1 |
| Google address metadata (`chromium-i18n` / libaddressinput data) | The libaddressinput repository is Apache-2.0 (V). The served JSON (for example `data/DE`, whose postcode regex is five digits) carries no licence statement (V, fetched), so its redistribution terms are U. Not needed: faker-js has the postcode patterns |
| Google libphonenumber `PhoneNumberMetadata.xml` | Apache-2.0 (V, file header). Could cross-check phone formats. Not needed for fictional ranges (§7) |

**Licence obligations.**

- MIT and Unicode-3.0 are permissive. Every artifact that contains the data must carry their notices.
- The EFF list already has the same duty, and it is met the same way:
  - `THIRD_PARTY_NOTICES.md` gains a "faker-js locale data" section and a "Unicode CLDR" section, each with the full notice text.
  - The web vault's and the extension's "Open-source licenses" view and `rv`'s notices show them ([ADR 0017](0017-licensing.md) §7).
- Combining data under these licences into an AGPL-3.0-only work is the ordinary case of permissive material in a copyleft work (L).

**The xtask:** `cargo xtask identity-data --faker <checkout> --cldr <checkout> [--check]`.

- **Input.** It reads local checkouts of the pinned upstream tags, which the maintainer fetches. The xtask does no network I/O itself, so a run is reproducible.
- **Verification.** It checks each input file against the SHA-256 listed in `data/identity/SOURCES.md`. That file records, per input file, the upstream URL, tag, commit, path, SHA-256 and licence.
- **Conversion.**
  - It applies the content rules and caps (§5).
  - It maps locales to countries (for example `de` → DE, `de_AT` → AT), using faker's own fallback chain `en_US` → `en` for first names.
  - It writes `identity-data-v1.txt` and records the output's SHA-256 in `SOURCES.md`.
- **`--check`.**
  - It regenerates the output and fails on any byte difference.
  - CI cannot run it, because the upstream checkouts are not committed. It is run by hand before a data change is merged, and the reviewer re-runs it.
- **Dependencies.**
  - It uses only crates already in `[workspace.dependencies]`.
  - A narrow hand-written extractor reads faker-js's `.ts` files. It accepts the `export default [ '…', … ]` and `{ female: [ … ], male: [ … ] }` shapes only. Any other shape is an error, never a guess.

### 7. Addresses and phones: consistency level and realism

- **Consistency.**
  - Within the chosen country:
    - the postcode matches one of the country's patterns;
    - the subdivision is a real subdivision of that country;
    - the city is a real city name of that country;
    - the street is a plausible street name for that country.
  - City, subdivision and postcode are **not** guaranteed to form a real combination. They are paired only where the upstream data already pairs them cheaply: US and CA postcode-by-state, and city|subdivision where faker lists it.
  - Real city–postcode pairs (GeoNames) were declined. They cost size and licence work, and they make it likelier that the whole generated address is somebody's real address.
- **Collision with reality.**
  - Any generated name, street and number can coincide with a real person or a real address.
  - The create form says so in one line: "Generated details are random and may match real people or places. Don't use them where you must give your real details."
  - The data never contains person records. Names, streets and cities are separate lists, drawn independently.
- **Phones** (Open question 5).
  - A random number in a country's real format can belong to a real subscriber, who would then receive the sign-up SMS codes.
  - Recommended: generate phones **only** from published fictional ranges. For example, NANP 555-0100 to 555-0199 for US and CA.
    - Source: Wikipedia, "Fictitious telephone number", read 2026-10-23 (L). The page also lists ranges for AU (for example `0491 570 xxx`), FR, DE, HU, IE, KR, SE and the UK.
    - A range enters the data file only with a citation of the regulator's own document in `SOURCES.md`. Until then each range is U.
  - Countries without a verified range get no phone.
  - A site that validates numbers may reject a fictional one. That cost is accepted.
- **Fingerprinting.**
  - A site that wants to can recognise identities drawn from a public list with a public algorithm, and fictional phone ranges.
  - Accepted: the feature is for throwaway sign-ups, not for passing as a specific real person.

### 8. Email before masked email exists (until M6)

Until M6 there is no masked-email domain, so the generator takes `email_domain` from the user (Open question 2, resolved as (a) by "Owner answers (2026-10-23, before acceptance)").

- **Decided:** a user-set "email domain for generated identities", such as the user's own catch-all domain or a forwarding service's domain. It is one domain. Where it is stored is Open question 7.
- **The email field until M6 is a plain email input**, holding the whole address. There are no registered masked-email domains yet, so §9 item 5's domain picker has nothing to recognise.
- **The interim domain does not get the domain button before M6.** It is a single domain, so a selector would offer one choice. Turning the setting into a list only to give the button something to list is scope the owner did not ask for. If the owner wants several interim domains, that is a small amendment: the setting becomes a list (at most 8), its first entry is the default, and §9 item 5 applies to the list unchanged. After M6, the interim domain joins the picker's list (§9 item 5).
- **No domain set.**
  - `identity.email` is **left empty**, and the field shows "Set an email domain to generate addresses".
  - The username (the nickname) is still filled.
  - A local part with no domain, or a placeholder domain such as `example.com`, is not used: it would be stored as if it were an address.
- **INV-65.**
  - The interim domain is the user's own. INV-65 governs **our** M6 aliases (THREAT_MODEL §4 A11 and §6.4, `smtp` RCPT probing). It does not bind a third-party catch-all.
  - The create form still says that a name-style address on a catch-all domain is easy to guess.

### 9. The masked-email seam (M6, after v1.0; nothing here is built by this ADR)

These requirements bind the M6 ADRs ([ADR 0068](0068-alias-identity-model.md) and [ADR 0069](0069-smtp-ingress-architecture.md), both Proposed, or their successors), so that M6 can plug into the generator without changing it:

1. **Link.**
   - When the mail module is enabled on the server, its configured mail domains are the **registered masked-email domains**. The first one is offered as the default `email_domain`, unless the user's saved default (Open question 7) is one of them.
   - The item links to its alias through ADR 0068's encrypted `alias.id` key. Before ADR 0068 is accepted, that key's Types column must widen from Login to **Login and Identity**.
   - The server keeps no item link (ADR 0068 §3).
   - The `mail_aliases` row is created **when the identity is saved, not when the form opens**. Otherwise every "New identity" form that is opened and then discarded would create an alias.
   - Regenerating the email before saving creates nothing.
2. **Entropy.**
   - Under INV-65 as it stands, the M6 local part is the §4 step 10 local part, then `.`, then a 13-character lowercase base32 token carrying 65 bits from the CSPRNG. For example: `anna.mueller98.k3x9q2m7w4p8r`.
   - The owner may amend INV-65 instead (Open question 3).
   - The token is drawn as a new step 11, after every v1 step, so the M3 vectors stay valid.
3. **Latest messages.**
   - The identity view gets a "Mailbox" panel showing the newest 5 messages for that `alias_id`: sender, subject, received time, and an "Open" link to ROADMAP §4.8's full mailbox view.
   - The messages are listed by `alias_id` through the M6 mailbox API and decrypted on the client with the mail key (ADR 0006 point 8).
   - Nothing about messages is stored in the item.
4. **Confirmation-code recognition.**
   - Codes are found **on the client, after decryption**. The server never sees plaintext (ROADMAP §2, principle 1).
   - A pure `rizzy-client` function, `extract_codes(subject, text_body, patterns) -> Vec<CodeCandidate>`, runs the built-in **default** patterns first, then the user's **custom** patterns.
   - The default patterns match:
     - 4–8 digit or alphanumeric codes near keywords such as "code", "verification", "OTP" and "confirm", in the v1 languages;
     - links whose path contains `verify` or `confirm`.
   - Custom patterns use a restricted template syntax: literal text plus a typed slot, such as `{6d}` or `{8an}`. They are not full regular expressions, so there is no backtracking risk and no regex dependency.
   - Limits: a pattern is at most 200 bytes, and a user has at most 64 of them. The pattern parser gets a fuzz target.
   - Custom patterns are account data. They sync encrypted as a new [ADR 0042](0042-account-settings-matching-layout.md) settings tag, which the M6 ADR assigns.
   - A detected code is offered for copying and autofill, as ROADMAP §4.8 (Should) describes: "Extract OTP / verification links from mail and offer them in autofill".
5. **The email field's domain picker** (the owner's answer (4)).
   - **What AliasVault does** (V, read 2026-10-23 at commit `4f0208ed7dbafb3656bc54e16fdef437316c4689`):
     - `apps/web/src/components/forms/EmailDomainField.tsx`: `isAliasDomain` (lines 13–14) checks the address's domain against the server's public, private and hidden-private domain lists. On load, a recognised domain puts the field in "alias" mode, anything else in free-text "email" mode (lines 37–40, 61–70).
     - In alias mode the text input holds only the local part (line 188). Next to it is a button showing `@` and the domain (lines 189–194). The button toggles a popup (line 190) that lists the visible private domains under "Private Email (AliasVault server)" and the public SpamOK domains under "Public Temp Email Providers", as chip buttons (lines 202–226).
     - Picking a domain (`selectDomain`, lines 119–125) replaces only the domain and keeps the local part. Typing `@` into the local part switches to free-text mode (lines 95–98). An "Email / Alias" toggle above the field switches modes by hand (lines 169–175), and a regenerate button sits at the end (lines 195–199).
     - The lists come from the server: `PRIVATE_EMAIL_DOMAINS` and `HIDDEN_PRIVATE_EMAIL_DOMAINS` environment variables (`apps/server/AliasVault.Api/Program.cs` lines 55 and 61), and a hard-coded public list (`apps/server/AliasVault.Api/Helpers/EmailDomainHelper.cs` line 20). They reach the client as `EmailDomains` (`apps/server/Shared/AliasVault.Shared/Models/WebApi/V2/Vault/EmailDomains.cs`) and are kept in vault metadata (`apps/web/src/vault/VaultStore.ts` lines 36–37). Hidden private domains are recognised but not offered (`EmailDomainField.tsx` line 36).
     - The popup has no `role`, no `aria-expanded` and no key handling: the file has no `onKeyDown`, `role=` or `aria-` attribute (V, searched). The chips are buttons with `aria-pressed` (`apps/web/src/components/shared/ToggleChip.tsx` line 16). The extension and the mobile app have their own copies (`apps/browser-extension/src/entrypoints/popup/components/Forms/EmailDomainField.tsx`, `apps/mobile-app/components/form/EmailDomainField.tsx`), not reviewed here.
   - **What we do.** The picker is built with M6, together with the registered domains it lists. The M3 implementation keeps a plain email input (§8).
     - **The list.** The registered masked-email domains (item 1), plus the user's interim domain (§8) if it is set and not already in the list. No third-party public temp-mail domains: their mail is readable by anyone who knows the address, and they are not ours to offer.
     - **Untrusted input.** The client takes the list from the server's M6 configuration response, keeps at most 64 entries, and drops any entry that fails §3's domain syntax. It is a UI list only: the server's own check that an alias's domain is one of its configured domains (ADR 0068 §3, the `domain` column) is what binds.
     - **Recognition.** The email's domain is the text after its last `@`. It is recognised when it equals an entry of the list, compared in ASCII lower case.
     - **Rendering.** A recognised address renders as `[local-part input] @ [domain button]`. Anything else (an unrecognised domain, no `@`, an empty list) renders as a plain email input with the whole address, exactly as before M6.
     - **The button.** It looks like a button and shows the domain. It is built as the WAI-ARIA Authoring Practices **select-only combobox** (L): `role="combobox"`, labelled "Email domain", with `aria-haspopup="listbox"`, `aria-expanded` and `aria-controls`, and the current domain as its value. Enter, Space, Down or Alt+Down opens a listbox of the list's domains, with the current one selected.
     - **The listbox** (`role="listbox"`, one `option` per domain): Up and Down move, Home and End jump, Enter chooses, Escape closes without a change, and focus stays on (or returns to) the combobox. A pointer click outside closes it without a change.
     - **Choosing a domain** replaces only the part after the last `@`. The local part and its edit state are unchanged. The stored `identity.email` is always the whole address `local@domain`: the picker is presentation only, with no new key and no new format.
     - **The local part** stays an editable input. Typing `@` into it switches the field to the plain input with the whole text, as AliasVault does. Clearing the field and typing a recognised address switches back.
     - **Where.** The web vault's `identity.email` field, on create and on edit. Other email fields (`login.email`) and the extension are left to the M6 ADR.
     - **Tests, with M6.** A web e2e with a stubbed list of registered domains: a recognised address renders split, choosing a domain keeps the local part, typing `@` falls back to the plain input, and an unrecognised domain renders plain. The split field and the open listbox are added to the axe audit and to the keyboard-only walk, with no rule suppressed. A unit test covers recognition (case, the last `@`, the 64-entry cap, invalid entries dropped).

### 10. UI scope

**Web vault, "New identity".**

- The form opens **already filled** by `generate_identity` with the defaults (§3, §8).
- Above the fields sits a generator bar:
  - **Sex:** a radio group, Male / Female. Its initial value is the default if one is set, else a random draw (§4 step 1).
  - **Country:** a select over the bundled set, with CLDR English names.
  - **Age:** a select listing the presets of §3 in their order, then **"Custom range"** and **"Exact age"**.
    - "Custom range" shows two labelled number inputs, Min and Max. "Exact age" shows one, Age. Both accept 18–99.
    - An invalid value (out of bounds, or Min above Max) shows an inline error tied to its input with `aria-describedby`, and nothing is redrawn until the value is valid.
    - A valid change redraws the birthday, and the email if it is still the generated one (§4).
    - When the form opens with a remembered range, the select shows the first preset with the same `min` and `max`, else "Exact age" if `min = max`, else "Custom range".
  - **Email style:** a radio group, "Name + birthday" / "Nickname".
  - A **Regenerate all** button.
- Each generated field has a **Regenerate** icon button (`aria-label` "Regenerate first name", and so on).
- Changing a picker redraws the dependent fields (§4) that the user has **not edited**.
- A field the user has typed in is never overwritten by a picker change or by Regenerate all. Only that field's own Regenerate button overwrites it.
- A polite live region announces each regeneration, for example "First name regenerated".
- A **Start blank** button clears every generated value, for users entering their real identity.

**Sex and Birthday in the field list.** These apply everywhere identity fields are shown and edited:

- `FIXED_FIELDS.identity` gains Sex: a select with Male and Female, or the stored text if it is anything else.
- It also gains Birthday: a date input when the value parses as `YYYY-MM-DD`, else a text input.

**Edit form.** There is no generator on the edit form in v1, since the owner's words are "when creating". The per-field Regenerate buttons appear only on create.

**Accessibility.**

- The generator bar and its controls are added to the web e2e axe audit and to the keyboard-only walk (`apps/web/e2e/a11y.ts`, `keyboard-nav.spec.ts`).
- They must pass with no rule suppressed.

**`rv`.**

- `rv generate identity [--sex male|female] [--country CC] [--age MIN-MAX|N|PRESET] [--email-style name|nickname] [--domain D] [--json]` prints a generated identity. `--age 28` is the exact age 28, `--age 18-27` a range, and `--age any` (or another preset `id` from §3) a preset.
- `rv add identity --generate [same flags]` pre-fills the create op.
- Both use the leaf's OS RNG and the local date.

**Extension.**

- It shows and edits the two new keys wherever it renders identity fields.
- It has **no generator in v1**. Generating from sign-up forms is ROADMAP §4.8's M6 row.

**Native apps (M3 desktop and later).** When they add identity creation, they call the same `rizzy-client` function through their bindings ([ADR 0019](0019-native-clients.md)). There is no separate implementation.

### 11. What this ADR does not change (checked for supersession)

| Document | Effect of this ADR |
|---|---|
| ADR 0018 §6, §7 (existing rows and the concealment list) and §11 | Unchanged. Two rows are added under §7's own rule |
| ADR 0042 §2–§5 | Unchanged. A tag is added under §2's own rule, and only if Open question 7 is answered (a) |
| ADR 0056 §2's index list | Unchanged |
| ADR 0076 | Unchanged. Identity autofill remains future work |
| ADR 0016 crate rules | Unchanged. No new crate or dependency edge. Nothing new depends on `getrandom`; the leaf crates already do |
| ADR 0017 | No rule changes. The new third-party data uses licences already on the allow-list, and its notices follow §7 |
| CRYPTO.md §12.1 | Gains a paragraph on acceptance. That is a documentation change, not a mechanism change |
| INV-65 | Not changed by this ADR. Open question 3 asks the owner whether to change it |

### On acceptance

1. **ROADMAP (needs owner approval).**
   - Add this row to [§4.2](../ROADMAP.md#42-core-vault-m1): `| S | Identity generator: new identities open pre-filled (sex, country, age preset, custom range or exact age; names by country, birthday, email, username, address, phone from fictional ranges) with per-field regenerate; web vault and rv ([ADR 0079](adr/0079-identity-generator.md)) | M3 |`.
   - If the owner prefers M8 or post-1.0 instead, this ADR's milestone header follows.
2. **ROADMAP §4.8**, first row: append "; builds on the M3 identity generator ([ADR 0079](adr/0079-identity-generator.md) §9)".
3. **CRYPTO.md §12.1**, "What the RNG produces":
   - Add "generated identities ([ADR 0079](adr/0079-identity-generator.md))".
   - Add one sentence: identity generation uses the same uniform-index routine without the constant-time copy, because the output is not a secret.
4. **THREAT_MODEL.md §4 A11 (Mitigations).** Next to the existing "Random name aliases …" sentence, add that ADR 0079 §9 item 2 is how generated identity addresses meet INV-65, or the owner's amended INV-65 (Open question 3).
5. **ADR 0042 §2**, only if Open question 7 is answered (a): an Amendments entry for the tag (the next unassigned one at that time) and the layout given in Open question 7.
6. **Proposed ADR 0068**, before its own acceptance: widen `alias.id`'s Types to Login and Identity (§9 item 1).
7. **Status bookkeeping:** CLAUDE.md's status line and the README index row.

`THIRD_PARTY_NOTICES.md`, `data/identity/SOURCES.md` and the schema doc table in `schema.rs` change with the implementation, not on acceptance.

### 12. Tests (for the implementation)

**Known-answer vectors**, in `crates/rizzy-client/src/identity_gen/tests.rs`:

- They use a seeded `ChaCha20Rng` (a dev-dependency `rizzy-client` already has) and a fixed `today` of 2026-10-23.
- They cover at least three countries × both sexes × both email styles, checking the exact output pairs.
- They include a 29 February `today` and a 29 February birthday.
- They cover each age mode: the preset 18–27, the preset 28+ (28–65), a custom range, and the exact age 28 (`[28, 28]`), the last also with a 29 February `today`.
- One vector pins `identity-data-v1.txt`'s SHA-256 and `VERSION`.

**Property tests**, for any seed, any supported option set and any `today` from 1970 to 2199:

- The age in completed years is in `[min, max]`. For an exact age `[n, n]` it is `n`, and the draw spans exactly 365 or 366 dates.
- Every entry of `AGE_PRESETS` validates and keeps its age in its bounds.
- The birthday is a valid `YYYY-MM-DD`.
- The email local part is at most 64 octets of `[a-z0-9._-]`, with no misplaced dots.
- The postcode matches one of the country's patterns.
- `identity.state` is one of the country's written forms.
- No field outside §3's list is generated. `ssn`, `passport_number` and `drivers_license` never are.
- `regenerate_field` changes only that field and its dependents.
- The same seed gives the same output.

**Uniformity smoke test.** A χ² check, over 100k draws, on `uniform(2)` for sex and on the birthday's day of year. It must stay fast and deterministic.

**Preset list test.** A unit test pins `AGE_PRESETS`: the twelve `id`s, their `min` and `max`, and their order (§3). Changing the list is a reviewed change to this test.

**Data tests.** The embedded file parses, is at most 384 KiB, follows the content rules (§5), and has the expected `NAME` and `VERSION`.

**Schema tests**, in `rizzy-core`:

- The two keys classify as `Known`: Text, Identity, not concealed.
- An older-client simulation, using the existing ADR 0018 §11 harness, carries them byte for byte.

**Fuzz targets.**

- `identity_data`: the data parser, on arbitrary bytes.
- `identity_options`: domain and age validation (preset `id`, custom range and exact age), on arbitrary input.

**Web e2e**, in `apps/web/e2e/identity-generator.spec.ts`:

- A new identity opens pre-filled.
- Each picker redraws only the untouched dependent fields.
- Each field's Regenerate button works, and Regenerate all keeps fields the user edited.
- Start blank clears every generated value.
- With no domain set, the email stays empty.
- The age select: each preset, "Custom range" and "Exact age" redraw the birthday inside the chosen bounds; an invalid custom value shows its error and redraws nothing; a remembered exact age reopens as "Exact age".
- The email field is a plain input (no registered domains before M6, §8).
- Saving persists all fields, and they survive a reload and a sync.
- An item whose `identity.sex` holds other text shows it as entered.

**Accessibility.** The axe audit and the keyboard-only walk cover the generator bar, including the age select with both custom modes open.

**`rv`.** CLI e2e tests for `rv generate identity --json` (its shape, a valid date, the country, and `--age` in all three forms) and for `rv add identity --generate`.

**wasm.** `cargo xtask expand-bindings --write`, with the reviewed baseline. Any rise in the `unsafe` count from the new exports must be explained in the review (AGENT_BRIEF).

### Owner answers (2026-10-23, before acceptance)

The owner gave two answers after the first draft of this ADR, verbatim. They are not an acceptance: the Status stays Proposed.

1. Age: "18-27 or 28, presets like aliasvault's and ability to set custom age range or custom age".
   - **Taken as:** the preset list of §3, which is AliasVault's nine five-year presets and its "Random" (21–65) plus the owner's 18–27 (first and the first-time default) and 28+ (28–65); a **Custom range** mode; and an **Exact age** mode, passed to the generator as `[n, n]`.
   - The draw is unchanged: uniform over the dates whose completed age today is in `[min, max]` (§4 step 4). AliasVault's birth-year approximation is not copied (§3).
   - Changed by it: §3 (`AgeRange`, `AGE_PRESETS`, `age_presets()`), §10 (the age select, `rv --age`), §12 (vectors, properties, the preset list test, e2e, accessibility), Open question 7 (the mode is derived, not stored) and the proposed ROADMAP row's wording. Open question 1 is resolved.
2. Email domain picker: "the mail one works similar to aliasvault if registered masked mail domain is recognized - make its domain part as button which opens selector for different registered domain mails".
   - **Taken as:** §9 item 5. When the address's domain is one of the registered masked-email domains, the field is `[local-part input] @ [domain button]`, and the button opens an accessible listbox of those domains; choosing one replaces only the domain. An unrecognised domain is a plain email input. The registered domains are server configuration that arrives with M6, after v1.0, so the picker is built with M6.
   - **Open question 2:** the answer describes every generated address as carrying a domain the user can switch, which rules out (b) (no domain) and (c) (no email until M6). This ADR therefore takes (a), the user-set interim domain (§8). The owner may still say otherwise at acceptance.
   - **The interim domain before M6:** a plain input, no button, because a single domain leaves nothing to select (§8). After M6 it joins the picker's list.
   - Changed by it: §8, §9 items 1 and 5. Open question 2 is resolved.

## Consequences

### Positive

- One click, or none, gives a complete throwaway identity. All its fields are real item fields: synced, exported and later autofillable.
- Sex and birthday become first-class fields. A later importer change can map AliasVault's gender and birthdate to them instead of to custom fields.
- The M6 alias work gets a fixed integration point (§9) without building mail now.
- The data is reproducible from pinned upstream files, with checksums and attribution, like the EFF list.

### Negative

- Every client bundle carries about 250–350 KiB of data (U until measured).
- Each data version is a maintenance chore: an xtask run, a review and new vectors.
- Every client artifact carries two more licence notices.
- Older clients show the two new keys as raw "other" fields until they update.
- Interim emails need the user to own or rent a catch-all domain. Without one, the email field stays empty.

### Risks

- **Data provenance inside faker-js.**
  - Faker does not document the provenance of each file (U).
  - Mitigations:
    - the bundle holds names and place names only, never records;
    - the sources above with unacceptable provenance are rejected;
    - a later data version can swap in government statistics per country.
- **Real-person collisions** of generated addresses or names (§7).
  - Mitigations:
    - the notice on the form;
    - fictional phone ranges only;
    - no national-ID numbers, ever.
- **The INV-65 conflict** in M6 (Open question 3) stays open until the owner answers it. M6 cannot start its alias generator without that answer.
- **The size budget** may not hold a larger country set. Mitigation: Alternative D is the documented fallback.

## Alternatives considered

- **A. The generator in `rizzy-core`, next to the password generator.** Rejected:
  - the server would carry the data;
  - the crypto audit surface would grow by content that is not cryptography.
- **B. The generator in TypeScript in the web vault.** Rejected:
  - `rv` and the native apps would each re-implement it, against ADR 0013's one-client-core rule;
  - there would be no shared vectors.
- **C. An Enum for `identity.sex` and a U64 for `identity.birthday`.** Rejected (§1):
  - older clients could not display them;
  - U64 milliseconds shift a civil date across time zones.
- **D. The data as a separate, lazily fetched static asset.**
  - `identity-data-v1.txt` would sit beside the wasm and be fetched on the first "New identity". It would be checked against a SHA-256 compiled into `rizzy-client`.
  - It keeps the wasm smaller. It costs one request and a failure path when offline.
  - Kept as the fallback if §5's budget is exceeded.
- **E. Real address combinations from GeoNames.** Rejected for v1 (§7):
  - the size;
  - the Royal Mail database-right carve-out;
  - a higher chance of producing a real person's full address.
- **F. Random phone numbers in the real national format.** Rejected (§7): the sign-up codes would go to a stranger.
- **G. Name-style masked addresses without a random token, in M6.** This ADR cannot choose it: INV-65 as written forbids it (Open question 3).
- **H. Downloading name lists in the client at runtime.** Rejected:
  - the vault would make network requests to third parties;
  - there would be no integrity anchor;
  - it would leak to those parties when users create identities.

## Open questions for the owner

1. **Age-range presets.** *Resolved* by the owner's answer (3) of 2026-10-23: AliasVault's presets plus 18–27 and 28+, a custom range and an exact age (§3, §10; "Owner answers (2026-10-23, before acceptance)"). The numbering of the questions below is kept, because the Decision refers to them by number.
2. **The email domain before M6.** *Resolved* as (a), a single user-set domain with the email left empty while it is unset (§8), read from the owner's answer (4); see "Owner answers (2026-10-23, before acceptance)". The masked-domain part of the email field is §9 item 5. The rejected options were (b) a local part with no domain, which stores something that is not an address in an email field, and (c) no email until M6, which drops part of the request for a year or more.
3. **The masked-email local part versus INV-65 (M6).**
   - Your shape, "first and last name + bday … @ maskeddomain", is what THREAT_MODEL §4 A11 calls guessable.
   - INV-65 requires at least 64 CSPRNG bits beyond name or digit decoration, to stop RCPT probing and alias enumeration.
   - Options:
     - (a) Keep INV-65, and append a 13-character base32 token (§9 item 2): `anna.mueller98.k3x9q2m7w4p8r`.
     - (b) Amend INV-65 and THREAT_MODEL Q-18 to accept guessable name-style aliases, relying on RCPT rate limits only.
     - (c) Offer both: (a) by default, and (b) behind a warning.
   - **Recommendation: (a).** This question concerns M6 only. The interim user domain (§8) is not affected.
4. **What "all data" includes.**
   - **Recommendation:**
     - Fill: sex, first and last name, birthday, username (the nickname), email (when a domain is set), address line 1, city, state or province, postcode and country.
     - Also fill a title derived from sex (Mr/Ms, Herr/Frau, M./Mme), and a phone as decided in question 5.
     - Leave middle name, company and address lines 2–3 empty.
     - Never generate SSN, passport or driver's licence numbers.
   - Alternatives: also fill a middle name in countries that use one (the US), or a company name (faker has company lists, MIT).
5. **Phone numbers.**
   - (a) Only from documented fictional ranges; blank where a country has none.
   - (b) Realistic random numbers in the national format.
   - (c) Never generate phones.
   - **Recommendation: (a)** (§7). With (b), sign-up codes can go to a real stranger.
6. **The v1 country set.**
   - **Recommendation:** 13 Latin-script countries whose surnames do not change by sex, and whose faker-js data covers names, streets, cities, subdivisions and postcodes: **US, GB, CA, AU, IE, DE, AT, CH, FR, ES, IT, NL, SE**.
     - Coverage is V for US, GB, CA, AU, IE, DE, AT, CH and FR, for IT (first names) and for SE (street patterns).
     - Coverage is U for ES and NL until the xtask runs.
   - A second batch, **PL, CZ, RU, UA**, waits for curated sex-split surname lists and a transliteration table for the ASCII email form.
     - faker-js's `pl` surnames are a single `generic` list (V), but Polish surnames change by sex (-ski/-ska).
     - faker-js's `ru` first names are split by sex (V).
   - If your own country should be in v1, say which.
7. **Where the generator's defaults live**: the default sex, country, age range, email style and email domain.
   - (a) Synced, in the encrypted account settings, as an ADR 0042 tag.
     - The tag is the next unassigned one at acceptance. ADR 0080, drafted in parallel, may need one too.
     - Layout: `u8 sex_default` (0 = random, 1 = male, 2 = female) ‖ `[2] country` (ASCII A–Z, or `0x0000` = none) ‖ `u8 age_min` ‖ `u8 age_max` (18 ≤ min ≤ max ≤ 99) ‖ `u8 email_style` (1 = name and birthday, 2 = nickname) ‖ `str(email_domain)` (empty = unset, else §3's syntax, at most 253 bytes).
     - Any other value is a violation inside a recognised tag, so ADR 0042's reject rule applies.
     - **The age mode is not stored**, only `age_min` and `age_max`. The picker derives the mode on open (§10): the first preset with the same bounds, else "Exact age" when `min = max`, else "Custom range". A custom range that equals a preset therefore reopens as that preset, which draws the same way. Adding or reordering presets later changes no stored byte and needs no tag change.
   - (b) Session-only, like the password generator's memory. The domain must be retyped after every unlock.
   - (c) Device-local storage.
   - **Recommendation: (a).** The catch-all domain belongs to the account, not to a device, and (b) makes the interim email impractical.
8. **Extension and `rv` scope in v1.**
   - **Recommendation:**
     - `rv generate identity` and `rv add identity --generate` in v1. They are cheap and share the vectors.
     - No generator in the extension until M6's sign-up-form row.

## References

- [ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), [§4.8](../ROADMAP.md#48-aliases--email-receiving-m6); §3 (M6 after v1.0, owner decision of 2026-10-22)
- ADRs:
  - [ADR 0013](0013-shared-client-core.md) §3–§4
  - [ADR 0016](0016-workspace-layout.md)
  - [ADR 0017](0017-licensing.md) §1, §5, §7
  - [ADR 0018](0018-item-record-encoding.md) §6, §7, §11
  - [ADR 0019](0019-native-clients.md)
  - [ADR 0020](0020-partial-supersession.md) point 9
  - [ADR 0036](0036-browser-extension-architecture-and-key-custody.md)
  - [ADR 0042](0042-account-settings-matching-layout.md) §2
  - [ADR 0055](0055-m3-item-type-field-keys.md)
  - [ADR 0056](0056-local-index-recently-used-search.md) §2
  - [ADR 0068](0068-alias-identity-model.md) (Proposed)
  - [ADR 0069](0069-smtp-ingress-architecture.md) (Proposed)
  - [ADR 0076](0076-autocomplete-driven-autofill.md) §3
- [CRYPTO.md §2](../CRYPTO.md#2-conventions), [§12.1](../CRYPTO.md#121-randomness); [THREAT_MODEL](../THREAT_MODEL.md): AST-7, §4 A11, §6.4, INV-65, Q-18
- Code: `crates/rizzy-core/src/item/schema.rs`, `crates/rizzy-core/src/generator/{mod.rs,wordlist.rs}`, `crates/rizzy-import/src/aliasvault.rs`, `apps/web/src/fields.ts`, `apps/web/src/generator-memory.ts`, `crates/xtask/src/equivalence_list.rs`, `THIRD_PARTY_NOTICES.md`
- External sources, all read 2026-10-23:
  - faker-js: <https://github.com/faker-js/faker> (`LICENSE`, `package.json` 10.6.0, `src/locales/*`)
  - Unicode License v3: <https://www.unicode.org/license.txt>; CLDR: <https://github.com/unicode-org/cldr>, <https://github.com/unicode-org/cldr-json>
  - Creative Commons, compatible licences: <https://creativecommons.org/share-your-work/licensing-considerations/compatible-licenses/>
  - name-dataset README: <https://github.com/philipperemy/name-dataset>
  - GeoNames postal-code readme: <https://download.geonames.org/export/zip/readme.txt>
  - Python Faker licence: <https://github.com/joke2k/faker/blob/master/LICENSE.txt>; the libphonenumber metadata header; libaddressinput's `LICENSE`
  - Wikipedia, "Fictitious telephone number" (secondary source, L)
  - AliasVault, <https://github.com/aliasvault/aliasvault> at commit `4f0208ed7dbafb3656bc54e16fdef437316c4689` (AGPL-3.0; read for behaviour only, no code or data copied): `core/rust/src/identity_generator/{mod.rs,tests.rs}`, `apps/web/src/pages/settings/IdentityGenerator.tsx`, `apps/web/src/components/forms/EmailDomainField.tsx`, `apps/web/src/components/shared/ToggleChip.tsx`, `apps/web/src/vault/VaultStore.ts`, `core/client/src/database/repositories/SettingsRepository.ts`, `apps/server/AliasVault.Api/{Program.cs,Helpers/EmailDomainHelper.cs}`, `apps/server/Shared/AliasVault.Shared/Models/WebApi/V2/Vault/EmailDomains.cs`
  - WAI-ARIA Authoring Practices Guide, "Select-Only Combobox" example: <https://www.w3.org/WAI/ARIA/apg/patterns/combobox/examples/combobox-select-only/> (L)
