# Identity data provenance (ADR 0079 §5, §6)

`crates/rizzy-client/src/identity_gen/identity-data-v1.txt`, the identity generator's bundled name
and address data, is compiled by `cargo xtask identity-data` (`crates/xtask/src/identity_data.rs`)
and is never edited by hand. This file is both an input and an output of that command:

- **Input.** The `identity-data-inputs` block below lists every upstream file the run reads, with
  its SHA-256. The xtask refuses to write anything if a file it reads is missing from the block,
  differs from its hash, or if a listed file is not read.
- **Output.** Everything between the `BEGIN GENERATED` and `END GENERATED` markers is rewritten by
  each run: the output's size and SHA-256, the per-file table with upstream URLs and licences, the
  sampling rule, every list's drop counts, and every country's derivations.
  `cargo xtask identity-data ... --check` regenerates both files and fails on any byte difference.

Everything outside the markers is written by hand.

## Upstream pins

| Upstream | Tag | Commit | Licence | Verified (2026-10-24) |
|---|---|---|---|---|
| [faker-js](https://github.com/faker-js/faker) | `v10.6.0` (release published 2026-08-14) | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | MIT | GitHub API `GET /repos/faker-js/faker/git/ref/tags/v10.6.0` gives this commit (a lightweight tag). The tag tarball `https://github.com/faker-js/faker/archive/refs/tags/v10.6.0.tar.gz` had SHA-256 `91b1996eb05266fe2c230a5550609921c05234b0ff2af83d92858a35351a3b42` when downloaded (GitHub generates these archives, so this hash is a record, not a promise). Each of the 117 files read has the git blob SHA-1 that the commit's tree lists (`GET /repos/faker-js/faker/git/trees/<commit>?recursive=1`) |
| [Unicode CLDR](https://github.com/unicode-org/cldr) | `release-49` (CLDR 49, release published 2026-10-21) | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | Unicode-3.0 | GitHub API `GET /repos/unicode-org/cldr/git/ref/tags/release-49` gives this commit (a lightweight tag). The 9 files read were fetched one by one from `https://raw.githubusercontent.com/unicode-org/cldr/release-49/<path>`, and each has the blob SHA-1 that `GET /repos/unicode-org/cldr/contents/<path>?ref=release-49` reports |

The licence texts are in `THIRD_PARTY_NOTICES.md` ("faker-js locale data", "Unicode CLDR"),
copied from `LICENSE` at each tag.

ADR 0079 §6 names `cldr-json` `cldr-localenames-full` for the territory names. The run reads the
same data from the CLDR repository's own `common/main/en.xml` at `release-49` instead (`cldr-json`
is generated from these XML files), so one pin covers every CLDR input.

## Fetching the inputs and re-running

```sh
mkdir -p /tmp/idg-up && cd /tmp/idg-up
curl -fL -o faker-v10.6.0.tar.gz https://github.com/faker-js/faker/archive/refs/tags/v10.6.0.tar.gz
tar xzf faker-v10.6.0.tar.gz     # creates faker-10.6.0/
for p in common/main/en.xml common/supplemental/subdivisions.xml \
         common/subdivisions/de.xml common/subdivisions/en.xml common/subdivisions/es.xml \
         common/subdivisions/fr.xml common/subdivisions/it.xml common/subdivisions/nl.xml \
         common/subdivisions/sv.xml; do
  curl -fL --create-dirs -o "cldr-release-49/$p" "https://raw.githubusercontent.com/unicode-org/cldr/release-49/$p"
done
cd -   # back to the workspace
cargo xtask identity-data --faker /tmp/idg-up/faker-10.6.0 --cldr /tmp/idg-up/cldr-release-49 --check
```

The xtask does no network I/O; the per-file hashes below are what makes a run reproducible. For a
new pin, a run against the new checkouts prints the block it would need; review every changed
file before pasting it.

## Decisions (summary; the generated report has the details)

- **Countries and faker locales** (ADR 0079 §6): US `en_US`, GB `en_GB`, CA `en_CA`, AU `en_AU`,
  IE `en_IE`, DE `de`, AT `de_AT`, CH `de_CH`, FR `fr`, ES `es`, IT `it`, NL `nl`, SE `sv`. Each
  key is read through faker's own fallback chain from `src/locale/<locale>.ts` (for example
  `de_AT` → `de` → `en`), so GB, CA and IE take their person names from faker's `en` lists.
- **First names:** faker's `female` and `male` lists only. The `generic` (unisex) lists some locales
  have are not written to `[first.*]`; they only feed `{{person.firstName}}` inside street and
  city patterns. No v1 country splits surnames by sex.
- **Titles** (the format contract's table): US, GB, CA, AU, IE `Mr` / `Ms`; DE, AT, CH `Herr` /
  `Frau`; FR `M.` / `Mme`; ES `Sr.` / `Sra.`; IT `Sig.` / `Sig.ra`; NL `Dhr.` / `Mevr.`; SE
  `Herr` / `Fru`. Basis: faker's `person/prefix.ts` where it has sex-split prefixes (`en` `Mr.` /
  `Ms.`, `de` `Herr` / `Frau`, `fr` `M` / `Mme`, `es` `Sr.` / `Sra.`, `nl` `Dhr.` / `Mevr.`),
  written in the country's usual form; `it` and `sv` have only generic prefixes, so IT and SE
  use the conventional `Sig.` / `Sig.ra` and `Herr` / `Fru`. The xtask does not read
  `prefix.ts`.
- **Cities.** Real names from faker's `city_name` lists for US (`en`, US cities; `en_US`'s own
  `city_pattern` does not use them), CA, DE, AT, CH, FR, ES and IT. **Synthetic for GB, AU, IE,
  NL and SE:** faker has no real city list for these locales, so their `city_pattern` is expanded
  with the fixed seed. ADR 0079 §7 says "the city is a real city name of that country"; this is a
  reported deviation, and no other source was added.
- **Streets.** faker's `street_pattern`: a plain list where the pattern is one list reference (DE,
  AT, CH), otherwise expanded with the fixed seed, which yields synthetic but plausible names
  ("<name> Street"). CH: faker's `de_CH` street list has 31 entries, under the 50-entry minimum,
  so `de`'s street names without "ß" are appended (Swiss Standard German writes "ss"); a reported
  deviation from faker's chain.
- **Subdivisions** (CLDR containment, `common/supplemental/subdivisions.xml`): the top-level ISO
  3166-2 entries of each country, minus dependencies that have their own ISO 3166-1 code: US is
  the 50 states and DC (AS, GU, MP, PR, UM, VI excluded); FR is the 13 metropolitan regions
  (Guadeloupe, Martinique, French Guiana, Réunion, Mayotte, Saint-Barthélemy, Saint-Martin, New
  Caledonia, French Polynesia, Saint-Pierre-et-Miquelon, the French Southern Territories and Wallis
  and Futuna excluded, and Clipperton, which has no ISO 3166-1 code, no population and no postal
  addresses); NL is the 12 provinces (Aruba, Curaçao, Sint Maarten and the three BQ special
  municipalities excluded); ES keeps Ceuta and Melilla. GB is its four countries (England,
  Northern Ireland, Scotland, Wales: the only top-level ISO 3166-2 entries). IE is the 26 counties
  (the members of the four provinces, which are the top level). Written form: the ISO suffix for
  US, CA and AU (`CA`, `ON`, `NSW`: the postal custom), the CLDR name in the country's language
  elsewhere (`de` for DE, AT, CH; `fr`, `es`, `it`, `nl`, `sv`; `en` for GB and IE). A name that
  breaks the display rule is dropped and listed in the report: CH-SG "St. Gallen" (the dot),
  and ES-RI, whose CLDR `es` name is "La Rioja²" (CLDR marks it to tell the autonomous community
  from the province ES-LO "La Rioja" inside it), so ES has 18 of its 19 entries.
- **Postcodes.** faker's patterns, expanded 1:1 where faker lists them in code (GB districts, FR
  departments). Exceptions, each in the report: IE's `*` (letter or digit) becomes every `#`/`?`
  combination; NL is one `#### ??` pattern per first digit, so the letter pairs SS, SD and SA that
  faker avoids can appear; US and CA per-state patterns are in `[postcode]` (US `number.int`
  ranges widened to 3-digit prefixes such as `995##`; CA one letter per province, then `#? #?#`,
  where `?` is uniform over A–Z, so the letters D, F, I, O, Q and U that Canada Post never uses
  can appear). faker's `en_US` gives New York only `06390`, so NY's one pattern is `063##`.
- **Transliteration** (`data/identity/translit.txt`): `[de]` (`ä` → `ae`, `ö` → `oe`, `ü` → `ue`)
  for DE, AT and CH; `[general]` diacritic folding elsewhere, including SE (`Åsa` → `asa`).

## Phones (ADR 0079 §7)

A range is included only where the regulator's own document was read. Read 2026-10-24.

- **US and CA: NANPA.** [555 Line Numbers](https://www.nanpa.com/numbering/555-line-numbers)
  (nanpa.com, the North American Numbering Plan Administrator): "The fictitious, non-working
  numbers, 555-0100 through 555-0199, will remain reserved for entertainment/advertising." The
  page reserves the line numbers, not area codes; the data uses them under eight fixed area codes
  per country (US 202, 212, 312, 415, 512, 617, 713, 808; CA 204, 403, 416, 514, 604, 613, 709,
  902). That this NANP-wide reservation covers Canadian area codes is read from NANPA's role, not
  from a CNAC or CRTC document (not checked).
- **GB: Ofcom.** [Telephone numbers for use in TV and radio drama programmes](https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama)
  (page metadata: published 2019-03-01): "Telephone numbers recommended for drama purposes cannot
  be allocated to communications providers for their customers ..." Used: mobile 07700 900000 to
  900999 and the fifteen geographic ranges (0113, 0114, 0115, 0116, 0117, 0118, 0121, 0131, 0141,
  0151, 0161 496 0000 to 0999; 020 7946 0000 to 0999; 0191 498 0000 to 0999; 028 9649 6000 to
  6999; 029 2018 0000 to 0999). Not used: 01632 960xxx (no area), freephone, premium rate and
  UK-wide ranges (not personal numbers), to stay within 16 patterns.
- **DE: Bundesnetzagentur.** [Mitteilung 148/2021, Amtsblatt 07/21 vom 14.04.2021, "Rufnummern
  für Medienproduktionen (Drama Numbers)"](https://www.bundesnetzagentur.de/DE/Fachthemen/Telekommunikation/Nummerierung/_DL/mittlg148_2021.pdf?__blob=publicationFile&v=1)
  (PDF SHA-256 `90ef6910da76066d2d648e4ac88ff494d65c34987bd19e32bf66ba44a87b3b9c`): numbers "die
  dauerhaft keinem Teilnehmer zugeteilt sind". Used: Berlin (0)30 23125 000 to 999, Frankfurt
  (0)69 90009 000 to 999, Hamburg (0)40 66969 000 to 999, Köln (0)221 4710 000 to 999, München
  (0)89 99998 000 to 999, and the two 100-number mobile blocks the notice lists, (0)171 39200 00 to
  99 and (0)176 040690 00 to 99 (provided by the mobile operators, published in the notice). The
  single mobile numbers it lists are not used. This PDF was fetched with certificate checking off,
  because this host's TLS path presented a self-signed certificate; its text matched the search
  engine's summary of the same notice.
- **No phone (no regulator document read):** AU (ACMA's page returned HTTP 403 to every fetch),
  SE (PTS's page is behind a bot challenge), FR (no ARCEP document found), IE (no ComReg document
  found), AT, CH, ES, IT and NL (none known; not searched further). The ranges Wikipedia lists for
  some of these stay unverified (U) and are not in the data.

## Input files

```identity-data-inputs
cldr common/main/en.xml f8cbf26964d0e349fc96d9e5a56292edcbaab25c8e64177ca4f111773dfb79cf
cldr common/subdivisions/de.xml 7cb92c1ba2bcc2a8f14210c4adc4534260637aacdeeeb7a821fe5a989842b178
cldr common/subdivisions/en.xml 637705773cb923d63bf71abaf05e6246fd853ef98f143bd9796b11d2c5ac10c0
cldr common/subdivisions/es.xml 287bde26d858e1564090f4fce680844fa7ef8644ae62030022fe165be9315ddf
cldr common/subdivisions/fr.xml 6b8127e03bff045e95517b77b2f74b5c9484761e4389693afe41eb477c45e765
cldr common/subdivisions/it.xml d2b6245c56479ee8cbf74eb723120457051eadcd7c27b9a23db88a7660eec666
cldr common/subdivisions/nl.xml 723ed99605305e48db182cb3032100b4a185c51f583bac099b8980828d9ce5ea
cldr common/subdivisions/sv.xml ecc3abc975d4d69cf371b46d4faf030c2893a9cbcde178863bf533bede942f6f
cldr common/supplemental/subdivisions.xml 63095a3b5bd4e0a00d9e1cf96853808cacd0ec7c826dbcbfd31755c6cb9b6c55
faker src/locale/de.ts 0c013f604460e21ddbecfb8b6883949b5008a945ab9faa255e52f8e414ebef89
faker src/locale/de_AT.ts c1c674a296071d470ec3b7481cd08965340b72be0f5b6ffb07e69104ccbd15f9
faker src/locale/de_CH.ts 362f1a2e4506a816653ebcf32a5286d9fbb1e3fa16beec613ce9cbe8b9efc566
faker src/locale/en_AU.ts 2967a4d395132cd20ec18b2f41eff084dfb500f4cb5dc0f38a73925eb074c9ab
faker src/locale/en_CA.ts 316b8bd79479fafc7cbe41313d51a495a270b2f6d14b13d55aa711508fda4760
faker src/locale/en_GB.ts f96e363b176d91df5e937da30dbde6337a90f9fcb0f2f05a0dc8d2dfc7ce95a3
faker src/locale/en_IE.ts f94e1d0f9345e893b2dc319f8af186805c048d1963680690099af45f02c1705f
faker src/locale/en_US.ts a1885767bf16e1755132d753c4ceea5e59c1d42766da851a9add55d9e0af70e2
faker src/locale/es.ts d2b03c0d4a6763c94b8d26888fefe346d8b15af6e2e4bdd242b93864fdbc0d69
faker src/locale/fr.ts 811c76428bb4c23632c302e4e4cd18ca100e44eb7e492b268d231dfd64fde823
faker src/locale/it.ts fc05a2b31326b0e5a88b674a2772ff299c662b932e9cab6ebc3a4b367ef7a15b
faker src/locale/nl.ts f10a1c9992058e024763a60ce45e0487550b16daaf2d1fd33d8b1115d7bff6bd
faker src/locale/sv.ts 02e74cf223e9b4c5dab448ba478c285ecccc7fe5fdccb099ebd99da808eedcfe
faker src/locales/de/location/building_number.ts 225a7a72e0c889896fddf7a5ec994db397a719e64fbaa8ebd4d688e8bc5c0604
faker src/locales/de/location/city_name.ts e009c718b9925f97d988878330461756544fa3d5c496780b6c1715f04dfd15f9
faker src/locales/de/location/postcode.ts 8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b
faker src/locales/de/location/street_address.ts 2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915
faker src/locales/de/location/street_name.ts 5e78fb68a7cfdb6550915246a5742e7b7d46f1c106ef3a6d22ede7d0cf052313
faker src/locales/de/location/street_pattern.ts cd5316b38d67ae2aaaaa9db431503108a6dffc67877388ae440ea9dd2269a9ec
faker src/locales/de/person/first_name.ts 6644cd98ac4f05c2b4cffc45f924546a9b0d16ad0a6582037aecbe96a1be7aba
faker src/locales/de/person/last_name.ts 6ee4b498176480c339744d7ac66682df5ffa67515cc7cc665cf8436d7b5da539
faker src/locales/de_AT/location/building_number.ts 225a7a72e0c889896fddf7a5ec994db397a719e64fbaa8ebd4d688e8bc5c0604
faker src/locales/de_AT/location/city_name.ts a2f04838947421fc6801077260c6bd7d95e94cd3bdd6cb966b0156b196766e5f
faker src/locales/de_AT/location/postcode.ts 3923ddebf15eefb40dfd96751de6e1095d84b4430c96f66b5d46e7a2b61ead8f
faker src/locales/de_AT/location/street_address.ts 2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915
faker src/locales/de_AT/location/street_name.ts 303adf1ab82bef8f54e982bbf8f25384a4bd574a186029853eb8b7839ca1e337
faker src/locales/de_AT/location/street_pattern.ts cd5316b38d67ae2aaaaa9db431503108a6dffc67877388ae440ea9dd2269a9ec
faker src/locales/de_AT/person/first_name.ts 23c904e3dd824851c6e4fa6e24fa4be89fb277b103cb773f58ab6534386e0f69
faker src/locales/de_AT/person/last_name.ts 6ee4b498176480c339744d7ac66682df5ffa67515cc7cc665cf8436d7b5da539
faker src/locales/de_CH/location/city_name.ts 4002b2372f6898d7d9a8132929a95e90d9b986942acc369f62787c4ff212ee21
faker src/locales/de_CH/location/postcode.ts 48c5b6a90fcf406094cf6029b686c6dd9eba94b5d01da6bdf99fe0c322b24783
faker src/locales/de_CH/location/street_name.ts 88a61483ecb14255f0fb6ee6a4c8edd2ed75c37971d20796d1bd2e33875368a9
faker src/locales/de_CH/location/street_pattern.ts cd5316b38d67ae2aaaaa9db431503108a6dffc67877388ae440ea9dd2269a9ec
faker src/locales/de_CH/person/first_name.ts af2ff672b5d83aeb911aeb471b35f32da2983e0e7a01d403517f197534e52184
faker src/locales/de_CH/person/last_name.ts ff904dd66b6986bbf1678c7794f605e286475fc99d90b54b0dc27b3198cc871c
faker src/locales/en/location/building_number.ts 2f55860e86a5e0e0d1a0e923fc215908b38c7a93e081f393c6940b72853eb13c
faker src/locales/en/location/city_name.ts 3b0ea7fa5cc0bae466bcb14ee03b81de16cf6e9c133a2d22991d5a136250f4a0
faker src/locales/en/location/city_prefix.ts b2deb4586fe1c8e6e2a10e55d82c4bdcb8d4d63d84610920c7c9077dcd9ce107
faker src/locales/en/location/city_suffix.ts db6563b52ff18012ce20a478cd3fbfd94f7fb56e2bb19b4337b886e6f869a1c5
faker src/locales/en/location/postcode.ts 2a32cc44a18f9c7ec40306e9df2b4091248290ba0a8133ca6a9dbcd8c6b1baa1
faker src/locales/en/location/street_address.ts 8f18e13dc84c462af23df5e24432eb5ec5aa36d9a61370c3f9622356c5428661
faker src/locales/en/location/street_suffix.ts a8933c5503d815697d56b5a08cf8d0a1b8cc08b3ea63d541b5bc0a39a556cc1d
faker src/locales/en/person/first_name.ts 9322102b15eced267ae503d4223ad377e0518613ae89308ec66ce85eaf452c81
faker src/locales/en/person/last_name.ts 0df0a5723c4b896935f384d6e5af686a8f0a6b4024662abdb1129cc9db1d68af
faker src/locales/en_AU/location/building_number.ts 707ab1a8c13f9fbd6a8a70fb9d3f62f7ebb48de037128ae69dd6a4aee209b49e
faker src/locales/en_AU/location/city_pattern.ts 5417533d66a916fe05c30e2096ee636f3473cc13934a8764ecea09ff7a458a19
faker src/locales/en_AU/location/postcode.ts 3923ddebf15eefb40dfd96751de6e1095d84b4430c96f66b5d46e7a2b61ead8f
faker src/locales/en_AU/location/street_pattern.ts 673e2e06e2a1a10c695ac396ecf1adefa1548b20913f72ff7e4fa5152d21de66
faker src/locales/en_AU/location/street_suffix.ts 90884a7922cb4611ae4aec53f50c40c35f82648bf8804f3e55b2f92424e7f5ce
faker src/locales/en_AU/person/first_name.ts 31b1147943784edda256fa680aeafbb7086a97512b499edd238fc113c2c1ff64
faker src/locales/en_AU/person/last_name.ts b4b0e09155f7888dda145f0c8d94da4bc0a327f239a46794c05c036157310052
faker src/locales/en_CA/location/city_name.ts 9edfb8f397409423c9fcf8c173696ccdeb356b9a73655cf3cc3f5b53ef64a80e
faker src/locales/en_CA/location/postcode_by_state.ts 56327d0c3e31f15454f693d0c8f66b6a04636f6ab73621a7b9efc39963f60156
faker src/locales/en_CA/location/street_pattern.ts 673e2e06e2a1a10c695ac396ecf1adefa1548b20913f72ff7e4fa5152d21de66
faker src/locales/en_GB/location/building_number.ts a9b595bd4f8bf52613556089906729cf9cacf63e6073aa51dadf8059a31b9cd6
faker src/locales/en_GB/location/city_infix.ts 44545c881d520e9debfe11d084a9d775d21c6180cfe6437af46559f5c9c81338
faker src/locales/en_GB/location/city_pattern.ts b5f4bd3c1cbecbe718b9d8e7efa2a2f2a04e93cc5993469dafd3dc1f01377887
faker src/locales/en_GB/location/city_prefix.ts 9dcbb0ba9688d72721b4f4a1d95f08b90b5cd9bc8fad02667d79ef6a92f6ee07
faker src/locales/en_GB/location/city_suffix.ts 7d9b39f01281e281de9f74a4997f8b0074fc2629e5fe7dbca330ec9953e3fef1
faker src/locales/en_GB/location/postcode.ts 8c845168765eb8a5fad6dfca46fe27251a7a135daae5b600cfd1708e5ea331de
faker src/locales/en_GB/location/street_name.ts 00a85628b679f8a1c1c98e34e6f0182e1f39359e3beb96eefc1dbfd39f3e035d
faker src/locales/en_GB/location/street_pattern.ts cdb6429395562c5cc98dc8c9181c8301f93740a3596dee1b4078e20696cd84ae
faker src/locales/en_GB/location/street_suffix.ts 348494012d3a4a4625c8dfebdf052629675547076020be01f09c41812bf31218
faker src/locales/en_IE/location/city_pattern.ts 5417533d66a916fe05c30e2096ee636f3473cc13934a8764ecea09ff7a458a19
faker src/locales/en_IE/location/postcode.ts 4fef877be362c5b3b21f991281daac267f205d01f399ff49a16bd7388b1a3a1f
faker src/locales/en_IE/location/street_pattern.ts 673e2e06e2a1a10c695ac396ecf1adefa1548b20913f72ff7e4fa5152d21de66
faker src/locales/en_US/location/postcode_by_state.ts eb967b1e0f4fc6dd5ed942dbe56d3a3eb45df7e35677bd414c0f8f7bb4d5a638
faker src/locales/en_US/location/street_name.ts 5ab55322089f607e088dfcd381021f9e55a6dc922b53aa6a2d5085ac991f1c84
faker src/locales/en_US/location/street_pattern.ts cdb6429395562c5cc98dc8c9181c8301f93740a3596dee1b4078e20696cd84ae
faker src/locales/es/location/building_number.ts 958d09660be9e089c121c038e1d1b93892021012b82d76908e2715e930bbb958
faker src/locales/es/location/city_name.ts d0d65f7493d46bcf15fa7348931bfc10a69f79b746658cbe34d97c0cbfee11e8
faker src/locales/es/location/postcode.ts 8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b
faker src/locales/es/location/street_address.ts d76d29080e8b47eaf9eae50f5965fa1bd8102698cb35ff50a52e98922930179a
faker src/locales/es/location/street_pattern.ts 178b919af06e3037e160007dd039731790558d53e6c4740df3576e5c22377061
faker src/locales/es/location/street_suffix.ts 8e2e11a206b879dba3a8969941d37c8d3a67d4fe46ad70042a40d836f3cc7f7f
faker src/locales/es/person/first_name.ts 2d458c133cbaea08c6dfee1b1b7e1597de0eb10ed5426ef794656a680e9abb55
faker src/locales/es/person/last_name.ts 3dd24c6bd1d0622ba3564777b673aaa64ac07fbdabe6d7b11dde701911a5dcb9
faker src/locales/fr/location/building_number.ts 6bd42fbd1c2e04e5df002bd63cb5565040ccd53b7e8fe01b8d0a3c7547b3856a
faker src/locales/fr/location/city_name.ts ea08d77fde3e6c5c0381cd93b24740262cfee1bc67193a07a9f807e070a490ea
faker src/locales/fr/location/postcode.ts 40152347616d1d57f3502e9528991fc6ce5f6fea987c04c74d89479825ca0b33
faker src/locales/fr/location/street_address.ts 8f18e13dc84c462af23df5e24432eb5ec5aa36d9a61370c3f9622356c5428661
faker src/locales/fr/location/street_pattern.ts b5b2ad7f5e4b6ec98acec275b2024d91e389b30efd2122e24aea2f7a198dcb44
faker src/locales/fr/location/street_prefix.ts c20f59a28287b3d7266d340905a1b07f3e05898a8551cc60e9cb0def2a7e804f
faker src/locales/fr/location/street_suffix.ts b0026a4f2717979e4002bad2d32c19fb0b0af7bd06e031558aac9fc2fccb04f7
faker src/locales/fr/person/first_name.ts b034459642d48525aed95f78868cf3e8646db670ff871a96905690389ee311fe
faker src/locales/fr/person/last_name.ts 7f4c33c0bbbf8f97723fae69be6ca8aac19fe1bb528eb260e20ee2a6c300dcf2
faker src/locales/it/location/building_number.ts a9b595bd4f8bf52613556089906729cf9cacf63e6073aa51dadf8059a31b9cd6
faker src/locales/it/location/city_name.ts 41e65c4da574555c86d3e0676f9672b11e924d006124a8a4a01deef24592b90a
faker src/locales/it/location/postcode.ts 8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b
faker src/locales/it/location/street_address.ts 787754cf5bd78827b9cb0350529a82cb3396c711980dd74f24aab46ff106ef57
faker src/locales/it/location/street_pattern.ts f218d61f00949a7eb1bdaae501247128bdda17c08246b5da99c739cd9d870fe7
faker src/locales/it/location/street_suffix.ts 97c523705a97ad371cf4876a7a32495974fd61c52b37ad266aac10508a9dfbea
faker src/locales/it/person/first_name.ts a9ffab3d4cd9fa5366854d5a29b1afa00605f2576bd98f7e91685b6254df4fa3
faker src/locales/it/person/last_name.ts 6e2011c1160f9b4adc1afb71459b31bfccf5ae0552afffe4ea6fb6c38d98b053
faker src/locales/nl/location/building_number.ts 3b93a57230ffae5e5a4fb7d2d728a607bb9d29412f790dd8dd42eab945905759
faker src/locales/nl/location/city_pattern.ts c7ea7c2ab14e5a2d15c86b9a42a281acae882895ed36d5adb7fc17c1d19253c0
faker src/locales/nl/location/city_prefix.ts 4b6e73edd5e8f4a6783f1c47cd470b513f4d2d5a3663e51748013073e480bc97
faker src/locales/nl/location/city_suffix.ts 8be4012b64f78eb9030d3fff6750cda78b11db2dac2b974c7a2ede0b0f72ddc3
faker src/locales/nl/location/postcode.ts 12f71034656ce8856e72b1d74d49873f4d9bba1a01badeade98405d3e831d10e
faker src/locales/nl/location/street_address.ts 2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915
faker src/locales/nl/location/street_pattern.ts fb86c3894e74cecfa8881ef1ad2b49876ce8eab77637d46c90c3f49bce3265c3
faker src/locales/nl/location/street_suffix.ts c494690b81bfd1a8586bb0e2da0113943e2a066061404d27453211d02d72f113
faker src/locales/nl/person/first_name.ts 8ca73ee8d35288bff45a407907ae630e9ae245b41768eb6eb8c849ea9981bf9c
faker src/locales/nl/person/last_name.ts 813c638a2fca3d932977cc8b614453e86489a86dda76bf6aee2dd52404745259
faker src/locales/sv/location/building_number.ts a9b595bd4f8bf52613556089906729cf9cacf63e6073aa51dadf8059a31b9cd6
faker src/locales/sv/location/city_pattern.ts 8c3244d2be81d0c85cda84eb37cc311fd25287746d63b52b3c21bc337206afc6
faker src/locales/sv/location/city_prefix.ts 4ee0c678f5454dae7650542566ca555ded25346fa8975f58741ae95372519b34
faker src/locales/sv/location/city_suffix.ts 16060f98f656ba7c8277c9322124e637d94294653300557d0b61f48948c563c8
faker src/locales/sv/location/common_street_suffix.ts 3e5ad095530ba3658b605cfe58754a8705d7c4a53ee1d718880bca30184143cb
faker src/locales/sv/location/postcode.ts 8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b
faker src/locales/sv/location/street_address.ts 2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915
faker src/locales/sv/location/street_name_part.ts 2cf969c0b6f54cd879e5c0ecf251d0aaa2bf2d785841f78994ab97216745ebb7
faker src/locales/sv/location/street_pattern.ts ab09b02a92776b1adb6aedfe178590f3a6b5c02dbfcbc5f0c73ddccbdef34097
faker src/locales/sv/location/street_prefix.ts a42b497b2cf8253b66dcc8b9ecf9fbd9e427fb1e9766ecbd708320154780948a
faker src/locales/sv/location/street_suffix.ts a3a65321943d9f2ff7e47acc77c4dd50ad159a475f2db747820815fd101c0914
faker src/locales/sv/person/first_name.ts 7c4c4c28e9ba0b28337325ba27971d142a743677f0fd72667a60074e8f7e0297
faker src/locales/sv/person/last_name.ts 6b49589fc2b6b18625af6d4ae2f5aedb68af5284d196e1c1efbbbf4fce9212f2
```

<!-- BEGIN GENERATED by `cargo xtask identity-data`; do not edit by hand -->

## Generated report

- Output: `crates/rizzy-client/src/identity_gen/identity-data-v1.txt`, 346852 bytes of the 393216-byte budget.
- Output SHA-256: `a4738097349e9f0aaaef6ca251c449e7dccb90b8290077aac70f48a7a30a42c7`

| Country | Bytes | Phone patterns |
|---|---:|---:|
| AT | 27160 | 0 |
| AU | 17693 | 0 |
| CA | 27159 | 8 |
| CH | 14661 | 0 |
| DE | 31170 | 7 |
| ES | 23349 | 0 |
| FR | 26012 | 0 |
| GB | 35137 | 16 |
| IE | 33920 | 0 |
| IT | 35707 | 0 |
| NL | 21774 | 0 |
| SE | 14436 | 0 |
| US | 38562 | 8 |

### Verified input files

Each file was checked against the input block above before the output was written.

| Upstream | Tag | Commit | Path | SHA-256 | Licence |
|---|---|---|---|---|---|
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/main/en.xml](https://github.com/unicode-org/cldr/blob/release-49/common/main/en.xml) | `f8cbf26964d0e349fc96d9e5a56292edcbaab25c8e64177ca4f111773dfb79cf` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/subdivisions/de.xml](https://github.com/unicode-org/cldr/blob/release-49/common/subdivisions/de.xml) | `7cb92c1ba2bcc2a8f14210c4adc4534260637aacdeeeb7a821fe5a989842b178` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/subdivisions/en.xml](https://github.com/unicode-org/cldr/blob/release-49/common/subdivisions/en.xml) | `637705773cb923d63bf71abaf05e6246fd853ef98f143bd9796b11d2c5ac10c0` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/subdivisions/es.xml](https://github.com/unicode-org/cldr/blob/release-49/common/subdivisions/es.xml) | `287bde26d858e1564090f4fce680844fa7ef8644ae62030022fe165be9315ddf` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/subdivisions/fr.xml](https://github.com/unicode-org/cldr/blob/release-49/common/subdivisions/fr.xml) | `6b8127e03bff045e95517b77b2f74b5c9484761e4389693afe41eb477c45e765` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/subdivisions/it.xml](https://github.com/unicode-org/cldr/blob/release-49/common/subdivisions/it.xml) | `d2b6245c56479ee8cbf74eb723120457051eadcd7c27b9a23db88a7660eec666` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/subdivisions/nl.xml](https://github.com/unicode-org/cldr/blob/release-49/common/subdivisions/nl.xml) | `723ed99605305e48db182cb3032100b4a185c51f583bac099b8980828d9ce5ea` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/subdivisions/sv.xml](https://github.com/unicode-org/cldr/blob/release-49/common/subdivisions/sv.xml) | `ecc3abc975d4d69cf371b46d4faf030c2893a9cbcde178863bf533bede942f6f` | Unicode-3.0 |
| cldr | release-49 | `96e54b273d2da4ec6fbad350ba19ff23fa24a588` | [common/supplemental/subdivisions.xml](https://github.com/unicode-org/cldr/blob/release-49/common/supplemental/subdivisions.xml) | `63095a3b5bd4e0a00d9e1cf96853808cacd0ec7c826dbcbfd31755c6cb9b6c55` | Unicode-3.0 |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/de.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/de.ts) | `0c013f604460e21ddbecfb8b6883949b5008a945ab9faa255e52f8e414ebef89` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/de_AT.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/de_AT.ts) | `c1c674a296071d470ec3b7481cd08965340b72be0f5b6ffb07e69104ccbd15f9` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/de_CH.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/de_CH.ts) | `362f1a2e4506a816653ebcf32a5286d9fbb1e3fa16beec613ce9cbe8b9efc566` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/en_AU.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/en_AU.ts) | `2967a4d395132cd20ec18b2f41eff084dfb500f4cb5dc0f38a73925eb074c9ab` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/en_CA.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/en_CA.ts) | `316b8bd79479fafc7cbe41313d51a495a270b2f6d14b13d55aa711508fda4760` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/en_GB.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/en_GB.ts) | `f96e363b176d91df5e937da30dbde6337a90f9fcb0f2f05a0dc8d2dfc7ce95a3` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/en_IE.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/en_IE.ts) | `f94e1d0f9345e893b2dc319f8af186805c048d1963680690099af45f02c1705f` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/en_US.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/en_US.ts) | `a1885767bf16e1755132d753c4ceea5e59c1d42766da851a9add55d9e0af70e2` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/es.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/es.ts) | `d2b03c0d4a6763c94b8d26888fefe346d8b15af6e2e4bdd242b93864fdbc0d69` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/fr.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/fr.ts) | `811c76428bb4c23632c302e4e4cd18ca100e44eb7e492b268d231dfd64fde823` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/it.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/it.ts) | `fc05a2b31326b0e5a88b674a2772ff299c662b932e9cab6ebc3a4b367ef7a15b` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/nl.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/nl.ts) | `f10a1c9992058e024763a60ce45e0487550b16daaf2d1fd33d8b1115d7bff6bd` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locale/sv.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locale/sv.ts) | `02e74cf223e9b4c5dab448ba478c285ecccc7fe5fdccb099ebd99da808eedcfe` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/location/building_number.ts) | `225a7a72e0c889896fddf7a5ec994db397a719e64fbaa8ebd4d688e8bc5c0604` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/location/city_name.ts) | `e009c718b9925f97d988878330461756544fa3d5c496780b6c1715f04dfd15f9` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/location/postcode.ts) | `8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/location/street_address.ts) | `2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/location/street_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/location/street_name.ts) | `5e78fb68a7cfdb6550915246a5742e7b7d46f1c106ef3a6d22ede7d0cf052313` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/location/street_pattern.ts) | `cd5316b38d67ae2aaaaa9db431503108a6dffc67877388ae440ea9dd2269a9ec` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/person/first_name.ts) | `6644cd98ac4f05c2b4cffc45f924546a9b0d16ad0a6582037aecbe96a1be7aba` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de/person/last_name.ts) | `6ee4b498176480c339744d7ac66682df5ffa67515cc7cc665cf8436d7b5da539` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/location/building_number.ts) | `225a7a72e0c889896fddf7a5ec994db397a719e64fbaa8ebd4d688e8bc5c0604` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/location/city_name.ts) | `a2f04838947421fc6801077260c6bd7d95e94cd3bdd6cb966b0156b196766e5f` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/location/postcode.ts) | `3923ddebf15eefb40dfd96751de6e1095d84b4430c96f66b5d46e7a2b61ead8f` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/location/street_address.ts) | `2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/location/street_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/location/street_name.ts) | `303adf1ab82bef8f54e982bbf8f25384a4bd574a186029853eb8b7839ca1e337` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/location/street_pattern.ts) | `cd5316b38d67ae2aaaaa9db431503108a6dffc67877388ae440ea9dd2269a9ec` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/person/first_name.ts) | `23c904e3dd824851c6e4fa6e24fa4be89fb277b103cb773f58ab6534386e0f69` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_AT/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_AT/person/last_name.ts) | `6ee4b498176480c339744d7ac66682df5ffa67515cc7cc665cf8436d7b5da539` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_CH/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_CH/location/city_name.ts) | `4002b2372f6898d7d9a8132929a95e90d9b986942acc369f62787c4ff212ee21` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_CH/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_CH/location/postcode.ts) | `48c5b6a90fcf406094cf6029b686c6dd9eba94b5d01da6bdf99fe0c322b24783` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_CH/location/street_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_CH/location/street_name.ts) | `88a61483ecb14255f0fb6ee6a4c8edd2ed75c37971d20796d1bd2e33875368a9` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_CH/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_CH/location/street_pattern.ts) | `cd5316b38d67ae2aaaaa9db431503108a6dffc67877388ae440ea9dd2269a9ec` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_CH/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_CH/person/first_name.ts) | `af2ff672b5d83aeb911aeb471b35f32da2983e0e7a01d403517f197534e52184` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/de_CH/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/de_CH/person/last_name.ts) | `ff904dd66b6986bbf1678c7794f605e286475fc99d90b54b0dc27b3198cc871c` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/location/building_number.ts) | `2f55860e86a5e0e0d1a0e923fc215908b38c7a93e081f393c6940b72853eb13c` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/location/city_name.ts) | `3b0ea7fa5cc0bae466bcb14ee03b81de16cf6e9c133a2d22991d5a136250f4a0` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/location/city_prefix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/location/city_prefix.ts) | `b2deb4586fe1c8e6e2a10e55d82c4bdcb8d4d63d84610920c7c9077dcd9ce107` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/location/city_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/location/city_suffix.ts) | `db6563b52ff18012ce20a478cd3fbfd94f7fb56e2bb19b4337b886e6f869a1c5` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/location/postcode.ts) | `2a32cc44a18f9c7ec40306e9df2b4091248290ba0a8133ca6a9dbcd8c6b1baa1` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/location/street_address.ts) | `8f18e13dc84c462af23df5e24432eb5ec5aa36d9a61370c3f9622356c5428661` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/location/street_suffix.ts) | `a8933c5503d815697d56b5a08cf8d0a1b8cc08b3ea63d541b5bc0a39a556cc1d` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/person/first_name.ts) | `9322102b15eced267ae503d4223ad377e0518613ae89308ec66ce85eaf452c81` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en/person/last_name.ts) | `0df0a5723c4b896935f384d6e5af686a8f0a6b4024662abdb1129cc9db1d68af` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_AU/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_AU/location/building_number.ts) | `707ab1a8c13f9fbd6a8a70fb9d3f62f7ebb48de037128ae69dd6a4aee209b49e` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_AU/location/city_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_AU/location/city_pattern.ts) | `5417533d66a916fe05c30e2096ee636f3473cc13934a8764ecea09ff7a458a19` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_AU/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_AU/location/postcode.ts) | `3923ddebf15eefb40dfd96751de6e1095d84b4430c96f66b5d46e7a2b61ead8f` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_AU/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_AU/location/street_pattern.ts) | `673e2e06e2a1a10c695ac396ecf1adefa1548b20913f72ff7e4fa5152d21de66` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_AU/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_AU/location/street_suffix.ts) | `90884a7922cb4611ae4aec53f50c40c35f82648bf8804f3e55b2f92424e7f5ce` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_AU/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_AU/person/first_name.ts) | `31b1147943784edda256fa680aeafbb7086a97512b499edd238fc113c2c1ff64` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_AU/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_AU/person/last_name.ts) | `b4b0e09155f7888dda145f0c8d94da4bc0a327f239a46794c05c036157310052` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_CA/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_CA/location/city_name.ts) | `9edfb8f397409423c9fcf8c173696ccdeb356b9a73655cf3cc3f5b53ef64a80e` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_CA/location/postcode_by_state.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_CA/location/postcode_by_state.ts) | `56327d0c3e31f15454f693d0c8f66b6a04636f6ab73621a7b9efc39963f60156` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_CA/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_CA/location/street_pattern.ts) | `673e2e06e2a1a10c695ac396ecf1adefa1548b20913f72ff7e4fa5152d21de66` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/building_number.ts) | `a9b595bd4f8bf52613556089906729cf9cacf63e6073aa51dadf8059a31b9cd6` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/city_infix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/city_infix.ts) | `44545c881d520e9debfe11d084a9d775d21c6180cfe6437af46559f5c9c81338` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/city_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/city_pattern.ts) | `b5f4bd3c1cbecbe718b9d8e7efa2a2f2a04e93cc5993469dafd3dc1f01377887` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/city_prefix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/city_prefix.ts) | `9dcbb0ba9688d72721b4f4a1d95f08b90b5cd9bc8fad02667d79ef6a92f6ee07` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/city_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/city_suffix.ts) | `7d9b39f01281e281de9f74a4997f8b0074fc2629e5fe7dbca330ec9953e3fef1` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/postcode.ts) | `8c845168765eb8a5fad6dfca46fe27251a7a135daae5b600cfd1708e5ea331de` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/street_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/street_name.ts) | `00a85628b679f8a1c1c98e34e6f0182e1f39359e3beb96eefc1dbfd39f3e035d` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/street_pattern.ts) | `cdb6429395562c5cc98dc8c9181c8301f93740a3596dee1b4078e20696cd84ae` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_GB/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_GB/location/street_suffix.ts) | `348494012d3a4a4625c8dfebdf052629675547076020be01f09c41812bf31218` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_IE/location/city_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_IE/location/city_pattern.ts) | `5417533d66a916fe05c30e2096ee636f3473cc13934a8764ecea09ff7a458a19` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_IE/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_IE/location/postcode.ts) | `4fef877be362c5b3b21f991281daac267f205d01f399ff49a16bd7388b1a3a1f` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_IE/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_IE/location/street_pattern.ts) | `673e2e06e2a1a10c695ac396ecf1adefa1548b20913f72ff7e4fa5152d21de66` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_US/location/postcode_by_state.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_US/location/postcode_by_state.ts) | `eb967b1e0f4fc6dd5ed942dbe56d3a3eb45df7e35677bd414c0f8f7bb4d5a638` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_US/location/street_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_US/location/street_name.ts) | `5ab55322089f607e088dfcd381021f9e55a6dc922b53aa6a2d5085ac991f1c84` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/en_US/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/en_US/location/street_pattern.ts) | `cdb6429395562c5cc98dc8c9181c8301f93740a3596dee1b4078e20696cd84ae` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/location/building_number.ts) | `958d09660be9e089c121c038e1d1b93892021012b82d76908e2715e930bbb958` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/location/city_name.ts) | `d0d65f7493d46bcf15fa7348931bfc10a69f79b746658cbe34d97c0cbfee11e8` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/location/postcode.ts) | `8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/location/street_address.ts) | `d76d29080e8b47eaf9eae50f5965fa1bd8102698cb35ff50a52e98922930179a` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/location/street_pattern.ts) | `178b919af06e3037e160007dd039731790558d53e6c4740df3576e5c22377061` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/location/street_suffix.ts) | `8e2e11a206b879dba3a8969941d37c8d3a67d4fe46ad70042a40d836f3cc7f7f` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/person/first_name.ts) | `2d458c133cbaea08c6dfee1b1b7e1597de0eb10ed5426ef794656a680e9abb55` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/es/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/es/person/last_name.ts) | `3dd24c6bd1d0622ba3564777b673aaa64ac07fbdabe6d7b11dde701911a5dcb9` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/location/building_number.ts) | `6bd42fbd1c2e04e5df002bd63cb5565040ccd53b7e8fe01b8d0a3c7547b3856a` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/location/city_name.ts) | `ea08d77fde3e6c5c0381cd93b24740262cfee1bc67193a07a9f807e070a490ea` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/location/postcode.ts) | `40152347616d1d57f3502e9528991fc6ce5f6fea987c04c74d89479825ca0b33` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/location/street_address.ts) | `8f18e13dc84c462af23df5e24432eb5ec5aa36d9a61370c3f9622356c5428661` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/location/street_pattern.ts) | `b5b2ad7f5e4b6ec98acec275b2024d91e389b30efd2122e24aea2f7a198dcb44` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/location/street_prefix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/location/street_prefix.ts) | `c20f59a28287b3d7266d340905a1b07f3e05898a8551cc60e9cb0def2a7e804f` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/location/street_suffix.ts) | `b0026a4f2717979e4002bad2d32c19fb0b0af7bd06e031558aac9fc2fccb04f7` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/person/first_name.ts) | `b034459642d48525aed95f78868cf3e8646db670ff871a96905690389ee311fe` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/fr/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/fr/person/last_name.ts) | `7f4c33c0bbbf8f97723fae69be6ca8aac19fe1bb528eb260e20ee2a6c300dcf2` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/location/building_number.ts) | `a9b595bd4f8bf52613556089906729cf9cacf63e6073aa51dadf8059a31b9cd6` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/location/city_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/location/city_name.ts) | `41e65c4da574555c86d3e0676f9672b11e924d006124a8a4a01deef24592b90a` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/location/postcode.ts) | `8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/location/street_address.ts) | `787754cf5bd78827b9cb0350529a82cb3396c711980dd74f24aab46ff106ef57` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/location/street_pattern.ts) | `f218d61f00949a7eb1bdaae501247128bdda17c08246b5da99c739cd9d870fe7` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/location/street_suffix.ts) | `97c523705a97ad371cf4876a7a32495974fd61c52b37ad266aac10508a9dfbea` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/person/first_name.ts) | `a9ffab3d4cd9fa5366854d5a29b1afa00605f2576bd98f7e91685b6254df4fa3` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/it/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/it/person/last_name.ts) | `6e2011c1160f9b4adc1afb71459b31bfccf5ae0552afffe4ea6fb6c38d98b053` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/building_number.ts) | `3b93a57230ffae5e5a4fb7d2d728a607bb9d29412f790dd8dd42eab945905759` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/city_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/city_pattern.ts) | `c7ea7c2ab14e5a2d15c86b9a42a281acae882895ed36d5adb7fc17c1d19253c0` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/city_prefix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/city_prefix.ts) | `4b6e73edd5e8f4a6783f1c47cd470b513f4d2d5a3663e51748013073e480bc97` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/city_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/city_suffix.ts) | `8be4012b64f78eb9030d3fff6750cda78b11db2dac2b974c7a2ede0b0f72ddc3` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/postcode.ts) | `12f71034656ce8856e72b1d74d49873f4d9bba1a01badeade98405d3e831d10e` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/street_address.ts) | `2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/street_pattern.ts) | `fb86c3894e74cecfa8881ef1ad2b49876ce8eab77637d46c90c3f49bce3265c3` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/location/street_suffix.ts) | `c494690b81bfd1a8586bb0e2da0113943e2a066061404d27453211d02d72f113` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/person/first_name.ts) | `8ca73ee8d35288bff45a407907ae630e9ae245b41768eb6eb8c849ea9981bf9c` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/nl/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/nl/person/last_name.ts) | `813c638a2fca3d932977cc8b614453e86489a86dda76bf6aee2dd52404745259` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/building_number.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/building_number.ts) | `a9b595bd4f8bf52613556089906729cf9cacf63e6073aa51dadf8059a31b9cd6` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/city_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/city_pattern.ts) | `8c3244d2be81d0c85cda84eb37cc311fd25287746d63b52b3c21bc337206afc6` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/city_prefix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/city_prefix.ts) | `4ee0c678f5454dae7650542566ca555ded25346fa8975f58741ae95372519b34` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/city_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/city_suffix.ts) | `16060f98f656ba7c8277c9322124e637d94294653300557d0b61f48948c563c8` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/common_street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/common_street_suffix.ts) | `3e5ad095530ba3658b605cfe58754a8705d7c4a53ee1d718880bca30184143cb` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/postcode.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/postcode.ts) | `8d7673467fd4b21bf17c10560408ccb7a871ffac17c011110cd984869e08172b` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/street_address.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/street_address.ts) | `2829261451a85377a96547583eaa9c1f4d7c9b8e7b897e07e3e96044705a3915` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/street_name_part.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/street_name_part.ts) | `2cf969c0b6f54cd879e5c0ecf251d0aaa2bf2d785841f78994ab97216745ebb7` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/street_pattern.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/street_pattern.ts) | `ab09b02a92776b1adb6aedfe178590f3a6b5c02dbfcbc5f0c73ddccbdef34097` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/street_prefix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/street_prefix.ts) | `a42b497b2cf8253b66dcc8b9ecf9fbd9e427fb1e9766ecbd708320154780948a` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/location/street_suffix.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/location/street_suffix.ts) | `a3a65321943d9f2ff7e47acc77c4dd50ad159a475f2db747820815fd101c0914` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/person/first_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/person/first_name.ts) | `7c4c4c28e9ba0b28337325ba27971d142a743677f0fd72667a60074e8f7e0297` | MIT |
| faker | v10.6.0 | `2cb04231a6ace91a59ebe577c653f4ec66478ca3` | [src/locales/sv/person/last_name.ts](https://github.com/faker-js/faker/blob/v10.6.0/src/locales/sv/person/last_name.ts) | `6b49589fc2b6b18625af6d4ae2f5aedb68af5284d196e1c1efbbbf4fce9212f2` | MIT |

### Sampling and expansion

- Generator: SplitMix64, seeded per list with `0x52495a5a59494447` XOR the 64-bit FNV-1a hash of the list label (for example `DE/first.female`).
- Caps: 400 first names per sex, 800 last names (per sex where split), 400 streets, 400 cities, every subdivision. faker's lists are alphabetical, not frequency-ordered, so a list over its cap keeps a partial Fisher-Yates sample (uniform index by rejection) of that size.
- Pattern lists: a pattern is drawn uniformly, then each reference uniformly from its list, until the cap is reached or 64 × cap draws are spent; entries that break the display rule or repeat are discarded and counted.
- Every list is written in ascending byte order; no list may have fewer than 50 entries.

### Lists

"Upstream" is the number of upstream entries, or of pattern draws. Dropped: by the display rule, or because the ascii form failed (an unmapped character or an over-long result).

| List | From | Method | Upstream | Dropped (rule) | Dropped (ascii) | Duplicates | Written |
|---|---|---|---:|---:|---:|---:|---:|
| AT/first.female | src/locales/de_AT/person/first_name.ts | fixed-seed sample of 400 from 573 | 573 | 0 | 0 | 0 | 400 |
| AT/first.male | src/locales/de_AT/person/first_name.ts | fixed-seed sample of 400 from 572 | 572 | 0 | 0 | 0 | 400 |
| AT/last | src/locales/de_AT/person/last_name.ts | fixed-seed sample of 800 from 1688 | 1688 | 0 | 0 | 0 | 800 |
| AT/street | src/locales/de_AT/location/street_pattern.ts → src/locales/de_AT/location/street_name.ts | all | 198 | 14 | 0 | 0 | 184 |
| AT/city | src/locales/de_AT/location/city_name.ts | all | 119 | 4 | 0 | 0 | 115 |
| AU/first.female | src/locales/en_AU/person/first_name.ts | all | 100 | 0 | 0 | 0 | 100 |
| AU/first.male | src/locales/en_AU/person/first_name.ts | all | 100 | 0 | 0 | 0 | 100 |
| AU/last | src/locales/en_AU/person/last_name.ts | all | 286 | 0 | 0 | 0 | 286 |
| AU/street | src/locales/en_AU/location/street_pattern.ts | pattern expansion, 2 patterns (synthetic) | 408 | 0 | 0 | 8 | 400 |
| AU/city | src/locales/en_AU/location/city_pattern.ts | pattern expansion, 4 patterns (synthetic) | 405 | 0 | 0 | 5 | 400 |
| CA/first.female | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1563 | 1563 | 0 | 0 | 0 | 400 |
| CA/first.male | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1391 | 1391 | 0 | 0 | 0 | 400 |
| CA/last | src/locales/en/person/last_name.ts | all | 473 | 0 | 0 | 0 | 473 |
| CA/street | src/locales/en_CA/location/street_pattern.ts | pattern expansion, 2 patterns (synthetic) | 400 | 0 | 0 | 0 | 400 |
| CA/city | src/locales/en_CA/location/city_name.ts | all | 220 | 3 | 0 | 0 | 217 |
| CH/first.female | src/locales/de_CH/person/first_name.ts | all | 137 | 0 | 0 | 0 | 137 |
| CH/first.male | src/locales/de_CH/person/first_name.ts | all | 178 | 0 | 0 | 0 | 178 |
| CH/last | src/locales/de_CH/person/last_name.ts | all | 209 | 0 | 0 | 0 | 209 |
| CH/street | src/locales/de_CH/location/street_pattern.ts → src/locales/de_CH/location/street_name.ts + src/locales/de/location/street_name.ts without entries containing "ß" | fixed-seed sample of 400 from 433 | 1047 | 613 | 0 | 1 | 400 |
| CH/city | src/locales/de_CH/location/city_name.ts | all | 100 | 2 | 0 | 0 | 98 |
| DE/first.female | src/locales/de/person/first_name.ts | fixed-seed sample of 400 from 573 | 573 | 0 | 0 | 0 | 400 |
| DE/first.male | src/locales/de/person/first_name.ts | fixed-seed sample of 400 from 562 | 562 | 0 | 0 | 0 | 400 |
| DE/last | src/locales/de/person/last_name.ts | fixed-seed sample of 800 from 1688 | 1688 | 0 | 0 | 0 | 800 |
| DE/street | src/locales/de/location/street_pattern.ts → src/locales/de/location/street_name.ts | fixed-seed sample of 400 from 407 | 1031 | 624 | 0 | 0 | 400 |
| DE/city | src/locales/de/location/city_name.ts | all | 200 | 9 | 0 | 0 | 191 |
| ES/first.female | src/locales/es/person/first_name.ts | all | 120 | 0 | 0 | 0 | 120 |
| ES/first.male | src/locales/es/person/first_name.ts | all | 107 | 0 | 0 | 0 | 107 |
| ES/last | src/locales/es/person/last_name.ts | all | 625 | 0 | 0 | 0 | 625 |
| ES/street | src/locales/es/location/street_pattern.ts | pattern expansion, 2 patterns (synthetic) | 400 | 0 | 0 | 0 | 400 |
| ES/city | src/locales/es/location/city_name.ts | all | 130 | 0 | 0 | 0 | 130 |
| FR/first.female | src/locales/fr/person/first_name.ts | fixed-seed sample of 400 from 435 | 435 | 0 | 0 | 0 | 400 |
| FR/first.male | src/locales/fr/person/first_name.ts | fixed-seed sample of 400 from 480 | 480 | 0 | 0 | 0 | 400 |
| FR/last | src/locales/fr/person/last_name.ts | all | 150 | 0 | 0 | 0 | 150 |
| FR/street | src/locales/fr/location/street_pattern.ts | pattern expansion, 1 patterns (synthetic) | 672 | 0 | 0 | 272 | 400 |
| FR/city | src/locales/fr/location/city_name.ts | all | 99 | 0 | 0 | 0 | 99 |
| GB/first.female | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1563 | 1563 | 0 | 0 | 0 | 400 |
| GB/first.male | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1391 | 1391 | 0 | 0 | 0 | 400 |
| GB/last | src/locales/en/person/last_name.ts | all | 473 | 0 | 0 | 0 | 473 |
| GB/street | src/locales/en_GB/location/street_pattern.ts | pattern expansion, 3 patterns (synthetic) | 418 | 0 | 0 | 18 | 400 |
| GB/city | src/locales/en_GB/location/city_pattern.ts | pattern expansion, 4 patterns (synthetic) | 415 | 13 | 0 | 2 | 400 |
| IE/first.female | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1563 | 1563 | 0 | 0 | 0 | 400 |
| IE/first.male | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1391 | 1391 | 0 | 0 | 0 | 400 |
| IE/last | src/locales/en/person/last_name.ts | all | 473 | 0 | 0 | 0 | 473 |
| IE/street | src/locales/en_IE/location/street_pattern.ts | pattern expansion, 2 patterns (synthetic) | 400 | 0 | 0 | 0 | 400 |
| IE/city | src/locales/en_IE/location/city_pattern.ts | pattern expansion, 4 patterns (synthetic) | 400 | 0 | 0 | 0 | 400 |
| IT/first.female | src/locales/it/person/first_name.ts | fixed-seed sample of 400 from 617 | 617 | 0 | 0 | 0 | 400 |
| IT/first.male | src/locales/it/person/first_name.ts | fixed-seed sample of 400 from 1083 | 1083 | 0 | 0 | 0 | 400 |
| IT/last | src/locales/it/person/last_name.ts | fixed-seed sample of 800 from 2170 | 2170 | 0 | 0 | 0 | 800 |
| IT/street | src/locales/it/location/street_pattern.ts | pattern expansion, 2 patterns (synthetic) | 403 | 0 | 0 | 3 | 400 |
| IT/city | src/locales/it/location/city_name.ts | fixed-seed sample of 400 from 979 | 979 | 0 | 0 | 0 | 400 |
| NL/first.female | src/locales/nl/person/first_name.ts | fixed-seed sample of 400 from 499 | 499 | 0 | 0 | 0 | 400 |
| NL/first.male | src/locales/nl/person/first_name.ts | fixed-seed sample of 400 from 571 | 572 | 1 | 0 | 0 | 400 |
| NL/last | src/locales/nl/person/last_name.ts | all | 131 | 0 | 0 | 0 | 131 |
| NL/street | src/locales/nl/location/street_pattern.ts | pattern expansion, 2 patterns (synthetic) | 432 | 0 | 0 | 32 | 400 |
| NL/city | src/locales/nl/location/city_pattern.ts | pattern expansion, 2 patterns (synthetic) | 404 | 0 | 0 | 4 | 400 |
| SE/first.female | src/locales/sv/person/first_name.ts | all | 100 | 0 | 0 | 0 | 100 |
| SE/first.male | src/locales/sv/person/first_name.ts | all | 100 | 0 | 0 | 0 | 100 |
| SE/last | src/locales/sv/person/last_name.ts | all | 100 | 0 | 0 | 0 | 100 |
| SE/street | src/locales/sv/location/street_pattern.ts | pattern expansion, 4 patterns (synthetic) | 524 | 0 | 0 | 124 | 400 |
| SE/city | src/locales/sv/location/city_pattern.ts | pattern expansion, 1 patterns (synthetic) | 935 | 0 | 0 | 535 | 400 |
| US/first.female | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1563 | 1563 | 0 | 0 | 0 | 400 |
| US/first.male | src/locales/en/person/first_name.ts | fixed-seed sample of 400 from 1391 | 1391 | 0 | 0 | 0 | 400 |
| US/last | src/locales/en/person/last_name.ts | all | 473 | 0 | 0 | 0 | 473 |
| US/street | src/locales/en_US/location/street_pattern.ts | pattern expansion, 3 patterns (synthetic) | 449 | 30 | 0 | 19 | 400 |
| US/city | src/locales/en/location/city_name.ts | fixed-seed sample of 400 from 914 | 927 | 13 | 0 | 0 | 400 |

### Per-country derivations

#### AT

- titles: Herr / Frau
- transliteration: [de] over [general]
- faker locale chain (src/locale/de_AT.ts): de_AT → de → en
- last names: the plain list in src/locales/de_AT/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 999: from src/locales/de_AT/location/building_number.ts ["###", "##", "#", "##a", "##b", "##c"]: the most '#' is 3, capped at 9999; letter and roman suffixes are not generated
- @address {street} {number}: from src/locales/de_AT/location/street_address.ts normal = "{{location.street}} {{location.buildingNumber}}"
- cities: real names, faker de_AT/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 9 written (the top-level ISO 3166-2 entries of the CLDR containment: 9 candidates under CLDR's 9 top-level entries); written form: the CLDR de name
- @postcode: 1 pattern(s) from src/locales/de_AT/location/postcode.ts
- @phone: none (no regulator citation verified)

#### AU

- titles: Mr / Ms
- transliteration: [general]
- faker locale chain (src/locale/en_AU.ts): en_AU → en
- last names: the plain list in src/locales/en_AU/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 9999: from src/locales/en_AU/location/building_number.ts ["####", "###", "##"]: the most '#' is 4, capped at 9999; letter and roman suffixes are not generated
- @address {number} {street}: from src/locales/en/location/street_address.ts normal = "{{location.buildingNumber}} {{location.street}}"
- cities: SYNTHETIC. faker has no real city list for this locale; src/locales/en_AU/location/city_pattern.ts is expanded with the fixed seed (ADR 0079 §7 asks for real city names: reported deviation)
- subdivisions: 8 written (the top-level ISO 3166-2 entries of the CLDR containment: 8 candidates under CLDR's 8 top-level entries); written form: the ISO 3166-2 suffix (postal custom)
- @postcode: 1 pattern(s) from src/locales/en_AU/location/postcode.ts
- @phone: none (no regulator citation verified)

#### CA

- titles: Mr / Ms
- transliteration: [general]
- faker locale chain (src/locale/en_CA.ts): en_CA → en
- first names: the sex-specific lists only; faker's 232 generic (unisex) entries in src/locales/en/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/en/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 9999: from src/locales/en/location/building_number.ts ["#####", "####", "###"]: the most '#' is 5, capped at 9999; letter and roman suffixes are not generated
- @address {number} {street}: from src/locales/en/location/street_address.ts normal = "{{location.buildingNumber}} {{location.street}}"
- cities: real names, faker en_CA/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 13 written (the top-level ISO 3166-2 entries of the CLDR containment: 13 candidates under CLDR's 13 top-level entries); written form: the ISO 3166-2 suffix (postal custom)
- [postcode]: 19 lines from src/locales/en_CA/location/postcode_by_state.ts; first letter per province from the regex; the regex's other letters, which exclude D F I O Q U, become '?' (uniform over A-Z, ADR 0079 §4 step 7)
- @postcode: the union of the 18 per-subdivision patterns (faker's own postcode file for this locale is not read)
- @phone: 8 patterns (citation above)

#### CH

- titles: Herr / Frau
- transliteration: [de] over [general]
- faker locale chain (src/locale/de_CH.ts): de_CH → de → en
- first names: the sex-specific lists only; faker's 1 generic (unisex) entries in src/locales/de_CH/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/de_CH/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 999: from src/locales/de/location/building_number.ts ["###", "##", "#", "##a", "##b", "##c"]: the most '#' is 3, capped at 9999; letter and roman suffixes are not generated
- @address {street} {number}: from src/locales/de/location/street_address.ts normal = "{{location.street}} {{location.buildingNumber}}"
- streets: faker's de_CH street_name list is under the 50-entry minimum, so de's street_name entries without "ß" are appended (Swiss Standard German spells ss, not ß): a reported deviation from faker's own chain
- cities: real names, faker de_CH/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 25 written (the top-level ISO 3166-2 entries of the CLDR containment: 26 candidates under CLDR's 26 top-level entries); written form: the CLDR de name; dropped by the display rule: CH-SG "St. Gallen"
- @postcode: 9 pattern(s) from src/locales/de_CH/location/postcode.ts
- @phone: none (no regulator citation verified)

#### DE

- titles: Herr / Frau
- transliteration: [de] over [general]
- faker locale chain (src/locale/de.ts): de → en
- first names: the sex-specific lists only; faker's 10 generic (unisex) entries in src/locales/de/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/de/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 999: from src/locales/de/location/building_number.ts ["###", "##", "#", "##a", "##b", "##c"]: the most '#' is 3, capped at 9999; letter and roman suffixes are not generated
- @address {street} {number}: from src/locales/de/location/street_address.ts normal = "{{location.street}} {{location.buildingNumber}}"
- cities: real names, faker de/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 16 written (the top-level ISO 3166-2 entries of the CLDR containment: 16 candidates under CLDR's 16 top-level entries); written form: the CLDR de name
- @postcode: 1 pattern(s) from src/locales/de/location/postcode.ts
- @phone: 7 patterns (citation above)

#### ES

- titles: Sr. / Sra.
- transliteration: [general]
- faker locale chain (src/locale/es.ts): es → en
- last names: the plain list in src/locales/es/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 99: from src/locales/es/location/building_number.ts [" s/n.", ", #", ", ##", " #", " ##"]: the most '#' is 2, capped at 9999; letter and roman suffixes are not generated; skipped ["s/n."]
- @address {street}, {number}: from src/locales/es/location/street_address.ts normal = "{{location.street}}{{location.buildingNumber}}" (the separator is the first numeric building-number entry's)
- cities: real names, faker es/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 18 written (the top-level ISO 3166-2 entries of the CLDR containment: 19 candidates under CLDR's 19 top-level entries); written form: the CLDR es name; dropped by the display rule: ES-RI "La Rioja²"
- @postcode: 1 pattern(s) from src/locales/es/location/postcode.ts
- @phone: none (no regulator citation verified)

#### FR

- titles: M. / Mme
- transliteration: [general]
- faker locale chain (src/locale/fr.ts): fr → en
- first names: the sex-specific lists only; faker's 16 generic (unisex) entries in src/locales/fr/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/fr/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 9999: from src/locales/fr/location/building_number.ts ["####", "###", "##", "#"]: the most '#' is 4, capped at 9999; letter and roman suffixes are not generated
- @address {number} {street}: from src/locales/fr/location/street_address.ts normal = "{{location.buildingNumber}} {{location.street}}"
- cities: real names, faker fr/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 13 written (the top-level ISO 3166-2 entries of the CLDR containment: 13 candidates under CLDR's 26 top-level entries, after excluding ["fr971", "fr972", "fr973", "fr974", "fr976", "frbl", "frcp", "frmf", "frnc", "frpf", "frpm", "frtf", "frwf"]); written form: the CLDR fr name
- @postcode: 108 pattern(s) from src/locales/fr/location/postcode.ts
- @phone: none (no regulator citation verified)

#### GB

- titles: Mr / Ms
- transliteration: [general]
- faker locale chain (src/locale/en_GB.ts): en_GB → en
- first names: the sex-specific lists only; faker's 232 generic (unisex) entries in src/locales/en/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/en/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 999: from src/locales/en_GB/location/building_number.ts ["###", "##", "#"]: the most '#' is 3, capped at 9999; letter and roman suffixes are not generated
- @address {number} {street}: from src/locales/en/location/street_address.ts normal = "{{location.buildingNumber}} {{location.street}}"
- cities: SYNTHETIC. faker has no real city list for this locale; src/locales/en_GB/location/city_pattern.ts is expanded with the fixed seed (ADR 0079 §7 asks for real city names: reported deviation)
- subdivisions: 4 written (the top-level ISO 3166-2 entries of the CLDR containment: 4 candidates under CLDR's 4 top-level entries); written form: the CLDR en name
- @postcode: 250 pattern(s) from src/locales/en_GB/location/postcode.ts (faker's district shape, expanded 1:1)
- @phone: 16 patterns (citation above)

#### IE

- titles: Mr / Ms
- transliteration: [general]
- faker locale chain (src/locale/en_IE.ts): en_IE → en
- first names: the sex-specific lists only; faker's 232 generic (unisex) entries in src/locales/en/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/en/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 9999: from src/locales/en/location/building_number.ts ["#####", "####", "###"]: the most '#' is 5, capped at 9999; letter and roman suffixes are not generated
- @address {number} {street}: from src/locales/en/location/street_address.ts normal = "{{location.buildingNumber}} {{location.street}}"
- cities: SYNTHETIC. faker has no real city list for this locale; src/locales/en_IE/location/city_pattern.ts is expanded with the fixed seed (ADR 0079 §7 asks for real city names: reported deviation)
- subdivisions: 26 written (the members of each top-level ISO 3166-2 entry: 26 candidates under CLDR's 4 top-level entries); written form: the CLDR en name
- @postcode: 224 pattern(s) from src/locales/en_IE/location/postcode.ts ('*' = letter or digit expanded into every '#'/'?' combination: the same outputs as faker, other weights)
- @phone: none (no regulator citation verified)

#### IT

- titles: Sig. / Sig.ra
- transliteration: [general]
- faker locale chain (src/locale/it.ts): it → en
- last names: the plain list in src/locales/it/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 999: from src/locales/it/location/building_number.ts ["###", "##", "#"]: the most '#' is 3, capped at 9999; letter and roman suffixes are not generated
- @address {street} {number}: from src/locales/it/location/street_address.ts normal = "{{location.street}} {{location.buildingNumber}}"
- cities: real names, faker it/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 20 written (the top-level ISO 3166-2 entries of the CLDR containment: 20 candidates under CLDR's 20 top-level entries); written form: the CLDR it name
- @postcode: 1 pattern(s) from src/locales/it/location/postcode.ts
- @phone: none (no regulator citation verified)

#### NL

- titles: Dhr. / Mevr.
- transliteration: [general]
- faker locale chain (src/locale/nl.ts): nl → en
- first names: the sex-specific lists only; faker's 15 generic (unisex) entries in src/locales/nl/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/nl/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 999: from src/locales/nl/location/building_number.ts ["#", "##", "###", "###a", "###b", "###c", "### I", "### II", "### III"]: the most '#' is 3, capped at 9999; letter and roman suffixes are not generated
- @address {street} {number}: from src/locales/nl/location/street_address.ts normal = "{{location.street}} {{location.buildingNumber}}"
- cities: SYNTHETIC. faker has no real city list for this locale; src/locales/nl/location/city_pattern.ts is expanded with the fixed seed (ADR 0079 §7 asks for real city names: reported deviation)
- subdivisions: 12 written (the top-level ISO 3166-2 entries of the CLDR containment: 12 candidates under CLDR's 18 top-level entries, after excluding ["nlaw", "nlbq1", "nlbq2", "nlbq3", "nlcw", "nlsx"]); written form: the CLDR nl name
- @postcode: 9 pattern(s) from src/locales/nl/location/postcode.ts (compressed to one '?? ' pattern per digit prefix; '?' is uniform over A-Z, so the pairs ["SS", "SD", "SA"] that faker excludes can appear)
- @phone: none (no regulator citation verified)

#### SE

- titles: Herr / Fru
- transliteration: [general]
- faker locale chain (src/locale/sv.ts): sv → en
- last names: the plain list in src/locales/sv/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 999: from src/locales/sv/location/building_number.ts ["###", "##", "#"]: the most '#' is 3, capped at 9999; letter and roman suffixes are not generated
- @address {street} {number}: from src/locales/sv/location/street_address.ts normal = "{{location.street}} {{location.buildingNumber}}"
- cities: SYNTHETIC. faker has no real city list for this locale; src/locales/sv/location/city_pattern.ts is expanded with the fixed seed (ADR 0079 §7 asks for real city names: reported deviation)
- subdivisions: 21 written (the top-level ISO 3166-2 entries of the CLDR containment: 21 candidates under CLDR's 21 top-level entries); written form: the CLDR sv name
- @postcode: 1 pattern(s) from src/locales/sv/location/postcode.ts
- @phone: none (no regulator citation verified)

#### US

- titles: Mr / Ms
- transliteration: [general]
- faker locale chain (src/locale/en_US.ts): en_US → en
- first names: the sex-specific lists only; faker's 232 generic (unisex) entries in src/locales/en/person/first_name.ts are not used for [first.*], only inside street and city patterns
- last names: the plain list in src/locales/en/person/last_name.ts; faker's last_name_pattern (occasional double names) is not applied
- @number 1 9999: from src/locales/en/location/building_number.ts ["#####", "####", "###"]: the most '#' is 5, capped at 9999; letter and roman suffixes are not generated
- @address {number} {street}: from src/locales/en/location/street_address.ts normal = "{{location.buildingNumber}} {{location.street}}"
- cities: real names, faker en/location/city_name.ts (the locale's city_pattern is not used)
- subdivisions: 51 written (the top-level ISO 3166-2 entries of the CLDR containment: 51 candidates under CLDR's 57 top-level entries, after excluding ["usas", "usgu", "usmp", "uspr", "usum", "usvi"]); written form: the ISO 3166-2 suffix (postal custom)
- [postcode]: 819 lines from src/locales/en_US/location/postcode_by_state.ts; number.int ranges widened to their 3-digit prefixes ("995##" covers 99500-99599 even where faker's range starts at 99501); keys outside the subdivision list skipped: US-PR
- @postcode: 2 pattern(s) from src/locales/en/location/postcode.ts
- @phone: 8 patterns (citation above)

<!-- END GENERATED -->
