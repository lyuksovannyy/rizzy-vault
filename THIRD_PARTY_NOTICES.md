# Third-party notices

This file lists third-party material that is copied into this repository's source, as opposed to
dependencies fetched by Cargo. Notices for Cargo and npm dependencies are generated per release
artifact ([ADR 0017](docs/adr/0017-licensing.md) §7) and are not kept here.

## EFF's Long Wordlist (`eff_large_wordlist.txt`)

**Owner decision (2026-09-26):** keep the EFF list, with attribution, rather than replace it. A
search on 2026-09-26 found no curated public-domain or CC0 English list of this size whose sources
are also public domain or CC0.

- **Used in:** `crates/rizzy-core/src/generator/eff_large_wordlist.txt`, the wordlist of the
  passphrase generator (CRYPTO.md §12.1). It is compiled into `rizzy-core` with `include_bytes!`,
  so it ships in every artifact that contains `rizzy-core`.
- **Author:** Electronic Frontier Foundation (EFF), "EFF's New Wordlists for Random
  Passphrases", published 2016-07-18. Source: <https://www.eff.org/dice> and
  <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>.
- **Licence:** Creative Commons Attribution 4.0 International (CC BY 4.0),
  <https://creativecommons.org/licenses/by/4.0/>. <https://www.eff.org/copyright>, checked
  2026-09-26, says original EFF material "may be freely distributed at will under the Creative
  Commons Attribution 4.0 International License (CC-BY), unless otherwise noted". The
  <https://www.eff.org/dice> page notes nothing else. The list was first published under
  CC BY 3.0 US.
- **Obligation:** every artifact that contains `rizzy-core` must show the attribution text below
  in its notices or about screen, or in a notices file that ships with it. For `rv`, that can be
  a licences command or a notices file in the release archive.
- **Changes:** none. The file is embedded byte for byte: 7,776 lines of five dice digits, a tab
  and a word. Its SHA-256 is
  `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`, which three independent
  mirrors agreed on; a unit test pins it.
- **Attribution text** (for notices screens): "EFF's Long Wordlist by the Electronic Frontier
  Foundation, <https://www.eff.org/dice>, licensed under CC BY 4.0
  (<https://creativecommons.org/licenses/by/4.0/>). Used unmodified."

## Default site groups (`data/equivalence/groups.txt`)

**Owner decision (2026-10-23):** [ADR 0080](docs/adr/0080-default-site-groups-vaultwarden-seed.md),
accepted as drafted: seed the signed global equivalence list from Vaultwarden's
`global_domains.json`, and attribute it here and on the clients' notices screens.

- **Used in:** `data/equivalence/groups.txt`, the human-editable source of the global
  equivalence list (ADR 0038 §1). Its groups are derived from upstream. Once the owner signs a
  list from it, the signed `data/equivalence/list.bin` is compiled into `rizzy-match` and so
  ships in every client. The signed list is a build product of `groups.txt` and gets no
  separate notice (ADR 0080 §4).
- **Authors:** the Bitwarden server contributors (`src/Core/Utilities/StaticStore.cs` and
  `src/Core/Enums/GlobalEquivalentDomainsType.cs` in <https://github.com/bitwarden/server>), via
  Vaultwarden (<https://github.com/dani-garcia/vaultwarden>), which generates its
  `src/static/global_domains.json` from those files.
- **Sources and commits:**
  - Vaultwarden `src/static/global_domains.json` at
    `b71cb7a832080d9fdfdd97bcccf065307cf73236` (the file last changed in
    `dde63e209e00e4e1a02d8e43175976386a31c53b`), SHA-256
    `3f2c8a39c8c1a8dd9a8c9f4c6b14201afd7113d4fea2b22a27e1847e95e7933a`, 15,910 bytes.
  - Its origin, bitwarden/server at `41ae9acb7b92fc8eef0b73c6cfa6eb2106a326f2`.
  - The subset kept by bitwarden/server PR #8404
    (<https://github.com/bitwarden/server/pull/8404>, `e1f32b96a33f0f5d63170690f0b83cce0b901d36`).
- **Licence:** GNU Affero General Public License v3.0. Vaultwarden is AGPL-3.0-only. Bitwarden
  server's `LICENSE.txt` makes AGPL v3.0 the default throughout that repository outside
  `/bitwarden_license`, and both source files are outside it with no other licence header. This
  is compatible with this project's AGPL-3.0-only ([ADR 0017](docs/adr/0017-licensing.md)).
  Whether a list of domain names is copyrightable at all is not settled here (not legal advice);
  the data is treated as AGPL-licensed and attributed.
- **Changes:**
  - Only the 22 groups bitwarden/server still maintains are taken; the other 69 are not.
  - Six members are removed: `amazon.com.be`, `net.cn`, `atlassian.net`, `statuspage.io`,
    `jira.com` and `yandex.ua` (ADR 0080 §2).
  - Upstream's Google group is merged with this project's YouTube and Google starter groups.
  - Each group has a fresh random 16-byte id; upstream `type` numbers and the per-user
    `excluded` flag are not imported.
  - Further members may be dropped during the owner's evidence review (ADR 0080 §3).
- **Trademarks:** Bitwarden's licence grants no rights in its trademarks. No Bitwarden mark is
  used beyond this attribution.
- **Attribution text** (for notices screens): "Default site groups derived from the Bitwarden
  server's equivalent-domains list via Vaultwarden, AGPL-3.0."
## faker-js locale data (`identity-data-v1.txt`)

- **Used in:** `crates/rizzy-client/src/identity_gen/identity-data-v1.txt`, the identity
  generator's bundled data ([ADR 0079](docs/adr/0079-identity-generator.md) §5, §6). It is compiled
  into `rizzy-client` with `include_str!`, so it ships in every artifact that contains
  `rizzy-client` (the web vault and extension through `rizzy-wasm`, and `rv`). Its first names,
  last names, street and city lists, house-number ranges, address order and postcode patterns
  come from faker-js's `src/locales/<locale>/person` and `/location` files.
- **Source:** @faker-js/faker, <https://github.com/faker-js/faker>, tag `v10.6.0` (commit
  `2cb04231a6ace91a59ebe577c653f4ec66478ca3`). `data/identity/SOURCES.md` lists every file used
  with its SHA-256.
- **Licence:** MIT. The notice below is `LICENSE` at that tag, verbatim (SHA-256
  `8c0814c525426e67c04ca562f28364be477003697903d257160c081d14b271bf`).
- **Changes:** selected, filtered, sampled and re-formatted by `cargo xtask identity-data`; street
  and city names for some countries are generated from faker's own patterns. `SOURCES.md` records
  every rule and drop.
- **Obligation:** every artifact that contains `rizzy-client` must carry the notice below.

    Faker - Copyright (c) 2022-2025

    This software consists of voluntary contributions made by many individuals.
    For exact contribution history, see the revision history
    available at https://github.com/faker-js/faker

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    ===

    From: https://github.com/faker-js/faker/commit/a9f98046c7d5eeaabe12fc587024c06d683800b8
    To: https://github.com/faker-js/faker/commit/29234378807c4141588861f69421bf20b5ac635e

    Based on faker.js, copyright Marak Squires and contributor, what follows below is the original license.

    ===

    faker.js - Copyright (c) 2011-2020
    Marak Squires
    http://github.com/marak/faker.js/

    faker.js was inspired by and has used data definitions from:

     * https://github.com/stympy/faker/ - Copyright (c) 2007-2010 Benjamin Curtis
     * http://search.cpan.org/~jasonk/Data-Faker-0.07/ - Copyright 2004-2005 by Jason Kohles

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Unicode CLDR (`identity-data-v1.txt`)

- **Used in:** the same file, `crates/rizzy-client/src/identity_gen/identity-data-v1.txt`: the
  English country names and the ISO 3166-2 subdivision codes and names (ADR 0079 §5, §6). It
  ships wherever `rizzy-client` does.
- **Source:** Unicode CLDR 49, <https://github.com/unicode-org/cldr>, tag `release-49` (commit
  `96e54b273d2da4ec6fbad350ba19ff23fa24a588`): `common/main/en.xml`,
  `common/supplemental/subdivisions.xml` and `common/subdivisions/{de,en,es,fr,it,nl,sv}.xml`, each
  with its SHA-256 in `data/identity/SOURCES.md`.
- **Licence:** Unicode License v3 (SPDX `Unicode-3.0`). The repository's `LICENSE` at that tag
  (SHA-256 `65eb33419e22a297550a811b5b535f5e532f9a7e0114b516c0ea18afd53c3804`) opens with a paragraph about the UTS #35 specification text, which is not
  used here, and then gives the licence of all other content, the data files included. That part
  is reproduced verbatim below, after the file's own copyright line.
- **Changes:** selected and re-formatted by `cargo xtask identity-data`; names that break the
  data file's character rules are dropped (`SOURCES.md` lists them).
- **Obligation:** every artifact that contains `rizzy-client` must carry the notice below.

    COPYRIGHT AND PERMISSION NOTICE

    Copyright © 2001–2026 Unicode, Inc.

    All other content in this repo is released under UNICODE LICENSE V3

    NOTICE TO USER: Carefully read the following legal agreement. BY
    DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
    SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
    TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
    DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of data files and any associated documentation (the "Data Files") or
    software and any associated documentation (the "Software") to deal in the
    Data Files or Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, and/or sell
    copies of the Data Files or Software, and to permit persons to whom the
    Data Files or Software are furnished to do so, provided that either (a)
    this copyright and permission notice appear with all copies of the Data
    Files or Software, or (b) this copyright and permission notice appear in
    associated Documentation.

    THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
    KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
    THIRD PARTY RIGHTS.

    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
    BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
    OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
    WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
    ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
    FILES OR SOFTWARE.

    Except as contained in this notice, the name of a copyright holder shall
    not be used in advertising or otherwise to promote the sale, use or other
    dealings in these Data Files or Software without prior written
    authorization of the copyright holder.

    SPDX-License-Identifier: Unicode-3.0
