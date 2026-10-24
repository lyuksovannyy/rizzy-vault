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
