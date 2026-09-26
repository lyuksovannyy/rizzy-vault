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
