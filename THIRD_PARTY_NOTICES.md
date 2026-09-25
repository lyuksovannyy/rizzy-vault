# Third-party notices

This file lists third-party material that is copied into this repository's source, as opposed to
dependencies fetched by Cargo. Notices for Cargo and npm dependencies are generated per release
artifact ([ADR 0017](docs/adr/0017-licensing.md) §7) and are not kept here.

> **Owner review needed.** ADR 0017 (licensing) is still Proposed. Whether the licence below is
> compatible with shipping this material in every rizzy-vault artifact, and whether this file is
> the right place for the notice, is for the owner to confirm.

## EFF's Long Wordlist (`eff_large_wordlist.txt`)

- **Used in:** `crates/rizzy-core/src/generator/eff_large_wordlist.txt`, the wordlist of the
  passphrase generator (CRYPTO.md §12.1). It is compiled into `rizzy-core` with `include_bytes!`,
  so it ships in every artifact that contains `rizzy-core`.
- **Author:** Electronic Frontier Foundation (EFF), "EFF's New Wordlists for Random
  Passphrases", published 2016-07-18. Source: <https://www.eff.org/dice> and
  <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>.
- **Licence:** Creative Commons Attribution 3.0 United States (CC BY 3.0 US),
  <https://creativecommons.org/licenses/by/3.0/us/>. This is the licence EFF states for the
  content of its website. It was not re-checked against eff.org when the file was added: the
  build machine could not reach eff.org (unverified).
- **Changes:** none. The file is embedded byte for byte: 7,776 lines of five dice digits, a tab
  and a word. Its SHA-256 is
  `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`, which three independent
  mirrors agreed on; a unit test pins it.
- **Attribution text** (for notices screens): "EFF's Long Wordlist by the Electronic Frontier
  Foundation, <https://www.eff.org/dice>, licensed under CC BY 3.0 US
  (<https://creativecommons.org/licenses/by/3.0/us/>). Used unmodified."
