# The signed equivalence list: generating the key and signing a list

This is the operator-facing companion to [ADR 0038](adr/0038-equivalent-domain-list.md), which
decides the format, signing and governance; read it first. This page says, step by step, how
the owner generates the offline list-signing key and signs a list with `cargo xtask
equivalence-list`, and the review rules every group must pass before it is ever signed.

## Status today

No production list-signing key exists yet, and no signed list is compiled into `rizzy-match`.
`crates/rizzy-match/src/compiled.rs`'s `GLOBAL_LIST` and `LIST_SIGNING_PUBLIC_KEY` are both
`None`, deliberately: there is no placeholder key and no placeholder signed blob, because
either would be a value that *looks* like it should verify something. Until the owner completes
the steps below, every client's merged equivalence view has no global groups, and equivalence
matching runs from each account's own user-defined groups only (ADR 0038 §1: "clients reject an
unsigned list").

A starter, human-editable source file already exists at
[`data/equivalence/groups.txt`](../data/equivalence/groups.txt), with the three groups named in
[ROADMAP §4.4](ROADMAP.md#44-url-matching--autofill-m2) (`youtube.com`/`youtu.be`/
`youtube-nocookie.com`, `google.com` + two ccTLD variants, `apple.com`/`icloud.com`). Its own
header documents the line format and the review rules. **It has not been through the ADR 0038
§4 two-maintainer review and ownership-proof process**, and must not be signed into a real,
shipped list until it has.

## 1. Generating the offline signing key

The key is a dedicated Ed25519 keypair, held separately from every release-signing credential
(ADR 0038 §3; THREAT_MODEL AST-16). `rizzy-core` reads the raw 32-byte seed form (RFC 8032),
the same form `E_id`/`E_dev` use internally — there is no key-file format of its own.

Generate 32 bytes from an OS CSPRNG and keep them offline, at minimum the same tier of
protection as the release tag-signing key (ADR 0038 "Owner answers at acceptance"; a hardware
token or an air-gapped machine, never a developer laptop's normal disk):

```sh
# macOS / Linux: 32 random bytes, written with no shell history of the bytes themselves.
head -c 32 /dev/urandom > equivalence-list-signing-key.seed
chmod 600 equivalence-list-signing-key.seed
```

The matching public key — the one that gets pinned into `crates/rizzy-match/src/compiled.rs` —
is derived from the seed the same way every other Ed25519 public key in this project is (RFC
8032 §5.1.5). The simplest way to read it back out without adding a dependency anywhere is a
one-line use of the `cargo xtask equivalence-list` tool itself: sign a throwaway one-group list
and read the signer's public key from the independent check below, or derive it with any
Ed25519 library you trust, offline, on the same air-gapped machine that holds the seed. Never
paste the seed into a chat, a ticket, or a shell command this repository's tooling will log.

**Never commit the seed file.** It never belongs in this repository, in an issue, or in CI
secrets: CI never signs a list (ADR 0038 §2, "no runtime fetch... the list only ever arrives as
build-time data reviewed in this repository's own release process" — the *signing* step is
explicitly the owner's own offline act, §3).

## 2. Editing the source file

Edit [`data/equivalence/groups.txt`](../data/equivalence/groups.txt) directly; its header is
the format reference. Each change needs, in the pull request that makes it (ADR 0038 §4):

1. **Ownership proof** for every domain added: shared WHOIS registrant/organisation, or a
   public cross-referencing statement on both domains (a `security.txt`, a support article).
   "Looks plausible next to a big brand" is not proof.
2. **Two-maintainer review**, once a second maintainer exists; until then, the sole
   maintainer's own review, with the evidence cited in the PR, so a later second reviewer can
   audit it.
3. **No third-party-hostable domain** unless the Public Suffix List already splits that suffix
   by registrant — flag it `third_party_hostable = 1` and say why in the PR.
4. **Per-ccTLD-variant proof.** `brand.com` and `brand.co.uk` each need their own evidence.
5. **A note of the next scheduled re-check** (at minimum every release cycle).

A new group gets a freshly generated, random 16-byte id (never derived from its domains):

```sh
python3 -c "import secrets; print(secrets.token_hex(16))"
```

Append the new line anywhere in the file — line order in `groups.txt` is cosmetic only.
`cargo xtask equivalence-list` sorts groups by id itself before signing, so there is never a
need to insert in sorted position or renumber existing lines.

## 3. Compiling and signing

```sh
cargo xtask equivalence-list data/equivalence/groups.txt \
    /path/to/equivalence-list-signing-key.seed \
    <list-version> <published-at-ms> \
    > data/equivalence/list.bin
```

- `<list-version>` is a `u32`, strictly greater than every previously published version (ADR
  0038 §2; INV-39). Keep a record of the last published version outside this repository (the
  signing machine, or the previous release's tag) — `rizzy-match` is a no-I/O crate and keeps
  no history itself.
- `<published-at-ms>` is informational only (ADR 0038 §1): milliseconds since the Unix epoch,
  for example `date +%s000`.
- The command fails loudly (non-zero exit, a message on stderr) on a source that does not
  parse, a key file that is not exactly 32 bytes, or an encoding overflow; nothing is printed
  to stdout unless signing succeeded.

Verify the output independently before shipping it — for example with the Python
`cryptography` package, entirely offline:

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

wire = open("data/equivalence/list.bin", "rb").read()
ctx, signature = wire[:-64], wire[-64:]
message = b"rizzy-vault/v1/sig/equivalence-list\x00" + ctx
ed25519.Ed25519PublicKey.from_public_bytes(PUBLIC_KEY_BYTES).verify(signature, message)
```

## 4. Shipping a signed list

In one reviewed change:

1. Set both constants in `crates/rizzy-match/src/compiled.rs` together:
   ```rust
   pub const GLOBAL_LIST: Option<&[u8]> = Some(include_bytes!("../data/equivalence/list.bin"));
   pub const LIST_SIGNING_PUBLIC_KEY: Option<[u8; 32]> = Some([ /* the 32 bytes, from step 1 */ ]);
   ```
2. Commit `data/equivalence/list.bin` (the signed bytes; not the seed).
3. Note the `list_version` shipped in the PR description, so the next list's version is easy
   to pick correctly (strictly greater).

There is no key-rotation mechanism for M2 (ADR 0038 §3): rotating the signing key means a new
client release with a new pinned public key, reviewed with the same care as any other change
to this file.

## Updating an already-shipped list

A new release: bump `<list-version>`, re-run step 3 with the same key, replace
`data/equivalence/list.bin`. There is no out-of-band update channel for M2 (ADR 0038 §2):
shipping an updated list always means a new client release.

## If the signing key is suspected compromised

Treat it exactly like any other release-credential incident (THREAT_MODEL AST-16; ADR 0038
§3): generate a new keypair (step 1), ship it in the next release with a bumped
`format_version` if the verification path itself changes, and treat every list "signed" after
the suspected compromise date as untrusted until re-signed with the new key.
