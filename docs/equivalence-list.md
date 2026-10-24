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

**The seed ("default site groups", [ADR 0080](adr/0080-default-site-groups-vaultwarden-seed.md)).**
[`data/equivalence/groups.txt`](../data/equivalence/groups.txt) holds the 22 groups (184
domains) bitwarden/server still maintains after its 2026-09 cut (PR #8404), taken from
Vaultwarden's `global_domains.json` at `b71cb7a8…` (SHA-256 `3f2c8a39…7933a`): Google (merged
with the former YouTube and Google starter groups), Apple, Merrill, Microsoft, PayPal, Amazon,
Comcast, Alibaba, Autodesk, Facebook, Disney, Turbotax, eBay, Morgan Stanley, Airbnb, Stack
Exchange, DocuSign, Ubiquiti, Yandex, Proton, Atlassian and Twitter. Six upstream members are
removed (`amazon.com.be`, `net.cn`, `atlassian.net`, `statuspage.io`, `jira.com`,
`yandex.ua`; ADR 0080 §2), and each group has a fresh random id. The file's header carries the
provenance; [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) carries the attribution.

**The seed is not signed yet.** [`data/equivalence/EVIDENCE.md`](../data/equivalence/EVIDENCE.md)
has one row per member, and every "Ownership evidence" cell is still `TODO (owner)`. Before
signing, the owner fills in the evidence for every member, drops each member that finds none
(ADR 0080 §3: no waiver), reviews alone as ADR 0038 §4 point 2 permits, and then signs list
version 1 offline (§3 below). When a second maintainer joins, the seed batch is the first thing
they review, retroactively.

When a list ships, its groups are on for every account by default, and each one can be turned
off and back on per account in the web vault's matching settings (ADR 0042 §3).

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
6. **Evidence recorded in [`data/equivalence/EVIDENCE.md`](../data/equivalence/EVIDENCE.md)**,
   one section per group, one row per member ([ADR 0080](adr/0080-default-site-groups-vaultwarden-seed.md)
   §3), so a later second maintainer can audit it without the forge.
7. **No domain in two groups.** `cargo xtask equivalence-list` refuses a source where one
   domain is in two global groups (ADR 0080 §2): "turn this group off" must mean it.

**The upstream re-check (ADR 0080 §3).** At each scheduled re-check (point 5), diff the shipped
groups against bitwarden/server's current `src/Core/Utilities/StaticStore.cs`. An upstream
**removal** of a group or member we ship triggers re-verification of that entry before the next
release (a removal signals a lapse, a sale or a divestiture). An upstream **addition** is only a
candidate for a normal proposal under the rules above. Upstream is never synced in bulk, and
Vaultwarden's file, a lagging mirror of the same data, is not consulted separately.

`cargo test -p xtask` parses the committed `groups.txt`, so a Public Suffix List bump that turns
a member into a suffix fails the pull request that makes it (ADR 0044).

**Start here, before editing the file.** File the proposal as a GitHub issue using the
[`equivalence-group`](../.github/ISSUE_TEMPLATE/equivalence-group.yml) template — it asks for
every point above. Once the evidence stands up to review, open the PR with the
[`equivalence-list`](../.github/PULL_REQUEST_TEMPLATE/equivalence-list.md) pull request
template, linking the issue. Both carry the `equivalence-list` label (the project owner
creates it in the repository's Settings → Labels; the issue template applies it
automatically once it exists), which is the review queue for this process. See
[CONTRIBUTING.md § Equivalence list contributions](../CONTRIBUTING.md#equivalence-list-contributions)
for the full path.

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
  no history itself. **Never sign two different lists with the same version**: a client accepts
  a list whose version equals the last one it accepted, because that can only be the same list
  re-verified at its next start (ADR 0080 §6). **Version 0 is reserved** and the tool refuses
  it; the first list is version 1.
- `<published-at-ms>` is informational only (ADR 0038 §1): milliseconds since the Unix epoch,
  for example `date +%s000`.
- The command fails loudly (non-zero exit, a message on stderr) on a source that does not
  parse (the message names the line, the member and the rule it breaks), a domain in two
  groups, a group id on two lines, version 0, a key file that is not exactly 32 bytes, or an
  encoding overflow; nothing is printed to stdout unless signing succeeded.
- The output path is always `data/equivalence/list.bin` at the repository root, next to its
  source. It is the one path `crates/rizzy-match/src/compiled.rs` includes.

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
   // The path is relative to crates/rizzy-match/src/: it is the repository root's
   // data/equivalence/list.bin.
   pub const GLOBAL_LIST: Option<&[u8]> =
       Some(include_bytes!("../../../data/equivalence/list.bin"));
   pub const LIST_SIGNING_PUBLIC_KEY: Option<[u8; 32]> = Some([ /* the 32 bytes, from step 1 */ ]);
   ```
2. Commit `data/equivalence/list.bin` (the signed bytes; not the seed).
3. Run `cargo test -p rizzy-match`. The tests in `compiled.rs` already exist and start
   checking the list as soon as both constants are set: it verifies at floor 0 and at its own
   version, it decodes to exactly the groups of `groups.txt`, every member passes ADR 0044, and
   no domain is in two groups (ADR 0080 §8).
4. Add the signed list to the fuzz corpus as `fuzz/corpus/equivalence_list/shipped-v<N>.bin`
   (ADR 0080 §8; the corpus already holds the seed signed with a test key).
5. Note the `list_version` shipped in the PR description, so the next list's version is easy
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
