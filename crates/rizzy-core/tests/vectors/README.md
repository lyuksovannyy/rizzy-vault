# Known-answer vectors

The committed vector files of [CRYPTO.md §15](../../../../docs/CRYPTO.md#15-testing) item 1. Tests replay every file on every run, so any change in behavior fails CI.

| File | Tier | Covers |
|---|---|---|
| `derivations.json` | A | Every §4.3 derivation implemented in M1, with the derived value itself: symmetric and public key ids, `pw_in` (with NFC), the OPAQUE context, the fake credential id and fake `kdf_id` selector, `server_unlock_key`, `local_unlock_key`, the recovery wrap key and auth token, the export file key, the server data subkeys, the server-secrets backup key, the device-grant PSK, the fingerprint and safety numbers, the device-set hash and the settings hash |
| `envelopes.json` | A | One envelope for each M1 purpose of §8.4 (two for `ITEM_OP` and `ITEM_SNAPSHOT`), with the context bytes, AAD, `k_enc` and commitment; the HPKE PSK device grant with its PSK, `info` and AAD. Each `ITEM_OP` and `ITEM_SNAPSHOT` vector carries its record's canonical header ([ADR 0012](../../../../docs/adr/0012-sync-engine.md) §3) as the input `canonical_header`: the context's fields are the header's, and its header hash is `SHA-256` of those bytes (an op header with no causal context and one with two entries; a snapshot header covering one device and one covering two) |
| `statements.json` | A | Every §10.2 statement: the bundle chain (first, two-signature identity change, silent update), device certificates (kinds 1–4, and certificates re-issued under a new identity key), revocations, `account-state` at signup, after a standard rotation, after a full rotation (all three with `settings_seq = 0`) and with settings, `op` with and without an item-key wrap, `snapshot` with one (all three over canonical ADR 0012 §3 headers, the first records of one item by the desktop device: `op/0` creates it, `snapshot/0` covers that op, `op/1` is a later edit whose causal context names two devices), device-signed and identity-signed `key-grant`, `device-auth`, `device-request` (one ordinary request, and seven request-targets signed byte for byte, which share every other input so that only the target tells their signed messages apart: an empty query, duplicate parameters, one octet percent-encoded in lower and in upper case, `/a/./b`, `/a/../b` and `//a`; [ADR 0028](../../../../docs/adr/0028-api-v1-http-conventions.md) item 5) |
| `encodings.json` | A | Secret Key and recovery-code formatting with check values, lenient parsing, rejected inputs; Padmé lengths, frames and rejected frames (§7, §8.5) |
| `items.json` | A | The schema layer of the item record ([ADR 0018](../../../../docs/adr/0018-item-record-encoding.md) §6, §7, §10): every value type encoded, and values a reader shows as unsupported; accepted field keys with their parts, and keys the grammar or the 160-byte limit rejects, among them the four §12 names; tag keys from names (NFC, no Cc, 1–64 bytes), and rejected names |
| `transcript.json` | B | Signup → login → unlock at `kdf_id` 1 with `RizzySuiteV1`: every OPAQUE message, `E_srv`, `E_local` |

## Format

Each file follows [`schema.json`](schema.json): `{schema, file, tier, spec, generator, seed, vectors}`, and each vector is `{id, kind, name, inputs, outputs}`.

- `id` is `<kind>/<name>/<index>`.
- `name` is the §4.3 label, the §8.4 purpose, the §10.2 statement type, the encoding, or the ADR 0018 rule (`value`, `field-key`, `tag-key`, each with its `/reject` or `/unsupported` variant).

Values follow these rules:
- Byte strings are lowercase hex.
- `u64` values are decimal strings, because JSON numbers lose precision above 2^53 in JavaScript.
- `u8`, `u16` and `u32` values are JSON numbers.
- Text (passwords, login names, origins, formatted codes) is a JSON string, unchanged.
- An envelope's context is a nested `ctx` object with the §8.4 field names.

The field names inside `inputs` and `outputs` are the ones the replay code in `src/test_vectors/` reads, one module per file.

## How they are made

The generator (`src/test_vectors/`) works like this:
- It draws every input from `ChaCha20Rng::seed_from_u64(seed)` (`chacha20` =0.10.2, ADR 0009). The seed is in each file.
- It computes the outputs through `rizzy-core`'s own API.
- In the tier A files, random values an operation draws internally are drawn first and stored as inputs: the envelope `nonce`, and HPKE's ephemeral `ikm_e`. They are then fed back through a test RNG that yields exactly those bytes and fails if the operation draws more or fewer. No seal function takes a nonce or `ikm_e` parameter, in test builds either (INV-12).
- `transcript.json` instead stores a second seed as an input. One `ChaCha20Rng` seeded from it drives the whole flow, opaque-ke included.
- The canonical op and snapshot headers (ADR 0012 §3) are `rizzy-sync`'s (module `header`), which `rizzy-core` cannot depend on ([ADR 0016](../../../../docs/adr/0016-workspace-layout.md)). `rizzy-core` takes a header as opaque bytes, so the generator writes the headers of the `op`, `snapshot`, `ITEM_OP` and `ITEM_SNAPSHOT` vectors by hand, field by field from the ADR text (`src/test_vectors/headers.rs`), and the replay reads them back with a strict decoder of its own. A `rizzy-sync` test (`crates/rizzy-sync/src/header/core_vectors.rs`) then parses every one of those committed headers with `rizzy_sync::header`, re-encodes it byte for byte, verifies each statement and rebuilds each envelope context from the parsed header and opens the envelope under it. So the two implementations of the layout are checked against each other on the committed bytes.

The replay tests (`cargo test -p rizzy-core --lib test_vectors`) recompute every output from its inputs with the same code and compare byte for byte. The computation also checks each output against the specification:
- every envelope opens again, and the typed wrap functions give the same bytes;
- the commitment, AAD, signed messages and container bodies are rebuilt from the CRYPTO.md formulas and compared;
- every statement verifies, and the bundles form a valid chain;
- every formatted code parses back and decodes to the same bits;
- every item value is its type byte and its §2-encoded payload, decodes and encodes back to the same bytes, and every unsupported value is still carried verbatim; every accepted key rebuilds from its parts, and every tag key is `tag/` and the lowercase hex of the name that `unicode-normalization` normalises to NFC directly.

A separate test regenerates every file from its seed and compares it with the committed file. That includes `derivations.json` and `transcript.json`, which run Argon2id.

When the files were generated on 2026-09-25, a separate Python implementation written from CRYPTO.md recomputed every tier A output then present. It used Python `cryptography` 50.0.1, argon2-cffi 25.1.0, and a hand-written HChaCha20 and RFC 9180 implementation checked against the published test vectors. That script is not in the repository. The vectors added since, `padding/frame/reject/3` (2026-09-26), `items.json` (2026-09-27) and `statement/device-request/1` to `7` (2026-09-30), were not part of that cross-check, and neither are the seven vectors regenerated over canonical headers on 2026-09-30 ("Change record" below): the cross-check covered their earlier bytes. Tier B values come only from this implementation.

## Changing a vector

**Tier A vectors are normative.** Changing an output means the format changed. That takes three things:
- a version bump of the construction concerned;
- an ADR note ([CRYPTO.md §15](../../../../docs/CRYPTO.md#15-testing) item 1);
- regenerated files.

Never edit a file by hand. The replay fails unless each file is exactly in its generated form. To regenerate:

```sh
cargo test -p rizzy-core --lib test_vectors::generate -- --ignored --exact
```

**Tier B (`transcript.json`) is a regression value.** It depends on opaque-ke, argon2, curve25519-dalek and the seeded RNG. The PR that bumps one of those crates regenerates it and says why in the PR.

### Change record

Every change to the bytes of a committed tier A vector is listed here ([CRYPTO.md §15](../../../../docs/CRYPTO.md#15-testing) item 1: "Changing one of these requires a version bump and an ADR note").

**2026-09-30: seven vectors regenerated over canonical ADR 0012 §3 headers.**

- *What changed.* The vectors below signed or bound placeholder header bytes: random bytes of a valid length, which `rizzy-sync`'s header parser rejects. They now carry canonical headers. Their inputs changed (`canonical_header`; for the envelope vectors it is a new input, and `ctx.op_header_hash` or `ctx.snapshot_header_hash` is now `SHA-256` of it), and so did every output computed from them.
  - `statement/op/0`, `statement/op/1`, `statement/snapshot/0`: input `canonical_header`; outputs `body`, `signed_message`, `message_hash`, `container`, `wire`. The inputs `envelope`, `item_key_wrap` and `signer_seed` and the outputs `envelope_hash`, `wrap_hash`, `signer_public_key` and `signer_key_id` are unchanged. `op/0` is now the 97-byte header (a create, with the wrap) and `op/1` the 145-byte one (an edit with a two-entry causal context, without a wrap); before, the lengths were the other way round.
  - `envelope/ITEM_OP/0`, `envelope/ITEM_OP/1`, `envelope/ITEM_SNAPSHOT/0`, `envelope/ITEM_SNAPSHOT/1`: new input `canonical_header`, input `ctx` header hash; outputs `ctx`, `aad`, `k_enc`, `commitment`, `envelope`. The inputs `key`, `nonce` and `plaintext` and every other `ctx` field are unchanged.
- *What did not change.* No construction, format or label: the same code computes the outputs, and the old inputs would still give the old outputs. So no construction's version is bumped. Every other vector of both files, and the four other files, are byte for byte what they were: the generator draws exactly the random bytes it drew before, in the same order.
- *ADR.* The headers are the layout [ADR 0012](../../../../docs/adr/0012-sync-engine.md) §3 already fixes, and §12 there asks for "real `rizzy-core` crypto" over them; no ADR text changes. This entry is the note §15 asks for. Whether it also belongs in an ADR is the owner's call.

## Not covered yet

- Constructions of M3 and M5: the local index key and shares. Those reserved, On-device parked ([ADR 0022](../../../../docs/adr/0022-server-mode-only.md)) get vectors with the ADR that revives them.
- HPKE Base mode (`0x10`), which no M1 purpose uses.
- The item-record encoding (ADR 0018), and rejection vectors for the canonical op and snapshot headers (ADR 0012 §3). Both are implemented in `rizzy-sync` (modules `record` and `header`), which `rizzy-core` cannot depend on. Their layout-level vectors are Rust test constants there (`crates/rizzy-sync/src/record/vectors.rs` and `crates/rizzy-sync/src/header/tests.rs`), not files in this directory's schema. The files here carry accepted headers only (seven, in the `op`, `snapshot`, `ITEM_OP` and `ITEM_SNAPSHOT` vectors), and the `ITEM_OP`/`ITEM_SNAPSHOT` vectors still carry placeholder plaintexts, as do the `envelope` and `item_key_wrap` inputs of the `op` and `snapshot` vectors (opaque bytes of a real envelope's length; the statement signs only their hash). Moving the record and header vectors into this schema, and the envelope-level record vectors of ADR 0018 §12, wait for an owner decision (CRYPTO.md §15 item 1(A), which records this current state).
- Running these files on wasm32 and through UniFFI (§15 item 8).
