# Known-answer vectors

The committed vector files of [CRYPTO.md §15](../../../../docs/CRYPTO.md#15-testing) item 1. Tests replay every file on every run, so any change in behavior fails CI.

| File | Tier | Covers |
|---|---|---|
| `derivations.json` | A | Every §4.3 derivation implemented in M1, with the derived value itself: symmetric and public key ids, `pw_in` (with NFC), the OPAQUE context, the fake credential id and fake `kdf_id` selector, `server_unlock_key`, `local_unlock_key`, the recovery wrap key and auth token, the export file key, the server data subkeys, the server-secrets backup key, the device-grant PSK, the fingerprint and safety numbers, the device-set hash and the settings hash |
| `envelopes.json` | A | One envelope for each M1 purpose of §8.4 (two for `ITEM_OP` and `ITEM_SNAPSHOT`), with the context bytes, AAD, `k_enc` and commitment; the HPKE PSK device grant with its PSK, `info` and AAD |
| `statements.json` | A | Every §10.2 statement: the bundle chain (first, two-signature identity change, silent update), device certificates (kinds 1–4, and certificates re-issued under a new identity key), revocations, `account-state` at signup, after a standard rotation, after a full rotation (all three with `settings_seq = 0`) and with settings, `op` with and without an item-key wrap, `snapshot` with one, device-signed and identity-signed `key-grant`, `device-auth`, `device-request` |
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

The replay tests (`cargo test -p rizzy-core --lib test_vectors`) recompute every output from its inputs with the same code and compare byte for byte. The computation also checks each output against the specification:
- every envelope opens again, and the typed wrap functions give the same bytes;
- the commitment, AAD, signed messages and container bodies are rebuilt from the CRYPTO.md formulas and compared;
- every statement verifies, and the bundles form a valid chain;
- every formatted code parses back and decodes to the same bits;
- every item value is its type byte and its §2-encoded payload, decodes and encodes back to the same bytes, and every unsupported value is still carried verbatim; every accepted key rebuilds from its parts, and every tag key is `tag/` and the lowercase hex of the name that `unicode-normalization` normalises to NFC directly.

A separate test regenerates every file from its seed and compares it with the committed file. That includes `derivations.json` and `transcript.json`, which run Argon2id.

When the files were generated on 2026-09-25, a separate Python implementation written from CRYPTO.md recomputed every tier A output then present. It used Python `cryptography` 50.0.1, argon2-cffi 25.1.0, and a hand-written HChaCha20 and RFC 9180 implementation checked against the published test vectors. That script is not in the repository. The vectors added since, `padding/frame/reject/3` (2026-09-26) and `items.json` (2026-09-27), were not part of that cross-check. Tier B values come only from this implementation.

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

## Not covered yet

- Constructions of M3 and M5: the local index key and shares. Those reserved, On-device parked ([ADR 0022](../../../../docs/adr/0022-server-mode-only.md)) get vectors with the ADR that revives them.
- HPKE Base mode (`0x10`), which no M1 purpose uses.
- The canonical op and snapshot headers (ADR 0012 §3) and the item-record encoding (ADR 0018). Both are implemented in `rizzy-sync` (modules `header` and `record`), which `rizzy-core` cannot depend on. Their layout-level vectors are Rust test constants there, not files in this directory's schema. The `op` and `snapshot` vectors here still carry placeholder bytes of a valid length as `canonical_header`, which `rizzy-sync`'s header parser rejects, and the `ITEM_OP`/`ITEM_SNAPSHOT` vectors carry placeholder plaintexts and header hashes. Moving the vectors into this schema and regenerating these over real headers waits for an owner decision (CRYPTO.md §15 item 1).
- Running these files on wasm32 and through UniFFI (§15 item 8).
