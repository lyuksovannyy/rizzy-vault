# Known-answer vectors

The committed vector files of [CRYPTO.md §15](../../../../docs/CRYPTO.md#15-testing) item 1. Tests replay every file on every run, so any change in behavior fails CI.

| File | Tier | Covers |
|---|---|---|
| `derivations.json` | A | Every §4.3 derivation implemented in M1, with the derived value itself: symmetric and public key ids, `pw_in` (with NFC), the OPAQUE context, the fake credential id and fake `kdf_id` selector, `server_unlock_key`, `local_unlock_key`, the recovery wrap key and auth token, the export file key, the server data subkeys, the server-secrets backup key, the device-grant PSK, the fingerprint and safety numbers, the device-set hash and the settings hash |
| `envelopes.json` | A | One envelope for each M1 purpose of §8.4 (two for `ITEM_OP` and `ITEM_SNAPSHOT`), with the context bytes, AAD, `k_enc` and commitment; the HPKE PSK device grant with its PSK, `info` and AAD |
| `statements.json` | A | Every §10.2 statement: the bundle chain (first, two-signature identity change, silent update), device certificates (kinds 1–4, and certificates re-issued under a new identity key), revocations, `account-state` at signup, after a standard rotation, after a full rotation (all three with `settings_seq = 0`) and with settings, `op` and `snapshot` with and without a wrap, device-signed and identity-signed `key-grant`, `device-auth`, `device-request` |
| `encodings.json` | A | Secret Key and recovery-code formatting with check values, lenient parsing, rejected inputs; Padmé lengths, frames and rejected frames (§7, §8.5) |
| `transcript.json` | B | Signup → login → unlock at `kdf_id` 1 with `RizzySuiteV1`: every OPAQUE message, `E_srv`, `E_local` |

## Format

Each file follows [`schema.json`](schema.json): `{schema, file, tier, spec, generator, seed, vectors}`, and each vector is `{id, kind, name, inputs, outputs}`.

- `id` is `<kind>/<name>/<index>`.
- `name` is the §4.3 label, the §8.4 purpose, the §10.2 statement type or the encoding.

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
- Random values an operation draws internally are drawn first and stored as inputs: the envelope `nonce`, and HPKE's ephemeral `ikm_e`. They are then fed back through a test RNG that yields exactly those bytes and fails if the operation draws more or fewer. No function takes a nonce, in test builds either (INV-12).

The replay tests (`cargo test -p rizzy-core --lib test_vectors`) recompute every output from its inputs with the same code and compare byte for byte. The computation also checks each output against the specification:
- every envelope opens again, and the typed wrap functions give the same bytes;
- the commitment, AAD, signed messages and container bodies are rebuilt from the CRYPTO.md formulas and compared;
- every statement verifies, and the bundles form a valid chain;
- every formatted code parses back and decodes to the same bits.

A separate test regenerates the three files that run no Argon2id from their seeds and compares them with the committed files.

When the files were generated on 2026-09-25, a separate Python implementation written from CRYPTO.md recomputed every tier A output. It used Python `cryptography` 50.0.1, argon2-cffi 25.1.0, and a hand-written HChaCha20 and RFC 9180 implementation checked against the published test vectors. That script is not in the repository. Tier B values come only from this implementation.

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

- Constructions of M3–M6: the relay key, local index key, shares, pairing, and the password-verifier and re-sync PSKs.
- HPKE Base mode (`0x10`), which no M1 purpose uses.
- The canonical op and snapshot headers (ADR 0012 §3) and the item-record encoding. Neither is implemented. The `op`, `snapshot` and `ITEM_OP`/`ITEM_SNAPSHOT` vectors carry placeholder bytes of a valid length in their place.
- Running these files on wasm32 and through UniFFI (§15 item 8).
