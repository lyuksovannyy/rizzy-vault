// SPDX-License-Identifier: AGPL-3.0-only

//! Known-answer vectors for the format version 2 container (CRYPTO.md §9.8, §15 item 1; ADR
//! 0071), at the real 8 MiB chunk length.
//!
//! The file is `crates/rizzy-core/tests/vectors/db_backup.json`, next to the other vector files
//! (§15 item 1 commits them there), in the same JSON shape; it is replayed here because the
//! container lives in `rizzy-server` (ADR 0071 "Crate ownership"), which `rizzy-core` cannot
//! depend on. The per-chunk envelope itself, its subkey, context, AAD and commitment, has its
//! own vectors in `envelopes.json` (`SERVER_DB_BACKUP`) and `derivations.json`
//! (`server/db-backup`).
//!
//! - **Generation** ([`generate`], ignored by default) draws every input from a seeded
//!   `ChaCha20Rng` and computes the outputs through [`db_backup::seal`]. The random values the
//!   writer draws (`backup_id`, then each chunk's nonce) are stored as inputs and fed back
//!   through [`ExactRng`], which fails the test if the writer draws more or fewer bytes.
//! - **Replay** ([`committed_vectors_replay`]) recomputes every output from the committed inputs
//!   and compares; it also opens every positive vector and checks every negative one fails with
//!   its recorded error.
//!
//! Vectors (`kind` `db-backup`):
//! - `single-chunk/0`, `single-chunk/1`: 1000-byte payloads under one backup key, in full: the
//!   header, each chunk's context, the whole file.
//! - `three-chunk/0`: a `2 × CHUNK_LEN + 1000`-byte payload (byte `i` = `i mod 251`, the input
//!   `plaintext_rule`): the header, each context, the SHA-256 of each envelope and of the
//!   file, and the short final envelope in full.
//! - `reject/N`: one mutation of a positive vector each (truncation, appended byte, reordered
//!   chunks, a dropped final chunk with the clear header edited to match, a chunk from another
//!   backup, header edits, bit flips) and the error the reader must return.
//!
//! Regenerate on purpose only: `cargo test -p rizzy-server --test db_backup -- --ignored
//! generate`, then review the diff.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: a failure fails the test, which CLAUDE.md allows"
)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::PathBuf;

use chacha20::ChaCha20Rng;
use chacha20::rand_core::{Rng as _, SeedableRng as _};
use rand_core::{TryCryptoRng, TryRng};
use rizzy_domain_auth::types::ServerDbBackupKey;
use rizzy_server::db_backup::{self, CHUNK_LEN, CHUNK_OVERHEAD, DbBackupError, HEADER_LEN};
use rizzy_storage::backup::file::{MAGIC, digest};
use serde_json::{Map, Value, json};

/// The generator's seed (`ChaCha20Rng::seed_from_u64`).
const SEED: u64 = 0x0908;

/// The `plaintext_rule` of the large vector.
const RULE: &str = "byte i = i mod 251";

/// The committed file.
fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rizzy-core/tests/vectors/db_backup.json")
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// An RNG that yields exactly the given bytes, in order; drawing past the end panics and
/// [`ExactRng::finish`] asserts every byte was drawn. Marked `CryptoRng` only so the API takes
/// it, like `rizzy-core`'s vector generator's.
struct ExactRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl ExactRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }

    #[track_caller]
    fn finish(self) {
        assert_eq!(
            self.pos,
            self.bytes.len(),
            "the writer drew fewer random bytes"
        );
    }
}

impl TryRng for ExactRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self.pos + dst.len();
        assert!(end <= self.bytes.len(), "the writer drew more random bytes");
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

impl TryCryptoRng for ExactRng {}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn random<const N: usize>(rng: &mut ChaCha20Rng) -> [u8; N] {
    let mut out = [0u8; N];
    rng.fill_bytes(&mut out);
    out
}

fn field<'a>(m: &'a Map<String, Value>, key: &str) -> &'a Value {
    m.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

fn bytes(m: &Map<String, Value>, key: &str) -> Vec<u8> {
    unhex(field(m, key).as_str().unwrap())
}

fn u64_of(m: &Map<String, Value>, key: &str) -> u64 {
    field(m, key).as_str().unwrap().parse().unwrap()
}

fn num(m: &Map<String, Value>, key: &str) -> u32 {
    u32::try_from(field(m, key).as_u64().unwrap()).unwrap()
}

/// The payload of the large vector: byte `i` = `i mod 251`.
fn rule_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

/// `backup_id ‖ u64 created_at_ms ‖ u32 backup_key_id ‖ u32 i ‖ u32 chunk_count` (§8.4).
fn ctx_bytes(backup_id: &[u8], created_at_ms: u64, key_id: u32, i: u32, count: u32) -> Vec<u8> {
    [
        backup_id,
        &created_at_ms.to_be_bytes(),
        &key_id.to_be_bytes(),
        &i.to_be_bytes(),
        &count.to_be_bytes(),
    ]
    .concat()
}

/// The envelopes of a file, by the framing of §9.8.
fn chunks(file: &[u8], plaintext_len: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut at = HEADER_LEN;
    let mut left = plaintext_len;
    while left > 0 {
        let len = left.min(CHUNK_LEN) + CHUNK_OVERHEAD;
        out.push(&file[at..at + len]);
        at += len;
        left -= len - CHUNK_OVERHEAD;
    }
    assert_eq!(at, file.len());
    out
}

// ---------------------------------------------------------------------------------------------
// Positive vectors
// ---------------------------------------------------------------------------------------------

/// A positive vector's inputs, drawn from the generator.
fn draw_inputs(
    rng: &mut ChaCha20Rng,
    key: &[u8; 32],
    key_id: u32,
    plaintext: Option<&[u8]>,
    len: usize,
) -> Value {
    let count = len.div_ceil(CHUNK_LEN);
    let nonces: Vec<String> = (0..count).map(|_| hex(&random::<24>(rng))).collect();
    let mut m = json!({
        "backup_key": hex(key),
        "backup_key_id": key_id,
        "created_at_ms": "1780000000000",
        "backup_id": hex(&random::<16>(rng)),
        "nonces": nonces,
    });
    let obj = m.as_object_mut().unwrap();
    if let Some(p) = plaintext {
        obj.insert("plaintext".into(), hex(p).into());
    } else {
        obj.insert("plaintext_len".into(), len.to_string().into());
        obj.insert("plaintext_rule".into(), RULE.into());
    }
    m
}

/// The payload a positive vector's inputs describe.
fn payload_of(inputs: &Map<String, Value>) -> Vec<u8> {
    if let Some(p) = inputs.get("plaintext") {
        unhex(p.as_str().unwrap())
    } else {
        assert_eq!(field(inputs, "plaintext_rule").as_str(), Some(RULE));
        rule_payload(usize::try_from(u64_of(inputs, "plaintext_len")).unwrap())
    }
}

fn key_of(inputs: &Map<String, Value>) -> ServerDbBackupKey {
    ServerDbBackupKey::from_slice(&bytes(inputs, "backup_key"), num(inputs, "backup_key_id"))
        .unwrap()
}

/// Seals a positive vector from its inputs, feeding its random inputs back exactly.
fn seal_vector(inputs: &Map<String, Value>) -> Vec<u8> {
    let mut random = bytes(inputs, "backup_id");
    for n in field(inputs, "nonces").as_array().unwrap() {
        random.extend(unhex(n.as_str().unwrap()));
    }
    let mut rng = ExactRng::new(random);
    let file = db_backup::seal(
        &mut rng,
        &key_of(inputs),
        &payload_of(inputs),
        u64_of(inputs, "created_at_ms"),
    )
    .unwrap();
    rng.finish();
    file
}

/// The outputs of a positive vector: computed, then checked against the §9.8 layout.
fn positive_outputs(inputs: &Map<String, Value>, file: &[u8], full: bool) -> Value {
    let payload = payload_of(inputs);
    let count = u32::try_from(payload.len().div_ceil(CHUNK_LEN)).unwrap();
    let created = u64_of(inputs, "created_at_ms");
    let key_id = num(inputs, "backup_key_id");
    let backup_id = bytes(inputs, "backup_id");

    // The header, field by field (§9.8).
    let header = [
        MAGIC.as_slice(),
        &2u16.to_be_bytes(),
        &backup_id,
        &created.to_be_bytes(),
        &key_id.to_be_bytes(),
        &u64::try_from(payload.len()).unwrap().to_be_bytes(),
        &count.to_be_bytes(),
    ]
    .concat();
    assert_eq!(&file[..HEADER_LEN], header.as_slice());
    let envelopes = chunks(file, payload.len());
    assert_eq!(envelopes.len(), count as usize);
    let nonces = field(inputs, "nonces").as_array().unwrap();
    for (i, env) in envelopes.iter().enumerate() {
        // 0x01 envelope: version, algorithm, key id, then the drawn nonce (§9.1).
        assert_eq!(&env[..2], &[0x01, 0x01]);
        assert_eq!(&env[18..42], unhex(nonces[i].as_str().unwrap()).as_slice());
        assert_eq!(&env[2..18], &envelopes[0][2..18], "one subkey per backup");
    }
    // It opens again, to the payload.
    let key = key_of(inputs);
    let opened = db_backup::open(|id| (id == key_id).then_some(&key), file).unwrap();
    assert_eq!(opened.as_slice(), payload.as_slice());

    let ctx: Vec<String> = (0..count)
        .map(|i| hex(&ctx_bytes(&backup_id, created, key_id, i, count)))
        .collect();
    let mut out = json!({
        "header": hex(&header),
        "chunk_ctx": ctx,
        "key_id": hex(&envelopes[0][2..18]),
    });
    let obj = out.as_object_mut().unwrap();
    if full {
        obj.insert("file".into(), hex(file).into());
    } else {
        let sums: Vec<String> = envelopes.iter().map(|e| hex(&digest(e))).collect();
        obj.insert("chunk_sha256".into(), sums.into());
        obj.insert(
            "final_chunk".into(),
            hex(envelopes[envelopes.len() - 1]).into(),
        );
        obj.insert("file_sha256".into(), hex(&digest(file)).into());
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Negative vectors
// ---------------------------------------------------------------------------------------------

/// Applies a `reject` vector's mutation to its base file.
fn mutate(files: &BTreeMap<String, (Vec<u8>, usize)>, inputs: &Map<String, Value>) -> Vec<u8> {
    let (base, plaintext_len) = &files[field(inputs, "base").as_str().unwrap()];
    let m = field(inputs, "mutation").as_object().unwrap();
    let mut file = base.clone();
    match field(m, "op").as_str().unwrap() {
        "truncate" => file.truncate(num(m, "len") as usize),
        "append" => file.extend(bytes(m, "bytes")),
        "flip" => file[num(m, "offset") as usize] ^= 1 << num(m, "bit"),
        "swap_chunks" => {
            let envs = chunks(base, *plaintext_len);
            let (a, b) = (num(m, "a") as usize, num(m, "b") as usize);
            assert_eq!(envs[a].len(), envs[b].len(), "swap chunks of one length");
            let mut swapped: Vec<&[u8]> = envs.clone();
            swapped.swap(a, b);
            file = [&base[..HEADER_LEN], &swapped.concat()].concat();
        }
        "drop_last_chunk_and_fix_header" => {
            // The clear fields edited to match: chunk_count - 1 and the payload of the kept
            // chunks, so the framing is consistent and only the AAD can refuse it.
            let envs = chunks(base, *plaintext_len);
            let kept = envs.len() - 1;
            file = [&base[..HEADER_LEN], &envs[..kept].concat()].concat();
            let len = u64::try_from(kept * CHUNK_LEN).unwrap();
            file[52..60].copy_from_slice(&len.to_be_bytes());
            file[60..64].copy_from_slice(&u32::try_from(kept).unwrap().to_be_bytes());
        }
        "splice_chunk" => {
            let (other, other_len) = &files[field(m, "from").as_str().unwrap()];
            let i = num(m, "chunk") as usize;
            let mine = chunks(base, *plaintext_len);
            let theirs = chunks(other, *other_len);
            let mut out = base[..HEADER_LEN].to_vec();
            for (j, env) in mine.iter().enumerate() {
                out.extend_from_slice(if j == i { theirs[i] } else { env });
            }
            file = out;
        }
        "set_header" => {
            let range = match field(m, "field").as_str().unwrap() {
                "created_at_ms" => 40..48,
                "backup_key_id" => 48..52,
                "plaintext_len" => 52..60,
                "chunk_count" => 60..64,
                other => panic!("header field {other}"),
            };
            let value: u64 = field(m, "value").as_str().unwrap().parse().unwrap();
            let width = range.len();
            file[range].copy_from_slice(&value.to_be_bytes()[8 - width..]);
        }
        other => panic!("mutation {other}"),
    }
    file
}

fn error_json(e: DbBackupError) -> Value {
    match e {
        DbBackupError::Malformed(rule) => json!({"kind": "malformed", "rule": rule}),
        DbBackupError::Authentication { chunk_index } => {
            json!({"kind": "authentication", "chunk_index": chunk_index})
        }
        DbBackupError::UnknownBackupKey { backup_key_id } => {
            json!({"kind": "unknown_backup_key", "backup_key_id": backup_key_id})
        }
        other => panic!("unexpected reader error {other:?}"),
    }
}

/// The reject vectors: (base, mutation). Offsets are into the header (§9.8: magic `0..22`,
/// `format_version` `22..24`, `backup_id` `24..40`, `created_at_ms` `40..48`, `backup_key_id`
/// `48..52`, `plaintext_len` `52..60`, `chunk_count` `60..64`) or an envelope (§9.1: key id at
/// +2, nonce at +18, commitment at +42, ciphertext at +74).
fn reject_mutations(single_len: usize, three_len: usize) -> Vec<(&'static str, Value)> {
    let single_file = HEADER_LEN + single_len + CHUNK_OVERHEAD;
    let three_final = HEADER_LEN + 2 * (CHUNK_LEN + CHUNK_OVERHEAD);
    vec![
        (
            "db-backup/single-chunk/0",
            json!({"op": "truncate", "len": single_file - 1}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "truncate", "len": HEADER_LEN}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "append", "bytes": "00"}),
        ),
        (
            "db-backup/three-chunk/0",
            json!({"op": "swap_chunks", "a": 0, "b": 1}),
        ),
        (
            "db-backup/three-chunk/0",
            json!({"op": "drop_last_chunk_and_fix_header"}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "splice_chunk", "from": "db-backup/single-chunk/1", "chunk": 0}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "flip", "offset": 24, "bit": 0}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "set_header", "field": "created_at_ms", "value": "1780000000001"}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "set_header", "field": "backup_key_id", "value": "9"}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "set_header", "field": "chunk_count", "value": "2"}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "set_header", "field": "plaintext_len", "value": (single_len - 1).to_string()}),
        ),
        (
            "db-backup/three-chunk/0",
            json!({"op": "set_header", "field": "plaintext_len", "value": (three_len + 1).to_string()}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "flip", "offset": 23, "bit": 0}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "flip", "offset": 0, "bit": 7}),
        ),
        (
            "db-backup/single-chunk/0",
            json!({"op": "flip", "offset": HEADER_LEN + 42, "bit": 3}),
        ),
        (
            "db-backup/three-chunk/0",
            json!({"op": "flip", "offset": three_final + 74, "bit": 0}),
        ),
    ]
}

// ---------------------------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------------------------

/// A vector object, the way the `rizzy-core` files write them.
fn vector(name: &str, index: usize, inputs: Value, outputs: Value) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), format!("db-backup/{name}/{index}").into());
    m.insert("kind".into(), "db-backup".into());
    m.insert("name".into(), name.into());
    m.insert("inputs".into(), inputs);
    m.insert("outputs".into(), outputs);
    Value::Object(m)
}

/// Computes every vector's outputs from its inputs (generation and replay share it).
fn compute(vectors: &[Value]) -> Vec<Value> {
    let mut files: BTreeMap<String, (Vec<u8>, usize)> = BTreeMap::new();
    let mut keys: BTreeMap<String, ServerDbBackupKey> = BTreeMap::new();
    let mut out = Vec::new();
    for v in vectors {
        let v = v.as_object().unwrap();
        let id = field(v, "id").as_str().unwrap().to_owned();
        let name = field(v, "name").as_str().unwrap();
        let inputs = field(v, "inputs").as_object().unwrap();
        let outputs = if name == "reject" {
            let base = field(inputs, "base").as_str().unwrap();
            let bad = mutate(&files, inputs);
            let key = &keys[base];
            let err = db_backup::open(|id| (id == key.backup_key_id()).then_some(key), &bad)
                .expect_err("a reject vector opens");
            json!({"error": error_json(err)})
        } else {
            let file = seal_vector(inputs);
            let outputs = positive_outputs(inputs, &file, name == "single-chunk");
            files.insert(id.clone(), (file, payload_of(inputs).len()));
            keys.insert(id.clone(), key_of(inputs));
            outputs
        };
        out.push(vector(
            name,
            id.rsplit('/').next().unwrap().parse().unwrap(),
            Value::Object(inputs.clone()),
            outputs,
        ));
    }
    out
}

/// Every vector, drawn from [`SEED`].
fn generated() -> Value {
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let key = random::<32>(&mut rng);
    let key_id = 1;
    let single = 1000;
    let three = 2 * CHUNK_LEN + 1000;
    let mut inputs = Vec::new();
    for i in 0..2 {
        let pt: Vec<u8> = (0..single).map(|_| (rng.next_u32() & 0xff) as u8).collect();
        inputs.push(vector(
            "single-chunk",
            i,
            draw_inputs(&mut rng, &key, key_id, Some(&pt), single),
            Value::Null,
        ));
    }
    inputs.push(vector(
        "three-chunk",
        0,
        draw_inputs(&mut rng, &key, key_id, None, three),
        Value::Null,
    ));
    for (i, (base, mutation)) in reject_mutations(single, three).into_iter().enumerate() {
        inputs.push(vector(
            "reject",
            i,
            json!({"base": base, "mutation": mutation}),
            Value::Null,
        ));
    }
    json!({
        "schema": "rizzy-vault/test-vectors/v1",
        "file": "db_backup",
        "tier": "A",
        "spec": "CRYPTO.md §9.8 (ADR 0071); replayed by rizzy-server tests/db_backup.rs",
        "generator": "ChaCha20Rng (chacha20 =0.10.2), seed_from_u64",
        "seed": SEED.to_string(),
        "vectors": compute(&inputs),
    })
}

#[test]
#[ignore = "rewrites crates/rizzy-core/tests/vectors/db_backup.json; run only to change a vector on purpose"]
fn generate() {
    let mut text = serde_json::to_string_pretty(&generated()).unwrap();
    text.push('\n');
    std::fs::write(path(), text).unwrap();
}

#[test]
fn committed_vectors_replay() {
    let text = std::fs::read_to_string(path()).unwrap();
    let committed: Value = serde_json::from_str(&text).unwrap();
    let file = committed.as_object().unwrap();
    assert_eq!(file["schema"], "rizzy-vault/test-vectors/v1");
    assert_eq!(file["file"], "db_backup");
    let vectors = file["vectors"].as_array().unwrap();
    // Every kind of vector is there: the two single-chunk files, the large one, and every
    // reject mutation.
    let ids: Vec<&str> = vectors.iter().map(|v| v["id"].as_str().unwrap()).collect();
    let mut expected = vec![
        "db-backup/single-chunk/0".to_owned(),
        "db-backup/single-chunk/1".to_owned(),
        "db-backup/three-chunk/0".to_owned(),
    ];
    expected.extend(
        (0..reject_mutations(1000, 2 * CHUNK_LEN + 1000).len())
            .map(|i| format!("db-backup/reject/{i}")),
    );
    assert_eq!(ids, expected);
    let recomputed = compute(vectors);
    for (got, want) in recomputed.iter().zip(vectors) {
        assert_eq!(got, want, "{}", want["id"]);
    }
    // The reject vectors hold the errors ADR 0071 and CRYPTO.md §9.8 call for; spot checks.
    let error = |i: usize| vectors[3 + i]["outputs"]["error"].clone();
    assert_eq!(
        error(3),
        json!({"kind": "authentication", "chunk_index": 0}),
        "reorder"
    );
    assert_eq!(
        error(4),
        json!({"kind": "authentication", "chunk_index": 0}),
        "truncation"
    );
    assert_eq!(
        error(5),
        json!({"kind": "authentication", "chunk_index": 0}),
        "chunk swap"
    );
    assert_eq!(
        error(8),
        json!({"kind": "unknown_backup_key", "backup_key_id": 9})
    );
    assert_eq!(
        error(15),
        json!({"kind": "authentication", "chunk_index": 2}),
        "final chunk"
    );
    // plaintext_len is in no AAD: its edit is refused by the framing, not a commitment.
    assert_eq!(error(10)["kind"], "malformed");
}
