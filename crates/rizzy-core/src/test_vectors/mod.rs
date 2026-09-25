//! Known-answer vector files (CRYPTO.md §15 item 1): generation and byte-for-byte replay.
//!
//! The files live in `crates/rizzy-core/tests/vectors/` and follow `schema.json` there; its
//! `README.md` says how they are made and what changing one takes. In short:
//!
//! - **Generation** ([`generate`], ignored by default) draws every input from a seeded
//!   `ChaCha20Rng` (`chacha20` =0.10.2, ADR 0009), computes the outputs through this crate's
//!   own API, and writes one JSON file per group. Random values an operation draws internally
//!   (the 24-byte envelope nonce, HPKE's ephemeral key material) are drawn first and stored as
//!   explicit inputs, then fed back through [`ExactRng`], which yields exactly those bytes and
//!   fails the test if the operation asks for more or fewer. No function takes a nonce, in test
//!   builds either (INV-12).
//! - **Replay** (one test per file) reads the committed file, recomputes every vector's
//!   outputs from its inputs with the same code, and compares them with the committed outputs.
//!   Any change in behaviour fails here. The computation also runs the checks that tie an
//!   output to the specification: every envelope opens again, every statement verifies,
//!   every formatted code parses back, and outputs the API hides (the commitment, the signed
//!   message) are rebuilt from the CRYPTO.md formula and compared with the bytes the API made.
//!
//! Tier A files are normative format vectors; `transcript.json` is the tier B regression
//! transcript (signup, login, unlock) and is regenerated, with a note, when a pinned crate
//! changes.

mod derivations;
mod encodings;
mod envelopes;
mod statements;
mod transcript;

use chacha20::ChaCha20Rng;
use rand_core::{SeedableRng as _, TryCryptoRng, TryRng};
use serde_json::{Map, Value};

use crate::test_util::seeded_rng;

/// The `schema` value of every file.
const SCHEMA: &str = "rizzy-vault/test-vectors/v1";

/// The generator named in every file.
const GENERATOR: &str = "rand_core 0.10 ChaCha20Rng::seed_from_u64 (chacha20 =0.10.2)";

/// Recomputes a vector's outputs from its name and inputs.
type Compute = fn(&str, &Map<String, Value>) -> Map<String, Value>;

/// One vector file.
struct VectorFile {
    /// File name without `.json`.
    name: &'static str,
    /// `"A"` (normative format vectors) or `"B"` (transcript regression vectors).
    tier: &'static str,
    /// The CRYPTO.md sections the file covers.
    spec: &'static str,
    /// The `ChaCha20Rng` seed the generator draws the inputs from.
    seed: u64,
    /// The committed file.
    committed: &'static str,
    generate: fn(&mut ChaCha20Rng) -> Vec<Vector>,
    compute: Compute,
    /// Checks across the vectors of one file (a bundle chain, for example).
    check_file: fn(&[Vector]),
}

const FILES: [VectorFile; 5] = [
    VectorFile {
        name: "derivations",
        tier: "A",
        spec: "CRYPTO.md §4.3, §4.4, §5.2, §5.3, §5.9, §5.11, §10.1, §10.3, §11.14",
        seed: 0x0403,
        committed: include_str!("../../tests/vectors/derivations.json"),
        generate: derivations::generate,
        compute: derivations::compute,
        check_file: |_| {},
    },
    VectorFile {
        name: "envelopes",
        tier: "A",
        spec: "CRYPTO.md §8.3, §8.4, §8.5, §9.1, §9.2, §10.1",
        seed: 0x0804,
        committed: include_str!("../../tests/vectors/envelopes.json"),
        generate: envelopes::generate,
        compute: envelopes::compute,
        check_file: envelopes::check_file,
    },
    VectorFile {
        name: "statements",
        tier: "A",
        spec: "CRYPTO.md §5.10, §9.3, §9.6, §10.1, §10.2, §11.6",
        seed: 0x1002,
        committed: include_str!("../../tests/vectors/statements.json"),
        generate: statements::generate,
        compute: statements::compute,
        check_file: statements::check_file,
    },
    VectorFile {
        name: "encodings",
        tier: "A",
        spec: "CRYPTO.md §4.3 (check characters), §7, §8.5, §11.9",
        seed: 0x0007,
        committed: include_str!("../../tests/vectors/encodings.json"),
        generate: encodings::generate,
        compute: encodings::compute,
        check_file: |_| {},
    },
    VectorFile {
        name: "transcript",
        tier: "B",
        spec: "CRYPTO.md §5, §11.1, §11.2, §11.3, §15 item 1 (B)",
        seed: 0x000b,
        committed: include_str!("../../tests/vectors/transcript.json"),
        generate: transcript::generate,
        compute: transcript::compute,
        check_file: |_| {},
    },
];

/// One vector: `{id, kind, name, inputs, outputs}`.
#[derive(Clone, Debug, PartialEq)]
struct Vector {
    id: String,
    kind: String,
    name: String,
    inputs: Map<String, Value>,
    outputs: Map<String, Value>,
}

impl Vector {
    /// Builds a vector, computing its outputs from its inputs.
    fn build(compute: Compute, kind: &str, name: &str, index: usize, inputs: Obj) -> Self {
        let inputs = inputs.0;
        Self {
            id: format!("{kind}/{name}/{index}"),
            kind: kind.to_owned(),
            name: name.to_owned(),
            outputs: compute(name, &inputs),
            inputs,
        }
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(self.id.clone()));
        m.insert("kind".into(), Value::String(self.kind.clone()));
        m.insert("name".into(), Value::String(self.name.clone()));
        m.insert("inputs".into(), Value::Object(self.inputs.clone()));
        m.insert("outputs".into(), Value::Object(self.outputs.clone()));
        Value::Object(m)
    }

    fn from_value(v: &Value) -> Self {
        let field = |key: &str| {
            v.get(key)
                .unwrap_or_else(|| panic!("vector without `{key}`: {v}"))
        };
        let string = |key: &str| field(key).as_str().expect("a string field").to_owned();
        let object = |key: &str| field(key).as_object().expect("an object field").clone();
        let id = string("id");
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b)),
            "vector id {id:?}"
        );
        Self {
            kind: string("kind"),
            name: string("name"),
            inputs: object("inputs"),
            outputs: object("outputs"),
            id,
        }
    }
}

/// Builds the whole JSON document of one file.
fn build_file(file: &VectorFile) -> Value {
    let mut rng = seeded_rng(file.seed);
    let vectors = (file.generate)(&mut rng);
    (file.check_file)(&vectors);
    let mut doc = Map::new();
    doc.insert("schema".into(), SCHEMA.into());
    doc.insert("file".into(), file.name.into());
    doc.insert("tier".into(), file.tier.into());
    doc.insert("spec".into(), file.spec.into());
    doc.insert("generator".into(), GENERATOR.into());
    doc.insert("seed".into(), Value::String(file.seed.to_string()));
    doc.insert(
        "vectors".into(),
        Value::Array(vectors.iter().map(Vector::to_value).collect()),
    );
    Value::Object(doc)
}

/// Pretty JSON with a trailing newline: the committed form.
fn render(doc: &Value) -> String {
    let mut text = serde_json::to_string_pretty(doc).expect("JSON");
    text.push('\n');
    text
}

/// Replays one committed file.
fn replay(file: &VectorFile) {
    let doc: Value = serde_json::from_str(file.committed)
        .unwrap_or_else(|e| panic!("{}.json is not JSON: {e}", file.name));
    let header = |key: &str| doc.get(key).and_then(Value::as_str).unwrap_or_default();
    assert_eq!(header("schema"), SCHEMA, "{}.json", file.name);
    assert_eq!(header("file"), file.name);
    assert_eq!(header("tier"), file.tier);
    assert_eq!(header("spec"), file.spec);
    assert_eq!(header("generator"), GENERATOR);
    assert_eq!(header("seed"), file.seed.to_string());
    assert_eq!(
        render(&doc),
        file.committed,
        "{}.json is not in its canonical form (regenerate it, never edit it by hand)",
        file.name
    );
    let vectors: Vec<Vector> = doc
        .get("vectors")
        .and_then(Value::as_array)
        .expect("a `vectors` array")
        .iter()
        .map(Vector::from_value)
        .collect();
    assert!(!vectors.is_empty(), "{}.json has no vectors", file.name);
    let mut ids: Vec<&str> = vectors.iter().map(|v| v.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        vectors.len(),
        "duplicate vector ids in {}",
        file.name
    );
    for v in &vectors {
        assert_eq!(v.id.split('/').next(), Some(v.kind.as_str()), "{}", v.id);
        let outputs = (file.compute)(&v.name, &v.inputs);
        for (key, expected) in &v.outputs {
            assert_eq!(
                outputs.get(key),
                Some(expected),
                "{}.json, vector {}: output `{key}` changed",
                file.name,
                v.id
            );
        }
        assert_eq!(
            outputs.keys().collect::<Vec<_>>(),
            v.outputs.keys().collect::<Vec<_>>(),
            "{}.json, vector {}: the set of outputs changed",
            file.name,
            v.id
        );
    }
    (file.check_file)(&vectors);
}

fn file(name: &str) -> &'static VectorFile {
    FILES
        .iter()
        .find(|f| f.name == name)
        .expect("a listed file")
}

#[test]
fn replay_derivations() {
    replay(file("derivations"));
}

#[test]
fn replay_envelopes() {
    replay(file("envelopes"));
}

#[test]
fn replay_statements() {
    replay(file("statements"));
}

#[test]
fn replay_encodings() {
    replay(file("encodings"));
}

#[test]
fn replay_transcript() {
    replay(file("transcript"));
}

/// Rewrites every committed vector file from its seed. Run only in a change that is meant to
/// change a vector, which also bumps the format version and adds an ADR note (README.md):
///
/// ```text
/// cargo test -p rizzy-core --lib test_vectors::generate -- --ignored --exact
/// ```
///
/// The replay tests compare against the files as they were compiled, so a run that rewrites a
/// file also fails them until the next build: nothing changes silently.
#[test]
#[ignore = "rewrites tests/vectors/*.json; run only to change a vector on purpose (README.md)"]
fn generate() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    for file in &FILES {
        let path = dir.join(format!("{}.json", file.name));
        std::fs::write(&path, render(&build_file(file)))
            .unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    }
}

// ---------------------------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------------------------

/// An ordered JSON object under construction.
struct Obj(Map<String, Value>);

impl Obj {
    fn new() -> Self {
        Self(Map::new())
    }

    /// A byte string, as lowercase hex.
    fn bytes(mut self, key: &str, value: &[u8]) -> Self {
        self.0.insert(key.into(), Value::String(to_hex(value)));
        self
    }

    /// A list of byte strings.
    fn bytes_list(mut self, key: &str, values: &[Vec<u8>]) -> Self {
        let list = values.iter().map(|v| Value::String(to_hex(v))).collect();
        self.0.insert(key.into(), Value::Array(list));
        self
    }

    /// A UTF-8 text value.
    fn text(mut self, key: &str, value: &str) -> Self {
        self.0.insert(key.into(), Value::String(value.to_owned()));
        self
    }

    /// A `u8`, `u16` or `u32`, as a JSON number.
    fn num(mut self, key: &str, value: u32) -> Self {
        self.0.insert(key.into(), Value::from(value));
        self
    }

    /// A `u64`, as a decimal string (JSON numbers lose precision above 2^53 in JavaScript).
    fn u64(mut self, key: &str, value: u64) -> Self {
        self.0.insert(key.into(), Value::String(value.to_string()));
        self
    }

    fn bool(mut self, key: &str, value: bool) -> Self {
        self.0.insert(key.into(), Value::Bool(value));
        self
    }

    fn null(mut self, key: &str) -> Self {
        self.0.insert(key.into(), Value::Null);
        self
    }

    fn obj(mut self, key: &str, value: Self) -> Self {
        self.0.insert(key.into(), Value::Object(value.0));
        self
    }

    fn done(self) -> Map<String, Value> {
        self.0
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn field<'a>(m: &'a Map<String, Value>, key: &str) -> &'a Value {
    m.get(key)
        .unwrap_or_else(|| panic!("missing field `{key}` in {m:?}"))
}

/// A hex byte string.
fn bytes(m: &Map<String, Value>, key: &str) -> Vec<u8> {
    let text = field(m, key).as_str().expect("a hex string");
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "`{key}` is not lowercase hex"
    );
    crate::test_util::hex(text)
}

/// A hex byte string of exactly `N` bytes.
fn arr<const N: usize>(m: &Map<String, Value>, key: &str) -> [u8; N] {
    bytes(m, key)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("`{key}` has {} bytes, expected {N}", v.len()))
}

/// A hex byte string, or `null`.
fn opt_bytes(m: &Map<String, Value>, key: &str) -> Option<Vec<u8>> {
    (!field(m, key).is_null()).then(|| bytes(m, key))
}

/// A list of hex byte strings.
fn bytes_list(m: &Map<String, Value>, key: &str) -> Vec<Vec<u8>> {
    field(m, key)
        .as_array()
        .expect("an array")
        .iter()
        .map(|v| crate::test_util::hex(v.as_str().expect("hex strings")))
        .collect()
}

fn text<'a>(m: &'a Map<String, Value>, key: &str) -> &'a str {
    field(m, key).as_str().expect("a text field")
}

/// A JSON number that fits `T`.
fn num<T: TryFrom<u64>>(m: &Map<String, Value>, key: &str) -> T {
    let n = field(m, key).as_u64().expect("a JSON number");
    T::try_from(n).unwrap_or_else(|_| panic!("`{key}` = {n} out of range"))
}

/// A `u64` written as a decimal string.
fn u64_of(m: &Map<String, Value>, key: &str) -> u64 {
    text(m, key).parse().expect("a decimal u64 string")
}

fn boolean(m: &Map<String, Value>, key: &str) -> bool {
    field(m, key).as_bool().expect("a boolean")
}

fn object<'a>(m: &'a Map<String, Value>, key: &str) -> &'a Map<String, Value> {
    field(m, key).as_object().expect("an object")
}

/// `N` bytes from the generator's RNG.
fn random<const N: usize>(rng: &mut ChaCha20Rng) -> [u8; N] {
    let mut out = [0u8; N];
    rand_core::Rng::fill_bytes(rng, &mut out);
    out
}

/// `len` bytes from the generator's RNG.
fn random_vec(rng: &mut ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand_core::Rng::fill_bytes(rng, &mut out);
    out
}

/// A `u32` below `bound` from the generator's RNG (a small epoch or counter).
fn small(rng: &mut ChaCha20Rng, bound: u32) -> u32 {
    rand_core::Rng::next_u32(rng) % bound
}

/// A fresh generator for a nested use, derived from the parent stream.
fn child_rng(rng: &mut ChaCha20Rng) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(rand_core::Rng::next_u64(rng))
}

// ---------------------------------------------------------------------------------------------
// The exact RNG
// ---------------------------------------------------------------------------------------------

/// An RNG that yields exactly the given bytes, in order. Drawing past the end panics, and
/// [`ExactRng::finish`] asserts that every byte was drawn, so a vector pins exactly the random
/// input an operation consumes. `next_u32` and `next_u64` read little-endian.
#[derive(Debug)]
struct ExactRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl ExactRng {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }

    #[track_caller]
    fn finish(self) {
        assert_eq!(
            self.pos,
            self.bytes.len(),
            "the operation drew {} of the {} random bytes the vector provides",
            self.pos,
            self.bytes.len()
        );
    }

    fn take(&mut self, dst: &mut [u8]) {
        let end = self.pos + dst.len();
        let src = self.bytes.get(self.pos..end).unwrap_or_else(|| {
            panic!(
                "the operation drew more random bytes than the {} the vector provides",
                self.bytes.len()
            )
        });
        dst.copy_from_slice(src);
        self.pos = end;
    }
}

impl TryRng for ExactRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.take(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.take(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.take(dst);
        Ok(())
    }
}

impl TryCryptoRng for ExactRng {}

#[test]
fn exact_rng_yields_exactly_its_bytes() {
    let mut rng = ExactRng::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    assert_eq!(rand_core::Rng::next_u32(&mut rng), 0x0403_0201);
    assert_eq!(rand_core::Rng::next_u64(&mut rng), 0x0c0b_0a09_0807_0605);
    let mut two = [0u8; 2];
    rand_core::Rng::fill_bytes(&mut rng, &mut two);
    assert_eq!(two, [13, 14]);
    rng.finish();
    let short = std::panic::catch_unwind(|| {
        let mut rng = ExactRng::new(&[1]);
        rand_core::Rng::next_u32(&mut rng)
    });
    assert!(short.is_err());
    let unused = std::panic::catch_unwind(|| ExactRng::new(&[1]).finish());
    assert!(unused.is_err());
}

/// The committed inputs really come from the documented seeds: regenerating a file from its
/// seed reproduces it byte for byte. Checked on the files that run no Argon2id; the replay
/// tests cover the other two.
#[test]
fn files_regenerate_identically_from_their_seeds() {
    for name in ["envelopes", "statements", "encodings"] {
        let f = file(name);
        assert_eq!(render(&build_file(f)), f.committed, "{name}.json");
    }
}
