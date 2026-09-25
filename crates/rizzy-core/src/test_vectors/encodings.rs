//! `encodings.json`: the Secret Key and recovery-code format (CRYPTO.md §7, §4.3 check
//! characters, §11.9) and Padmé framing (§8.5), with accepted and rejected inputs.

use chacha20::ChaCha20Rng;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

use super::{Obj, Vector, bytes, random, random_vec, text, u64_of};
use crate::labels::{self, Label};
use crate::padding;
use crate::secret_key::{RecoveryCode, SecretKey};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The two code kinds: vector name, prefix, check label.
const KINDS: [(&str, &str, Label); 2] = [
    ("secret-key", "RV1-", labels::SECRET_KEY_CHECK),
    ("recovery-code", "RVR1-", labels::RECOVERY_CODE_CHECK),
];

fn kind_of(name: &str) -> (&'static str, &'static str, Label) {
    let base = name.split('/').next().unwrap_or(name);
    KINDS
        .into_iter()
        .find(|(n, _, _)| *n == base)
        .unwrap_or_else(|| panic!("no code kind {name}"))
}

fn vector(kind: &str, name: &str, index: usize, inputs: Obj) -> Vector {
    Vector::build(compute, kind, name, index, inputs)
}

/// Formats a code through the API (`SecretKey` or `RecoveryCode`).
fn format_code(name: &str, code: &[u8]) -> String {
    match kind_of(name).0 {
        "secret-key" => SecretKey::from_slice(code)
            .expect("16 bytes")
            .to_formatted()
            .to_string(),
        _ => RecoveryCode::from_slice(code)
            .expect("16 bytes")
            .to_formatted()
            .to_string(),
    }
}

/// Parses a typed code through the API.
fn parse_code(name: &str, typed: &str) -> Option<[u8; 16]> {
    match kind_of(name).0 {
        "secret-key" => SecretKey::parse(typed).ok().map(|k| *k.expose_secret()),
        _ => RecoveryCode::parse(typed).ok().map(|k| *k.expose_secret()),
    }
}

/// A typo: the symbol at `index` of the 28 replaced by the next alphabet symbol.
fn with_symbol(formatted: &str, prefix: &str, index: usize, f: impl Fn(u8) -> u8) -> String {
    let body: Vec<u8> = formatted
        .strip_prefix(prefix)
        .expect("prefix")
        .bytes()
        .filter(|b| *b != b'-')
        .collect();
    let mut body = body;
    let v = ALPHABET
        .iter()
        .position(|a| *a == body[index])
        .expect("a symbol");
    body[index] = ALPHABET[usize::from(f(u8::try_from(v).expect("< 32"))) % 32];
    let groups: Vec<String> = body
        .chunks(4)
        .map(|c| String::from_utf8(c.to_vec()).expect("ASCII"))
        .collect();
    format!("{prefix}{}", groups.join("-"))
}

pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    let mut out = Vec::new();
    for (name, prefix, _) in KINDS {
        let codes: Vec<[u8; 16]> = (0..3).map(|_| random::<16>(rng)).collect();
        for (i, code) in codes.iter().enumerate() {
            out.push(vector("encoding", name, i, Obj::new().bytes("code", code)));
        }
        // Lenient parsing (§7): case, O → 0, I/L → 1, spaces and dashes ignored.
        let formatted = format_code(name, &codes[0]);
        let lenient = [
            formatted.to_lowercase().replace('-', " "),
            formatted
                .replace('0', "O")
                .replace('1', "l")
                .replace('-', ""),
            format!("  {}  ", formatted.replace('-', " - ")),
        ];
        for (i, typed) in lenient.iter().enumerate() {
            out.push(vector(
                "encoding",
                &format!("{name}/parse"),
                i,
                Obj::new().text("typed", typed),
            ));
        }
        // Rejected (§7): a typo the check value catches, non-zero pad bits, the other prefix.
        let typo = (1..32)
            .map(|d| with_symbol(&formatted, prefix, 7, |v| v + d))
            .find(|t| parse_code(name, t).is_none())
            .expect("the check catches some typo");
        let pad = with_symbol(&formatted, prefix, 25, |v| v ^ 0b01);
        let other_prefix = if prefix == "RV1-" {
            formatted.replacen("RV1-", "RVR1-", 1)
        } else {
            formatted.replacen("RVR1-", "RV1-", 1)
        };
        for (i, typed) in [typo, pad, other_prefix].iter().enumerate() {
            out.push(vector(
                "encoding",
                &format!("{name}/reject"),
                i,
                Obj::new().text("typed", typed),
            ));
        }
    }

    for (i, len) in [
        2u64,
        3,
        9,
        17,
        100,
        255,
        256,
        257,
        260,
        1000,
        1025,
        65_535,
        (1 << 20) + 1,
        16 * 1024 * 1024 - 1,
        u64::from(u32::MAX) + 1,
    ]
    .into_iter()
    .enumerate()
    {
        out.push(vector("padding", "padme", i, Obj::new().u64("length", len)));
    }
    for (i, len) in [0usize, 1, 17, 252, 253, 300, 1000].into_iter().enumerate() {
        out.push(vector(
            "padding",
            "frame",
            i,
            Obj::new().bytes("data", &random_vec(rng, len)),
        ));
    }
    // Rejected frames (§8.5): data_len past the end, non-zero padding, a non-canonical length.
    let good = padding::frame(b"abc")
        .expect("frame")
        .expose_secret()
        .to_vec();
    let mut too_long = good.clone();
    too_long[3] = 0xff;
    let mut dirty = good.clone();
    dirty[200] = 1;
    let mut short = good;
    short.truncate(255);
    for (i, frame) in [too_long, dirty, short].iter().enumerate() {
        out.push(vector(
            "padding",
            "frame/reject",
            i,
            Obj::new().bytes("frame", frame),
        ));
    }
    out
}

/// The 10-bit check value from the §4.3 formula: the top 10 bits of
/// `SHA-256(LABEL(check) ‖ 0x00 ‖ code)`.
fn check_value(label: Label, code: &[u8]) -> u16 {
    let digest = Sha256::new()
        .chain_update(label.as_bytes())
        .chain_update([0x00])
        .chain_update(code)
        .finalize();
    (u16::from(digest[0]) << 2) | u16::from(digest[1] >> 6)
}

/// Decodes the 28 symbols of a formatted code independently of the API: 128 code bits, 2 pad
/// bits, 10 check bits, MSB first.
fn decode(formatted: &str, prefix: &str) -> ([u8; 16], u8, u16) {
    let values: Vec<u64> = formatted
        .strip_prefix(prefix)
        .expect("prefix")
        .split('-')
        .inspect(|g| assert_eq!(g.len(), 4, "groups of four"))
        .flat_map(str::bytes)
        .map(|b| {
            let v = ALPHABET.iter().position(|a| *a == b).expect("a symbol");
            u64::try_from(v).expect("< 32")
        })
        .collect();
    assert_eq!(values.len(), 28);
    let mut bits: Vec<u8> = Vec::with_capacity(140);
    for v in &values {
        for shift in (0..5).rev() {
            bits.push(u8::try_from((v >> shift) & 1).expect("a bit"));
        }
    }
    let take = |range: core::ops::Range<usize>| {
        bits[range]
            .iter()
            .fold(0u64, |acc, b| (acc << 1) | u64::from(*b))
    };
    let mut code = [0u8; 16];
    for (i, byte) in code.iter_mut().enumerate() {
        *byte = u8::try_from(take(i * 8..i * 8 + 8)).expect("a byte");
    }
    let pad = u8::try_from(take(128..130)).expect("2 bits");
    let check = u16::try_from(take(130..140)).expect("10 bits");
    (code, pad, check)
}

pub(super) fn compute(name: &str, m: &Map<String, Value>) -> Map<String, Value> {
    match name {
        "secret-key" | "recovery-code" => {
            let (_, prefix, label) = kind_of(name);
            let code = bytes(m, "code");
            let formatted = format_code(name, &code);
            let (decoded, pad, check) = decode(&formatted, prefix);
            assert_eq!(decoded.as_slice(), code.as_slice());
            assert_eq!(pad, 0);
            assert_eq!(check, check_value(label, &code));
            assert_eq!(parse_code(name, &formatted), Some(decoded));
            // The Emergency Kit confirmation re-types the last group (§7).
            let last = formatted.rsplit('-').next().expect("a group");
            let ok = match name {
                "secret-key" => SecretKey::from_slice(&code)
                    .expect("16 bytes")
                    .matches_last_group(last),
                _ => RecoveryCode::from_slice(&code)
                    .expect("16 bytes")
                    .matches_last_group(last),
            };
            assert!(ok);
            Obj::new()
                .text("formatted", &formatted)
                .num("check_value", u32::from(check))
                .done()
        }
        "secret-key/parse" | "recovery-code/parse" => {
            let code = parse_code(name, text(m, "typed")).expect("accepted");
            Obj::new().bytes("code", &code).done()
        }
        "secret-key/reject" | "recovery-code/reject" => {
            assert!(
                parse_code(name, text(m, "typed")).is_none(),
                "must be rejected"
            );
            Obj::new().bool("accepted", false).done()
        }
        "padme" => {
            let len = u64_of(m, "length");
            let padded = padding::padme(len).expect("no overflow");
            // At most 12 % overhead above 2^8 (§8.5, PURBs).
            assert!(len < 256 || (padded - len) * 100 <= len * 12);
            Obj::new().u64("padme", padded).done()
        }
        "frame" => {
            let data = bytes(m, "data");
            let frame = padding::frame(&data).expect("frame");
            let frame = frame.expose_secret();
            assert_eq!(padding::unframe(frame).expect("unframe"), data.as_slice());
            // u32(data_len) ‖ data ‖ zeros up to max(256, Padmé(4 + data_len)).
            let data_len = u32::try_from(data.len()).expect("small");
            let padded = padding::padme(4 + u64::from(data_len))
                .map(|p| p.max(256))
                .expect("padme");
            assert_eq!(u64::try_from(frame.len()).expect("small"), padded);
            assert_eq!(frame.get(..4), Some(&data_len.to_be_bytes()[..]));
            Obj::new()
                .num("padded_len", u32::try_from(frame.len()).expect("small"))
                .bytes("frame", frame)
                .done()
        }
        "frame/reject" => {
            assert!(
                padding::unframe(&bytes(m, "frame")).is_err(),
                "must be rejected"
            );
            Obj::new().bool("accepted", false).done()
        }
        other => panic!("unknown encoding vector {other}"),
    }
}
