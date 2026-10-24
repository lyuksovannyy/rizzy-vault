// SPDX-License-Identifier: AGPL-3.0-only

//! `breach.json`: the breach-check digest, prefix and suffix match (CRYPTO.md §11.16;
//! ADR 0053 item 1).
//!
//! `digest` vectors hold a candidate password and its uppercase hex SHA-1 digest of
//! `UTF-8(NFC(password))`, split into the 5-character prefix the client sends and the
//! 35-character suffix it keeps. Fixtures with published answers (the empty string and "abc"
//! from FIPS 180, "password" from HIBP's documentation), the two NFC forms of one string, and
//! passwords drawn from the seeded RNG. `match` vectors hold a password and a range body in
//! the upstream's `SUFFIX:COUNT` CRLF format, and the count of the matching entry (`0` for
//! none, or for a padded entry).

use core::fmt::Write as _;

use chacha20::ChaCha20Rng;
use serde_json::{Map, Value};
use sha1::{Digest as _, Sha1};
use unicode_normalization::UnicodeNormalization as _;

use super::{Obj, Vector, random_vec, text, u64_of};
use crate::breach::{BreachDigest, PREFIX_LEN};

/// Builds vector `breach/<name>/<index>`.
fn vector(name: &str, index: usize, inputs: Obj) -> Vector {
    Vector::build(compute, "breach", name, index, inputs)
}

/// A printable-ASCII password of `len` characters from the generator's RNG.
fn random_password(rng: &mut ChaCha20Rng, len: usize) -> String {
    random_vec(rng, len)
        .into_iter()
        .map(|b| char::from(b'!' + b % 94))
        .collect()
}

/// The fixtures and the drawn passwords, then the range matches.
pub(super) fn generate(rng: &mut ChaCha20Rng) -> Vec<Vector> {
    let mut passwords: Vec<String> = [
        "",
        "abc",
        "password",
        // One string in its composed and decomposed NFC forms: one digest.
        "caf\u{e9} cr\u{e8}me",
        "cafe\u{301} cre\u{300}me",
        // Not trimmed, not case-folded.
        " password ",
        "PASSWORD",
        // A non-Latin script and a character outside the BMP.
        "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c} \u{1f511}",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    passwords.push(random_password(rng, 20));
    passwords.push(random_password(rng, 64));
    let mut out: Vec<Vector> = passwords
        .iter()
        .enumerate()
        .map(|(i, p)| vector("digest", i, Obj::new().text("password", p)))
        .collect();

    // Range bodies around the suffix of "password" (5BAA6 / 1E4C9B93F3F0682250B6CF8331B7EE68FD8).
    let hit = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
    let near = "1E4C9B93F3F0682250B6CF8331B7EE68FD9";
    let other = "0018A45C4D1DEF81644B54AB7F969B88D65";
    let ranges = [
        // A hit in the middle, a miss, a hit as the last line without a line ending, a padded
        // entry (count 0) for the suffix, an empty body, and the one-off neighbour only.
        format!("{other}:1\r\n{hit}:52256179\r\n{near}:3"),
        format!("{other}:1\r\n{near}:3\r\n"),
        format!("{other}:1\r\n{near}:3\r\n{hit}:7"),
        format!("{other}:1\r\n{hit}:0"),
        String::new(),
        format!("{near}:3"),
    ];
    for (i, range) in ranges.iter().enumerate() {
        out.push(vector(
            "match",
            i,
            Obj::new().text("password", "password").text("range", range),
        ));
    }
    out
}

/// The digest of the `password` input through the crate's API, as text.
fn digest_of(inputs: &Map<String, Value>) -> String {
    let digest = BreachDigest::of_password(text(inputs, "password")).expect("a digest");
    String::from_utf8(digest.expose_secret().to_vec()).expect("ASCII hex")
}

/// Recomputes one vector. `digest` also checks the API against an independent computation:
/// NFC by `unicode-normalization` directly, SHA-1 by `sha1` directly, hex by `format!`.
pub(super) fn compute(name: &str, inputs: &Map<String, Value>) -> Map<String, Value> {
    match name {
        "digest" => {
            let password = text(inputs, "password");
            let hex = digest_of(inputs);
            let nfc: String = password.nfc().collect();
            let independent =
                Sha1::digest(nfc.as_bytes())
                    .iter()
                    .fold(String::new(), |mut acc, b| {
                        let _infallible = write!(acc, "{b:02X}");
                        acc
                    });
            assert_eq!(hex, independent, "the digest of {password:?}");
            let digest = BreachDigest::of_password(password).expect("a digest");
            assert_eq!(&digest.prefix()[..], &hex.as_bytes()[..PREFIX_LEN]);
            Obj::new()
                .text("digest", &hex)
                .text("prefix", &hex[..PREFIX_LEN])
                .text("suffix", &hex[PREFIX_LEN..])
                .0
        }
        "match" => {
            let digest = BreachDigest::of_password(text(inputs, "password")).expect("a digest");
            // The upstream format, read the simple way: CRLF lines of `SUFFIX:COUNT`.
            let entries: Vec<(&[u8], u64)> = text(inputs, "range")
                .split("\r\n")
                .filter(|line| !line.is_empty())
                .map(|line| {
                    let (suffix, count) = line.split_once(':').expect("SUFFIX:COUNT");
                    (suffix.as_bytes(), count.parse().expect("a count"))
                })
                .collect();
            let count = digest.count_in(entries);
            let out = Obj::new().u64("count", count).0;
            assert_eq!(u64_of(&out, "count"), count);
            out
        }
        other => panic!("no breach vector {other}"),
    }
}
