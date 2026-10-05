//! Fuzzes `rv`'s private CA file reader (`rizzy_cli::tls::parse_ca_pem`; ADR 0030 Decision 4).
//! The file is named by the user, but a damaged or hostile one must be refused without a
//! panic, before any connection.
//!
//! For each input, the parser must not panic. An accepted file holds between one and
//! `MAX_CA_CERTIFICATES` trust anchors and is at most `MAX_CA_FILE_LEN` bytes; a refused one is
//! `CliError::BadInput`. The input is also tried wrapped in one `CERTIFICATE` block (as base64),
//! so the `basicConstraints` walk and the trust-anchor step see arbitrary DER, not only what
//! survives the PEM layer.
//!
//! ```text
//! cargo +nightly fuzz run ca_pem
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_cli::CliError;
use rizzy_cli::tls::{MAX_CA_CERTIFICATES, MAX_CA_FILE_LEN, parse_ca_pem};

/// Checks one outcome of the parser (the number of trust anchors) on `len` input bytes.
fn check(len: usize, outcome: Result<usize, CliError>) {
    match outcome {
        Ok(anchors) => {
            assert!(len <= MAX_CA_FILE_LEN);
            assert!((1..=MAX_CA_CERTIFICATES).contains(&anchors));
        }
        Err(e) => assert!(matches!(e, CliError::BadInput(_)), "{e:?}"),
    }
}

/// Standard base64 with padding, wrapped at 64 columns, as PEM writes it.
fn base64_lines(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in der.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    let mut wrapped = String::new();
    for (i, c) in out.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            wrapped.push('\n');
        }
        wrapped.push(c);
    }
    wrapped
}

fuzz_target!(|data: &[u8]| {
    check(data.len(), parse_ca_pem(data).map(|roots| roots.len()));
    let wrapped = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_lines(data)
    );
    check(
        wrapped.len(),
        parse_ca_pem(wrapped.as_bytes()).map(|roots| roots.len()),
    );
});
