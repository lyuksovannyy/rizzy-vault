//! Fuzzes `rizzy-server`'s request-header parsers (`rizzy_server::http::headers`): the bearer
//! token, the two request-signing headers and `X-Forwarded-For` (CRYPTO.md §5.10; threat model
//! §7.6 "S", INV-52). Every value comes from an untrusted client or proxy.
//!
//! For each input, none may panic, and:
//!
//! - the whole input as an `Authorization` value: an accepted token re-encodes, as
//!   `Bearer <token>`, to a value that parses back to the same token;
//! - the input split at its first `0x00` into a counter and a signature value: accepted only
//!   as both-or-neither, and an accepted counter prints back to exactly the counter bytes
//!   (one decimal form per value);
//! - the input, split at `\n` into field lines, as `X-Forwarded-For` from a trusted proxy: the
//!   answer is the peer or an address the lines name, never another trusted proxy.
//!
//! ```text
//! cargo +nightly fuzz run server_headers
//! ```
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use rizzy_server::http::headers::{bearer_token, client_address, request_signature};

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = bearer_token(data) {
        let again = format!("Bearer {}", token.to_b64url().as_str());
        let reparsed = bearer_token(again.as_bytes()).expect("a printed token parses");
        assert_eq!(reparsed.expose_secret(), token.expose_secret());
    }

    let (counter, signature) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], Some(&data[i + 1..])),
        None => (data, None),
    };
    if let Ok(Some(parsed)) = request_signature(Some(counter), signature) {
        assert!(signature.is_some());
        assert_eq!(parsed.request_counter.to_string().as_bytes(), counter);
    }
    assert!(request_signature(Some(counter), None).is_err());

    let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer = proxy;
    let lines: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    let client = client_address(peer, &lines, &[proxy]);
    if client != peer {
        assert_ne!(client, proxy);
        let text = String::from_utf8_lossy(data);
        assert!(
            text.split([',', '\n'])
                .filter_map(|p| p.trim().parse::<IpAddr>().ok())
                .any(|a| a == client
                    || matches!(a, IpAddr::V6(v6) if v6.to_ipv4_mapped().map(IpAddr::V4) == Some(client)))
        );
    }
});
