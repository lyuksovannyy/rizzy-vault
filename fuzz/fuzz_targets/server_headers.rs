//! Fuzzes `rizzy-server`'s request-header parsers (`rizzy_server::http::headers`): the bearer
//! token, the two request-signing headers, `Content-Length`, `Rizzy-Client` and
//! `X-Forwarded-For` (ADR 0028 items 4, 5, 7, 11 and 14; CRYPTO.md §5.10; threat model §7.6
//! "S", INV-52). Every value comes from an untrusted client or proxy.
//!
//! For each input, none may panic, and:
//!
//! - the whole input as an `Authorization` value: an accepted token re-encodes, as
//!   `Bearer <token>`, to a value that parses back to the same token;
//! - the input split at its first `0x00` into a counter and a signature value: accepted only
//!   as both-or-neither, and an accepted counter prints back to exactly the counter bytes
//!   (one decimal form per value);
//! - the whole input as a `Content-Length`: an accepted value is ASCII digits only and is the
//!   number they spell;
//! - the whole input as a `Rizzy-Client`: an accepted value prints back to exactly the input
//!   and names one of ADR 0028's platforms; with no minimum nobody is refused, and a refused
//!   header is always a well-formed one;
//! - the input, split at `\n` into field lines, as `X-Forwarded-For`. From a peer that is not
//!   a trusted proxy the answer is the peer, whatever the lines hold. From a trusted proxy the
//!   answer is an address the lines name, never a trusted proxy, or a refusal; it is never the
//!   proxy's own address (ADR 0028 item 11), and client-controlled lines prepended on the left
//!   never change it.
//!
//! ```text
//! cargo +nightly fuzz run server_headers
//! ```
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use rizzy_proto::meta::{MinClientVersion, PLATFORMS, Platform, Version};
use rizzy_server::http::headers::{
    bearer_token, client_address, client_header, client_refused, content_length, request_signature,
};

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

    if let Ok(length) = content_length(data) {
        assert!(!data.is_empty() && data.iter().all(u8::is_ascii_digit));
        let digits = core::str::from_utf8(data).expect("ASCII digits");
        assert_eq!(
            digits.trim_start_matches('0').parse::<u64>().unwrap_or(0),
            length
        );
    }

    let minimums = [MinClientVersion {
        platform: Platform::from_str("cli").expect("a platform"),
        version: Version::from_str("1.0.0").expect("a version"),
    }];
    let parsed = client_header(data);
    if let Ok(header) = &parsed {
        assert_eq!(header.to_string().as_bytes(), data);
        assert!(PLATFORMS.contains(&header.platform.as_str()));
    }
    assert!(!client_refused(Some(data), &[]));
    if client_refused(Some(data), &minimums) {
        assert!(parsed.is_ok_and(|header| header.platform.as_str() == "cli"));
    }

    let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let outsider = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let lines: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    assert_eq!(client_address(outsider, &lines, &[proxy]), Ok(outsider));
    let answer = client_address(proxy, &lines, &[proxy]);
    if let Ok(client) = answer {
        assert_ne!(client, proxy);
        let text = String::from_utf8_lossy(data);
        assert!(
            text.split([',', '\n'])
                .filter_map(|p| p.trim_matches([' ', '\t']).parse::<IpAddr>().ok())
                .any(|a| a == client
                    || matches!(a, IpAddr::V6(v6) if v6.to_ipv4_mapped().map(IpAddr::V4) == Some(client)))
        );
        // What a client prepends on the left is never read.
        let mut longer: Vec<&[u8]> = vec![b"203.0.113.77, garbage"];
        longer.extend_from_slice(&lines);
        assert_eq!(client_address(proxy, &longer, &[proxy]), Ok(client));
    }
});
