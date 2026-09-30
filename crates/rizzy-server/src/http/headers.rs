//! Parsers for the request headers the `api` role reads: the bearer token, the two
//! request-signing values, `Content-Length`, `Rizzy-Client` and `X-Forwarded-For` ([ADR 0028]
//! items 4, 5, 7, 11 and 14; CRYPTO.md §5.10; threat model §7.6 "S", INV-52).
//!
//! - **Bearer token** (item 4): `Authorization: Bearer <token>`, the token as the 43 base64url
//!   characters of its 32 bytes (CRYPTO.md §9.6). The scheme name is matched
//!   case-insensitively; nothing else is accepted, and the token is never read from a URL or a
//!   cookie (INV-52).
//! - **Request signing** (item 5): [`REQUEST_COUNTER_HEADER`] carries the `request_counter` in
//!   decimal ASCII, 1–20 digits within `u64`, no sign, no leading zero (`0` alone is valid);
//!   [`REQUEST_SIGNATURE_HEADER`] carries the 82-byte `device-request` signature container as
//!   110 base64url characters. Both or neither.
//! - **`Content-Length`** (item 7): decimal digits within `u64`, nothing else.
//! - **`Rizzy-Client`** (item 14): `<platform>/<version>`, the platform one of the eight ADR
//!   0028 names. A missing or malformed header is served normally until v1.0
//!   ([`client_refused`]).
//! - **`X-Forwarded-For`** (item 11): read only from a configured proxy, from the right, within
//!   bounds; when it does not give a client address the request is refused, never attributed to
//!   the proxy ([`client_address`]).
//!
//! The header names and the lengths come from `rizzy-proto` (through the auth domain's `types`
//! module), which clients share. Every parser here is bounded (it checks a value's length
//! before decoding it), never panics, and returns an error that names no value. They are fuzzed
//! by the `server_headers` target.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md

use std::net::IpAddr;

use rizzy_domain_auth::types::RequestSignature;
use rizzy_domain_auth::types::SIGNATURE_CONTAINER_LEN;
use rizzy_domain_auth::types::{
    BEARER_SCHEME, BEARER_TOKEN_CHARS, ClientHeader, Fixed, MAX_REQUEST_COUNTER_DIGITS,
    MinClientVersion, REQUEST_SIGNATURE_CHARS, SessionToken, client_too_old,
};
pub use rizzy_domain_auth::types::{
    CLIENT_HEADER, REQUEST_COUNTER_HEADER, REQUEST_SIGNATURE_HEADER,
};

/// The length of the one `Authorization` value accepted: the scheme, one space, the token.
const AUTHORIZATION_LEN: usize = BEARER_SCHEME.len() + 1 + BEARER_TOKEN_CHARS;

/// How many bytes of `X-Forwarded-For` are read, counted from the right end of the last field
/// line over all lines: room for a chain of proxies, each at most an IPv6 address.
pub const MAX_FORWARDED_FOR_LEN: usize = 1024;

/// The most `X-Forwarded-For` field lines read, counted from the last ([`client_address`]).
pub const MAX_FORWARDED_FOR_LINES: usize = 16;

/// The longest text of one address: an IPv6 address with an embedded dotted quad.
const MAX_ADDRESS_LEN: usize = 45;

/// A header value that could not be used. Carries nothing of the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadHeader;

/// Parses an `Authorization` value into the bearer token (module docs).
///
/// # Errors
/// [`BadHeader`] for any other scheme, form or length.
pub fn bearer_token(value: &[u8]) -> Result<SessionToken, BadHeader> {
    if value.len() != AUTHORIZATION_LEN {
        return Err(BadHeader);
    }
    let text = core::str::from_utf8(value).map_err(|_| BadHeader)?;
    let (scheme, token) = text.split_once(' ').ok_or(BadHeader)?;
    if !scheme.eq_ignore_ascii_case(BEARER_SCHEME) || token.len() != BEARER_TOKEN_CHARS {
        return Err(BadHeader);
    }
    SessionToken::from_b64url(token).map_err(|_| BadHeader)
}

/// Parses the two request-signing headers (module docs): `None` when both are absent.
///
/// # Errors
/// [`BadHeader`] when only one is present or either is malformed.
pub fn request_signature(
    counter: Option<&[u8]>,
    signature: Option<&[u8]>,
) -> Result<Option<RequestSignature>, BadHeader> {
    let (counter, signature) = match (counter, signature) {
        (None, None) => return Ok(None),
        (Some(c), Some(s)) => (c, s),
        _ => return Err(BadHeader),
    };
    Ok(Some(RequestSignature {
        request_counter: request_counter(counter)?,
        signature: container(signature)?,
    }))
}

/// ASCII decimal digits as a `u64`; an empty value, any other byte, or a value past `u64::MAX`
/// is refused.
fn decimal_u64(value: &[u8]) -> Result<u64, BadHeader> {
    if value.is_empty() {
        return Err(BadHeader);
    }
    let mut n: u64 = 0;
    for &b in value {
        if !b.is_ascii_digit() {
            return Err(BadHeader);
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))
            .ok_or(BadHeader)?;
    }
    Ok(n)
}

/// The `request_counter`: a `u64` in decimal, 1–20 ASCII digits, no leading zero except `0`
/// itself, so every value has one spelling.
fn request_counter(value: &[u8]) -> Result<u64, BadHeader> {
    if value.len() > MAX_REQUEST_COUNTER_DIGITS || (value.len() > 1 && value.first() == Some(&b'0'))
    {
        return Err(BadHeader);
    }
    decimal_u64(value)
}

/// The signature container, base64url of exactly its 82 bytes.
fn container(value: &[u8]) -> Result<Fixed<SIGNATURE_CONTAINER_LEN>, BadHeader> {
    if value.len() != REQUEST_SIGNATURE_CHARS {
        return Err(BadHeader);
    }
    let text = core::str::from_utf8(value).map_err(|_| BadHeader)?;
    Fixed::from_b64url(text).map_err(|_| BadHeader)
}

/// Parses a `Content-Length` value ([ADR 0028] item 7: "a `Content-Length` that is not a
/// decimal `u64` is `400`"): ASCII digits only, within `u64`. No sign, no space and no list;
/// leading zeros are digits and are read.
///
/// # Errors
/// [`BadHeader`] for anything else.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub fn content_length(value: &[u8]) -> Result<u64, BadHeader> {
    decimal_u64(value)
}

/// Parses a `Rizzy-Client` value ([ADR 0028] item 14): `<platform>/<version>`, the platform one
/// of the eight ADR 0028 names, the version at most 64 bytes of `[0-9A-Za-z.+-]`.
///
/// # Errors
/// [`BadHeader`] for a value that is too long, not of that form, or names another platform.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub fn client_header(value: &[u8]) -> Result<ClientHeader, BadHeader> {
    if value.len() > ClientHeader::MAX_LEN {
        return Err(BadHeader);
    }
    let text = core::str::from_utf8(value).map_err(|_| BadHeader)?;
    let header = ClientHeader::parse(text).map_err(|_| BadHeader)?;
    if header.has_known_platform() {
        Ok(header)
    } else {
        Err(BadHeader)
    }
}

/// Whether a request with this `Rizzy-Client` header is answered `400 client_too_old` ([ADR
/// 0028] item 14): the header parses ([`client_header`]) and its platform has a minimum in
/// `minimums` above its version (`SemVer` 2.0.0 precedence; a version that is not `SemVer` counts
/// as below any minimum).
///
/// `value` is `None` when the request carries no such header, or more than one. A missing or
/// malformed header is **not** refused: it is served normally until v1.0 (owner decision on
/// open question 2), so that `curl` works. The header is compatibility signalling, not a
/// security boundary: nothing is granted on its strength.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
#[must_use]
pub fn client_refused(value: Option<&[u8]>, minimums: &[MinClientVersion]) -> bool {
    value
        .and_then(|v| client_header(v).ok())
        .is_some_and(|header| client_too_old(&header, minimums))
}

/// Bytes of optional whitespace (RFC 9110 §5.6.3: space and horizontal tab) removed from both
/// ends.
fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

/// One `X-Forwarded-For` element as an address: an IPv4 dotted quad or IPv6 text, optional
/// whitespace around it, nothing else (no port, no brackets, no `unknown`, no obfuscated node).
fn forwarded_element(element: &[u8]) -> Result<IpAddr, BadHeader> {
    let element = trim_ows(element);
    if element.len() > MAX_ADDRESS_LEN {
        return Err(BadHeader);
    }
    core::str::from_utf8(element)
        .ok()
        .and_then(|text| text.parse::<IpAddr>().ok())
        .ok_or(BadHeader)
}

/// The client's address for rate limiting ([ADR 0028] item 11; threat model §7.6 "S": "XFF
/// trusted only from configured proxies").
///
/// - **The peer is not a trusted proxy:** the peer's address; `X-Forwarded-For` is not read.
/// - **The peer is a trusted proxy:** the first address from the right of all
///   `X-Forwarded-For` field lines that is not a trusted proxy. `forwarded_for` holds every
///   field line of the request, in the order received (empty when there is none). RFC 9110
///   §5.3 makes repeated field lines one comma-joined list, and a proxy may append a line of
///   its own instead of extending the client's, so the lines are read as that one list, from
///   the last line's right end.
///
/// Only the right end is read: at most [`MAX_FORWARDED_FOR_LINES`] lines and
/// [`MAX_FORWARDED_FOR_LEN`] bytes (elements and the separators between them), counted from
/// the right. Whatever the client wrote left of the found address is never read, since any
/// client can prepend it, however long.
///
/// Matching is address equality, an IPv4-mapped IPv6 address read as the IPv4 address it names.
///
/// # Errors
/// [`BadHeader`] when the peer is a trusted proxy and the header gives no client address: it
/// is missing, or a malformed element, the read bound or the left end comes before an untrusted
/// address. The caller answers `400 invalid_request`. The request is never attributed to the
/// proxy's own address, whose rate-limit bucket every user behind it shares: a proxy that does
/// not set the header is a configuration error, and it fails closed.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
pub fn client_address(
    peer: IpAddr,
    forwarded_for: &[&[u8]],
    trusted: &[IpAddr],
) -> Result<IpAddr, BadHeader> {
    let is_trusted = |addr: IpAddr| trusted.iter().any(|t| canonical(*t) == addr);
    let peer = canonical(peer);
    if !is_trusted(peer) {
        return Ok(peer);
    }
    // Bytes read so far, from the right: every element, and one separator before each element
    // but the first.
    let mut read = 0usize;
    for (index, line) in forwarded_for.iter().rev().enumerate() {
        if index >= MAX_FORWARDED_FOR_LINES {
            return Err(BadHeader);
        }
        for element in line.rsplit(|&b| b == b',') {
            let separator = usize::from(read != 0 || index != 0);
            read = read.saturating_add(separator).saturating_add(element.len());
            if read > MAX_FORWARDED_FOR_LEN {
                return Err(BadHeader);
            }
            let addr = canonical(forwarded_element(element)?);
            if !is_trusted(addr) {
                return Ok(addr);
            }
        }
    }
    // No header at all, or only trusted proxies up to the left end.
    Err(BadHeader)
}

/// An IPv4-mapped IPv6 address as the IPv4 address it names; anything else unchanged.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// The rate-limit source of a client address ([ADR 0028] item 11): the 4 bytes of an IPv4
/// address, or the first 8 bytes (the /64 prefix) of an IPv6 address. One IPv6 subscriber
/// usually holds a whole /64, so counting per address would give an attacker 2^64 buckets.
///
/// [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
#[must_use]
pub fn rate_limit_source(addr: IpAddr) -> Vec<u8> {
    match canonical(addr) {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().iter().take(8).copied().collect(),
    }
}

#[cfg(test)]
mod tests {
    //! The header grammars and the forwarded-address rule.

    use std::net::{Ipv4Addr, Ipv6Addr};

    use rizzy_domain_auth::types::{Platform, Version};

    use super::*;

    #[test]
    fn header_names_are_adr_0028s() {
        assert_eq!(REQUEST_COUNTER_HEADER, "Rizzy-Request-Counter");
        assert_eq!(REQUEST_SIGNATURE_HEADER, "Rizzy-Request-Signature");
        assert_eq!(CLIENT_HEADER, "Rizzy-Client");
        assert_eq!(AUTHORIZATION_LEN, 50);
    }

    #[test]
    fn bearer_values() {
        let token = "A".repeat(43);
        assert!(bearer_token(format!("Bearer {token}").as_bytes()).is_ok());
        assert!(bearer_token(format!("bearer {token}").as_bytes()).is_ok());
        assert!(bearer_token(format!("BEARER {token}").as_bytes()).is_ok());
        for bad in [
            format!("Basic {token}"),
            format!("Bearer  {token}"),
            format!("Bearer {token}="),
            format!("Bearer {token} "),
            format!(" Bearer {token}"),
            format!("Bearer\t{token}"),
            format!("Bearer {}", "A".repeat(42)),
            format!("Bearer {}", "A".repeat(44)),
            // Not base64url: the standard alphabet's `+` and `/`.
            format!("Bearer {}+", "A".repeat(42)),
            format!("Bearer {}/", "A".repeat(42)),
            format!("Token {token}a"),
            "Bearer".to_owned(),
            String::new(),
        ] {
            assert_eq!(bearer_token(bad.as_bytes()).err(), Some(BadHeader), "{bad}");
        }
        assert!(bearer_token(&[b'B'; 100]).is_err());
    }

    #[test]
    fn signature_values() {
        let sig = "A".repeat(110);
        let parsed = request_signature(Some(b"42"), Some(sig.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(parsed.request_counter, 42);
        assert_eq!(request_signature(None, None), Ok(None));
        assert!(request_signature(Some(b"0"), Some(sig.as_bytes())).is_ok());
        assert!(request_signature(Some(b"18446744073709551615"), Some(sig.as_bytes())).is_ok());
        for counter in [
            &b""[..],
            b"00",
            b"01",
            b"+1",
            b"-1",
            b"1 ",
            b" 1",
            b"0x1",
            b"1e3",
            b"18446744073709551616",
            b"123456789012345678901",
        ] {
            assert!(
                request_signature(Some(counter), Some(sig.as_bytes())).is_err(),
                "{counter:?}"
            );
        }
        assert!(request_signature(Some(b"1"), None).is_err());
        assert!(request_signature(None, Some(sig.as_bytes())).is_err());
        assert!(request_signature(Some(b"1"), Some(&sig.as_bytes()[1..])).is_err());
        let long = "A".repeat(111);
        assert!(request_signature(Some(b"1"), Some(long.as_bytes())).is_err());
        let padded = format!("{}=", "A".repeat(109));
        assert!(request_signature(Some(b"1"), Some(padded.as_bytes())).is_err());
    }

    #[test]
    fn content_length_is_a_decimal_u64() {
        assert_eq!(content_length(b"0"), Ok(0));
        assert_eq!(content_length(b"1048576"), Ok(1_048_576));
        assert_eq!(content_length(b"007"), Ok(7));
        assert_eq!(content_length(b"18446744073709551615"), Ok(u64::MAX));
        for bad in [
            &b""[..],
            b"+5",
            b"-5",
            b" 5",
            b"5 ",
            b"5,5",
            b"0x10",
            b"1e3",
            b"18446744073709551616",
        ] {
            assert_eq!(content_length(bad), Err(BadHeader), "{bad:?}");
        }
    }

    #[test]
    fn client_header_values() {
        for good in [
            "cli/0.1.0",
            "web/1.2.3-rc.1+build",
            "extension/2.0.0",
            "macos/1.0.0",
            "windows/1.0.0",
            "linux/1.0.0",
            "ios/1.0.0",
            "android/not-semver",
        ] {
            assert!(client_header(good.as_bytes()).is_ok(), "{good}");
        }
        for bad in [
            "",
            "cli",
            "cli/",
            "/1.0.0",
            "CLI/1.0.0",
            "freebsd/1.0.0",
            "cli/1.0.0/x",
            "cli /1.0.0",
            "cli/1.0.0 ",
        ] {
            assert_eq!(
                client_header(bad.as_bytes()).err(),
                Some(BadHeader),
                "{bad:?}"
            );
        }
        let long = format!("cli/{}", "1".repeat(100));
        assert!(client_header(long.as_bytes()).is_err());
        assert!(client_header(&[0xff, b'/', b'1']).is_err());
    }

    #[test]
    fn only_a_well_formed_header_below_a_minimum_is_refused() {
        let minimums = [MinClientVersion {
            platform: Platform::from_str("cli").unwrap(),
            version: Version::from_str("0.3.0").unwrap(),
        }];
        assert!(client_refused(Some(b"cli/0.2.9"), &minimums));
        assert!(client_refused(Some(b"cli/0.3.0-rc.1"), &minimums));
        assert!(client_refused(Some(b"cli/nightly"), &minimums));
        assert!(!client_refused(Some(b"cli/0.3.0"), &minimums));
        assert!(!client_refused(Some(b"cli/1.0.0"), &minimums));
        // Another platform has no minimum.
        assert!(!client_refused(Some(b"web/0.0.1"), &minimums));
        // Missing or malformed: served normally until v1.0.
        assert!(!client_refused(None, &minimums));
        assert!(!client_refused(Some(b"curl/8.0.0"), &minimums));
        assert!(!client_refused(Some(b"cli"), &minimums));
        assert!(!client_refused(Some(b""), &minimums));
        // No minimum configured: nobody is refused.
        assert!(!client_refused(Some(b"cli/0.0.1"), &[]));
    }

    /// A trusted proxy, an untrusted client and another untrusted address.
    fn addresses() -> (IpAddr, IpAddr, IpAddr) {
        (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        )
    }

    #[test]
    fn forwarded_for_only_from_trusted_proxies() {
        let (proxy, client, other) = addresses();
        // Not trusted: the header is not read, whatever it holds.
        assert_eq!(
            client_address(other, &[&b"198.51.100.7"[..]], &[proxy]),
            Ok(other)
        );
        assert_eq!(client_address(other, &[&b"x"[..]], &[proxy]), Ok(other));
        assert_eq!(client_address(other, &[], &[proxy]), Ok(other));
        assert_eq!(client_address(other, &[], &[]), Ok(other));
        // Trusted: the rightmost untrusted address.
        assert_eq!(
            client_address(proxy, &[&b"1.2.3.4, 198.51.100.7"[..]], &[proxy]),
            Ok(client)
        );
        assert_eq!(
            client_address(proxy, &[&b"198.51.100.7, 10.0.0.2"[..]], &[proxy]),
            Ok(client)
        );
        assert_eq!(
            client_address(proxy, &[&b"198.51.100.7,\t10.0.0.2 "[..]], &[proxy]),
            Ok(client)
        );
        // A mapped peer matches the IPv4 proxy, and a mapped element is read as IPv4.
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped());
        assert_eq!(
            client_address(mapped, &[&b"198.51.100.7"[..]], &[proxy]),
            Ok(client)
        );
        assert_eq!(
            client_address(
                proxy,
                &[&b"::ffff:198.51.100.7, ::ffff:10.0.0.2"[..]],
                &[proxy]
            ),
            Ok(client)
        );
        // An IPv6 client.
        assert_eq!(
            client_address(proxy, &[&b"2001:db8::1"[..]], &[proxy]),
            Ok("2001:db8::1".parse().unwrap())
        );
    }

    /// ADR 0028 item 11, amended: no fallback to the proxy's address.
    #[test]
    fn a_trusted_proxy_without_a_usable_header_is_refused() {
        let (proxy, client, _) = addresses();
        // Missing.
        assert_eq!(client_address(proxy, &[], &[proxy]), Err(BadHeader));
        // Present and empty.
        assert_eq!(client_address(proxy, &[&b""[..]], &[proxy]), Err(BadHeader));
        // A malformed element before an untrusted address.
        for bad in [
            &b"x"[..],
            b"198.51.100.7, x",
            b"198.51.100.7,",
            b"198.51.100.7,,10.0.0.2",
            b"198.51.100.7, unknown",
            b"198.51.100.7, 10.0.0.2:443",
            b"198.51.100.7, [2001:db8::1]",
            b"198.51.100.7, fe80::1%eth0",
            b"198.51.100.7, 10.0.0.2\r",
            b"198.51.100.7, \xff",
        ] {
            assert_eq!(
                client_address(proxy, &[bad], &[proxy]),
                Err(BadHeader),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // The left end before an untrusted address: only trusted proxies are named.
        assert_eq!(
            client_address(proxy, &[&b"10.0.0.2, 10.0.0.2"[..]], &[proxy]),
            Err(BadHeader)
        );
        // A malformed element left of the found address is never read.
        assert_eq!(
            client_address(proxy, &[&b"x, 198.51.100.7, 10.0.0.2"[..]], &[proxy]),
            Ok(client)
        );
    }

    #[test]
    fn forwarded_for_lines_are_one_list_read_from_the_right() {
        let (proxy, client, _) = addresses();
        // Two field lines are one list (RFC 9110 §5.3): a line the client sent first cannot
        // hide the address the proxy appended in a line of its own.
        assert_eq!(
            client_address(proxy, &[&b"1.2.3.4"[..], &b"198.51.100.7"[..]], &[proxy]),
            Ok(client)
        );
        assert_eq!(
            client_address(
                proxy,
                &[&b"1.2.3.4"[..], &b"198.51.100.7, 10.0.0.2"[..]],
                &[proxy]
            ),
            Ok(client)
        );
        assert_eq!(
            client_address(proxy, &[&b"x"[..], &b"198.51.100.7"[..]], &[proxy]),
            Ok(client),
            "the rightmost untrusted address is found before the malformed line"
        );
        assert_eq!(
            client_address(proxy, &[&b"198.51.100.7"[..], &b"x"[..]], &[proxy]),
            Err(BadHeader)
        );
    }

    #[test]
    fn forwarded_for_bounds_count_from_the_right() {
        let (proxy, client, _) = addresses();
        // The client-controlled part left of the found address is never read: neither many
        // lines nor many bytes there change the answer.
        let mut many = vec![&b"garbage"[..]; 10 * MAX_FORWARDED_FOR_LINES];
        many.push(b"198.51.100.7");
        assert_eq!(client_address(proxy, &many, &[proxy]), Ok(client));
        let huge = vec![b'z'; 64 * MAX_FORWARDED_FOR_LEN];
        assert_eq!(
            client_address(proxy, &[&huge, &b"198.51.100.7, 10.0.0.2"[..]], &[proxy]),
            Ok(client)
        );
        let mut one_line = huge.clone();
        one_line.extend_from_slice(b", 198.51.100.7");
        assert_eq!(client_address(proxy, &[&one_line], &[proxy]), Ok(client));

        // The line bound: the untrusted address in the 16th line from the right is found, in
        // the 17th it is not.
        let mut lines = vec![&b"198.51.100.7"[..]];
        lines.extend(vec![&b"10.0.0.2"[..]; MAX_FORWARDED_FOR_LINES - 1]);
        assert_eq!(client_address(proxy, &lines, &[proxy]), Ok(client));
        lines.push(b"10.0.0.2");
        assert_eq!(client_address(proxy, &lines, &[proxy]), Err(BadHeader));

        // The byte bound: 1024 bytes from the right are read, 1025 are not. Each trusted
        // element is `10.0.0.2` (8 bytes) plus its separator; spaces pad the last one.
        let tail = |padding: usize| {
            let mut line = b"198.51.100.7".to_vec();
            for _ in 0..100 {
                line.extend_from_slice(b",10.0.0.2");
            }
            line.push(b',');
            line.extend(std::iter::repeat_n(b' ', padding));
            line.extend_from_slice(b"10.0.0.2");
            line
        };
        // 12 + 100 * 9 + 1 + padding + 8 bytes in all.
        let exact = tail(MAX_FORWARDED_FOR_LEN - 921);
        assert_eq!(exact.len(), MAX_FORWARDED_FOR_LEN);
        assert_eq!(client_address(proxy, &[&exact], &[proxy]), Ok(client));
        let over = tail(MAX_FORWARDED_FOR_LEN - 920);
        assert_eq!(client_address(proxy, &[&over], &[proxy]), Err(BadHeader));
    }

    #[test]
    fn sources() {
        assert_eq!(
            rate_limit_source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            [192, 0, 2, 1]
        );
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 9));
        assert_eq!(rate_limit_source(a), rate_limit_source(b));
        assert_eq!(rate_limit_source(a).len(), 8);
        let c = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 3, 4, 5, 6));
        assert_ne!(rate_limit_source(a), rate_limit_source(c));
        // A mapped address is counted as the IPv4 address it names.
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        assert_eq!(rate_limit_source(mapped), [192, 0, 2, 1]);
    }
}
