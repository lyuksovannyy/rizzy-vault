//! Parsers for the request headers the `api` role reads: the bearer token, the two
//! request-signing values, and `X-Forwarded-For` (CRYPTO.md §5.10; ADR 0002 owner decision 2;
//! threat model §7.6 "S", INV-52).
//!
//! **Wire details this crate decides** (no Accepted ADR fixes them; `rizzy-proto`'s
//! `RequestSignature` leaves "the header names and value encoding" to the API specification;
//! reported to the owner, pre-v1.0 under ADR 0002 point 5):
//! - The bearer token travels as `Authorization: Bearer <token>`, the token as base64url
//!   without padding of its 32 bytes (43 characters), like every binary value (CRYPTO.md
//!   §9.6). The scheme name is matched case-insensitively (RFC 9110 §11.1); nothing else is
//!   accepted, and the token is never read from a URL or a cookie (INV-52).
//! - A signed request carries [`REQUEST_COUNTER`]: the `request_counter` in decimal ASCII, no
//!   sign, no leading zero (`0` alone is allowed), at most 20 digits and within `u64`; and
//!   [`REQUEST_SIGNATURE`]: the `device-request` signature container (82 bytes) as base64url
//!   without padding (110 characters). Both or neither.
//!
//! Every parser here is bounded (it checks a value's length before decoding it), never panics,
//! and returns an error that names no value. They are fuzzed by the `server_headers` target.

use std::net::IpAddr;

use rizzy_domain_auth::types::RequestSignature;
use rizzy_domain_auth::types::SIGNATURE_CONTAINER_LEN;
use rizzy_domain_auth::types::{Fixed, SessionToken, b64url_len};

/// The request header of the `request_counter` (this crate's name, module docs).
pub const REQUEST_COUNTER: &str = "rizzy-request-counter";

/// The request header of the `device-request` signature container (this crate's name, module
/// docs).
pub const REQUEST_SIGNATURE: &str = "rizzy-request-signature";

/// The longest `Authorization` value read: `Bearer ` and 43 characters, with room for case and
/// no more.
const MAX_AUTHORIZATION_LEN: usize = 64;

/// The longest `X-Forwarded-For` read, over all its field lines together: a chain of proxies,
/// each at most an IPv6 address.
pub const MAX_FORWARDED_FOR_LEN: usize = 1024;

/// The most `X-Forwarded-For` field lines read ([`client_address`]).
pub const MAX_FORWARDED_FOR_LINES: usize = 16;

/// A header value that could not be used. Carries nothing of the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadHeader;

/// Parses an `Authorization` value into the bearer token (module docs).
///
/// # Errors
/// [`BadHeader`] for any other scheme, form or length.
pub fn bearer_token(value: &[u8]) -> Result<SessionToken, BadHeader> {
    if value.len() > MAX_AUTHORIZATION_LEN {
        return Err(BadHeader);
    }
    let text = core::str::from_utf8(value).map_err(|_| BadHeader)?;
    let (scheme, token) = text.split_once(' ').ok_or(BadHeader)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.len() != b64url_len(SessionToken::LEN) {
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
        request_counter: decimal_u64(counter)?,
        signature: container(signature)?,
    }))
}

/// A `u64` in decimal: 1–20 ASCII digits, no leading zero except `0` itself.
fn decimal_u64(value: &[u8]) -> Result<u64, BadHeader> {
    if value.is_empty() || value.len() > 20 || (value.len() > 1 && value.first() == Some(&b'0')) {
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

/// The signature container, base64url of exactly its 82 bytes.
fn container(value: &[u8]) -> Result<Fixed<SIGNATURE_CONTAINER_LEN>, BadHeader> {
    if value.len() != b64url_len(SIGNATURE_CONTAINER_LEN) {
        return Err(BadHeader);
    }
    let text = core::str::from_utf8(value).map_err(|_| BadHeader)?;
    Fixed::from_b64url(text).map_err(|_| BadHeader)
}

/// The client's address for rate limiting (threat model §7.6 "S": "XFF trusted only from
/// configured proxies"). When the peer is a trusted proxy, `X-Forwarded-For` is read from the
/// right, skipping trusted proxies, and the first other address is the client; a malformed or
/// over-long header, or one naming only trusted proxies, falls back to the peer. Addresses a
/// client wrote further left are never used, since any client can prepend them.
///
/// `forwarded_for` holds every `X-Forwarded-For` field line of the request, in the order
/// received (empty when there is none). RFC 9110 §5.3 makes repeated field lines one
/// comma-joined list, and a proxy may append a line of its own instead of extending the
/// client's, so the lines are read as that one list, from the last line's right end. The length
/// bound, [`MAX_FORWARDED_FOR_LEN`], covers all lines together, and at most
/// [`MAX_FORWARDED_FOR_LINES`] lines are read; past either, the answer is the peer.
#[must_use]
pub fn client_address(peer: IpAddr, forwarded_for: &[&[u8]], trusted: &[IpAddr]) -> IpAddr {
    let peer = canonical(peer);
    if !trusted.iter().any(|t| canonical(*t) == peer) {
        return peer;
    }
    let total = forwarded_for
        .iter()
        .fold(0usize, |n, line| n.saturating_add(line.len()));
    if forwarded_for.is_empty()
        || forwarded_for.len() > MAX_FORWARDED_FOR_LINES
        || total > MAX_FORWARDED_FOR_LEN
    {
        return peer;
    }
    for line in forwarded_for.iter().rev() {
        let Ok(text) = core::str::from_utf8(line) else {
            return peer;
        };
        for part in text.rsplit(',') {
            let Ok(addr) = part.trim().parse::<IpAddr>() else {
                return peer;
            };
            let addr = canonical(addr);
            if !trusted.iter().any(|t| canonical(*t) == addr) {
                return addr;
            }
        }
    }
    peer
}

/// An IPv4-mapped IPv6 address as the IPv4 address it names; anything else unchanged.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// The rate-limit source of a client address: the 4 bytes of an IPv4 address, or the first 8
/// bytes (the /64 prefix) of an IPv6 address. One IPv6 subscriber usually holds a whole /64, so
/// counting per address would give an attacker 2^64 buckets (this crate's reading; ADR 0010 §5
/// says "per (account, source)" without defining a source).
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

    use super::*;

    #[test]
    fn bearer_values() {
        let token = "A".repeat(43);
        assert!(bearer_token(format!("Bearer {token}").as_bytes()).is_ok());
        assert!(bearer_token(format!("bearer {token}").as_bytes()).is_ok());
        for bad in [
            format!("Basic {token}"),
            format!("Bearer  {token}"),
            format!("Bearer {token}="),
            format!("Bearer {}", "A".repeat(42)),
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
            b"01",
            b"+1",
            b"-1",
            b"1 ",
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
    }

    #[test]
    fn forwarded_for_only_from_trusted_proxies() {
        let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        // Not trusted: the header is ignored.
        assert_eq!(
            client_address(other, &[&b"198.51.100.7"[..]], &[proxy]),
            other
        );
        // Trusted: the rightmost untrusted address.
        assert_eq!(
            client_address(proxy, &[&b"1.2.3.4, 198.51.100.7"[..]], &[proxy]),
            client
        );
        assert_eq!(
            client_address(proxy, &[&b"198.51.100.7, 10.0.0.2"[..]], &[proxy]),
            client
        );
        // Malformed or missing: the peer.
        assert_eq!(client_address(proxy, &[&b"x"[..]], &[proxy]), proxy);
        assert_eq!(client_address(proxy, &[], &[proxy]), proxy);
        // A mapped peer matches the IPv4 proxy.
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped());
        assert_eq!(
            client_address(mapped, &[&b"198.51.100.7"[..]], &[proxy]),
            client
        );
        // Two field lines are one list (RFC 9110 §5.3): a line the client sent first cannot
        // hide the address the proxy appended in a line of its own.
        assert_eq!(
            client_address(proxy, &[&b"1.2.3.4"[..], &b"198.51.100.7"[..]], &[proxy]),
            client
        );
        assert_eq!(
            client_address(
                proxy,
                &[&b"1.2.3.4"[..], &b"198.51.100.7, 10.0.0.2"[..]],
                &[proxy]
            ),
            client
        );
        // A malformed line anywhere, too many lines, or too many bytes over all lines: the
        // peer.
        assert_eq!(
            client_address(proxy, &[&b"x"[..], &b"198.51.100.7"[..]], &[proxy]),
            client,
            "the rightmost untrusted address is found before the malformed line"
        );
        assert_eq!(
            client_address(proxy, &[&b"198.51.100.7"[..], &b"x"[..]], &[proxy]),
            proxy
        );
        let many = vec![&b"198.51.100.7"[..]; MAX_FORWARDED_FOR_LINES + 1];
        assert_eq!(client_address(proxy, &many, &[proxy]), proxy);
        let half = vec![b' '; MAX_FORWARDED_FOR_LEN / 2];
        let mut tail = half.clone();
        tail.extend_from_slice(b"198.51.100.7");
        assert_eq!(client_address(proxy, &[&half, &tail], &[proxy]), proxy);
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
    }
}
