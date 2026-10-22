// SPDX-License-Identifier: AGPL-3.0-only

//! The address allow-list of INV-51 ([ADR 0010] §2): the `icons` role connects only to
//! globally routable unicast addresses, on ports 80 and 443 (443 only for the breach check,
//! INV-77).
//!
//! An allow-list, not a deny-list: an address is accepted only if it is in the global unicast
//! space **and** in none of the IANA special-purpose ranges listed below. Ranges the
//! registries mark globally reachable but that no web server lives in (AS112, AMT, the 6to4
//! relay anycast, the IETF protocol assignments) are refused as well: refusing more than
//! INV-51 requires is safe, accepting less is not.
//!
//! - **IPv4** (RFC 6890 and the IANA IPv4 special-purpose registry): `0.0.0.0/8`,
//!   `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`,
//!   `192.0.0.0/24`, `192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`,
//!   `192.88.99.0/24`, `192.168.0.0/16`, `192.175.48.0/24`, `198.18.0.0/15`,
//!   `198.51.100.0/24`, `203.0.113.0/24`, multicast `224.0.0.0/4`, `240.0.0.0/4` (reserved,
//!   with the limited broadcast `255.255.255.255`).
//! - **IPv6**: only `2000::/3` (global unicast) is accepted, minus `2001::/23` (IETF protocol
//!   assignments, Teredo and ORCHID included), `2001:db8::/32` (documentation), `2002::/16`
//!   (6to4) and `3fff::/20` (documentation). Everything outside `2000::/3` is refused:
//!   unspecified, loopback, IPv4-compatible, discard-only `100::/64`, unique-local
//!   `fc00::/7`, link-local `fe80::/10`, multicast `ff00::/8`, the local-use NAT64
//!   `64:ff9b:1::/48`.
//! - **Embedded IPv4**: an IPv4-mapped address (`::ffff:0:0/96`) and a well-known-prefix NAT64
//!   address (`64:ff9b::/96`) are judged by the IPv4 address they embed.
//!
//! The registries were not re-read for this module (U, as `THREAT_MODEL.md` §11 records); the list
//! is the one INV-51 names plus the ranges above.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The port of HTTPS, the only port the breach check connects to (INV-77).
pub const HTTPS_PORT: u16 = 443;

/// The refused IPv4 ranges, as `(network, prefix length)`.
const REFUSED_V4: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 31, 196, 0], 24),
    ([192, 52, 193, 0], 24),
    ([192, 88, 99, 0], 24),
    ([192, 168, 0, 0], 16),
    ([192, 175, 48, 0], 24),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

/// The refused ranges inside `2000::/3`, as `(network, prefix length)`.
const REFUSED_V6_GLOBAL: &[([u16; 8], u8)] = &[
    ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
    ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
    ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
];

/// Whether the top `len` bits of `a` and `b` agree.
const fn same_prefix(a: u128, b: u128, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    if len >= 128 {
        return a == b;
    }
    let shift = 128 - len as u32;
    (a >> shift) == (b >> shift)
}

/// Whether `ip` is a globally routable unicast IPv4 address.
#[must_use]
pub fn is_allowed_v4(ip: Ipv4Addr) -> bool {
    let a = u32::from(ip);
    !REFUSED_V4.iter().any(|(net, len)| {
        let n = u32::from(Ipv4Addr::from(*net));
        let shift = 32 - u32::from(*len);
        (a >> shift) == (n >> shift)
    })
}

/// The IPv4 address embedded in an IPv4-mapped (`::ffff:0:0/96`) or well-known NAT64
/// (`64:ff9b::/96`) address.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    match ip.segments() {
        [0, 0, 0, 0, 0, 0xffff, high, low] | [0x64, 0xff9b, 0, 0, 0, 0, high, low] => {
            Some(Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)))
        }
        _ => None,
    }
}

/// Whether `ip` is a globally routable unicast IPv6 address (module docs), judging an
/// embedded IPv4 address as IPv4.
#[must_use]
pub fn is_allowed_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return is_allowed_v4(v4);
    }
    let a = u128::from(ip);
    let global_unicast = same_prefix(a, u128::from(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0)), 3);
    global_unicast
        && !REFUSED_V6_GLOBAL
            .iter()
            .any(|(net, len)| same_prefix(a, u128::from(Ipv6Addr::from(*net)), *len))
}

/// Whether `ip` passes the INV-51 allow-list.
#[must_use]
pub fn is_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_allowed_v4(v4),
        IpAddr::V6(v6) => is_allowed_v6(v6),
    }
}

/// Of the addresses a resolution returned, the first that passes the allow-list on `port`:
/// every address is checked, and the caller connects to exactly the one returned, never
/// resolving again (INV-51: no second resolution). `None` when none passes.
pub fn pick_address<I>(addresses: I, port: u16) -> Option<SocketAddr>
where
    I: IntoIterator<Item = SocketAddr>,
{
    addresses
        .into_iter()
        .find(|a| a.port() == port && is_allowed(a.ip()))
}

#[cfg(test)]
mod tests {
    //! One case per refused range (INV-51's suite), the embedded forms of a private address,
    //! the port rule, and accepted public addresses.

    use super::*;

    fn v4(text: &str) -> bool {
        is_allowed(text.parse().unwrap())
    }

    #[test]
    fn every_refused_ipv4_range_is_refused_at_both_ends() {
        for (net, len) in REFUSED_V4 {
            let n = u32::from(Ipv4Addr::from(*net));
            let size = 1u64 << (32 - u32::from(*len));
            let last = u32::try_from(u64::from(n) + size - 1).unwrap();
            for a in [n, last] {
                assert!(!is_allowed_v4(Ipv4Addr::from(a)), "{}", Ipv4Addr::from(a));
            }
        }
        for text in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!v4(text), "{text}");
        }
    }

    #[test]
    fn public_ipv4_neighbours_are_allowed() {
        for text in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
        ] {
            assert!(v4(text), "{text}");
        }
    }

    #[test]
    fn ipv6_allow_list() {
        for text in [
            "::",
            "::1",
            "::7f00:1",
            "100::1",
            "64:ff9b:1::1",
            "2001::1",
            "2001:1ff:ffff::1",
            "2001:db8::1",
            "2002:c000:0201::1",
            "3fff::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "4000::1",
            "8000::1",
        ] {
            assert!(!v4(text), "{text}");
        }
        for text in [
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
            "2001:200::1",
            "3ffe::1",
        ] {
            assert!(v4(text), "{text}");
        }
    }

    #[test]
    fn embedded_ipv4_is_judged_as_ipv4() {
        for text in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b::c0a8:101",
        ] {
            assert!(!v4(text), "{text}");
        }
        for text in ["::ffff:1.1.1.1", "64:ff9b::808:808"] {
            assert!(v4(text), "{text}");
        }
    }

    #[test]
    fn pick_checks_every_address_and_the_port() {
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        // DNS rebinding: a private answer before the public one is skipped, never used.
        let picked = pick_address(
            [
                addr("127.0.0.1:443"),
                addr("10.0.0.1:443"),
                addr("1.1.1.1:443"),
            ],
            HTTPS_PORT,
        );
        assert_eq!(picked, Some(addr("1.1.1.1:443")));
        assert_eq!(
            pick_address([addr("127.0.0.1:443"), addr("[::1]:443")], HTTPS_PORT),
            None
        );
        // A non-standard port is never connected to.
        assert_eq!(pick_address([addr("1.1.1.1:8443")], HTTPS_PORT), None);
        assert_eq!(pick_address([addr("1.1.1.1:80")], HTTPS_PORT), None);
        assert_eq!(pick_address(core::iter::empty(), HTTPS_PORT), None);
    }
}
