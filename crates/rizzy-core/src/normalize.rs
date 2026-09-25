//! Normalisation of login names and server origins (CRYPTO.md §2).
//!
//! Both values are public, but they are bound into security decisions, so each has exactly one
//! normalisation function, used by the client and the server alike:
//!
//! - [`LoginName`] is the one function §2 and §5.9 require for the account lookup, the
//!   uniqueness check, the fake credential id and the fake `kdf_id`. Real and unknown names are
//!   therefore always handled with the same string.
//! - [`ServerOrigin`] is `scheme "://" host [":" port]`, bound into the OPAQUE Context (§5.3) and
//!   into device authentication (§5.10).
//!
//! Neither function allocates in proportion to anything but its (bounded) input, and neither
//! panics.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

/// Longest accepted login name, in bytes (CRYPTO.md §2).
pub const LOGIN_NAME_MAX_LEN: usize = 254;

/// Longest accepted DNS host name, in bytes (RFC 1035 without the trailing dot).
pub const HOST_MAX_LEN: usize = 253;

/// Longest accepted origin input, in bytes. The longest canonical origin
/// (`https://` + 253-byte host + `:65535`) is 267 bytes; anything much longer is not an origin.
pub const ORIGIN_INPUT_MAX_LEN: usize = 512;

/// Why a login name or origin was rejected. Carries no part of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NormalizeError {
    /// The login name is empty or longer than 254 bytes.
    LoginNameLength,
    /// The login name contains a byte outside `[a-z0-9._+@-]` after ASCII lowercasing.
    LoginNameCharacter,
    /// The origin is not `scheme "://" authority` with an optional single trailing `/`, or is
    /// too long, or is not ASCII.
    OriginSyntax,
    /// The scheme is not `https` or `http`.
    OriginScheme,
    /// The origin carries user information, a path, a query or a fragment.
    OriginComponent,
    /// The host is not a valid DNS name, canonical dotted-quad IPv4 address or bracketed IPv6
    /// address.
    OriginHost,
    /// The port is empty, has a leading zero, or is outside `1..=65535`.
    OriginPort,
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LoginNameLength => "login name must be 1 to 254 characters",
            Self::LoginNameCharacter => "login name may contain only letters, digits and . _ + @ -",
            Self::OriginSyntax => "not a server address of the form https://host[:port]",
            Self::OriginScheme => "server address must use https or http",
            Self::OriginComponent => {
                "server address must not contain a user name, path, query or fragment"
            }
            Self::OriginHost => "invalid host in server address",
            Self::OriginPort => "invalid port in server address",
        })
    }
}

impl core::error::Error for NormalizeError {}

/// A normalised login name (CRYPTO.md §2).
///
/// `login_name` is the ASCII-lowercased input. After lowercasing it must be 1–254 bytes from
/// `[a-z0-9._+@-]`. Anything else, including any non-ASCII character, is rejected at signup and at
/// login, before any lookup. ASCII-only avoids a dependency on Unicode case-folding tables, which
/// change between releases (owner decision, CRYPTO.md §16 question 13).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoginName(String);

impl LoginName {
    /// Normalises and validates a login name.
    ///
    /// # Errors
    /// [`NormalizeError::LoginNameLength`] or [`NormalizeError::LoginNameCharacter`].
    pub fn parse(input: &str) -> Result<Self, NormalizeError> {
        // ASCII lowercasing never changes the byte length, so the length is checked first,
        // before anything is allocated.
        if input.is_empty() || input.len() > LOGIN_NAME_MAX_LEN {
            return Err(NormalizeError::LoginNameLength);
        }
        if !input
            .bytes()
            .all(|b| is_login_name_byte(b.to_ascii_lowercase()))
        {
            return Err(NormalizeError::LoginNameCharacter);
        }
        Ok(Self(input.to_ascii_lowercase()))
    }

    /// The normalised name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_login_name_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'@' | b'-')
}

impl fmt::Debug for LoginName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LoginName").field(&self.0).finish()
    }
}

impl fmt::Display for LoginName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The URI scheme of a server origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `https`, default port 443.
    Https,
    /// `http`, default port 80. Allowed for local and development servers; the scheme is part of
    /// the origin, so an `http` origin never matches an `https` one.
    Http,
}

impl Scheme {
    /// The scheme as written in an origin.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }

    /// The scheme's default port, which a canonical origin omits.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }
}

/// A canonical server origin (CRYPTO.md §2): `scheme "://" host [":" port]`, with scheme and
/// host ASCII-lowercased, no trailing slash, and the port omitted when it is the scheme's
/// default.
///
/// On the client it is the origin the client actually connected to (for the web vault,
/// `location.origin`); on the server it is the configured canonical origin. It is bound into the
/// OPAQUE Context ([`crate::opaque::OpaqueContext`]) and into device authentication.
///
/// Readings of §2, chosen to fail closed rather than guess:
/// - **Schemes.** Only `https` and `http`, the only schemes a rizzy-vault server speaks. Their
///   default ports are 443 and 80.
/// - **Input.** The input may end in one `/` (the empty path), which is dropped. User
///   information, any other path, a query or a fragment is rejected rather than stripped, so a
///   configuration typo is noticed instead of silently binding another string.
/// - **Hosts.** A DNS name of letter-digit-hyphen labels (1–63 bytes each, 253 in total, no
///   leading or trailing hyphen, no trailing dot); a dotted-quad IPv4 address in canonical form;
///   or a bracketed IPv6 address, re-serialised in the RFC 5952 form that browsers also use.
///   Internationalised names must already be in their `xn--` form: no IDNA mapping is done, and
///   any non-ASCII input is rejected. A name whose last label is numeric (or `0x`-hex) is treated
///   as an IPv4 address, as browsers do, and must be a canonical dotted quad. IPv4-mapped IPv6
///   addresses are rejected, because browsers and Rust serialise them differently.
/// - **Ports.** Decimal, no leading zero, `1..=65535`. An empty port (`host:`) is rejected.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ServerOrigin {
    text: String,
    scheme: Scheme,
}

impl ServerOrigin {
    /// Parses and canonicalises an origin.
    ///
    /// # Errors
    /// A [`NormalizeError`] naming the part that is wrong.
    pub fn parse(input: &str) -> Result<Self, NormalizeError> {
        if input.len() > ORIGIN_INPUT_MAX_LEN || !input.is_ascii() {
            return Err(NormalizeError::OriginSyntax);
        }
        let (scheme_text, rest) = input
            .split_once("://")
            .ok_or(NormalizeError::OriginSyntax)?;
        let scheme = if scheme_text.eq_ignore_ascii_case("https") {
            Scheme::Https
        } else if scheme_text.eq_ignore_ascii_case("http") {
            Scheme::Http
        } else {
            return Err(NormalizeError::OriginScheme);
        };

        // The authority ends at the first '/', '?' or '#'. What follows may only be one '/'.
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if !(tail.is_empty() || tail == "/") {
            return Err(NormalizeError::OriginComponent);
        }
        if authority.contains('@') {
            return Err(NormalizeError::OriginComponent);
        }

        let (host, port) = split_host_port(authority)?;
        let host = canonical_host(host)?;
        let port = match port {
            None => None,
            Some(text) => Some(parse_port(text)?).filter(|p| *p != scheme.default_port()),
        };

        let mut text = String::with_capacity(scheme.as_str().len() + 3 + host.len() + 6);
        text.push_str(scheme.as_str());
        text.push_str("://");
        text.push_str(&host);
        if let Some(port) = port {
            text.push(':');
            text.push_str(&port.to_string());
        }
        Ok(Self { text, scheme })
    }

    /// The canonical origin string, e.g. `https://vault.example.com`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }
}

impl fmt::Debug for ServerOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ServerOrigin").field(&self.text).finish()
    }
}

impl fmt::Display for ServerOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Splits `host[:port]` or `[v6][:port]`. The host part keeps its brackets.
fn split_host_port(authority: &str) -> Result<(&str, Option<&str>), NormalizeError> {
    if authority.starts_with('[') {
        let close = authority.find(']').ok_or(NormalizeError::OriginHost)?;
        let (host, after) = authority.split_at(close + 1);
        return match after.strip_prefix(':') {
            Some(port) => Ok((host, Some(port))),
            None if after.is_empty() => Ok((host, None)),
            None => Err(NormalizeError::OriginHost),
        };
    }
    match authority.split_once(':') {
        Some((_, port)) if port.contains(':') => Err(NormalizeError::OriginHost),
        Some((host, port)) => Ok((host, Some(port))),
        None => Ok((authority, None)),
    }
}

fn parse_port(text: &str) -> Result<u16, NormalizeError> {
    let digits_only = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !digits_only || text.starts_with('0') || text.len() > 5 {
        return Err(NormalizeError::OriginPort);
    }
    text.parse::<u16>().map_err(|_| NormalizeError::OriginPort)
}

/// The canonical, lowercased host, or an error.
fn canonical_host(host: &str) -> Result<String, NormalizeError> {
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or(NormalizeError::OriginHost)?;
        let addr: Ipv6Addr = inner.parse().map_err(|_| NormalizeError::OriginHost)?;
        if addr.to_ipv4_mapped().is_some() {
            return Err(NormalizeError::OriginHost);
        }
        return Ok(format!("[{addr}]"));
    }

    let host = host.to_ascii_lowercase();
    if host.is_empty() || host.len() > HOST_MAX_LEN {
        return Err(NormalizeError::OriginHost);
    }
    let last_label = host.rsplit('.').next().unwrap_or_default();
    if is_numeric_label(last_label) {
        // Browsers parse such a host as an IPv4 address (with octal and hex forms); accept only
        // the canonical dotted quad, which every parser reads the same way.
        let addr: Ipv4Addr = host.parse().map_err(|_| NormalizeError::OriginHost)?;
        return if addr.to_string() == host {
            Ok(host)
        } else {
            Err(NormalizeError::OriginHost)
        };
    }
    if host.split('.').all(is_dns_label) {
        Ok(host)
    } else {
        Err(NormalizeError::OriginHost)
    }
}

/// Whether a label is decimal digits, or `0x` followed by hex digits (the WHATWG URL
/// "ends in a number" rule).
fn is_numeric_label(label: &str) -> bool {
    if !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    label
        .strip_prefix("0x")
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A lowercase letter-digit-hyphen label of 1–63 bytes with no leading or trailing hyphen.
fn is_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn login_names_are_ascii_lowercased() {
        for (input, expected) in [
            ("Alice", "alice"),
            ("ALICE@Example.COM", "alice@example.com"),
            ("a.b_c+d@e-f", "a.b_c+d@e-f"),
            ("0", "0"),
            ("-", "-"),
        ] {
            assert_eq!(LoginName::parse(input).unwrap().as_str(), expected);
        }
        // Same string for every spelling: the lookup, the fake id and the fake kdf_id agree.
        assert_eq!(
            LoginName::parse("Bob").unwrap(),
            LoginName::parse("bOB").unwrap()
        );
    }

    #[test]
    fn login_name_length_bounds() {
        assert_eq!(LoginName::parse(""), Err(NormalizeError::LoginNameLength));
        let max = "a".repeat(LOGIN_NAME_MAX_LEN);
        assert_eq!(LoginName::parse(&max).unwrap().as_str(), max);
        assert_eq!(
            LoginName::parse(&"a".repeat(LOGIN_NAME_MAX_LEN + 1)),
            Err(NormalizeError::LoginNameLength)
        );
    }

    #[test]
    fn login_names_reject_everything_outside_the_set() {
        for bad in [
            "a b",
            "a\tb",
            "a/b",
            "a:b",
            "a\0b",
            "é",
            "straße",
            "\u{212A}elvin", // Kelvin sign: Unicode lowercases it to 'k'; ASCII does not
            "İ",
            "a!",
            "a%40b",
        ] {
            assert_eq!(
                LoginName::parse(bad),
                Err(NormalizeError::LoginNameCharacter),
                "{bad:?}"
            );
        }
    }

    fn origin(input: &str) -> Result<String, NormalizeError> {
        ServerOrigin::parse(input).map(|o| o.as_str().to_owned())
    }

    #[test]
    fn origins_are_canonicalised() {
        for (input, expected) in [
            ("https://vault.example.com", "https://vault.example.com"),
            ("HTTPS://Vault.Example.COM/", "https://vault.example.com"),
            ("https://vault.example.com:443", "https://vault.example.com"),
            (
                "https://vault.example.com:8443",
                "https://vault.example.com:8443",
            ),
            ("http://localhost:80", "http://localhost"),
            ("http://localhost:8080/", "http://localhost:8080"),
            (
                "http://vault.example.com:443",
                "http://vault.example.com:443",
            ),
            ("https://192.168.1.10:8443", "https://192.168.1.10:8443"),
            ("https://[::1]", "https://[::1]"),
            ("https://[0:0:0:0:0:0:0:1]:443", "https://[::1]"),
            ("https://[FE80::1]:9000", "https://[fe80::1]:9000"),
            (
                "https://xn--bcher-kva.example",
                "https://xn--bcher-kva.example",
            ),
            ("https://a-b.c1", "https://a-b.c1"),
        ] {
            assert_eq!(origin(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn origins_reject_other_shapes() {
        use NormalizeError as E;
        for (input, err) in [
            ("vault.example.com", E::OriginSyntax),
            ("https:/vault.example.com", E::OriginSyntax),
            ("https://bücher.example", E::OriginSyntax),
            ("ftp://vault.example.com", E::OriginScheme),
            ("wss://vault.example.com", E::OriginScheme),
            ("https://vault.example.com/path", E::OriginComponent),
            ("https://vault.example.com//", E::OriginComponent),
            ("https://vault.example.com?x=1", E::OriginComponent),
            ("https://vault.example.com/?x", E::OriginComponent),
            ("https://vault.example.com#f", E::OriginComponent),
            ("https://user@vault.example.com", E::OriginComponent),
            ("https://user:pw@vault.example.com", E::OriginComponent),
            ("https://", E::OriginHost),
            ("https://:443", E::OriginHost),
            ("https://vault..example.com", E::OriginHost),
            ("https://vault.example.com.", E::OriginHost),
            ("https://-vault.example.com", E::OriginHost),
            ("https://vault-.example.com", E::OriginHost),
            ("https://vault_1.example.com", E::OriginHost),
            ("https://vault example.com", E::OriginHost),
            ("https://0x7f.0.0.1", E::OriginHost),
            ("https://127.1", E::OriginHost),
            ("https://010.0.0.1", E::OriginHost),
            ("https://256.0.0.1", E::OriginHost),
            ("https://example.0x10", E::OriginHost),
            ("https://[::ffff:1.2.3.4]", E::OriginHost),
            ("https://[fe80::1%25eth0]", E::OriginHost),
            ("https://[::1", E::OriginHost),
            ("https://[::1]x", E::OriginHost),
            ("https://a:1:2", E::OriginHost),
            ("https://vault.example.com:", E::OriginPort),
            ("https://vault.example.com:0", E::OriginPort),
            ("https://vault.example.com:0443", E::OriginPort),
            ("https://vault.example.com:65536", E::OriginPort),
            ("https://vault.example.com:+443", E::OriginPort),
            ("https://vault.example.com:44a", E::OriginPort),
        ] {
            assert_eq!(origin(input), Err(err), "{input}");
        }
        let long_label = format!("https://{}.com", "a".repeat(64));
        assert_eq!(origin(&long_label), Err(E::OriginHost));
        let long_host = format!("https://{}a.com", "a.".repeat(125));
        assert_eq!(origin(&long_host), Err(E::OriginHost));
        let too_long = format!("https://{}", "a".repeat(ORIGIN_INPUT_MAX_LEN));
        assert_eq!(origin(&too_long), Err(E::OriginSyntax));
    }

    #[test]
    fn scheme_is_part_of_the_origin() {
        let https = ServerOrigin::parse("https://v.example").unwrap();
        let http = ServerOrigin::parse("http://v.example").unwrap();
        assert_ne!(https, http);
        assert_eq!(https.scheme(), Scheme::Https);
        assert_eq!(http.scheme().default_port(), 80);
        assert_eq!(format!("{https}"), "https://v.example");
    }

    proptest! {
        #[test]
        fn normalisers_never_panic_and_are_idempotent(input in "\\PC{0,80}") {
            if let Ok(name) = LoginName::parse(&input) {
                prop_assert_eq!(LoginName::parse(name.as_str()), Ok(name.clone()));
            }
            if let Ok(o) = ServerOrigin::parse(&input) {
                prop_assert_eq!(ServerOrigin::parse(o.as_str()), Ok(o.clone()));
            }
        }

        #[test]
        fn url_like_inputs_never_panic(
            scheme in "(https?|HTTP|ftp)",
            host in "[a-zA-Z0-9.\\-\\[\\]:_]{0,40}",
            port in proptest::option::of("[0-9]{0,6}"),
            tail in "(|/|/x|\\?q|#f)",
        ) {
            let input = match port {
                Some(p) => format!("{scheme}://{host}:{p}{tail}"),
                None => format!("{scheme}://{host}{tail}"),
            };
            if let Ok(o) = ServerOrigin::parse(&input) {
                prop_assert_eq!(ServerOrigin::parse(o.as_str()), Ok(o.clone()));
                prop_assert!(!o.as_str().ends_with('/'));
            }
        }
    }
}
