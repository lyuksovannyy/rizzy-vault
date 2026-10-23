// SPDX-License-Identifier: AGPL-3.0-only

//! Where a favicon request goes: a scheme, a host, a port and a path ([ADR 0052] points 2–3).
//!
//! A [`Target`] is built from the requested hostname ([`Target::origin`]) or resolved from a
//! `Location` header or a `<link rel="icon">` `href` against the request that produced it
//! ([`Target::resolve`]). No URL crate is used: the accepted forms are few and checked byte by
//! byte, and everything else is refused, which ends the fetch with no icon.
//!
//! - **Schemes** `http` and `https` only (case-insensitive); `data:`, `javascript:` and
//!   every other scheme are refused.
//! - **Hosts** pass [`rizzy_proto::icons::is_valid_host`] after lowercasing: RFC 1123 syntax,
//!   ASCII only. IP literals in brackets, userinfo (`user@`) and percent-encoded hosts are
//!   refused.
//! - **Ports** 80 and 443 only (INV-51), the scheme's default when none is written.
//! - **Paths** keep only RFC 3986 path and query characters (no space, no control byte, no
//!   non-ASCII byte, no backslash, `"`, `<`, `>`, `{`, `}`, `|`, `^` or ``` ` ```); the fragment is
//!   dropped. A reference is at most [`MAX_REFERENCE_LEN`] bytes.
//! - **Relative references** resolve against the base request's own scheme, host and port
//!   (never an assumed one): `//host/path`, `/path`, `?query` and `path` (relative to the
//!   base path's directory). Dot segments are left for the upstream to interpret: they cannot
//!   leave the host.
//!
//! `Debug` prints the scheme and port only: hosts and paths name the sites a user has accounts
//! on, which this role never logs (INV-51; threat model §7.11 "I").
//!
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md

use core::fmt;

use rizzy_proto::icons::{IconHost, is_valid_host};

use crate::allow::HTTPS_PORT;

/// The port of plain HTTP, the only other port INV-51 allows.
pub const HTTP_PORT: u16 = 80;

/// The longest `Location` value or `href` accepted, in bytes.
pub const MAX_REFERENCE_LEN: usize = 2048;

/// A request scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

impl Scheme {
    /// The scheme's name, as in a URL and in a cache file name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// The scheme's default port.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => HTTP_PORT,
            Self::Https => HTTPS_PORT,
        }
    }
}

/// Why a reference was refused. Carries none of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetError {
    /// Longer than [`MAX_REFERENCE_LEN`] or empty.
    Length,
    /// A scheme other than `http` or `https`, or a scheme without `//`.
    Scheme,
    /// A host that is not RFC 1123 syntax, a bracketed IP literal, or userinfo.
    Host,
    /// A port other than 80 or 443, or not a number.
    Port,
    /// A byte outside the accepted path and query characters.
    Character,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "reference too long or empty",
            Self::Scheme => "scheme not http or https",
            Self::Host => "host not accepted",
            Self::Port => "port not 80 or 443",
            Self::Character => "character not accepted in a path",
        })
    }
}

impl std::error::Error for TargetError {}

/// One request's destination (module docs).
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    /// `http` or `https`.
    scheme: Scheme,
    /// A lowercase hostname that passed [`is_valid_host`].
    host: String,
    /// 80 or 443.
    port: u16,
    /// The path and query, starting with `/`, without a fragment.
    path: String,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("scheme", &self.scheme)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// Whether `b` may appear in a path or query (RFC 3986 `pchar`, `/`, `?` and `%` for
/// percent-encoding).
const fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'%'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'?'
        )
}

/// Checks a path-and-query.
fn check_path(path: &str) -> Result<(), TargetError> {
    if path.bytes().all(is_path_byte) {
        Ok(())
    } else {
        Err(TargetError::Character)
    }
}

/// Splits `scheme:` off `text`, if it starts with one (RFC 3986 §3.1 syntax).
fn split_scheme(text: &str) -> Option<(&str, &str)> {
    let colon = text.find(':')?;
    let (scheme, rest) = text.split_at(colon);
    let mut bytes = scheme.bytes();
    let first = bytes.next()?;
    if !first.is_ascii_alphabetic()
        || !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some((scheme, rest.get(1..)?))
}

impl Target {
    /// `path` on `host` at the scheme's default port.
    #[must_use]
    pub fn origin(host: &IconHost, scheme: Scheme, path: &str) -> Self {
        Self {
            scheme,
            host: host.as_str().to_owned(),
            port: scheme.default_port(),
            path: path.to_owned(),
        }
    }

    /// The same host and path at another scheme and port (the port-80 fallback of ADR 0052
    /// point 2, which reuses the checked address).
    #[must_use]
    pub fn with_scheme(&self, scheme: Scheme, port: u16) -> Self {
        Self {
            scheme,
            host: self.host.clone(),
            port,
            path: self.path.clone(),
        }
    }

    /// The same scheme, host and port with another path (discovery's `GET /`).
    #[must_use]
    pub fn with_path(&self, path: &str) -> Self {
        Self {
            scheme: self.scheme,
            host: self.host.clone(),
            port: self.port,
            path: path.to_owned(),
        }
    }

    /// The scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The lowercase hostname.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, 80 or 443.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The path and query, starting with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The value of the request's `Host` header: the hostname, with the port only when it is
    /// not the scheme's default.
    #[must_use]
    pub fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Resolves `reference` (a `Location` value or an `href`) against `self`, the request
    /// that produced it (module docs).
    ///
    /// # Errors
    /// [`TargetError`].
    pub fn resolve(&self, reference: &str) -> Result<Self, TargetError> {
        let reference = reference.trim_matches(|c: char| c.is_ascii_whitespace());
        if reference.is_empty() || reference.len() > MAX_REFERENCE_LEN {
            return Err(TargetError::Length);
        }
        let reference = reference.split_once('#').map_or(reference, |(r, _)| r);
        if let Some(rest) = reference.strip_prefix("//") {
            return Self::from_authority(self.scheme, rest);
        }
        if let Some((scheme, rest)) = split_scheme(reference) {
            let scheme = if scheme.eq_ignore_ascii_case("https") {
                Scheme::Https
            } else if scheme.eq_ignore_ascii_case("http") {
                Scheme::Http
            } else {
                return Err(TargetError::Scheme);
            };
            let rest = rest.strip_prefix("//").ok_or(TargetError::Scheme)?;
            return Self::from_authority(scheme, rest);
        }
        check_path(reference)?;
        let path = if reference.starts_with('/') {
            reference.to_owned()
        } else if reference.starts_with('?') {
            let base = self
                .path
                .split_once('?')
                .map_or(self.path.as_str(), |(p, _)| p);
            format!("{base}{reference}")
        } else {
            let base = self
                .path
                .split_once('?')
                .map_or(self.path.as_str(), |(p, _)| p);
            let dir = base.rfind('/').and_then(|i| base.get(..=i)).unwrap_or("/");
            format!("{dir}{reference}")
        };
        if path.is_empty() || path.len() > MAX_REFERENCE_LEN {
            return Err(TargetError::Length);
        }
        Ok(self.with_path(&path))
    }

    /// `authority[/path]` after `scheme://` or `//`.
    fn from_authority(scheme: Scheme, rest: &str) -> Result<Self, TargetError> {
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains('@') || authority.starts_with('[') {
            return Err(TargetError::Host);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                if port.is_empty()
                    || port.len() > 5
                    || port.starts_with('0')
                    || !port.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(TargetError::Port);
                }
                let port: u16 = port.parse().map_err(|_| TargetError::Port)?;
                (host, port)
            }
            None => (authority, scheme.default_port()),
        };
        if port != HTTP_PORT && port != HTTPS_PORT {
            return Err(TargetError::Port);
        }
        let host = host.to_ascii_lowercase();
        if !is_valid_host(&host) {
            return Err(TargetError::Host);
        }
        check_path(path)?;
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Every accepted reference form, and the refusals.

    use super::*;

    fn base() -> Target {
        let host = IconHost::parse("example.com").unwrap();
        Target::origin(&host, Scheme::Https, "/dir/page?x=1")
    }

    fn parts(t: &Target) -> (Scheme, &str, u16, &str) {
        (t.scheme(), t.host(), t.port(), t.path())
    }

    #[test]
    fn absolute_references() {
        let b = base();
        let t = b.resolve("https://cdn.example.net/i/fav.png").unwrap();
        assert_eq!(
            parts(&t),
            (Scheme::Https, "cdn.example.net", 443, "/i/fav.png")
        );
        let t = b.resolve("HTTP://WWW.Example.COM").unwrap();
        assert_eq!(parts(&t), (Scheme::Http, "www.example.com", 80, "/"));
        let t = b.resolve("http://example.com:443/a?b=c#frag").unwrap();
        assert_eq!(parts(&t), (Scheme::Http, "example.com", 443, "/a?b=c"));
        assert_eq!(t.host_header(), "example.com:443");
        let t = b.resolve("https://example.com?q").unwrap();
        assert_eq!(parts(&t), (Scheme::Https, "example.com", 443, "/?q"));
        let t = b.resolve("  //static.example.org/f.ico \n").unwrap();
        assert_eq!(
            parts(&t),
            (Scheme::Https, "static.example.org", 443, "/f.ico")
        );
        assert_eq!(t.host_header(), "static.example.org");
    }

    #[test]
    fn relative_references_use_the_base_request() {
        let b = base();
        assert_eq!(b.resolve("/favicon.png").unwrap().path(), "/favicon.png");
        assert_eq!(b.resolve("img/f.png").unwrap().path(), "/dir/img/f.png");
        assert_eq!(b.resolve("?v=2").unwrap().path(), "/dir/page?v=2");
        assert_eq!(b.resolve("../f.png").unwrap().path(), "/dir/../f.png");
        let r = b.resolve("f.png#x").unwrap();
        assert_eq!(parts(&r), (Scheme::Https, "example.com", 443, "/dir/f.png"));
        let http = b.with_scheme(Scheme::Http, 80);
        let r = http.resolve("/a.ico").unwrap();
        assert_eq!(parts(&r), (Scheme::Http, "example.com", 80, "/a.ico"));
        let root = b.with_path("/");
        assert_eq!(root.resolve("f.ico").unwrap().path(), "/f.ico");
    }

    #[test]
    fn refusals() {
        let b = base();
        let long = format!("/{}", "a".repeat(MAX_REFERENCE_LEN));
        for (reference, error) in [
            ("", TargetError::Length),
            ("   ", TargetError::Length),
            (long.as_str(), TargetError::Length),
            ("data:image/png;base64,AAAA", TargetError::Scheme),
            ("javascript:alert(1)", TargetError::Scheme),
            ("ftp://example.com/f.ico", TargetError::Scheme),
            ("file:///etc/passwd", TargetError::Scheme),
            ("https:example.com/f.ico", TargetError::Scheme),
            ("https://user:pw@example.com/", TargetError::Host),
            ("https://[::1]/", TargetError::Host),
            ("https://127.0.0.1@evil/", TargetError::Host),
            ("https://exa_mple.com/", TargetError::Host),
            ("https:///path", TargetError::Host),
            ("https://ex%61mple.com/", TargetError::Host),
            ("https://b\u{fc}cher.de/", TargetError::Host),
            ("https://example.com:8080/", TargetError::Port),
            ("https://example.com:22/", TargetError::Port),
            ("https://example.com:/", TargetError::Port),
            ("https://example.com:0443/", TargetError::Port),
            ("https://example.com:99999/", TargetError::Port),
            ("https://example.com:+443/", TargetError::Port),
            ("/a b", TargetError::Character),
            ("/a\\b", TargetError::Character),
            ("/a\"b", TargetError::Character),
            ("/<script>", TargetError::Character),
            ("/caf\u{e9}.png", TargetError::Character),
            ("/a\r\nHost: evil", TargetError::Character),
            ("https://example.com/a\tb", TargetError::Character),
        ] {
            assert_eq!(b.resolve(reference), Err(error), "{reference:?}");
        }
    }

    #[test]
    fn debug_prints_no_host_or_path() {
        let t = base()
            .resolve("https://secret-bank.example/private")
            .unwrap();
        let printed = format!("{t:?}");
        assert!(
            !printed.contains("secret") && !printed.contains("private"),
            "{printed}"
        );
    }
}
