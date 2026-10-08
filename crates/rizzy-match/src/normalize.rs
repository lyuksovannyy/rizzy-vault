//! URL normalisation (ADR 0037 §2) and bare-domain normalisation (ADR 0038 §1).
//!
//! [`NormalizedUrl::parse`] is the one entry point every match mode and security rule builds
//! on: scheme restricted to `http`/`https` (INV-42), host IDNA-processed to its A-label form
//! and lower-cased (the `url` crate already runs the WHATWG domain-to-ASCII algorithm — the
//! same algorithm `idna` 1.x implements — while parsing the host of a special-scheme URL, so
//! [`NormalizedUrl::host`] is already in A-label form; mixed-script input is therefore *never*
//! stored or displayed as decoded Unicode, which is the mitigation ADR 0037 §2 point 4 names
//! for homograph attacks), a trailing dot on the host stripped, the default port for the
//! scheme omitted, the path defaulted to `/`, and the registrable domain computed from the
//! compiled-in Public Suffix List snapshot ([`crate::suffix`]).
//!
//! [`normalize_domain`] is the separate, narrower path for a *bare* domain string that is not
//! a full URL: an equivalence-group entry (ADR 0038 §1) or a domain a person types into a
//! user-defined group. It calls the `idna` crate directly, because there is no URL for the
//! `url` crate's host parser to process.

use idna::AsciiDenyList;

use crate::error::{DomainError, MAX_HOST_LEN, MAX_URL_LEN, NormalizeError};
use crate::suffix;

/// The `http(s)` scheme of a normalised URL (ADR 0037 §2 point 2; INV-42 bans every other
/// scheme from matching or filling).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http://`.
    Http,
    /// `https://`.
    Https,
}

impl Scheme {
    /// The scheme's lower-case name, as it appears in a normalised URL.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// The scheme's default port (80, 443), omitted from a normalised URL carrying that port
    /// (ADR 0037 §2 point 5).
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// A URL normalised per ADR 0037 §2: scheme, A-label host, a non-default port only, the
/// registrable domain, and the path (kept for every mode; only *Starts with* and *Regex* use
/// it, ADR 0037 §2 point 6).
///
/// Comparisons between two values use the accessors below, never `Debug`: `Debug` exists for
/// logs and tests, not as a comparison key, and carries no secret (a URL is never secret data
/// in this project's threat model, ADR 0037 §1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedUrl {
    /// `http` or `https`.
    scheme: Scheme,
    /// The IDNA A-label host, lower-case, with any trailing dot stripped.
    host: String,
    /// `Some` only for a port other than the scheme's default (ADR 0037 §2 point 5).
    port: Option<u16>,
    /// The registrable domain (eTLD+1) of `host` against the compiled-in PSL snapshot
    /// ([`crate::suffix::registrable_domain`]). `None` when `host` is itself a public suffix
    /// or above one (`co.uk`, `github.io`, `com`): such a host has no registrable domain, so it
    /// can never pass the registrable-domain gate (ADR 0037 §4, INV-38) against anything,
    /// including another occurrence of the same bare suffix.
    ///
    /// An IP-literal host (`192.168.1.1`, `::1`) is never run through the PSL at all — it is
    /// `Some(host)`, the literal address itself, so two different IP hosts can never collide on
    /// a shared "registrable domain" the way two different IPv4 addresses sharing their last two
    /// octets otherwise would under the PSL's "unlisted TLD" fallback. An unqualified
    /// single-label hostname with no PSL suffix (`localhost`, a bare internal hostname) is
    /// treated the same way, `Some(host)`, so *Host*/*Exact* mode still work for it; a bare
    /// public suffix that does contain a dot (`co.uk`) stays `None`.
    registrable_domain: Option<String>,
    /// The normalised path: always starts with `/` (the `url` crate already defaults an empty
    /// path to `/` for a special scheme, ADR 0037 §2 point 6 "default paths"). Query and
    /// fragment are dropped unconditionally, for every mode, including *Regex* (ADR 0037 §2
    /// point 6: the full *normalised* URL, which never carries a query).
    path: String,
}

impl NormalizedUrl {
    /// Parses and normalises a raw URL (an item's `uri/<id>/value`, or the page the user is
    /// on).
    ///
    /// # Errors
    /// [`NormalizeError::TooLong`] if `raw` exceeds [`MAX_URL_LEN`], checked before parsing;
    /// [`NormalizeError::Parse`] if it is not an absolute URL the `url` crate accepts;
    /// [`NormalizeError::UnsupportedScheme`] if the scheme is not `http` or `https`;
    /// [`NormalizeError::NoHost`] if the URL has no host (unreachable for a parsed `http(s)`
    /// URL, kept for completeness); [`NormalizeError::HostTooLong`] if the host exceeds
    /// [`MAX_HOST_LEN`] after normalisation.
    pub fn parse(raw: &str) -> Result<Self, NormalizeError> {
        if raw.len() > MAX_URL_LEN {
            return Err(NormalizeError::TooLong);
        }
        let parsed = url::Url::parse(raw).map_err(|_| NormalizeError::Parse)?;
        let scheme = match parsed.scheme() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(NormalizeError::UnsupportedScheme),
        };
        let raw_host = parsed.host_str().ok_or(NormalizeError::NoHost)?;
        // The `url` crate already lower-cases and IDNA-processes the host of a special-scheme
        // URL into its A-label form. Only the trailing-dot strip (ADR 0037 §2 point 3) and the
        // length bound are this crate's own.
        let host = raw_host.strip_suffix('.').unwrap_or(raw_host);
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return Err(NormalizeError::HostTooLong);
        }
        let port = parsed.port().filter(|p| *p != scheme.default_port());
        // `url::Host` (not `host_str`) decides whether `host` is a domain name at all: the `psl`
        // crate's eTLD+1 algorithm has no concept of an IP address, and on one it silently
        // degenerates to "last two dot-separated components", colliding `192.168.1.1` and
        // `10.0.1.1` on the bogus "registrable domain" `1.1` (confirmed against the pinned `psl`
        // `=2.1.240`). An IP-literal host is therefore never passed to `psl::domain_str` at all:
        // it is its own "registrable domain" below, so the gate (`modes::registrable_gate`,
        // INV-38) degenerates to exact-IP equality instead of a PSL lookup, closing that
        // collision while still letting *Host*/*Exact* mode work for a self-hosted/intranet
        // login reached by IP literal.
        let is_ip_literal = matches!(parsed.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)));
        let registrable_domain = if is_ip_literal {
            Some(host.to_owned())
        } else {
            suffix::registrable_domain(host).or_else(|| {
                // A bare public suffix (`co.uk`, `com`) correctly has no registrable domain
                // (INV-38) and must stay `None`. A host with no dot at all is not a suffix of
                // anything the PSL knows about — it is an unqualified local hostname
                // (`localhost`, an internal hostname with no domain) — and the PSL's "unlisted
                // TLD" fallback (treat the last label as the suffix) also reports it as having no
                // registrable domain beneath it, which would otherwise fail the gate even for
                // *Host*/*Exact* mode against a byte-identical page. Treat it as its own
                // registrable domain instead, same as the IP-literal case above: the gate then
                // only ever matches that exact literal host, never a fabricated eTLD+1.
                (!host.contains('.')).then(|| host.to_owned())
            })
        };
        let path = parsed.path();
        let path = if path.is_empty() { "/" } else { path };
        Ok(Self {
            scheme,
            host: host.into(),
            port,
            registrable_domain,
            path: path.into(),
        })
    }

    /// The scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The IDNA A-label host, lower-case, no trailing dot.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, only when it is not the scheme's default.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The registrable domain (eTLD+1), or `None` when `host` is itself a public suffix or
    /// above one.
    #[must_use]
    pub fn registrable_domain(&self) -> Option<&str> {
        self.registrable_domain.as_deref()
    }

    /// The normalised path (always starts with `/`; never carries a query or fragment).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The full normalised URL: `scheme://host[:port]path`. *Exact* compares this value
    /// byte-for-byte; *Starts with* and *Regex* match against it (ADR 0037 §4; §2 point 6).
    #[must_use]
    pub fn normalized_string(&self) -> String {
        match self.port {
            Some(port) => format!(
                "{}://{}:{}{}",
                self.scheme.as_str(),
                self.host,
                port,
                self.path
            ),
            None => format!("{}://{}{}", self.scheme.as_str(), self.host, self.path),
        }
    }
}

/// Normalises a bare domain string (not a full URL) to its IDNA A-label form: lower-case,
/// punycode for any non-ASCII label, no trailing dot (ADR 0037 §2 point 3; ADR 0038 §1: group
/// domains are stored "each in normalized A-label form").
///
/// Used for an equivalence-group entry — built into the compiled-in global list by `cargo
/// xtask equivalence-list`, or typed by the account owner into a user-defined group — never
/// for a full URL, which goes through [`NormalizedUrl::parse`] instead.
///
/// # Errors
/// [`DomainError::TooLong`] if `raw` exceeds [`MAX_HOST_LEN`]; [`DomainError::Invalid`] if
/// `idna`'s domain-to-ASCII algorithm rejects it; [`DomainError::Empty`] if the result is
/// empty.
pub fn normalize_domain(raw: &str) -> Result<String, DomainError> {
    if raw.len() > MAX_HOST_LEN {
        return Err(DomainError::TooLong);
    }
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    let ascii = idna::domain_to_ascii_cow(trimmed.as_bytes(), AsciiDenyList::URL)
        .map_err(|_| DomainError::Invalid)?;
    if ascii.is_empty() {
        return Err(DomainError::Empty);
    }
    if ascii.len() > MAX_HOST_LEN {
        return Err(DomainError::TooLong);
    }
    Ok(ascii.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        for raw in ["ftp://example.com/", "javascript:alert(1)", "ssh://host/"] {
            assert_eq!(
                NormalizedUrl::parse(raw).unwrap_err(),
                NormalizeError::UnsupportedScheme
            );
        }
    }

    #[test]
    fn rejects_unparseable_input() {
        assert_eq!(
            NormalizedUrl::parse("not a url at all").unwrap_err(),
            NormalizeError::Parse
        );
    }

    #[test]
    fn rejects_oversized_input() {
        let huge = format!("https://example.com/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(
            NormalizedUrl::parse(&huge).unwrap_err(),
            NormalizeError::TooLong
        );
    }

    #[test]
    fn lowercases_host_and_strips_trailing_dot() {
        let a = NormalizedUrl::parse("https://EXAMPLE.com./path").unwrap();
        let b = NormalizedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(a.host(), "example.com");
        assert_eq!(a, b);
    }

    #[test]
    fn default_ports_are_omitted() {
        let http = NormalizedUrl::parse("http://example.com:80/").unwrap();
        let https = NormalizedUrl::parse("https://example.com:443/").unwrap();
        assert_eq!(http.port(), None);
        assert_eq!(https.port(), None);
    }

    #[test]
    fn non_default_port_is_kept_and_compared() {
        let a = NormalizedUrl::parse("https://example.com:8443/").unwrap();
        let b = NormalizedUrl::parse("https://example.com/").unwrap();
        assert_eq!(a.port(), Some(8443));
        assert_ne!(a.normalized_string(), b.normalized_string());
    }

    #[test]
    fn query_and_fragment_are_dropped() {
        let a = NormalizedUrl::parse("https://example.com/path?x=1#frag").unwrap();
        assert_eq!(a.normalized_string(), "https://example.com/path");
    }

    #[test]
    fn empty_path_defaults_to_root() {
        let a = NormalizedUrl::parse("https://example.com").unwrap();
        assert_eq!(a.path(), "/");
    }

    #[test]
    fn registrable_domain_examples() {
        assert_eq!(
            NormalizedUrl::parse("https://a.b.example.co.uk/")
                .unwrap()
                .registrable_domain(),
            Some("example.co.uk")
        );
        assert_eq!(
            NormalizedUrl::parse("https://co.uk/")
                .unwrap()
                .registrable_domain(),
            None
        );
        assert_eq!(
            NormalizedUrl::parse("https://github.io/")
                .unwrap()
                .registrable_domain(),
            None
        );
        assert_eq!(
            NormalizedUrl::parse("https://foo.github.io/")
                .unwrap()
                .registrable_domain(),
            Some("foo.github.io")
        );
    }

    #[test]
    fn idn_hosts_compare_by_a_label() {
        // "münchen.de" and its punycode form normalise to the same A-label host.
        let unicode = NormalizedUrl::parse("https://münchen.de/").unwrap();
        let punycode = NormalizedUrl::parse("https://xn--mnchen-3ya.de/").unwrap();
        assert_eq!(unicode.host(), "xn--mnchen-3ya.de");
        assert_eq!(unicode, punycode);
    }

    #[test]
    fn evil_lookalike_is_not_the_real_registrable_domain() {
        let evil = NormalizedUrl::parse("https://evil-youtube.com/").unwrap();
        let real = NormalizedUrl::parse("https://youtube.com/").unwrap();
        assert_ne!(evil.registrable_domain(), None);
        assert_ne!(evil.registrable_domain(), real.registrable_domain());
    }

    #[test]
    fn host_subdomain_takeover_lookalike_has_a_different_registrable_domain() {
        let lookalike = NormalizedUrl::parse("https://bank.com.evil.example/").unwrap();
        assert_eq!(lookalike.registrable_domain(), Some("evil.example"));
    }

    #[test]
    fn ip_literal_hosts_never_collide_on_a_shared_registrable_domain() {
        // Regression: `psl::domain_str` has no concept of an IP address and falls back to
        // "last two dot-separated components", which made `192.168.1.1` and `10.0.1.1` both
        // compute the bogus registrable domain `1.1`. Neither may equal the other now.
        let a = NormalizedUrl::parse("https://192.168.1.1/login").unwrap();
        let b = NormalizedUrl::parse("https://10.0.1.1/").unwrap();
        assert_ne!(a.registrable_domain(), b.registrable_domain());
        assert_eq!(a.registrable_domain(), Some("192.168.1.1"));
        assert_eq!(b.registrable_domain(), Some("10.0.1.1"));
    }

    #[test]
    fn ipv4_literal_same_host_has_a_registrable_domain_equal_to_itself() {
        let a = NormalizedUrl::parse("https://192.168.1.1/login").unwrap();
        let same = NormalizedUrl::parse("https://192.168.1.1/anything").unwrap();
        assert_eq!(a.registrable_domain(), same.registrable_domain());
    }

    #[test]
    fn ipv6_literal_host_has_a_registrable_domain_equal_to_itself() {
        let a = NormalizedUrl::parse("https://[::1]:8443/admin").unwrap();
        assert_eq!(a.registrable_domain(), Some(a.host()));
    }

    #[test]
    fn bare_single_label_hostname_is_its_own_registrable_domain() {
        // "localhost" and an unqualified internal hostname have no PSL suffix at all, but they
        // are not a *public* suffix either (unlike `co.uk`): treat the host as its own
        // registrable domain so Host/Exact mode keep working for a byte-identical page.
        let a = NormalizedUrl::parse("https://localhost:8443/admin").unwrap();
        assert_eq!(a.registrable_domain(), Some("localhost"));
        let b = NormalizedUrl::parse("https://nas/admin").unwrap();
        assert_eq!(b.registrable_domain(), Some("nas"));
        // Two different unqualified hostnames still never collide.
        assert_ne!(a.registrable_domain(), b.registrable_domain());
    }

    #[test]
    fn bare_public_suffix_with_a_dot_still_has_no_registrable_domain() {
        // Unchanged by the IP/single-label carve-out: `co.uk` has a dot and a real PSL rule, so
        // it must stay `None` (INV-38), never fall into the "no PSL suffix" self-domain case.
        assert_eq!(
            NormalizedUrl::parse("https://co.uk/")
                .unwrap()
                .registrable_domain(),
            None
        );
    }

    #[test]
    fn idn_homograph_is_not_the_real_registrable_domain() {
        // INV-38 "Verified by": an IDN homograph (Cyrillic а U+0430 for Latin a) must normalise
        // to a *different* A-label/registrable domain than the real brand domain, not just a
        // different string before normalisation.
        let homograph = NormalizedUrl::parse("https://\u{0430}pple.com/").unwrap();
        let real = NormalizedUrl::parse("https://apple.com/").unwrap();
        assert_ne!(homograph.host(), real.host());
        assert_ne!(homograph.registrable_domain(), real.registrable_domain());
    }

    proptest::proptest! {
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            if let Ok(s) = core::str::from_utf8(&bytes) {
                let _ = NormalizedUrl::parse(s);
                let _ = normalize_domain(s);
            }
        }

        #[test]
        fn normalized_string_is_idempotent(host in "[a-z0-9]{1,10}\\.(com|net|org)", path in "/[a-z0-9/]{0,20}") {
            let raw = format!("https://{host}{path}");
            if let Ok(first) = NormalizedUrl::parse(&raw) {
                let again = NormalizedUrl::parse(&first.normalized_string()).unwrap();
                assert_eq!(first, again);
                assert_eq!(first.normalized_string(), again.normalized_string());
            }
        }
    }
}
