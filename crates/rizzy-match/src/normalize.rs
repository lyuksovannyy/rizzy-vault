// SPDX-License-Identifier: AGPL-3.0-only

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
        //
        // Strip *every* trailing dot, not just one: `url` 2.5.8's own host parser keeps a run
        // of trailing dots in `host_str()` verbatim (confirmed against the pinned version —
        // `Url::parse("https://example.com../").host_str() == Some("example.com..")`), so
        // `strip_suffix('.')` left one dot behind for any run of two or more. That dot then
        // reached `suffix::registrable_domain` below, where the `psl` crate's eTLD+1 algorithm
        // degenerates on it: `example.com..` and `evil.com...` (after the single strip) both
        // computed the bogus registrable domain `"com."`, colliding two unrelated hosts, and
        // `co.uk...` computed `"uk."` instead of `None`, defeating the bare-public-suffix rule
        // (ADR 0037 §4, INV-38). `trim_end_matches` removes the whole run, so a bare run of
        // dots (`"....../"`) also collapses to the empty host the length check below already
        // rejects, rather than surviving as a non-empty, all-dot "host".
        let host = raw_host.trim_end_matches('.');
        if host.is_empty() || host.len() > MAX_HOST_LEN {
            return Err(NormalizeError::HostTooLong);
        }
        let port = parsed.port().filter(|p| *p != scheme.default_port());
        // The `psl` crate's eTLD+1 algorithm has no concept of an IP address, and on one it
        // silently degenerates to "last two dot-separated components", colliding `192.168.1.1`
        // and `10.0.1.1` on the bogus "registrable domain" `1.1` (confirmed against the pinned
        // `psl` `=2.1.240`). An IP-literal host is therefore never passed to `psl::domain_str` at
        // all: it is its own "registrable domain" below, so the gate (`modes::registrable_gate`,
        // INV-38) degenerates to exact-IP equality instead of a PSL lookup, closing that
        // collision while still letting *Host*/*Exact* mode work for a self-hosted/intranet
        // login reached by IP literal.
        //
        // Classify the TRIMMED `host`, not `parsed.host()`'s classification of the untrimmed
        // `raw_host`: `url` 2.5.8's own host parser only recognises a dotted-decimal-looking
        // host as `Host::Ipv4` when it carries at most one trailing dot, and falls back to
        // `Host::Domain` for a run of two or more (confirmed against the pinned version).
        // Trusting that classification after trimming every trailing dot off `host` let an
        // IP-literal host with 2+ trailing dots reach `suffix::registrable_domain` below instead
        // of this branch, reopening the exact collision this comment describes for
        // `"192.168.1.1../"` and `"10.0.1.1../"` alike. Parsing `host` itself as an `IpAddr` is
        // trailing-dot-count-independent, so it stays correct for any run length.
        //
        // `host_str()` keeps an IPv6 literal's `[` `]` brackets (`"[::1]"`, confirmed against
        // the pinned version), which `IpAddr` never parses, so strip them first. Note this is
        // *not* merely cosmetic: without the strip, every IPv6 literal would misclassify as
        // non-IP here and fall through to the branches below instead of this one — it would
        // still land on the same final `Some(host)` only because `url`'s own WHATWG host
        // serializer (what actually produces `host_str()`, not `std`'s `Ipv6Addr::Display`,
        // which does special-case IPv4-mapped/-compatible addresses into dotted-quad form) never
        // renders an IPv6 host with a literal `.`, so `suffix::registrable_domain` below always
        // returns `None` for one and the dotless-hostname carve-out fires instead. Stripping the
        // brackets keeps every IPv6 literal on the IP-literal branch it was always on
        // (`matches!(parsed.host(), Some(url::Host::Ipv6(_)))`, pre-dating this diff) rather than
        // depending on that three-step coincidence to reach the same place.
        let ip_candidate = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host);
        let is_ip_literal = ip_candidate.parse::<core::net::IpAddr>().is_ok();
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
    // Run `raw` through `idna` *first*, with no pre-trim, then strip every trailing dot from
    // its OUTPUT. Trimming the raw input first (an earlier version of this function did
    // exactly that) only ever catches ASCII U+002E: the UTS-46 domain-to-ASCII algorithm
    // `idna::domain_to_ascii_cow` implements also treats U+3002 (IDEOGRAPHIC FULL STOP),
    // U+FF0E (FULLWIDTH FULL STOP) and U+FF61 (HALFWIDTH IDEOGRAPHIC FULL STOP) as label
    // separators and renders each one as a literal `.` in its output — dots that do not exist
    // in `raw` at all, so a pre-trim cannot see them (confirmed against the pinned `idna`
    // `1.1.0`: `domain_to_ascii_cow("a\u{3002}\u{3002}")` returns `Ok("a..")`). Pre-trimming
    // therefore left those idna-produced dots in the returned value, breaking both the
    // documented "no trailing dot" postcondition and idempotence: re-normalising that same
    // output ("a..") hit the ASCII trim this time and returned "a", so `f(f(x)) != f(x)`
    // (regression: `EquivalenceGroup::new` would store "a.." as a group member — its own
    // round-trip check only compares the one normalisation it runs — while
    // `EquivalenceGroup::decode`'s self-check, `normalize_domain(stored) == stored`, would
    // then reject that exact member as `Malformed` on every future load of the very list
    // `new` just built).
    //
    // Trimming the output instead reaches the fixed point in one pass: `idna` is already
    // idempotent on a dot-free ASCII A-label (its own contract), so normalising the trimmed
    // result again repeats the same no-op trim and returns the identical string. A run of
    // bare dots or separators (ASCII or not) collapses the same way a single one does —
    // `Empty`, never a shorter-but-still-dotted, non-empty intermediate value — because the
    // emptiness check below runs *after* the trim, not before it.
    let ascii = idna::domain_to_ascii_cow(raw.as_bytes(), AsciiDenyList::URL)
        .map_err(|_| DomainError::Invalid)?;
    let trimmed = ascii.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DomainError::Empty);
    }
    if trimmed.len() > MAX_HOST_LEN {
        return Err(DomainError::TooLong);
    }
    Ok(trimmed.to_owned())
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
    fn parse_strips_a_run_of_trailing_dots_from_the_host() {
        // Regression: `url` 2.5.8's host parser keeps a run of trailing dots in `host_str()`
        // verbatim, and `strip_suffix('.')` only ever removed one of them, so
        // `parse("https://example.com../").host()` used to return `"example.com."` — a host
        // that still carried a dot `NormalizedUrl`'s own doc promises are stripped. A run of
        // any length must collapse to the same dot-free host as zero or one trailing dot.
        let none = NormalizedUrl::parse("https://example.com/").unwrap();
        let one = NormalizedUrl::parse("https://example.com./").unwrap();
        let two = NormalizedUrl::parse("https://example.com../").unwrap();
        let five = NormalizedUrl::parse("https://example.com...../").unwrap();
        for u in [&one, &two, &five] {
            assert_eq!(u.host(), "example.com");
            assert_eq!(u, &none);
        }
    }

    #[test]
    fn registrable_domain_does_not_collide_across_hosts_with_trailing_dot_runs() {
        // Regression: with the single-strip bug, `parse("https://example.com.../")` and
        // `parse("https://evil.com.../")` both left two trailing dots in `host` after
        // stripping one, and `psl::domain_str` degenerated on that leftover run to the same
        // bogus registrable domain `"com."` for both — colliding two unrelated sites under
        // INV-38's own gate. Trimming the whole run keeps them distinct.
        let example = NormalizedUrl::parse("https://example.com.../").unwrap();
        let evil = NormalizedUrl::parse("https://evil.com.../").unwrap();
        assert_eq!(example.registrable_domain(), Some("example.com"));
        assert_eq!(evil.registrable_domain(), Some("evil.com"));
        assert_ne!(example.registrable_domain(), evil.registrable_domain());
    }

    #[test]
    fn ip_literal_registrable_domain_does_not_collide_across_trailing_dot_runs() {
        // Regression: `is_ip_literal` was derived from `parsed.host()`'s classification of the
        // UNTRIMMED `raw_host`, and `url` 2.5.8 only classifies a dotted-decimal-looking host as
        // `Host::Ipv4` when it carries at most one trailing dot; with two or more it falls back
        // to `Host::Domain`. The trimmed `host` string then reached `suffix::registrable_domain`
        // instead of the IP-literal branch, so two different IP-literal hosts each carrying a
        // run of two or more trailing dots degenerated to the same bogus `psl`-on-an-IP
        // registrable domain — the exact collision the IP-literal carve-out above exists to
        // close, reopened for this one shape.
        let a = NormalizedUrl::parse("https://192.168.1.1../").unwrap();
        let b = NormalizedUrl::parse("https://10.0.1.1../").unwrap();
        assert_ne!(a.registrable_domain(), b.registrable_domain());
        assert_eq!(a.registrable_domain(), Some("192.168.1.1"));
        assert_eq!(b.registrable_domain(), Some("10.0.1.1"));
        assert_eq!(
            a.registrable_domain(),
            NormalizedUrl::parse("https://192.168.1.1/")
                .unwrap()
                .registrable_domain()
        );
    }

    #[test]
    fn bare_suffix_with_a_trailing_dot_run_still_has_no_registrable_domain() {
        // Regression: the single-strip bug left `co.uk..` as `host` for `"co.uk.../"`, and
        // `psl::domain_str("co.uk..")` computed `Some("uk.")` instead of `None` — defeating
        // the bare-public-suffix rule (INV-38) for any input with two or more trailing dots.
        assert_eq!(
            NormalizedUrl::parse("https://co.uk.../")
                .unwrap()
                .registrable_domain(),
            None
        );
    }

    #[test]
    fn an_all_dot_host_is_rejected_rather_than_kept_as_a_degenerate_host() {
        // A host that is nothing but dots collapses to the empty string once every trailing
        // dot is trimmed (there is no non-dot character left to not be "trailing"), which the
        // existing empty-host check must still catch — it must never survive as a non-empty,
        // all-dot "host" the registrable-domain gate (or anything else) could later compare.
        assert_eq!(
            NormalizedUrl::parse("https://....../").unwrap_err(),
            NormalizeError::HostTooLong
        );
    }

    #[test]
    fn trailing_dot_runs_never_change_which_hosts_share_a_registrable_domain() {
        // The general statement the two regressions above are concrete instances of: the
        // number of trailing dots on a host (zero or more, ASCII) must never change whether
        // two hosts' registrable domains are equal. Same base host, any dot count: always
        // equal. Different base hosts, any dot counts: never equal.
        let dot_counts = 0..=4;
        for n in dot_counts.clone() {
            let a =
                NormalizedUrl::parse(&format!("https://example.com{}/", ".".repeat(n))).unwrap();
            assert_eq!(a.registrable_domain(), Some("example.com"));
            for m in dot_counts.clone() {
                let b = NormalizedUrl::parse(&format!("https://evil.example{}/", ".".repeat(m)))
                    .unwrap();
                assert_ne!(a.registrable_domain(), b.registrable_domain());
            }
        }
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

    #[test]
    fn normalize_domain_rejects_dot_only_input_regardless_of_run_length() {
        // Regression: `normalize_domain` used to strip only one trailing dot
        // (`strip_suffix`), so a run of two or more dots left one dot behind ("..": one dot
        // left after stripping one), which `idna` happily accepts as the non-empty domain
        // ".". That broke the function's own documented postcondition ("no trailing dot")
        // on the very first call, and made it non-idempotent: re-normalising "." (the
        // output of normalizing "..") hits the single-dot path and correctly returns
        // `Empty`, so `f(f("..")) != f("..")`. Every run of bare dots must normalise the
        // same way a single dot does: `Empty`, not a degenerate non-empty domain.
        assert_eq!(normalize_domain(".").unwrap_err(), DomainError::Empty);
        assert_eq!(normalize_domain("..").unwrap_err(), DomainError::Empty);
        assert_eq!(normalize_domain("...").unwrap_err(), DomainError::Empty);
        assert_eq!(normalize_domain(".....").unwrap_err(), DomainError::Empty);
    }

    #[test]
    fn normalize_domain_strips_dots_idna_itself_produces_from_separator_code_points() {
        // Regression: `idna::domain_to_ascii_cow` treats U+3002 (IDEOGRAPHIC FULL STOP),
        // U+FF0E (FULLWIDTH FULL STOP) and U+FF61 (HALFWIDTH IDEOGRAPHIC FULL STOP) as label
        // separators and renders each one as a literal ASCII `.` in its *output* — dots that
        // never existed in the raw input, so a pre-idna trim of the raw string cannot see
        // them. `normalize_domain("a\u{3002}\u{3002}")` used to return `Ok("a..")`: non-empty,
        // but still carrying a trailing dot, and non-idempotent (re-normalising "a.." hit the
        // ASCII-only path and returned "a"). Trimming idna's own output reaches "a" directly.
        for separator in ['\u{3002}', '\u{ff0e}', '\u{ff61}'] {
            let doubled = format!("a{separator}{separator}");
            assert_eq!(
                normalize_domain(&doubled).as_deref(),
                Ok("a"),
                "{doubled:?}"
            );
            let single = format!("a{separator}");
            assert_eq!(normalize_domain(&single).as_deref(), Ok("a"), "{single:?}");
            // A bare run of separators, with nothing before it, normalises to `Empty` the
            // same way a bare run of ASCII dots does.
            let bare = separator.to_string().repeat(3);
            assert_eq!(normalize_domain(&bare).unwrap_err(), DomainError::Empty);
        }
    }

    #[test]
    fn normalize_domain_is_idempotent_on_a_concrete_regression_case() {
        // Companion to `normalized_string_is_idempotent` below (which only covers
        // `NormalizedUrl`, not `normalize_domain`): normalising `normalize_domain`'s own
        // output again must give the same value back, the property the fuzz target
        // `url_normalize` checks and the one this exact input ("..") used to break.
        for raw in [
            ".",
            "..",
            "...",
            "example.com",
            "example.com.",
            "EXAMPLE.COM..",
            "a\u{3002}\u{3002}",
            "a\u{ff0e}\u{ff0e}",
            "a\u{ff61}\u{ff61}",
            "\u{3002}\u{3002}",
        ] {
            if let Ok(first) = normalize_domain(raw) {
                assert_eq!(normalize_domain(&first).as_deref(), Ok(first.as_str()));
            }
        }
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
        fn normalized_string_is_idempotent(
            // A trailing run of 0..=3 ASCII dots on the generated host (`\\.{0,3}` after the
            // suffix label): mirrors the fuzz target's own idempotence check over an input
            // family the single-trailing-dot bug used to break.
            host in "[a-z0-9]{1,10}\\.(com|net|org)\\.{0,3}",
            path in "/[a-z0-9/]{0,20}",
        ) {
            let raw = format!("https://{host}{path}");
            if let Ok(first) = NormalizedUrl::parse(&raw) {
                let again = NormalizedUrl::parse(&first.normalized_string()).unwrap();
                assert_eq!(first, again);
                assert_eq!(first.normalized_string(), again.normalized_string());
                assert!(!first.host().ends_with('.'));
            }
        }

        #[test]
        fn registrable_domain_is_invariant_under_trailing_dot_runs(
            dots_a in 0usize..5,
            dots_b in 0usize..5,
        ) {
            // INV-38's own statement, generalised: the number of trailing dots on a host must
            // never change whether two hosts' registrable domains are equal. `example.com`
            // under any dot-run length always shares its registrable domain with
            // `example.com` under any *other* dot-run length, and never with the unrelated
            // `evil.example` under any dot-run length either — the exact family the
            // `example.com...`/`evil.com...` collision regression above pins concretely.
            let same_a = NormalizedUrl::parse(&format!("https://example.com{}/", ".".repeat(dots_a)))
                .unwrap();
            let same_b = NormalizedUrl::parse(&format!("https://example.com{}/", ".".repeat(dots_b)))
                .unwrap();
            let other = NormalizedUrl::parse(&format!("https://evil.example{}/", ".".repeat(dots_b)))
                .unwrap();
            assert_eq!(same_a.registrable_domain(), same_b.registrable_domain());
            assert_ne!(same_a.registrable_domain(), other.registrable_domain());
        }

        #[test]
        fn normalize_domain_output_is_idempotent(
            dots in 0usize..6,
            host in "[a-z0-9]{0,10}",
            sep_idx in 0u8..4,
        ) {
            // `host` with a trailing run of 0..=5 of one of the four code points idna treats
            // as a label separator: ASCII U+002E, and the three non-ASCII separators
            // (U+3002, U+FF0E, U+FF61) idna's own domain-to-ASCII processing renders as a
            // literal `.` in its output. Covers the whole family the regressions above pin
            // concrete cases for, ASCII and non-ASCII alike.
            let separator = ['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'][usize::from(sep_idx)];
            let raw = format!("{host}{}", separator.to_string().repeat(dots));
            if let Ok(first) = normalize_domain(&raw) {
                assert_eq!(normalize_domain(&first).as_deref(), Ok(first.as_str()));
                assert!(!first.is_empty());
                assert!(!first.ends_with('.'));
            }
        }
    }
}
