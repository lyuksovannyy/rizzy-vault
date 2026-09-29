//! Response security headers (threat model INV-49, §7.7, §7.14; INV-52).
//!
//! **Every response** gets, unless the handler set its own:
//! - `Strict-Transport-Security: max-age=31536000`. No `includeSubDomains` and no `preload`: a
//!   self-hoster's other subdomains are not the server's to pin (this crate's reading of "HSTS",
//!   INV-49). Browsers ignore it over plain HTTP, so a local test is not affected.
//! - `X-Content-Type-Options: nosniff` (INV-49).
//! - `Referrer-Policy: no-referrer` (§7.7 "I").
//! - `X-Frame-Options: DENY`, for browsers that predate `frame-ancestors`.
//! - `Content-Security-Policy`: [`API_CSP`], which allows nothing to load, unless the handler
//!   set the web vault's [`WEB_CSP`].
//!
//! **API responses** also get `Cache-Control: no-store`: they carry session tokens and
//! ciphertext, which no cache between the client and the server should keep.
//!
//! **The web vault's CSP** ([`WEB_CSP`], INV-49): no inline script and no `eval`, except
//! `'wasm-unsafe-eval'` for the wasm core; no third-party origin anywhere (`'self'` only);
//! `frame-ancestors 'none'`; plus `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`
//! and Trusted Types for script sinks where the browser supports them (§7.1 "T": "Trusted Types
//! where supported"). Inline styles are refused too. The M1 step 5 web vault is built to this
//! policy; a change to it is a security change.

use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue};

/// The web vault's Content Security Policy (module docs, INV-49).
pub const WEB_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; \
worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; \
frame-ancestors 'none'; require-trusted-types-for 'script'";

/// The policy of every other response: nothing may load, nothing may frame it.
pub const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// The HSTS value (module docs).
pub const HSTS: &str = "max-age=31536000";

/// Adds the headers every response carries, keeping a CSP the handler set.
pub fn add_common(headers: &mut HeaderMap) {
    headers.insert(STRICT_TRANSPORT_SECURITY, HeaderValue::from_static(HSTS));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    if !headers.contains_key(CONTENT_SECURITY_POLICY) {
        headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(API_CSP));
    }
}

/// Adds `Cache-Control: no-store` (API responses).
pub fn add_no_store(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// Sets the web vault's CSP.
pub fn add_web_csp(headers: &mut HeaderMap) {
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(WEB_CSP));
}

#[cfg(test)]
mod tests {
    //! The web CSP says what INV-49 requires, and no more is allowed.

    use super::*;

    #[test]
    fn web_csp_meets_inv_49() {
        let directives: Vec<&str> = WEB_CSP.split(';').map(str::trim).collect();
        assert!(directives.contains(&"script-src 'self' 'wasm-unsafe-eval'"));
        assert!(directives.contains(&"frame-ancestors 'none'"));
        assert!(directives.contains(&"default-src 'none'"));
        assert!(!WEB_CSP.contains("unsafe-inline"));
        assert!(!WEB_CSP.contains("'unsafe-eval'"));
        assert!(!WEB_CSP.contains("http"));
        assert!(!WEB_CSP.contains('*'));
        assert!(HeaderValue::from_str(WEB_CSP).is_ok());
    }
}
