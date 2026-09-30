//! The `web` role (ADR 0010 §1, §4; threat model §7.7).
//!
//! ADR 0010 §4 embeds the web vault in the binary behind the `embed-web` cargo feature, off by
//! default, and says: "Without the feature, `web` serves a fixed page saying that this build has
//! no web vault." The web vault itself (`apps/web`) is M1 step 5 and does not exist yet, so this
//! build has no `embed-web` feature at all and always serves that fixed page.
//!
//! **What is served** (ADR 0028 item 15). `GET` or `HEAD` of `/` or `/index.html` answers the
//! page; every other path outside `/api/` answers a plain-text `404`, whatever the method. Any
//! other method on the two page paths answers a plain-text `405` (this crate's reading: item 15
//! names no answer for it, and item 3 gives `405` to a method a route does not serve).
//! Nothing is read from the file system and no
//! path is built from the request (§7.7 "E": "Assets served from memory, with no filesystem
//! path built from the request"). Every answer carries the web vault's CSP and the common
//! headers ([`super::security`], INV-49). The page has no script, no style and no external
//! reference, so it renders under that policy.

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, Method, StatusCode, Uri};
use axum::response::Response;

use super::security;

/// The fixed page of a build without the web vault (ADR 0010 §4).
pub const PLACEHOLDER_PAGE: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n\
<meta charset=\"utf-8\">\n<title>rizzy-vault</title>\n</head>\n<body>\n\
<h1>rizzy-vault</h1>\n<p>This server build has no web vault. Use a rizzy-vault client.</p>\n\
</body>\n</html>\n";

/// Answers one request to the `web` role (module docs).
#[must_use]
pub fn respond(method: &Method, uri: &Uri) -> Response {
    let (status, content_type, body) = if !matches!(uri.path(), "/" | "/index.html") {
        (
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n",
        )
    } else if method != Method::GET && method != Method::HEAD {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            "method not allowed\n",
        )
    } else {
        (StatusCode::OK, "text/html; charset=utf-8", PLACEHOLDER_PAGE)
    };
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(body)
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    security::add_web_csp(headers);
    response
}
