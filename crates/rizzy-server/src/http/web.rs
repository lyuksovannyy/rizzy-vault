//! The `web` role (ADR 0010 §1, §4; threat model §7.7).
//!
//! ADR 0010 §4 embeds the web vault in the binary behind the `embed-web` cargo feature, off by
//! default, and says: "Without the feature, `web` serves a fixed page saying that this build has
//! no web vault."
//!
//! - **Without `embed-web`** (every Rust CI job; no JavaScript toolchain needed): `GET` or
//!   `HEAD` of `/` or `/index.html` answers [`PLACEHOLDER_PAGE`]. This is exactly ADR 0028
//!   item 15.
//! - **With `embed-web`**: the same two paths answer the web vault's `index.html`, and the
//!   fixed list of built files in [`ASSETS`] is served at its own paths (`/assets/app.js`,
//!   the core Worker, the wasm module, the stylesheet). The build of `apps/web` must exist
//!   first (`pnpm --filter @rizzy-vault/web build` writes `apps/web/dist/`); each file is
//!   embedded with `include_bytes!`, so a missing one fails the compile, and the Vite build
//!   fails when its output holds any other file (`apps/web/vite.config.ts`).
//!
//! **Reading of ADR 0028 item 15 with the feature on.** Item 15 lists only `/` and
//! `/index.html`, which is all a build without the web vault has. The web vault cannot run
//! from those two paths: its CSP ([`super::security::WEB_CSP`], INV-49) refuses inline script
//! and style, and ADR 0013 §4 runs the core in a dedicated Worker, which needs a script URL of
//! its own. ADR 0010 §4 embeds "web assets" (plural) for that reason. This module keeps item
//! 15's reason (§7.7 "E": nothing read from disk, no path built from the request) and serves,
//! in addition to the two page paths, exactly the paths of [`ASSETS`], matched as whole
//! strings against a table fixed at compile time. Every other path outside `/api/` stays a
//! plain-text `404`. This reading is reported to the owner: item 15 needs an amendment (a new
//! ADR, ADR 0020 point 9) naming the asset paths.
//!
//! **What is served.** `GET` or `HEAD` of a served path answers it; every other path outside
//! `/api/` answers a plain-text `404`, whatever the method. Any other method on a served path
//! answers a plain-text `405` (this crate's reading: item 15 names no answer for it, and item 3
//! gives `405` to a method a route does not serve). Every answer carries the web vault's CSP
//! and the common headers ([`super::security`], INV-49). The embedded files carry
//! `Cache-Control: no-cache`: their names have no content hash, so a browser must revalidate
//! them to pick up a new release (and, with no validator sent, it fetches them again).
//! The placeholder page has no script, no style and no external reference, so it renders under
//! that policy; the web vault is built to it (no inline script or style, `'self'` only, the
//! Worker's script URL through a Trusted Types policy).

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, StatusCode, Uri};
use axum::response::Response;

use super::security;

/// The fixed page of a build without the web vault (ADR 0010 §4).
pub const PLACEHOLDER_PAGE: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n\
<meta charset=\"utf-8\">\n<title>rizzy-vault</title>\n</head>\n<body>\n\
<h1>rizzy-vault</h1>\n<p>This server build has no web vault. Use a rizzy-vault client.</p>\n\
</body>\n</html>\n";

/// One embedded file of the web vault, served from memory at `path`.
#[derive(Debug)]
pub struct Asset {
    /// The request path, matched exactly (`/assets/app.js`).
    pub path: &'static str,
    /// The `Content-Type` it is served with.
    pub content_type: &'static str,
    /// The file's bytes.
    pub body: &'static [u8],
}

/// Embeds one file of `apps/web/dist/` (the path under `dist/` is the URL path).
#[cfg(feature = "embed-web")]
macro_rules! asset {
    ($path:literal, $content_type:literal) => {
        Asset {
            path: concat!("/", $path),
            content_type: $content_type,
            body: include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../apps/web/dist/",
                $path
            )),
        }
    };
}

/// The web vault's files besides `index.html`, exactly as `apps/web/assets.ts` lists them
/// (its test checks that the two lists agree). Empty without `embed-web`.
#[cfg(feature = "embed-web")]
pub const ASSETS: &[Asset] = &[
    asset!("assets/app.js", "text/javascript; charset=utf-8"),
    asset!("assets/style.css", "text/css; charset=utf-8"),
    asset!("assets/core-worker.js", "text/javascript; charset=utf-8"),
    asset!("assets/rizzy_core_bg.wasm", "application/wasm"),
];

/// The web vault's files besides `index.html`: none in a build without `embed-web`.
#[cfg(not(feature = "embed-web"))]
pub const ASSETS: &[Asset] = &[];

/// The page at `/` and `/index.html`: the web vault's `index.html`.
#[cfg(feature = "embed-web")]
pub const INDEX_PAGE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../apps/web/dist/index.html"
));

/// The page at `/` and `/index.html`: [`PLACEHOLDER_PAGE`] without `embed-web`.
#[cfg(not(feature = "embed-web"))]
pub const INDEX_PAGE: &[u8] = PLACEHOLDER_PAGE.as_bytes();

/// Whether this build embeds the web vault.
pub const EMBEDS_WEB_VAULT: bool = cfg!(feature = "embed-web");

/// What a path serves: its content type and bytes, or `None` for a `404`.
fn lookup(path: &str) -> Option<(&'static str, &'static [u8])> {
    if matches!(path, "/" | "/index.html") {
        return Some(("text/html; charset=utf-8", INDEX_PAGE));
    }
    ASSETS
        .iter()
        .find(|asset| asset.path == path)
        .map(|asset| (asset.content_type, asset.body))
}

/// Answers one request to the `web` role (module docs).
#[must_use]
pub fn respond(method: &Method, uri: &Uri) -> Response {
    let found = lookup(uri.path());
    let (status, content_type, body): (StatusCode, &'static str, &'static [u8]) = match found {
        None => (
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            b"not found\n",
        ),
        Some(_) if method != Method::GET && method != Method::HEAD => (
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            b"method not allowed\n",
        ),
        Some((content_type, body)) => (StatusCode::OK, content_type, body),
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
    if EMBEDS_WEB_VAULT && status == StatusCode::OK {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    security::add_web_csp(headers);
    response
}

#[cfg(test)]
mod tests {
    //! The path table: exact matches only, nothing built from the request.

    use super::*;

    #[test]
    fn only_the_listed_paths_are_served() {
        assert!(lookup("/").is_some());
        assert!(lookup("/index.html").is_some());
        for asset in ASSETS {
            assert!(asset.path.starts_with("/assets/"));
            assert!(lookup(asset.path).is_some());
            assert!(!asset.body.is_empty(), "{}", asset.path);
        }
        for path in [
            "",
            "/index.htm",
            "/INDEX.HTML",
            "/assets",
            "/assets/",
            "/assets/../index.html",
            "/assets/app.js/",
            "/assets//app.js",
            "/assets/APP.JS",
            "/assets/app.js%00",
            "/favicon.ico",
            "/api/meta",
        ] {
            assert!(lookup(path).is_none(), "{path}");
        }
        assert_eq!(ASSETS.is_empty(), !EMBEDS_WEB_VAULT);
        assert_eq!(INDEX_PAGE == PLACEHOLDER_PAGE.as_bytes(), !EMBEDS_WEB_VAULT);
    }

    #[test]
    fn a_wrong_method_on_a_served_path_is_405() {
        let uri: Uri = "/index.html".parse().unwrap_or_default();
        let reply = respond(&Method::POST, &uri);
        assert_eq!(reply.status(), StatusCode::METHOD_NOT_ALLOWED);
        let uri: Uri = "/nothing".parse().unwrap_or_default();
        assert_eq!(respond(&Method::POST, &uri).status(), StatusCode::NOT_FOUND);
    }
}
