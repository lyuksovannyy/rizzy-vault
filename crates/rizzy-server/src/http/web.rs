// SPDX-License-Identifier: AGPL-3.0-only

//! The `web` role (ADR 0010 §1, §4; [ADR 0049]; threat model §7.7).
//!
//! ADR 0010 §4 embeds the web vault in the binary behind the `embed-web` cargo feature, off by
//! default, and says: "Without the feature, `web` serves a fixed page saying that this build has
//! no web vault."
//!
//! - **Without `embed-web`** (every Rust CI job; no JavaScript toolchain needed): `GET` or
//!   `HEAD` of `/` or `/index.html` answers [`PLACEHOLDER_PAGE`], and the asset rows are not
//!   served (`404`).
//! - **With `embed-web`**: the same two paths answer the web vault's `index.html`, and the
//!   fixed list of built files in [`ASSETS`] is served at its own paths (`/assets/app.js`,
//!   the core Worker, the wasm module, the stylesheet). The build of `apps/web` must exist
//!   first (`pnpm --filter @rizzy-vault/web build` writes `apps/web/dist/`); each file is
//!   embedded with `include_bytes!`, so a missing one fails the compile, and the Vite build
//!   fails when its output holds any other file (`apps/web/vite.config.ts`).
//!
//! **The route table** ([ADR 0049], which supersedes ADR 0028 item 15 in full). The role answers
//! only from [`ROUTES`], fixed at compile time and matched against the request-target's path
//! byte for byte: no decoding, no normalisation. A row is a [`Route::Literal`] path, matched
//! exactly, or a [`Route::Segment`]: a fixed prefix plus exactly one path segment whose value
//! selects nothing that is served, reaches no filesystem, builds no redirect or echoed string
//! and is never logged (the access log names the role, `web`, never the path: `super::fallback`).
//! The M1 table is ADR 0049's, literal rows only: `/` and `/index.html`, and the four asset
//! paths of [`ASSET_PATHS`]. A row is added only by an Accepted ADR that names it, recorded as an
//! amendment of ADR 0049 ("Extending the table"); the M5 share link (`/s/<share_id>`, ADR 0064)
//! is such a later row, and nothing of it is built here. A test pins [`ROUTES`] to the ADR's
//! table.
//!
//! **What is served.** `GET` or `HEAD` of a row answers it; every other path outside `/api/`
//! answers a plain-text `404`, whatever the method. Any other method on a row answers a
//! plain-text `405` (ADR 0049: item 3's status code, not its `/api/` JSON body). Every answer
//! this table gives, the page, an asset, the `404` and the `405`, carries `WEB_CSP` and the
//! common headers ([`super::security`], INV-49). The embedded files carry
//! `Cache-Control: no-cache`: their names have no content hash, so a browser must revalidate
//! them to pick up a new release (and, with no validator sent, it fetches them again).
//! The placeholder page has no script, no style and no external reference, so it renders under
//! that policy; the web vault is built to it (no inline script or style, `'self'` only, the
//! Worker's script URL through a Trusted Types policy).
//!
//! [ADR 0049]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0049-web-role-route-table.md

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

/// One row of the route table ([ADR 0049] "The route table"). Matched against the
/// request-target's path byte for byte, with no decoding and no normalisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// A literal path, matched exactly (`/`, `/index.html`, each asset path).
    Literal(&'static str),
    /// A fixed prefix ending in `/`, plus exactly one non-empty path segment (no `/` in it).
    /// The segment's value never selects what is served (a row serves one fixed response),
    /// never reaches the filesystem, never builds a redirect or an echoed string, and is never
    /// logged. No M1 row has this shape; ADR 0049 "Extending the table" adds one only through an
    /// Accepted ADR that names it.
    Segment(&'static str),
}

impl Route {
    /// Whether `path` is this row.
    #[must_use]
    pub fn matches(self, path: &str) -> bool {
        match self {
            Self::Literal(literal) => path == literal,
            Self::Segment(prefix) => path
                .strip_prefix(prefix)
                .is_some_and(|segment| !segment.is_empty() && !segment.contains('/')),
        }
    }
}

/// What a row serves: one fixed response, whatever the path that matched it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Serves {
    /// [`INDEX_PAGE`].
    Index,
    /// The embedded file at this path, or `404` in a build without `embed-web`.
    Asset(&'static str),
}

/// The embedded-asset rows of ADR 0049's M1 table, the same in every build: [`ASSETS`] serves
/// them under `embed-web`, and a build without it answers them `404`.
pub const ASSET_PATHS: [&str; 4] = [
    "/assets/app.js",
    "/assets/style.css",
    "/assets/core-worker.js",
    "/assets/rizzy_core_bg.wasm",
];

/// The route table with what each row serves (ADR 0049 "The M1 table"). Adding, removing or
/// renaming a row needs an Accepted ADR and an amendment of ADR 0049 (module docs).
const TABLE: [(Route, Serves); 6] = [
    (Route::Literal("/"), Serves::Index),
    (Route::Literal("/index.html"), Serves::Index),
    (
        Route::Literal(ASSET_PATHS[0]),
        Serves::Asset(ASSET_PATHS[0]),
    ),
    (
        Route::Literal(ASSET_PATHS[1]),
        Serves::Asset(ASSET_PATHS[1]),
    ),
    (
        Route::Literal(ASSET_PATHS[2]),
        Serves::Asset(ASSET_PATHS[2]),
    ),
    (
        Route::Literal(ASSET_PATHS[3]),
        Serves::Asset(ASSET_PATHS[3]),
    ),
];

/// The rows of the route table, in order.
pub const ROUTES: [Route; 6] = {
    let mut routes = [Route::Literal(""); 6];
    let mut i = 0;
    while i < TABLE.len() {
        routes[i] = TABLE[i].0;
        i += 1;
    }
    routes
};

/// The row `path` matches, if any.
fn route_of(path: &str) -> Option<Serves> {
    TABLE
        .iter()
        .find(|(route, _)| route.matches(path))
        .map(|(_, serves)| *serves)
}

/// What a path serves: its content type and bytes, or `None` for a `404`.
fn lookup(path: &str) -> Option<(&'static str, &'static [u8])> {
    match route_of(path)? {
        Serves::Index => Some(("text/html; charset=utf-8", INDEX_PAGE)),
        Serves::Asset(row) => ASSETS
            .iter()
            .find(|asset| asset.path == row)
            .map(|asset| (asset.content_type, asset.body)),
    }
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
    //! The route table: exactly ADR 0049's rows, exact matches only, nothing built from the
    //! request.

    use super::*;

    /// ADR 0049's M1 table and its amendments: every backticked path that opens a table row.
    fn adr_rows() -> Vec<String> {
        let adr = include_str!("../../../../docs/adr/0049-web-role-route-table.md");
        let mut rows = Vec::new();
        for line in adr.lines().filter(|l| l.starts_with("| `/")) {
            let first = line.split('|').nth(1).unwrap_or_default();
            for (i, part) in first.split('`').enumerate() {
                if i % 2 == 1 {
                    rows.push(part.to_owned());
                }
            }
        }
        rows
    }

    #[test]
    fn the_table_is_adr_0049s() {
        let mut ours: Vec<String> = ROUTES
            .iter()
            .map(|r| match r {
                Route::Literal(p) | Route::Segment(p) => (*p).to_owned(),
            })
            .collect();
        let mut adr = adr_rows();
        ours.sort();
        adr.sort();
        assert_eq!(ours, adr);
        assert!(
            ROUTES.iter().all(|r| matches!(r, Route::Literal(_))),
            "M1 has literal rows only"
        );
        // The embedded files are the asset rows, in every build (the `asset!` calls below are
        // what `embed-web` embeds; `apps/web/test/assets.test.ts` pins them to the Vite build).
        let source = include_str!("web.rs");
        let mut embedded: Vec<String> = source
            .split("asset!(\"")
            .skip(1)
            .filter_map(|s| s.split('"').next())
            .map(|p| format!("/{p}"))
            .collect();
        let mut assets: Vec<String> = ASSET_PATHS.iter().map(|p| (*p).to_owned()).collect();
        embedded.sort();
        assets.sort();
        assert_eq!(embedded, assets);
        for asset in ASSETS {
            assert!(ASSET_PATHS.contains(&asset.path), "{}", asset.path);
        }
    }

    #[test]
    fn a_segment_row_takes_exactly_one_segment() {
        let row = Route::Segment("/s/");
        assert!(row.matches("/s/abc"));
        for path in [
            "/s/", "/s", "/s/abc/", "/s/a/b", "/s//", "/S/abc", "/x/s/abc",
        ] {
            assert!(!row.matches(path), "{path}");
        }
        // No such row in M1: the share link is not served.
        assert!(lookup("/s/abc").is_none());
    }

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
