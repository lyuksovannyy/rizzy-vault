// SPDX-License-Identifier: AGPL-3.0-only

//! The admin listener's router (ADR 0060 §1, §2; ADR 0010 §1; threat model §7.19, INV-69).
//!
//! **The boundary.** This router is served only on `RIZZY_ADMIN_LISTEN`
//! ([`crate::config::Config::admin_listen`]), by a second listener that runs whenever the `api`
//! role does ([`crate::server`]). It is never merged into [`super::router`], so an `/admin/...`
//! request on the public listener is that listener's plain `404`, and the public API
//! (`/api/v1/...`, a vault session token with it) does not exist here: this router holds no
//! [`super::api::Api`] state and no route of it reads a vault session, an account or a byte of
//! ciphertext. Every answer of this listener carries [`security::ADMIN_CSP`] and the common
//! headers ([`security::add_common`]), and one access-log line under the fixed route name
//! `admin` (never the request's path, a header or a body).
//!
//! **What it serves at M3: nothing yet.** Every request is a plain-text `404`. ADR 0060 §1
//! names the screens (user list, disable-user confirm, signup-mode toggle, SMTP settings), but
//! its owner answer 5 holds every one of them back: admin login, bootstrap-token redemption, the
//! second factor and session issuance (INV-69) are an authentication protocol that needs its own
//! Accepted ADR first, and "no screen behind it merges" until then. So this module builds none of
//! ADR 0060's `auth.rs` (login), `forms.rs` (CSRF and form parsing for the screens behind that
//! login) or `templates/admin/` (Askama pages) yet. The settings those screens would toggle have
//! no storage schema either (owner answer 3: an ADR 0011 follow-up), invite-only signup waits for
//! its own ADR (answer 6), the SMTP password's sealing purpose `0x0103` has no name or ctx yet
//! (CRYPTO.md §5.11), and the metrics endpoint that answer 4 places on this listener has no ADR
//! deciding what it serves.

use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::Response;

use super::{RouteName, access_log, security};

/// The route name of every answer of the admin listener, for the access log.
pub const ROUTE: &str = "admin";

/// Builds the admin listener's router (module docs). It takes no state: nothing it answers
/// depends on the `api` role's database or sessions yet.
pub fn router() -> Router {
    Router::new()
        .fallback(|| async { not_found() })
        .layer(middleware::from_fn(access_log))
        .layer(middleware::map_response(finish))
}

/// The admin listener's plain-text `404`.
fn not_found() -> Response {
    let mut response = Response::new(Body::from("not found\n"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.extensions_mut().insert(RouteName(ROUTE));
    response
}

/// Adds the admin CSP and the headers every response carries.
async fn finish(mut response: Response) -> Response {
    security::add_admin_csp(response.headers_mut());
    security::add_common(response.headers_mut());
    response
}
