//! The public listener's router: the `api` role under `/api/`, the `web` role everywhere else
//! ([ADR 0010] §1, §4; [ADR 0002] point 3).
//!
//! One listener serves both roles when both run; each is present only when its role is. A
//! request under `/api/` with no `api` role, or to an unknown `/api/` path, answers
//! `404 not_found` in the uniform error body; any other path with no `web` role answers a
//! plain `404`. Every response passes through [`security::add_common`] (HSTS, `nosniff`,
//! `no-referrer`, a CSP) and one access-log line ([`crate::log`]: method, route template,
//! status, duration; never the raw path, a header or a body).
//!
//! [ADR 0002]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0002-own-protocol.md
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md

pub mod api;
pub mod headers;
pub mod security;
pub mod web;

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{MethodFilter, get, on};
use rizzy_domain_auth::types::ErrorCode;
use rizzy_domain_auth::types::META_PATH;

use self::api::{Api, Endpoint, HttpMethod, dispatch, error_response};
use crate::log::{self, Field};

/// The route a response answered, for the access log: a path template from the source, never
/// the request's own path.
#[derive(Clone, Copy, Debug)]
pub struct RouteName(pub &'static str);

/// Builds the router for the roles present: `api` when `api` is `Some`, `web` when `web`.
pub fn router(api: Option<Arc<Api>>, web: bool) -> Router {
    let mut router = Router::new();
    if let Some(api) = api {
        let mut api_router: Router<Arc<Api>> =
            Router::new().route(META_PATH, get(|| async { api::meta() }));
        for &endpoint in Endpoint::ALL {
            let handler = move |State(api): State<Arc<Api>>, request: Request| {
                dispatch(api, endpoint, request)
            };
            let filter = match endpoint.method() {
                HttpMethod::Get => MethodFilter::GET.or(MethodFilter::HEAD),
                HttpMethod::Post => MethodFilter::POST,
            };
            api_router = api_router.route(endpoint.path(), on(filter, handler));
        }
        router = router.merge(api_router.with_state(api));
    }
    router
        .method_not_allowed_fallback(|| async {
            let mut response = error_response(ErrorCode::InvalidRequest, "method_not_allowed");
            *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            response
        })
        .fallback(move |request: Request| async move { fallback(web, &request) })
        .layer(middleware::from_fn(access_log))
        .layer(middleware::map_response(finish))
}

/// Answers a request no route matched (module docs).
fn fallback(web: bool, request: &Request) -> Response {
    let path = request.uri().path();
    if path == "/api" || path.starts_with("/api/") {
        return error_response(ErrorCode::NotFound, "unmatched");
    }
    let mut response = if web {
        web::respond(request.method(), request.uri())
    } else {
        let mut response = Response::new(axum::body::Body::from("not found\n"));
        *response.status_mut() = StatusCode::NOT_FOUND;
        response
    };
    response.extensions_mut().insert(RouteName("web"));
    response
}

/// Adds the headers every response carries.
async fn finish(mut response: Response) -> Response {
    security::add_common(response.headers_mut());
    response
}

/// The method name for the access log: one of a fixed set.
fn method_name(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        _ => "OTHER",
    }
}

/// Writes one access-log line per request (module docs).
async fn access_log(request: Request, next: Next) -> Response {
    let method = method_name(request.method());
    let start = Instant::now();
    let response = next.run(request).await;
    let route = response
        .extensions()
        .get::<RouteName>()
        .map_or("unmatched", |r| r.0);
    let millis = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    log::info(
        "http_request",
        &[
            Field::Str("method", method),
            Field::Str("route", route),
            Field::U64("status", u64::from(response.status().as_u16())),
            Field::U64("duration_ms", millis),
        ],
    );
    response
}
