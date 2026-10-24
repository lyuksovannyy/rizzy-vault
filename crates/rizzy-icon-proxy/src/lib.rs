// SPDX-License-Identifier: AGPL-3.0-only

//! `rizzy-icon-proxy` — the egress of the `icons` role ([ADR 0010] §1–§2, [ADR 0052],
//! [ADR 0053]; [ADR 0016] §3 row `rizzy-icon-proxy`).
//!
//! The `icons` role is the one process that reaches the internet. It holds no database
//! credentials and no server secrets ([ADR 0010] §2), and this crate depends on `rizzy-proto`
//! only ([ADR 0016] R3: no storage, bus, domain, sqlx or `rizzy-core`; it handles no keys).
//!
//! # What this build has
//!
//! The favicon fetch of [ADR 0052] (discovery, redirects, re-encoding) and the breach check of
//! [ADR 0053], over shared pieces: the allow-list, the DNS-pinned connection, the cache and the
//! limiter.
//!
//! | Module | Spec | Purpose |
//! |---|---|---|
//! | [`allow`] | INV-51 | The address allow-list: globally routable unicast only, IPv4-mapped and NAT64 judged by the embedded IPv4 address |
//! | [`connect`] | INV-51, INV-77; ADR 0052 point 2 | Resolve once, check every address, connect to exactly one checked address, TLS 1.3 with Mozilla's roots, verified against the hostname |
//! | [`cache`] | ADR 0052 point 5; ADR 0053 item 4 | The shared on-disk cache: TTL, a total-size cap, oldest-first eviction |
//! | [`limit`] | ADR 0052 point 6, owner answer 5; ADR 0053 item 8 | The per-source token bucket, with a global fallback bucket |
//! | [`target`] | ADR 0052 points 2–3; INV-51 | Where a request goes: `http`/`https`, an RFC 1123 host, port 80 or 443; `Location` and `href` resolution |
//! | [`discover`] | ADR 0052 point 3 | The bounded `<link rel="icon">` scan of a page's first 64 KiB |
//! | [`decode`] | ADR 0052 point 4; INV-76 | Decoding under limits and re-encoding to a 128×128 PNG |
//! | [`favicon`] | ADR 0052 points 2–5; INV-51, INV-76 | The fetch: cache, `/favicon.ico`, redirects, the port-80 fallback, discovery, the time budget |
//! | [`breach`] | ADR 0053; CRYPTO.md §11.16; INV-77 | The range query to the one fixed upstream host, cached by prefix |
//!
//! # Rules
//!
//! - **No identity, no log.** Nothing that reaches this crate names an account, a session or
//!   an item; the crate logs nothing, and its errors carry no prefix, upstream answer or
//!   address.
//! - **The connector is injected.** [`breach::BreachService`] takes any
//!   [`connect::Connector`] and [`favicon::FaviconService`] any [`connect::Dialer`].
//!   Production passes [`connect::PinnedTls`] to both; tests pass a connector or dialer to a
//!   local fake upstream, so no test touches the network. No setting selects a
//!   connector: only code can.
//! - **No `unsafe`, no panics** (workspace lints, and `forbid(unsafe_code)` below).
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod allow;
pub mod breach;
pub mod cache;
pub mod connect;
pub mod decode;
pub mod discover;
pub mod favicon;
pub mod limit;
pub mod target;

/// The wire types and path of the breach check, for the role's router in `rizzy-server`
/// (which reaches `rizzy-proto` only through the crates ADR 0016 §3 lets it depend on).
pub mod wire {
    pub use rizzy_proto::breach::{BreachRangeRequest, BreachRangeResponse, HashPrefix, RangeBody};
    pub use rizzy_proto::http::paths::{ICONS_BREACH_RANGE, ICONS_FETCH, ICONS_PREFIX};
    pub use rizzy_proto::icons::{IconData, IconFetchRequest, IconFetchResponse, IconHost};
}
