// SPDX-License-Identifier: AGPL-3.0-only

//! The per-source token bucket of the `icons` role ([ADR 0052] point 6 and owner answer 5:
//! 30 requests per minute, burst 10; [ADR 0053] item 8: the breach-check endpoint inherits
//! that limit, per source, with a conservative global cap where no source can be told
//! apart).
//!
//! - **The source** is what [ADR 0028] item 11 makes it: an IPv4 address, or the /64 of an
//!   IPv6 address (IPv4-mapped IPv6 read as IPv4). The caller derives the client address
//!   (the peer, or `X-Forwarded-For` from a trusted proxy) and passes it in.
//! - **The bucket** is a generic cell rate algorithm (GCRA): one request every
//!   `60 s / per_minute`, with up to `burst` at once. A refusal says how long until the next
//!   request would pass (the `Retry-After`).
//! - **Memory is bounded.** At most [`MAX_SOURCES`] sources are tracked; buckets that have
//!   refilled are dropped first. When the table is still full, a request is charged to one
//!   **global** bucket with the same rate instead: the conservative fallback of ADR 0053
//!   item 8. Counters live in memory only (the role has no database), and nothing about a
//!   source is ever logged.
//!
//! With several `icons` replicas the effective limit multiplies by their number, as ADR 0052
//! point 6 accepts.
//!
//! [ADR 0028]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0028-api-v1-http-conventions.md
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md
//! [ADR 0053]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0053-hibp-breach-check-egress.md

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Requests per minute per source (ADR 0052 owner answer 5).
pub const PER_MINUTE: u32 = 30;

/// Requests a source may make at once (ADR 0052 owner answer 5).
pub const BURST: u32 = 10;

/// Sources tracked at most; past this, requests share the global bucket.
pub const MAX_SOURCES: usize = 65_536;

/// A rate-limit source: an IPv4 address or an IPv6 /64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Source {
    /// An IPv4 address (or an IPv4-mapped IPv6 one).
    V4([u8; 4]),
    /// The first 64 bits of an IPv6 address.
    V6([u8; 8]),
}

impl Source {
    /// The source of `ip` (ADR 0028 item 11).
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return Self::V4(v4.octets());
                }
                let mut net = [0u8; 8];
                for (n, b) in net.iter_mut().zip(v6.octets().iter()) {
                    *n = *b;
                }
                Self::V6(net)
            }
        }
    }
}

/// One GCRA cell: the theoretical arrival time of the next request.
#[derive(Clone, Copy, Debug)]
struct Cell {
    /// When the bucket is full again; at or before `now` it is full.
    tat: Instant,
}

/// The limiter. Not thread-safe by itself: the caller holds it in a mutex.
#[derive(Debug)]
pub struct RateLimiter {
    /// The time one request costs: `60 s / per_minute`.
    interval: Duration,
    /// How far ahead of `now` the theoretical arrival time may run: `interval × (burst − 1)`.
    tolerance: Duration,
    /// Per-source cells.
    cells: HashMap<Source, Cell>,
    /// The fallback cell.
    global: Option<Cell>,
    /// The table's size limit.
    max_sources: usize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(PER_MINUTE, BURST, MAX_SOURCES)
    }
}

impl RateLimiter {
    /// A limiter of `per_minute` requests per minute with bursts of `burst`, tracking at most
    /// `max_sources` sources. A zero rate or burst is read as 1.
    #[must_use]
    pub fn new(per_minute: u32, burst: u32, max_sources: usize) -> Self {
        let interval = Duration::from_secs(60) / per_minute.max(1);
        Self {
            interval,
            tolerance: interval.saturating_mul(burst.max(1).saturating_sub(1)),
            cells: HashMap::new(),
            global: None,
            max_sources,
        }
    }

    /// Charges one request from `ip` at `now`.
    ///
    /// # Errors
    /// The time until a request would pass, when the bucket is empty.
    pub fn check(&mut self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let source = Source::of(ip);
        if !self.cells.contains_key(&source) && self.cells.len() >= self.max_sources {
            self.cells.retain(|_, cell| cell.tat > now);
        }
        let (interval, tolerance) = (self.interval, self.tolerance);
        if self.cells.contains_key(&source) || self.cells.len() < self.max_sources {
            let cell = self.cells.entry(source).or_insert(Cell { tat: now });
            charge(cell, now, interval, tolerance)
        } else {
            let cell = self.global.get_or_insert(Cell { tat: now });
            charge(cell, now, interval, tolerance)
        }
    }

    /// How many sources are tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.cells.len()
    }
}

/// The GCRA step: pass when `tat − tolerance ≤ now`, then move `tat` one interval on.
fn charge(
    cell: &mut Cell,
    now: Instant,
    interval: Duration,
    tolerance: Duration,
) -> Result<(), Duration> {
    let tat = cell.tat.max(now);
    let allowed_at = tat.checked_sub(tolerance).unwrap_or(now);
    if allowed_at > now {
        return Err(allowed_at.saturating_duration_since(now));
    }
    cell.tat = tat + interval;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The burst, the refill, the /64 grouping and the bounded table.

    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn burst_then_one_every_two_seconds() {
        let mut limiter = RateLimiter::default();
        let t0 = Instant::now();
        for _ in 0..BURST {
            assert_eq!(limiter.check(ip("203.0.113.5"), t0), Ok(()));
        }
        let wait = limiter.check(ip("203.0.113.5"), t0).unwrap_err();
        assert_eq!(wait, Duration::from_secs(2));
        // Another source is unaffected.
        assert_eq!(limiter.check(ip("203.0.113.6"), t0), Ok(()));
        // After the interval, one more passes, and only one.
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(limiter.check(ip("203.0.113.5"), t1), Ok(()));
        assert!(limiter.check(ip("203.0.113.5"), t1).is_err());
        // A full minute refills the burst.
        let t2 = t1 + Duration::from_secs(60);
        for _ in 0..BURST {
            assert_eq!(limiter.check(ip("203.0.113.5"), t2), Ok(()));
        }
        assert!(limiter.check(ip("203.0.113.5"), t2).is_err());
    }

    #[test]
    fn one_ipv6_64_is_one_source_and_mapped_ipv4_is_ipv4() {
        let mut limiter = RateLimiter::new(30, 1, 16);
        let t0 = Instant::now();
        assert_eq!(limiter.check(ip("2001:db8:1:2::1"), t0), Ok(()));
        assert!(limiter.check(ip("2001:db8:1:2:ffff::9"), t0).is_err());
        assert_eq!(limiter.check(ip("2001:db8:1:3::1"), t0), Ok(()));
        assert_eq!(
            limiter.check(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), t0),
            Ok(())
        );
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        assert!(limiter.check(mapped, t0).is_err());
        let _ = Ipv6Addr::LOCALHOST;
    }

    #[test]
    fn a_full_table_falls_back_to_the_global_bucket() {
        let mut limiter = RateLimiter::new(30, 2, 2);
        let t0 = Instant::now();
        assert_eq!(limiter.check(ip("198.51.100.1"), t0), Ok(()));
        assert_eq!(limiter.check(ip("198.51.100.2"), t0), Ok(()));
        assert_eq!(limiter.tracked(), 2);
        // Untracked sources now share one bucket of burst 2.
        assert_eq!(limiter.check(ip("198.51.100.3"), t0), Ok(()));
        assert_eq!(limiter.check(ip("198.51.100.4"), t0), Ok(()));
        assert!(limiter.check(ip("198.51.100.5"), t0).is_err());
        assert_eq!(limiter.tracked(), 2);
        // Once tracked buckets refill, they are dropped and new sources get their own.
        let later = t0 + Duration::from_secs(120);
        assert_eq!(limiter.check(ip("198.51.100.5"), later), Ok(()));
        assert!(limiter.tracked() <= 2);
    }
}
