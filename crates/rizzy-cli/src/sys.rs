//! The two things the libraries never do themselves: draw OS randomness and read the clock
//! (ADR 0016 R2; ADR 0009 "RNG rules"; CRYPTO.md §12.1). This leaf crate supplies both to
//! `rizzy-client`.

use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::SysRng;
use rand_core::UnwrapErr;

/// The RNG every client-core call receives: `rand_core::UnwrapErr(getrandom::SysRng)`, exactly
/// as ADR 0009 "RNG rules" prescribes for the leaf crates. It holds no state; each call reads
/// the OS CSPRNG. An OS RNG failure panics inside `UnwrapErr`, which the release profile turns
/// into an abort (`panic = "abort"`): there is no fallback source (CRYPTO.md §12.1).
pub type OsRng = UnwrapErr<SysRng>;

/// A handle to the OS CSPRNG (see [`OsRng`]).
#[must_use]
pub const fn os_rng() -> OsRng {
    UnwrapErr(SysRng)
}

/// The host's wall clock: milliseconds since the Unix epoch. A clock before 1970 reads as 0 and
/// one past `u64::MAX` ms as `u64::MAX`; neither panics.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
