//! The randomness the libraries never draw themselves (ADR 0016 R2; ADR 0009 "RNG rules", as
//! ADR 0019 §1.3 restates its third bullet; CRYPTO.md §12.1). This leaf crate supplies it to
//! `rizzy-client`.
//!
//! On `wasm32-unknown-unknown` getrandom's `wasm_js` backend reads `crypto.getRandomValues`
//! (in a browser, a Worker, and Node 19 or later); this is the one crate that enables it (ADR
//! 0016 R2 (c), checked by `cargo xtask check-deps`). On the host, where CI builds and tests the
//! crate, the same type reads the OS source.
//!
//! The clock is not read here either: every call that needs the time takes `now_ms` from the
//! host (`Date.now()`; ADR 0013 §2, "Wall clock").

use getrandom::SysRng;
use rand_core::UnwrapErr;

/// The RNG every client-core call receives: `rand_core::UnwrapErr(getrandom::SysRng)`, as ADR
/// 0009 prescribes for the leaf crates. It holds no state. A failure of the source panics inside
/// `UnwrapErr`; the release profile aborts (`panic = "abort"`), which traps the wasm instance:
/// there is no fallback source (CRYPTO.md §12.1).
pub(crate) type Rng = UnwrapErr<SysRng>;

/// A handle to the CSPRNG (see [`Rng`]).
pub(crate) const fn os_rng() -> Rng {
    UnwrapErr(SysRng)
}
