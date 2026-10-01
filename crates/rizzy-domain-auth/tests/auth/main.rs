//! Integration tests of `rizzy-domain-auth` against real SQLite files, with `rizzy-core`'s
//! client-side functions playing the client.
//!
//! | Module | What it covers |
//! |---|---|
//! | `flow` | signup → login → device authentication → signed requests; replay and window rejection; the account view verifies on the client |
//! | `enumeration` | unknown and real login names answer alike; rate limits; the re-authentication bucket (INV-7) |
//! | `state` | enrolment, compare-and-swap races, forks, idempotent repeats (CRYPTO.md §10.2) |
//! | `revocation` | suspension, revocation with a rotation, H checks (§11.8) |
//! | `recovery` | the waiting period, cancellation, release and the recovery commit (§11.9) |
//! | `second_factor` | TOTP enrolment, login with 2FA, replay of a step (§11.15) |
//! | `requests` | the `rizzy-proto` entry points the server calls: password change, settings, suspension, self-revocation, recovery, TOTP |
//! | `restore` | the reconciliation epoch after a restore: its end, its limit, the device-set check (INV-59) |
//! | `single_use` | login states and challenges used once on every path; no login across a credential change (§5.10, §5.11, INV-59) |
//! | `secrets` | the startup checks and what the database never holds (INV-8, INV-50) |
//! | `data_key` | after a data-key rotation: TOTP rows re-sealed under the account lock, the old key dropped once no row names it (§5.11 "Rotation") |
//! | `window` | the replay window at its edges, through the database: the first counter, `max − 63`, `max − 64`, jumps, forged requests, a restart, the highest recordable counter (ADR 0028 item 5) |

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code; each scenario reads top to bottom as one flow"
)]

mod common;
mod data_key;
mod enumeration;
mod flow;
mod recovery;
mod requests;
mod restore;
mod revocation;
mod second_factor;
mod secrets;
mod single_use;
mod state;
mod window;
