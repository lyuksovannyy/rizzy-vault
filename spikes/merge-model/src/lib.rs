//! Executable model of the rizzy-vault sync merge (spike, see `README.md`).
//!
//! It models one item, 2-5 devices, a Server-mode server (ADR 0012 §7 as partly replaced by
//! ADR 0021), snapshots, compaction, rotation, revocation and a server restore, and checks
//! ADR 0012 §12 properties 1-3 over exhaustive and seeded-random schedules. The `integrated`
//! configuration carries the rules the spike's five answers chose (README "Results").
//!
//! Every modelled rule cites the ADR text it implements. Where the text is ambiguous the most
//! literal reading is implemented and marked `AMBIGUOUS:`; `README.md` lists them.
#![forbid(unsafe_code)]

pub mod absorb;
pub mod check;
pub mod config;
pub mod explore;
pub mod item;
pub mod random;
pub mod replica;
pub mod rng;
pub mod scenarios;
pub mod server;
pub mod types;
pub mod world;
