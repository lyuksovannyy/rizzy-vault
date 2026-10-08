//! `rizzy-match` — URL normalisation, registrable-domain and match-mode decisions, and the
//! signed equivalence list (ADR 0037, ADR 0038).
//!
//! # Contract
//!
//! - **No I/O.** No filesystem, network, clock, environment, process or thread APIs
//!   (ADR 0016 R1). The compiled-in Public Suffix List snapshot ([`suffix`]) and, once the
//!   owner signs one, the global equivalence list, both arrive as data compiled into this
//!   crate's dependency closure or source — never fetched at run time.
//! - **No randomness.** Every function here is a pure decision over its arguments, plus one
//!   Ed25519 verification that draws no randomness ([`rizzy_core::sign::verify_detached`]).
//! - **Builds for `wasm32-unknown-unknown`.**
//! - **Narrowing only** (ADR 0037 §4; INV-38). The registrable-domain gate and the HTTPS→HTTP
//!   rule ([`modes::decide`], [`security`]) sit outside the per-mode dispatch, so a mode can
//!   only narrow what the gate already allowed, never widen past it.
//!
//! # Modules
//!
//! - [`normalize`]: [`normalize::NormalizedUrl`], the one normalisation every mode and
//!   security rule builds on, and [`normalize::normalize_domain`] for a bare domain string
//!   (an equivalence-group entry).
//! - [`suffix`]: the compiled-in Public Suffix List snapshot and registrable-domain
//!   computation.
//! - [`modes`]: [`modes::MatchMode`], [`modes::decide`] and the outcome types.
//! - [`security`]: the pure decision functions of ADR 0037 §5.
//! - [`equivalence`]: the signed global equivalence list's format, verification and the
//!   merged [`equivalence::EquivalenceView`].
//! - [`error`]: every error type and size bound.
//!
//! # No compiled-in global list yet
//!
//! The production list-signing key does not exist yet: the owner generates it offline
//! (`docs/equivalence-list.md`) and signs a first list with `cargo xtask equivalence-list`.
//! Until then, [`compiled::GLOBAL_LIST`] and [`compiled::LIST_SIGNING_PUBLIC_KEY`] are both
//! `None`, so a client's merged [`equivalence::EquivalenceView`] has no global groups and
//! equivalence matching runs from the account's own user-defined groups only — never from an
//! unsigned or placeholder source ([`compiled`]'s tests assert this).

pub mod compiled;
pub mod equivalence;
pub mod error;
pub mod modes;
pub mod normalize;
pub mod security;
pub mod suffix;

pub use equivalence::{EquivalenceGroup, EquivalenceList, EquivalenceView, GroupId};
pub use error::{DomainError, EquivalenceListError, NormalizeError};
pub use modes::{EffectiveMode, MatchMode, MatchOutcome, MatchedVia, decide};
pub use normalize::{NormalizedUrl, Scheme, normalize_domain};
