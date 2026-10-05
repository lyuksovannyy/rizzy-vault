//! The rules table of ADR 0016 §3–§5 and ADR 0009, as data.
//!
//! **This table is a security boundary.** Review a change to it like a change to `deny.toml`
//! (ADR 0016, Risks): widening an allow-list or an internal edge is how a no-I/O crate would
//! start doing I/O, or an ingress crate would get a route to the database.
//!
//! Every crate of ADR 0016 §2 and §3 has a row, including the planned ones, so the checks apply
//! the moment a crate is created. ADR 0022 removes the `rizzy-domain-relay` row of §3. ADR 0019
//! (§1.3, §1.4) withdraws `rizzy-desktop`, moves `rizzy-ffi` to M3 and adds `rizzy-ffi-cpp`. A
//! workspace member without a row is itself a violation.
//!
//! What is here:
//!
//! - [`CRATES`]: one [`CrateRule`] per crate: its side (R6), whether it is a no-I/O crate and
//!   its external allow-list (R1), getrandom and `wasm_js` rights (R2), its allowed internal
//!   dependencies (§3), its sqlx rights (R5), openssl rights (ADR 0009) and
//!   rustix rights (ADR 0024).
//! - [`CORE_EXTERNAL_ALLOW`] and [`PROTO_EXTERNAL_ALLOW`]: the R1 allow-lists of `rizzy-core` and
//!   `rizzy-proto`, as `name@compat` ([`compat`]).
//! - The deny-lists: [`NO_IO_FORBIDDEN`] (R1), [`ISOLATED_INGRESS`] (R3), [`SERVER_WIRED`] and
//!   [`SQLX`] (R5), [`OPENSSL`], [`RUSTIX`].
//! - The `rand` and getrandom rules: [`RAND`], [`RANDOMNESS_CRATES`],
//!   [`GETRANDOM_WASM_FEATURES`].
//! - ADR 0009's required and forbidden feature sets: [`FEATURE_RULES`]. The same list names the
//!   crypto crates every member declares with `default-features = false` ([`defaults_off`]).
//! - The R1 API-side clippy lists: [`NO_IO_CLIPPY_LISTS`].
//! - The generated Rust that ADR 0019 §4.1's `unsafe` token scan skips: [`GENERATED_RUST`].
//!
//! The unit tests restate the rights ADR 0016 and ADR 0009 assign, with ADR 0019 §1.4's
//! replacing rows (`rows_match_adr_0016`: the no-I/O crates, the getrandom leaves, `wasm_js`,
//! sqlx, the one dev-only edge, openssl, rustix and the rows ADR 0022 and ADR 0019 remove;
//! `sides_match_adr_0016_r6`: the R6 sides; `crypto_crates_match_adr_0009`: the crates of ADR
//! 0009's required feature sets), so changing one of those in a row also means changing a test.
//! Otherwise, internal edges are checked for well-formedness plus R4 and the R5 server-wired
//! edges, and allow-list entries for well-formedness and against the forbidden and `rand` rules
//! (`rand_and_getrandom_are_never_allow_listed_by_accident`).

/// Which side of the client/server split a crate is on (ADR 0016 R6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    /// `rizzy-core`, `rizzy-sync`, `rizzy-proto`: used by both sides.
    Shared,
    /// Client-side crates.
    Client,
    /// Server-side crates.
    Server,
    /// Repository tooling (`xtask`), never shipped.
    Tool,
}

/// Who may depend on sqlx directly (ADR 0016 R5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sqlx {
    /// No direct sqlx dependency.
    Forbidden,
    /// Any driver: `rizzy-storage` and the domain crates.
    Server,
    /// The native client leaf crates: the `sqlite` driver only.
    SqliteOnly,
}

/// One crate of ADR 0016 §2/§3.
#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a rules table: each flag is one independent rule of ADR 0016 or ADR 0009"
)]
pub(crate) struct CrateRule {
    /// Package name.
    pub(crate) name: &'static str,
    /// Manifest directory, relative to the workspace root (§1: the directory name equals the
    /// crate name).
    pub(crate) dir: &'static str,
    /// Client, server, shared or tooling (R6).
    pub(crate) side: Side,
    /// A no-I/O crate (R1): allow-listed external crates only, no randomness crates, no
    /// getrandom anywhere in the closure.
    pub(crate) no_io: bool,
    /// May depend on getrandom directly (R2 (c)): the leaf crates and `xtask`.
    pub(crate) getrandom_direct: bool,
    /// May enable getrandom's `wasm_js` feature (R2 (c)): `rizzy-wasm` only.
    pub(crate) wasm_js: bool,
    /// The internal crates it may depend on (§3 "May depend on (internal)", and the §3 notes
    /// for the binaries), for every dependency kind.
    pub(crate) internal: &'static [&'static str],
    /// Extra internal crates it may depend on as a dev-dependency only (§4 "Dev-dependencies",
    /// owner decision 4: `rizzy-server` → `rizzy-client`).
    pub(crate) dev_internal: &'static [&'static str],
    /// Direct sqlx dependency (R5).
    pub(crate) sqlx: Sqlx,
    /// May reach openssl (ADR 0009 owner decision 1: `rizzy-server` and the domain crate that
    /// does `WebAuthn`).
    pub(crate) openssl: bool,
    /// May depend on rustix (ADR 0024 point 2: the leaf crates `rizzy-server` and `rizzy-cli` in
    /// M1, and the binding leaves `rizzy-ffi` and `rizzy-ffi-cpp`), for core-dump disabling
    /// (threat model INV-60).
    pub(crate) rustix: bool,
    /// R1 allow-list of external crates for this crate's own dependencies, as `name@compat`
    /// ([`compat`]). The allow-lists of its internal dependencies are added to it.
    pub(crate) external_allow: &'static [&'static str],
}

impl CrateRule {
    /// A row with every right off: no internal dependencies, no getrandom, no sqlx, no openssl,
    /// no rustix, and not a no-I/O crate. The builder methods below turn rights on one by one.
    const fn new(name: &'static str, dir: &'static str, side: Side) -> Self {
        Self {
            name,
            dir,
            side,
            no_io: false,
            getrandom_direct: false,
            wasm_js: false,
            internal: &[],
            dev_internal: &[],
            sqlx: Sqlx::Forbidden,
            openssl: false,
            rustix: false,
            external_allow: &[],
        }
    }

    /// Marks the crate as a no-I/O crate (R1) with this external allow-list.
    const fn no_io(mut self, external_allow: &'static [&'static str]) -> Self {
        self.no_io = true;
        self.external_allow = external_allow;
        self
    }

    /// Sets the internal crates it may depend on, for every dependency kind (§3).
    const fn internal(mut self, internal: &'static [&'static str]) -> Self {
        self.internal = internal;
        self
    }

    /// Marks the crate as a leaf that may depend on getrandom directly (R2 (c)).
    const fn leaf(mut self) -> Self {
        self.getrandom_direct = true;
        self
    }

    /// Lets the crate depend on rustix (ADR 0024 point 2).
    const fn rustix(mut self) -> Self {
        self.rustix = true;
        self
    }

    /// Sets its direct sqlx rights (R5).
    const fn sqlx(mut self, sqlx: Sqlx) -> Self {
        self.sqlx = sqlx;
        self
    }
}

/// The R1 allow-list of `rizzy-core` (ADR 0016 §5): its normal and build closure, generated
/// from `Cargo.lock` in M1 with every feature of every workspace member switched on and every
/// target included, as `name@compat`. It includes the whole opaque-ke tree of CRYPTO.md §3
/// (curve25519-dalek 4, voprf, `rand` 0.8 / `rand_core` 0.6, the elliptic-curve 0.13 stack,
/// digest/hkdf/hmac of the previous generation), the proc-macro crates those use at build time,
/// and `libc`, which `cpufeatures` uses for CPU feature detection on aarch64 Linux and Android
/// only. `rand@0.8` is here only for the opaque-ke edge; [`RAND`] restricts it further.
///
/// A new crate, or a semver-incompatible version of one, fails the check until it is added
/// here in a reviewed change.
pub(crate) const CORE_EXTERNAL_ALLOW: &[&str] = &[
    "aead@0.6",
    "argon2@0.6",
    "base16ct@0.2",
    "base64ct@1",
    "blake2@0.11",
    "block-buffer@0.10",
    "block-buffer@0.12",
    "cfg-if@1",
    "chacha20@0.10",
    "chacha20poly1305@0.11",
    "cipher@0.5",
    "cmov@0.5",
    "const-oid@0.9",
    "cpufeatures@0.2",
    "cpufeatures@0.3",
    "crypto-bigint@0.5",
    "crypto-common@0.1",
    "crypto-common@0.2",
    "ctutils@0.4",
    "curve25519-dalek-derive@0.1",
    "curve25519-dalek@4",
    "curve25519-dalek@5",
    "der@0.7",
    "derive-where@1",
    "digest@0.10",
    "digest@0.11",
    "displaydoc@0.2",
    "ed25519-dalek@3",
    "ed25519@3",
    "elliptic-curve@0.13",
    "ff@0.13",
    "fiat-crypto@0.2",
    "fiat-crypto@0.3",
    "generic-array@0.14",
    "group@0.13",
    "hkdf@0.12",
    "hkdf@0.13",
    "hmac@0.12",
    "hmac@0.13",
    "hpke@0.14",
    "hybrid-array@0.4",
    "inout@0.2",
    "libc@0.2",
    "opaque-ke@4",
    "poly1305@0.9",
    "proc-macro2@1",
    "quote@1",
    "rand@0.8",
    "rand_core@0.10",
    "rand_core@0.6",
    "rustc_version@0.4",
    "sec1@0.7",
    "semver@1",
    "sha1@0.11",
    "sha2@0.10",
    "sha2@0.11",
    "signature@3",
    "subtle@2",
    "syn@2",
    "syn@3",
    "tinyvec@1",
    "typenum@1",
    "unicode-ident@1",
    "unicode-normalization@0.1",
    "universal-hash@0.6",
    "version_check@0.9",
    "voprf@0.5",
    "x25519-dalek@3",
    "zeroize@1",
    "zeroize_derive@1",
];

/// The R1 allow-list of `rizzy-proto` (ADR 0016 §3 row: "serde"; §5), generated from `Cargo.lock`
/// when the crate was created in M1 step 3, as `name@compat`: `serde` with its derive
/// (`serde_core`, `serde_derive` and the proc-macro crates `proc-macro2`, `quote`, `syn` 3 and
/// `unicode-ident`), `base64ct` for CRYPTO.md §9.6's base64url (the version `rizzy-core` pins),
/// and `zeroize` for the secret wire types, with `zeroize_derive` and `syn` 2, which the
/// workspace-unified `zeroize` features bring in. Every entry is also on
/// [`CORE_EXTERNAL_ALLOW`] except the three `serde` crates. The `openapi` feature adds nothing
/// yet: its schema-derive crate is not chosen (ADR 0002 point 3), and adding it here is a
/// reviewed change, marked as feature-gated (§3 notes).
pub(crate) const PROTO_EXTERNAL_ALLOW: &[&str] = &[
    "base64ct@1",
    "proc-macro2@1",
    "quote@1",
    "serde@1",
    "serde_core@1",
    "serde_derive@1",
    "syn@2",
    "syn@3",
    "unicode-ident@1",
    "zeroize@1",
    "zeroize_derive@1",
];

/// The domain crates (ADR 0016 §3). R4: none depends on another.
pub(crate) const DOMAIN_PREFIX: &str = "rizzy-domain-";

/// Every crate of ADR 0016 §2 (current) and §3 (planned).
pub(crate) const CRATES: &[CrateRule] = &[
    // §2, current crates.
    CrateRule::new("rizzy-core", "crates/rizzy-core", Side::Shared).no_io(CORE_EXTERNAL_ALLOW),
    CrateRule::new("rizzy-sync", "crates/rizzy-sync", Side::Shared)
        .no_io(&[])
        .internal(&["rizzy-core"]),
    CrateRule {
        dev_internal: &["rizzy-client"],
        openssl: true,
        ..CrateRule::new("rizzy-server", "crates/rizzy-server", Side::Server)
            .leaf()
            .rustix()
            .internal(&[
                "rizzy-domain-auth",
                "rizzy-domain-vault",
                "rizzy-domain-share",
                "rizzy-domain-mail",
                "rizzy-domain-org",
                "rizzy-storage",
                "rizzy-bus",
                "rizzy-smtp-ingress",
                "rizzy-icon-proxy",
            ])
    },
    // `rizzy-cli` depends on `rizzy-core` in M0 and moves to `rizzy-client` in M1 (§3 notes).
    CrateRule::new("rizzy-cli", "crates/rizzy-cli", Side::Client)
        .leaf()
        .rustix()
        .internal(&["rizzy-core", "rizzy-client"])
        .sqlx(Sqlx::SqliteOnly),
    // §3 lists no internal dependency for `xtask`, but its notes say `xtask` is the one crate
    // that enables `rizzy-proto`'s `openapi` feature, which needs that edge.
    CrateRule::new("xtask", "crates/xtask", Side::Tool)
        .leaf()
        .internal(&["rizzy-proto"]),
    // §3, planned crates. Their R1 allow-lists start empty: the PR that creates a no-I/O crate
    // adds its list, generated from `Cargo.lock` (§5). `rizzy-proto` exists since M1 step 3.
    CrateRule::new("rizzy-proto", "crates/rizzy-proto", Side::Shared).no_io(PROTO_EXTERNAL_ALLOW),
    CrateRule::new("rizzy-import", "crates/rizzy-import", Side::Client)
        .no_io(&[])
        .internal(&["rizzy-core"]),
    CrateRule::new("rizzy-client", "crates/rizzy-client", Side::Client)
        .no_io(&[])
        .internal(&[
            "rizzy-core",
            "rizzy-sync",
            "rizzy-proto",
            "rizzy-import",
            "rizzy-match",
        ]),
    CrateRule {
        wasm_js: true,
        ..CrateRule::new("rizzy-wasm", "crates/rizzy-wasm", Side::Client)
            .leaf()
            .internal(&["rizzy-client"])
    },
    CrateRule::new("rizzy-storage", "crates/rizzy-storage", Side::Server).sqlx(Sqlx::Server),
    CrateRule::new("rizzy-bus", "crates/rizzy-bus", Side::Server),
    CrateRule {
        openssl: true,
        ..CrateRule::new(
            "rizzy-domain-auth",
            "crates/rizzy-domain-auth",
            Side::Server,
        )
        .internal(&["rizzy-core", "rizzy-proto", "rizzy-storage", "rizzy-bus"])
        .sqlx(Sqlx::Server)
    },
    CrateRule::new(
        "rizzy-domain-vault",
        "crates/rizzy-domain-vault",
        Side::Server,
    )
    .internal(&[
        "rizzy-core",
        "rizzy-sync",
        "rizzy-proto",
        "rizzy-storage",
        "rizzy-bus",
    ])
    .sqlx(Sqlx::Server),
    CrateRule::new("rizzy-match", "crates/rizzy-match", Side::Client)
        .no_io(&[])
        .internal(&["rizzy-core"]),
    CrateRule::new("rizzy-icon-proxy", "crates/rizzy-icon-proxy", Side::Server)
        .internal(&["rizzy-proto"]),
    CrateRule::new(
        "rizzy-domain-share",
        "crates/rizzy-domain-share",
        Side::Server,
    )
    .internal(&["rizzy-proto", "rizzy-storage", "rizzy-bus"])
    .sqlx(Sqlx::Server),
    CrateRule::new(
        "rizzy-domain-mail",
        "crates/rizzy-domain-mail",
        Side::Server,
    )
    .internal(&["rizzy-proto", "rizzy-storage", "rizzy-bus"])
    .sqlx(Sqlx::Server),
    CrateRule::new(
        "rizzy-smtp-ingress",
        "crates/rizzy-smtp-ingress",
        Side::Server,
    )
    .internal(&["rizzy-core", "rizzy-proto"]),
    // The native binding crates, as ADR 0019 §1.4 restates their §3 rows: `rizzy-ffi` from M3
    // (UniFFI), `rizzy-ffi-cpp` with the Linux client (Diplomat). Both are leaves (R2 (c)),
    // sqlite-only sqlx holders (R5) and client-side (R6).
    CrateRule::new("rizzy-ffi", "crates/rizzy-ffi", Side::Client)
        .leaf()
        .rustix()
        .internal(&["rizzy-client"])
        .sqlx(Sqlx::SqliteOnly),
    CrateRule::new("rizzy-ffi-cpp", "crates/rizzy-ffi-cpp", Side::Client)
        .leaf()
        .rustix()
        .internal(&["rizzy-client"])
        .sqlx(Sqlx::SqliteOnly),
    CrateRule::new("rizzy-domain-org", "crates/rizzy-domain-org", Side::Server)
        .internal(&["rizzy-core", "rizzy-proto", "rizzy-storage", "rizzy-bus"])
        .sqlx(Sqlx::Server),
];

/// Crates that no R1 crate may reach, whatever the allow-list says, with the reason printed on
/// a violation. `*` at the end matches a prefix.
pub(crate) const NO_IO_FORBIDDEN: &[(&str, &str)] = &[
    ("getrandom", "OS randomness (R1, R2 (a))"),
    ("tokio", "an async runtime does I/O"),
    ("tokio-*", "an async runtime does I/O"),
    ("mio", "an event loop does I/O"),
    ("async-std", "an async runtime does I/O"),
    ("smol", "an async runtime does I/O"),
    ("socket2", "network I/O"),
    ("sqlx", "database access"),
    ("sqlx-*", "database access"),
    ("reqwest", "an HTTP client"),
    ("hyper", "an HTTP implementation"),
    ("hyper-*", "an HTTP implementation"),
    ("h2", "an HTTP implementation"),
    ("ureq", "an HTTP client"),
    ("isahc", "an HTTP client"),
    ("surf", "an HTTP client"),
    ("attohttpc", "an HTTP client"),
    ("curl", "an HTTP client"),
    ("rustls", "TLS belongs to the leaf crates"),
    ("native-tls", "TLS belongs to the leaf crates"),
    ("openssl", "TLS belongs to the leaf crates"),
    ("openssl-sys", "TLS belongs to the leaf crates"),
    ("wasm-bindgen", "JavaScript bindings belong to rizzy-wasm"),
    ("js-sys", "JavaScript bindings belong to rizzy-wasm"),
    ("web-sys", "JavaScript bindings belong to rizzy-wasm"),
];

/// The one allowed `rand` in an R1 closure (ADR 0009 "RNG rules", ADR 0016 R1): version 0.8,
/// reached only from opaque-ke, with default features off. No `rand` feature at all is allowed:
/// every feature of `rand` 0.8 is either `std`-dependent (`std`, `std_rng`, `getrandom`) or not
/// needed by opaque-ke, so an enabled feature means something changed and needs review.
pub(crate) struct RandRule {
    /// The only allowed `name@compat`.
    pub(crate) allowed: &'static str,
    /// The only crates allowed to depend on it.
    pub(crate) parents: &'static [&'static str],
    /// The features it may have enabled.
    pub(crate) features: &'static [&'static str],
}

/// See [`RandRule`].
pub(crate) const RAND: RandRule = RandRule {
    allowed: "rand@0.8",
    parents: &["opaque-ke"],
    features: &[],
};

/// Crates that must not depend on `rand` or getrandom directly, in any dependency kind (R1: "no
/// direct dependency on `rand` or getrandom").
pub(crate) const RANDOMNESS_CRATES: &[&str] = &["rand", "getrandom"];

/// ADR 0009 "Required feature sets" for one crypto crate in `rizzy-core`'s closure.
///
/// Every declaration of the crate, by any member and in any dependency kind, must also turn
/// default features off ([`defaults_off`]).
pub(crate) struct FeatureRule {
    /// `name@compat` of the resolved package ([`compat`]).
    pub(crate) package: &'static str,
    /// Features [`FEATURE_RULES_CRATE`] must turn on in its own normal-dependency entry for the
    /// package. The entry, not the unified graph, is what counts: a feature some other member
    /// turns on is not on when `rizzy-core` is built alone.
    pub(crate) required: &'static [&'static str],
    /// Features no build may turn on, checked on the workspace-unified graph (a superset of any
    /// single build, so a pass holds for every build).
    pub(crate) forbidden: &'static [&'static str],
}

impl FeatureRule {
    /// The package name: [`FeatureRule::package`] without its `@compat` suffix.
    pub(crate) fn crate_name(&self) -> &'static str {
        self.package
            .split_once('@')
            .map_or(self.package, |(name, _)| name)
    }
}

/// The crate whose dependency entries [`FeatureRule::required`] is checked against.
pub(crate) const FEATURE_RULES_CRATE: &str = "rizzy-core";

/// ADR 0009 "Required feature sets" and its amendment of 2026-09-26. A rule applies when its
/// package is in `rizzy-core`'s normal and build closure. `blake2` and `poly1305` are never
/// called; `rizzy-core` declares them only so that feature unification turns on their `zeroize`,
/// which `argon2` and `chacha20poly1305` do not forward. Such a declaration looks unused, so
/// this rule is what stops a cleanup from dropping it. `hkdf` 0.13 has no features, so its
/// entry checks nothing here; it is listed because that section names it, which puts it under
/// [`defaults_off`].
pub(crate) const FEATURE_RULES: &[FeatureRule] = &[
    FeatureRule {
        package: "opaque-ke@4",
        required: &["ristretto255"],
        forbidden: &["argon2", "std"],
    },
    FeatureRule {
        package: "hpke@0.14",
        required: &["alloc", "x25519", "chacha"],
        forbidden: &["mlkem", "getrandom"],
    },
    FeatureRule {
        package: "argon2@0.6",
        required: &["zeroize"],
        forbidden: &["alloc", "parallel"],
    },
    FeatureRule {
        package: "blake2@0.11",
        required: &["zeroize"],
        forbidden: &[],
    },
    FeatureRule {
        package: "sha2@0.11",
        required: &["zeroize"],
        forbidden: &[],
    },
    FeatureRule {
        package: "hmac@0.13",
        required: &["zeroize"],
        forbidden: &[],
    },
    FeatureRule {
        package: "sha1@0.11",
        required: &["zeroize"],
        forbidden: &[],
    },
    FeatureRule {
        package: "hkdf@0.13",
        required: &[],
        forbidden: &[],
    },
    FeatureRule {
        package: "chacha20poly1305@0.11",
        required: &["alloc", "zeroize"],
        forbidden: &[],
    },
    FeatureRule {
        package: "poly1305@0.9",
        required: &["zeroize"],
        forbidden: &[],
    },
    FeatureRule {
        package: "ed25519-dalek@3",
        required: &["fast", "zeroize"],
        forbidden: &["legacy_compatibility", "hazmat"],
    },
];

/// Whether every declaration of the package `name`, by every workspace member and in every
/// dependency kind, must turn default features off (ADR 0009 "Required feature sets"): true for
/// the crates of [`FEATURE_RULES`], `blake2` and `poly1305` included.
///
/// ADR 0009 writes `default-features = false` for `opaque-ke`, `hpke`, `argon2`,
/// `chacha20poly1305`, `ed25519-dalek`, `blake2` and `poly1305`. For `sha2`, `hmac`, `sha1` and
/// `hkdf` it gives the feature set alone (`["zeroize"]`, or none for `hkdf`); the workspace
/// declares them with defaults off too (root `Cargo.toml`), so they are held to the same rule.
/// With the pinned versions, the defaults of `hpke`, `argon2` and `chacha20poly1305` turn on
/// their `getrandom` feature, `hpke`'s also `mlkem` and `argon2`'s also the forbidden `alloc`;
/// `opaque-ke`'s add `serde`, `blake2`'s `alloc`, and `sha2`'s and `sha1`'s `alloc` and `oid`
/// (crate manifests). The match is by package name, so every version counts: `sha2` also
/// covers the 0.10 copy OPAQUE uses, whose ADR 0009 row says `default-features = false` too,
/// and a new version is covered before anyone updates its row.
pub(crate) fn defaults_off(name: &str) -> bool {
    FEATURE_RULES.iter().any(|r| r.crate_name() == name)
}

/// R3: `rizzy-smtp-ingress` and `rizzy-icon-proxy` reach none of these, over normal, build and
/// dev dependencies. `rizzy-icon-proxy` also does not reach `rizzy-core` (it handles no keys).
pub(crate) const ISOLATED_INGRESS: &[(&str, &[&str])] = &[
    (
        "rizzy-smtp-ingress",
        &[
            "rizzy-storage",
            "rizzy-bus",
            "rizzy-domain-*",
            "sqlx",
            "sqlx-*",
        ],
    ),
    (
        "rizzy-icon-proxy",
        &[
            "rizzy-storage",
            "rizzy-bus",
            "rizzy-domain-*",
            "sqlx",
            "sqlx-*",
            "rizzy-core",
        ],
    ),
];

/// R5: only `rizzy-server` depends on these.
pub(crate) const SERVER_WIRED: &[&str] =
    &["rizzy-domain-*", "rizzy-smtp-ingress", "rizzy-icon-proxy"];

/// R5: the sqlx packages. A direct dependency on any of them is a sqlx dependency.
pub(crate) const SQLX: &[&str] = &["sqlx", "sqlx-*"];

/// R5: driver features and driver crates a client leaf crate must not enable or depend on. Only
/// the `sqlite` driver (`sqlite`, `sqlite-unbundled`) is allowed.
pub(crate) const SQLX_NON_SQLITE_FEATURES: &[&str] =
    &["postgres", "mysql", "mssql", "all-databases"];
/// See [`SQLX_NON_SQLITE_FEATURES`].
pub(crate) const SQLX_NON_SQLITE_CRATES: &[&str] = &["sqlx-postgres", "sqlx-mysql"];

/// ADR 0009 owner decision 1: `openssl` and `openssl-sys` are reachable only from the crates
/// whose row sets `openssl`.
pub(crate) const OPENSSL: &[&str] = &["openssl", "openssl-sys"];

/// ADR 0024 point 2: the core-dump crate. Only the crates whose row sets `rustix` declare it, in
/// any dependency kind, and it is in no other member's normal or build closure.
pub(crate) const RUSTIX: &str = "rustix";

/// R7: crates with an accepted exception that copy the workspace lint table with only
/// `unsafe_code` changed. Adding one takes a new ADR; there are none.
pub(crate) const LINT_EXCEPTIONS: &[&str] = &[];

/// ADR 0019 §4.1: directories of generated Rust, relative to the workspace root, that the
/// first-party `unsafe` token scan skips ([`crate::unsafe_scan`]). §4.1 commits the
/// macro-expanded binding crate as a reviewed baseline under the binding crate's directory; that
/// code is not first party, and §4.1's baseline diff reviews its `unsafe`. The baseline is
/// committed for `rizzy-wasm` (owner decision 7), checked by [`crate::bindings`]. An entry is
/// reviewed like the rest of this table.
pub(crate) const GENERATED_RUST: &[&str] = &[crate::bindings::BASELINE_DIR];

/// ADR 0030 Decision 3: the rustls `dangerous()` APIs (a custom or disabled server-certificate
/// verifier, in the `danger` modules) must not appear in first-party code. The scan reports
/// these word tokens, comments and literals excluded, in the files [`danger_scanned`] selects.
/// The ADR names the tokens `dangerous` and `danger::`; the bare word `danger` is reported
/// whatever follows it, the conservative reading, so `use rustls::client::danger as d;` is
/// caught as well.
pub(crate) const DANGER_WORDS: &[&str] = &["dangerous", "danger"];

/// Whether `path` (relative to the workspace root, `/` separators) is in the scope of the
/// [`DANGER_WORDS`] scan: `crates/<crate>/src/…` (ADR 0030 Decision 3). Tests, fuzz targets and
/// spikes are outside it.
pub(crate) fn danger_scanned(path: &str) -> bool {
    path.strip_prefix("crates/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(krate, rest)| !krate.is_empty() && rest.starts_with("src/"))
}

/// ADR 0016 §3 notes: only `xtask` enables `rizzy-proto`'s `openapi` feature.
pub(crate) const OPENAPI_FEATURE: (&str, &str, &str) = ("rizzy-proto", "openapi", "xtask");

/// R2 (c): the getrandom features that switch on the JavaScript backend, which only
/// `rizzy-wasm` may enable. getrandom 0.3 and later call it `wasm_js`; getrandom 0.2 calls the
/// same backend `js`, and still reaches the workspace through third-party crates (ADR 0016,
/// Context), so it counts too.
pub(crate) const GETRANDOM_WASM_FEATURES: &[&str] = &["wasm_js", "js"];

/// R1, API side (ADR 0016 §5, "the clippy lists"): the `disallowed-types` of every no-I/O
/// crate's `clippy.toml`. Item paths only: clippy 1.94.1 ignores a module path ("found a
/// module") and then flags nothing from it.
pub(crate) const NO_IO_DISALLOWED_TYPES: &[&str] = &[
    "std::fs::File",
    "std::fs::OpenOptions",
    "std::fs::DirBuilder",
    "std::fs::ReadDir",
    "std::net::TcpStream",
    "std::net::TcpListener",
    "std::net::UdpSocket",
    "std::process::Command",
    "std::process::Child",
    "std::thread::Builder",
];

/// R1, API side: the `disallowed-methods` of every no-I/O crate's `clippy.toml` (see
/// [`NO_IO_DISALLOWED_TYPES`]).
pub(crate) const NO_IO_DISALLOWED_METHODS: &[&str] = &[
    "std::fs::read",
    "std::fs::read_to_string",
    "std::fs::write",
    "std::fs::read_dir",
    "std::fs::create_dir",
    "std::fs::create_dir_all",
    "std::fs::remove_file",
    "std::fs::remove_dir",
    "std::fs::remove_dir_all",
    "std::fs::rename",
    "std::fs::copy",
    "std::fs::metadata",
    "std::net::ToSocketAddrs::to_socket_addrs",
    "std::env::var",
    "std::env::var_os",
    "std::env::vars",
    "std::env::args",
    "std::env::current_dir",
    "std::env::temp_dir",
    "std::process::exit",
    "std::thread::spawn",
    "std::time::SystemTime::now",
    "std::time::Instant::now",
];

/// R1, API side: each list key of a no-I/O crate's `clippy.toml` with its entries.
pub(crate) const NO_IO_CLIPPY_LISTS: &[(&str, &[&str])] = &[
    ("disallowed-types", NO_IO_DISALLOWED_TYPES),
    ("disallowed-methods", NO_IO_DISALLOWED_METHODS),
];

/// The keys a `{ path = ..., ... }` entry of those lists may have. Never `allow-invalid`: it
/// silences the warning an invalid or module path gets, which ADR 0016 §5 relies on.
pub(crate) const CLIPPY_ENTRY_KEYS: &[&str] = &["path", "reason", "replacement"];

/// The row for `name`, if any.
pub(crate) fn rule(name: &str) -> Option<&'static CrateRule> {
    CRATES.iter().find(|r| r.name == name)
}

/// Whether `name` matches `pattern`, where a trailing `*` matches any suffix.
pub(crate) fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// Whether `name` matches any of `patterns`.
pub(crate) fn matches_any(patterns: &[&str], name: &str) -> bool {
    patterns.iter().any(|p| matches(p, name))
}

/// The semver-compatibility key of a version: `0.x` for `0.x.y`, the major version otherwise.
/// `0.0.z` versions are compatible only with themselves, so they keep all three parts.
/// Pre-release and build suffixes (`-rc.1`, `+meta`) are dropped first, so `2.0.0-rc.1` keys as
/// `2`.
pub(crate) fn compat(version: &str) -> String {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let mut parts = core.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("0"), Some("0"), Some(patch)) => format!("0.0.{patch}"),
        (Some("0"), Some(minor), _) => format!("0.{minor}"),
        (Some(major), _, _) => major.to_owned(),
        (None, _, _) => core.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_row_is_unique_and_well_formed() {
        let names: HashSet<&str> = CRATES.iter().map(|r| r.name).collect();
        assert_eq!(names.len(), CRATES.len(), "duplicate row");
        for r in CRATES {
            assert!(
                r.name == "xtask" || r.name.starts_with("rizzy-"),
                "{}",
                r.name
            );
            assert_eq!(
                r.dir,
                format!("crates/{}", r.name),
                "{}: lives in crates/<name> (ADR 0016 §1; §7 as ADR 0019 §1.4 restates it)",
                r.name
            );
            for dep in r.internal.iter().chain(r.dev_internal) {
                assert!(names.contains(dep), "{} names unknown crate {dep}", r.name);
                assert_ne!(*dep, r.name);
            }
            // Leaf crates are never dependencies (CLAUDE.md, ADR 0016 §2, ADR 0019 §1.4).
            for leaf in [
                "rizzy-server",
                "rizzy-cli",
                "rizzy-wasm",
                "rizzy-ffi",
                "rizzy-ffi-cpp",
            ] {
                assert!(
                    !r.internal.contains(&leaf),
                    "{} depends on leaf {leaf}",
                    r.name
                );
            }
            if !r.no_io {
                assert!(r.external_allow.is_empty(), "{}", r.name);
            }
        }
    }

    /// The ADR 0016 §3 table and notes, R2 (c) and R5, as partially superseded by ADR 0022 (the
    /// `rizzy-domain-relay` row) and ADR 0019 (§1.4's replacing rows), restated: a change to the
    /// table must change this test.
    #[test]
    fn rows_match_adr_0016() {
        assert!(rule("rizzy-domain-relay").is_none(), "ADR 0022 §1");
        assert!(rule("rizzy-desktop").is_none(), "ADR 0019 §1.3: withdrawn");

        let no_io: HashSet<&str> = CRATES.iter().filter(|r| r.no_io).map(|r| r.name).collect();
        let expected: HashSet<&str> = [
            "rizzy-core",
            "rizzy-sync",
            "rizzy-proto",
            "rizzy-client",
            "rizzy-import",
            "rizzy-match",
        ]
        .into();
        assert_eq!(no_io, expected, "R1");

        let leaves: HashSet<&str> = CRATES
            .iter()
            .filter(|r| r.getrandom_direct)
            .map(|r| r.name)
            .collect();
        let expected: HashSet<&str> = [
            "rizzy-server",
            "rizzy-cli",
            "rizzy-wasm",
            "rizzy-ffi",
            "rizzy-ffi-cpp",
            "xtask",
        ]
        .into();
        assert_eq!(leaves, expected, "R2 (c)");

        let wasm_js: Vec<&str> = CRATES
            .iter()
            .filter(|r| r.wasm_js)
            .map(|r| r.name)
            .collect();
        assert_eq!(wasm_js, ["rizzy-wasm"], "R2 (c)");

        let sqlite_only: HashSet<&str> = CRATES
            .iter()
            .filter(|r| r.sqlx == Sqlx::SqliteOnly)
            .map(|r| r.name)
            .collect();
        assert_eq!(
            sqlite_only,
            ["rizzy-cli", "rizzy-ffi", "rizzy-ffi-cpp"].into(),
            "R5"
        );
        for r in CRATES {
            let holds_sqlx = r.name == "rizzy-storage" || r.name.starts_with(DOMAIN_PREFIX);
            assert_eq!(r.sqlx == Sqlx::Server, holds_sqlx, "R5 {}", r.name);
            // R4: no domain crate lists another.
            if r.name.starts_with(DOMAIN_PREFIX) {
                assert!(!r.internal.iter().any(|d| d.starts_with(DOMAIN_PREFIX)));
            }
            // R5: only rizzy-server lists the server-wired crates.
            if r.name != "rizzy-server" {
                assert!(!r.internal.iter().any(|d| matches_any(SERVER_WIRED, d)));
            }
        }

        let dev: Vec<(&str, &[&str])> = CRATES
            .iter()
            .filter(|r| !r.dev_internal.is_empty())
            .map(|r| (r.name, r.dev_internal))
            .collect();
        assert_eq!(
            dev,
            [("rizzy-server", &["rizzy-client"][..])],
            "owner decision 4"
        );

        let openssl: HashSet<&str> = CRATES
            .iter()
            .filter(|r| r.openssl)
            .map(|r| r.name)
            .collect();
        assert_eq!(
            openssl,
            ["rizzy-server", "rizzy-domain-auth"].into(),
            "ADR 0009 owner decision 1"
        );

        let rustix: HashSet<&str> = CRATES.iter().filter(|r| r.rustix).map(|r| r.name).collect();
        assert_eq!(
            rustix,
            ["rizzy-server", "rizzy-cli", "rizzy-ffi", "rizzy-ffi-cpp"].into(),
            "ADR 0024 point 2"
        );
        // Leaf crates only: nothing may depend on a crate that holds rustix.
        for r in CRATES {
            for dep in r.internal.iter().chain(r.dev_internal) {
                assert!(
                    !CRATES.iter().any(|d| d.name == *dep && d.rustix),
                    "ADR 0024 point 2: {} depends on {dep}",
                    r.name
                );
            }
        }
    }

    /// ADR 0016 R6's client-side, server-side and shared crates, as ADR 0019 §1.4 restates the
    /// rule, restated: a change to a row's side must change this test.
    #[test]
    fn sides_match_adr_0016_r6() {
        let side = |s: Side| -> HashSet<&str> {
            CRATES
                .iter()
                .filter(|r| r.side == s)
                .map(|r| r.name)
                .collect()
        };
        let client: HashSet<&str> = [
            "rizzy-client",
            "rizzy-import",
            "rizzy-match",
            "rizzy-wasm",
            "rizzy-ffi",
            "rizzy-ffi-cpp",
            "rizzy-cli",
        ]
        .into();
        assert_eq!(side(Side::Client), client, "R6");
        let server: HashSet<&str> = [
            "rizzy-storage",
            "rizzy-bus",
            "rizzy-smtp-ingress",
            "rizzy-icon-proxy",
            "rizzy-server",
        ]
        .into();
        let (domains, others): (HashSet<&str>, HashSet<&str>) = side(Side::Server)
            .into_iter()
            .partition(|n| n.starts_with(DOMAIN_PREFIX));
        assert_eq!(others, server, "R6");
        assert!(
            CRATES
                .iter()
                .filter(|r| r.name.starts_with(DOMAIN_PREFIX))
                .all(|r| domains.contains(r.name)),
            "R6: every rizzy-domain-* crate is server-side"
        );
        let shared: HashSet<&str> = ["rizzy-core", "rizzy-sync", "rizzy-proto"].into();
        assert_eq!(side(Side::Shared), shared, "R6");
        assert_eq!(side(Side::Tool), ["xtask"].into(), "R6");
    }

    /// ADR 0019 §4.1, owner decision 7: the `unsafe` token scan skips only the committed
    /// expansion baseline of `rizzy-wasm`. A new entry changes this test.
    #[test]
    fn only_the_wasm_baseline_is_skipped() {
        assert_eq!(GENERATED_RUST, ["crates/rizzy-wasm/generated"]);
    }

    /// ADR 0030 Decision 3: the tokens and the scope of the rustls `dangerous()` scan.
    #[test]
    fn the_danger_scan_covers_crate_sources() {
        assert_eq!(DANGER_WORDS, ["dangerous", "danger"]);
        assert!(danger_scanned("crates/rizzy-cli/src/tls.rs"));
        assert!(danger_scanned("crates/rizzy-cli/src/device/x.rs"));
        assert!(danger_scanned("crates/xtask/src/main.rs"));
        assert!(!danger_scanned("crates/rizzy-cli/tests/tls.rs"));
        assert!(!danger_scanned("crates/rizzy-cli/build.rs"));
        assert!(!danger_scanned("crates//src/x.rs"));
        assert!(!danger_scanned("fuzz/fuzz_targets/ca_pem.rs"));
        assert!(!danger_scanned("spikes/x/src/main.rs"));
    }

    /// ADR 0009 "Required feature sets" and its 2026-09-26 amendment, restated: these are the
    /// crates every member declares with default features off. A change to the list must
    /// change this test.
    #[test]
    fn crypto_crates_match_adr_0009() {
        let names: HashSet<&str> = FEATURE_RULES.iter().map(FeatureRule::crate_name).collect();
        let expected: HashSet<&str> = [
            "opaque-ke",
            "hpke",
            "argon2",
            "blake2",
            "sha2",
            "hmac",
            "sha1",
            "hkdf",
            "chacha20poly1305",
            "poly1305",
            "ed25519-dalek",
        ]
        .into();
        assert_eq!(names, expected);
        for name in expected {
            assert!(defaults_off(name), "{name}");
        }
        // Not crypto crates of that section, or not crates at all.
        for name in [
            "serde_json",
            "proptest",
            "sha",
            "sha2_010",
            "blake2@0.11",
            "",
        ] {
            assert!(!defaults_off(name), "{name}");
        }
    }

    #[test]
    fn rand_and_getrandom_are_never_allow_listed_by_accident() {
        for r in CRATES {
            for entry in r.external_allow {
                let name = entry.split('@').next().unwrap_or(entry);
                assert!(
                    !NO_IO_FORBIDDEN.iter().any(|(p, _)| matches(p, name)),
                    "{} allow-lists forbidden crate {entry}",
                    r.name
                );
                assert!(name != "rand" || *entry == RAND.allowed, "{entry}");
            }
        }
    }

    /// ADR 0016 §5: entries name items, never modules, and no entry appears twice.
    #[test]
    fn clippy_lists_name_items() {
        for (list, entries) in NO_IO_CLIPPY_LISTS {
            let unique: HashSet<&&str> = entries.iter().collect();
            assert_eq!(unique.len(), entries.len(), "{list}: duplicate entry");
            for entry in *entries {
                let segments: Vec<&str> = entry.split("::").collect();
                assert!(segments.len() >= 3, "{list}: `{entry}` looks like a module");
                assert_eq!(segments.first(), Some(&"std"), "{list}: {entry}");
                assert!(segments.iter().all(|s| !s.is_empty()), "{list}: {entry}");
            }
        }
        assert_eq!(
            NO_IO_CLIPPY_LISTS
                .iter()
                .map(|(list, entries)| (*list, entries.len()))
                .collect::<Vec<_>>(),
            [("disallowed-types", 10), ("disallowed-methods", 23)],
            "ADR 0016 §5 lists 10 types and 23 methods"
        );
        assert!(!CLIPPY_ENTRY_KEYS.contains(&"allow-invalid"));
    }

    #[test]
    fn compat_keys() {
        assert_eq!(compat("0.8.8"), "0.8");
        assert_eq!(compat("0.10.1"), "0.10");
        assert_eq!(compat("1.9.0"), "1");
        assert_eq!(compat("4.1.3"), "4");
        assert_eq!(compat("0.0.7"), "0.0.7");
        assert_eq!(compat("2.0.0-rc.1"), "2");
    }

    #[test]
    fn wildcard_matching() {
        assert!(matches("sqlx-*", "sqlx-postgres"));
        assert!(!matches("sqlx-*", "sqlx"));
        assert!(matches("sqlx", "sqlx"));
        assert!(!matches("sqlx", "sqlxx"));
        assert!(matches_any(SERVER_WIRED, "rizzy-domain-auth"));
        assert!(!matches_any(SERVER_WIRED, "rizzy-domain"));
    }
}
