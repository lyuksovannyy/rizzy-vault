//! The rules table of ADR 0016 §3–§5 and ADR 0009, as data.
//!
//! **This table is a security boundary.** Review a change to it like a change to `deny.toml`
//! (ADR 0016, Risks): widening an allow-list or an internal edge is how a no-I/O crate would
//! start doing I/O, or an ingress crate would get a route to the database.
//!
//! Every crate of ADR 0016 §2 and §3 has a row, including the planned ones, so the checks apply
//! the moment a crate is created. A workspace member without a row is itself a violation.

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
    /// crate name, except the Tauri crate, which lives in the desktop app, §7).
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
    /// R1 allow-list of external crates for this crate's own dependencies, as `name@compat`
    /// ([`compat`]). The allow-lists of its internal dependencies are added to it.
    pub(crate) external_allow: &'static [&'static str],
}

impl CrateRule {
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
            external_allow: &[],
        }
    }

    const fn no_io(mut self, external_allow: &'static [&'static str]) -> Self {
        self.no_io = true;
        self.external_allow = external_allow;
        self
    }

    const fn internal(mut self, internal: &'static [&'static str]) -> Self {
        self.internal = internal;
        self
    }

    const fn leaf(mut self) -> Self {
        self.getrandom_direct = true;
        self
    }

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
            .internal(&[
                "rizzy-domain-auth",
                "rizzy-domain-vault",
                "rizzy-domain-relay",
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
        .internal(&["rizzy-core", "rizzy-client"])
        .sqlx(Sqlx::SqliteOnly),
    // §3 lists no internal dependency for `xtask`, but its notes say `xtask` is the one crate
    // that enables `rizzy-proto`'s `openapi` feature, which needs that edge.
    CrateRule::new("xtask", "crates/xtask", Side::Tool)
        .leaf()
        .internal(&["rizzy-proto"]),
    // §3, planned crates. Their R1 allow-lists start empty: the PR that creates a no-I/O crate
    // adds its list, generated from `Cargo.lock` (§5).
    CrateRule::new("rizzy-proto", "crates/rizzy-proto", Side::Shared).no_io(&[]),
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
    CrateRule::new("rizzy-desktop", "apps/desktop/src-tauri", Side::Client)
        .leaf()
        .internal(&["rizzy-client"])
        .sqlx(Sqlx::SqliteOnly),
    CrateRule::new(
        "rizzy-domain-relay",
        "crates/rizzy-domain-relay",
        Side::Server,
    )
    .internal(&["rizzy-sync", "rizzy-proto", "rizzy-storage", "rizzy-bus"])
    .sqlx(Sqlx::Server),
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
    CrateRule::new("rizzy-ffi", "crates/rizzy-ffi", Side::Client)
        .leaf()
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

/// R7: crates with an accepted exception that copy the workspace lint table with only
/// `unsafe_code` changed. Adding one takes a new ADR; there are none.
pub(crate) const LINT_EXCEPTIONS: &[&str] = &[];

/// ADR 0016 §3 notes: only `xtask` enables `rizzy-proto`'s `openapi` feature.
pub(crate) const OPENAPI_FEATURE: (&str, &str, &str) = ("rizzy-proto", "openapi", "xtask");

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
            assert!(
                r.dir.ends_with(r.name) || r.name == "rizzy-desktop",
                "{}: directory name equals crate name (ADR 0016 §1)",
                r.name
            );
            for dep in r.internal.iter().chain(r.dev_internal) {
                assert!(names.contains(dep), "{} names unknown crate {dep}", r.name);
                assert_ne!(*dep, r.name);
            }
            // Leaf binaries are never dependencies (CLAUDE.md, ADR 0016 §2).
            for leaf in [
                "rizzy-server",
                "rizzy-cli",
                "rizzy-desktop",
                "rizzy-wasm",
                "rizzy-ffi",
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

    /// The ADR 0016 §3 table and notes, restated: a change to the table must change this test.
    #[test]
    fn rows_match_adr_0016() {
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
            "rizzy-desktop",
            "rizzy-wasm",
            "rizzy-ffi",
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
            ["rizzy-cli", "rizzy-desktop", "rizzy-ffi"].into(),
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
