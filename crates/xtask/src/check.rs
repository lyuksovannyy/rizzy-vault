//! Rule evaluation for `cargo xtask check-deps` (ADR 0016 §4, §5; ADR 0009; ADR 0019 §4.1;
//! ADR 0024).
//!
//! Every check is a pure function of the resolved graphs, the manifests and the first-party Rust
//! sources, so the unit tests run them on synthetic inputs.
//!
//! **Which graph.** `cargo metadata --all-features` resolves the whole workspace at once, so
//! each package's features are the union over every member and every dependency kind (dev
//! features included). That graph is a superset of what cargo resolves when one crate is built
//! alone (`cargo tree -p <crate>`), which is the evaluation ADR 0016 §5 names for the getrandom
//! rule. Checking the superset is the conservative reading: a pass here implies the per-crate
//! rule holds. The cost is a possible false alarm: if a server-side crate ever turns on a
//! feature of a crate that an R1 crate also uses (ADR 0016 §5's example: `rand`'s `std`), this
//! check fails although the R1 crate built alone is clean. The failure message says how to
//! tell the two apart, and resolving it is a reviewed change to this tool (ADR 0016, Risks).
//!
//! **Which dependency kinds.** A crate's closure is walked with [`Graph::closure`], which takes
//! one set of kinds for the crate's own edges and another for every edge after that. The R1,
//! getrandom, rustix and feature checks use normal and build edges throughout, because tests may
//! use dev-only helpers (ADR 0016 §4). R3, R6 and the openssl rule also follow the crate's own
//! dev edges, then normal and build edges below them: a dependency's dev-dependencies are
//! never built for its dependents, so they are not followed. The checks on declarations (R1's
//! direct `rand` and getrandom, R2, R5, the `openapi` feature, rustix (ADR 0024), and ADR 0009's
//! `default-features = false` on the crypto crates) read every member's entries of every kind.
//!
//! **What this does not check.** Whether a no-I/O crate calls an I/O API is the job of its
//! `clippy.toml` lists under `cargo lint` (checked here only for their contents) and of
//! `cargo check-wasm`. Table ownership (R4, tables) belongs to the planned
//! `cargo xtask check-tables` (ADR 0011, ADR 0016 §5), which does not exist yet. The unit
//! tests in `check/tests.rs` start from a clean tree shaped like the workspace and break one
//! rule at a time; a rule this module misses is a hole in a security boundary.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use crate::manifest::{self, Manifest, TomlValue};
use crate::metadata::{Declared, Graph, Kind, Package};
use crate::rules::{self, CrateRule, Side, Sqlx};
use crate::unsafe_scan;

/// One broken rule.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Violation {
    /// The rule, as ADR 0016, ADR 0009 or ADR 0019 names it.
    pub(crate) rule: &'static str,
    /// The crate that breaks it, `workspace`, or for the `unsafe` token scan the file.
    pub(crate) krate: String,
    /// What is wrong and what to do.
    pub(crate) message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.rule, self.krate, self.message)
    }
}

/// Everything the checks read.
#[derive(Debug)]
pub(crate) struct Inputs {
    /// `cargo metadata --all-features`, every target.
    pub(crate) all_targets: Graph,
    /// The same, with `--filter-platform` for each named target (wasm32 and the host).
    pub(crate) per_target: Vec<(String, Graph)>,
    /// Each workspace member's manifest, by crate name.
    pub(crate) manifests: Vec<(String, Manifest)>,
    /// The root `Cargo.toml`.
    pub(crate) workspace_manifest: Manifest,
    /// `.cargo/config.toml`.
    pub(crate) cargo_config: Manifest,
    /// The root `clippy.toml` (empty if there is none).
    pub(crate) root_clippy: Manifest,
    /// Each no-I/O member's `clippy.toml`, by crate name; `None` if the file does not exist.
    pub(crate) clippy_configs: Vec<(String, Option<Manifest>)>,
    /// Every `.clippy.toml` at the workspace root or in a no-I/O crate's directory. Clippy reads
    /// it in preference to `clippy.toml`, so it would replace the checked file.
    pub(crate) hidden_clippy_configs: Vec<String>,
    /// Every first-party `.rs` file, as (path relative to the workspace root, text), for the
    /// `unsafe` token scan ([`unsafe_scan`]).
    pub(crate) rust_sources: Vec<(String, String)>,
    /// The expansion baseline of `rizzy-wasm` and the locked wasm-bindgen version, for ADR 0019
    /// §4.1 (b) ([`crate::bindings::check`]).
    pub(crate) bindings: crate::bindings::BaselineInput,
}

/// Normal and build dependencies: what ships in, or runs to build, a crate.
const NORMAL_BUILD: &[Kind] = &[Kind::Normal, Kind::Build];
/// Every dependency kind, for the closures that cover dev-dependencies too (R3, R6, openssl).
/// R5 and the §3 internal edges look at direct edges of every kind without it.
const ALL_KINDS: &[Kind] = &[Kind::Normal, Kind::Build, Kind::Dev];

/// Runs every check. An empty result means the tree passes.
///
/// The R1 closure check runs on the all-targets graph, so a dependency that appears only under
/// some `cfg(target)` still counts; the getrandom check also runs on each graph in
/// [`Inputs::per_target`]. The result is sorted and de-duplicated, so the same problem found
/// on two graphs is printed once.
pub(crate) fn run(inputs: &Inputs) -> Vec<Violation> {
    let g = &inputs.all_targets;
    let mut out = Vec::new();
    known_crates(g, &mut out);
    no_io_closure(g, "some target (all targets considered)", &mut out);
    for (target, graph) in &inputs.per_target {
        getrandom_closure(graph, target, &mut out);
    }
    direct_dependencies(g, &mut out);
    crypto_features(g, &mut out);
    crypto_default_features(g, &mut out);
    internal_edges(g, &mut out);
    isolated_ingress(g, &mut out);
    client_server_split(g, &mut out);
    openssl(g, &mut out);
    rustix(g, &mut out);
    manifests(inputs, &mut out);
    workspace_files(inputs, &mut out);
    clippy_configs(inputs, &mut out);
    wasm_alias(g, &inputs.cargo_config, &mut out);
    unsafe_tokens(&inputs.rust_sources, &mut out);
    danger_tokens(&inputs.rust_sources, &mut out);
    for message in crate::bindings::check(&inputs.bindings) {
        out.push(violation(
            "ADR 0019 §4.1",
            crate::bindings::WASM_CRATE,
            message,
        ));
    }
    out.sort();
    out.dedup();
    out
}

/// Builds a [`Violation`].
fn violation(rule: &'static str, krate: &str, message: String) -> Violation {
    Violation {
        rule,
        krate: krate.to_owned(),
        message,
    }
}

/// The members of `g` with their rows. Members without a row are reported by
/// [`known_crates`] and skipped by the other checks.
fn members(g: &Graph) -> Vec<(usize, &'static CrateRule)> {
    g.members()
        .filter_map(|i| Some((i, rules::rule(&g.package(i)?.name)?)))
        .collect()
}

/// The package name at index `i`, or `?` for an index outside the graph (never the case for
/// indices the graph itself produced).
fn name(g: &Graph, i: usize) -> &str {
    g.package(i).map_or("?", |p| p.name.as_str())
}

/// Every member has a row in the rules table and lives where ADR 0016 §1 and §7 say.
fn known_crates(g: &Graph, out: &mut Vec<Violation>) {
    for i in g.members() {
        let Some(p) = g.package(i) else { continue };
        let Some(rule) = rules::rule(&p.name) else {
            out.push(violation(
                "ADR 0016 §3",
                &p.name,
                "this crate is not in xtask's rules table (crates/xtask/src/rules.rs). \
                 Adding a crate needs an ADR 0016 change first, then a row here"
                    .to_owned(),
            ));
            continue;
        };
        let expected = format!(
            "{}/{}/Cargo.toml",
            g.workspace_root.trim_end_matches('/'),
            rule.dir
        );
        if normalise_path(&p.manifest_path) != normalise_path(&expected) {
            out.push(violation(
                "ADR 0016 §1",
                &p.name,
                format!(
                    "manifest is at {}, expected {} (directory name = crate name)",
                    p.manifest_path, expected
                ),
            ));
        }
    }
}

/// The path with Windows separators turned into `/`, so manifest paths compare on every OS.
fn normalise_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// The union of a crate's R1 allow-list and those of its internal dependencies.
///
/// Walks the rules table's "may depend on" edges, not the resolved graph: a crate may reach
/// what its allowed internal dependencies may reach. `seen` stops the walk on a cycle.
fn allow_list(rule: &CrateRule) -> BTreeSet<&'static str> {
    let mut set: BTreeSet<&'static str> = rule.external_allow.iter().copied().collect();
    let mut stack: Vec<&str> = rule.internal.to_vec();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    while let Some(dep) = stack.pop() {
        if !seen.insert(dep) {
            continue;
        }
        if let Some(r) = rules::rule(dep) {
            set.extend(r.external_allow.iter().copied());
            stack.extend(r.internal.iter().copied());
        }
    }
    set
}

/// R1: the normal and build closure of each no-I/O crate holds only allow-listed external
/// crates, nothing from [`rules::NO_IO_FORBIDDEN`], and `rand` only as [`rules::RAND`] allows.
///
/// An external package is keyed as `name@compat` ([`rules::compat`]), so a semver-compatible
/// update passes and a new major (or new `0.x`) version fails until it is allow-listed. A
/// forbidden crate is reported with its reason and not also as "not allow-listed". `target`
/// only names the graph in the message.
fn no_io_closure(g: &Graph, target: &str, out: &mut Vec<Violation>) {
    for (root, rule) in members(g) {
        if !rule.no_io {
            continue;
        }
        let allowed = allow_list(rule);
        let reach = g.closure(root, NORMAL_BUILD, NORMAL_BUILD, &|_, _, _| false);
        for &i in reach.keys() {
            let Some(p) = g.package(i) else { continue };
            if i == root {
                continue;
            }
            if p.is_member {
                // Internal edges are checked by `internal_edges`; the no-I/O property of an
                // internal crate is checked on that crate itself.
                continue;
            }
            let path = g.path(&reach, i);
            if let Some((_, why)) = rules::NO_IO_FORBIDDEN
                .iter()
                .find(|(pattern, _)| rules::matches(pattern, &p.name))
            {
                out.push(violation(
                    "ADR 0016 R1",
                    rule.name,
                    format!(
                        "reaches {} on {target}: {why}. Path: {path}.{}",
                        p.label(),
                        unification_hint(rule.name, &p.name)
                    ),
                ));
                continue;
            }
            let key = format!("{}@{}", p.name, rules::compat(&p.version));
            if !allowed.contains(key.as_str()) {
                out.push(violation(
                    "ADR 0016 R1",
                    rule.name,
                    format!(
                        "reaches {} ({key}), which is not on its external allow-list. Path: \
                         {path}. A new dependency of a no-I/O crate is reviewed like a \
                         security change; if it is approved, add `{key}` in \
                         crates/xtask/src/rules.rs.",
                        p.label()
                    ),
                ));
            }
            if p.name == "rand" {
                rand_rule(g, &reach, i, rule.name, out);
            }
        }
    }
}

/// ADR 0009 "RNG rules": `rand` 0.8 only through opaque-ke, with no features.
///
/// Checks three things for the `rand` package at index `rand`, reached by the no-I/O crate
/// `krate`: its version is the allowed one, every package in `reach` with a normal or build
/// edge to it is an allowed parent, and no feature is enabled on it in the unified graph.
fn rand_rule(
    g: &Graph,
    reach: &HashMap<usize, Option<usize>>,
    rand: usize,
    krate: &str,
    out: &mut Vec<Violation>,
) {
    let Some(p) = g.package(rand) else { return };
    if format!("rand@{}", rules::compat(&p.version)) != rules::RAND.allowed {
        out.push(violation(
            "ADR 0009 RNG rules",
            krate,
            format!(
                "{} is not the one allowed `rand` ({}, through opaque-ke only)",
                p.label(),
                rules::RAND.allowed
            ),
        ));
    }
    let parents: BTreeSet<&str> = reach
        .keys()
        .filter_map(|&i| g.package(i))
        .filter(|q| {
            q.deps
                .iter()
                .any(|e| e.to == rand && e.kinds.iter().any(|k| NORMAL_BUILD.contains(k)))
        })
        .map(|q| q.name.as_str())
        .collect();
    let stray: Vec<&str> = parents
        .iter()
        .copied()
        .filter(|n| !rules::RAND.parents.contains(n))
        .collect();
    if !stray.is_empty() {
        out.push(violation(
            "ADR 0009 RNG rules",
            krate,
            format!(
                "{} is reached through {}; `rand` is allowed only as a dependency of {}",
                p.label(),
                stray.join(", "),
                rules::RAND.parents.join(", ")
            ),
        ));
    }
    let features: Vec<&str> = p
        .features
        .iter()
        .map(String::as_str)
        .filter(|f| !rules::RAND.features.contains(f))
        .collect();
    if !features.is_empty() {
        out.push(violation(
            "ADR 0009 RNG rules",
            krate,
            format!(
                "{} has features [{}] enabled; it is allowed only with default features off \
                 and no features.{}",
                p.label(),
                features.join(", "),
                unification_hint(krate, "rand")
            ),
        ));
    }
}

/// ADR 0009 "Required feature sets" ([`rules::FEATURE_RULES`]): for each listed crypto crate in
/// `rizzy-core`'s normal and build closure, every normal-dependency entry of `rizzy-core` that
/// resolves to it turns on the required features, and no build turns on a forbidden one.
fn crypto_features(g: &Graph, out: &mut Vec<Violation>) {
    let krate = rules::FEATURE_RULES_CRATE;
    let Some(root) = g.member(krate) else { return };
    let Some(p) = g.package(root) else { return };
    let reach = g.closure(root, NORMAL_BUILD, NORMAL_BUILD, &|_, _, _| false);
    let mut reached: Vec<usize> = reach.keys().copied().collect();
    reached.sort_unstable();
    for i in reached {
        let Some(dep) = g.package(i).filter(|d| !d.is_member) else {
            continue;
        };
        let key = format!("{}@{}", dep.name, rules::compat(&dep.version));
        let Some(rule) = rules::FEATURE_RULES.iter().find(|r| r.package == key) else {
            continue;
        };
        // rizzy-core's own normal entries that resolve to this very package.
        let entries: Vec<&Declared> = p
            .declared
            .iter()
            .filter(|d| {
                let extern_name = d.key().replace('-', "_");
                d.kind == Kind::Normal
                    && d.name == dep.name
                    && p.deps.iter().any(|e| {
                        e.to == i && e.name == extern_name && e.kinds.contains(&Kind::Normal)
                    })
            })
            .collect();
        // A required feature is missing when rizzy-core has no entry of its own for the package
        // (it is reached only through another crate, so nothing in rizzy-core's manifest turns
        // the feature on when it is built alone), or when any of its own entries leaves it off.
        let missing: Vec<&str> = rule
            .required
            .iter()
            .copied()
            .filter(|f| {
                entries.is_empty() || entries.iter().any(|d| !d.features.iter().any(|x| x == f))
            })
            .collect();
        if !missing.is_empty() {
            out.push(violation(
                "ADR 0009 required feature sets",
                krate,
                format!(
                    "reaches {} (path: {}) but its own `[dependencies]` entry for it does not \
                     turn on [{}]. Declare `{}.workspace = true`; the workspace entry carries \
                     the ADR 0009 feature set. A feature another crate turns on does not count: \
                     it is off when {krate} is built alone.",
                    dep.label(),
                    g.path(&reach, i),
                    missing.join(", "),
                    dep.name
                ),
            ));
        }
        let forbidden: Vec<&str> = dep
            .features
            .iter()
            .map(String::as_str)
            .filter(|f| rule.forbidden.contains(f))
            .collect();
        if !forbidden.is_empty() {
            out.push(violation(
                "ADR 0009 required feature sets",
                krate,
                format!(
                    "{} has [{}] enabled, which ADR 0009 forbids.{}",
                    dep.label(),
                    forbidden.join(", "),
                    unification_hint(krate, &dep.name)
                ),
            ));
        }
    }
}

/// The default-features check on the crates of ADR 0009 "Required feature sets"
/// ([`rules::FEATURE_RULES`], [`rules::defaults_off`]). The ADR names those crates; the scope
/// is this check's: every workspace member declares each of them with
/// `default-features = false`, in every dependency kind, and never turns its `default` feature
/// back on, whether in the entry or through its `[features]` table ([`declared_features`]).
///
/// Dev and build entries count too. ADR 0009 states the feature sets with no exception for a
/// dependency kind, and cargo unifies a crate's dev-dependency features into its test builds,
/// where the known-answer vectors run: `hpke` with defaults as a dev-dependency of `rizzy-core`
/// would build those tests with getrandom and `mlkem`. This reads the members' declarations,
/// not the resolved graph. A default that a third-party crate turns on is caught, where it
/// matters, by the forbidden half of [`crypto_features`] and by the R1 getrandom rule.
fn crypto_default_features(g: &Graph, out: &mut Vec<Violation>) {
    for i in g.members() {
        let Some(p) = g.package(i) else { continue };
        for dep in &p.declared {
            if !rules::defaults_off(&dep.name) {
                continue;
            }
            let how = if dep.default_features {
                "`default-features` is not `false`"
            } else if declared_features(p, dep).contains(&"default") {
                "the entry or the `[features]` table turns on its `default` feature"
            } else {
                continue;
            };
            let key = dep.key();
            let package = if key == dep.name {
                String::new()
            } else {
                format!(" (package `{}`)", dep.name)
            };
            out.push(violation(
                "ADR 0009 required feature sets",
                &p.name,
                format!(
                    "declares the {} `{key}`{package} with default features on: {how}. \
                     `{}` is a crate of ADR 0009's required feature sets; this check requires \
                     `default-features = false` on every declaration of those crates, by every \
                     member and in every dependency kind. Use `{key}.workspace = true`, keep \
                     `default-features = false` on its `[workspace.dependencies]` entry in the \
                     root Cargo.toml, and do not name `{key}/default`.",
                    dep.kind.section(),
                    dep.name,
                ),
            ));
        }
    }
}

/// The sentence appended to a failure found on the unified graph: how to check with
/// `cargo tree` whether `krate` built alone also reaches `dep` (module docs, "Which graph").
fn unification_hint(krate: &str, dep: &str) -> String {
    format!(
        " (This check reads the workspace-unified graph. To see whether {krate} built alone \
         also reaches it, run `cargo tree -p {krate} -e normal,build --target all -i {dep}`.)"
    )
}

/// R1 and R2 (a): getrandom never in a no-I/O crate's closure, per named target.
///
/// `g` is one of the `--filter-platform` graphs, so a getrandom edge that exists only on
/// wasm32 or only on the host is caught on that target, with the target in the message.
fn getrandom_closure(g: &Graph, target: &str, out: &mut Vec<Violation>) {
    for (root, rule) in members(g) {
        if !rule.no_io {
            continue;
        }
        let reach = g.closure(root, NORMAL_BUILD, NORMAL_BUILD, &|_, _, _| false);
        for &i in reach.keys() {
            let Some(p) = g.package(i) else { continue };
            if p.name == "getrandom" {
                out.push(violation(
                    "ADR 0016 R1/R2",
                    rule.name,
                    format!(
                        "getrandom ({}) is in its dependency closure on {target}. Path: {}.{}",
                        p.version,
                        g.path(&reach, i),
                        unification_hint(rule.name, "getrandom")
                    ),
                ));
            }
        }
    }
}

/// The features a member turns on for one of its declared dependencies: those in the
/// dependency's own entry, plus every `key/feature` and `key?/feature` in the member's
/// `[features]` table, whatever feature carries it. A `[features]` entry enables the feature as
/// surely as the dependency entry does once the member's feature is on, and `--all-features`
/// turns every one on. `key` is the dependency's rename, if it has one.
fn declared_features<'a>(p: &'a Package, dep: &'a Declared) -> Vec<&'a str> {
    let mut features: Vec<&str> = dep.features.iter().map(String::as_str).collect();
    for entry in p.feature_table.iter().flat_map(|(_, enables)| enables) {
        if let Some((key, feature)) = entry.split_once('/')
            && key.strip_suffix('?').unwrap_or(key) == dep.key()
        {
            features.push(feature);
        }
    }
    features
}

/// Direct dependencies as declared: R1 (no `rand` or getrandom in a no-I/O crate), R2 (getrandom
/// only in leaf crates, `wasm_js` only in `rizzy-wasm`), R5 (sqlx holders and the client
/// sqlite-only rule), and the `openapi` feature of `rizzy-proto`. Features count whether the
/// dependency entry or the member's `[features]` table turns them on ([`declared_features`]).
fn direct_dependencies(g: &Graph, out: &mut Vec<Violation>) {
    // The resolved getrandom packages that rizzy-wasm itself turns the JavaScript backend on for.
    let mut wasm_js_by_wasm: BTreeSet<usize> = BTreeSet::new();
    for (i, rule) in members(g) {
        let Some(p) = g.package(i) else { continue };
        for dep in &p.declared {
            let what = format!("{} `{}`", dep.kind.section(), dep.name);
            let features = declared_features(p, dep);
            if rule.no_io && rules::RANDOMNESS_CRATES.contains(&dep.name.as_str()) {
                out.push(violation(
                    "ADR 0016 R1",
                    rule.name,
                    format!(
                        "declares a {what}: no-I/O crates take an injected \
                         `rand_core::CryptoRng` and never depend on `rand` or getrandom"
                    ),
                ));
            }
            if dep.name == "getrandom" {
                getrandom_entry(g, p, dep, &features, rule, &mut wasm_js_by_wasm, out);
            }
            if rules::matches_any(rules::SQLX, &dep.name) {
                sqlx_entry(dep, &features, rule, out);
            }
            let (proto, feature, owner) = rules::OPENAPI_FEATURE;
            if dep.name == proto && features.contains(&feature) && rule.name != owner {
                out.push(violation(
                    "ADR 0016 §3",
                    rule.name,
                    format!("enables {proto}'s `{feature}` feature; only {owner} may"),
                ));
            }
        }
    }
    // Backstop: a resolved JavaScript backend on any getrandom package other than the ones
    // rizzy-wasm's own entries resolve to came from somewhere else, such as a third-party crate
    // or a second getrandom version.
    for (i, p) in g.packages.iter().enumerate() {
        if p.name != "getrandom" || wasm_js_by_wasm.contains(&i) {
            continue;
        }
        if let Some(f) = p
            .features
            .iter()
            .find(|f| rules::GETRANDOM_WASM_FEATURES.contains(&f.as_str()))
        {
            out.push(violation(
                "ADR 0016 R2",
                &p.label(),
                format!("has `{f}` enabled, but not by rizzy-wasm; a dependency switched it on"),
            ));
        }
    }
}

/// R2 for one declared getrandom dependency of member `p`: only leaf crates declare it, and only
/// `rizzy-wasm` turns on its JavaScript backend. For `rizzy-wasm`, records the resolved packages
/// this entry points at in `wasm_js_by_wasm`.
fn getrandom_entry(
    g: &Graph,
    p: &Package,
    dep: &Declared,
    features: &[&str],
    rule: &CrateRule,
    wasm_js_by_wasm: &mut BTreeSet<usize>,
    out: &mut Vec<Violation>,
) {
    if !rule.getrandom_direct {
        out.push(violation(
            "ADR 0016 R2",
            rule.name,
            format!(
                "declares a {} `{}`: only the leaf crates depend on getrandom directly; \
                 libraries take an injected RNG",
                dep.kind.section(),
                dep.name
            ),
        ));
    }
    let backend: Vec<&str> = features
        .iter()
        .copied()
        .filter(|f| rules::GETRANDOM_WASM_FEATURES.contains(f))
        .collect();
    if backend.is_empty() {
        return;
    }
    if rule.wasm_js {
        // The resolved package this very dependency entry points at.
        let extern_name = dep.key().replace('-', "_");
        wasm_js_by_wasm.extend(
            p.deps
                .iter()
                .filter(|e| e.name == extern_name && name(g, e.to) == "getrandom")
                .map(|e| e.to),
        );
    } else {
        out.push(violation(
            "ADR 0016 R2",
            rule.name,
            format!(
                "enables getrandom's `{}` (in the dependency entry or through `[features]`); \
                 only rizzy-wasm may",
                backend.join("`, `")
            ),
        ));
    }
}

/// R5 for one declared sqlx dependency: only the holders declare it, and a client leaf crate
/// only with the sqlite driver.
fn sqlx_entry(dep: &Declared, features: &[&str], rule: &CrateRule, out: &mut Vec<Violation>) {
    let what = format!("{} `{}`", dep.kind.section(), dep.name);
    match rule.sqlx {
        Sqlx::Forbidden => out.push(violation(
            "ADR 0016 R5",
            rule.name,
            format!(
                "declares a {what}; only rizzy-storage, the domain crates and the native client \
                 leaf crates depend on sqlx"
            ),
        )),
        Sqlx::SqliteOnly => {
            let drivers: Vec<&str> = features
                .iter()
                .copied()
                .filter(|f| rules::matches_any(rules::SQLX_NON_SQLITE_FEATURES, f))
                .collect();
            if !drivers.is_empty() || rules::SQLX_NON_SQLITE_CRATES.contains(&dep.name.as_str()) {
                out.push(violation(
                    "ADR 0016 R5",
                    rule.name,
                    format!(
                        "{what} enables a non-sqlite driver ({}); client leaf crates use only \
                         the sqlite driver",
                        if drivers.is_empty() {
                            dep.name.clone()
                        } else {
                            drivers.join(", ")
                        }
                    ),
                ));
            }
        }
        Sqlx::Server => {}
    }
}

/// Internal edges: the §3 "May depend on (internal)" column, for every dependency kind, with
/// the one dev-only exception; R4 (no domain crate depends on another); R5 (only
/// `rizzy-server` depends on the domain crates and the ingress crates).
fn internal_edges(g: &Graph, out: &mut Vec<Violation>) {
    for (i, rule) in members(g) {
        let Some(p) = g.package(i) else { continue };
        for edge in &p.deps {
            let Some(dep) = g.package(edge.to) else {
                continue;
            };
            if !dep.is_member {
                continue;
            }
            for &kind in &edge.kinds {
                let allowed = rule.internal.contains(&dep.name.as_str())
                    || (kind == Kind::Dev && rule.dev_internal.contains(&dep.name.as_str()));
                if !allowed {
                    out.push(violation(
                        "ADR 0016 §3",
                        rule.name,
                        format!(
                            "{} on {} is not allowed; it may depend on [{}]{}",
                            kind.section(),
                            dep.name,
                            rule.internal.join(", "),
                            if rule.dev_internal.is_empty() {
                                String::new()
                            } else {
                                format!(
                                    " and, as a dev-dependency, [{}]",
                                    rule.dev_internal.join(", ")
                                )
                            }
                        ),
                    ));
                }
            }
            if rule.name.starts_with(rules::DOMAIN_PREFIX)
                && dep.name.starts_with(rules::DOMAIN_PREFIX)
            {
                out.push(violation(
                    "ADR 0016 R4",
                    rule.name,
                    format!(
                        "depends on {}; domains are separate, define a trait that rizzy-server \
                         wires, or use rizzy-bus events",
                        dep.name
                    ),
                ));
            }
            if rules::matches_any(rules::SERVER_WIRED, &dep.name) && rule.name != "rizzy-server" {
                out.push(violation(
                    "ADR 0016 R5",
                    rule.name,
                    format!("depends on {}; only rizzy-server depends on it", dep.name),
                ));
            }
        }
    }
}

/// R3: the ingress crates reach no storage, bus, domain or sqlx crate (and `rizzy-icon-proxy`
/// no `rizzy-core`), over normal, build and dev dependencies.
fn isolated_ingress(g: &Graph, out: &mut Vec<Violation>) {
    for (krate, forbidden) in rules::ISOLATED_INGRESS {
        let Some(root) = g.member(krate) else {
            continue;
        };
        let reach = g.closure(root, ALL_KINDS, NORMAL_BUILD, &|_, _, _| false);
        for &i in reach.keys() {
            if i != root && rules::matches_any(forbidden, name(g, i)) {
                out.push(violation(
                    "ADR 0016 R3",
                    krate,
                    format!(
                        "reaches {}: isolated ingress has no route to the database. Path: {}",
                        name(g, i),
                        g.path(&reach, i)
                    ),
                ));
            }
        }
    }
}

/// R6: client-side and server-side crates never reach each other, over normal, build and dev
/// dependencies, except `rizzy-server`'s dev-dependency on `rizzy-client` and what lies behind
/// it (owner decision 4).
fn client_server_split(g: &Graph, out: &mut Vec<Violation>) {
    for (root, rule) in members(g) {
        let other = match rule.side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
            Side::Shared | Side::Tool => continue,
        };
        // The one exception (ADR 0016 owner decision 4): the root's own dev edge to a
        // `dev_internal` crate is not followed, so what rizzy-server reaches only through its
        // dev-dependency on rizzy-client is not reported. A normal or build edge to the same
        // crate is still followed.
        let skip = |from: usize, to: usize, kind: Kind| {
            from == root && kind == Kind::Dev && rule.dev_internal.contains(&name(g, to))
        };
        let reach = g.closure(root, ALL_KINDS, NORMAL_BUILD, &skip);
        for &i in reach.keys() {
            let Some(dep_rule) = g
                .package(i)
                .filter(|p| p.is_member)
                .and_then(|p| rules::rule(&p.name))
            else {
                continue;
            };
            if dep_rule.side == other {
                out.push(violation(
                    "ADR 0016 R6",
                    rule.name,
                    format!(
                        "a {:?}-side crate reaches the {:?}-side crate {}. Path: {}",
                        rule.side,
                        other,
                        dep_rule.name,
                        g.path(&reach, i)
                    ),
                ));
            }
        }
    }
}

/// ADR 0009 owner decision 1: `openssl` and `openssl-sys` are reachable only from the crates
/// allowed to reach them, over normal, build and dev dependencies.
fn openssl(g: &Graph, out: &mut Vec<Violation>) {
    for (root, rule) in members(g) {
        if rule.openssl {
            continue;
        }
        let reach = g.closure(root, ALL_KINDS, NORMAL_BUILD, &|_, _, _| false);
        for &i in reach.keys() {
            if rules::OPENSSL.contains(&name(g, i)) {
                out.push(violation(
                    "ADR 0009 owner decision 1",
                    rule.name,
                    format!(
                        "reaches {}; only rizzy-server and rizzy-domain-auth may. Path: {}",
                        name(g, i),
                        g.path(&reach, i)
                    ),
                ));
            }
        }
    }
}

/// ADR 0024 point 2: rustix only in the leaf crates whose row allows it. A member without the
/// right must not declare it in any dependency kind, and must not reach it over normal and build
/// dependencies either, so it never ships in a library (`rizzy-core`, `rizzy-sync`,
/// `rizzy-client`, a server library) through a third-party crate. Dev-only paths below a
/// member are not followed: they never ship.
fn rustix(g: &Graph, out: &mut Vec<Violation>) {
    for (root, rule) in members(g) {
        if rule.rustix {
            continue;
        }
        let Some(p) = g.package(root) else { continue };
        for dep in p.declared.iter().filter(|d| d.name == rules::RUSTIX) {
            out.push(violation(
                "ADR 0024 point 2",
                rule.name,
                format!(
                    "declares a {} `{}`; only the leaf crates rizzy-server, rizzy-cli, rizzy-ffi \
                     and rizzy-ffi-cpp depend on rustix",
                    dep.kind.section(),
                    dep.name
                ),
            ));
        }
        let reach = g.closure(root, NORMAL_BUILD, NORMAL_BUILD, &|_, _, _| false);
        for &i in reach.keys() {
            if name(g, i) == rules::RUSTIX {
                out.push(violation(
                    "ADR 0024 point 2",
                    rule.name,
                    format!(
                        "reaches rustix; only the leaf crates that hold it may. Path: {}",
                        g.path(&reach, i)
                    ),
                ));
            }
        }
    }
}

/// R7 and R8, read from each member's manifest.
///
/// A line the TOML reader could not read fails the crate, since it could hide the tables
/// checked here. R8: `publish`, `license` and `rust-version` are inherited from the workspace.
/// R7: `[lints]` holds exactly `workspace = true`, unless the crate is on
/// [`rules::LINT_EXCEPTIONS`] (empty), in which case [`lint_copy`] compares its table.
fn manifests(inputs: &Inputs, out: &mut Vec<Violation>) {
    for (krate, manifest) in &inputs.manifests {
        for error in &manifest.errors {
            out.push(violation(
                "ADR 0016 R7/R8",
                krate,
                format!("Cargo.toml {error}; check-deps cannot read it, so it cannot pass"),
            ));
        }
        for field in ["publish", "license", "rust-version"] {
            if !manifest.inherits("package", field) {
                out.push(violation(
                    "ADR 0016 R8",
                    krate,
                    format!("`{field}` must be inherited: `{field}.workspace = true`"),
                ));
            }
        }
        let lints: Vec<(&str, &str)> = manifest.under("lints").collect();
        let inherits = matches!(lints.as_slice(), [("lints.workspace", "true")])
            || matches!(lints.as_slice(), [("lints", "{workspace=true}")]);
        if inherits {
            continue;
        }
        if rules::LINT_EXCEPTIONS.contains(&krate.as_str()) {
            lint_copy(krate, manifest, &inputs.workspace_manifest, out);
        } else {
            out.push(violation(
                "ADR 0016 R7",
                krate,
                "must set `[lints] workspace = true` and nothing else in `[lints]`".to_owned(),
            ));
        }
    }
}

/// R7 exception: the crate's lint table equals the workspace's except `unsafe_code`.
fn lint_copy(krate: &str, manifest: &Manifest, workspace: &Manifest, out: &mut Vec<Violation>) {
    let exempt = "lints.rust.unsafe_code";
    let theirs: BTreeSet<(String, &str)> = manifest
        .under("lints")
        .filter(|(k, _)| *k != exempt)
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
    let ours: BTreeSet<(String, &str)> = workspace
        .under("workspace.lints")
        .map(|(k, v)| (k.trim_start_matches("workspace.").to_owned(), v))
        .filter(|(k, _)| k != exempt)
        .collect();
    if theirs != ours || manifest.get(exempt).is_none() {
        out.push(violation(
            "ADR 0016 R7",
            krate,
            "has a lint-table exception, so its `[lints]` must copy `[workspace.lints]` exactly, \
             changing only `rust.unsafe_code`"
                .to_owned(),
        ));
    }
}

/// R7 on the workspace side: `[workspace.lints.rust]` sets `unsafe_code = "forbid"`. `deny` is
/// not enough: an in-source `#[allow]` or `#[expect]` can lower `deny`, never `forbid` (E0453).
/// Also reports the lines the reader could not read in the root manifest and in
/// `.cargo/config.toml`: a line hidden from it could hide the lint table or the alias.
fn workspace_files(inputs: &Inputs, out: &mut Vec<Violation>) {
    for (file, rule, m) in [
        ("Cargo.toml", "ADR 0016 R7", &inputs.workspace_manifest),
        (".cargo/config.toml", "ADR 0016 §5", &inputs.cargo_config),
    ] {
        for error in &m.errors {
            out.push(violation(
                rule,
                "workspace",
                format!("{file} {error}; check-deps cannot read it, so it cannot pass"),
            ));
        }
    }
    let key = "workspace.lints.rust.unsafe_code";
    let entries: Vec<(&str, &str)> = inputs.workspace_manifest.under(key).collect();
    let forbid = TomlValue::Str("forbid".to_owned());
    let forbids = match entries.as_slice() {
        [(k, v)] if *k == key => match manifest::parse_value(v) {
            Ok(level @ TomlValue::Str(_)) => level == forbid,
            // `{ level = "forbid", priority = N }`.
            Ok(TomlValue::Table(fields)) => {
                let levels: Vec<&TomlValue> = fields
                    .iter()
                    .filter(|(k, _)| k == "level")
                    .map(|(_, v)| v)
                    .collect();
                levels == [&forbid]
                    && fields.iter().all(|(k, v)| {
                        k == "level" || (k == "priority" && matches!(v, TomlValue::Bare(_)))
                    })
            }
            _ => false,
        },
        _ => false,
    };
    if !forbids {
        out.push(violation(
            "ADR 0016 R7",
            "workspace",
            "the root Cargo.toml must set `unsafe_code = \"forbid\"` in `[workspace.lints.rust]`; \
             not `deny` or `allow`, because in-source attributes can lower `deny` but never \
             `forbid`"
                .to_owned(),
        ));
    }
}

/// ADR 0016 §5, R1 API side: every no-I/O crate has a `clippy.toml` that repeats every key of
/// the root one (a crate-level `clippy.toml` replaces the root file, it does not merge with it),
/// sets nothing else, and whose `disallowed-types` and `disallowed-methods` equal the ADR's
/// lists ([`rules::NO_IO_CLIPPY_LISTS`]) plus any the root file has. Nothing may replace those
/// files: no `.clippy.toml` beside them, no `CLIPPY_CONF_DIR` in `.cargo/config.toml`.
fn clippy_configs(inputs: &Inputs, out: &mut Vec<Violation>) {
    let root = &inputs.root_clippy;
    let mut unreadable: Vec<String> = root.errors.clone();
    for (list, _) in rules::NO_IO_CLIPPY_LISTS {
        if let Some(Err(e)) = root.get(list).map(clippy_paths) {
            unreadable.push(format!("`{list}`: {e}"));
        }
    }
    for what in unreadable {
        out.push(violation(
            "ADR 0016 §5",
            "workspace",
            format!("clippy.toml {what}; check-deps cannot read it, so it cannot pass"),
        ));
    }
    for hidden in &inputs.hidden_clippy_configs {
        out.push(violation(
            "ADR 0016 §5",
            "workspace",
            format!(
                "{hidden} exists; clippy reads it instead of clippy.toml, so the checked R1 \
                 lists would not apply. Remove it"
            ),
        ));
    }
    if let Some((key, _)) = inputs.cargo_config.entries.iter().find(|(k, v)| {
        (k == "env" || k.starts_with("env."))
            && (k.contains("CLIPPY_CONF_DIR") || v.contains("CLIPPY_CONF_DIR"))
    }) {
        out.push(violation(
            "ADR 0016 §5",
            "workspace",
            format!(
                ".cargo/config.toml sets `{key}`, which points clippy away from each crate's \
                 clippy.toml and so switches off the R1 lists"
            ),
        ));
    }
    for (krate, file) in &inputs.clippy_configs {
        match file {
            Some(file) => clippy_file(krate, file, root, out),
            None => out.push(violation(
                "ADR 0016 §5",
                krate,
                "has no clippy.toml: a no-I/O crate carries one that repeats the root \
                 clippy.toml and adds the R1 disallowed-types and disallowed-methods lists \
                 (copy crates/rizzy-core/clippy.toml)"
                    .to_owned(),
            )),
        }
    }
}

/// One no-I/O crate's `clippy.toml` against the root one and the ADR 0016 §5 lists.
fn clippy_file(krate: &str, file: &Manifest, root: &Manifest, out: &mut Vec<Violation>) {
    let lists: Vec<&str> = rules::NO_IO_CLIPPY_LISTS.iter().map(|(l, _)| *l).collect();
    let unreadable = |what: String| {
        violation(
            "ADR 0016 §5",
            krate,
            format!("clippy.toml {what}; check-deps cannot read it, so it cannot pass"),
        )
    };
    for error in &file.errors {
        out.push(unreadable(error.clone()));
    }
    for (key, value) in &root.entries {
        if !lists.contains(&key.as_str()) && file.get(key) != Some(value.as_str()) {
            out.push(violation(
                "ADR 0016 §5",
                krate,
                format!(
                    "its clippy.toml does not repeat the root clippy.toml's `{key} = {value}`; \
                     a crate-level clippy.toml replaces the root one"
                ),
            ));
        }
    }
    for (key, _) in &file.entries {
        if !lists.contains(&key.as_str()) && root.get(key).is_none() {
            out.push(violation(
                "ADR 0016 §5",
                krate,
                format!(
                    "its clippy.toml sets `{key}`, which the root clippy.toml does not; it must \
                     be the root file plus the R1 lists"
                ),
            ));
        }
    }
    for (list, adr) in rules::NO_IO_CLIPPY_LISTS {
        let mut expected: BTreeSet<String> = adr.iter().map(|p| (*p).to_owned()).collect();
        // A root list the crate file must repeat; an unreadable one is reported on the root.
        if let Some(Ok(paths)) = root.get(list).map(clippy_paths) {
            expected.extend(paths);
        }
        let paths = match file.get(list).map(clippy_paths) {
            Some(Ok(paths)) => paths,
            Some(Err(e)) => {
                out.push(unreadable(format!("`{list}`: {e}")));
                continue;
            }
            None => Vec::new(),
        };
        let got: BTreeSet<String> = paths.iter().cloned().collect();
        let missing: Vec<&str> = expected.difference(&got).map(String::as_str).collect();
        let extra: Vec<&str> = got.difference(&expected).map(String::as_str).collect();
        if !missing.is_empty() || !extra.is_empty() || got.len() != paths.len() {
            out.push(violation(
                "ADR 0016 §5",
                krate,
                format!(
                    "its clippy.toml `{list}` must list ADR 0016 §5's entries once each \
                     (crates/xtask/src/rules.rs); missing [{}], not in the ADR [{}]",
                    missing.join(", "),
                    extra.join(", ")
                ),
            ));
        }
    }
}

/// The paths of a `disallowed-types` or `disallowed-methods` value: each entry is a path
/// string or a `{ path = "...", reason = "..." }` table with only [`rules::CLIPPY_ENTRY_KEYS`].
fn clippy_paths(value: &str) -> Result<Vec<String>, String> {
    let TomlValue::Array(items) = manifest::parse_value(value)? else {
        return Err("expected an array".to_owned());
    };
    items
        .into_iter()
        .map(|item| match item {
            TomlValue::Str(path) => Ok(path),
            TomlValue::Table(fields) => {
                if let Some((key, _)) = fields
                    .iter()
                    .find(|(k, _)| !rules::CLIPPY_ENTRY_KEYS.contains(&k.as_str()))
                {
                    return Err(format!(
                        "an entry sets `{key}`; only `{}` are allowed (`allow-invalid` would hide \
                         the warning for a module path)",
                        rules::CLIPPY_ENTRY_KEYS.join("`, `")
                    ));
                }
                let paths: Vec<&TomlValue> = fields
                    .iter()
                    .filter(|(k, _)| k == "path")
                    .map(|(_, v)| v)
                    .collect();
                match paths.as_slice() {
                    [TomlValue::Str(path)] => Ok(path.clone()),
                    _ => Err("an entry needs exactly one string `path`".to_owned()),
                }
            }
            _ => Err("an entry is neither a path string nor a `{ path = ... }` table".to_owned()),
        })
        .collect()
}

/// ADR 0016 §5 ("fails when clippy's output contains 'found a module'"): the problems clippy
/// reports with a `clippy.toml` entry. That is every line saying "found a module" (clippy then
/// ignores the entry), and every other diagnostic located in a `clippy.toml`, such as a path
/// that "does not refer to a reachable function". `-D warnings` does not make these errors
/// (checked with clippy 1.94.1), so `cargo lint` passes with them.
pub(crate) fn clippy_config_warnings(output: &str) -> Vec<String> {
    let mut found = BTreeSet::new();
    // The current diagnostic's first line, and whether it still has to be reported.
    let mut message = "";
    let mut pending = false;
    // Clippy prints a diagnostic as a `warning: ...` or `error: ...` line, usually followed by
    // a `--> path:line:column` location line. A diagnostic whose location is a clippy.toml is
    // reported with that location; a "found a module" diagnostic is reported even without
    // one, and so is any other line that says "found a module".
    for line in output.lines() {
        let location = line.trim_start().strip_prefix("--> ");
        if line.starts_with("warning") || line.starts_with("error") {
            if pending {
                found.insert(message.trim().to_owned());
            }
            message = line;
            pending = line.contains("found a module");
        } else if let Some(location) = location.filter(|l| in_clippy_toml(l)) {
            found.insert(format!("{} (at {location})", message.trim()));
            pending = false;
        } else if line.contains("found a module") {
            found.insert(line.trim().to_owned());
        }
    }
    if pending {
        found.insert(message.trim().to_owned());
    }
    found.into_iter().collect()
}

/// Whether a diagnostic location `path:line:column` is in a `clippy.toml` or `.clippy.toml`.
fn in_clippy_toml(location: &str) -> bool {
    // Split from the right: the path itself may contain `:` (a Windows drive letter).
    let mut parts = location.trim().rsplitn(3, ':');
    let (column, line, path) = (parts.next(), parts.next(), parts.next());
    let number =
        |s: Option<&str>| s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    number(column) && number(line) && path.is_some_and(|p| p.ends_with("clippy.toml"))
}

/// ADR 0016 §5 (R1, build side): `cargo check-wasm` covers every no-I/O crate and
/// `rizzy-wasm`.
fn wasm_alias(g: &Graph, config: &Manifest, out: &mut Vec<Violation>) {
    let alias = config.get("alias.check-wasm").unwrap_or_default();
    let words: Vec<&str> = alias.trim_matches('"').split_whitespace().collect();
    // `normalise_value` removed the spaces outside the string only, so the words are intact.
    let has = |flag: &str, value: &str| {
        words
            .windows(2)
            .any(|w| matches!(w, [f, v] if *f == flag && *v == value))
    };
    if !has("--target", "wasm32-unknown-unknown") {
        out.push(violation(
            "ADR 0016 §5",
            "workspace",
            "the `check-wasm` alias in .cargo/config.toml must pass \
             `--target wasm32-unknown-unknown`"
                .to_owned(),
        ));
    }
    for (_, rule) in members(g) {
        if (rule.no_io || rule.wasm_js) && !(has("-p", rule.name) || has("--package", rule.name)) {
            out.push(violation(
                "ADR 0016 §5",
                rule.name,
                "must be checked by the `check-wasm` alias in .cargo/config.toml \
                 (`-p <crate>`)"
                    .to_owned(),
            ));
        }
    }
}

/// ADR 0019 §4.1: no `unsafe` keyword token in a first-party `.rs` file ([`unsafe_scan`]). Each
/// token is one violation, located by file, line and column. A file the scan cannot read to its
/// end fails closed.
fn unsafe_tokens(sources: &[(String, String)], out: &mut Vec<Violation>) {
    let rule = "ADR 0019 §4.1";
    for (path, text) in sources {
        match unsafe_scan::unsafe_tokens(text) {
            Ok(found) => out.extend(found.into_iter().map(|at| {
                violation(
                    rule,
                    path,
                    format!(
                        "line {}, column {}: the `unsafe` keyword in first-party source. Our \
                         code gets no `unsafe` exception (ADR 0013 owner decision 1, ADR 0019 \
                         owner decision 7), and `forbid(unsafe_code)` can miss `unsafe` in a \
                         macro's input",
                        at.line, at.column
                    ),
                )
            })),
            Err(e) => out.push(violation(
                rule,
                path,
                format!("{e}; the rest of the file cannot be scanned, so it cannot pass"),
            )),
        }
    }
}

/// ADR 0030 Decision 3: no rustls `dangerous()` API in `crates/*/src`. Reports every
/// [`rules::DANGER_WORDS`] token, comments and literals excluded, in the files
/// [`rules::danger_scanned`] selects. A file the lexer cannot finish is already a violation of
/// [`unsafe_tokens`], which scans the same files, so it is not reported twice here.
fn danger_tokens(sources: &[(String, String)], out: &mut Vec<Violation>) {
    let rule = "ADR 0030 Decision 3";
    for (path, text) in sources {
        if !rules::danger_scanned(path) {
            continue;
        }
        let Ok(found) = unsafe_scan::word_tokens(text, rules::DANGER_WORDS) else {
            continue;
        };
        out.extend(found.into_iter().map(|(index, at)| {
            let word = rules::DANGER_WORDS.get(index).copied().unwrap_or("?");
            violation(
                rule,
                path,
                format!(
                    "line {}, column {}: the token `{word}` in first-party source. The rustls \
                     `dangerous()` APIs (a custom or disabled certificate verifier) must not \
                     appear in our code; trust is the public roots or a private CA file",
                    at.line, at.column
                ),
            )
        }));
    }
}

#[cfg(test)]
mod tests;
