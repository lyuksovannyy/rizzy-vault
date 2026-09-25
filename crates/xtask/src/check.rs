//! Rule evaluation for `cargo xtask check-deps` (ADR 0016 §4, §5; ADR 0009).
//!
//! Every check is a pure function of the resolved graphs and the manifests, so the unit tests
//! run them on synthetic metadata.
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

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use crate::manifest::Manifest;
use crate::metadata::{Graph, Kind};
use crate::rules::{self, CrateRule, Side, Sqlx};

/// One broken rule.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Violation {
    /// The rule, as ADR 0016 or ADR 0009 names it.
    pub(crate) rule: &'static str,
    /// The crate that breaks it.
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
}

const NORMAL_BUILD: &[Kind] = &[Kind::Normal, Kind::Build];
const ALL_KINDS: &[Kind] = &[Kind::Normal, Kind::Build, Kind::Dev];

/// Runs every check. An empty result means the tree passes.
pub(crate) fn run(inputs: &Inputs) -> Vec<Violation> {
    let g = &inputs.all_targets;
    let mut out = Vec::new();
    known_crates(g, &mut out);
    no_io_closure(g, "some target (all targets considered)", &mut out);
    for (target, graph) in &inputs.per_target {
        getrandom_closure(graph, target, &mut out);
    }
    direct_dependencies(g, &mut out);
    internal_edges(g, &mut out);
    isolated_ingress(g, &mut out);
    client_server_split(g, &mut out);
    openssl(g, &mut out);
    manifests(inputs, &mut out);
    wasm_alias(g, &inputs.cargo_config, &mut out);
    out.sort();
    out.dedup();
    out
}

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

fn normalise_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// The union of a crate's R1 allow-list and those of its internal dependencies.
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

fn unification_hint(krate: &str, dep: &str) -> String {
    format!(
        " (This check reads the workspace-unified graph. To see whether {krate} built alone \
         also reaches it, run `cargo tree -p {krate} -e normal,build --target all -i {dep}`.)"
    )
}

/// R1 and R2 (a): getrandom never in a no-I/O crate's closure, per named target.
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

/// Direct dependencies as declared: R1 (no `rand` or getrandom in a no-I/O crate), R2 (getrandom
/// only in leaf crates, `wasm_js` only in `rizzy-wasm`), R5 (sqlx holders and the client
/// sqlite-only rule), and the `openapi` feature of `rizzy-proto`.
fn direct_dependencies(g: &Graph, out: &mut Vec<Violation>) {
    let mut wasm_js_declared_by_wasm = false;
    for (i, rule) in members(g) {
        let Some(p) = g.package(i) else { continue };
        for dep in &p.declared {
            let what = format!("{} `{}`", dep.kind.section(), dep.name);
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
                if !rule.getrandom_direct {
                    out.push(violation(
                        "ADR 0016 R2",
                        rule.name,
                        format!(
                            "declares a {what}: only the leaf crates depend on getrandom \
                             directly; libraries take an injected RNG"
                        ),
                    ));
                }
                if dep.features.iter().any(|f| f == "wasm_js") {
                    if rule.wasm_js {
                        wasm_js_declared_by_wasm = true;
                    } else {
                        out.push(violation(
                            "ADR 0016 R2",
                            rule.name,
                            "enables getrandom's `wasm_js`; only rizzy-wasm may".to_owned(),
                        ));
                    }
                }
            }
            if rules::matches_any(rules::SQLX, &dep.name) {
                match rule.sqlx {
                    Sqlx::Forbidden => out.push(violation(
                        "ADR 0016 R5",
                        rule.name,
                        format!(
                            "declares a {what}; only rizzy-storage, the domain crates and the \
                             native client leaf crates depend on sqlx"
                        ),
                    )),
                    Sqlx::SqliteOnly => {
                        let drivers: Vec<&str> = dep
                            .features
                            .iter()
                            .map(String::as_str)
                            .filter(|f| rules::matches_any(rules::SQLX_NON_SQLITE_FEATURES, f))
                            .collect();
                        if !drivers.is_empty()
                            || rules::SQLX_NON_SQLITE_CRATES.contains(&dep.name.as_str())
                        {
                            out.push(violation(
                                "ADR 0016 R5",
                                rule.name,
                                format!(
                                    "{what} enables a non-sqlite driver ({}); client leaf \
                                     crates use only the sqlite driver",
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
            let (proto, feature, owner) = rules::OPENAPI_FEATURE;
            if dep.name == proto && dep.features.iter().any(|f| f == feature) && rule.name != owner
            {
                out.push(violation(
                    "ADR 0016 §3",
                    rule.name,
                    format!("enables {proto}'s `{feature}` feature; only {owner} may"),
                ));
            }
        }
    }
    // A resolved `wasm_js` that rizzy-wasm did not ask for came from somewhere else.
    for p in &g.packages {
        if p.name == "getrandom"
            && p.features.iter().any(|f| f == "wasm_js")
            && !wasm_js_declared_by_wasm
        {
            out.push(violation(
                "ADR 0016 R2",
                &p.label(),
                "has `wasm_js` enabled, but not by rizzy-wasm; a dependency switched it on"
                    .to_owned(),
            ));
        }
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

/// R7 and R8, read from each member's manifest.
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

#[cfg(test)]
mod tests;
