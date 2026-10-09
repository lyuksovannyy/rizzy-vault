//! The resolved dependency graph, read from `cargo metadata --format-version 1` JSON.
//!
//! Only the fields the checks need are kept. The JSON is read through `serde_json::Value`, and
//! a missing or mistyped field is an error: the check fails closed rather than skipping a
//! package it could not read. The two exceptions are fields cargo itself leaves out or sets to
//! `null` for the default: a dependency's `kind` (normal) and its `rename` (none).
//!
//! Packages are stored in a `Vec` and referred to by index; resolved edges point at those
//! indices. The `resolve` section is required, so `cargo metadata --no-deps` output is refused.

use std::collections::HashMap;

use serde_json::Value;

/// A dependency kind, as `cargo metadata` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    /// `[dependencies]`.
    Normal,
    /// `[build-dependencies]`.
    Build,
    /// `[dev-dependencies]`.
    Dev,
}

impl Kind {
    /// Reads a `kind` value: `null` is a normal dependency, `"build"` and `"dev"` the others.
    ///
    /// # Errors
    ///
    /// Returns a message for any other value.
    fn parse(value: &Value) -> Result<Self, String> {
        match value {
            Value::Null => Ok(Self::Normal),
            Value::String(s) if s == "build" => Ok(Self::Build),
            Value::String(s) if s == "dev" => Ok(Self::Dev),
            other => Err(format!("unknown dependency kind {other}")),
        }
    }

    /// The Cargo manifest section name, for messages.
    pub(crate) const fn section(self) -> &'static str {
        match self {
            Self::Normal => "dependency",
            Self::Build => "build-dependency",
            Self::Dev => "dev-dependency",
        }
    }
}

/// A resolved edge: `to` is a package index, `kinds` every kind it is used as, `name` the
/// crate name the dependent uses for it (the rename, if any, with `-` as `_`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Edge {
    /// Index of the dependency in [`Graph::packages`].
    pub(crate) to: usize,
    /// Every kind the edge is used as, each once, over all targets of the graph.
    pub(crate) kinds: Vec<Kind>,
    /// The extern crate name the dependent uses: the rename if any, else the package name,
    /// with `-` as `_`.
    pub(crate) name: String,
}

/// A dependency as declared in a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Declared {
    /// The package name (not the rename).
    pub(crate) name: String,
    /// The rename (`key = { package = "name" }`), if any.
    pub(crate) rename: Option<String>,
    /// The manifest section it is declared in.
    pub(crate) kind: Kind,
    /// The features the entry itself lists (not those turned on through `[features]`).
    pub(crate) features: Vec<String>,
    /// Whether the entry keeps default features (`default-features` not set to `false`). The
    /// ADR 0009 default-features check in `check.rs` requires `false` for every crate that
    /// [`crate::rules::defaults_off`] names, in every member and every dependency kind.
    pub(crate) default_features: bool,
    /// Whether the dependency is optional (`optional = true`). An optional dependency's
    /// resolved edge ([`Edge`]) is only "live" — actually compiled — when the owning package's
    /// own resolved [`Package::features`] names it ([`Graph::closure`]'s liveness filter):
    /// Cargo always includes the implicit per-optional-dependency feature (named after the
    /// dependency's [`Declared::key`]) in a node's resolved `features` whenever that dependency
    /// ends up switched on, however it got enabled. A non-optional dependency has no such gate.
    pub(crate) optional: bool,
}

impl Declared {
    /// The key the manifest uses for it: the rename, or the package name. `[features]` entries
    /// (`key/feature`) refer to it by this key, and resolved edges ([`Edge::name`]) by this key
    /// with `-` as `_`.
    pub(crate) fn key(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.name)
    }
}

/// One package with its resolved features and edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Package {
    /// Cargo's package id, the key that links `packages` and `resolve.nodes`.
    pub(crate) id: String,
    /// The package name.
    pub(crate) name: String,
    /// The exact version, as `cargo metadata` prints it.
    pub(crate) version: String,
    /// Absolute path of its `Cargo.toml`.
    pub(crate) manifest_path: String,
    /// Whether it is a workspace member (listed in `workspace_members`).
    pub(crate) is_member: bool,
    /// Resolved features, unified across the workspace.
    pub(crate) features: Vec<String>,
    /// Resolved edges from its `resolve` node. Empty for a package the graph does not resolve.
    pub(crate) deps: Vec<Edge>,
    /// Its dependencies as its manifest declares them: every `[dependencies]`/
    /// `[build-dependencies]`/`[dev-dependencies]` entry, from every `[target.'cfg(..)'.…]`
    /// table and the untargeted one alike, flattened into one list. Each entry keeps its own
    /// [`Declared::kind`]; none keeps which `cfg(..)` (or none) it came from — `cargo
    /// metadata`'s per-platform resolution already decides whether the edge exists at all, and
    /// [`Graph::edge_is_live`] checks every entry that matches a `(kind, name)`, not just one,
    /// precisely because more than one can exist here.
    pub(crate) declared: Vec<Declared>,
    /// The package's own `[features]` table: each feature with what it enables, in name order.
    pub(crate) feature_table: Vec<(String, Vec<String>)>,
}

impl Package {
    /// Whether this package's own resolved [`features`](Self::features) switch the optional
    /// dependency named `key` on.
    ///
    /// Cargo creates an implicit feature named after an optional dependency's key, *unless* the
    /// manifest refers to it with namespaced `"dep:key"` syntax anywhere, in which case the
    /// implicit feature is suppressed even though the dependency itself can still be switched
    /// on. So a bare membership test on `features` is not enough (that is the hole a first
    /// version of this check had): a package like `features = ["json"]` with
    /// `json = ["dep:serde_json"]` never has `"serde_json"` in its resolved `features`, yet the
    /// dependency is fully live.
    ///
    /// The correct test: `key` is activated if it appears in `features` directly (the implicit
    /// feature did fire), or if some feature that **is** in `features` lists, in its own
    /// `[features]` entry, a *strong* reference to `key`: the bare name `"key"`, the namespaced
    /// `"dep:key"`, or a slash form `"key/sub"` — anything except the *weak* `"key?/sub"`, which
    /// only configures `key` if something else already turned it on and never turns it on by
    /// itself. `features` is already Cargo's fully expanded, transitively-closed activation set
    /// for this node, so only each active feature's own direct `enables` list needs checking,
    /// not a further recursive feature-to-feature walk.
    fn activates(&self, key: &str) -> bool {
        if self.features.iter().any(|f| f == key) {
            return true;
        }
        self.feature_table
            .iter()
            .filter(|(name, _)| self.features.iter().any(|f| f == name))
            .flat_map(|(_, enables)| enables)
            .any(|e| {
                let name = e.split('/').next().unwrap_or(e);
                !name.ends_with('?') && name.strip_prefix("dep:").unwrap_or(name) == key
            })
    }

    /// `name version`, for messages.
    pub(crate) fn label(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// The resolved graph.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Graph {
    /// Every package, in `cargo metadata` order; all indices refer to this list.
    pub(crate) packages: Vec<Package>,
    /// The workspace root directory, used to check where each member lives.
    pub(crate) workspace_root: String,
}

impl Graph {
    /// Parses `cargo metadata --format-version 1` output.
    ///
    /// Reads `packages` first (names, versions, declared dependencies, `[features]` tables),
    /// then fills each package's resolved features and edges from `resolve.nodes`.
    ///
    /// # Errors
    ///
    /// Returns a message when the JSON is invalid, the format version is not 1, the resolve
    /// graph is missing, a required field is missing or has the wrong type, a dependency kind
    /// is unknown, or a node, edge or workspace member names a package that is not listed.
    pub(crate) fn from_json(text: &str) -> Result<Self, String> {
        let root: Value =
            serde_json::from_str(text).map_err(|e| format!("cargo metadata JSON: {e}"))?;
        if root.get("version").and_then(Value::as_u64) != Some(1) {
            return Err("cargo metadata: expected format version 1".to_owned());
        }
        let members: Vec<&str> = array(&root, "workspace_members")?
            .iter()
            .map(|v| v.as_str().ok_or("workspace_members: expected strings"))
            .collect::<Result<_, _>>()?;
        let resolve = root
            .get("resolve")
            .filter(|v| v.is_object())
            .ok_or("cargo metadata: no resolve graph (was --no-deps passed?)")?;

        let mut packages = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for p in array(&root, "packages")? {
            let id = string(p, "id")?;
            let declared = array(p, "dependencies")?
                .iter()
                .map(|d| {
                    Ok(Declared {
                        name: string(d, "name")?,
                        rename: match d.get("rename") {
                            None | Some(Value::Null) => None,
                            Some(Value::String(r)) => Some(r.clone()),
                            Some(_) => return Err("dependency: rename".to_owned()),
                        },
                        kind: Kind::parse(d.get("kind").unwrap_or(&Value::Null))?,
                        features: strings(d, "features")?,
                        default_features: d
                            .get("uses_default_features")
                            .and_then(Value::as_bool)
                            .ok_or("dependency: uses_default_features")?,
                        optional: d
                            .get("optional")
                            .and_then(Value::as_bool)
                            .ok_or("dependency: optional")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            index.insert(id.clone(), packages.len());
            packages.push(Package {
                is_member: members.contains(&id.as_str()),
                name: string(p, "name")?,
                version: string(p, "version")?,
                manifest_path: string(p, "manifest_path")?,
                features: Vec::new(),
                deps: Vec::new(),
                declared,
                feature_table: feature_table(p)?,
                id,
            });
        }

        for node in array(resolve, "nodes")? {
            let id = string(node, "id")?;
            let &from = index
                .get(&id)
                .ok_or_else(|| format!("resolve node {id} has no package"))?;
            let mut deps = Vec::new();
            for dep in array(node, "deps")? {
                let pkg = string(dep, "pkg")?;
                let name = string(dep, "name")?;
                let &to = index
                    .get(&pkg)
                    .ok_or_else(|| format!("resolve edge to unknown package {pkg}"))?;
                let mut kinds = Vec::new();
                for k in array(dep, "dep_kinds")? {
                    let kind = Kind::parse(k.get("kind").unwrap_or(&Value::Null))?;
                    if !kinds.contains(&kind) {
                        kinds.push(kind);
                    }
                }
                deps.push(Edge { to, kinds, name });
            }
            let features = strings(node, "features")?;
            let package = packages
                .get_mut(from)
                .ok_or("resolve node index out of range")?;
            package.deps = deps;
            package.features = features;
        }

        for member in &members {
            if !index.contains_key(*member) {
                return Err(format!("workspace member {member} has no package"));
            }
        }
        Ok(Self {
            packages,
            workspace_root: string(&root, "workspace_root")?,
        })
    }

    /// The package at `index`. Indices come from this graph, so this never fails for them.
    pub(crate) fn package(&self, index: usize) -> Option<&Package> {
        self.packages.get(index)
    }

    /// The workspace member named `name`.
    pub(crate) fn member(&self, name: &str) -> Option<usize> {
        self.packages
            .iter()
            .position(|p| p.is_member && p.name == name)
    }

    /// Indices of every workspace member.
    pub(crate) fn members(&self) -> impl Iterator<Item = usize> + '_ {
        self.packages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_member)
            .map(|(i, _)| i)
    }

    /// Everything `root` reaches: the root's own edges of `root_kinds`, then the edges of
    /// `kinds` of every package reached, skipping edges for which `skip(from, to, kind)` holds
    /// or which [`Graph::edge_is_live`] says are not actually compiled.
    ///
    /// Returns each reached package with the package it was first reached from (`None` for the
    /// root), in breadth-first order, so [`Graph::path`] gives a shortest path.
    pub(crate) fn closure(
        &self,
        root: usize,
        root_kinds: &[Kind],
        kinds: &[Kind],
        skip: &dyn Fn(usize, usize, Kind) -> bool,
    ) -> HashMap<usize, Option<usize>> {
        let mut parent: HashMap<usize, Option<usize>> = HashMap::from([(root, None)]);
        let mut queue = std::collections::VecDeque::from([root]);
        while let Some(from) = queue.pop_front() {
            let allowed = if from == root { root_kinds } else { kinds };
            let Some(package) = self.package(from) else {
                continue;
            };
            for edge in &package.deps {
                let used = edge.kinds.iter().any(|k| {
                    allowed.contains(k)
                        && !skip(from, edge.to, *k)
                        && Self::edge_is_live(package, edge, *k)
                });
                if used && !parent.contains_key(&edge.to) {
                    parent.insert(edge.to, Some(from));
                    queue.push_back(edge.to);
                }
            }
        }
        parent
    }

    /// Whether `edge`, used as `kind`, is actually compiled for `package` — not merely a
    /// possible edge `cargo metadata` lists.
    ///
    /// `cargo metadata`'s `resolve.nodes[].deps` keeps an edge to an optional dependency even
    /// when no feature anywhere ever switches it on (observed directly: `p256` 0.14.0's
    /// `primeorder` dependency declares `serdect` as `optional = true`, behind a `serde`
    /// feature nothing in this workspace requests; `primeorder`'s own resolved `features` stay
    /// `["alloc"]`, and no `serdect`/`serde`/`serde_core`/`serde_derive` artifact is ever
    /// produced by `cargo check`/`cargo check-wasm` — confirmed against `target/`). Counting
    /// that edge as "reached" over-approximates what R1 and the getrandom rule are checking.
    ///
    /// A **non-optional** dependency is always live: nothing gates it. An **optional** one is
    /// live only if [`Package::activates`] says `package`'s own resolved `features` switch the
    /// dependency's key on, directly or through another active feature's `enables` list. A weak
    /// reference alone (`"key?/feat"`) never switches it on by itself, which is exactly the case
    /// that produces a dormant-but-listed edge.
    ///
    /// A manifest can declare the same `(kind, name)` more than once — once per
    /// `[target.'cfg(..)'.dependencies]` table, each with its own `optional`. [`Declared`] does
    /// not record which `cfg(..)` a declaration came from (cargo's own per-platform resolution
    /// already folded that into whether the edge is resolved at all), so every declaration
    /// matching `(kind, name)` is checked, not just the first found: the edge counts as live if
    /// *any* of them is non-optional or is an activated optional, and dormant only if *every*
    /// one is optional and inactive. Taking the first match alone (an earlier version of this
    /// check did) is a fail-open hole — a dependency declared optional-and-inactive under one
    /// target and plain (non-optional) under another would be dropped from the closure walk
    /// whenever the optional declaration happened to be found first, even though the edge is
    /// unconditionally live on the target the plain declaration covers.
    ///
    /// When no [`Declared`] entry matches at all (should not happen for a well-formed graph;
    /// the package did declare every edge it resolves), the edge is treated as live: failing
    /// open here would silently hide a real dependency, which is worse than one false alarm.
    fn edge_is_live(package: &Package, edge: &Edge, kind: Kind) -> bool {
        let mut declared = package
            .declared
            .iter()
            .filter(|d| d.kind == kind && d.key().replace('-', "_") == edge.name)
            .peekable();
        if declared.peek().is_none() {
            return true;
        }
        declared.any(|d| !d.optional || package.activates(d.key()))
    }

    /// `a -> b -> c`, the path to `to` recorded by [`Graph::closure`].
    pub(crate) fn path(&self, parents: &HashMap<usize, Option<usize>>, to: usize) -> String {
        let mut names = Vec::new();
        let mut at = Some(to);
        while let Some(i) = at {
            names.push(self.package(i).map_or("?", |p| p.name.as_str()));
            // A cycle cannot occur in a parent map built breadth-first; the bound is a guard.
            if names.len() > parents.len() {
                break;
            }
            at = parents.get(&i).copied().flatten();
        }
        names.reverse();
        names.join(" -> ")
    }
}

/// The array at `value[key]`.
///
/// # Errors
///
/// Returns a message when the key is missing or not an array.
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("cargo metadata: `{key}` is not an array"))
}

/// The string at `value[key]`, copied.
///
/// # Errors
///
/// Returns a message when the key is missing or not a string.
fn string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("cargo metadata: `{key}` is not a string"))
}

/// A package's `features` map (feature name → what it enables), in name order.
///
/// # Errors
///
/// Returns a message when the map is missing, or a feature is not an array of strings.
fn feature_table(package: &Value) -> Result<Vec<(String, Vec<String>)>, String> {
    package
        .get("features")
        .and_then(Value::as_object)
        .ok_or("cargo metadata: package `features` is not an object")?
        .iter()
        .map(|(name, enables)| {
            let enables = enables
                .as_array()
                .ok_or_else(|| format!("cargo metadata: feature `{name}` is not an array"))?
                .iter()
                .map(|v| {
                    v.as_str().map(str::to_owned).ok_or_else(|| {
                        format!("cargo metadata: feature `{name}` holds a non-string")
                    })
                })
                .collect::<Result<_, _>>()?;
            Ok((name.clone(), enables))
        })
        .collect()
}

/// The array of strings at `value[key]`.
///
/// # Errors
///
/// Returns a message when the key is missing, not an array, or holds a non-string.
fn strings(value: &Value, key: &str) -> Result<Vec<String>, String> {
    array(value, key)?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("cargo metadata: `{key}` holds a non-string"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed-down `cargo metadata` document: a member `a` with a normal, a dev (renamed) and
    /// a target-specific build edge, a `[features]` table, and two optional dependencies, `d`
    /// (declared but never switched on by anything in `a`'s own resolved `features`, the shape
    /// of the dormant `primeorder -> serdect` edge `p256` 0.14.0 produces) and `e` (switched on:
    /// `a`'s resolved `features` names it).
    const SAMPLE: &str = r#"{
      "version": 1,
      "workspace_root": "/ws",
      "workspace_members": ["path+file:///ws/crates/a#0.0.0"],
      "packages": [
        {"id": "path+file:///ws/crates/a#0.0.0", "name": "a", "version": "0.0.0",
         "manifest_path": "/ws/crates/a/Cargo.toml",
         "dependencies": [
           {"name": "b", "kind": null, "features": ["x"], "uses_default_features": false,
            "rename": null, "optional": false},
           {"name": "c", "kind": "dev", "features": [], "uses_default_features": true,
            "rename": "c-old", "optional": false},
           {"name": "b", "kind": "build", "features": [], "uses_default_features": true,
            "optional": false},
           {"name": "d", "kind": null, "features": [], "uses_default_features": false,
            "rename": null, "optional": true},
           {"name": "e", "kind": null, "features": [], "uses_default_features": false,
            "rename": null, "optional": true}
         ],
         "features": {"web": ["b/y", "c-old?/z"], "default": ["web"]}},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#b@1.2.3", "name": "b",
         "version": "1.2.3", "manifest_path": "/reg/b/Cargo.toml", "dependencies": [],
         "features": {}},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#c@0.4.0", "name": "c",
         "version": "0.4.0", "manifest_path": "/reg/c/Cargo.toml", "dependencies": [],
         "features": {}},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#d@0.1.0", "name": "d",
         "version": "0.1.0", "manifest_path": "/reg/d/Cargo.toml", "dependencies": [],
         "features": {}},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#e@0.1.0", "name": "e",
         "version": "0.1.0", "manifest_path": "/reg/e/Cargo.toml", "dependencies": [],
         "features": {}}
      ],
      "resolve": {"root": null, "nodes": [
        {"id": "path+file:///ws/crates/a#0.0.0", "features": ["e"],
         "deps": [
           {"name": "b", "pkg": "registry+https://github.com/rust-lang/crates.io-index#b@1.2.3",
            "dep_kinds": [{"kind": null, "target": null},
                          {"kind": "build", "target": "cfg(unix)"}]},
           {"name": "c_old",
            "pkg": "registry+https://github.com/rust-lang/crates.io-index#c@0.4.0",
            "dep_kinds": [{"kind": "dev", "target": null}]},
           {"name": "d", "pkg": "registry+https://github.com/rust-lang/crates.io-index#d@0.1.0",
            "dep_kinds": [{"kind": null, "target": null}]},
           {"name": "e", "pkg": "registry+https://github.com/rust-lang/crates.io-index#e@0.1.0",
            "dep_kinds": [{"kind": null, "target": null}]}
         ]},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#b@1.2.3",
         "features": ["default", "x"], "deps": []},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#c@0.4.0",
         "features": [], "deps": []},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#d@0.1.0",
         "features": [], "deps": []},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#e@0.1.0",
         "features": [], "deps": []}
      ]}
    }"#;

    #[test]
    fn parses_packages_edges_and_declarations() {
        let g = Graph::from_json(SAMPLE).unwrap();
        assert_eq!(g.workspace_root, "/ws");
        let a = g.member("a").unwrap();
        assert_eq!(g.members().collect::<Vec<_>>(), [a]);
        let pa = g.package(a).unwrap();
        assert_eq!(pa.deps.len(), 4);
        assert_eq!(pa.deps[0].kinds, [Kind::Normal, Kind::Build]);
        assert_eq!(pa.deps[1].kinds, [Kind::Dev]);
        assert_eq!(pa.declared[0].features, ["x"]);
        assert!(!pa.declared[0].default_features);
        assert!(!pa.declared[0].optional);
        assert_eq!(pa.declared[1].kind, Kind::Dev);
        assert_eq!(pa.declared[0].key(), "b");
        assert_eq!(pa.declared[1].key(), "c-old");
        assert_eq!(pa.deps[1].name, "c_old");
        assert!(pa.declared[3].optional, "d is declared optional");
        assert!(pa.declared[4].optional, "e is declared optional");
        assert_eq!(pa.features, ["e"], "only e is switched on for a itself");
        assert_eq!(
            pa.feature_table,
            [
                ("default".to_owned(), vec!["web".to_owned()]),
                (
                    "web".to_owned(),
                    vec!["b/y".to_owned(), "c-old?/z".to_owned()]
                ),
            ]
        );
        let b = pa.deps[0].to;
        assert_eq!(g.package(b).unwrap().label(), "b 1.2.3");
        assert_eq!(g.package(b).unwrap().features, ["default", "x"]);
        assert!(!g.package(b).unwrap().is_member);
    }

    #[test]
    fn closure_follows_only_the_requested_kinds() {
        let g = Graph::from_json(SAMPLE).unwrap();
        let a = g.member("a").unwrap();
        let normal = g.closure(
            a,
            &[Kind::Normal, Kind::Build],
            &[Kind::Normal],
            &|_, _, _| false,
        );
        // a, b (non-optional) and e (optional, switched on): d (optional, dormant) is excluded.
        assert_eq!(normal.len(), 3);
        let all = g.closure(
            a,
            &[Kind::Normal, Kind::Build, Kind::Dev],
            &[Kind::Normal],
            &|_, _, _| false,
        );
        assert_eq!(all.len(), 4);
        let c = g.package(a).unwrap().deps[1].to;
        assert_eq!(g.path(&all, c), "a -> c");
        let skipped = g.closure(a, &[Kind::Dev], &[Kind::Normal], &|_, to, _| to == c);
        assert_eq!(skipped.len(), 1);
    }

    #[test]
    fn dormant_optional_dependency_is_not_reached() {
        // `d` is declared `optional = true` and nothing in `a`'s own resolved `features`
        // switches it on (only `e` is there) — the shape of `p256` 0.14.0's
        // `primeorder -> serdect` edge (ADR 0041, ADR 0009 amendment): `cargo metadata` still
        // lists the edge, but it is never actually compiled.
        let g = Graph::from_json(SAMPLE).unwrap();
        let a = g.member("a").unwrap();
        let d = g.package(a).unwrap().deps[2].to;
        assert_eq!(g.package(d).unwrap().name, "d");
        let reach = g.closure(a, &[Kind::Normal], &[Kind::Normal], &|_, _, _| false);
        assert!(
            !reach.contains_key(&d),
            "a dormant optional edge must not be reached"
        );
    }

    #[test]
    fn activated_optional_dependency_is_still_reached() {
        // `e` is just as optional as `d`, but `a`'s resolved `features` names it, so the edge
        // is live: an activated optional dependency must still be caught by every rule that
        // walks the closure (R1, getrandom and the rest), exactly as a non-optional one is.
        let g = Graph::from_json(SAMPLE).unwrap();
        let a = g.member("a").unwrap();
        let e = g.package(a).unwrap().deps[3].to;
        assert_eq!(g.package(e).unwrap().name, "e");
        let reach = g.closure(a, &[Kind::Normal], &[Kind::Normal], &|_, _, _| false);
        assert!(
            reach.contains_key(&e),
            "an activated optional edge must still be reached"
        );
    }

    /// A minimal two-package graph: `p` (a member) with one optional dependency `serde_json`,
    /// `p`'s resolved `features` and `feature_table` set by the caller.
    fn two_package_graph(
        p_features: &[&str],
        p_feature_table: &[(&str, &[&str])],
    ) -> (Graph, usize, usize) {
        let mut g = Graph {
            packages: Vec::new(),
            workspace_root: "/ws".to_owned(),
        };
        let dep = g.packages.len();
        g.packages.push(Package {
            id: "serde_json".to_owned(),
            name: "serde_json".to_owned(),
            version: "1.0.0".to_owned(),
            manifest_path: "/reg/serde_json/Cargo.toml".to_owned(),
            is_member: false,
            features: Vec::new(),
            deps: Vec::new(),
            declared: Vec::new(),
            feature_table: Vec::new(),
        });
        let p = g.packages.len();
        g.packages.push(Package {
            id: "p".to_owned(),
            name: "p".to_owned(),
            version: "1.0.0".to_owned(),
            manifest_path: "/ws/p/Cargo.toml".to_owned(),
            is_member: true,
            features: p_features.iter().map(|f| (*f).to_owned()).collect(),
            deps: vec![Edge {
                to: dep,
                kinds: vec![Kind::Normal],
                name: "serde_json".to_owned(),
            }],
            declared: vec![Declared {
                name: "serde_json".to_owned(),
                rename: None,
                kind: Kind::Normal,
                features: Vec::new(),
                default_features: false,
                optional: true,
            }],
            feature_table: p_feature_table
                .iter()
                .map(|(name, enables)| {
                    (
                        (*name).to_owned(),
                        enables.iter().map(|e| (*e).to_owned()).collect(),
                    )
                })
                .collect(),
        });
        (g, p, dep)
    }

    /// Like [`two_package_graph`], but takes `p`'s declarations of `serde_json` directly,
    /// so a test can push more than one — the shape a manifest with both an untargeted and a
    /// `[target.'cfg(..)'.dependencies]` table for the same crate produces.
    fn two_package_graph_declared(declared: Vec<Declared>) -> (Graph, usize, usize) {
        let mut g = Graph {
            packages: Vec::new(),
            workspace_root: "/ws".to_owned(),
        };
        let dep = g.packages.len();
        g.packages.push(Package {
            id: "serde_json".to_owned(),
            name: "serde_json".to_owned(),
            version: "1.0.0".to_owned(),
            manifest_path: "/reg/serde_json/Cargo.toml".to_owned(),
            is_member: false,
            features: Vec::new(),
            deps: Vec::new(),
            declared: Vec::new(),
            feature_table: Vec::new(),
        });
        let p = g.packages.len();
        g.packages.push(Package {
            id: "p".to_owned(),
            name: "p".to_owned(),
            version: "1.0.0".to_owned(),
            manifest_path: "/ws/p/Cargo.toml".to_owned(),
            is_member: true,
            features: Vec::new(),
            deps: vec![Edge {
                to: dep,
                kinds: vec![Kind::Normal],
                name: "serde_json".to_owned(),
            }],
            declared,
            feature_table: Vec::new(),
        });
        (g, p, dep)
    }

    /// One `Declared` entry for `serde_json`, normal kind, with the given `optional`.
    fn serde_json_declared(optional: bool) -> Declared {
        Declared {
            name: "serde_json".to_owned(),
            rename: None,
            kind: Kind::Normal,
            features: Vec::new(),
            default_features: false,
            optional,
        }
    }

    #[test]
    fn edge_optional_under_one_declaration_and_plain_under_another_stays_live() {
        // A manifest can declare the same `(kind, name)` twice: once under a
        // `[target.'cfg(..)'.dependencies]` table as `optional = true`, once under the plain
        // `[dependencies]` table as not optional. Nothing activates the optional declaration
        // here, but the plain one unconditionally compiles the dependency, so the edge must
        // stay live — taking only the first matching declaration (the fail-open bug this
        // guards against) would drop it whenever the optional one happened to be found first.
        let (g, p, dep) =
            two_package_graph_declared(vec![serde_json_declared(true), serde_json_declared(false)]);
        let reach = g.closure(p, &[Kind::Normal], &[Kind::Normal], &|_, _, _| false);
        assert!(
            reach.contains_key(&dep),
            "a non-optional declaration on any target keeps the edge live"
        );
    }

    #[test]
    fn edge_with_a_single_dormant_optional_declaration_is_still_ignored() {
        // Guards the fix above against over-correcting into "any declaration list is live by
        // default": a dependency with exactly one declaration, optional and never activated,
        // must still be dormant.
        let (g, p, dep) = two_package_graph_declared(vec![serde_json_declared(true)]);
        let reach = g.closure(p, &[Kind::Normal], &[Kind::Normal], &|_, _, _| false);
        assert!(
            !reach.contains_key(&dep),
            "a single dormant optional declaration must still be ignored"
        );
    }

    #[test]
    fn namespaced_dep_syntax_without_implicit_feature_is_still_live() {
        // `p`'s "json" feature activates `serde_json` via `dep:` syntax: Cargo suppresses the
        // implicit `serde_json` feature whenever `dep:` syntax names it anywhere, so it never
        // appears in `p`'s resolved `features` (`["json"]`) even though the dependency is fully
        // live. A bare membership test on `features` alone — the hole an earlier version of
        // this check had — would wrongly call this dormant and silently drop everything under
        // it from every closure-based rule (R1, getrandom, openssl, rustix).
        let (g, p, dep) = two_package_graph(&["json"], &[("json", &["dep:serde_json"])]);
        let reach = g.closure(p, &[Kind::Normal], &[Kind::Normal], &|_, _, _| false);
        assert!(
            reach.contains_key(&dep),
            "`dep:` syntax must still count as live"
        );
    }

    #[test]
    fn weak_reference_alone_does_not_activate_the_dependency() {
        // `p`'s "alloc" feature only weakly configures `serde_json` (`"serde_json?/alloc"`):
        // nothing strongly activates it, so the dependency stays dormant even though "alloc"
        // itself is active and mentions the key.
        let (g, p, dep) = two_package_graph(&["alloc"], &[("alloc", &["serde_json?/alloc"])]);
        let reach = g.closure(p, &[Kind::Normal], &[Kind::Normal], &|_, _, _| false);
        assert!(
            !reach.contains_key(&dep),
            "a weak reference alone must not activate the dependency"
        );
    }

    #[test]
    fn strong_slash_reference_activates_the_dependency() {
        // `p`'s "full" feature strongly references `serde_json/std` (no `?`): that both turns
        // the dependency on and sets its `std` feature, so the edge is live even though the
        // bare key "serde_json" never appears in `p`'s resolved `features`.
        let (g, p, dep) = two_package_graph(&["full"], &[("full", &["serde_json/std"])]);
        let reach = g.closure(p, &[Kind::Normal], &[Kind::Normal], &|_, _, _| false);
        assert!(
            reach.contains_key(&dep),
            "a strong slash reference must activate the dependency"
        );
    }

    #[test]
    fn malformed_documents_are_errors() {
        assert!(Graph::from_json("{").is_err());
        assert!(Graph::from_json(r#"{"version": 2}"#).is_err());
        let no_resolve = SAMPLE.replace("\"resolve\"", "\"unresolved\"");
        assert!(Graph::from_json(&no_resolve).is_err());
        let bad_kind = SAMPLE.replace(
            "\"kind\": \"dev\", \"target\"",
            "\"kind\": \"odd\", \"target\"",
        );
        assert!(Graph::from_json(&bad_kind).is_err());
        let no_features = SAMPLE.replace("\"features\": {}}", "\"features\": []}");
        assert!(Graph::from_json(&no_features).is_err());
        let bad_rename = SAMPLE.replace("\"rename\": \"c-old\"", "\"rename\": 1");
        assert!(Graph::from_json(&bad_rename).is_err());
    }
}
