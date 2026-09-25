//! The resolved dependency graph, read from `cargo metadata --format-version 1` JSON.
//!
//! Only the fields the checks need are kept. The JSON is read through `serde_json::Value`, and
//! a missing or mistyped field is an error: the check fails closed rather than skipping a
//! package it could not read.

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

/// A resolved edge: `to` is a package index, `kinds` every kind it is used as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Edge {
    pub(crate) to: usize,
    pub(crate) kinds: Vec<Kind>,
}

/// A dependency as declared in a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Declared {
    /// The package name (not the rename).
    pub(crate) name: String,
    pub(crate) kind: Kind,
    pub(crate) features: Vec<String>,
    pub(crate) default_features: bool,
}

/// One package with its resolved features and edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Package {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) manifest_path: String,
    pub(crate) is_member: bool,
    /// Resolved features, unified across the workspace.
    pub(crate) features: Vec<String>,
    pub(crate) deps: Vec<Edge>,
    pub(crate) declared: Vec<Declared>,
}

impl Package {
    /// `name version`, for messages.
    pub(crate) fn label(&self) -> String {
        format!("{} {}", self.name, self.version)
    }
}

/// The resolved graph.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Graph {
    pub(crate) packages: Vec<Package>,
    pub(crate) workspace_root: String,
}

impl Graph {
    /// Parses `cargo metadata --format-version 1` output.
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
                        kind: Kind::parse(d.get("kind").unwrap_or(&Value::Null))?,
                        features: strings(d, "features")?,
                        default_features: d
                            .get("uses_default_features")
                            .and_then(Value::as_bool)
                            .ok_or("dependency: uses_default_features")?,
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
                deps.push(Edge { to, kinds });
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
    /// `kinds` of every package reached, skipping edges for which `skip(from, to, kind)` holds.
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
                let used = edge
                    .kinds
                    .iter()
                    .any(|k| allowed.contains(k) && !skip(from, edge.to, *k));
                if used && !parent.contains_key(&edge.to) {
                    parent.insert(edge.to, Some(from));
                    queue.push_back(edge.to);
                }
            }
        }
        parent
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

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("cargo metadata: `{key}` is not an array"))
}

fn string(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("cargo metadata: `{key}` is not a string"))
}

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

    /// A trimmed-down `cargo metadata` document: a member `a` with a normal, a dev and a
    /// target-specific build edge.
    const SAMPLE: &str = r#"{
      "version": 1,
      "workspace_root": "/ws",
      "workspace_members": ["path+file:///ws/crates/a#0.0.0"],
      "packages": [
        {"id": "path+file:///ws/crates/a#0.0.0", "name": "a", "version": "0.0.0",
         "manifest_path": "/ws/crates/a/Cargo.toml",
         "dependencies": [
           {"name": "b", "kind": null, "features": ["x"], "uses_default_features": false},
           {"name": "c", "kind": "dev", "features": [], "uses_default_features": true},
           {"name": "b", "kind": "build", "features": [], "uses_default_features": true}
         ]},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#b@1.2.3", "name": "b",
         "version": "1.2.3", "manifest_path": "/reg/b/Cargo.toml", "dependencies": []},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#c@0.4.0", "name": "c",
         "version": "0.4.0", "manifest_path": "/reg/c/Cargo.toml", "dependencies": []}
      ],
      "resolve": {"root": null, "nodes": [
        {"id": "path+file:///ws/crates/a#0.0.0", "features": [],
         "deps": [
           {"pkg": "registry+https://github.com/rust-lang/crates.io-index#b@1.2.3",
            "dep_kinds": [{"kind": null, "target": null},
                          {"kind": "build", "target": "cfg(unix)"}]},
           {"pkg": "registry+https://github.com/rust-lang/crates.io-index#c@0.4.0",
            "dep_kinds": [{"kind": "dev", "target": null}]}
         ]},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#b@1.2.3",
         "features": ["default", "x"], "deps": []},
        {"id": "registry+https://github.com/rust-lang/crates.io-index#c@0.4.0",
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
        assert_eq!(pa.deps.len(), 2);
        assert_eq!(pa.deps[0].kinds, [Kind::Normal, Kind::Build]);
        assert_eq!(pa.deps[1].kinds, [Kind::Dev]);
        assert_eq!(pa.declared[0].features, ["x"]);
        assert!(!pa.declared[0].default_features);
        assert_eq!(pa.declared[1].kind, Kind::Dev);
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
        assert_eq!(normal.len(), 2);
        let all = g.closure(
            a,
            &[Kind::Normal, Kind::Build, Kind::Dev],
            &[Kind::Normal],
            &|_, _, _| false,
        );
        assert_eq!(all.len(), 3);
        let c = g.package(a).unwrap().deps[1].to;
        assert_eq!(g.path(&all, c), "a -> c");
        let skipped = g.closure(a, &[Kind::Dev], &[Kind::Normal], &|_, to, _| to == c);
        assert_eq!(skipped.len(), 1);
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
    }
}
