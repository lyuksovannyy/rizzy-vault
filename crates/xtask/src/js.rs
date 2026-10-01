//! `cargo xtask check-js`: the JavaScript dependency policy of ADR 0014 §3, which "mirrors
//! `deny.toml`" and "lands with the first package in M1" (`packages/core`).
//!
//! | Rule (ADR 0014 §3) | Check |
//! |---|---|
//! | One package manager, pinned | the root `package.json` has `packageManager: "pnpm@X.Y.Z"` |
//! | Committed lockfile | `pnpm-lock.yaml` exists (CI installs with `--frozen-lockfile`) |
//! | Exact versions | every specifier in `dependencies`, `devDependencies`, `optionalDependencies` and `peerDependencies` of every workspace `package.json` is an exact version, or the `workspace:` protocol |
//! | Install scripts disabled; allow-list starts empty | `pnpm-workspace.yaml` sets `onlyBuiltDependencies: []`, and its entries are exactly [`BUILT_DEPENDENCIES`] (owner-approved, none today) |
//! | Licence allow-list | every licence `pnpm licenses list --json` reports is allowed by `deny.toml`'s `[licenses] allow` list (one list for both ecosystems); an `OR` expression needs one allowed alternative, an `AND` expression all of them |
//! | Advisory check | `pnpm audit` reports nothing |
//!
//! The first four read files only. The last two run `pnpm` in the workspace root, after
//! `pnpm install --frozen-lockfile`; `pnpm audit` needs the network. Review of a new dependency
//! stays a review (CLAUDE.md "Dependencies").
//!
//! Workspace packages are the directories under `packages/` and `apps/` that hold a
//! `package.json`, the globs `pnpm-workspace.yaml` names.

use std::path::Path;
use std::process::Command;

/// The packages allowed to run install scripts (ADR 0014 §3): owner-approved entries only.
pub(crate) const BUILT_DEPENDENCIES: &[&str] = &[];

/// The dependency fields of a `package.json`.
const DEPENDENCY_FIELDS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

/// Whether `spec` is an exact version: `MAJOR.MINOR.PATCH`, optionally with a pre-release or
/// build suffix of `[0-9A-Za-z.-]`.
pub(crate) fn exact_version(spec: &str) -> bool {
    let (core, suffix) = match spec.find(['-', '+']) {
        Some(at) => spec.split_at(at),
        None => (spec, ""),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && suffix
            .bytes()
            .skip(1)
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && (suffix.is_empty() || suffix.len() > 1)
}

/// The violations of one `package.json` (`path` names it in the messages): specifiers that
/// are not exact, and for the root a missing or unpinned `packageManager`.
pub(crate) fn check_manifest(path: &str, text: &str, root: bool) -> Vec<String> {
    let json: serde_json::Value = match serde_json::from_str(text) {
        Ok(json) => json,
        Err(e) => return vec![format!("{path}: not JSON: {e}")],
    };
    let mut out = Vec::new();
    if root {
        let pinned = json
            .get("packageManager")
            .and_then(serde_json::Value::as_str)
            .and_then(|pm| pm.strip_prefix("pnpm@"))
            .is_some_and(exact_version);
        if !pinned {
            out.push(format!(
                "{path}: `packageManager` must pin pnpm to an exact version (`pnpm@X.Y.Z`)"
            ));
        }
    }
    for field in DEPENDENCY_FIELDS {
        let Some(deps) = json.get(field) else {
            continue;
        };
        let Some(deps) = deps.as_object() else {
            out.push(format!("{path}: `{field}` is not an object"));
            continue;
        };
        for (name, spec) in deps {
            let ok = spec
                .as_str()
                .is_some_and(|s| s.starts_with("workspace:") || exact_version(s));
            if !ok {
                out.push(format!(
                    "{path}: {field}.{name} = {spec}: not an exact version (ADR 0014 §3)"
                ));
            }
        }
    }
    out
}

/// The entries of `onlyBuiltDependencies` in `pnpm-workspace.yaml`, if the key is set in the
/// flow form this repository writes (`onlyBuiltDependencies: [a, b]`, `[]` for none). `None`
/// when the key is missing or written in another form.
pub(crate) fn built_dependencies(workspace_yaml: &str) -> Option<Vec<String>> {
    let line = workspace_yaml
        .lines()
        .find(|l| l.starts_with("onlyBuiltDependencies:"))?;
    let value = line.strip_prefix("onlyBuiltDependencies:")?.trim();
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    Some(
        inner
            .split(',')
            .map(|s| s.trim().trim_matches(['"', '\'']).to_owned())
            .collect(),
    )
}

/// The `[licenses] allow` list of `deny.toml`.
pub(crate) fn deny_allow_list(deny: &str) -> Vec<String> {
    let mut in_licenses = false;
    let mut in_allow = false;
    let mut out = Vec::new();
    for line in deny.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && !in_allow {
            in_licenses = line == "[licenses]";
            continue;
        }
        if in_licenses && line.starts_with("allow") && line.contains('[') {
            in_allow = true;
        }
        if in_allow {
            out.extend(line.split('"').skip(1).step_by(2).map(str::to_owned));
            if line.contains(']') {
                in_allow = false;
            }
        }
    }
    out
}

/// Whether the SPDX expression `expr` is allowed by `allow`: an `OR` of terms needs one allowed
/// term, an `AND` all of them; parentheses are ignored, which reads `(A OR B) AND C` as
/// `A OR B AND C` and so may refuse an expression it could accept, never the reverse.
pub(crate) fn license_allowed(expr: &str, allow: &[String]) -> bool {
    let flat = expr.replace(['(', ')'], " ");
    flat.split(" OR ").any(|alternative| {
        alternative
            .split(" AND ")
            .map(str::trim)
            .all(|term| !term.is_empty() && allow.iter().any(|a| a == term))
    })
}

/// Runs `pnpm` with `args` in `root`; returns its stdout and whether it succeeded.
fn pnpm(root: &Path, args: &[&str]) -> Result<(String, bool), String> {
    let out = Command::new("pnpm")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|e| format!("running pnpm {args:?}: {e} (is pnpm installed?)"))?;
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.success(),
    ))
}

/// The workspace `package.json` files: the root's, and one per directory under `packages/` and
/// `apps/`, as (path relative to `root`, text).
fn manifests(root: &Path) -> Result<Vec<(String, String)>, String> {
    let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let mut out = vec![("package.json".to_owned(), read(&root.join("package.json"))?)];
    for group in ["packages", "apps"] {
        let Ok(entries) = std::fs::read_dir(root.join(group)) else {
            continue;
        };
        let mut dirs: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        dirs.sort();
        for dir in dirs {
            let manifest = dir.join("package.json");
            if manifest.is_file() {
                let name = dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push((format!("{group}/{name}/package.json"), read(&manifest)?));
            }
        }
    }
    Ok(out)
}

/// `cargo xtask check-js` (module docs). Returns the report, or every violation.
///
/// # Errors
///
/// A violation of a rule, or a file or `pnpm` run that fails.
pub(crate) fn check_js(root: &Path) -> Result<String, String> {
    let mut violations = Vec::new();
    let manifests = manifests(root)?;
    for (path, text) in &manifests {
        violations.extend(check_manifest(path, text, path == "package.json"));
    }
    if !root.join("pnpm-lock.yaml").is_file() {
        violations.push("pnpm-lock.yaml is not committed".to_owned());
    }
    let workspace = std::fs::read_to_string(root.join("pnpm-workspace.yaml"))
        .map_err(|e| format!("pnpm-workspace.yaml: {e}"))?;
    match built_dependencies(&workspace) {
        Some(built)
            if built
                .iter()
                .map(String::as_str)
                .eq(BUILT_DEPENDENCIES.iter().copied()) => {}
        Some(built) => violations.push(format!(
            "pnpm-workspace.yaml: onlyBuiltDependencies is {built:?}; the owner-approved list \
             is {BUILT_DEPENDENCIES:?} (crates/xtask/src/js.rs)"
        )),
        None => violations.push(
            "pnpm-workspace.yaml must set `onlyBuiltDependencies: [...]` (ADR 0014 §3)".to_owned(),
        ),
    }
    let deny =
        std::fs::read_to_string(root.join("deny.toml")).map_err(|e| format!("deny.toml: {e}"))?;
    let allow = deny_allow_list(&deny);
    let (licenses, ok) = pnpm(root, &["licenses", "list", "--json"])?;
    if !ok {
        return Err("pnpm licenses list failed; run `pnpm install --frozen-lockfile` first".into());
    }
    let licenses: serde_json::Value = serde_json::from_str(&licenses)
        .map_err(|e| format!("pnpm licenses list printed no JSON: {e}"))?;
    let groups = licenses
        .as_object()
        .ok_or("pnpm licenses list: not an object")?;
    let mut packages = 0;
    for (license, entries) in groups {
        let names: Vec<&str> = entries
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get("name").and_then(serde_json::Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        packages += names.len();
        if !license_allowed(license, &allow) {
            violations.push(format!(
                "licence `{license}` is not on deny.toml's allow list: {}",
                names.join(", ")
            ));
        }
    }
    let (audit, clean) = pnpm(root, &["audit"])?;
    if !clean {
        violations.push(format!("pnpm audit reports advisories:\n{}", audit.trim()));
    }
    if violations.is_empty() {
        Ok(format!(
            "check-js: ok ({} package.json files, {packages} installed packages; exact \
             versions, pinned pnpm, empty install-script allow-list, deny.toml licences, no \
             advisories; ADR 0014 §3)",
            manifests.len()
        ))
    } else {
        Err(format!(
            "{}\ncheck-js: {} violation(s) of ADR 0014 §3",
            violations.join("\n"),
            violations.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_versions_pass() {
        for ok in ["1.2.3", "0.0.0", "10.30.2", "1.0.0-rc.1", "1.0.0+build.5"] {
            assert!(exact_version(ok), "{ok}");
        }
        for bad in [
            "^1.2.3",
            "~1.2.3",
            "1.2",
            "1.2.x",
            ">=1.0.0",
            "*",
            "latest",
            "1.2.3 - 2.0.0",
            "1.2.3-",
            "",
            "v1.2.3",
            "1.2.3||2.0.0",
        ] {
            assert!(!exact_version(bad), "{bad}");
        }
    }

    #[test]
    fn manifests_are_checked_field_by_field() {
        let root = r#"{"packageManager":"pnpm@10.30.2","devDependencies":{"a":"1.0.0"}}"#;
        assert!(check_manifest("package.json", root, true).is_empty());
        let unpinned = r#"{"packageManager":"pnpm@^10"}"#;
        assert_eq!(check_manifest("package.json", unpinned, true).len(), 1);
        let ranges = r#"{"dependencies":{"a":"^1.0.0","b":"workspace:*"},"peerDependencies":{"c":"~2.0.0"}}"#;
        assert_eq!(
            check_manifest("packages/x/package.json", ranges, false).len(),
            2
        );
        assert_eq!(check_manifest("p", "not json", false).len(), 1);
    }

    #[test]
    fn the_install_script_allow_list_is_read() {
        assert_eq!(
            built_dependencies("packages:\n  - x\nonlyBuiltDependencies: []\n"),
            Some(vec![])
        );
        assert_eq!(
            built_dependencies("onlyBuiltDependencies: [esbuild, \"sharp\"]\n"),
            Some(vec!["esbuild".to_owned(), "sharp".to_owned()])
        );
        assert_eq!(
            built_dependencies("onlyBuiltDependencies:\n  - esbuild\n"),
            None
        );
        assert_eq!(built_dependencies("packages: []\n"), None);
    }

    #[test]
    fn licences_follow_deny_toml() {
        let deny = "[licenses]\nversion = 2\nallow = [\n  \"MIT\", # comment\n  \"Apache-2.0\",\n]\n[bans]\nallow = [\"x\"]\n";
        let allow = deny_allow_list(deny);
        assert_eq!(allow, ["MIT", "Apache-2.0"]);
        assert!(license_allowed("MIT", &allow));
        assert!(license_allowed("(MIT OR GPL-3.0)", &allow));
        assert!(license_allowed("MIT AND Apache-2.0", &allow));
        assert!(!license_allowed("MIT AND GPL-3.0", &allow));
        assert!(!license_allowed("GPL-3.0", &allow));
        assert!(!license_allowed("", &allow));
        assert!(!license_allowed("Unknown", &allow));
    }
}
