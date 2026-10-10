//! `cargo xtask check-manifest`: checks the built browser-extension manifests (Chromium and
//! Firefox) against INV-40 and ADR 0036 §4/§5 / ADR 0040 (HANDOFF gap X4, audit uid
//! `X4-INV40-MANIFEST-CI-CHECK`). Today these hold only by inspection; this gives them a check
//! that fails the moment any of them drifts — the gap's own example: adding
//! `externally_connectable` for web origins, a wider web-accessible-resources entry, or
//! `all_frames: true` would not fail any existing check.
//!
//! | Rule | Source |
//! |---|---|
//! | `manifest_version` is 3 | ADR 0036 §2 (MV3) |
//! | No `externally_connectable` key at all | [INV-40](../../../docs/THREAT_MODEL.md#8-security-invariants); ADR 0036 §4 last bullet ("not even the web vault's own origin") |
//! | `permissions` is a subset of the allow-list ([`BASE_ALLOWED_PERMISSIONS`], plus [`Browser::extra_permission`]) | INV-40 ("the background treats every ... message as untrusted"; a wider permission set widens what a compromised context could reach) |
//! | `host_permissions` is exactly [`EXPECTED_HOST_PERMISSIONS`] | ADR 0037 (matching needs every host; never wider, e.g. `<all_urls>`, which also covers `file:`/`ftp:`) |
//! | Every `content_scripts` entry has `all_frames: false`, `matches` of `http`/`https` only, and no `world: "MAIN"` | INV-37 clause 2, INV-40; ADR 0036 §4 |
//! | `web_accessible_resources` exposes only a subset of [`EXPECTED_WEB_ACCESSIBLE_RESOURCES`], to `http`/`https` only | ADR 0036 §4 ("no `externally_connectable`... not even the web vault"); exposing an unlisted page (e.g. the popup or options page) would let a hostile page navigate or iframe straight into privileged UI |
//! | `content_security_policy.extension_pages` allows only [`ALLOWED_CSP_SCRIPT_SRC`] in `script-src`, `'self'` or `'none'` in `object-src`, `'none'` in `base-uri` | ADR 0036 (MV3 bans remote code; no inline/eval beyond the one wasm exception) |
//!
//! Changing an allow-list above is a security review, same framing as `rules.rs`'s own
//! crate-boundary tables.
//!
//! Reads the **built** manifests (`apps/extension/dist/{chromium,firefox}/manifest.json`, which
//! `vite.config.ts`'s `rizzy-copy-manifest` plugin copies verbatim from
//! `apps/extension/manifest.{chromium,firefox}.json`), not the source files directly: a built
//! artifact is what a store submission or a loaded unpacked extension actually ships, and it is
//! the shape a future bundler transform could still alter even if the source file looks right.
//!
//! CI wiring is blocked on the owner (`docs/HANDOFF.md` "CI workflow edits" lists it alongside
//! `check-tables`); until then this runs locally, documented next to the other checks in
//! `CONTRIBUTING.md`.

use std::fs;
use std::path::Path;

use serde_json::Value;

/// The two builds this command checks (`apps/extension/manifest.chromium.json` and
/// `manifest.firefox.json`), and the one permission each is allowed that the other is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Browser {
    /// `dist/chromium/manifest.json`.
    Chromium,
    /// `dist/firefox/manifest.json`.
    Firefox,
}

impl Browser {
    /// This build's own extra allowed permission, beyond [`BASE_ALLOWED_PERMISSIONS`]:
    /// `offscreen` for Chromium only (ADR 0036 §2 — Firefox holds the core in its background
    /// page instead and never calls `chrome.offscreen`).
    const fn extra_permission(self) -> Option<&'static str> {
        match self {
            Self::Chromium => Some("offscreen"),
            Self::Firefox => None,
        }
    }

    /// The label used in violation messages and in [`check_built_manifests`]'s file lookup.
    const fn dist_dir(self) -> &'static str {
        match self {
            Self::Chromium => "chromium",
            Self::Firefox => "firefox",
        }
    }
}

/// Permissions every build may declare ([`Browser::extra_permission`] adds one more for
/// Chromium). Anything outside this list is a violation: this is a strict allow-list, not a
/// deny-list of known-bad permissions, precisely because the gap this check closes is "a new
/// permission would not fail any existing check."
const BASE_ALLOWED_PERMISSIONS: &[&str] = &["storage", "idle"];

/// The exact `host_permissions` every build must declare: neither wider (e.g. `<all_urls>`,
/// which also matches `file:`/`ftp:`) nor narrower (matching needs every http(s) host, ADR
/// 0037).
const EXPECTED_HOST_PERMISSIONS: &[&str] = &["http://*/*", "https://*/*"];

/// The exact `web_accessible_resources[].resources` every build may expose, at most (checked as
/// a subset, [`check_web_accessible_resources`] below — a build exposing fewer, even zero, of
/// these still passes): the extension-origin UI pages the content script injects into an
/// untrusted page (ADR 0036 §4, §6: the inline-menu iframe app, the passkey-consent iframe app,
/// and the passkey page-world shim it loads). Nothing else — in particular never the popup or options page,
/// which carry no secrets of their own either but are the one place `packages/core`'s
/// messaging-backed client talks to the long-lived context, and have no reason to be reachable
/// from a page's own `<iframe src="...">` or navigation at all.
const EXPECTED_WEB_ACCESSIBLE_RESOURCES: &[&str] = &[
    "src/inline-menu/index.html",
    "src/passkey-consent/index.html",
    "src/content/passkey-page-shim.js",
];

/// `script-src` tokens the extension-pages CSP may contain (MV3 bans remote code outright; the
/// one exception is the wasm instantiation `rizzy-wasm` needs). Tokenized on whitespace, never
/// matched as a substring — `'wasm-unsafe-eval'` must never be mistaken for the broader
/// `'unsafe-eval'` it happens to contain as a substring, in either direction.
const ALLOWED_CSP_SCRIPT_SRC: &[&str] = &["'self'", "'wasm-unsafe-eval'"];

/// A JSON array of strings at `manifest[key]`, or `None` if the key is missing or not an array
/// of strings.
fn string_array<'a>(manifest: &'a Value, key: &str) -> Option<Vec<&'a str>> {
    manifest
        .get(key)?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect()
}

/// Whether every element of `actual` is one of `allowed` (a subset check, order-independent).
fn is_subset_of(actual: &[&str], allowed: &[&str]) -> bool {
    actual.iter().all(|a| allowed.contains(a))
}

/// Whether `actual` and `expected` contain exactly the same strings (order-independent). The
/// `len()` equality means this is NOT duplicate-insensitive: a manifest with a duplicated entry
/// has a different length from `expected` and is rejected, not treated as equivalent to the
/// deduplicated set.
fn same_set(actual: &[&str], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && is_subset_of(actual, expected)
        && is_subset_of(expected, actual)
}

/// `permissions` (module docs table, row 3).
fn check_permissions(browser: Browser, manifest: &Value) -> Vec<String> {
    let Some(permissions) = string_array(manifest, "permissions") else {
        return vec!["permissions must be an array of strings".to_owned()];
    };
    let mut allowed = BASE_ALLOWED_PERMISSIONS.to_vec();
    if let Some(extra) = browser.extra_permission() {
        allowed.push(extra);
    }
    if is_subset_of(&permissions, &allowed) {
        Vec::new()
    } else {
        vec![format!(
            "permissions {permissions:?} is not a subset of the allow-list {allowed:?} (INV-40; crates/xtask/src/ext_manifest.rs)"
        )]
    }
}

/// `host_permissions` (module docs table, row 4).
fn check_host_permissions(manifest: &Value) -> Vec<String> {
    let Some(hosts) = string_array(manifest, "host_permissions") else {
        return vec!["host_permissions must be an array of strings".to_owned()];
    };
    if same_set(&hosts, EXPECTED_HOST_PERMISSIONS) {
        Vec::new()
    } else {
        vec![format!(
            "host_permissions {hosts:?} must be exactly {EXPECTED_HOST_PERMISSIONS:?} (ADR 0037)"
        )]
    }
}

/// Every `content_scripts` entry (module docs table, row 5): `all_frames: false`, `matches` of
/// `http(s)` patterns only — never `<all_urls>`, `file://*/*` or anything else that would run
/// this extension's own code somewhere INV-37/INV-40 does not expect it — and no `world:
/// "MAIN"`. MV3's default (absent, or explicitly `"ISOLATED"`) is the isolated world
/// `docs/THREAT_MODEL.md`'s A7 mitigations and INV-36–INV-40 all assume; `"MAIN"` would run the
/// content script in the page's own world instead, sharing its JS globals and reachable by the
/// page's own code, not merely its shared DOM/BOM.
fn check_content_scripts(manifest: &Value) -> Vec<String> {
    let Some(entries) = manifest.get("content_scripts").and_then(Value::as_array) else {
        return vec!["content_scripts must be an array".to_owned()];
    };
    let mut out = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        if entry.get("all_frames").and_then(Value::as_bool) != Some(false) {
            out.push(format!(
                "content_scripts[{i}].all_frames must be false (INV-37 clause 2, INV-40; ADR 0036 §4)"
            ));
        }
        let matches = entry
            .get("matches")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if matches.is_empty()
            || !matches
                .iter()
                .all(|m| m.starts_with("http://") || m.starts_with("https://"))
        {
            out.push(format!(
                "content_scripts[{i}].matches {matches:?} must contain only http(s) patterns"
            ));
        }
        if let Some(world) = entry.get("world").and_then(Value::as_str)
            && world != "ISOLATED"
        {
            out.push(format!(
                "content_scripts[{i}].world {world:?} must be absent or \"ISOLATED\", never \"MAIN\" (INV-37/INV-40; THREAT_MODEL.md A7)"
            ));
        }
    }
    out
}

/// `web_accessible_resources` (module docs table, row 6).
fn check_web_accessible_resources(manifest: &Value) -> Vec<String> {
    let Some(entries) = manifest
        .get("web_accessible_resources")
        .and_then(Value::as_array)
    else {
        return vec!["web_accessible_resources must be an array".to_owned()];
    };
    let mut out = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let resources = entry
            .get("resources")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if !is_subset_of(&resources, EXPECTED_WEB_ACCESSIBLE_RESOURCES) {
            out.push(format!(
                "web_accessible_resources[{i}].resources {resources:?} is not a subset of {EXPECTED_WEB_ACCESSIBLE_RESOURCES:?} \
                 (ADR 0036 §4: exposing an unlisted page, e.g. the popup or options page, would let a hostile page navigate or \
                 iframe straight into privileged UI)"
            ));
        }
        let matches = entry
            .get("matches")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if matches.is_empty()
            || !matches
                .iter()
                .all(|m| m.starts_with("http://") || m.starts_with("https://"))
        {
            out.push(format!(
                "web_accessible_resources[{i}].matches {matches:?} must contain only http(s) patterns"
            ));
        }
    }
    out
}

/// One parsed `Content-Security-Policy`-style directive list: `directive -> sources`, tokenized
/// on whitespace within each `;`-separated directive (never a substring match, so
/// `'wasm-unsafe-eval'` is never mistaken for `'unsafe-eval'`).
fn csp_directive<'a>(csp: &'a str, directive: &str) -> Option<Vec<&'a str>> {
    for part in csp.split(';') {
        let mut tokens = part.split_whitespace();
        if tokens.next() == Some(directive) {
            return Some(tokens.collect());
        }
    }
    None
}

/// `content_security_policy.extension_pages` (module docs table, row 7).
fn check_csp(manifest: &Value) -> Vec<String> {
    let Some(csp) = manifest
        .get("content_security_policy")
        .and_then(|v| v.get("extension_pages"))
        .and_then(Value::as_str)
    else {
        return vec!["content_security_policy.extension_pages must be a string".to_owned()];
    };
    let mut out = Vec::new();
    match csp_directive(csp, "script-src") {
        Some(sources) if !sources.is_empty() && is_subset_of(&sources, ALLOWED_CSP_SCRIPT_SRC) => {}
        Some(sources) => out.push(format!(
            "content_security_policy.extension_pages script-src {sources:?} is not a subset of {ALLOWED_CSP_SCRIPT_SRC:?} \
             (MV3 bans remote code; no inline/eval beyond the one wasm exception)"
        )),
        None => out.push("content_security_policy.extension_pages has no script-src directive".to_owned()),
    }
    match csp_directive(csp, "object-src") {
        Some(sources) if sources == ["'self'"] || sources == ["'none'"] => {}
        Some(sources) => out.push(format!("content_security_policy.extension_pages object-src {sources:?} must be 'self' or 'none'")),
        None => out.push("content_security_policy.extension_pages has no object-src directive".to_owned()),
    }
    match csp_directive(csp, "base-uri") {
        Some(sources) if sources == ["'none'"] => {}
        Some(sources) => out.push(format!(
            "content_security_policy.extension_pages base-uri {sources:?} must be 'none'"
        )),
        None => {
            out.push(
                "content_security_policy.extension_pages has no base-uri directive".to_owned(),
            );
        }
    }
    out
}

/// Checks one already-parsed manifest and returns every violation found (module docs table).
pub(crate) fn check_manifest_security(browser: Browser, manifest: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if manifest.get("manifest_version").and_then(Value::as_u64) != Some(3) {
        out.push("manifest_version must be 3 (MV3, ADR 0036 §2)".to_owned());
    }
    if manifest.get("externally_connectable").is_some() {
        out.push(
            "must not declare externally_connectable at all (INV-40; ADR 0036 §4: \"not even the web vault's own origin\")"
                .to_owned(),
        );
    }
    out.extend(check_permissions(browser, manifest));
    out.extend(check_host_permissions(manifest));
    out.extend(check_content_scripts(manifest));
    out.extend(check_web_accessible_resources(manifest));
    out.extend(check_csp(manifest));
    out
}

/// `cargo xtask check-manifest`: reads and checks both built manifests under `root`
/// (`apps/extension/dist/{chromium,firefox}/manifest.json`). Returns the report, or every
/// violation across both builds, each prefixed with its build's name.
///
/// # Errors
///
/// A built manifest is missing (run `pnpm run build` in `apps/extension` first — `build-wasm`
/// before that) or is not valid JSON.
pub(crate) fn check_built_manifests(root: &Path) -> Result<String, String> {
    let mut violations = Vec::new();
    let mut checked = 0usize;
    for browser in [Browser::Chromium, Browser::Firefox] {
        let path = root
            .join("apps")
            .join("extension")
            .join("dist")
            .join(browser.dist_dir())
            .join("manifest.json");
        let text = fs::read_to_string(&path).map_err(|e| {
            format!(
                "{}: {e} (run `pnpm run build` in apps/extension first, after `cargo xtask build-wasm`)",
                path.display()
            )
        })?;
        let manifest: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{}: not JSON: {e}", path.display()))?;
        checked += 1;
        for v in check_manifest_security(browser, &manifest) {
            violations.push(format!("{}: {v}", path.display()));
        }
    }
    if violations.is_empty() {
        Ok(format!(
            "check-manifest: ok ({checked} built manifests; INV-40, ADR 0036 §4/§5, ADR 0040)"
        ))
    } else {
        Err(format!(
            "{}\ncheck-manifest: {} violation(s) of INV-40 / ADR 0036 §4/§5 / ADR 0040. The allow-lists are in \
             crates/xtask/src/ext_manifest.rs; changing one is a security review.",
            violations.join("\n"),
            violations.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A minimal, fully-compliant Chromium manifest — every field this module checks, nothing
    /// it does not allow.
    fn good_chromium() -> Value {
        json!({
            "manifest_version": 3,
            "permissions": ["storage", "offscreen", "idle"],
            "host_permissions": ["http://*/*", "https://*/*"],
            "content_scripts": [
                { "matches": ["http://*/*", "https://*/*"], "all_frames": false },
                { "matches": ["https://*/*"], "all_frames": false }
            ],
            "web_accessible_resources": [
                {
                    "resources": ["src/inline-menu/index.html", "src/passkey-consent/index.html", "src/content/passkey-page-shim.js"],
                    "matches": ["http://*/*", "https://*/*"]
                }
            ],
            "content_security_policy": {
                "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'none'"
            }
        })
    }

    /// The same shape, minus the Chromium-only `offscreen` permission — Firefox's own real
    /// manifest shape.
    fn good_firefox() -> Value {
        let mut m = good_chromium();
        m["permissions"] = json!(["storage", "idle"]);
        m
    }

    /// Exercises the hand-written fixtures above (mirrors of the allow-list constants in this
    /// same file), NOT the real committed manifest source files — see
    /// `the_real_committed_manifest_source_files_pass` below for that.
    #[test]
    fn the_fixture_shaped_manifests_pass() {
        assert_eq!(
            check_manifest_security(Browser::Chromium, &good_chromium()),
            Vec::<String>::new()
        );
        assert_eq!(
            check_manifest_security(Browser::Firefox, &good_firefox()),
            Vec::<String>::new()
        );
    }

    /// Reads the REAL committed `apps/extension/manifest.{chromium,firefox}.json` source files
    /// (never the fixtures above, which only mirror this module's own allow-lists and so could
    /// never catch the source files actually drifting) and runs them through
    /// `check_manifest_security` directly. Needs no built `dist/` tree, so unlike
    /// `check_built_manifests` (exercised only by the separate, not-yet-CI-wired `cargo xtask
    /// check-manifest`), this runs under plain `cargo test --workspace` — closing the gap where
    /// a real regression (e.g. a new permission, a wider `web_accessible_resources` entry) could
    /// drift the source files while `cargo test` stayed green.
    #[test]
    fn the_real_committed_manifest_source_files_pass() {
        let chromium: Value = serde_json::from_str(include_str!(
            "../../../apps/extension/manifest.chromium.json"
        ))
        .expect("apps/extension/manifest.chromium.json must be valid JSON");
        let firefox: Value = serde_json::from_str(include_str!(
            "../../../apps/extension/manifest.firefox.json"
        ))
        .expect("apps/extension/manifest.firefox.json must be valid JSON");
        assert_eq!(
            check_manifest_security(Browser::Chromium, &chromium),
            Vec::<String>::new(),
            "apps/extension/manifest.chromium.json violates the allow-lists in this module"
        );
        assert_eq!(
            check_manifest_security(Browser::Firefox, &firefox),
            Vec::<String>::new(),
            "apps/extension/manifest.firefox.json violates the allow-lists in this module"
        );
    }

    #[test]
    fn firefox_is_not_allowed_the_chromium_only_offscreen_permission() {
        let mut m = good_firefox();
        m["permissions"] = json!(["storage", "idle", "offscreen"]);
        assert!(!check_manifest_security(Browser::Firefox, &m).is_empty());
        // The very same permission set is fine for Chromium.
        assert!(check_manifest_security(Browser::Chromium, &m).is_empty());
    }

    #[test]
    fn manifest_version_must_be_exactly_3() {
        let mut m = good_chromium();
        m["manifest_version"] = json!(2);
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("manifest_version")));
    }

    #[test]
    fn externally_connectable_for_any_value_is_a_violation() {
        let mut m = good_chromium();
        m["externally_connectable"] = json!({ "matches": ["https://rizzy-vault.example/*"] });
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("externally_connectable"))
        );
    }

    #[test]
    fn an_unlisted_permission_is_a_violation() {
        let mut m = good_chromium();
        m["permissions"] = json!(["storage", "offscreen", "idle", "tabs"]);
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("permissions")));
    }

    #[test]
    fn host_permissions_must_be_exactly_the_two_patterns_not_all_urls() {
        let mut m = good_chromium();
        m["host_permissions"] = json!(["<all_urls>"]);
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("host_permissions")));
    }

    #[test]
    fn a_content_script_with_all_frames_true_is_a_violation() {
        let mut m = good_chromium();
        m["content_scripts"][0]["all_frames"] = json!(true);
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("all_frames")));
    }

    #[test]
    fn a_content_script_matching_file_urls_is_a_violation() {
        let mut m = good_chromium();
        m["content_scripts"][0]["matches"] = json!(["file://*/*"]);
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("matches")));
    }

    #[test]
    fn a_content_script_running_in_the_main_world_is_a_violation() {
        let mut m = good_chromium();
        m["content_scripts"][0]["world"] = json!("MAIN");
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("world")));
    }

    #[test]
    fn a_content_script_explicitly_isolated_is_not_a_violation() {
        let mut m = good_chromium();
        m["content_scripts"][0]["world"] = json!("ISOLATED");
        assert!(check_manifest_security(Browser::Chromium, &m).is_empty());
    }

    #[test]
    fn web_accessible_resources_exposing_the_popup_is_a_violation() {
        let mut m = good_chromium();
        m["web_accessible_resources"][0]["resources"] = json!(["src/popup/index.html"]);
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("web_accessible_resources"))
        );
    }

    #[test]
    fn csp_allowing_unsafe_eval_is_a_violation_but_wasm_unsafe_eval_is_not_mistaken_for_it() {
        let mut m = good_chromium();
        m["content_security_policy"]["extension_pages"] =
            json!("script-src 'self' 'unsafe-eval'; object-src 'self'; base-uri 'none'");
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("script-src")));
        // The real, legitimate CSP (wasm-unsafe-eval, never plain unsafe-eval) must NOT trip the
        // same check — a naive substring check on "unsafe-eval" would flag this too.
        assert!(check_manifest_security(Browser::Chromium, &good_chromium()).is_empty());
    }

    #[test]
    fn csp_allowing_a_remote_script_source_is_a_violation() {
        let mut m = good_chromium();
        m["content_security_policy"]["extension_pages"] =
            json!("script-src 'self' https://evil.example; object-src 'self'; base-uri 'none'");
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("script-src")));
    }

    #[test]
    fn csp_object_src_wide_open_is_a_violation() {
        let mut m = good_chromium();
        m["content_security_policy"]["extension_pages"] =
            json!("script-src 'self' 'wasm-unsafe-eval'; object-src *; base-uri 'none'");
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("object-src")));
    }

    /// `object-src 'none'` is strictly tighter than `'self'` (nothing may load there at all) and
    /// is explicitly allowed by `check_csp`'s own match arm — the module docs table said only
    /// `'self'` was allowed, which this test (previously untested) pins against drifting back.
    #[test]
    fn csp_object_src_none_is_not_a_violation() {
        let mut m = good_chromium();
        m["content_security_policy"]["extension_pages"] =
            json!("script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'");
        assert!(check_manifest_security(Browser::Chromium, &m).is_empty());
    }

    #[test]
    fn csp_base_uri_not_none_is_a_violation() {
        let mut m = good_chromium();
        m["content_security_policy"]["extension_pages"] =
            json!("script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; base-uri 'self'");
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.iter().any(|v| v.contains("base-uri")));
    }

    #[test]
    fn missing_arrays_are_violations_not_panics() {
        let m = json!({ "manifest_version": 3 });
        let violations = check_manifest_security(Browser::Chromium, &m);
        assert!(violations.len() >= 4);
    }

    #[test]
    fn check_built_manifests_reports_a_clear_message_when_dist_is_missing() {
        let dir = std::env::temp_dir().join(format!(
            "rizzy-xtask-ext-manifest-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        let result = check_built_manifests(&dir);
        let _ = fs::remove_dir_all(&dir);
        let Err(message) = result else {
            panic!("expected an error for a missing dist/ directory");
        };
        assert!(message.contains("pnpm run build"), "message was: {message}");
    }
}
