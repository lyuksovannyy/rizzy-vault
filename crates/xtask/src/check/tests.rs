//! Rule evaluation on synthetic metadata: a clean tree shaped like the current workspace, then
//! one violation at a time.

use super::*;
use crate::metadata::{Declared, Edge, Package};

const ROOT: &str = "/ws";

/// Builds a synthetic resolved graph.
struct Tree {
    g: Graph,
    config: Manifest,
    manifests: Vec<(String, Manifest)>,
    wasm: Option<Graph>,
    workspace_manifest: Manifest,
    root_clippy: Manifest,
    clippy_configs: Vec<(String, Option<Manifest>)>,
    hidden_clippy_configs: Vec<String>,
    rust_sources: Vec<(String, String)>,
}

const GOOD_MANIFEST: &str = "[package]\nname = \"x\"\nlicense.workspace = true\n\
    publish.workspace = true\nrust-version.workspace = true\n[lints]\nworkspace = true\n";

const WORKSPACE_MANIFEST: &str = "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n\
    [workspace.lints.clippy]\nall = { level = \"deny\", priority = -1 }\n";

const ROOT_CLIPPY: &str = "msrv = \"1.94\"\nallow-unwrap-in-tests = true\n";

/// A no-I/O crate's clippy.toml: [`ROOT_CLIPPY`] plus the ADR 0016 §5 lists, one entry as a
/// plain string and the rest as `{ path, reason }` tables, spread over lines.
fn good_clippy() -> String {
    use std::fmt::Write as _;
    let mut text = format!("# comment\n{ROOT_CLIPPY}");
    for (list, entries) in rules::NO_IO_CLIPPY_LISTS {
        let _ = writeln!(text, "{list} = [");
        for (n, entry) in entries.iter().enumerate() {
            if n == 0 {
                let _ = writeln!(text, "  \"{entry}\",");
            } else {
                let _ = writeln!(text, "  {{ path = \"{entry}\", reason = \"R1, a, b\" }},");
            }
        }
        text.push_str("]\n");
    }
    text
}

impl Tree {
    /// The current workspace in miniature: rizzy-core with part of its real closure, rizzy-sync,
    /// rizzy-server, rizzy-cli and xtask, and one first-party source with `unsafe` only in a
    /// comment and a longer word.
    fn current() -> Self {
        let mut t = Self {
            g: Graph {
                packages: Vec::new(),
                workspace_root: ROOT.to_owned(),
            },
            config: Manifest::parse(
                "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync --target \
                 wasm32-unknown-unknown --locked\"\n",
            ),
            manifests: Vec::new(),
            wasm: None,
            workspace_manifest: Manifest::parse(WORKSPACE_MANIFEST),
            root_clippy: Manifest::parse(ROOT_CLIPPY),
            clippy_configs: Vec::new(),
            hidden_clippy_configs: Vec::new(),
            rust_sources: vec![(
                "crates/rizzy-core/src/lib.rs".to_owned(),
                "//! No `unsafe` code.\n#![forbid(unsafe_code)]\n".to_owned(),
            )],
        };
        let core = t.member("rizzy-core");
        let sync = t.member("rizzy-sync");
        t.member("rizzy-server");
        let cli = t.member("rizzy-cli");
        let xtask = t.member("xtask");
        let opaque = t.external("opaque-ke", "4.0.1");
        let rand = t.external("rand", "0.8.8");
        let rand_core = t.external("rand_core", "0.6.4");
        let zeroize = t.external("zeroize", "1.9.0");
        let proptest = t.external("proptest", "1.11.0");
        let getrandom = t.external("getrandom", "0.3.4");
        let serde_json = t.external("serde_json", "1.0.151");
        t.edge(core, opaque, &[Kind::Normal]);
        t.edge(opaque, rand, &[Kind::Normal]);
        t.edge(rand, rand_core, &[Kind::Normal]);
        t.edge(core, zeroize, &[Kind::Normal]);
        t.edge(core, proptest, &[Kind::Dev]);
        t.edge(proptest, getrandom, &[Kind::Normal]);
        t.edge(sync, core, &[Kind::Normal]);
        t.edge(cli, core, &[Kind::Normal]);
        t.edge(xtask, serde_json, &[Kind::Normal]);
        t.declare(core, "opaque-ke", Kind::Normal, &["ristretto255"]);
        t.declare(core, "zeroize", Kind::Normal, &[]);
        t.declare(core, "proptest", Kind::Dev, &["std"]);
        t
    }

    fn member(&mut self, name: &str) -> usize {
        let dir = rules::rule(name).map_or_else(|| format!("crates/{name}"), |r| r.dir.to_owned());
        let i = self.push(Package {
            id: format!("path+file://{ROOT}/{dir}#0.0.0"),
            name: name.to_owned(),
            version: "0.0.0".to_owned(),
            manifest_path: format!("{ROOT}/{dir}/Cargo.toml"),
            is_member: true,
            features: Vec::new(),
            deps: Vec::new(),
            declared: Vec::new(),
            feature_table: Vec::new(),
        });
        self.manifests
            .push((name.to_owned(), Manifest::parse(GOOD_MANIFEST)));
        if rules::rule(name).is_some_and(|r| r.no_io) {
            self.clippy_configs
                .push((name.to_owned(), Some(Manifest::parse(&good_clippy()))));
        }
        i
    }

    fn external(&mut self, name: &str, version: &str) -> usize {
        self.push(Package {
            id: format!("registry#{name}@{version}"),
            name: name.to_owned(),
            version: version.to_owned(),
            manifest_path: format!("/registry/{name}-{version}/Cargo.toml"),
            is_member: false,
            features: Vec::new(),
            deps: Vec::new(),
            declared: Vec::new(),
            feature_table: Vec::new(),
        })
    }

    fn push(&mut self, p: Package) -> usize {
        self.g.packages.push(p);
        self.g.packages.len() - 1
    }

    fn edge(&mut self, from: usize, to: usize, kinds: &[Kind]) {
        let name = self.g.packages[to].name.replace('-', "_");
        self.edge_named(from, to, kinds, &name);
    }

    /// An edge the dependent knows under `name` (a renamed dependency).
    fn edge_named(&mut self, from: usize, to: usize, kinds: &[Kind], name: &str) {
        self.g.packages[from].deps.push(Edge {
            to,
            kinds: kinds.to_vec(),
            name: name.to_owned(),
        });
    }

    fn declare(&mut self, from: usize, name: &str, kind: Kind, features: &[&str]) {
        self.g.packages[from].declared.push(Declared {
            name: name.to_owned(),
            rename: None,
            kind,
            features: features.iter().map(|f| (*f).to_owned()).collect(),
            default_features: false,
        });
    }

    /// A `[features]` entry of `from`: `feature = [enables...]`.
    fn feature(&mut self, from: usize, feature: &str, enables: &[&str]) {
        self.g.packages[from].feature_table.push((
            feature.to_owned(),
            enables.iter().map(|e| (*e).to_owned()).collect(),
        ));
    }

    fn id(&self, name: &str) -> usize {
        self.g
            .packages
            .iter()
            .position(|p| p.name == name)
            .expect("the package exists in the synthetic tree")
    }

    fn run(&self) -> Vec<Violation> {
        let wasm = self.wasm.clone().unwrap_or_else(|| self.g.clone());
        run(&Inputs {
            all_targets: self.g.clone(),
            per_target: vec![
                ("wasm32-unknown-unknown".to_owned(), wasm),
                ("x86_64-unknown-linux-gnu".to_owned(), self.g.clone()),
            ],
            manifests: self.manifests.clone(),
            workspace_manifest: self.workspace_manifest.clone(),
            cargo_config: self.config.clone(),
            root_clippy: self.root_clippy.clone(),
            clippy_configs: self.clippy_configs.clone(),
            hidden_clippy_configs: self.hidden_clippy_configs.clone(),
            rust_sources: self.rust_sources.clone(),
        })
    }
}

/// Asserts that only `rule` fired, and that it fired for `krate` with a message containing
/// `needle`. (A violation in `rizzy-core`'s closure also fires for `rizzy-sync`, which reaches
/// it through `rizzy-core`.)
#[track_caller]
fn assert_only(violations: &[Violation], rule: &str, krate: &str, needle: &str) {
    for v in violations {
        assert_eq!(v.rule, rule, "{violations:#?}");
    }
    assert_fires(violations, rule, krate, needle);
}

#[track_caller]
fn assert_fires(violations: &[Violation], rule: &str, krate: &str, needle: &str) {
    assert!(
        violations
            .iter()
            .any(|v| v.rule == rule && v.krate == krate && v.message.contains(needle)),
        "expected [{rule}] {krate}: ..{needle}..; got {violations:#?}"
    );
}

#[test]
fn the_current_tree_shape_passes() {
    assert_eq!(Tree::current().run(), []);
}

// ---- R1: no-I/O closures -----------------------------------------------------------------

#[test]
fn r1_forbidden_io_crate_in_the_closure() {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let foo = t.external("aead", "0.6.1");
    let tokio = t.external("tokio", "1.40.0");
    t.edge(core, foo, &[Kind::Normal]);
    t.edge(foo, tokio, &[Kind::Normal]);
    assert_only(
        &t.run(),
        "ADR 0016 R1",
        "rizzy-core",
        "rizzy-core -> aead -> tokio",
    );
}

#[test]
fn r1_unlisted_external_crate() {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let pad = t.external("left-pad", "1.0.0");
    t.edge(core, pad, &[Kind::Build]);
    assert_only(&t.run(), "ADR 0016 R1", "rizzy-core", "left-pad@1");
}

#[test]
fn r1_semver_incompatible_version_is_not_listed() {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let zeroize2 = t.external("zeroize", "2.0.0");
    t.edge(core, zeroize2, &[Kind::Normal]);
    assert_only(&t.run(), "ADR 0016 R1", "rizzy-core", "zeroize@2");
}

#[test]
fn r1_applies_through_internal_dependencies() {
    // rizzy-sync reaches core's closure; a crate outside both allow-lists fires for both.
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let pad = t.external("left-pad", "1.0.0");
    t.edge(core, pad, &[Kind::Normal]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R1", "rizzy-core", "left-pad");
    assert_fires(
        &v,
        "ADR 0016 R1",
        "rizzy-sync",
        "rizzy-sync -> rizzy-core -> left-pad",
    );
}

#[test]
fn r1_dev_dependencies_may_use_test_crates() {
    // proptest and its getrandom are dev-only: allowed (R1 covers normal and build only).
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let chacha = t.external("chacha20", "0.10.2");
    t.edge(core, chacha, &[Kind::Dev]);
    assert_eq!(t.run(), []);
}

#[test]
fn r1_getrandom_on_wasm32_only() {
    // Reachable only in the wasm32-filtered graph: reported for that target.
    let mut t = Tree::current();
    let mut wasm = t.g.clone();
    let rand_core = t.id("rand_core");
    wasm.packages.push(Package {
        id: "registry#getrandom@0.2.15".to_owned(),
        name: "getrandom".to_owned(),
        version: "0.2.15".to_owned(),
        manifest_path: "/registry/getrandom/Cargo.toml".to_owned(),
        is_member: false,
        features: vec!["js".to_owned()],
        deps: Vec::new(),
        declared: Vec::new(),
        feature_table: Vec::new(),
    });
    let gr = wasm.packages.len() - 1;
    wasm.packages[rand_core].deps.push(Edge {
        to: gr,
        kinds: vec![Kind::Normal],
        name: "getrandom".to_owned(),
    });
    t.wasm = Some(wasm);
    let v = t.run();
    assert_fires(
        &v,
        "ADR 0016 R1/R2",
        "rizzy-core",
        "on wasm32-unknown-unknown",
    );
    assert_fires(
        &v,
        "ADR 0016 R1/R2",
        "rizzy-sync",
        "on wasm32-unknown-unknown",
    );
    assert_fires(
        &v,
        "ADR 0016 R1/R2",
        "rizzy-core",
        "cargo tree -p rizzy-core",
    );
    assert!(v.iter().all(|x| !x.message.contains("x86_64")), "{v:#?}");
}

#[test]
fn r1_getrandom_in_every_target_graph_is_also_forbidden_by_name() {
    let mut t = Tree::current();
    let rand_core = t.id("rand_core");
    let getrandom = t.id("getrandom");
    t.edge(rand_core, getrandom, &[Kind::Normal]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R1", "rizzy-core", "OS randomness");
    assert_fires(
        &v,
        "ADR 0016 R1/R2",
        "rizzy-core",
        "x86_64-unknown-linux-gnu",
    );
}

#[test]
fn rand_only_through_opaque_ke() {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let rand = t.id("rand");
    let voprf = t.external("voprf", "0.5.0");
    t.edge(core, voprf, &[Kind::Normal]);
    t.edge(voprf, rand, &[Kind::Normal]);
    assert_only(
        &t.run(),
        "ADR 0009 RNG rules",
        "rizzy-core",
        "through voprf",
    );
}

#[test]
fn rand_with_features_is_rejected() {
    let mut t = Tree::current();
    let rand = t.id("rand");
    t.g.packages[rand].features = vec!["std".to_owned(), "std_rng".to_owned()];
    let v = t.run();
    assert_fires(&v, "ADR 0009 RNG rules", "rizzy-core", "[std, std_rng]");
    assert_fires(&v, "ADR 0009 RNG rules", "rizzy-sync", "[std, std_rng]");
}

#[test]
fn rand_other_major_version_is_not_listed() {
    let mut t = Tree::current();
    let opaque = t.id("opaque-ke");
    let rand9 = t.external("rand", "0.9.2");
    t.edge(opaque, rand9, &[Kind::Normal]);
    assert_fires(&t.run(), "ADR 0016 R1", "rizzy-core", "rand@0.9");
}

#[test]
fn r1_no_direct_randomness_dependency_in_any_kind() {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    t.declare(core, "rand", Kind::Dev, &[]);
    assert_only(
        &t.run(),
        "ADR 0016 R1",
        "rizzy-core",
        "dev-dependency `rand`",
    );
}

// ---- ADR 0009 required feature sets --------------------------------------------------------

/// [`Tree::current`] plus rizzy-core → argon2 → blake2 and rizzy-core → chacha20poly1305 →
/// poly1305, all declared by rizzy-core with the ADR 0009 feature sets.
fn with_crypto_crates() -> Tree {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let argon2 = t.external("argon2", "0.6.0");
    let blake2 = t.external("blake2", "0.11.0");
    let aead = t.external("chacha20poly1305", "0.11.0");
    let poly1305 = t.external("poly1305", "0.9.1");
    for (from, to) in [
        (core, argon2),
        (argon2, blake2),
        (core, blake2),
        (core, aead),
        (aead, poly1305),
        (core, poly1305),
    ] {
        t.edge(from, to, &[Kind::Normal]);
    }
    t.declare(core, "argon2", Kind::Normal, &["zeroize"]);
    t.declare(core, "blake2", Kind::Normal, &["zeroize"]);
    t.declare(
        core,
        "chacha20poly1305",
        Kind::Normal,
        &["alloc", "zeroize"],
    );
    t.declare(core, "poly1305", Kind::Normal, &["zeroize"]);
    for (i, features) in [
        (argon2, &["zeroize"][..]),
        (blake2, &["zeroize"]),
        (aead, &["alloc", "zeroize"]),
        (poly1305, &["zeroize"]),
    ] {
        t.g.packages[i].features = features.iter().map(|f| (*f).to_owned()).collect();
    }
    t
}

#[test]
fn adr0009_crypto_feature_sets_pass_when_declared() {
    assert_eq!(with_crypto_crates().run(), []);
}

#[test]
fn adr0009_blake2_and_poly1305_must_stay_declared_with_zeroize() {
    // The review's regression: the two feature-only dependencies deleted from rizzy-core's
    // manifest. They look unused, and before this rule every check still passed.
    for name in ["blake2", "poly1305"] {
        let mut t = with_crypto_crates();
        let core = t.id("rizzy-core");
        let dep = t.id(name);
        t.g.packages[core].declared.retain(|d| d.name != name);
        t.g.packages[core].deps.retain(|e| e.to != dep);
        t.g.packages[dep].features.clear();
        assert_only(
            &t.run(),
            "ADR 0009 required feature sets",
            "rizzy-core",
            &format!("does not turn on [zeroize]. Declare `{name}.workspace = true`"),
        );
    }
    // Declared, but without the feature.
    let mut t = with_crypto_crates();
    let core = t.id("rizzy-core");
    for d in &mut t.g.packages[core].declared {
        if d.name == "blake2" {
            d.features.clear();
        }
    }
    assert_only(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-core",
        "blake2 0.11.0",
    );
}

#[test]
fn adr0009_a_feature_from_elsewhere_does_not_count() {
    // Another member turning on sha2's `zeroize` hides nothing: rizzy-core built alone would
    // lack it. Only rizzy-core's own entry counts.
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let cli = t.id("rizzy-cli");
    let sha2 = t.external("sha2", "0.11.0");
    t.edge(core, sha2, &[Kind::Normal]);
    t.edge(cli, sha2, &[Kind::Normal]);
    t.declare(core, "sha2", Kind::Normal, &[]);
    t.declare(cli, "sha2", Kind::Normal, &["zeroize"]);
    t.g.packages[sha2].features = vec!["zeroize".to_owned()];
    assert_only(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-core",
        "sha2 0.11.0",
    );
    // A dev-dependency entry does not count either.
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let sha2 = t.external("sha2", "0.11.0");
    t.edge(core, sha2, &[Kind::Normal, Kind::Dev]);
    t.declare(core, "sha2", Kind::Normal, &[]);
    t.declare(core, "sha2", Kind::Dev, &["zeroize"]);
    assert_fires(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-core",
        "sha2 0.11.0",
    );
}

#[test]
fn adr0009_rules_are_per_version() {
    // sha2 0.10 (opaque-ke's hash, renamed `sha2_010` in rizzy-core) has no required features;
    // sha2 0.11 needs `zeroize`, and the entry that counts is the one that resolves to it.
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let sha2_010 = t.external("sha2", "0.10.9");
    let sha2 = t.external("sha2", "0.11.0");
    t.edge_named(core, sha2_010, &[Kind::Normal], "sha2_010");
    t.edge(core, sha2, &[Kind::Normal]);
    t.declare(core, "sha2", Kind::Normal, &["zeroize"]);
    t.declare(core, "sha2", Kind::Normal, &[]);
    t.g.packages[core].declared.last_mut().unwrap().rename = Some("sha2_010".to_owned());
    assert_eq!(t.run(), []);
    // The zeroize feature moved to the 0.10 entry: 0.11 lacks it.
    for d in &mut t.g.packages[core].declared {
        if d.name == "sha2" {
            d.features = if d.rename.is_some() {
                vec!["zeroize".to_owned()]
            } else {
                Vec::new()
            };
        }
    }
    assert_only(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-core",
        "sha2 0.11.0",
    );
}

#[test]
fn adr0009_forbidden_features_fail_on_the_unified_graph() {
    for (name, feature) in [("argon2", "alloc"), ("argon2", "parallel")] {
        let mut t = with_crypto_crates();
        let i = t.id(name);
        t.g.packages[i].features.push(feature.to_owned());
        assert_only(
            &t.run(),
            "ADR 0009 required feature sets",
            "rizzy-core",
            &format!("[{feature}] enabled"),
        );
    }
    let mut t = Tree::current();
    let opaque = t.id("opaque-ke");
    t.g.packages[opaque].features = vec!["ristretto255".to_owned(), "std".to_owned()];
    assert_only(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-core",
        "opaque-ke 4.0.1 has [std] enabled",
    );
}

// ---- ADR 0009: crypto crates declared with `default-features = false` ----------------------

/// Turns default features back on in `from`'s `kind` entries for the package `name`.
fn keep_defaults(t: &mut Tree, from: usize, name: &str, kind: Kind) {
    for d in &mut t.g.packages[from].declared {
        if d.name == name && d.kind == kind {
            d.default_features = true;
        }
    }
}

/// [`with_crypto_crates`] plus crypto entries of every kind outside rizzy-core, all with
/// default features off: rizzy-cli's `hpke`, xtask's dev-dependency on `sha2` 0.11 and its
/// build-dependency on `sha2` 0.10 renamed `sha2_010`.
fn with_crypto_entries_everywhere() -> Tree {
    let mut t = with_crypto_crates();
    let cli = t.id("rizzy-cli");
    let xtask = t.id("xtask");
    let hpke = t.external("hpke", "0.14.1");
    let sha2 = t.external("sha2", "0.11.0");
    let sha2_010 = t.external("sha2", "0.10.9");
    t.edge(cli, hpke, &[Kind::Normal]);
    t.edge(xtask, sha2, &[Kind::Dev]);
    t.edge_named(xtask, sha2_010, &[Kind::Build], "sha2_010");
    t.declare(cli, "hpke", Kind::Normal, &["alloc", "x25519", "chacha"]);
    t.declare(xtask, "sha2", Kind::Dev, &["zeroize"]);
    t.declare(xtask, "sha2", Kind::Build, &[]);
    t.g.packages[xtask].declared.last_mut().unwrap().rename = Some("sha2_010".to_owned());
    t
}

#[test]
fn adr0009_crypto_crates_without_default_features_pass() {
    assert_eq!(with_crypto_crates().run(), []);
    assert_eq!(with_crypto_entries_everywhere().run(), []);
    // The rule covers the ADR 0009 crypto crates only: other crates may keep their defaults.
    let mut t = with_crypto_entries_everywhere();
    let core = t.id("rizzy-core");
    let xtask = t.id("xtask");
    t.declare(xtask, "serde_json", Kind::Normal, &["std"]);
    keep_defaults(&mut t, xtask, "serde_json", Kind::Normal);
    keep_defaults(&mut t, core, "proptest", Kind::Dev);
    assert_eq!(t.run(), []);
}

#[test]
fn adr0009_blake2_and_poly1305_with_default_features_as_normal_dependencies() {
    for name in ["blake2", "poly1305"] {
        let mut t = with_crypto_crates();
        let core = t.id("rizzy-core");
        keep_defaults(&mut t, core, name, Kind::Normal);
        let v = t.run();
        assert_only(
            &v,
            "ADR 0009 required feature sets",
            "rizzy-core",
            &format!(
                "declares the dependency `{name}` with default features on: `default-features` \
                 is not `false`"
            ),
        );
        assert_eq!(v.len(), 1, "{v:#?}");
    }
}

#[test]
fn adr0009_default_features_on_a_dev_dependency() {
    // Tests that want the RNG-less hpke API would pull getrandom and mlkem into rizzy-core's
    // test build, where the known-answer vectors run.
    let mut t = with_crypto_crates();
    let core = t.id("rizzy-core");
    let hpke = t.external("hpke", "0.14.1");
    t.edge(core, hpke, &[Kind::Dev]);
    t.declare(core, "hpke", Kind::Dev, &[]);
    keep_defaults(&mut t, core, "hpke", Kind::Dev);
    assert_only(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-core",
        "declares the dev-dependency `hpke` with default features on",
    );
}

#[test]
fn adr0009_default_features_in_members_other_than_rizzy_core() {
    let cases = [
        ("rizzy-cli", "hpke", Kind::Normal, "dependency `hpke`"),
        ("xtask", "sha2", Kind::Dev, "dev-dependency `sha2`"),
        (
            "xtask",
            "sha2",
            Kind::Build,
            "build-dependency `sha2_010` (package `sha2`)",
        ),
    ];
    for (member, name, kind, needle) in cases {
        let mut t = with_crypto_entries_everywhere();
        let from = t.id(member);
        keep_defaults(&mut t, from, name, kind);
        let v = t.run();
        assert_only(&v, "ADR 0009 required feature sets", member, needle);
        assert!(v.iter().all(|x| x.krate == member), "{v:#?}");
    }
}

#[test]
fn adr0009_default_feature_turned_on_by_name() {
    // `default-features = false` in the entry, then `default` named in the entry itself or in
    // the member's `[features]` table: the defaults are on all the same.
    let mut t = with_crypto_crates();
    let core = t.id("rizzy-core");
    t.feature(core, "extras", &["poly1305?/default"]);
    assert_only(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-core",
        "`poly1305` with default features on: the entry or the `[features]` table",
    );

    let mut t = with_crypto_entries_everywhere();
    let cli = t.id("rizzy-cli");
    for d in &mut t.g.packages[cli].declared {
        if d.name == "hpke" {
            d.features.push("default".to_owned());
        }
    }
    assert_only(
        &t.run(),
        "ADR 0009 required feature sets",
        "rizzy-cli",
        "`hpke` with default features on",
    );
}

// ---- R2: getrandom and wasm_js ------------------------------------------------------------

#[test]
fn r2_libraries_never_declare_getrandom() {
    let mut t = Tree::current();
    let sync = t.id("rizzy-sync");
    t.declare(sync, "getrandom", Kind::Normal, &[]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R2", "rizzy-sync", "only the leaf crates");
    assert_fires(
        &v,
        "ADR 0016 R1",
        "rizzy-sync",
        "never depend on `rand` or getrandom",
    );
}

#[test]
fn r2_leaf_crates_may_declare_getrandom_but_not_wasm_js() {
    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    t.declare(cli, "getrandom", Kind::Normal, &["sys_rng"]);
    assert_eq!(t.run(), []);
    t.declare(cli, "getrandom", Kind::Normal, &["wasm_js"]);
    assert_only(&t.run(), "ADR 0016 R2", "rizzy-cli", "only rizzy-wasm");
}

#[test]
fn r2_wasm_js_switched_on_by_a_dependency() {
    let mut t = Tree::current();
    let getrandom = t.id("getrandom");
    t.g.packages[getrandom].features = vec!["wasm_js".to_owned()];
    assert_only(
        &t.run(),
        "ADR 0016 R2",
        "getrandom 0.3.4",
        "not by rizzy-wasm",
    );
}

/// The current tree plus rizzy-client and rizzy-wasm, which enables `wasm_js` on getrandom
/// 0.3.4 as R2 (c) allows.
fn with_rizzy_wasm() -> Tree {
    let mut t = Tree::current();
    let wasm = t.member("rizzy-wasm");
    let client = t.member("rizzy-client");
    let core = t.id("rizzy-core");
    let getrandom = t.id("getrandom");
    t.edge(wasm, client, &[Kind::Normal]);
    t.edge(client, core, &[Kind::Normal]);
    t.edge(wasm, getrandom, &[Kind::Normal]);
    t.declare(wasm, "getrandom", Kind::Normal, &["wasm_js"]);
    t.g.packages[getrandom].features = vec!["wasm_js".to_owned()];
    t.config = Manifest::parse(
        "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync -p rizzy-client \
         -p rizzy-wasm --target wasm32-unknown-unknown\"\n",
    );
    t
}

#[test]
fn r2_rizzy_wasm_may_enable_wasm_js() {
    assert_eq!(with_rizzy_wasm().run(), []);

    // Also through a renamed dependency and its `[features]` table.
    let mut t = Tree::current();
    let wasm = t.member("rizzy-wasm");
    let client = t.member("rizzy-client");
    let core = t.id("rizzy-core");
    let getrandom = t.id("getrandom");
    t.edge(wasm, client, &[Kind::Normal]);
    t.edge(client, core, &[Kind::Normal]);
    t.edge_named(wasm, getrandom, &[Kind::Normal], "getrandom03");
    t.declare(wasm, "getrandom", Kind::Normal, &[]);
    t.g.packages[wasm].declared[0].rename = Some("getrandom03".to_owned());
    t.feature(wasm, "default", &["getrandom03/wasm_js"]);
    t.g.packages[getrandom].features = vec!["wasm_js".to_owned()];
    t.config = with_rizzy_wasm().config;
    assert_eq!(t.run(), []);
}

#[test]
fn r2_wasm_js_through_the_features_table() {
    // Before the `[features]` table was read, this passed: the entry has no features.
    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    t.declare(cli, "getrandom", Kind::Normal, &[]);
    t.feature(cli, "web", &["getrandom?/wasm_js"]);
    assert_only(&t.run(), "ADR 0016 R2", "rizzy-cli", "only rizzy-wasm");
}

#[test]
fn r2_another_enabler_is_reported_while_rizzy_wasm_enables_it_too() {
    // Before, rizzy-wasm's own declaration switched the whole check off.
    let mut t = with_rizzy_wasm();
    let cli = t.id("rizzy-cli");
    t.declare(cli, "getrandom", Kind::Normal, &[]);
    t.feature(cli, "web", &["getrandom/wasm_js"]);
    assert_only(&t.run(), "ADR 0016 R2", "rizzy-cli", "only rizzy-wasm");
}

#[test]
fn r2_a_second_getrandom_is_not_masked_by_rizzy_wasm() {
    // rizzy-wasm enables `wasm_js` on getrandom 0.3.4; a dependency enables `js` on 0.2.
    let mut t = with_rizzy_wasm();
    let rand_core = t.id("rand_core");
    let old = t.external("getrandom", "0.2.15");
    t.edge(rand_core, old, &[Kind::Normal]);
    t.g.packages[old].features = vec!["js".to_owned()];
    let v = t.run();
    assert_fires(&v, "ADR 0016 R2", "getrandom 0.2.15", "has `js` enabled");
    assert!(
        v.iter().all(|x| x.krate != "getrandom 0.3.4"),
        "rizzy-wasm's own getrandom is allowed: {v:#?}"
    );
}

#[test]
fn r2_getrandom_02_js_counts_as_wasm_js() {
    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    t.declare(cli, "getrandom", Kind::Normal, &["js"]);
    assert_only(&t.run(), "ADR 0016 R2", "rizzy-cli", "`js`");

    let mut t = Tree::current();
    let getrandom = t.id("getrandom");
    t.g.packages[getrandom].features = vec!["std".to_owned(), "js".to_owned()];
    assert_only(
        &t.run(),
        "ADR 0016 R2",
        "getrandom 0.3.4",
        "not by rizzy-wasm",
    );
}

// ---- §3 internal edges, R4, R5 ------------------------------------------------------------

#[test]
fn dependencies_point_one_way() {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    let sync = t.id("rizzy-sync");
    t.edge(core, sync, &[Kind::Dev]);
    assert_only(
        &t.run(),
        "ADR 0016 §3",
        "rizzy-core",
        "dev-dependency on rizzy-sync",
    );
}

#[test]
fn nothing_depends_on_a_leaf() {
    let mut t = Tree::current();
    let sync = t.id("rizzy-sync");
    let cli = t.id("rizzy-cli");
    t.edge(sync, cli, &[Kind::Normal]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 §3", "rizzy-sync", "dependency on rizzy-cli");
}

#[test]
fn r4_domains_are_separate() {
    let mut t = Tree::current();
    let auth = t.member("rizzy-domain-auth");
    let vault = t.member("rizzy-domain-vault");
    let server = t.id("rizzy-server");
    t.edge(server, auth, &[Kind::Normal]);
    t.edge(server, vault, &[Kind::Normal]);
    t.edge(vault, auth, &[Kind::Dev]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R4", "rizzy-domain-vault", "rizzy-domain-auth");
    assert_fires(&v, "ADR 0016 R5", "rizzy-domain-vault", "only rizzy-server");
}

#[test]
fn r5_only_the_server_wires_domains_and_ingress() {
    let mut t = Tree::current();
    let ingress = t.member("rizzy-smtp-ingress");
    let cli = t.id("rizzy-cli");
    t.edge(cli, ingress, &[Kind::Normal]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R5", "rizzy-cli", "rizzy-smtp-ingress");
    assert_fires(&v, "ADR 0016 R6", "rizzy-cli", "rizzy-smtp-ingress");
}

#[test]
fn r5_sqlx_holders() {
    let mut t = Tree::current();
    let core = t.id("rizzy-core");
    t.declare(core, "sqlx", Kind::Dev, &[]);
    assert_only(
        &t.run(),
        "ADR 0016 R5",
        "rizzy-core",
        "dev-dependency `sqlx`",
    );

    let mut t = Tree::current();
    let storage = t.member("rizzy-storage");
    let server = t.id("rizzy-server");
    t.edge(server, storage, &[Kind::Normal]);
    t.declare(
        storage,
        "sqlx",
        Kind::Normal,
        &["postgres", "runtime-tokio"],
    );
    assert_eq!(t.run(), []);
}

#[test]
fn r5_client_leaf_crates_use_only_the_sqlite_driver() {
    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    t.declare(
        cli,
        "sqlx",
        Kind::Normal,
        &["sqlite", "runtime-tokio", "migrate"],
    );
    assert_eq!(t.run(), []);
    t.declare(cli, "sqlx", Kind::Normal, &["sqlite", "postgres"]);
    assert_only(&t.run(), "ADR 0016 R5", "rizzy-cli", "(postgres)");

    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    t.declare(cli, "sqlx-mysql", Kind::Normal, &[]);
    assert_only(&t.run(), "ADR 0016 R5", "rizzy-cli", "(sqlx-mysql)");
}

#[test]
fn r5_a_driver_through_the_features_table() {
    // Before the `[features]` table was read, this passed.
    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    t.declare(cli, "sqlx", Kind::Normal, &["sqlite"]);
    t.feature(cli, "default", &["server"]);
    t.feature(cli, "server", &["dep:sqlx", "sqlx/postgres"]);
    assert_only(&t.run(), "ADR 0016 R5", "rizzy-cli", "(postgres)");
}

// ---- R3: isolated ingress -----------------------------------------------------------------

#[test]
fn r3_ingress_has_no_route_to_the_database_even_in_tests() {
    let mut t = Tree::current();
    let ingress = t.member("rizzy-smtp-ingress");
    let storage = t.member("rizzy-storage");
    let server = t.id("rizzy-server");
    t.edge(server, ingress, &[Kind::Normal]);
    t.edge(server, storage, &[Kind::Normal]);
    t.edge(ingress, storage, &[Kind::Dev]);
    let v = t.run();
    assert_fires(
        &v,
        "ADR 0016 R3",
        "rizzy-smtp-ingress",
        "rizzy-smtp-ingress -> rizzy-storage",
    );
    assert_fires(&v, "ADR 0016 §3", "rizzy-smtp-ingress", "rizzy-storage");
}

#[test]
fn r3_sqlx_through_a_third_party_crate() {
    let mut t = Tree::current();
    let ingress = t.member("rizzy-smtp-ingress");
    let server = t.id("rizzy-server");
    t.edge(server, ingress, &[Kind::Normal]);
    let helper = t.external("mail-db-helper", "1.0.0");
    let sqlx = t.external("sqlx-core", "0.8.6");
    t.edge(ingress, helper, &[Kind::Normal]);
    t.edge(helper, sqlx, &[Kind::Normal]);
    assert_only(
        &t.run(),
        "ADR 0016 R3",
        "rizzy-smtp-ingress",
        "rizzy-smtp-ingress -> mail-db-helper -> sqlx-core",
    );
}

#[test]
fn r3_icon_proxy_handles_no_keys() {
    let mut t = Tree::current();
    let proxy = t.member("rizzy-icon-proxy");
    let server = t.id("rizzy-server");
    let core = t.id("rizzy-core");
    t.edge(server, proxy, &[Kind::Normal]);
    t.edge(proxy, core, &[Kind::Normal]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R3", "rizzy-icon-proxy", "rizzy-core");
}

// ---- R6: client and server ------------------------------------------------------------------

#[test]
fn r6_client_never_reaches_server() {
    let mut t = Tree::current();
    let bus = t.member("rizzy-bus");
    let cli = t.id("rizzy-cli");
    t.edge(cli, bus, &[Kind::Dev]);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R6", "rizzy-cli", "rizzy-cli -> rizzy-bus");
}

#[test]
fn r6_server_dev_dependency_on_client_is_the_one_exception() {
    let mut t = Tree::current();
    let client = t.member("rizzy-client");
    let import = t.member("rizzy-import");
    let server = t.id("rizzy-server");
    let core = t.id("rizzy-core");
    t.edge(client, import, &[Kind::Normal]);
    t.edge(client, core, &[Kind::Normal]);
    t.edge(import, core, &[Kind::Normal]);
    t.edge(server, client, &[Kind::Dev]);
    t.config = Manifest::parse(
        "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync -p rizzy-client \
         -p rizzy-import --target wasm32-unknown-unknown\"\n",
    );
    assert_eq!(t.run(), []);

    // As a normal dependency it is a violation of both the table and R6.
    t.edge(server, client, &[Kind::Normal]);
    let v = t.run();
    assert_fires(
        &v,
        "ADR 0016 §3",
        "rizzy-server",
        "dependency on rizzy-client",
    );
    assert_fires(
        &v,
        "ADR 0016 R6",
        "rizzy-server",
        "rizzy-server -> rizzy-client",
    );
}

#[test]
fn r6_the_exception_covers_rizzy_client_only() {
    let mut t = Tree::current();
    let matcher = t.member("rizzy-match");
    let server = t.id("rizzy-server");
    let core = t.id("rizzy-core");
    t.edge(matcher, core, &[Kind::Normal]);
    t.edge(server, matcher, &[Kind::Dev]);
    t.config = Manifest::parse(
        "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync -p rizzy-match \
         --target wasm32-unknown-unknown\"\n",
    );
    let v = t.run();
    assert_fires(&v, "ADR 0016 R6", "rizzy-server", "rizzy-match");
}

// ---- ADR 0009: openssl ----------------------------------------------------------------------

#[test]
fn openssl_only_where_webauthn_lives() {
    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    let server = t.id("rizzy-server");
    let tls = t.external("native-tls", "0.2.12");
    let openssl = t.external("openssl", "0.10.66");
    t.edge(server, openssl, &[Kind::Normal]);
    t.edge(cli, tls, &[Kind::Normal]);
    t.edge(tls, openssl, &[Kind::Normal]);
    assert_only(
        &t.run(),
        "ADR 0009 owner decision 1",
        "rizzy-cli",
        "rizzy-cli -> native-tls -> openssl",
    );
}

// ---- ADR 0024: rustix ---------------------------------------------------------------------

#[test]
fn rustix_is_declared_only_by_the_allowed_leaf_crates() {
    let mut t = Tree::current();
    let cli = t.id("rizzy-cli");
    let server = t.id("rizzy-server");
    let rustix = t.external("rustix", "1.1.5");
    t.edge(cli, rustix, &[Kind::Normal]);
    t.edge(server, rustix, &[Kind::Normal]);
    t.declare(cli, "rustix", Kind::Normal, &["process"]);
    t.declare(server, "rustix", Kind::Normal, &["process"]);
    assert_eq!(t.run(), []);

    let sync = t.id("rizzy-sync");
    t.declare(sync, "rustix", Kind::Dev, &["process"]);
    assert_fires(
        &t.run(),
        "ADR 0024 point 2",
        "rizzy-sync",
        "declares a dev-dependency `rustix`",
    );
    let xtask = t.id("xtask");
    t.declare(xtask, "rustix", Kind::Normal, &["process"]);
    assert_fires(
        &t.run(),
        "ADR 0024 point 2",
        "xtask",
        "only the leaf crates",
    );
}

#[test]
fn rustix_never_ships_in_another_member_through_a_third_party_crate() {
    let mut t = Tree::current();
    let xtask = t.id("xtask");
    let tempfile = t.external("tempfile", "3.20.0");
    let rustix = t.external("rustix", "1.1.5");
    t.edge(tempfile, rustix, &[Kind::Normal]);
    // A dev-only path does not ship.
    t.edge(xtask, tempfile, &[Kind::Dev]);
    assert_eq!(t.run(), []);
    t.edge(xtask, tempfile, &[Kind::Normal]);
    assert_only(
        &t.run(),
        "ADR 0024 point 2",
        "xtask",
        "xtask -> tempfile -> rustix",
    );
}

// ---- R7, R8, §1, §3, §5 -----------------------------------------------------------------------

#[test]
fn r8_publish_license_and_rust_version_are_inherited() {
    let mut t = Tree::current();
    t.manifests[0].1 = Manifest::parse(
        "[package]\nlicense = \"MIT\"\npublish.workspace = true\nrust-version = \"1.94\"\n\
         [lints]\nworkspace = true\n",
    );
    let v = t.run();
    assert_fires(&v, "ADR 0016 R8", "rizzy-core", "`license`");
    assert_fires(&v, "ADR 0016 R8", "rizzy-core", "`rust-version`");
    assert_eq!(v.len(), 2, "{v:#?}");
}

#[test]
fn r7_lints_are_inherited_and_nothing_else() {
    for lints in [
        "",
        "[lints]\nworkspace = false\n",
        "[lints]\nworkspace = true\n[lints.rust]\nunsafe_code = \"allow\"\n",
        "[lints.rust]\nunsafe_code = \"allow\"\n",
    ] {
        let mut t = Tree::current();
        t.manifests[1].1 = Manifest::parse(&format!(
            "[package]\nlicense.workspace = true\npublish.workspace = true\n\
             rust-version.workspace = true\n{lints}"
        ));
        assert_only(&t.run(), "ADR 0016 R7", "rizzy-sync", "workspace = true");
    }
    let mut t = Tree::current();
    // The inline form, which TOML allows only before the first table header.
    t.manifests[1].1 = Manifest::parse(
        "lints = { workspace = true }\n[package]\nlicense.workspace = true\n\
         publish.workspace = true\nrust-version.workspace = true\n",
    );
    assert_eq!(t.run(), []);
}

#[test]
fn r7_exception_copy_must_match_the_workspace_table() {
    let workspace = Manifest::parse(
        "[workspace.lints.rust]\nunsafe_code = \"forbid\"\nunreachable_pub = \"warn\"\n\
         [workspace.lints.clippy]\nall = { level = \"deny\", priority = -1 }\n",
    );
    let copy = Manifest::parse(
        "[lints.rust]\nunsafe_code = \"deny\"\nunreachable_pub = \"warn\"\n\
         [lints.clippy]\nall = {level=\"deny\", priority=-1}\n",
    );
    let mut out = Vec::new();
    lint_copy("rizzy-ffi", &copy, &workspace, &mut out);
    assert_eq!(out, []);
    let drifted =
        Manifest::parse("[lints.rust]\nunsafe_code = \"deny\"\n[lints.clippy]\nall = \"warn\"\n");
    lint_copy("rizzy-ffi", &drifted, &workspace, &mut out);
    assert_eq!(out.len(), 1);
}

#[test]
fn unreadable_manifests_fail_closed() {
    let mut t = Tree::current();
    t.manifests[0].1 = Manifest::parse(&format!("{GOOD_MANIFEST}what is this\n"));
    assert_only(&t.run(), "ADR 0016 R7/R8", "rizzy-core", "cannot read it");
}

#[test]
fn unknown_crates_and_misplaced_crates() {
    let mut t = Tree::current();
    t.member("rizzy-extra");
    assert_only(&t.run(), "ADR 0016 §3", "rizzy-extra", "rules table");

    let mut t = Tree::current();
    let sync = t.id("rizzy-sync");
    t.g.packages[sync].manifest_path = format!("{ROOT}/crates/sync/Cargo.toml");
    assert_only(
        &t.run(),
        "ADR 0016 §1",
        "rizzy-sync",
        "directory name = crate name",
    );
}

#[test]
fn check_wasm_covers_every_no_io_crate() {
    let mut t = Tree::current();
    t.config = Manifest::parse(
        "[alias]\ncheck-wasm = \"check -p rizzy-core --target wasm32-unknown-unknown\"\n",
    );
    assert_only(&t.run(), "ADR 0016 §5", "rizzy-sync", "check-wasm");

    let mut t = Tree::current();
    t.config = Manifest::parse("[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync\"\n");
    assert_only(
        &t.run(),
        "ADR 0016 §5",
        "workspace",
        "wasm32-unknown-unknown",
    );
}

#[test]
fn only_xtask_enables_openapi() {
    let mut t = Tree::current();
    let proto = t.member("rizzy-proto");
    let cli = t.id("rizzy-cli");
    let xtask = t.id("xtask");
    t.edge(xtask, proto, &[Kind::Normal]);
    t.declare(xtask, "rizzy-proto", Kind::Normal, &["openapi"]);
    t.config = Manifest::parse(
        "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync -p rizzy-proto \
         --target wasm32-unknown-unknown\"\n",
    );
    assert_eq!(t.run(), []);
    t.declare(cli, "rizzy-proto", Kind::Normal, &["openapi"]);
    assert_only(&t.run(), "ADR 0016 §3", "rizzy-cli", "only xtask");
}

#[test]
fn openapi_through_the_features_table() {
    // The review's bypass: `[features] x = ["rizzy-proto/openapi"]`, here on a renamed
    // dependency. Before the `[features]` table was read, this passed.
    let mut t = Tree::current();
    let proto = t.member("rizzy-proto");
    let client = t.member("rizzy-client");
    let core = t.id("rizzy-core");
    t.edge(client, core, &[Kind::Normal]);
    t.edge_named(client, proto, &[Kind::Normal], "proto");
    t.declare(client, "rizzy-proto", Kind::Normal, &[]);
    t.g.packages[client].declared[0].rename = Some("proto".to_owned());
    t.config = Manifest::parse(
        "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync -p rizzy-proto \
         -p rizzy-client --target wasm32-unknown-unknown\"\n",
    );
    assert_eq!(t.run(), []);
    t.feature(client, "docs", &["proto?/openapi"]);
    assert_only(&t.run(), "ADR 0016 §3", "rizzy-client", "only xtask");
}

// ---- R7, workspace side ---------------------------------------------------------------------

#[test]
fn r7_the_workspace_forbids_unsafe_code() {
    // Before, only the members' `[lints] workspace = true` was checked, never the table itself.
    for table in [
        "unsafe_code = \"deny\"\n",
        "unsafe_code = \"allow\"\n",
        "unsafe_code = \"warn\"\n",
        "unreachable_pub = \"warn\"\n",
        "unsafe_code = { level = \"deny\", priority = -1 }\n",
        "unsafe_code = { level = \"forbid\", level = \"allow\" }\n",
        "unsafe_code = { level = \"forbid\", reason = \"x\" }\n",
        "unsafe_code = [\"forbid\"]\n",
        "unsafe_code.level = \"forbid\"\n",
        "unsafe_code = \"forbid\"\nunsafe_code = \"allow\"\n",
    ] {
        let mut t = Tree::current();
        t.workspace_manifest = Manifest::parse(&format!("[workspace.lints.rust]\n{table}"));
        assert_only(
            &t.run(),
            "ADR 0016 R7",
            "workspace",
            "`unsafe_code = \"forbid\"`",
        );
    }
    let mut t = Tree::current();
    t.workspace_manifest = Manifest::parse("[workspace]\nmembers = [\"crates/*\"]\n");
    assert_only(
        &t.run(),
        "ADR 0016 R7",
        "workspace",
        "`unsafe_code = \"forbid\"`",
    );

    for table in [
        "unsafe_code = 'forbid'\n",
        "unsafe_code = { level = \"forbid\", priority = -1 }\n",
    ] {
        let mut t = Tree::current();
        t.workspace_manifest = Manifest::parse(&format!("[workspace.lints.rust]\n{table}"));
        assert_eq!(t.run(), [], "{table}");
    }
}

#[test]
fn r7_the_committed_workspace_manifest_passes() {
    let mut t = Tree::current();
    t.workspace_manifest = Manifest::parse(include_str!("../../../../Cargo.toml"));
    t.config = Manifest::parse(include_str!("../../../../.cargo/config.toml"));
    assert_eq!(t.run(), []);
}

/// The threat model's INV-57 ("CI builds use --locked"): every alias CI runs passes `--locked`.
/// Before, `cargo xtask` could rewrite a stale Cargo.lock before xtask's own `--locked` metadata
/// read.
#[test]
fn every_committed_alias_is_locked() {
    let config = Manifest::parse(include_str!("../../../../.cargo/config.toml"));
    let aliases: Vec<(&str, &str)> = config.under("alias").collect();
    assert_eq!(aliases.len(), 3, "{aliases:?}");
    for (alias, command) in aliases {
        let words: Vec<&str> = command.trim_matches('"').split_whitespace().collect();
        let args = words.split(|w| *w == "--").next().unwrap_or_default();
        assert!(args.contains(&"--locked"), "{alias} = {command}");
    }
}

#[test]
fn unreadable_workspace_files_fail_closed() {
    let mut t = Tree::current();
    t.workspace_manifest = Manifest::parse(&format!("{WORKSPACE_MANIFEST}what is this\n"));
    assert_only(&t.run(), "ADR 0016 R7", "workspace", "Cargo.toml line 5");

    let mut t = Tree::current();
    t.config = Manifest::parse(
        "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync --target \
         wasm32-unknown-unknown\"\nx = '''\n",
    );
    assert_only(
        &t.run(),
        "ADR 0016 §5",
        "workspace",
        ".cargo/config.toml line 3",
    );
}

#[test]
fn r7_a_crafted_manifest_cannot_hide_a_missing_lints_table() {
    // tooling#3: Cargo applies no lints to this crate; the old reader saw `[lints]` and passed.
    let mut t = Tree::current();
    t.manifests[1].1 = Manifest::parse(crate::manifest::HIDDEN_LINTS);
    let v = t.run();
    assert_fires(&v, "ADR 0016 R7/R8", "rizzy-sync", "multi-line string");
    assert_fires(&v, "ADR 0016 R7", "rizzy-sync", "workspace = true");
}

#[test]
fn r7_r8_quoted_keys_cannot_fake_inheritance() {
    // The review's second desynchronisation: Cargo reads `"lints.workspace"` as one unknown key
    // (a warning only), so this crate gets no workspace lints and `unsafe` compiles in it. The
    // old reader split on `.` first and saw `lints.workspace = true`.
    let mut t = Tree::current();
    t.manifests[1].1 = Manifest::parse(
        "\"lints.workspace\" = true\n[package]\nlicense.workspace = true\n\
         \"publish.workspace\" = true\nrust-version.workspace = true\n",
    );
    let v = t.run();
    assert_fires(
        &v,
        "ADR 0016 R7/R8",
        "rizzy-sync",
        "quoted keys are not read",
    );
    assert_fires(&v, "ADR 0016 R7", "rizzy-sync", "workspace = true");
    assert_fires(&v, "ADR 0016 R8", "rizzy-sync", "`publish`");
}

#[test]
fn r7_a_quoted_key_cannot_fake_the_workspace_unsafe_code_level() {
    // The same trick on the root manifest: the real `unsafe_code` entry removed, and a quoted
    // key that Cargo ignores put in its place.
    let mut t = Tree::current();
    t.workspace_manifest = Manifest::parse(
        "[workspace]\n\"lints.rust.unsafe_code\" = \"forbid\"\n\
         [workspace.lints.clippy]\nall = { level = \"deny\", priority = -1 }\n",
    );
    let v = t.run();
    assert_fires(&v, "ADR 0016 R7", "workspace", "quoted keys are not read");
    assert_fires(&v, "ADR 0016 R7", "workspace", "`unsafe_code = \"forbid\"`");
}

// ---- R1, API side: the clippy lists ---------------------------------------------------------

#[track_caller]
fn assert_clippy_config_fires(config: &str, needle: &str) {
    let mut t = Tree::current();
    t.clippy_configs[1].1 = Some(Manifest::parse(config));
    assert_only(&t.run(), "ADR 0016 §5", "rizzy-sync", needle);
}

#[test]
fn r1_every_no_io_crate_has_a_clippy_toml() {
    let mut t = Tree::current();
    assert_eq!(t.clippy_configs[1].0, "rizzy-sync");
    t.clippy_configs[1].1 = None;
    assert_only(&t.run(), "ADR 0016 §5", "rizzy-sync", "has no clippy.toml");

    // A new no-I/O crate needs one too.
    let mut t = Tree::current();
    t.member("rizzy-match");
    let last = t.clippy_configs.len() - 1;
    t.clippy_configs[last].1 = None;
    let v = t.run();
    assert_fires(&v, "ADR 0016 §5", "rizzy-match", "has no clippy.toml");
}

#[test]
fn r1_clippy_toml_repeats_the_root_keys_and_nothing_else() {
    let good = good_clippy();
    assert_clippy_config_fires(
        &good.replace("allow-unwrap-in-tests = true\n", ""),
        "`allow-unwrap-in-tests = true`",
    );
    assert_clippy_config_fires(
        &good.replace("msrv = \"1.94\"", "msrv = \"1.80\""),
        "`msrv = \"1.94\"`",
    );
    assert_clippy_config_fires(
        &format!("avoid-breaking-exported-api = false\n{good}"),
        "sets `avoid-breaking-exported-api`",
    );
}

#[test]
fn r1_clippy_lists_equal_the_adr_set() {
    let good = good_clippy();
    assert_clippy_config_fires(
        &good.replace("  \"std::fs::read\",\n", ""),
        "missing [std::fs::read]",
    );
    assert_clippy_config_fires(
        &good.replace(
            "  { path = \"std::time::Instant::now\", reason = \"R1, a, b\" },\n",
            "",
        ),
        "missing [std::time::Instant::now]",
    );
    // A module path: clippy would ignore it ("found a module").
    assert_clippy_config_fires(
        &good.replace(
            "disallowed-methods = [\n",
            "disallowed-methods = [\n  \"std::fs\",\n",
        ),
        "not in the ADR [std::fs]",
    );
    assert_clippy_config_fires(
        &good.replace(
            "disallowed-methods = [\n",
            "disallowed-methods = [\n  \"std::fs::write\",\n",
        ),
        "once each",
    );
    assert_clippy_config_fires(
        &good.replace(
            "{ path = \"std::fs::write\", reason = \"R1, a, b\" }",
            "{ path = \"std::fs::write\", allow-invalid = true }",
        ),
        "sets `allow-invalid`",
    );
    assert_clippy_config_fires(
        &good.replace(
            "{ path = \"std::fs::write\", reason = \"R1, a, b\" }",
            "{ reason = \"no path\" }",
        ),
        "exactly one string `path`",
    );
    let only_methods = format!(
        "{ROOT_CLIPPY}disallowed-methods{}",
        good.split("disallowed-methods").nth(1).unwrap_or_default()
    );
    assert_clippy_config_fires(&only_methods, "`disallowed-types` must list");
    assert_clippy_config_fires(
        &good.replace(
            "disallowed-types = [",
            "disallowed-types = \"std::fs::File\"\n#[",
        ),
        "expected an array",
    );
}

#[test]
fn r1_root_clippy_lists_are_repeated_too() {
    let mut t = Tree::current();
    t.root_clippy = Manifest::parse(&format!(
        "{ROOT_CLIPPY}disallowed-methods = [\"std::io::stdin\"]\n"
    ));
    let v = t.run();
    assert_fires(&v, "ADR 0016 §5", "rizzy-core", "missing [std::io::stdin]");
    assert_fires(&v, "ADR 0016 §5", "rizzy-sync", "missing [std::io::stdin]");
}

#[test]
fn r1_clippy_toml_cannot_be_replaced() {
    let mut t = Tree::current();
    t.hidden_clippy_configs = vec!["/ws/crates/rizzy-core/.clippy.toml".to_owned()];
    assert_only(&t.run(), "ADR 0016 §5", "workspace", ".clippy.toml exists");

    let mut t = Tree::current();
    t.config = Manifest::parse(&format!(
        "{}[env]\nCLIPPY_CONF_DIR = {{ value = \"x\", relative = true }}\n",
        "[alias]\ncheck-wasm = \"check -p rizzy-core -p rizzy-sync --target \
         wasm32-unknown-unknown\"\n"
    ));
    assert_only(&t.run(), "ADR 0016 §5", "workspace", "env.CLIPPY_CONF_DIR");

    let mut t = Tree::current();
    t.config = Manifest::parse(
        "env = { CLIPPY_CONF_DIR = \"x\" }\n[alias]\ncheck-wasm = \"check -p rizzy-core -p \
         rizzy-sync --target wasm32-unknown-unknown\"\n",
    );
    assert_only(&t.run(), "ADR 0016 §5", "workspace", "sets `env`");
}

#[test]
fn r1_the_committed_clippy_files_pass() {
    let mut t = Tree::current();
    t.root_clippy = Manifest::parse(include_str!("../../../../clippy.toml"));
    t.clippy_configs = vec![
        (
            "rizzy-core".to_owned(),
            Some(Manifest::parse(include_str!(
                "../../../rizzy-core/clippy.toml"
            ))),
        ),
        (
            "rizzy-sync".to_owned(),
            Some(Manifest::parse(include_str!(
                "../../../rizzy-sync/clippy.toml"
            ))),
        ),
    ];
    assert_eq!(t.run(), []);
}

/// Clippy 1.94.1's output for a crate-level clippy.toml with a module path, an unreachable
/// path and a type in the methods list, followed by an ordinary lint (trimmed).
const CLIPPY_OUTPUT: &str = "\
    Checking rizzy-sync v0.0.0 (/ws/crates/rizzy-sync)
warning: expected a function, found a module
  --> /ws/crates/rizzy-sync/clippy.toml:11:3
   |
11 |   { path = \"std::fs\", reason = \"test\" },
   |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: add `allow-invalid = true` to the entry to suppress this warning

warning: `std::env::nope` does not refer to a reachable function
  --> C:\\ws\\crates\\rizzy-sync\\clippy.toml:12:3
   |
12 |   \"std::env::nope\",
   |   ^^^^^^^^^^^^^^^^

warning: expected a type, found a module
warning: use of a disallowed method `std::fs::read`
  --> crates/rizzy-core/src/lib.rs:74:5
   |
74 |     std::fs::read(\"x\")
warning: `rizzy-sync` (lib) generated 3 warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.09s
";

#[test]
fn clippy_output_with_config_warnings_fails() {
    assert_eq!(
        clippy_config_warnings(CLIPPY_OUTPUT),
        [
            "warning: `std::env::nope` does not refer to a reachable function (at \
             C:\\ws\\crates\\rizzy-sync\\clippy.toml:12:3)",
            "warning: expected a function, found a module (at \
             /ws/crates/rizzy-sync/clippy.toml:11:3)",
            "warning: expected a type, found a module",
        ]
    );
    let clean = "    Checking rizzy-core v0.0.0 (/ws/crates/rizzy-core)\n\
                 warning: use of a disallowed method `std::fs::read`\n  \
                 --> crates/rizzy-core/src/lib.rs:74:5\n\
                 note: see clippy.toml:3 for the list\n    Finished `dev` profile\n";
    assert_eq!(clippy_config_warnings(clean), Vec::<String>::new());
}

// ---- ADR 0019 §4.1: the first-party `unsafe` token scan ------------------------------------

#[test]
fn unsafe_token_in_first_party_source_fails() {
    let mut t = Tree::current();
    t.rust_sources.push((
        "crates/rizzy-cli/src/ffi.rs".to_owned(),
        "// no unsafe here\n#[unsafe(no_mangle)]\npub extern \"C\" fn f() {}\n".to_owned(),
    ));
    assert_only(
        &t.run(),
        "ADR 0019 §4.1",
        "crates/rizzy-cli/src/ffi.rs",
        "line 2, column 3: the `unsafe` keyword",
    );

    // In a macro's input, where `forbid(unsafe_code)` can miss it (ADR 0019, Context).
    let mut t = Tree::current();
    t.rust_sources.push((
        "fuzz/fuzz_targets/x.rs".to_owned(),
        "bridge! { unsafe extern \"C++\" { fn g(); } }\n".to_owned(),
    ));
    assert_only(
        &t.run(),
        "ADR 0019 §4.1",
        "fuzz/fuzz_targets/x.rs",
        "line 1, column 11",
    );
}

#[test]
fn unsafe_in_comments_strings_and_other_words_passes() {
    let mut t = Tree::current();
    t.rust_sources.push((
        "crates/rizzy-core/src/x.rs".to_owned(),
        "#![forbid(unsafe_code)]\n/// No `unsafe`.\nconst S: &str = r#\"unsafe {\"#;\n\
         fn r#unsafe() {}\n"
            .to_owned(),
    ));
    assert_eq!(t.run(), []);
}

#[test]
fn unsafe_scan_fails_closed_on_an_unterminated_literal() {
    let mut t = Tree::current();
    t.rust_sources.push((
        "crates/rizzy-sync/src/x.rs".to_owned(),
        "const S: &str = \"\\\";\nunsafe fn f() {}\n".to_owned(),
    ));
    assert_only(
        &t.run(),
        "ADR 0019 §4.1",
        "crates/rizzy-sync/src/x.rs",
        "unterminated string literal at line 1, column 17; the rest of the file cannot be scanned",
    );
}
