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
}

const GOOD_MANIFEST: &str = "[package]\nname = \"x\"\nlicense.workspace = true\n\
    publish.workspace = true\nrust-version.workspace = true\n[lints]\nworkspace = true\n";

impl Tree {
    /// The current workspace in miniature: rizzy-core with part of its real closure, rizzy-sync,
    /// rizzy-server, rizzy-cli and xtask.
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
        });
        self.manifests
            .push((name.to_owned(), Manifest::parse(GOOD_MANIFEST)));
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
        })
    }

    fn push(&mut self, p: Package) -> usize {
        self.g.packages.push(p);
        self.g.packages.len() - 1
    }

    fn edge(&mut self, from: usize, to: usize, kinds: &[Kind]) {
        self.g.packages[from].deps.push(Edge {
            to,
            kinds: kinds.to_vec(),
        });
    }

    fn declare(&mut self, from: usize, name: &str, kind: Kind, features: &[&str]) {
        self.g.packages[from].declared.push(Declared {
            name: name.to_owned(),
            kind,
            features: features.iter().map(|f| (*f).to_owned()).collect(),
            default_features: false,
        });
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
            workspace_manifest: Manifest::parse(
                "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n\
                 [workspace.lints.clippy]\nall = { level = \"deny\", priority = -1 }\n",
            ),
            cargo_config: self.config.clone(),
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
    });
    let gr = wasm.packages.len() - 1;
    wasm.packages[rand_core].deps.push(Edge {
        to: gr,
        kinds: vec![Kind::Normal],
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

#[test]
fn r2_rizzy_wasm_may_enable_wasm_js() {
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
    assert_eq!(t.run(), []);
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
