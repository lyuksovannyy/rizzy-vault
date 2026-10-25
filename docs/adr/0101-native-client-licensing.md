# ADR 0101: Native-client repository licensing: AGPL-3.0-only with two §7 permissions, store channels, the Windows App SDK, Qt LGPLv3, DCO and licence gates in the client repositories

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (must be Accepted before the first commit to any client repository; the legal review of ADR 0017 owner decision 5, as replaced by §10, before the first external code contribution to any repository and before the first submission to a channel of §6 that needs Part A)

## Context

**Trigger.** The 2026-10-25 ADR gap review ([summary](../reviews/2026-10-25-adr-gap-review.md), finding M3; raw findings G02-6, G03-1 and G10-27 in [docs/reviews/2026-10-25-raw/](../reviews/2026-10-25-raw/)) found that the licensing ADR two Accepted ADRs defer to does not exist. The owner said "start" on 2026-10-25, after the review.

**Evidence (V, read in this tree on 2026-10-25):**

- [ADR 0017](0017-licensing.md) (Accepted 2026-09-27; Partially superseded by ADR 0073 (§7 in part)), after its owner decisions: "Not covered by these answers: the licensing items [ADR 0019](0019-native-clients.md) §15 lists for the native-client repositories."
- [ADR 0019](0019-native-clients.md) (Accepted) §15: "A new ADR that partially supersedes it must decide or update:", followed by eleven items. Its "On acceptance" list: "A new ADR that partially supersedes ADR 0017: the §15 items." G10-27 records that it "was never written".
- G02-6 [major]: the deferred items "have no ADR, while M3 native-client work needs them"; "ADR 0017 §3's timing rule ("before the first external code contribution") applies to that repository too".
- G03-1 [major] quotes ADR 0019 §15 item 7, "The Swift gate (macOS), a NuGet gate (Windows) and a C++/Qt module gate (Linux) are needed from the first M3 release of each client.", and notes that §9's publish-together policy waits "for ADR 0017's legal review (U)".
- ADR 0019 §2 makes channels and toolkits conditional on this ADR: macOS, "Mac App Store only if ADR 0017 allows it (§15 item 3)"; Windows, "the Microsoft Store, which signs submissions (V), if ADR 0017 allows it (§15 item 3)"; Linux, "LGPLv3 modules only, linked dynamically, subject to ADR 0017 granting the Qt exception (§15 item 5)"; Android, "Google Play, subject to ADR 0017 (§15 item 9)".
- ADR 0017 §5 bans third-party LGPL: "third-party copyleft is not covered by the Decision 3 permission or by a CLA. Only the holder of that code can grant either, so one such crate in a client build blocks App Store distribution (M7) and any later relicensing. License compatibility is not the reason". Owner decision 6 admits a copyleft exception "only if it is never reachable from an app-store client build".
- ADR 0017 §3: the App Store permission "must be in place before the first external code contribution is merged"; "Adding it after external code has landed needs every code contributor's consent"; "The text is drafted and reviewed by a lawyer before it is committed." The text is not committed yet (ADR 0017 owner decisions, "Not done yet"; [README](../../README.md) M0 row: "its App Store permission text is not done yet").
- ADR 0019 §6: client repositories hold no Rust ("No `Cargo.toml`, `.rs` or `build.rs`"), "consume only released core artifacts (§7)", and get "a licence and DCO/sign-off policy as ADR 0017 decides (§15 items 1–2)"; "A repository is created when real code goes into it". None of the four exists yet (U: not checked on GitHub; nothing in this tree refers to one as existing).

**The window is still open (V, `git log` of this tree, 2026-10-25).** Commit authors are `lyuksovannyy` (two addresses), `Agent <agent@rizzy.dev>` and `Claude <noreply@anthropic.com>`; the last two are AI coding agents working for the owner. No other human author appears. So the owner can still choose any terms for this repository and, since they do not exist yet, for the client repositories. Whether AI-generated code carries copyright, and for whom, is U; it does not change the owner's freedom here.

**Licence facts this ADR relies on.**

- AGPL-3.0 (V, [LICENSE](../../LICENSE)): "System Libraries" are anything that "(a) is included in the normal form of packaging a Major Component, but which is not part of that Major Component, and (b) serves only to enable use of the work with that Major Component, or to implement a Standard Interface"; a "Major Component" is "a major essential component (kernel, window system, and so on) of the specific operating system". Corresponding Source "does not include the work's System Libraries" but includes "the source code for shared libraries and dynamically linked subprograms that the work is specifically designed to require". §7: additional permissions on the whole program "shall be treated as though they were included in this License"; a recipient may "remove any additional permissions from that copy". §10 forbids further restrictions and §12 then says one "may not convey it at all" (as quoted in ADR 0017).
- That Apple's App Store usage rules are §10 "further restrictions" (the FSF's reading), and the VLC removal of 2011: U (ADR 0017 Context; not re-read).
- The Mac App Store is under the same Apple developer agreement and Standard EULA as the iOS App Store: L (secondary sources, not read at the source this session). Apple lets the provider supply its own licence instead of the Standard EULA: V (ADR 0019 §15 item 3). Whether an AGPL custom EULA settles §10: U.
- Microsoft Store policies have no open-source-specific rule: L (ADR 0019 §15 item 3). Whether a submitter may supply its own licence terms in place of Microsoft's standard application licence terms: U.
- Google Play's agreement prevails over the developer's EULA: U (ADR 0019 §15 item 9). F-Droid builds from source: V (ADR 0019 §7).
- Windows App SDK: the NuGet package is under Microsoft Software License Terms (MSLT), unlike the MIT GitHub repository; they require distributors to bind end users to terms that protect Microsoft, to indemnify Microsoft, and not to make the SDK subject to a source-disclosure licence (V, ADR 0019 §15 item 4). Whether its runtime is in the normal form of packaging Windows, and so could be a System Library: U. Our working reading is that it ships as a separate framework package and is not one (U).
- Qt: modules are offered under LGPLv3, and 14 modules are GPL-only, including Qml Compiler, Quick Timeline and Virtual Keyboard (V, ADR 0019 §2 Linux row). Qt's tools are GPLv3 with the Qt exception (V, ADR 0019 §15 item 5). Qt warns that "online application stores may have rules that are in conflict with LGPL" (V, ADR 0019 §15 item 5). That conveying a bundled copy of Qt's object code needs Qt's source under LGPLv3 §4 and GPLv3 §6: L (our reading, as ADR 0019 §2). That open-source Qt is offered as LGPL-3.0-only or GPL-2.0-only or GPL-3.0-only for the LGPL modules: U.
- MPL-2.0 (e.g. `uniffi`, ADR 0017 §5) §3.2 lets the Executable Form be licensed under different terms if they do not limit recipients' rights in the Source Code Form: U (our reading, licence not re-read this session). JNA on its Apache-2.0 option: V (ADR 0019 §2 Android row). Sparkle is MIT: L (ADR 0019 §15 item 6). The licence of code generated from MPL-2.0 templates: U (ADR 0019 §15 item 6).
- SPDX: whether SPDX 3 `AdditionRef-` expressions suit a custom addition, and how scanners handle them: U.
- A §7 additional permission that lets a GPL or AGPL program be combined with named non-free libraries (a "linking exception") is the usual remedy for a non-free platform library: L (FSF FAQ, not re-read this session).

**Constraints.**

- Every client build is a combined work containing the AGPL core (ADR 0017 Context, "The core decides the client license question"; ADR 0019 §15 item 1). A client licence cannot remove a store conflict; only every copyright holder's permission can.
- A permission can be widened later only with every contributor's consent, and any downstream recipient can narrow it (§7). The scope chosen now is the widest the project will ever have for community code.
- ADR 0017 owner decision 4: M10 stays all-AGPL and community code is never sold under other terms. Relicensing is not a goal this ADR protects.
- This ADR is not legal advice. Every legal judgement in it is our reading, tagged U or L, and is on the paid review's list (§9).

## Decision

### 1. One licence for every repository

- Each client repository (`rizzy-vault-apple`, `rizzy-vault-android`, `rizzy-vault-windows`, `rizzy-vault-linux`) is licensed **AGPL-3.0-only**, as this repository is (ADR 0017 Decision 2), plus the additional permissions of §2 once their reviewed text is committed.
- **Why AGPL, not a permissive or GPL client licence.**
  - Compatibility does not force AGPL: MIT, Apache-2.0 (in one direction) and MPL-2.0 client code could be combined with the AGPL core, and GPL-3.0 combines with AGPL through §13 (V, LICENSE §13). But a distributed client is conveyed as a whole under AGPL §5(c) anyway, so a separate client licence gives the recipients of the app nothing. It would only let a third party pair our UI with another, possibly closed, core, which the project does not want (ADR 0017 owner decision 4), and it would double the compliance story (ADR 0017 Decision 1, second bullet).
  - A permissive client licence would not remove the store conflict: the core's holders must grant Part A regardless.
  - GPL-3.0 for the clients changes nothing for the combined work (the core's §13 terms stay) and would need its own wording of the permissions.
- **Files in each client repository's first commit:** `LICENSE` (the verbatim AGPL v3 text, byte-identical to this repository's `LICENSE`); `README.md` with a "License" section in the form of this repository's; `CONTRIBUTING.md` with the "Sign-off" section of §3; `rizzy-core.pin` (§3.1); `licensing/client-allow.toml` (§5.2); `ADDITIONAL-PERMISSIONS.txt` (§2) as soon as the reviewed text exists in this repository. Until then the client repository merges no external code PR (§2.4).
- **Per-file headers** are `AGPL-3.0-only` (§7). The permissions are stated at repository level (§2.3).

### 2. The additional-permissions file (Parts A and B)

#### 2.1 One file, one version, in every repository

- **Path:** `ADDITIONAL-PERMISSIONS.txt` at the repository root; UTF-8, LF line endings, no byte-order mark.
- **Format, version 1.** Line 1 is exactly `rizzy-vault additional permissions under GNU AGPL version 3 section 7, version 1`. Line 2 is empty. Then the reviewed text, in two headed parts, `Part A. Distribution platforms` and `Part B. Platform libraries`, and a closing paragraph naming the five repositories it applies to. Nothing else is in the file.
- **Canonical copy:** this repository's. Each client repository holds a byte-identical copy. Every repository's README "License" section names the file, its version and its SHA-256.
- **Shipped in every core artifact.** Every artifact of ADR 0019 §7 gains a top-level directory `licensing/` with `ADDITIONAL-PERMISSIONS.txt` and `client-allow.toml` copied from the tagged tree. This adds files to the artifacts; how a client pins them (ADR 0019 §7, column "How the client pins it") does not change.
- **Client CI job `licensing-files`:** the client's `ADDITIONAL-PERMISSIONS.txt` and `licensing/client-allow.toml` must be byte-identical to the copies inside the pinned core artifact; otherwise it fails with `LIC-010` (§5.3).
- **A new version** (line 1 ending `version 2`) is a new ADR. It covers only code whose holders agree to it; until every holder of a repository's code has agreed, that repository keeps the old version. Version 1 therefore has to be right.

#### 2.2 Required elements (the lawyer writes the wording; the elements are decided here)

**Part A, distribution platforms.** Granted for the repository's whole program and for that program combined with the programs of the other four repositories:

- **A1.** Permission to convey the covered work in object code form through a *Distribution Platform*: a service run by a third party that conveys software to recipients under its own terms, which add restrictions on the recipients' use, copying or redistribution beyond those of the AGPL. The text names, as non-exhaustive examples, the Apple App Store (iOS and iPadOS), the Mac App Store, TestFlight, the Microsoft Store and Google Play.
- **A2.** Condition: the Corresponding Source of the exact build conveyed is available under the AGPL plus these permissions, at no charge, from a public URL named in the platform listing or the app's About screen, from the moment the build is first available on the platform until at least three years after it was last available there.
- **A3.** Condition: the conveyor adds no restriction beyond what the platform itself imposes, and anyone may build the same source and convey it under the AGPL outside the platform.
- **A4.** Where a platform requires its own code signing, AGPL §6 Installation Information is met by the Corresponding Source plus build and install instructions that let a recipient build and install the work on that platform with their own signing credentials; the conveyor's signing keys and platform account credentials are not Installation Information (U, review item R3).
- **A5.** Part A covers no third-party code in the build. Such code needs its own licence to allow the platform (§4, §5).

**Part B, platform libraries.**

- **B1.** Permission to combine the work with, and convey it together with, a *Platform Library*: a library published by the vendor of an operating system the work targets (Apple, Google, Microsoft), as part of that vendor's official SDK or runtime for building native applications for that operating system, used unmodified, under the vendor's licence terms.
- **B2.** The work's Corresponding Source need not include a Platform Library's source, and the vendor's terms on the Platform Library itself are not further restrictions under AGPL §10 for conveying the combination.
- **B3.** Part B covers no other non-free code. Each Platform Library in use is listed in `client-allow.toml` as an exception of kind `platform-library` (§5.2), so the set in use is reviewed and visible; the list neither narrows nor widens B1.

**Why both parts are in every repository, the core included.** A store app contains the core's code, so the core's holders must grant Part A. The Windows app combines the core with the Windows App SDK, so the core's holders must grant Part B too. One identical file means no holder grants less than the combined work needs.

**Kept from ADR 0017 §3, unchanged:** the permissions spread through inbound = outbound DCO contributions ("How it spreads."); a downstream recipient may remove them, and we do not merge code from a fork that removed them ("Downstream."); the text is drafted and reviewed by a lawyer before it is committed ("Wording.").

#### 2.3 Where the permissions are stated

- In the permission file; in each repository's README "License" section (one sentence naming the file, its version and SHA-256); in the notices file and licences screen of every artifact (§8.2).
- Per-file SPDX headers stay `AGPL-3.0-only`. If the legal review (§9, R8) requires a per-file notice or an SPDX `WITH` or `AdditionRef-` expression, that is a new ADR, not a header edit.

#### 2.4 Timing

- The file is committed in this repository, and in every client repository that exists at the time, before the first external code contribution to **any** of the five repositories is merged. A client repository created later carries it in its first commit.
- Until then, every repository merges external documentation PRs only (ADR 0017 §3 "Timing.", extended to all five).
- No build is submitted to a Distribution Platform until the file is committed in this repository and in that client's repository, and the legal review (§9) has covered that platform.

### 3. DCO 1.1 and the sign-off check in every client repository

- **Same terms.** Contributions to a client repository come in under its licence (inbound = outbound) with a DCO 1.1 `Signed-off-by:` trailer on every commit, as ADR 0017 Decision 4 decides for this repository. No CLA.
- **The check is this repository's `cargo xtask check-signoff`**, run unchanged against the client repository, never reimplemented. Two implementations of its matching rules (author name exact, email case-insensitive, merge commits included; `crates/xtask/src/signoff.rs`, V) would drift.
  - Client CI checks out `rizzy-vault` at the commit in the client's `rizzy-core.pin` (§3.1), into a directory outside the client tree (`$RUNNER_TEMP/rizzy-vault`), installs the toolchain of that commit's `rust-toolchain.toml`, and runs `cargo xtask check-signoff --repo <client checkout> <base>..<head>` on pull requests and the squash-commit mode on `main`. No Rust enters the client repository (ADR 0019 §6); the "no Rust" check scans only the client tree.
  - `--repo <path>` is new (implementation step 2): it runs the same `git` commands with `-C <path>`. Without it, behaviour is unchanged.
- **Repository settings (owner action, per client repository, as ADR 0017 §4 for this one):** squash default "Pull request title and commit details" (`PR_TITLE`, `COMMIT_MESSAGES`); merge commits and rebase merging disabled; "Require contributors to sign off on web-based commits" enabled.
- **AI agents never sign off.** Each client repository's `CONTRIBUTING.md` "Sign-off" section, and its agent-instructions file if it has one, say: AI coding agents never add `Signed-off-by`; the human who opens the PR adds it after review; AI assistance is marked with a `Co-Authored-By:` trailer.

#### 3.1 `rizzy-core.pin` (format version 1)

Each client repository has one TOML file at its root naming the core release it consumes:

~~~toml
format = "rizzy-core-pin/1"
tag = "v0.3.0"                                          # the signed core tag (ADR 0019 §7)
commit = "0123456789abcdef0123456789abcdef01234567"    # 40 lowercase hex
~~~

- Unknown keys, a missing key, another `format`, or a `commit` that is not 40 lowercase hex fail with `LIC-011`.
- CI checks that `tag` resolves to `commit` in `rizzy-vault`, and that every artifact URL pinned through ADR 0019 §7's mechanism names the same `tag`; a mismatch fails with `LIC-012`. Checksums stay where ADR 0019 §7 puts them; this file does not repeat them.

### 4. Third-party code in the client apps, and how the Rust core is linked

#### 4.1 The Rust core

Every client links the core only through the attested artifacts of ADR 0019 §7 (XCFramework, AAR, nupkg, C++ tarball), or through its build-from-source path with the same tag, flags and lockfile.

- **Static or dynamic linking of the core is not a licensing question.** The core's crate graph holds our own AGPL code plus licences on the ADR 0017 §5 allow-list (permissive and MPL-2.0); `cargo deny` keeps GPL, LGPL and third-party AGPL out (ADR 0017 owner decision 6). AGPL treats the combination as one work however it is linked, and no LGPL relinking duty arises, because no LGPL crate is in the graph. MPL-2.0 is file-level: the uniffi runtime's source is in the core's source archive (ADR 0017 §7), and its Executable Form may ship under store terms (MPL-2.0 §3.2; U, our reading). The linkage form (a static library in the XCFramework; a `cdylib` in the AAR, the nupkg and the C++ tarball) is ADR 0019's technical choice, settled by its spikes.
- **Generated glue** (Swift and Kotlin from UniFFI, C# from uniffi-bindgen-cs, C++ from Diplomat) is treated as covered by its generator's template licence where that is MPL-2.0 (the conservative reading; U, review item R9). It ships as source in the attested artifact (ADR 0019 §7), so it is in the Corresponding Source anyway, and the notices file lists it under the template's licence.
- None of this depends on the owner being the copyright holder: once Part A is committed, the same rules let a third party convey a store build.

#### 4.2 Per client

| Client | Third-party code and its basis | Store basis |
|---|---|---|
| macOS, iOS (`rizzy-vault-apple`) | Apple SDK frameworks: System Libraries, as they ship with the OS (L, our reading); Part B covers any that is not. Swift packages: the allow-list (§5). Sparkle (MIT, L) only in the Developer ID build, never in a store build, which the store updates | Part A, plus a custom EULA (§6.1) |
| Android (`rizzy-vault-android`) | The Android framework: a System Library (L). AndroidX and Kotlin libraries: the allow-list (Apache-2.0, L). JNA on its Apache-2.0 option (V), recorded as an election. Google Play Services and any other proprietary Google library: forbidden | Part A for Google Play; none for F-Droid and APKs |
| Windows (`rizzy-vault-windows`) | The Windows App SDK and WinUI 3 from NuGet under the MSLT: Part B, with `platform-library` exception entries (§5.2). .NET runtime and C#/WinRT projection packages: the allow-list (MIT, L) | Part A for the Microsoft Store; none for direct MSIX or unpackaged builds |
| Linux (`rizzy-vault-linux`) | Qt LGPLv3 modules under §4.3 | No Distribution Platform in §6 |

#### 4.3 Qt (Linux only): the LGPLv3 exception and its conditions

ADR 0017 §5 bans third-party LGPL because the project cannot grant Part A for it, which would block store distribution and any later relicensing. Neither reason applies to the Linux client: no Linux channel in §6 is a Distribution Platform, and relicensing is not a goal (ADR 0017 owner decision 4). LGPLv3 itself allows combination with an AGPL work (ADR 0017 §5, "License compatibility is not the reason"). So Qt is admitted, on all of these conditions:

1. **Scope.** `rizzy-vault-linux` only. No other repository and no Rust crate depends on Qt; `rizzy-ffi-cpp` never links Qt.
2. **Licence option.** Qt is used under LGPL-3.0-only. GPL-2.0-only is incompatible with AGPLv3 and is never chosen.
3. **Modules.** Only the modules listed in `client-allow.toml` (§5.2) with ecosystem `qt`. The initial list: Qt Core, Qt GUI, Qt DBus, Qt QML, Qt Quick, Qt Quick Controls (Basic style), Qt SVG, and the Wayland client and xcb platform plugins. That each is available under LGPLv3: L (to be read at Qt's licensing pages, V, in the implementation PR). None of the 14 GPL-only modules. Adding a module is an amendment that adds one exception entry.
4. **Dynamic linking only**, against unmodified upstream Qt. Static Qt fails the gate (`LIC-007`). A patched Qt needs a new ADR.
5. **A bundled Qt carries Qt's source.** Any artifact that contains Qt binaries (an AppImage, or a `.deb` that bundles Qt) has the exact upstream Qt source tarballs used, with their SHA-256 and Qt's configure options, in its source archive (§8.1). An artifact that uses the system's Qt (a `.deb` depending on distribution Qt packages) or the Flatpak runtime's Qt does not.
6. **Notices.** The About dialog says the app uses Qt under the LGPLv3 and links to the licences screen, which carries the LGPLv3 and GPLv3 texts and Qt's copyright notices (LGPLv3 §4(a)–(c); L, our reading).
7. **Replaceability.** The Linux README explains how to run the app against another Qt build (`--appimage-extract` and `LD_LIBRARY_PATH`, or the system Qt for the `.deb`). Whether this and condition 5 meet LGPLv3 §4(d) and (e) for a bundled copy: L, review item R6.
8. **Qt's build tools** (moc, rcc, qmlcachegen; GPLv3 with the Qt exception, V) run only at build time and never ship. The commercial Qt Quick Compiler is not used.

#### 4.4 The Windows App SDK and its MSLT

- **Reasoning.** If the Windows App SDK is not a System Library (U; we assume it is not), plain AGPL would require its source in the Corresponding Source, which we cannot provide, and the MSLT's end-user terms may be further restrictions (U). Part B removes both problems for our code, by permission of our own holders: the SDK is outside the Corresponding Source, and its terms bind only the SDK. The MSLT's term "not to make the SDK subject to a source-disclosure licence" is then met, because Part B excludes it from AGPL's source duty (U, review item R4).
- **What stays with the owner:** a distributor's MSLT duties (binding end users to terms that protect Microsoft, and indemnifying Microsoft; V via ADR 0019 §15 item 4) fall on whoever distributes the Windows app. That is business and legal risk for the owner personally (open question 4).
- The NuGet gate admits the SDK packages only as `platform-library` exceptions with the SHA-256 of the MSLT text recorded (§5.2). A changed licence text fails with `LIC-004` and needs a new review before the bump ships.

### 5. Licence gates in the client repositories

#### 5.1 When and what

| Repository | Ecosystem key | Input | Required from |
|---|---|---|---|
| `rizzy-vault-apple` | `swiftpm` | `Package.resolved` | The first macOS release (M3) |
| `rizzy-vault-android` | `gradle` | The resolved runtime classpath of the release variant, with `gradle/verification-metadata.xml` | The first Android release (M7) |
| `rizzy-vault-windows` | `nuget` | `packages.lock.json` in locked mode (ADR 0019 §7) | The first Windows release (M3) |
| `rizzy-vault-linux` | `cmake`, `qt` | The CMake `FetchContent` and `ExternalProject` declarations with `URL_HASH`; the Qt modules the build links, from `find_package(Qt6 COMPONENTS ...)` | The first Linux release (M3) |

- Each gate runs on every pull request and in the release job. The release job fails unless the gate exits 0 on the exact release commit.
- The core artifacts are not inputs: their Rust graph is gated by `cargo deny` in this repository, and their notices file is merged as is (§8.2).
- The tool per ecosystem is chosen in each client's first implementation PR, with the justification CLAUDE.md requires for a new dependency (U: no tool evaluated). The contract below binds whatever tool is chosen; a thin wrapper may adapt its output.

#### 5.2 `client-allow.toml` (format version 1)

The allow-list and every client exception are one file in this repository, `licensing/client-allow.toml`, copied into every core artifact and byte-identical in each client repository (§2.1):

~~~toml
format = "rizzy-client-allowlist/1"
# Must equal deny.toml [licenses] allow, as a set (cargo xtask check-client-allowlist).
allow = ["MIT", "MIT-0", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause",
         "ISC", "Zlib", "CC0-1.0", "Unicode-3.0", "MPL-2.0", "CDLA-Permissive-2.0"]

[[exception]]
repo = "rizzy-vault-linux"     # one of the four client repositories
ecosystem = "qt"               # swiftpm | gradle | nuget | cmake | qt
package = "Qt Core"            # exact package id, or the Qt module name
licence = "LGPL-3.0-only"      # an SPDX id, or LicenseRef-<name>
kind = "copyleft-dynamic"      # copyleft-dynamic | platform-library | election
reason = "ADR 0101 §4.3"
# licence_sha256 = "<64 lowercase hex>"   required when licence starts with "LicenseRef-"
~~~

- `copyleft-dynamic`: LGPL licences only, ecosystems `qt` or `cmake` only, `rizzy-vault-linux` only. Static linking fails with `LIC-007`.
- `platform-library`: a Part B library. `licence` is a `LicenseRef-` with `licence_sha256` of the vendor's licence text as fetched for the review.
- `election`: a multi-licensed package used on an allowed option (e.g. JNA, `licence = "Apache-2.0"`); the notices file records the choice.
- The `allow` set must equal `deny.toml`'s `[licenses] allow` set; `cargo xtask check-client-allowlist` fails this repository's CI on any difference. ADR 0017 owner decision 6 keeps both AGPL ids off `allow`, so the clients inherit that.
- Changing `allow` or adding an exception is an amendment, as ADR 0017 §5 "Changing the list" says for `deny.toml`, and it reaches the clients through a core release.

#### 5.3 Gate behaviour and errors

- **Exit codes:** `0` every package passes; `1` at least one policy violation; `2` input or infrastructure error (unreadable lockfile, failed metadata fetch, unknown format version). A gate never turns `2` into a pass. CI may retry a job that exited `2` at most twice; `1` is never retried.
- **Diagnostics:** one line per finding, `<code> <ecosystem> <package>@<version>: <message>`, packages in lockfile order and, within a package, in code order.

  | Code | Meaning |
  |---|---|
  | `LIC-001` | Licence expression not satisfied by `allow`, and no matching exception |
  | `LIC-002` | No licence metadata found for the package (unknown is a failure, never a pass) |
  | `LIC-003` | An exception exists, but for another `repo` or `ecosystem` |
  | `LIC-004` | A `LicenseRef-` exception whose licence text SHA-256 differs from `licence_sha256` |
  | `LIC-005` | A Qt module that is not listed (every GPL-only module is unlisted) |
  | `LIC-006` | A dependency other than a Platform Library whose source cannot be obtained for the source archive (§8.1) |
  | `LIC-007` | An LGPL package linked statically |
  | `LIC-010` | `ADDITIONAL-PERMISSIONS.txt` or `client-allow.toml` differs from the copy in the pinned core artifact |
  | `LIC-011` | A versioned file (`rizzy-core.pin`, `client-allow.toml`, the report) is malformed or has an unknown `format` |
  | `LIC-012` | `rizzy-core.pin` disagrees with the tag or with the pinned artifact URLs |

- **Report.** Each run writes `licence-report.json` only after the whole evaluation has finished (to a temporary name, then renamed), so a run that crashes leaves no report, and the release job, which requires one, fails closed:

  ~~~json
  {"format": "rizzy-licence-report/1", "repo": "rizzy-vault-windows", "commit": "<40 hex>", "core_tag": "v0.3.0",
   "packages": [{"ecosystem": "nuget", "name": "Microsoft.WindowsAppSDK", "version": "2.5.1",
                 "licence": "LicenseRef-MSLT-WindowsAppSDK", "basis": "platform-library", "source": "none"}]}
  ~~~

  `basis` is `allow`, `copyleft-dynamic`, `platform-library` or `election`. `source` is `archived` or `none`, and only a `platform-library` may be `none`. The notices generator (§8.2) reads this report, never the lockfiles.

### 6. Distribution channel register

A client is distributed only through a channel listed here. A new channel is an amendment that adds a row.

| Channel | Client | Licence basis | Conditions | Earliest |
|---|---|---|---|---|
| Developer ID signed and notarized download | macOS | AGPL (+ Part B if ever needed) | Notarization adds no terms for recipients (L) | M3 |
| Mac App Store | macOS | Part A | §2.4; custom EULA (§6.1); review item R1 | Open question 3 |
| Apple App Store, TestFlight | iOS, iPadOS (TestFlight also macOS) | Part A | As for the Mac App Store | M7 |
| Direct MSIX or unpackaged download | Windows | AGPL + Part B | §4.4 | M3 |
| Microsoft Store | Windows | Part A + Part B | §2.4; its own licence terms if the Store accepts them (U); review items R1, R4 | Open question 3 |
| AppImage; `.deb` | Linux | AGPL + the Qt exception (§4.3) | A bundled Qt carries its source (§4.3 condition 5) | M3 |
| Flatpak (Flathub) on the KDE runtime | Linux | AGPL + the Qt exception | Flathub adds no terms for recipients (U; checked before the first submission) | After AppImage and `.deb` (ADR 0015 owner decision 2, carried by ADR 0019) |
| Google Play | Android | Part A | §2.4; review item R7 | M7 |
| F-Droid; APK on the release page | Android | AGPL | F-Droid builds from source (ADR 0019 §7) | M7 |

The Snap Store, winget, Homebrew casks and every other channel are not listed, so not allowed until amended in.

#### 6.1 Store listings

- **Apple stores:** the listing supplies a custom licence agreement: the AGPL v3 text followed by `ADDITIONAL-PERMISSIONS.txt`, so Apple's Standard EULA does not apply (V that Apple allows a custom licence; U that this settles §10). Part A is still required; the custom EULA does not replace it.
- **Microsoft Store:** the same text as the app's licence terms, if the Store accepts developer-supplied terms (U).
- **Every store listing and every About screen** names the URL of that build's source archive (§8.1). That is how Part A's condition A2 is met.

### 7. SPDX headers in client repositories

- Every source file we write in every client repository starts with `SPDX-License-Identifier: AGPL-3.0-only` in the language's comment syntax, on its first line, or on the line after a shebang, an XML declaration (`<?xml ...?>`) or an unavoidable byte-order mark. That covers every file type in those repositories that has comment syntax: Swift (`Package.swift` included), Kotlin (`.kt`, `.kts`), C#, C++ headers and sources, QML, XAML and other XML (`.csproj`, `.plist`, Android manifests and resources, `.appxmanifest`), CMake, shell and PowerShell, CSS, HTML.
- Files that cannot carry comments (JSON, lockfiles, asset-catalog contents, images) are covered by the repository-level statement; the check skips them by extension.
- **The check is this repository's `cargo xtask check-spdx`**, run like the sign-off check (§3): `cargo xtask check-spdx --root <client checkout>`, with its language table extended to the types above (implementation step 3). A missing or malformed header fails client CI from the first commit.

### 8. Corresponding Source and notices for each client release

#### 8.1 The source archive

Each client release attaches `<repo>-<version>-source.tar.zst` to the client's release page, with its SHA-256 in the release notes. It contains:

1. the client repository's tree at the release tag (`git archive`);
2. `rizzy-core.pin` and a file `CORE-SOURCE.txt` naming, by URL and SHA-256, the core's own source archive of ADR 0017 §7 for the pinned tag. That is our own release, which we control; ADR 0017 §7 rejected only registries we do not control. A core tag's source archive is never deleted while any client release that names it is offered on any channel, nor for three years after the last such offer;
3. the source of every third-party dependency whose `basis` in `licence-report.json` is not `platform-library`: Swift packages at their resolved revisions, Gradle and NuGet packages' source artifacts or the upstream source at the tagged version, CMake-fetched sources by their `URL_HASH`, and Qt's source tarballs when Qt is bundled (§4.3 condition 5). A dependency whose source cannot be obtained fails the gate with `LIC-006` and blocks the release;
4. `BUILD.md`: the exact toolchain versions (Xcode; the Android Gradle Plugin and JDK; the .NET SDK and Windows App SDK; Qt and CMake) and the commands that rebuild the release binary from this archive plus the Platform Libraries, and install it (Part A, element A4).

**Publishing order (settles the practical part of ADR 0019 §9 point 3).** The source archive is published when the client release tag is pushed, before any store submission and before the binary is available on any channel. No build ever ships without its source, and whether a store submission counts as conveying changes nothing we do (review item R5 only confirms it). For an embargoed security fix this adds no exposure beyond what ADR 0019 §9 point 2 already accepts for the public core tag: the client tag is pushed when its build is submitted.

#### 8.2 Notices

- The client release job generates `THIRD-PARTY-NOTICES.txt` from `licence-report.json` (client dependencies with full licence texts, Qt's copyright notices, the JNA election), then appends the notices file of the pinned core artifact unchanged, then `ADDITIONAL-PERMISSIONS.txt`. It is never edited by hand; a failed generation fails the release.
- It ships in the bundle and is shown in the app: in the About screen on macOS and Windows, in the in-app licences screen on iOS and Android, and in the About dialog on Linux together with the Qt notice of §4.3 condition 6.

### 9. Questions for the paid legal review

These are the legal judgements this ADR rests on. This ADR decides none of them; each is on the review's list (ADR 0017 owner decision 5, as replaced in §10):

- **R1.** Does Part A, with a custom EULA, allow conveying through the Apple App Store, the Mac App Store, TestFlight and the Microsoft Store?
- **R2.** Does Part A's definition of a Distribution Platform cover the channels named, and no more than intended?
- **R3.** Does element A4 meet AGPL §6's Installation Information duty for User Products on iOS and macOS?
- **R4.** Is the Windows App SDK a System Library (we assume not)? Does Part B resolve its MSLT terms against AGPL §10? What do the MSLT's indemnity and end-user terms oblige the owner to do?
- **R5.** Does a store submission count as conveying (ADR 0019 §9 point 3)?
- **R6.** Do §4.3 conditions 5–7 meet LGPLv3 §4 for a Qt copy bundled in an AppImage?
- **R7.** Does Google Play's term that its agreement prevails over the developer's EULA conflict with AGPL, and does Part A cover it?
- **R8.** Must the permissions appear in each file's notice, or is the repository-level statement enough (§2.3)?
- **R9.** Under which licence is code generated from MPL-2.0 templates (UniFFI, uniffi-bindgen-cs), and what must the notices say?

### 10. What this ADR supersedes

Under ADR 0020 point 9. Each entry names one part of [ADR 0017](0017-licensing.md) and gives the full text that replaces it; that text binds as Decision text of this ADR once this ADR is Accepted. Every part of ADR 0017 not named here stays binding as written, including ADR 0073's replacement of the second sentence of §7's "Not an SBOM." bullet. Nothing in [ADR 0019](0019-native-clients.md) is superseded: this ADR answers its §15 list, which by its own heading decides nothing.

| # | ADR 0017 part | Replacing text |
|---|---|---|
| 1 | Context, table "Distribution channels on the roadmap", row "M3" | A row with first cell "M3" and second cell: "Native desktop releases from the client repositories of ADR 0019 (macOS from `rizzy-vault-apple`, Windows from `rizzy-vault-windows`, Linux from `rizzy-vault-linux`) and their update feeds. Each client uses only the channels in ADR 0101 §6's channel register, which also says when the Mac App Store and the Microsoft Store may be used." |
| 2 | Context, the same table, row "M7" | A row with first cell "M7" and second cell: "The mobile apps from `rizzy-vault-apple` (iOS and iPadOS) and `rizzy-vault-android`: the Apple App Store, TestFlight, Google Play, F-Droid and APKs on the release page, as ADR 0101 §6's channel register allows." |
| 3 | Context, "The core decides the client license question.", third sub-bullet ("natively in desktop ([ADR 0015](0015-desktop-tauri.md)) and the CLI.") | "through the binding crates of ADR 0019 §4 in the native desktop clients (Swift on macOS, C# on Windows, C++ on Linux), and natively in the CLI." |
| 4 | Decision §1, first bullet ("Everything in this repository is licensed AGPL-3.0, ..."), with its three sub-bullets | "Everything in this repository and in each client repository of ADR 0019 §6 (`rizzy-vault-apple`, `rizzy-vault-android`, `rizzy-vault-windows`, `rizzy-vault-linux`) is licensed AGPL-3.0, with the version chosen as in Decision 2, plus the additional permissions of ADR 0101 §2 once their reviewed text is committed. That covers: the server, `rizzy-core`, `rizzy-sync`, `rv` and every future crate; the web vault and the browser extension; and, in the client repositories, the native desktop and mobile apps, their platform extensions (AutoFill and credential providers, the Safari wrapper if one is built) and their build scripts." |
| 5 | Decision §3, the "**What.**" bullet | "**What.** The GPLv3/AGPLv3 §7 additional permissions of ADR 0101 §2. Part A allows conveying the covered work through distribution platforms whose terms add restrictions on recipients, such as the Apple App Store, the Mac App Store, the Microsoft Store and Google Play, on the condition that the Corresponding Source of that exact build is available under the AGPL. Part B allows combining it with vendor platform libraries such as the Windows App SDK. Both are one versioned file, `ADDITIONAL-PERMISSIONS.txt`, byte-identical in this repository and in every client repository, each granting them for the whole program of that repository and for its combination with the others." |
| 6 | Decision §3, the "**Timing.**" bullet | "**Timing.** The permission file is committed in this repository, and in every client repository that exists then, before the first external code contribution to any of these repositories is merged; a client repository created later carries it in its first commit. Documentation does not ship in app builds, so documentation PRs do not need it. Adding it after external code has landed needs every code contributor's consent." |
| 7 | Decision §3, the "**SPDX.**" bullet | "**SPDX.** Per-file headers stay `AGPL-3.0-only` (Decision 6). The permissions are stated at repository level: in the permission file, in the README's license section with the file's version and SHA-256, and in the notices file of every artifact. If the legal review requires a per-file notice or an SPDX `WITH` or `AdditionRef-` expression, that is a new ADR. Our crates are `publish = false` and excluded from cargo-deny's license check, so this affects only SBOM and scanning tools." |
| 8 | Decision §5, the "**Beyond Rust.**" bullet | "**Beyond Rust.** `cargo deny` covers Rust only. Before the first JavaScript dependency lands (web vault, M1), CI must get an equivalent license gate over the JS lockfile with the same allow-list; the tool is chosen with the UI stack ([ADR 0014](0014-ui-stack.md)). Each client repository gets the licence gate of ADR 0101 §5 from its first release: SwiftPM for `rizzy-vault-apple`, NuGet for `rizzy-vault-windows`, and CMake plus Qt modules for `rizzy-vault-linux` from M3; Gradle for `rizzy-vault-android` from M7. Their allow-list is `licensing/client-allow.toml`, whose `allow` set equals this list. Its exceptions (Qt LGPL-3.0-only modules for the Linux client only, ADR 0101 Part B platform libraries, licence elections) are amendments, like any change to this list." |
| 9 | Decision §6, first bullet (from "Every source file we write starts with the SPDX line" to the parenthetical on comment syntax, its code block included) | "Every source file we write, in this repository and in every client repository, starts with the SPDX line `SPDX-License-Identifier: AGPL-3.0-only` in the comment syntax of its language, on its first line, or on the line after a shebang, an XML declaration or an unavoidable byte-order mark. That covers every file type with comment syntax, including Rust, TypeScript/JavaScript, Swift, Kotlin and Kotlin scripts, C#, C++, QML, XAML and other XML, CMake, shell and PowerShell, CSS and HTML templates. The expression follows Decision 2 and ADR 0101 §2.3. In the client repositories the check is this repository's `cargo xtask check-spdx` (ADR 0101 §7)." |
| 10 | Decision §7, the "**Generated in the release job, never maintained by hand.**" bullet, its second sentence ("It is built from `Cargo.lock` and the JS lockfile.") | "In this repository it is built from `Cargo.lock` and the JS lockfile; in a client repository it is generated from the client's `licence-report.json`, followed by the notices file of the pinned core artifact and the permission file (ADR 0101 §8.2)." |
| 11 | Decision §7, notices table, row "Desktop" | A row with first cell "Desktop (macOS, Windows and Linux clients)" and second cell "Bundle and About screen; on Linux the About dialog also carries the Qt LGPLv3 notice (ADR 0101 §4.3)". |
| 12 | Decision §7, notices table, row "Mobile" | A row with first cell "Mobile (iOS and Android)" and second cell "Bundle and in-app licenses screen". |
| 13 | Decision §7, the "**Source offer.**" bullet, its first two sentences ("Each release links to its exact tag ... compiled into the release artifacts." and "That is the `cargo vendor` output ... JS lockfile.") | "**Source offer.** Each release, of this repository or of a client repository, links to its exact tag and attaches a complete source archive: the tagged tree plus the source of every dependency compiled into the release artifacts. For this repository that is the `cargo vendor` output for the Rust crates and the package tarballs named in the JS lockfile; for a client release it is the archive of ADR 0101 §8.1, published before the binary is available on any channel." |
| 14 | Owner decision 5 ("**Legal review budget**") | "5. **Legal review budget** → one paid review, before the first external code contribution to any of the five repositories is merged and before any submission to a channel that needs ADR 0101 §2 Part A. It covers the README license notice, the ADR 0101 §2 permission file (Parts A and B), the DCO terms, and questions R1–R9 of ADR 0101 §9." |

On acceptance, ADR 0017's status line names these parts as: Context in part, §1 in part, §3 in part, §5 in part, §6 in part, §7 in part, owner decision 5.

### 11. Enforcement summary

| Rule | Where it is enforced |
|---|---|
| The permission file is identical everywhere | `licensing-files` job in each client's CI (`LIC-010`); this repository's release job copies it into every artifact |
| `allow` equals `deny.toml` | `cargo xtask check-client-allowlist` in this repository's CI |
| Sign-off on every client commit | This repository's `cargo xtask check-signoff --repo`, in client CI |
| SPDX headers in the clients | This repository's `cargo xtask check-spdx --root`, in client CI |
| Client dependency licences, Qt modules, static LGPL, missing source | The §5 gate of each client (`LIC-001` to `LIC-007`) |
| Channel register and store listings | The release checklist of each client repository; the owner reviews each first submission to a channel |

## Consequences

### Positive

- One licence, one permission file and one DCO rule across five repositories; a contributor's grant in any of them covers what the combined store app needs.
- The Mac App Store and the Microsoft Store become possible from M3, instead of being blocked by wording keyed to M7, without a later hunt for consents.
- Qt and the Windows App SDK get explicit, reviewable bases instead of an unwritten exception to ADR 0017 §5.
- Every client release publishes its source first, which settles ADR 0019 §9 point 3's publishing question in practice.
- The sign-off and SPDX checks have one implementation, this repository's xtask, so client repositories cannot drift from it.

### Negative

- Part B is a linking exception for vendor libraries. It weakens copyleft for that one category: a fork may ship our code with any vendor SDK library.
- The permission text must be right the first time; a version 2 needs every holder's consent.
- Client CI must check out this repository and build its xtask: a Rust toolchain in client CI and minutes per run (not measured, U).
- Source archives with every dependency's source, and Qt's tarballs for an AppImage, are large (not measured, U).
- The legal review grows from three documents to those plus nine questions (open question 6).
- The MSLT indemnity is real risk for an individual owner (open question 4).

### Risks

- **The review answers R1, R4 or R7 with no, or a store rejects the custom EULA.** The affected channel is then removed from §6 by a new ADR; the non-store channels are unaffected.
- **Part A does not hold up against a holder's objection or a store's reading.** Signal: an objection or a removal. Mitigation: the Developer ID, direct MSIX and APK channels stay available.
- **The Windows App SDK's licence changes.** Signal: `LIC-004` on a version bump. The review re-runs before the bump ships.
- **Qt changes its open-source terms or moves a module to GPL-only.** Signal: the module check in a Qt bump PR. The module is dropped, or a new ADR is needed.
- **An external code contribution is merged before §2.4 is met.** Mitigation as in ADR 0017's Risks: no external code PR is merged in any repository until the file is committed.

## Alternatives considered

- **A permissive (MIT, Apache-2.0) or MPL-2.0 licence for the client repositories.** Compatible, but the combined work is still AGPL, the core's holders must still grant Part A, and it invites pairing our UI with a closed core. Rejected (§1).
- **GPL-3.0 for the client repositories.** Combines with the AGPL core through §13 but changes nothing for the combined work, and needs its own permission wording. Rejected.
- **A store permission for the Apple App Store only, as ADR 0017's M7 wording assumed.** Simpler to word, but it can never be widened without every contributor's consent, and the Mac App Store and the Microsoft Store are already in ADR 0019's M3 plan. Rejected.
- **A different permission text per repository.** Each repository would grant only what it needs, but the core's holders must grant everything the combined apps need anyway. Rejected for one file.
- **Rely on the System Library exception for the Windows App SDK, without Part B.** Rests on a reading we think is wrong (U). Rejected; Part B is explicit.
- **Drop WinUI 3 for a toolkit with a free licence.** Reopens ADR 0019 owner decision 2 (the toolkits). Not proposed; open question 4 keeps it as the fallback.
- **Ban Qt and use GTK.** Reopens ADR 0019 owner decision 2 (Qt, chosen over GTK). Rejected: the reasons for ADR 0017 §5's LGPL ban do not apply to the Linux channels.
- **Reimplement the sign-off and SPDX checks in each client repository** (shell, or a GitHub app). Faster CI, but the implementations drift. Rejected.
- **A CLA in the client repositories.** Would let the owner submit to stores without Part A, but contradicts ADR 0017 owner decisions 2 and 4. Rejected.

## Open questions for the owner

1. **Client licence (§1): AGPL-3.0-only for all four client repositories, with the same permission file?** Recommended: yes. The alternative, MIT for client UI code, removes nothing of the store problem.
2. **Part A's scope (§2.2): every Distribution Platform, with the Mac App Store, TestFlight, the Microsoft Store and Google Play named, from version 1?** Recommended: yes, because a narrower version 1 can never be widened without every contributor's consent.
3. **When the Mac App Store and the Microsoft Store may be used (§6).** Recommended: the Mac App Store not before M7, together with iOS (one review, one Apple submission pipeline; Developer ID and notarization already cover M3). The Microsoft Store in M3 as soon as R1 and R4 are answered yes, since it signs submissions and Azure Artifact Signing is restricted (ADR 0019 §2, Windows row).
4. **The Windows App SDK (§4.4): accept its MSLT, including the indemnity and the end-user terms, with Part B?** Recommended: yes, conditional on R4. If R4 says no, the fallback is a new ADR reopening ADR 0019 owner decision 2 (WinUI 3 as the Windows toolkit), never shipping without a basis.
5. **Qt (§4.3): admit Qt's LGPL-3.0-only modules for the Linux client only, on the eight conditions?** Recommended: yes; the reasons for ADR 0017 §5's ban (stores, relicensing) do not apply to the Linux channels.
6. **The legal review (§10, entry 14, replacing owner decision 5): one review covering Parts A and B and R1–R9, before the first external code contribution to any repository and before any Part A submission?** Recommended: yes, one review, because the permission text cannot be revised cheaply later. It costs more than the three-document review owner decision 5 budgeted (amount U).

## On acceptance

The change that accepts this ADR makes these edits. None of them is made now.

- Records the owner's answers to the open questions in the Decision above, and removes any part the owner rejects.
- Sets ADR 0017's status line to `Partially superseded by [ADR 0073](0073-signed-images-sbom-provenance.md) (§7 in part); [ADR 0101](0101-native-client-licensing.md) (Context in part, §1 in part, §3 in part, §5 in part, §6 in part, §7 in part, owner decision 5)`, and the same in ADR 0017's row of [README.md](README.md) (ADR 0020 point 9).
- Updates this ADR's index row, and [CLAUDE.md](../../CLAUDE.md)'s list of Accepted ADRs (the lead's edit).
- Adds to [README.md](README.md) "Gates": "Before the first commit to any client repository: 0101 Accepted. Before the first external code contribution to any repository, and before any Part A store submission: the legal review of ADR 0017 owner decision 5 (as replaced by ADR 0101) done, and `ADDITIONAL-PERMISSIONS.txt` committed."
- Proposes to the owner a [ROADMAP](../ROADMAP.md) M3 line making this ADR a gate for the macOS client (a ROADMAP change the owner approves), and adds a [HANDOFF](../HANDOFF.md) line.
- Updates this repository's [README.md](../../README.md) "License" section and [CONTRIBUTING.md](../../CONTRIBUTING.md) "Sign-off" section to say the same terms apply in the client repositories.

## Implementation plan

Steps 1–4 are in this repository and need this ADR Accepted (licensing is behind the CLAUDE.md ADR gate). Steps 5–7 happen in each client repository when it is created.

1. **`licensing/client-allow.toml` (format 1) and `cargo xtask check-client-allowlist`.** Reads the file with a 64 KiB cap, rejects unknown keys, and checks `format`, that `allow` equals `deny.toml`'s set, and each exception's fields (`repo` one of the four names, `ecosystem` one of the five keys, the `kind` rules of §5.2, `licence_sha256` as 64 lowercase hex for a `LicenseRef-`). Wired into CI. Tests, one fixture per rule: a good file passes; an extra or missing `allow` entry fails; `copyleft-dynamic` on `nuget` fails; a `LicenseRef-` without a hash fails; an unknown `format` fails with `LIC-011`.
2. **`check-signoff --repo <path>`.** Passes `-C <path>` to every `git` call; the default is unchanged. Tests: the existing unit tests unchanged; an integration test on a temporary repository outside the workspace (a signed commit passes, an unsigned one fails, a sign-off by another identity fails).
3. **`check-spdx --root <path>`** and the language table for Swift, Kotlin (`.kt`, `.kts`), C#, C++ (`.h`, `.hpp`, `.cpp`), QML, XAML and XML project files, CMake and PowerShell, with §7's XML-declaration rule. Tests: one good and one bad fixture per new type; a header after `<?xml ...?>` passes; JSON is skipped.
4. **Release workflow:** copies `ADDITIONAL-PERMISSIONS.txt` (once committed) and `client-allow.toml` into `licensing/` of every ADR 0019 §7 artifact. Test: a release dry run lists both files in each artifact, with the SHA-256 of the tagged tree's copies. The permission file itself is committed only after the legal review (ADR 0017 §3 "Wording.").
5. **The client repository's first commit:** `LICENSE`, README "License", CONTRIBUTING "Sign-off", `rizzy-core.pin`, `licensing/client-allow.toml`, and `ADDITIONAL-PERMISSIONS.txt` if it exists here; CI jobs `no-rust`, `dco`, `spdx` and `licensing-files` from day one. Tests, as negative fixtures on a scratch branch in the creating PR: an unsigned commit fails `dco`; a `.swift`, `.cs` or `.qml` file without a header fails `spdx`; an edited permission copy fails with `LIC-010`; a short `commit` in `rizzy-core.pin` fails with `LIC-011`.
6. **The licence gate (§5) and `licence-report.json`,** before the client's first release. Tests: a GPL-3.0 package fails with `LIC-001`; a package without licence metadata fails with `LIC-002`; the Windows App SDK with a changed licence hash fails with `LIC-004`; a CMake list with `Qt6::VirtualKeyboard` fails with `LIC-005`; a static Qt fails with `LIC-007`; a run killed before the end leaves no report, and the release job fails.
7. **The client release job:** the source archive (§8.1) published at tag push; the notices merge (§8.2); the About and licences screens; the store listing text (§6.1). Tests: CI rebuilds the binary from the archive by following `BUILD.md` (signing excluded); the notices file contains the core's notices byte for byte and the permission file; the store-upload step depends on the publish step, so it cannot start before the archive is attached.

## References

- [ADR 0017](0017-licensing.md): licensing and contribution terms; partially superseded by this ADR (§10).
- [ADR 0019](0019-native-clients.md): native clients; §2 platform rows, §6 repositories, §7 artifacts, §9 security releases, §15 the items this ADR answers.
- [ADR 0020](0020-partial-supersession.md) point 9: partial supersession.
- [ADR 0073](0073-signed-images-sbom-provenance.md): the SBOM licence field (unchanged; §2.3 supplies the note it anticipates).
- [ADR 0016](0016-workspace-layout.md): crate boundaries (`rizzy-ffi` and `rizzy-ffi-cpp` as leaf crates).
- [ADR 0015](0015-desktop-tauri.md): superseded by ADR 0019; its owner decision 2 (AppImage and `.deb` first) is carried there.
- The gap review: [summary](../reviews/2026-10-25-adr-gap-review.md); [G02](../reviews/2026-10-25-raw/G02.md) (G02-6), [G03](../reviews/2026-10-25-raw/G03.md) (G03-1), [G10](../reviews/2026-10-25-raw/G10.md) (G10-27).
- [LICENSE](../../LICENSE) (AGPL v3: §1 definitions, §6, §7, §10, §12, §13); [CONTRIBUTING.md](../../CONTRIBUTING.md) "Sign-off"; `crates/xtask/src/signoff.rs`; `crates/xtask/src/spdx.rs`.
